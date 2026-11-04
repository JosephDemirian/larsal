//! Reads and writes vault files and key files.
#![forbid(unsafe_code)]
// Rust rule 4: no panics on input. Here, not in Cargo.toml: [lints] workspace = true
// cannot be mixed with a crate lint table. Test code is exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Rust rule 13: every public item says in plain words what it guarantees.
#![deny(missing_docs)]

mod buffer;
pub mod detect;
pub mod document;
pub mod error;
pub mod hashed_blocks;
pub mod header;
pub mod inner;
pub mod integrity;
pub mod kdf_params;
pub mod keyfile;
pub mod keys;
pub mod limits;
pub mod payload;
pub mod share_item;

pub use error::Error;

use app_crypto::kdf::{CostReport, Host};

/// What [`open`] gives back when it does not fail.
#[derive(Debug)]
pub enum Opened {
    /// The KDF cost is in the ask band (CRY-02.14): show the report, and on
    /// yes call [`open`] again with it as the approval. No key work has run.
    Ask(CostReport),
    /// The vault is open.
    Vault(Box<OpenedVault>),
}

/// An opened vault with what the later writer needs from the file.
pub struct OpenedVault {
    /// The outer header, authenticated by the header HMAC (cipher, KDF,
    /// compression, public custom data, version).
    pub header: header::Header,
    /// The vault; `read_version` holds the file's version (FMT-16.24).
    pub vault: app_model::Vault,
    /// Read warnings (dangling attachment refs, renamed attachments,
    /// unresolved references). They never hold a value.
    pub warnings: Vec<document::Warning>,
    /// This open's transformed key, for the next save's check (CRY-03.16).
    pub key: keys::TransformedKey,
}

/// Ids, counts, version and settings kinds only, never user text (LD-88):
/// the public custom data (it may hold a name the user typed) is counted,
/// not printed.
impl core::fmt::Debug for OpenedVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let h = &self.header;
        let kdf = match &h.kdf {
            app_crypto::kdf::KdfParams::AesKdf { .. } => "AES-KDF",
            app_crypto::kdf::KdfParams::Argon2 {
                kind: app_crypto::kdf::Argon2Type::D,
                ..
            } => "Argon2d",
            app_crypto::kdf::KdfParams::Argon2 { .. } => "Argon2id",
        };
        f.debug_struct("OpenedVault")
            .field("version", &(h.major, h.minor))
            .field("cipher", &h.cipher)
            .field("compression", &h.compression)
            .field("kdf", &kdf)
            .field("public_custom_data", &h.public_custom_data.len())
            .field("vault", &self.vault)
            .field("warnings", &self.warnings.len())
            .finish()
    }
}

/// Opens a vault file: [`payload::open_payload`] (header, key, integrity,
/// decryption, gzip, inner header), then [`document::read`] on its XML with
/// the field stream at byte 0 and the inner header pool.
///
/// Guarantees: those of both steps; the open time of the document read is
/// taken once, here (FMT-11 "open time"). For version 3 files the reader
/// also checks the document's header hash over the raw header (FMT-05.12).
///
/// # Errors
/// One kind of FMT-01.33 from the first failing step; a document problem is
/// `Corrupt`, `Unsupported` or `TooLarge` (see [`document::Reason::kind`]).
pub fn open(
    file: &[u8],
    credentials: &keys::Credentials<'_>,
    host: &mut Host,
    limits: &limits::Limits,
    approval: Option<&CostReport>,
) -> Result<Opened, Error> {
    let payload = match payload::open_payload(file, credentials, host, limits, approval)? {
        payload::Open::Ask(report) => return Ok(Opened::Ask(report)),
        payload::Open::Opened(p) => *p,
    };
    let payload::Payload {
        header,
        inner,
        xml,
        mut field_stream,
        transformed_key,
    } = payload;
    let opts = document::Options {
        open_time: now(),
        limits,
        // Version 3: the document's HeaderHash covers the raw header (FMT-05.12).
        v3_header: header.v3.as_ref().and(file.get(..header.len)),
    };
    let pool: Vec<&[u8]> = inner.pool.iter().map(|item| xml.pool_item(item)).collect();
    let doc = document::read(xml.bytes(), &mut field_stream, &pool, &opts)?;
    drop(xml);
    let mut vault = doc.vault;
    vault.read_version = Some(app_model::FileVersion {
        major: header.major,
        minor: header.minor,
    });
    vault.encryption = header::encryption_of(&header);
    vault.public_custom_data = header::public_items(&header.public_custom_data);
    Ok(Opened::Vault(Box::new(OpenedVault {
        header,
        vault,
        warnings: doc.warnings,
        key: transformed_key,
    })))
}

/// The current UTC time in whole seconds (FMT-11 "open time", the save time).
fn now() -> app_model::Time {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    app_model::Time::from_unix(secs).unwrap_or_default()
}

/// What [`save`] gives back when it does not fail.
#[derive(Debug)]
pub enum Saved {
    /// The KDF cost is in the ask band (CRY-02.14): show the report, and on
    /// yes call [`save`] again with it as the approval. No key work has run
    /// and nothing was written.
    Ask(CostReport),
    /// The new file, ready for the atomic save of APP-05.
    File(Box<SavedFile>),
}

/// The bytes of a saved vault file and what the next save needs.
pub struct SavedFile {
    /// The whole file: header, header hash, header HMAC, block stream; it
    /// ends with its final block (FMT-01.20).
    pub bytes: Vec<u8>,
    /// The version written (FMT-16.18 to FMT-16.24).
    pub version: app_model::FileVersion,
    /// This save's transformed key, for the next save's check (CRY-03.16).
    pub key: keys::TransformedKey,
}

impl core::fmt::Debug for SavedFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SavedFile")
            .field("len", &self.bytes.len())
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Builds a version 4 file of `vault` (FMT-16.18), in the order of CRY-03.10:
/// every fresh value is drawn first (master seed, IV or nonce, 32-byte KDF
/// salt, 64-byte stream key, padding item; CRY-03.1 to CRY-03.7), then the
/// KDF cost check, the hardware key asked with the new salt, the KDF, and
/// the key-change check against `previous` (CRY-03.16); then the document
/// (FMT-10 to FMT-15) at the version FMT-16.19 and FMT-16.24 pick, the
/// inner header, gzip, encryption, header, header hash, header HMAC and
/// HMAC blocks (FMT-05.9, FMT-06.8, FMT-08.10, FMT-09.4).
///
/// Guarantees: App never writes what it would refuse to read: the document
/// is read back under `limits` with the reader itself, and the header and
/// file sizes are checked, before the bytes are returned (FMT-08.12). No
/// file is touched here; a failure returns only the error. Every secret
/// stays in a wiping type.
///
/// # Errors
/// `Corrupt` for a model that breaks an invariant of `app_model::invariants`
/// (it cannot be written correctly), before anything else; `NoCredentials`
/// before any key work (FMT-04.16); `HardwareKey` from the
/// device; `TooLarge` naming the limit the vault passes, or the KDF cost;
/// `Unsupported` for KDF settings out of range; `Io(Other)` when the random
/// source fails (LD-76) or the new transformed key equals `previous`
/// (LD-92).
pub fn save(
    vault: &app_model::Vault,
    credentials: &keys::Credentials<'_>,
    previous: Option<&keys::TransformedKey>,
    host: &mut Host,
    limits: &limits::Limits,
    approval: Option<&CostReport>,
) -> Result<Saved, Error> {
    let random_failed = |_| Error::Io(std::io::ErrorKind::Other); // LD-76
    let mut draw = |n: usize| app_crypto::random::bytes(n).map_err(random_failed);
    let mut pick = |n: u32| app_crypto::random::below(n).map_err(random_failed);
    let source = Source {
        draw: &mut draw,
        pick: &mut pick,
    };
    save_from(
        vault,
        credentials,
        previous,
        host,
        limits,
        approval,
        now(),
        source,
    )
}

/// Where a save's fresh values come from. [`save`] always passes the OS
/// source of `app_crypto::random` (CRY-03.9, AT-B04); only this crate's own
/// unit tests pass a scripted or failing one (CRY-03 T12, T13, T21).
struct Source<'a> {
    /// `n` random bytes.
    draw: &'a mut dyn FnMut(usize) -> Result<app_crypto::secret::SecretBytes, Error>,
    /// A whole number in `0..n`, unbiased.
    pick: &'a mut dyn FnMut(u32) -> Result<u32, Error>,
}

/// [`save`] with the save time and the random source given.
#[allow(clippy::too_many_arguments)]
fn save_from(
    vault: &app_model::Vault,
    credentials: &keys::Credentials<'_>,
    previous: Option<&keys::TransformedKey>,
    host: &mut Host,
    limits: &limits::Limits,
    approval: Option<&CostReport>,
    time: app_model::Time,
    source: Source<'_>,
) -> Result<Saved, Error> {
    use app_crypto::kdf::{KdfParams, Verdict};
    use limits::Limit;
    // A model that breaks an invariant cannot be written correctly: refused
    // before any key work (FMT-01.33 `Corrupt`).
    if app_model::invariants::check(vault).is_err() {
        return Err(Error::Corrupt);
    }
    if credentials.is_empty() {
        return Err(Error::NoCredentials);
    }
    // CRY-03.1 to CRY-03.7: separate draws, all before any key work.
    let fresh = source.draw;
    let salt = fresh(32)?;
    let (cipher, compression, kdf) =
        header::header_settings(&vault.encryption, salt.expose().to_vec());
    let master_seed: [u8; 32] = fresh(32)?.expose().try_into().map_err(|_| Error::Corrupt)?;
    let iv = fresh(cipher.iv_len())?;
    let stream_key = keys::LockedKey::new(fresh(64)?);
    let padding_len = (source.pick)(448)?.saturating_add(64);
    let padding = fresh(usize::try_from(padding_len).map_err(|_| Error::Corrupt)?)?;
    let padding_hex: String = padding
        .expose()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // Key work (FMT-04): cost check, hardware key with the new salt, KDF.
    let cleared = match app_crypto::kdf::assess(&kdf, host, &limits.kdf, approval) {
        Ok(Verdict::Run(cleared)) => cleared,
        Ok(Verdict::Ask(report)) => return Ok(Saved::Ask(report)),
        Err(app_crypto::Error::KdfCost) => return Err(Error::TooLarge(Limit::KdfCost)),
        Err(_) => return Err(Error::Unsupported),
    };
    let challenge = match &kdf {
        KdfParams::AesKdf { seed, .. } => seed,
        KdfParams::Argon2 { salt, .. } => salt,
    };
    let hardware = match credentials.hardware_key {
        Some(key) => Some(keys::LockedKey::new(keys::hardware_part(key, challenge)?)),
        None => None,
    };
    let password = credentials
        .password
        .map(|p| keys::LockedKey::new(keys::password_part(p)));
    let composite = keys::LockedKey::new(keys::composite_key(
        password.as_deref(),
        credentials.key_file.map(keyfile::KeyFileKey::key),
        hardware.as_deref(),
    ));
    drop(password);
    drop(hardware); // not needed by the derivation, which can take seconds (SR-07)
    payload::probe::count(|c| c.kdf = c.kdf.saturating_add(1));
    let transformed = keys::LockedKey::new(
        app_crypto::kdf::derive(&composite, &cleared).map_err(|_| Error::Unsupported)?,
    );
    drop(composite);
    if previous.is_some_and(|p| p.same_as(&transformed)) {
        return Err(Error::Io(std::io::ErrorKind::Other)); // CRY-03.16, LD-92
    }
    let final_keys = keys::final_keys(&master_seed, &transformed);
    // The document, then the reader's own check of it (FMT-08.12).
    let minor = document::write::minor_version(vault);
    let stamp = document::write::SaveStamp { padding_hex, time };
    let mut stream = app_crypto::stream::FieldStream::chacha20_from_stream_key(&stream_key)
        .map_err(|_| Error::Corrupt)?;
    let written = document::write::write(vault, minor, &mut stream, &stamp)?;
    let pool: Vec<&[u8]> = written.pool.iter().map(|p| p.expose()).collect();
    let mut check = app_crypto::stream::FieldStream::chacha20_from_stream_key(&stream_key)
        .map_err(|_| Error::Corrupt)?;
    let opts = document::Options {
        open_time: time,
        limits,
        v3_header: None,
    };
    // ponytail: a full second read holds a second model in memory; count
    // while writing if saves of vaults near the limits need less memory.
    drop(document::read(written.xml(), &mut check, &pool, &opts)?);
    // The payload (FMT-08.10): inner header and document, gzip, encryption.
    let mut u = buffer::Grow::new();
    inner::write_inner(&mut u, &stream_key, &written.pool)?;
    drop(stream_key);
    u.extend(written.xml());
    drop(written);
    if u.len > limits.total {
        return Err(Error::TooLarge(Limit::Total));
    }
    let ciphertext = match compression {
        header::Compression::Gzip => {
            let packed = payload::gzip(u.as_slice())?;
            drop(u);
            payload::encrypt(
                cipher,
                &final_keys.cipher_key,
                iv.expose(),
                packed.as_slice(),
            )?
        }
        header::Compression::None => {
            let sealed =
                payload::encrypt(cipher, &final_keys.cipher_key, iv.expose(), u.as_slice())?;
            drop(u);
            sealed
        }
    };
    // The file (FMT-05.9, FMT-06.8): header, its hash, its HMAC, blocks.
    let public = header::map_entries(&vault.public_custom_data);
    let head = header::write_header(
        minor,
        cipher,
        compression,
        &master_seed,
        iv.expose(),
        &kdf,
        &public,
    )?;
    if head.len() > limits.header {
        return Err(Error::TooLarge(Limit::Header));
    }
    let mut file = head.clone();
    file.extend_from_slice(app_crypto::hash::sha256(&[&head]).expose());
    file.extend_from_slice(integrity::header_hmac(&final_keys.hmac_key, &head).expose());
    file.extend(integrity::write_blocks(
        &ciphertext,
        &final_keys.hmac_key,
        integrity::WRITE_BLOCK,
    )?);
    if file.len() > limits.total_file {
        return Err(Error::TooLarge(Limit::TotalFile));
    }
    header::read_header(&file, limits)?; // never a header App would refuse
    Ok(Saved::File(Box::new(SavedFile {
        bytes: file,
        version: app_model::FileVersion { major: 4, minor },
        key: keys::TransformedKey {
            key: transformed,
            kdf,
            v4: true,
        },
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use app_crypto::kdf::SpeedRecord;
    use app_crypto::secret::{SecretBytes, SecretString};
    use app_model::{Group, Kdf, Time, Uuid, Vault};

    fn vault() -> Vault {
        let mut v = Vault::new(Group::new(Uuid([1; 16]), "R".into(), Time(0)), Time(0));
        v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
        v
    }

    fn host() -> Host {
        Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: None,
            aes_record: Some(SpeedRecord {
                count: 100_000_000,
                memory_kib: 0,
                lanes: 1,
                ms: 1_000,
            }),
        }
    }

    /// Saves `vault()` with password `demo-pass` and the given source.
    fn run(
        previous: Option<&keys::TransformedKey>,
        draw: &mut dyn FnMut(usize) -> Result<SecretBytes, Error>,
    ) -> Result<Saved, Error> {
        let p = SecretString::new("demo-pass".into());
        let creds = keys::Credentials {
            password: Some(&p),
            ..Default::default()
        };
        let mut pick = |_n: u32| Ok(0);
        let source = Source {
            draw,
            pick: &mut pick,
        };
        save_from(
            &vault(),
            &creds,
            previous,
            &mut host(),
            &limits::Limits::DEFAULT,
            None,
            Time(0),
            source,
        )
    }

    fn fixed(n: usize) -> Result<SecretBytes, Error> {
        Ok(SecretBytes::new(vec![0x5A; n]))
    }

    #[test]
    fn cry_03_t12_source_failure() {
        let mut fail = |_n: usize| Err(Error::Io(std::io::ErrorKind::Other));
        assert_eq!(
            run(None, &mut fail).unwrap_err(),
            Error::Io(std::io::ErrorKind::Other)
        );
    }

    #[test]
    fn cry_03_t13_order_third_draw_fails() {
        // Every fresh value is drawn before any key work (CRY-03.10): a
        // failing third draw (the IV), fourth (the stream key) or fifth
        // (the padding item) stops the save with no KDF run and no bytes.
        for fail_at in 3..=5 {
            let _ = payload::probe::take();
            let mut calls = 0;
            let mut nth = |n: usize| {
                calls += 1;
                if calls == fail_at {
                    Err(Error::Io(std::io::ErrorKind::Other))
                } else {
                    fixed(n)
                }
            };
            assert_eq!(
                run(None, &mut nth).unwrap_err(),
                Error::Io(std::io::ErrorKind::Other),
                "draw {fail_at}"
            );
            assert_eq!(payload::probe::take().kdf, 0, "draw {fail_at}");
        }
    }

    #[test]
    fn cry_03_t21_key_change_check() {
        // A source that repeats itself gives the same salt, so the KDF
        // returns the previous transformed key: the save fails (LD-92).
        let Ok(Saved::File(first)) = run(None, &mut fixed) else {
            panic!("the first save works")
        };
        assert_eq!(
            run(Some(&first.key), &mut fixed).unwrap_err(),
            Error::Io(std::io::ErrorKind::Other)
        );
        // With the OS source the same save works and the key differs.
        let p = SecretString::new("demo-pass".into());
        let creds = keys::Credentials {
            password: Some(&p),
            ..Default::default()
        };
        let Ok(Saved::File(second)) = save(
            &vault(),
            &creds,
            Some(&first.key),
            &mut host(),
            &limits::Limits::DEFAULT,
            None,
        ) else {
            panic!("a save with fresh values works")
        };
        assert!(!second.key.same_as(&first.key.key));
        assert!(!format!("{:?} {:?}", first.key, second).contains("0x"));
    }

    /// MOD-11.31, LD-269 (2): `transform` gives the very `T` an open of the
    /// file gives, from the file's KDF settings and seed alone: version 4
    /// with the hardware key asked with the KDF seed, and version 3 with no
    /// hardware part in `T`; other credentials give another `T`.
    #[test]
    fn mod11_31_transform_gives_the_key_of_the_open() {
        let p = SecretString::new("demo-pass".into());
        let slot = keys::SoftwareKey {
            secret: SecretBytes::new(vec![9; 20]),
            mode: keys::SlotMode::Fixed,
        };
        let creds = keys::Credentials {
            password: Some(&p),
            hardware_key: Some(&slot),
            ..Default::default()
        };
        let (mut h, l) = (host(), limits::Limits::DEFAULT);
        let Ok(Saved::File(file)) = save(&vault(), &creds, None, &mut h, &l, None) else {
            panic!("saved")
        };
        let Ok(Opened::Vault(opened)) = open(&file.bytes, &creds, &mut h, &l, None) else {
            panic!("opened")
        };
        assert!(opened.key.v4() && *opened.key.kdf() == opened.header.kdf);
        let t = payload::transform(&creds, &opened.header.kdf, true, &mut h, &l).unwrap();
        assert!(opened.key.same_as(&t.key));
        assert_eq!(
            t.salted_digest(&[3; 32]),
            opened.key.salted_digest(&[3; 32])
        );
        let no_slot = keys::Credentials {
            hardware_key: None,
            ..creds
        };
        let t = payload::transform(&no_slot, &opened.header.kdf, true, &mut h, &l).unwrap();
        assert!(!opened.key.same_as(&t.key), "the hardware part counts");
        let t = payload::transform(&creds, &opened.header.kdf, false, &mut h, &l).unwrap();
        assert!(!opened.key.same_as(&t.key), "version 3 leaves it out");
        assert_ne!(t.salted_digest(&[3; 32]), t.salted_digest(&[4; 32]));
        // A version 3 demo file (testdata README: password `demo-pass-1`).
        let v3 = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/password-only.appvault"
        ))
        .unwrap();
        let p1 = SecretString::new("demo-pass-1".into());
        let creds = keys::Credentials {
            password: Some(&p1),
            ..Default::default()
        };
        let Ok(Opened::Vault(opened)) = open(&v3, &creds, &mut h, &l, None) else {
            panic!("opened")
        };
        assert!(!opened.key.v4());
        // No device is asked for a version 3 key: a slot given changes nothing.
        struct Counted(core::cell::Cell<u32>);
        impl keys::ChallengeResponse for Counted {
            fn challenge(&self, _: &[u8; 64]) -> Result<SecretBytes, error::HardwareKeyReason> {
                self.0.set(self.0.get() + 1);
                Ok(SecretBytes::new(vec![1; 20]))
            }
        }
        let counted = Counted(core::cell::Cell::new(0));
        let with_slot = keys::Credentials {
            hardware_key: Some(&counted),
            ..creds
        };
        let t = payload::transform(&with_slot, &opened.header.kdf, false, &mut h, &l).unwrap();
        assert!(opened.key.same_as(&t.key));
        assert_eq!(counted.0.get(), 0, "no device asked");
        assert_eq!(
            payload::transform(
                &keys::Credentials::default(),
                &opened.header.kdf,
                false,
                &mut h,
                &l
            )
            .unwrap_err(),
            Error::NoCredentials
        );
    }
}
