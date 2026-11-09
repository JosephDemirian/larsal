//! Keys this Mac retired (MOD-11.31; decided: spec/decisions.md LD-267 (2),
//! LD-269 (2), (3)). A key is retired when this Mac replaced it: by its own
//! credential change (MOD-12.10, `settings::Applied::key_changed`) or when a
//! merge put the other copy's key in its place ([`replaced_by_merge`]). The
//! caller then makes a [`Record`] of the key it held before, from the last
//! open or save, and keeps it in local state that is never synced. A copy
//! whose credentials match a record ([`is_retired`]) is never merged on its
//! own; with the user's Merge anyway it gets the content merge only
//! (`merge::Options::retired`).
//!
//! Guarantees: a record holds a fresh 32-byte salt from larsal-crypto's random
//! source (never the file's master seed), `SHA-256(salt || T)` of the
//! transformed key `T` (FMT-04.11), and the KDF settings and seed `T` was
//! made with. A key of a password plus another part (a key file or a
//! hardware key) also gets the digest of the password-alone key, with the
//! same salt, settings and seed ([`password_alone`]; LD-288 (2), LD-291
//! (1)), and credentials match either digest. It holds no key or password
//! bytes, equals neither `K_enc` nor `K_mac`, never shows in `Debug`
//! output, and its digests are compared in constant time (Rust rule 6).

use crate::Error;
use crate::merge::{Kind, Merged, Options};
use larsal_crypto::kdf::{Argon2Type, Host, KdfParams};
use larsal_format::keys::{Credentials, TransformedKey};
use larsal_format::limits::Limits;
use larsal_model::json::{Map, Value};

/// One key this Mac retired.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    /// A fresh value from larsal-crypto's random source.
    pub salt: [u8; 32],
    /// `SHA-256(salt || T)`.
    pub digest: [u8; 32],
    /// `SHA-256(salt || T')` of the password-alone key `T'` (LD-288 (2));
    /// `None` for a key with one part, and for a version 3 key of a
    /// password and a hardware key only, whose `T` already is `T'`
    /// (FMT-04.15, LD-291 (1)).
    pub alone: Option<[u8; 32]>,
    /// The KDF settings and seed `T` was made with (public header values).
    pub kdf: KdfParams,
    /// `T` holds the hardware key part (a version 4 file, FMT-04.6).
    pub v4: bool,
}

impl core::fmt::Debug for Record {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Record([hidden])")
    }
}

impl Record {
    /// The record of `key`, the transformed key of the last open or save
    /// under the key this Mac retires, with a fresh salt.
    ///
    /// # Errors
    /// `RandomSource` when no fresh salt can be drawn.
    pub fn new(key: &TransformedKey) -> Result<Self, Error> {
        Self::with(key, None)
    }

    /// The record of `key` with the second digest of `alone`, the
    /// password-alone key [`password_alone`] made with `key`'s settings and
    /// seed (MOD-11.31, LD-288 (2)); one fresh salt for both (LD-291 (1)).
    ///
    /// # Errors
    /// `RandomSource` when no fresh salt can be drawn.
    pub fn with(key: &TransformedKey, alone: Option<&TransformedKey>) -> Result<Self, Error> {
        let mut salt = [0u8; 32];
        larsal_crypto::random::fill(&mut salt).map_err(|_| Error::RandomSource)?;
        Ok(Self {
            digest: key.salted_digest(&salt),
            alone: alone.map(|a| a.salted_digest(&salt)),
            salt,
            kdf: key.kdf().clone(),
            v4: key.v4(),
        })
    }

    /// True when `credentials` give the key this record was made of: they
    /// run through the record's KDF settings and seed, so a copy saved again
    /// with a fresh seed (FMT-04.17) still matches. Runs the KDF: call it
    /// off the main thread.
    ///
    /// # Errors
    /// The key work's own (`larsal_format::payload::transform`); the caller
    /// then merges nothing.
    pub fn matches(
        &self,
        credentials: &Credentials<'_>,
        host: &mut Host,
        limits: &Limits,
    ) -> Result<bool, larsal_format::Error> {
        let t = larsal_format::payload::transform(credentials, &self.kdf, self.v4, host, limits)?;
        let mine = t.salted_digest(&self.salt);
        // Both compares run, so the time says nothing of which matched.
        let full = larsal_crypto::secret::ct_eq(&mine, &self.digest);
        let alone = self
            .alone
            .is_some_and(|a| larsal_crypto::secret::ct_eq(&mine, &a));
        Ok(full | alone)
    }
}

/// LD-288 (2), MOD-11.31: the transformed key of the password alone, made
/// with `key`'s KDF settings and seed, when `credentials` (the parts `key`
/// was made of) hold a password plus a key file or, in a version 4 file, a
/// hardware key; `None` otherwise, with no KDF run. A version 3 key keeps
/// the hardware part out of `T` (FMT-04.15), so with a password and a
/// hardware key only its `T` already is the password-alone key (LD-291
/// (1)). Runs the KDF once: call it off the main thread, at the credential
/// change, when the user waits anyway.
///
/// # Errors
/// The key work's own (`larsal_format::payload::transform`).
pub fn password_alone(
    key: &TransformedKey,
    credentials: &Credentials<'_>,
    host: &mut Host,
    limits: &Limits,
) -> Result<Option<TransformedKey>, larsal_format::Error> {
    let other = credentials.key_file.is_some() || (key.v4() && credentials.hardware_key.is_some());
    let Some(password) = credentials.password.filter(|_| other) else {
        return Ok(None);
    };
    let alone = Credentials {
        password: Some(password),
        ..Credentials::default()
    };
    larsal_format::payload::transform(&alone, key.kdf(), key.v4(), host, limits).map(Some)
}

/// True when `credentials`, given for a copy that did not open with this
/// vault's own key, match any record: the copy is under a key this Mac
/// retired (MOD-11.31). One KDF run per record until a match.
///
/// # Errors
/// As [`Record::matches`].
pub fn is_retired(
    records: &[Record],
    credentials: &Credentials<'_>,
    host: &mut Host,
    limits: &Limits,
) -> Result<bool, larsal_format::Error> {
    for r in records {
        if r.matches(credentials, host, limits)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// True when the merge `merged` (run with `o`) put the other copy's key in
/// place of this Mac's, so the key this Mac held before is now retired and
/// the caller makes its [`Record`]. `other_key` is true when the other copy
/// opened with credentials the user gave for it, not with this vault's own
/// key (MOD-11.29); with one key nothing is retired. After a change on disk
/// and in server sync this Mac's vault is the source, so the result keeps
/// the other copy's key unless `key_taken`; in every other merge this Mac's
/// vault is the target. A dry run or a content merge of a retired copy
/// replaces nothing.
#[must_use]
pub fn replaced_by_merge(o: &Options, merged: &Merged, other_key: bool) -> bool {
    let own_is_source = matches!(o.kind, Kind::ChangeOnDisk | Kind::ServerSync);
    other_key && !o.dry_run && !o.retired && merged.key_taken != own_is_source
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i.checked_add(2)?)?, 16).ok())
        .collect()
}

fn unhex32(v: &Value) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(unhex(v.as_str()?)?).ok()
}

fn params_json(k: &KdfParams) -> Value {
    let mut m = Map::new();
    match k {
        KdfParams::AesKdf { rounds, seed } => {
            m.insert("aes".into(), (*rounds).into());
            m.insert("seed".into(), hex(seed).into());
        }
        KdfParams::Argon2 {
            kind,
            version,
            iterations,
            memory_kib,
            lanes,
            salt,
        } => {
            let name = if *kind == Argon2Type::D { "d" } else { "id" };
            m.insert("argon2".into(), name.into());
            m.insert("v".into(), (*version).into());
            m.insert("i".into(), (*iterations).into());
            m.insert("m".into(), (*memory_kib).into());
            m.insert("p".into(), (*lanes).into());
            m.insert("salt".into(), hex(salt).into());
        }
    }
    Value::Object(m)
}

fn params_of(v: &Value) -> Option<KdfParams> {
    if let Some(rounds) = v["aes"].as_u64() {
        return Some(KdfParams::AesKdf {
            rounds,
            seed: unhex(v["seed"].as_str()?)?,
        });
    }
    Some(KdfParams::Argon2 {
        kind: match v["argon2"].as_str()? {
            "d" => Argon2Type::D,
            "id" => Argon2Type::Id,
            _ => return None,
        },
        version: v["v"].as_u64()?,
        iterations: v["i"].as_u64()?,
        memory_kib: v["m"].as_u64()?,
        lanes: v["p"].as_u64()?,
        salt: unhex(v["salt"].as_str()?)?,
    })
}

/// `r` as the JSON record both local state files keep (MOD-11.31, SYN-03.3).
#[must_use]
pub fn record_json(r: &Record) -> Value {
    let mut o = Map::new();
    o.insert("salt".into(), hex(&r.salt).into());
    o.insert("digest".into(), hex(&r.digest).into());
    if let Some(a) = r.alone {
        o.insert("alone".into(), hex(&a).into());
    }
    o.insert("kdf".into(), params_json(&r.kdf));
    o.insert("v4".into(), r.v4.into());
    Value::Object(o)
}

/// The record of [`record_json`]; `None` for a key or value it does not know.
#[must_use]
pub fn record_of_json(v: &Value) -> Option<Record> {
    let known = ["salt", "digest", "alone", "kdf", "v4"];
    if !v
        .as_object()
        .is_some_and(|m| m.keys().all(|k| known.contains(&k.as_str())))
    {
        return None;
    }
    Some(Record {
        salt: unhex32(&v["salt"])?,
        digest: unhex32(&v["digest"])?,
        alone: match &v["alone"] {
            Value::Null => None,
            a => Some(unhex32(a)?),
        },
        kdf: params_of(&v["kdf"])?,
        v4: v["v4"].as_bool()?,
    })
}
