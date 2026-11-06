//! Header hash and header HMAC (FMT-05), and the HMAC block stream of
//! version 4 (FMT-06).
//!
//! Guarantees: every tag is compared in constant time (Rust rule 6); the
//! block stream is checked whole, up to its final block, before any byte of
//! it is handed on (FMT-06.9); every block length is checked against the
//! bytes left before anything is read (FMT-06.10); bytes after the final
//! block are never read (FMT-06.12, LD-01); every failure is `Corrupt`,
//! never `WrongKey` (FMT-06.13).

use crate::error::Error;
use crate::header::{read_header, write_header};
use crate::limits::{Limit, Limits};
use larsal_crypto::hash::{sha256, sha512};
use larsal_crypto::mac::{hmac_sha256, verify_hmac_sha256};
use larsal_crypto::secret::{SecretBytes, ct_eq};

/// Size of each data block Larsal writes: 1 MiB (FMT-06.8).
pub const WRITE_BLOCK: usize = 1 << 20;

/// True when `stored` is the SHA-256 of `header` (FMT-05.3). Proves no
/// authenticity: anyone can recompute it.
#[must_use]
pub fn header_hash_ok(header: &[u8], stored: &[u8]) -> bool {
    ct_eq(sha256(&[header]).expose(), stored)
}

/// `K_i = SHA-512(LE64(i) || K)` (FMT-06.4); the header uses index 2^64 - 1 (FMT-05.5).
fn block_key(hmac_key: &SecretBytes, index: u64) -> SecretBytes {
    sha512(&[&index.to_le_bytes(), hmac_key.expose()])
}

/// The header HMAC of FMT-05.6 over the raw header bytes, keyed from `K_mac`.
#[must_use]
pub fn header_hmac(hmac_key: &SecretBytes, header: &[u8]) -> SecretBytes {
    let key = block_key(hmac_key, u64::MAX);
    // The HMAC crate takes keys of any length, so this never fails.
    hmac_sha256(key.expose(), &[header]).unwrap_or_else(|_| SecretBytes::new(Vec::new()))
}

/// True when `stored` is the header HMAC of `header` under `K_mac`, compared
/// in constant time (FMT-05.6). A mismatch means the wrong key (FMT-05.8).
#[must_use]
pub fn header_hmac_ok(hmac_key: &SecretBytes, header: &[u8], stored: &[u8]) -> bool {
    let key = block_key(hmac_key, u64::MAX);
    verify_hmac_sha256(key.expose(), &[header], stored)
}

/// One block at the start of `rest`, its HMAC not yet checked: tag, size field,
/// data and what follows (FMT-06.2, FMT-06.10).
#[allow(clippy::type_complexity)]
fn next_block<'a>(
    rest: &'a [u8],
    limits: &Limits,
) -> Result<(&'a [u8; 32], &'a [u8; 4], &'a [u8], &'a [u8]), Error> {
    let (tag, after) = rest.split_first_chunk::<32>().ok_or(Error::Corrupt)?;
    let (size, after) = after.split_first_chunk::<4>().ok_or(Error::Corrupt)?;
    let n = usize::try_from(i32::from_le_bytes(*size)).map_err(|_| Error::Corrupt)?;
    if n > limits.block {
        return Err(Error::Corrupt);
    }
    let (data, after) = after.split_at_checked(n).ok_or(Error::Corrupt)?;
    Ok((tag, size, data, after))
}

/// True when `file` is a version 4 file with no room the reader skips: its
/// outer header is, byte for byte, what `write_header` makes of the values it
/// read (a version 3 header never is), and its block stream ends at the file's
/// last byte (SYN-03.5 step 2).
/// That leaves out a comment or unknown field (FMT-02.21), end field data other
/// than Larsal's (FMT-02.3), extra entries or bytes in a typed map (FMT-03.6),
/// and anything past the final block (FMT-01.20). Each of these opens and a
/// Larsal save drops it.
///
/// Guarantees: no key and no key derivation; reads only inside `file`; no tag
/// is checked, so it says nothing of who wrote the file or whether it opens.
/// The values themselves are not judged: the seeds, the salt, the ciphertext
/// and field 12, which is public by design and which a save keeps (FMT-03.22).
#[must_use]
pub fn exact_frame(file: &[u8], limits: &Limits) -> bool {
    let Ok(h) = read_header(file, limits) else {
        return false;
    };
    let head = write_header(
        h.minor,
        h.cipher,
        h.compression,
        &h.master_seed,
        &h.iv,
        &h.kdf,
        &h.public_custom_data,
    );
    if !head.is_ok_and(|head| file.get(..h.len) == Some(head.as_slice())) {
        return false;
    }
    let Some(mut rest) = h.len.checked_add(64).and_then(|start| file.get(start..)) else {
        return false;
    };
    loop {
        let Ok((_, _, data, after)) = next_block(rest, limits) else {
            return false;
        };
        if data.is_empty() {
            return after.is_empty();
        }
        rest = after;
    }
}

/// Walks the block stream that starts at `stream` (file offset `H + 64`)
/// and returns the data part of every block, in order, as slices of
/// `stream`: joined, they are the ciphertext (FMT-06.7).
///
/// # Errors
/// `Corrupt` for a negative or oversized size, a cut, a bad HMAC, a missing
/// final block, or an empty payload (FMT-06.10, FMT-06.11, FMT-06.6, FMT-06.14).
pub fn read_blocks<'a>(
    stream: &'a [u8],
    hmac_key: &SecretBytes,
    limits: &Limits,
) -> Result<Vec<&'a [u8]>, Error> {
    let mut rest = stream;
    let mut out = Vec::new();
    for index in 0..u64::MAX {
        let (tag, size, data, after) = next_block(rest, limits)?;
        let key = block_key(hmac_key, index);
        if !verify_hmac_sha256(key.expose(), &[&index.to_le_bytes(), size, data], tag) {
            return Err(Error::Corrupt);
        }
        if data.is_empty() {
            return if out.is_empty() {
                Err(Error::Corrupt)
            } else {
                Ok(out)
            };
        }
        out.push(data);
        rest = after;
    }
    Err(Error::Corrupt) // index 2^64 - 1 is the header's (FMT-06.3)
}

/// Writes `ciphertext` as a block stream with data blocks of `block_size`
/// bytes (the last one shorter), then the final empty block (FMT-06.8).
/// Pass [`WRITE_BLOCK`] for what Larsal writes.
///
/// # Errors
/// `TooLarge` if `block_size` is 0 or over the signed 32-bit size field.
pub fn write_blocks(
    ciphertext: &[u8],
    hmac_key: &SecretBytes,
    block_size: usize,
) -> Result<Vec<u8>, Error> {
    if block_size == 0 || i32::try_from(block_size).is_err() {
        return Err(Error::TooLarge(Limit::Block));
    }
    let mut out = Vec::new();
    let mut index: u64 = 0;
    for data in ciphertext.chunks(block_size).chain([&[][..]]) {
        let size = u32::try_from(data.len())
            .map_err(|_| Error::TooLarge(Limit::Block))?
            .to_le_bytes();
        let key = block_key(hmac_key, index);
        let tag = hmac_sha256(key.expose(), &[&index.to_le_bytes(), &size, data])
            .map_err(|_| Error::TooLarge(Limit::Block))?;
        out.extend_from_slice(tag.expose());
        out.extend_from_slice(&size);
        out.extend_from_slice(data);
        index = index.checked_add(1).ok_or(Error::TooLarge(Limit::Block))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf_params::{BYTES, MapEntry, write_map};
    use crate::{Saved, keys};
    use larsal_crypto::kdf::{Host, SpeedRecord};
    use larsal_crypto::secret::SecretString;
    use larsal_model::settings::{Cipher, Compression};
    use larsal_model::{Argon2Kind, Group, Kdf, PublicItem, Time, Uuid, Vault};

    const AES: Kdf = Kdf::AesKdf { rounds: 1 };
    const ARGON: Kdf = Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: 1,
        memory_kib: 64,
        lanes: 1,
    };

    fn saved(cipher: Cipher, compression: Compression, kdf: Kdf, public: &[&str]) -> Vec<u8> {
        let mut v = Vault::new(Group::new(Uuid([1; 16]), "R".into(), Time(0)), Time(0));
        v.encryption.cipher = cipher;
        v.encryption.compression = compression;
        v.encryption.kdf = kdf;
        v.public_custom_data = public
            .iter()
            .map(|name| PublicItem {
                kind: BYTES,
                name: name.as_bytes().to_vec(),
                value: b"demo".to_vec(),
            })
            .collect();
        let mut host = Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: Some(SpeedRecord {
                count: 100,
                memory_kib: 64,
                lanes: 1,
                ms: 1,
            }),
            aes_record: Some(SpeedRecord {
                count: 100_000_000,
                memory_kib: 0,
                lanes: 1,
                ms: 1_000,
            }),
        };
        let p = SecretString::new("demo-pass".into());
        let creds = keys::Credentials {
            password: Some(&p),
            ..Default::default()
        };
        let limits = Limits::DEFAULT;
        match crate::save(&v, &creds, None, &mut host, &limits, None).unwrap() {
            Saved::File(f) => f.bytes,
            Saved::Ask(r) => match crate::save(&v, &creds, None, &mut host, &limits, Some(&r)) {
                Ok(Saved::File(f)) => f.bytes,
                other => panic!("{other:?}"),
            },
        }
    }

    fn plain() -> Vec<u8> {
        saved(Cipher::Aes256, Compression::Gzip, AES, &[])
    }

    /// The header fields of `file` as stored, and the header's length.
    #[allow(clippy::arithmetic_side_effects)]
    fn fields(file: &[u8]) -> (Vec<(u8, Vec<u8>)>, usize) {
        let (mut pos, mut out) = (12, Vec::new());
        loop {
            let id = file[pos];
            let len = u32::from_le_bytes(file[pos + 1..pos + 5].try_into().unwrap()) as usize;
            out.push((id, file[pos + 5..pos + 5 + len].to_vec()));
            pos += 5 + len;
            if id == 0 {
                return (out, pos);
            }
        }
    }

    /// `file` with its header fields changed by `change`. The check bytes stay
    /// as they were: `exact_frame` reads no tag.
    fn with_fields(file: &[u8], change: impl FnOnce(&mut Vec<(u8, Vec<u8>)>)) -> Vec<u8> {
        let (mut list, end) = fields(file);
        change(&mut list);
        let mut out = file[..12].to_vec();
        for (id, data) in list {
            out.push(id);
            out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&data);
        }
        out.extend_from_slice(&file[end..]);
        out
    }

    fn is_exact(file: &[u8]) -> bool {
        exact_frame(file, &Limits::DEFAULT)
    }

    /// SYN-03.5 step 2: every file Larsal saves is exact, whatever its settings,
    /// so a save always gives a file that can go up.
    #[test]
    fn syn03_5_t60_every_file_larsal_saves_has_an_exact_frame() {
        for cipher in [Cipher::Aes256, Cipher::Twofish256, Cipher::ChaCha20] {
            for compression in [Compression::Gzip, Compression::None] {
                for kdf in [AES, ARGON] {
                    for public in [&[][..], &["zeta", "alpha"][..]] {
                        let file = saved(cipher, compression, kdf, public);
                        assert!(
                            is_exact(&file),
                            "{cipher:?} {compression:?} {kdf:?} {public:?}"
                        );
                    }
                }
            }
        }
    }

    /// FMT-01.20, SYN-03.5 step 2: whatever lies past the final block, or a file
    /// that ends before it, is not exact. Opening stays tolerant (LD-01).
    #[test]
    fn syn03_5_t60_any_byte_after_the_final_block_is_not_exact() {
        let file = plain();
        let last = file[file.len() - 36..].to_vec();
        for tail in [&b"x"[..], &[0; 36][..], &last[..], b"Demo plain text"] {
            let mut with = file.clone();
            with.extend_from_slice(tail);
            assert!(!is_exact(&with), "{tail:?}");
        }
        assert!(!is_exact(&file[..file.len() - 1]));
        assert!(!is_exact(&file[..file.len() - 36]));
    }

    /// FMT-02.3, FMT-02.21, FMT-03.6, SYN-03.5 step 2: each place the reader skips
    /// in the outer header is not exact.
    #[test]
    fn syn03_5_t60_room_in_the_outer_header_is_not_exact() {
        let file = plain();
        let map_entry = |m: &mut Vec<u8>| {
            m.pop();
            m.extend_from_slice(&[BYTES, 1, 0, 0, 0, b'Z', 4, 0, 0, 0]);
            m.extend_from_slice(b"note");
            m.push(0);
        };
        type Change = Box<dyn FnOnce(&mut Vec<(u8, Vec<u8>)>)>;
        let plants: Vec<(&str, Change)> = vec![
            (
                "comment",
                Box::new(|l| l.insert(0, (1, b"Demo note".to_vec()))),
            ),
            (
                "unknown id",
                Box::new(|l| l.insert(2, (200, b"Demo note".to_vec()))),
            ),
            (
                "end data",
                Box::new(|l| l.last_mut().unwrap().1 = b"Demo note".to_vec()),
            ),
            (
                "end data empty",
                Box::new(|l| l.last_mut().unwrap().1.clear()),
            ),
            (
                "map entry",
                Box::new(move |l| {
                    let kdf = l.iter_mut().find(|(id, _)| *id == 11).unwrap();
                    map_entry(&mut kdf.1);
                }),
            ),
            (
                "after the map",
                Box::new(|l| {
                    l.iter_mut()
                        .find(|(id, _)| *id == 11)
                        .unwrap()
                        .1
                        .extend_from_slice(b"Demo note");
                }),
            ),
            (
                "empty public map",
                Box::new(|l| {
                    let end = l.len() - 1;
                    l.insert(end, (12, write_map(&[]).unwrap()));
                }),
            ),
            ("other order", Box::new(|l| l.swap(0, 1))),
        ];
        for (name, change) in plants {
            let planted = with_fields(&file, change);
            assert!(
                read_header(&planted, &Limits::DEFAULT).is_ok(),
                "{name} reads"
            );
            assert!(!is_exact(&planted), "{name}");
        }
        assert!(
            is_exact(&with_fields(&file, |_| {})),
            "the helper changes nothing"
        );
    }

    /// FMT-03.22, SYN-03 Security notes: field 12 is public by design and a save
    /// keeps it, so its entries pass. An unsorted map does not: no save writes one.
    #[test]
    fn syn03_5_t60_field_12_passes_only_as_a_save_writes_it() {
        let file = saved(Cipher::Aes256, Compression::Gzip, AES, &["alpha", "zeta"]);
        assert!(is_exact(&file));
        let entry = |name: &[u8]| MapEntry {
            kind: BYTES,
            name: name.to_vec(),
            value: b"demo".to_vec(),
        };
        let unsorted = with_fields(&file, |l| {
            let at = l.iter().position(|(id, _)| *id == 12).unwrap();
            let (mut a, b) = (
                write_map(&[entry(b"zeta")]).unwrap(),
                write_map(&[entry(b"alpha")]).unwrap(),
            );
            a.pop();
            a.extend_from_slice(&b[2..]);
            l[at].1 = a;
        });
        assert!(read_header(&unsorted, &Limits::DEFAULT).is_ok());
        assert!(!is_exact(&unsorted));
    }

    /// SYN-03.5 step 2: version 3 and files that are no vault are never exact.
    /// Demo files of version 4 made by the tools in testdata are.
    #[test]
    fn syn03_5_t60_version_3_and_other_files_are_not_exact() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/");
        let read = |name: &str| std::fs::read(format!("{dir}{name}.larsalvault")).unwrap();
        for name in ["rich-v3", "password-only"] {
            assert!(!is_exact(&read(name)), "{name}");
        }
        for name in ["option-a-personal", "rich-v4"] {
            assert!(is_exact(&read(name)), "{name}");
        }
        assert!(!is_exact(b""));
        assert!(!is_exact(b"Demo plain text"));
        assert!(!is_exact(&plain()[..40]));
    }

    /// SYN-03.5 step 2: the values are not judged. A minor version no save would
    /// write is exact, because the header writer makes the same bytes of it.
    #[test]
    fn syn03_5_t60_a_chosen_minor_version_is_a_value_and_passes() {
        let mut file = plain();
        (file[8], file[9]) = (0x7A, 0x7A);
        assert!(is_exact(&file));
    }
}
