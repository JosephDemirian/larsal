//! The typed key-value map of version 4 header fields 11 and 12 (FMT-03):
//! structure, version, types, and the KDF settings it describes.
//!
//! Guarantees: every length is checked against the bytes left in the field
//! before anything is read or allocated (FMT-03.3); the checks run in the
//! order of FMT-03.20 (version, then structure, then the KDF settings);
//! numbers are read at their full stored width and never cut (FMT-03.18).

use crate::error::Error;
use crate::limits::Limit;
use app_crypto::kdf::{AES_KDF_ID, AES_KDF_NEW_ID, ARGON2D_ID, ARGON2ID_ID, Argon2Type, KdfParams};
use std::collections::HashSet;

/// Type byte `04`: unsigned 32-bit.
pub const UINT32: u8 = 0x04;
/// Type byte `05`: unsigned 64-bit.
pub const UINT64: u8 = 0x05;
/// Type byte `08`: boolean, one byte.
pub const BOOL: u8 = 0x08;
/// Type byte `0C`: signed 32-bit.
pub const INT32: u8 = 0x0C;
/// Type byte `0D`: signed 64-bit.
pub const INT64: u8 = 0x0D;
/// Type byte `18`: text bytes.
pub const STRING: u8 = 0x18;
/// Type byte `42`: raw bytes.
pub const BYTES: u8 = 0x42;

/// One map entry, kept exactly as stored (FMT-03.7, FMT-03.8, FMT-03.22).
/// Public header data: never a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntry {
    /// The type byte, one of the constants above.
    pub kind: u8,
    /// The name bytes, compared as exact bytes.
    pub name: Vec<u8>,
    /// The value bytes, as stored.
    pub value: Vec<u8>,
}

/// Parses a map's structure (FMT-03.1 to FMT-03.6, FMT-03.9). Bytes after
/// the terminator are ignored (FMT-03.6).
///
/// # Errors
/// `Unsupported` for a map version with major 2 or more (FMT-03.2);
/// `Corrupt` for any structure fault, checked after the version.
pub fn parse_map(data: &[u8]) -> Result<Vec<MapEntry>, Error> {
    let (version, mut rest) = data.split_first_chunk::<2>().ok_or(Error::Corrupt)?;
    if u16::from_le_bytes(*version) >> 8 >= 2 {
        return Err(Error::Unsupported);
    }
    let mut entries: Vec<MapEntry> = Vec::new();
    // Names seen, for the duplicate check in constant time per entry.
    let mut names: HashSet<&[u8]> = HashSet::new();
    loop {
        let (&kind, after) = rest.split_first().ok_or(Error::Corrupt)?;
        if kind == 0 {
            return Ok(entries);
        }
        let (name, after) = take_sized(after)?;
        let (value, after) = take_sized(after)?;
        rest = after;
        let fixed = match kind {
            UINT32 | INT32 => Some(4),
            UINT64 | INT64 => Some(8),
            BOOL => Some(1),
            STRING | BYTES => None,
            _ => return Err(Error::Corrupt),
        };
        if fixed.is_some_and(|n| n != value.len()) || !names.insert(name) {
            return Err(Error::Corrupt);
        }
        entries.push(MapEntry {
            kind,
            name: name.to_vec(),
            value: value.to_vec(),
        });
    }
}

/// A 4-byte length, then that many bytes, all inside `data` (FMT-03.3).
fn take_sized(data: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (len, rest) = data.split_first_chunk::<4>().ok_or(Error::Corrupt)?;
    let len = usize::try_from(u32::from_le_bytes(*len)).map_err(|_| Error::Corrupt)?;
    rest.split_at_checked(len).ok_or(Error::Corrupt)
}

/// Parses header field 11 into KDF settings (FMT-03.11 to FMT-03.17, plus
/// m ≥ 8 × p of CRY-02.10), all before any key work.
///
/// # Errors
/// As [`parse_map`] for the structure; `Unsupported` for every problem with
/// the settings themselves (FMT-03.20).
pub fn parse_kdf(data: &[u8]) -> Result<KdfParams, Error> {
    let entries = parse_map(data)?;
    let get = |name: &[u8]| entries.iter().find(|e| e.name == name);
    let bytes = |name: &[u8]| match get(name) {
        Some(e) if e.kind == BYTES => Ok(e.value.clone()),
        _ => Err(Error::Unsupported),
    };
    let number = |name: &[u8]| get(name).ok_or(Error::Unsupported).and_then(number);
    let id = bytes(b"$UUID")?;
    let kind = match <[u8; 16]>::try_from(id.as_slice()).map_err(|_| Error::Unsupported)? {
        AES_KDF_ID | AES_KDF_NEW_ID => {
            let (rounds, seed) = (number(b"R")?, bytes(b"S")?);
            if !(1..=MAX_COUNT).contains(&rounds) || seed.len() != 32 {
                return Err(Error::Unsupported);
            }
            return Ok(KdfParams::AesKdf { rounds, seed });
        }
        ARGON2D_ID => Argon2Type::D,
        ARGON2ID_ID => Argon2Type::Id,
        _ => return Err(Error::Unsupported),
    };
    let salt = bytes(b"S")?;
    let (version, lanes) = (number(b"V")?, number(b"P")?);
    let (memory, iterations) = (number(b"M")?, number(b"I")?);
    let memory_kib = memory / 1024;
    // K and A must be absent or empty ByteArrays (FMT-03.15, FMT-03.17).
    let unused_empty =
        |name: &[u8]| get(name).is_none_or(|e| e.kind == BYTES && e.value.is_empty());
    let ok = (8..=32).contains(&salt.len())
        && matches!(version, 0x10 | 0x13)
        && (1..=MAX_LANES).contains(&lanes)
        && (8..=MAX_MEMORY_KIB).contains(&memory_kib)
        && lanes.checked_mul(8).is_some_and(|min| memory_kib >= min)
        && (1..=MAX_COUNT).contains(&iterations)
        && unused_empty(b"K")
        && unused_empty(b"A");
    if !ok {
        return Err(Error::Unsupported);
    }
    Ok(KdfParams::Argon2 {
        kind,
        version,
        iterations,
        memory_kib,
        lanes,
        salt,
    })
}

/// Highest I and R (FMT-03.12, FMT-03.16).
const MAX_COUNT: u64 = 2_147_483_646;
/// Highest P (FMT-03.12).
const MAX_LANES: u64 = 16_777_215;
/// Highest m in KiB: M below 2^42 bytes (FMT-03.12).
const MAX_MEMORY_KIB: u64 = 4_294_967_295;

/// A numeric KDF value: any integer type, never negative (FMT-03.17).
fn number(e: &MapEntry) -> Result<u64, Error> {
    let v = e.value.as_slice();
    let n = match (e.kind, v.len()) {
        (UINT32, 4) => u64::from(u32::from_le_bytes(
            v.try_into().map_err(|_| Error::Corrupt)?,
        )),
        (UINT64, 8) => u64::from_le_bytes(v.try_into().map_err(|_| Error::Corrupt)?),
        (INT32, 4) => u64::try_from(i32::from_le_bytes(
            v.try_into().map_err(|_| Error::Corrupt)?,
        ))
        .map_err(|_| Error::Unsupported)?,
        (INT64, 8) => u64::try_from(i64::from_le_bytes(
            v.try_into().map_err(|_| Error::Corrupt)?,
        ))
        .map_err(|_| Error::Unsupported)?,
        _ => return Err(Error::Unsupported),
    };
    Ok(n)
}

/// Writes a map (FMT-03.21, FMT-03.22): version `00 01`, the entries sorted
/// by name bytes ascending, each as type, name and value with 4-byte
/// lengths, then `00`.
///
/// # Errors
/// `TooLarge(Header)` for a name or value over 4 GiB, which no header holds.
pub fn write_map(entries: &[MapEntry]) -> Result<Vec<u8>, Error> {
    let mut sorted: Vec<&MapEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = vec![0x00, 0x01];
    for e in sorted {
        out.push(e.kind);
        for part in [&e.name, &e.value] {
            let len = u32::try_from(part.len()).map_err(|_| Error::TooLarge(Limit::Header))?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(part);
        }
    }
    out.push(0x00);
    Ok(out)
}

/// Header field 11 for `params` (FMT-03.21): Argon2 as `$UUID`, `I`, `M`
/// (KiB × 1024), `P`, `S`, `V` = 0x13 always (LD-17); AES-KDF as `$UUID`
/// (the older id), `R`, `S`. The salt or seed is written as given; a save
/// passes 32 fresh bytes (LD-15).
///
/// # Errors
/// `TooLarge(Header)` only for a salt over 4 GiB.
pub fn write_kdf(params: &KdfParams) -> Result<Vec<u8>, Error> {
    let e = |kind: u8, name: &[u8], value: Vec<u8>| MapEntry {
        kind,
        name: name.to_vec(),
        value,
    };
    let entries = match params {
        KdfParams::AesKdf { rounds, seed } => vec![
            e(BYTES, b"$UUID", AES_KDF_ID.to_vec()),
            e(UINT64, b"R", rounds.to_le_bytes().to_vec()),
            e(BYTES, b"S", seed.clone()),
        ],
        KdfParams::Argon2 {
            kind,
            iterations,
            memory_kib,
            lanes,
            salt,
            ..
        } => {
            let id = match kind {
                Argon2Type::D => ARGON2D_ID,
                Argon2Type::Id => ARGON2ID_ID,
            };
            let lanes = u32::try_from(*lanes).unwrap_or(u32::MAX);
            vec![
                e(BYTES, b"$UUID", id.to_vec()),
                e(UINT64, b"I", iterations.to_le_bytes().to_vec()),
                e(
                    UINT64,
                    b"M",
                    memory_kib.saturating_mul(1024).to_le_bytes().to_vec(),
                ),
                e(UINT32, b"P", lanes.to_le_bytes().to_vec()),
                e(BYTES, b"S", salt.clone()),
                e(UINT32, b"V", 0x13u32.to_le_bytes().to_vec()),
            ]
        }
    };
    write_map(&entries)
}
