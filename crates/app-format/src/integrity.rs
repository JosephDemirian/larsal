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
use crate::limits::{Limit, Limits};
use app_crypto::hash::{sha256, sha512};
use app_crypto::mac::{hmac_sha256, verify_hmac_sha256};
use app_crypto::secret::{SecretBytes, ct_eq};

/// Size of each data block App writes: 1 MiB (FMT-06.8).
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
        let (tag, after) = rest.split_first_chunk::<32>().ok_or(Error::Corrupt)?;
        let (size, after) = after.split_first_chunk::<4>().ok_or(Error::Corrupt)?;
        let n = usize::try_from(i32::from_le_bytes(*size)).map_err(|_| Error::Corrupt)?;
        if n > limits.block {
            return Err(Error::Corrupt);
        }
        let (data, after) = after.split_at_checked(n).ok_or(Error::Corrupt)?;
        let key = block_key(hmac_key, index);
        if !verify_hmac_sha256(key.expose(), &[&index.to_le_bytes(), size, data], tag) {
            return Err(Error::Corrupt);
        }
        if n == 0 {
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
/// Pass [`WRITE_BLOCK`] for what App writes.
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
