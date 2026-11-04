//! The hashed block stream of version 3 (FMT-07), inside the encryption,
//! after the 32 start bytes.
//!
//! Guarantees: the whole stream is checked up to its final block before any
//! byte of it is handed on (FMT-07.8); every size is checked against the
//! bytes left before anything is read (FMT-07.9); hashes are compared in
//! constant time; nothing after the final block is read, the padding
//! included (FMT-07.11, LD-01); every failure is `Corrupt` (FMT-07.12).

use crate::error::Error;
use crate::limits::Limits;
use larsal_crypto::hash::sha256;
use larsal_crypto::secret::ct_eq;

/// Walks the hashed block stream at the start of `stream` and returns the
/// data part of every block in order, as slices of `stream`: joined, they
/// are the document stream (FMT-07.6).
///
/// # Errors
/// `Corrupt` for a wrong index, a negative or oversized size, a cut, a hash
/// mismatch, a final block with a non-zero hash, a missing final block, or
/// no data block at all (FMT-07.3 to FMT-07.5, FMT-07.9, FMT-07.10, FMT-07.13).
pub fn read_hashed_blocks<'a>(stream: &'a [u8], limits: &Limits) -> Result<Vec<&'a [u8]>, Error> {
    let mut rest = stream;
    let mut out = Vec::new();
    for position in 0..=u32::MAX {
        let (index, after) = rest.split_first_chunk::<4>().ok_or(Error::Corrupt)?;
        let (hash, after) = after.split_first_chunk::<32>().ok_or(Error::Corrupt)?;
        let (size, after) = after.split_first_chunk::<4>().ok_or(Error::Corrupt)?;
        if u32::from_le_bytes(*index) != position {
            return Err(Error::Corrupt);
        }
        let n = usize::try_from(i32::from_le_bytes(*size)).map_err(|_| Error::Corrupt)?;
        if n > limits.block {
            return Err(Error::Corrupt);
        }
        let (data, after) = after.split_at_checked(n).ok_or(Error::Corrupt)?;
        if n == 0 {
            if hash.iter().any(|&b| b != 0) || out.is_empty() {
                return Err(Error::Corrupt);
            }
            return Ok(out);
        }
        if !ct_eq(sha256(&[data]).expose(), hash) {
            return Err(Error::Corrupt);
        }
        out.push(data);
        rest = after;
    }
    Err(Error::Corrupt) // the index would wrap (FMT-07 Edge cases)
}
