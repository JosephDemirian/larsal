//! Keystreams for protected fields (story E2-S6; spec FMT-09, CRY-01.14,
//! CRY-01.15): ChaCha20 for version 4, Salsa20 for reading version 3.
//!
//! One [`FieldStream`] serves a whole document. Each call XORs the next
//! keystream bytes onto the data, so values of any length, in any number of
//! calls, use one continuous keystream from byte 0 (FMT-09.11, CRY-01.7).
//! [`FieldStream::chacha20_from_stream_key`] and
//! [`FieldStream::salsa20_from_stream_key`] derive the key and nonce from the
//! inner header's stream key (FMT-09.9, FMT-09.10).
//!
//! Guarantees:
//! - A key that is not 32 bytes, or a nonce of the wrong length, is refused
//!   before any work.
//! - The keystream never wraps around: past the limit every call fails with
//!   [`Error::StreamLimit`] and leaves the data unchanged. ChaCha20 covers
//!   2^32 - 1 blocks of 64 bytes, Salsa20 2^64 - 1.
//! - The cipher state and the buffered rest of a keystream block are wiped
//!   on drop (the crates' `zeroize` features). The state lives on the heap,
//!   so moving a [`FieldStream`] copies only a pointer, and every public call
//!   zeroes a fixed 32 KiB of stack below it afterwards (best effort). The
//!   data is changed in place, so no other copy of a value is made.

use crate::error::Error;
use crate::hash;
use crate::secret::{SecretBytes, scrubbed};
use chacha20::cipher::{KeyIvInit, StreamCipher};

/// Key length of both field stream ciphers, in bytes.
pub const KEY_LEN: usize = 32;

/// ChaCha20 nonce length, in bytes.
pub const CHACHA20_NONCE_LEN: usize = 12;

/// Salsa20 nonce length, in bytes.
pub const SALSA20_NONCE_LEN: usize = 8;

/// The fixed Salsa20 nonce of version 3 field streams (FMT-09.10).
pub const SALSA20_FIELD_NONCE: [u8; SALSA20_NONCE_LEN] =
    [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

/// A protected-field keystream, positioned at the next unused byte.
pub struct FieldStream(Kind);

enum Kind {
    ChaCha20(Box<chacha20::ChaCha20>),
    Salsa20(Box<salsa20::Salsa20>),
}

impl FieldStream {
    /// ChaCha20 with the RFC 8439 block function, a 32-byte key, a 12-byte
    /// nonce and a 32-bit block counter that starts at 0 (FMT-09.9).
    ///
    /// # Errors
    /// [`Error::KeyLength`], then [`Error::IvLength`] for a nonce that is not
    /// 12 bytes.
    pub fn chacha20(key: &SecretBytes, nonce: &[u8]) -> Result<Self, Error> {
        scrubbed(|| init(key, nonce, CHACHA20_NONCE_LEN).map(|c| Self(Kind::ChaCha20(Box::new(c)))))
    }

    /// Salsa20/20 with a 32-byte key, an 8-byte nonce and a 64-bit block
    /// counter that starts at 0, as in Bernstein's specification (FMT-09.10).
    ///
    /// # Errors
    /// [`Error::KeyLength`], then [`Error::IvLength`] for a nonce that is not
    /// 8 bytes.
    pub fn salsa20(key: &SecretBytes, nonce: &[u8]) -> Result<Self, Error> {
        scrubbed(|| init(key, nonce, SALSA20_NONCE_LEN).map(|c| Self(Kind::Salsa20(Box::new(c)))))
    }

    /// The version 4 field stream: ChaCha20 with key = SHA-512(stream key)
    /// bytes 0 to 31 and nonce = bytes 32 to 43 (FMT-09.9, CRY-01.14).
    ///
    /// # Errors
    /// None in practice; the lengths are fixed by the hash.
    pub fn chacha20_from_stream_key(stream_key: &SecretBytes) -> Result<Self, Error> {
        scrubbed(|| {
            let h = hash::sha512(&[stream_key.expose()]);
            let (key, rest) = h
                .expose()
                .split_at_checked(KEY_LEN)
                .ok_or(Error::KeyLength)?;
            let nonce = rest.get(..CHACHA20_NONCE_LEN).ok_or(Error::IvLength)?;
            Self::chacha20(&SecretBytes::new(key.to_vec()), nonce)
        })
    }

    /// The version 3 field stream: Salsa20 with key = SHA-256(stream key) and
    /// the fixed nonce [`SALSA20_FIELD_NONCE`] (FMT-09.10, CRY-01.15).
    ///
    /// # Errors
    /// None in practice; the lengths are fixed.
    pub fn salsa20_from_stream_key(stream_key: &SecretBytes) -> Result<Self, Error> {
        scrubbed(|| Self::salsa20(&hash::sha256(&[stream_key.expose()]), &SALSA20_FIELD_NONCE))
    }

    /// XORs the next `data.len()` keystream bytes onto `data`, in place. The
    /// same call encrypts and decrypts.
    ///
    /// # Errors
    /// [`Error::StreamLimit`] if the keystream would pass its limit; `data`
    /// and the position are left unchanged.
    pub fn apply(&mut self, data: &mut [u8]) -> Result<(), Error> {
        scrubbed(|| {
            match &mut self.0 {
                Kind::ChaCha20(c) => c.try_apply_keystream(data),
                Kind::Salsa20(c) => c.try_apply_keystream(data),
            }
            .map_err(|_| Error::StreamLimit)
        })
    }
}

fn init<T: KeyIvInit>(key: &SecretBytes, nonce: &[u8], nonce_len: usize) -> Result<T, Error> {
    if key.len() != KEY_LEN {
        return Err(Error::KeyLength);
    }
    if nonce.len() != nonce_len {
        return Err(Error::IvLength);
    }
    T::new_from_slices(key.expose(), nonce).map_err(|_| Error::KeyLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::cipher::StreamCipherSeek;

    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}

    // Compile-time proof: both cipher states wipe themselves on drop.
    #[test]
    fn state_is_wiped_on_drop() {
        let key = SecretBytes::new(vec![1; KEY_LEN]);
        let streams = [
            FieldStream::chacha20(&key, &[0; CHACHA20_NONCE_LEN]).unwrap(),
            FieldStream::salsa20(&key, &[0; SALSA20_NONCE_LEN]).unwrap(),
        ];
        for s in &streams {
            match &s.0 {
                Kind::ChaCha20(c) => wipes(c.as_ref()),
                Kind::Salsa20(c) => wipes(c.as_ref()),
            }
        }
    }

    // CRY-01.13 for the field stream: no wrap-around past the last block.
    #[test]
    fn chacha20_field_stream_stops_at_the_block_limit() {
        let key = SecretBytes::new(vec![9; KEY_LEN]);
        let mut s = FieldStream::chacha20(&key, &[0; CHACHA20_NONCE_LEN]).unwrap();
        if let Kind::ChaCha20(c) = &mut s.0 {
            c.seek(u64::from(u32::MAX - 1) * 64 + 60);
        }
        let mut data = [0u8; 5];
        assert_eq!(s.apply(&mut data), Err(Error::StreamLimit));
        assert_eq!(data, [0; 5], "data unchanged after the refusal");
        let mut four = [0u8; 4];
        assert_eq!(s.apply(&mut four), Ok(()));
        assert_ne!(four, [0; 4]);
        assert_eq!(s.apply(&mut [0u8; 1]), Err(Error::StreamLimit));
    }
}
