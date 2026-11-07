//! ChaCha20-Poly1305 (RFC 8439) in place, for the file format (E22-S3,
//! FIL-01.19). No arrangement: the caller says the key, the nonce and the
//! associated data; this file says nothing of chunks or counters.
//!
//! Guarantees: the data stays in the caller's buffer, so a plaintext lives
//! only where the caller put it; an open checks the tag first and leaves the
//! buffer unchanged when it fails; the crate's key state wipes itself on drop
//! (its `zeroize` feature, checked below) and 32 KiB of stack below each call
//! is zeroed after it.

use crate::Error;
use crate::secret::{SecretBytes, scrubbed};
use chacha20poly1305::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

/// Bytes of a key.
pub const KEY: usize = 32;
/// Bytes of a nonce.
pub const NONCE: usize = 12;
/// Bytes of a tag.
pub const TAG: usize = 16;

/// Encrypts `data` in place under `key` and `nonce`, and returns its tag.
/// A nonce must never repeat under one key; the caller holds that rule.
///
/// # Errors
/// [`Error::KeyLength`] for a key that is not 32 bytes, before any work;
/// [`Error::TooLarge`] for data over the limit of RFC 8439 (about 256 GiB).
pub fn seal_in_place(
    key: &SecretBytes,
    nonce: &[u8; NONCE],
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; TAG], Error> {
    scrubbed(|| {
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| Error::KeyLength)?;
        let tag = cipher
            .encrypt_inout_detached(nonce.into(), aad, data.into())
            .map_err(|_| Error::TooLarge)?;
        Ok(tag.into())
    })
}

/// Checks `tag` over `data` and, only if it holds, decrypts `data` in place.
///
/// # Errors
/// [`Error::Decrypt`] for any change of the key, nonce, associated data,
/// ciphertext or tag, with `data` unchanged; [`Error::KeyLength`] for a key
/// that is not 32 bytes, before any work.
pub fn open_in_place(
    key: &SecretBytes,
    nonce: &[u8; NONCE],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG],
) -> Result<(), Error> {
    scrubbed(|| {
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| Error::KeyLength)?;
        cipher
            .decrypt_inout_detached(nonce.into(), aad, data.into(), tag.into())
            .map_err(|_| Error::Decrypt)
    })
}

// Compile-time proof of "wipes itself on drop": turning off the crate's
// `zeroize` feature breaks the build here.
const _: () = {
    const fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<ChaCha20Poly1305>();
};
