//! AES Key Wrap (RFC 3394) with a 256-bit key-encryption key and 32-byte key data,
//! for the folder key file (E23-S3, FIL-04.3). Never the padded variant, and not the
//! AES-GCM wrap of `wrap.rs`, which is another algorithm.
//!
//! Guarantees: an unwrapped key lives only in a [`SecretBytes`]; a failed integrity
//! check gives no key data; the AES key schedule wipes itself on drop (checked below)
//! and 32 KiB of stack below each call is zeroed after it. RFC 3394's intermediate
//! blocks live on that stack.

use crate::Error;
use crate::secret::{SecretBytes, scrubbed};
use aes_kw::{KeyInit, KwAes256};

/// Bytes of the key-encryption key.
pub const KEK: usize = 32;
/// Bytes of the key data.
pub const KEY: usize = 32;
/// Bytes of a wrapped key.
pub const WRAPPED: usize = 40;

/// Wraps the 32-byte `key` under the 32-byte `kek`.
///
/// # Errors
/// [`Error::KeyLength`] for any other length, before any work.
pub fn wrap(kek: &SecretBytes, key: &SecretBytes) -> Result<[u8; WRAPPED], Error> {
    if key.len() != KEY {
        return Err(Error::KeyLength);
    }
    let mut out = [0u8; WRAPPED];
    scrubbed(|| {
        let kw = KwAes256::new_from_slice(kek.expose()).map_err(|_| Error::KeyLength)?;
        kw.wrap_key(key.expose(), &mut out)
            .map(|_| ())
            .map_err(|_| Error::KeyLength)
    })?;
    Ok(out)
}

/// Unwraps 40 bytes under the 32-byte `kek`.
///
/// # Errors
/// [`Error::WrapInvalid`] for any other length of `wrapped` and for a failed integrity
/// check, with no key data; [`Error::KeyLength`] for a `kek` that is not 32 bytes.
pub fn unwrap(kek: &SecretBytes, wrapped: &[u8]) -> Result<SecretBytes, Error> {
    if wrapped.len() != WRAPPED {
        return Err(Error::WrapInvalid);
    }
    let mut key = SecretBytes::zeroed(KEY);
    scrubbed(|| {
        let kw = KwAes256::new_from_slice(kek.expose()).map_err(|_| Error::KeyLength)?;
        kw.unwrap_key(wrapped, key.expose_mut())
            .map(|_| ())
            .map_err(|_| Error::WrapInvalid)
    })?;
    Ok(key)
}

// Compile-time proof of "wipes itself on drop".
const _: () = {
    const fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<KwAes256>();
};
