//! SHA-256, SHA-512 and SHA-1 (story E2-S3), one-shot and streaming.
//!
//! - Every digest comes back as [`SecretBytes`], because many are keys or
//!   key parts (spec FMT-04: `P`, `C`, `K_enc`, `K_mac`; FMT-18: the key file
//!   part `F`). A public digest (the header hash, FMT-05.3) is read with
//!   [`SecretBytes::expose`].
//! - One-shot functions take a list of parts hashed as if joined, so a caller
//!   never builds an unwiped joined copy of secret inputs (`S || T`).
//! - [`Hasher`] takes the input piece by piece, for large inputs such as key
//!   files (FMT-18.5); the result equals the one-shot digest of all pieces.
//! - SHA-1 is here only for formats and standards that demand it.
//! - The hash state inside the crates is wiped on drop (their `zeroize`
//!   feature). The state lives on the heap and is finished in place; after
//!   `update` and `finalize` a fixed 32 KiB of stack below the call is zeroed
//!   (best effort), which covers the input and digest copies the crates leave.

use crate::secret::{SecretBytes, scrubbed};
use sha2::Digest;
use zeroize::Zeroize;

/// A hash function this module offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA-1 (FIPS 180-4), 20-byte digest. Only where a format demands it.
    Sha1,
    /// SHA-256 (FIPS 180-4), 32-byte digest.
    Sha256,
    /// SHA-512 (FIPS 180-4), 64-byte digest.
    Sha512,
}

/// A streaming hash: feed it pieces with [`Hasher::update`], then
/// [`Hasher::finalize`].
///
/// Guarantees: the digest equals the one-shot digest of all pieces joined in
/// order, however the input was split. No `Clone`, no `Debug`; the state is
/// wiped when the value is dropped or finalized.
///
/// Rustdoc on stable does not check the error codes below, so this example
/// shows the same setup compiles; each failing example then fails only on
/// its last line.
/// ```
/// use larsal_crypto::hash::{Algorithm, Hasher, sha256};
/// let mut h = Hasher::new(Algorithm::Sha256);
/// h.update(b"abc");
/// assert_eq!(h.finalize(), sha256(&[b"abc"]));
/// ```
/// No `Clone`, so no copy of the state escapes the wipe:
/// ```compile_fail,E0599
/// use larsal_crypto::hash::{Algorithm, Hasher};
/// let h = Hasher::new(Algorithm::Sha256);
/// let _copy = h.clone();
/// ```
/// No `Debug`, so the state never reaches a log:
/// ```compile_fail,E0277
/// use larsal_crypto::hash::{Algorithm, Hasher};
/// let h = Hasher::new(Algorithm::Sha256);
/// println!("{h:?}");
/// ```
pub struct Hasher(Box<State>);

// Compile-time proof of "wiped when dropped": each state type must wipe
// itself on drop, so removing a crate's `zeroize` feature breaks the build.
const _: () = {
    const fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<sha1::Sha1>();
    wiped_on_drop::<sha2::Sha256>();
    wiped_on_drop::<sha2::Sha512>();
};

enum State {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

impl Hasher {
    /// Starts an empty hash with the chosen algorithm.
    #[must_use]
    pub fn new(algorithm: Algorithm) -> Self {
        Self(Box::new(match algorithm {
            Algorithm::Sha1 => State::Sha1(sha1::Sha1::new()),
            Algorithm::Sha256 => State::Sha256(sha2::Sha256::new()),
            Algorithm::Sha512 => State::Sha512(sha2::Sha512::new()),
        }))
    }

    /// Adds the next piece of input. Any size, including empty.
    pub fn update(&mut self, data: &[u8]) {
        scrubbed(|| match self.0.as_mut() {
            State::Sha1(h) => h.update(data),
            State::Sha256(h) => h.update(data),
            State::Sha512(h) => h.update(data),
        });
    }

    /// Ends the hash and returns the digest: 20, 32 or 64 bytes for SHA-1,
    /// SHA-256 or SHA-512.
    #[must_use]
    pub fn finalize(mut self) -> SecretBytes {
        scrubbed(|| match self.0.as_mut() {
            State::Sha1(h) => finish(h),
            State::Sha256(h) => finish(h),
            State::Sha512(h) => finish(h),
        })
    }
}

/// SHA-256 of `parts` joined in order. Always 32 bytes.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> SecretBytes {
    digest(Algorithm::Sha256, parts)
}

/// SHA-512 of `parts` joined in order. Always 64 bytes.
#[must_use]
pub fn sha512(parts: &[&[u8]]) -> SecretBytes {
    digest(Algorithm::Sha512, parts)
}

/// SHA-1 of `parts` joined in order. Always 20 bytes. Use only where a
/// format or standard demands SHA-1.
#[must_use]
pub fn sha1(parts: &[&[u8]]) -> SecretBytes {
    digest(Algorithm::Sha1, parts)
}

fn digest(algorithm: Algorithm, parts: &[&[u8]]) -> SecretBytes {
    let mut h = Hasher::new(algorithm);
    for part in parts {
        h.update(part);
    }
    h.finalize()
}

// In place, so the state stays in the box and is wiped when the box drops.
fn finish<D: Digest + sha2::digest::FixedOutputReset>(h: &mut D) -> SecretBytes {
    let mut out = Digest::finalize_reset(h);
    let digest = SecretBytes::new(out.to_vec());
    out.zeroize();
    digest
}
