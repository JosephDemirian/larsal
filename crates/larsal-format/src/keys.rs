//! The key flow of FMT-04: credential parts, composite key, and the final
//! keys of version 4.
//!
//! Guarantees: every part and key lives only in [`SecretBytes`] (FMT-04.19);
//! where this crate holds one (the parts, `C`, `T`, `K_enc`, `K_mac` and the
//! stream key) it is a [`LockedKey`], whose pages stay out of swap for as
//! long as it lives (APP-11.9); the password is hashed exactly as given,
//! with no normalization or trimming (FMT-04.1); parts are always joined as
//! password, key file, hardware key (FMT-04.4); an absent part adds no
//! bytes (FMT-04.5, FMT-04.6).

use crate::error::{Error, HardwareKeyReason};
use crate::keyfile::KeyFileKey;
use larsal_crypto::hash::{sha256, sha512};
use larsal_crypto::kdf::KdfParams;
#[cfg(any(test, feature = "software-key"))]
use larsal_crypto::mac::hmac_sha1;
use larsal_crypto::secret::{SecretBytes, SecretString};

/// Key material held by this crate (APP-11.9, SR-07, AT-C05): a
/// [`SecretBytes`] whose heap pages are locked in RAM (`mlock`, through
/// `larsal_platform::memory::lock`) from creation until it is dropped. On drop
/// the bytes are wiped and freed first, then the pages are unlocked, so the
/// key is never in a page that may be swapped. When the kernel refuses the
/// lock (its memory lock limit), Larsal goes on with the key unlocked after one
/// warning (M11-01). Reads go through [`Deref`](core::ops::Deref) to the
/// `SecretBytes`; moving it moves no key byte.
pub struct LockedKey {
    // Declaration order is drop order: wipe and free the key, then unlock.
    key: SecretBytes,
    #[cfg(target_os = "macos")]
    pages: Option<larsal_platform::memory::Locked>,
}

impl LockedKey {
    /// Locks the pages under `key` and keeps them locked while it lives.
    #[must_use]
    pub fn new(key: SecretBytes) -> Self {
        Self {
            #[cfg(target_os = "macos")]
            pages: larsal_platform::memory::lock(key.expose()),
            key,
        }
    }

    /// True when the pages under the key are locked (the test hook of
    /// APP-11.9-b). False for an empty key or when the kernel refused.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        #[cfg(target_os = "macos")]
        return self.pages.is_some();
        #[cfg(not(target_os = "macos"))]
        return false;
    }
}

impl core::ops::Deref for LockedKey {
    type Target = SecretBytes;

    fn deref(&self) -> &SecretBytes {
        &self.key
    }
}

impl core::fmt::Debug for LockedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[hidden]")
    }
}

/// A hardware key slot programmed for HMAC-SHA1 challenge-response
/// (FMT-04.8 to FMT-04.10; the device side is INT-07 and E10).
pub trait ChallengeResponse {
    /// Sends the 64-byte padded challenge and returns the slot's answer,
    /// which must be 20 bytes. A device problem is a [`HardwareKeyReason`].
    ///
    /// # Errors
    /// The reason the device failed; never a wrong-key result.
    fn challenge(&self, padded: &[u8; 64]) -> Result<SecretBytes, HardwareKeyReason>;
}

/// How a slot hashes the padded challenge (FMT-04 Edge cases, INT-07).
/// Tests only, with [`SoftwareKey`] (INT-07.29).
#[cfg(any(test, feature = "software-key"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotMode {
    /// Drops the trailing bytes equal to the last byte, then hashes the
    /// rest. The reference's own test data uses this mode.
    Variable,
    /// Hashes all 64 bytes.
    Fixed,
}

/// A software stand-in for a hardware key: HMAC-SHA1 with a demo secret,
/// for tests and for INT-07's checks (OD-01: no physical key yet). Built
/// only into tests: the `software-key` feature, never on in a product build
/// (INT-07.29).
#[cfg(any(test, feature = "software-key"))]
#[derive(Debug)]
pub struct SoftwareKey {
    /// The slot's HMAC-SHA1 secret.
    pub secret: SecretBytes,
    /// How the slot treats the challenge.
    pub mode: SlotMode,
}

#[cfg(any(test, feature = "software-key"))]
impl ChallengeResponse for SoftwareKey {
    fn challenge(&self, padded: &[u8; 64]) -> Result<SecretBytes, HardwareKeyReason> {
        let msg = match self.mode {
            SlotMode::Fixed => padded.as_slice(),
            SlotMode::Variable => {
                let last = padded.last().copied().unwrap_or(0);
                let keep = padded
                    .iter()
                    .rposition(|&b| b != last)
                    .map_or(0, |i| i.saturating_add(1));
                padded.get(..keep).unwrap_or(&[])
            }
        };
        hmac_sha1(self.secret.expose(), &[msg]).map_err(|_| HardwareKeyReason::Failed)
    }
}

/// The credentials of one open. At least one part must be present
/// (FMT-04.16). The key file is given as its read result (`F`), because
/// key files are read as a stream (FMT-18.5) and `F` is what a save keeps
/// (FMT-04.17).
#[derive(Clone, Copy, Default)]
pub struct Credentials<'a> {
    /// The password, exactly as typed. `Some` of an empty text is the empty
    /// password, which differs from `None` (FMT-04.2).
    pub password: Option<&'a SecretString>,
    /// The key file component from [`crate::keyfile::read_key_file`].
    pub key_file: Option<&'a KeyFileKey>,
    /// A hardware key slot.
    pub hardware_key: Option<&'a dyn ChallengeResponse>,
}

impl core::fmt::Debug for Credentials<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[hidden]")
    }
}

impl Credentials<'_> {
    /// True when no part at all is present: the open or save is refused
    /// with `NoCredentials` before any key work (FMT-04.16, LD-13).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.key_file.is_none() && self.hardware_key.is_none()
    }
}

/// `P = SHA256(UTF-8 bytes of the password)` (FMT-04.1).
#[must_use]
pub fn password_part(password: &SecretString) -> SecretBytes {
    sha256(&[password.expose().as_bytes()])
}

/// The 64-byte challenge for a seed of `n` bytes: the seed, then `64 - n`
/// bytes each holding `64 - n` (FMT-04.9).
///
/// # Errors
/// `Unsupported` for a seed longer than 64 bytes (the KDF map allows 8 to 32).
pub fn padded_challenge(seed: &[u8]) -> Result<[u8; 64], Error> {
    let pad = u8::try_from(64usize.checked_sub(seed.len()).ok_or(Error::Unsupported)?)
        .map_err(|_| Error::Unsupported)?;
    let mut out = [pad; 64];
    out.get_mut(..seed.len())
        .ok_or(Error::Unsupported)?
        .copy_from_slice(seed);
    Ok(out)
}

/// Asks the hardware key with the padded `seed` and returns
/// `R = SHA256(answer)` (FMT-04.6, FMT-04.8 to FMT-04.10). Version 4 passes
/// the KDF seed.
///
/// # Errors
/// `HardwareKey` with the device's reason, or `BadAnswer` when the answer is
/// not 20 bytes; never `WrongKey`.
pub fn hardware_part(key: &dyn ChallengeResponse, seed: &[u8]) -> Result<SecretBytes, Error> {
    let answer = key
        .challenge(&padded_challenge(seed)?)
        .map_err(Error::HardwareKey)?;
    if answer.len() != 20 {
        return Err(Error::HardwareKey(HardwareKeyReason::BadAnswer));
    }
    Ok(sha256(&[answer.expose()]))
}

/// `C = SHA256([P] || [F] || [R])`: the present parts in this order
/// (FMT-04.5). Pass `None` for an absent part.
#[must_use]
pub fn composite_key(
    password: Option<&SecretBytes>,
    key_file: Option<&SecretBytes>,
    hardware: Option<&SecretBytes>,
) -> SecretBytes {
    let parts: Vec<&[u8]> = [password, key_file, hardware]
        .into_iter()
        .flatten()
        .map(SecretBytes::expose)
        .collect();
    sha256(&parts)
}

/// The two final keys of a version 4 file (FMT-04.13, FMT-04.14), each
/// in locked pages.
#[derive(Debug)]
pub struct FinalKeys {
    /// `K_enc = SHA256(S || T)`: the 32-byte payload cipher key.
    pub cipher_key: LockedKey,
    /// `K_mac = SHA512(S || T || 01)`: the 64-byte HMAC base key.
    pub hmac_key: LockedKey,
}

/// Mixes the transformed key `T` with the master seed `S` (FMT-04.13, FMT-04.14).
#[must_use]
pub fn final_keys(master_seed: &[u8], transformed: &SecretBytes) -> FinalKeys {
    FinalKeys {
        cipher_key: LockedKey::new(sha256(&[master_seed, transformed.expose()])),
        hmac_key: LockedKey::new(sha512(&[master_seed, transformed.expose(), &[1]])),
    }
}

/// The version 3 cipher key `K_enc = SHA256(S || [R3] || T)`, where `R3` is
/// the hardware key part asked with the master seed (FMT-04.15, FMT-17.9).
/// Version 3 has no HMAC key.
#[must_use]
pub fn cipher_key_v3(
    master_seed: &[u8],
    hardware: Option<&SecretBytes>,
    transformed: &SecretBytes,
) -> SecretBytes {
    let r3 = hardware.map_or(&[][..], SecretBytes::expose);
    sha256(&[master_seed, r3, transformed.expose()])
}

/// The transformed key `T` of the last open or successful save of a vault,
/// held in wiped memory only so the next save can check that its new `T`
/// differs (CRY-03.16), in locked pages for as long as the vault stays
/// unlocked, with the KDF settings and seed it was made with. Its bytes
/// never leave this crate: a retired-key record (MOD-11.31) gets only
/// [`TransformedKey::salted_digest`].
pub struct TransformedKey {
    pub(crate) key: LockedKey,
    pub(crate) kdf: KdfParams,
    pub(crate) v4: bool,
}

impl core::fmt::Debug for TransformedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TransformedKey([hidden])")
    }
}

impl TransformedKey {
    /// True when `t` equals this key, compared in constant time (Rust rule 6).
    #[must_use]
    pub(crate) fn same_as(&self, t: &SecretBytes) -> bool {
        larsal_crypto::secret::ct_eq(self.key.expose(), t.expose())
    }

    /// The KDF settings and seed `T` was made with (public header values,
    /// FMT-03).
    #[must_use]
    pub fn kdf(&self) -> &KdfParams {
        &self.kdf
    }

    /// True when a version 4 open or save made `T`: the hardware key part,
    /// asked with the KDF seed, is in it (FMT-04.6); version 3 keeps that
    /// part out of `T` (FMT-04.15).
    #[must_use]
    pub fn v4(&self) -> bool {
        self.v4
    }

    /// `SHA-256(salt || T)` for a retired-key record (MOD-11.31, LD-269
    /// (2)). With a fresh salt, never the file's master seed, it equals
    /// neither `K_enc = SHA-256(S || T)` nor `K_mac` (FMT-04.13, FMT-04.14),
    /// and `T` cannot be read back from it.
    #[must_use]
    pub fn salted_digest(&self, salt: &[u8]) -> [u8; 32] {
        <[u8; 32]>::try_from(sha256(&[salt, self.key.expose()]).expose()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// APP-11.9-b: every holder of key material in this crate locks it.
    #[test]
    fn app11_9_held_keys_are_in_locked_pages() {
        let t = SecretBytes::new(vec![7; 32]);
        let k = final_keys(&[1; 32], &t);
        assert!(
            k.cipher_key.is_locked() && k.hmac_key.is_locked(),
            "K_enc, K_mac"
        );
        let t = TransformedKey {
            key: LockedKey::new(t),
            kdf: KdfParams::AesKdf {
                rounds: 1,
                seed: vec![0; 32],
            },
            v4: true,
        };
        assert!(t.key.is_locked(), "T");
        // An inner header: stream id 3, a 64-byte stream key, the end field.
        let mut u = vec![1, 4, 0, 0, 0, 3, 0, 0, 0, 2, 64, 0, 0, 0];
        u.extend([9; 64]);
        u.extend([0, 0, 0, 0, 0]);
        let inner = crate::inner::read_inner(&u, &crate::limits::Limits::DEFAULT).unwrap();
        assert!(inner.stream_key.is_locked(), "stream key");
        let f = crate::keyfile::read_key_file(
            std::io::Cursor::new([5u8; 32]),
            &crate::limits::Limits::DEFAULT,
        )
        .unwrap();
        assert!(f.key.is_locked(), "F");
        assert!(
            !LockedKey::new(SecretBytes::new(Vec::new())).is_locked(),
            "nothing to lock"
        );
    }
}
