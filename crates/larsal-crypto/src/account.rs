//! Account keys (story E25-S3, CRY-05.8, SYN-06.14): what a Mac draws at
//! sign-up, the receiving key's binding, the account blob's plaintext and
//! the pin compare. E17-S1 sends and stores them (`PUT /v1/account/keys`);
//! nothing here talks to a server.
//!
//! - `S_acct`, the account secret: 32 bytes from larsal-crypto's random source.
//! - The identity key: CRY-05.5's composite ML-DSA-65 + Ed25519 key, private
//!   64 bytes, public ([`AccountKeys::identity_public_key`]) 1,984 bytes.
//! - The receiving key: an X-Wing key (CRY-05.2), a 32-byte seed, public
//!   ([`AccountKeys::kem_public_key`]) 1,216 bytes.
//! - The binding ([`AccountKeys::kem_signature`]): the composite signature
//!   over the field list (`sync-kem-key-v1`, `account_id`, the receiving
//!   public key), 3,373 bytes; it replaces `sync-x25519-v1`.
//! - The blob's plaintext ([`AccountKeys::blob_plaintext`]): the identity
//!   private key then the receiving seed, 96 bytes.
//!
//! Secrets (CRY-05.17): `S_acct`, both private keys and the blob's plaintext
//! are only in [`SecretBytes`], wiped on drop; `Debug` prints `[hidden]`.

use crate::secret::{SecretBytes, ct_eq};
use crate::{Error, pq, random, sign};
use core::fmt;

/// `S_acct`, in bytes (SYN-06.1).
pub const ACCOUNT_SECRET: usize = 32;
/// The blob's plaintext: identity private key (64) ‖ receiving seed (32).
pub const BLOB_PLAINTEXT: usize = 96;
/// The label of the receiving key's binding (CRY-04.2, CRY-05.8).
const KEM_LABEL: &[u8] = b"sync-kem-key-v1";

/// One account's keys (CRY-05.8): `S_acct`, the composite identity key and
/// the X-Wing receiving key, with their public keys.
pub struct AccountKeys {
    account_secret: SecretBytes,
    identity_private_key: SecretBytes,
    identity_public_key: Vec<u8>,
    kem_seed: SecretBytes,
    kem_public_key: Vec<u8>,
}

impl AccountKeys {
    /// Draws a new account's keys at sign-up: `S_acct` (32 bytes), the
    /// composite identity key (64) and the receiving seed (32), in that
    /// order, from larsal-crypto's random source.
    ///
    /// Guarantees: a failing source fails closed: nothing is returned.
    ///
    /// # Errors
    /// [`Error::RandomSource`] if the random source fails or the system
    /// cannot start a call's worker thread.
    pub fn new() -> Result<Self, Error> {
        Self::new_with(random::bytes)
    }

    fn new_with(mut draw: impl FnMut(usize) -> Result<SecretBytes, Error>) -> Result<Self, Error> {
        let account_secret = draw(ACCOUNT_SECRET)?;
        let identity_private_key = draw(pq::IDENTITY_PRIVATE)?;
        let kem_seed = draw(pq::SEED)?;
        Self::from_secrets(account_secret, identity_private_key, kem_seed)
            .map_err(|_| Error::RandomSource)
    }

    /// The keys of an account restored from `S_acct` and the blob's 96-byte
    /// plaintext ([`AccountKeys::blob_plaintext`]); the public keys come
    /// from the seeds.
    ///
    /// # Errors
    /// [`Error::KeyLength`] when `S_acct` is not 32 bytes or the plaintext not
    /// 96; [`Error::RandomSource`] when the system cannot start a call's
    /// worker thread.
    pub fn from_blob(
        account_secret: SecretBytes,
        blob_plaintext: &SecretBytes,
    ) -> Result<Self, Error> {
        let (identity, seed) = blob_plaintext
            .expose()
            .split_at_checked(pq::IDENTITY_PRIVATE)
            .ok_or(Error::KeyLength)?;
        Self::from_secrets(
            account_secret,
            SecretBytes::new(identity.to_vec()),
            SecretBytes::new(seed.to_vec()),
        )
    }

    fn from_secrets(
        account_secret: SecretBytes,
        identity_private_key: SecretBytes,
        kem_seed: SecretBytes,
    ) -> Result<Self, Error> {
        if account_secret.len() != ACCOUNT_SECRET {
            return Err(Error::KeyLength);
        }
        let identity_public_key = pq::identity_public(&identity_private_key)?;
        let kem_public_key = pq::xwing_public(&kem_seed)?;
        Ok(Self {
            account_secret,
            identity_private_key,
            identity_public_key,
            kem_seed,
            kem_public_key,
        })
    }

    /// `S_acct` (32 bytes).
    #[must_use]
    pub fn account_secret(&self) -> &SecretBytes {
        &self.account_secret
    }

    /// The composite identity private key (64 bytes), for
    /// [`crate::wrap_record::make`] and the account's other signatures.
    #[must_use]
    pub fn identity_private_key(&self) -> &SecretBytes {
        &self.identity_private_key
    }

    /// The composite identity public key (1,984 bytes).
    #[must_use]
    pub fn identity_public_key(&self) -> &[u8] {
        &self.identity_public_key
    }

    /// The X-Wing receiving seed (32 bytes), for [`crate::wrap_record::open`].
    #[must_use]
    pub fn kem_seed(&self) -> &SecretBytes {
        &self.kem_seed
    }

    /// The X-Wing receiving public key (1,216 bytes).
    #[must_use]
    pub fn kem_public_key(&self) -> &[u8] {
        &self.kem_public_key
    }

    /// The receiving key's binding (CRY-05.8): the composite signature over
    /// the field list (`sync-kem-key-v1`, `account_id`, the receiving public
    /// key), 3,373 bytes.
    ///
    /// # Errors
    /// Those of [`pq::composite_sign`].
    pub fn kem_signature(&self, account_id: &[u8; 16]) -> Result<Vec<u8>, Error> {
        pq::composite_sign(
            &self.identity_private_key,
            &binding(account_id, &self.kem_public_key)?,
        )
    }

    /// The account blob's plaintext (CRY-05.8): the identity private key (64
    /// bytes) then the receiving seed (32), 96 bytes, version 1.
    #[must_use]
    pub fn blob_plaintext(&self) -> SecretBytes {
        let mut out = SecretBytes::zeroed(BLOB_PLAINTEXT);
        let (identity, seed) = out.expose_mut().split_at_mut(pq::IDENTITY_PRIVATE);
        identity.copy_from_slice(self.identity_private_key.expose());
        seed.copy_from_slice(self.kem_seed.expose());
        out
    }
}

impl fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[hidden]")
    }
}

/// The bytes a binding covers.
fn binding(account_id: &[u8; 16], kem_public_key: &[u8]) -> Result<Vec<u8>, Error> {
    sign::field_list(&[KEM_LABEL, account_id, kem_public_key])
}

/// Checks another account's receiving key binding (CRY-05.8, CRY-05.7): the
/// receiving key passes [`pq::seal`]'s key check (1,216 bytes, and FIPS 203
/// section 7.2's type and modulus check on its ML-KEM part), then
/// `kem_signature` is a composite signature by `identity_public_key` over
/// (`sync-kem-key-v1`, `account_id`, `kem_public_key`).
///
/// Guarantees: a 32-byte X25519 receiving key, and a 1,216-byte one with an
/// ML-KEM coefficient of 3,329 or more, are refused before any signature
/// check (CRY-05's edge cases); an Ed25519-only binding and a binding over
/// `sync-x25519-v1` are refused.
///
/// # Errors
/// [`Error::SignatureInvalid`] for every failure, with no detail.
pub fn check_kem_binding(
    identity_public_key: &[u8],
    account_id: &[u8; 16],
    kem_public_key: &[u8],
    kem_signature: &[u8],
) -> Result<(), Error> {
    pq::receiving_key(kem_public_key).map_err(|_| Error::SignatureInvalid)?;
    let signed = binding(account_id, kem_public_key).map_err(|_| Error::SignatureInvalid)?;
    pq::composite_verify(identity_public_key, &signed, kem_signature)
}

/// True when an account's keys equal its pin (CRY-05.8, SYN-06.6,
/// SHR-02.11): the whole 1,984-byte identity key and the whole 1,216-byte
/// receiving key, each compared in constant time (CRY-04.11), and the
/// receiving key passes [`pq::seal`]'s key check.
///
/// Guarantees: a pin of any other size, or a receiving key that fails FIPS
/// 203's check, never matches; the compare does not stop at the first
/// differing byte.
#[must_use]
pub fn pins_match(
    pinned_identity: &[u8],
    pinned_kem: &[u8],
    identity_public_key: &[u8],
    kem_public_key: &[u8],
) -> bool {
    let sizes =
        (pinned_identity.len() == pq::IDENTITY_PUBLIC) & (pinned_kem.len() == pq::PUBLIC_KEY);
    let key = pq::receiving_key(kem_public_key).is_ok();
    sizes & key & ct_eq(pinned_identity, identity_public_key) & ct_eq(pinned_kem, kem_public_key)
}

#[cfg(test)]
mod tests;
