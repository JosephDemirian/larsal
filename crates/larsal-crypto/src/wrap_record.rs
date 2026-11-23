//! The hybrid wrap record (story E25-S3, CRY-05.4 in place of CRY-04.6's
//! suite): a key sealed to a receiving key with [`pq`]'s one HPKE suite
//! `[25722, 1, 3]` (MLKEM768-X25519, HKDF-SHA256, ChaCha20-Poly1305) and
//! signed by its sender's composite identity key (CRY-05.5). It is the only
//! wrap record Larsal makes or opens (CRY-05.7): the key-file part wrap (P7),
//! group key wraps (P8) and the seal of `S_acct` for a new Mac all use it.
//!
//! Opening keeps CRY-04.6's order: (1) the suite, (2) the caller's info,
//! (3) the composite signature with the pinned identity key, (4) the hybrid
//! HPKE open. A record with any other suite, CRY-04.5's classical
//! `[32, 1, 2]` included, is refused at step 1, before any signature check:
//! there is no fallback, so a server cannot downgrade a wrap.
//!
//! Secrets (CRY-05.17): the receiving seed and the identity private key are
//! used only inside [`pq`]'s calls; the opened plaintext is only in the
//! returned [`SecretBytes`]. Nothing in a record is secret.

use crate::secret::SecretBytes;
use crate::{Error, pq, sign};

/// The one suite a record carries: KEM, KDF and AEAD ids (CRY-05.3, [`pq::SUITE`]).
pub const SUITE: [u16; 3] = pq::SUITE;
/// The label of a record's signature (CRY-04.2).
const LABEL: &[u8] = b"sync-wrap-v1";

/// A signed wrap record (CRY-04.6, CRY-05.4): an HPKE wrap and its sender's
/// composite signature over the field list (`sync-wrap-v1`, the suite as
/// three u16, enc, ct, info, signer id). Nothing in it is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapRecord {
    /// KEM, KDF and AEAD ids; [`open`] takes only [`SUITE`].
    pub suite: [u16; 3],
    /// The HPKE enc ([`pq::ENC`], 1,120 bytes).
    pub enc: Vec<u8>,
    /// The HPKE ciphertext: the plaintext plus a 16-byte tag.
    pub ct: Vec<u8>,
    /// The HPKE info: a field list naming the wrap's purpose and identities.
    pub info: Vec<u8>,
    /// The signer's 16-byte id.
    pub signer: [u8; 16],
    /// The composite signature ([`pq::SIGNATURE`], 3,373 bytes).
    pub signature: Vec<u8>,
}

/// The bytes a record's signature covers.
fn signed_part(
    suite: [u16; 3],
    enc: &[u8],
    ct: &[u8],
    info: &[u8],
    signer: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let [kem, kdf, aead] = suite.map(u16::to_be_bytes);
    sign::field_list(&[LABEL, &kem, &kdf, &aead, enc, ct, info, signer])
}

/// Seals `plaintext` to the receiving key `recipient` with `info`
/// ([`pq::seal`]) and signs the record with the signer's composite identity
/// private key ([`pq::composite_sign`]).
///
/// Guarantees: a receiving key that is not a valid 1,216-byte X-Wing key is
/// refused before any random draw, so nothing is sealed to it (CRY-05.8).
///
/// # Errors
/// Those of [`pq::seal`] (among them [`Error::KeyLength`] for a 32-byte
/// X25519 key) and of [`pq::composite_sign`]; nothing is returned.
pub fn make(
    recipient: &[u8],
    info: &[u8],
    plaintext: &[u8],
    signer: [u8; 16],
    identity: &SecretBytes,
) -> Result<WrapRecord, Error> {
    let (enc, ct) = pq::seal(recipient, info, plaintext)?;
    let signature = pq::composite_sign(identity, &signed_part(SUITE, &enc, &ct, info, &signer)?)?;
    Ok(WrapRecord {
        suite: SUITE,
        enc,
        ct,
        info: info.to_vec(),
        signer,
        signature,
    })
}

/// Opens a signed wrap record (CRY-05.4), in this order: (1) the suite is
/// [`SUITE`]; (2) the record's info equals `expected_info`, which the caller
/// builds for what it expects (never taken from the record); (3) the
/// composite signature verifies with `signer_public`, the 1,984-byte
/// identity key the caller pinned for the record's signer; (4) the hybrid
/// HPKE open ([`pq::open`]) with the receiving seed, where an enc that is not
/// 1,120 bytes is refused before any decapsulation.
///
/// Guarantees: no step runs before the steps above it passed; the plaintext
/// is only in the returned [`SecretBytes`].
///
/// # Errors
/// [`Error::WrapInvalid`] for every failure, with no detail.
pub fn open(
    record: &WrapRecord,
    signer_public: &[u8],
    expected_info: &[u8],
    seed: &SecretBytes,
) -> Result<SecretBytes, Error> {
    if record.suite != SUITE {
        return Err(Error::WrapInvalid);
    }
    if record.info.as_slice() != expected_info {
        return Err(Error::WrapInvalid);
    }
    let signed = signed_part(
        record.suite,
        &record.enc,
        &record.ct,
        &record.info,
        &record.signer,
    )
    .map_err(|_| Error::WrapInvalid)?;
    #[cfg(test)]
    probe::count();
    pq::composite_verify(signer_public, &signed, &record.signature)
        .map_err(|_| Error::WrapInvalid)?;
    pq::open(seed, &record.enc, expected_info, &record.ct).map_err(|_| Error::WrapInvalid)
}

/// Test-only: how many times [`open`] reached its signature check (step 3)
/// on this thread (CRY-05 T12).
#[cfg(test)]
mod probe {
    use core::cell::Cell;

    thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn count() {
        CALLS.with(|n| n.set(n.get().wrapping_add(1)));
    }

    /// Calls on this thread since the last `take`.
    pub(super) fn take() -> usize {
        CALLS.with(Cell::take)
    }
}

#[cfg(test)]
mod tests;
