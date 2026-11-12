//! Post-quantum building blocks (story E25-S2, CRY-05): the hybrid KEM
//! MLKEM768-X25519 (X-Wing) under one HPKE suite, and the composite
//! signature ML-DSA-65 + Ed25519 of RFC 10073.
//!
//! - **HPKE** (CRY-05.3): base mode, single shot, the one suite KEM 0x647a
//!   MLKEM768-X25519, KDF 0x0001 HKDF-SHA256, AEAD 0x0003 ChaCha20-Poly1305
//!   ([`SUITE`]), empty associated data. No psk, auth or export mode, no
//!   other suite, and no ML-KEM or X25519 alone: the KEM and its SHA3-256
//!   combiner are the vendored `hpke`, `x-wing` and `ml-kem` code (CRY-05.2).
//!   A receiving key's private part is its 32-byte X-Wing seed; the ML-KEM
//!   and X25519 keys are expanded from it inside each call.
//! - **Composite signature** (CRY-05.5): `M' = Prefix ‖ Label ‖ len(ctx) ‖
//!   ctx ‖ SHA-512(M)` with Larsal's ctx always empty; ML-DSA-65 signs M'
//!   with context Label, hedged with 32 bytes from `larsal-crypto::random`,
//!   and Ed25519 signs M'; a signature is valid only when both halves verify
//!   (Ed25519 strictly). The halves are never reachable alone (CRY-05.6).
//!
//! Secrets (CRY-05.17): seeds, private keys and opened plaintexts are only in
//! [`SecretBytes`]; the vendored key types (built with their `zeroize`
//! features, wiped on drop) live only inside one call, on a short-lived
//! worker thread of its own (`secret::scrubbed_thread`: a 1 MiB stack, of
//! which 768 KiB below the work are zeroed when it returns, then the thread
//! ends). So no expanded key is left in the caller's stack, and a caller on
//! a 512 KiB macOS secondary thread can make every call. [`composite_verify`]
//! holds no secret and runs on the caller's thread. Errors hold no input
//! bytes.
//!
//! Test seams are private to this module: the random draw of [`seal`],
//! [`xwing_keypair`], [`identity_keypair`] and [`composite_sign`] (a script
//! in known-answer tests), associated data and a signature context. Outside
//! this module they cannot be named:
//! ```compile_fail
//! let _ = larsal_crypto::pq::seal_with;
//! ```
//! ```compile_fail
//! let _ = larsal_crypto::pq::sign_with;
//! ```
//! ```compile_fail
//! let _ = larsal_crypto::pq::verify_ctx;
//! ```
//! ```compile_fail
//! let _ = larsal_crypto::pq::open_aad;
//! ```
//! Control: the public functions can be named.
//! ```
//! let _ = (larsal_crypto::pq::seal, larsal_crypto::pq::composite_sign);
//! let _ = (larsal_crypto::pq::open, larsal_crypto::pq::composite_verify);
//! ```

use crate::random::{self, Prepared};
use crate::secret::{SecretBytes, scrubbed_thread};
use crate::{Error, hash, sign};
use ::hpke::aead::{AeadTag, ChaCha20Poly1305};
use ::hpke::inout::InOutBuf;
use ::hpke::kdf::HkdfSha256;
use ::hpke::kem::XWing;
use ::hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use ml_dsa::{EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, VerifyingKey};

type PrivateKey = <XWing as ::hpke::Kem>::PrivateKey;
type PublicKey = <XWing as ::hpke::Kem>::PublicKey;
type EncappedKey = <XWing as ::hpke::Kem>::EncappedKey;

/// The one hybrid suite: KEM, KDF and AEAD ids (CRY-05.3).
pub const SUITE: [u16; 3] = [0x647a, 0x0001, 0x0003];
/// The largest plaintext [`seal`] takes (CRY-05 inputs table).
pub const MAX_PLAINTEXT: usize = 1024;
/// The largest info [`seal`] and [`open`] take.
pub const MAX_INFO: usize = 512;
/// A receiving key's private seed (Nsk), in bytes.
pub const SEED: usize = 32;
/// A receiving public key (Npk): ML-KEM-768 (1,184) ‖ X25519 (32).
pub const PUBLIC_KEY: usize = 1216;
/// An enc (Nenc): ML-KEM-768 ciphertext (1,088) ‖ X25519 share (32).
pub const ENC: usize = 1120;
/// An identity private key: ML-DSA-65 seed ξ (32) ‖ Ed25519 seed (32).
pub const IDENTITY_PRIVATE: usize = 64;
/// An identity public key: ML-DSA-65 (1,952) ‖ Ed25519 (32).
pub const IDENTITY_PUBLIC: usize = 1984;
/// A composite signature: ML-DSA-65 (3,309) ‖ Ed25519 (64).
pub const SIGNATURE: usize = 3373;

/// Nt of ChaCha20-Poly1305.
const TAG: usize = 16;
/// The random bytes of one X-Wing encapsulation.
const ENCAP_RANDOMNESS: usize = 64;
/// The ML-DSA-65 parts of the composite.
const MLDSA_PUBLIC: usize = 1952;
const MLDSA_SIGNATURE: usize = 3309;
/// The random bytes of one hedged ML-DSA signature (FIPS 204 Algorithm 2).
const RND: usize = 32;
/// RFC 10073: the prefix of every composite M'.
const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
/// RFC 10073: the label of id-MLDSA65-Ed25519-SHA512, also ML-DSA's context.
const LABEL: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// Makes a new X-Wing receiving key: a 32-byte seed from larsal-crypto's
/// random source and its 1,216-byte public key (CRY-05.2).
///
/// Guarantees: the seed is only in the returned [`SecretBytes`].
///
/// # Errors
/// [`Error::RandomSource`] if the random source fails or the system cannot
/// start the call's worker thread; nothing is returned.
pub fn xwing_keypair() -> Result<(SecretBytes, Vec<u8>), Error> {
    keypair_with(random::bytes)
}

fn keypair_with(
    draw: impl FnOnce(usize) -> Result<SecretBytes, Error>,
) -> Result<(SecretBytes, Vec<u8>), Error> {
    let seed = draw(SEED)?;
    let public = xwing_public(&seed).map_err(|_| Error::RandomSource)?;
    Ok((seed, public))
}

/// The 1,216-byte X-Wing public key of a 32-byte seed (the ML-KEM-768 and
/// X25519 keys expanded from it with SHAKE256, as the vendored X-Wing does).
///
/// # Errors
/// [`Error::KeyLength`] when the seed is not 32 bytes;
/// [`Error::RandomSource`] when the system cannot start the call's worker
/// thread.
pub fn xwing_public(seed: &SecretBytes) -> Result<Vec<u8>, Error> {
    if seed.len() != SEED {
        return Err(Error::KeyLength);
    }
    let mut public = vec![0u8; PUBLIC_KEY];
    scrubbed_thread(Error::RandomSource, || {
        xwing_public_in(seed.expose(), &mut public)
    })??;
    Ok(public)
}

/// The secret work of [`xwing_public`], on its worker thread.
fn xwing_public_in(seed: &[u8], public: &mut [u8]) -> Result<(), Error> {
    let sk = PrivateKey::from_bytes(seed).map_err(|_| Error::KeyLength)?;
    XWing::sk_to_pk(&sk).write_exact(public);
    Ok(())
}

/// Seals `plaintext` to the X-Wing public key `recipient` with `info`
/// (RFC 9180 `SealBase` with [`SUITE`]), and returns enc (1,120 bytes) and
/// the ciphertext (plaintext plus a 16-byte tag).
///
/// Guarantees: the key is checked before any random draw: 1,216 bytes, and
/// its ML-KEM part passes FIPS 203 section 7.2's encapsulation key check.
///
/// # Errors
/// [`Error::TooLarge`] for a plaintext over [`MAX_PLAINTEXT`] or an info over
/// [`MAX_INFO`], before any work; [`Error::KeyLength`] for a key that is not
/// 1,216 bytes; [`Error::WrapInvalid`] for a key whose ML-KEM part fails the
/// check, or when the system cannot start the call's worker thread;
/// [`Error::RandomSource`] if the random source fails.
pub fn seal(recipient: &[u8], info: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    seal_with(random::bytes, recipient, info, &[], plaintext)
}

/// [`seal`] with `draw` for the 64 encapsulation bytes (`random::bytes` in
/// product code, the record's ikmE in tests) and associated data (empty in
/// product code).
fn seal_with(
    draw: impl FnOnce(usize) -> Result<SecretBytes, Error>,
    recipient: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if plaintext.len() > MAX_PLAINTEXT || info.len() > MAX_INFO {
        return Err(Error::TooLarge);
    }
    if recipient.len() != PUBLIC_KEY {
        return Err(Error::KeyLength);
    }
    // The vendored decode runs FIPS 203 section 7.2's type and modulus check.
    let recipient = PublicKey::from_bytes(recipient).map_err(|_| Error::WrapInvalid)?;
    let mut rng = Prepared::new(draw(ENCAP_RANDOMNESS)?);
    let mut ct = vec![0u8; plaintext.len()];
    // The ephemeral X-Wing keys and the shared secret are inline values.
    let (encapped, tag) = scrubbed_thread(Error::WrapInvalid, || {
        seal_in(&recipient, info, aad, plaintext, &mut ct, &mut rng)
    })??;
    // The encapsulation must use exactly the 64 bytes drawn above.
    if !rng.served_once() {
        return Err(Error::RandomSource);
    }
    let mut enc = vec![0u8; ENC];
    encapped.write_exact(&mut enc);
    let mut tag_bytes = [0u8; TAG];
    tag.write_exact(&mut tag_bytes);
    ct.extend_from_slice(&tag_bytes);
    Ok((enc, ct))
}

/// The secret work of [`seal_with`], on its worker thread.
fn seal_in(
    recipient: &PublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ct: &mut [u8],
    rng: &mut Prepared,
) -> Result<(EncappedKey, AeadTag<ChaCha20Poly1305>), Error> {
    let buf = InOutBuf::new(plaintext, ct).map_err(|_| Error::WrapInvalid)?;
    ::hpke::single_shot_seal_inout_detached_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        recipient,
        info,
        buf,
        aad,
        rng,
    )
    .map_err(|_| Error::WrapInvalid)
}

/// Opens a ciphertext sealed by [`seal`] (RFC 9180 `OpenBase` with
/// [`SUITE`]) with the recipient's 32-byte seed, enc and the same info.
///
/// Guarantees: the plaintext is only in the returned [`SecretBytes`]; on
/// failure nothing of it is returned. An enc that is not 1,120 bytes is
/// refused before any decapsulation. A changed enc or ct decapsulates to
/// another secret (ML-KEM's implicit rejection) and fails at the tag.
///
/// # Errors
/// [`Error::KeyLength`] for a seed that is not 32 bytes;
/// [`Error::WrapInvalid`] for every other failure, among them a tag that does
/// not verify, an enc that is not 1,120 bytes, and an info over [`MAX_INFO`]
/// or a ciphertext over [`MAX_PLAINTEXT`] plus 16 bytes, before any work;
/// also when the system cannot start the call's worker thread.
pub fn open(seed: &SecretBytes, enc: &[u8], info: &[u8], ct: &[u8]) -> Result<SecretBytes, Error> {
    open_aad(seed, enc, info, &[], ct)
}

fn open_aad(
    seed: &SecretBytes,
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<SecretBytes, Error> {
    if seed.len() != SEED {
        return Err(Error::KeyLength);
    }
    let len = ct.len().checked_sub(TAG).ok_or(Error::WrapInvalid)?;
    if len > MAX_PLAINTEXT || info.len() > MAX_INFO || enc.len() != ENC {
        return Err(Error::WrapInvalid);
    }
    let (body, tag) = ct.split_at_checked(len).ok_or(Error::WrapInvalid)?;
    // enc and the tag are public: decoded here, so the T10 count stays on
    // the caller's thread.
    let enc = EncappedKey::from_bytes(enc).map_err(|_| Error::WrapInvalid)?;
    let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(tag).map_err(|_| Error::WrapInvalid)?;
    let mut out = SecretBytes::zeroed(len);
    #[cfg(test)]
    probe::count();
    scrubbed_thread(Error::WrapInvalid, || {
        open_in(seed.expose(), &enc, &tag, info, aad, body, out.expose_mut())
    })??;
    Ok(out)
}

/// The secret work of [`open_aad`], on its worker thread.
fn open_in(
    seed: &[u8],
    enc: &EncappedKey,
    tag: &AeadTag<ChaCha20Poly1305>,
    info: &[u8],
    aad: &[u8],
    body: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let sk = PrivateKey::from_bytes(seed).map_err(|_| Error::KeyLength)?;
    let buf = InOutBuf::new(body, out).map_err(|_| Error::WrapInvalid)?;
    ::hpke::single_shot_open_inout_detached::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk,
        enc,
        info,
        buf,
        aad,
        tag,
    )
    .map_err(|_| Error::WrapInvalid)
}

/// Makes a new composite identity key (CRY-05.5): 64 bytes from
/// larsal-crypto's random source, the ML-DSA-65 seed ξ then the Ed25519
/// seed, and the 1,984-byte public key.
///
/// Guarantees: the private key is only in the returned [`SecretBytes`].
///
/// # Errors
/// [`Error::RandomSource`] if the random source fails or the system cannot
/// start the call's worker thread; nothing is returned.
pub fn identity_keypair() -> Result<(SecretBytes, Vec<u8>), Error> {
    identity_keypair_with(random::bytes)
}

fn identity_keypair_with(
    draw: impl FnOnce(usize) -> Result<SecretBytes, Error>,
) -> Result<(SecretBytes, Vec<u8>), Error> {
    let private = draw(IDENTITY_PRIVATE)?;
    let public = identity_public(&private).map_err(|_| Error::RandomSource)?;
    Ok((private, public))
}

/// The two seeds of a 64-byte identity private key.
fn halves(private: &SecretBytes) -> Result<(&[u8; 32], &[u8; 32]), Error> {
    let (ml, ed) = private
        .expose()
        .split_first_chunk::<32>()
        .ok_or(Error::KeyLength)?;
    let ed: &[u8; 32] = ed.try_into().map_err(|_| Error::KeyLength)?;
    Ok((ml, ed))
}

/// The 1,984-byte composite public key of a 64-byte identity private key:
/// ML-DSA-65's public key (FIPS 204 Algorithm 6 from ξ) ‖ Ed25519's.
///
/// # Errors
/// [`Error::KeyLength`] when the private key is not 64 bytes;
/// [`Error::RandomSource`] when the system cannot start the call's worker
/// thread.
pub fn identity_public(private: &SecretBytes) -> Result<Vec<u8>, Error> {
    let (ml_seed, ed_seed) = halves(private)?;
    let mut public = vec![0u8; IDENTITY_PUBLIC];
    let (ml_out, ed_out) = public.split_at_mut(MLDSA_PUBLIC);
    scrubbed_thread(Error::RandomSource, || {
        identity_public_in(ml_seed, ed_seed, ml_out, ed_out);
    })?;
    Ok(public)
}

/// The secret work of [`identity_public`], on its worker thread.
fn identity_public_in(
    ml_seed: &[u8; 32],
    ed_seed: &[u8; 32],
    ml_out: &mut [u8],
    ed_out: &mut [u8],
) {
    let key = ExpandedSigningKey::<MlDsa65>::from_seed(ml_seed.into());
    ml_out.copy_from_slice(&key.verifying_key().encode());
    ed_out.copy_from_slice(
        &ed25519_dalek::SigningKey::from_bytes(ed_seed)
            .verifying_key()
            .to_bytes(),
    );
}

/// RFC 10073's M' for `message` and `ctx`: Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖
/// SHA-512(message).
fn message_prime(message: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u8::try_from(ctx.len()).map_err(|_| Error::TooLarge)?;
    let digest = hash::sha512(&[message]);
    Ok([PREFIX, LABEL, &[len], ctx, digest.expose()].concat())
}

/// Signs `message` with the composite identity key (CRY-05.5): ML-DSA-65
/// over M' with context Label, hedged with 32 fresh bytes from
/// larsal-crypto's random source, and pure Ed25519 over M'; Larsal's ctx is
/// empty. Returns the 3,373-byte signature.
///
/// Guarantees: two signatures over one message differ (hedged); the private
/// key is used only inside this call.
///
/// # Errors
/// [`Error::KeyLength`] when the private key is not 64 bytes;
/// [`Error::RandomSource`] if the random source fails or the system cannot
/// start the call's worker thread; nothing is returned.
pub fn composite_sign(private: &SecretBytes, message: &[u8]) -> Result<Vec<u8>, Error> {
    sign_with(random::bytes, private, message, &[])
}

/// [`composite_sign`] with `draw` for the 32 hedging bytes (32 zero bytes
/// give FIPS 204's deterministic variant, known-answer tests only) and a ctx
/// (empty in product code).
fn sign_with(
    draw: impl FnOnce(usize) -> Result<SecretBytes, Error>,
    private: &SecretBytes,
    message: &[u8],
    ctx: &[u8],
) -> Result<Vec<u8>, Error> {
    let (ml_seed, ed_seed) = halves(private)?;
    let m_prime = message_prime(message, ctx)?;
    let mut rng = Prepared::new(draw(RND)?);
    let mut signature = vec![0u8; SIGNATURE];
    let (ml_out, ed_out) = signature.split_at_mut(MLDSA_SIGNATURE);
    scrubbed_thread(Error::RandomSource, || {
        sign_in(ml_seed, ed_seed, &m_prime, &mut rng, ml_out, ed_out)
    })??;
    // The ML-DSA half must take exactly the 32 bytes drawn above.
    if !rng.served_once() {
        return Err(Error::RandomSource);
    }
    Ok(signature)
}

/// The secret work of [`sign_with`], on its worker thread.
fn sign_in(
    ml_seed: &[u8; 32],
    ed_seed: &[u8; 32],
    m_prime: &[u8],
    rng: &mut Prepared,
    ml_out: &mut [u8],
    ed_out: &mut [u8],
) -> Result<(), Error> {
    use ed25519_dalek::Signer as _;
    let key = ExpandedSigningKey::<MlDsa65>::from_seed(ml_seed.into());
    let ml = key
        .sign_randomized(m_prime, LABEL, rng)
        .map_err(|_| Error::RandomSource)?;
    ml_out.copy_from_slice(&ml.encode());
    let ed = ed25519_dalek::SigningKey::from_bytes(ed_seed).sign(m_prime);
    ed_out.copy_from_slice(&ed.to_bytes());
    Ok(())
}

/// Checks a composite signature (CRY-05.5): the public key is exactly 1,984
/// bytes and the signature 3,373; ML-DSA-65 checks its half over M' with
/// context Label (FIPS 204 Algorithm 3) and Ed25519 its half strictly
/// (CRY-04.3); both must pass. Larsal's ctx is empty.
///
/// Guarantees: lengths and the ML-DSA encodings are decoded before any check.
///
/// # Errors
/// [`Error::SignatureInvalid`] for every failure, with no detail of which
/// half failed.
pub fn composite_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    verify_ctx(public, message, &[], signature)
}

/// [`composite_verify`] with a ctx (empty in product code; RFC 10073's
/// `sWithContext` vector in tests).
fn verify_ctx(public: &[u8], message: &[u8], ctx: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public.len() != IDENTITY_PUBLIC || signature.len() != SIGNATURE {
        return Err(Error::SignatureInvalid);
    }
    let (ml_public, ed_public) = public
        .split_at_checked(MLDSA_PUBLIC)
        .ok_or(Error::SignatureInvalid)?;
    let (ml_signature, ed_signature) = signature
        .split_at_checked(MLDSA_SIGNATURE)
        .ok_or(Error::SignatureInvalid)?;
    let ml_public =
        EncodedVerifyingKey::<MlDsa65>::try_from(ml_public).map_err(|_| Error::SignatureInvalid)?;
    let ml_signature = ml_dsa::Signature::<MlDsa65>::try_from(ml_signature)
        .map_err(|_| Error::SignatureInvalid)?;
    let m_prime = message_prime(message, ctx).map_err(|_| Error::SignatureInvalid)?;
    let ml_ok = VerifyingKey::<MlDsa65>::decode(&ml_public).verify_with_context(
        &m_prime,
        LABEL,
        &ml_signature,
    );
    let ed_ok = sign::ed25519_verify(ed_public, &m_prime, ed_signature).is_ok();
    // Both halves always run; only both together are a valid signature.
    if ml_ok & ed_ok {
        Ok(())
    } else {
        Err(Error::SignatureInvalid)
    }
}

/// Test-only: how many times [`open`] reached the vendored decapsulation on
/// this thread (CRY-05 T10).
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
