//! HPKE base mode for one suite, and the signed wrap record (story E16-S2,
//! CRY-04.5 and CRY-04.6).
//!
//! The suite is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM
//! (RFC 9180 section 7: 0x0020, 0x0001, 0x0002), single shot, with empty
//! associated data. No psk, auth or export mode is reachable from here.
//! Private keys and opened plaintexts live only in [`SecretBytes`]; the
//! hpke key types live only inside one call (wiped on drop), with 32 KiB of
//! stack below the call zeroed after it. Every random byte comes from
//! `app-crypto::random`, drawn before any work (CRY-04.12).
//!
//! Base mode does not say who sent a wrap (RFC 9180 section 9.8), so a wrap
//! that crosses the server is a [`WrapRecord`], signed by its sender.

use crate::Error;
use crate::random::{self, Prepared};
use crate::secret::{SecretBytes, scrubbed};
use crate::sign;
use ::hpke::aead::{AeadTag, AesGcm256};
use ::hpke::inout::InOutBuf;
use ::hpke::kdf::HkdfSha256;
use ::hpke::kem::X25519HkdfSha256;
use ::hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};

type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as ::hpke::Kem>::PrivateKey;
type PublicKey = <Kem as ::hpke::Kem>::PublicKey;
type EncappedKey = <Kem as ::hpke::Kem>::EncappedKey;

/// The one suite: KEM, KDF and AEAD ids (RFC 9180 section 7).
pub const SUITE: [u16; 3] = [0x0020, 0x0001, 0x0002];
/// The largest plaintext [`seal`] takes (CRY-04 inputs table).
pub const MAX_PLAINTEXT: usize = 1024;
/// The largest info [`seal`] and [`open`] take.
pub const MAX_INFO: usize = 512;
/// Nsk, Npk and Nenc of the suite (RFC 9180 section 7.1).
const KEY: usize = 32;
/// Nt of AES-256-GCM.
const TAG: usize = 16;
/// The label of a wrap record's signature (CRY-04.2).
const WRAP_LABEL: &[u8] = b"sync-wrap-v1";

/// Makes a new X25519 key pair (RFC 9180 section 7.1.3, DeriveKeyPair over
/// 32 bytes from app-crypto's random source).
///
/// Guarantees: the private key (32 bytes) is only in the returned
/// [`SecretBytes`]; the public key is its 32-byte encoding.
///
/// # Errors
/// [`Error::RandomSource`] if the random source fails; nothing is returned.
pub fn x25519_keypair() -> Result<(SecretBytes, [u8; 32]), Error> {
    keypair_with(random::bytes)
}

fn keypair_with(
    draw: impl FnOnce(usize) -> Result<SecretBytes, Error>,
) -> Result<(SecretBytes, [u8; 32]), Error> {
    let ikm = draw(KEY)?;
    let mut private = SecretBytes::zeroed(KEY);
    let mut public = [0u8; KEY];
    scrubbed(|| {
        let (sk, pk) = Kem::derive_keypair(ikm.expose());
        sk.write_exact(private.expose_mut());
        pk.write_exact(&mut public);
    });
    Ok((private, public))
}

/// Seals `plaintext` to the X25519 public key `recipient` with `info`
/// (RFC 9180 `SealBase`, section 6.1), and returns enc (32 bytes) and the
/// ciphertext (plaintext plus a 16-byte tag).
///
/// # Errors
/// [`Error::TooLarge`] for a plaintext over [`MAX_PLAINTEXT`] or an info over
/// [`MAX_INFO`], before any work; [`Error::KeyLength`] for a public key that
/// is not 32 bytes; [`Error::RandomSource`] if the random source fails;
/// [`Error::WrapInvalid`] if the X25519 result is all zero bytes (a
/// small-order public key, RFC 9180 section 7.1.4).
pub fn seal(recipient: &[u8], info: &[u8], plaintext: &[u8]) -> Result<([u8; 32], Vec<u8>), Error> {
    seal_with(random::bytes, recipient, info, &[], plaintext)
}

/// [`seal`] with `draw` for the random bytes (`random::bytes` in product
/// code, a script in tests) and associated data (empty in product code).
fn seal_with(
    draw: impl FnOnce(usize) -> Result<SecretBytes, Error>,
    recipient: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; 32], Vec<u8>), Error> {
    if plaintext.len() > MAX_PLAINTEXT || info.len() > MAX_INFO {
        return Err(Error::TooLarge);
    }
    let recipient = PublicKey::from_bytes(recipient).map_err(|_| Error::KeyLength)?;
    let mut rng = Prepared::new(draw(KEY)?);
    let mut ct = vec![0u8; plaintext.len()];
    let (encapped, tag) = scrubbed(|| {
        let buf = InOutBuf::new(plaintext, &mut ct).map_err(|_| Error::WrapInvalid)?;
        ::hpke::single_shot_seal_inout_detached_with_rng::<AesGcm256, HkdfSha256, Kem>(
            &OpModeS::Base,
            &recipient,
            info,
            buf,
            aad,
            &mut rng,
        )
        .map_err(|_| Error::WrapInvalid)
    })?;
    // The ephemeral key must be exactly the 32 bytes drawn above.
    if !rng.served_once() {
        return Err(Error::RandomSource);
    }
    let mut enc = [0u8; KEY];
    encapped.write_exact(&mut enc);
    let mut tag_bytes = [0u8; TAG];
    tag.write_exact(&mut tag_bytes);
    ct.extend_from_slice(&tag_bytes);
    Ok((enc, ct))
}

/// Opens a ciphertext sealed by [`seal`] (RFC 9180 `OpenBase`, section 6.1)
/// with the recipient's 32-byte X25519 private key, enc and the same info.
///
/// Guarantees: the plaintext is only in the returned [`SecretBytes`]; on
/// failure nothing of it is returned.
///
/// # Errors
/// [`Error::KeyLength`] for a private key that is not 32 bytes;
/// [`Error::WrapInvalid`] for every other failure, among them a tag that does
/// not verify, an enc that is not 32 bytes, an X25519 result of all zero
/// bytes (RFC 9180 section 7.1.4), and an info over [`MAX_INFO`] or a
/// ciphertext over [`MAX_PLAINTEXT`] plus 16 bytes, before any work.
pub fn open(
    private: &SecretBytes,
    enc: &[u8],
    info: &[u8],
    ct: &[u8],
) -> Result<SecretBytes, Error> {
    open_aad(private, enc, info, &[], ct)
}

fn open_aad(
    private: &SecretBytes,
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<SecretBytes, Error> {
    let len = ct.len().checked_sub(TAG).ok_or(Error::WrapInvalid)?;
    if len > MAX_PLAINTEXT || info.len() > MAX_INFO {
        return Err(Error::WrapInvalid);
    }
    let (body, tag) = ct.split_at_checked(len).ok_or(Error::WrapInvalid)?;
    let mut out = SecretBytes::zeroed(len);
    scrubbed(|| {
        let sk = PrivateKey::from_bytes(private.expose()).map_err(|_| Error::KeyLength)?;
        let enc = EncappedKey::from_bytes(enc).map_err(|_| Error::WrapInvalid)?;
        let tag = AeadTag::<AesGcm256>::from_bytes(tag).map_err(|_| Error::WrapInvalid)?;
        let buf = InOutBuf::new(body, out.expose_mut()).map_err(|_| Error::WrapInvalid)?;
        ::hpke::single_shot_open_inout_detached::<AesGcm256, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            info,
            buf,
            aad,
            &tag,
        )
        .map_err(|_| Error::WrapInvalid)
    })?;
    Ok(out)
}

/// A signed wrap record (CRY-04.6): an HPKE wrap and its sender's Ed25519
/// signature over the field list (`sync-wrap-v1`, the suite as three u16,
/// enc, ct, info, signer id). Nothing in it is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapRecord {
    /// KEM, KDF and AEAD ids; [`open_wrap`] takes only [`SUITE`].
    pub suite: [u16; 3],
    /// The HPKE enc.
    pub enc: Vec<u8>,
    /// The HPKE ciphertext.
    pub ct: Vec<u8>,
    /// The HPKE info: a field list naming the wrap's purpose and identities.
    pub info: Vec<u8>,
    /// The signer's 16-byte id.
    pub signer: [u8; 16],
    /// The Ed25519 signature (64 bytes).
    pub signature: Vec<u8>,
}

/// The bytes a wrap record's signature covers.
fn signed_part(
    suite: [u16; 3],
    enc: &[u8],
    ct: &[u8],
    info: &[u8],
    signer: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let [kem, kdf, aead] = suite.map(u16::to_be_bytes);
    sign::field_list(&[WRAP_LABEL, &kem, &kdf, &aead, enc, ct, info, signer])
}

/// Seals `plaintext` to `recipient` with `info` ([`seal`]) and signs the
/// record with the signer's Ed25519 seed (CRY-04.6).
///
/// # Errors
/// Those of [`seal`], and [`Error::KeyLength`] for a seed that is not 32 bytes.
pub fn make_wrap(
    recipient: &[u8],
    info: &[u8],
    plaintext: &[u8],
    signer: [u8; 16],
    signer_seed: &SecretBytes,
) -> Result<WrapRecord, Error> {
    let (enc, ct) = seal(recipient, info, plaintext)?;
    let signature =
        sign::ed25519_sign(signer_seed, &signed_part(SUITE, &enc, &ct, info, &signer)?)?;
    Ok(WrapRecord {
        suite: SUITE,
        enc: enc.to_vec(),
        ct,
        info: info.to_vec(),
        signer,
        signature: signature.to_vec(),
    })
}

/// Opens a signed wrap record (CRY-04.6), in this order: (1) the suite is
/// [`SUITE`]; (2) the record's info equals `expected_info`, which the caller
/// builds for what it expects (never taken from the record); (3) the
/// signature verifies with `signer_public`, the key the caller trusts for the
/// record's signer; (4) HPKE open ([`open`]) with `expected_info`.
///
/// Guarantees: no step runs before the steps above it passed; the plaintext
/// is only in the returned [`SecretBytes`].
///
/// # Errors
/// [`Error::WrapInvalid`] for every failure, with no detail.
pub fn open_wrap(
    record: &WrapRecord,
    signer_public: &[u8],
    expected_info: &[u8],
    private: &SecretBytes,
) -> Result<SecretBytes, Error> {
    if record.suite != SUITE || record.info.as_slice() != expected_info {
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
    sign::ed25519_verify(signer_public, &signed, &record.signature)
        .map_err(|_| Error::WrapInvalid)?;
    open(private, &record.enc, expected_info, &record.ct).map_err(|_| Error::WrapInvalid)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A hex string value `"name":"…"` of a JSON object written without spaces.
    fn field<'a>(object: &'a str, name: &str) -> &'a str {
        let key = format!("\"{name}\":\"");
        let start = object.find(&key).unwrap() + key.len();
        &object[start..start + object[start..].find('"').unwrap()]
    }

    /// CRY-04.13, T07: the one base-mode record of the suite (mode 0,
    /// kem_id 32, kdf_id 1, aead_id 2) in the RFC 9180 test vectors of
    /// cfrg/draft-irtf-cfrg-hpke at commit
    /// 5f503c564da00b0687b3de75f1dfbdfc4079ad31,
    /// <https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json>
    /// (RFC 9180 Appendix A has no vector for this suite). The file is the
    /// hpke 0.14.1 copy's own `test-vectors/origrfc-5f503c5.json` (LD-303
    /// (5)): its bytes are pinned by the copy's checksum list
    /// (scripts/check-vendor.sh) and by the SHA-256 below.
    struct Vectors {
        info: Vec<u8>,
        ikm_r: Vec<u8>,
        ikm_e: Vec<u8>,
        sk_rm: Vec<u8>,
        pk_rm: Vec<u8>,
        enc: Vec<u8>,
        /// (aad, ct, pt) in sequence order.
        encryptions: Vec<[Vec<u8>; 3]>,
    }

    fn vectors() -> Vectors {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/crates-io/hpke-0.14.1/test-vectors/origrfc-5f503c5.json"
        );
        let file = std::fs::read(path).unwrap();
        assert_eq!(
            crate::hash::sha256(&[&file]).expose(),
            hex("61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6")
        );
        let text = std::str::from_utf8(&file).unwrap();
        let head = r#"{"mode":0,"kem_id":32,"kdf_id":1,"aead_id":2,"#;
        assert_eq!(text.matches(head).count(), 1);
        let start = text.find(head).unwrap();
        // The record ends at its matching brace (hex strings hold none).
        let mut depth = 0usize;
        let mut end = start;
        for (i, c) in text[start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let record = &text[start..end];
        assert_eq!(record.len(), 59_898);
        let list = &record[record.find(r#""encryptions":["#).unwrap()..];
        let list = &list[..list.find(']').unwrap()];
        let encryptions: Vec<[Vec<u8>; 3]> = list
            .split('{')
            .skip(1)
            .map(|e| {
                [
                    hex(field(e, "aad")),
                    hex(field(e, "ct")),
                    hex(field(e, "pt")),
                ]
            })
            .collect();
        assert_eq!(encryptions.len(), 257);
        Vectors {
            info: hex(field(record, "info")),
            ikm_r: hex(field(record, "ikmR")),
            ikm_e: hex(field(record, "ikmE")),
            sk_rm: hex(field(record, "skRm")),
            pk_rm: hex(field(record, "pkRm")),
            enc: hex(field(record, "enc")),
            encryptions,
        }
    }

    /// A draw that returns these bytes: the test seam for the ephemeral and
    /// recipient keys.
    fn scripted(bytes: &[u8]) -> impl FnOnce(usize) -> Result<SecretBytes, Error> {
        let bytes = bytes.to_vec();
        move |_| Ok(SecretBytes::new(bytes))
    }

    fn down(_: usize) -> Result<SecretBytes, Error> {
        Err(Error::RandomSource)
    }

    #[test]
    fn t07_rfc9180_vectors_open_and_seal() {
        let v = vectors();
        // DeriveKeyPair(ikmR) through App's key pair path gives pkRm.
        let (_, pk) = keypair_with(scripted(&v.ikm_r)).unwrap();
        assert_eq!(pk.to_vec(), v.pk_rm);
        let sk = SecretBytes::new(v.sk_rm.clone());
        // App's single shot: the first encryption (sequence 0) opens, and
        // seals to the record's enc and ct with the record's ikmE.
        let [aad, ct, pt] = &v.encryptions[0];
        let opened = open_aad(&sk, &v.enc, &v.info, aad, ct).unwrap();
        assert_eq!(opened.expose(), pt.as_slice());
        let (enc, sealed) = seal_with(scripted(&v.ikm_e), &v.pk_rm, &v.info, aad, pt).unwrap();
        assert_eq!((enc.to_vec(), &sealed), (v.enc.clone(), ct));
        // Every listed encryption, in order, through the copy's contexts:
        // the receiver from skRm and enc opens each, and the sender with
        // ikmE (through the same one-shot generator) gives enc and each ct.
        let sk = PrivateKey::from_bytes(&v.sk_rm).unwrap();
        let enc = EncappedKey::from_bytes(&v.enc).unwrap();
        let mut receiver = ::hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            &v.info,
        )
        .unwrap();
        let mut rng = Prepared::new(SecretBytes::new(v.ikm_e.clone()));
        let (enc, mut sender) = ::hpke::setup_sender_with_rng::<AesGcm256, HkdfSha256, Kem>(
            &OpModeS::Base,
            &PublicKey::from_bytes(&v.pk_rm).unwrap(),
            &v.info,
            &mut rng,
        )
        .unwrap();
        assert!(rng.served_once());
        assert_eq!(enc.to_bytes().to_vec(), v.enc);
        for (i, [aad, ct, pt]) in v.encryptions.iter().enumerate() {
            assert_eq!(&receiver.open(ct, aad).unwrap(), pt, "open {i}");
            assert_eq!(&sender.seal(pt, aad).unwrap(), ct, "seal {i}");
        }
    }

    #[test]
    fn t08_round_trip_and_one_more_byte_of_info() {
        let (sk, pk) = x25519_keypair().unwrap();
        let info = b"demo info";
        let plaintext = [0x5a; 32];
        let (enc, ct) = seal(&pk, info, &plaintext).unwrap();
        assert_eq!(ct.len(), 48);
        assert_eq!(open(&sk, &enc, info, &ct).unwrap().expose(), plaintext);
        assert_eq!(
            open(&sk, &enc, b"demo info!", &ct).err(),
            Some(Error::WrapInvalid)
        );
    }

    #[test]
    fn edge_cases_of_seal_and_open() {
        let (sk, pk) = x25519_keypair().unwrap();
        let (enc, ct) = seal(&pk, b"i", b"demo").unwrap();
        // An enc of 31 bytes, and the all-zero point as enc (its X25519
        // result is all zero, RFC 9180 section 7.1.4).
        assert_eq!(
            open(&sk, &enc[..31], b"i", &ct).err(),
            Some(Error::WrapInvalid)
        );
        assert_eq!(
            open(&sk, &[0; 32], b"i", &ct).err(),
            Some(Error::WrapInvalid)
        );
        // A ciphertext shorter than a tag, or over the limit: refused.
        assert_eq!(
            open(&sk, &enc, b"i", &ct[..15]).err(),
            Some(Error::WrapInvalid)
        );
        let big = vec![0; MAX_PLAINTEXT + TAG + 1];
        assert_eq!(open(&sk, &enc, b"i", &big).err(), Some(Error::WrapInvalid));
        let long_info = vec![0; MAX_INFO + 1];
        assert_eq!(
            open(&sk, &enc, &long_info, &ct).err(),
            Some(Error::WrapInvalid)
        );
        // Wraps over the limits that would open, made with the copy itself:
        // refused all the same.
        let copy_seal = |info: &[u8], pt: &[u8]| {
            let mut rng = Prepared::new(SecretBytes::new(vec![5; 32]));
            let (enc, ct) = ::hpke::single_shot_seal_with_rng::<AesGcm256, HkdfSha256, Kem>(
                &OpModeS::Base,
                &PublicKey::from_bytes(&pk).unwrap(),
                info,
                pt,
                &[],
                &mut rng,
            )
            .unwrap();
            (enc.to_bytes().to_vec(), ct)
        };
        let (e, c) = copy_seal(&long_info, b"demo");
        assert_eq!(
            open(&sk, &e, &long_info, &c).err(),
            Some(Error::WrapInvalid)
        );
        let (e, c) = copy_seal(b"i", &vec![3; MAX_PLAINTEXT + 1]);
        assert_eq!(open(&sk, &e, b"i", &c).err(), Some(Error::WrapInvalid));
        // Seal limits, before any work (no random draw: the draw would fail).
        assert_eq!(
            seal_with(down, &pk, b"i", &[], &vec![0; MAX_PLAINTEXT + 1]).err(),
            Some(Error::TooLarge)
        );
        assert_eq!(
            seal_with(down, &pk, &long_info, &[], b"demo").err(),
            Some(Error::TooLarge)
        );
        // The largest plaintext and info pass.
        let (enc, ct) = seal(&pk, &vec![1; MAX_INFO], &vec![2; MAX_PLAINTEXT]).unwrap();
        assert_eq!(
            open(&sk, &enc, &vec![1; MAX_INFO], &ct).unwrap().len(),
            MAX_PLAINTEXT
        );
        // A small-order recipient key (the zero point) gives an all-zero
        // X25519 result: refused.
        assert_eq!(
            seal(&[0; 32], b"i", b"demo").err(),
            Some(Error::WrapInvalid)
        );
        assert_eq!(seal(&pk[..31], b"i", b"demo").err(), Some(Error::KeyLength));
        assert_eq!(
            open(&SecretBytes::new(vec![1; 31]), &enc, b"i", &ct).err(),
            Some(Error::KeyLength)
        );
    }

    #[test]
    fn t17_a_failed_random_draw_makes_nothing() {
        assert_eq!(keypair_with(down).err(), Some(Error::RandomSource));
        let (_, pk) = x25519_keypair().unwrap();
        assert_eq!(
            seal_with(down, &pk, b"i", &[], b"demo").err(),
            Some(Error::RandomSource)
        );
    }

    #[test]
    fn cry04_12_seal_refuses_an_ephemeral_key_it_did_not_draw_exactly() {
        // The one-shot generator serves only one fill of exactly the drawn
        // length; a draw of the wrong length fails closed.
        let (_, pk) = x25519_keypair().unwrap();
        for n in [31, 33] {
            assert_eq!(
                seal_with(scripted(&vec![9; n]), &pk, b"i", &[], b"demo").err(),
                Some(Error::RandomSource),
                "{n}"
            );
        }
        assert!(seal_with(scripted(&[9; 32]), &pk, b"i", &[], b"demo").is_ok());
    }

    /// CRY-04.12 (as T12 for the AES wrap): every seal draws a fresh
    /// ephemeral key, and every key pair is fresh.
    #[test]
    fn cry04_12_every_seal_and_key_pair_is_fresh() {
        let (_, pk) = x25519_keypair().unwrap();
        let encs: std::collections::BTreeSet<[u8; 32]> = (0..1000)
            .map(|_| seal(&pk, b"i", b"demo").unwrap().0)
            .collect();
        assert_eq!(encs.len(), 1000);
        let pks: std::collections::BTreeSet<[u8; 32]> =
            (0..100).map(|_| x25519_keypair().unwrap().1).collect();
        assert_eq!(pks.len(), 100);
    }

    fn signer() -> (SecretBytes, [u8; 32]) {
        let seed = SecretBytes::new(vec![0x11; 32]);
        let public = sign::ed25519_public(&seed).unwrap();
        (seed, public)
    }

    #[test]
    fn t09_record_checks_run_in_order() {
        let (sk, pk) = x25519_keypair().unwrap();
        let (seed, signer_pk) = signer();
        let info = b"demo wrap info";
        let record = make_wrap(&pk, info, b"demo key part", [3; 16], &seed).unwrap();
        let _ = sign::probe::take();
        assert_eq!(
            open_wrap(&record, &signer_pk, info, &sk).unwrap().expose(),
            b"demo key part"
        );
        assert_eq!(sign::probe::take(), 1);
        // Another suite: refused at step 1, before any signature check.
        let mut other = record.clone();
        other.suite = [0x0020, 0x0001, 0x0003];
        assert_eq!(
            open_wrap(&other, &signer_pk, info, &sk).err(),
            Some(Error::WrapInvalid)
        );
        assert_eq!(sign::probe::take(), 0);
        // Another expected info (valid for another vault): step 2, no check.
        assert_eq!(
            open_wrap(&record, &signer_pk, b"demo wrap info for vault 2", &sk).err(),
            Some(Error::WrapInvalid)
        );
        assert_eq!(sign::probe::take(), 0);
        // Another trusted key: step 3.
        let stranger = sign::ed25519_public(&SecretBytes::new(vec![0x22; 32])).unwrap();
        assert_eq!(
            open_wrap(&record, &stranger, info, &sk).err(),
            Some(Error::WrapInvalid)
        );
        assert_eq!(sign::probe::take(), 1);
        // One changed byte of ct: the signature fails first (step 3).
        let mut changed = record.clone();
        changed.ct[0] ^= 1;
        assert_eq!(
            open_wrap(&changed, &signer_pk, info, &sk).err(),
            Some(Error::WrapInvalid)
        );
        assert_eq!(sign::probe::take(), 1);
        // A record the right signer signed over a wrap to another key: step 4.
        let (other_sk, _) = x25519_keypair().unwrap();
        assert_eq!(
            open_wrap(&record, &signer_pk, info, &other_sk).err(),
            Some(Error::WrapInvalid)
        );
    }

    #[test]
    fn cry04_6_the_signature_covers_the_whole_field_list() {
        // The signed bytes, built by hand from CRY-04.6 and CRY-04.2: the
        // label, the suite as three u16, enc, ct, info and the signer id,
        // each after its length as a u32 big endian.
        let (_, pk) = x25519_keypair().unwrap();
        let (seed, signer_pk) = signer();
        let r = make_wrap(&pk, b"demo info", b"demo", [3; 16], &seed).unwrap();
        let mut signed = Vec::new();
        for f in [
            &b"sync-wrap-v1"[..],
            &[0, 0x20],
            &[0, 1],
            &[0, 2],
            &r.enc,
            &r.ct,
            b"demo info",
            &[3; 16],
        ] {
            signed.extend_from_slice(&(f.len() as u32).to_be_bytes());
            signed.extend_from_slice(f);
        }
        assert_eq!(
            sign::ed25519_verify(&signer_pk, &signed, &r.signature),
            Ok(())
        );
    }

    #[test]
    fn t10_one_changed_byte_of_a_record_fails() {
        let (sk, pk) = x25519_keypair().unwrap();
        let (seed, signer_pk) = signer();
        let info = b"demo wrap info";
        let record = make_wrap(&pk, info, b"demo account secret", [3; 16], &seed).unwrap();
        assert!(open_wrap(&record, &signer_pk, info, &sk).is_ok());
        let lens = [record.enc.len(), record.ct.len(), record.info.len(), 16, 64];
        for (part, len) in lens.into_iter().enumerate() {
            for i in 0..len {
                let mut r = record.clone();
                match part {
                    0 => r.enc[i] ^= 1,
                    1 => r.ct[i] ^= 1,
                    2 => r.info[i] ^= 1,
                    3 => r.signer[i] ^= 1,
                    _ => r.signature[i] ^= 1,
                }
                assert_eq!(
                    open_wrap(&r, &signer_pk, info, &sk).err(),
                    Some(Error::WrapInvalid),
                    "part {part} byte {i}"
                );
            }
        }
    }

    #[test]
    fn cry04_10_secrets_print_nothing() {
        let (sk, pk) = x25519_keypair().unwrap();
        assert_eq!(format!("{sk:?}"), "[hidden]");
        let (enc, ct) = seal(&pk, b"i", b"demo secret").unwrap();
        let opened = open(&sk, &enc, b"i", &ct).unwrap();
        assert_eq!(format!("{opened:?}"), "[hidden]");
    }

    proptest::proptest! {
        /// Hostile enc, info and ciphertext give an answer, never a panic.
        #[test]
        fn hostile_open_never_panics(
            enc in proptest::collection::vec(0u8..=255, 0..40),
            info in proptest::collection::vec(0u8..=255, 0..20),
            ct in proptest::collection::vec(0u8..=255, 0..80),
        ) {
            let sk = SecretBytes::new(vec![7; 32]);
            proptest::prop_assert!(open(&sk, &enc, &info, &ct).is_err());
        }

        /// Round trip (Rust rule 10): open(seal(x)) == x for every info and
        /// plaintext within the limits, one flipped ciphertext byte gives
        /// WrapInvalid, and open_wrap(make_wrap(x)) == x.
        #[test]
        fn seal_open_and_wrap_round_trip(
            info in proptest::collection::vec(0u8..=255, 0..=MAX_INFO),
            plaintext in proptest::collection::vec(0u8..=255, 0..=MAX_PLAINTEXT),
            signer_id in proptest::array::uniform16(0u8..=255),
            flip in proptest::prelude::any::<proptest::sample::Index>(),
        ) {
            let (sk, pk) = x25519_keypair().unwrap();
            let (enc, mut ct) = seal(&pk, &info, &plaintext).unwrap();
            proptest::prop_assert_eq!(ct.len(), plaintext.len() + TAG);
            proptest::prop_assert_eq!(
                open(&sk, &enc, &info, &ct).unwrap().expose().to_vec(),
                plaintext.clone()
            );
            let i = flip.index(ct.len());
            ct[i] ^= 1;
            proptest::prop_assert_eq!(open(&sk, &enc, &info, &ct).err(), Some(Error::WrapInvalid));
            let (seed, signer_pk) = signer();
            let record = make_wrap(&pk, &info, &plaintext, signer_id, &seed).unwrap();
            proptest::prop_assert_eq!(
                open_wrap(&record, &signer_pk, &info, &sk).unwrap().expose().to_vec(),
                plaintext
            );
        }
    }
}
