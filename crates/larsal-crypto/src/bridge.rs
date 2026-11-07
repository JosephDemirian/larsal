//! The browser bridge channel (story E7-S1; INT-01.49, LD-274 (1)): X25519
//! (RFC 7748), HKDF-SHA256 (RFC 5869) with an empty salt and one key per
//! direction, and AES-256-GCM (NIST SP 800-38D) with 12-byte nonces, a
//! 16-byte tag and no associated data. The extension does the same with
//! WebCrypto (INT-11.7), so both sides must give INT-01.50's bytes.
//!
//! Guarantees: X25519 secret keys, X25519 results, derived keys and opened
//! contents live only in [`SecretBytes`] (a [`Secret`] is one); the crate's
//! own key type is made only inside a call, and 32 KiB of stack below each
//! call is zeroed after it (`secret::scrubbed`). An X25519 result of all
//! zero bytes (a low-order public key) is never returned. Every random byte
//! comes from `larsal-crypto::random`.

use crate::Error;
use crate::random;
use crate::secret::{SecretBytes, scrubbed};
use crate::wrap::hkdf_sha256;
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit};
use x25519_dalek::{PublicKey, StaticSecret};

/// Bytes of an X25519 key or result, and of a channel key.
pub const KEY: usize = 32;
/// Bytes of a nonce (INT-01.23).
pub const NONCE: usize = 12;
/// Bytes of the tag at the end of every box (INT-01.21).
pub const TAG: usize = 16;

/// The info labels of INT-01.49, followed by raw public keys.
const REQUEST: &[u8] = b"browser-bridge request key v1";
const REPLY: &[u8] = b"browser-bridge reply key v1";
const PROOF: &[u8] = b"browser-bridge proof key v1";

/// An X25519 secret key: a session key or an identification key.
///
/// Guarantees: its 32 bytes live only in a [`SecretBytes`], wiped on drop,
/// whose buffer never moves, so moving a `Secret` (into a session, into a
/// map that grows) copies no key byte; no `Clone`; `Debug` prints
/// `[hidden]`.
pub struct Secret(SecretBytes);

impl Secret {
    /// A fresh key from larsal-crypto's random source.
    ///
    /// # Errors
    /// [`Error::RandomSource`] if the random source fails; nothing is returned.
    pub fn generate() -> Result<Self, Error> {
        scrubbed(|| random::bytes(KEY)).map(Self)
    }

    /// The key held in `bytes`: a file identity from the vault (FIL-01.15), a
    /// fresh ephemeral secret (FIL-01.3). Takes the buffer without copying it.
    ///
    /// # Errors
    /// [`Error::KeyLength`] for anything but 32 bytes; `bytes` is wiped.
    pub fn from_bytes(bytes: SecretBytes) -> Result<Self, Error> {
        if bytes.len() == KEY {
            Ok(Self(bytes))
        } else {
            Err(Error::KeyLength)
        }
    }

    /// x25519-dalek's key of this key's bytes (RFC 7748 clamps them when used).
    /// Called only inside `scrubbed`; the key wipes itself on drop.
    fn key(&self) -> StaticSecret {
        let mut bytes = [0u8; KEY];
        bytes
            .iter_mut()
            .zip(self.0.expose())
            .for_each(|(k, b)| *k = *b);
        StaticSecret::from(bytes)
    }

    /// The public key, X25519(secret, 9).
    #[must_use]
    pub fn public(&self) -> [u8; KEY] {
        scrubbed(|| PublicKey::from(&self.key()).to_bytes())
    }

    /// X25519(secret, `their`) (RFC 7748 section 5), the input key material
    /// of [`request_key`], [`reply_key`] and [`proof_key`].
    ///
    /// Guarantees: `None` when the result is all zero bytes, which every
    /// low-order public key gives (RFC 7748 section 6.1); the result is
    /// never returned then. The check runs in constant time.
    #[must_use]
    pub fn agree(&self, their: &[u8; KEY]) -> Option<SecretBytes> {
        scrubbed(|| {
            let shared = self.key().diffie_hellman(&PublicKey::from(*their));
            shared
                .was_contributory()
                .then(|| SecretBytes::new(shared.as_bytes().to_vec()))
        })
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([hidden])")
    }
}

/// The request key (INT-01.49): HKDF-SHA256 with an empty salt over the
/// session's X25519 result `z`, info `browser-bridge request key v1` ‖
/// `client` ‖ `app`. The client seals requests with it; Larsal opens them.
///
/// # Errors
/// None in practice (32 bytes is below HKDF's limit): [`Error::KeyLength`].
pub fn request_key(
    z: &SecretBytes,
    client: &[u8; KEY],
    app: &[u8; KEY],
) -> Result<SecretBytes, Error> {
    derive(z, REQUEST, &[client, app])
}

/// The reply key (INT-01.49): as [`request_key`] with the label
/// `browser-bridge reply key v1`. Larsal seals replies and notices with it.
///
/// # Errors
/// None in practice: [`Error::KeyLength`].
pub fn reply_key(
    z: &SecretBytes,
    client: &[u8; KEY],
    app: &[u8; KEY],
) -> Result<SecretBytes, Error> {
    derive(z, REPLY, &[client, app])
}

/// The proof key (INT-01.49, INT-01.28): HKDF-SHA256 with an empty salt
/// over `z_id` = X25519(identification secret, `app`) = X25519(Larsal's session
/// secret, `id`), info `browser-bridge proof key v1` ‖ `client` ‖ `app` ‖ `id`.
///
/// # Errors
/// None in practice: [`Error::KeyLength`].
pub fn proof_key(
    z_id: &SecretBytes,
    client: &[u8; KEY],
    app: &[u8; KEY],
    id: &[u8; KEY],
) -> Result<SecretBytes, Error> {
    derive(z_id, PROOF, &[client, app, id])
}

fn derive(z: &SecretBytes, label: &[u8], keys: &[&[u8; KEY]]) -> Result<SecretBytes, Error> {
    let mut info = label.to_vec();
    keys.iter().for_each(|k| info.extend_from_slice(*k));
    // RFC 5869 section 2.2: an empty salt is HashLen zero bytes.
    hkdf_sha256(&[], z, &info)
}

/// The box of INT-01.21: AES-256-GCM of `content` under the 32-byte `key`
/// with `nonce` and no associated data, as ciphertext ‖ 16-byte tag (the
/// form WebCrypto's `encrypt` returns).
///
/// # Errors
/// [`Error::KeyLength`] for a key that is not 32 bytes, before any work;
/// [`Error::TooLarge`] for content over GCM's limit (about 64 GiB).
pub fn seal(key: &SecretBytes, nonce: &[u8; NONCE], content: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != KEY {
        return Err(Error::KeyLength);
    }
    let mut out = vec![0u8; content.len()];
    let tag = scrubbed(|| {
        let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::KeyLength)?;
        let buf = InOutBuf::new(content, &mut out).map_err(|_| Error::TooLarge)?;
        cipher
            .encrypt_inout_detached(nonce.into(), &[], buf)
            .map_err(|_| Error::TooLarge)
    })?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens a box made by [`seal`] with the same key and nonce.
///
/// Guarantees: the content is only in the returned [`SecretBytes`]; the tag
/// is checked before anything is decrypted, so on failure nothing of the
/// content is made.
///
/// # Errors
/// [`Error::Decrypt`] for any change of the key, nonce, ciphertext or tag,
/// and for a box shorter than the tag; [`Error::KeyLength`] for a key that
/// is not 32 bytes.
pub fn open(key: &SecretBytes, nonce: &[u8; NONCE], sealed: &[u8]) -> Result<SecretBytes, Error> {
    if key.len() != KEY {
        return Err(Error::KeyLength);
    }
    let len = sealed.len().checked_sub(TAG).ok_or(Error::Decrypt)?;
    let (body, tag) = sealed.split_at_checked(len).ok_or(Error::Decrypt)?;
    let mut out = SecretBytes::zeroed(len);
    scrubbed(|| {
        let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::KeyLength)?;
        let tag = tag.try_into().map_err(|_| Error::Decrypt)?;
        let buf = InOutBuf::new(body, out.expose_mut()).map_err(|_| Error::Decrypt)?;
        cipher
            .decrypt_inout_detached(nonce.into(), &[], buf, tag)
            .map_err(|_| Error::Decrypt)
    })?;
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key32(s: &str) -> [u8; KEY] {
        hex(s).try_into().unwrap()
    }

    fn secret(s: &str) -> Secret {
        Secret(SecretBytes::new(hex(s)))
    }

    fn bytes(s: &str) -> SecretBytes {
        SecretBytes::new(hex(s))
    }

    fn hexed(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // RFC 7748 section 6.1.
    const ALICE_SECRET: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_SECRET: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    /// T78: RFC 7748 section 6.1, both ways.
    #[test]
    fn t78_x25519_gives_rfc_7748_section_6_1() {
        let (a, b) = (secret(ALICE_SECRET), secret(BOB_SECRET));
        assert_eq!(hexed(&a.public()), ALICE_PUBLIC);
        assert_eq!(hexed(&b.public()), BOB_PUBLIC);
        let ab = a.agree(&key32(BOB_PUBLIC)).unwrap();
        let ba = b.agree(&key32(ALICE_PUBLIC)).unwrap();
        assert_eq!(hexed(ab.expose()), SHARED);
        assert_eq!(hexed(ba.expose()), SHARED);
    }

    /// INT-01.20, INT-01.28, AT-F03: every low-order public key gives an
    /// all-zero result, which is refused (the list: points of order 1, 2, 4
    /// and 8 and their non-canonical forms, RFC 7748 section 6.1).
    #[test]
    fn low_order_public_keys_give_no_result() {
        let a = Secret::generate().unwrap();
        for point in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            assert!(a.agree(&key32(point)).is_none(), "{point}");
        }
        assert!(a.agree(&key32(ALICE_PUBLIC)).is_some());
    }

    /// T78: RFC 5869 appendix A.1 to A.3, PRK and OKM (A.3: the empty salt
    /// this channel uses), through the crate the key schedule calls.
    #[test]
    fn t78_hkdf_sha256_gives_rfc_5869_a1_to_a3() {
        let a2_ikm: String = (0x00..=0x4f).map(|b: u8| format!("{b:02x}")).collect();
        let a2_salt: String = (0x60..=0xaf).map(|b: u8| format!("{b:02x}")).collect();
        let a2_info: String = (0xb0..=0xff).map(|b: u8| format!("{b:02x}")).collect();
        let ikm22 = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let cases = [
            (
                ikm22,
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            ),
            (
                a2_ikm.as_str(),
                a2_salt.as_str(),
                a2_info.as_str(),
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                ikm22,
                "",
                "",
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ),
        ];
        for (ikm, salt, info, prk, okm) in cases {
            let (got_prk, hk) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(&hex(salt)), &hex(ikm));
            assert_eq!(hexed(&got_prk), prk);
            let mut out = vec![0u8; okm.len() / 2];
            hk.expand(&hex(info), &mut out).unwrap();
            assert_eq!(hexed(&out), okm);
        }
        // The salt the key schedule passes (empty) is RFC 5869's "not provided".
        let mut none = [0u8; 42];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &hex(ikm22))
            .expand(&[], &mut none)
            .unwrap();
        assert_eq!(hexed(&none), cases[2].4);
    }

    /// T78: NIST CAVP `gcmEncryptExtIV256.rsp`, Count 0 of PTlen 0, 128 and
    /// 408 (G3 with 160 bits of associated data, through the crate itself);
    /// G1 and G2 also through [`seal`] and [`open`].
    #[test]
    fn t78_aes_256_gcm_gives_nist_cavp_g1_to_g3() {
        let cases = [
            (
                "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
                "516c33929df5a3284ff463d7",
                "",
                "",
                "",
                "bdc1ac884d332457a1d2664f168c76f0",
            ),
            (
                "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
                "0d18e06c7c725ac9e362e1ce",
                "2db5168e932556f8089a0622981d017d",
                "",
                "fa4362189661d163fcd6a56d8bf0405a",
                "d636ac1bbedd5cc3ee727dc2ab4a9489",
            ),
            (
                "24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f",
                "9ff18563b978ec281b3f2794",
                "27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb158bd9abb3868fdc0d0b074b5f01b2c",
                "adb5ec720ccf9898500028bf34afccbcaca126ef",
                "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae82057ad55994cf59ad7f67c0fa5e85fab8",
                "bc95c532fecc594c36d1550286a7a3f0",
            ),
        ];
        for (key, iv, pt, aad, ct, tag) in cases {
            let cipher = Aes256Gcm::new_from_slice(&hex(key)).unwrap();
            let nonce: [u8; NONCE] = hex(iv).try_into().unwrap();
            let mut sealed = hex(pt);
            let tag_bytes = cipher
                .encrypt_inout_detached((&nonce).into(), &hex(aad), sealed.as_mut_slice().into())
                .unwrap();
            sealed.extend_from_slice(&tag_bytes);
            assert_eq!(hexed(&sealed), format!("{ct}{tag}"));
            if aad.is_empty() {
                let k = bytes(key);
                assert_eq!(
                    hexed(&seal(&k, &nonce, &hex(pt)).unwrap()),
                    format!("{ct}{tag}")
                );
                assert_eq!(hexed(open(&k, &nonce, &sealed).unwrap().expose()), pt);
            }
        }
    }

    // INT-01.50's fixed inputs: c = Alice, a = Bob, the identification key i.
    const ID_SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const N1: [u8; NONCE] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const N2: [u8; NONCE] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    const P1: &[u8] = br#"{"type":"status","req":1}"#;
    const P2: &[u8] = br#"{"type":"status","req":1,"vaults":[]}"#;

    // Larsal's own channel vectors (INT-01.50 CV-2 to CV-9), computed here and
    // in WebCrypto in headless Chrome (extension/test/test_channel_vectors.py).
    const CV2: &str = "e4b77f9fa8df1e045efa982b7a70fe6194b4cdb32153a5c034d80a5d63ec1e74";
    const CV3: &str = "999ff990adb5b4328ba790203c0e5e09e22b7cc989d2ba515754f70922b20da7";
    const CV4: &str =
        "5c843e032bda41a65a5cbe0903401ab186ef872add0a69ee862fa035dbe679eeaf1de73c93cafc6e7f";
    const CV5: &str = "d58bf61c8472d102d307203c8a89d13e5d8205fd0ad99803d18551dd97216027aa9eae11a9e2f08823592d7c41c7703f78a589837a";
    const CV6: &str = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
    const CV7: &str = "d0bda120f120bed6b1c132f737ab678e1a4358c0984a617d2fe14f665460932f";
    const CV8: &str = "2bb001852cfa20c1028578b07956ef04efa252c1d2659bae42fac46c5a3be859";
    const CV9: &str = "3206e2599b88ce227a7a9a6a09d2b52e7279593b2a02c502b476917c592ead05e1440ebc6f879ac3fba856cd6c3e8652";

    /// T79: CV-1 to CV-9 of INT-01.50.
    #[test]
    fn t79_channel_vectors_cv1_to_cv9() {
        let (c, a, i) = (secret(ALICE_SECRET), secret(BOB_SECRET), secret(ID_SECRET));
        let (client, app) = (c.public(), a.public());
        // CV-1: the info bytes.
        let mut info = REQUEST.to_vec();
        info.extend_from_slice(&client);
        info.extend_from_slice(&app);
        assert_eq!(
            REQUEST,
            hex("62726f777365722d6272696467652072657175657374206b6579207631")
        );
        assert_eq!(
            REPLY,
            hex("62726f777365722d627269646765207265706c79206b6579207631")
        );
        assert_eq!(
            PROOF,
            hex("62726f777365722d6272696467652070726f6f66206b6579207631")
        );
        assert_eq!(info.len(), 93);
        assert_eq!((REPLY.len() + 64, PROOF.len() + 96), (91, 123));
        // Z is RFC 7748's K, the same both ways.
        let z = a.agree(&client).unwrap();
        assert_eq!(hexed(z.expose()), SHARED);
        assert_eq!(c.agree(&app).unwrap().expose(), z.expose());
        let request = request_key(&z, &client, &app).unwrap();
        let reply = reply_key(&z, &client, &app).unwrap();
        let cv4 = seal(&request, &N1, P1).unwrap();
        let cv5 = seal(&reply, &N1, P2).unwrap();
        let id = i.public();
        let z_id = i.agree(&app).unwrap();
        assert_eq!(
            a.agree(&id).unwrap().expose(),
            z_id.expose(),
            "CV-7 both ways"
        );
        let proof = proof_key(&z_id, &client, &app, &id).unwrap();
        let cv9 = seal(&proof, &N2, &client).unwrap();
        let got = [
            hexed(request.expose()),
            hexed(reply.expose()),
            hexed(&cv4),
            hexed(&cv5),
            hexed(&id),
            hexed(z_id.expose()),
            hexed(proof.expose()),
            hexed(&cv9),
        ];
        assert_eq!((cv4.len(), cv5.len(), cv9.len()), (41, 53, 48));
        assert_eq!(got, [CV2, CV3, CV4, CV5, CV6, CV7, CV8, CV9]);
        // Each box opens only with its own key (INT-01.49, T80, T81).
        assert_eq!(open(&request, &N1, &cv4).unwrap().expose(), P1);
        assert_eq!(open(&reply, &N1, &cv5).unwrap().expose(), P2);
        assert_eq!(open(&reply, &N1, &cv4).unwrap_err(), Error::Decrypt);
        assert_eq!(open(&request, &N1, &cv5).unwrap_err(), Error::Decrypt);
    }

    /// AT-F03: a changed bit anywhere, another nonce or a box shorter than
    /// the tag does not open; nothing of the content comes back.
    #[test]
    fn changed_or_short_boxes_do_not_open() {
        let key = random::bytes(KEY).unwrap();
        let sealed = seal(&key, &N1, P1).unwrap();
        for bit in 0..sealed.len() * 8 {
            let mut bad = sealed.clone();
            bad[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(open(&key, &N1, &bad).unwrap_err(), Error::Decrypt);
        }
        assert_eq!(open(&key, &N2, &sealed).unwrap_err(), Error::Decrypt);
        assert_eq!(open(&key, &N1, &sealed[..15]).unwrap_err(), Error::Decrypt);
        assert_eq!(
            open(&SecretBytes::zeroed(31), &N1, &sealed).unwrap_err(),
            Error::KeyLength
        );
        assert_eq!(
            seal(&SecretBytes::zeroed(33), &N1, P1).unwrap_err(),
            Error::KeyLength
        );
    }

    /// Rule 3: a secret key never shows in `Debug` output.
    #[test]
    fn secret_debug_is_hidden() {
        assert_eq!(format!("{:?}", secret(ID_SECRET)), "Secret([hidden])");
        let a = Secret::generate().unwrap();
        let b = Secret::generate().unwrap();
        assert_ne!(a.public(), b.public());
    }

    proptest! {
        /// Rust rule 10: seal and open round trip.
        #[test]
        fn seal_then_open_gives_the_content(content in proptest::collection::vec(any::<u8>(), 0..2048), nonce in any::<[u8; NONCE]>()) {
            let key = random::bytes(KEY).unwrap();
            let sealed = seal(&key, &nonce, &content).unwrap();
            prop_assert_eq!(sealed.len(), content.len() + TAG);
            let opened = open(&key, &nonce, &sealed).unwrap();
            prop_assert_eq!(opened.expose(), &content[..]);
        }
    }
}
