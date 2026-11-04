//! The AES-256-GCM key wrap, HKDF-SHA256 and the account's two-secret key
//! (story E16-S2, CRY-04.7 to CRY-04.9).
//!
//! Keys, input key material and every opened or derived value live only in
//! [`SecretBytes`]; 32 KiB of stack below each call is zeroed after it.

use crate::Error;
use crate::kdf;
use crate::random;
use crate::secret::{SecretBytes, SecretString, scrubbed};
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit};

/// The largest plaintext [`seal`] takes (CRY-04 inputs table).
pub const MAX_PLAINTEXT: usize = 4096;
const KEY: usize = 32;
const NONCE: usize = 12;
const TAG: usize = 16;
/// The HKDF info of `K_wrap` (CRY-04.2, SYN-06.3).
const ACCOUNT_KEY_INFO: &[u8] = b"sync-account-key-v1";

/// Wraps `plaintext` with a 32-byte key and associated data (NIST SP
/// 800-38D, AES-256-GCM, CRY-04.7): a fresh 12-byte nonce from larsal-crypto's
/// random source for every call (the random IV construction, section
/// 8.2.2), and a 16-byte tag. Output: nonce ‖ ciphertext ‖ tag.
///
/// # Errors
/// [`Error::KeyLength`] for a key that is not 32 bytes and
/// [`Error::TooLarge`] for a plaintext over [`MAX_PLAINTEXT`], both before
/// any work; [`Error::RandomSource`] if the random source fails, and then
/// nothing is returned.
pub fn seal(key: &SecretBytes, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    seal_with(random::bytes, key, aad, plaintext)
}

/// [`seal`] with `draw` for the nonce (`random::bytes` in product code, a
/// script in tests).
fn seal_with(
    draw: impl FnOnce(usize) -> Result<SecretBytes, Error>,
    key: &SecretBytes,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if key.len() != KEY {
        return Err(Error::KeyLength);
    }
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error::TooLarge);
    }
    let nonce = draw(NONCE)?;
    let mut body = vec![0u8; plaintext.len()];
    let tag = scrubbed(|| {
        let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::KeyLength)?;
        let nonce = nonce.expose().try_into().map_err(|_| Error::IvLength)?;
        let buf = InOutBuf::new(plaintext, &mut body).map_err(|_| Error::TooLarge)?;
        cipher
            .encrypt_inout_detached(nonce, aad, buf)
            .map_err(|_| Error::TooLarge)
    })?;
    let mut out = nonce.expose().to_vec();
    out.extend_from_slice(&body);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens bytes made by [`seal`] with the same key and associated data.
///
/// Guarantees: the plaintext is only in the returned [`SecretBytes`]; the
/// tag is checked before anything is decrypted, so on failure nothing of
/// the plaintext is made.
///
/// # Errors
/// [`Error::WrapInvalid`] for any change of the key, nonce, ciphertext, tag or
/// associated data, and for input shorter than a nonce and a tag or longer
/// than the largest wrap, before any work; else [`Error::KeyLength`] for a
/// key that is not 32 bytes.
pub fn open(key: &SecretBytes, aad: &[u8], wrapped: &[u8]) -> Result<SecretBytes, Error> {
    let (nonce, rest) = wrapped.split_at_checked(NONCE).ok_or(Error::WrapInvalid)?;
    let len = rest.len().checked_sub(TAG).ok_or(Error::WrapInvalid)?;
    if len > MAX_PLAINTEXT {
        return Err(Error::WrapInvalid);
    }
    let (body, tag) = rest.split_at_checked(len).ok_or(Error::WrapInvalid)?;
    let mut out = SecretBytes::zeroed(len);
    scrubbed(|| {
        let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::KeyLength)?;
        let nonce = nonce.try_into().map_err(|_| Error::WrapInvalid)?;
        let tag = tag.try_into().map_err(|_| Error::WrapInvalid)?;
        let buf = InOutBuf::new(body, out.expose_mut()).map_err(|_| Error::WrapInvalid)?;
        cipher
            .decrypt_inout_detached(nonce, aad, buf, tag)
            .map_err(|_| Error::WrapInvalid)
    })?;
    Ok(out)
}

/// HKDF-SHA256 (RFC 5869, CRY-04.8): extract with `salt`, then expand with
/// `info`, to 32 bytes.
///
/// # Errors
/// None in practice: 32 bytes is far below HKDF's limit; the crate's error
/// would come back as [`Error::KeyLength`].
pub fn hkdf_sha256(salt: &[u8], ikm: &SecretBytes, info: &[u8]) -> Result<SecretBytes, Error> {
    let mut out = SecretBytes::zeroed(KEY);
    scrubbed(|| {
        hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm.expose())
            .expand(info, out.expose_mut())
            .map_err(|_| Error::KeyLength)
    })?;
    Ok(out)
}

/// The two-secret key `K_wrap` of an account (CRY-04.9, SYN-06.3):
/// `A` = Argon2id version 0x13 over the password's UTF-8 bytes with `salt`,
/// 65,536 KiB, 3 iterations, 4 lanes, 32 bytes (RFC 9106 section 4, the
/// second recommended option); then HKDF-SHA256 with salt `account_id`,
/// input key material `account_secret ‖ A` and info `sync-account-key-v1`.
///
/// Guarantees: the settings are fixed here, so no caller can run it weaker
/// or costlier; neither secret alone gives the key; `A`, the input key
/// material and the key are only in [`SecretBytes`].
///
/// # Errors
/// [`Error::KeyLength`] for an account secret that is not 32 bytes;
/// [`Error::KdfSettings`] if the Argon2 memory cannot be allocated.
pub fn account_key(
    password: &SecretString,
    salt: &[u8; 32],
    account_secret: &SecretBytes,
    account_id: &[u8; 16],
) -> Result<SecretBytes, Error> {
    if account_secret.len() != KEY {
        return Err(Error::KeyLength);
    }
    let password = SecretBytes::new(password.expose().as_bytes().to_vec());
    // The same Argon2id as the import files' (FEA-08.49): version 0x13, no
    // secret key, no associated data; only the settings differ.
    let a = kdf::import_argon2id(&password, salt, 3, 64, 4, KEY)?;
    drop(password);
    let mut ikm = SecretBytes::zeroed(2 * KEY);
    let (first, second) = ikm
        .expose_mut()
        .split_at_mut_checked(KEY)
        .ok_or(Error::KeyLength)?;
    first.copy_from_slice(account_secret.expose());
    second.copy_from_slice(a.expose());
    drop(a);
    hkdf_sha256(account_id, &ikm, ACCOUNT_KEY_INFO)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The AES-256 cases with 96-bit IVs (test cases 13 to 16: key, IV,
    /// plaintext, associated data, ciphertext, tag) of McGrew and Viega, "The
    /// Galois/Counter Mode of Operation (GCM)", Appendix B, the GCM
    /// specification NIST SP 800-38D is built on:
    /// <https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/gcm/gcm-spec.pdf>.
    const GCM_SPEC: [[&str; 6]; 4] = [
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        ],
        [
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            "b094dac5d93471bdec1a502270e3cc6c",
        ],
        [
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        ],
    ];

    #[test]
    fn t11_aes256gcm_published_vectors() {
        for [key, iv, pt, aad, ct, tag] in GCM_SPEC {
            let key = SecretBytes::new(hex(key));
            let (iv, pt, aad) = (hex(iv), hex(pt), hex(aad));
            let want = [iv.clone(), hex(ct), hex(tag)].concat();
            let made = seal_with(|_| Ok(SecretBytes::new(iv)), &key, &aad, &pt).unwrap();
            assert_eq!(made, want);
            assert_eq!(open(&key, &aad, &want).unwrap().expose(), pt.as_slice());
        }
    }

    /// CRY-04.13, T11: the AES-256-GCM vectors that the aes-gcm 0.11.1 copy
    /// keeps as test data (whole upstream files, F-172; their bytes are
    /// pinned by the copy's checksum list, scripts/check-vendor.sh, and by
    /// the SHA-256 below):
    /// - `tests/aes256gcm.rs`: the 375 NIST CAVP vectors of
    ///   `gcmEncryptExtIV256.rsp` with 96-bit IVs and 128-bit tags,
    ///   <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes>;
    /// - `tests/data/wycheproof-256_pass.blb` and `wycheproof-256_fail.blb`:
    ///   the 256-bit-key, 96-bit-IV cases of Wycheproof `aes_gcm_test.json`
    ///   (<https://github.com/C2SP/wycheproof/tree/main/testvectors_v1>), made
    ///   by RustCrypto's `wycheproof2blb`, 5 blobs a case: key, IV,
    ///   associated data, plaintext, ciphertext and tag.
    #[test]
    fn t11_aes256gcm_cavp_and_wycheproof_vectors() {
        let read = |name: &str, sha: &str| {
            let path = format!(
                "{}/../../vendor/crates-io/aes-gcm-0.11.1/tests/{name}",
                env!("CARGO_MANIFEST_DIR")
            );
            let file = std::fs::read(path).unwrap();
            assert_eq!(crate::hash::sha256(&[&file]).expose(), hex(sha), "{name}");
            file
        };
        // Sealed with the case's IV, the plaintext gives IV, ciphertext and
        // tag, and that opens again.
        let pass = |key: &[u8], iv: &[u8], aad: &[u8], pt: &[u8], ct_tag: &[u8]| {
            assert_eq!((key.len(), iv.len(), ct_tag.len()), (32, 12, pt.len() + 16));
            let key = SecretBytes::new(key.to_vec());
            let want = [iv, ct_tag].concat();
            let made = seal_with(|_| Ok(SecretBytes::new(iv.to_vec())), &key, aad, pt).unwrap();
            assert_eq!(made, want);
            assert_eq!(open(&key, aad, &want).unwrap().expose(), pt);
        };
        let file = read(
            "aes256gcm.rs",
            "c474f9b86a6ee7d262e65df555bfe6009f0af675da9a06da365acebc07bbac0c",
        );
        // Each field is `b""` or `&hex!("...")`.
        let field = |case: &str, name: &str| {
            let rest = &case[case.find(&format!(" {name}: ")).unwrap() + name.len() + 3..];
            if rest.starts_with("b\"\"") {
                return Vec::new();
            }
            assert!(rest.starts_with("&hex!("), "{name}");
            let rest = &rest[rest.find('"').unwrap() + 1..];
            hex(&rest[..rest.find('"').unwrap()])
        };
        let cases: Vec<&str> = std::str::from_utf8(&file)
            .unwrap()
            .split("TestVector {")
            .skip(1)
            .collect();
        assert_eq!(cases.len(), 375);
        for case in cases {
            let [key, iv, pt, aad, ct, tag] =
                ["key", "nonce", "plaintext", "aad", "ciphertext", "tag"].map(|n| field(case, n));
            pass(&key, &iv, &aad, &pt, &[ct, tag].concat());
        }
        let file = read(
            "data/wycheproof-256_pass.blb",
            "e2580efd9a277f2fae1701df23933107697f9ab949d6d65bb408285ce97ef17e",
        );
        let blobs = crate::sign::tests::blobby(&file);
        assert_eq!(blobs.len(), 21 * 5);
        for c in blobs.chunks(5) {
            pass(c[0], c[1], c[2], c[3], c[4]);
        }
        let file = read(
            "data/wycheproof-256_fail.blb",
            "779a9c81ecf5b5099036c7b3f354bd5875122e2f26d0db060ad5a7b8d221199a",
        );
        let blobs = crate::sign::tests::blobby(&file);
        assert_eq!(blobs.len(), 27 * 5);
        for c in blobs.chunks(5) {
            assert_eq!((c[0].len(), c[1].len()), (32, 12));
            let key = SecretBytes::new(c[0].to_vec());
            let wrapped = [c[1], c[4]].concat();
            assert_eq!(
                open(&key, c[2], &wrapped).err(),
                Some(Error::WrapInvalid),
                "{c:02x?}"
            );
        }
    }

    #[test]
    fn cry04_14_one_changed_byte_of_a_wrap_or_its_data_fails() {
        // CRY-04.7: any change of the nonce, ciphertext or tag (every byte),
        // the associated data or the key gives WrapInvalid.
        let [key, iv, pt, aad, ct, tag] = GCM_SPEC[3];
        let (key, aad) = (SecretBytes::new(hex(key)), hex(aad));
        let wrapped = [hex(iv), hex(ct), hex(tag)].concat();
        assert_eq!(open(&key, &aad, &wrapped).unwrap().expose(), hex(pt));
        for i in 0..wrapped.len() {
            let mut w = wrapped.clone();
            w[i] ^= 0x80;
            assert_eq!(
                open(&key, &aad, &w).err(),
                Some(Error::WrapInvalid),
                "byte {i}"
            );
        }
        for i in 0..aad.len() {
            let mut a = aad.clone();
            a[i] ^= 1;
            assert_eq!(open(&key, &a, &wrapped).err(), Some(Error::WrapInvalid));
        }
        let mut other = key.expose().to_vec();
        other[31] ^= 1;
        assert_eq!(
            open(&SecretBytes::new(other), &aad, &wrapped).err(),
            Some(Error::WrapInvalid)
        );
    }

    #[test]
    fn t12_a_thousand_wraps_have_a_thousand_nonces() {
        let key = SecretBytes::new(vec![0x42; 32]);
        let nonces: std::collections::BTreeSet<Vec<u8>> = (0..1000)
            .map(|_| seal(&key, b"ad", b"demo blob").unwrap()[..NONCE].to_vec())
            .collect();
        assert_eq!(nonces.len(), 1000);
    }

    #[test]
    fn limits_and_lengths() {
        let key = SecretBytes::new(vec![1; 32]);
        let fail = |_| Err(Error::RandomSource);
        // Checked before any work: the draw would fail.
        assert_eq!(
            seal_with(fail, &key, b"", &vec![0; MAX_PLAINTEXT + 1]).err(),
            Some(Error::TooLarge)
        );
        assert_eq!(
            seal_with(fail, &SecretBytes::new(vec![1; 31]), b"", b"x").err(),
            Some(Error::KeyLength)
        );
        let big = seal(&key, b"", &vec![7; MAX_PLAINTEXT]).unwrap();
        assert_eq!(open(&key, b"", &big).unwrap().len(), MAX_PLAINTEXT);
        // A wrap over the limit that would open, made with aes-gcm itself:
        // refused all the same.
        let cipher = Aes256Gcm::new_from_slice(key.expose()).unwrap();
        let mut body = vec![7; MAX_PLAINTEXT + 1];
        let nonce = [9u8; NONCE];
        let tag = cipher
            .encrypt_inout_detached((&nonce).into(), b"", InOutBuf::from(body.as_mut_slice()))
            .unwrap();
        let too_big = [&nonce[..], &body, &tag].concat();
        assert_eq!(open(&key, b"", &too_big).err(), Some(Error::WrapInvalid));
        for n in [0, 11, 12, 27] {
            assert_eq!(
                open(&key, b"", &vec![0; n]).err(),
                Some(Error::WrapInvalid),
                "{n}"
            );
        }
        assert_eq!(
            open(&SecretBytes::new(vec![1; 16]), b"", &big).err(),
            Some(Error::KeyLength)
        );
    }

    #[test]
    fn t17_a_failed_random_draw_makes_nothing() {
        let key = SecretBytes::new(vec![1; 32]);
        assert_eq!(
            seal_with(|_| Err(Error::RandomSource), &key, b"", b"demo").err(),
            Some(Error::RandomSource)
        );
    }

    /// RFC 5869 appendix A, test cases 1 to 3 (IKM, salt, info, OKM), from
    /// <https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A>. The OKM of
    /// a 32-byte output is the first 32 bytes of each case's longer OKM.
    #[test]
    fn t13_hkdf_sha256_rfc5869_vectors() {
        let range = |a: u8, b: u8| (a..=b).collect::<Vec<u8>>();
        let cases = [
            (
                vec![0x0b; 22],
                hex("000102030405060708090a0b0c"),
                hex("f0f1f2f3f4f5f6f7f8f9"),
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            ),
            (
                range(0x00, 0x4f),
                range(0x60, 0xaf),
                range(0xb0, 0xff),
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                vec![0x0b; 22],
                vec![],
                vec![],
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ),
        ];
        for (ikm, salt, info, okm) in cases {
            let out = hkdf_sha256(&salt, &SecretBytes::new(ikm), &info).unwrap();
            assert_eq!(out.expose(), &hex(okm)[..32]);
        }
    }

    /// T14: SYN-06 T03's inputs (password `demo`, salt 32 bytes of 0x01,
    /// `S_acct` 32 bytes of 0x02, `account_id` 16 bytes of 0x03). The value
    /// was computed outside Larsal with an independent Argon2id written from
    /// RFC 9106 on Python's hashlib.blake2b (checked first against RFC 9106
    /// section 5.3) and HKDF from Python's hmac module (RFC 5869 steps).
    #[test]
    fn t14_two_secret_key_known_value() {
        let k = account_key(
            &SecretString::new("demo".into()),
            &[0x01; 32],
            &SecretBytes::new(vec![0x02; 32]),
            &[0x03; 16],
        )
        .unwrap();
        assert_eq!(k.expose(), hex(TWO_SECRET_KEY));
        assert_eq!(format!("{k:?}"), "[hidden]");
        assert_eq!(
            account_key(
                &SecretString::new("demo".into()),
                &[0x01; 32],
                &SecretBytes::new(vec![0x02; 31]),
                &[0x03; 16],
            )
            .err(),
            Some(Error::KeyLength)
        );
    }

    const TWO_SECRET_KEY: &str = "8b6010029fcc980d13724ef292cb837349560f329001e61caba7a12e549fbed6";

    #[test]
    fn cry04_10_secrets_print_nothing() {
        let key = SecretBytes::new(vec![1; 32]);
        let opened = open(&key, b"", &seal(&key, b"", b"demo").unwrap()).unwrap();
        assert_eq!(format!("{opened:?}"), "[hidden]");
        let okm = hkdf_sha256(b"s", &key, b"i").unwrap();
        assert_eq!(format!("{okm:?}"), "[hidden]");
    }

    proptest::proptest! {
        /// Hostile wrapped bytes give an answer, never a panic.
        #[test]
        fn hostile_open_never_panics(w in proptest::collection::vec(0u8..=255, 0..100)) {
            let key = SecretBytes::new(vec![7; 32]);
            proptest::prop_assert!(open(&key, b"ad", &w).is_err());
        }

        /// Round trip (Rust rule 10): a wrap is nonce, ciphertext and tag
        /// (12 + n + 16 bytes), open(seal(x)) == x, and one flipped byte
        /// gives WrapInvalid.
        #[test]
        fn seal_open_round_trip(
            key in proptest::array::uniform32(0u8..=255),
            aad in proptest::collection::vec(0u8..=255, 0..64),
            plaintext in proptest::collection::vec(0u8..=255, 0..=MAX_PLAINTEXT),
            flip in proptest::prelude::any::<proptest::sample::Index>(),
        ) {
            let key = SecretBytes::new(key.to_vec());
            let mut wrapped = seal(&key, &aad, &plaintext).unwrap();
            proptest::prop_assert_eq!(wrapped.len(), NONCE + plaintext.len() + TAG);
            proptest::prop_assert_eq!(
                open(&key, &aad, &wrapped).unwrap().expose().to_vec(),
                plaintext
            );
            let i = flip.index(wrapped.len());
            wrapped[i] ^= 1;
            proptest::prop_assert_eq!(open(&key, &aad, &wrapped).err(), Some(Error::WrapInvalid));
        }
    }
}
