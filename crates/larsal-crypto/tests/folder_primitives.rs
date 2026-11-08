//! E23-S3, FIL-04.12: known answers for the folder format's primitives, through
//! larsal-crypto only, before any format vector. RFC 3394 section 4.6, RFC 7914 N/r
//! validity and NIST CAVP AES-256-GCM (96-bit nonce, 128-bit tag; a chosen row per
//! length pair here, every row of the two response files in the ignored test). RFC
//! 5297 is in `src/siv.rs`, RFC 7914 section 12 in `file_primitives.rs`.

use larsal_crypto::secret::SecretBytes;
use larsal_crypto::{Error, base64, gcm, kdf, keywrap, mac};
use std::time::{Duration, Instant};

fn hex(text: &str) -> Vec<u8> {
    let t: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    t.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn rfc3394_4_6_wraps_and_unwraps_256_bits_under_a_256_bit_kek() {
    let kek = SecretBytes::new(hex(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    ));
    let key = hex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    let want =
        hex("28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21");
    let wrapped = keywrap::wrap(&kek, &SecretBytes::new(key.clone())).unwrap();
    assert_eq!(wrapped.to_vec(), want);
    assert_eq!(keywrap::unwrap(&kek, &wrapped).unwrap().expose(), &key[..]);
}

#[test]
fn fil04_t03_any_change_to_a_wrapped_key_gives_no_key_data() {
    let kek = SecretBytes::new(vec![3u8; 32]);
    let wrapped = keywrap::wrap(&kek, &SecretBytes::new(vec![5u8; 32])).unwrap();
    for at in 0..wrapped.len() {
        let mut bad = wrapped;
        bad[at] ^= 1;
        assert_eq!(
            keywrap::unwrap(&kek, &bad).err(),
            Some(Error::WrapInvalid),
            "{at}"
        );
    }
    for len in [0, 8, 32, 39, 41, 48] {
        assert_eq!(
            keywrap::unwrap(&kek, &vec![0u8; len]).err(),
            Some(Error::WrapInvalid)
        );
    }
    let other = SecretBytes::new(vec![4u8; 32]);
    assert_eq!(
        keywrap::unwrap(&other, &wrapped).err(),
        Some(Error::WrapInvalid)
    );
    assert_eq!(
        keywrap::wrap(&kek, &SecretBytes::new(vec![5u8; 24])).err(),
        Some(Error::KeyLength)
    );
    assert_eq!(
        keywrap::wrap(&SecretBytes::new(vec![5u8; 24]), &other).err(),
        Some(Error::KeyLength)
    );
}

/// FIL-04.3, LD-376: validity apart from the ceilings, with no allocation or work.
#[test]
fn fil04_t03_rfc7914_validity_is_not_the_ceiling() {
    // Valid and within the ceiling.
    for (log_n, r) in [(15u8, 1u32), (1, 1), (20, 8), (18, 32), (15, 8)] {
        assert_eq!(kdf::scrypt_settings(log_n, r, 1), Ok(()), "{log_n} {r}");
    }
    // Fits the ceiling, invalid by RFC 7914.
    let start = Instant::now();
    assert_eq!(kdf::scrypt_settings(16, 1, 1), Err(Error::KdfSettings));
    assert_eq!(
        kdf::scrypt(b"demo", b"salt", 16, 1, 1, 32).map(|_| ()),
        Err(Error::KdfSettings)
    );
    assert_eq!(
        kdf::scrypt(b"demo", b"salt", 19, 1, 1, 32).map(|_| ()),
        Err(Error::KdfSettings)
    );
    assert!(start.elapsed() < Duration::from_secs(1), "no work ran");
    // Valid by the RFC, over the ceiling.
    assert_eq!(kdf::scrypt_settings(21, 8, 1), Err(Error::KdfCost));
    assert_eq!(kdf::scrypt_settings(18, 33, 1), Err(Error::KdfCost));
    // Every overflow is an answer, not a wrap.
    assert_eq!(
        kdf::scrypt_settings(255, u32::MAX, u32::MAX),
        Err(Error::KdfCost)
    );
    assert_eq!(kdf::scrypt_settings(0, 1, 1), Err(Error::KdfCost));
    // The valid control at r = 1 really runs: the RFC's own first row.
    assert!(kdf::scrypt(b"", b"", 4, 1, 1, 64).is_ok());
}

/// Key, nonce, plaintext, associated data, ciphertext, tag.
const GCM_ROWS: [(&str, &str, &str, &str, &str, &str); 6] = [
    (
        "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        "516c33929df5a3284ff463d7",
        "",
        "",
        "",
        "bdc1ac884d332457a1d2664f168c76f0",
    ),
    (
        "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223",
        "d79cf22d504cc793c3fb6c8a",
        "",
        "b96baa8c1c75a671bfb2d08d06be5f36",
        "",
        "3e5d486aa2e30b22e040b85723a06e76",
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
        "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b",
        "ac93a1a6145299bde902f21a",
        "2d71bcfa914e4ac045b2aa60955fad24",
        "1e0889016f67601c8ebea4943bc23ad6",
        "8995ae2e6df3dbf96fac7b7137bae67f",
        "eca5aa77d51d4a0a14d9c51e1da474ab",
    ),
    (
        "24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f",
        "9ff18563b978ec281b3f2794",
        "27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb158bd9abb3868fdc0d0b074b5f01b2c",
        "adb5ec720ccf9898500028bf34afccbcaca126ef",
        "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae82057ad55994cf59ad7f67c0fa5e85fab8",
        "bc95c532fecc594c36d1550286a7a3f0",
    ),
    (
        "148579a3cbca86d5520d66c0ec71ca5f7e41ba78e56dc6eebd566fed547fe691",
        "b08a5ea1927499c6ecbfd4e0",
        "9d0b15fdf1bd595f91f8b3abc0f7dec927dfd4799935a1795d9ce00c9b879434420fe42c275a7cd7b39d638fb81ca52b49dc41",
        "e4f963f015ffbb99ee3349bbaf7e8e8e6c2a71c230a48f9d59860a29091d2747e01a5ca572347e247d25f56ba7ae8e05cde2be3c97931292c02370208ecd097ef692687fecf2f419d3200162a6480a57dad408a0dfeb492e2c5d",
        "2097e372950a5e9383c675e89eea1c314f999159f5611344b298cda45e62843716f215f82ee663919c64002a5c198d7878fd3f",
        "adbecdb0d5c2224d804d2886ff9a5760",
    ),
];

fn gcm_row(key: &str, nonce: &str, plain: &str, aad: &str, cipher: &str, tag: &str) {
    let key = SecretBytes::new(hex(key));
    let nonce: [u8; 12] = hex(nonce).try_into().unwrap();
    let (plain, aad, cipher) = (hex(plain), hex(aad), hex(cipher));
    let tag: [u8; 16] = hex(tag).try_into().unwrap();
    let mut data = plain.clone();
    let got = gcm::seal_in_place(&key, &nonce, &aad, &mut data).unwrap();
    assert_eq!(data, cipher);
    assert_eq!(got, tag);
    gcm::open_in_place(&key, &nonce, &aad, &mut data, &tag).unwrap();
    assert_eq!(data, plain);
}

#[test]
fn nist_cavp_gcm_256_chosen_rows() {
    for (k, n, p, a, c, t) in GCM_ROWS {
        gcm_row(k, n, p, a, c, t);
    }
}

/// gcmDecrypt256: a row marked FAIL and a good one.
#[test]
fn nist_cavp_gcm_256_decrypt_rows() {
    let key = SecretBytes::new(hex(
        "e5a8123f2e2e007d4e379ba114a2fb66e6613f57c72d4e4f024964053028a831",
    ));
    let nonce: [u8; 12] = hex("51e43385bf533e168427e1ad").try_into().unwrap();
    let tag: [u8; 16] = hex("38fe845c66e66bdd884c2aecafd280e6").try_into().unwrap();
    assert_eq!(
        gcm::open_in_place(&key, &nonce, b"", &mut [], &tag),
        Err(Error::Decrypt)
    );
    let key = SecretBytes::new(hex(
        "4c8ebfe1444ec1b2d503c6986659af2c94fafe945f72c1e8486a5acfedb8a0f8",
    ));
    let nonce: [u8; 12] = hex("473360e0ad24889959858995").try_into().unwrap();
    let tag: [u8; 16] = hex("c26a379b6d98ef2852ead8ce83a833a7").try_into().unwrap();
    let mut data = hex("d2c78110ac7e8f107c0df0570bd7c90c");
    gcm::open_in_place(&key, &nonce, b"", &mut data, &tag).unwrap();
    assert_eq!(data, hex("7789b41cb3ee548814ca0b388c10b343"));
}

/// FIL-04.6: an open that fails leaves the ciphertext as it was: no early plaintext.
#[test]
fn fil04_t07_a_failed_open_leaves_the_buffer_unchanged() {
    let key = SecretBytes::new(vec![1u8; 32]);
    let nonce = [2u8; 12];
    let plain = b"demo plaintext demo plaintext".to_vec();
    let mut data = plain.clone();
    let tag = gcm::seal_in_place(&key, &nonce, b"aad", &mut data).unwrap();
    let sealed = data.clone();
    assert_ne!(sealed, plain);
    let mut bad_tag = tag;
    bad_tag[15] ^= 1;
    for (n, a, t) in [
        ([3u8; 12], &b"aad"[..], tag),
        (nonce, &b"aaD"[..], tag),
        (nonce, &b"aad"[..], bad_tag),
    ] {
        assert_eq!(
            gcm::open_in_place(&key, &n, a, &mut data, &t),
            Err(Error::Decrypt)
        );
        assert_eq!(data, sealed);
    }
    assert_eq!(
        gcm::seal_in_place(&SecretBytes::new(vec![0; 16]), &nonce, b"", &mut data).err(),
        Some(Error::KeyLength)
    );
}

/// The two response files whole, when `LARSAL_NIST_DIR` names them. Not in the tree.
#[test]
#[ignore = "reads the NIST response files from LARSAL_NIST_DIR"]
fn nist_cavp_gcm_256_every_row_of_both_files() {
    let dir = std::env::var("LARSAL_NIST_DIR").unwrap();
    let (mut sealed, mut opened, mut refused) = (0, 0, 0);
    for (name, decrypting) in [
        ("gcmEncryptExtIV256.rsp", false),
        ("gcmDecrypt256.rsp", true),
    ] {
        let text = std::fs::read_to_string(format!("{dir}/{name}")).unwrap();
        let mut iv_bits = 0;
        let mut tag_bits = 0;
        for block in text.split("\n\r\n").chain(std::iter::empty()) {
            for line in block.lines() {
                let line = line.trim();
                if let Some(v) = line.strip_prefix("[IVlen = ") {
                    iv_bits = v.trim_end_matches(']').parse().unwrap();
                }
                if let Some(v) = line.strip_prefix("[Taglen = ") {
                    tag_bits = v.trim_end_matches(']').parse().unwrap();
                }
            }
            let get = |k: &str| {
                block.lines().map(str::trim).find_map(|l| {
                    l.strip_prefix(k)
                        .and_then(|r| r.strip_prefix(" ="))
                        .map(str::trim)
                })
            };
            let (Some(key), Some(iv), Some(ct), Some(aad), Some(tag)) =
                (get("Key"), get("IV"), get("CT"), get("AAD"), get("Tag"))
            else {
                continue;
            };
            if iv_bits != 96 || tag_bits != 128 {
                continue;
            }
            let fail = block.lines().any(|l| l.trim() == "FAIL");
            if decrypting {
                let k = SecretBytes::new(hex(key));
                let n: [u8; 12] = hex(iv).try_into().unwrap();
                let t: [u8; 16] = hex(tag).try_into().unwrap();
                let mut data = hex(ct);
                let got = gcm::open_in_place(&k, &n, &hex(aad), &mut data, &t);
                if fail {
                    assert_eq!(got, Err(Error::Decrypt));
                    assert_eq!(data, hex(ct));
                    refused += 1;
                } else {
                    got.unwrap();
                    assert_eq!(data, hex(get("PT").unwrap()));
                    opened += 1;
                }
            } else {
                gcm_row(key, iv, get("PT").unwrap(), aad, ct, tag);
                sealed += 1;
            }
        }
    }
    println!("sealed {sealed} opened {opened} refused {refused}");
    assert!(
        sealed >= 375 && opened > 100 && refused > 100,
        "{sealed} {opened} {refused}"
    );
}

/// A folder configuration may name HS384 or HS512 (FIL-04.1). RFC 4231 test case 1.
#[test]
fn rfc4231_case1_hmac_sha384_and_sha512_verify() {
    let key = [0x0bu8; 20];
    let t384 = hex(
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
    );
    let t512 = hex(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    );
    assert_eq!(
        mac::hmac_sha384(&key, &[b"Hi There"]).unwrap().expose(),
        &t384[..]
    );
    assert!(mac::verify_hmac_sha384(&key, &[b"Hi", b" There"], &t384));
    assert!(!mac::verify_hmac_sha384(&key, &[b"Hi There!"], &t384));
    assert!(!mac::verify_hmac_sha384(&key, &[b"Hi There"], &t384[..47]));
    assert!(mac::verify_hmac_sha512(&key, &[b"Hi There"], &t512));
    assert!(!mac::verify_hmac_sha512(&key, &[b"Hi There"], &t384));
}

/// FIL-04.10: one byte string, one padded URL-safe text.
#[test]
fn fil04_t10_padded_url_base64_has_one_text() {
    let form = base64::Form::UrlPadded;
    assert_eq!(base64::encode(form, b"\xfb\xff\xfe"), "-__-");
    assert_eq!(base64::encode(form, b"\xfb"), "-w==");
    assert_eq!(base64::decode(form, "-w==").unwrap(), b"\xfb");
    for bad in ["-w", "-w=", "-x==", "+w==", "-w==="] {
        assert_eq!(
            base64::decode(form, bad).err(),
            Some(Error::Base64),
            "{bad}"
        );
    }
}
