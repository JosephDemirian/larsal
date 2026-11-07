//! The primitives of the file format (E22-S3): RFC vectors for each one, the
//! refusals FIL-01 and FIL-03 ask of this layer, and the new base64 form.

use larsal_crypto::base64::{self, Form};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{Error, aead, bech32, bridge::Secret, kdf, wrap};
use std::time::{Duration, Instant};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

// RFC 8439 section 2.8.2.
const AEAD_PT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
const AEAD_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
const AEAD_NONCE: &str = "070000004041424344454647";
const AEAD_CT: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
3ff4def08e4b7a9de576d26586cec64b6116";
const AEAD_TAG: &str = "1ae10b594f09e26a7e902ecbd0600691";

fn aead_key() -> SecretBytes {
    SecretBytes::new((0x80..=0x9f).collect())
}

#[test]
fn rfc8439_2_8_2_seal_gives_the_published_ciphertext_and_tag() {
    let nonce: [u8; 12] = hex(AEAD_NONCE).try_into().unwrap();
    let mut data = AEAD_PT.to_vec();
    let tag = aead::seal_in_place(&aead_key(), &nonce, &hex(AEAD_AAD), &mut data).unwrap();
    assert_eq!(data, hex(AEAD_CT));
    assert_eq!(tag.to_vec(), hex(AEAD_TAG));
}

#[test]
fn rfc8439_2_8_2_open_gives_the_plaintext_and_a_change_leaves_the_data_alone() {
    let nonce: [u8; 12] = hex(AEAD_NONCE).try_into().unwrap();
    let tag: [u8; 16] = hex(AEAD_TAG).try_into().unwrap();
    let aad = hex(AEAD_AAD);
    let mut data = hex(AEAD_CT);
    aead::open_in_place(&aead_key(), &nonce, &aad, &mut data, &tag).unwrap();
    assert_eq!(data, AEAD_PT);

    let ct = hex(AEAD_CT);
    let mut bad = ct.clone();
    bad[7] ^= 1;
    let keep = bad.clone();
    assert_eq!(
        aead::open_in_place(&aead_key(), &nonce, &aad, &mut bad, &tag),
        Err(Error::Decrypt)
    );
    assert_eq!(bad, keep, "a failed open leaves the data as it was");
    let mut flip = tag;
    flip[15] ^= 0x80;
    let mut data = ct.clone();
    assert_eq!(
        aead::open_in_place(&aead_key(), &nonce, &aad, &mut data, &flip),
        Err(Error::Decrypt)
    );
    let mut other_nonce = nonce;
    other_nonce[11] ^= 1;
    assert_eq!(
        aead::open_in_place(&aead_key(), &other_nonce, &aad, &mut data, &tag),
        Err(Error::Decrypt)
    );
    assert_eq!(
        aead::open_in_place(&aead_key(), &nonce, b"", &mut data, &tag),
        Err(Error::Decrypt)
    );
    assert_eq!(data, ct);
}

#[test]
fn aead_refuses_a_key_that_is_not_32_bytes() {
    let short = SecretBytes::new(vec![1; 31]);
    let mut data = [0u8; 4];
    assert_eq!(
        aead::seal_in_place(&short, &[0; 12], b"", &mut data),
        Err(Error::KeyLength)
    );
    assert_eq!(
        aead::open_in_place(&short, &[0; 12], b"", &mut data, &[0; 16]),
        Err(Error::KeyLength)
    );
}

// RFC 7914 section 12, all four vectors. The last takes 1 GiB, the ceiling.
#[test]
fn rfc7914_section_12_every_vector() {
    type Case = (&'static [u8], &'static [u8], u8, u32, u32, &'static str);
    let cases: [Case; 4] = [
        (
            b"",
            b"",
            4,
            1,
            1,
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
        ),
        (
            b"password",
            b"NaCl",
            10,
            8,
            16,
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
             2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
        ),
        (
            b"pleaseletmein",
            b"SodiumChloride",
            14,
            8,
            1,
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2\
             d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
        ),
        (
            b"pleaseletmein",
            b"SodiumChloride",
            20,
            8,
            1,
            "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa47\
             8e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4",
        ),
    ];
    for (pw, salt, log_n, r, p, want) in cases {
        let got = kdf::scrypt(pw, salt, log_n, r, p, 64).unwrap();
        assert_eq!(got.expose(), hex(want), "log_n {log_n}");
    }
}

// FIL-03.2 at this layer: refused at once, not after the memory is taken.
#[test]
fn scrypt_refuses_a_cost_out_of_range_at_once() {
    let start = Instant::now();
    for (log_n, r, p) in [
        (21, 8, 1),
        (20, 8, 2),
        (20, 16, 1),
        (0, 8, 1),
        (1, 0, 1),
        (1, 8, 0),
        (63, 8, 1),
        (64, 8, 1),
        (255, 8, 1),
        (1, u32::MAX, u32::MAX),
    ] {
        assert_eq!(
            kdf::scrypt(b"demo", b"salt", log_n, r, p, 32).map(|_| ()),
            Err(Error::KdfCost),
            "{log_n} {r} {p}"
        );
    }
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(
        kdf::scrypt(b"demo", b"salt", 1, 8, 1, 0).map(|_| ()),
        Err(Error::KeyLength)
    );
}

// RFC 7748 section 5.2 (the scalar and point vector) and section 6.1.
#[test]
fn rfc7748_x25519_through_from_bytes() {
    let k = Secret::from_bytes(SecretBytes::new(hex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    )))
    .unwrap();
    let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    assert_eq!(
        k.agree(&u).unwrap().expose(),
        hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    );

    let alice = Secret::from_bytes(SecretBytes::new(hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    )))
    .unwrap();
    let bob = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    assert_eq!(
        alice.public(),
        hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        alice.agree(&bob).unwrap().expose(),
        hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
}

#[test]
fn from_bytes_refuses_a_key_that_is_not_32_bytes() {
    for len in [0, 31, 33] {
        assert_eq!(
            Secret::from_bytes(SecretBytes::new(vec![1; len])).map(|_| ()),
            Err(Error::KeyLength)
        );
    }
}

// RFC 5869 appendix A.1, through the call the file format uses.
#[test]
fn rfc5869_a1_through_hkdf_sha256() {
    let ikm = SecretBytes::new(vec![0x0b; 22]);
    let got = wrap::hkdf_sha256(
        &hex("000102030405060708090a0b0c"),
        &ikm,
        &hex("f0f1f2f3f4f5f6f7f8f9"),
    )
    .unwrap();
    assert_eq!(
        got.expose(),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
    );
}

// BIP-173's test string and a 32-byte value made by the published encoder.
#[test]
fn bech32_reads_and_writes_the_original_checksum_only() {
    let empty = bech32::decode("a", "a12uel5l", 0).unwrap();
    assert!(empty.is_empty());
    assert_eq!(bech32::decode("A", "A12UEL5L", 0).unwrap().len(), 0);
    let data = SecretBytes::new((0u8..32).collect());
    let lower = bech32::encode_lower("demo", data.expose()).unwrap();
    assert!(lower.starts_with("demo1"));
    assert_eq!(
        bech32::decode("demo", &lower, 32).unwrap().expose(),
        data.expose()
    );
    let upper = bech32::encode_upper_secret("demo-", &data).unwrap();
    assert!(upper.expose().starts_with("DEMO-1"));
    assert_eq!(upper.expose(), upper.expose().to_ascii_uppercase());
    assert_eq!(
        bech32::decode("demo-", upper.expose(), 32)
            .unwrap()
            .expose(),
        data.expose()
    );
    assert_eq!(lower.len(), 5 + 52 + 6);
}

#[test]
fn bech32_refuses_bech32m_mixed_case_and_wrong_shapes() {
    let lower = bech32::encode_lower("demo", &[7; 32]).unwrap();
    // BIP-350's test string has a Bech32m checksum.
    assert_eq!(
        bech32::decode("a", "a1lqfn3a", 0).map(|_| ()),
        Err(Error::Bech32)
    );
    let mut mixed = lower.clone().into_bytes();
    mixed[10] = mixed[10].to_ascii_uppercase();
    if mixed[10] == lower.as_bytes()[10] {
        mixed[11] = mixed[11].to_ascii_uppercase();
    }
    for (hrp, text, len) in [
        ("demo", String::from_utf8(mixed).unwrap(), 32),
        ("other", lower.clone(), 32),
        ("demo", lower.clone(), 31),
        ("demo", lower.clone(), 33),
        ("demo", format!("{lower}q"), 32),
        ("demo", "demo1".repeat(60), 32),
        ("demo", String::new(), 0),
    ] {
        assert_eq!(
            bech32::decode(hrp, &text, len).map(|_| ()),
            Err(Error::Bech32),
            "{hrp} {text}"
        );
    }
    // Set padding bits: 31 bytes take 50 characters and 2 spare bits.
    let good = bech32::encode_lower("demo", &[0; 31]).unwrap();
    assert!(bech32::decode("demo", &good, 31).is_ok());
    // Written by a separate script (testdata/make_derived.py of larsal-files):
    // the same bytes with a valid checksum, then with nonzero padding bits.
    let same = "demo-1qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurs6c8rr3";
    assert_eq!(bech32::encode_lower("demo-", &[7; 32]).unwrap(), same);
    assert_eq!(bech32::decode("demo-", same, 32).unwrap().expose(), [7; 32]);
    let bad_padding = "demo-1qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qur38wnk7r";
    assert_eq!(
        bech32::decode("demo-", bad_padding, 32).map(|_| ()),
        Err(Error::Bech32)
    );
    assert_eq!(
        bech32::decode("demo", &"q".repeat(257), 32).map(|_| ()),
        Err(Error::Bech32)
    );
}

#[test]
fn the_secret_encoder_gives_a_type_that_hides_its_text() {
    let s: SecretString =
        bech32::encode_upper_secret("demo-", &SecretBytes::new(vec![1; 32])).unwrap();
    assert_eq!(format!("{s:?}"), "[hidden]");
    assert_eq!(format!("{:?}", Error::Bech32), "Bech32");
}

#[test]
fn unpadded_form_is_canonical() {
    assert_eq!(base64::encode(Form::Unpadded, b"A"), "QQ");
    assert_eq!(base64::decode(Form::Unpadded, "QQ").unwrap(), b"A");
    for bad in ["QQ==", "QQ=", "QR", "Q", "Q Q", "QQ\n", "Q-"] {
        assert_eq!(
            base64::decode(Form::Unpadded, bad),
            Err(Error::Base64),
            "{bad}"
        );
    }
    let mut out = [0u8; 2];
    assert_eq!(base64::decode_unpadded_into(b"QUI", &mut out), Ok(2));
    assert_eq!(&out, b"AB");
    assert_eq!(
        base64::decode_unpadded_into(b"QUJD", &mut out),
        Err(Error::Base64),
        "the buffer is too short"
    );
    for bad in [&b"QR"[..], b"QQ==", b"QQ="] {
        assert_eq!(
            base64::decode_unpadded_into(bad, &mut out),
            Err(Error::Base64)
        );
    }
    assert_eq!(base64::decode_unpadded_into(b"", &mut out), Ok(0));
}
