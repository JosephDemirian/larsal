//! Protected-field keystream tests (story E2-S6; spec FMT-09, CRY-01.14,
//! CRY-01.15): standard vectors and every FMT-09 and CRY-01 keystream case.
//!
//! The FMT-09 key and nonce derivation is larsal-crypto's own
//! (`FieldStream::*_from_stream_key`): ChaCha20 key and nonce =
//! SHA-512(stream key) bytes 0-31 and 32-43; Salsa20 key = SHA-256(stream
//! key), nonce = E8 30 09 4B 97 20 5D 2A. `derivation_matches_fmt09` checks
//! it against sha2 directly.
//!
//! Cross-checks on this Mac: the ChaCha20 vectors with
//! /opt/homebrew/bin/openssl (IV = 4 zero counter bytes + nonce), the Salsa20
//! vectors with a textbook Salsa20/20 written from Bernstein's specification and with libgcrypt and libsodium (Verify)
//! (python3 -I), the hashes with python3 hashlib. All agree with the cards.

use larsal_crypto::Error;
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::stream::FieldStream;
use proptest::prelude::*;
use sha2::{Digest, Sha256, Sha512};

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// Standard base64 (RFC 4648 section 4), so the cards' stored values can be
/// used exactly as printed.
fn b64(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut bits, mut n, mut out) = (0u32, 0, Vec::new());
    for c in s.bytes().filter(|&c| c != b'=' && !c.is_ascii_whitespace()) {
        let v = ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
        bits = (bits << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    out
}

/// FMT-09.9 / CRY-01.14.
fn chacha_field(stream_key: &[u8]) -> FieldStream {
    FieldStream::chacha20_from_stream_key(&SecretBytes::new(stream_key.to_vec())).unwrap()
}

/// FMT-09.10 / CRY-01.15.
fn salsa_field(stream_key: &[u8]) -> FieldStream {
    FieldStream::salsa20_from_stream_key(&SecretBytes::new(stream_key.to_vec())).unwrap()
}

#[test]
fn derivation_matches_fmt09() {
    // The derivation written out with sha2, for any stream key length.
    for len in [0usize, 1, 32, 64, 200] {
        let sk: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let h = Sha512::digest(&sk);
        let mut want =
            FieldStream::chacha20(&SecretBytes::new(h[..32].to_vec()), &h[32..44]).unwrap();
        assert_eq!(
            keystream(&mut chacha_field(&sk), 200),
            keystream(&mut want, 200)
        );
        let k = Sha256::digest(&sk);
        let nonce = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
        let mut want = FieldStream::salsa20(&SecretBytes::new(k.to_vec()), &nonce).unwrap();
        assert_eq!(
            keystream(&mut salsa_field(&sk), 200),
            keystream(&mut want, 200)
        );
    }
}

fn xor(s: &mut FieldStream, data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    s.apply(&mut v).unwrap();
    v
}

fn keystream(s: &mut FieldStream, n: usize) -> Vec<u8> {
    xor(s, &vec![0; n])
}

/// S4 = 00 01 .. 3F (FMT-09 version 4 common vector, CRY-01 T22).
fn s4() -> Vec<u8> {
    (0u8..64).collect()
}

/// S3 = 00 01 .. 1F (FMT-09 version 3 common vector, CRY-01 T25).
fn s3() -> Vec<u8> {
    (0u8..32).collect()
}

// ---------------------------------------------------------- standard vectors

// RFC 8439 appendix A.1 #1, #2 and section 2.3.2 through the field stream:
// IETF ChaCha20, counter from 0 (blocks after the first are reached by using
// up 64 bytes).
#[test]
fn chacha20_rfc8439_vectors() {
    let zero_key = SecretBytes::new(vec![0; 32]);
    let mut s = FieldStream::chacha20(&zero_key, &[0; 12]).unwrap();
    assert_eq!(
        keystream(&mut s, 64),
        hex(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        ),
        "A.1 #1"
    );
    assert_eq!(
        keystream(&mut s, 64),
        hex(
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"
        ),
        "A.1 #2"
    );
    let k = SecretBytes::new((0u8..32).collect());
    let mut s = FieldStream::chacha20(&k, &hex("000000090000004a00000000")).unwrap();
    let _ = keystream(&mut s, 64);
    assert_eq!(
        keystream(&mut s, 64),
        hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        ),
        "2.3.2"
    );
}

// eSTREAM verified Salsa20/20 256-bit vectors: CRY-01 T24 (key F3 F4 .. 12)
// and Set 1 vector 0 (key 80 00 .. 00, also in the salsa20 crate's tests).
#[test]
fn salsa20_estream_vectors_cry01_t24() {
    let k = SecretBytes::new(hex(
        "f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112",
    ));
    let mut s = FieldStream::salsa20(&k, &[0; 8]).unwrap();
    assert_eq!(
        keystream(&mut s, 64),
        hex(
            "b4c0afa503be7fc29a62058166d56f8f5d27dc246f75b9ad8760c8c39dfd87492d3b76d5d9637f009eada14458a52dfb09815337e72672681dddc24633750d83"
        )
    );
    let mut k = vec![0; 32];
    k[0] = 0x80;
    let mut s = FieldStream::salsa20(&SecretBytes::new(k), &[0; 8]).unwrap();
    assert_eq!(
        keystream(&mut s, 64),
        hex(
            "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117"
        )
    );
}

// ------------------------------------------------- FMT-09 / CRY-01, ChaCha20

// CRY-01 T22, FMT-09 T09-03: derivation and keystream bytes 0 to 127.
#[test]
fn chacha20_field_derivation_and_keystream_fmt09_t03_cry01_t22() {
    let h = Sha512::digest(s4());
    assert_eq!(
        h.to_vec(),
        hex(
            "ee4320ebaf3fdb4f2c832b137200c08e235e0fa7bbd0eb1740c7063ba8a0d151da77e003398e1714a955d475b05e3e950b639503b452ec185de4229bc4873949"
        )
    );
    assert_eq!(h[32..44], hex("da77e003398e1714a955d475")[..], "nonce");
    let mut s = chacha_field(&s4());
    assert_eq!(
        keystream(&mut s, 64),
        hex(
            "8ce8bc610ac05ff2e3dd88b49a1404c2844f148037027476b83d58f5609adf65f8fa87d8b5f5287f6cfdbdb69adea2f942e4acf5a9ad9e860623477a73a24c4e"
        ),
        "bytes 0-63"
    );
    assert_eq!(
        keystream(&mut s, 64),
        hex(
            "3a3218fc0306b095a7e705df6cb03ffc592d2ce6e3a9ba6c5a78a8bc8b908a71d2939459f6403e659ba440eb2faa4650e378be36e898db366a2d6f28555d76e1"
        ),
        "bytes 64-127"
    );
}

// CRY-01 T23: two values in document order share one keystream.
#[test]
fn chacha20_two_values_cry01_t23() {
    let mut s = chacha_field(&s4());
    let a = xor(&mut s, b"demo-secret-1");
    let b = xor(&mut s, b"pw2");
    assert_eq!(a, hex("e88dd10e27b33a9191b8fc99ab"));
    assert_eq!(a, b64("6I3RDiezOpGRuPyZqw=="));
    assert_eq!(b, hex("6473f0"));
    assert_eq!(b, b64("ZHPw"));
}

// FMT-09 T09-06: values "pw-one", "Sécret ✓", "" (takes no bytes), "zz".
#[test]
fn chacha20_encode_values_fmt09_t06() {
    let mut s = chacha_field(&s4());
    assert_eq!(xor(&mut s, b"pw-one"), b64("/J+RDmSl"));
    let secret = "Sécret ✓".as_bytes();
    assert_eq!(secret, hex("53c3a963726574 20 e29c93").as_slice());
    assert_eq!(xor(&mut s, secret), b64("DDFKvvrR7jTmXhc="));
    assert_eq!(xor(&mut s, b""), b"");
    assert_eq!(xor(&mut s, b"zz"), b64("NW4="));
}

// FMT-09 T09-07: 128 bytes split into values of 7, 1, 12, 44 and 64 bytes
// equal the 128 bytes XORed with keystream bytes 0 to 127 in one go.
#[test]
fn chacha20_split_values_fmt09_t07() {
    let plain: Vec<u8> = (0u8..128).map(|i| i.wrapping_mul(37) ^ 0x5A).collect();
    let whole = xor(&mut chacha_field(&s4()), &plain);
    let mut s = chacha_field(&s4());
    let mut joined = Vec::new();
    let mut rest = &plain[..];
    for n in [7, 1, 12, 44, 64] {
        let (head, tail) = rest.split_at(n);
        joined.extend(xor(&mut s, head));
        rest = tail;
    }
    assert_eq!(joined, whole);
}

// FMT-09 T09-08: Notes, Password, UserName in entry "Alpha", in that order.
#[test]
fn chacha20_entry_values_fmt09_t08() {
    let mut s = chacha_field(&s4());
    assert_eq!(xor(&mut s, b"secret note"), b64("/43fE2+0f5yMqe0="));
    assert_eq!(xor(&mut s, b"pw-alpha"), b64("xO05Za70J3U="));
    assert_eq!(xor(&mut s, b"alice"), b64("4VtrFxM="));
}

// FMT-09 T09-14: the second vault, whose writer wrongly took keystream bytes
// for the unknown FooBar ("ABCD", bytes 0-3) before the password (bytes 4-9).
// The first vault's password is the T09-06 value from byte 0.
#[test]
fn chacha20_unknown_element_offsets_fmt09_t14() {
    let mut s = chacha_field(&s4());
    assert_eq!(xor(&mut s, b"ABCD"), b64("zar/JQ=="));
    assert_eq!(xor(&mut s, b"pw-one"), b64("erdynY24"));
    assert_eq!(xor(&mut chacha_field(&s4()), &b64("/J+RDmSl")), b"pw-one");
}

// FMT-09 T09-18 (41 FF 42 C3 at offset 0) and T09-35 (41 00 42 43 44, then
// "after"): decrypting gives exactly these bytes; UTF-8 handling is the
// format's job.
#[test]
fn chacha20_decrypt_raw_bytes_fmt09_t18_t35() {
    assert_eq!(
        xor(&mut chacha_field(&s4()), &b64("zRf+og==")),
        hex("41ff42c3")
    );
    let mut s = chacha_field(&s4());
    assert_eq!(xor(&mut s, &b64("zej+Ik4=")), hex("4100424344"));
    assert_eq!(xor(&mut s, &b64("oTmGhq8=")), b"after");
}

// FMT-09 T09-41: K01 to K14, consecutive keystream bytes 0 to 49.
#[test]
fn chacha20_fourteen_values_fmt09_t41() {
    let cases = [
        ("e28241", 0..=2, "bmr9"),
        ("f0808041", 3..=6, "kYpAHg=="),
        ("eda08041", 7..=10, "H0NdyQ=="),
        ("41e282", 11..=13, "9XiW"),
        ("f09f9841", 14..=17, "9F0cDg=="),
        ("c0af41", 18..=20, "1C92"),
        ("efbbbf41", 21..=24, "7c/J+Q=="),
        ("41efbbbf42", 25..=29, "fLdO39g="),
        ("efbfbe41", 30..=33, "MNpGuw=="),
        ("f490808041", 34..=38, "c0g1dWk="),
        ("8041", 39..=40, "/y0="),
        ("e282ac", 41..=43, "Hz8a"),
        ("efbbbf", 44..=46, "dWUd"),
        ("f09f98", 47..=49, "Cd18"),
    ];
    let mut s = chacha_field(&s4());
    let mut offset = 0;
    for (i, (plain, range, stored)) in cases.into_iter().enumerate() {
        assert_eq!(*range.start(), offset, "K{:02} offset", i + 1);
        let plain = hex(plain);
        assert_eq!(plain.len(), range.count());
        assert_eq!(xor(&mut s, &b64(stored)), plain, "K{:02}", i + 1);
        offset += plain.len();
    }
}

// FMT-09 T09-43: U+FEFF "A" is written as EF BB BF EF BB BF 41.
#[test]
fn chacha20_leading_bom_value_fmt09_t43() {
    let mut s = chacha_field(&s4());
    assert_eq!(xor(&mut s, &hex("efbbbfefbbbf41")), b64("Y1MDjrF/Hg=="));
}

// --------------------------------------------------- FMT-09 / CRY-01, Salsa20

// CRY-01 T25, FMT-09 T09-04: derivation and keystream bytes 0 to 63.
#[test]
fn salsa20_field_derivation_and_keystream_fmt09_t04_cry01_t25() {
    assert_eq!(
        Sha256::digest(s3()).to_vec(),
        hex("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd")
    );
    let mut s = salsa_field(&s3());
    assert_eq!(
        keystream(&mut s, 64),
        hex(
            "f9beb52962838a2c3c8227ceed909273277197ffafe66de4599f4ad62da69c1d1d257176ef84bf30437d0f072d1db132c70af1bf836ccc081918a236194ca6ae"
        )
    );
}

// CRY-01 T26: two values with the Salsa20 field stream.
#[test]
fn salsa20_two_values_cry01_t26() {
    let mut s = salsa_field(&s3());
    let a = xor(&mut s, b"demo-secret-1");
    let b = xor(&mut s, b"pw2");
    assert_eq!(a, hex("9ddbd8464ff0ef4f4ee753e3dc"));
    assert_eq!(a, b64("ndvYRk/w709O51Pj3A=="));
    assert_eq!(b, hex("e0e541"));
    assert_eq!(b, b64("4OVB"));
}

// FMT-09 T09-05: version 4 with field 1 = 2 (Salsa20) and the 64-byte S4.
#[test]
fn salsa20_with_s4_fmt09_t05() {
    assert_eq!(
        Sha256::digest(s4()).to_vec(),
        hex("fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108")
    );
    assert_eq!(
        keystream(&mut salsa_field(&s4()), 16),
        hex("0f49b2bd1392f303c02eef124cd0fda0")
    );
}

// FMT-09 T09-11 (encode "Password", "ABC") and T09-33 (decode the first value).
#[test]
fn salsa20_values_fmt09_t11_t33() {
    let mut s = salsa_field(&s3());
    assert_eq!(xor(&mut s, b"Password"), b64("qd/GWhXs+Eg="));
    assert_eq!(xor(&mut s, b"ABC"), b64("fcBk"));
    assert_eq!(
        xor(&mut salsa_field(&s3()), &b64("qd/GWhXs+Eg=")),
        b"Password"
    );
}

// ------------------------------------------------------------ length checks

#[test]
fn key_and_nonce_lengths_are_checked_before_any_work() {
    let good = SecretBytes::new(vec![1; 32]);
    for n in [0, 16, 31, 33, 64] {
        let k = SecretBytes::new(vec![1; n]);
        assert_eq!(
            FieldStream::chacha20(&k, &[0; 12]).err(),
            Some(Error::KeyLength)
        );
        assert_eq!(
            FieldStream::salsa20(&k, &[0; 8]).err(),
            Some(Error::KeyLength)
        );
        assert_eq!(
            FieldStream::chacha20(&k, &[0; 3]).err(),
            Some(Error::KeyLength)
        );
    }
    for n in [0, 8, 11, 13, 16, 24] {
        assert_eq!(
            FieldStream::chacha20(&good, &vec![0; n]).err(),
            Some(Error::IvLength)
        );
    }
    for n in [0, 7, 9, 12, 24] {
        assert_eq!(
            FieldStream::salsa20(&good, &vec![0; n]).err(),
            Some(Error::IvLength)
        );
    }
}

// ------------------------------------------------------------ property tests

proptest! {
    // One continuous keystream: values split at any lengths equal one call
    // (FMT-09.11, CRY-01.7), for both ciphers.
    #[test]
    fn split_values_equal_one_call(
        salsa in any::<bool>(),
        stream_key in prop::collection::vec(any::<u8>(), 1..80),
        data in prop::collection::vec(any::<u8>(), 0..400),
        sizes in prop::collection::vec(0usize..70, 1..10),
    ) {
        let make = |k: &[u8]| if salsa { salsa_field(k) } else { chacha_field(k) };
        let whole = xor(&mut make(&stream_key), &data);
        let mut s = make(&stream_key);
        let mut joined = Vec::new();
        let mut rest = &data[..];
        for &n in sizes.iter().cycle().take(data.len() + sizes.len()) {
            let (head, tail) = rest.split_at(n.min(rest.len()));
            joined.extend(xor(&mut s, head));
            rest = tail;
        }
        joined.extend(xor(&mut s, rest));
        prop_assert_eq!(joined, whole);
    }

    // Encrypt then decrypt with a fresh stream from the same key gives the
    // value back.
    #[test]
    fn round_trip(
        salsa in any::<bool>(),
        stream_key in prop::collection::vec(any::<u8>(), 1..80),
        data in prop::collection::vec(any::<u8>(), 0..400),
    ) {
        let make = |k: &[u8]| if salsa { salsa_field(k) } else { chacha_field(k) };
        let ct = xor(&mut make(&stream_key), &data);
        prop_assert_eq!(xor(&mut make(&stream_key), &ct), data);
    }
}
