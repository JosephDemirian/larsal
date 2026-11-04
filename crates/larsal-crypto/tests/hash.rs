//! Story E2-S3: SHA-1, SHA-256 and SHA-512, one-shot and streaming.
//!
//! Vector sources (every expected value was also cross-checked with
//! `python3 -I` hashlib on this Mac):
//! - FIPS 180-4 / NIST "Examples with Intermediate Values" for SHA-1,
//!   SHA-256 and SHA-512: "abc", the 448-bit message
//!   "abcdbcdecdefdefg...nopq", the 896-bit message (SHA-512 example),
//!   one million "a".
//! - The NIST long-message test (the 64-byte pattern repeated 16,777,216
//!   times, 1 GiB), for streaming.

use larsal_crypto::hash::{Algorithm, Hasher, sha1, sha256, sha512};
use proptest::prelude::*;

const M448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const M896: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn one_shot(alg: Algorithm, data: &[u8]) -> Vec<u8> {
    let d = match alg {
        Algorithm::Sha1 => sha1(&[data]),
        Algorithm::Sha256 => sha256(&[data]),
        Algorithm::Sha512 => sha512(&[data]),
    };
    d.expose().to_vec()
}

fn streamed(alg: Algorithm, data: &[u8], piece: usize) -> Vec<u8> {
    let mut h = Hasher::new(alg);
    for chunk in data.chunks(piece) {
        h.update(chunk);
    }
    h.finalize().expose().to_vec()
}

/// Checks one-shot, streamed in odd pieces, and split into parts.
fn check(alg: Algorithm, data: &[u8], want: &str) {
    let want = hex(want);
    assert_eq!(one_shot(alg, data), want, "{alg:?} one-shot");
    assert_eq!(streamed(alg, data, 7), want, "{alg:?} streamed");
    let (a, b) = data.split_at(data.len() / 3);
    let parts = match alg {
        Algorithm::Sha1 => sha1(&[a, b]),
        Algorithm::Sha256 => sha256(&[a, b]),
        Algorithm::Sha512 => sha512(&[a, b]),
    };
    assert_eq!(parts.expose(), want.as_slice(), "{alg:?} parts");
}

// FIPS 180-4 examples, SHA-1.
#[test]
fn sha1_fips_180_4_vectors() {
    check(
        Algorithm::Sha1,
        b"abc",
        "a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d",
    );
    check(
        Algorithm::Sha1,
        M448,
        "84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1",
    );
    check(
        Algorithm::Sha1,
        &[b'a'; 1_000_000],
        "34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f",
    );
}

// FIPS 180-4 examples, SHA-256.
#[test]
fn sha256_fips_180_4_vectors() {
    check(
        Algorithm::Sha256,
        b"abc",
        "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",
    );
    check(
        Algorithm::Sha256,
        M448,
        "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1",
    );
    check(
        Algorithm::Sha256,
        &[b'a'; 1_000_000],
        "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0",
    );
}

// FIPS 180-4 examples, SHA-512 ("abc", the 896-bit message, one million "a");
// the 448-bit message from the NIST SHA-512 test set.
#[test]
fn sha512_fips_180_4_vectors() {
    check(
        Algorithm::Sha512,
        b"abc",
        "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a
         2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f",
    );
    check(
        Algorithm::Sha512,
        M448,
        "204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335
         96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445",
    );
    check(
        Algorithm::Sha512,
        M896,
        "8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018
         501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909",
    );
    check(
        Algorithm::Sha512,
        &[b'a'; 1_000_000],
        "e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb
         de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b",
    );
}

// Empty input: FIPS 180-4 padding of a zero-length message (NIST test set).
#[test]
fn empty_input_and_no_parts() {
    let sha256_empty = "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855";
    check(Algorithm::Sha256, b"", sha256_empty);
    assert_eq!(sha256(&[]).expose(), hex(sha256_empty).as_slice());
    assert_eq!(
        Hasher::new(Algorithm::Sha256).finalize().expose(),
        hex(sha256_empty).as_slice()
    );
    // SHA-1 and SHA-512 of the empty message (NIST test set; cross-checked
    // with python3 -I hashlib).
    check(
        Algorithm::Sha1,
        b"",
        "da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709",
    );
    check(
        Algorithm::Sha512,
        b"",
        "cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce
         47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e",
    );
    assert_eq!(sha1(&[]).len(), 20);
    assert_eq!(sha512(&[]).len(), 64);
}

// Streaming of large input: NIST long-message test, 1 GiB in 1 MiB pieces.
#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn streaming_one_gib_nist_long_message() {
    let piece = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_384);
    assert_eq!(piece.len(), 1 << 20);
    let mut hs = [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512].map(Hasher::new);
    for _ in 0..1024 {
        for h in &mut hs {
            h.update(&piece);
        }
    }
    let [h1, h256, h512] = hs;
    assert_eq!(
        h1.finalize().expose(),
        hex("7789f0c9 ef7bfc40 d9331114 3dfbe69e 2017f592").as_slice()
    );
    assert_eq!(
        h256.finalize().expose(),
        hex("50e72a0e 26442fe2 552dc393 8ac58658 228c0cbf b1d2ca87 2ae43526 6fcd055e").as_slice()
    );
    assert_eq!(
        h512.finalize().expose(),
        hex(
            "b47c933421ea2db1 49ad6e10fce6c7f9 3d0752380180ffd7 f4629a712134831d
             77be6091b819ed35 2c2967a2e2d4fa50 50723c9630691f1a 05a7281dbe6c1086"
        )
        .as_slice()
    );
}

fn algorithm() -> impl Strategy<Value = Algorithm> {
    prop_oneof![
        Just(Algorithm::Sha1),
        Just(Algorithm::Sha256),
        Just(Algorithm::Sha512)
    ]
}

proptest! {
    // Round trip: streaming in any split equals one-shot.
    #[test]
    fn streaming_equals_one_shot(
        alg in algorithm(),
        data in proptest::collection::vec(any::<u8>(), 0..2048),
        cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..8),
    ) {
        let mut at: Vec<usize> = cuts.iter().map(|c| c.index(data.len() + 1)).collect();
        at.sort_unstable();
        let mut h = Hasher::new(alg);
        let mut start = 0;
        for &end in &at {
            h.update(&data[start..end]);
            start = end;
        }
        h.update(&data[start..]);
        prop_assert_eq!(h.finalize().expose().to_vec(), one_shot(alg, &data));
    }

    // Parts are hashed as if joined.
    #[test]
    fn parts_equal_joined(
        a in proptest::collection::vec(any::<u8>(), 0..300),
        b in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let joined = [a.as_slice(), b.as_slice()].concat();
        prop_assert_eq!(sha256(&[&a, &b]), sha256(&[&joined]));
        prop_assert_eq!(sha512(&[&a, &b]), sha512(&[&joined]));
        prop_assert_eq!(sha1(&[&a, &b]), sha1(&[&joined]));
    }
}
