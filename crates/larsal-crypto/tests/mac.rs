//! Story E2-S3: HMAC-SHA-256 and HMAC-SHA-1, constant-time verify; story
//! E4-S10: HMAC-SHA-512.
//!
//! Vector sources (every expected value was also cross-checked with
//! `python3 -I` hmac and hashlib on this Mac):
//! - RFC 4231 section 4, test cases 1 to 7, HMAC-SHA-256.
//! - RFC 2202 section 3, test cases 1 to 7, HMAC-SHA-1.
//! - RFC 4231 section 4, test cases 1 to 7, HMAC-SHA-512.
//! - A 64-byte demo key (the block size, the only key length the format
//!   uses): value from `python3 -I` hmac, cross-checked with /usr/bin/openssl.

use larsal_crypto::mac::{
    hmac_sha1, hmac_sha256, hmac_sha512, verify_hmac_sha1, verify_hmac_sha256,
};
use proptest::prelude::*;
use std::hint::black_box;
use std::time::Instant;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const LARGE_KEY_TEXT: &[u8] = b"Test Using Larger Than Block-Size Key - Hash Key First";

// RFC 4231 section 4.2 to 4.8 (case 5's tag is truncated to 128 bits there).
#[test]
fn hmac_sha256_rfc_4231_cases_1_to_7() {
    let key4: Vec<u8> = (0x01..=0x19).collect();
    let cases: [(&[u8], &[u8], &str); 7] = [
        (&[0x0b; 20], b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (&[0xaa; 20], &[0xdd; 50], "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (&key4, &[0xcd; 50], "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (&[0x0c; 20], b"Test With Truncation", "a3b6167473100ee06e0c796c2955552b"),
        (&[0xaa; 131], LARGE_KEY_TEXT, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (
            &[0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];
    for (i, (key, data, want)) in cases.iter().enumerate() {
        let want = hex(want);
        let tag = hmac_sha256(key, &[data]).unwrap();
        assert_eq!(tag.len(), 32);
        assert_eq!(
            &tag.expose()[..want.len()],
            want.as_slice(),
            "case {}",
            i + 1
        );
        assert!(
            verify_hmac_sha256(key, &[data], tag.expose()),
            "case {}",
            i + 1
        );
        if want.len() == 32 {
            assert!(verify_hmac_sha256(key, &[data], &want), "case {}", i + 1);
        } else {
            // A truncated tag is never accepted by verify (full length only).
            assert!(!verify_hmac_sha256(key, &[data], &want), "case {}", i + 1);
        }
    }
}

// RFC 4231 section 4.2 to 4.8, the HMAC-SHA-512 lines (case 5 truncated to
// 128 bits there).
#[test]
fn hmac_sha512_rfc_4231_cases_1_to_7() {
    let key4: Vec<u8> = (0x01..=0x19).collect();
    let cases: [(&[u8], &[u8], &str); 7] = [
        (&[0x0b; 20], b"Hi There", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
        (b"Jefe", b"what do ya want for nothing?", "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),
        (&[0xaa; 20], &[0xdd; 50], "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"),
        (&key4, &[0xcd; 50], "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"),
        (&[0x0c; 20], b"Test With Truncation", "415fad6271580a531d4179bc891d87a6"),
        (&[0xaa; 131], LARGE_KEY_TEXT, "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"),
        (
            &[0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        ),
    ];
    for (i, (key, data, want)) in cases.iter().enumerate() {
        let want = hex(want);
        let tag = hmac_sha512(key, &[data]).unwrap();
        assert_eq!(tag.len(), 64);
        assert_eq!(
            &tag.expose()[..want.len()],
            want.as_slice(),
            "case {}",
            i + 1
        );
    }
    // Parts are MACed as if joined.
    let joined = hmac_sha512(b"Jefe", &[b"what do ya want for nothing?"]).unwrap();
    let split = hmac_sha512(b"Jefe", &[b"what do ya ", b"want for nothing?"]).unwrap();
    assert_eq!(joined.expose(), split.expose());
}

// RFC 2202 section 3 (case 5's full 160-bit tag is given there too).
#[test]
fn hmac_sha1_rfc_2202_cases_1_to_7() {
    let key4: Vec<u8> = (0x01..=0x19).collect();
    let cases: [(&[u8], &[u8], &str); 7] = [
        (
            &[0x0b; 20],
            b"Hi There",
            "b617318655057264e28bc0b6fb378c8ef146be00",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
        ),
        (
            &[0xaa; 20],
            &[0xdd; 50],
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
        ),
        (
            &key4,
            &[0xcd; 50],
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
        ),
        (
            &[0x0c; 20],
            b"Test With Truncation",
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
        ),
        (
            &[0xaa; 80],
            LARGE_KEY_TEXT,
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        ),
        (
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        ),
    ];
    for (i, (key, data, want)) in cases.iter().enumerate() {
        let want = hex(want);
        assert_eq!(
            hmac_sha1(key, &[data]).unwrap().expose(),
            want.as_slice(),
            "case {}",
            i + 1
        );
        assert!(verify_hmac_sha1(key, &[data], &want), "case {}", i + 1);
    }
}

#[test]
fn verify_rejects_wrong_tags_wrong_lengths_and_wrong_keys() {
    let key = [0x0b; 20];
    let good = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert!(verify_hmac_sha256(&key, &[b"Hi There"], &good));
    for i in [0, 15, 31] {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        assert!(
            !verify_hmac_sha256(&key, &[b"Hi There"], &bad),
            "flip at {i}"
        );
    }
    assert!(!verify_hmac_sha256(&key, &[b"Hi There"], &good[..31]));
    assert!(!verify_hmac_sha256(
        &key,
        &[b"Hi There"],
        &[good.as_slice(), &[0]].concat()
    ));
    assert!(!verify_hmac_sha256(&key, &[b"Hi There"], &[]));
    assert!(!verify_hmac_sha256(&[0x0c; 20], &[b"Hi There"], &good));
    assert!(!verify_hmac_sha256(&key, &[b"Hi there"], &good));
    // A SHA-256 tag is never a SHA-1 tag.
    assert!(!verify_hmac_sha1(&key, &[b"Hi There"], &good));
}

#[test]
fn verify_returns_bool_never_the_tag() {
    // The public signature is the proof: verify gives a plain bool.
    type Verify = fn(&[u8], &[&[u8]], &[u8]) -> bool;
    let f: Verify = verify_hmac_sha256;
    let g: Verify = verify_hmac_sha1;
    assert!(!f(b"k", &[b"m"], &[0; 32]));
    assert!(!g(b"k", &[b"m"], &[0; 20]));
}

#[test]
fn empty_key_and_message_work() {
    // Cross-checked with python3 -I: hmac.new(b"", b"", hashlib.sha256).
    let want = hex("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    assert_eq!(hmac_sha256(&[], &[]).unwrap().expose(), want.as_slice());
    assert!(verify_hmac_sha256(&[], &[], &want));
}

#[test]
fn hmac_sha256_with_a_block_size_key() {
    // FMT-05.6 and FMT-06.5 key HMAC-SHA-256 with 64 bytes (K_hdr, K_i).
    // Demo key 00 01 .. 3f. Value from python3 -I:
    // hmac.new(bytes(range(64)), msg, hashlib.sha256), and the same from
    // openssl dgst -sha256 -mac HMAC -macopt hexkey:0001..3f.
    let key: Vec<u8> = (0..64).collect();
    let msg: &[u8] = b"demo message for a 64-byte key";
    let want = hex("8a99e51da6cf5575515f744edeafe69865d6c46814ae41cfe548df0aff79b9df");
    assert_eq!(hmac_sha256(&key, &[msg]).unwrap().expose(), want.as_slice());
    assert!(verify_hmac_sha256(&key, &[msg], &want));
}

/// Welch's t statistic of two samples.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean_var = |x: &[f64]| {
        let n = x.len() as f64;
        let m = x.iter().sum::<f64>() / n;
        let v = x.iter().map(|y| (y - m).powi(2)).sum::<f64>() / (n - 1.0);
        (m, v / n)
    };
    let (ma, va) = mean_var(a);
    let (mb, vb) = mean_var(b);
    (ma - mb) / (va + vb).sqrt()
}

// AT-B05 timing test on MAC checks (plan/attacks-and-checks.md). Interleaves
// verify calls with a tag wrong at byte 0, a tag wrong at byte 31 and the
// right tag, and requires |t| < 10 (Welch) between every pair, the bound the
// dudect method uses for "maybe constant time". The HMAC computation's run
// time hides a 32-byte compare, so this is a smoke check; the guard against a
// regression to an early-exit compare is the probe test in src/mac.rs.
// Run: cargo test -p larsal-crypto --release --test mac -- --ignored
#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn verify_time_does_not_depend_on_the_tag() {
    const ROUNDS: usize = 200_000;
    let key = [0x0b; 64];
    let msg: &[u8] = b"demo message";
    let good = hmac_sha256(&key, &[msg]).unwrap().expose().to_vec();
    let mut first = good.clone();
    first[0] ^= 1;
    let mut last = good.clone();
    last[31] ^= 1;
    let tags = [first, last, good];
    let mut times: [Vec<f64>; 3] = std::array::from_fn(|_| Vec::with_capacity(ROUNDS));
    for i in 0..ROUNDS {
        // Rotate the order each round so no class always runs first.
        for k in 0..3 {
            let c = (i + k) % 3;
            let start = Instant::now();
            black_box(verify_hmac_sha256(
                black_box(&key),
                black_box(&[msg]),
                black_box(&tags[c]),
            ));
            times[c].push(start.elapsed().as_nanos() as f64);
        }
    }
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let t = welch_t(&times[a], &times[b]);
        println!("classes {a} and {b}: t = {t:.2}");
        assert!(t.abs() < 10.0, "classes {a} and {b}: t = {t}");
    }
}

proptest! {
    // Round trip: a computed tag verifies; one flipped bit does not; parts
    // are MACed as if joined.
    #[test]
    fn compute_then_verify(
        key in proptest::collection::vec(any::<u8>(), 0..200),
        a in proptest::collection::vec(any::<u8>(), 0..300),
        b in proptest::collection::vec(any::<u8>(), 0..300),
        bit in 0usize..256,
    ) {
        let joined = [a.as_slice(), b.as_slice()].concat();
        let tag = hmac_sha256(&key, &[&a, &b]).unwrap();
        prop_assert_eq!(&tag, &hmac_sha256(&key, &[&joined]).unwrap());
        prop_assert!(verify_hmac_sha256(&key, &[&joined], tag.expose()));
        let mut bad = tag.expose().to_vec();
        bad[bit / 8] ^= 1 << (bit % 8);
        prop_assert!(!verify_hmac_sha256(&key, &[&joined], &bad));

        let tag1 = hmac_sha1(&key, &[&a, &b]).unwrap();
        prop_assert_eq!(&tag1, &hmac_sha1(&key, &[&joined]).unwrap());
        prop_assert!(verify_hmac_sha1(&key, &[&joined], tag1.expose()));
        let mut bad1 = tag1.expose().to_vec();
        bad1[(bit / 8) % 20] ^= 1 << (bit % 8);
        prop_assert!(!verify_hmac_sha1(&key, &[&joined], &bad1));
    }
}
