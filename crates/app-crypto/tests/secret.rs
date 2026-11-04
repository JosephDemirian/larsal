//! Story E2-S1: the public behavior of `SecretBytes` and `SecretString`.
//! The wipe-on-drop proof is a unit test in src/secret.rs (it needs a
//! test-only hook); the Clone and Display compile-fail tests are doctests there.

use app_crypto::secret::{SecretBytes, SecretString};
use proptest::prelude::*;
use subtle::ConstantTimeEq;

#[test]
fn debug_prints_hidden() {
    let bytes = SecretBytes::new(b"demo key bytes".to_vec());
    let text = SecretString::new(String::from("demo password"));
    assert_eq!(format!("{bytes:?}"), "[hidden]");
    assert_eq!(format!("{bytes:#?}"), "[hidden]");
    assert_eq!(format!("{text:?}"), "[hidden]");
    assert_eq!(format!("{text:#?}"), "[hidden]");
}

#[test]
fn debug_hides_inside_a_derived_debug() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Login {
        user: &'static str,
        password: SecretString,
    }
    let login = Login {
        user: "demo",
        password: SecretString::new(String::from("demo password")),
    };
    let out = format!("{login:?}");
    assert!(out.contains("[hidden]"), "{out}");
    assert!(!out.contains("demo password"), "{out}");
}

#[test]
fn equality_by_content() {
    let a = SecretBytes::new(vec![1, 2, 3, 4]);
    assert_eq!(a, SecretBytes::new(vec![1, 2, 3, 4]));
    assert_ne!(a, SecretBytes::new(vec![9, 2, 3, 4])); // first byte differs
    assert_ne!(a, SecretBytes::new(vec![1, 2, 3, 9])); // last byte differs
    assert_ne!(a, SecretBytes::new(vec![1, 2, 3])); // shorter
    assert_ne!(a, SecretBytes::new(vec![1, 2, 3, 4, 5])); // longer
    assert_eq!(SecretBytes::new(vec![]), SecretBytes::zeroed(0));

    let s = SecretString::new(String::from("demo"));
    assert_eq!(s, SecretString::new(String::from("demo")));
    assert_ne!(s, SecretString::new(String::from("Demo")));
    assert_ne!(s, SecretString::new(String::from("demo ")));
}

#[test]
fn zeroed_then_filled_in_place() {
    let mut key = SecretBytes::zeroed(32);
    assert_eq!(key.len(), 32);
    assert!(key.expose().iter().all(|&b| b == 0));
    key.expose_mut().copy_from_slice(&[7; 32]);
    assert_eq!(key.expose(), &[7; 32]);
}

#[test]
fn length_and_empty() {
    assert!(SecretBytes::new(Vec::new()).is_empty());
    assert!(SecretString::new(String::new()).is_empty());
    let s = SecretString::new(String::from("pässwörd")); // UTF-8 bytes, not chars
    assert_eq!(s.len(), 10);
    assert!(!s.is_empty());
}

proptest! {
    #[test]
    fn bytes_round_trip(v in proptest::collection::vec(any::<u8>(), 0..512)) {
        let secret = SecretBytes::new(v.clone());
        prop_assert_eq!(secret.expose(), v.as_slice());
        prop_assert_eq!(secret.len(), v.len());
    }

    #[test]
    fn string_round_trip(s in ".{0,64}") {
        let secret = SecretString::new(s.clone());
        prop_assert_eq!(secret.expose(), s.as_str());
        prop_assert_eq!(secret.len(), s.len());
    }

    #[test]
    fn bytes_equality_matches_plain_equality(
        a in proptest::collection::vec(any::<u8>(), 0..64),
        b in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let (sa, sb) = (SecretBytes::new(a.clone()), SecretBytes::new(b.clone()));
        prop_assert_eq!(sa == sb, a == b);
        prop_assert_eq!(bool::from(sa.ct_eq(&sb)), a == b);
        prop_assert!(sa == SecretBytes::new(a));
    }

    #[test]
    fn string_equality_matches_plain_equality(a in ".{0,16}", b in ".{0,16}") {
        let (sa, sb) = (SecretString::new(a.clone()), SecretString::new(b.clone()));
        prop_assert_eq!(sa == sb, a == b);
        prop_assert_eq!(bool::from(sa.ct_eq(&sb)), a == b);
        prop_assert!(sa == SecretString::new(a));
    }
}

#[test]
fn ct_eq_compares_plain_bytes() {
    // For the version 3 start bytes (FMT-05.10): equal, one bit off at the
    // start or the end, and a different length.
    use app_crypto::secret::ct_eq;
    let a = [7u8; 32];
    let mut first = a;
    first[0] ^= 1;
    let mut last = a;
    last[31] ^= 0x80;
    assert!(ct_eq(&a, &a));
    assert!(!ct_eq(&a, &first));
    assert!(!ct_eq(&a, &last));
    assert!(!ct_eq(&a, &a[..31]));
    assert!(ct_eq(&[], &[]));
}

/// Welch's t between two samples.
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

/// The sample without its slowest 10% (dudect's crop: the system's own
/// pauses hide a step of under a cycle).
fn cropped(mut x: Vec<f64>) -> Vec<f64> {
    x.sort_by(f64::total_cmp);
    x.truncate(x.len() * 9 / 10);
    x
}

// F-099 (E13-S2 AT-B05, RT-B2): the bare compare's time does not depend on
// where two 32-byte tags differ. Per-byte `subtle` compares took about
// 0.2 ns longer for a difference at byte 31 than at byte 0 on an Apple M4
// Pro (cropped t -11 to -36); one OR-fold and one compare show nothing.
// Batches of 256 calls on one fixed buffer, classes in a random order,
// |t| < 5 after the crop (the OR-fold stayed under 2.5). Timing: run alone.
// Run: cargo test -p app-crypto --release --test secret -- --ignored
#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn f_099_compare_time_does_not_depend_on_where_tags_differ() {
    use app_crypto::secret::ct_eq;
    use std::hint::black_box;
    use std::time::Instant;
    const BATCHES: usize = 100_000;
    let want = [0x5Au8; 32];
    let mut first = want;
    first[0] ^= 1;
    let mut last = want;
    last[31] ^= 1;
    let classes = [first, last];
    let mut tag = [0u8; 32];
    let mut times: [Vec<f64>; 2] = [Vec::with_capacity(BATCHES), Vec::with_capacity(BATCHES)];
    // A fixed-seed xorshift picks the order; no random source needed.
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    while times[0].len() < BATCHES || times[1].len() < BATCHES {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let c = usize::from(seed & 1 == 1);
        if times[c].len() == BATCHES {
            continue;
        }
        tag.copy_from_slice(&classes[c]);
        let start = Instant::now();
        for _ in 0..256 {
            black_box(ct_eq(black_box(&want), black_box(&tag)));
        }
        times[c].push(start.elapsed().as_nanos() as f64);
    }
    let [a, b] = times;
    let raw = welch_t(&a, &b);
    let t = welch_t(&cropped(a), &cropped(b));
    println!("byte 0 vs byte 31 wrong: t = {raw:.2} (cropped {t:.2})");
    assert!(t.abs() < 5.0, "cropped t = {t:.2}");
}
