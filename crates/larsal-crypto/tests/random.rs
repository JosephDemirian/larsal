//! Story E2-S2: the public behavior of the OS random source.
//! The "source fails, so an error and no value" proof and the exact
//! rejection-rule checks are unit tests in src/random.rs (they need the
//! internal seam that takes the source as a parameter).

use larsal_crypto::{Error, random};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Pearson's chi-square statistic of `counts` against a uniform spread.
fn chi_square(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    let expected = total as f64 / counts.len() as f64;
    counts
        .iter()
        .map(|&c| (c as f64 - expected).powi(2) / expected)
        .sum()
}

// Critical values: the chi-square upper tail at about 1e-7 (computed with the
// regularized incomplete gamma function in python3 -I): df 447 -> 620,
// df 191 -> 300 (tail about 8e-7). For df 2 the tail is exactly exp(-x/2),
// so 40 has a tail of about 2e-9. A correct generator fails these tests about
// once in ten million runs.
//
// These chi-square tests are smoke checks for gross bias. A bias as small as
// plain `x % n` on 32-bit draws (256 in 2^32 for n = 448) is invisible in a
// million draws; the proof that below() is exactly uniform is the unit tests
// of the rejection rule in src/random.rs.
const CRIT_DF_447: f64 = 620.0;
const CRIT_DF_191: f64 = 300.0;
const CRIT_DF_2: f64 = 40.0;

#[test]
fn below_shows_no_bias_over_one_million_draws() {
    // n = 448: the padding length spread of CRY-03.7 (64 to 511).
    let mut counts = vec![0u64; 448];
    for _ in 0..1_000_000 {
        counts[random::below(448).unwrap() as usize] += 1;
    }
    let stat = chi_square(&counts);
    assert!(stat < CRIT_DF_447, "chi-square {stat} over df 447");
}

#[test]
fn below_shows_no_bias_where_plain_modulo_would() {
    // n = 3 * 2^30: 2^32 mod n = 2^30, so plain `x % n` without rejection
    // would put half of all draws in the first third of the range. Counted by
    // third (v >> 30), a correct below() stays flat.
    let mut counts = [0u64; 3];
    for _ in 0..1_000_000 {
        counts[(random::below(3 << 30).unwrap() >> 30) as usize] += 1;
    }
    let stat = chi_square(&counts);
    assert!(stat < CRIT_DF_2, "chi-square {stat} over df 2");
}

#[test]
fn the_chi_square_test_catches_a_biased_generator() {
    // Control: the classic biased reduction (one byte mod 192, no rejection)
    // on the same number of draws must fail the same kind of test, so the
    // test above catches gross bias (not a bias as small as 256 in 2^32).
    let raw = random::bytes(1_000_000).unwrap();
    let mut counts = vec![0u64; 192];
    for &b in raw.expose() {
        counts[usize::from(b) % 192] += 1;
    }
    let stat = chi_square(&counts);
    assert!(stat > CRIT_DF_191, "chi-square {stat} should show the bias");
}

#[test]
fn below_stays_in_range() {
    assert_eq!(random::below(0), Err(Error::EmptyRange));
    for _ in 0..1000 {
        assert_eq!(random::below(1).unwrap(), 0);
        assert!(random::below(2).unwrap() < 2);
        assert!(random::below(u32::MAX).unwrap() < u32::MAX);
        assert!(random::below((1 << 31) + 1).unwrap() <= 1 << 31);
    }
}

#[test]
fn bytes_and_fill_give_the_asked_length_and_fresh_values() {
    for n in [0, 1, 12, 16, 32, 64, 1000] {
        assert_eq!(random::bytes(n).unwrap().len(), n);
    }
    // CRY-03.8 in small: 10,000 draws of 32 bytes never repeat.
    let mut seen = HashSet::new();
    for _ in 0..10_000 {
        assert!(seen.insert(random::bytes(32).unwrap().expose().to_vec()));
    }
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    random::fill(&mut a).unwrap();
    random::fill(&mut b).unwrap();
    assert_ne!(a, b);
    random::fill(&mut []).unwrap();
}

#[test]
fn uuid_v4_has_version_and_variant_bits_and_never_repeats() {
    let mut seen = HashSet::new();
    let mut free_bits_or = [0u8; 16];
    for _ in 0..10_000 {
        let id = random::uuid_v4().unwrap();
        assert_eq!(id[6] >> 4, 4, "version nibble");
        assert_eq!(id[8] >> 6, 0b10, "variant bits");
        assert!(seen.insert(id));
        for (o, b) in free_bits_or.iter_mut().zip(id) {
            *o |= b;
        }
    }
    // Every bit outside the fixed six was 1 at least once.
    let mut want = [0xFF; 16];
    want[6] = 0x4F;
    want[8] = 0xBF;
    assert_eq!(free_bits_or, want);
}

/// Every file under `dir`, in subfolders too.
fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn only_random_rs_reaches_the_os_source() {
    // AT-B04 inside this crate: no other source file, in any subfolder, names
    // a random source. The workspace-wide check is CRY-03 T11 / AT-B04.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    files_under(&src, &mut files);
    assert!(files.len() > 1);
    let words = [
        "getrandom",
        "rand_core",
        "rand::",
        "SysRng",
        "OsRng",
        "StdRng",
        "SmallRng",
        "ThreadRng",
        "thread_rng",
    ];
    for path in files.iter().filter(|p| **p != src.join("random.rs")) {
        let text = std::fs::read_to_string(path).unwrap();
        for word in words {
            assert!(!text.contains(word), "{} names {word}", path.display());
        }
    }
}
