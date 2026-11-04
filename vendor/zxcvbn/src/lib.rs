//! zxcvbn 3.1.1, App's patched copy (spec/decisions.md LD-136). Upstream:
//! <https://github.com/shssoichiro/zxcvbn-rs>, MIT (see LICENSE).
//!
//! App changes, each marked `App change (LD-136)` where it is made:
//! 1. Guesses are `f64` end to end (Match, the patterns, the scoring, the
//!    sequence search, Entropy, CrackTimes): nothing overflows or
//!    saturates. (scoring.rs, matching/patterns.rs, matching/mod.rs,
//!    time_estimates.rs, lib.rs)
//! 2. Every map whose iteration order can change a result is ordered: the
//!    sequence search tables (scoring.rs `Optimal`), the dictionary list
//!    (frequency_lists.rs), the keyboard graph list, the l33t table and
//!    the l33t substitution maps (matching/mod.rs, matching/patterns.rs).
//!    Left as hash maps, because only lookups or order-free sums touch
//!    them: each dictionary's word map, the user inputs, the keyboard
//!    graphs' key maps, the date splits and the test-only character class
//!    table.
//! 3. The wasm-only code (its 3 `unsafe` blocks and the `custom_wasm_env`
//!    feature) is gone, and the crate forbids `unsafe`. (lib.rs,
//!    scoring.rs, Cargo.toml)
//! 4. One product-name entry is removed from the password frequency list
//!    (the owner's naming rule). (frequency_lists.rs)
//! 5. `matching::omnimatch` is public, and so is `estimate_guesses` (at
//!    the crate root): App chooses the match sequence by its own price
//!    (LD-140), and `omnimatch`'s matches carry no guesses until they are
//!    estimated. (matching/mod.rs, scoring.rs, lib.rs)
//! 6. The `itertools` calls are standard-library code (LD-247 (5)): two
//!    `join`s collect into a `Vec` and join it, and `unique` keeps the first
//!    of each pair in order. (matching/mod.rs, feedback.rs, Cargo.toml)
//! 7. The `lazy_static` statics are `std::sync::LazyLock` (E0-S7 R1).
//!    (adjacency_graphs.rs, frequency_lists.rs, matching/mod.rs,
//!    scoring.rs, lib.rs, Cargo.toml)
//! 8. The reference year is the UTC year of `SystemTime::now()`, worked out
//!    by `utc_year` (public, so App tests it) with the standard library, not
//!    the `time` crate (E0-S7 R3). (scoring.rs, lib.rs, Cargo.toml)
//! 9. The six patterns are hand-written matchers that find what the
//!    `regex` and `fancy-regex` searches found (E0-S7 R7, R11): the
//!    recent-year pattern, the two maybe-date patterns and the three
//!    repeat patterns. (matching/mod.rs, Cargo.toml)
//! 10. No build script runs (`build = false`, LD-255 (1)). (Cargo.toml)
//!
//! Left out of the copy (F-050; not built, not shipped): README,
//! CHANGELOG, benches, CI files, dev-dependencies and package metadata
//! (the published Cargo.toml.orig, Cargo.lock, rustfmt.toml and VCS
//! information).
//!
//! The crate's own `#[cfg(test)]` modules are left as upstream wrote them:
//! they need dev-dependencies this copy does not carry and are not built;
//! App's tests (app-core `fea05`) cover the copy.
#![forbid(unsafe_code)] // App change (LD-136) 3.
#![recursion_limit = "128"]
#![warn(missing_docs)]

#[macro_use]
#[cfg(feature = "builder")]
extern crate derive_builder;

use std::time::Duration;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

pub use scoring::Score;
pub use scoring::estimate_guesses; // App change (LD-136, LD-140) 5.
pub use scoring::utc_year; // App change (LD-136) 8.
use time_estimates::CrackTimes;

pub use crate::matching::Match;

mod adjacency_graphs;
pub mod feedback;
mod frequency_lists;
/// Defines structures for matches found in a password
pub mod matching;
mod scoring;
pub mod time_estimates;

#[cfg(feature = "ser")]
mod serialization_utils;

// App change (LD-136) 3: the wasm-only variants of this function are gone.
fn time_scoped<F, R>(f: F) -> (R, Duration)
where
    F: FnOnce() -> R,
{
    let start_time = std::time::Instant::now();
    let result = f();
    let calc_time = std::time::Instant::now().duration_since(start_time);
    (result, calc_time)
}

/// Contains the results of an entropy calculation
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "ser", derive(serde::Deserialize, serde::Serialize))]
pub struct Entropy {
    /// Estimated guesses needed to crack the password
    guesses: f64, // App change (LD-136) 1.
    /// Order of magnitude of `guesses`
    #[cfg_attr(
        feature = "ser",
        serde(deserialize_with = "crate::serialization_utils::deserialize_f64_null_as_nan")
    )]
    guesses_log10: f64,
    /// List of back-of-the-envelope crack time estimations based on a few scenarios.
    crack_times: time_estimates::CrackTimes,
    /// Overall strength score from 0-4.
    /// Any score less than 3 should be considered too weak.
    score: Score,
    /// Verbal feedback to help choose better passwords. Set when `score` <= 2.
    feedback: Option<feedback::Feedback>,
    /// The list of patterns the guess calculation was based on
    sequence: Vec<Match>,
    /// How long it took to calculate the answer.
    calc_time: Duration,
}

impl Entropy {
    /// The estimated number of guesses needed to crack the password.
    pub fn guesses(&self) -> f64 {
        // App change (LD-136) 1: f64.
        self.guesses
    }

    /// The order of magnitude of `guesses`.
    pub fn guesses_log10(&self) -> f64 {
        self.guesses_log10
    }

    /// List of back-of-the-envelope crack time estimations based on a few scenarios.
    pub fn crack_times(&self) -> time_estimates::CrackTimes {
        self.crack_times
    }

    /// Overall strength score from 0-4.
    /// Any score less than 3 should be considered too weak.
    pub fn score(&self) -> Score {
        self.score
    }

    /// Feedback to help choose better passwords. Set when `score` <= 2.
    pub fn feedback(&self) -> Option<&feedback::Feedback> {
        self.feedback.as_ref()
    }

    /// The list of patterns the guess calculation was based on
    pub fn sequence(&self) -> &[Match] {
        &self.sequence
    }

    /// How long it took to calculate the answer.
    pub fn calculation_time(&self) -> Duration {
        self.calc_time
    }
}

/// Takes a password string and optionally a list of user-supplied inputs
/// (e.g. username, email, first name) and calculates the strength of the password
/// based on entropy, using a number of different factors.
pub fn zxcvbn(password: &str, user_inputs: &[&str]) -> Entropy {
    if password.is_empty() {
        return Entropy {
            guesses: 0.0, // App change (LD-136) 1.
            guesses_log10: f64::NEG_INFINITY,
            crack_times: CrackTimes::new(0.0),
            score: Score::Zero,
            feedback: feedback::get_feedback(Score::Zero, &[]),
            sequence: Vec::default(),
            calc_time: Duration::from_secs(0),
        };
    }

    let (result, calc_time) = time_scoped(|| {
        // Only evaluate the first 100 characters of the input.
        // This prevents potential DoS attacks from sending extremely long input strings.
        let password = password.chars().take(100).collect::<String>();

        let sanitized_inputs = user_inputs
            .iter()
            .enumerate()
            .map(|(i, x)| (x.to_lowercase(), i + 1))
            .collect();

        let matches = matching::omnimatch(&password, &sanitized_inputs);
        scoring::most_guessable_match_sequence(&password, &matches, false)
    });
    let (crack_times, score) = time_estimates::estimate_attack_times(result.guesses);
    let feedback = feedback::get_feedback(score, &result.sequence);

    Entropy {
        guesses: result.guesses,
        guesses_log10: result.guesses_log10,
        crack_times,
        score,
        feedback,
        sequence: result.sequence,
        calc_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck::TestResult;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;

    quickcheck! {
        fn test_zxcvbn_doesnt_panic(password: String, user_inputs: Vec<String>) -> TestResult {
            let inputs = user_inputs.iter().map(|s| s.as_ref()).collect::<Vec<&str>>();
            zxcvbn(&password, &inputs);
            TestResult::from_bool(true)
        }

        #[cfg(feature = "ser")]
        fn test_zxcvbn_serialisation_doesnt_panic(password: String, user_inputs: Vec<String>) -> TestResult {
            let inputs = user_inputs.iter().map(|s| s.as_ref()).collect::<Vec<&str>>();
            serde_json::to_string(&zxcvbn(&password, &inputs)).ok();
            TestResult::from_bool(true)
        }

        #[cfg(feature = "ser")]
        fn test_zxcvbn_serialization_roundtrip(password: String, user_inputs: Vec<String>) -> TestResult {
            let inputs = user_inputs.iter().map(|s| s.as_ref()).collect::<Vec<&str>>();
            let entropy = zxcvbn(&password, &inputs);
            // When the entropy is not a finite number (otherwise our equality test fails). We test
            // this scenario separately
            if !entropy.guesses_log10.is_finite() {
                //panic!("infinite guesses_log10: {} => {}", password, entropy.guesses_log10);
                return TestResult::discard();
            }
            let serialized_entropy = serde_json::to_string(&entropy);
            assert!(serialized_entropy.is_ok());
            let serialized_entropy = serialized_entropy.expect("serialized entropy");
            let deserialized_entropy = serde_json::from_str::<Entropy>(&serialized_entropy);
            assert!(deserialized_entropy.is_ok());
            let deserialized_entropy = deserialized_entropy.expect("deserialized entropy");

            // Apply a mask to trim the last bit when comparing guesses_log10, since Serde loses
            // precision when deserializing
            const MASK: u64 = 0x1111111111111110;

            let original_equal_to_deserialized_version =
                (entropy.guesses == deserialized_entropy.guesses) &&
                (entropy.crack_times == deserialized_entropy.crack_times) &&
                (entropy.score == deserialized_entropy.score) &&
                (entropy.feedback == deserialized_entropy.feedback) &&
                (entropy.sequence == deserialized_entropy.sequence) &&
                (entropy.calc_time == deserialized_entropy.calc_time) &&
                (entropy.guesses_log10.to_bits() & MASK == deserialized_entropy.guesses_log10.to_bits() & MASK);

            TestResult::from_bool(original_equal_to_deserialized_version)
        }
    }

    #[test]
    #[cfg(feature = "ser")]
    fn test_zxcvbn_serialization_non_finite_guesses_log10() {
        let entropy = zxcvbn("", &[]);
        assert!(!entropy.guesses_log10.is_finite());

        let serialized_entropy = serde_json::to_string(&entropy);
        assert!(serialized_entropy.is_ok());
        let serialized_entropy = serialized_entropy.expect("serialized entropy");
        let deserialized_entropy = serde_json::from_str::<Entropy>(&serialized_entropy);
        assert!(deserialized_entropy.is_ok());
        let deserialized_entropy = deserialized_entropy.expect("deserialized entropy");
        assert!(!deserialized_entropy.guesses_log10.is_finite());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_zxcvbn() {
        let password = "r0sebudmaelstrom11/20/91aaaa";
        let entropy = zxcvbn(password, &[]);
        assert_eq!(entropy.guesses_log10 as u16, 14);
        assert_eq!(entropy.score, Score::Four);
        assert!(!entropy.sequence.is_empty());
        assert!(entropy.feedback.is_none());
        assert!(entropy.calc_time.as_nanos() > 0);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_zxcvbn_empty() {
        let password = "";
        let entropy = zxcvbn(password, &[]);
        assert_eq!(entropy.score, Score::Zero);
        assert_eq!(entropy.guesses, 0);
        assert_eq!(entropy.guesses_log10, f64::NEG_INFINITY);
        assert_eq!(entropy.crack_times, CrackTimes::new(0));
        assert_eq!(entropy.sequence, Vec::default());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_zxcvbn_unicode() {
        let password = "𐰊𐰂𐰄𐰀𐰁";
        let entropy = zxcvbn(password, &[]);
        assert_eq!(entropy.score, Score::One);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_zxcvbn_unicode_2() {
        let password = "r0sebudmaelstrom丂/20/91aaaa";
        let entropy = zxcvbn(password, &[]);
        assert_eq!(entropy.score, Score::Four);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_issue_13() {
        let password = "Imaginative-Say-Shoulder-Dish-0";
        let entropy = zxcvbn(password, &[]);
        assert_eq!(entropy.score, Score::Four);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_issue_15_example_1() {
        let password = "TestMeNow!";
        let entropy = zxcvbn(password, &[]);
        assert_eq!(entropy.guesses, 372_010_000);
        assert!((entropy.guesses_log10 - 8.57055461430783).abs() < f64::EPSILON);
        assert_eq!(entropy.score, Score::Three);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_issue_15_example_2() {
        let password = "hey<123";
        let entropy = zxcvbn(password, &[]);
        assert_eq!(entropy.guesses, 1_010_000);
        assert!((entropy.guesses_log10 - 6.004321373782642).abs() < f64::EPSILON);
        assert_eq!(entropy.score, Score::Two);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_overflow_safety() {
        let password = "!QASW@#EDFR$%TGHY^&UJKI*(OL";
        let entropy = zxcvbn(password, &[]);
        assert_eq!(entropy.guesses, u64::MAX);
        assert_eq!(entropy.score, Score::Four);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_unicode_mb() {
        let password = "08märz2010";
        let entropy = zxcvbn(password, &[]);
        assert_eq!(entropy.guesses, 100010000);
        assert_eq!(entropy.score, Score::Three);
    }
}
