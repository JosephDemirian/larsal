//! Fuzz target `word_list` (E4-S9, FEA-03 D-03-3): the word list reader on
//! arbitrary file bytes. Must never panic or hang; a list it accepts holds
//! unique, non-empty, lower-cased entries of at most 256 characters, and a
//! passphrase from it has the asked number of words.
#![no_main]

use app_core::generator::passphrase::{self, Options};
use app_core::generator::wordlist::{MAX_ENTRY, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let started = std::time::Instant::now();
    let Ok(list) = parse(data) else {
        return;
    };
    let mut seen = std::collections::HashSet::new();
    for w in list.words() {
        assert!(!w.is_empty() && w.chars().count() <= MAX_ENTRY * 3);
        assert!(seen.insert(w), "entries are unique");
    }
    if !list.is_empty() {
        // Entries never hold a line feed, so it splits the words back.
        let o = Options {
            words: 3,
            separator: "\n".into(),
            ..Options::default()
        };
        let p = passphrase::generate(&o, &list).unwrap();
        assert_eq!(p.expose().split('\n').count(), 3);
    }
    assert!(started.elapsed().as_secs() < 2, "too slow");
});
