//! Fuzz target `csv_import` (E4-S13): the CSV import (FEA-08 section B) on
//! arbitrary file bytes with arbitrary screen options. Must never panic,
//! hang or allocate by a hostile number (FEA-08.65, FEA-08.67). Every
//! record after the skipped ones becomes one entry; the result keeps the
//! model invariants, also after placement into a new vault.
//!
//! Input: an option byte (bits 0-1 encoding, 2-4 qualifier, 5 backslash
//! escapes, 6 first row names, 7 skip the most rows), a byte choosing the
//! separator (low 4 bits) and the comment character (high 4 bits), then the
//! file.
#![no_main]

use larsal_core::import::csv::{
    self, COMMENTS, Encoding, Mapping, Options, QUALIFIERS, SEPARATORS,
};
use larsal_core::import::{self, Context};
use larsal_core::time::Utc;
use larsal_model::{Group, Time, Uuid, Vault};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::AtomicBool;

fuzz_target!(|data: &[u8]| {
    let [a, b, file @ ..] = data else {
        return;
    };
    let encodings = [
        Encoding::Utf8,
        Encoding::Windows1252,
        Encoding::Utf16,
        Encoding::Utf16Le,
    ];
    let o = Options {
        encoding: encodings[usize::from(a & 3)],
        qualifier: QUALIFIERS[usize::from((a >> 2) & 7) % QUALIFIERS.len()],
        separator: SEPARATORS[usize::from(b & 15) % SEPARATORS.len()],
        comment: COMMENTS[usize::from(b >> 4) % COMMENTS.len()],
        backslash: a & 32 != 0,
        first_row_names: a & 64 != 0,
    };
    let Ok(p) = csv::parse(file, &o) else {
        return;
    };
    assert!(p.columns <= 10_000 && p.rows() <= 1_000_000);
    assert_eq!(p.screen_names(&[None; 11]).len(), p.columns);
    let (min, max) = p.skip_range();
    assert!(min <= max);
    let skip = if a & 128 != 0 { max } else { min };
    let cancel = AtomicBool::new(false);
    let now = Time(63_900_000_000);
    let ctx = Context::new(now, &Utc, &cancel);
    // The automatic mapping, and every target on some column so every
    // value path runs.
    let all: Mapping = core::array::from_fn(|i| (p.columns > 0).then(|| i % p.columns));
    for map in [csv::auto_map(&p, None), all] {
        let _ = csv::questions(&p, &map);
        let Ok(r) = csv::build(&p, &map, skip, "/fuzz/in.csv", &ctx) else {
            continue;
        };
        assert_eq!(
            r.vault.root.all_entries().count(),
            p.rows().saturating_sub(skip)
        );
        assert_eq!(larsal_model::invariants::check(&r.vault), Ok(()));
        assert_eq!(import::preview(&r).len(), p.rows().saturating_sub(skip));
        let mut new = Vault::new(Group::new(Uuid([1; 16]), "New".into(), now), now);
        if import::into_new_vault(&mut new, r, now).is_ok() {
            assert_eq!(larsal_model::invariants::check(&new), Ok(()));
        }
    }
});
