//! Fuzz target `json_import` (E4-S13): the Bitwarden JSON reader (plain,
//! and the envelope of a password-protected export up to the key
//! derivation) and the Proton Pass JSON reader (FEA-08 sections E and F)
//! on the same arbitrary bytes. Must never panic, hang or allocate by a
//! hostile number (FEA-08.65, FEA-08.67). A result keeps the model
//! invariants, also after placement into an open vault.
//!
//! No password is passed, so a protected file stops before any key
//! derivation (its cost comes from the file): the derivations are
//! app-crypto's, tested on vectors.
#![no_main]

use app_core::import::{self, Context, bitwarden, proton};
use app_core::time::Utc;
use app_model::{Group, Time, Uuid, Vault};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::AtomicBool;

fuzz_target!(|data: &[u8]| {
    let cancel = AtomicBool::new(false);
    let now = Time(63_900_000_000);
    let ctx = Context::new(now, &Utc, &cancel);
    for r in [bitwarden::read(data, None, &ctx), proton::read(data, &ctx)] {
        let Ok(r) = r else {
            continue;
        };
        assert_eq!(app_model::invariants::check(&r.vault), Ok(()));
        let _ = import::preview(&r);
        let mut root = Group::new(Uuid([1; 16]), "Root".into(), now);
        root.groups
            .push(Group::new(Uuid([2; 16]), "Work".into(), now));
        let mut target = Vault::new(root, now);
        if import::into_group(&mut target, Uuid([2; 16]), r, now).is_ok() {
            assert_eq!(app_model::invariants::check(&target), Ok(()));
        }
    }
});
