//! Fuzz target `share_merge` (E11-S6, RT-2, RT-10): two or more merges of hostile
//! containers into a share group, past the reader (INT-08.16 step 3, INT-08.32,
//! SI-09), then the vault's own merges of all six kinds. The input format and the
//! oracle are in `crates/larsal-share/tests/share_merge_oracle/mod.rs`.
#![no_main]

#[path = "../../crates/larsal-share/tests/share_merge_oracle/mod.rs"]
mod oracle;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    oracle::check(data);
});
