//! Fuzz target `kdf_map` (E3-S10): the KDF map and the typed map of header
//! fields 11 and 12 must never panic (AT-A10), and what they accept must
//! survive being written back and read again (FMT-03.21, FMT-03.22).
#![no_main]

use app_crypto::kdf::KdfParams;
use app_format::kdf_params::{parse_kdf, parse_map, write_kdf, write_map};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = parse_kdf(data) {
        let back = parse_kdf(&write_kdf(&p).unwrap()).unwrap();
        // Written as Argon2 version 0x13 always (LD-17).
        let want = match p {
            KdfParams::Argon2 {
                kind,
                iterations,
                memory_kib,
                lanes,
                salt,
                ..
            } => KdfParams::Argon2 {
                kind,
                version: 0x13,
                iterations,
                memory_kib,
                lanes,
                salt,
            },
            other => other,
        };
        assert_eq!(back, want);
    }
    if let Ok(mut entries) = parse_map(data) {
        let back = parse_map(&write_map(&entries).unwrap()).unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(back, entries);
    }
});
