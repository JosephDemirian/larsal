//! Fuzz target `vault_header` (E3-S2): the outer header reader of both
//! layouts and the typed map reader must never panic, hang or allocate
//! from an unchecked length, whatever the bytes (AT-A10).
#![no_main]

use larsal_format::header::read_header;
use larsal_format::kdf_params::{parse_kdf, parse_map};
use larsal_format::limits::Limits;
use libfuzzer_sys::fuzz_target;

/// Signatures and version 4.1, then 3.1: so most inputs reach the field loop.
const V4: [u8; 12] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 0, 4, 0];
const V3: [u8; 12] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 0, 3, 0];

fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT;
    let _ = read_header(data, &limits);
    for preamble in [V4, V3] {
        let file = [&preamble[..], data].concat();
        if let Ok(h) = read_header(&file, &limits) {
            assert!(h.len <= file.len());
        }
    }
    let _ = parse_kdf(data);
    let _ = parse_map(data);
});
