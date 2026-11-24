//! Fuzz target `inner_header` (E3-S10): the version 4 inner header reader
//! and the strict gunzip must never panic, hang or allocate from a declared
//! size (AT-A10, AT-A06).
#![no_main]

use larsal_format::inner::read_inner;
use larsal_format::limits::Limits;
use larsal_format::payload::gunzip;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut lim = Limits::DEFAULT;
    lim.total = 4 << 20;
    if let Ok(h) = read_inner(data, &lim) {
        assert!(h.len <= data.len());
        for item in &h.pool {
            assert!(item.range.end <= h.len);
        }
        let _ = h.field_stream();
    }
    if let Ok(u) = gunzip(data, 4 << 20) {
        assert!(u.len() <= 4 << 20);
        let _ = read_inner(u.expose(), &lim);
    }
});
