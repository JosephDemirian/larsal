//! Fuzz target `icon_decode` (LD-115): App's icon decoder (`icons::Images`,
//! PNG through `png`, ICO through App's own reader, E0-S7 R10) on arbitrary
//! bytes. Must never panic, hang or allocate past the limits (MOD-06.7,
//! LD-109); whatever it returns is a PNG of at most 128 × 128 pixels that
//! reads back.
#![no_main]

use app_core::icons::{Images, Limits, decode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Lower than the defaults so every run stays fast; the code paths are
    // the same.
    let limits = Limits {
        bytes: 1 << 20,
        pixels: 512,
    };
    let Some(out) = decode(data, &Images, &limits) else {
        return;
    };
    let mut r = png::Decoder::new(std::io::Cursor::new(&out))
        .read_info()
        .expect("App's PNG reads back");
    let (w, h) = r.info().size();
    assert!(
        (1..=128).contains(&w) && (1..=128).contains(&h),
        "{w} × {h}"
    );
    let mut buf = vec![0; r.output_buffer_size().expect("a buffer size")];
    r.next_frame(&mut buf).expect("App's PNG decodes");
});
