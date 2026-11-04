//! Fuzz target `key_file` (E3-S10): the key file reader on arbitrary bytes
//! must never panic, hang or allocate from an unchecked length (AT-A10).
#![no_main]

use app_format::keyfile::read_key_file;
use app_format::limits::Limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(k) = read_key_file(std::io::Cursor::new(data), &Limits::DEFAULT) {
        assert_eq!(k.key().len(), 32);
    }
});
