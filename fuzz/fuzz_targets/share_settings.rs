//! Fuzz target `share_settings` (E11-S2): the share settings item reader
//! (INT-08.2, INT-08.3, AT-A10). Must never panic, hang or allocate by a
//! hostile number; every item it reads writes back and reads again the
//! same.
//!
//! Input: a mode byte, then the rest. Bit 0 clear: the rest is the item
//! value as text. Set: the rest is the XML, which the target encodes in
//! base64, so the XML reader is reached with any content; in this mode
//! `@S` stands for the root element name (see `expand`).
#![no_main]

use larsal_crypto::base64::{self, Form};
use larsal_share::settings::{self, ROOT};
use libfuzzer_sys::fuzz_target;

/// `data` with every `@S` replaced by the root element name: the stored
/// seeds hold the placeholder, so no seed file carries the name as text
/// (AGENTS.md rule 1).
fn expand(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut rest = data;
    while let Some(at) = rest.windows(2).position(|w| w == b"@S") {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(ROOT);
        rest = &rest[at + 2..];
    }
    out.extend_from_slice(rest);
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let value = if mode & 1 == 0 {
        String::from_utf8_lossy(rest).into_owned()
    } else {
        base64::encode(Form::Padded, &expand(rest))
    };
    let Some(mut s) = settings::read(&value) else {
        return;
    };
    let again = settings::read(s.write().unwrap().expose()).unwrap();
    assert_eq!(again.mode(), s.mode());
    assert_eq!(again.group, s.group);
    assert!(!again.group.is_zero());
    assert_eq!(again.path, s.path);
    assert_eq!(again.password.expose(), s.password.expose());
    assert_eq!(again.keep_groups, s.keep_groups);
});
