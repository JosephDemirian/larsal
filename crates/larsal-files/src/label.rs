//! The plain text a screen may show for a chosen file (FIL-03.14).

use std::ffi::OsStr;

/// A file name as safe plain text: direction controls removed, every other
/// control character and line break shown as a visible escape, bytes that are not UTF-8
/// replaced. The raw name stays with the file's capability; errors never
/// carry it. The result is plain text: no Markdown or link means anything.
#[must_use]
pub fn clean_label(name: &OsStr) -> String {
    let mut out = String::new();
    for c in name.to_string_lossy().chars() {
        match c {
            '\u{61C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}' => {}
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') => {
                out.extend(c.escape_default());
            }
            c => out.push(c),
        }
    }
    out
}
