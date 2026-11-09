//! Unicode Normalization Form C for folder passwords and names (E23-S3, FIL-04.4,
//! FIL-04.9), through the one approved crate, so Foundation never sees a secret.
//! The crate's table is Unicode 17; newer characters pass through unchanged, and that
//! their peer agrees is unproved.
//!
//! Guarantees: the result is written once, into a buffer of fixed capacity that
//! wipes on drop, so it never moves and leaves no unwiped copy; 32 KiB of stack below
//! the call is zeroed after it. No trimming, case folding or compatibility mapping.
//! Limit: a run of more than four pending combining marks spills inside the crate to
//! a small heap buffer freed unwiped; the zeroing allocator of the product wipes it.

use crate::Error;
use crate::secret::{SecretString, scrubbed};
use unicode_normalization::UnicodeNormalization;

/// NFC of `text`, at most `max` bytes of UTF-8.
///
/// # Errors
/// [`Error::TooLarge`] for a result over `max`, with what was written wiped.
pub fn nfc_bounded(text: &str, max: usize) -> Result<SecretString, Error> {
    // NFC grows UTF-8 at most threefold (UAX #15); the check below holds regardless.
    let room = text.len().saturating_mul(3).min(max);
    let mut out = SecretString::new(String::with_capacity(room));
    scrubbed(|| {
        for c in text.chars().nfc() {
            if !out.push_within_capacity(c) {
                return Err(Error::TooLarge);
            }
        }
        Ok(())
    })?;
    Ok(out)
}

/// True when `text` is already in NFC.
#[must_use]
pub fn is_nfc(text: &str) -> bool {
    unicode_normalization::is_nfc(text)
}

/// E11-S6, INT-08.34: the key two file names share when APFS, case-insensitive
/// as a Mac's volume is, takes them for one file: canonical decomposition with
/// full Unicode case folding, so a long s is an s, a sharp s is two, and a
/// composed accent is its decomposed form. Dotless i and dotted capital I stay
/// apart from plain i, as the file system keeps them. Characters newer than the
/// file system's table can join more than it does; never fewer. Names are not
/// secrets: the result is a plain `String`.
#[must_use]
pub fn file_name_key(name: &str) -> String {
    let folded: String = name.nfd().flat_map(fold).collect();
    folded.nfd().collect()
}

/// Full case folding of one character, from the standard library's tables:
/// lower, then upper, then lower reaches the fold's class for every character
/// but one. Dotless i uppercases to plain I, and the fold keeps it apart.
fn fold(c: char) -> Vec<char> {
    if c == '\u{131}' {
        return vec![c];
    }
    c.to_lowercase()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fil04_t04_composed_and_decomposed_give_the_same_bytes() {
        let a = nfc_bounded("caf\u{e9}", 64).unwrap();
        let b = nfc_bounded("cafe\u{301}", 64).unwrap();
        assert_eq!(a.expose().as_bytes(), b.expose().as_bytes());
        assert_eq!(a.expose().as_bytes(), "caf\u{e9}".as_bytes());
        assert!(is_nfc("caf\u{e9}") && !is_nfc("cafe\u{301}"));
    }

    #[test]
    fn fil04_t04_nothing_but_composition_changes() {
        for text in [" a b ", "a\0b", "\u{fb01}", "A", "\u{2126}x"] {
            let got = nfc_bounded(text, 64).unwrap();
            if text == "\u{2126}x" {
                // A singleton canonical mapping: NFC, not a compatibility one.
                assert_eq!(got.expose(), "\u{3a9}x");
            } else {
                assert_eq!(
                    got.expose(),
                    text,
                    "no trim, no folding, no compatibility map"
                );
            }
        }
    }

    #[test]
    fn fil06_t01_the_bound_holds_after_normalization() {
        assert!(nfc_bounded("abcd", 4).is_ok());
        assert_eq!(nfc_bounded("abcde", 4).err(), Some(Error::TooLarge));
        // U+0958 composition exclusion: one 3-byte character becomes 6 bytes.
        assert_eq!(nfc_bounded("\u{958}", 6).unwrap().expose().len(), 6);
        assert_eq!(nfc_bounded("\u{958}", 5).err(), Some(Error::TooLarge));
    }

    #[test]
    fn e11s6_names_the_file_system_takes_for_one() {
        for (a, b) in [
            ("larsalvault", "LARSALVAULT"),
            ("v.old.lar\u{17f}alvault", "v.old.larsalvault"),
            ("v\u{e9}.old", "ve\u{301}.OLD"),
            ("\u{212a}elvin", "kelvin"),
            ("gro\u{df}", "GROSS"),
            ("gro\u{1e9e}", "gross"),
            ("\u{130}", "i\u{307}"),
            ("\u{ac00}", "\u{1100}\u{1161}"),
            ("a\u{323}\u{307}", "a\u{307}\u{323}"),
            ("\u{fb01}", "FI"),
            ("\u{3c2}", "\u{3a3}"),
            // C1-07, C2-6: marks in the other order, one of which folds to a
            // letter: the first decomposition puts them in order before that.
            ("X\u{345}\u{301}", "X\u{301}\u{345}"),
            ("n\u{200d}\u{345}\u{307}", "n\u{200d}\u{307}\u{345}"),
        ] {
            assert_eq!(file_name_key(a), file_name_key(b), "{a:?} and {b:?}");
        }
    }

    #[test]
    fn e11s6_names_the_file_system_keeps_apart() {
        for (a, b) in [
            ("\u{131}", "i"),
            ("\u{131}", "I"),
            ("\u{130}", "i"),
            ("\u{130}", "\u{131}"),
            ("a\u{200d}b", "ab"),
            ("a\u{202e}b", "ab"),
            ("a\u{ad}b", "ab"),
            ("a\u{fe0f}b", "ab"),
        ] {
            assert_ne!(file_name_key(a), file_name_key(b), "{a:?} and {b:?}");
        }
    }
}
