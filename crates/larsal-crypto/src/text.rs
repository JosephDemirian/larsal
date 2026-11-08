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
}
