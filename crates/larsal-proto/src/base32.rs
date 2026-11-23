//! Base32 as Larsal shows secrets to type (RFC 4648 section 6): upper case,
//! no padding, the Recovery Kit's `S_acct` (SYN-06.7, 52 characters) and the
//! approval code (SYN-06.11, 26 characters). Written in groups of 4 joined
//! by `-`, or as one run; read case-blind with spaces, tabs and `-`
//! ignored, and only in its one canonical form (the unused low bits of the
//! last character zero).
//!
//! Guarantees: the bytes read go straight into a [`SecretBytes`]; the text
//! written goes into a [`SecretString`] built at its final size, so it never
//! moves and leaves no unwiped copy. Untrusted text; never panics.

use larsal_crypto::secret::{SecretBytes, SecretString};

/// RFC 4648 section 6's alphabet.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The characters of `len` bytes: ceil(8 * len / 5).
#[must_use]
pub const fn chars(len: usize) -> usize {
    len.saturating_mul(8).saturating_add(4) / 5
}

/// `bytes` in base32, in groups of 4 joined by `-` when `grouped`.
#[must_use]
pub fn encode(bytes: &[u8], grouped: bool) -> SecretString {
    let n = chars(bytes.len());
    let mut out = String::with_capacity(n.saturating_add(n / 4));
    push(&mut out, bytes, grouped);
    SecretString::new(out)
}

/// Pushes `bytes` in base32 onto `out`, in groups of 4 joined by `-` when
/// `grouped`.
pub fn push(out: &mut String, bytes: &[u8], grouped: bool) {
    let (mut acc, mut bits, mut n) = (0u16, 0u32, 0usize);
    let mut put = |out: &mut String, value: u16| {
        if grouped && n != 0 && n.is_multiple_of(4) {
            out.push('-');
        }
        let c = ALPHABET
            .get(usize::from(value & 31))
            .copied()
            .unwrap_or(b'A');
        out.push(char::from(c));
        n = n.wrapping_add(1);
    };
    for b in bytes {
        acc = acc.wrapping_shl(8) | u16::from(*b);
        bits = bits.wrapping_add(8);
        while bits >= 5 {
            bits = bits.wrapping_sub(5);
            put(out, acc.wrapping_shr(bits));
            acc &= 1u16.wrapping_shl(bits).wrapping_sub(1);
        }
    }
    if bits > 0 {
        put(out, acc.wrapping_shl(5u32.wrapping_sub(bits)));
    }
}

/// The `len` bytes `text` spells: [`chars`]`(len)` characters of the
/// alphabet in either case, spaces, tabs and `-` ignored, the unused low
/// bits zero. `None` for anything else.
#[must_use]
pub fn read(text: &str, len: usize) -> Option<SecretBytes> {
    let mut out = SecretBytes::zeroed(len);
    let (mut acc, mut bits, mut n, mut count) = (0u16, 0u32, 0usize, 0usize);
    for c in text.bytes() {
        if matches!(c, b'-' | b' ' | b'\t') {
            continue;
        }
        let value = match c.to_ascii_uppercase() {
            u @ b'A'..=b'Z' => u.wrapping_sub(b'A'),
            d @ b'2'..=b'7' => d.wrapping_sub(b'2').wrapping_add(26),
            _ => return None,
        };
        count = count.wrapping_add(1);
        acc = acc.wrapping_shl(5) | u16::from(value);
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            *out.expose_mut().get_mut(n)? = u8::try_from(acc.wrapping_shr(bits)).ok()?;
            n = n.wrapping_add(1);
            acc &= 1u16.wrapping_shl(bits).wrapping_sub(1);
        }
    }
    let unused =
        u32::try_from(chars(len).wrapping_mul(5).wrapping_sub(len.wrapping_mul(8))).ok()?;
    (count == chars(len) && n == len && bits == unused && acc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 section 10's base32 vectors, without their padding, and
    /// the two lengths Larsal reads.
    #[test]
    fn rfc4648_vectors_and_larsals_two_lengths() {
        for (bytes, text) in [
            (&b"f"[..], "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(encode(bytes, false).expose(), text);
            assert_eq!(read(text, bytes.len()).unwrap().expose(), bytes);
        }
        assert_eq!((chars(16), chars(32)), (26, 52));
        let code: Vec<u8> = (0u8..16).collect();
        let grouped = encode(&code, true);
        assert_eq!(grouped.expose(), "AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4");
        assert_eq!(encode(&code, false).expose(), "AAAQEAYEAUDAOCAJBIFQYDIOB4");
        // Read case-blind, separators ignored.
        for typed in [
            "AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4",
            "aaaq eayE auda ocaj bifq ydio b4",
            "aaaqeayeaudaocajbifqydiob4",
            " AAAQ\tEAYE-AUDA OCAJ-BIFQ YDIO-B4 ",
        ] {
            assert_eq!(read(typed, 16).unwrap().expose(), code, "{typed:?}");
        }
        // Wrong length, a character outside the alphabet, unused bits set.
        for bad in [
            "AAAQEAYEAUDAOCAJBIFQYDIOB",
            "AAAQEAYEAUDAOCAJBIFQYDIOB4A",
            "AAAQEAYEAUDAOCAJBIFQYDIOB1",
            "AAAQEAYEAUDAOCAJBIFQYDIOB5",
            "AAAQEAYEAUDAOCAJBIFQYDIOB=",
            "",
        ] {
            assert!(read(bad, 16).is_none(), "{bad:?}");
        }
    }
}
