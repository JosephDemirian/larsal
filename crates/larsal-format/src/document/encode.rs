//! Value encodings of the document (FMT-12): times, booleans, three-state
//! switches, integers, ids, base64, and protected text decoding (FMT-09.15).
//!
//! Every function here works on one value's text, never panics, and never
//! allocates more than a small multiple of its input.

use larsal_model::{Switch, Time, Uuid, times::Civil};

/// Lenient base64 decode (FMT-12.20): skips every character outside
/// `A-Z a-z 0-9 + /` (padding, white space, `-`, `_` included), emits a byte
/// per 8 collected bits, drops leftover bits. Never fails; the output is at
/// most three quarters of the input length.
#[must_use]
pub fn base64_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(base64_decoded_len(text));
    base64_decode_into(text, |b| out.push(b));
    out
}

/// Same as [`base64_decode`], handing each byte to `push`, so callers can
/// decode straight into a buffer that is wiped on drop.
pub fn base64_decode_into(text: &str, push: impl FnMut(u8)) {
    base64_decode_bytes(text.bytes(), push);
}

/// [`base64_decode_into`] over text given as a run of bytes, for a value
/// whose text came in several pieces (one decode, no joined copy).
pub fn base64_decode_bytes(bytes: impl Iterator<Item = u8>, mut push: impl FnMut(u8)) {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in bytes {
        let Some(v) = sextet(c) else { continue };
        acc = (acc.wrapping_shl(6) | u32::from(v)) & 0xFFFF;
        bits = bits.wrapping_add(6);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            push((acc.wrapping_shr(bits) & 0xFF) as u8);
        }
    }
}

/// Number of bytes [`base64_decode`] gives for `text`.
#[must_use]
pub fn base64_decoded_len(text: &str) -> usize {
    base64_decoded_len_bytes(text.bytes())
}

/// [`base64_decoded_len`] over text given as a run of bytes.
#[must_use]
pub fn base64_decoded_len_bytes(bytes: impl Iterator<Item = u8>) -> usize {
    let n = bytes.filter(|c| sextet(*c).is_some()).count();
    // n * 6 / 8 without overflow: n is at most the text length.
    (n / 4).saturating_mul(3).saturating_add(match n % 4 {
        2 => 1,
        3 => 2,
        _ => 0,
    })
}

fn sextet(c: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|i| u8::try_from(i).ok())
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with `=` padding, no line breaks (FMT-12.21).
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() / 3).saturating_add(1).saturating_mul(4));
    base64_each(data, |c| out.push(char::from(c)));
    out
}

/// [`base64_encode`], one output byte at a time, so a caller can write it
/// straight into a wiping buffer (the plain XML export, FEA-09.14).
pub(crate) fn base64_each(data: &[u8], mut push: impl FnMut(u8)) {
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .chain(core::iter::repeat(&0))
            .take(3)
            .fold(0u32, |n, &b| n.wrapping_shl(8) | u32::from(b));
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                let idx = (n.wrapping_shr(shift) & 63) as usize;
                push(ALPHABET.get(idx).copied().unwrap_or(b'A'));
            } else {
                push(b'=');
            }
        }
    }
}

/// True when `text` has the strict base64 shape of FMT-12.4: groups of four
/// alphabet characters, the last one optionally `xxx=` or `xx==`, nothing
/// else. Empty text has the shape.
#[must_use]
pub fn has_base64_shape(text: &str) -> bool {
    let b = text.as_bytes();
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    b.len().is_multiple_of(4)
        && pad <= 2
        && b.iter()
            .take(b.len().saturating_sub(pad))
            .all(|c| sextet(*c).is_some())
}

/// A time from its text (FMT-12.4 to FMT-12.7): the binary form when the
/// text has the base64 shape, otherwise Larsal's text grammar; invalid text is
/// `open_time`. Never fails.
#[must_use]
pub fn parse_time(text: &str, open_time: Time) -> Time {
    if has_base64_shape(text) {
        let mut raw = [0u8; 8];
        let mut slots = raw.iter_mut();
        base64_decode_into(text, |b| {
            if let Some(slot) = slots.next() {
                *slot = b;
            }
        });
        return Time(i64::from_le_bytes(raw));
    }
    parse_text_time(text).unwrap_or(open_time)
}

/// The binary form of a time (FMT-12.2): base64 of the 8-byte little-endian
/// seconds count, always 12 characters.
#[must_use]
pub fn time_to_binary(t: Time) -> String {
    base64_encode(&t.0.to_le_bytes())
}

/// A cursor over the ASCII bytes of a time text.
struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    /// Takes exactly `n` ASCII digits as a number.
    fn digits(&mut self, n: usize) -> Option<u32> {
        let (d, rest) = self.0.split_at_checked(n)?;
        let v = d.iter().try_fold(0u32, |acc, c| {
            c.is_ascii_digit()
                .then(|| acc.checked_mul(10)?.checked_add(u32::from(c & 0x0F)))
                .flatten()
        })?;
        self.0 = rest;
        Some(v)
    }

    /// Takes one byte when it is one of `set`.
    fn take(&mut self, set: &[u8]) -> Option<u8> {
        let (&c, rest) = self.0.split_first()?;
        set.contains(&c).then(|| {
            self.0 = rest;
            c
        })
    }

    fn peek_digit(&self) -> bool {
        self.0.first().is_some_and(u8::is_ascii_digit)
    }

    /// True when only a final `Z` or `z` is left, or nothing.
    fn at_end_or_z(&self) -> bool {
        matches!(self.0, [] | [b'Z' | b'z'])
    }
}

/// Larsal's text time grammar (FMT-12.6). `None` when the text does not match.
fn parse_text_time(text: &str) -> Option<Time> {
    let mut c = Cursor(text.as_bytes());
    let year = c.digits(4)?;
    c.take(b"-")?;
    let month = c.digits(2)?;
    c.take(b"-")?;
    let day = c.digits(2)?;
    let date = Time::from_civil(Civil {
        year: i64::from(year),
        month,
        day,
        hour: 0,
        minute: 0,
        second: 0,
    })?;
    if c.0.is_empty() {
        return Some(date);
    }
    c.take(b"Tt ")?;
    let hour = c.digits(2)?;
    c.take(b":")?;
    let minute = c.digits(2)?;
    let mut second = 0;
    let mut whole = true;
    if c.take(b":").is_some() {
        second = c.digits(2)?;
        if c.take(b".,").is_some() {
            if !c.peek_digit() {
                return None;
            }
            while c.peek_digit() {
                c.0 = c.0.get(1..)?;
            }
            whole = false;
        }
    }
    let end_of_day = hour == 24 && minute == 0 && second == 0 && whole;
    if (hour > 23 && !end_of_day) || minute > 59 || second > 59 {
        return None;
    }
    let of_day = hour
        .checked_mul(3600)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    let mut secs = date.0.checked_add(i64::from(of_day))?;
    if !c.at_end_or_z() {
        let sign = c.take(b"+-")?;
        let oh = c.digits(2)?;
        let om = if c.take(b":").is_some() || c.peek_digit() {
            c.digits(2)?
        } else {
            0
        };
        if oh > 23 || om > 59 {
            return None;
        }
        if c.0.is_empty() {
            let off = i64::from(oh.checked_mul(3600)?.checked_add(om.checked_mul(60)?)?);
            secs = if sign == b'+' {
                secs.checked_sub(off)?
            } else {
                secs.checked_add(off)?
            };
        } else if !c.at_end_or_z() {
            return None;
        }
        // An offset directly followed by `Z` is read as UTC (rule 6).
    }
    Some(Time(secs))
}

/// Folds a text for the boolean and switch words (FMT-12.10): ASCII letters
/// lowercased and U+017F (long s) read as `s`, the only fold that can make
/// these words; any other character stays and so fails the compare.
fn folds_to(text: &str, word: &str) -> bool {
    let mut w = word.chars();
    for c in text.chars() {
        let f = if c == '\u{17F}' {
            's'
        } else {
            c.to_ascii_lowercase()
        };
        if w.next() != Some(f) {
            return false;
        }
    }
    w.next().is_none()
}

/// A boolean element (FMT-12.10): `true`/`false` in any case, empty is
/// false, anything else `None` (the document is rejected).
#[must_use]
pub fn parse_bool(text: &str) -> Option<bool> {
    if text.is_empty() || folds_to(text, "false") {
        Some(false)
    } else if folds_to(text, "true") {
        Some(true)
    } else {
        None
    }
}

/// A three-state switch (FMT-12.12): `null`, `true` or `false` in any case;
/// anything else, empty included, is `None` (the document is rejected).
#[must_use]
pub fn parse_switch(text: &str) -> Option<Switch> {
    if folds_to(text, "null") {
        Some(Switch::Inherit)
    } else if folds_to(text, "true") {
        Some(Switch::On)
    } else if folds_to(text, "false") {
        Some(Switch::Off)
    } else {
        None
    }
}

/// An attribute boolean (FMT-12.13): `true` in any ASCII case, or exactly `1`.
#[must_use]
pub fn attr_true(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true")
}

/// A 32-bit integer (FMT-12.15): Unicode white space trimmed, one optional
/// sign (`+`, `-` or U+2212), then ASCII digits; `None` otherwise or when it
/// does not fit (the document is rejected).
#[must_use]
pub fn parse_i32(text: &str) -> Option<i32> {
    let t = text.trim();
    let (neg, rest) = if let Some(r) = t.strip_prefix('-').or_else(|| t.strip_prefix('\u{2212}')) {
        (true, r)
    } else if let Some(r) = t.strip_prefix('+') {
        (false, r)
    } else {
        (false, t)
    };
    if rest.is_empty() {
        return None;
    }
    let v = rest.bytes().try_fold(0i64, |acc, c| {
        if !c.is_ascii_digit() || acc > 1 << 31 {
            return None;
        }
        acc.checked_mul(10)?.checked_add(i64::from(c & 0x0F))
    })?;
    i32::try_from(if neg { v.checked_neg()? } else { v }).ok()
}

/// An id (FMT-12.17): lenient base64; any length other than 16 bytes, or 16
/// zero bytes, is the zero id. Never fails.
#[must_use]
pub fn parse_uuid(text: &str) -> Uuid {
    uuid_from_bytes(&base64_decode(text))
}

/// 16 bytes as an id; any other length is the zero id (FMT-12.17).
#[must_use]
pub fn uuid_from_bytes(bytes: &[u8]) -> Uuid {
    <[u8; 16]>::try_from(bytes).map_or(Uuid::ZERO, Uuid)
}

/// The text form of an id (FMT-12.16): always 24 characters.
#[must_use]
pub fn uuid_to_text(u: Uuid) -> String {
    base64_encode(&u.0)
}

/// Decodes the plaintext of a protected text value (FMT-09.15): one leading
/// `EF BB BF` dropped (LD-25), then every well-formed UTF-8 sequence (RFC
/// 3629) kept, and every byte that is not part of one replaced by its own
/// U+FFFD. `00` bytes are kept as U+0000. The result has exact capacity, so
/// it can go straight into a `SecretString` without a stray copy.
#[must_use]
pub fn decode_protected_text(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let mut len = 0usize;
    walk_utf8(bytes, |s| len = len.saturating_add(s.len()));
    let mut out = String::with_capacity(len);
    walk_utf8(bytes, |s| out.push_str(s));
    out
}

/// Calls `f` with each decoded piece: a valid run, or "\u{FFFD}" per bad byte.
fn walk_utf8(mut bytes: &[u8], mut f: impl FnMut(&str)) {
    while !bytes.is_empty() {
        match core::str::from_utf8(bytes) {
            Ok(s) => {
                f(s);
                return;
            }
            Err(e) => {
                let (good, rest) = bytes.split_at(e.valid_up_to());
                // `good` is valid UTF-8 by the error's own report.
                f(core::str::from_utf8(good).unwrap_or(""));
                f("\u{FFFD}");
                bytes = rest.get(1..).unwrap_or(&[]);
            }
        }
    }
}

/// True for a character of the XML 1.0 Char set (FMT-12.24). Rust `char`
/// excludes lone surrogates already.
#[must_use]
pub fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

#[cfg(test)]
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const OPEN: Time = Time(63_928_466_372); // 2026-10-24T19:19:32Z

    // FMT-12.20 lenient decode.
    #[test]
    fn fmt_12_20_lenient_decode() {
        let cases: [(&str, &[u8]); 9] = [
            ("QUJDRA==", b"ABCD"),
            ("QUJD RA==", b"ABCD"),
            ("QUJDRA", b"ABCD"),
            ("QUJDR", b"ABC"),
            ("QUJDRB==", b"ABCD"),
            ("QUJDRA=AQ==", &[0x41, 0x42, 0x43, 0x44, 0x00, 0x10]),
            ("-_", b""),
            ("====", b""),
            ("", b""),
        ];
        for (text, want) in cases {
            assert_eq!(base64_decode(text), want, "{text}");
            assert_eq!(base64_decoded_len(text), want.len(), "{text}");
        }
    }

    // FMT-12.21 encode.
    #[test]
    fn fmt_12_21_encode() {
        assert_eq!(
            base64_encode(b"this is an attachment"),
            "dGhpcyBpcyBhbiBhdHRhY2htZW50"
        );
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"A"), "QQ==");
        assert_eq!(base64_encode(b"AB"), "QUI=");
    }

    // FMT-12.1, FMT-12.2 binary write.
    #[test]
    fn fmt_12_2_binary_write() {
        assert_eq!(time_to_binary(Time(63_416_885_093)), "Zd/www4AAAA=");
        assert_eq!(time_to_binary(Time(63_928_396_800)), "AOxt4g4AAAA=");
        assert_eq!(time_to_binary(Time(0)), "AAAAAAAAAAA=");
        assert_eq!(time_to_binary(Time(315_537_897_599)), "fziGd0kAAAA=");
        assert_eq!(
            time_to_binary(Time::from_unix(1 << 31).unwrap()),
            "APeR9w4AAAA="
        );
        assert_eq!(
            Time(62_135_596_800).0.to_le_bytes(),
            [0x00, 0xF7, 0x91, 0x77, 0x0E, 0, 0, 0]
        );
    }

    // FMT-12.4 form choice and shape.
    #[test]
    fn fmt_12_4_form_choice() {
        assert_eq!(parse_time("Zd/www4AAAA=", OPEN), Time(63_416_885_093));
        assert_eq!(
            parse_time("2010-08-08T17:24:53Z", OPEN),
            Time(63_416_885_093)
        );
        assert_eq!(parse_time("AAAAAAAAAAA", OPEN), OPEN);
        assert_eq!(parse_time("Zd/www4AAAA=\n", OPEN), OPEN);
        assert!(has_base64_shape(""));
        assert!(has_base64_shape("QUI="));
        assert!(has_base64_shape("QQ=="));
        assert!(!has_base64_shape("Q==A"));
        assert!(!has_base64_shape("Q=A="));
        assert!(!has_base64_shape("===="));
    }

    // FMT-12.5 binary read.
    #[test]
    fn fmt_12_5_binary_read() {
        assert_eq!(parse_time("", OPEN), Time(0));
        assert_eq!(parse_time("AQAAAA==", OPEN), Time(1));
        assert_eq!(parse_time("Zd/www4AAAABAgME", OPEN), Time(63_416_885_093));
        assert_eq!(parse_time("//////////8=", OPEN), Time(-1));
        assert_eq!(parse_time("AAAA", OPEN), Time(0));
        assert_eq!(parse_time("20100808", OPEN), Time(66_854_713_576_923));
        assert_eq!(parse_time("/////////38=", OPEN), Time(i64::MAX));
        assert_eq!(parse_time("AAAAAAAAAIA=", OPEN), Time(i64::MIN));
    }

    // FMT-12.6 text forms, every accepted row.
    #[test]
    fn fmt_12_6_text_accepted() {
        let cases: [(&str, i64); 30] = [
            ("2010-08-08T17:24:53Z", 63_416_885_093),
            ("2010-08-08T17:24:53z", 63_416_885_093),
            ("2010-08-08t17:24:53Z", 63_416_885_093),
            ("2010-08-08T17:24:53+02:00", 63_416_877_893),
            ("2010-08-08T17:24:53+05:00", 63_416_867_093),
            ("2010-08-08T17:24:53+0500", 63_416_867_093),
            ("2010-08-08T17:24:53+05", 63_416_867_093),
            ("2010-08-08T17:24:53-05:30", 63_416_904_893),
            ("2010-08-08T17:24:53-0530", 63_416_904_893),
            ("2010-08-08T17:24:53-05", 63_416_903_093),
            ("2010-08-08T17:24:53+00:00", 63_416_885_093),
            ("2010-08-08T17:24:53-00:00", 63_416_885_093),
            ("2010-08-08T17:24:53+23:59", 63_416_798_753),
            ("2010-08-08T17:24:53.789Z", 63_416_885_093),
            ("2010-08-08T17:24:53,5Z", 63_416_885_093),
            ("2010-08-08T17:24:53.1234567Z", 63_416_885_093),
            ("2010-08-08T17:24:53.5+02:00", 63_416_877_893),
            ("2010-08-08 17:24:53Z", 63_416_885_093),
            ("2010-08-08T17:24Z", 63_416_885_040),
            ("2010-08-08T17:24+05:00", 63_416_867_040),
            ("2010-08-08T24:00:00Z", 63_416_908_800),
            ("2010-08-08T24:00Z", 63_416_908_800),
            ("2010-08-08T17:24:53+02:00Z", 63_416_885_093),
            ("2010-08-08T17:24:53+05:00Z", 63_416_885_093),
            ("2010-08-08T17:24:53", 63_416_885_093),
            ("2010-08-08", 63_416_822_400),
            ("2010-08-08T17:24", 63_416_885_040),
            ("9999-12-31T24:00:00Z", 315_537_897_600),
            ("0001-01-01T00:00:00+01:00", -3600),
            ("9999-12-31T23:59:59-01:00", 315_537_901_199),
        ];
        for (text, want) in cases {
            assert_eq!(parse_time(text, OPEN), Time(want), "{text}");
        }
    }

    // FMT-12.28 k: Larsal reads an offset before a final Z as UTC.
    #[test]
    fn fmt_12_28_k_offset_then_z() {
        for (text, want) in [
            ("2010-08-08T17:24+02:00Z", 63_416_885_040),
            ("2010-08-08T17:24+0200Z", 63_416_885_040),
            ("2010-08-08T17:24-05Z", 63_416_885_040),
            ("2010-08-08T24:00+02:00Z", 63_416_908_800),
            ("2010-08-08T17:24:53.5+02:00Z", 63_416_885_093),
            ("2010-08-08T17:24:53,5+02:00Z", 63_416_885_093),
            ("2010-08-08T17:24:53.12+02:00Z", 63_416_885_093),
            ("2010-08-08T17:24:53.123+02:00Z", 63_416_885_093),
            ("2010-08-08T17:24:53+0200Z", 63_416_885_093),
            ("2010-08-08T17:24:53+02Z", 63_416_885_093),
            ("2010-08-08T17:24:53-05:30z", 63_416_885_093),
            ("2010-08-08T17:24:53.1234+02:00Z", 63_416_885_093),
            ("2010-08-08T24:00:00+02:00Z", 63_416_908_800),
            ("2010-08-08T24:00:00-05:00Z", 63_416_908_800),
            ("2010-08-08T17:24:53.12345Z", 63_416_885_093),
        ] {
            assert_eq!(parse_time(text, OPEN), Time(want), "{text}");
        }
    }

    // FMT-12.6 invalid in both, and FMT-12.28 a to j, l: Larsal reads open time.
    #[test]
    fn fmt_12_6_and_12_28_invalid() {
        let s = "2010-08-08T17:24:53";
        let owned = [
            format!("{s} "),
            format!("{s}\n"),
            format!("{s}Z "),
            format!("{s}Z\n"),
            format!("{s}garbage"),
            format!("{s}UTC"),
            format!("{s}Zgarbage"),
            format!("{s} Z"),
            format!("{s}xyzZ"),
            format!("{s} +05:00"),
            format!("{s}x+05:00"),
            format!("{s}+5"),
            format!("{s}+050"),
            format!("{s}+05:0"),
            format!("{s}+05:3"),
            format!("{s}+5:30"),
            format!("{s}+-05:00"),
            format!("{s}+24:00"),
            format!("{s}+02:60"),
            format!("{s}+05:00:00"),
            format!("{s}+02:00 "),
            format!("{s}-garbage"),
            format!("{s}.5Zjunk"),
            format!("{s}.5garbage"),
            format!("{s}.12garbage"),
            format!("{s}.5xyzZ"),
            format!("{s}.1234garbage"),
            format!("{s}.5 "),
            format!("{s}.5\u{A0}"),
            format!("{s}."),
            format!("{s}.Z"),
            format!("{s}.1234xyzZ"),
            format!("{s}.123 Z"),
            format!("{s}.1234x+05:00"),
            format!("{s}.12 3Z"),
            format!("{s}. Z"),
            format!("{s}.\u{665}Z"),
            format!("{s}.5x+05:00"),
        ];
        let fixed = [
            " 2010-08-08T17:24:53Z",
            "+2010-08-08T17:24:53Z",
            "10000-01-01T00:00:00Z",
            "0000-01-01T00:00:00Z",
            "2010-8-8T17:24:53Z",
            "2010-08-08T7:24:53Z",
            "2010-08-08T17:4:53Z",
            "2010-08-08T17Z",
            "2010-08-08T24:00:01Z",
            "2010-08-08T24:00:00.5Z",
            "2010-08-08T25:00:00Z",
            "2010-08-08T17:60:00Z",
            "2016-12-31T23:59:60Z",
            "2010-02-30T00:00:00Z",
            "2010-08-08Z",
            "2010-08-08T",
            "2010-08-08 ",
            "2010-08-08x17:24:53Z",
            "2010-08-08T17:24:Z",
            "2010-08-08T17:24xZ",
            "2010-08-08T17:24 Z",
            "2010-08-08T17.5Z",
            "2010-08-08T17,5Z",
            "2010-08-08T17:24.Z",
            "2010-08-08T17:24.5xZ",
            "2010-08-08T17:24.5 ",
            "2010-08-08T17:24.5Z",
            "2010-08-08T17:24,5Z",
            "2010-08-08T17:24.25+05:00",
            "2010-08-08T24:00.0Z",
            "2010-08-08T17:24.5",
            "2010+08+08T17:24:53Z",
            "2010~08~08T17:24:53Z",
            "2010 08 08T17:24:53Z",
            "2010--8-08T17:24:53Z",
            "2010-08-08T17:24:-5Z",
            "2010-08-08T17:24:5Z",
            "2010/08/08T17:24:53Z",
            "2010.08.08T17:24:53Z",
            "2010/08/08",
            "2010-+8-08T17:24:53Z",
            "2010-08-08T+7:24:53Z",
            "+201-08-08T17:24:53Z",
            "2010-08-08T24:00:00.0Z",
            "2010-08-08T24:00:00,000Z",
            "2010-08-08T24:00:00.0004Z",
            "2010-08-08T24:00:00.0+02:00",
            "2010-08-08T24:00:00.0+02:00Z",
            "garbage",
        ];
        for text in owned.iter().map(String::as_str).chain(fixed) {
            assert_eq!(parse_time(text, OPEN), OPEN, "{text:?}");
        }
    }

    // FMT-12.10, FMT-12.11 (read side).
    #[test]
    fn fmt_12_10_booleans() {
        for t in ["true", "TRUE", "tRuE"] {
            assert_eq!(parse_bool(t), Some(true), "{t}");
        }
        for t in ["False", "", "fal\u{17F}e"] {
            assert_eq!(parse_bool(t), Some(false), "{t}");
        }
        for t in ["1", "0", "yes", " True ", "True\n", "tru\u{E9}"] {
            assert_eq!(parse_bool(t), None, "{t:?}");
        }
    }

    // FMT-12.12 three-state.
    #[test]
    fn fmt_12_12_switches() {
        for (t, want) in [
            ("null", Switch::Inherit),
            ("NULL", Switch::Inherit),
            ("nuLL", Switch::Inherit),
            ("true", Switch::On),
            ("TRUE", Switch::On),
            ("false", Switch::Off),
            ("fal\u{17F}e", Switch::Off),
        ] {
            assert_eq!(parse_switch(t), Some(want), "{t}");
        }
        for t in ["", "1", "0", " null", "inherit"] {
            assert_eq!(parse_switch(t), None, "{t:?}");
        }
    }

    // FMT-12.13 attribute booleans.
    #[test]
    fn fmt_12_13_attribute() {
        assert!(attr_true("1"));
        assert!(attr_true("TRUE"));
        assert!(attr_true("True"));
        assert!(!attr_true("yes"));
        assert!(!attr_true(""));
        assert!(!attr_true("False"));
    }

    // FMT-12.15 integers.
    #[test]
    fn fmt_12_15_integers() {
        for (t, want) in [
            (" -1 ", -1),
            ("+7", 7),
            ("007", 7),
            ("\t8\n", 8),
            ("\u{A0}5\u{A0}", 5),
            ("\u{2002}5", 5),
            ("-2147483648", i32::MIN),
            ("2147483647", i32::MAX),
            ("\u{2212}5", -5),
            (" \u{2212}5 ", -5),
            ("\u{2212}05", -5),
            ("\u{2212}0", 0),
            ("\u{2212}2147483648", i32::MIN),
        ] {
            assert_eq!(parse_i32(t), Some(want), "{t:?}");
        }
        for t in [
            "",
            "0x10",
            "7.0",
            "1e3",
            "- 1",
            "--1",
            "1,000",
            "1 000",
            "2147483648",
            "-2147483649",
            "\u{661}",
            "\u{2212} 5",
            "5\u{2212}",
            "\u{2212}\u{2212}5",
            "+-5",
            "\u{2212}+5",
            "+\u{2212}5",
            "\u{FF0D}5",
            "\u{FE63}5",
            "\u{2013}5",
            "\u{FF0B}5",
            "\u{207A}5",
            "\u{2212}2147483649",
            "99999999999999999999",
        ] {
            assert_eq!(parse_i32(t), None, "{t:?}");
        }
    }

    // FMT-12.16, FMT-12.17 ids.
    #[test]
    fn fmt_12_16_17_ids() {
        let want = Uuid([
            0xAC, 0x7E, 0x31, 0xA7, 0x5F, 0xF7, 0x4A, 0x85, 0x90, 0x79, 0x84, 0xCB, 0x77, 0x01,
            0x4D, 0x54,
        ]);
        assert_eq!(uuid_to_text(want), "rH4xp1/3SoWQeYTLdwFNVA==");
        assert_eq!(uuid_to_text(Uuid::ZERO), "AAAAAAAAAAAAAAAAAAAAAA==");
        for t in [
            "rH4xp1/3 SoWQe\nYTLdwFNVA==",
            "rH4xp1/3SoWQeYTLdwFNVA",
            "rH4xp1/3SoWQeYTL=dwFNVA==",
        ] {
            assert_eq!(parse_uuid(t), want, "{t:?}");
        }
        for t in [
            "rH4xp1/3SoWQeYTLdwFN",
            "rH4xp1/3SoWQeYTLdwFNVAA=",
            "rH4xp1_3SoWQeYTLdwFNVA==",
            "!!!!",
            "",
            "AAAAAAAAAAAAAAAAAAAAAA==",
        ] {
            assert_eq!(parse_uuid(t), Uuid::ZERO, "{t:?}");
        }
    }

    // FMT-09.15 (T09-41, T09-42 shapes) and LD-25.
    #[test]
    fn fmt_09_15_protected_text_decoding() {
        assert_eq!(decode_protected_text(&[0xEF, 0xBB, 0xBF, 0x41]), "A");
        assert_eq!(
            decode_protected_text(&[0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF, 0x41]),
            "\u{FEFF}A"
        );
        // Per byte, not maximal subpart: E2 82 41 gives two U+FFFD.
        assert_eq!(
            decode_protected_text(&[0xE2, 0x82, 0x41]),
            "\u{FFFD}\u{FFFD}A"
        );
        assert_eq!(decode_protected_text(&[0x61, 0x00, 0x62]), "a\u{0}b");
        assert_eq!(decode_protected_text(&[0xC0, 0xAF]), "\u{FFFD}\u{FFFD}");
        assert_eq!(
            decode_protected_text(&[0xED, 0xA0, 0x80]),
            "\u{FFFD}\u{FFFD}\u{FFFD}"
        );
        assert_eq!(decode_protected_text("é\u{FFFE}".as_bytes()), "é\u{FFFE}");
        let s = decode_protected_text(b"Secret");
        assert_eq!(s.capacity(), s.len());
    }

    // FMT-12.24 character set.
    #[test]
    fn fmt_12_24_xml_chars() {
        for c in [
            '\t',
            '\n',
            '\r',
            ' ',
            '\u{80}',
            '\u{D7FF}',
            '\u{E000}',
            '\u{FFFD}',
            '\u{10437}',
        ] {
            assert!(is_xml_char(c), "{c:?}");
        }
        for c in [
            '\u{0}', '\u{1}', '\u{B}', '\u{C}', '\u{1F}', '\u{FFFE}', '\u{FFFF}',
        ] {
            assert!(!is_xml_char(c), "{c:?}");
        }
    }
}
