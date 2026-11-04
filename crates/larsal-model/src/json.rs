//! Larsal's own JSON reader and writer (RFC 8259; E0-S7 R12, in place of
//! `serde_json`): the settings files, the saved searches and browser items
//! a vault keeps as text, and the line one Larsal instance sends another.
//!
//! Guarantees:
//! - The reader takes untrusted bytes and never panics. Input longer than
//!   [`MAX_INPUT`] bytes is refused before anything is read; nesting deeper
//!   than [`MAX_DEPTH`] is refused before it is built (the recursion is
//!   bounded by it); any other problem is an [`Error`] with its byte offset.
//! - It is strict: one value with only whitespace around it, UTF-8, no
//!   comments or trailing commas, no raw control characters or lone
//!   surrogates in strings, and no number too large for an `f64`.
//! - Objects keep their members sorted by key (a [`Map`]), as the old
//!   crate did: a repeated key keeps its last value, or is refused by
//!   [`from_slice_unique`]. So every file Larsal writes has the bytes it had.
//! - A number is kept as written, and written back the same.
//! - The writer is the compact form, or the pretty form with two spaces.
//!
//! Not for secrets: strings are plain `String`s, freed unwiped. Imports,
//! which hold passwords, have their own reader (larsal-core `import/json.rs`).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

/// The longest input the reader takes, in bytes (the largest expected
/// export of the test data is 13.6 MB; Larsal's own files are at most 1 MiB).
pub const MAX_INPUT: usize = 16 << 20;
/// The deepest nesting of arrays and objects the reader takes; the old
/// crate's limit (128 levels refused, 127 taken).
pub const MAX_DEPTH: usize = 127;

/// An object's members, sorted by key.
pub type Map = BTreeMap<String, Value>;

/// One JSON value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Value {
    /// `null`; also what a missing member reads as through `value["key"]`.
    #[default]
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as written.
    Number(Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Map),
}

/// A number as written in the input, or as Larsal wrote it: always the RFC 8259
/// grammar, and never too large for an `f64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number(String);

impl Number {
    /// The value when it is a whole number written without a fraction or an
    /// exponent and fits an `i64`; `None` otherwise (as the old crate:
    /// `-0`, `1.0` and `1e2` are not whole numbers).
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.whole()?.parse().ok()
    }

    /// As [`Number::as_i64`], for an `u64`.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.whole()?.parse().ok()
    }

    fn whole(&self) -> Option<&str> {
        (!self.0.contains(['.', 'e', 'E']) && self.0 != "-0").then_some(self.0.as_str())
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

static NULL: Value = Value::Null;

impl Value {
    /// The flag of a `Bool`.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// A whole `Number` that fits an `i64` ([`Number::as_i64`]).
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    /// A whole `Number` that fits an `u64` ([`Number::as_u64`]).
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    /// The text of a `String`.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The items of an `Array`.
    #[must_use]
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The items of an `Array`, to change.
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The members of an `Object`.
    #[must_use]
    pub fn as_object(&self) -> Option<&Map> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    /// The member `key` of an `Object`; `None` for a missing key or any
    /// other value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.get(key)
    }

    /// As [`Value::get`], to change.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        match self {
            Value::Object(m) => m.get_mut(key),
            _ => None,
        }
    }
}

/// `value["key"]`: the member, or `Null` when there is none.
impl std::ops::Index<&str> for Value {
    type Output = Value;
    fn index(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&NULL)
    }
}

impl PartialEq<i64> for Value {
    fn eq(&self, other: &i64) -> bool {
        self.as_i64() == Some(*other)
    }
}

impl PartialEq<bool> for Value {
    fn eq(&self, other: &bool) -> bool {
        self.as_bool() == Some(*other)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

macro_rules! from_int {
    ($($t:ty),*) => {$(
        impl From<$t> for Value {
            fn from(n: $t) -> Self {
                Value::Number(Number(n.to_string()))
            }
        }
    )*};
}
from_int!(i32, i64, u32, u64);

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(items: Vec<T>) -> Self {
        Value::Array(items.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<Value>, const N: usize> From<[T; N]> for Value {
    fn from(items: [T; N]) -> Self {
        Value::Array(items.into_iter().map(Into::into).collect())
    }
}

impl From<Map> for Value {
    fn from(m: Map) -> Self {
        Value::Object(m)
    }
}

/// An object from string keys and values that turn into a [`Value`]:
/// `json!({"v": 1, "cmd": "open"})`, `json!({})`. Nested objects are built
/// with a nested `json!`.
#[macro_export]
macro_rules! json {
    ({ $($key:literal : $value:expr),* $(,)? }) => {{
        #[allow(unused_mut)]
        let mut map = $crate::json::Map::new();
        $(map.insert(::std::string::String::from($key), $crate::json::Value::from($value));)*
        $crate::json::Value::Object(map)
    }};
}

/// The compact form, as [`to_string`].
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_string(self))
    }
}

/// Input that is not JSON Larsal takes, with the byte offset where reading
/// stopped. It never holds text from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// The byte offset.
    pub at: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not valid JSON at byte {}", self.at)
    }
}

impl std::error::Error for Error {}

/// Reads one JSON value; a repeated key keeps its last value.
///
/// # Errors
/// [`Error`] for anything else (module guarantees).
pub fn from_slice(bytes: &[u8]) -> Result<Value, Error> {
    read(bytes, false)
}

/// As [`from_slice`], from text.
///
/// # Errors
/// As [`from_slice`].
pub fn from_str(text: &str) -> Result<Value, Error> {
    read(text.as_bytes(), false)
}

/// As [`from_slice`], but an object with a repeated key is refused.
///
/// # Errors
/// As [`from_slice`].
pub fn from_slice_unique(bytes: &[u8]) -> Result<Value, Error> {
    read(bytes, true)
}

/// The compact form: no whitespace, members in key order.
#[must_use]
pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out, None);
    out
}

/// The pretty form: one item per line, two spaces per level, `": "`
/// after a key, `[]` and `{}` when empty, no newline at the end.
#[must_use]
pub fn to_string_pretty(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out, Some(0));
    out
}

// ponytail: the writer recurses; values come from the reader (at most
// MAX_DEPTH deep) or from Larsal's own code (a few levels).
fn write(value: &Value, out: &mut String, level: Option<usize>) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.0),
        Value::String(s) => quote(s, out),
        Value::Array(a) => seq(out, ['[', ']'], a.iter().map(|v| (None, v)), level),
        Value::Object(m) => seq(
            out,
            ['{', '}'],
            m.iter().map(|(k, v)| (Some(k.as_str()), v)),
            level,
        ),
    }
}

fn seq<'a>(
    out: &mut String,
    [open, close]: [char; 2],
    items: impl Iterator<Item = (Option<&'a str>, &'a Value)>,
    level: Option<usize>,
) {
    let inner = level.map(|l| l.saturating_add(1));
    let line = |out: &mut String, l: usize| {
        out.push('\n');
        (0..l).for_each(|_| out.push_str("  "));
    };
    out.push(open);
    let mut empty = true;
    for (key, value) in items {
        if !empty {
            out.push(',');
        }
        empty = false;
        if let Some(l) = inner {
            line(out, l);
        }
        if let Some(k) = key {
            quote(k, out);
            out.push_str(if inner.is_some() { ": " } else { ":" });
        }
        write(value, out, inner);
    }
    if let (Some(l), false) = (level, empty) {
        line(out, l);
    }
    out.push(close);
}

fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn read(bytes: &[u8], unique: bool) -> Result<Value, Error> {
    if bytes.len() > MAX_INPUT {
        return Err(Error { at: MAX_INPUT });
    }
    let mut r = Reader {
        b: bytes,
        at: 0,
        depth: 0,
        unique,
    };
    let value = r.value()?;
    r.space();
    if r.at < bytes.len() {
        return Err(r.err());
    }
    Ok(value)
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    depth: usize,
    unique: bool,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.at).copied()
    }

    fn bump(&mut self) {
        self.at = self.at.saturating_add(1);
    }

    fn err(&self) -> Error {
        Error { at: self.at }
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.peek() != Some(byte) {
            return Err(self.err());
        }
        self.bump();
        Ok(())
    }

    fn value(&mut self) -> Result<Value, Error> {
        self.space();
        match self.peek() {
            Some(b'n') => self.word(b"null", Value::Null),
            Some(b't') => self.word(b"true", Value::Bool(true)),
            Some(b'f') => self.word(b"false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b'[') => self.nested(Self::array),
            Some(b'{') => self.nested(Self::object),
            _ => Err(self.err()),
        }
    }

    fn word(&mut self, word: &[u8], value: Value) -> Result<Value, Error> {
        if !self
            .b
            .get(self.at..)
            .is_some_and(|rest| rest.starts_with(word))
        {
            return Err(self.err());
        }
        self.at = self.at.saturating_add(word.len());
        Ok(value)
    }

    /// One level down: refused past [`MAX_DEPTH`].
    fn nested(&mut self, inside: fn(&mut Self) -> Result<Value, Error>) -> Result<Value, Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.err());
        }
        self.depth = self.depth.saturating_add(1);
        self.bump();
        let value = inside(self)?;
        self.depth = self.depth.saturating_sub(1);
        Ok(value)
    }

    fn array(&mut self) -> Result<Value, Error> {
        let mut items = Vec::new();
        self.space();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.space();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.err()),
            }
        }
    }

    fn object(&mut self) -> Result<Value, Error> {
        let mut map = Map::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Value::Object(map));
        }
        loop {
            self.space();
            let at = self.at;
            if self.peek() != Some(b'"') {
                return Err(self.err());
            }
            let key = self.string()?;
            self.space();
            self.expect(b':')?;
            let value = self.value()?;
            if map.insert(key, value).is_some() && self.unique {
                return Err(Error { at });
            }
            self.space();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b'}') => {
                    self.bump();
                    return Ok(Value::Object(map));
                }
                _ => return Err(self.err()),
            }
        }
    }

    fn digits(&mut self) -> Result<(), Error> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.err());
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        Ok(())
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        if self.peek() == Some(b'0') {
            self.bump();
        } else {
            self.digits()?;
        }
        if self.peek() == Some(b'.') {
            self.bump();
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            self.digits()?;
        }
        let text = self
            .b
            .get(start..self.at)
            .and_then(|t| std::str::from_utf8(t).ok())
            .ok_or(Error { at: start })?;
        if !text.parse::<f64>().is_ok_and(f64::is_finite) {
            return Err(Error { at: start });
        }
        Ok(Value::Number(Number(text.to_owned())))
    }

    /// A string from its opening quote; escapes decoded, UTF-8 checked.
    fn string(&mut self) -> Result<String, Error> {
        let start = self.at;
        self.bump();
        let mut out = Vec::new();
        loop {
            let Some(b) = self.peek() else {
                return Err(self.err());
            };
            match b {
                b'"' => {
                    self.bump();
                    return String::from_utf8(out).map_err(|_| Error { at: start });
                }
                b'\\' => {
                    self.bump();
                    let c = self.escape()?;
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                0..0x20 => return Err(self.err()),
                _ => {
                    out.push(b);
                    self.bump();
                }
            }
        }
    }

    /// The character of the escape after a backslash.
    fn escape(&mut self) -> Result<char, Error> {
        let at = self.at;
        let c = match self.peek() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.bump();
                let high = self.hex4()?;
                let code = match high {
                    0xD800..=0xDBFF => {
                        self.expect(b'\\')?;
                        self.expect(b'u')?;
                        let low = self.hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&low) {
                            return Err(Error { at });
                        }
                        0x10000_u32
                            .saturating_add(high.saturating_sub(0xD800).saturating_mul(0x400))
                            .saturating_add(low.saturating_sub(0xDC00))
                    }
                    _ => high,
                };
                return char::from_u32(code).ok_or(Error { at });
            }
            _ => return Err(self.err()),
        };
        self.bump();
        Ok(c)
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let digits = self
            .b
            .get(self.at..self.at.saturating_add(4))
            .filter(|d| d.len() == 4 && d.iter().all(u8::is_ascii_hexdigit))
            .and_then(|d| std::str::from_utf8(d).ok())
            .ok_or_else(|| self.err())?;
        let n = u32::from_str_radix(digits, 16).map_err(|_| self.err())?;
        self.at = self.at.saturating_add(4);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Value {
        from_str(text).unwrap_or_else(|e| panic!("{text:?}: {e}"))
    }

    fn bad(text: &str) {
        assert!(from_str(text).is_err(), "{text:?} was taken");
    }

    #[test]
    fn writes_both_forms_in_key_order() {
        let v = ok(r#" {"b": [1, -2.50e+3, true, null], "a": {}, "c": [], "d": {"x": "y"}} "#);
        assert_eq!(
            to_string(&v),
            r#"{"a":{},"b":[1,-2.50e+3,true,null],"c":[],"d":{"x":"y"}}"#
        );
        assert_eq!(
            to_string_pretty(&v),
            "{\n  \"a\": {},\n  \"b\": [\n    1,\n    -2.50e+3,\n    true,\n    null\n  ],\n  \"c\": [],\n  \"d\": {\n    \"x\": \"y\"\n  }\n}"
        );
        assert_eq!(ok(&to_string_pretty(&v)), v);
        assert_eq!(to_string(&Value::from(7)), "7");
        assert_eq!(v.to_string(), to_string(&v));
    }

    #[test]
    fn strings_escape_and_decode() {
        let s = "q\"b\\s/n\nr\rt\tb\u{8}f\u{c}\u{1}\u{1f}\u{7f}é\u{1F600}";
        let text = to_string(&Value::from(s));
        assert_eq!(
            text,
            "\"q\\\"b\\\\s/n\\nr\\rt\\tb\\bf\\f\\u0001\\u001f\u{7f}é\u{1F600}\""
        );
        assert_eq!(ok(&text), Value::from(s));
        assert_eq!(ok(r#""é\/😀A""#), Value::from("é/\u{1F600}A"));
        assert_eq!(ok(r#""\uD83D\uDE00""#), Value::from("\u{1F600}"));
        for lone in [
            r#""\uD83D\nDE00""#,
            r#""\uD83DxuDE00""#,
            r#""\u+041""#,
            r#""\uD83D""#,
            r#""\uD83Dx""#,
            r#""\uD83DA""#,
            r#""\uD83D\u0041""#,
            r#""\uD83D\uD83D""#,
            r#""\uDE00""#,
            r#""\u12""#,
            r#""\x""#,
            "\"a\u{1}\"",
            "\"open",
            "\"\\",
        ] {
            bad(lone);
        }
        assert!(from_slice(b"\"\xff\"").is_err(), "not UTF-8");
        assert!(from_slice(b"\"\xc3\"").is_err(), "a cut sequence");
    }

    #[test]
    fn numbers_as_written() {
        for n in [
            "0", "-0", "12", "-12", "1.5", "1e5", "1E-5", "-0.0e+0", "1e-400",
        ] {
            assert_eq!(to_string(&ok(n)), n);
        }
        for n in [
            "01", "+1", "1.", ".5", "1e", "1e+", "-", "--1", "1e400", "-1e400", "0x1",
        ] {
            bad(n);
        }
        assert_eq!(ok("9223372036854775807").as_i64(), Some(i64::MAX));
        assert_eq!(ok("-9223372036854775808").as_i64(), Some(i64::MIN));
        assert_eq!(ok("9223372036854775808").as_i64(), None);
        assert_eq!(ok("18446744073709551615").as_u64(), Some(u64::MAX));
        assert_eq!(ok("18446744073709551616").as_u64(), None);
        for not_whole in ["-0", "1.0", "1e2", "1E2"] {
            assert_eq!(ok(not_whole).as_i64(), None, "{not_whole}");
        }
        assert_eq!(ok("-5").as_u64(), None);
        assert_eq!(ok("600"), 600);
        assert_eq!(ok("true"), true);
    }

    #[test]
    fn strict_syntax() {
        for text in [
            "",
            " ",
            "[1,]",
            "{\"a\":1,}",
            "[1 2]",
            "{\"a\" 1}",
            "{a:1}",
            "nul",
            "True",
            "[1]x",
            "{} {}",
            "\u{feff}{}",
            "// c\n{}",
            "{\"a\":}",
            "[",
            "{",
            "]",
            "'a'",
            "\u{c}1",
        ] {
            bad(text);
        }
        assert_eq!(ok(" \t\r\n[ ] \n"), Value::Array(Vec::new()));
        assert_eq!(from_str("[1,x]"), Err(Error { at: 3 }));
    }

    #[test]
    fn repeated_keys() {
        let v = ok(r#"{"a":1,"a":2}"#);
        assert_eq!(v["a"], 2);
        assert_eq!(
            from_slice_unique(br#"{"a":1,"b":{"c":1,"c":2}}"#),
            Err(Error { at: 18 })
        );
        assert!(from_slice_unique(br#"{"a":1,"b":{"a":1}}"#).is_ok());
    }

    #[test]
    fn limits() {
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(from_str(&deep(MAX_DEPTH)).is_ok());
        assert_eq!(from_str(&deep(MAX_DEPTH + 1)), Err(Error { at: MAX_DEPTH }));
        let objects = format!(
            "{}1{}",
            "{\"a\":".repeat(MAX_DEPTH + 1),
            "}".repeat(MAX_DEPTH + 1)
        );
        assert!(from_str(&objects).is_err());
        let mut big = vec![b' '; MAX_INPUT];
        big[0] = b'0';
        assert!(from_slice(&big).is_ok());
        big.push(b' ');
        assert_eq!(from_slice(&big), Err(Error { at: MAX_INPUT }));
    }

    #[test]
    fn lookups_and_builders() {
        let v = crate::json!({"s": "x", "n": 3, "l": [1, 2], "b": true, "o": Map::new()});
        assert_eq!(v["s"].as_str(), Some("x"));
        assert_eq!(v["missing"], Value::Null);
        assert_eq!(v["s"]["deeper"], Value::Null);
        assert_eq!(v.get("l").and_then(Value::as_array).map(Vec::len), Some(2));
        assert_eq!(v["b"].as_bool(), Some(true));
        assert!(v["o"].as_object().is_some_and(Map::is_empty));
        assert_eq!(to_string(&crate::json!({})), "{}");
        let mut w = v.clone();
        if let Some(Value::Array(a)) = w.get_mut("l") {
            a.push(Value::Null);
        }
        assert_eq!(w["l"].as_array().map(Vec::len), Some(3));
    }
}
