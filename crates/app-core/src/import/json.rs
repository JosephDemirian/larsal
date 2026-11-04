//! A bounded JSON reader for import files (RFC 8259; FEA-08.43, FEA-08.51,
//! FEA-08.65 to FEA-08.67).
//!
//! Why not `serde_json`: its values and its string scratch buffer are plain
//! `String`s that are freed unwiped, so a decrypted export would leave every
//! password in freed memory (FEA-08.66, SR-07). Here every string value is
//! decoded straight into a wiping buffer and kept as a `SecretString`.
//!
//! Guarantees: iterative (no recursion while parsing), so depth costs no
//! stack; nesting deeper than [`MAX_DEPTH`], a string longer than
//! [`MAX_TEXT`] bytes or more than [`MAX_VALUES`] values is refused before
//! it is built; any other problem is [`ImportError::Json`] with the byte
//! offset and a fixed reason, never text from the file. Object keys are
//! plain text (names, not values). Numbers are kept as `f64`; readers take
//! integers through [`Json::int`], which reads a number that does not fit
//! as missing (FEA-08.65). A secret written as a number (a PIN without
//! quotes) is therefore not wiped, nor are the old copies left when a list
//! of values grows (F-053, accepted until the zeroing allocator).

use super::{ImportError, JsonReason, Limit, MAX_TEXT};
use crate::text::Text;
use app_crypto::secret::SecretString;

/// Deepest nesting of arrays and objects (FEA-08.67).
pub const MAX_DEPTH: usize = 512;
/// Most values in one document (FEA-08.67, LD-143 (5)). It bounds memory
/// for a hostile file of tiny values (about 60 bytes of model per value,
/// so at most about 1 GiB), far above what a real export of the
/// 1,000,000-entry result limit needs.
pub const MAX_VALUES: usize = 16_777_216;

/// One JSON value.
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(f64),
    Str(SecretString),
    Array(Vec<Json>),
    /// Members in file order; a repeated key keeps every copy, and
    /// [`Json::get`] takes the last one.
    Object(Vec<(String, Json)>),
}

/// The missing value: what every lookup on a wrong type gives.
static NULL: Json = Json::Null;

impl Json {
    /// The member `key` of an object (the last one when repeated); `Null`
    /// for a missing key or when this is not an object.
    pub(crate) fn get(&self, key: &str) -> &Json {
        match self {
            Json::Object(m) => m
                .iter()
                .rev()
                .find(|(k, _)| k == key)
                .map_or(&NULL, |(_, v)| v),
            _ => &NULL,
        }
    }

    /// Follows a path of keys.
    pub(crate) fn at(&self, path: &[&str]) -> &Json {
        path.iter().fold(self, |v, k| v.get(k))
    }

    /// The items of an array; empty for any other type.
    pub(crate) fn items(&self) -> &[Json] {
        match self {
            Json::Array(a) => a,
            _ => &[],
        }
    }

    /// The members of an object; empty for any other type.
    pub(crate) fn members(&self) -> &[(String, Json)] {
        match self {
            Json::Object(m) => m,
            _ => &[],
        }
    }

    pub(crate) fn is_array(&self) -> bool {
        matches!(self, Json::Array(_))
    }

    pub(crate) fn is_object(&self) -> bool {
        matches!(self, Json::Object(_))
    }

    /// The text of a string; `""` for any other type.
    pub(crate) fn str(&self) -> &str {
        match self {
            Json::Str(s) => s.expose(),
            _ => "",
        }
    }

    /// True only for the JSON value `true`.
    pub(crate) fn is_true(&self) -> bool {
        matches!(self, Json::Bool(true))
    }

    /// A whole number that fits 64 bits; `None` for anything else.
    pub(crate) fn int(&self) -> Option<i64> {
        match self {
            // 2^63 is exactly representable; every f64 below it in
            // magnitude with no fraction converts without loss.
            Json::Number(n) if n.is_finite() && n.fract() == 0.0 && n.abs() < 2f64.powi(63) =>
            {
                #[allow(clippy::cast_possible_truncation)]
                Some(*n as i64)
            }
            _ => None,
        }
    }

    /// The value as text: a string as is, a whole number in decimal, a
    /// boolean as `true` or `false`; `""` for anything else.
    pub(crate) fn text(&self) -> SecretString {
        let mut t = Text::new();
        match self {
            Json::Str(s) => t.push_str(s.expose()),
            Json::Bool(b) => t.push_str(if *b { "true" } else { "false" }),
            Json::Number(_) => {
                if let Some(i) = self.int() {
                    let _ = core::fmt::Write::write_fmt(&mut t, format_args!("{i}"));
                }
            }
            _ => {}
        }
        t.into_secret()
    }
}

enum Frame {
    Array(Vec<Json>),
    Object(Vec<(String, Json)>, String),
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    values: usize,
    max_values: usize,
}

type R<T> = Result<T, ImportError>;

/// Parses one JSON document. A UTF-8 byte order mark at the start is
/// skipped; anything after the value but white space is an error.
pub(crate) fn parse(bytes: &[u8]) -> R<Json> {
    parse_with(bytes, MAX_VALUES)
}

/// [`parse`] with a value limit (the unit tests lower it).
fn parse_with(bytes: &[u8], max_values: usize) -> R<Json> {
    let start = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        3
    } else {
        0
    };
    let mut p = Parser {
        b: bytes,
        i: start,
        values: 0,
        max_values,
    };
    let mut stack: Vec<Frame> = Vec::new();
    loop {
        p.ws();
        let mut value = match p.peek() {
            Some(b'{') | Some(b'[') if stack.len() >= MAX_DEPTH => {
                return Err(ImportError::TooLarge(Limit::Depth));
            }
            Some(b'{') => {
                p.bump();
                p.count()?;
                p.ws();
                if p.eat(b'}') {
                    Json::Object(Vec::new())
                } else {
                    let key = p.key()?;
                    stack.push(Frame::Object(Vec::new(), key));
                    continue;
                }
            }
            Some(b'[') => {
                p.bump();
                p.count()?;
                p.ws();
                if p.eat(b']') {
                    Json::Array(Vec::new())
                } else {
                    stack.push(Frame::Array(Vec::new()));
                    continue;
                }
            }
            _ => p.scalar()?,
        };
        // Attach the value, closing every container it completes.
        loop {
            match stack.last_mut() {
                None => {
                    p.ws();
                    return if p.i < p.b.len() {
                        Err(p.err(JsonReason::Trailing))
                    } else {
                        Ok(value)
                    };
                }
                Some(Frame::Array(items)) => {
                    items.push(value);
                    p.ws();
                    if p.eat(b',') {
                        break;
                    }
                    if !p.eat(b']') {
                        return Err(p.err(JsonReason::Expected));
                    }
                    let Some(Frame::Array(items)) = stack.pop() else {
                        return Err(p.err(JsonReason::Expected));
                    };
                    value = Json::Array(items);
                }
                Some(Frame::Object(members, key)) => {
                    members.push((core::mem::take(key), value));
                    p.ws();
                    if p.eat(b',') {
                        p.ws();
                        *key = p.key()?;
                        break;
                    }
                    if !p.eat(b'}') {
                        return Err(p.err(JsonReason::Expected));
                    }
                    let Some(Frame::Object(members, _)) = stack.pop() else {
                        return Err(p.err(JsonReason::Expected));
                    };
                    value = Json::Object(members);
                }
            }
        }
    }
}

impl Parser<'_> {
    fn err(&self, reason: JsonReason) -> ImportError {
        ImportError::Json {
            offset: self.i,
            reason,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn bump(&mut self) {
        self.i = self.i.saturating_add(1);
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn count(&mut self) -> R<()> {
        self.values = self.values.saturating_add(1);
        if self.values > self.max_values {
            return Err(ImportError::TooLarge(Limit::JsonValues));
        }
        Ok(())
    }

    /// A string, a number, `true`, `false` or `null`.
    fn scalar(&mut self) -> R<Json> {
        self.count()?;
        match self.peek() {
            Some(b'"') => Ok(Json::Str(self.string()?.into_secret())),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b't') => self.word(b"true", Json::Bool(true)),
            Some(b'f') => self.word(b"false", Json::Bool(false)),
            Some(b'n') => self.word(b"null", Json::Null),
            None => Err(self.err(JsonReason::End)),
            Some(_) => Err(self.err(JsonReason::Unexpected)),
        }
    }

    fn word(&mut self, w: &[u8], v: Json) -> R<Json> {
        let end = self.i.saturating_add(w.len());
        if self.b.get(self.i..end) == Some(w) {
            self.i = end;
            Ok(v)
        } else {
            Err(self.err(JsonReason::Unexpected))
        }
    }

    /// RFC 8259 section 6: `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
    fn number(&mut self) -> R<Json> {
        let start = self.i;
        self.eat(b'-');
        match self.peek() {
            Some(b'0') => self.bump(),
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.err(JsonReason::Number)),
        }
        if self.eat(b'.') {
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err(JsonReason::Number));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if !self.eat(b'+') {
                self.eat(b'-');
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err(JsonReason::Number));
            }
            self.digits();
        }
        let text = self
            .b
            .get(start..self.i)
            .and_then(|t| core::str::from_utf8(t).ok())
            .unwrap_or("");
        // The grammar above is a subset of what f64 parsing accepts; a
        // value too large becomes infinity and reads as missing.
        text.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| self.err(JsonReason::Number))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
    }

    /// An object key and the `:` after it.
    fn key(&mut self) -> R<String> {
        if self.peek() != Some(b'"') {
            return Err(self.err(JsonReason::Expected));
        }
        let key = self.string()?.as_str().to_owned();
        self.ws();
        if !self.eat(b':') {
            return Err(self.err(JsonReason::Expected));
        }
        Ok(key)
    }

    /// A string from its opening quote, decoded into a wiping buffer.
    fn string(&mut self) -> R<Text> {
        self.bump();
        let mut out = Text::new();
        loop {
            // Copy the run of plain bytes up to the next quote, backslash or
            // control character in one step.
            let rest = self.b.get(self.i..).unwrap_or(&[]);
            let run = rest
                .iter()
                .position(|&c| c == b'"' || c == b'\\' || c < 0x20)
                .unwrap_or(rest.len());
            let chunk = rest.get(..run).unwrap_or(&[]);
            // Refused before the copy, so the buffer never passes the limit.
            if out.len().saturating_add(run) > MAX_TEXT {
                return Err(ImportError::TooLarge(Limit::Text));
            }
            match core::str::from_utf8(chunk) {
                Ok(s) => out.push_str(s),
                Err(e) => {
                    self.i = self.i.saturating_add(e.valid_up_to());
                    return Err(self.err(JsonReason::Utf8));
                }
            }
            self.i = self.i.saturating_add(run);
            match self.peek() {
                Some(b'"') => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.bump();
                    let c = self.escape()?;
                    if out.len().saturating_add(c.len_utf8()) > MAX_TEXT {
                        return Err(ImportError::TooLarge(Limit::Text));
                    }
                    out.push(c);
                }
                Some(_) => return Err(self.err(JsonReason::Control)),
                None => return Err(self.err(JsonReason::End)),
            }
        }
    }

    /// One escape after its backslash (RFC 8259 section 7). A lone
    /// surrogate becomes U+FFFD.
    fn escape(&mut self) -> R<char> {
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
                let hi = self.hex4()?;
                let c = if (0xD800..0xDC00).contains(&hi)
                    && self.b.get(self.i..self.i.saturating_add(2)) == Some(b"\\u")
                {
                    let save = self.i;
                    self.i = self.i.saturating_add(2);
                    let lo = self.hex4()?;
                    if (0xDC00..0xE000).contains(&lo) {
                        let v = 0x10000u32
                            .saturating_add((hi.saturating_sub(0xD800)) << 10)
                            .saturating_add(lo.saturating_sub(0xDC00));
                        char::from_u32(v).unwrap_or('\u{FFFD}')
                    } else {
                        // Not a pair: the high half alone, the next escape read again.
                        self.i = save;
                        '\u{FFFD}'
                    }
                } else {
                    char::from_u32(hi).unwrap_or('\u{FFFD}')
                };
                return Ok(c);
            }
            _ => return Err(self.err(JsonReason::Escape)),
        };
        self.bump();
        Ok(c)
    }

    fn hex4(&mut self) -> R<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = self
                .peek()
                .and_then(|c| char::from(c).to_digit(16))
                .ok_or_else(|| self.err(JsonReason::Escape))?;
            v = (v << 4) | d;
            self.bump();
        }
        Ok(v)
    }
}

#[cfg(test)]
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn err(text: &str) -> ImportError {
        parse(text.as_bytes()).err().expect("an error")
    }

    #[test]
    fn values_and_lookups() {
        let j = parse(
            br#" {"a":[1,-2.5e1,true,null,"x\u00e9\ud83d\ude00\n"],"a":{"b":"last"},"n":1e400} "#,
        )
        .unwrap();
        assert_eq!(j.at(&["a", "b"]).str(), "last");
        assert!(j.get("n").int().is_none(), "infinity reads as missing");
        assert!(j.get("missing").items().is_empty());
        let first =
            parse(br#"[1,-25,true,null,"x\u00e9\ud83d\ude00\n",9007199254740993]"#).unwrap();
        let items = first.items();
        assert_eq!(items[0].int(), Some(1));
        assert_eq!(items[1].int(), Some(-25));
        assert!(items[2].is_true());
        assert_eq!(items[4].str(), "x\u{e9}\u{1F600}\n");
        assert_eq!(items[0].text().expose(), "1");
        assert_eq!(items[2].text().expose(), "true");
        assert_eq!(parse(b"\xEF\xBB\xBF{}").unwrap().members().len(), 0);
        assert_eq!(parse(br#""\ud800x""#).unwrap().str(), "\u{FFFD}x");
    }

    #[test]
    fn errors_name_the_offset_only() {
        assert_eq!(
            err("{bad"),
            ImportError::Json {
                offset: 1,
                reason: JsonReason::Expected
            }
        );
        for bad in [
            "",
            "[1,]",
            "{\"a\" 1}",
            "01",
            "1.",
            "-",
            "\"a\u{1}\"",
            "\"\\x\"",
            "[1] 2",
            "\"open",
        ] {
            assert!(matches!(err(bad), ImportError::Json { .. }), "{bad:?}");
        }
        assert!(matches!(
            parse(b"\"\xff\""),
            Err(ImportError::Json {
                reason: JsonReason::Utf8,
                ..
            })
        ));
    }

    #[test]
    fn value_limit() {
        // Containers and scalars both count; the value past the limit is
        // refused before it is built.
        assert_eq!(MAX_VALUES, 16_777_216);
        assert!(parse_with(b"[1,2,3,[]]", 5).is_ok());
        assert_eq!(
            parse_with(b"[1,2,3,[],4]", 5).err(),
            Some(ImportError::TooLarge(Limit::JsonValues))
        );
        assert_eq!(
            parse_with(b"{\"a\":[{},{}]}", 3).err(),
            Some(ImportError::TooLarge(Limit::JsonValues))
        );
    }

    #[test]
    fn text_limit_is_checked_before_the_copy() {
        let mut at = b"\"".to_vec();
        at.resize(MAX_TEXT + 1, b'a');
        at.push(b'"');
        assert_eq!(parse(&at).unwrap().str().len(), MAX_TEXT);
        let mut over = at.clone();
        over.insert(1, b'a');
        assert_eq!(parse(&over).err(), Some(ImportError::TooLarge(Limit::Text)));
        // An escape that would pass the limit.
        let mut esc = at;
        esc.pop();
        esc.extend(b"\\n\"");
        assert_eq!(parse(&esc).err(), Some(ImportError::TooLarge(Limit::Text)));
    }

    #[test]
    fn depth_limit_is_512() {
        let ok = format!("{}{}", "[".repeat(512), "]".repeat(512));
        assert!(parse(ok.as_bytes()).is_ok());
        let deep = format!("{}{}", "[".repeat(513), "]".repeat(513));
        assert_eq!(
            parse(deep.as_bytes()).err(),
            Some(ImportError::TooLarge(Limit::Depth))
        );
        let deep_obj = "{\"a\":".repeat(600);
        assert_eq!(
            parse(deep_obj.as_bytes()).err(),
            Some(ImportError::TooLarge(Limit::Depth))
        );
    }
}
