//! The sequence reader (INT-05.2, INT-05.3, R05-2): brace escapes, the
//! brace count, and tokens from left to right.
//!
//! Guarantees (AT-G03, LD-184 (1)): time is linear in the sequence length.
//! Plain text is walked in place, never copied into records; the reader
//! keeps one 4-byte record per `{` of the sequence, reserved once, and
//! pairs braces with a heap stack of at most one 4-byte record per `{`,
//! reserved once, never by recursion, so no nesting depth can overflow the
//! call stack. A sequence of 4 GiB or more is refused as MI05-21 (stored
//! texts hold at most 64 MiB, LD-22).

use crate::error::{Error, shown};
use crate::{MAX_NEST, Mods};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Open,
    Close,
    Char,
    /// `{{}`: a literal `{` (INT-05.2).
    LitOpen,
    /// `{}}`: a literal `}`.
    LitClose,
}

/// A `{` that starts no brace token. While a `{` waits on the pairing
/// stack, its record holds its state instead: no item yet, items, or a
/// nested group that is not a token.
const NONE: u32 = u32::MAX;
const EMPTY: u32 = u32::MAX - 1;
const FULL: u32 = u32::MAX - 2;
const BAD: u32 = u32::MAX - 3;

/// The item at byte `at`: an escape, a brace or one character, with its
/// length as written and the character it stands for. Escapes are read
/// left to right, so every caller starts at an item boundary.
fn item(seq: &str, at: usize) -> Option<(Kind, usize, char)> {
    let rest = seq.get(at..)?;
    if rest.starts_with("{{}") {
        return Some((Kind::LitOpen, 3, '{'));
    }
    if rest.starts_with("{}}") {
        return Some((Kind::LitClose, 3, '}'));
    }
    let c = rest.chars().next()?;
    let kind = match c {
        '{' => Kind::Open,
        '}' => Kind::Close,
        _ => Kind::Char,
    };
    Some((kind, c.len_utf8(), c))
}

/// The record of the k-th `{`.
fn slot(ends: &mut [u32], k: u32) -> Option<&mut u32> {
    ends.get_mut(usize::try_from(k).ok()?)
}

/// The items from byte `at` up to byte `end`, with their offsets.
fn items(seq: &str, mut at: usize, end: usize) -> impl Iterator<Item = (usize, Kind, char)> + '_ {
    core::iter::from_fn(move || {
        if at >= end {
            return None;
        }
        let (kind, len, c) = item(seq, at)?;
        let here = at;
        at = at.saturating_add(len);
        Some((here, kind, c))
    })
}

/// One token (INT-05.3), with the modifiers written in front of it; `text`
/// is the whole token as written, modifiers included.
pub(crate) enum Token<'s> {
    /// One character (INT-05.4).
    Char { mods: Mods, ch: char, text: &'s str },
    /// A brace token: the text between its outer braces (escapes already
    /// turned into braces).
    Brace {
        mods: Mods,
        content: String,
        text: &'s str,
    },
}

/// Reads tokens one by one; the first error ends the reading.
pub(crate) struct Reader<'s> {
    seq: &'s str,
    /// For the k-th `{` of the sequence: the byte offset of its matching
    /// `}` when it starts a brace token, else `NONE`.
    ends: Vec<u32>,
    /// The byte offset of the next token, and the number of `{` before it.
    at: usize,
    open: usize,
}

impl<'s> Reader<'s> {
    /// Applies the escapes and checks the brace count (INT-05.2): MI05-11
    /// when the `{` and `}` left over differ in number. Then pairs the
    /// braces like MOD-08.1: a `{` starts a brace token when its matching
    /// `}` ends a non-empty run of items, each a character or a nested
    /// brace token.
    pub(crate) fn new(seq: &'s str) -> Result<Self, Error> {
        if u32::try_from(seq.len()).map_or(true, |n| n >= BAD) {
            return Err(Error::TooManyKeys);
        }
        let (mut opens, mut closes, mut depth, mut deepest) = (0usize, 0usize, 0usize, 0usize);
        for (_, kind, _) in items(seq, 0, seq.len()) {
            match kind {
                Kind::Open => {
                    opens = opens.saturating_add(1);
                    depth = depth.saturating_add(1);
                    deepest = deepest.max(depth);
                }
                Kind::Close => {
                    closes = closes.saturating_add(1);
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        if opens != closes {
            return Err(Error::Unpaired);
        }
        let mut ends: Vec<u32> = Vec::with_capacity(opens);
        let mut stack: Vec<u32> = Vec::with_capacity(deepest);
        for (at, kind, _) in items(seq, 0, seq.len()) {
            match kind {
                Kind::Open => {
                    stack.push(u32::try_from(ends.len()).unwrap_or(NONE));
                    ends.push(EMPTY);
                }
                Kind::Close => {
                    let Some(k) = stack.pop() else { continue };
                    let ok = slot(&mut ends, k).is_some_and(|s| {
                        let ok = *s == FULL;
                        *s = if ok {
                            u32::try_from(at).unwrap_or(NONE)
                        } else {
                            NONE
                        };
                        ok
                    });
                    if let Some(s) = stack.last().and_then(|&p| slot(&mut ends, p)) {
                        *s = if ok && *s != BAD { FULL } else { BAD };
                    }
                }
                _ => {
                    if let Some(s) = stack.last().and_then(|&p| slot(&mut ends, p))
                        && *s == EMPTY
                    {
                        *s = FULL;
                    }
                }
            }
        }
        for k in stack {
            if let Some(s) = slot(&mut ends, k) {
                *s = NONE;
            }
        }
        Ok(Self {
            seq,
            ends,
            at: 0,
            open: 0,
        })
    }

    fn slice(&self, from: usize, to: usize) -> &'s str {
        self.seq.get(from..to).unwrap_or("")
    }

    /// The brace token from the `{` at `open_at` to the `}` at `close`.
    fn brace(
        &mut self,
        start: usize,
        mods: Mods,
        open_at: usize,
        close: usize,
    ) -> Result<Token<'s>, Error> {
        let inner = open_at.saturating_add(1);
        let (mut depth, mut deepest, mut opens) = (0u32, 0u32, 0usize);
        for (_, kind, _) in items(self.seq, inner, close) {
            match kind {
                Kind::Open => {
                    opens = opens.saturating_add(1);
                    depth = depth.saturating_add(1);
                    deepest = deepest.max(depth);
                }
                Kind::Close => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        self.open = self.open.saturating_add(opens);
        self.at = close.saturating_add(1);
        let text = self.slice(start, self.at);
        if deepest.saturating_add(1) > MAX_NEST {
            self.at = self.seq.len();
            return Err(Error::TooDeep(shown(text)));
        }
        let content = items(self.seq, inner, close).map(|(_, _, c)| c).collect();
        Ok(Token::Brace {
            mods,
            content,
            text,
        })
    }
}

impl<'s> Iterator for Reader<'s> {
    type Item = Result<Token<'s>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.at;
        let mut mods = Mods::NONE;
        while let Some((Kind::Char, len, c)) = item(self.seq, self.at) {
            mods = mods
                | match c {
                    '+' => Mods::SHIFT,
                    '^' => Mods::CONTROL,
                    '%' => Mods::OPTION,
                    '#' => Mods::COMMAND,
                    _ => break,
                };
            self.at = self.at.saturating_add(len);
        }
        let Some((kind, len, ch)) = item(self.seq, self.at) else {
            // INT-05.3, D-INT05-13 (4): modifiers with nothing after them.
            return (self.at > start)
                .then(|| Err(Error::DanglingMods(shown(self.slice(start, self.at)))));
        };
        let at = self.at;
        self.at = at.saturating_add(len);
        if kind == Kind::Open {
            let k = self.open;
            self.open = k.saturating_add(1);
            let close = self.ends.get(k).filter(|&&e| e != NONE);
            if let Some(close) = close.and_then(|&e| usize::try_from(e).ok()) {
                return Some(self.brace(start, mods, at, close));
            }
        }
        Some(Ok(Token::Char {
            mods,
            ch,
            text: self.slice(start, self.at),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;

    const MB10: usize = 10 * 1024 * 1024;

    /// LD-184 (1): memory follows the brace count, not the length.
    #[test]
    fn ld184_1_memory_follows_the_braces() {
        // 10 MB of plain text with three tokens: three records.
        let seq = format!("{{TAB}}{}{{C:x}}{{DELAY 5}}", "a".repeat(MB10));
        let r = Reader::new(&seq).unwrap();
        assert_eq!(r.ends.capacity(), 3);
        // 10 MB of tokens: one 4-byte record per `{`, reserved once.
        let seq = "{C:x}".repeat(MB10 / 5);
        let r = Reader::new(&seq).unwrap();
        assert_eq!(r.ends.capacity(), MB10 / 5);
        assert!(r.ends.capacity() * 4 <= seq.len());
        // 10 MB nested 3.5 million deep: still one record per `{`.
        let n = MB10 / 3;
        let seq = format!("{}{}", "{a".repeat(n), "}".repeat(n));
        let r = Reader::new(&seq).unwrap();
        assert_eq!(r.ends.capacity(), n);
        assert_eq!(r.count(), 1, "one token: MI05-25");
    }
}
