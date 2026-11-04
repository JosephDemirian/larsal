//! Random passwords from character groups (FEA-02).
//!
//! Guarantees: groups are built in the class table's order (FEA-02.1), the
//! look-alike set is exactly FEA-02.2's (with U+00B7, D-02-1), the extra
//! group is deduplicated and never look-alike filtered (FEA-02.3), the
//! excluded text wins everywhere (FEA-02.4), the checks run in FEA-02.5's
//! order before anything is drawn or allocated by size, and the draws run
//! in FEA-02.7 and FEA-02.8's order. Every index comes from
//! `app_crypto::random::below` (FEA-02.6).

use super::{Chars, Os, Source};
use crate::text::Text;
use app_crypto::secret::SecretString;

/// The longest password the core makes (D-02-4).
pub const MAX_LENGTH: u32 = 10_000;
/// The longest the screen's number field allows (FEA-02.10).
pub const SCREEN_MAX_LENGTH: u32 = 999;
/// The longest extra or excluded text, in characters (D-02-4).
pub const MAX_TEXT: usize = 1_024;

/// A character class (FEA-02 class table). [`Class::Special`] is App's one
/// group of all 32 symbols (D-02-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// `a` to `z`.
    Lower,
    /// `A` to `Z`.
    Upper,
    /// `0` to `9`.
    Digits,
    /// The six symbol classes as one group (App's simple view chip).
    Special,
    /// `( ) [ ] { }`.
    Brackets,
    /// `, . : ;`.
    Punctuation,
    /// `"` and `'`.
    Quotes,
    /// `- / \ _ |`.
    Dashes,
    /// `! * + < = > ?`.
    Math,
    /// `# $ % & @ ^ `` ` `` ~`.
    Signs,
    /// U+00A1 to U+00AC, then U+00AE to U+00FF.
    Extended,
}

/// Group order (FEA-02.1); `Special` sits where the six symbol classes sit.
const ORDER: [Class; 11] = [
    Class::Lower,
    Class::Upper,
    Class::Digits,
    Class::Special,
    Class::Brackets,
    Class::Punctuation,
    Class::Quotes,
    Class::Dashes,
    Class::Math,
    Class::Signs,
    Class::Extended,
];

/// The six symbol classes, in order.
const SYMBOLS: [Class; 6] = [
    Class::Brackets,
    Class::Punctuation,
    Class::Quotes,
    Class::Dashes,
    Class::Math,
    Class::Signs,
];

/// Removed by look-alike exclusion from the classes (FEA-02.2, D-02-1).
const LOOKALIKE: [char; 11] = ['l', 'B', 'G', 'I', 'O', '0', '1', '6', '8', '|', '\u{b7}'];

impl Class {
    /// The characters of the class in table order.
    #[must_use]
    pub fn chars(self) -> Vec<char> {
        let text = |s: &str| s.chars().collect::<Vec<char>>();
        match self {
            Self::Lower => ('a'..='z').collect(),
            Self::Upper => ('A'..='Z').collect(),
            Self::Digits => ('0'..='9').collect(),
            Self::Brackets => text("()[]{}"),
            Self::Punctuation => text(",.:;"),
            Self::Quotes => text("\"'"),
            Self::Dashes => text("-/\\_|"),
            Self::Math => text("!*+<=>?"),
            Self::Signs => text("#$%&@^`~"),
            Self::Extended => ('\u{a1}'..='\u{ac}').chain('\u{ae}'..='\u{ff}').collect(),
            Self::Special => SYMBOLS.iter().flat_map(|c| c.chars()).collect(),
        }
    }
}

/// The generator options (FEA-02 options table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Number of characters, 1 to 10,000 (D-02-4).
    pub length: u32,
    /// The selected classes; order does not matter.
    pub classes: Vec<Class>,
    /// One more group: each distinct character once (FEA-02.3).
    pub extra: String,
    /// Characters removed from every group (FEA-02.4).
    pub excluded: String,
    /// FEA-02.2.
    pub exclude_lookalike: bool,
    /// At least one character from every group (FEA-02.8).
    pub every_group: bool,
}

impl Default for Options {
    /// App's screen defaults (FEA-02.11, D-02-2 b): 20 characters; lower,
    /// upper, digits and `special`; look-alike and every group on.
    fn default() -> Self {
        Self {
            length: 20,
            classes: vec![Class::Upper, Class::Lower, Class::Digits, Class::Special],
            extra: String::new(),
            excluded: String::new(),
            exclude_lookalike: true,
            every_group: true,
        }
    }
}

impl Options {
    /// The built-in fallback options (FEA-02 defaults): 32 characters;
    /// lower, upper, digits; look-alike and every group on.
    #[must_use]
    pub fn fallback() -> Self {
        Self {
            length: 32,
            classes: vec![Class::Lower, Class::Upper, Class::Digits],
            extra: String::new(),
            excluded: String::new(),
            exclude_lookalike: true,
            every_group: true,
        }
    }

    /// What App's simple view applies (FEA-02.12, D-02-2 b): the hidden
    /// advanced options (the six symbol chips, extra, excluded) are not
    /// applied; look-alike and every group are.
    #[must_use]
    pub fn simple_view(&self) -> Self {
        Self {
            classes: self
                .classes
                .iter()
                .copied()
                .filter(|c| !SYMBOLS.contains(c))
                .collect(),
            extra: String::new(),
            excluded: String::new(),
            ..self.clone()
        }
    }

    /// The hex preset (FEA-02.13 with D-02-6): upper and digits only,
    /// excluded `G` to `Z`, look-alike off, extra cleared, so the output
    /// uses exactly `0-9 A-F`. Every group stays as it is.
    pub fn hex(&mut self) {
        self.classes = vec![Class::Upper, Class::Digits];
        "GHIJKLMNOPQRSTUVWXYZ".clone_into(&mut self.excluded);
        self.extra.clear();
        self.exclude_lookalike = false;
    }

    /// The command line's options (FEA-02.21): no class and no custom set
    /// gives lower, upper, digits; a custom set is the extra group; with
    /// neither flag both are on, else only the given ones.
    #[must_use]
    pub fn command_line(
        length: u32,
        classes: &[Class],
        custom: Option<&str>,
        exclude: &str,
        exclude_similar: bool,
        every_group: bool,
    ) -> Self {
        let none = !exclude_similar && !every_group;
        Self {
            length,
            classes: if classes.is_empty() && custom.is_none() {
                vec![Class::Lower, Class::Upper, Class::Digits]
            } else {
                classes.to_vec()
            },
            extra: custom.unwrap_or("").to_owned(),
            excluded: exclude.to_owned(),
            exclude_lookalike: none || exclude_similar,
            every_group: none || every_group,
        }
    }
}

/// Why options cannot make a password (FEA-02.5, D-02-4), first failure
/// first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// `MSG-GEN-LENGTH`: the length is outside 1 to 10,000.
    LengthOutOfRange,
    /// The extra or excluded text is over 1,024 characters (D-02-4).
    TextTooLong,
    /// `MSG-GEN-NO-CHARS`: no non-empty group remains.
    NoCharacters,
    /// `MSG-GEN-TOO-SHORT`: every group needs this length at least.
    TooShortForEveryGroup(u32),
}

/// A generation error (FEA-02 outputs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The options are invalid; nothing was drawn.
    InvalidOptions(Invalid),
    /// `MSG-GEN-RANDOM`: the OS random source failed; no value is kept.
    RandomFailed,
}

/// The non-empty groups in order (FEA-02.1 to FEA-02.4), after the length
/// and text checks of FEA-02.5 (1) and D-02-4.
///
/// # Errors
/// [`Invalid`] for the first failed check.
pub fn groups(o: &Options) -> Result<Vec<Vec<char>>, Invalid> {
    if !(1..=MAX_LENGTH).contains(&o.length) {
        return Err(Invalid::LengthOutOfRange);
    }
    if o.extra.chars().nth(MAX_TEXT).is_some() || o.excluded.chars().nth(MAX_TEXT).is_some() {
        return Err(Invalid::TextTooLong);
    }
    let keep = |c: &char| !o.excluded.contains(*c);
    let mut out = Vec::new();
    for class in ORDER.iter().filter(|c| o.classes.contains(c)) {
        let g: Vec<char> = class
            .chars()
            .into_iter()
            .filter(|c| !(o.exclude_lookalike && LOOKALIKE.contains(c)))
            .filter(keep)
            .collect();
        out.push(g);
    }
    let mut extra: Vec<char> = Vec::new();
    for c in o.extra.chars().filter(|c| !is_control(*c)).filter(keep) {
        if !extra.contains(&c) {
            extra.push(c);
        }
    }
    out.push(extra);
    out.retain(|g| !g.is_empty());
    if out.is_empty() {
        return Err(Invalid::NoCharacters);
    }
    let count = u32::try_from(out.len()).unwrap_or(u32::MAX);
    if o.every_group && o.length < count {
        return Err(Invalid::TooShortForEveryGroup(count));
    }
    Ok(out)
}

/// U+0000 to U+001F and U+007F to U+009F are dropped from extra (D-02-4).
fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

/// A password for `o` from the OS random source (FEA-02.5 to FEA-02.8).
///
/// # Errors
/// [`Error::InvalidOptions`] as [`groups`]; [`Error::RandomFailed`] when
/// the source fails, with no partial value kept.
pub fn generate(o: &Options) -> Result<SecretString, Error> {
    generate_from(&mut Os, o)
}

/// The password for a new entry (FEA-02.19): what the saved options give,
/// or the built-in fallback options when they are invalid.
///
/// # Errors
/// [`Error::RandomFailed`] when the source fails.
pub fn for_new_entry(saved: &Options) -> Result<SecretString, Error> {
    match generate(saved) {
        Err(Error::InvalidOptions(_)) => generate(&Options::fallback()),
        other => other,
    }
}

/// The popup's start length (FEA-02.17): the character count of the
/// field's text when it is not empty, at most 999; else the saved length.
#[must_use]
pub fn start_length(field: &str, saved: u32) -> u32 {
    match crate::text::char_count(field) {
        0 => saved,
        n => u32::try_from(n).map_or(SCREEN_MAX_LENGTH, |n| n.min(SCREEN_MAX_LENGTH)),
    }
}

pub(crate) fn generate_from(src: &mut impl Source, o: &Options) -> Result<SecretString, Error> {
    let groups = groups(o).map_err(Error::InvalidOptions)?;
    let pool: Vec<char> = groups.iter().flatten().copied().collect();
    let len =
        usize::try_from(o.length).map_err(|_| Error::InvalidOptions(Invalid::LengthOutOfRange))?;
    let mut out = Chars::new(len);
    let mut pick = |set: &[char]| -> Result<char, Error> {
        let n = u32::try_from(set.len()).map_err(|_| Error::RandomFailed)?;
        let i = src.below(n).ok_or(Error::RandomFailed)?;
        set.get(usize::try_from(i).map_err(|_| Error::RandomFailed)?)
            .copied()
            .ok_or(Error::RandomFailed)
    };
    let mut at = 0usize;
    if o.every_group {
        for g in &groups {
            out.set(at, pick(g)?);
            at = at.saturating_add(1);
        }
    }
    while at < len {
        out.set(at, pick(&pool)?);
        at = at.saturating_add(1);
    }
    if o.every_group {
        for i in (1..len).rev() {
            let bound = u32::try_from(i.saturating_add(1)).map_err(|_| Error::RandomFailed)?;
            let j = src.below(bound).ok_or(Error::RandomFailed)?;
            out.swap(i, usize::try_from(j).map_err(|_| Error::RandomFailed)?);
        }
    }
    let mut text = Text::new();
    for i in 0..len {
        text.push(out.get(i));
    }
    Ok(text.into_secret())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The card's scripted source: given values, every bound recorded.
    struct Scripted {
        values: Vec<u32>,
        bounds: Vec<u32>,
    }

    impl Scripted {
        fn new(values: &[u32]) -> Self {
            Self {
                values: values.iter().rev().copied().collect(),
                bounds: Vec::new(),
            }
        }
    }

    impl Source for Scripted {
        fn below(&mut self, n: u32) -> Option<u32> {
            self.bounds.push(n);
            let v = self.values.pop()?;
            assert!(v < n, "scripted value {v} not below {n}");
            Some(v)
        }
    }

    fn opts(classes: &[Class], length: u32) -> Options {
        Options {
            length,
            classes: classes.to_vec(),
            extra: String::new(),
            excluded: String::new(),
            exclude_lookalike: false,
            every_group: false,
        }
    }

    #[test]
    fn fea02_1_order_scripted() {
        let mut s = Scripted::new(&[0, 9, 10, 15]);
        let o = opts(&[Class::Brackets, Class::Digits], 4);
        assert_eq!(generate_from(&mut s, &o).unwrap().expose(), "09(}");
        assert_eq!(s.bounds, [16, 16, 16, 16]);
    }

    #[test]
    fn fea02_6_fail_closed() {
        // The source fails at the third draw: an error, no value.
        let mut s = Scripted::new(&[1, 2]);
        let o = opts(&[Class::Digits], 8);
        assert_eq!(generate_from(&mut s, &o).err(), Some(Error::RandomFailed));
        let mut s = Scripted::new(&[]);
        let mut every = opts(&[Class::Digits, Class::Lower], 4);
        every.every_group = true;
        assert_eq!(
            generate_from(&mut s, &every).err(),
            Some(Error::RandomFailed)
        );
        // Invalid options draw nothing.
        let mut s = Scripted::new(&[]);
        assert!(generate_from(&mut s, &opts(&[], 4)).is_err());
        assert!(s.bounds.is_empty());
    }

    #[test]
    fn fea02_7_scripted() {
        let mut s = Scripted::new(&[0, 10, 24]);
        let mut o = opts(&[Class::Lower], 3);
        o.exclude_lookalike = true;
        assert_eq!(generate_from(&mut s, &o).unwrap().expose(), "akz");
        assert_eq!(s.bounds, [25, 25, 25]);
    }

    #[test]
    fn fea02_8_scripted() {
        let mut s = Scripted::new(&[4, 0, 10, 0, 1]);
        let mut o = opts(&[Class::Digits], 3);
        o.extra = "x".into();
        o.every_group = true;
        assert_eq!(generate_from(&mut s, &o).unwrap().expose(), "xx4");
        assert_eq!(s.bounds, [10, 1, 11, 3, 2]);
    }

    #[test]
    fn chars_buffer_round_trips_and_swaps() {
        let mut c = Chars::new(3);
        for (i, ch) in ['a', '\u{1f600}', '\u{ff}'].into_iter().enumerate() {
            c.set(i, ch);
        }
        c.swap(0, 2);
        assert_eq!([c.get(0), c.get(1), c.get(2)], ['\u{ff}', '\u{1f600}', 'a']);
        assert_eq!(c.get(3), '\0');
    }
}
