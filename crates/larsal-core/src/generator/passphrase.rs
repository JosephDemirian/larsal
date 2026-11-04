//! Passphrases: words picked at random from a word list (FEA-03.2 to
//! FEA-03.7).
//!
//! Guarantees: every word and the mixed-case position come from
//! `larsal_crypto::random::below`, uniform and with replacement (FEA-03.6);
//! the checks of D-03-5 and D-03-4 run before anything is drawn; the
//! passphrase is built in a wiping buffer and returned as a `SecretString`.

use super::wordlist::WordList;
use super::{Os, Source};
use crate::text::Text;
use larsal_crypto::secret::SecretString;

/// The most words the core makes (D-03-5).
pub const MAX_WORDS: u32 = 1_000;
/// The most words the screen's number field allows (FEA-03.3).
pub const SCREEN_MAX_WORDS: u32 = 100;
/// The longest separator in characters (D-03-5).
pub const MAX_SEPARATOR: usize = 64;

/// The word case (FEA-03.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Case {
    /// Every word in lower case (default).
    Lower,
    /// Every word in upper case.
    Upper,
    /// First character upper, the rest lower (D-03-2).
    Title,
    /// One word at a random position upper, the others lower.
    Mixed,
}

/// The passphrase options (FEA-03 options table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Word count, 1 to 1,000 (D-03-5).
    pub words: u32,
    /// Text between words, not trimmed, at most 64 characters.
    pub separator: String,
    /// The word case.
    pub case: Case,
}

impl Default for Options {
    /// 7 words, one space, lower case (FEA-03 defaults).
    fn default() -> Self {
        Self {
            words: 7,
            separator: " ".to_owned(),
            case: Case::Lower,
        }
    }
}

impl Options {
    /// The command line's options (FEA-03.16): `words` words, lower case,
    /// one space.
    #[must_use]
    pub fn command_line(words: u32) -> Self {
        Self {
            words,
            ..Self::default()
        }
    }
}

/// A passphrase error, first failure first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `MSG-PP-COUNT`: the word count is outside 1 to 1,000 (D-03-5).
    CountOutOfRange,
    /// The separator is over 64 characters (D-03-5).
    SeparatorTooLong,
    /// `MSG-PP-LIST-EMPTY`: the list has no entries (D-03-4).
    EmptyWordList,
    /// `MSG-GEN-RANDOM`: the OS random source failed; no value is kept.
    RandomFailed,
}

/// A passphrase for `o` from `list`, with the OS random source.
///
/// # Errors
/// See [`Error`].
pub fn generate(o: &Options, list: &WordList) -> Result<SecretString, Error> {
    generate_from(&mut Os, o, list)
}

/// The entropy shown (FEA-03.7): word count × log2(N), 0 for an empty
/// list; not adjusted for case or separator.
#[must_use]
pub fn entropy(words: u32, list: &WordList) -> f64 {
    let n = u32::try_from(list.len()).map_or(f64::from(u32::MAX), f64::from);
    if n < 1.0 {
        0.0
    } else {
        f64::from(words) * n.log2()
    }
}

pub(crate) fn generate_from(
    src: &mut impl Source,
    o: &Options,
    list: &WordList,
) -> Result<SecretString, Error> {
    if !(1..=MAX_WORDS).contains(&o.words) {
        return Err(Error::CountOutOfRange);
    }
    if o.separator.chars().nth(MAX_SEPARATOR).is_some() {
        return Err(Error::SeparatorTooLong);
    }
    let n = u32::try_from(list.len()).map_err(|_| Error::EmptyWordList)?;
    if n == 0 {
        return Err(Error::EmptyWordList);
    }
    let upper_at = match o.case {
        Case::Mixed => Some(src.below(o.words).ok_or(Error::RandomFailed)?),
        _ => None,
    };
    let mut out = Text::new();
    for i in 0..o.words {
        let pick = src.below(n).ok_or(Error::RandomFailed)?;
        let word = usize::try_from(pick)
            .ok()
            .and_then(|p| list.get(p))
            .ok_or(Error::RandomFailed)?;
        if i > 0 {
            out.push_str(&o.separator);
        }
        let case = match o.case {
            Case::Mixed if upper_at == Some(i) => Case::Upper,
            Case::Mixed => Case::Lower,
            other => other,
        };
        push_cased(&mut out, word, case);
    }
    Ok(out.into_secret())
}

/// Full Unicode case mapping, one character at a time (FEA-03.5).
fn push_cased(out: &mut Text, word: &str, case: Case) {
    for (i, c) in word.chars().enumerate() {
        let upper = case == Case::Upper || (case == Case::Title && i == 0);
        if upper {
            c.to_uppercase().for_each(|u| out.push(u));
        } else {
            c.to_lowercase().for_each(|l| out.push(l));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::wordlist::parse;
    use super::*;

    struct Scripted {
        values: Vec<u32>,
        bounds: Vec<u32>,
    }

    impl Source for Scripted {
        fn below(&mut self, n: u32) -> Option<u32> {
            self.bounds.push(n);
            if self.values.is_empty() {
                return None;
            }
            let v = self.values.remove(0);
            assert!(v < n);
            Some(v)
        }
    }

    fn run(
        list: &str,
        words: u32,
        sep: &str,
        case: Case,
        script: &[u32],
    ) -> (SecretString, Vec<u32>) {
        let list = parse(list.as_bytes()).unwrap();
        let mut s = Scripted {
            values: script.to_vec(),
            bounds: Vec::new(),
        };
        let o = Options {
            words,
            separator: sep.into(),
            case,
        };
        (generate_from(&mut s, &o, &list).unwrap(), s.bounds)
    }

    const LIST_A: &str = "alpha\nbravo\ncharlie\ndelta\necho\nfoxtrot\n";

    #[test]
    fn fea03_4_separator_scripted() {
        assert_eq!(
            run(LIST_A, 3, "", Case::Lower, &[0, 1, 1]).0.expose(),
            "alphabravobravo"
        );
        assert_eq!(
            run(LIST_A, 2, " + ", Case::Lower, &[2, 3]).0.expose(),
            "charlie + delta"
        );
    }

    #[test]
    fn fea03_5_case_scripted() {
        let (title, bounds) = run(LIST_A, 3, "-", Case::Title, &[5, 0, 5]);
        assert_eq!(title.expose(), "Foxtrot-Alpha-Foxtrot");
        assert_eq!(bounds, [6, 6, 6]);
        let (mixed, bounds) = run(LIST_A, 3, "-", Case::Mixed, &[1, 2, 3, 4]);
        assert_eq!(mixed.expose(), "charlie-DELTA-echo");
        assert_eq!(bounds, [3, 6, 6, 6]);
        assert_eq!(
            run(LIST_A, 2, " ", Case::Upper, &[0, 1]).0.expose(),
            "ALPHA BRAVO"
        );
        assert_eq!(
            run("\u{df}ig\nzeta\n", 1, " ", Case::Upper, &[0])
                .0
                .expose(),
            "SSIG"
        );
        assert_eq!(
            run("aPPle\n", 1, " ", Case::Title, &[0]).0.expose(),
            "Apple"
        );
    }

    #[test]
    fn fea03_8_order_scripted() {
        assert_eq!(run(LIST_A, 1, " ", Case::Lower, &[3]).0.expose(), "delta");
    }

    #[test]
    fn fea03_6_fail_closed() {
        let list = parse(LIST_A.as_bytes()).unwrap();
        let mut s = Scripted {
            values: vec![1],
            bounds: Vec::new(),
        };
        let o = Options::default();
        assert_eq!(
            generate_from(&mut s, &o, &list).err(),
            Some(Error::RandomFailed)
        );
    }
}
