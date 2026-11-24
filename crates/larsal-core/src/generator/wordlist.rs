//! Word lists for passphrases (FEA-03.1, FEA-03.8 to FEA-03.11): the
//! built-in list and the reader for user list files.
//!
//! Built-in list (D-03-1): the EFF Large Wordlist for Passphrases,
//! published by the Electronic Frontier Foundation in 2016,
//! https://www.eff.org/dice (file:
//! https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt), compiled
//! in unmodified from `eff_large_wordlist.txt` next to this file: 7,776
//! lines of a five-digit dice code, a tab and the word. Used under the
//! Creative Commons Attribution 4.0 International license (CC BY 4.0):
//! EFF's copyright page (https://www.eff.org/copyright, read 2026-10-31)
//! puts EFF's original material under it; the list was published under
//! CC BY 3.0 US. The list retains its own license and is exempt from Larsal's
//! first-party restrictions under LICENSE section 4 (E14-S2). CC BY 4.0 asks
//! for the creator, the source, a note that it is unmodified, the license
//! and its no-warranty notice: [`ATTRIBUTION`], which Larsal shows in About
//! (macos/Larsal/Resources/Credits.rtf), in `larsal --license` and in the
//! third-party notices (scripts/make-sbom.sh). Check value (FEA-03.1):
//! SHA-256 of the 7,776 words, each followed by LF, is
//! 6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522.
//!
//! Guarantees for user files (D-03-3): files over 4 MiB, text that is not
//! valid UTF-8 (or UTF-16 after its byte order mark), more than 500,000
//! unique entries or an entry over 256 characters are refused; reading is
//! linear in the file size. A word list is not secret.

use std::collections::HashSet;
use std::sync::OnceLock;

/// The largest user list file (D-03-3).
pub const MAX_FILE: usize = 4 * 1024 * 1024;
/// The most unique entries (D-03-3).
pub const MAX_ENTRIES: usize = 500_000;
/// The longest entry in characters (D-03-3).
pub const MAX_ENTRY: usize = 256;
/// Fewer unique entries show `MSG-PP-LIST-SMALL` (FEA-03.12).
pub const MIN_RECOMMENDED: usize = 1_296;

/// The built-in list's attribution (CC BY 4.0, section 3(a)), word for word
/// wherever Larsal shows it (E14-S2).
pub const ATTRIBUTION: &str = "Word list: EFF Large Wordlist for Passphrases, by the Electronic Frontier Foundation, https://www.eff.org/dice, unmodified, used under the Creative Commons Attribution 4.0 International license (CC BY 4.0, https://creativecommons.org/licenses/by/4.0/), which provides it as is, with no warranty.";

const BUILTIN: &str = include_str!("eff_large_wordlist.txt");
const SIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----";

/// Why a user list file was refused (D-03-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListError {
    /// `MSG-PP-LIST-NOT-UTF8`.
    NotUtf8,
    /// `MSG-PP-LIST-TOO-BIG`.
    TooBig,
}

/// A loaded word list: unique entries, lower-cased (D-03-2), in order of
/// first appearance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordList {
    words: Vec<String>,
}

impl WordList {
    /// The number of unique entries (N of FEA-03.7).
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// No entries: generation gives `MSG-PP-LIST-EMPTY` (D-03-4).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// Fewer than 1,296 entries: the small-list warning (FEA-03.12).
    #[must_use]
    pub fn is_small(&self) -> bool {
        self.words.len() < MIN_RECOMMENDED
    }

    /// The entry at `i`.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&str> {
        self.words.get(i).map(String::as_str)
    }

    /// Every entry in order.
    pub fn words(&self) -> impl Iterator<Item = &str> {
        self.words.iter().map(String::as_str)
    }
}

/// The built-in list (FEA-03.1), read once.
#[must_use]
pub fn builtin() -> &'static WordList {
    static LIST: OnceLock<WordList> = OnceLock::new();
    LIST.get_or_init(|| parse(BUILTIN.as_bytes()).unwrap_or(WordList { words: Vec::new() }))
}

/// Reads a word list file (FEA-03.8 to FEA-03.11 with D-03-2, D-03-3).
///
/// # Errors
/// [`ListError::TooBig`] or [`ListError::NotUtf8`] (D-03-3).
pub fn parse(bytes: &[u8]) -> Result<WordList, ListError> {
    if bytes.len() > MAX_FILE {
        return Err(ListError::TooBig);
    }
    let text = decode(bytes)?;
    let mut lines = text.split('\n').flat_map(|l| l.split('\r'));
    let signed = text.starts_with(SIGNED);
    if signed {
        // FEA-03.9: skip the armor headers up to the first blank line.
        for l in lines.by_ref() {
            if l.trim().is_empty() {
                break;
            }
        }
    }
    let mut seen = HashSet::new();
    let mut words = Vec::new();
    for line in lines {
        let line = if signed {
            if line.starts_with(SIGNATURE) {
                break;
            }
            line.strip_prefix("- ").unwrap_or(line)
        } else {
            line
        };
        let entry = strip_dice(line.trim());
        if entry.is_empty() {
            continue;
        }
        if entry.chars().nth(MAX_ENTRY).is_some() {
            return Err(ListError::TooBig);
        }
        let mut lower = String::with_capacity(entry.len());
        for c in entry.chars() {
            lower.extend(c.to_lowercase());
        }
        if seen.insert(lower.clone()) {
            if words.len() == MAX_ENTRIES {
                return Err(ListError::TooBig);
            }
            words.push(lower);
        }
    }
    Ok(WordList { words })
}

/// FEA-03.8 (1) and D-03-3: UTF-8 with an optional byte order mark, or
/// UTF-16 after its byte order mark.
fn decode(bytes: &[u8]) -> Result<String, ListError> {
    let utf16 = |rest: &[u8], big: bool| {
        let units = rest.chunks(2).map(|p| match p {
            [a, b] if big => Ok(u16::from_be_bytes([*a, *b])),
            [a, b] => Ok(u16::from_le_bytes([*a, *b])),
            _ => Err(ListError::NotUtf8),
        });
        let units: Result<Vec<u16>, ListError> = units.collect();
        String::from_utf16(&units?).map_err(|_| ListError::NotUtf8)
    };
    match bytes {
        [0xef, 0xbb, 0xbf, rest @ ..] => core::str::from_utf8(rest)
            .map(str::to_owned)
            .map_err(|_| ListError::NotUtf8),
        [0xfe, 0xff, rest @ ..] => utf16(rest, true),
        [0xff, 0xfe, rest @ ..] => utf16(rest, false),
        _ => core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| ListError::NotUtf8),
    }
}

fn ascii_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// FEA-03.8 (4): digits with optional `-digits` groups, ASCII white space,
/// then one run without ASCII white space: keep only the run.
fn strip_dice(line: &str) -> &str {
    let code_end = line
        .find(|c: char| !(c.is_ascii_digit() || c == '-'))
        .unwrap_or(line.len());
    let code = line.get(..code_end).unwrap_or("");
    let groups_ok = !code.is_empty() && code.split('-').all(|g| !g.is_empty());
    let rest = line.get(code_end..).unwrap_or("");
    let run = rest.trim_start_matches(ascii_space);
    if groups_ok && run.len() < rest.len() && !run.is_empty() && !run.contains(ascii_space) {
        run
    } else {
        line
    }
}
