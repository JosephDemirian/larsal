//! The password generator of the window and of the editor's password field
//! (E5-S6, FEA-02, FEA-03): app-core's one generator core, its value kept
//! here.
//!
//! Guarantees:
//! - The value made or typed lives only here, in a `SecretString`. Swift gets
//!   it to show it, as a Show the user asked for (FEA-02.23, AGENTS.md
//!   rule 4), and never sends it back: Copy and Use are commands on the value
//!   held here.
//! - Each value comes with its strength: FEA-05's estimate of the text, or
//!   FEA-03.7's formula for a passphrase as made. The estimate runs on the
//!   calling thread: Swift calls off the main thread (LD-137).
//! - A new value, closing the generator, and every lock, lock-all and close
//!   drop the value (D-02-5). Each drop moves a counter; a value made or
//!   typed while a drop came is dropped too, never kept.
//! - Options are checked before they are copied or saved (D-02-4, D-03-5,
//!   AT-E03).
//! - Options the screen cannot make give no value and a plain reason
//!   (D-02-3 (b)); nothing is drawn for them.
//! - The options are saved on Apply and when the window's generator closes
//!   (FEA-02.18), in the settings store (APP-01 S-PWGEN, LD-204, E5-S9).
//!   Generated values are never saved.

use crate::session::{AppError, MAX_TEXT, Session};
use crate::views::{Copied, Rating, count};
use app_core::generator::{passphrase, password, wordlist};
use app_core::health::{Level, bits_with, score, zxcvbn_bits};
use app_crypto::secret::SecretString;
use std::fmt;
use std::sync::{MutexGuard, PoisonError};

/// The passphrase word case (FEA-03.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WordCase {
    /// Every word in lower case.
    Lower,
    /// Every word in upper case.
    Upper,
    /// First character upper, the rest lower.
    Title,
    /// One word upper, the others lower.
    Mixed,
}

/// The generator's options (APP-01 S-PWGEN-01 to -22, the ones the screen
/// shows). No secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GeneratorOptions {
    /// The Passphrase tab (`generator.kind`).
    pub passphrase: bool,
    /// Characters, 1 to 999 (FEA-02.10).
    pub length: u32,
    /// `A–Z`.
    pub upper: bool,
    /// `a–z`.
    pub lower: bool,
    /// `0–9`.
    pub digits: bool,
    /// `!@#$`: the 32 symbols as one group (D-02-2 (b)).
    pub special: bool,
    /// `Äéß`: U+00A1 to U+00FF without U+00AD.
    pub extended: bool,
    /// Leave out look-alikes (FEA-02.2).
    pub exclude_lookalike: bool,
    /// At least one character of every chosen type (FEA-02.8).
    pub every_group: bool,
    /// Words, 1 to 100 (FEA-03.3).
    pub words: u32,
    /// Between words, at most 64 characters (D-03-5).
    pub separator: String,
    /// The word case.
    pub case: WordCase,
}

impl Default for GeneratorOptions {
    /// FEA-02.11 with D-02-2 (b), and FEA-03's defaults.
    fn default() -> Self {
        Self {
            passphrase: false,
            length: 20,
            upper: true,
            lower: true,
            digits: true,
            special: true,
            extended: false,
            exclude_lookalike: true,
            every_group: true,
            words: 7,
            separator: " ".to_owned(),
            case: WordCase::Lower,
        }
    }
}

/// A value to show and its strength. `Debug` hides the value (Rust rule 3).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct Generated {
    /// The value, shown as the user asked (FEA-02.23); empty with `problem`.
    pub value: String,
    /// Its strength: level (Bad shown as Poor, FEA-05.8), whole bits and
    /// characters.
    pub rating: Rating,
    /// Why nothing was made (`MSG-GEN-*`, `MSG-PP-*`), in plain words.
    pub problem: Option<String>,
}

impl fmt::Debug for Generated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generated")
            .field("value", &"<hidden>")
            .field("rating", &self.rating)
            .field("problem", &self.problem)
            .finish()
    }
}

/// The session's generator: the value on screen, the saved options, and
/// the drops so far.
#[derive(Default)]
pub(crate) struct State {
    saved: Option<GeneratorOptions>,
    value: Option<SecretString>,
    drops: u64,
}

impl State {
    /// Drops the value and counts the drop.
    fn drop_value(&mut self) {
        self.value = None;
        self.drops = self.drops.wrapping_add(1);
    }
}

/// Answered when the generator's value was dropped while a value was being
/// made or rated (a lock, a close): nothing is kept or shown.
const MSG_CLOSED: &str = "The generator was closed.";

/// `MSG-GEN-LENGTH`.
const MSG_LENGTH: &str = "Choose a length from 1 to 999.";
/// `MSG-PP-COUNT`.
const MSG_COUNT: &str = "Choose from 1 to 100 words.";
/// D-03-5's separator limit.
const MSG_SEPARATOR: &str = "The separator can have at most 64 characters.";
/// `MSG-GEN-RANDOM`.
const MSG_RANDOM: &str = "Could not get random numbers from macOS. Nothing was made.";

/// A value with `o` and its strength in bits, or the reason there is none.
pub(crate) fn make(o: &GeneratorOptions) -> Result<(SecretString, f64), String> {
    if o.passphrase {
        if !(1..=passphrase::SCREEN_MAX_WORDS).contains(&o.words) {
            return Err(MSG_COUNT.to_owned());
        }
        // D-03-5: checked before the separator is copied.
        if too_long(&o.separator) {
            return Err(MSG_SEPARATOR.to_owned());
        }
        let case = match o.case {
            WordCase::Lower => passphrase::Case::Lower,
            WordCase::Upper => passphrase::Case::Upper,
            WordCase::Title => passphrase::Case::Title,
            WordCase::Mixed => passphrase::Case::Mixed,
        };
        let options = passphrase::Options {
            words: o.words,
            separator: o.separator.clone(),
            case,
        };
        let list = wordlist::builtin();
        let value = passphrase::generate(&options, list).map_err(|e| {
            match e {
                passphrase::Error::CountOutOfRange => MSG_COUNT,
                passphrase::Error::SeparatorTooLong => MSG_SEPARATOR,
                passphrase::Error::EmptyWordList => "The word list is empty.",
                passphrase::Error::RandomFailed => MSG_RANDOM,
            }
            .to_owned()
        })?;
        // FEA-03.7: the formula, not the estimate, for a phrase as made.
        return Ok((value, passphrase::entropy(o.words, list)));
    }
    if !(1..=password::SCREEN_MAX_LENGTH).contains(&o.length) {
        return Err(MSG_LENGTH.to_owned());
    }
    let value = password::generate(&password_options(o)).map_err(|e| match e {
        password::Error::InvalidOptions(password::Invalid::LengthOutOfRange) => {
            MSG_LENGTH.to_owned()
        }
        password::Error::InvalidOptions(password::Invalid::TextTooLong) => {
            "The extra or left-out characters are too long.".to_owned()
        }
        password::Error::InvalidOptions(password::Invalid::NoCharacters) => {
            "Choose at least one character type.".to_owned()
        }
        password::Error::InvalidOptions(password::Invalid::TooShortForEveryGroup(n)) => {
            format!("A character of every chosen type needs a length of at least {n}.")
        }
        password::Error::RandomFailed => MSG_RANDOM.to_owned(),
    })?;
    let bits = estimate(&value);
    Ok((value, bits))
}

/// The password options in `o`; its passphrase choice is not read.
pub(crate) fn password_options(o: &GeneratorOptions) -> password::Options {
    let classes = [
        (o.lower, password::Class::Lower),
        (o.upper, password::Class::Upper),
        (o.digits, password::Class::Digits),
        (o.special, password::Class::Special),
        (o.extended, password::Class::Extended),
    ];
    password::Options {
        length: o.length,
        classes: classes
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, c)| *c)
            .collect(),
        extra: String::new(),
        excluded: String::new(),
        exclude_lookalike: o.exclude_lookalike,
        every_group: o.every_group,
    }
}

/// The separator is over 64 characters (D-03-5); counts at most 65.
fn too_long(separator: &str) -> bool {
    separator.chars().nth(passphrase::MAX_SEPARATOR).is_some()
}

/// FEA-05's estimate of a text with no entry around it (no user inputs).
pub(crate) fn estimate(text: &SecretString) -> f64 {
    bits_with(&zxcvbn_bits, text.expose(), &[])
}

/// The strength line (FEA-02.15 in the mockup's look "level · bits"): the
/// FEA-05.4 level, Bad shown as Poor (FEA-05.8), E in whole bits.
fn rating(bits: f64, text: &str) -> Rating {
    let level = Level::of(score(bits));
    let shown = if level == Level::Bad {
        Level::Poor
    } else {
        level
    };
    Rating {
        level: shown.name().to_owned(),
        word: shown.name().to_owned(),
        segments: level.quality(),
        attention: false,
        expired: false,
        issue: String::new(),
        reasons: Vec::new(),
        chars: count(text.chars().count()),
        // `as` saturates; E is never negative.
        bits: bits.round() as u32,
    }
}

impl Session {
    /// A copy of the value held here, for the Sharing page's password
    /// field (share_edit.rs); `Refused` with none.
    pub(crate) fn generated(&self) -> Result<SecretString, AppError> {
        match &self.generator().value {
            Some(v) if !v.is_empty() => Ok(SecretString::new(v.expose().to_owned())),
            _ => Err(AppError::Refused(
                "There is no generated password to use.".to_owned(),
            )),
        }
    }

    fn generator(&self) -> MutexGuard<'_, State> {
        self.generator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// D-02-5: every lock, lock-all and close drops the generator's value.
    /// Takes only the generator's lock, never the session's.
    pub(crate) fn drop_generated(&self) {
        self.generator().drop_value();
    }

    /// Keeps a value made since drop `start`, and returns it to be shown;
    /// a drop meanwhile (a lock, a close) drops it instead (D-02-5).
    fn keep_made(&self, start: u64, made: Result<(SecretString, f64), String>) -> Generated {
        let mut state = self.generator();
        let (value, bits) = match made {
            Ok(made) if state.drops == start => made,
            Ok(_) => return nothing(MSG_CLOSED),
            Err(problem) => {
                state.drop_value();
                return nothing(&problem);
            }
        };
        let shown = Generated {
            value: value.expose().to_owned(),
            rating: rating(bits, value.expose()),
            problem: None,
        };
        state.value = Some(value);
        shown
    }
}

/// No value, and why.
fn nothing(problem: &str) -> Generated {
    Generated {
        value: String::new(),
        rating: rating(0.0, ""),
        problem: Some(problem.to_owned()),
    }
}

#[uniffi::export]
impl Session {
    /// The options the generator opens with (FEA-02.18): the saved ones,
    /// else the defaults. Opened from vault `vault`'s editor, the length is
    /// that of the password field's text when it is not empty, at most 999
    /// (FEA-02.17).
    #[must_use]
    pub fn generator_options(&self, vault: Option<u64>) -> GeneratorOptions {
        let saved = self.generator().saved.clone();
        let mut options = saved.unwrap_or_else(|| self.settings.generator());
        if let Some(text) = vault.and_then(|v| {
            self.draft_password(v)
                .or_else(|_| self.share_edit_show(v))
                .ok()
        }) {
            let text = SecretString::new(text);
            options.length = password::start_length(text.expose(), options.length);
        }
        options
    }

    /// Makes a value with `options` (FEA-02.5 to FEA-02.8, FEA-03.4 to
    /// FEA-03.6) and keeps it in place of the one before; returns it to be
    /// shown, with its strength (a crossing of LD-220: the generator's value). Invalid options: no value, the reason in
    /// `problem` (D-02-3 (b)). Rates on this thread: call it off the main
    /// thread.
    #[must_use]
    pub fn generate(&self, options: GeneratorOptions) -> Generated {
        // Made and rated outside the lock; the old value goes on the swap.
        let start = self.generator().drops;
        self.keep_made(start, make(&options))
    }

    /// The user typed over the shown value (FEA-02.16): `text` becomes the
    /// value; its strength is FEA-05's estimate, also on the Passphrase tab
    /// (D-03-7). Call it off the main thread.
    ///
    /// # Errors
    /// `TooLong` over 64 KiB: the value is dropped too, so Copy and Use never
    /// act on one no longer shown. `Refused` when a lock or close came while
    /// it was rated.
    pub fn edit_generated(&self, text: String) -> Result<Rating, AppError> {
        let start = {
            let mut state = self.generator();
            if text.len() > MAX_TEXT {
                state.drop_value();
                return Err(AppError::TooLong);
            }
            state.drops
        };
        let text = SecretString::new(text);
        let shown = rating(estimate(&text), text.expose());
        let mut state = self.generator();
        if state.drops != start {
            return Err(AppError::Refused(MSG_CLOSED.to_owned()));
        }
        state.value = Some(text);
        Ok(shown)
    }

    /// Copy (FEA-02.20, APP-03 `copy.generated`): the value held here goes to
    /// the clipboard as every copy does (markers, countdown, cleared on
    /// lock); the label is `Password`. No value: `Copied.empty`.
    ///
    /// # Errors
    /// `NotAvailable` when the clipboard could not be written.
    pub fn copy_generated(&self) -> Result<Copied, AppError> {
        let state = self.generator();
        let value = state.value.as_ref().map_or("", SecretString::expose);
        self.copy_value("Password".to_owned(), value)
    }

    /// Apply (`ACT-GEN-APPLY`, FEA-02.17): the value held here becomes the
    /// password of vault `vault`'s editor draft. Returns its length.
    ///
    /// # Errors
    /// `Refused` with no value or no editor open; `TooLong`.
    pub fn use_generated(&self, vault: u64) -> Result<u32, AppError> {
        // Taken out first: the session's lock is never taken under the
        // generator's.
        let value = match &self.generator().value {
            Some(v) if !v.is_empty() => v.expose().to_owned(),
            _ => {
                return Err(AppError::Refused(
                    "There is no generated password to use.".to_owned(),
                ));
            }
        };
        // `set_password` wraps it in a `SecretString` at once.
        self.set_password(vault, value)
    }

    /// The generator closes: its value is dropped (FEA-02.23). `save` keeps
    /// those options for the next opening (FEA-02.18: on Apply and when the
    /// window's generator closes); `None`, or options with a separator over
    /// 64 characters (D-03-5), keep the saved ones.
    pub fn close_generator(&self, save: Option<GeneratorOptions>) {
        let mut state = self.generator();
        state.drop_value();
        if let Some(options) = save.filter(|o| !too_long(&o.separator)) {
            self.settings.store_generator(&options);
            state.saved = Some(options);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GeneratorOptions, make};
    use crate::session::Session;

    /// D-02-5 in Rust alone: a lock while a value is being made or rated
    /// drops that value too; it is never kept after the lock.
    #[test]
    fn d_02_5_lock_during_rating_keeps_nothing() {
        let s = Session::new();
        let start = s.generator().drops;
        let made = make(&GeneratorOptions::default());
        s.lock_all();
        let shown = s.keep_made(start, made);
        assert_eq!(shown.value, "");
        assert!(s.generator().value.is_none());
        assert!(s.copy_generated().unwrap().empty);
        // Without a drop between, the value is kept.
        let start = s.generator().drops;
        let shown = s.keep_made(start, make(&GeneratorOptions::default()));
        assert_eq!(shown.value.chars().count(), 20);
        assert!(s.generator().value.is_some());
    }
}
