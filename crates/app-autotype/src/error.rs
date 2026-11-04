//! Why a run stops before typing (INT-05 Messages, MI05-11 to MI05-27).
//!
//! Guarantees: a reason holds only a token as written in the sequence, cut
//! to its first 40 characters, a modifier run, or one character of the
//! sequence text (INT-05.18). It never holds a resolved value, a field
//! value or a window title (Rust rule 3).

use crate::Mods;

/// The alert title every reason goes under (MI05-10).
pub const TITLE: &str = "Auto-Type stopped";

/// One reason of INT-05; `Display` gives the card's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// MI05-11 (INT-05.2).
    Unpaired,
    /// MI05-12 (INT-05.6, INT-05.17).
    Repeat(String),
    /// MI05-13 (INT-05.7).
    Wait(String),
    /// MI05-14 (INT-05.7).
    Pause(String),
    /// MI05-15 (INT-05.7).
    Number(String),
    /// MI05-16 (INT-05.9).
    Otp,
    /// MI05-17 (INT-05.10).
    NoField(String),
    /// MI05-18 (INT-05.10).
    PickTooLong(String),
    /// MI05-19 (INT-05.13).
    Unknown(String),
    /// MI05-20 (INT-05.13).
    Conversion(String),
    /// MI05-21 (INT-05.16, LD-186 (2)).
    TooManyKeys,
    /// MI05-22 (INT-05.16).
    TooLong,
    /// MI05-23 (INT-05.42): a character of the sequence text and the
    /// modifiers in front of it.
    NoKey {
        /// The character as written.
        ch: char,
        /// The modifiers of its token.
        mods: Mods,
    },
    /// MI05-24 (INT-05.3): the modifier run as written.
    DanglingMods(String),
    /// MI05-25 (R05-2, LD-177).
    TooDeep(String),
    /// MI05-26 (R05-4, LD-177).
    Shortcut(String),
    /// MI05-27 (R05-7, LD-177): MOD-08 hit its depth budget or a work
    /// bound.
    Grows(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unpaired => f.write_str("A { or } has no partner."),
            Self::Repeat(v) => write!(f, "{v} repeats more than 100 times."),
            Self::Wait(v) => write!(f, "{v} waits longer than 10 seconds."),
            Self::Pause(v) => write!(f, "{v} pauses more than 500 ms between keys."),
            Self::Number(v) => write!(f, "{v} needs a number."),
            Self::Otp => f.write_str("The one-time code settings of this entry are not valid."),
            Self::NoField(v) => write!(f, "{v} names a field this entry doesn't have."),
            Self::PickTooLong(v) => write!(
                f,
                "{v}: the field has more than 256 characters to pick from."
            ),
            Self::Unknown(v) => write!(f, "{v} is not a placeholder App knows."),
            Self::Conversion(v) => write!(f, "{v} is not a conversion App can use."),
            Self::TooManyKeys => {
                f.write_str("The sequence has more than 10,000 keys, waits and pauses.")
            }
            Self::TooLong => {
                f.write_str("The waits in the sequence add up to more than 60 seconds.")
            }
            Self::NoKey { ch, mods } => write!(
                f,
                "{ch} can't be typed with {mods} on this keyboard layout."
            ),
            Self::DanglingMods(v) => {
                write!(f, "{v} at the end of the sequence have no key to go with.")
            }
            Self::TooDeep(v) => write!(f, "{v} has braces nested more than 32 deep."),
            Self::Shortcut(v) => write!(f, "{v} is App's own Auto-Type shortcut."),
            Self::Grows(v) => write!(f, "{v} refers to itself or grows too large."),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// The card's message id, for the screen layer and the debug log.
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Error::Unpaired => "MI05-11",
            Error::Repeat(_) => "MI05-12",
            Error::Wait(_) => "MI05-13",
            Error::Pause(_) => "MI05-14",
            Error::Number(_) => "MI05-15",
            Error::Otp => "MI05-16",
            Error::NoField(_) => "MI05-17",
            Error::PickTooLong(_) => "MI05-18",
            Error::Unknown(_) => "MI05-19",
            Error::Conversion(_) => "MI05-20",
            Error::TooManyKeys => "MI05-21",
            Error::TooLong => "MI05-22",
            Error::NoKey { .. } => "MI05-23",
            Error::DanglingMods(_) => "MI05-24",
            Error::TooDeep(_) => "MI05-25",
            Error::Shortcut(_) => "MI05-26",
            Error::Grows(_) => "MI05-27",
        }
    }
}

/// A token as a message may show it: its first 40 characters (INT-05.18).
pub(crate) fn shown(token: &str) -> String {
    token.chars().take(40).collect()
}
