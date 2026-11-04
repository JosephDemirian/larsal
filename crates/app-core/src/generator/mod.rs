//! The password and passphrase generator (story E4-S9): one core for the
//! toolbar generator, every password field popup, the browser request, the
//! new-entry password and the command line (FEA-02, FEA-03).
//!
//! Guarantees (SG-01, AT-B04):
//! - Every random index comes from `app_crypto::random::below`: the OS
//!   source, no seed, no modulo bias. The public functions take no source;
//!   the scripted source the card's tests need exists only in this crate's
//!   unit tests.
//! - A source failure fails closed: an error and no partial value.
//! - Every output lives in a `SecretString`; the working buffers wipe
//!   themselves (FEA-02.23, FEA-03.17).
//!
//! The strength line (FEA-02.15, D-03-7) is FEA-05's estimate, story E4-S11;
//! the passphrase formula (FEA-03.7) is here.

pub mod passphrase;
pub mod password;
pub mod wordlist;

use app_crypto::secret::SecretBytes;

/// A random source: an index in `0..n`, every value equally likely.
pub(crate) trait Source {
    /// `None` when the source failed (or `n` is 0).
    fn below(&mut self, n: u32) -> Option<u32>;
}

/// The one source of product code: the OS, through `app-crypto`.
pub(crate) struct Os;

impl Source for Os {
    fn below(&mut self, n: u32) -> Option<u32> {
        app_crypto::random::below(n).ok()
    }
}

/// A wiping array of characters (stored as 4-byte code points), for the
/// picks and the shuffle of FEA-02.8.
pub(crate) struct Chars(SecretBytes);

impl Chars {
    pub(crate) fn new(len: usize) -> Self {
        Self(SecretBytes::zeroed(len.saturating_mul(4)))
    }

    pub(crate) fn get(&self, i: usize) -> char {
        let at = i.saturating_mul(4);
        self.0
            .expose()
            .get(at..at.saturating_add(4))
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .and_then(|b| char::from_u32(u32::from_le_bytes(b)))
            .unwrap_or('\0')
    }

    pub(crate) fn set(&mut self, i: usize, c: char) {
        let at = i.saturating_mul(4);
        if let Some(slot) = self.0.expose_mut().get_mut(at..at.saturating_add(4)) {
            slot.copy_from_slice(&u32::from(c).to_le_bytes());
        }
    }

    pub(crate) fn swap(&mut self, i: usize, j: usize) {
        let (a, b) = (self.get(i), self.get(j));
        self.set(i, b);
        self.set(j, a);
    }
}

/// The quality word of a strength (FEA-02.15, FEA-03.7): FEA-05.4's levels
/// of the score floor(bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Score 0 or less (the empty text).
    Bad,
    /// Score 1 to 39.
    Poor,
    /// Score 40 to 74.
    Weak,
    /// Score 75 to 99.
    Good,
    /// Score 100 and up.
    Excellent,
}

/// The level of a strength in bits (FEA-05.4 bands on floor(bits)).
#[must_use]
pub fn level(bits: f64) -> Level {
    if bits >= 100.0 {
        Level::Excellent
    } else if bits >= 75.0 {
        Level::Good
    } else if bits >= 40.0 {
        Level::Weak
    } else if bits >= 1.0 {
        Level::Poor
    } else {
        Level::Bad
    }
}
