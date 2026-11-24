//! 16-byte ids of groups, entries, custom icons and deleted objects.

use core::fmt;

/// A 16-byte id in RFC 4122 byte order (the order of its canonical hex text).
///
/// Guarantees: plain data, no secret. The all-zero id means "none" in the file
/// (FMT-12.16); the model never gives a group or entry the zero id
/// (`invariants.rs`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    /// The all-zero id, "none" in the file.
    pub const ZERO: Uuid = Uuid([0; 16]);

    /// True for the all-zero id.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }

    /// `None` for the all-zero id, the id otherwise: how references read it.
    #[must_use]
    pub fn non_zero(self) -> Option<Uuid> {
        (!self.is_zero()).then_some(self)
    }
}

impl fmt::Debug for Uuid {
    /// Lowercase hex, 32 digits. Ids are not secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_means_none() {
        assert!(Uuid::ZERO.is_zero());
        assert_eq!(Uuid::ZERO.non_zero(), None);
        let id = Uuid([1; 16]);
        assert_eq!(id.non_zero(), Some(id));
        assert_eq!(format!("{id:?}"), "01".repeat(16));
    }
}
