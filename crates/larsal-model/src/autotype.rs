//! Auto-Type settings and window associations of an entry (FMT-11.24,
//! MOD-01.18).

use crate::unknown::UnknownElement;

/// The auto-type block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoType {
    /// `Enabled`, default true.
    pub enabled: bool,
    /// `DataTransferObfuscation`, default 0, kept as read.
    pub obfuscation: i32,
    /// `DefaultSequence`; empty means "use the group's".
    pub default_sequence: String,
    /// Window associations in stored order; duplicates and empty ones kept.
    pub associations: Vec<Association>,
    /// Kept unknown children of all `AutoType` blocks, in read order.
    pub unknown: Vec<UnknownElement>,
}

/// One window association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association {
    /// `Window`.
    pub window: String,
    /// `KeystrokeSequence`.
    pub sequence: String,
    /// Kept unknown children of `Association`.
    pub unknown: Vec<UnknownElement>,
}

impl Default for AutoType {
    /// Enabled, obfuscation 0, empty sequence, no associations.
    fn default() -> Self {
        AutoType {
            enabled: true,
            obfuscation: 0,
            default_sequence: String::new(),
            associations: Vec::new(),
            unknown: Vec::new(),
        }
    }
}
