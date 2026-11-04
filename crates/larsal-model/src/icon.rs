//! Icons: a standard icon number or a custom icon (MOD-06, FMT-11.10,
//! FMT-11.11, FMT-14.1).

use crate::times::Time;
use crate::unknown::UnknownElement;
use crate::uuid::Uuid;

/// The icon a group or entry shows.
///
/// Guarantees: a custom icon always means icon number 0 in the file
/// (FMT-11.11); the custom icon id may name no icon in the vault, and is then
/// kept as read (FMT-11.38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// Standard icon number. Read values are 0 or more (negative reads as 0,
    /// FMT-11.10); there is no upper limit.
    Standard(i32),
    /// Custom icon id.
    Custom(Uuid),
}

/// Standard icon of a new group (MOD-06.2, FMT-11.6).
pub const GROUP_DEFAULT: Icon = Icon::Standard(48);
/// Standard icon of an entry without `IconID` (FMT-11.15).
pub const ENTRY_DEFAULT: Icon = Icon::Standard(0);

/// One custom icon of the vault (FMT-14.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomIcon {
    /// Never the zero id; unique among custom icons.
    pub uuid: Uuid,
    /// Name, empty when none (4.1).
    pub name: String,
    /// Last modification time, when one was read or set (4.1, FMT-16.10).
    pub last_modified: Option<Time>,
    /// Image bytes as stored; decoded only for display (MOD-06, LD-65).
    pub data: Vec<u8>,
    /// Kept unknown children of `Icon`.
    pub unknown: Vec<UnknownElement>,
}
