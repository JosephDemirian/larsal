//! The error kinds of opening, creating and saving a vault (spec FMT-01.33,
//! the one list). No variant holds a key, password, protected value or other
//! secret; a key file's version text and an operating system error kind are
//! the only data carried, and neither is secret.

use crate::limits::Limit;

/// Every way an `app-format` call can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Under 12 bytes, or the first bytes are not a vault's (FMT-01.2, FMT-01.5).
    NotAVault,
    /// A vault of the old version 1 format (FMT-01.4); the screen offers import.
    OldFormat,
    /// A version, id, flag or setting App cannot handle (FMT-01.7, FMT-02,
    /// FMT-03, FMT-08, FMT-09, FMT-17, CRY-02.16).
    Unsupported,
    /// Damaged frame, header, map, block, padding, gzip, inner header or
    /// document; a missing required field; a file cut off early.
    Corrupt,
    /// No credential part at all (FMT-04.16; on open before the KDF, LD-13).
    NoCredentials,
    /// A key file problem (FMT-18.19), before any key derivation.
    KeyFile(KeyFileReason),
    /// A hardware key problem (FMT-04.10, FMT-04.17); never `WrongKey`.
    HardwareKey(HardwareKeyReason),
    /// Over a limit in `limits.rs`, or a KDF cost above a refuse ceiling;
    /// names the limit (FMT-08.12 names).
    TooLarge(Limit),
    /// Header HMAC mismatch (version 4) or start bytes mismatch (version 3, LD-12).
    WrongKey,
    /// Reading or writing the vault file failed in the operating system.
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAVault => f.write_str("not a vault file"),
            Self::OldFormat => f.write_str("vault in the old format"),
            Self::Unsupported => f.write_str("unsupported vault feature"),
            Self::Corrupt => f.write_str("vault file is damaged"),
            Self::NoCredentials => f.write_str("no password, key file or hardware key given"),
            Self::KeyFile(v) => write!(f, "key file problem: {v}"),
            Self::HardwareKey(v) => write!(f, "hardware key problem: {v}"),
            Self::TooLarge(v) => write!(f, "vault is over the {v} limit"),
            Self::WrongKey => f.write_str("wrong password or key"),
            Self::Io(v) => write!(f, "vault file input or output failed: {v:?}"),
        }
    }
}

impl std::error::Error for Error {}

/// Why a key file was refused (FMT-18.19, one per row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFileReason {
    /// The file is empty (FMT-18.2).
    Empty,
    /// A key file document version other than 1.0 or 2.0 (FMT-18.10), with
    /// its version text only when that is at most 16 characters of digits
    /// and dots; otherwise empty (LD-87).
    UnsupportedVersion(String),
    /// The check value does not match (FMT-18.13).
    CheckValueMismatch,
    /// The key data cannot be read (FMT-18.12 to FMT-18.14).
    DataUnreadable,
    /// Opening or reading the key file failed in the operating system.
    Io(std::io::ErrorKind),
    /// A pipe, socket, folder or other non-regular file.
    NotRegularFile,
    /// A key file document that declares a DTD (FMT-18.17, LD-30).
    Dtd,
    /// Over a key file limit (D-18-3, LD-22, LD-83), naming it.
    TooLarge(Limit),
}

impl std::fmt::Display for KeyFileReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("empty"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            Self::CheckValueMismatch => f.write_str("check value mismatch"),
            Self::DataUnreadable => f.write_str("key data unreadable"),
            Self::Io(v) => write!(f, "cannot read: {v:?}"),
            Self::NotRegularFile => f.write_str("not a regular file"),
            Self::Dtd => f.write_str("DTD not accepted"),
            Self::TooLarge(v) => write!(f, "over the {v} limit"),
        }
    }
}

impl std::error::Error for KeyFileReason {}

/// Why a hardware key failed (FMT-04.10, FMT-04.17; details in INT-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareKeyReason {
    /// No device, or it was removed.
    Missing,
    /// No answer in time.
    TimedOut,
    /// The slot is not set up for challenge-response.
    SlotNotConfigured,
    /// The answer is not 20 bytes.
    BadAnswer,
    /// macOS refused to open the key (INT-07.7, D-INT07-3, LD-173).
    NotPermitted,
    /// Any other device failure.
    Failed,
}

impl std::fmt::Display for HardwareKeyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("device missing"),
            Self::TimedOut => f.write_str("timed out"),
            Self::SlotNotConfigured => f.write_str("slot not configured"),
            Self::BadAnswer => f.write_str("bad answer length"),
            Self::NotPermitted => f.write_str("not permitted"),
            Self::Failed => f.write_str("device failure"),
        }
    }
}

impl std::error::Error for HardwareKeyReason {}
