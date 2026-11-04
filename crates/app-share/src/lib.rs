//! Shared groups (E11; spec INT-08): one group of a vault copied to a
//! separate file, the container, and read back from it.
//!
//! E11-S2: [`settings`] reads and writes a group's share settings item
//! (INT-08.1 to INT-08.5); [`container`] reads unsigned and zip containers
//! by their first bytes with the share key (INT-08.6, INT-08.8, INT-08.9,
//! INT-08.36) and builds and writes unsigned containers (INT-08.12 to
//! INT-08.14, INT-08.33, INT-08.35). App writes no signatures
//! (D-INT08-1 (a)). E11-S3: [`run`] says which shares run, imports inside
//! the share group and builds a pass's banner (INT-08.15 to INT-08.20,
//! INT-08.31, INT-08.32); app-ffi runs the passes off the main thread.
//!
//! Guarantees: every container and every share item is untrusted input
//! (AT-A08): reads stay inside app-format's limits, a zip member never
//! inflates past the vault file limit (AT-A06), and a KDF cost that would
//! need a question is refused, because nobody is asked (AT-A05). The share
//! password lives only in `SecretString` (INT-08.39, SR-14): no `Debug`
//! output or [`Error`] holds it, nor a path or any other vault text.
#![forbid(unsafe_code)]
// Rust rule 4: share items and containers are hostile input. Test code is
// exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

pub mod container;
pub mod run;
pub mod settings;

/// Why a container is not a share file (MI08-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotShare {
    /// The first bytes are neither a vault's nor a zip archive's.
    UnknownKind,
    /// The zip archive holds no vault entry.
    NoVault,
    /// The zip archive holds the vault entry twice.
    TwoVaults,
}

/// Every way a share call can fail. Holds no password, path or other
/// vault text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// MI08-04.
    NotShare(NotShare),
    /// The vault reader's or writer's reason (MI08-02, MI08-03): a wrong
    /// share password is `WrongKey`; a damaged zip archive `Corrupt`, one
    /// that uses ZIP64, encryption or another method `Unsupported`; a file
    /// or zip member over the vault file limit `TooLarge(TotalFile)`; a KDF
    /// cost that would need a question `TooLarge(KdfCost)`.
    Vault(app_format::Error),
    /// The system's reason (MI08-02, MI08-07).
    Io(std::io::ErrorKind),
    /// The share group is not in the vault.
    NoGroup,
    /// The share group is in the recycle bin, so it is inactive
    /// (INT-08.35).
    Recycled,
    /// The random source failed.
    RandomSource,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotShare(NotShare::UnknownKind) => {
                f.write_str("not a share file: unknown file kind")
            }
            Self::NotShare(NotShare::NoVault) => {
                f.write_str("not a share file: the archive holds no vault")
            }
            Self::NotShare(NotShare::TwoVaults) => {
                f.write_str("not a share file: the archive holds two vaults")
            }
            Self::Vault(e) => e.fmt(f),
            Self::Io(k) => write!(f, "the file could not be read or written: {k:?}"),
            Self::NoGroup => f.write_str("the shared group is not in the vault"),
            Self::Recycled => f.write_str("the shared group is in the recycle bin"),
            Self::RandomSource => f.write_str("random source failed"),
        }
    }
}

impl std::error::Error for Error {}
