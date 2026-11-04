//! Tells a vault file from any other file by its first 12 bytes (FMT-01.2 to
//! FMT-01.7), and reads a vault source with the total file limit (FMT-01.31).
//! Allocates nothing based on the bytes it looks at.

use crate::error::Error;
use crate::limits::{Limit, Limits};
use std::io::Read;

/// Bytes 0 to 3 of every vault file (FMT-01.3).
pub const SIGNATURE_1: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];
/// Bytes 4 to 7 of a version 2, 3 or 4 vault (FMT-01.3).
pub const SIGNATURE_2: [u8; 4] = [0x67, 0xFB, 0x4B, 0xB5];
/// Bytes 4 to 7 of the old version 1 format (FMT-01.4).
pub const SIGNATURE_2_OLD: [u8; 4] = [0x65, 0xFB, 0x4B, 0xB5];

/// What the first 12 bytes say (FMT-01.2 to FMT-01.5). The version is not
/// judged here; [`check`] does that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detected {
    /// Signatures of the version 2 to 4 family, with the version field split.
    Vault {
        /// High 16 bits of the version field (bytes 10 and 11).
        major: u16,
        /// Low 16 bits of the version field (bytes 8 and 9).
        minor: u16,
    },
    /// The old version 1 format (FMT-01.4); not opened, offered as an import.
    OldFormat,
    /// Any other first 8 bytes (FMT-01.5).
    NotAVault,
    /// Fewer than 12 bytes (FMT-01.2).
    TooShort,
}

/// Reads the signatures and version from the first 12 bytes of `file`.
#[must_use]
pub fn detect(file: &[u8]) -> Detected {
    let Some(head) = file.first_chunk::<12>() else {
        return Detected::TooShort;
    };
    let [s0, s1, s2, s3, t0, t1, t2, t3, n0, n1, j0, j1] = *head;
    if [s0, s1, s2, s3] != SIGNATURE_1 {
        return Detected::NotAVault;
    }
    match [t0, t1, t2, t3] {
        SIGNATURE_2 => Detected::Vault {
            major: u16::from_le_bytes([j0, j1]),
            minor: u16::from_le_bytes([n0, n1]),
        },
        SIGNATURE_2_OLD => Detected::OldFormat,
        _ => Detected::NotAVault,
    }
}

/// Detection plus the version check (FMT-01.7): `(major, minor)` for majors
/// 2, 3 and 4 with any minor.
///
/// # Errors
/// `NotAVault` (too short or other bytes), `OldFormat`, or `Unsupported`
/// for major 0, 1, or 5 and above (FMT-01.33).
pub fn check(file: &[u8]) -> Result<(u16, u16), Error> {
    match detect(file) {
        Detected::Vault { major, minor } if (2..=4).contains(&major) => Ok((major, minor)),
        Detected::Vault { .. } => Err(Error::Unsupported),
        Detected::OldFormat => Err(Error::OldFormat),
        Detected::NotAVault | Detected::TooShort => Err(Error::NotAVault),
    }
}

/// The read step's limit rule (FMT-01.31 step 2): a file over
/// `limits.total_file` is `TooLarge` only when its first 12 bytes pass
/// [`check`]; otherwise its detection result is reported later, after the
/// credentials (FMT-05.7).
///
/// # Errors
/// `TooLarge`, as above.
pub fn check_total(file: &[u8], limits: &Limits) -> Result<(), Error> {
    if file.len() > limits.total_file && check(file).is_ok() {
        return Err(Error::TooLarge(Limit::TotalFile));
    }
    Ok(())
}

/// Reads a whole vault source into memory, never more than
/// `limits.total_file` + 1 bytes (FMT-01.31, FMT-01.32). The buffer grows
/// with the bytes that arrive; no size anyone declares is trusted.
///
/// Guarantees: a source over the limit whose first 12 bytes pass [`check`]
/// gives `TooLarge`; one whose first 12 bytes fail is returned as read (cut
/// at limit + 1 bytes), so the open reports its detection result after the
/// credentials step (FMT-05.7).
///
/// # Errors
/// `TooLarge` as above; `Io` with the operating system's error kind.
pub fn read_vault<R: Read>(src: R, limits: &Limits) -> Result<Vec<u8>, Error> {
    let cap = u64::try_from(limits.total_file)
        .map_err(|_| Error::TooLarge(Limit::TotalFile))?
        .saturating_add(1);
    let mut file = Vec::new();
    src.take(cap)
        .read_to_end(&mut file)
        .map_err(|e| Error::Io(e.kind()))?;
    check_total(&file, limits)?;
    Ok(file)
}
