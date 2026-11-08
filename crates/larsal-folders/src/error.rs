//! The crate's error type, in the user's words (FIL-06.18): plain tags with the exact
//! fixed messages of FIL-06. No variant holds a path, a name, a key, an offset, a cost,
//! an OS reason or any part of a file.

use std::io;

/// The format a refused folder uses. The words the user sees are one message; the
/// name is for the code that offers help, and is never counted as a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Format 8 with the `SIV_CTRMAC` cipher combination.
    SivCtrMac,
    /// Format 8 with another cipher combination.
    OtherCipher,
    /// A format number other than 8, proven by the folder's own keys.
    OtherFormat,
    /// A key file older than format 8, with no configuration, proven by its keys.
    PreFormat8,
    /// A universal vault format file.
    Uvf,
    /// A key that lives on a server. No network call and no key derivation ran.
    RemoteKey,
}

/// Every way a folder operation can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// MSG-FOLDER-OPEN: every credential, authentication, hostile structure and
    /// limit failure, with no detail that says which.
    Open,
    /// MSG-FOLDER-PROFILE: a format this crate does not run, refused by name.
    Profile(Refused),
    /// MSG-FOLDER-INPUT: the chosen location or source cannot be used.
    Input,
    /// MSG-FOLDER-NAME: a name that cannot be used safely.
    Name,
    /// MSG-FOLDER-EXISTS: an item already has this name. Nothing was replaced.
    Exists,
    /// MSG-FOLDER-BUSY: another operation of this session is running.
    Busy,
    /// MSG-FOLDER-CHANGED: the item changed in storage. Nothing was replaced.
    Changed,
    /// MSG-FOLDER-CONFLICT: both versions are kept, and the reserved name of one is
    /// taken by different data, so publishing stopped.
    Conflict,
    /// MSG-FOLDER-DELETE-CONFLICT: the deletion is pending; the edited version stays.
    DeleteConflict,
    /// MSG-FOLDER-RECOVERY: recovery copies would pass their ceiling. Nothing changed.
    Recovery,
    /// MSG-FOLDER-SPACE: not enough free space.
    Space,
    /// MSG-FOLDER-IO: an actual read or write failure.
    Io,
    /// MSG-FOLDER-UNCERTAIN: the change is unconfirmed, or what it left could not be
    /// proven ours and stays.
    Uncertain,
    /// MSG-FOLDER-LOCKED: the session is locked.
    Locked,
    /// Proposed, E23-S3: the encryption master key's shared budget (FIL-06.16) has run
    /// out on this Mac, or its ledger cannot be trusted. Reads go on; no write starts.
    Budget,
    /// Proposed, E23-S3: cancelled at a safe point, and owned cleanup succeeded.
    Cancelled,
    /// Proposed, E23-S3: a folder cannot move into itself or below itself (POSIX
    /// `rename` refuses the same move with `EINVAL`). Nothing changed.
    Inside,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Open => {
                "This encrypted folder or file could not be opened. Check the password and try again."
            }
            Self::Profile(_) => "This folder uses a format Larsal does not support yet.",
            Self::Input => "Choose local files or a folder. Links and special files cannot be added.",
            Self::Name => "Choose a name that can be used safely on this disk.",
            Self::Exists => "An item already has this name. Keep both or choose a different name.",
            Self::Busy => "A folder operation is already running.",
            Self::Changed => "This item changed in storage. Larsal kept your version for review.",
            Self::Conflict => "Both versions are kept. Choose how to keep them.",
            Self::DeleteConflict => {
                "Another version changed this item. Deletion is pending; the edited version is kept."
            }
            Self::Recovery => {
                "There is not enough room to keep recovery copies safely. Review recovery copies before changing this folder."
            }
            Self::Space => "There is not enough free space. Free some space or choose another disk.",
            Self::Io => "The files could not be read or saved. Check access and try again.",
            Self::Uncertain => {
                "Larsal could not confirm that this change was saved safely. Keep the source and review the recovery copies."
            }
            Self::Locked => "This encrypted folder is locked. Unlock it to see its files.",
            Self::Budget => {
                "This folder has reached the safe limit for new encrypted data on this Mac. Your files can still be read."
            }
            Self::Cancelled => "Cancelled. Nothing was changed.",
            Self::Inside => "A folder cannot be moved into itself or into a folder inside it.",
        })
    }
}

impl std::error::Error for Error {}

/// A system error in the user's words: full disk or quota says so, all else is I/O.
/// The cause stays out of the value (FIL-06.18).
pub(crate) fn io(e: &io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => Error::Space,
        _ => Error::Io,
    }
}
