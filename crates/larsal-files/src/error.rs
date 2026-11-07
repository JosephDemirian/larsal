//! The crate's error type, in the user's words (FIL-03.13, FIL-03.14): plain
//! tags with the exact fixed messages of FIL-03. No variant holds a path, a
//! key, an offset, a cost, an OS reason or any part of a file.

use std::io;

/// Every way a file operation can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// MSG-FILE-DECRYPT: every failure of a file's syntax, credential, header,
    /// tag, order, truncation, unsupported recipient or hostile limit.
    Decrypt,
    /// MSG-FILE-INPUT: the selection is not one local regular file.
    Input,
    /// MSG-FILE-PASSPHRASE: an empty or over-limit passphrase; no KDF ran.
    Passphrase,
    /// MSG-FILE-RECIPIENT: a recipient key is not a valid native X25519 key,
    /// or the list is empty or too long.
    Recipient,
    /// MSG-FILE-EXISTS: the chosen output name is taken. Nothing was changed.
    Exists,
    /// MSG-FILE-DESTINATION: the chosen folder or name cannot be used.
    Destination,
    /// MSG-FILE-CHANGED: the source changed while it was captured or read.
    Changed,
    /// MSG-FILE-SPACE: the disk ran out of space.
    Space,
    /// MSG-FILE-IO: an actual read or write failure.
    Io,
    /// Proposed, E22-S3: the chosen disk cannot keep a new file private, so a
    /// decrypted output is refused. E22-S4 adds the warned consent.
    Unprotected,
    /// MSG-FILE-CLEANUP: an incomplete output could not be emptied, so it may hold
    /// readable data.
    Cleanup,
    /// Proposed, E22-S3: an incomplete output was emptied through its own handle,
    /// but its name was not as expected or could not be removed.
    CleanupEmpty,
    /// MSG-FILE-UNCERTAIN: every byte was written, but its save is unconfirmed.
    Uncertain,
    /// MSG-FILE-CANCELLED: cancelled, and handled cleanup succeeded.
    Cancelled,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Decrypt => {
                "This file could not be decrypted. Check the passphrase or file key and try again."
            }
            Self::Input => "Choose one local file. Folders and links are not supported here.",
            Self::Passphrase => "Enter a passphrase within the allowed size.",
            Self::Recipient => "Add a valid native X25519 recipient key.",
            Self::Exists => "A file already exists with this name. Choose a different name.",
            Self::Destination => {
                "This location cannot be used. Choose another folder and a new file name."
            }
            Self::Changed => "The source file changed. Choose it again and try once more.",
            Self::Space => "There is not enough free space. Free some space or choose another disk.",
            Self::Io => "The file could not be read or saved. Check access to the files and try again.",
            Self::Unprotected => {
                "This disk cannot keep a decrypted file private. Choose another folder and a new file name."
            }
            Self::Cleanup => {
                "Larsal could not remove an incomplete file. It may contain readable data. Check the destination before you leave."
            }
            Self::CleanupEmpty => {
                "Larsal could not remove a file it made. The file is empty. Check the destination before you leave."
            }
            Self::Uncertain => {
                "A file was written, but Larsal could not confirm it was saved safely. Keep the source and check the destination."
            }
            Self::Cancelled => "The file operation was cancelled.",
        })
    }
}

impl std::error::Error for Error {}

/// Why a decrypt stopped, before normalizing into [`Error`]. Only the crate's
/// own vector checks read the cause (FIL-03.17); nothing outside the crate can
/// see it, so a user never learns which family failed (FIL-03.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The binary header breaks the grammar, a limit or a known stanza's shape, or
    /// the nonce after it is missing or short.
    Header,
    /// No credential opens a stanza.
    NoMatch,
    /// The header MAC does not hold.
    Mac,
    /// A chunk is short, out of place or does not authenticate, or a nonce read
    /// again is not the one first read.
    Payload,
    /// The armor is not strict.
    Armor,
    /// Not about the file's contents: an I/O fault or a cancel, as it is.
    Other(Error),
}

impl From<Failure> for Error {
    fn from(f: Failure) -> Self {
        match f {
            Failure::Header
            | Failure::NoMatch
            | Failure::Mac
            | Failure::Payload
            | Failure::Armor => Self::Decrypt,
            Failure::Other(e) => e,
        }
    }
}

/// The fixed message of an OS error: never its text (FIL-03.14).
pub(crate) fn io_error(e: &io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => Error::Space,
        _ => Error::Io,
    }
}
