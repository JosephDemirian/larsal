//! Larsal and the SSH agent (E9-S1, E9-S2; spec INT-06).
//!
//! E9-S1, Larsal as a client of the system agent: [`SshKey`] reads an OpenSSH
//! private key and decrypts it in memory; [`Agent`] adds it to the agent
//! with limits, removes one key or all keys, and lists what the agent
//! holds. One connection per request, one request at a time.
//!
//! E9-S2: [`Settings`] reads and writes an entry's SSH settings attachment;
//! [`EntryKey`] finds an entry's key in an attachment or a file and unlocks
//! it with the entry's password resolved as Copy resolves it;
//! [`unlock_plan`] says which keys go where when a vault unlocks; a
//! [`Keyring`] keeps Larsal's records and the keys of Larsal's own agent and
//! empties both at lock; [`OwnAgent`] is Larsal's own agent for keys that ask
//! before each use, asking through an [`Asker`] before every signature.
//!
//! Every failure is an [`Error`] that maps to one of the card's messages
//! ([`messages`]); none holds a secret.
#![forbid(unsafe_code)]
// Rust rule 4: agent replies and key files are hostile input. Test code is
// exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

mod agent;
mod entry;
mod key;
mod keyring;
pub mod messages;
mod server;
mod settings;

pub use agent::{
    Agent, Identity, Limits, MAX_LIFETIME, MAX_REPLY, MAX_SOCKET_PATH, SK_PROVIDER_DEFAULT, TIMEOUT,
};
pub use entry::{EntryKey, Step, has_ssh_key, key_path, unlock_plan};
pub use key::{MAX_KEY_SIZE, MAX_ROUNDS, SshKey};
pub use keyring::{Keyring, Leaving, Place, Refused, Session};
pub use larsal_crypto::ssh::AgentKey;
pub use server::{
    Asker, IDLE, MAX_CLIENTS, Options, OwnAgent, QUESTION_TIME, Question, known_host_name,
    setup_line,
};
pub use settings::{MAX_SETTINGS, SETTINGS_NAME, Settings, Source};

use std::path::PathBuf;

/// Why the agent could not be reached (MI06-02). For the debug log and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Nothing listens on the socket.
    Connect,
    /// The connect and the whole reply took longer than [`TIMEOUT`].
    Timeout,
    /// The agent closed the connection before the whole reply arrived.
    Closed,
    /// The reply is longer than [`MAX_REPLY`].
    TooLong,
    /// The reply is empty, has the wrong message number, or does not parse.
    Protocol,
}

/// Every way this crate fails (Rust rule 8). Each value names one message of
/// spec INT-06 ([`Error::id`]). Guarantees: no value holds a key byte, a
/// passphrase or any other secret; paths, cipher and type names and round
/// counts are not secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// MI06-01: no socket override and no `SSH_AUTH_SOCK`.
    NoAgent,
    /// MI06-02: connect, timeout, closed connection, oversize or bad reply.
    Unreachable {
        /// The socket path.
        path: PathBuf,
        /// What went wrong.
        why: Failure,
    },
    /// MI06-03: the path is missing (LD-183 (1)), too long, not a socket, or
    /// not the user's, or the process at the other end runs as another user.
    /// Nothing was sent.
    NotOurSocket {
        /// The socket path.
        path: PathBuf,
    },
    /// MI06-04: the agent answered failure to an add.
    AddRefused {
        /// A lifetime limit was sent (adds the hint about time limits).
        lifetime: bool,
        /// The key lives on a security key (adds the provider hint).
        security_key: bool,
    },
    /// MI06-08: the key is over [`MAX_KEY_SIZE`]; nothing was parsed.
    TooLarge,
    /// MI06-09: the key has no bytes.
    Empty,
    /// MI06-10: not an SSH private key Larsal reads.
    NotAKey,
    /// MI06-11: an older PEM, PKCS#8 or PuTTY key; the user converts it.
    OldFormat,
    /// MI06-12: a DSA key.
    Dsa,
    /// MI06-13: a cipher or key type Larsal does not read, with its name.
    Unsupported(String),
    /// MI06-14: a protected key and an empty passphrase; nothing was tried.
    NoPassphrase,
    /// MI06-15: the passphrase does not unlock the key.
    WrongPassphrase,
    /// MI06-16: the key's bcrypt-pbkdf rounds are outside 1 to
    /// [`MAX_ROUNDS`]; refused before any key derivation.
    TooManyRounds(u32),
    /// MI06-17: a lifetime of 0 (or above [`MAX_LIFETIME`]); nothing sent.
    Lifetime,
    /// MI06-21: the agent answered failure to remove all.
    RemoveAllRefused,
    /// MI06-05: Larsal's records hold this key for another open vault, named.
    OtherVault(String),
    /// MI06-06: the entry has no attachment with the stored name.
    NoAttachment,
    /// MI06-07: the key file cannot be opened (missing, a folder, no
    /// permission, not a regular file).
    CannotOpen {
        /// The path Larsal tried, after INT-06.5's expansion.
        path: PathBuf,
    },
    /// MI06-24: the settings attachment cannot be read (INT-06.2).
    SettingsUnreadable,
    /// MI06-33: Larsal's own agent cannot sign with this key type, so "Ask
    /// before each use" is not possible for it (INT-06.33).
    CannotAsk,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAgent => f.write_str("no SSH agent socket is set"),
            Self::Unreachable { path, why } => write!(
                f,
                "the SSH agent at {} could not be reached ({why:?})",
                path.display()
            ),
            Self::NotOurSocket { path } => write!(
                f,
                "{} is not an SSH agent socket of this user",
                path.display()
            ),
            Self::AddRefused { .. } => f.write_str("the SSH agent refused the key"),
            Self::TooLarge => f.write_str("the key is over 1 MiB"),
            Self::Empty => f.write_str("the key is empty"),
            Self::NotAKey => f.write_str("not an SSH private key Larsal reads"),
            Self::OldFormat => f.write_str("an older key format"),
            Self::Dsa => f.write_str("a DSA key"),
            Self::Unsupported(v) => write!(f, "uses {v}, which Larsal does not read"),
            Self::NoPassphrase => f.write_str("the key needs a passphrase"),
            Self::WrongPassphrase => f.write_str("the passphrase does not unlock the key"),
            Self::TooManyRounds(v) => write!(f, "the key uses {v} rounds"),
            Self::Lifetime => f.write_str("the time limit is out of range"),
            Self::RemoveAllRefused => f.write_str("the SSH agent did not remove its keys"),
            Self::OtherVault(_) => f.write_str("the key is loaded from another open vault"),
            Self::NoAttachment => f.write_str("the entry has no attachment with that name"),
            Self::CannotOpen { path } => {
                write!(f, "the key file {} cannot be opened", path.display())
            }
            Self::SettingsUnreadable => f.write_str("the SSH settings cannot be read"),
            Self::CannotAsk => f.write_str("Larsal cannot ask before each use of this key type"),
        }
    }
}

impl std::error::Error for Error {}
