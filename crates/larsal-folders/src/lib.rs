//! A folder of files, each file and each name encrypted on its own (E23-S3; spec FIL-04,
//! FIL-06), in the public classic format 8 with `SIV_GCM`: the profile
//! `classic8-gcm-local-1` of LD-372. Every other profile is refused by name
//! ([`Error::Profile`]) and never counted as a success. This crate arranges the format
//! and the flow; every primitive and random byte comes through `larsal-crypto`, every
//! descriptor call through `larsal-platform`.
//!
//! A read is a chain of states, each made only from the one before it (FIL-06.4,
//! FIL-06.5), so no plaintext can be reached before a whole file is proven:
//!
//! ```text
//! Vault::capture  ciphertext into private scratch, then sealed
//!   -> Snapshot    one read handle, no name, no writer
//!   -> Validated   every chunk proven; the plaintext only ever reached a wiped buffer
//!   -> write_to    the same handle again, every tag checked again
//! ```
//!
//! Skipping a state does not compile:
//! ```compile_fail
//! fn straight_to_plaintext(s: larsal_folders::Snapshot<'_>, out: &mut Vec<u8>) {
//!     let _ = s.write_to(out, &mut |_, _| true);
//! }
//! ```
//! ```compile_fail
//! fn around_capture(vault: &larsal_folders::Vault) {
//!     let _ = larsal_folders::Validated { vault };
//! }
//! ```
//! Control: with every state in order it compiles.
//! ```
//! fn in_order(
//!     s: larsal_folders::Snapshot<'_>,
//!     out: &mut Vec<u8>,
//! ) -> Result<u64, larsal_folders::Error> {
//!     s.validate(&mut |_, _| true)?.write_to(out, &mut |_, _| true)
//! }
//! ```
//!
//! Guarantees: at most 4 worker threads and 8 chunk buffers for a pass, whatever the file
//! size; no plaintext file is ever written (reads go to the caller's sink); every failure
//! that depends on a file's bytes or a credential is the one [`Error::Open`]; master keys,
//! content keys, clear names and plaintext live only in wiping types, and a lock takes the
//! keys away before it returns. Limits, by the format's nature: an authentic old file, a
//! swap of two authentic files and a cut at a chunk boundary all pass (FIL-04.7,
//! FIL-04.8), and sizes, counts, times and tree shape stay visible to storage (FIL-04.15).
#![forbid(unsafe_code)]
// Rust rule 4: folders are hostile input. Test code is exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

mod budget;
mod content;
mod error;
mod format;
#[cfg(feature = "fuzz-door")]
pub mod fuzz_door;
mod keys;
pub mod limits;
mod names;
mod read;
mod recovery;
mod seam;
mod stores;
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests;
mod vault;
mod write;

pub use budget::BudgetReport;
pub use error::{Error, Refused};
pub use read::{Snapshot, Validated};
pub use recovery::{Kept, OpKind, OpState, RecoveryItem};
pub use stores::Stores;
pub use vault::{Digest, Entry, Kind, Listing, Node, Vault};
pub use write::{Outcome, Saved};

/// Which long step a progress call is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Deriving the key from the password. One call before and one after.
    Kdf,
    /// Copying ciphertext into scratch.
    Capture,
    /// Checking every chunk, with the plaintext thrown away.
    Validate,
    /// Handing the plaintext to its sink.
    Write,
    /// Encrypting and storing new content.
    Encrypt,
}

/// Called after each chunk with the step and the bytes done so far, never with any
/// content. Returning false cancels the operation at that safe point: owned buffers are
/// wiped and owned staging is removed. A cleanup that fails is said, never a cancel.
pub type Control<'a> = &'a mut dyn FnMut(Phase, u64) -> bool;
