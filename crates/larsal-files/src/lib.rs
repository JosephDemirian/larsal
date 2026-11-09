//! File encryption (E22-S3; spec FIL-01, FIL-03): one file in the public age v1
//! format, in the passphrase mode or the public key mode. The profile is
//! binary writes, binary and strict armor reads, one scrypt recipient or 1 to
//! 1,024 native X25519 recipients. This crate arranges the format and the
//! flow; every primitive and random byte comes through `larsal-crypto`, every
//! descriptor call through `larsal-platform`.
//!
//! A decrypt is a chain of states, each made only from the one before it
//! (FIL-03.4), so no plaintext can be reached before the whole file is proven:
//!
//! ```text
//! ScratchRoot::capture_*  ciphertext into private scratch, then sealed
//!   -> Snapshot           one read handle, no name, no writer
//!   -> Unwrapped          header bound and parsed, key unwrapped, MAC checked
//!   -> Validation         every chunk, the final marker and EOF checked; a
//!        Ready(Validated)   plaintext only ever reached a wiped buffer
//!        Weak(WeakFile)   the same, and the file needs the user's consent
//!   -> Validated::save_new  a new file only now, then the same bytes again
//! ```
//!
//! Skipping a state does not compile:
//! ```compile_fail
//! fn straight_to_plaintext(s: larsal_files::Snapshot, out: &mut Vec<u8>) {
//!     let _ = s.write_to(out, &mut |_, _| true);
//! }
//! ```
//! ```compile_fail
//! fn unvalidated(u: larsal_files::Unwrapped, out: &mut Vec<u8>) {
//!     let _ = u.write_to(out, &mut |_, _| true);
//! }
//! ```
//! ```compile_fail
//! fn no_consent(w: larsal_files::WeakFile, out: &mut Vec<u8>) {
//!     let _ = w.write_to(out, &mut |_, _| true);
//! }
//! ```
//! ```compile_fail
//! fn around_consent(data: &[u8], unlock: &larsal_files::Unlock) {
//!     let _ = larsal_files::open_bounded(data, unlock, 1024);
//! }
//! ```
//! ```compile_fail
//! fn around_capture(data: &[u8]) {
//!     let _ = larsal_files::Snapshot::in_memory(data);
//! }
//! ```
//! Control: with every state in order it compiles.
//! ```
//! fn in_order(
//!     s: larsal_files::Snapshot,
//!     unlock: &larsal_files::Unlock,
//!     out: &mut Vec<u8>,
//! ) -> Result<u64, larsal_files::Error> {
//!     let keep_going = &mut |_: larsal_files::Phase, _: u64| true;
//!     match s.unlock(unlock)?.validate(keep_going)? {
//!         larsal_files::Validation::Ready(v) => v.write_to(out, keep_going),
//!         larsal_files::Validation::Weak(w) => w.accept().write_to(out, keep_going),
//!     }
//! }
//! ```
//!
//! Guarantees: working memory does not grow with the file (two chunk buffers
//! and at most the 2 MiB header, plus scrypt's memory at its ceiling); no
//! plaintext is ever written to scratch; every decrypt failure that depends on
//! the file gives the one [`Error::Decrypt`]; passphrases, identities, file
//! keys, payload keys and plaintext live only in wiping types. No process, no
//! network, no ambient key search.
#![forbid(unsafe_code)]
// Rust rule 4: files are hostile input. Test code is exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

mod armor;
mod decrypt;
mod encrypt;
mod error;
mod fsio;
mod header;
mod keys;
mod label;
pub mod limits;
mod payload;
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests;

pub use decrypt::{Snapshot, Unlock, Unwrapped, Validated, Validation, WeakFile};
pub use encrypt::{Lock, encrypt_file, encrypt_stream};
pub use error::Error;
#[cfg(feature = "test-volume")]
pub use fsio::test_volume;
pub use fsio::{OutputFolder, ScratchRoot, SourceFile};
pub use keys::{Identities, Recipient, generate_identity};
pub use label::clean_label;

/// Which long step a progress call is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Copying ciphertext into scratch.
    Capture,
    /// Checking every chunk, with the plaintext thrown away.
    Validate,
    /// Writing the plaintext to its output.
    Write,
    /// Writing the ciphertext to its output.
    Encrypt,
}

/// Called after each chunk with the step and the bytes done so far, never with
/// any content. Returning false cancels the operation at that safe point
/// (FIL-03.11): owned buffers are wiped, owned scratch is removed, an owned output
/// is emptied and its removal tried. A cleanup that fails is said, never a cancel.
pub type Control<'a> = &'a mut dyn FnMut(Phase, u64) -> bool;
