//! App's sync client (E16-S7a; spec SYN-03, SYN-04; spec/research/
//! sync-server.md P3, P4). [`client`] talks to App's own server through
//! app-platform `net.rs` with the pinned certificate (SYN-01.2) and signs
//! in with the device key of `device_key.rs` (SYN-04); [`sync`] runs the
//! loop of P3 (download, merge, safe save, upload with `If-Match`, at most
//! 3 tries), its timing (SYN-03.4) and the rollback guard of P4
//! (SYN-03.7); [`state`] is this Mac's local state, never synced
//! (SYN-03.3). The open vault, its merge and its save stay with the caller
//! (app-ffi), behind [`sync::Local`].
//!
//! Guarantees: nothing runs by itself (no thread, no timer); the session
//! token lives only in memory, in a `SecretString`; no reply text from the
//! server is ever shown or kept (SYN-01.9); every reply is bounded before
//! it is read (SYN-01.10); this crate writes no log line (SYN-01.13, Rust
//! rule 9); only encrypted vault bytes, ids, versions and the device's
//! signature leave the Mac (SYN-03.14). Key-file parts and key changes
//! come with E16-S7b, upload signatures with E17-S1.
#![forbid(unsafe_code)]
// Rust rule 4: replies come from the network. Test code is exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

pub mod client;
pub mod state;
pub mod sync;

#[cfg(feature = "test-server")]
pub mod test_server;
