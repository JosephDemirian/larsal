//! The only door to crypto crates: secret types, random numbers, ciphers, hashes, key derivation, base64,
//! signatures, HPKE, key wrap, the browser bridge channel, and the file and folder format primitives.
#![forbid(unsafe_code)]
// Rust rule 4: no panics on input. Here, not in Cargo.toml: [lints] workspace = true
// cannot be mixed with a crate lint table. Test code is exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Rust rule 13: every public item says in plain words what it guarantees.
#![deny(missing_docs)]

pub mod aead;
pub mod base64;
pub mod bech32;
pub mod bridge;
pub mod cipher;
pub mod error;
pub mod gcm;
pub mod hash;
pub mod hpke;
pub mod kdf;
pub mod keywrap;
pub mod mac;
pub mod random;
pub mod secret;
pub mod selftest;
pub mod sign;
pub mod siv;
pub mod ssh;
pub mod stream;
pub mod text;
pub mod wrap;

pub use error::Error;
