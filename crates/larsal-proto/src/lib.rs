//! Larsal's sync wire format (E16; spec SYN-01), shared by Larsal's sync server
//! and its client.
//!
//! E16-S3 holds the parts the server skeleton needs: [`limits`] (every size
//! and time of SYN-01.10 and SYN-01.11), [`routes`] (the paths it serves and
//! the 404 and 405 rule of SYN-01.3) and [`messages`] (the record rules of
//! SYN-01.8, the health record of SYN-01.14 and the error body of SYN-01.9).
//! E16-S4 adds the vault routes, their ETag and precondition rules and the
//! vault records (SYN-01.6). E16-S5 adds the account and sign-in routes and
//! records, the session header (SYN-01.4, SYN-01.5, SYN-04), [`signin`] (the
//! message a device key signs) and [`wrap`] (the wrap record and its 4 KiB
//! limit, LD-305 (5)). Later stories add their routes and records here.
//!
//! Guarantees: every reader takes untrusted bytes and never panics; a record
//! over its size limit is refused before it is parsed. This crate never
//! names larsal-format, larsal-core or larsal-platform: the server links it, and the
//! server never links the vault reader (P16).
#![forbid(unsafe_code)]
// Rust rule 4: records come from the network. Test code is exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

pub mod limits;
pub mod messages;
pub mod routes;
pub mod signin;
pub mod wrap;

use std::fmt;

/// Why a record was refused (SYN-01.8). It never holds text from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// More bytes than the record's limit (SYN-01.10).
    TooLarge,
    /// Not one JSON value (RFC 8259), or an object with a repeated key.
    NotJson,
    /// The value is not one JSON object.
    NotObject,
    /// Arrays and objects nest deeper than [`limits::MAX_RECORD_DEPTH`].
    TooDeep,
    /// A field the record needs is missing.
    Missing(&'static str),
    /// A field has the wrong type, or a number outside its range.
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooLarge => f.write_str("the record is over its size limit"),
            Error::NotJson => f.write_str("the record is not valid JSON"),
            Error::NotObject => f.write_str("the record is not one JSON object"),
            Error::TooDeep => f.write_str("the record nests too deep"),
            Error::Missing(field) => write!(f, "the record has no {field} field"),
            Error::Invalid(field) => write!(f, "the record's {field} field is not valid"),
        }
    }
}

impl std::error::Error for Error {}
