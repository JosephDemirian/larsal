//! Every operation on a vault (E4): entries and groups with their times
//! (MOD-01, MOD-02; `edit`), history (MOD-03; `history`), the recycle bin
//! (MOD-04; `recycle`), attachments (MOD-05), icons (MOD-06), tags (MOD-07),
//! references and placeholders (MOD-08; `refs`, `url`), expiry (MOD-09;
//! `expiry`, `time`), cloning (MOD-10; `clone`), search (FEA-01; `search`),
//! the generator (FEA-02, FEA-03; `generator`), one-time passwords
//! (FEA-04; `totp`), the strength estimate and Health Check (FEA-05;
//! `health`), the breach check (FEA-06; `breach`) and statistics (FEA-07;
//! `stats`), import (FEA-08; `import`) and export (FEA-09; `export`).
//!
//! Guarantees: every operation works on an `larsal_model::Vault` in memory and
//! leaves it holding `larsal_model::invariants::check`; a refused operation
//! changes nothing; each operation takes `now` once, so all changes of one
//! change batch get one time (MOD-01.26).
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
#![deny(missing_docs)]

pub mod attachments;
pub mod auto_open;
pub mod breach;
pub mod clone;
pub mod edit;
pub mod error;
pub mod expiry;
pub mod export;
pub mod generator;
pub mod guard;
pub mod health;
pub mod history;
pub mod icons;
pub mod import;
pub mod merge;
pub mod pattern;
pub mod recycle;
pub mod refs;
pub mod retired;
pub mod search;
pub mod settings;
pub mod stats;
pub mod storage;
pub mod tags;
mod text;
pub mod time;
pub mod totp;
mod tree;
pub mod url;

pub use error::{Error, NameProblem};
