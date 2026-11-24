//! The XML document inside a vault file, to and from `larsal-model`
//! (FMT-10 to FMT-15). Reading is E3-S6; writing is E3-S7.

pub mod encode;
pub mod read;
pub mod write;

pub use read::{Document, Limit, Options, Reason, Warning, read, read_plain};
