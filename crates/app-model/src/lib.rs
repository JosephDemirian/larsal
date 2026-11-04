//! The data types of a vault: groups, entries, fields, history. No file
//! access and no crypto calls; app-crypto is used only for its secret types
//! (spec/decisions.md LD-75).
#![forbid(unsafe_code)]
// Rust rule 13: every public item says in plain words what it guarantees.
#![deny(missing_docs)]

pub mod attachment;
pub mod autotype;
pub mod custom_data;
pub mod entry;
pub mod group;
pub mod icon;
pub mod invariants;
pub mod json;
pub mod settings;
pub mod times;
pub mod unknown;
pub mod uuid;
pub mod vault;

pub use attachment::Attachment;
pub use autotype::{Association, AutoType};
pub use custom_data::{CustomData, CustomDataItem};
pub use entry::{Entry, Field};
pub use group::{Group, Switch};
pub use icon::{CustomIcon, Icon};
pub use settings::{Argon2Kind, Cipher, Compression, Encryption, Kdf, PublicItem};
pub use times::{Time, Times};
pub use unknown::{UnknownElement, UnknownNode};
pub use uuid::Uuid;
pub use vault::{DeletedObject, FileVersion, MemoryProtection, Meta, Vault};
