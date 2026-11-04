//! The operating system: clipboard, lock signals, Touch ID, hardening,
//! memory hygiene, network, the device's sign-in key.
// deny, not forbid: the macos/ module allows unsafe (Rust rule 2).
#![deny(unsafe_code)]
#![deny(missing_docs)]

#[cfg(all(target_os = "macos", feature = "appkit"))]
pub mod clipboard;
#[cfg(all(target_os = "macos", feature = "device-key"))]
pub mod device_key;
#[cfg(target_os = "macos")]
pub mod hardening;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(all(target_os = "macos", feature = "memory"))]
pub mod memory;
#[cfg(all(target_os = "macos", feature = "net"))]
pub mod net;
