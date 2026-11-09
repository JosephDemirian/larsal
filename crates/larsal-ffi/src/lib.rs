//! The bindings crate: the only crate that exports to Swift (LD-156). Every
//! export is listed in API.md. Start-up, flags and the single instance follow
//! APP-09: the Mac app's entry calls `start::start` first.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod auto_open;
pub mod autotype;
pub mod autotype_typing;
pub mod bridge_vaults;
pub mod browser;
pub mod cli;
pub mod copies;
pub mod edit;
pub mod export;
pub mod generator;
pub mod hwkey;
pub mod icon_fetch;
pub mod instance;
pub mod larsal_settings;
mod local_state;
pub mod messages;
mod open_copies;
pub mod qr;
pub mod reports;
pub mod saving;
pub mod security_keys;
pub mod session;
pub mod share;
pub mod share_edit;
#[cfg(test)]
mod share_holes;
pub mod ssh;
pub mod start;
#[cfg(feature = "sync")]
pub mod sync;
#[cfg(test)]
mod test_dir;
pub mod vault_settings;
pub mod views;
pub mod window;
pub mod wizard;

uniffi::setup_scaffolding!();

/// SR-07 (LD-133, LD-156 (10)): every block Rust frees in the Mac app is
/// zeroed before the system gets it back: the copies of crates Larsal does not
/// control and the UniFFI buffers that carry records to Swift. In the static
/// library this covers Rust's allocations only; Swift's own go through
/// `malloc`.
#[global_allocator]
static ALLOC: larsal_platform::memory::Zeroing<std::alloc::System> =
    larsal_platform::memory::Zeroing(std::alloc::System);

/// Takes nothing; returns the version of the Rust core, for example `0.1.0`.
/// No vault data.
#[uniffi::export]
#[must_use]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Takes nothing; returns true when this Rust core is a debug build (debug
/// lock and socket names, the test variable of APP-09.29). A Release app
/// refuses to start with one.
#[uniffi::export]
#[must_use]
pub fn core_is_debug() -> bool {
    cfg!(debug_assertions)
}

/// Takes nothing; returns true only in a debug build started by a test or a
/// Mac QA snapshot (`LARSAL_TEST_HIDDEN`): the app then shows no window and
/// never becomes active. Always false in a release build.
#[uniffi::export]
#[must_use]
pub fn launch_hidden() -> bool {
    instance::hidden()
}

/// The settings file paths of F02 and F03 (APP-09.5, read by
/// `larsal_settings`); `None` keeps the normal location. Larsal reads no environment variable for them.
pub struct SettingsFiles {
    /// F02.
    pub config: Option<std::path::PathBuf>,
    /// F03.
    pub local_config: Option<std::path::PathBuf>,
}
