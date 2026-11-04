//! Bridges to macOS. The only place in this crate where `unsafe` is allowed
//! (Rust rule 2). Every block carries a `// SAFETY:` note; the
//! `undocumented_unsafe_blocks` lint enforces it. Every function here is safe
//! to call.
#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(feature = "code-sign")]
mod codesign;
mod folder;
mod instance;
pub mod keyboard;
#[cfg(feature = "memory")]
pub(crate) mod memory;
#[cfg(feature = "appkit")]
pub(crate) mod pasteboard;
mod pipe;
mod process;
mod signals;
mod system;
mod terminal;
#[cfg(feature = "net")]
pub(crate) mod trust;

#[cfg(feature = "code-sign")]
pub use codesign::peer_meets;
pub use folder::{
    create_in, dataless, is_file_in, keep_file_info, open_regular, remove_in, rename_in,
};
pub use instance::{effective_uid, peer_uid, user_temp_dir};
pub use pipe::ignore_broken_pipes;
pub use process::{core_dumps_off, deny_debugger};
#[cfg(any(test, feature = "test-signals"))]
pub use signals::reset_quit_signals_for_tests;
pub use signals::{QuitGuard, catch_quit};
pub use system::{host_name, kernel, thread_cpu_time, utc_offset};
#[cfg(feature = "appkit")]
pub use system::{os_version, physical_memory};
pub use terminal::{EchoOff, echo_off};
