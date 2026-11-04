//! Memory hygiene (SR-07, APP-11.9, LD-133; story E6-S6).
//!
//! Guarantees:
//! - [`Zeroing`] wraps an allocator and zeroes every block before handing
//!   it back (C11 `memset_s`, which the compiler may not drop). The `larsal`
//!   tool and `larsal-ffi` install it as the global allocator, so every block
//!   Rust frees is zero when the system gets it back: buffers of crates Larsal
//!   does not control (gzip windows, the strength estimator's copies, JSON
//!   number lists, the UniFFI buffers that cross to Swift) included.
//!   `realloc` allocates, copies and frees, so the old block of a moved
//!   buffer is zeroed too.
//! - [`lock`] keeps the pages under a buffer in RAM (`mlock`) until the
//!   [`Locked`] it returns is dropped. Locks nest per page (the macOS kernel
//!   counts them, `mlock(2)`), so two buffers on one page each keep it
//!   locked. When the kernel refuses (RLIMIT_MEMLOCK or the system wired
//!   limit; this crate never raises a limit) it writes M11-01 once per
//!   process and returns `None`, and the caller goes on unlocked (APP-11.9).
//!
//! Limits: only Rust's own allocations: Swift, Objective-C and system
//! libraries call `malloc` directly. Stack copies and registers are not heap
//! (`larsal_crypto::secret` scrubs the stack). macOS has no per-range core dump
//! exclusion; release builds turn core dumps off (APP-11.2).

use crate::hardening::M11_01;
use crate::macos::memory as os;
use std::sync::Once;

#[cfg(any(test, feature = "test-memory"))]
pub use os::{Probe, Seen, marker_survives_free, set_needle, wired_bytes, zero_stack_words_after};
pub use os::{Zeroing, page_size};

/// Pages kept in RAM by [`lock`]; dropping it undoes that lock.
pub struct Locked {
    start: usize,
    len: usize,
}

impl Drop for Locked {
    fn drop(&mut self) {
        // Fails only when the range is no longer mapped, and then nothing
        // is locked any more.
        let _ = os::munlock(self.start, self.len);
    }
}

/// Locks the whole pages under `bytes` (APP-11.9: key material). Returns
/// `None` for an empty slice, or after writing M11-01 (once per process)
/// when the kernel refuses; nothing is locked then.
#[must_use = "dropping it unlocks the pages at once"]
pub fn lock(bytes: &[u8]) -> Option<Locked> {
    static WARN: Once = Once::new();
    if bytes.is_empty() {
        return None;
    }
    let page = os::page_size();
    let addr = bytes.as_ptr() as usize;
    let start = addr & !(page - 1);
    let len = (addr + bytes.len()).next_multiple_of(page) - start;
    match os::mlock(start, len) {
        Ok(()) => Some(Locked { start, len }),
        Err(_) => {
            WARN.call_once(|| eprintln!("{M11_01}"));
            None
        }
    }
}
