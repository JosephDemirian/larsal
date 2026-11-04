//! Process hardening, the first action of App's processes (APP-11.1 to
//! APP-11.5; SR-05, AT-C03). Shared by the window app (`app-ffi`, APP-09.1
//! step 1) and the command line tool.
//!
//! Guarantees:
//! - a release build sets the core file limit to 0 (APP-11.2), then denies
//!   debugger attach (APP-11.3); a failure of the first does not skip the
//!   second, and any failure writes M11-01 once on stderr and goes on
//!   (APP-11.4, D-APP11-2);
//! - a build with debug assertions on skips both, so a debugger can attach
//!   (APP-11.5); nothing else can: no flag, environment variable, setting or
//!   file is read here;
//! - environment injection (`DYLD_*`) and foreign libraries are left to the
//!   hardened runtime of the signed bundle (APP-11.6, APP-11.7), as Apple
//!   documents and as the reference does on macOS.

use crate::macos;
use std::io;

/// M11-01.
pub const M11_01: &str = "Process protection could not be fully applied.";

/// Applies APP-11.2 and APP-11.3 in a release build; does nothing in a build
/// with debug assertions. Returns false when a step failed, after writing
/// M11-01 on stderr; the caller goes on starting.
pub fn harden() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    let applied = apply(macos::core_dumps_off, macos::deny_debugger);
    if !applied {
        eprintln!("{M11_01}");
    }
    applied
}

/// Both steps, in order, each one whatever the other did.
fn apply(core: impl FnOnce() -> io::Result<()>, deny: impl FnOnce() -> io::Result<()>) -> bool {
    let core = core().is_ok();
    let deny = deny().is_ok();
    core && deny
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn app11_4_a_failed_core_limit_still_denies_attach() {
        let denied = Cell::new(false);
        let fail = || Err(io::Error::other("refused"));
        let deny = || {
            denied.set(true);
            Ok(())
        };
        assert!(!apply(fail, deny));
        assert!(denied.get(), "deny-attach was skipped");
        // Each failure alone, and none.
        assert!(!apply(|| Ok(()), fail));
        assert!(apply(|| Ok(()), || Ok(())));
    }
}
