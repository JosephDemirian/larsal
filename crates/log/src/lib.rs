//! Larsal's own `log` facade (E0-S7 R6, LD-221 (2)). The packages that call
//! `log` keep compiling against it: ureq and ureq-proto in larsal-platform's
//! `net` client, goblin in the bindings generator. Nothing they log goes
//! anywhere. Larsal never installed a logger, so with the published crate
//! every call was already off; here there is no way to turn one on
//! (dependencies never log, AGENTS.md rule 4).
//!
//! Only the API those packages call: [`trace!`], [`debug!`], [`warn!`],
//! [`log_enabled!`] and the two [`Level`]s they ask about. Guarantees: the
//! format arguments are type-checked and never evaluated, as in the
//! published crate when no logger is set; `log_enabled!` is always false.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// A log level, as the callers name it in [`log_enabled!`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// Debug output.
    Debug,
    /// Trace output.
    Trace,
}

/// Whether messages of a level are logged: never. The level is evaluated.
#[macro_export]
macro_rules! log_enabled {
    ($lvl:expr) => {{
        let _: $crate::Level = $lvl;
        false
    }};
}

/// A trace message: checked by the compiler, never evaluated or written.
#[macro_export]
macro_rules! trace {
    ($($arg:tt)+) => {
        if false {
            let _ = ::core::format_args!($($arg)+);
        }
    };
}

/// A debug message: checked by the compiler, never evaluated or written.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {
        if false {
            let _ = ::core::format_args!($($arg)+);
        }
    };
}

/// A warning: checked by the compiler, never evaluated or written.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {
        if false {
            let _ = ::core::format_args!($($arg)+);
        }
    };
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    #[test]
    fn nothing_is_enabled_and_no_argument_is_evaluated() {
        assert!(!log_enabled!(crate::Level::Trace));
        assert!(!log_enabled!(crate::Level::Debug));
        let calls = Cell::new(0);
        let touch = || {
            calls.set(calls.get() + 1);
            "demo"
        };
        trace!("{}", touch());
        debug!("{} {:?}", touch(), touch());
        warn!("{}", touch());
        assert_eq!(calls.get(), 0);
    }
}
