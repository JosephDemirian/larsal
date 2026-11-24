//! Quit signals caught without a terminal (INT-10.29, SC-07), and under the
//! echo-off guard of `terminal.rs` (INT-10.12): while a [`QuitGuard`] lives,
//! SIGINT, SIGTERM, SIGQUIT and SIGHUP are only noted; the waiter sees the
//! note, does its cleanup, and dropping the guard puts the earlier signal
//! actions back and raises the signal again, so the process still ends by
//! it. A signal that is ignored when the guard starts stays ignored (LD-178:
//! `nohup` and background jobs), as Unix tools have always done.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// The quit signals of INT-10 (exit code table).
pub(crate) const QUIT: [libc::c_int; 4] =
    [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP];

/// The quit signal noted while a guard lives; 0 for none.
static CAUGHT: AtomicI32 = AtomicI32::new(0);

/// True while a [`QuitGuard`] lives (F-063): a second one would save the
/// first one's `note` handler and put it back for good.
static LIVE: AtomicBool = AtomicBool::new(false);

/// The handler while a guard lives. It only stores the signal number: an
/// atomic store is async-signal-safe.
extern "C" fn note(signal: libc::c_int) {
    CAUGHT.store(signal, Ordering::SeqCst);
}

/// Quit signals are noted, not acted on, until this value is dropped;
/// dropping it puts the saved actions back, then raises a noted signal.
/// Only one lives at a time (an `EchoOff` holds one): the noted signal is
/// one process-wide value, so [`catch_quit`] refuses a second.
pub struct QuitGuard {
    /// The action replaced for each signal of [`QUIT`]; `None` where the
    /// signal was ignored and left alone.
    actions: [Option<libc::sigaction>; 4],
}

/// Starts noting quit signals instead of acting on them; signals ignored
/// now stay ignored.
///
/// # Errors
/// A guard already lives (F-063; nothing changed); or the system refused
/// to read or change a signal action, and then every action is as it was
/// and a signal noted meanwhile is raised.
pub fn catch_quit() -> io::Result<QuitGuard> {
    if LIVE.swap(true, Ordering::SeqCst) {
        return Err(io::Error::other("a quit guard already lives"));
    }
    CAUGHT.store(0, Ordering::SeqCst);
    let catch = libc::sigaction {
        sa_sigaction: note as extern "C" fn(libc::c_int) as libc::sighandler_t,
        sa_mask: 0, // block no other signal while `note` runs
        sa_flags: 0,
    };
    let mut actions = [None; 4];
    for (slot, signal) in actions.iter_mut().zip(QUIT) {
        let mut current = catch;
        // SAFETY: a null new action makes sigaction only read the current
        // one into `current`, a complete sigaction value that lives across
        // the call.
        let read = unsafe { libc::sigaction(signal, std::ptr::null(), &mut current) };
        if read == 0 && current.sa_sigaction == libc::SIG_IGN {
            continue; // LD-178: an ignored signal stays ignored
        }
        // SAFETY: `catch` and `current` are complete sigaction values that
        // live across the call, and `note` does only an atomic store, which
        // is async-signal-safe.
        if read != 0 || unsafe { libc::sigaction(signal, &catch, &mut current) } != 0 {
            let error = io::Error::last_os_error();
            put_back(&actions);
            LIVE.store(false, Ordering::SeqCst);
            raise_caught();
            return Err(error);
        }
        *slot = Some(current);
    }
    Ok(QuitGuard { actions })
}

impl QuitGuard {
    /// The quit signal noted so far, if any.
    #[must_use]
    pub fn caught(&self) -> Option<i32> {
        match CAUGHT.load(Ordering::SeqCst) {
            0 => None,
            signal => Some(signal),
        }
    }

    /// Waits `time`, looking every 50 ms; returns early with the signal
    /// when one is noted.
    #[must_use]
    pub fn wait(&self, time: Duration) -> Option<i32> {
        let end = Instant::now() + time;
        loop {
            if let Some(signal) = self.caught() {
                return Some(signal);
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            std::thread::sleep(left.min(Duration::from_millis(50)));
        }
    }
}

impl Drop for QuitGuard {
    fn drop(&mut self) {
        put_back(&self.actions);
        LIVE.store(false, Ordering::SeqCst);
        raise_caught();
    }
}

/// Puts back the actions [`catch_quit`] replaced, in [`QUIT`] order.
fn put_back(actions: &[Option<libc::sigaction>]) {
    for (signal, action) in QUIT.iter().zip(actions) {
        if let Some(action) = action {
            // SAFETY: `action` is a complete sigaction that the system
            // returned for this signal.
            unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) };
        }
    }
}

/// Raises the noted quit signal, if any, and clears the note. Call only
/// after [`put_back`], so the signal gets the process's own action again.
fn raise_caught() {
    let caught = CAUGHT.swap(0, Ordering::SeqCst);
    if caught != 0 {
        // SAFETY: raise only sends `caught`, one of the quit signals, to this
        // thread; its action is again the one the process had before the
        // guard, so the process ends as if the guard had not been there.
        unsafe { libc::raise(caught) };
    }
}

/// Tests only: every quit signal back to its default action. A test runner
/// started in the background has SIGINT and SIGQUIT ignored and passes that
/// on to the processes it starts; the guard leaves ignored signals alone
/// (LD-178), so signal cases reset them once first (LD-180). Not for
/// product code.
#[doc(hidden)]
#[cfg(any(test, feature = "test-signals"))]
pub fn reset_quit_signals_for_tests() {
    let default = libc::sigaction {
        sa_sigaction: libc::SIG_DFL,
        sa_mask: 0,
        sa_flags: 0,
    };
    for signal in QUIT {
        // SAFETY: `default` is a complete sigaction value that lives across
        // the call; SIG_DFL installs no handler of ours, and a null old
        // action asks for nothing back.
        unsafe { libc::sigaction(signal, &default, std::ptr::null_mut()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};

    /// Run by `int10_29_quit_signal_is_noted_then_ends_the_process` in a
    /// child process: waits under a guard, reports the noted signal on
    /// stdout (the "cleanup"), then drops the guard.
    #[test]
    #[ignore = "a child of int10_29_quit_signal_is_noted_then_ends_the_process"]
    fn guard_child() {
        // The ignored case starts this child with SIGINT ignored on purpose.
        if std::env::var_os("KEEP_IGNORED").is_none() {
            reset_quit_signals_for_tests();
        }
        let guard = catch_quit().unwrap();
        println!("ready");
        let _ = std::io::stdout().flush();
        let wait = if std::env::var_os("KEEP_IGNORED").is_some() {
            1
        } else {
            30
        };
        let signal = guard.wait(Duration::from_secs(wait));
        println!("noted {}", signal.unwrap_or(0));
        let _ = std::io::stdout().flush();
        drop(guard); // ends the process with the signal
        std::process::exit(3);
    }

    #[test]
    fn int10_29_quit_signal_is_noted_then_ends_the_process() {
        let me = std::env::current_exe().unwrap();
        for signal in QUIT {
            let mut child = Command::new(&me)
                .args([
                    "--exact",
                    "macos::signals::tests::guard_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut out = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            while !line.contains("ready") {
                line.clear();
                assert!(out.read_line(&mut line).unwrap() > 0, "child ended early");
            }
            let status = Command::new("/bin/kill")
                .args([format!("-{signal}"), child.id().to_string()])
                .status()
                .unwrap();
            assert!(status.success());
            let mut rest = String::new();
            while out.read_line(&mut rest).unwrap() > 0 {}
            let ended = child.wait().unwrap();
            assert!(rest.contains(&format!("noted {signal}")), "{rest}");
            assert_eq!(ended.signal(), Some(signal), "{ended:?}");
        }
    }

    /// LD-178: a child started with SIGINT ignored (as `nohup` or a
    /// background job does) keeps ignoring it under the guard.
    #[test]
    fn ld178_ignored_sigint_stays_ignored() {
        let me = std::env::current_exe().unwrap();
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "trap '' INT; exec \"$0\" \"$@\"",
                me.to_str().unwrap(),
                "--exact",
                "macos::signals::tests::guard_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KEEP_IGNORED", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while !line.contains("ready") {
            line.clear();
            assert!(out.read_line(&mut line).unwrap() > 0, "child ended early");
        }
        let sent = Command::new("/bin/kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        let mut rest = String::new();
        while out.read_line(&mut rest).unwrap() > 0 {}
        let ended = child.wait().unwrap();
        assert!(rest.contains("noted 0"), "{rest}");
        assert_eq!((ended.signal(), ended.code()), (None, Some(3)), "{ended:?}");
    }

    /// The in-process cases share the one guard, so they take turns.
    static ONE_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn wait_without_a_signal_takes_its_time() {
        let _turn = ONE_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let guard = catch_quit().unwrap();
        let start = Instant::now();
        assert_eq!(guard.wait(Duration::from_millis(120)), None);
        assert!(start.elapsed() >= Duration::from_millis(120));
        drop(guard);
    }

    /// F-063: a second guard is refused, so dropping the guards in either
    /// order puts back the actions from before the first.
    #[test]
    fn f_063_second_quit_guard_is_refused() {
        let _turn = ONE_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let action = || {
            let mut now = libc::sigaction {
                sa_sigaction: 0,
                sa_mask: 0,
                sa_flags: 0,
            };
            // SAFETY: a null new action only reads the current one into
            // `now`, a complete sigaction value that lives across the call.
            unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut now) };
            now.sa_sigaction
        };
        let before = action();
        let first = catch_quit().unwrap();
        let second = catch_quit();
        assert!(second.is_err(), "a second guard was made");
        drop(first);
        drop(second);
        assert_eq!(action(), before, "SIGTERM's action was not put back");
        drop(catch_quit().unwrap()); // free again after the drop
    }
}
