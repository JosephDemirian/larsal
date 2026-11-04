//! Echo off while a password is typed at a terminal (APP-09.16, INT-10.12).
//! A quit signal (SIGINT, SIGTERM, SIGQUIT, SIGHUP) during that time still
//! ends the process, but only after the terminal settings are back, as
//! `readpassphrase(3)` does: the signal is noted (by `signals.rs`), the read
//! stops, the settings and the earlier signal actions are put back, then the
//! signal is raised again. A signal ignored at start stays ignored (LD-178).

use super::signals::{self, QuitGuard};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};

/// Echo stays off on the terminal until this value is dropped; dropping it
/// puts the saved terminal settings and signal actions back, then raises a
/// quit signal that arrived meanwhile. Only one may live at a time: the
/// noted signal is one process-wide value.
pub struct EchoOff<'fd> {
    fd: BorrowedFd<'fd>,
    saved: libc::termios,
    /// Dropped after the terminal is restored: puts the signal actions back
    /// and raises a noted quit signal.
    quit: QuitGuard,
}

/// Turns echo off on the terminal `fd` and keeps every other setting. Typed
/// input not yet read is discarded, as for a password prompt. Until the
/// returned value is dropped, a quit signal is only noted; read only after
/// [`EchoOff::wait_for_input`]. Fails when `fd` is not a terminal. Only one
/// [`EchoOff`] may live at a time.
pub fn echo_off(fd: BorrowedFd<'_>) -> io::Result<EchoOff<'_>> {
    let mut saved = MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `fd` stays open while borrowed and `saved` is valid for writes
    // of a termios. assume_init runs only after tcgetattr returned 0, which
    // means it filled every field.
    let saved = unsafe {
        if libc::tcgetattr(fd.as_raw_fd(), saved.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        saved.assume_init()
    };
    // A quit signal noted before a failed install still ends the process.
    let quit = signals::catch_quit()?;
    let mut quiet = saved;
    quiet.c_lflag &= !libc::ECHO;
    // SAFETY: `fd` stays open while borrowed and `quiet` is a complete termios.
    if unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSAFLUSH, &quiet) } != 0 {
        let error = io::Error::last_os_error();
        // A quit signal noted meanwhile still ends the process.
        drop(quit);
        return Err(error);
    }
    Ok(EchoOff { fd, saved, quit })
}

impl EchoOff<'_> {
    /// Waits until the terminal has input to read. Fails once a quit signal
    /// has arrived: then stop reading and drop this value, which restores the
    /// terminal and ends App with that signal. It looks every 100 ms, so it
    /// does not matter which thread the signal reached.
    pub fn wait_for_input(&self) -> io::Result<()> {
        loop {
            if self.quit.caught().is_some() {
                return Err(io::Error::other("a quit signal arrived"));
            }
            let mut wanted = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `wanted` is one valid pollfd for the whole call, and its
            // descriptor stays open while borrowed.
            match unsafe { libc::poll(&mut wanted, 1, 100) } {
                0 => {}
                ready if ready > 0 => return Ok(()),
                _ => {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
    }
}

impl Drop for EchoOff<'_> {
    fn drop(&mut self) {
        // SAFETY: the borrow of `fd` outlives `self`, so it is still open, and
        // `saved` is the complete termios read by echo_off.
        unsafe { libc::tcsetattr(self.fd.as_raw_fd(), libc::TCSANOW, &self.saved) };
        // Then `quit` drops: the signal actions go back and a noted quit
        // signal is raised.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// A new pseudo-terminal: (controller, terminal).
    fn pty() -> (OwnedFd, OwnedFd) {
        let (mut controller, mut terminal) = (-1, -1);
        let null = std::ptr::null_mut();
        // SAFETY: both out-pointers are valid for writes of a c_int; null
        // name, settings and size are allowed and ask for the defaults.
        let rc = unsafe {
            libc::openpty(
                &mut controller,
                &mut terminal,
                null,
                null.cast(),
                null.cast(),
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        // SAFETY: openpty returned 0, so both are new open descriptors that
        // nothing else owns.
        unsafe {
            (
                OwnedFd::from_raw_fd(controller),
                OwnedFd::from_raw_fd(terminal),
            )
        }
    }

    fn echo_is_on(fd: BorrowedFd<'_>) -> bool {
        let mut now = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: as in echo_off: `fd` is open and `now` is valid for writes;
        // assume_init runs only after tcgetattr returned 0.
        let now = unsafe {
            assert_eq!(libc::tcgetattr(fd.as_raw_fd(), now.as_mut_ptr()), 0);
            now.assume_init()
        };
        now.c_lflag & libc::ECHO != 0
    }

    /// Run by `app09_16_quit_signal_at_the_prompt_restores_the_terminal` in
    /// a child process, with a pseudo-terminal as standard input: reads as
    /// App's prompt does until a quit signal arrives.
    #[test]
    #[ignore = "a child of app09_16_quit_signal_at_the_prompt_restores_the_terminal"]
    fn prompt_child() {
        let input = std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
        // A shell starts background jobs with SIGINT and SIGQUIT ignored, and
        // the child inherits that; this case needs the default actions.
        signals::reset_quit_signals_for_tests();
        let echo = echo_off(input.as_fd()).unwrap();
        let mut byte = [0];
        while echo.wait_for_input().is_ok() {
            let _ = (&input).read(&mut byte);
        }
        drop(echo); // ends the process with the signal
        std::process::exit(3);
    }

    #[test]
    fn app09_16_quit_signal_at_the_prompt_restores_the_terminal() {
        let me = std::env::current_exe().unwrap();
        for signal in signals::QUIT {
            let (_controller, terminal) = pty();
            assert!(echo_is_on(terminal.as_fd()));
            let mut child = Command::new(&me)
                .args([
                    "--exact",
                    "macos::terminal::tests::prompt_child",
                    "--ignored",
                    "--nocapture",
                ])
                .stdin(Stdio::from(terminal.try_clone().unwrap()))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while echo_is_on(terminal.as_fd()) {
                assert!(Instant::now() < deadline, "the child never turned echo off");
                std::thread::sleep(Duration::from_millis(20));
            }
            let status = Command::new("/bin/kill")
                .args([format!("-{signal}"), child.id().to_string()])
                .status()
                .unwrap();
            assert!(status.success());
            let ended = child.wait().unwrap();
            assert_eq!(ended.signal(), Some(signal), "{ended:?}");
            assert!(
                echo_is_on(terminal.as_fd()),
                "echo still off after signal {signal}"
            );
        }
    }
}
