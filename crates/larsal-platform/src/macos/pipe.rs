//! Broken pipes (LD-179). A Rust program ignores SIGPIPE before `main`, but
//! the window app starts in Swift, so a write to a socket whose other end has
//! closed (the instance channel, an SSH agent) would end Larsal. Ignoring the
//! signal turns such a write into an `EPIPE` error the caller handles.

use std::io;

/// Sets SIGPIPE to "ignore" for the whole process.
///
/// # Errors
/// The system refused the change.
pub fn ignore_broken_pipes() -> io::Result<()> {
    // SAFETY: `signal` takes a signal number and a handler value; SIG_IGN is
    // a constant the system defines, so no handler code of ours is set.
    let old = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    if old == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    const ROLE: &str = "LARSAL_TEST_PIPE_ROLE";

    /// A child: SIGPIPE back to its default (as a Swift start leaves it),
    /// then, in role `guarded`, [`ignore_broken_pipes`]; then a write to a
    /// socket whose other end is closed.
    #[test]
    #[ignore = "a child of a_write_to_a_closed_socket_is_an_error_not_a_signal"]
    fn broken_pipe_child() {
        let Ok(role) = std::env::var(ROLE) else {
            return;
        };
        // SAFETY: SIG_DFL is a constant the system defines; no handler code
        // of ours is set.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
        if role == "guarded" {
            ignore_broken_pipes().unwrap();
        }
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        let error = ours.write_all(&[0; 64]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    fn run(role: &str) -> std::process::ExitStatus {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "macos::pipe::tests::broken_pipe_child"])
            .args(["--ignored", "--test-threads=1"])
            .env(ROLE, role)
            .output()
            .unwrap()
            .status
    }

    #[test]
    fn a_write_to_a_closed_socket_is_an_error_not_a_signal() {
        // Control: without the call, the write ends the process by SIGPIPE.
        assert_eq!(run("bare").signal(), Some(libc::SIGPIPE));
        let guarded = run("guarded");
        assert!(guarded.success(), "{guarded:?}");
    }
}
