//! The per-user temporary folder and the peer of a Unix socket (APP-09.7, APP-09.14).

use std::ffi::OsString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// The per-user temporary folder that macOS reports: `confstr` with
/// `_CS_DARWIN_USER_TEMP_DIR`, the folder `getconf DARWIN_USER_TEMP_DIR`
/// prints. The system makes it for the user with mode 0700. Never read from
/// `TMPDIR` or any other environment variable.
pub fn user_temp_dir() -> io::Result<PathBuf> {
    let mut buf = vec![0u8; 1024]; // PATH_MAX on macOS
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes, and confstr
    // writes at most that many, the closing NUL included.
    let needed = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    // `needed` counts the closing NUL; 0 means the call failed.
    match needed {
        0 => Err(io::Error::last_os_error()),
        1 => Err(io::Error::other(
            "the system reported an empty user temp folder",
        )),
        n if n > buf.len() => Err(io::Error::other("the user temp folder path is too long")),
        n => {
            buf.truncate(n - 1);
            Ok(PathBuf::from(OsString::from_vec(buf)))
        }
    }
}

/// The effective user id of the process at the other end of `stream`, as the
/// kernel recorded it when the connection was made.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: the descriptor stays open while `stream` is borrowed, and `uid`
    // and `gid` are valid for writes.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The effective user id of this process.
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, cannot fail and touches none of our memory.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_folder_is_the_os_one_and_private() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = user_temp_dir().unwrap();
        let out = std::process::Command::new("/usr/bin/getconf")
            .arg("DARWIN_USER_TEMP_DIR")
            .env("TMPDIR", "/nonexistent-tmpdir/")
            .output()
            .unwrap();
        let want = String::from_utf8(out.stdout).unwrap();
        assert_eq!(dir.to_str().unwrap(), want.trim_end());
        let meta = std::fs::metadata(&dir).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        assert_eq!(meta.uid(), effective_uid());
    }

    #[test]
    fn peer_of_a_socket_pair_is_this_user() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), effective_uid());
    }
}
