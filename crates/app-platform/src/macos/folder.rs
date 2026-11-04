//! Steps inside one open folder (F-047, LD-131, F-162): the safe save makes
//! its temp file, checks it and renames it over the vault relative to the
//! folder's open descriptor (`openat(2)`, `fstatat(2)`, `renameat(2)`,
//! `unlinkat(2)`), so no path above the folder is looked up again after
//! the folder is open. A folder moved or replaced meanwhile cannot
//! redirect the write into another folder.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// True when `name` in the open folder `dir` is the open file `file`: a
/// regular file with its device and inode. A symbolic link there is never
/// followed.
pub fn is_file_in(dir: &File, name: &OsStr, file: &File) -> io::Result<bool> {
    let name = c_name(name)?;
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `dir` stays open while borrowed, `name` is a NUL-terminated
    // string that lives across the call, and `st` is valid for writes of a
    // stat. assume_init runs only after fstatat returned 0, which means it
    // filled every field.
    let st = unsafe {
        let flags = libc::AT_SYMLINK_NOFOLLOW;
        if libc::fstatat(dir.as_raw_fd(), name.as_ptr(), st.as_mut_ptr(), flags) != 0 {
            return Err(io::Error::last_os_error());
        }
        st.assume_init()
    };
    let open = file.metadata()?;
    // `as u64` as the standard library's own `MetadataExt::dev` converts it.
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFREG
        && st.st_dev as u64 == open.dev()
        && st.st_ino == open.ino())
}

/// F-162: makes the new file `name` in the open folder `dir`, to write,
/// with mode `mode`: exclusive, and a link at `name` is never followed
/// (`O_CREAT | O_EXCL | O_NOFOLLOW`). The file is made in that folder even
/// when its path names another one by now.
///
/// # Errors
/// The system's error; `AlreadyExists` when `name` is taken.
pub fn create_in(dir: &File, name: &OsStr, mode: u32) -> io::Result<File> {
    let name = c_name(name)?;
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `dir` stays open while borrowed and `name` is a NUL-terminated
    // string that lives across the call; with O_CREAT openat reads one more
    // argument, the mode, passed as the unsigned int it expects.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor that nothing else owns, so
    // the File takes it over and closes it once.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// F-162: removes the file `name` from the open folder `dir`.
///
/// # Errors
/// The system's error.
pub fn remove_in(dir: &File, name: &OsStr) -> io::Result<()> {
    let name = c_name(name)?;
    // SAFETY: `dir` stays open while borrowed and `name` is a NUL-terminated
    // string that lives across the call.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Renames `from` to `to`, both names in the open folder `dir`: the rename
/// happens in that folder even when its path names another one by now.
pub fn rename_in(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let (from, to) = (c_name(from)?, c_name(to)?);
    let fd = dir.as_raw_fd();
    // SAFETY: `dir` stays open while borrowed, and both names are
    // NUL-terminated strings that live across the call.
    if unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// F-101 (LD-225 (1)): opens the file at `path` to read, never waiting: a
/// path that is not a regular file after links (a FIFO, a device, a
/// socket, a folder) is refused before any open, the open does not block
/// (`O_NONBLOCK`, `O_NOCTTY`), and the open file is checked again
/// (`fstat`), so a pipe swapped in meanwhile is refused too.
///
/// # Errors
/// The system's error; `InvalidInput` for anything but a regular file.
pub fn open_regular(path: &std::path::Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let not_regular = || io::Error::from(io::ErrorKind::InvalidInput);
    if !std::fs::metadata(path)?.is_file() {
        return Err(not_regular());
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    if f.metadata()?.is_file() {
        Ok(f)
    } else {
        Err(not_regular())
    }
}

/// `SF_DATALESS` of `<sys/stat.h>` (libc 0.2.191 has no constant).
const SF_DATALESS: u32 = 0x4000_0000;

/// APP-05.24: the file at `path` is dataless (a cloud file not on this Mac
/// yet), so a read of it would fetch it; false when it cannot be read.
#[must_use]
pub fn dataless(path: &std::path::Path) -> bool {
    use std::os::macos::fs::MetadataExt;
    std::fs::metadata(path).is_ok_and(|m| m.st_flags() & SF_DATALESS != 0)
}

/// The Finder tags attribute.
const TAGS: &std::ffi::CStr = c"com.apple.metadata:_kMDItemUserTags";

/// APP-05.11 step 5 (LD-129, F-089): gives the new file `to` the creation
/// date, the Finder tags and the access control list of the file at
/// `from`, so a safe save that renames `to` over it keeps them. `from` is
/// opened without following a link and without blocking; a missing `from`
/// (a new file) and a part it does not have are no error. Each part is
/// copied on its own, so one that cannot be copied keeps the others.
///
/// # Errors
/// The system's error when `from` cannot be read, or the first error of a
/// part that could not be copied.
pub fn keep_file_info(from: &std::path::Path, to: &File) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let src = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(from)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    [creation_date(&src, to), tags(&src, to), acl(&src, to)]
        .into_iter()
        .collect()
}

/// The creation date of the open file `src` set on the open file `to`.
fn creation_date(src: &File, to: &File) -> io::Result<()> {
    let mut list = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_CRTIME,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    // The reply: a 4-byte length, then the creation time.
    let mut buf = [0u8; 4 + size_of::<libc::timespec>()];
    // SAFETY: `src` stays open while borrowed; `list` and `buf` live
    // across the call and the size passed is `buf`'s own, so the kernel
    // writes at most `buf.len()` bytes and reads only `list`.
    let got = unsafe {
        libc::fgetattrlist(
            src.as_raw_fd(),
            (&raw mut list).cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
        )
    };
    if got != 0 {
        return Err(io::Error::last_os_error());
    }
    // A volume without creation dates leaves the time out of the reply.
    let whole = buf.len();
    let (len, time) = buf.split_at_mut(4);
    let len = len.try_into().map_or(0, u32::from_ne_bytes);
    if usize::try_from(len).unwrap_or(0) < whole {
        return Ok(());
    }
    // SAFETY: `to` stays open while borrowed; `list` and `time` live across
    // the call and the size passed is `time`'s own: the timespec the reply
    // holds. The kernel only reads them.
    let set = unsafe {
        libc::fsetattrlist(
            to.as_raw_fd(),
            (&raw mut list).cast(),
            time.as_mut_ptr().cast(),
            time.len(),
            0,
        )
    };
    if set == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The Finder tags attribute of the open file `src` set on the open file
/// `to`.
fn tags(src: &File, to: &File) -> io::Result<()> {
    let (s, d) = (src.as_raw_fd(), to.as_raw_fd());
    let mut tags = vec![0u8; 64 * 1024];
    // SAFETY: `src` stays open while borrowed; the name is NUL-terminated
    // and static; `tags` is valid for writes of its length and lives across
    // the call.
    let n =
        unsafe { libc::fgetxattr(s, TAGS.as_ptr(), tags.as_mut_ptr().cast(), tags.len(), 0, 0) };
    let Ok(n) = usize::try_from(n) else {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::ENOATTR) {
            Ok(())
        } else {
            Err(e)
        };
    };
    // SAFETY: `to` stays open while borrowed; the name as above; the kernel
    // wrote the first `n` bytes of `tags` (`n` is at most its length) and
    // only reads them here.
    if unsafe { libc::fsetxattr(d, TAGS.as_ptr(), tags.as_ptr().cast(), n, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The access control list of the open file `src` set on the open file
/// `to`.
fn acl(src: &File, to: &File) -> io::Result<()> {
    let (s, d) = (src.as_raw_fd(), to.as_raw_fd());
    // SAFETY: both files stay open while borrowed; a null state is allowed
    // and the flag copies the access control list only.
    if unsafe { libc::fcopyfile(s, d, std::ptr::null_mut(), libc::COPYFILE_ACL) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{Duration, SystemTime};

    /// LD-277 (4): a file that is on this Mac is not dataless, nor is a
    /// missing one.
    #[test]
    fn e15s4_a_local_file_is_not_dataless() {
        let file = std::env::temp_dir().join(format!("app-dataless-{}", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        assert!(!dataless(&file));
        let _ = std::fs::remove_file(&file);
        assert!(!dataless(&file));
    }

    /// F-162: a folder renamed after it was opened, and a link put at its
    /// old path: `create_in` makes the file in the folder that was opened,
    /// exclusive and with the mode given, and `remove_in` removes it there.
    #[test]
    fn f162_create_in_and_remove_in_stay_in_the_open_folder() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("app-create-in-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (a, b, other) = (dir.join("a"), dir.join("b"), dir.join("other"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let open = File::open(&a).unwrap();
        std::fs::rename(&a, &b).unwrap();
        std::os::unix::fs::symlink(&other, &a).unwrap();
        let name = OsStr::new("t.tmp");
        let f = create_in(&open, name, 0o600).unwrap();
        assert!(is_file_in(&open, name, &f).unwrap());
        assert!(b.join("t.tmp").is_file() && !other.join("t.tmp").exists());
        let mode = std::fs::metadata(b.join("t.tmp"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let again = create_in(&open, name, 0o600).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        remove_in(&open, name).unwrap();
        assert!(!b.join("t.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F-089, LD-227 (4): a part that cannot be copied keeps the others. A
    /// tags attribute past the 64 KiB read fails; the creation date and the
    /// access list are copied all the same, and the error comes back.
    #[test]
    fn f_089_each_part_is_copied_on_its_own() {
        let dir = std::env::temp_dir().join(format!("app-keep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (from, to) = (dir.join("from"), dir.join("to"));
        std::fs::write(&from, b"demo").unwrap();
        // A modification time before the creation date moves it back (APFS).
        let born = SystemTime::UNIX_EPOCH + Duration::from_secs(1_577_836_800); // 2020-01-01
        let f = File::options().write(true).open(&from).unwrap();
        f.set_modified(born).unwrap();
        let tags = TAGS.to_str().unwrap();
        let big = "00".repeat(70 * 1024);
        let tool = |cmd: &str, args: &[&str], p: &std::path::Path| {
            let out = Command::new(cmd).args(args).arg(p).output().unwrap();
            assert!(out.status.success(), "{cmd} {args:?}");
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        tool("/usr/bin/xattr", &["-wx", tags, &big], &from);
        tool("/bin/chmod", &["+a", "everyone allow read"], &from);
        let new = File::create(&to).unwrap();
        assert!(keep_file_info(&from, &new).is_err(), "the tags error");
        assert_eq!(std::fs::metadata(&to).unwrap().created().unwrap(), born);
        assert!(tool("/bin/ls", &["-le"], &to).contains("everyone allow read"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
