//! Storage (APP-05, story E4-S15): the only file that touches vault files
//! on disk. It writes the bytes larsal-format built, safely; makes the backup
//! before a save; notices a change on disk by its checksum; names backups.
//!
//! Guarantees:
//! - Safe save (APP-05.11, AT-I01): the new bytes go to a temp file next to
//!   the vault, made with exclusive create (a planted link is never
//!   followed) and mode 0600, written in full and synced to the device,
//!   then renamed over the vault in one step, and the folder is synced. A
//!   failure removes the temp file and leaves the old file as it was
//!   (APP-05.13, AT-I02, AT-I03). So the vault path always holds the old or
//!   the new version. Backups take the same path (LD-131).
//! - Modes are set on the open file, never by path. Right before each
//!   rename the temp path must still name the file Larsal wrote (link-free
//!   metadata against the open file), and the vault is checked once more
//!   for a change on disk (LD-131). The temp file is made, checked and
//!   renamed in the folder opened once before it, never by path (F-047,
//!   F-162), and after the rename the target must name Larsal's file, else
//!   the save failed (F-047).
//! - Reads of a whole vault file stop at the total file limit (APP-05.16).
//! - The real path is written: a symbolic link stays a link and its target
//!   is replaced; other hard links keep the old content (APP-05.9,
//!   APP-05.12, AT-I04).
//! - New vaults, backups and temp files are 0600; a re-save keeps the
//!   vault's permission bits (APP-05.12, APP-05.21, AT-I06).
//! - Before writing to the vault's own path the file on disk is compared
//!   with the last checksum Larsal knows; a change is never overwritten
//!   without the user's choice (APP-05.10, SD-03, AT-I05). From that last
//!   check to the rename the file on disk is held with an exclusive
//!   advisory lock, so two writers take turns and the second one's check
//!   sees the first one's save (F-110).
//! - A vault path or Save As target that is not a regular file (a FIFO, a
//!   device, a folder) is refused before any open; every read of the vault
//!   file opens without blocking and checks the open file (F-101).
//! - No error holds vault content; reasons are the system's error kinds.
//! - Exports (FEA-09.15) and import files (FEA-08.67) go through here too:
//!   [`write_export`] takes the safe path with mode 0600 and replaces a
//!   link at the target instead of writing through it;
//!   [`write_export_except`] never replaces an open vault's file, checked
//!   in the folder the write uses right before the rename (F-162);
//!   [`read_limited`] refuses a file over its limit before allocating and
//!   reads into wiping memory.

use larsal_crypto::hash::sha256;
use larsal_model::times::Civil;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

/// Bytes of the file the checksum hashes (APP-05 "Checksum").
pub const CHECKSUM_LEN: usize = 1_024;
/// Consecutive failed safe saves before the unsafe-method question
/// (APP-05.14).
pub const FAILURES_BEFORE_ASK: u32 = 3;
/// Mode of every file Larsal makes here (AT-I06).
pub const OWNER_ONLY: u32 = 0o600;

/// SHA-256 of the first 1,024 bytes and the file length (APP-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checksum {
    /// The whole file's length.
    pub len: u64,
    /// SHA-256 of its first 1,024 bytes (all of them when shorter).
    pub head: [u8; 32],
}

/// The checksum of file bytes.
#[must_use]
pub fn checksum(bytes: &[u8]) -> Checksum {
    let head = bytes.get(..CHECKSUM_LEN.min(bytes.len())).unwrap_or(&[]);
    let digest = sha256(&[head]);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.expose().get(..32).unwrap_or(&[0; 32]));
    Checksum {
        len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        head: out,
    }
}

/// The checksum of the file at `path`, reading only its first 1,024
/// bytes; `Ok(None)` when it does not exist.
///
/// # Errors
/// The system's error when it exists but cannot be read; `InvalidInput`
/// when it is not a regular file (F-101: a pipe is never waited on).
pub fn read_checksum(path: &Path) -> io::Result<Option<Checksum>> {
    let mut f = match larsal_platform::macos::open_regular(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    let mut head = Vec::with_capacity(CHECKSUM_LEN);
    Read::take(&mut f, CHECKSUM_LEN as u64).read_to_end(&mut head)?;
    let digest = sha256(&[&head]);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.expose().get(..32).unwrap_or(&[0; 32]));
    Ok(Some(Checksum { len, head: out }))
}

/// APP-05.24: the new checksum when the file at `path` differs from
/// `last`; `None` when it is the same or cannot be opened (a missing file
/// or a share briefly away raises no event).
#[must_use]
pub fn changed_on_disk(path: &Path, last: &Checksum) -> Option<Checksum> {
    match read_checksum(path) {
        Ok(Some(now)) if now != *last => Some(now),
        _ => None,
    }
}

/// APP-05.9: the vault path with every symbolic link resolved; a path
/// whose target does not exist is the path as given.
#[must_use]
pub fn real_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// What file `path` is (LD-319, F-224): its device and inode, so a name
/// through a link or in another case is the same file; for a path that
/// does not exist, its resolved real path.
///
/// # Errors
/// The resolved real path when the path cannot be read.
pub fn file_id(path: &Path) -> Result<(u64, u64), PathBuf> {
    fs::metadata(path)
        .map(|m| (m.dev(), m.ino()))
        .map_err(|_| real_path(path))
}

/// INT-08.34: `a` and `b` are one file for the file system. Both there: by
/// device and inode, so a link, a hard link and any spelling count. One not
/// there: the same folder (by what folder it is) and the same name as
/// [`larsal_crypto::text::file_name_key`] compares names. A name that cannot
/// be compared counts as the same (fail closed).
#[must_use]
pub fn same_entry(a: &Path, b: &Path) -> bool {
    if let (Ok(x), Ok(y)) = (file_id(a), file_id(b)) {
        return x == y;
    }
    let folder = |p: &Path| file_id(&resolved_backup_folder(&folder_of(p)));
    match (a.file_name(), b.file_name()) {
        (Some(x), Some(y)) => folder(a) == folder(b) && same_name(x, y).unwrap_or(true),
        _ => true,
    }
}

/// The file system's compare of two names; `None` when one is not text.
fn same_name(a: &OsStr, b: &OsStr) -> Option<bool> {
    let key = |n: &OsStr| n.to_str().map(larsal_crypto::text::file_name_key);
    Some(key(a)? == key(b)?)
}

pub use larsal_platform::macos::{NodeInfo as Stamp, NodeType};

/// INT-08.34: the rename that never replaces; on a volume with no exclusive
/// rename (`ENOTSUP`, `EINVAL`: `Unsupported`, `InvalidInput`) it is the plain rename.
fn rename_new_in(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    match larsal_platform::macos::rename_new_in(dir, from, dir, to) {
        Err(e) if matches!(e.kind(), ErrorKind::Unsupported | ErrorKind::InvalidInput) => {
            larsal_platform::macos::rename_in(dir, from, to)
        }
        done => done,
    }
}

/// How a save writes (APP-05.11, APP-05.15, APP-05.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Temp file next to the vault, synced, renamed over it.
    Safe,
    /// Temp file in Larsal's private folder, the vault deleted, then moved.
    TempMove,
    /// The file rewritten in place, the old bytes kept for a restore.
    Direct,
}

/// The backup before a save (APP-05.19 to APP-05.21).
#[derive(Debug, Clone, Copy)]
pub struct Backup<'a> {
    /// The path pattern (`save.backup.path`); empty means the default.
    pub pattern: &'a str,
    /// The local time of the save.
    pub local: Civil,
    /// Milliseconds of the local time (`zzz`).
    pub millis: u32,
    /// The user's home folder, for `~/`.
    pub home: &'a Path,
}

#[cfg(feature = "test-faults")]
pub use faults::{Fault, FaultPoint};

/// The storage test hook (LD-129 (6)): only in builds with the
/// `test-faults` feature, which only larsal-core's own tests turn on.
#[cfg(feature = "test-faults")]
mod faults {
    use std::io::ErrorKind;

    /// Where a test makes a step fail.
    #[derive(Debug, Clone, Copy)]
    pub enum FaultPoint {
        /// Half way through writing the new bytes.
        Write,
        /// The sync to the device.
        Sync,
        /// The rename over the vault (safe) or the move (temp_move).
        Rename,
        /// Nothing fails: right before the safe rename, after the identity
        /// check, the hook gets the temp file's path, as another writer in
        /// the folder would (F-047).
        Swap(fn(&std::path::Path)),
    }

    /// A failure a test injects.
    #[derive(Debug, Clone)]
    pub struct Fault {
        /// Where.
        pub at: FaultPoint,
        /// The error kind returned there.
        pub kind: ErrorKind,
        /// A fixed temp file name instead of the random one.
        pub temp_name: Option<String>,
    }

    impl Fault {
        pub(super) fn hits(&self, at: FaultPoint) -> Option<ErrorKind> {
            (core::mem::discriminant(&self.at) == core::mem::discriminant(&at)).then_some(self.kind)
        }
        pub(super) fn temp_name(&self) -> Option<&str> {
            self.temp_name.as_deref()
        }
        pub(super) fn before_rename(&self, temp: &std::path::Path) {
            if let FaultPoint::Swap(hook) = self.at {
                hook(temp);
            }
        }
    }
}

/// Without the feature there is no fault at all: these types have no
/// value, so every `Option<&Fault>` is `None`.
#[cfg(not(feature = "test-faults"))]
enum Fault {}

#[cfg(not(feature = "test-faults"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    Write,
    Sync,
    Rename,
}

#[cfg(not(feature = "test-faults"))]
impl Fault {
    fn hits(&self, _: FaultPoint) -> Option<ErrorKind> {
        match *self {}
    }
    fn temp_name(&self) -> Option<&str> {
        match *self {}
    }
    fn before_rename(&self, _: &Path) {
        match *self {}
    }
}

/// The total file limit (FMT-01.31): reads of a vault file for a backup or
/// the direct method stop here.
pub const MAX_FILE: u64 = (1 << 30) + (64 << 20);

/// One save of a vault (APP-05.10 to APP-05.19).
pub struct SaveRequest<'a> {
    /// The vault's path as the user knows it.
    pub path: &'a Path,
    /// The file bytes larsal-format built.
    pub bytes: &'a [u8],
    /// The checksum Larsal last read or wrote at this path; `None` when it
    /// never did (no pre-save check).
    pub last_known: Option<Checksum>,
    /// "Ignore disk changes until saved", or Overwrite (APP-05.27, .28).
    pub ignore_disk_changes: bool,
    /// The write method.
    pub method: Method,
    /// The backup, when `save.backup.enabled` is on.
    pub backup: Option<Backup<'a>>,
    /// Larsal's private temp folder (for `temp_move`).
    pub private_temp: &'a Path,
    /// Test hook only (`test-faults` feature).
    #[cfg(feature = "test-faults")]
    pub fault: Option<Fault>,
}

impl<'a> SaveRequest<'a> {
    /// The command line tool's save (INT-10.20): the safe method, no
    /// backup, the pre-save check against `last_known`. The same value with
    /// or without the test hook, so a caller outside larsal-core builds either
    /// way.
    #[must_use]
    pub fn plain(
        path: &'a Path,
        bytes: &'a [u8],
        last_known: Option<Checksum>,
        private_temp: &'a Path,
    ) -> Self {
        Self {
            path,
            bytes,
            last_known,
            ignore_disk_changes: false,
            method: Method::Safe,
            backup: None,
            private_temp,
            #[cfg(feature = "test-faults")]
            fault: None,
        }
    }
}

/// What a save did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveReport {
    /// The checksum of the bytes written: the new last-known checksum.
    pub checksum: Checksum,
    /// The file had vanished and was written anew (`MSG-SAVE-RECREATED`).
    pub recreated: bool,
    /// The backup's path, or why it could not be made (the save went on;
    /// `MSG-SAVE-BACKUP-FAILED`).
    pub backup: Option<Result<PathBuf, ErrorKind>>,
}

/// Why a save wrote nothing to the vault path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveError {
    /// APP-05.10 step 3: the file changed on disk; ask (APP-05.28). Not a
    /// failure for APP-05.14. Also found once more right before the rename
    /// (LD-131), and right after it (F-047): another program's file then
    /// holds the vault path, not Larsal's version and not the old one.
    ChangedOnDisk(Checksum),
    /// APP-05.10 step 2: the file exists but cannot be read.
    CannotRead(ErrorKind),
    /// The write failed; the old file is intact. For `temp_move` without a
    /// backup, the temp file with the new bytes is kept here. A temp file
    /// replaced behind Larsal's back gives `Other` (LD-131).
    Write {
        /// The system's reason.
        kind: ErrorKind,
        /// The kept temp file (APP-05.15).
        kept_temp: Option<PathBuf>,
    },
}

/// Saves `r.bytes` to the vault (APP-05.10 to APP-05.19).
///
/// # Errors
/// [`SaveError`]; the vault path then holds its old version, except for
/// [`SaveError::ChangedOnDisk`] found after the rename (F-047).
pub fn save(r: &SaveRequest<'_>) -> Result<SaveReport, SaveError> {
    #[cfg(feature = "test-faults")]
    let fault = r.fault.as_ref();
    #[cfg(not(feature = "test-faults"))]
    let fault: Option<&Fault> = None;
    let real = real_path(r.path);
    // F-101: a vault path or Save As target that is not a regular file (a
    // FIFO, a device, a folder) is refused before any open.
    if fs::metadata(&real).is_ok_and(|m| !m.is_file()) {
        return Err(SaveError::Write {
            kind: ErrorKind::InvalidInput,
            kept_temp: None,
        });
    }
    let mut recreated = false;
    // What the pre-save check saw, for the second check before the rename.
    let mut expected: Option<Option<Checksum>> = None;
    if !r.ignore_disk_changes
        && let Some(last) = r.last_known
    {
        match read_checksum(&real) {
            Ok(None) => {
                recreated = true;
                expected = Some(None);
            }
            Ok(Some(now)) if now != last => return Err(SaveError::ChangedOnDisk(now)),
            Ok(Some(_)) => expected = Some(Some(last)),
            Err(e) => return Err(SaveError::CannotRead(e.kind())),
        }
    }
    let dangling = fs::symlink_metadata(r.path).is_ok_and(|m| m.file_type().is_symlink())
        && fs::metadata(r.path).is_err();
    if dangling && r.method == Method::Direct {
        // The direct method would create a file where a dangling link points.
        return Err(SaveError::Write {
            kind: ErrorKind::NotFound,
            kept_temp: None,
        });
    }
    let existing = fs::metadata(&real).ok();
    if existing
        .as_ref()
        .is_some_and(|m| m.permissions().readonly())
    {
        // A file without any write bit is not replaced (APP-05.13, LD-129).
        return Err(SaveError::Write {
            kind: ErrorKind::PermissionDenied,
            kept_temp: None,
        });
    }
    let mode = existing
        .as_ref()
        .map_or(OWNER_ONLY, |m| m.permissions().mode() & 0o7777);
    let backup = match (r.backup, &existing) {
        (Some(b), Some(_)) => Some(make_backup(&real, &b)),
        _ => None,
    };
    let backup_path = backup.as_ref().and_then(|b| b.as_ref().ok().cloned());
    // F-110: the file now on disk stays locked from this check to the
    // write, so a second writer's check waits and then sees this save.
    let recheck = || -> Result<Option<File>, SaveError> {
        let Some(before) = expected else {
            return Ok(None);
        };
        let held = lock_vault(&real)?;
        match read_checksum(&real) {
            Ok(Some(now)) if Some(now) != before => Err(SaveError::ChangedOnDisk(now)),
            _ => Ok(held),
        }
    };
    match r.method {
        Method::Safe => replace_file(
            &folder_of(&real),
            &real,
            r.bytes,
            (mode, true),
            fault,
            &|_| recheck(),
        ),
        Method::TempMove => temp_move(
            &real,
            r.bytes,
            mode,
            r.private_temp,
            backup_path.as_deref(),
            fault,
            &recheck,
        ),
        Method::Direct => recheck().and_then(|_held| direct(&real, r.bytes, fault)),
    }?;
    Ok(SaveReport {
        checksum: checksum(r.bytes),
        recreated,
        backup,
    })
}

fn fail(fault: Option<&Fault>, at: FaultPoint) -> io::Result<()> {
    match fault.and_then(|f| f.hits(at)) {
        Some(kind) => Err(io::Error::from(kind)),
        None => Ok(()),
    }
}

fn write_err(e: &io::Error) -> SaveError {
    SaveError::Write {
        kind: e.kind(),
        kept_temp: None,
    }
}

/// Eight characters from `a`–`z` and `0`–`9` (APP-05.11 step 3).
fn random_suffix() -> io::Result<String> {
    const CHARS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(8);
    for _ in 0..8 {
        let i = larsal_crypto::random::below(36).map_err(|_| io::Error::from(ErrorKind::Other))?;
        let c = usize::try_from(i)
            .ok()
            .and_then(|i| CHARS.get(i))
            .copied()
            .unwrap_or(b'a');
        out.push(char::from(c));
    }
    Ok(out)
}

/// The longest file name the file system takes.
const NAME_MAX: usize = 255;

/// `.` + the file name + `.` + 8 random characters + `.tmp`, the file name
/// cut so the whole stays within 255 bytes (long vault names still save).
fn temp_name(name: &str, suffix: &str) -> String {
    let room = NAME_MAX.saturating_sub(suffix.len()).saturating_sub(6);
    let mut cut = name.len().min(room);
    while !name.is_char_boundary(cut) {
        cut = cut.saturating_sub(1);
    }
    format!(".{}.{suffix}.tmp", name.get(..cut).unwrap_or(""))
}

/// Creates the temp file exclusively with mode 0600 (no link followed);
/// with `folder`, the open folder `dir`, in that folder (F-162).
fn create_temp(
    dir: &Path,
    folder: Option<&File>,
    name: &str,
    fault: Option<&Fault>,
) -> io::Result<(PathBuf, File)> {
    let fixed = fault.and_then(|f| f.temp_name()).map(str::to_owned);
    for _ in 0..8 {
        let file_name = match &fixed {
            Some(n) => n.clone(),
            None => temp_name(name, &random_suffix()?),
        };
        let path = dir.join(&file_name);
        let made = match folder {
            Some(folder) => {
                larsal_platform::macos::create_in(folder, OsStr::new(&file_name), OWNER_ONLY)
            }
            None => OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(OWNER_ONLY)
                .open(&path),
        };
        match made {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists && fixed.is_none() => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::from(ErrorKind::AlreadyExists))
}

/// Writes every byte and syncs to the device (`sync_all` is a full sync
/// on macOS).
fn write_synced(f: &mut File, bytes: &[u8], fault: Option<&Fault>) -> io::Result<()> {
    if fault.and_then(|x| x.hits(FaultPoint::Write)).is_some() {
        let half = bytes.get(..bytes.len() / 2).unwrap_or(&[]);
        f.write_all(half)?;
        fail(fault, FaultPoint::Write)?;
    }
    f.write_all(bytes)?;
    fail(fault, FaultPoint::Sync)?;
    f.sync_all()
}

/// LD-131: the temp path still names the file Larsal wrote: link-free
/// metadata of the path against the open file's own.
fn still_ours(path: &Path, f: &File) -> io::Result<()> {
    let (on_disk, open) = (fs::symlink_metadata(path)?, f.metadata()?);
    if on_disk.file_type().is_file() && on_disk.dev() == open.dev() && on_disk.ino() == open.ino() {
        Ok(())
    } else {
        Err(io::Error::other("the temp file was replaced"))
    }
}

/// F-047: `name` in the open folder `dir` is the file Larsal wrote.
fn ours_in(dir: &File, name: &OsStr, f: &File) -> io::Result<()> {
    if larsal_platform::macos::is_file_in(dir, name, f)? {
        Ok(())
    } else {
        Err(io::Error::other("the temp file was replaced"))
    }
}

/// F-110: how long a save waits for another writer's lock on the vault
/// file; a writer holds it only from its last check to its rename.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// F-110: the vault file now on disk at `real`, opened without blocking
/// (F-101) and held with an exclusive advisory lock (`flock`; no lock
/// file, APP-05.17), so two writers' last checks and renames take turns.
/// `None` when there is no file to lock or its file system has no locks
/// (the save goes on as before); `ResourceBusy` when another program holds
/// the lock past [`LOCK_WAIT`].
fn lock_vault(real: &Path) -> Result<Option<File>, SaveError> {
    let Ok(f) = larsal_platform::macos::open_regular(real) else {
        return Ok(None);
    };
    let start = Instant::now();
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(Some(f)),
            Err(fs::TryLockError::WouldBlock) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(write_err(&io::Error::from(ErrorKind::ResourceBusy)));
            }
            Err(fs::TryLockError::Error(_)) => return Ok(None),
        }
    }
}

fn folder_of(real: &Path) -> PathBuf {
    match real.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// APP-05.11 steps 3 to 6 with LD-131, for the vault and for its backup:
/// an exclusive temp file in `dir`, written and synced, its mode set on the
/// open file, then (after `recheck` and the identity check) renamed over
/// `target`, and the folder synced. With `keep` the temp file first takes
/// the creation date, Finder tags and access control list of `target`
/// (APP-05.11 step 5, F-089); a part that cannot be copied does not fail
/// the save. A failure removes Larsal's own temp file and leaves `target` as
/// it was. F-047, F-162: the temp file is made, checked, renamed and
/// removed in `dir` as opened once at the start; a temp file swapped after
/// the check is caught at `target` and gives [`SaveError::ChangedOnDisk`].
/// `recheck` gets that open folder.
fn replace_file(
    dir: &Path,
    target: &Path,
    bytes: &[u8],
    (mode, keep): (u32, bool),
    fault: Option<&Fault>,
    recheck: &dyn Fn(&File) -> Result<Option<File>, SaveError>,
) -> Result<(), SaveError> {
    let target_name = target
        .file_name()
        .ok_or_else(|| write_err(&io::Error::from(ErrorKind::InvalidInput)))?;
    let name = target_name.to_string_lossy();
    let folder = larsal_platform::macos::open_folder(dir).map_err(|e| write_err(&e))?;
    let (temp, mut f) = create_temp(dir, Some(&folder), &name, fault).map_err(|e| write_err(&e))?;
    let temp_name = temp.file_name().unwrap_or_default();
    let remove = || larsal_platform::macos::remove_in(&folder, temp_name);
    let written = write_synced(&mut f, bytes, fault)
        .and_then(|()| f.set_permissions(fs::Permissions::from_mode(mode)));
    if let Err(e) = written {
        drop(f);
        let _ = remove();
        return Err(write_err(&e));
    }
    if keep {
        let _ = larsal_platform::macos::keep_file_info(target, &f);
    }
    let held = match recheck(&folder) {
        Ok(held) => held,
        Err(e) => {
            drop(f);
            let _ = remove();
            return Err(e);
        }
    };
    // Not ours any more: leave the path alone, it holds someone else's file.
    ours_in(&folder, temp_name, &f).map_err(|e| write_err(&e))?;
    // INT-08.34: nothing there now, so what appears from here on is another
    // writer's file and stays.
    let new = matches!(
        larsal_platform::macos::stamp_in(&folder, target_name),
        Ok(None)
    );
    if let Some(x) = fault {
        x.before_rename(&temp);
    }
    let rename = if new {
        rename_new_in
    } else {
        larsal_platform::macos::rename_in
    };
    let renamed =
        fail(fault, FaultPoint::Rename).and_then(|()| rename(&folder, temp_name, target_name));
    if let Err(e) = renamed {
        drop(f);
        let _ = remove();
        return Err(write_err(&e));
    }
    // F-047: a temp file swapped after the check put someone else's file
    // at `target`; that is not a save, and the old file is gone too: the
    // file changed on disk (APP-05.28 asks).
    let landed = ours_in(&folder, target_name, &f);
    drop((f, held));
    // The rename is in the folder's entry: sync the folder too.
    let _ = folder.sync_all();
    landed.map_err(|_| {
        let now = read_checksum(target).ok().flatten();
        SaveError::ChangedOnDisk(now.unwrap_or_else(|| checksum(&[])))
    })
}

/// APP-05.15: not atomic; a failed move restores the backup or keeps the
/// temp file for the user.
fn temp_move(
    real: &Path,
    bytes: &[u8],
    mode: u32,
    private: &Path,
    backup: Option<&Path>,
    fault: Option<&Fault>,
    recheck: &dyn Fn() -> Result<Option<File>, SaveError>,
) -> Result<(), SaveError> {
    fs::create_dir_all(private).map_err(|e| write_err(&e))?;
    let name = real
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let (temp, mut f) = create_temp(private, None, &name, fault).map_err(|e| write_err(&e))?;
    let written = write_synced(&mut f, bytes, fault)
        .map_err(|e| write_err(&e))
        .and_then(|()| recheck());
    let _held = match written {
        Ok(held) => held,
        Err(e) => {
            drop(f);
            let _ = fs::remove_file(&temp);
            return Err(e);
        }
    };
    still_ours(&temp, &f)
        .and_then(|()| f.set_permissions(fs::Permissions::from_mode(mode)))
        .map_err(|e| write_err(&e))?;
    let moved = match fs::remove_file(real) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
    .and_then(|()| fail(fault, FaultPoint::Rename))
    .and_then(|()| match fs::rename(&temp, real) {
        // Another volume: copy, then remove the temp file.
        Err(e) if e.kind() == ErrorKind::CrossesDevices => {
            fs::copy(&temp, real).and_then(|_| fs::remove_file(&temp))
        }
        other => other,
    });
    match moved {
        Ok(()) => Ok(()),
        Err(e) => match backup {
            Some(b) => {
                let _ = fs::copy(b, real)
                    .and_then(|_| fs::set_permissions(real, fs::Permissions::from_mode(mode)));
                let _ = fs::remove_file(&temp);
                Err(write_err(&e))
            }
            None => {
                // The kept temp file stays owner-only (T22).
                let _ = f.set_permissions(fs::Permissions::from_mode(OWNER_ONLY));
                Err(SaveError::Write {
                    kind: e.kind(),
                    kept_temp: Some(temp),
                })
            }
        },
    }
}

/// FEA-09.15: writes an export to `path` the safe way: a new temp file in
/// the target's folder (exclusive create, mode 0600), written in full and
/// synced, then renamed over `path` in one step. A symbolic link at `path`
/// is replaced by the new file, never followed, and an existing file gets
/// mode 0600 whatever it had. On any error the temp file is removed and
/// anything at `path` is unchanged.
///
/// # Errors
/// The system's error; nothing is left behind.
pub fn write_export(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_export_except(path, bytes, &[])
}

/// INT-08.34 (F-162): [`write_export`] that never replaces the file of a
/// path in `keep` (the files of the open vaults and their backups, F-269).
/// Right before the rename, the entry at the target's name in the folder
/// the write uses, opened once after the bytes were built, is compared with
/// each of those files by device and inode; the check and the rename work
/// in that open folder, so a folder or link swapped meanwhile cannot move
/// the write onto one of them.
///
/// # Errors
/// `PermissionDenied` when the target is the file of a path in `keep`;
/// else as [`write_export`]. Nothing is left behind.
pub fn write_export_except(path: &Path, bytes: &[u8], keep: &[PathBuf]) -> io::Result<()> {
    write_export_if(path, bytes, keep, &|_| true)
}

/// What is at `path` now, a link not followed (INT-08.34): `None` when
/// nothing has that name or its folder is not there.
///
/// # Errors
/// The system's error when the folder cannot be read; `InvalidInput` for a
/// path with no file name.
pub fn stamp(path: &Path) -> io::Result<Option<Stamp>> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::from(ErrorKind::InvalidInput))?;
    match larsal_platform::macos::open_folder(&folder_of(path)) {
        Ok(folder) => larsal_platform::macos::stamp_in(&folder, name),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// INT-08.34: [`write_export_except`] that also asks `expected` about what is
/// at the target's name, in the folder the write uses, right before the
/// rename. The check of `keep` comes first.
///
/// # Errors
/// `AlreadyExists` when `expected` says no; else as
/// [`write_export_except`]. Nothing is left behind.
pub fn write_export_if(
    path: &Path,
    bytes: &[u8],
    keep: &[PathBuf],
    expected: &dyn Fn(Option<Stamp>) -> bool,
) -> io::Result<()> {
    let name = path.file_name().unwrap_or_default();
    let guard = |folder: &File| {
        let theirs = keep.iter().any(|p| {
            larsal_platform::macos::open_regular(p)
                .and_then(|f| larsal_platform::macos::is_file_in(folder, name, &f))
                .unwrap_or(false)
        });
        if theirs {
            return Err(write_err(&io::Error::from(ErrorKind::PermissionDenied)));
        }
        let now = larsal_platform::macos::stamp_in(folder, name).map_err(|e| write_err(&e))?;
        if expected(now) {
            Ok(None)
        } else {
            Err(write_err(&io::Error::from(ErrorKind::AlreadyExists)))
        }
    };
    replace_file(
        &folder_of(path),
        path,
        bytes,
        (OWNER_ONLY, false),
        None,
        &guard,
    )
    .map_err(|e| match e {
        SaveError::Write { kind, .. } | SaveError::CannotRead(kind) => io::Error::from(kind),
        SaveError::ChangedOnDisk(_) => io::Error::from(ErrorKind::Other),
    })
}

/// Reads the whole file at `path` into wiping memory (FEA-08.66), refusing
/// a file longer than `max` bytes before anything is allocated
/// (FEA-08.67). The buffer is made once at the file's size, so no grown
/// copy is left unwiped.
///
/// # Errors
/// The system's error; `FileTooLarge` over `max`; `UnexpectedEof` or
/// `FileTooLarge` when the file changes size while it is read.
pub fn read_limited(path: &Path, max: u64) -> io::Result<larsal_crypto::secret::SecretBytes> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    if len > max {
        return Err(io::Error::from(ErrorKind::FileTooLarge));
    }
    let size = usize::try_from(len).map_err(|_| io::Error::from(ErrorKind::FileTooLarge))?;
    let mut out = larsal_crypto::secret::SecretBytes::zeroed(size);
    f.read_exact(out.expose_mut())?;
    if f.read(&mut [0u8; 1])? != 0 {
        return Err(io::Error::from(ErrorKind::FileTooLarge));
    }
    Ok(out)
}

/// Reads a whole vault file (a backup source, the direct method, a
/// shared-group container, INT-08.16), refusing one over the total file
/// limit; a path that is not a regular file is refused before any read and
/// never waited on (F-101).
///
/// # Errors
/// The system's error; `InvalidInput` for a file that is not regular;
/// `FileTooLarge` over [`MAX_FILE`].
pub fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let f = larsal_platform::macos::open_regular(path)?;
    if f.metadata()?.len() > MAX_FILE {
        return Err(io::Error::from(ErrorKind::FileTooLarge));
    }
    let mut out = Vec::new();
    Read::take(f, MAX_FILE.saturating_add(1)).read_to_end(&mut out)?;
    if u64::try_from(out.len()).unwrap_or(u64::MAX) > MAX_FILE {
        return Err(io::Error::from(ErrorKind::FileTooLarge));
    }
    Ok(out)
}

/// APP-05.16: rewritten in place; any failure after the truncation writes
/// the old bytes back.
fn direct(real: &Path, bytes: &[u8], fault: Option<&Fault>) -> Result<(), SaveError> {
    let old = match read_bounded(real) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(write_err(&e)),
    };
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(OWNER_ONLY)
        .open(real)
        .map_err(|e| write_err(&e))?;
    if let Err(e) = write_synced(&mut f, bytes, fault) {
        if let Some(old) = old {
            let _ = f.set_len(0).and_then(|()| {
                use std::io::Seek;
                f.seek(io::SeekFrom::Start(0))?;
                f.write_all(&old)?;
                f.sync_all()
            });
        }
        return Err(write_err(&e));
    }
    Ok(())
}

/// APP-05.19, APP-05.21 with LD-131: the file on disk copied to the backup
/// path through the same safe path as a save (an exclusive temp file, mode
/// 0600 on the open file, renamed over the backup name), so a link planted
/// at the backup name is replaced, never written through.
fn make_backup(real: &Path, b: &Backup<'_>) -> Result<PathBuf, ErrorKind> {
    let path = backup_path(b.pattern, real, b.local, b.millis, b.home);
    let dir = folder_of(&path);
    fs::create_dir_all(&dir).map_err(|e| e.kind())?;
    let bytes = read_bounded(real).map_err(|e| e.kind())?;
    replace_file(&dir, &path, &bytes, (OWNER_ONLY, false), None, &|_| {
        Ok(None)
    })
    .map_err(|e| match e {
        SaveError::Write { kind, .. } | SaveError::CannotRead(kind) => kind,
        SaveError::ChangedOnDisk(_) => ErrorKind::Other,
    })?;
    Ok(path)
}

/// The default backup pattern (APP-05 settings).
pub const DEFAULT_BACKUP_PATTERN: &str = "{FILE_NAME}.old.larsalvault";

/// APP-05.20, APP-05.21: the backup path for the vault at `real` (its real
/// path) saved at local time `t`: placeholders replaced in one pass, `~/`
/// from `home`, a relative result taken from the vault's folder.
#[must_use]
pub fn backup_path(pattern: &str, real: &Path, t: Civil, millis: u32, home: &Path) -> PathBuf {
    let pattern = if pattern.is_empty() {
        DEFAULT_BACKUP_PATTERN
    } else {
        pattern
    };
    let text = expand(pattern, &file_stem(real), Some((t, millis)));
    if let Some(rest) = text.strip_prefix("~/") {
        return home.join(rest);
    }
    let p = PathBuf::from(&text);
    if p.is_absolute() {
        p
    } else {
        folder_of(real).join(p)
    }
}

/// The file name without its last extension (APP-05.20 `{FILE_NAME}`).
fn file_stem(real: &Path) -> String {
    let name = real
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    match name.rfind('.') {
        Some(i) => name.get(..i).unwrap_or("").to_owned(),
        None => name,
    }
}

// NUL cannot be a file name: literal stars in folders must stay literal.
const TIME_GLOB: char = '\0';
const GLOB_TIME: Civil = Civil {
    year: 1,
    month: 1,
    day: 1,
    hour: 0,
    minute: 0,
    second: 0,
};

/// One pass from left to right; with `time` `None` time components become
/// wildcard markers (for APP-05.33's matching).
fn expand(pattern: &str, stem: &str, time: Option<(Civil, u32)>) -> String {
    let mut out = String::new();
    let mut rest = pattern;
    while let Some(c) = rest.chars().next() {
        if let Some(after) = rest.strip_prefix("\\{") {
            out.push('{');
            rest = after;
            continue;
        }
        if let Some(after) = rest.strip_prefix("\\}") {
            out.push('}');
            rest = after;
            continue;
        }
        if c == '{'
            && let Some(close) = rest.find('}')
        {
            let inner = rest.get(1..close).unwrap_or("");
            let replaced = if inner == "FILE_NAME" {
                Some(stem.to_owned())
            } else if inner == "TIME" || inner == "TIME:" {
                Some(time.map_or_else(
                    || TIME_GLOB.to_string(),
                    |(t, ms)| format_time("dd_MM_yyyy_HH-mm-ss", t, ms),
                ))
            } else if let Some(f) = inner.strip_prefix("TIME:") {
                (!f.contains(['{', '\\']))
                    .then(|| time.map_or_else(|| time_glob(f), |(t, ms)| format_time(f, t, ms)))
            } else {
                None
            };
            if let Some(r) = replaced {
                out.push_str(&r);
                rest = rest.get(close.saturating_add(1)..).unwrap_or("");
                continue;
            }
        }
        out.push(c);
        rest = rest.get(c.len_utf8()..).unwrap_or("");
    }
    out
}

/// Numeric tokens cannot add separators; use the formatter to keep quoted
/// slashes and path-resolution components without choosing today's directory.
fn time_glob(format: &str) -> String {
    let shape = format_time(format, GLOB_TIME, 0);
    if shape.is_empty() {
        return TIME_GLOB.to_string();
    }
    shape
        .split('/')
        .map(|part| {
            if part.is_empty() {
                String::new()
            } else {
                TIME_GLOB.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// APP-05.20's numeric time tokens, longest match first; quoted text as
/// is (`''` is one quote).
fn format_time(f: &str, t: Civil, millis: u32) -> String {
    let mut out = String::new();
    let mut rest = f;
    let tokens: [(&str, String); 16] = [
        ("yyyy", format!("{:04}", t.year)),
        ("yy", format!("{:02}", t.year.rem_euclid(100))),
        ("MM", format!("{:02}", t.month)),
        ("M", t.month.to_string()),
        ("dd", format!("{:02}", t.day)),
        ("d", t.day.to_string()),
        ("HH", format!("{:02}", t.hour)),
        ("H", t.hour.to_string()),
        ("hh", format!("{:02}", t.hour)),
        ("h", t.hour.to_string()),
        ("mm", format!("{:02}", t.minute)),
        ("m", t.minute.to_string()),
        ("ss", format!("{:02}", t.second)),
        ("s", t.second.to_string()),
        ("zzz", format!("{millis:03}")),
        ("''", "'".to_owned()),
    ];
    'outer: while let Some(c) = rest.chars().next() {
        for (tok, value) in &tokens {
            if let Some(after) = rest.strip_prefix(tok) {
                out.push_str(value);
                rest = after;
                continue 'outer;
            }
        }
        if c == '\'' {
            let body = rest.get(1..).unwrap_or("");
            let end = body.find('\'').unwrap_or(body.len());
            out.push_str(body.get(..end).unwrap_or(""));
            rest = body.get(end.saturating_add(1)..).unwrap_or("");
            continue;
        }
        out.push(c);
        rest = rest.get(c.len_utf8()..).unwrap_or("");
    }
    out
}

/// APP-05.33: the copies Larsal made of this vault that still exist: files in
/// the backup pattern's folder whose names match it (each time placeholder
/// matching any text), and the recovery copy. The vault file itself is
/// never listed, however the pattern spells its folder (SG43, F-224).
#[must_use]
pub fn old_copies(
    pattern: &str,
    real: &Path,
    home: &Path,
    recovery: Option<&Path>,
) -> Vec<PathBuf> {
    let glob = backup_glob(pattern, real, home);
    let mut out = Vec::new();
    let vault = file_id(real);
    if let (Some(dir), Some(name)) = (glob.parent(), glob.file_name()) {
        for folder in backup_folders(dir, None) {
            let exact = larsal_platform::macos::case_sensitive(&folder);
            for e in fs::read_dir(&folder).into_iter().flatten().flatten() {
                // SG43: the vault itself by what file it is, never by the
                // spelling of the pattern's folder (F-224).
                // Fed to a delete: a name that cannot be compared is not
                // listed, and a volume that tells names apart by case keeps
                // them apart here.
                if name_matches(name, &e.file_name(), '*', exact) == Some(true)
                    && e.path().is_file()
                    && file_id(&e.path()) != vault
                {
                    out.push(e.path());
                }
            }
        }
    }
    out.sort();
    if let Some(r) = recovery.filter(|r| r.is_file()) {
        out.push(r.to_path_buf());
    }
    out
}

/// APP-05.17 step 4, INT-08.34 (F-269): `path` is a name the backup
/// pattern of the vault at `real` gives, each time placeholder matching any
/// text, whether the file exists or not. Folders compare by what folder
/// they are, names as the file system compares them (E11-S6); a name that
/// cannot be compared counts as a backup (fail closed).
#[must_use]
pub fn is_backup(pattern: &str, real: &Path, home: &Path, path: &Path) -> bool {
    let glob = backup_glob(pattern, real, home);
    match (
        glob.parent(),
        glob.file_name(),
        path.parent(),
        path.file_name(),
    ) {
        (Some(dir), Some(name), Some(folder), Some(file)) => {
            let folder = resolved_backup_folder(folder);
            backup_name_matches(name, file, '*') != Some(false)
                && backup_folders(dir, Some(&folder))
                    .iter()
                    .any(|dir| file_id(&resolved_backup_folder(dir)) == file_id(&folder))
        }
        _ => false,
    }
}

/// `None` when one of the names is not text, so it cannot be compared as the
/// file system compares it.
fn backup_name_matches(pattern: &OsStr, name: &OsStr, wildcard: char) -> Option<bool> {
    name_matches(pattern, name, wildcard, false)
}

/// [`backup_name_matches`], with `exact` comparing the names as they are.
fn name_matches(pattern: &OsStr, name: &OsStr, wildcard: char, exact: bool) -> Option<bool> {
    let key = |n: &OsStr| {
        n.to_str().map(|n| {
            if exact {
                n.to_owned()
            } else {
                larsal_crypto::text::file_name_key(n)
            }
        })
    };
    let pattern = key(pattern)?;
    // Keep the existing filename glob behavior; directory stars are literal.
    let pattern = if wildcard == '*' {
        pattern.replace(TIME_GLOB, "*")
    } else {
        pattern
    };
    Some(matches_glob(&pattern, &key(name)?, wildcard))
}

/// Resolve the existing ancestor too when a backup folder has not been made.
fn resolved_backup_folder(path: &Path) -> PathBuf {
    path.ancestors()
        .find_map(|ancestor| {
            fs::canonicalize(ancestor).ok().and_then(|real| {
                path.strip_prefix(ancestor).ok().map(|suffix| {
                    suffix.components().fold(real, |mut real, part| {
                        if part == Component::ParentDir {
                            real.pop();
                        } else {
                            real.push(part);
                        }
                        // A missing suffix can return to an existing link.
                        fs::canonicalize(&real).unwrap_or(real)
                    })
                })
            })
        })
        .unwrap_or_else(|| path.to_path_buf())
}

/// Expand only the pattern's directory components, never a recursive wildcard.
/// A candidate contributes missing components for the before-creation guard.
fn backup_folders(dir: &Path, candidate: Option<&Path>) -> Vec<PathBuf> {
    let mut root = PathBuf::new();
    let mut parts = Vec::new();
    for part in dir.components() {
        if parts.is_empty() && !part.as_os_str().to_string_lossy().contains(TIME_GLOB) {
            root.push(part);
        } else {
            parts.push(part);
        }
    }
    let mut folders = vec![root];
    let mut deferred = vec![Vec::new(); parts.len().saturating_add(1)];
    for (i, part) in parts.iter().enumerate() {
        let name = part.as_os_str();
        let wildcard = name.to_string_lossy().contains(TIME_GLOB);
        let mut rejoin = None;
        if wildcard {
            let mut depth = 1_usize;
            for (j, part) in parts.iter().enumerate().skip(i.saturating_add(1)) {
                match part {
                    Component::ParentDir => depth = depth.saturating_sub(1),
                    Component::CurDir => (),
                    _ => depth = depth.saturating_add(1),
                }
                if depth == 0 {
                    rejoin = Some(j.saturating_add(1));
                    break;
                }
            }
        }
        let mut next = Vec::new();
        for folder in folders {
            if wildcard {
                // A missing matching child and its suffix can be cancelled by `..`.
                if let Some(step) = rejoin
                    && let Some(pending) = deferred.get_mut(step)
                {
                    pending.push(folder.clone());
                }
                if let Ok(list) = fs::read_dir(&folder) {
                    next.extend(
                        list.flatten()
                            .filter(|e| {
                                let exact = candidate.is_none()
                                    && larsal_platform::macos::case_sensitive(&folder);
                                name_matches(name, &e.file_name(), TIME_GLOB, exact) == Some(true)
                                    && e.path().is_dir()
                            })
                            .map(|e| e.path()),
                    );
                }
            } else {
                next.push(folder.join(name));
            }
            for extra in candidate.into_iter().flat_map(|p| p.ancestors()) {
                if let (Some(parent), Some(file)) = (extra.parent(), extra.file_name())
                    && file_id(&resolved_backup_folder(parent))
                        == file_id(&resolved_backup_folder(&folder))
                    && (if wildcard {
                        backup_name_matches(name, file, TIME_GLOB) != Some(false)
                    } else {
                        name == file
                    })
                    && !next.iter().any(|p| p == extra)
                {
                    next.push(extra.to_path_buf());
                }
            }
        }
        if let Some(pending) = deferred.get_mut(i.saturating_add(1)) {
            next.append(pending);
        }
        // Alias cycles cannot multiply the same directory at one pattern depth.
        next.sort();
        let mut seen = BTreeSet::new();
        next.retain(|p| seen.insert(file_id(&resolved_backup_folder(p))));
        folders = next;
    }
    folders
}

/// The backup pattern's path for the vault at `real`, each time
/// placeholder as `*` (APP-05.33); an empty pattern is the default.
fn backup_glob(pattern: &str, real: &Path, home: &Path) -> PathBuf {
    let pattern = if pattern.is_empty() {
        DEFAULT_BACKUP_PATTERN
    } else {
        pattern
    };
    let stem = file_stem(real);
    let glob = expand(pattern, &stem, None);
    let shape = expand(pattern, &stem, Some((GLOB_TIME, 0)));
    let parts: Vec<_> = glob.split('/').collect();
    let last = parts.len().saturating_sub(1);
    // Resolution uses whole components, even when several placeholders form one.
    let glob = shape
        .split('/')
        .zip(parts)
        .enumerate()
        .map(|(i, (shape, glob))| {
            if i != last && (matches!(shape, "" | "." | "..") || (i == 0 && shape == "~")) {
                shape
            } else {
                glob
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    match glob.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if Path::new(&glob).is_absolute() => PathBuf::from(&glob),
        None => folder_of(real).join(&glob),
    }
}

/// `*` matches any text; everything else exactly.
fn matches_glob(glob: &str, name: &str, wildcard: char) -> bool {
    let parts: Vec<&str> = glob.split(wildcard).collect();
    let (Some(first), Some(last)) = (parts.first(), parts.last()) else {
        return false;
    };
    if parts.len() == 1 {
        return glob == name;
    }
    if !name.starts_with(first)
        || name.len() < first.len().saturating_add(last.len())
        || !name.ends_with(last)
    {
        return false;
    }
    let mut at = first.len();
    let end = name.len().saturating_sub(last.len());
    for p in parts.iter().skip(1).take(parts.len().saturating_sub(2)) {
        match name.get(at..end).and_then(|s| s.find(p)) {
            Some(i) => at = at.saturating_add(i).saturating_add(p.len()),
            None => return false,
        }
    }
    true
}

/// APP-05.18: whether the real path can be written: the file (when it
/// exists) has a write bit and the folder takes a new file.
#[must_use]
pub fn is_writable(real: &Path) -> bool {
    if fs::metadata(real).is_ok_and(|m| m.permissions().readonly()) {
        return false;
    }
    let dir = folder_of(real);
    let Ok(suffix) = random_suffix() else {
        return false;
    };
    let probe = dir.join(format!(".larsal-write-check.{suffix}"));
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(OWNER_ONLY)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// APP-05.14: consecutive failed saves of one vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Failures {
    count: u32,
}

impl Failures {
    /// Counts a failed save (not a changed-on-disk refusal, and not a
    /// reason no other method can help with: permission denied, read-only
    /// file system, no space, not a regular file, another program holding
    /// the file's lock (F-110, F-124: the other methods take the same
    /// lock)). `true` when a safe save failed for the third time in a row:
    /// ask `MSG-SAVE-UNSAFE-ASK` (LD-52).
    pub fn failed(&mut self, e: &SaveError, method: Method) -> bool {
        let counts = match e {
            SaveError::ChangedOnDisk(_) => false,
            SaveError::CannotRead(kind) | SaveError::Write { kind, .. } => !matches!(
                kind,
                ErrorKind::PermissionDenied
                    | ErrorKind::ReadOnlyFilesystem
                    | ErrorKind::StorageFull
                    | ErrorKind::InvalidInput
                    | ErrorKind::ResourceBusy
            ),
        };
        if counts {
            self.count = self.count.saturating_add(1);
        }
        counts && method == Method::Safe && self.count >= FAILURES_BEFORE_ASK
    }

    /// A good save, an unlock or a reload resets the count.
    pub fn reset(&mut self) {
        self.count = 0;
    }

    /// The count.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C2-9: the compare a case-sensitive volume gets. This Mac's volumes are
    /// case-insensitive, so `old_copies` itself cannot reach it here.
    #[test]
    fn e11s6_old_copies_compare_exactly_where_the_volume_tells_names_apart() {
        let (pattern, name) = (OsStr::new("v*.old"), OsStr::new("V1.OLD"));
        assert_eq!(name_matches(pattern, name, '*', false), Some(true));
        assert_eq!(name_matches(pattern, name, '*', true), Some(false));
        assert_eq!(
            name_matches(pattern, OsStr::new("v1.old"), '*', true),
            Some(true)
        );
    }
}
