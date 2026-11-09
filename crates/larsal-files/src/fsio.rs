//! Every file system call of the crate (FIL-03.5, FIL-03.6, FIL-03.8 to
//! FIL-03.11): the source, the ciphertext scratch and the new output. Scratch
//! only ever takes ciphertext: the write path here has no way to reach a
//! plaintext buffer, and the flow in `decrypt.rs` hands plaintext only to
//! [`NewOutput`], made after the whole check.

use crate::decrypt::Snapshot;
use crate::error::{Error, io_error};
use crate::{Control, Phase, payload};
use larsal_crypto::random;
use larsal_platform::macos::{
    create_in, effective_uid, has_acl, ignores_ownership, is_file_in, make_dir_in, open_dir_in,
    open_regular_nofollow, remove_dir_in, remove_in, rename_new_in,
};
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, Metadata};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

const OWNER_FILE: u32 = 0o600;
const OWNER_DIR: u32 = 0o700;
const MODE_BITS: u32 = 0o7777;
const OP_PREFIX: &str = "op-";
/// `op-` and 32 hex digits.
const OP_NAME: usize = 35;
const SNAPSHOT: &str = "ciphertext";
const COPY_BUFFER: usize = 65_536;
const MAX_NAME: usize = 255;
/// An output's own folder in the chosen one, until its last byte (F-340).
const STAGING_PREFIX: &str = ".larsal-staging-";
/// The incomplete output's name inside it.
const STAGED: &str = "incomplete";
/// The look before a capture (V-2): the version line, or the armor's first line
/// after its widest legal white space.
const LOOK: usize = crate::limits::MAX_ARMOR_SPACE + 64;

/// What makes a file the same file: compared before and after it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileId {
    fn of(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn owned_with_mode(m: &Metadata, mode: u32) -> bool {
    m.uid() == effective_uid() && m.mode() & MODE_BITS == mode
}

/// The volume is mounted ignoring ownership, or cannot say: its modes bind no one,
/// whatever they show (FIL-03.8).
fn no_owners(file: &File) -> bool {
    #[cfg(test)]
    {
        if watch::hits(watch::Fault::VolumeNoOwners) {
            return true;
        }
    }
    !matches!(ignores_ownership(file), Ok(false))
}

/// This user's, exactly `mode`, on a volume that keeps it, and no access list: a
/// list is a way in that the mode does not show, and it comes from a folder without
/// anyone asking (FIL-03.8, FIL-03.20). A list that cannot be read counts as one.
fn private(file: &File, mode: u32) -> bool {
    file.metadata().is_ok_and(|m| owned_with_mode(&m, mode))
        && !no_owners(file)
        && matches!(has_acl(file), Ok(false))
}

/// What a new output will hold, which decides where it may go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Holds {
    /// Readable data: only on a volume that keeps the file private.
    Plaintext,
    /// Safe to carry on any volume.
    Ciphertext,
}

/// The handle a sealed snapshot is read through.
pub(crate) type SealedFile = File;

/// One chosen input, opened once, without following a final link (FIL-03.5):
/// its handle, never its path, is what gets read.
pub struct SourceFile {
    file: File,
    path: PathBuf,
    id: FileId,
}

impl SourceFile {
    /// Opens `path` to read, never waiting and never through a final link.
    ///
    /// # Errors
    /// [`Error::Input`] for a missing path, a folder, a link or anything but a
    /// regular file; [`Error::Changed`] if the path changed during the open;
    /// [`Error::Io`] for another fault. No file is changed.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let before = fs::symlink_metadata(path).map_err(|e| match e.kind() {
            ErrorKind::NotFound => Error::Input,
            _ => io_error(&e),
        })?;
        if !before.is_file() {
            return Err(Error::Input);
        }
        #[cfg(test)]
        watch::before_source_open(path);
        // A link put there since the look is refused by the open itself.
        let file = open_regular_nofollow(path).map_err(|e| match e.kind() {
            ErrorKind::InvalidInput | ErrorKind::NotFound => Error::Input,
            _ => io_error(&e),
        })?;
        let opened = file.metadata().map_err(|e| io_error(&e))?;
        // Another file put there since the look gives another inode.
        if !same_inode(&before, &opened) {
            return Err(Error::Changed);
        }
        Ok(Self {
            file,
            path: path.to_owned(),
            id: FileId::of(&opened),
        })
    }

    pub(crate) fn reader(&self) -> impl Read + use<'_> {
        &self.file
    }

    /// The handle's file and the name it was chosen by both still say what they
    /// said at the open, and exactly `count` bytes came (FIL-03.5).
    pub(crate) fn check_unchanged(&self, count: u64) -> Result<(), Error> {
        let now = self.file.metadata().map_err(|e| io_error(&e))?;
        let named = fs::symlink_metadata(&self.path).map_err(|_| Error::Changed)?;
        if FileId::of(&now) != self.id || !same_inode(&now, &named) || count != self.id.size {
            return Err(Error::Changed);
        }
        Ok(())
    }
}

/// The app's private local scratch folder, chosen by the caller: mode 0700,
/// owned by this user, never a cloud folder. Holds ciphertext only.
pub struct ScratchRoot {
    dir: File,
    path: PathBuf,
}

impl ScratchRoot {
    /// Opens the folder and checks it is the user's own, closed to everyone else,
    /// by its mode and by having no access list.
    ///
    /// # Errors
    /// [`Error::Destination`] for anything else; no file is changed.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let dir = File::open(path).map_err(|_| Error::Destination)?;
        let meta = dir.metadata().map_err(|_| Error::Destination)?;
        if !meta.is_dir() || !private(&dir, OWNER_DIR) {
            return Err(Error::Destination);
        }
        Ok(Self {
            dir,
            path: path.to_owned(),
        })
    }

    /// No operating system call here makes or lists a folder through a
    /// descriptor: the root's name must still be the root that was opened.
    fn still_named(&self) -> Result<(), Error> {
        let (held, named) = (self.dir.metadata(), fs::symlink_metadata(&self.path));
        if matches!((&held, &named), (Ok(h), Ok(n)) if same_inode(h, n)) {
            Ok(())
        } else {
            Err(Error::Destination)
        }
    }

    /// Captures the ciphertext of an opened file into fresh scratch and seals
    /// it (FIL-03.5, FIL-03.6). A source that changes during the copy is
    /// refused, before any output.
    ///
    /// # Errors
    /// [`Error::Changed`], [`Error::Space`], [`Error::Io`] or
    /// [`Error::Cancelled`], with owned scratch removed. [`Error::Io`], whatever
    /// stopped the capture, when it could not be removed: the ciphertext stays
    /// for the sweep at the next start (FIL-03.11).
    pub fn capture_file(
        &self,
        source: SourceFile,
        control: Control<'_>,
    ) -> Result<Snapshot, Error> {
        self.capture(&mut source.reader(), control, &|n| {
            source.check_unchanged(n)
        })
    }

    /// Captures a stream of unknown length, counted as it comes, and seals it.
    ///
    /// # Errors
    /// As [`Self::capture_file`], without [`Error::Changed`].
    pub fn capture_stream(
        &self,
        input: &mut dyn Read,
        control: Control<'_>,
    ) -> Result<Snapshot, Error> {
        self.capture(input, control, &|_| Ok(()))
    }

    fn capture(
        &self,
        input: &mut dyn Read,
        control: Control<'_>,
        check: &dyn Fn(u64) -> Result<(), Error>,
    ) -> Result<Snapshot, Error> {
        // V-2: a file that does not start as this format is refused before any
        // scratch exists, so a plain file chosen by mistake is never copied.
        let start = look(input)?;
        if !crate::keys::looks_encrypted(&start) {
            return Err(Error::Decrypt);
        }
        let mut op = Operation::begin(self)?;
        let captured = op
            .copy(&mut start.as_slice().chain(input), control)
            .and_then(|n| check(n).map(|()| n))
            .and_then(|n| op.seal(n));
        match captured {
            Ok(file) => {
                op.close()?;
                Ok(Snapshot { src: file })
            }
            // What stopped it may be said only once cleanup held (FIL-03.11).
            Err(e) => Err(op.discard().map_or(Error::Io, |()| e)),
        }
    }

    /// At the next start: removes ciphertext a crash left before sealing
    /// (FIL-03.11). Touches only a real folder named as this crate names them,
    /// with this user's 0700, unlocked (no live operation holds it), holding
    /// nothing but this user's one regular 0600 snapshot file, not hard linked.
    /// Anything else is left alone, and nothing is judged by its age. Returns
    /// how many it removed.
    ///
    /// # Errors
    /// [`Error::Destination`] if the root's name is no longer the root opened:
    /// nothing is touched. [`Error::Io`] if the folder cannot be read, or an owned
    /// leftover cannot be removed; what it could remove is gone.
    pub fn sweep(&self) -> Result<usize, Error> {
        // ponytail: the list below goes by name, after this check, as std has no
        // listing by descriptor. Whoever can rename this user's folders in between
        // can aim it elsewhere, where it still takes only this crate's exact form.
        // A listing by descriptor in larsal-platform closes that if it ever counts.
        self.still_named()?;
        let mut removed = 0usize;
        let mut failed = false;
        let entries = fs::read_dir(&self.path).map_err(|e| io_error(&e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_error(&e))?;
            if !is_op_name(&entry.file_name()) {
                continue;
            }
            match sweep_one(&entry.path()) {
                Ok(true) => removed = removed.saturating_add(1),
                Ok(false) => {}
                Err(_) => failed = true,
            }
        }
        if failed { Err(Error::Io) } else { Ok(removed) }
    }
}

/// The first bytes of an input, at most [`LOOK`]: they go on to the copy.
fn look(input: &mut dyn Read) -> Result<Vec<u8>, Error> {
    let mut start = vec![0u8; LOOK];
    let mut got = 0usize;
    while let Some(rest) = start.get_mut(got..).filter(|r| !r.is_empty()) {
        match input.read(rest) {
            Ok(0) => break,
            Ok(n) => got = got.saturating_add(n),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io_error(&e)),
        }
    }
    start.truncate(got);
    Ok(start)
}

fn is_op_name(name: &OsStr) -> bool {
    let name = name.as_bytes();
    name.len() == OP_NAME
        && name.starts_with(OP_PREFIX.as_bytes())
        && name
            .iter()
            .skip(OP_PREFIX.len())
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn sweep_one(path: &Path) -> io::Result<bool> {
    let named = fs::symlink_metadata(path)?;
    if !named.is_dir() || !owned_with_mode(&named, OWNER_DIR) {
        return Ok(false);
    }
    let dir = File::open(path)?;
    let opened = dir.metadata()?;
    if !same_inode(&named, &opened) || !private(&dir, OWNER_DIR) || dir.try_lock().is_err() {
        return Ok(false);
    }
    let mut holds_snapshot = false;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        if entry.file_name() != OsStr::new(SNAPSHOT)
            || !meta.is_file()
            || meta.nlink() != 1
            || !owned_with_mode(&meta, OWNER_FILE)
        {
            return Ok(false);
        }
        holds_snapshot = true;
    }
    if holds_snapshot {
        remove_in(&dir, OsStr::new(SNAPSHOT))?;
    }
    fs::remove_dir(path)?;
    Ok(true)
}

/// One capture in progress. Its folder is locked for as long as this lives, so
/// a sweep in another process leaves it alone.
struct Operation {
    path: PathBuf,
    dir: File,
    write: Option<File>,
}

impl Operation {
    fn begin(root: &ScratchRoot) -> Result<Self, Error> {
        root.still_named()?;
        let random_name = random::bytes(16).map_err(|_| Error::Io)?;
        let mut name = OsString::from(OP_PREFIX);
        for b in random_name.expose() {
            name.push(format!("{b:02x}"));
        }
        let path = root.path.join(&name);
        #[cfg(test)]
        watch::record(watch::Event::ScratchDir);
        DirBuilder::new()
            .mode(OWNER_DIR)
            .create(&path)
            .map_err(|e| io_error(&e))?;
        let dir = File::open(&path).map_err(|e| io_error(&e))?;
        let mut op = Self {
            path,
            dir,
            write: None,
        };
        match op.make_snapshot() {
            Ok(()) => Ok(op),
            // Nothing of it stays, or the caller hears that it did (FIL-03.11).
            Err(e) => Err(op.discard().map_or(Error::Io, |()| e)),
        }
    }

    /// The operation's folder proven private, locked, and the empty snapshot in
    /// it. A file takes its list from its folder, so a clean folder means a clean
    /// file: no ciphertext goes anywhere a list can follow it.
    fn make_snapshot(&mut self) -> Result<(), Error> {
        let made = self.dir.metadata().map_err(|e| io_error(&e))?;
        if !made.is_dir() || !private(&self.dir, OWNER_DIR) || self.dir.try_lock().is_err() {
            return Err(Error::Destination);
        }
        #[cfg(test)]
        watch::record(watch::Event::ScratchCreate);
        let write =
            create_in(&self.dir, OsStr::new(SNAPSHOT), OWNER_FILE).map_err(|e| io_error(&e))?;
        let file = write.metadata().map_err(|e| io_error(&e))?;
        self.write = Some(write);
        if !file.is_file() || file.nlink() != 1 || !owned_with_mode(&file, OWNER_FILE) {
            return Err(Error::Destination);
        }
        Ok(())
    }

    /// Copies ciphertext into the named snapshot, counting actual bytes.
    fn copy(&mut self, input: &mut dyn Read, control: Control<'_>) -> Result<u64, Error> {
        let mut buf = vec![0u8; COPY_BUFFER];
        let mut total = 0u64;
        let write = self.write.as_mut().ok_or(Error::Io)?;
        loop {
            let n = match input.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_error(&e)),
            };
            if n == 0 {
                return Ok(total);
            }
            let bytes = buf.get(..n).ok_or(Error::Io)?;
            write_scratch(write, bytes).map_err(|e| io_error(&e))?;
            total = payload::count(total, n).map_err(Error::from)?;
            if !control(Phase::Capture, total) {
                return Err(Error::Cancelled);
            }
        }
    }

    /// FIL-03.6: a read handle on the same inode, then every writer closed,
    /// then the name gone. Proven by the inode's own link count.
    fn seal(&mut self, count: u64) -> Result<File, Error> {
        #[cfg(test)]
        watch::record(watch::Event::ScratchSeal);
        let write = self.write.take().ok_or(Error::Io)?;
        let read = File::open(self.path.join(SNAPSHOT)).map_err(|e| io_error(&e))?;
        let (r, w) = (
            read.metadata().map_err(|e| io_error(&e))?,
            write.metadata().map_err(|e| io_error(&e))?,
        );
        if !same_inode(&r, &w) || r.len() != count || r.nlink() != 1 {
            return Err(Error::Io);
        }
        drop(write);
        remove_in(&self.dir, OsStr::new(SNAPSHOT)).map_err(|e| io_error(&e))?;
        if read.metadata().map_err(|e| io_error(&e))?.nlink() != 0 {
            return Err(Error::Io);
        }
        Ok(read)
    }

    /// After sealing: the empty folder goes, and with it the lock.
    fn close(self) -> Result<(), Error> {
        fs::remove_dir(&self.path).map_err(|e| io_error(&e))
    }

    /// Before sealing, or after a fault: the snapshot and the folder go.
    fn discard(self) -> io::Result<()> {
        drop(self.write);
        match remove_in(&self.dir, OsStr::new(SNAPSHOT)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        fs::remove_dir(&self.path)
    }
}

/// The one way bytes reach scratch. Its only caller is [`Operation::copy`], with
/// bytes straight from the ciphertext source.
fn write_scratch(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    {
        watch::record(watch::Event::ScratchWrite(bytes.to_vec()));
        if watch::hits(watch::Fault::ScratchFull) {
            return Err(watch::full());
        }
    }
    file.write_all(bytes)
}

/// The chosen folder for a new output, bound to its descriptor once (FIL-03.8):
/// a folder moved or replaced later cannot redirect a write.
pub struct OutputFolder(File);

impl OutputFolder {
    /// Opens the folder.
    ///
    /// # Errors
    /// [`Error::Destination`] when `path` is not a folder this user can open.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let dir = File::open(path).map_err(|_| Error::Destination)?;
        if dir.metadata().map_err(|_| Error::Destination)?.is_dir() {
            Ok(Self(dir))
        } else {
            Err(Error::Destination)
        }
    }
}

/// One plain file name: nothing a lookup could read as a way out of the folder.
fn check_name(name: &OsStr) -> Result<(), Error> {
    let mut parts = Path::new(name).components();
    let plain = matches!(parts.next(), Some(Component::Normal(n)) if n == name)
        && parts.next().is_none()
        && name.len() <= MAX_NAME
        && !name.as_bytes().contains(&0);
    if plain {
        Ok(())
    } else {
        Err(Error::Destination)
    }
}

/// A new output, from its exclusive creation to its end. Plaintext reaches the
/// disk only through this, and this exists only after a whole check.
///
/// F-340 (FIL-03.9): the output is made and written in a fresh folder of its own
/// inside the chosen one, by descriptor, 0700 with no access list, so no other user
/// can put a name in it. Only the last step gives it the chosen name, by a rename
/// that never replaces. A cleanup therefore removes only a name inside that folder,
/// which can only be the file it made: no look at a name and then an unlink of it.
pub(crate) struct NewOutput<'a> {
    dir: &'a File,
    name: &'a OsStr,
    staging: File,
    staging_name: OsString,
    file: File,
}

/// What a failed create of the output's folder or file says.
fn create_error(e: &io::Error) -> Error {
    match e.kind() {
        ErrorKind::StorageFull | ErrorKind::QuotaExceeded => Error::Space,
        _ => Error::Destination,
    }
}

impl<'a> NewOutput<'a> {
    /// A name already taken in the folder, by anything, fails here, before any
    /// write; one taken later fails at the rename, which never replaces.
    /// Refused before the first byte, and not repaired, when the folder passed
    /// an access list on: whoever it lets in can open the empty file before any
    /// clear runs and keep that handle, and a handle cannot be taken back. Only a
    /// file that never had a list gets the bytes, on any volume. A disk that cannot
    /// keep plaintext private asks `warned` first, before any byte (E22-S4,
    /// MSG-FILE-UNPROTECTED's warned consent): only a yes keeps the new file.
    pub(crate) fn create(
        folder: &'a OutputFolder,
        name: &'a OsStr,
        holds: Holds,
        warned: &mut dyn FnMut() -> bool,
    ) -> Result<Self, Error> {
        check_name(name)?;
        #[cfg(test)]
        watch::record(watch::Event::OutputCreate);
        match is_file_in(&folder.0, name, &folder.0) {
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Ok(_) => return Err(Error::Exists),
            Err(_) => return Err(Error::Destination),
        }
        let random_name = random::bytes(16).map_err(|_| Error::Io)?;
        let mut staging_name = OsString::from(STAGING_PREFIX);
        for b in random_name.expose() {
            staging_name.push(format!("{b:02x}"));
        }
        make_dir_in(&folder.0, &staging_name, 0o700).map_err(|e| create_error(&e))?;
        // A folder made a moment ago that will not go is said, though empty.
        let undo = |refused: Error| match remove_dir_in(&folder.0, &staging_name) {
            Ok(()) => refused,
            Err(_) => Error::CleanupEmpty,
        };
        let Ok(staging) = open_dir_in(&folder.0, &staging_name) else {
            return Err(undo(Error::Destination));
        };
        // Ours, with no list. Its mode is not judged here: a volume that reads
        // 0700 back as something else cannot keep a file private either, and the
        // check on the file says so for plaintext.
        let ours = staging.metadata().is_ok_and(|m| {
            m.is_dir()
                && matches!(has_acl(&staging), Ok(false))
                && (m.uid() == effective_uid() || no_owners(&staging))
        });
        let file = if ours {
            create_in(&staging, OsStr::new(STAGED), OWNER_FILE).map_err(|e| create_error(&e))
        } else {
            Err(Error::Destination)
        };
        let file = match file {
            Ok(file) => file,
            Err(e) => return Err(undo(e)),
        };
        let out = Self {
            dir: &folder.0,
            name,
            staging,
            staging_name,
            file,
        };
        match out.check_new(holds) {
            Ok(()) => Ok(out),
            Err(Error::Unprotected) if warned() => Ok(out),
            Err(refused) => {
                out.abort()?;
                Err(refused)
            }
        }
    }

    /// FIL-03.8 on the new file. A volume that reads a new 0600 file back with
    /// another mode, or is mounted ignoring ownership, cannot keep it private:
    /// ciphertext may go there, plaintext may not. The rest holds everywhere.
    fn check_new(&self, holds: Holds) -> Result<(), Error> {
        let made = self.file.metadata().map_err(|_| Error::Destination)?;
        if !made.is_file() || links(&made) != 1 || !matches!(has_acl(&self.file), Ok(false)) {
            return Err(Error::Destination);
        }
        if new_mode(&made) == OWNER_FILE && !no_owners(&self.file) {
            return if made.uid() == effective_uid() {
                Ok(())
            } else {
                Err(Error::Destination)
            };
        }
        match holds {
            Holds::Plaintext => Err(Error::Unprotected),
            Holds::Ciphertext => Ok(()),
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        #[cfg(test)]
        {
            watch::record(watch::Event::OutputWrite(bytes.to_vec()));
            if watch::hits(watch::Fault::OutputFull) {
                return Err(io_error(&watch::full()));
            }
            if watch::hits(watch::Fault::OutputShort) {
                let half = bytes.get(..bytes.len() / 2).unwrap_or(&[]);
                self.file.write_all(half).map_err(|e| io_error(&e))?;
                return Err(Error::Io);
            }
        }
        self.file.write_all(bytes).map_err(|e| io_error(&e))
    }

    /// Completion: the bytes on the device, then the chosen name by a rename that
    /// never replaces, then the name still this file. A name taken meanwhile is
    /// [`Error::Exists`], and the incomplete file goes as in [`Self::abort`]. If the
    /// rest cannot be confirmed, the complete file is kept and said to be
    /// uncertain (FIL-03.10). Rust's `File` has no checked close; the sync sees
    /// the errors a close could report on the file systems the app supports.
    pub(crate) fn finish(self) -> Result<(), Error> {
        let synced = sync_output(&self.file);
        #[cfg(test)]
        watch::before_commit();
        if let Err(e) = rename_new_in(&self.staging, OsStr::new(STAGED), self.dir, self.name) {
            let refused = if e.kind() == ErrorKind::AlreadyExists {
                Error::Exists
            } else {
                Error::Destination
            };
            self.abort()?;
            return Err(refused);
        }
        let named = is_file_in(self.dir, self.name, &self.file).unwrap_or(false);
        // The folder entry too. Not every file system takes this, so its result
        // is not judged: the same policy as the safe save (APP-05).
        let _ = self.dir.sync_all();
        // ponytail: an empty output folder that cannot go after a good rename is
        // not said; it holds nothing. Say it if a volume is ever seen to keep one.
        let _ = self.remove_staging();
        if synced.is_ok() && named {
            Ok(())
        } else {
            Err(Error::Uncertain)
        }
    }

    /// Handled failure or cancel. The file is emptied through its descriptor, then
    /// its one name is removed inside the output's own folder, which only this
    /// operation can write: no name in the chosen folder is ever unlinked (F-340).
    /// Removed, the file has no name left and its room comes back with the
    /// descriptor, so what stopped the work is said even when the emptying failed,
    /// as on a full disk (F-341). Then the empty folder goes, if its name is still
    /// that folder. A name or folder that stays is [`Error::CleanupEmpty`] when the
    /// file was emptied or removed, and [`Error::Cleanup`] when it was neither.
    pub(crate) fn abort(self) -> Result<(), Error> {
        let emptied = empty_output(&self.file);
        #[cfg(test)]
        watch::before_cleanup_unlink();
        let removed = remove_staged(&self.staging);
        match (removed && self.remove_staging(), removed || emptied) {
            (true, _) => Ok(()),
            (false, true) => Err(Error::CleanupEmpty),
            (false, false) => Err(Error::Cleanup),
        }
    }

    /// The output's folder goes only while its name is still that folder; one
    /// holding anything stays, with all it holds.
    ///
    /// ponytail: the look and the remove are two calls on a name, as no call
    /// removes a folder by its handle. What a swap in between can lose is only
    /// an empty folder at a random 32-hex name, put there by someone who can
    /// already rename entries of that folder and so remove that empty folder
    /// anyway; a folder holding anything, and every file, is never removed. In a
    /// folder with the sticky bit no one else can rename this one at all.
    fn remove_staging(&self) -> bool {
        let still = open_dir_in(self.dir, &self.staging_name)
            .and_then(|d| Ok((d.metadata()?, self.staging.metadata()?)))
            .is_ok_and(|(named, held)| same_inode(&named, &held));
        still && remove_dir_in(self.dir, &self.staging_name).is_ok()
    }
}

/// The incomplete output's one name, removed inside its own folder.
fn remove_staged(staging: &File) -> bool {
    #[cfg(test)]
    {
        if watch::hits(watch::Fault::OutputPinned) {
            return false;
        }
    }
    remove_in(staging, OsStr::new(STAGED)).is_ok()
}

/// The names a new output has.
fn links(made: &Metadata) -> u64 {
    #[cfg(test)]
    {
        if watch::hits(watch::Fault::OutputLinked) {
            return 2;
        }
    }
    made.nlink()
}

/// The mode a new output reads back with.
fn new_mode(made: &Metadata) -> u32 {
    #[cfg(test)]
    {
        if watch::hits(watch::Fault::VolumeOtherMode) {
            return 0o700;
        }
    }
    #[cfg(feature = "test-volume")]
    {
        if test_volume::on() {
            return 0o700;
        }
    }
    made.mode() & MODE_BITS
}

/// Other crates' tests only (feature `test-volume`, never in a product build):
/// while on, every new output reads back as on a volume that cannot keep a file
/// private, as the `VolumeOtherMode` fault does here, so larsal-ffi's tests reach
/// MSG-FILE-UNPROTECTED's warned consent through the app's own job (C1R3-02).
#[cfg(feature = "test-volume")]
pub mod test_volume {
    use std::sync::atomic::{AtomicBool, Ordering};

    static ON: AtomicBool = AtomicBool::new(false);

    /// Every new output in this process reads back unprotected while `on`.
    pub fn set(on: bool) {
        ON.store(on, Ordering::SeqCst);
    }

    pub(super) fn on() -> bool {
        ON.load(Ordering::SeqCst)
    }
}

fn empty_output(file: &File) -> bool {
    #[cfg(test)]
    {
        if watch::hits(watch::Fault::OutputStuck) {
            return false;
        }
    }
    file.set_len(0).is_ok()
}

fn sync_output(file: &File) -> io::Result<()> {
    #[cfg(test)]
    {
        if watch::hits(watch::Fault::OutputSync) {
            return Err(io::Error::from(ErrorKind::Other));
        }
    }
    file.sync_all()
}

/// Test-only: what the crate asked the file system to do, in order, and faults
/// to inject (FIL-03-T05, FIL-03-T10, and acceptance check 4).
#[cfg(test)]
pub(crate) mod watch {
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::path::Path;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Event {
        ScratchDir,
        ScratchCreate,
        ScratchWrite(Vec<u8>),
        ScratchSeal,
        OutputCreate,
        OutputWrite(Vec<u8>),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Fault {
        ScratchFull,
        OutputFull,
        OutputShort,
        OutputSync,
        /// The output cannot be emptied.
        OutputStuck,
        /// The volume reads a new 0600 file back with another mode.
        VolumeOtherMode,
        /// The volume is mounted ignoring ownership.
        VolumeNoOwners,
        /// The incomplete output's name cannot be removed.
        OutputPinned,
        /// The new output has a second name.
        OutputLinked,
    }

    type Change = Box<dyn FnOnce(&Path)>;

    type Hook = Box<dyn FnOnce()>;

    thread_local! {
        static LOG: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
        static FAULT: Cell<Option<Fault>> = const { Cell::new(None) };
        static ALSO: Cell<Option<Fault>> = const { Cell::new(None) };
        static AT_OPEN: RefCell<Option<Change>> = const { RefCell::new(None) };
        static AT_UNLINK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static AT_COMMIT: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// `change` runs once, right before the next cleanup removes a name: the
    /// moment F-340's race lives in.
    pub(crate) fn at_cleanup_unlink(change: Hook) {
        AT_UNLINK.with(|c| *c.borrow_mut() = Some(change));
    }

    pub(crate) fn before_cleanup_unlink() {
        if let Some(change) = AT_UNLINK.with(RefCell::take) {
            change();
        }
    }

    /// `change` runs once, right before the next output takes its chosen name.
    pub(crate) fn at_commit(change: Hook) {
        AT_COMMIT.with(|c| *c.borrow_mut() = Some(change));
    }

    pub(crate) fn before_commit() {
        if let Some(change) = AT_COMMIT.with(RefCell::take) {
            change();
        }
    }

    /// A second fault at the same time as the one [`inject`] set.
    pub(crate) fn inject_also(fault: Fault) {
        ALSO.with(|f| f.set(Some(fault)));
    }

    /// `change` runs once, between the next source's look at its path and its open.
    pub(crate) fn at_source_open(change: Change) {
        AT_OPEN.with(|c| *c.borrow_mut() = Some(change));
    }

    pub(crate) fn before_source_open(path: &Path) {
        if let Some(change) = AT_OPEN.with(RefCell::take) {
            change(path);
        }
    }

    pub(crate) fn record(event: Event) {
        LOG.with(|l| l.borrow_mut().push(event));
    }

    pub(crate) fn take() -> Vec<Event> {
        LOG.with(RefCell::take)
    }

    pub(crate) fn inject(fault: Fault) {
        FAULT.with(|f| f.set(Some(fault)));
    }

    pub(crate) fn clear_faults() {
        FAULT.with(|f| f.set(None));
        ALSO.with(|f| f.set(None));
    }

    pub(crate) fn hits(fault: Fault) -> bool {
        FAULT.with(Cell::get) == Some(fault) || ALSO.with(Cell::get) == Some(fault)
    }

    pub(crate) fn full() -> io::Error {
        io::Error::from(io::ErrorKind::StorageFull)
    }
}
