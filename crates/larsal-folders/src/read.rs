//! Custody and the read chain (FIL-06.4, FIL-06.5): capture ciphertext through one
//! verified handle into private scratch, seal it, prove all of it, and only then give
//! plaintext from the same handle. A state's only way in is the state before it.

use crate::Control;
use crate::Phase;
use crate::content::{self, Gate, HEADER, Plan};
use crate::error::{Error, io};
use crate::keys::MasterKeys;
use crate::names::hex;
use crate::recovery::Kept;
use crate::vault::{Digest, Kind, Node, Vault};
use larsal_crypto::hash::{Algorithm, Hasher};
use larsal_crypto::random;
use larsal_platform::macos::{
    NodeInfo, create_in, info_of, make_dir_in, open_dir_in, open_regular_in, remove_dir_in,
    remove_in,
};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;

const COPY_BLOCK: usize = 1 << 20;

/// What was seen of the source: nothing changed under the copy if all of it still holds.
fn same_source(a: &NodeInfo, b: &NodeInfo) -> bool {
    a == b
}

/// Opens one stored object: a regular file with one name, never a link or a FIFO, never
/// waiting. A second name is refused: a hard link is another way to change it.
pub(crate) fn open_object(dir: &File, name: &OsStr) -> Result<(File, NodeInfo), Error> {
    let file = open_regular_in(dir, name).map_err(|e| match e.kind() {
        std::io::ErrorKind::InvalidInput => Error::Open,
        _ => io(&e),
    })?;
    let info = info_of(&file).map_err(|e| io(&e))?;
    if info.nlink != 1 {
        return Err(Error::Open);
    }
    Ok((file, info))
}

/// What a verified copy of an object is.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Copied {
    pub(crate) digest: Digest,
    pub(crate) len: u64,
    pub(crate) source: NodeInfo,
}

/// Copies one object through one handle into `dest`, with its digest, and proves the
/// source did not change: size, identity and times before and after, and the bytes
/// counted. Any difference, or any I/O failure, aborts.
pub(crate) fn copy_verified(
    dir: &File,
    name: &OsStr,
    dest: &mut File,
    gate: &mut Gate<'_>,
) -> Result<Copied, Error> {
    let (mut src, before) = open_object(dir, name)?;
    crate::seam::hit("capture.after_open")?;
    let mut hasher = Hasher::new(Algorithm::Sha256);
    let mut block = vec![0u8; COPY_BLOCK];
    let mut copied = 0u64;
    loop {
        let got = match src.read(&mut block) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io(&e)),
        };
        if got == 0 {
            break;
        }
        let part = block.get(..got).ok_or(Error::Io)?;
        crate::seam::hit("capture.write")?;
        dest.write_all(part).map_err(|e| io(&e))?;
        hasher.update(part);
        let n = u64::try_from(got).map_err(|_| Error::Io)?;
        copied = copied.checked_add(n).ok_or(Error::Io)?;
        if copied > before.size {
            return Err(Error::Io);
        }
        gate.pass(n)?;
    }
    crate::seam::hit("capture.before_recheck")?;
    let after = info_of(&src).map_err(|e| io(&e))?;
    if copied != before.size || !same_source(&before, &after) {
        return Err(Error::Io);
    }
    dest.sync_all().map_err(|e| io(&e))?;
    let digest = Digest::from_hash(hasher.finalize().expose())?;
    Ok(Copied {
        digest,
        len: copied,
        source: before,
    })
}

/// Ciphertext in custody: one read handle on a file with no name and no writer. It has
/// not been proven.
#[derive(Debug)]
pub struct Snapshot<'v> {
    vault: &'v Vault,
    file: File,
    digest: Digest,
    len: u64,
}

/// Ciphertext whose every chunk has been proven. Only this hands out plaintext. Holds no
/// key: it opens the header again from the session's keys, so a lock leaves it unable to
/// release anything.
#[derive(Debug)]
pub struct Validated<'v> {
    vault: &'v Vault,
    file: File,
    digest: Digest,
    plan: Plan,
}

/// Reads a whole file's header from custody.
fn header_of(file: &File) -> Result<[u8; HEADER], Error> {
    let mut header = [0u8; HEADER];
    file.read_exact_at(&mut header, 0)
        .map_err(|_| Error::Open)?;
    Ok(header)
}

/// One pass over sealed ciphertext: the header proven, every chunk proven, each given
/// to `sink` in order.
fn pass(
    vault: &Vault,
    keys: &MasterKeys,
    file: &File,
    plan: Plan,
    gate: &mut Gate<'_>,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let (key, nonce) = content::open_header(keys, &header_of(file)?)?;
    content::open_chunks(
        &key,
        &nonce,
        plan,
        vault.workers_for(plan.chunks),
        &mut |at, room| file.read_exact_at(room, at).map_err(|_| Error::Open),
        gate,
        sink,
    )
}

impl<'v> Snapshot<'v> {
    /// The SHA-256 of the captured ciphertext: the version an update names as its base.
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// Proves the whole file with the plaintext thrown away.
    ///
    /// # Errors
    /// [`Error::Open`] for any changed byte, illegal fragment, reorder, repeat or splice,
    /// with no plaintext given anywhere; [`Error::Locked`], [`Error::Cancelled`].
    pub fn validate(self, control: Control<'_>) -> Result<Validated<'v>, Error> {
        let turn = self.vault.exclusive()?;
        let keys = turn.keys()?;
        let plan = content::plan(self.len)?;
        let mut gate = self.vault.gate(control, Phase::Validate);
        pass(self.vault, keys, &self.file, plan, &mut gate, &mut |_| {
            Ok(())
        })?;
        Ok(Validated {
            vault: self.vault,
            file: self.file,
            digest: self.digest,
            plan,
        })
    }
}

impl Validated<'_> {
    /// The SHA-256 of the proven ciphertext.
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// The plaintext size.
    #[must_use]
    pub fn plain_len(&self) -> u64 {
        self.plan.plain
    }

    /// Gives the plaintext to `out`, from the same handle, checking every tag again.
    ///
    /// # Errors
    /// [`Error::Locked`] once the session is locked; [`Error::Open`] if custody failed,
    /// [`Error::Io`] if `out` did, [`Error::Cancelled`].
    pub fn write_to(self, out: &mut dyn Write, control: Control<'_>) -> Result<u64, Error> {
        let turn = self.vault.exclusive()?;
        let keys = turn.keys()?;
        let mut gate = self.vault.gate(control, Phase::Write);
        pass(
            self.vault,
            keys,
            &self.file,
            self.plan,
            &mut gate,
            &mut |plain| out.write_all(plain).map_err(|e| io(&e)),
        )?;
        Ok(self.plan.plain)
    }
}

impl Vault {
    /// Captures a file's ciphertext into private scratch and seals it (FIL-06.4). A link's
    /// target is stored the same way, and comes back as bytes: it is never followed.
    ///
    /// # Errors
    /// [`Error::Open`] for a node that is no file or a hostile object; [`Error::Io`] when
    /// the source changed or could not be read, with nothing kept; [`Error::Locked`],
    /// [`Error::Busy`], [`Error::Cancelled`].
    pub fn capture(&self, node: &Node, control: Control<'_>) -> Result<Snapshot<'_>, Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        self.check_node(node)?;
        if !matches!(node.kind(), Kind::File | Kind::Link) {
            return Err(Error::Open);
        }
        let (dir, name) = self.place(keys, node)?;
        let mut gate = self.gate(control, Phase::Capture);
        self.scratch_copy(&dir, &name, &mut gate)
            .map(|(file, copied)| Snapshot {
                vault: self,
                file,
                digest: copied.digest,
                len: copied.len,
            })
    }

    /// Captures one copy of a recovery record: ciphertext in custody like any other, so
    /// its plaintext comes only through the same chain.
    ///
    /// # Errors
    /// [`Error::Input`] for an unknown or unproven record or copy, others as
    /// [`Vault::capture`].
    pub fn capture_recovery(
        &self,
        id: &str,
        which: Kept,
        control: Control<'_>,
    ) -> Result<Snapshot<'_>, Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        let record = self.open_record(keys, id)?;
        let mut gate = self.gate(control, Phase::Capture);
        let (file, copied) = self.scratch_copy(&record.dir, OsStr::new(which.file()), &mut gate)?;
        let wanted = match which {
            Kept::Base => record.journal.base,
            Kept::New => record.journal.new,
        };
        if wanted != Some(copied.digest) {
            return Err(Error::Input);
        }
        Ok(Snapshot {
            vault: self,
            file,
            digest: copied.digest,
            len: copied.len,
        })
    }

    /// A verified copy into fresh private scratch, sealed: every writable handle closed,
    /// the writable name gone, one read handle kept.
    fn scratch_copy(
        &self,
        dir: &File,
        name: &OsStr,
        gate: &mut Gate<'_>,
    ) -> Result<(File, Copied), Error> {
        let mut id = [0u8; 16];
        random::fill(&mut id).map_err(|_| Error::Io)?;
        let op = format!("op-{}", hex(&id));
        let op = OsStr::new(&op);
        make_dir_in(self.scratch(), op, 0o700).map_err(|e| io(&e))?;
        let place = open_dir_in(self.scratch(), op).map_err(|e| io(&e))?;
        let file_name = OsStr::new("ciphertext");
        let done = (|| {
            let mut writer = create_in(&place, file_name, 0o600).map_err(|e| io(&e))?;
            let copied = copy_verified(dir, name, &mut writer, gate)?;
            let reader = open_regular_in(&place, file_name).map_err(|e| io(&e))?;
            drop(writer);
            Ok::<_, Error>((reader, copied))
        })();
        // Whatever happened, the name goes: scratch is ours, and holds only ciphertext.
        let unlinked = remove_in(&place, file_name);
        let removed = remove_dir_in(self.scratch(), op);
        let (reader, copied) = done?;
        unlinked.map_err(|e| io(&e))?;
        removed.map_err(|e| io(&e))?;
        if info_of(&reader).map_err(|e| io(&e))?.nlink != 0 {
            return Err(Error::Io);
        }
        Ok((reader, copied))
    }

    /// Reads a whole file to `out`: capture, prove, then release.
    ///
    /// # Errors
    /// As the three states.
    pub fn read_to(
        &self,
        node: &Node,
        out: &mut dyn Write,
        control: Control<'_>,
    ) -> Result<u64, Error> {
        let snapshot = self.capture(node, &mut *control)?;
        snapshot.validate(&mut *control)?.write_to(out, control)
    }
}
