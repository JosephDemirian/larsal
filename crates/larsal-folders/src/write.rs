//! Every change to a folder (FIL-06.6, FIL-06.7, FIL-06.10 to FIL-06.13). A change works in
//! one private staging folder per operation, bound by its descriptor, on the folder's own
//! volume; keeps its ciphertext copies in the local recovery store first; and publishes
//! with the system's exclusive rename or swap, so it never replaces by accident and never
//! truncates. Each step is recorded, and a crash at any step leaves a state `resume` can
//! finish or a state that is whole as it stands.
//!
//! Nothing here looks at a public name and then unlinks it (F-340): what goes is removed
//! inside the private folder, only if it is still the object this operation made, and the
//! folder itself only goes when empty. What cannot be proven ours stays, and is said.

use crate::Control;
use crate::Phase;
use crate::content::{self, Gate};
use crate::error::{Error, io};
use crate::keys::MasterKeys;
use crate::limits::{GCM_INVOCATIONS, MAX_CHILDREN, MAX_DEPTH, MAX_DIR_ID, MAX_NODES};
use crate::names::{self, BACKUP, CONTENTS, DIR_FILE, INFLATED, Stored, hex};
use crate::read::{Copied, copy_verified, open_object};
use crate::recovery::{
    BASE, Journal, NEW, OpKind, OpState, Record, RecoveryItem, clear_journal_scratch, read_journal,
};
use crate::seam::{crashed, hit};
use crate::stores::check_private;
use crate::vault::{Digest, Kind, Node, Vault, read_small, write_new};
use larsal_crypto::hash::{Algorithm, Hasher};
use larsal_crypto::random;
use larsal_platform::macos::{
    NodeInfo, NodeType, create_in, free_bytes, info_in, info_of, make_dir_in, names_in,
    open_dir_in, remove_dir_in, remove_in, rename_new_in, swap_in,
};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;

const STAGED: &str = "new";
const ASIDE: &str = "node";
const DUPLICATE: &str = "duplicate";
const HOME: &str = "home";
const JOURNAL_ALLOWANCE: u64 = 16_384;
const STAGING_PREFIX: &str = ".larsal-staging-";
const COMPARE_BLOCK: usize = 1 << 20;

/// How an update or an admitted version ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The file now holds the new version.
    Replaced,
    /// Another version was there: both are kept by the rule of FIL-06.10.
    KeptBoth,
    /// The same bytes were there already: nothing was added.
    Identical,
}

/// What an update or an admitted version did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Saved {
    /// How it ended.
    pub outcome: Outcome,
    /// The version's digest.
    pub digest: Digest,
}

/// The name a competing version is kept under, in clear, in the same folder.
fn conflict_name(digest: &Digest) -> String {
    format!("conflict-{}.bin", digest.hex())
}

/// One operation's private folder on the folder's own volume.
struct Staging {
    name: OsString,
    dir: File,
    /// What this operation made here: only these may go.
    own: Vec<(&'static str, (u64, u64))>,
}

impl std::fmt::Debug for Staging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Staging")
    }
}

fn identity(info: &NodeInfo) -> (u64, u64) {
    (info.dev, info.ino)
}

/// The system's refusal of an exclusive step, in the user's words.
fn taken(e: &std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::AlreadyExists {
        Error::Exists
    } else {
        io(e)
    }
}

fn random_hex() -> Result<String, Error> {
    let mut id = [0u8; 16];
    random::fill(&mut id).map_err(|_| Error::Io)?;
    Ok(hex(&id))
}

/// A whole-file digest and length through one handle.
fn digest_of_file(mut file: &File) -> Result<(Digest, u64), Error> {
    let mut hasher = Hasher::new(Algorithm::Sha256);
    let mut block = vec![0u8; COMPARE_BLOCK];
    let mut total = 0u64;
    loop {
        let got = match file.read(&mut block) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io(&e)),
        };
        if got == 0 {
            break;
        }
        hasher.update(block.get(..got).ok_or(Error::Io)?);
        total = total
            .checked_add(u64::try_from(got).map_err(|_| Error::Io)?)
            .ok_or(Error::Io)?;
    }
    Ok((Digest::from_hash(hasher.finalize().expose())?, total))
}

/// The digest of an object, or `None` when nothing has that name.
fn digest_at(dir: &File, name: &OsStr) -> Result<Option<Digest>, Error> {
    let (file, _) = match open_object(dir, name) {
        Ok(f) => f,
        Err(Error::Io) if matches!(info_in(dir, name), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    Ok(Some(digest_of_file(&file)?.0))
}

/// True when two objects hold the same bytes, by a bounded streaming comparison:
/// deduplication goes only by the bytes (FIL-06.10).
fn same_bytes(a: &File, b: &File) -> Result<bool, Error> {
    use std::os::unix::fs::FileExt;
    let (la, lb) = (
        a.metadata().map_err(|e| io(&e))?.len(),
        b.metadata().map_err(|e| io(&e))?.len(),
    );
    if la != lb {
        return Ok(false);
    }
    let (mut xa, mut xb) = (vec![0u8; COMPARE_BLOCK], vec![0u8; COMPARE_BLOCK]);
    let mut at = 0u64;
    while at < la {
        let n = usize::try_from((la.saturating_sub(at)).min(COMPARE_BLOCK as u64))
            .map_err(|_| Error::Io)?;
        let (pa, pb) = (
            xa.get_mut(..n).ok_or(Error::Io)?,
            xb.get_mut(..n).ok_or(Error::Io)?,
        );
        a.read_exact_at(pa, at).map_err(|e| io(&e))?;
        b.read_exact_at(pb, at).map_err(|e| io(&e))?;
        if pa != pb {
            return Ok(false);
        }
        at = at.saturating_add(n as u64);
    }
    Ok(true)
}

impl Vault {
    fn new_staging(&self) -> Result<Staging, Error> {
        let name = OsString::from(format!("{STAGING_PREFIX}{}", random_hex()?));
        make_dir_in(&self.root, &name, 0o700).map_err(|e| io(&e))?;
        let dir = open_dir_in(&self.root, &name).map_err(|e| io(&e))?;
        Ok(Staging {
            name,
            dir,
            own: Vec::new(),
        })
    }

    /// Removes what this operation made, then the folder if it is empty. Anything else
    /// planted there keeps the folder and its bytes: the answer is `Uncertain`.
    fn close_staging(&self, staging: &Staging) -> Result<(), Error> {
        for (name, id) in &staging.own {
            let os = OsStr::new(name);
            match info_in(&staging.dir, os) {
                Ok(info) if identity(&info) == *id => {
                    if info.kind == NodeType::Dir {
                        for inner in [INFLATED, CONTENTS, DIR_FILE] {
                            if let Ok(node) = open_dir_in(&staging.dir, os) {
                                let _ = remove_in(&node, OsStr::new(inner));
                            }
                        }
                        let _ = remove_dir_in(&staging.dir, os);
                    } else {
                        let _ = remove_in(&staging.dir, os);
                    }
                }
                _ => {}
            }
        }
        match remove_dir_in(&self.root, &staging.name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::Uncertain),
        }
    }

    /// The end of a step sequence: on success tidy up, on failure tidy up and keep the
    /// true cause (F-341), and say `Uncertain` only when something could not be proven
    /// ours. A crash point leaves everything as it stands.
    fn settle<T>(&self, staging: &Staging, result: Result<T, Error>) -> Result<T, Error> {
        if crashed() {
            return result;
        }
        let closed = self.close_staging(staging);
        match (result, closed) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(e)) => Err(e),
            (Err(cause), Ok(())) => Err(cause),
            (Err(_), Err(e)) => Err(e),
        }
    }

    fn ceiling(&self) -> u64 {
        #[cfg(test)]
        {
            self.ceiling.load(Ordering::SeqCst)
        }
        #[cfg(not(test))]
        {
            crate::limits::RECOVERY_CEILING
        }
    }

    /// FIL-06.13: before any change, the copies must fit under the ceiling and on the
    /// disk, and the staged copy on the folder's disk. Nothing is ever pruned to fit.
    pub(crate) fn preflight(&self, keep: u64, stage: u64) -> Result<(), Error> {
        let need = keep.checked_add(JOURNAL_ALLOWANCE).ok_or(Error::Recovery)?;
        let used = self.recovery_used.load(Ordering::SeqCst);
        if used.checked_add(need).is_none_or(|t| t > self.ceiling()) {
            return Err(Error::Recovery);
        }
        let store = info_of(&self.recovery).map_err(|e| io(&e))?;
        let vault = info_of(&self.root).map_err(|e| io(&e))?;
        let store_free = free_bytes(&self.recovery).map_err(|e| io(&e))?;
        let vault_free = free_bytes(&self.root).map_err(|e| io(&e))?;
        let enough = if store.dev == vault.dev {
            need.checked_add(stage).is_some_and(|t| t <= store_free)
        } else {
            need <= store_free && stage <= vault_free
        };
        if enough { Ok(()) } else { Err(Error::Space) }
    }

    fn begin(
        &self,
        keys: &MasterKeys,
        kind: OpKind,
        parent: &[u8],
        stored: &Stored,
        keep: u64,
        stage: u64,
    ) -> Result<Record, Error> {
        self.preflight(keep, stage)?;
        let id = format!("op-{}", random_hex()?);
        make_dir_in(&self.recovery, OsStr::new(&id), 0o700).map_err(|e| io(&e))?;
        let dir = open_dir_in(&self.recovery, OsStr::new(&id)).map_err(|e| io(&e))?;
        let record = Record {
            dir,
            journal: Journal {
                id,
                kind,
                state: OpState::Begun,
                parent: parent.to_vec(),
                stored: stored.clone(),
                to: None,
                dir_id: None,
                node_is_dir: false,
                base: None,
                new: None,
                staging: None,
            },
        };
        if let Err(e) = record
            .save(keys)
            .and_then(|()| self.recovery.sync_all().map_err(|e| io(&e)))
        {
            self.drop_incomplete(&record);
            return Err(e);
        }
        self.note_kept(JOURNAL_ALLOWANCE);
        Ok(record)
    }

    /// A staging folder this record names, durably, before anything is put in it.
    fn stage_for(&self, keys: &MasterKeys, record: &mut Record) -> Result<Staging, Error> {
        let staging = self.new_staging()?;
        record.journal.staging = staging.name.to_str().map(str::to_owned);
        if let Err(e) = record.save(keys) {
            self.drop_incomplete(record);
            return self.settle(&staging, Err(e));
        }
        Ok(staging)
    }

    fn note_kept(&self, bytes: u64) {
        self.recovery_used.fetch_add(bytes, Ordering::SeqCst);
    }

    /// FIL-06.8: a handle is bound to the node it named. Before a write the node is read
    /// again, and the write goes on only while it holds the handle's directory ID (none,
    /// for a file); anything else is out of date, [`Error::Changed`], and nothing has
    /// changed. The top folder has no node: the root's identity binds it.
    fn bound(&self, keys: &MasterKeys, node: &Node) -> Result<(), Error> {
        self.check_node(node)?;
        let Some(stored) = &node.stored else {
            let top =
                node.kind == Kind::Dir && node.dir_id.as_deref().is_some_and(<[u8]>::is_empty);
            return if top { Ok(()) } else { Err(Error::Open) };
        };
        let folder = self.content_dir(keys, &node.parent)?;
        let now = self.classify(keys, &folder, &node.parent, OsStr::new(stored.entry()));
        if now.node.dir_id == node.dir_id {
            Ok(())
        } else {
            Err(Error::Changed)
        }
    }

    /// FIL-06.3's node limit for a walk; a test may lower it.
    fn node_limit(&self) -> usize {
        #[cfg(test)]
        {
            self.node_limit.load(Ordering::SeqCst)
        }
        #[cfg(not(test))]
        {
            MAX_NODES
        }
    }

    /// Writes a new whole file: one header from the shared budget, fresh key and nonces,
    /// never resumed (FIL-04.5); ciphertext to the staged name and the recovery copy
    /// together, both durable before this returns.
    fn seal_to_staging(
        &self,
        keys: &MasterKeys,
        staging: &mut Staging,
        record: &Record,
        input: &mut dyn Read,
        expected: u64,
        control: Control<'_>,
    ) -> Result<(Digest, u64), Error> {
        let mut staged = create_in(&staging.dir, OsStr::new(STAGED), 0o600).map_err(|e| io(&e))?;
        staging
            .own
            .push((STAGED, identity(&info_of(&staged).map_err(|e| io(&e))?)));
        let mut kept = create_in(&record.dir, OsStr::new(NEW), 0o600).map_err(|e| io(&e))?;
        self.budget.take(keys)?;
        let (header, key, nonce) = content::new_header(keys)?;
        let mut hasher = Hasher::new(Algorithm::Sha256);
        staged.write_all(&header).map_err(|e| io(&e))?;
        kept.write_all(&header).map_err(|e| io(&e))?;
        hasher.update(&header);
        let mut written = u64::try_from(header.len()).map_err(|_| Error::Io)?;
        let workers = self.workers_for(u64::MAX);
        let mut gate: Gate<'_> = self.gate(control, Phase::Encrypt);
        let plain = content::seal_chunks(
            &key,
            &nonce,
            workers,
            GCM_INVOCATIONS,
            input,
            &mut gate,
            &mut |bytes| {
                hit("write.chunk")?;
                staged.write_all(bytes).map_err(|e| io(&e))?;
                kept.write_all(bytes).map_err(|e| io(&e))?;
                hasher.update(bytes);
                written =
                    written.saturating_add(u64::try_from(bytes.len()).map_err(|_| Error::Io)?);
                Ok(())
            },
        )?;
        if plain != expected {
            return Err(Error::Input);
        }
        hit("write.before_sync")?;
        staged.sync_all().map_err(|e| io(&e))?;
        kept.sync_all().map_err(|e| io(&e))?;
        record.dir.sync_all().map_err(|e| io(&e))?;
        staging.dir.sync_all().map_err(|e| io(&e))?;
        self.still_allowed()?;
        self.note_kept(written);
        Ok((Digest::from_hash(hasher.finalize().expose())?, written))
    }

    /// Removes an aborted record whose copy is incomplete: it holds nothing worth review.
    fn drop_incomplete(&self, record: &Record) {
        for name in [NEW, BASE, crate::recovery::JOURNAL] {
            let _ = remove_in(&record.dir, OsStr::new(name));
        }
        clear_journal_scratch(&record.dir);
        let _ = remove_dir_in(&self.recovery, OsStr::new(&record.journal.id));
    }

    /// A new file with new content at `stored` in `folder`, whichever way it is stored.
    fn publish(
        &self,
        staging: &mut Staging,
        name: &str,
        folder: &File,
        stored: &Stored,
    ) -> Result<(), Error> {
        self.still_allowed()?;
        let from = OsStr::new(name);
        match stored {
            Stored::Plain(entry) => {
                rename_new_in(&staging.dir, from, folder, OsStr::new(entry))
                    .map_err(|e| taken(&e))?;
            }
            Stored::Short { deflated, inflated } => {
                let home = self.short_home(staging, inflated)?;
                rename_new_in(&staging.dir, from, &home, OsStr::new(CONTENTS))
                    .map_err(|e| io(&e))?;
                home.sync_all().map_err(|e| io(&e))?;
                let published =
                    rename_new_in(&staging.dir, OsStr::new(HOME), folder, OsStr::new(deflated));
                if let Err(e) = published {
                    // Taken: the version goes back to its staged name, whole.
                    rename_new_in(&home, OsStr::new(CONTENTS), &staging.dir, from)
                        .map_err(|e| io(&e))?;
                    remove_in(&home, OsStr::new(INFLATED)).map_err(|e| io(&e))?;
                    remove_dir_in(&staging.dir, OsStr::new(HOME)).map_err(|e| io(&e))?;
                    staging.own.retain(|(n, _)| *n != HOME);
                    return Err(taken(&e));
                }
            }
        }
        folder.sync_all().map_err(|e| io(&e))?;
        staging.dir.sync_all().map_err(|e| io(&e))
    }

    /// A shortened node's folder, whole except for its object, in staging.
    fn short_home(&self, staging: &mut Staging, inflated: &str) -> Result<File, Error> {
        make_dir_in(&staging.dir, OsStr::new(HOME), 0o700).map_err(|e| io(&e))?;
        let home = open_dir_in(&staging.dir, OsStr::new(HOME)).map_err(|e| io(&e))?;
        staging
            .own
            .push((HOME, identity(&info_of(&home).map_err(|e| io(&e))?)));
        write_new(&home, INFLATED, inflated.as_bytes())?;
        Ok(home)
    }

    /// FIL-06.2: no two items for one name, as the disk may see it. An exact stored match
    /// is one lookup; a fold looks at every proven name, at most 10,000.
    fn refuse_collision(
        &self,
        keys: &MasterKeys,
        folder: &File,
        parent: &[u8],
        name: &str,
        skip: Option<&Stored>,
    ) -> Result<(), Error> {
        let wanted = names::fold(name);
        // One scan per new name; a sorted local index if a folder of 10,000
        // items is written to often.
        let raw = names_in(folder, MAX_CHILDREN).map_err(|e| io(&e))?;
        if raw.len() > MAX_CHILDREN {
            return Err(Error::Open);
        }
        for entry in raw {
            if entry == BACKUP {
                continue;
            }
            if skip.is_some_and(|s| OsStr::new(s.entry()) == entry) {
                continue;
            }
            let row = self.classify(keys, folder, parent, &entry);
            if row
                .name
                .is_some_and(|n| names::fold(n.expose()).expose() == wanted.expose())
            {
                return Err(Error::Exists);
            }
        }
        Ok(())
    }

    /// Creates a file with a new name (FIL-06.6): it never replaces an existing one.
    /// `expected_len` is the plaintext size the checks ran on; other input stops.
    ///
    /// # Errors
    /// [`Error::Name`], [`Error::Exists`], [`Error::Recovery`], [`Error::Space`],
    /// [`Error::Budget`], [`Error::Input`], [`Error::Cancelled`], [`Error::Locked`],
    /// [`Error::Busy`], [`Error::Io`], [`Error::Uncertain`].
    pub fn create_file(
        &self,
        parent: &Node,
        name: &str,
        input: &mut dyn Read,
        expected_len: u64,
        control: Control<'_>,
    ) -> Result<Node, Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        self.bound(keys, parent)?;
        let parent_id = self.dir_id_of(parent)?;
        let clear = names::check_new(name)?;
        let folder = self.content_dir(keys, parent_id)?;
        self.refuse_collision(keys, &folder, parent_id, clear.expose(), None)?;
        let stored = Stored::of(keys, parent_id, clear.expose(), self.threshold)?;
        let stored_len = content::stored_len(expected_len)?;
        let mut record = self.begin(
            keys,
            OpKind::Create,
            parent_id,
            &stored,
            stored_len,
            stored_len,
        )?;
        let mut staging = self.stage_for(keys, &mut record)?;
        hit("create.after_journal")?;
        let sealed =
            self.seal_to_staging(keys, &mut staging, &record, input, expected_len, control);
        let done = match sealed {
            Ok((digest, _)) => {
                self.finish_create(keys, &mut staging, &mut record, &folder, &stored, digest)
            }
            Err(e) => {
                if !crashed() {
                    self.drop_incomplete(&record);
                }
                Err(e)
            }
        };
        let node = self.settle(
            &staging,
            done.map(|()| self.node(parent_id, stored, Kind::File, None)),
        )?;
        Ok(node)
    }

    fn finish_create(
        &self,
        keys: &MasterKeys,
        staging: &mut Staging,
        record: &mut Record,
        folder: &File,
        stored: &Stored,
        digest: Digest,
    ) -> Result<(), Error> {
        record.journal.new = Some(digest);
        record.set_state(keys, OpState::Staged)?;
        hit("create.after_stage")?;
        let published = self
            .publish(staging, STAGED, folder, stored)
            .and_then(|()| {
                hit("create.after_publish")?;
                record.set_state(keys, OpState::Published)
            });
        if let Err(e) = published {
            if !crashed() {
                // The ciphertext stays for review: the change did not happen.
                let _ = record.set_state(keys, OpState::Aborted);
            }
            return Err(e);
        }
        record.set_state(keys, OpState::Done)
    }

    /// New content for a file (FIL-06.6, FIL-06.11): `base` is the version the edit started
    /// from. The current version and the new one are durable here first. If storage holds
    /// anything else, or nothing, the edit is kept beside it: nothing is replaced.
    ///
    /// # Errors
    /// As [`Vault::create_file`]; [`Error::Conflict`] when a reserved name is taken by
    /// different data, with every copy kept.
    pub fn update_file(
        &self,
        node: &Node,
        base: &Digest,
        input: &mut dyn Read,
        expected_len: u64,
        control: Control<'_>,
    ) -> Result<Saved, Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        self.bound(keys, node)?;
        if node.kind != Kind::File {
            return Err(Error::Open);
        }
        let stored = node.stored.as_ref().ok_or(Error::Open)?;
        let folder = self.content_dir(keys, &node.parent)?;
        let new_len = content::stored_len(expected_len)?;
        let base_len = match self.place_of(&folder, stored, Kind::File) {
            Ok((dir, name)) => info_in(&dir, &name).map_or(0, |i| i.size),
            Err(_) => 0,
        };
        let keep = new_len.checked_add(base_len).ok_or(Error::Recovery)?;
        let mut record = self.begin(keys, OpKind::Update, &node.parent, stored, keep, new_len)?;
        let mut staging = self.stage_for(keys, &mut record)?;
        let done = self.update_steps(
            keys,
            &mut staging,
            &mut record,
            &folder,
            stored,
            *base,
            input,
            expected_len,
            control,
        );
        if let Err(e) = done {
            if crashed() {
                return Err(e);
            }
            if record.journal.new.is_none() {
                self.drop_incomplete(&record);
            } else if record.journal.state == OpState::Published {
                // The folder has the new version; what is left is for review.
                return self.settle(&staging, Err(Error::Uncertain));
            } else {
                let _ = record.set_state(keys, OpState::Aborted);
            }
            return self.settle(&staging, Err(e));
        }
        self.settle(&staging, done)
    }

    #[allow(clippy::too_many_arguments)]
    fn update_steps(
        &self,
        keys: &MasterKeys,
        staging: &mut Staging,
        record: &mut Record,
        folder: &File,
        stored: &Stored,
        base: Digest,
        input: &mut dyn Read,
        expected_len: u64,
        control: Control<'_>,
    ) -> Result<Saved, Error> {
        // The current version first, in the recovery store (FIL-06.6).
        let current = self.keep_base(keys, record, folder, stored, Kind::File)?;
        hit("update.after_base")?;
        let (digest, _) =
            self.seal_to_staging(keys, staging, record, input, expected_len, control)?;
        record.journal.new = Some(digest);
        record.set_state(keys, OpState::Staged)?;
        hit("update.after_stage")?;
        hit("update.before_swap")?;
        let unchanged = |c: &Copied| {
            c.digest == base
                && self
                    .place_of(folder, stored, Kind::File)
                    .is_ok_and(|(dir, name)| info_in(&dir, &name).is_ok_and(|now| now == c.source))
        };
        let Some(current) = current.filter(unchanged) else {
            // Different, missing, or changed since the copy: the edit is kept as a
            // conflict, and what storage holds stays (FIL-06.11).
            record.journal.kind = OpKind::Admit;
            record.save(keys)?;
            let outcome =
                self.admit_steps(keys, staging, record, folder, stored, STAGED, digest)?;
            record.set_state(keys, OpState::Done)?;
            return Ok(Saved { outcome, digest });
        };
        let outcome = self.swap_in_new(keys, staging, record, folder, stored, &current)?;
        record.set_state(keys, OpState::Done)?;
        Ok(Saved { outcome, digest })
    }

    /// Moves the staged version into place at once, then looks at what came out.
    #[allow(clippy::too_many_arguments)]
    fn swap_in_new(
        &self,
        keys: &MasterKeys,
        staging: &mut Staging,
        record: &mut Record,
        folder: &File,
        stored: &Stored,
        current: &Copied,
    ) -> Result<Outcome, Error> {
        self.still_allowed()?;
        let (dir, name) = self.place_of(folder, stored, Kind::File)?;
        let swapped = hit("update.swap").and_then(|()| {
            swap_in(&staging.dir, OsStr::new(STAGED), &dir, &name).map_err(|e| io(&e))
        });
        match swapped {
            Ok(()) => {}
            Err(cause) => {
                // Only a volume without the call is a reason to go the other way, still
                // exclusive at both steps; never a replace, a truncate or a direct write.
                if !self.swap_unsupported(&dir, &name)? || cause != Error::Io {
                    return Err(cause);
                }
                rename_new_in(&dir, &name, &staging.dir, OsStr::new(ASIDE)).map_err(|e| io(&e))?;
                rename_new_in(&staging.dir, OsStr::new(STAGED), &dir, &name)
                    .map_err(|e| taken(&e))?;
                rename_new_in(
                    &staging.dir,
                    OsStr::new(ASIDE),
                    &staging.dir,
                    OsStr::new(STAGED),
                )
                .map_err(|e| io(&e))?;
            }
        }
        dir.sync_all().map_err(|e| io(&e))?;
        staging.dir.sync_all().map_err(|e| io(&e))?;
        hit("update.after_swap")?;
        record.set_state(keys, OpState::Published)?;
        // What came out must be the version captured. Anything else is another writer's,
        // and is kept by the rule, whole (FIL-06.11).
        // The name now holds another object: it may go only once it is proven the copy
        // kept, so until then cleanup leaves it, and says so.
        staging.own.retain(|(n, _)| *n != STAGED);
        let out = OsStr::new(STAGED);
        let (came_out, _) = digest_of_file(&open_object(&staging.dir, out)?.0)?;
        if came_out == current.digest {
            remove_in(&staging.dir, out).map_err(|e| io(&e))?;
            staging.dir.sync_all().map_err(|e| io(&e))?;
            hit("update.after_old_removed")?;
            return Ok(Outcome::Replaced);
        }
        let kept = self.admit_steps(keys, staging, record, folder, stored, STAGED, came_out)?;
        if kept == Outcome::Identical {
            remove_in(&staging.dir, out).map_err(|e| io(&e))?;
        }
        Ok(Outcome::KeptBoth)
    }

    fn swap_unsupported(&self, dir: &File, name: &OsStr) -> Result<bool, Error> {
        #[cfg(test)]
        if crate::tests::swap_says_unsupported() {
            return Ok(true);
        }
        // Probe with the two names the same: a volume with the call answers at once.
        Ok(matches!(
            swap_in(dir, name, dir, name),
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported
        ))
    }

    /// A verified copy of the current object as this record's `base`, or `None` if it is
    /// gone. A hostile object stops the change.
    fn keep_base(
        &self,
        keys: &MasterKeys,
        record: &mut Record,
        folder: &File,
        stored: &Stored,
        kind: Kind,
    ) -> Result<Option<Copied>, Error> {
        let (dir, name) = match self.place_of(folder, stored, kind) {
            Ok(place) => place,
            Err(Error::Open) if matches!(info_in(folder, OsStr::new(stored.entry())), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if matches!(info_in(&dir, &name), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) {
            return Ok(None);
        }
        let mut copy = create_in(&record.dir, OsStr::new(BASE), 0o600).map_err(|e| io(&e))?;
        let mut go = |_: Phase, _: u64| true;
        let mut gate = self.gate(&mut go, Phase::Capture);
        let copied = copy_verified(&dir, &name, &mut copy, &mut gate)?;
        record.dir.sync_all().map_err(|e| io(&e))?;
        self.note_kept(copied.len);
        record.journal.base = Some(copied.digest);
        record.save(keys)?;
        Ok(Some(copied))
    }

    /// Keep Both (FIL-06.10). The original name always holds the smallest digest of the
    /// versions seen; every other is `conflict-<digest>.bin`, its ciphertext moved byte
    /// for byte; byte-identical versions are one. So any arrival order gives the same set.
    /// A reserved name taken by different data stops here, with everything kept.
    #[allow(clippy::too_many_arguments)]
    fn admit_steps(
        &self,
        keys: &MasterKeys,
        staging: &mut Staging,
        record: &Record,
        folder: &File,
        original: &Stored,
        candidate: &str,
        digest: Digest,
    ) -> Result<Outcome, Error> {
        let parent = record.journal.parent.clone();
        let current = self.current_digest(folder, original)?;
        let Some(current) = current else {
            self.publish(staging, candidate, folder, original)?;
            return Ok(Outcome::Replaced);
        };
        if current == digest {
            let (dir, name) = self.place_of(folder, original, Kind::File)?;
            let same = same_bytes(
                &open_object(&dir, &name)?.0,
                &open_object(&staging.dir, OsStr::new(candidate))?.0,
            )?;
            return if same {
                Ok(Outcome::Identical)
            } else {
                Err(Error::Conflict)
            };
        }
        if digest < current {
            let home = Stored::of(keys, &parent, &conflict_name(&current), self.threshold)?;
            match self.switch_home(staging, folder, original, folder, &home, Kind::File, false) {
                Ok(()) => {}
                Err(Error::Exists) => {
                    // Already kept under its name. Only byte-identical data goes.
                    let (kept_dir, kept_name) = self.place_of(folder, &home, Kind::File)?;
                    let kept = open_object(&kept_dir, &kept_name)?.0;
                    self.remove_duplicate(staging, folder, original, &kept)?;
                }
                Err(e) => return Err(e),
            }
            hit("admit.after_move_old")?;
            self.publish(staging, candidate, folder, original)?;
            return Ok(Outcome::KeptBoth);
        }
        let home = Stored::of(keys, &parent, &conflict_name(&digest), self.threshold)?;
        match self.publish(staging, candidate, folder, &home) {
            Ok(()) => Ok(Outcome::KeptBoth),
            Err(Error::Exists) => {
                let (kept_dir, kept_name) = self.place_of(folder, &home, Kind::File)?;
                let kept = open_object(&kept_dir, &kept_name)?.0;
                let cand = open_object(&staging.dir, OsStr::new(candidate))?.0;
                if same_bytes(&kept, &cand)? {
                    Ok(Outcome::Identical)
                } else {
                    Err(Error::Conflict)
                }
            }
            Err(e) => Err(e),
        }
    }

    fn current_digest(&self, folder: &File, stored: &Stored) -> Result<Option<Digest>, Error> {
        match self.place_of(folder, stored, Kind::File) {
            Ok((dir, name)) => digest_at(&dir, &name),
            Err(Error::Open) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Removes the file node at `stored` when its bytes equal `kept`, a copy kept under
    /// another name. The node goes aside into this operation's staging first, in one
    /// atomic step that takes whatever is there now, and only there is it compared and
    /// removed: a version another writer put at the name meanwhile goes back whole and the
    /// answer is a conflict. No name in the folder is looked at and then unlinked (F-340).
    fn remove_duplicate(
        &self,
        staging: &Staging,
        folder: &File,
        stored: &Stored,
        kept: &File,
    ) -> Result<(), Error> {
        hit("admit.before_duplicate")?;
        self.still_allowed()?;
        let (entry, dup) = (OsStr::new(stored.entry()), OsStr::new(DUPLICATE));
        rename_new_in(folder, entry, &staging.dir, dup).map_err(|e| io(&e))?;
        folder.sync_all().map_err(|e| io(&e))?;
        let (dir, name) = self.aside_object(staging, stored, DUPLICATE)?;
        if !same_bytes(kept, &open_object(&dir, &name)?.0)? {
            rename_new_in(&staging.dir, dup, folder, entry).map_err(|e| taken(&e))?;
            folder.sync_all().map_err(|e| io(&e))?;
            return Err(Error::Conflict);
        }
        if matches!(stored, Stored::Short { .. }) {
            remove_in(&dir, OsStr::new(CONTENTS)).map_err(|e| io(&e))?;
            remove_in(&dir, OsStr::new(INFLATED)).map_err(|e| io(&e))?;
            remove_dir_in(&staging.dir, dup).map_err(|e| io(&e))?;
        } else {
            remove_in(&staging.dir, dup).map_err(|e| io(&e))?;
        }
        staging.dir.sync_all().map_err(|e| io(&e))
    }

    /// Admits a version seen elsewhere, a provider's conflict copy say, as raw ciphertext:
    /// it is proven whole under this folder's keys first, a suffix is never believed
    /// (FIL-06.11), then kept by the rule of FIL-06.10.
    ///
    /// # Errors
    /// [`Error::Open`] for a version that does not prove itself, with nothing kept; others
    /// as [`Vault::update_file`].
    pub fn admit_version(
        &self,
        parent: &Node,
        name: &str,
        ciphertext: &mut dyn Read,
        expected_stored_len: u64,
        control: Control<'_>,
    ) -> Result<Saved, Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        self.bound(keys, parent)?;
        let parent_id = self.dir_id_of(parent)?;
        let clear = names::check_new(name)?;
        let folder = self.content_dir(keys, parent_id)?;
        let stored = Stored::of(keys, parent_id, clear.expose(), self.threshold)?;
        content::plan(expected_stored_len)?;
        let mut record = self.begin(
            keys,
            OpKind::Admit,
            parent_id,
            &stored,
            expected_stored_len,
            expected_stored_len,
        )?;
        let mut staging = self.stage_for(keys, &mut record)?;
        let mut gate = self.gate(control, Phase::Capture);
        let done = self.admit_copy(
            keys,
            &mut staging,
            &mut record,
            &folder,
            &stored,
            ciphertext,
            expected_stored_len,
            &mut gate,
        );
        if done.is_err() && !crashed() && record.journal.new.is_none() {
            self.drop_incomplete(&record);
        } else if done.is_err() && !crashed() {
            let _ = record.set_state(keys, OpState::Aborted);
        }
        self.settle(&staging, done)
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_copy(
        &self,
        keys: &MasterKeys,
        staging: &mut Staging,
        record: &mut Record,
        folder: &File,
        stored: &Stored,
        ciphertext: &mut dyn Read,
        expected: u64,
        gate: &mut Gate<'_>,
    ) -> Result<Saved, Error> {
        let mut staged = create_in(&staging.dir, OsStr::new(STAGED), 0o600).map_err(|e| io(&e))?;
        staging
            .own
            .push((STAGED, identity(&info_of(&staged).map_err(|e| io(&e))?)));
        let mut kept = create_in(&record.dir, OsStr::new(NEW), 0o600).map_err(|e| io(&e))?;
        let mut hasher = Hasher::new(Algorithm::Sha256);
        let mut block = vec![0u8; COMPARE_BLOCK];
        let mut total = 0u64;
        loop {
            let got = match ciphertext.read(&mut block) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io(&e)),
            };
            if got == 0 {
                break;
            }
            let part = block.get(..got).ok_or(Error::Io)?;
            total = total.saturating_add(u64::try_from(got).map_err(|_| Error::Io)?);
            if total > expected {
                return Err(Error::Input);
            }
            staged.write_all(part).map_err(|e| io(&e))?;
            kept.write_all(part).map_err(|e| io(&e))?;
            hasher.update(part);
            gate.pass(u64::try_from(got).map_err(|_| Error::Io)?)?;
        }
        if total != expected {
            return Err(Error::Input);
        }
        staged.sync_all().map_err(|e| io(&e))?;
        kept.sync_all().map_err(|e| io(&e))?;
        let reader = open_object(&staging.dir, OsStr::new(STAGED))?.0;
        self.prove_stored(keys, &reader, total)?;
        let digest = Digest::from_hash(hasher.finalize().expose())?;
        self.note_kept(total);
        record.journal.new = Some(digest);
        record.set_state(keys, OpState::Staged)?;
        hit("admit.after_stage")?;
        let outcome = self.admit_steps(keys, staging, record, folder, stored, STAGED, digest)?;
        record.set_state(keys, OpState::Done)?;
        Ok(Saved { outcome, digest })
    }

    /// Proves a whole stored file, with the plaintext thrown away.
    fn prove_stored(&self, keys: &MasterKeys, file: &File, len: u64) -> Result<(), Error> {
        use std::os::unix::fs::FileExt;
        let plan = content::plan(len)?;
        let mut header = [0u8; content::HEADER];
        file.read_exact_at(&mut header, 0)
            .map_err(|_| Error::Open)?;
        let (key, nonce) = content::open_header(keys, &header)?;
        let mut go = |_: Phase, _: u64| true;
        let mut gate = self.gate(&mut go, Phase::Validate);
        content::open_chunks(
            &key,
            &nonce,
            plan,
            self.workers_for(plan.chunks),
            &mut |at, room| file.read_exact_at(room, at).map_err(|_| Error::Open),
            &mut gate,
            &mut |_| Ok(()),
        )
    }

    /// Makes a folder (FIL-04.10): its content folder and backup first, then its node.
    /// Until the node is there the folder is unreachable, and a crash leaves only what
    /// `resume` removes by its exact names.
    ///
    /// # Errors
    /// As [`Vault::create_file`].
    pub fn make_dir(&self, parent: &Node, name: &str) -> Result<Node, Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        self.bound(keys, parent)?;
        let parent_id = self.dir_id_of(parent)?;
        let clear = names::check_new(name)?;
        let folder = self.content_dir(keys, parent_id)?;
        self.refuse_collision(keys, &folder, parent_id, clear.expose(), None)?;
        let stored = Stored::of(keys, parent_id, clear.expose(), self.threshold)?;
        let id = random::uuid_v4().map_err(|_| Error::Io)?;
        let id = crate::format::uuid_text(&id).into_bytes();
        let mut record = self.begin(
            keys,
            OpKind::Mkdir,
            parent_id,
            &stored,
            0,
            JOURNAL_ALLOWANCE,
        )?;
        record.journal.dir_id = Some(id.clone());
        let mut staging = self.stage_for(keys, &mut record)?;
        let done = self.make_dir_steps(keys, &mut staging, &mut record, &folder, &stored, &id);
        if let Err(e) = done {
            if !crashed() {
                let _ = self.remove_content_dir(keys, &id);
                let _ = record.set_state(keys, OpState::Aborted);
            }
            return self.settle(&staging, Err(e));
        }
        self.settle(
            &staging,
            Ok(self.node(parent_id, stored, Kind::Dir, Some(id))),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_dir_steps(
        &self,
        keys: &MasterKeys,
        staging: &mut Staging,
        record: &mut Record,
        folder: &File,
        stored: &Stored,
        id: &[u8],
    ) -> Result<(), Error> {
        self.make_content_dir(keys, id)?;
        hit("mkdir.after_content")?;
        let home = match stored {
            Stored::Plain(_) => {
                make_dir_in(&staging.dir, OsStr::new(HOME), 0o700).map_err(|e| io(&e))?;
                let home = open_dir_in(&staging.dir, OsStr::new(HOME)).map_err(|e| io(&e))?;
                staging
                    .own
                    .push((HOME, identity(&info_of(&home).map_err(|e| io(&e))?)));
                home
            }
            Stored::Short { inflated, .. } => self.short_home(staging, inflated)?,
        };
        write_new(&home, DIR_FILE, id)?;
        home.sync_all().map_err(|e| io(&e))?;
        self.still_allowed()?;
        rename_new_in(
            &staging.dir,
            OsStr::new(HOME),
            folder,
            OsStr::new(stored.entry()),
        )
        .map_err(|e| taken(&e))?;
        folder.sync_all().map_err(|e| io(&e))?;
        hit("mkdir.after_link")?;
        record.set_state(keys, OpState::Done)
    }

    /// Removes a directory's content folder and backup, by their exact names, if that is
    /// all it holds; the shared first-level folder goes only when empty.
    fn remove_content_dir(&self, keys: &MasterKeys, id: &[u8]) -> Result<(), Error> {
        let (first, second) = names::dir_path(keys, id)?;
        let d = self.child_dir(&self.root, "d")?;
        let first_dir = self.child_dir(&d, &first)?;
        let content = self.child_dir(&first_dir, &second)?;
        match remove_in(&content, OsStr::new(BACKUP)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(&e)),
        }
        remove_dir_in(&first_dir, OsStr::new(&second)).map_err(|e| io(&e))?;
        let _ = remove_dir_in(&d, OsStr::new(&first));
        d.sync_all().map_err(|e| io(&e))
    }

    /// Moves a node to a new home with no replacing. A plain move is one atomic step. Any
    /// other is three: make the new home, switch the object, remove the old home; the
    /// source stays reachable until the new state is durable, and `resuming` finishes the
    /// steps a crash left (FIL-06.7).
    #[allow(clippy::too_many_arguments)]
    fn switch_home(
        &self,
        staging: &mut Staging,
        from_folder: &File,
        from: &Stored,
        to_folder: &File,
        to: &Stored,
        kind: Kind,
        resuming: bool,
    ) -> Result<(), Error> {
        hit("rename.before_switch")?;
        self.still_allowed()?;
        if let (Stored::Plain(a), Stored::Plain(b)) = (from, to)
            && !resuming
        {
            rename_new_in(from_folder, OsStr::new(a), to_folder, OsStr::new(b))
                .map_err(|e| taken(&e))?;
            from_folder.sync_all().map_err(|e| io(&e))?;
            return to_folder.sync_all().map_err(|e| io(&e));
        }
        let entry = OsStr::new(to.entry());
        let home_there = info_in(to_folder, entry).is_ok();
        let plain_file = matches!(to, Stored::Plain(_)) && kind == Kind::File;
        if home_there && !resuming {
            return Err(Error::Exists);
        }
        if !home_there && !plain_file {
            let home = match to {
                Stored::Plain(_) => {
                    make_dir_in(&staging.dir, OsStr::new(HOME), 0o700).map_err(|e| io(&e))?;
                    let home = open_dir_in(&staging.dir, OsStr::new(HOME)).map_err(|e| io(&e))?;
                    staging
                        .own
                        .push((HOME, identity(&info_of(&home).map_err(|e| io(&e))?)));
                    home
                }
                Stored::Short { inflated, .. } => self.short_home(staging, inflated)?,
            };
            home.sync_all().map_err(|e| io(&e))?;
            rename_new_in(&staging.dir, OsStr::new(HOME), to_folder, entry)
                .map_err(|e| taken(&e))?;
            to_folder.sync_all().map_err(|e| io(&e))?;
        }
        hit("rename.after_partial")?;
        let source = self.place_of(from_folder, from, kind);
        let target = if plain_file {
            Ok((
                to_folder.try_clone().map_err(|e| io(&e))?,
                OsString::from(to.entry()),
            ))
        } else {
            self.place_of(to_folder, to, kind)
        }?;
        if let Ok((src_dir, src_name)) = &source {
            let moved = rename_new_in(src_dir, src_name, &target.0, &target.1);
            match moved {
                Ok(()) => {
                    src_dir.sync_all().map_err(|e| io(&e))?;
                    target.0.sync_all().map_err(|e| io(&e))?;
                }
                // Resuming, the object may have gone over before the crash.
                Err(e) if resuming && e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) if resuming && e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(taken(&e)),
            }
        } else if !resuming {
            return Err(Error::Changed);
        }
        hit("rename.after_switch")?;
        self.remove_old_home(from_folder, from, kind)?;
        from_folder.sync_all().map_err(|e| io(&e))
    }

    /// The old home of a moved node, by its exact parts. It goes only when empty.
    fn remove_old_home(&self, folder: &File, stored: &Stored, kind: Kind) -> Result<(), Error> {
        let entry = OsStr::new(stored.entry());
        match stored {
            Stored::Plain(_) if kind == Kind::File => Ok(()),
            Stored::Plain(_) => match remove_dir_in(folder, entry) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(io(&e)),
            },
            Stored::Short { .. } => {
                let Ok(home) = open_dir_in(folder, entry) else {
                    return Ok(());
                };
                let _ = remove_in(&home, OsStr::new(INFLATED));
                match remove_dir_in(folder, entry) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(io(&e)),
                }
            }
        }
    }

    /// Gives a file or folder a new name or a new place (FIL-06.7, FIL-06.12). The stored
    /// content does not change, not one byte. A handle that is out of date finds nothing
    /// to move, and says so: the node and the new parent are read again first, and a
    /// folder's must still hold the handle's directory ID.
    ///
    /// # Errors
    /// [`Error::Changed`] when the node or the new parent is no longer the one the handle
    /// named; [`Error::Inside`] for a folder moved into itself or below itself; others as
    /// [`Vault::create_file`].
    pub fn rename(&self, node: &Node, new_parent: &Node, new_name: &str) -> Result<Node, Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        self.bound(keys, node)?;
        if !matches!(node.kind, Kind::File | Kind::Dir) {
            return Err(Error::Open);
        }
        let from = node.stored.as_ref().ok_or(Error::Open)?;
        self.bound(keys, new_parent)?;
        let to_parent = self.dir_id_of(new_parent)?;
        let clear = names::check_new(new_name)?;
        let from_folder = self.content_dir(keys, &node.parent)?;
        let to_folder = self.content_dir(keys, to_parent)?;
        if info_in(&from_folder, OsStr::new(from.entry())).is_err() {
            return Err(Error::Changed);
        }
        let same_folder = node.parent == to_parent;
        // FIL-06.7: a folder moved into itself or below itself would leave the tree with
        // its whole subtree. Refused before anything changes, as POSIX rename does.
        if let (Kind::Dir, Some(id), false) = (node.kind, &node.dir_id, same_folder)
            && (to_parent == id.as_slice() || self.ids_below(keys, id, None)?.contains(to_parent))
        {
            return Err(Error::Inside);
        }
        self.refuse_collision(
            keys,
            &to_folder,
            to_parent,
            clear.expose(),
            same_folder.then_some(from),
        )?;
        let to = Stored::of(keys, to_parent, clear.expose(), self.threshold)?;
        if same_folder && to == *from {
            return Ok(node.clone());
        }
        let mut record = self.begin(
            keys,
            OpKind::Rename,
            &node.parent,
            from,
            0,
            JOURNAL_ALLOWANCE,
        )?;
        record.journal.to = Some((to_parent.to_vec(), to.clone()));
        record.journal.node_is_dir = node.kind == Kind::Dir;
        let mut staging = self.stage_for(keys, &mut record)?;
        let moved = self.switch_home(
            &mut staging,
            &from_folder,
            from,
            &to_folder,
            &to,
            node.kind,
            false,
        );
        let moved = moved.and_then(|()| record.set_state(keys, OpState::Done));
        if moved.is_err() && !crashed() {
            let _ = record.set_state(keys, OpState::Aborted);
        }
        self.settle(&staging, moved)?;
        Ok(self.node(to_parent, to, node.kind, node.dir_id.clone()))
    }

    /// Deletes a file (FIL-06.12): its version is durable here first, and if storage holds
    /// anything but `base` the deletion stays pending and the file stays. Nothing but this
    /// exact version is removed.
    ///
    /// # Errors
    /// [`Error::DeleteConflict`] for another version, [`Error::Changed`] for a file already
    /// gone; others as [`Vault::create_file`].
    pub fn delete_file(&self, node: &Node, base: &Digest) -> Result<(), Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        self.bound(keys, node)?;
        self.delete_file_inner(keys, node, *base)
    }

    fn delete_file_inner(&self, keys: &MasterKeys, node: &Node, base: Digest) -> Result<(), Error> {
        if node.kind != Kind::File {
            return Err(Error::Open);
        }
        let stored = node.stored.as_ref().ok_or(Error::Open)?;
        let folder = self.content_dir(keys, &node.parent)?;
        let (dir, name) = self.place_of(&folder, stored, Kind::File)?;
        let size = info_in(&dir, &name)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Error::Changed
                } else {
                    io(&e)
                }
            })?
            .size;
        let mut record = self.begin(
            keys,
            OpKind::Delete,
            &node.parent,
            stored,
            size,
            JOURNAL_ALLOWANCE,
        )?;
        let mut staging = self.stage_for(keys, &mut record)?;
        let done = self.delete_steps(keys, &mut staging, &mut record, &folder, stored, base);
        if done.is_err() && !crashed() && record.journal.state == OpState::Begun {
            let _ = record.set_state(keys, OpState::Aborted);
        }
        self.settle(&staging, done)
    }

    fn delete_steps(
        &self,
        keys: &MasterKeys,
        staging: &mut Staging,
        record: &mut Record,
        folder: &File,
        stored: &Stored,
        base: Digest,
    ) -> Result<(), Error> {
        let current = self.keep_base(keys, record, folder, stored, Kind::File)?;
        hit("delete.after_base")?;
        let current = current.ok_or(Error::Changed)?;
        if current.digest != base {
            record.set_state(keys, OpState::Pending)?;
            return Err(Error::DeleteConflict);
        }
        self.still_allowed()?;
        let entry = OsStr::new(stored.entry());
        rename_new_in(folder, entry, &staging.dir, OsStr::new(ASIDE)).map_err(|e| io(&e))?;
        let aside = info_in(&staging.dir, OsStr::new(ASIDE)).map_err(|e| io(&e))?;
        staging.own.push((ASIDE, identity(&aside)));
        folder.sync_all().map_err(|e| io(&e))?;
        staging.dir.sync_all().map_err(|e| io(&e))?;
        hit("delete.after_aside")?;
        // What came out must be the version kept. Anything else goes back where it was.
        let (now_dir, now_name) = self.aside_object(staging, stored, ASIDE)?;
        let (seen, _) = digest_of_file(&open_object(&now_dir, &now_name)?.0)?;
        if seen != current.digest {
            staging.own.retain(|(n, _)| *n != ASIDE);
            record.set_state(keys, OpState::Pending)?;
            rename_new_in(&staging.dir, OsStr::new(ASIDE), folder, entry).map_err(|e| taken(&e))?;
            folder.sync_all().map_err(|e| io(&e))?;
            return Err(Error::DeleteConflict);
        }
        record.set_state(keys, OpState::Published)?;
        record.set_state(keys, OpState::Done)
    }

    /// Where the content of a file node moved aside under `aside` in staging is.
    fn aside_object(
        &self,
        staging: &Staging,
        stored: &Stored,
        aside: &str,
    ) -> Result<(File, OsString), Error> {
        match stored {
            Stored::Plain(_) => Ok((
                staging.dir.try_clone().map_err(|e| io(&e))?,
                OsString::from(aside),
            )),
            Stored::Short { .. } => Ok((
                open_dir_in(&staging.dir, OsStr::new(aside)).map_err(|e| io(&e))?,
                OsString::from(CONTENTS),
            )),
        }
    }

    /// Deletes an empty folder (FIL-06.12): its node goes aside, then its content folder
    /// and backup by their exact names. A folder with anything in it stays. When another
    /// live folder uses the same directory ID, found by the same walk of the whole folder
    /// a tree delete makes (with its limits, see [`Vault::delete_tree`]), only this node
    /// goes and the content stays for the other. The top folder is never deleted.
    ///
    /// # Errors
    /// [`Error::DeleteConflict`] for a folder that is not empty; [`Error::Changed`] for a
    /// handle that is out of date; [`Error::Open`] for the top folder or a walk limit;
    /// others as [`Vault::create_file`].
    pub fn delete_dir(&self, node: &Node) -> Result<(), Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        self.bound(keys, node)?;
        let id = self.dir_id_of(node)?;
        if node.stored.is_none() {
            return Err(Error::Open);
        }
        if !Self::holds_only_backup(&self.content_dir(keys, id)?)? {
            return Err(Error::DeleteConflict);
        }
        let shared = self.ids_below(keys, b"", Some(node))?.contains(id);
        self.delete_dir_inner(keys, node, shared)
    }

    fn holds_only_backup(folder: &File) -> Result<bool, Error> {
        let names = names_in(folder, 2).map_err(|e| io(&e))?;
        Ok(names.iter().all(|n| n == BACKUP))
    }

    /// `shared`: another live folder uses this ID (FIL-06.12), so its content is that
    /// folder's too and stays; only this node goes.
    fn delete_dir_inner(&self, keys: &MasterKeys, node: &Node, shared: bool) -> Result<(), Error> {
        let id = self.dir_id_of(node)?.to_vec();
        if node.stored.is_none() {
            return Err(Error::Open);
        }
        let stored = node.stored.as_ref().ok_or(Error::Open)?;
        let content = if shared {
            None
        } else {
            Some(self.content_dir(keys, &id)?)
        };
        if let Some(content) = &content
            && !Self::holds_only_backup(content)?
        {
            return Err(Error::DeleteConflict);
        }
        let folder = self.content_dir(keys, &node.parent)?;
        let mut record = self.begin(
            keys,
            OpKind::Rmdir,
            &node.parent,
            stored,
            4096,
            JOURNAL_ALLOWANCE,
        )?;
        // No ID in the journal for a shared one: a resume then removes no content either.
        record.journal.dir_id = content.is_some().then(|| id.clone());
        let mut staging = self.stage_for(keys, &mut record)?;
        let done = self.delete_dir_steps(
            keys,
            &mut staging,
            &mut record,
            &folder,
            content.as_ref(),
            stored,
            &id,
        );
        if done.is_err() && !crashed() && record.journal.state == OpState::Begun {
            let _ = record.set_state(keys, OpState::Aborted);
        }
        self.settle(&staging, done)
    }

    #[allow(clippy::too_many_arguments)]
    fn delete_dir_steps(
        &self,
        keys: &MasterKeys,
        staging: &mut Staging,
        record: &mut Record,
        folder: &File,
        content: Option<&File>,
        stored: &Stored,
        id: &[u8],
    ) -> Result<(), Error> {
        hit("rmdir.before_aside")?;
        self.still_allowed()?;
        let entry = OsStr::new(stored.entry());
        rename_new_in(folder, entry, &staging.dir, OsStr::new(ASIDE)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Changed
            } else {
                io(&e)
            }
        })?;
        let aside = info_in(&staging.dir, OsStr::new(ASIDE)).map_err(|e| io(&e))?;
        staging.own.push((ASIDE, identity(&aside)));
        folder.sync_all().map_err(|e| io(&e))?;
        // FIL-06.8: what came out must hold the handle's ID; another node goes back.
        let came_out = open_dir_in(&staging.dir, OsStr::new(ASIDE))
            .ok()
            .and_then(|n| read_small(&n, DIR_FILE, MAX_DIR_ID).ok());
        if came_out.as_deref() != Some(id) {
            staging.own.retain(|(n, _)| *n != ASIDE);
            rename_new_in(&staging.dir, OsStr::new(ASIDE), folder, entry).map_err(|e| taken(&e))?;
            folder.sync_all().map_err(|e| io(&e))?;
            return Err(Error::Changed);
        }
        record.set_state(keys, OpState::Published)?;
        hit("rmdir.after_aside")?;
        let Some(content) = content else {
            return record.set_state(keys, OpState::Done);
        };
        if !Self::holds_only_backup(content)? {
            // An item arrived meanwhile: nothing that holds anything is removed.
            staging.own.retain(|(n, _)| *n != ASIDE);
            record.set_state(keys, OpState::Pending)?;
            rename_new_in(&staging.dir, OsStr::new(ASIDE), folder, entry).map_err(|e| taken(&e))?;
            folder.sync_all().map_err(|e| io(&e))?;
            return Err(Error::DeleteConflict);
        }
        self.remove_content_dir(keys, id)?;
        hit("rmdir.after_content")?;
        record.set_state(keys, OpState::Done)
    }

    /// Deletes a folder and all it holds (FIL-06.12): a bounded look first, with no
    /// following of a directory ID seen twice, nor of one that a live folder outside the
    /// subtree also uses (only that node goes); every file's ciphertext is durable here
    /// before it goes. Any invalid, link or unknown node stops the whole thing before
    /// anything is removed, and a change on the way stops at that item: what was already
    /// removed is in recovery, and what was not is untouched.
    ///
    /// The IDs used outside come from one walk of the whole folder before anything else,
    /// and it fails closed: a folder anywhere with more than 10,000 items, or more than
    /// 1,000,000 nodes in all, refuses the delete with nothing changed, and a lock waits
    /// for the walk as for any running operation. The top folder itself is never deleted
    /// (FIL-06.3: work is below the selected root).
    ///
    /// # Errors
    /// [`Error::Open`] for the top folder, a node that gives no authority or a limit;
    /// [`Error::Changed`] for a handle that is out of date; others as
    /// [`Vault::delete_file`].
    pub fn delete_tree(&self, node: &Node) -> Result<(), Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        self.bound(keys, node)?;
        if node.stored.is_none() {
            return Err(Error::Open);
        }
        // FIL-06.12: the IDs folders outside this subtree use are never followed.
        let outside = self.ids_below(keys, b"", Some(node))?;
        let mut order = Vec::new();
        let mut seen = BTreeSet::new();
        let mut count = 0usize;
        let mut bytes = 0u64;
        self.survey(
            keys, node, 0, &outside, &mut seen, &mut count, &mut bytes, &mut order,
        )?;
        self.preflight(bytes, JOURNAL_ALLOWANCE)?;
        for (item, digest) in order {
            match item.kind {
                Kind::File => self.delete_file_inner(keys, &item, digest.ok_or(Error::Open)?)?,
                _ => {
                    let shared = item.dir_id.as_ref().is_some_and(|id| outside.contains(id));
                    self.delete_dir_inner(keys, &item, shared)?;
                }
            }
        }
        Ok(())
    }

    /// Every directory ID that a valid folder node reachable from directory `from` holds.
    /// The walk enters each ID once, never enters the node `skip`, and stops at the tree
    /// limits of FIL-06.3 with [`Error::Open`]. A folder node with no content folder
    /// behind it holds nothing below.
    // One whole scan per call; a local ID index if large folders move or go often.
    fn ids_below(
        &self,
        keys: &MasterKeys,
        from: &[u8],
        skip: Option<&Node>,
    ) -> Result<BTreeSet<Vec<u8>>, Error> {
        let skipped = skip.and_then(|s| Some((s.parent.as_slice(), s.stored.as_ref()?.entry())));
        let mut found = BTreeSet::new();
        let mut todo = vec![from.to_vec()];
        let mut count = 0usize;
        while let Some(id) = todo.pop() {
            let folder = match self.content_dir(keys, &id) {
                Ok(folder) => folder,
                Err(Error::Open) => continue,
                Err(e) => return Err(e),
            };
            let raw = names_in(&folder, MAX_CHILDREN.saturating_add(1)).map_err(|e| io(&e))?;
            if raw.len() > MAX_CHILDREN.saturating_add(1) {
                return Err(Error::Open);
            }
            for entry in raw {
                if entry == BACKUP || skipped.is_some_and(|(p, e)| p == id && entry == e) {
                    continue;
                }
                count = count.saturating_add(1);
                if count > self.node_limit() {
                    return Err(Error::Open);
                }
                let row = self.classify(keys, &folder, &id, &entry);
                if let (Kind::Dir, Some(child)) = (row.kind, row.node.dir_id)
                    && found.insert(child.clone())
                {
                    todo.push(child);
                }
            }
        }
        Ok(found)
    }

    /// One folder of the look before a tree delete: children first, bounded, each version
    /// read now, so a later change is seen as one. A folder whose ID a folder outside the
    /// subtree also uses is not followed: only its node goes (FIL-06.12).
    #[allow(clippy::too_many_arguments)]
    fn survey(
        &self,
        keys: &MasterKeys,
        node: &Node,
        depth: usize,
        outside: &BTreeSet<Vec<u8>>,
        seen: &mut BTreeSet<Vec<u8>>,
        count: &mut usize,
        bytes: &mut u64,
        order: &mut Vec<(Node, Option<Digest>)>,
    ) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Open);
        }
        let id = self.dir_id_of(node)?.to_vec();
        if !seen.insert(id.clone()) {
            return Err(Error::Open);
        }
        if outside.contains(&id) {
            order.push((node.clone(), None));
            return Ok(());
        }
        let folder = self.content_dir(keys, &id)?;
        let raw = names_in(&folder, MAX_CHILDREN.saturating_add(1)).map_err(|e| io(&e))?;
        if raw.len() > MAX_CHILDREN.saturating_add(1) {
            return Err(Error::Open);
        }
        for entry in raw {
            if entry == BACKUP {
                continue;
            }
            *count = count.saturating_add(1);
            if *count > self.node_limit() {
                return Err(Error::Open);
            }
            let row = self.classify(keys, &folder, &id, &entry);
            match row.kind {
                Kind::File => {
                    let stored = row.node.stored.as_ref().ok_or(Error::Open)?;
                    let (dir, name) = self.place_of(&folder, stored, Kind::File)?;
                    let (file, info) = open_object(&dir, &name)?;
                    *bytes = bytes.saturating_add(info.size);
                    let (digest, _) = digest_of_file(&file)?;
                    order.push((row.node, Some(digest)));
                }
                Kind::Dir => {
                    self.survey(
                        keys,
                        &row.node,
                        depth.saturating_add(1),
                        outside,
                        seen,
                        count,
                        bytes,
                        order,
                    )?;
                }
                _ => return Err(Error::Open),
            }
        }
        order.push((node.clone(), None));
        Ok(())
    }

    /// Finishes or marks every record a crash left, by exact names only (FIL-06.7). A
    /// record that does not prove itself is left alone. A record whose repair fails stays
    /// as it is, for review; the folder still opens.
    pub(crate) fn resume_records(&self) -> Result<(), Error> {
        let turn = self.reading()?;
        let keys = turn.keys()?;
        check_private(&self.recovery)?;
        let mut used = 0u64;
        for name in names_in(&self.recovery, MAX_NODES).map_err(|e| io(&e))? {
            let Some(id) = name.to_str().filter(|n| n.starts_with("op-")) else {
                continue;
            };
            let Ok(dir) = open_dir_in(&self.recovery, &name) else {
                continue;
            };
            used = used.saturating_add(JOURNAL_ALLOWANCE);
            for copy in [BASE, NEW] {
                if let Ok(i) = info_in(&dir, OsStr::new(copy)) {
                    used = used.saturating_add(i.size);
                }
            }
            clear_journal_scratch(&dir);
            let Some(journal) = read_journal(keys, &dir, id)? else {
                continue;
            };
            if matches!(
                journal.state,
                OpState::Done | OpState::Aborted | OpState::Pending
            ) {
                continue;
            }
            let mut record = Record { dir, journal };
            let _ = self.resume_one(keys, &mut record);
        }
        self.recovery_used.store(used, Ordering::SeqCst);
        Ok(())
    }

    fn staging_of(&self, journal: &Journal) -> Option<Staging> {
        let name = journal.staging.as_deref()?;
        if !name.starts_with(STAGING_PREFIX) {
            return None;
        }
        let dir = open_dir_in(&self.root, OsStr::new(name)).ok()?;
        Some(Staging {
            name: OsString::from(name),
            dir,
            own: Vec::new(),
        })
    }

    /// Removes a known name from staging only when it holds a version this record proves.
    fn clear_known(staging: &Staging, name: &str, proven: &[Option<Digest>]) {
        let os = OsStr::new(name);
        if let Ok(Some(digest)) = digest_at(&staging.dir, os)
            && proven.contains(&Some(digest))
        {
            let _ = remove_in(&staging.dir, os);
        }
    }

    /// Removes an aside node of known shape: its exact parts, then the empty folder.
    fn clear_aside(staging: &Staging) {
        let os = OsStr::new(ASIDE);
        if let Ok(node) = open_dir_in(&staging.dir, os) {
            for inner in [INFLATED, CONTENTS, DIR_FILE] {
                let _ = remove_in(&node, OsStr::new(inner));
            }
            let _ = remove_dir_in(&staging.dir, os);
        }
    }

    fn clear_home(staging: &Staging) {
        let os = OsStr::new(HOME);
        if let Ok(node) = open_dir_in(&staging.dir, os) {
            let _ = remove_in(&node, OsStr::new(INFLATED));
            let _ = remove_in(&node, OsStr::new(DIR_FILE));
            let _ = remove_dir_in(&staging.dir, os);
        }
    }

    fn resume_one(&self, keys: &MasterKeys, record: &mut Record) -> Result<(), Error> {
        let journal = record.journal.clone();
        let mut staging = self.staging_of(&journal);
        let folder = self.content_dir(keys, &journal.parent)?;
        if journal.new.is_none()
            && matches!(
                journal.kind,
                OpKind::Create | OpKind::Update | OpKind::Admit
            )
        {
            // It never finished writing, so nothing can have gone out: both partial
            // copies are this record's own, and prove nothing.
            let _ = remove_in(&record.dir, OsStr::new(NEW));
            if let Some(staging) = staging.as_ref() {
                let _ = remove_in(&staging.dir, OsStr::new(STAGED));
                let _ = self.close_staging(staging);
            }
            return record.set_state(keys, OpState::Aborted);
        }
        let end = match journal.kind {
            OpKind::Create => {
                let now = self.current_digest(&folder, &journal.stored)?;
                if journal.new.is_some() && now == journal.new {
                    OpState::Done
                } else {
                    OpState::Aborted
                }
            }
            OpKind::Update | OpKind::Admit => {
                self.resume_version(keys, record, staging.as_mut(), &folder)?
            }
            OpKind::Delete => self.resume_delete(staging.as_mut(), &folder, &journal)?,
            OpKind::Mkdir => {
                if info_in(&folder, OsStr::new(journal.stored.entry())).is_ok() {
                    OpState::Done
                } else {
                    if let Some(id) = &journal.dir_id {
                        let _ = self.remove_content_dir(keys, id);
                    }
                    OpState::Aborted
                }
            }
            OpKind::Rmdir => self.resume_rmdir(keys, staging.as_ref(), &folder, &journal)?,
            OpKind::Rename => self.resume_rename(keys, staging.as_mut(), &folder, &journal)?,
        };
        if let Some(staging) = staging.as_ref() {
            Self::clear_known(staging, STAGED, &[journal.base, journal.new]);
            Self::clear_known(staging, ASIDE, &[journal.base]);
            Self::clear_aside(staging);
            Self::clear_home(staging);
            let _ = self.close_staging(staging);
        }
        record.set_state(keys, end)
    }

    /// An update or a kept version a crash stopped. The staged name holds the new version
    /// (nothing happened), the old one (the swap happened), or another writer's: kept.
    fn resume_version(
        &self,
        keys: &MasterKeys,
        record: &Record,
        staging: Option<&mut Staging>,
        folder: &File,
    ) -> Result<OpState, Error> {
        let journal = &record.journal;
        let Some(staging) = staging else {
            return Ok(
                if self.current_digest(folder, &journal.stored)? == journal.new {
                    OpState::Done
                } else {
                    OpState::Aborted
                },
            );
        };
        let staged = digest_at(&staging.dir, OsStr::new(STAGED))?;
        let current = self.current_digest(folder, &journal.stored)?;
        Ok(match (staged, journal.kind) {
            (None, _) => {
                if current == journal.new {
                    OpState::Done
                } else {
                    OpState::Aborted
                }
            }
            (Some(d), OpKind::Update)
                if Some(d) == journal.new
                    && current.is_some()
                    && journal.state == OpState::Staged =>
            {
                OpState::Aborted
            }
            (Some(d), OpKind::Update) if Some(d) == journal.base && current == journal.new => {
                OpState::Done
            }
            (Some(d), _) => {
                self.admit_steps(keys, staging, record, folder, &journal.stored, STAGED, d)?;
                OpState::Done
            }
        })
    }

    fn resume_delete(
        &self,
        staging: Option<&mut Staging>,
        folder: &File,
        journal: &Journal,
    ) -> Result<OpState, Error> {
        let Some(staging) = staging else {
            return Ok(OpState::Aborted);
        };
        let Ok((dir, name)) = self.aside_object(staging, &journal.stored, ASIDE) else {
            return Ok(OpState::Aborted);
        };
        match digest_at(&dir, &name) {
            Ok(Some(seen)) if Some(seen) == journal.base => Ok(OpState::Done),
            Ok(Some(_)) => {
                // Not the version kept: back where it was, or it stays where it is.
                let entry = OsStr::new(journal.stored.entry());
                rename_new_in(&staging.dir, OsStr::new(ASIDE), folder, entry)
                    .map_err(|e| taken(&e))?;
                Ok(OpState::Pending)
            }
            _ => Ok(OpState::Aborted),
        }
    }

    /// A folder delete a crash stopped, finished as the live path finishes it (FIL-06.12):
    /// a node aside that holds another ID goes back to its place (FIL-06.8); the content
    /// folder goes only when it holds nothing but its backup; an item that arrived
    /// meanwhile keeps it, the node goes back beside it, and the deletion is pending. A
    /// shared node's record names no ID: only its node goes.
    fn resume_rmdir(
        &self,
        keys: &MasterKeys,
        staging: Option<&Staging>,
        folder: &File,
        journal: &Journal,
    ) -> Result<OpState, Error> {
        let entry = OsStr::new(journal.stored.entry());
        if info_in(folder, entry).is_ok() {
            return Ok(OpState::Aborted);
        }
        let Some(id) = &journal.dir_id else {
            return Ok(OpState::Done);
        };
        if let Some(staging) = staging
            && info_in(&staging.dir, OsStr::new(ASIDE)).is_ok()
        {
            let aside = open_dir_in(&staging.dir, OsStr::new(ASIDE))
                .ok()
                .and_then(|n| read_small(&n, DIR_FILE, MAX_DIR_ID).ok());
            if aside.as_deref() != Some(id.as_slice()) {
                rename_new_in(&staging.dir, OsStr::new(ASIDE), folder, entry)
                    .map_err(|e| taken(&e))?;
                folder.sync_all().map_err(|e| io(&e))?;
                return Ok(OpState::Aborted);
            }
        }
        let content = match self.content_dir(keys, id) {
            Ok(content) => content,
            // Removed before the crash.
            Err(Error::Open) => return Ok(OpState::Done),
            Err(e) => return Err(e),
        };
        if Self::holds_only_backup(&content)? {
            let _ = self.remove_content_dir(keys, id);
            return Ok(OpState::Done);
        }
        if let Some(staging) = staging
            && info_in(&staging.dir, OsStr::new(ASIDE)).is_ok()
        {
            rename_new_in(&staging.dir, OsStr::new(ASIDE), folder, entry).map_err(|e| taken(&e))?;
            folder.sync_all().map_err(|e| io(&e))?;
        }
        Ok(OpState::Pending)
    }

    fn resume_rename(
        &self,
        keys: &MasterKeys,
        staging: Option<&mut Staging>,
        folder: &File,
        journal: &Journal,
    ) -> Result<OpState, Error> {
        let (to_parent, to) = journal.to.as_ref().ok_or(Error::Open)?;
        let to_folder = self.content_dir(keys, to_parent)?;
        let kind = if journal.node_is_dir {
            Kind::Dir
        } else {
            Kind::File
        };
        let Some(staging) = staging else {
            return Ok(OpState::Aborted);
        };
        let from_there = info_in(folder, OsStr::new(journal.stored.entry())).is_ok();
        let to_there = info_in(&to_folder, OsStr::new(to.entry())).is_ok();
        if !from_there && !to_there {
            return Ok(OpState::Aborted);
        }
        if matches!((&journal.stored, to), (Stored::Plain(_), Stored::Plain(_))) && !to_there {
            return Ok(OpState::Aborted);
        }
        if from_there || to_there {
            self.switch_home(staging, folder, &journal.stored, &to_folder, to, kind, true)?;
        }
        Ok(OpState::Done)
    }

    /// Opens a proven record, or says [`Error::Input`].
    pub(crate) fn open_record(&self, keys: &MasterKeys, id: &str) -> Result<Record, Error> {
        if !id.starts_with("op-") || id.contains('/') {
            return Err(Error::Input);
        }
        let dir = open_dir_in(&self.recovery, OsStr::new(id)).map_err(|_| Error::Input)?;
        check_private(&dir).map_err(|_| Error::Input)?;
        let journal = read_journal(keys, &dir, id)?.ok_or(Error::Input)?;
        Ok(Record { dir, journal })
    }

    /// Every record in this store, proven or not. Clear names come back only here, in this
    /// live session (FIL-06.13).
    ///
    /// # Errors
    /// [`Error::Locked`], [`Error::Io`].
    pub fn recovery_items(&self) -> Result<Vec<RecoveryItem>, Error> {
        let turn = self.reading()?;
        let keys = turn.keys()?;
        let mut items = Vec::new();
        for name in names_in(&self.recovery, MAX_NODES).map_err(|e| io(&e))? {
            let Some(id) = name.to_str().filter(|n| n.starts_with("op-")) else {
                continue;
            };
            let journal = open_dir_in(&self.recovery, &name)
                .ok()
                .and_then(|dir| read_journal(keys, &dir, id).ok().flatten());
            items.push(match journal {
                Some(j) => {
                    let name = names::open_name(keys, &j.parent, j.stored.sealed()).ok();
                    RecoveryItem {
                        id: id.to_owned(),
                        kind: Some(j.kind),
                        state: Some(j.state),
                        proven: true,
                        name,
                        base: j.base,
                        new: j.new,
                    }
                }
                None => RecoveryItem {
                    id: id.to_owned(),
                    kind: None,
                    state: None,
                    proven: false,
                    name: None,
                    base: None,
                    new: None,
                },
            });
        }
        Ok(items)
    }

    /// Removes one finished record, only if everything in it is exactly what its journal
    /// says (FIL-06.14). A forged journal, a replaced copy, an unknown file, a link or a
    /// bad mode stops it, and all of it stays.
    ///
    /// # Errors
    /// [`Error::Input`] for an unproven or unfinished record; [`Error::Uncertain`] when
    /// anything in it is not what was expected; [`Error::Locked`].
    pub fn recovery_discard(
        &self,
        id: &str,
        base: Option<Digest>,
        new: Option<Digest>,
    ) -> Result<(), Error> {
        let turn = self.exclusive()?;
        let keys = turn.keys()?;
        let record = self.open_record(keys, id)?;
        let journal = &record.journal;
        if !matches!(
            journal.state,
            OpState::Done | OpState::Aborted | OpState::Pending
        ) || journal.base != base
            || journal.new != new
        {
            return Err(Error::Input);
        }
        let mut sizes = 0u64;
        for (copy, want) in [(BASE, base), (NEW, new)] {
            match (digest_at(&record.dir, OsStr::new(copy)), want) {
                (Ok(Some(found)), Some(w)) if found == w => {
                    let size = info_in(&record.dir, OsStr::new(copy)).map_or(0, |i| i.size);
                    sizes = sizes.saturating_add(size);
                }
                (Ok(None), None) => {}
                _ => return Err(Error::Uncertain),
            }
        }
        let allowed = [BASE, NEW, crate::recovery::JOURNAL];
        let found = names_in(&record.dir, 8).map_err(|e| io(&e))?;
        if !found
            .iter()
            .all(|n| n.to_str().is_some_and(|t| allowed.contains(&t)))
        {
            return Err(Error::Uncertain);
        }
        for copy in [BASE, NEW] {
            match remove_in(&record.dir, OsStr::new(copy)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Uncertain),
            }
        }
        remove_in(&record.dir, OsStr::new(crate::recovery::JOURNAL))
            .map_err(|_| Error::Uncertain)?;
        remove_dir_in(&self.recovery, OsStr::new(id)).map_err(|_| Error::Uncertain)?;
        let freed = sizes.saturating_add(JOURNAL_ALLOWANCE);
        let used = self.recovery_used.load(Ordering::SeqCst);
        self.recovery_used
            .store(used.saturating_sub(freed), Ordering::SeqCst);
        self.recovery.sync_all().map_err(|e| io(&e))
    }
}
