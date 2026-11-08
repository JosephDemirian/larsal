//! Durable records of what a change is doing (FIL-06.7, FIL-06.13, FIL-06.14). One folder
//! per operation under an app-owned 0700 store: a journal, and ciphertext copies named
//! `base` and `new`. The journal holds only the encrypted name, the parent's directory
//! ID, digests and state, with a MAC under a derived key: a forged or replaced journal
//! proves nothing and removes nothing. Clear names exist only in a live session.

use crate::error::{Error, io};
use crate::keys::MasterKeys;
use crate::names::{Stored, hex};
use crate::vault::Digest;
use larsal_crypto::mac;
use larsal_crypto::secret::SecretString;
use larsal_platform::macos::{create_in, open_regular_in, remove_in, rename_in};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};

pub(crate) const JOURNAL: &str = "journal";
const JOURNAL_NEW: &str = "journal.new";
pub(crate) const BASE: &str = "base";
pub(crate) const NEW: &str = "new";
const MAX_JOURNAL: u64 = 16_384;
const LABEL: &[u8] = b"larsal-folders journal v1";

/// What an operation was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    /// A new file.
    Create,
    /// New content for a file.
    Update,
    /// A competing version kept beside the others.
    Admit,
    /// A file removed.
    Delete,
    /// A new folder.
    Mkdir,
    /// A folder removed.
    Rmdir,
    /// A new name or place.
    Rename,
}

/// How far an operation got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpState {
    /// Recorded; nothing in the folder changed.
    Begun,
    /// The new ciphertext is durable here and staged there.
    Staged,
    /// The change is in the folder; only tidying is left.
    Published,
    /// Finished. The copies stay until discarded.
    Done,
    /// Stopped; the folder has what it had. The copies stay until discarded.
    Aborted,
    /// A deletion that meets another version: the edited version stays.
    Pending,
}

/// Which copy of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// What the folder held before.
    Base,
    /// What the operation wrote.
    New,
}

impl Kept {
    pub(crate) fn file(self) -> &'static str {
        match self {
            Self::Base => BASE,
            Self::New => NEW,
        }
    }
}

/// One operation's record, for review. `proven` false means its journal does not prove
/// itself under these keys: it says nothing, and it can be neither read nor discarded.
pub struct RecoveryItem {
    /// The record's own name.
    pub id: String,
    /// What it was, when proven.
    pub kind: Option<OpKind>,
    /// How far it got, when proven.
    pub state: Option<OpState>,
    /// Whether the journal proved itself.
    pub proven: bool,
    /// The clear name, recovered only here, in this live session.
    pub name: Option<SecretString>,
    /// The digest of `base`, if there is one.
    pub base: Option<Digest>,
    /// The digest of `new`, if there is one.
    pub new: Option<Digest>,
}

impl std::fmt::Debug for RecoveryItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RecoveryItem({}, {:?}, {:?}, {})",
            self.id, self.kind, self.state, self.proven
        )
    }
}

/// A journal's whole content: only encrypted names, public IDs and digests.
#[derive(Debug, Clone)]
pub(crate) struct Journal {
    pub(crate) id: String,
    pub(crate) kind: OpKind,
    pub(crate) state: OpState,
    pub(crate) parent: Vec<u8>,
    pub(crate) stored: Stored,
    /// For a rename: where it goes.
    pub(crate) to: Option<(Vec<u8>, Stored)>,
    /// For a folder, its own ID; for a rename, what the node is (see `node_is_dir`).
    pub(crate) dir_id: Option<Vec<u8>>,
    pub(crate) node_is_dir: bool,
    pub(crate) base: Option<Digest>,
    pub(crate) new: Option<Digest>,
    pub(crate) staging: Option<String>,
}

fn kind_text(k: OpKind) -> &'static str {
    match k {
        OpKind::Create => "create",
        OpKind::Update => "update",
        OpKind::Admit => "admit",
        OpKind::Delete => "delete",
        OpKind::Mkdir => "mkdir",
        OpKind::Rmdir => "rmdir",
        OpKind::Rename => "rename",
    }
}

fn state_text(s: OpState) -> &'static str {
    match s {
        OpState::Begun => "begun",
        OpState::Staged => "staged",
        OpState::Published => "published",
        OpState::Done => "done",
        OpState::Aborted => "aborted",
        OpState::Pending => "pending",
    }
}

fn stored_lines(out: &mut String, key: &str, stored: &Stored) {
    use std::fmt::Write;
    let (entry, inflated) = match stored {
        Stored::Plain(n) => (n.as_str(), "-"),
        Stored::Short { deflated, inflated } => (deflated.as_str(), inflated.as_str()),
    };
    let _ = writeln!(out, "{key}_entry={entry}\n{key}_inflated={inflated}");
}

fn body_of(j: &Journal) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "v=1\nop={}\nkind={}\nstate={}",
        j.id,
        kind_text(j.kind),
        state_text(j.state)
    );
    let _ = writeln!(out, "parent={}", hex(&j.parent));
    stored_lines(&mut out, "from", &j.stored);
    match &j.to {
        Some((parent, stored)) => {
            let _ = writeln!(out, "to_parent={}", hex(parent));
            stored_lines(&mut out, "to", stored);
        }
        None => {
            let _ = writeln!(out, "to_parent=-\nto_entry=-\nto_inflated=-");
        }
    }
    let id = j.dir_id.as_deref().map_or_else(|| "-".to_owned(), hex);
    let _ = writeln!(out, "dir_id={id}\nnode_is_dir={}", u8::from(j.node_is_dir));
    let digest = |d: &Option<Digest>| d.as_ref().map_or_else(|| "-".to_owned(), Digest::hex);
    let _ = writeln!(out, "base={}\nnew={}", digest(&j.base), digest(&j.new));
    let _ = writeln!(out, "staging={}", j.staging.as_deref().unwrap_or("-"));
    out
}

pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let (pairs, _) = bytes.as_chunks::<2>();
    pairs
        .iter()
        .map(|[a, b]| {
            let high = char::from(*a).to_digit(16)?;
            let low = char::from(*b).to_digit(16)?;
            u8::try_from(high.checked_mul(16)?.checked_add(low)?).ok()
        })
        .collect()
}

fn digest_of(text: &str) -> Option<Option<Digest>> {
    if text == "-" {
        return Some(None);
    }
    let bytes: [u8; 32] = unhex(text)?.try_into().ok()?;
    Some(Some(Digest(bytes)))
}

fn stored_of(entry: &str, inflated: &str) -> Stored {
    if inflated == "-" {
        Stored::Plain(entry.to_owned())
    } else {
        Stored::Short {
            deflated: entry.to_owned(),
            inflated: inflated.to_owned(),
        }
    }
}

/// A proven journal's body, if it names the record `id`.
fn parse_body(body: &str, id: &str) -> Option<Journal> {
    let get = |key: &str| {
        body.lines().find_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k == key).then_some(v)
        })
    };
    if get("v")? != "1" || get("op")? != id {
        return None;
    }
    let kind = match get("kind")? {
        "create" => OpKind::Create,
        "update" => OpKind::Update,
        "admit" => OpKind::Admit,
        "delete" => OpKind::Delete,
        "mkdir" => OpKind::Mkdir,
        "rmdir" => OpKind::Rmdir,
        "rename" => OpKind::Rename,
        _ => return None,
    };
    let state = match get("state")? {
        "begun" => OpState::Begun,
        "staged" => OpState::Staged,
        "published" => OpState::Published,
        "done" => OpState::Done,
        "aborted" => OpState::Aborted,
        "pending" => OpState::Pending,
        _ => return None,
    };
    let to = match get("to_parent")? {
        "-" => None,
        parent => Some((
            unhex(parent)?,
            stored_of(get("to_entry")?, get("to_inflated")?),
        )),
    };
    let dir_id = match get("dir_id")? {
        "-" => None,
        id => Some(unhex(id)?),
    };
    Some(Journal {
        id: get("op")?.to_owned(),
        kind,
        state,
        parent: unhex(get("parent")?)?,
        stored: stored_of(get("from_entry")?, get("from_inflated")?),
        to,
        dir_id,
        node_is_dir: get("node_is_dir")? == "1",
        base: digest_of(get("base")?)?,
        new: digest_of(get("new")?)?,
        staging: match get("staging")? {
            "-" => None,
            s => Some(s.to_owned()),
        },
    })
}

fn sealed_journal(keys: &MasterKeys, j: &Journal) -> Result<String, Error> {
    let key = keys.derived(LABEL)?;
    let body = body_of(j);
    let tag = mac::hmac_sha256(key.expose(), &[body.as_bytes()]).map_err(|_| Error::Io)?;
    Ok(format!("{body}mac={}\n", hex(tag.expose())))
}

/// One operation's open record.
#[derive(Debug)]
pub(crate) struct Record {
    pub(crate) dir: File,
    pub(crate) journal: Journal,
}

impl Record {
    /// Replaces the journal at once, durably.
    pub(crate) fn save(&self, keys: &MasterKeys) -> Result<(), Error> {
        let text = sealed_journal(keys, &self.journal)?;
        let scratch = OsStr::new(JOURNAL_NEW);
        let mut file = create_in(&self.dir, scratch, 0o600).map_err(|e| io(&e))?;
        file.write_all(text.as_bytes()).map_err(|e| io(&e))?;
        file.sync_all().map_err(|e| io(&e))?;
        rename_in(&self.dir, scratch, OsStr::new(JOURNAL)).map_err(|e| io(&e))?;
        self.dir.sync_all().map_err(|e| io(&e))
    }

    /// Sets the state, then saves.
    pub(crate) fn set_state(&mut self, keys: &MasterKeys, state: OpState) -> Result<(), Error> {
        self.journal.state = state;
        self.save(keys)
    }
}

/// A journal read back, if it proves itself under these keys and names this record.
pub(crate) fn read_journal(
    keys: &MasterKeys,
    dir: &File,
    id: &str,
) -> Result<Option<Journal>, Error> {
    let file = match open_regular_in(dir, OsStr::new(JOURNAL)) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    let mut text = String::new();
    if file.take(MAX_JOURNAL).read_to_string(&mut text).is_err() {
        return Ok(None);
    }
    let Some((body, tag)) = text.rsplit_once("mac=") else {
        return Ok(None);
    };
    let Some(tag) = unhex(tag.trim_end_matches('\n')) else {
        return Ok(None);
    };
    let key = keys.derived(LABEL)?;
    if !mac::verify_hmac_sha256(key.expose(), &[body.as_bytes()], &tag) {
        return Ok(None);
    }
    Ok(parse_body(body, id))
}

/// Removes a leftover journal scratch file of a crash, by the one name it can have.
pub(crate) fn clear_journal_scratch(dir: &File) {
    let _ = remove_in(dir, OsStr::new(JOURNAL_NEW));
}
