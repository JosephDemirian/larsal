//! The session (FIL-04.13, FIL-06.8): one unlocked folder, its keys, and the rule that a
//! lock wins. A running operation holds a read guard on the keys and looks at the revoked
//! flag at every chunk; `lock` sets the flag at once, then waits for the guard, then drops
//! the keys. So when `lock` returns no effect of the session is left, and no key is.

use crate::Control;
use crate::Phase;
use crate::budget::{Budget, BudgetReport};
use crate::content::{self, Gate};
use crate::error::{Error, Refused, io};
use crate::format::{self, CONFIG_FILE, KEY_FILE, UVF_FILE};
use crate::keys::{self, MasterKeys};
use crate::limits::{
    CREATE_LOG_N, CREATE_R, CREATE_SALT, CREATE_THRESHOLD, MAX_CHILDREN, MAX_DIR_ID, MAX_INFLATED,
    MAX_PAGE, MAX_WORKERS,
};
use crate::names::{
    self, BACKUP, CONTENTS, DIR_FILE, INFLATED, LINK_FILE, PLAIN_EXT, SHORT_EXT, Stored,
};
use crate::stores::{Stores, private_child};
use larsal_crypto::keywrap;
use larsal_crypto::mac;
use larsal_crypto::random;
#[cfg(feature = "fuzz-door")]
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::secret::SecretString;
use larsal_platform::macos::{
    NodeType, create_in, info_in, info_of, make_dir_in, names_in, open_dir, open_dir_in,
    open_regular_in,
};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard};

/// Gives every session its own number, so a node of another session is refused.
static GENERATION: AtomicU64 = AtomicU64::new(1);

/// The SHA-256 of a stored file's whole ciphertext: what names a version (FIL-06.10).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub(crate) [u8; 32]);

impl Digest {
    pub(crate) fn from_hash(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(bytes.try_into().map_err(|_| Error::Io)?))
    }

    /// The full lower case hex.
    #[must_use]
    pub fn hex(&self) -> String {
        names::hex(&self.0)
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

/// What a listed item is. Only `File` and `Dir` can be read or changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A regular file.
    File,
    /// A folder.
    Dir,
    /// A link in the format. Listed, its target readable as bytes, never followed.
    Link,
    /// A real operating system link, a FIFO, a device, a second hard link or a type this
    /// crate does not know. Never touched.
    Unsupported,
    /// Malformed: a bad name, a bad mapping, a missing marker. Never touched.
    Invalid,
    /// Two kinds at once. Never touched.
    Ambiguous,
}

/// An opaque place in one session: where the object is, in the format's encrypted terms.
/// Holds no clear name and no key.
#[derive(Clone)]
pub struct Node {
    pub(crate) generation: u64,
    pub(crate) parent: Vec<u8>,
    pub(crate) stored: Option<Stored>,
    pub(crate) kind: Kind,
    pub(crate) dir_id: Option<Vec<u8>>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node({:?})", self.kind)
    }
}

impl Node {
    /// What it is.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }
}

/// One row of a listing. Invalid rows are visible, never skipped, and show no raw text.
pub struct Entry {
    /// The clear name, when it proved itself. `None` for an invalid row.
    pub name: Option<SecretString>,
    /// False for a proven name that is not safe here (FIL-06.2): show it as an
    /// unsupported row; it never becomes a path.
    pub safe: bool,
    /// What it is.
    pub kind: Kind,
    /// The plaintext size of a file of legal shape.
    pub size: Option<u64>,
    /// Its handle.
    pub node: Node,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Entry({:?}, {:?})", self.kind, self.size)
    }
}

/// One operation's right to the keys.
pub(crate) struct Turn<'v> {
    keys: RwLockReadGuard<'v, Option<MasterKeys>>,
    _busy: Option<MutexGuard<'v, ()>>,
}

impl Turn<'_> {
    pub(crate) fn keys(&self) -> Result<&MasterKeys, Error> {
        self.keys.as_ref().ok_or(Error::Locked)
    }
}

/// One unlocked folder. See the module docs for how a lock works.
pub struct Vault {
    pub(crate) root: File,
    root_path: PathBuf,
    root_id: (u64, u64),
    generation: u64,
    revoked: AtomicBool,
    keys: RwLock<Option<MasterKeys>>,
    pub(crate) threshold: usize,
    scratch: File,
    pub(crate) recovery: File,
    pub(crate) budget: Budget,
    pub(crate) recovery_used: AtomicU64,
    busy: Mutex<()>,
    workers: AtomicUsize,
    weak: bool,
    #[cfg(test)]
    pub(crate) ceiling: AtomicU64,
    #[cfg(test)]
    pub(crate) node_limit: AtomicUsize,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vault(locked: {})", self.revoked.load(Ordering::SeqCst))
    }
}

/// An open page-by-page listing of one folder.
pub struct Listing<'v> {
    vault: &'v Vault,
    dir: File,
    parent: Vec<u8>,
    names: Vec<OsString>,
    at: usize,
}

impl std::fmt::Debug for Listing<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Listing({} of {})", self.at, self.names.len())
    }
}

impl Listing<'_> {
    /// How many rows this listing has.
    #[must_use]
    pub fn total(&self) -> usize {
        self.names.len()
    }

    /// The next rows, at most `max` and at most 256; empty at the end.
    ///
    /// # Errors
    /// [`Error::Locked`] once the session is locked.
    pub fn next_page(&mut self, max: usize) -> Result<Vec<Entry>, Error> {
        let turn = self.vault.reading()?;
        let keys = turn.keys()?;
        let take = max.min(MAX_PAGE);
        let end = self.at.saturating_add(take).min(self.names.len());
        let rows = self.names.get(self.at..end).ok_or(Error::Io)?;
        let page = rows
            .iter()
            .map(|raw| self.vault.classify(keys, &self.dir, &self.parent, raw))
            .collect();
        self.at = end;
        Ok(page)
    }
}

fn root_identity(path: &Path) -> Result<(u64, u64), Error> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).map_err(|e| io(&e))?;
    Ok((meta.dev(), meta.ino()))
}

/// A metadata file, bounded. Missing says `None`.
fn read_metadata(root: &File, name: &str) -> Result<Option<Vec<u8>>, Error> {
    let file = match open_regular_in(root, OsStr::new(name)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Open),
    };
    let limit = u64::try_from(crate::limits::MAX_METADATA).map_err(|_| Error::Open)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io(&e))?;
    Ok(Some(bytes))
}

/// A small object of known bound. Too long is hostile.
pub(crate) fn read_small(dir: &File, name: &str, max: usize) -> Result<Vec<u8>, Error> {
    let file = open_regular_in(dir, OsStr::new(name)).map_err(|_| Error::Open)?;
    let limit = u64::try_from(max).map_err(|_| Error::Open)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io(&e))?;
    if bytes.len() > max {
        return Err(Error::Open);
    }
    Ok(bytes)
}

/// A new small file, exclusive, durable.
pub(crate) fn write_new(dir: &File, name: &str, bytes: &[u8]) -> Result<(), Error> {
    let mut file = create_in(dir, OsStr::new(name), 0o600).map_err(|e| io(&e))?;
    file.write_all(bytes).map_err(|e| io(&e))?;
    file.sync_all().map_err(|e| io(&e))
}

/// A directory ID is at most 36 printable ASCII bytes, none of them empty.
fn valid_dir_id(id: &[u8]) -> bool {
    !id.is_empty() && id.len() <= MAX_DIR_ID && id.iter().all(u8::is_ascii_graphic)
}

impl Vault {
    fn start(
        root: File,
        root_path: PathBuf,
        keys: MasterKeys,
        threshold: usize,
        stores: &Stores,
        weak: bool,
    ) -> Result<Self, Error> {
        let store_id = keys.store_id()?;
        let scratch = private_child(stores.root(), "scratch")?;
        let recovery_root = private_child(stores.root(), "recovery")?;
        let ledger_root = private_child(stores.root(), "ledger")?;
        let recovery = private_child(&recovery_root, &store_id)?;
        let ledger = private_child(&ledger_root, &store_id)?;
        let root_id = {
            let info = info_of(&root).map_err(|e| io(&e))?;
            (info.dev, info.ino)
        };
        Ok(Self {
            root,
            root_path,
            root_id,
            generation: GENERATION.fetch_add(1, Ordering::SeqCst),
            revoked: AtomicBool::new(false),
            keys: RwLock::new(Some(keys)),
            threshold,
            scratch,
            recovery,
            budget: Budget::new(ledger),
            recovery_used: AtomicU64::new(0),
            busy: Mutex::new(()),
            workers: AtomicUsize::new(
                std::thread::available_parallelism()
                    .map_or(1, usize::from)
                    .clamp(1, MAX_WORKERS),
            ),
            weak,
            #[cfg(test)]
            ceiling: AtomicU64::new(crate::limits::RECOVERY_CEILING),
            #[cfg(test)]
            node_limit: AtomicUsize::new(crate::limits::MAX_NODES),
        })
    }

    /// The stores must be outside the folder: a recovery copy is never synced.
    fn check_apart(folder: &Path, stores: &Stores) -> Result<(), Error> {
        let folder = std::fs::canonicalize(folder).map_err(|_| Error::Input)?;
        let stores = std::fs::canonicalize(stores.path()).map_err(|_| Error::Input)?;
        if stores.starts_with(&folder) || folder.starts_with(&stores) {
            return Err(Error::Input);
        }
        Ok(())
    }

    /// Makes a new encrypted folder at `path`, which must be missing or an empty folder,
    /// and opens it: scrypt N = 2^18, r = 8, p = 1, a 32-byte salt, HS256 and threshold 220
    /// (FIL-04.1, FIL-04.3). The configuration is written last, so a stop leaves no folder
    /// that says it is one.
    ///
    /// # Errors
    /// [`Error::Input`] for a used location or an empty password; [`Error::Cancelled`],
    /// [`Error::Space`], [`Error::Io`].
    pub fn create(
        path: &Path,
        password: &SecretString,
        stores: &Stores,
        control: Control<'_>,
    ) -> Result<Self, Error> {
        if password.is_empty() {
            return Err(Error::Input);
        }
        let normal = keys::normalized_password(password).map_err(|_| Error::Input)?;
        let made = match std::fs::create_dir(path) {
            Ok(()) => {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| io(&e))?;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(io(&e)),
        };
        if let Err(e) = Self::check_apart(path, stores) {
            // Only the empty folder this call made goes, as on a cancel.
            if made {
                let _ = std::fs::remove_dir(path);
            }
            return Err(e);
        }
        let root = open_dir(path).map_err(|_| Error::Input)?;
        if !names_in(&root, 0).map_err(|e| io(&e))?.is_empty() {
            return Err(Error::Input);
        }
        let mut salt = vec![0u8; CREATE_SALT];
        random::fill(&mut salt).map_err(|_| Error::Io)?;
        let enc = random::bytes(keywrap::KEY).map_err(|_| Error::Io)?;
        let mac_key = random::bytes(keywrap::KEY).map_err(|_| Error::Io)?;
        if !control(Phase::Kdf, 0) {
            if made {
                let _ = std::fs::remove_dir(path);
            }
            return Err(Error::Cancelled);
        }
        let kek = keys::derive_kek(&normal, &salt, CREATE_LOG_N, CREATE_R)?;
        drop(normal);
        if !control(Phase::Kdf, 1) {
            if made {
                let _ = std::fs::remove_dir(path);
            }
            return Err(Error::Cancelled);
        }
        let wrapped_enc = keywrap::wrap(&kek, &enc).map_err(|_| Error::Io)?;
        let wrapped_mac = keywrap::wrap(&kek, &mac_key).map_err(|_| Error::Io)?;
        drop(kek);
        let version_mac =
            mac::hmac_sha256(mac_key.expose(), &[&999u32.to_be_bytes()]).map_err(|_| Error::Io)?;
        let key_file = format::write_key_file(
            1u64 << CREATE_LOG_N,
            CREATE_R,
            &salt,
            &wrapped_enc,
            &wrapped_mac,
            version_mac.expose(),
        );
        let keys = MasterKeys::new(enc, mac_key)?;
        let jti = random::uuid_v4().map_err(|_| Error::Io)?;
        let config = format::write_config(&keys.raw, &format::uuid_text(&jti))?;
        let vault = Self::start(
            root,
            path.to_path_buf(),
            keys,
            CREATE_THRESHOLD,
            stores,
            false,
        )?;
        vault
            .fill_new_folder(&key_file, &config)
            .map_err(|e| match e {
                Error::Space => Error::Space,
                _ => Error::Uncertain,
            })?;
        Ok(vault)
    }

    fn fill_new_folder(&self, key_file: &str, config: &str) -> Result<(), Error> {
        let turn = self.reading()?;
        let keys = turn.keys()?;
        make_dir_in(&self.root, OsStr::new("d"), 0o700).map_err(|e| io(&e))?;
        self.make_content_dir(keys, b"")?;
        write_new(&self.root, KEY_FILE, key_file.as_bytes())?;
        write_new(&self.root, CONFIG_FILE, config.as_bytes())?;
        self.root.sync_all().map_err(|e| io(&e))
    }

    /// Opens a folder: every check in the order FIL-04.2 and FIL-04.3 ask, with no key
    /// derivation until every bound holds, and no session until the wrapping, the version
    /// MAC and the configuration's signature all hold. Records a crash left are finished
    /// or marked here, by their exact names only.
    ///
    /// # Errors
    /// [`Error::Open`] for every credential, authenticity and hostile structure failure;
    /// [`Error::Profile`] for another format, by name; [`Error::Input`], [`Error::Cancelled`].
    pub fn unlock(
        path: &Path,
        password: &SecretString,
        stores: &Stores,
        control: Control<'_>,
    ) -> Result<Self, Error> {
        Self::check_apart(path, stores)?;
        let root = open_dir(path).map_err(|_| Error::Input)?;
        if info_in(&root, OsStr::new(UVF_FILE)).is_ok() {
            return Err(Error::Profile(Refused::Uvf));
        }
        let config = read_metadata(&root, CONFIG_FILE)?;
        let parsed = config.as_deref().map(format::parse_config).transpose()?;
        let key_file = read_metadata(&root, KEY_FILE)?.ok_or(Error::Open)?;
        let file = format::parse_key_file(&key_file)?;
        let normal = keys::normalized_password(password)?;
        if !control(Phase::Kdf, 0) {
            return Err(Error::Cancelled);
        }
        let kek = keys::derive_kek(&normal, &file.salt, file.log_n, file.r)?;
        drop(normal);
        if !control(Phase::Kdf, 1) {
            return Err(Error::Cancelled);
        }
        let (enc, mac_key) = keys::unwrap_keys(&kek, &file)?;
        drop(kek);
        if !file.version_proven(&mac_key) {
            return Err(Error::Open);
        }
        let Some(parsed) = parsed else {
            return Err(if file.predates_config() {
                Error::Profile(Refused::PreFormat8)
            } else {
                Error::Open
            });
        };
        let keys = MasterKeys::new(enc, mac_key)?;
        if !parsed.signed_by(&keys.raw) {
            return Err(Error::Open);
        }
        let threshold = parsed.authenticated_threshold()?;
        if !file.fits_a_config() {
            return Err(Error::Open);
        }
        let weak = file.log_n < CREATE_LOG_N;
        let vault = Self::start(root, path.to_path_buf(), keys, threshold, stores, weak)?;
        vault.resume_records()?;
        Ok(vault)
    }

    /// FIL-06.1: this folder's key file costs less than a new folder's would. Known only
    /// after authentication; nothing is ever rewritten for it.
    #[must_use]
    pub fn weak_kdf(&self) -> bool {
        self.weak
    }

    /// Sets the workers of later passes, from 1 to 4.
    pub fn set_workers(&self, workers: usize) {
        self.workers
            .store(workers.clamp(1, MAX_WORKERS), Ordering::SeqCst);
    }

    pub(crate) fn workers_for(&self, chunks: u64) -> usize {
        let set = self.workers.load(Ordering::SeqCst);
        usize::try_from(chunks).map_or(set, |c| c.clamp(1, set))
    }

    /// Takes the session's right to do anything new, at once, without waiting: the flag
    /// the next chunk, the next listing page and the next operation look at. Call
    /// [`Vault::lock`] to also wait for what is running and drop the keys.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }

    /// Locks: revokes at once, waits until no operation holds the keys, and drops them.
    /// When it returns, every key of this session has been wiped.
    pub fn lock(&self) {
        self.revoke();
        let mut keys = self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *keys = None;
    }

    /// Asked right before each change takes effect: a revoke between two steps stops the
    /// next one, and a long sync does not carry a change past it (FIL-06.8). `lock` then
    /// waits for the turn, so an effect that began before the revoke is the only one left.
    pub(crate) fn still_allowed(&self) -> Result<(), Error> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(Error::Locked)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn keys_are_gone(&self) -> bool {
        self.keys.read().is_ok_and(|keys| keys.is_none())
    }

    pub(crate) fn scratch(&self) -> &File {
        &self.scratch
    }

    pub(crate) fn gate<'a>(&'a self, control: Control<'a>, phase: Phase) -> Gate<'a> {
        Gate {
            revoked: &self.revoked,
            control,
            phase,
            done: 0,
        }
    }

    fn root_unchanged(&self) -> Result<(), Error> {
        if root_identity(&self.root_path)? == self.root_id {
            Ok(())
        } else {
            Err(Error::Changed)
        }
    }

    fn turn<'v>(&'v self, busy: Option<MutexGuard<'v, ()>>) -> Result<Turn<'v>, Error> {
        let keys = self
            .keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if keys.is_none() || self.revoked.load(Ordering::SeqCst) {
            return Err(Error::Locked);
        }
        self.root_unchanged()?;
        // The guard is taken before the flag is read: from here a lock waits for this
        // turn, and a revoke after this point is seen at the next chunk (FIL-06.8).
        Ok(Turn { keys, _busy: busy })
    }

    /// A turn that may run beside other readers: listing and looking up.
    pub(crate) fn reading(&self) -> Result<Turn<'_>, Error> {
        self.turn(None)
    }

    /// The one content or change operation of this session (FIL-06.1).
    pub(crate) fn exclusive(&self) -> Result<Turn<'_>, Error> {
        if self.revoked.load(Ordering::SeqCst) {
            return Err(Error::Locked);
        }
        let busy = self.busy.try_lock().map_err(|_| Error::Busy)?;
        self.turn(Some(busy))
    }

    pub(crate) fn check_node(&self, node: &Node) -> Result<(), Error> {
        if node.generation == self.generation {
            Ok(())
        } else {
            Err(Error::Locked)
        }
    }

    /// A folder below this one, with no link followed and no mount crossed.
    pub(crate) fn child_dir(&self, dir: &File, name: &str) -> Result<File, Error> {
        let child = open_dir_in(dir, OsStr::new(name)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput => Error::Open,
            _ => io(&e),
        })?;
        let info = info_of(&child).map_err(|e| io(&e))?;
        if info.dev != self.root_id.0 {
            return Err(Error::Open);
        }
        Ok(child)
    }

    /// The folder holding the children of directory `id`.
    pub(crate) fn content_dir(&self, keys: &MasterKeys, id: &[u8]) -> Result<File, Error> {
        let (first, second) = names::dir_path(keys, id)?;
        let d = self.child_dir(&self.root, "d")?;
        let first = self.child_dir(&d, &first)?;
        self.child_dir(&first, &second)
    }

    /// Makes directory `id`'s folder and its encrypted backup. Takes a header from the
    /// shared budget: a backup is an invocation like any other (FIL-06.16).
    pub(crate) fn make_content_dir(&self, keys: &MasterKeys, id: &[u8]) -> Result<(), Error> {
        let (first, second) = names::dir_path(keys, id)?;
        let d = self.child_dir(&self.root, "d")?;
        match make_dir_in(&d, OsStr::new(&first), 0o700) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io(&e)),
        }
        let first_dir = self.child_dir(&d, &first)?;
        make_dir_in(&first_dir, OsStr::new(&second), 0o700).map_err(|e| io(&e))?;
        let content = self.child_dir(&first_dir, &second)?;
        self.budget.take(keys)?;
        let backup = content::seal_small(keys, id)?;
        write_new(&content, BACKUP, &backup)?;
        content.sync_all().map_err(|e| io(&e))?;
        first_dir.sync_all().map_err(|e| io(&e))?;
        d.sync_all().map_err(|e| io(&e))
    }

    /// The handle of the top folder.
    ///
    /// # Errors
    /// [`Error::Locked`].
    pub fn root_dir(&self) -> Result<Node, Error> {
        let _turn = self.reading()?;
        Ok(Node {
            generation: self.generation,
            parent: Vec::new(),
            stored: None,
            kind: Kind::Dir,
            dir_id: Some(Vec::new()),
        })
    }

    pub(crate) fn dir_id_of<'n>(&self, node: &'n Node) -> Result<&'n [u8], Error> {
        self.check_node(node)?;
        match (node.kind, &node.dir_id) {
            (Kind::Dir, Some(id)) => Ok(id),
            _ => Err(Error::Open),
        }
    }

    /// Opens a listing of a folder (FIL-06.3): at most 10,000 rows, or a visible refusal.
    /// Pages are read later, each at most 256.
    ///
    /// # Errors
    /// [`Error::Open`] for a missing folder or one over the limit; [`Error::Locked`].
    pub fn open_listing(&self, dir: &Node) -> Result<Listing<'_>, Error> {
        let turn = self.reading()?;
        let keys = turn.keys()?;
        let id = self.dir_id_of(dir)?.to_vec();
        let folder = self.content_dir(keys, &id)?;
        let mut names = names_in(&folder, MAX_CHILDREN.saturating_add(1)).map_err(|e| io(&e))?;
        names.retain(|n| n != BACKUP);
        if names.len() > MAX_CHILDREN {
            return Err(Error::Open);
        }
        Ok(Listing {
            vault: self,
            dir: folder,
            parent: id,
            names,
            at: 0,
        })
    }

    /// Finds one name in a folder, by its encrypted form, with no scan.
    ///
    /// # Errors
    /// [`Error::Name`] for an unusable name; [`Error::Open`], [`Error::Locked`].
    pub fn lookup(&self, dir: &Node, name: &str) -> Result<Option<Entry>, Error> {
        let turn = self.reading()?;
        let keys = turn.keys()?;
        let id = self.dir_id_of(dir)?;
        let normal = names::check_new(name)?;
        let folder = self.content_dir(keys, id)?;
        let stored = Stored::of(keys, id, normal.expose(), self.threshold)?;
        let entry = OsStr::new(stored.entry());
        match info_in(&folder, entry) {
            Ok(_) => Ok(Some(self.classify(keys, &folder, id, entry))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(&e)),
        }
    }

    fn row(
        &self,
        parent: &[u8],
        stored: Option<Stored>,
        kind: Kind,
        name: Option<SecretString>,
    ) -> Entry {
        let safe = name
            .as_ref()
            .is_some_and(|n| names::is_safe_stored(n.expose()));
        Entry {
            name,
            safe,
            kind,
            size: None,
            node: Node {
                generation: self.generation,
                parent: parent.to_vec(),
                stored,
                kind,
                dir_id: None,
            },
        }
    }

    /// What the marker files in a node's folder say. A folder holding anything else is
    /// of a type this crate does not know, and is left alone (FIL-04.10, FIL-04.11).
    fn node_kind(&self, node_dir: &File, shortened: bool) -> (Kind, Option<Vec<u8>>) {
        let Ok(found) = names_in(node_dir, 8) else {
            return (Kind::Invalid, None);
        };
        let (mut files, mut dirs, mut links, mut other) = (0u8, 0u8, 0u8, 0u8);
        for name in &found {
            match name.to_str() {
                Some(CONTENTS) if shortened => files = files.saturating_add(1),
                Some(DIR_FILE) => dirs = dirs.saturating_add(1),
                Some(LINK_FILE) => links = links.saturating_add(1),
                Some(INFLATED) if shortened => {}
                _ => other = other.saturating_add(1),
            }
        }
        if other > 0 {
            return (Kind::Unsupported, None);
        }
        match files.saturating_add(dirs).saturating_add(links) {
            0 => return (Kind::Invalid, None),
            1 => {}
            _ => return (Kind::Ambiguous, None),
        }
        let marker = if files == 1 {
            CONTENTS
        } else if dirs == 1 {
            DIR_FILE
        } else {
            LINK_FILE
        };
        match info_in(node_dir, OsStr::new(marker)) {
            Ok(i) if i.kind == NodeType::File && i.nlink == 1 => {}
            Ok(_) => return (Kind::Unsupported, None),
            Err(_) => return (Kind::Invalid, None),
        }
        if files == 1 {
            return (Kind::File, None);
        }
        if links == 1 {
            return (Kind::Link, None);
        }
        match read_small(node_dir, DIR_FILE, MAX_DIR_ID) {
            Ok(id) if valid_dir_id(&id) => (Kind::Dir, Some(id)),
            _ => (Kind::Invalid, None),
        }
    }

    /// One raw name in a folder, as a row. Never fails, and never repairs: whatever is
    /// wrong with a node is a visible row, and the node stays on disk (FIL-04.10).
    pub(crate) fn classify(
        &self,
        keys: &MasterKeys,
        folder: &File,
        parent: &[u8],
        raw: &OsStr,
    ) -> Entry {
        let Some(text) = raw.to_str() else {
            return self.row(parent, None, Kind::Invalid, None);
        };
        let Ok(info) = info_in(folder, raw) else {
            return self.row(parent, None, Kind::Invalid, None);
        };
        if text.ends_with(SHORT_EXT) {
            return self.classify_short(keys, folder, parent, text, info.kind);
        }
        if !text.ends_with(PLAIN_EXT) || text.len() > self.threshold {
            return self.row(parent, None, Kind::Invalid, None);
        }
        let Ok(name) = names::open_name(keys, parent, text) else {
            return self.row(parent, None, Kind::Invalid, None);
        };
        let stored = Some(Stored::Plain(text.to_owned()));
        match info.kind {
            NodeType::File if info.nlink == 1 => {
                let mut row = self.row(parent, stored, Kind::File, Some(name));
                row.size = content::plan(info.size).ok().map(|p| p.plain);
                row
            }
            NodeType::Dir => {
                let Ok(node_dir) = self.child_dir(folder, text) else {
                    return self.row(parent, None, Kind::Invalid, Some(name));
                };
                let (kind, id) = self.node_kind(&node_dir, false);
                let mut row = self.row(parent, stored, kind, Some(name));
                row.node.dir_id = id;
                row
            }
            _ => self.row(parent, stored, Kind::Unsupported, Some(name)),
        }
    }

    fn classify_short(
        &self,
        keys: &MasterKeys,
        folder: &File,
        parent: &[u8],
        text: &str,
        kind: NodeType,
    ) -> Entry {
        if kind != NodeType::Dir {
            return self.row(parent, None, Kind::Invalid, None);
        }
        let Ok(node_dir) = self.child_dir(folder, text) else {
            return self.row(parent, None, Kind::Invalid, None);
        };
        let inflated = read_small(&node_dir, INFLATED, MAX_INFLATED)
            .and_then(|bytes| names::check_mapping(text, &bytes, self.threshold));
        let Ok(inflated) = inflated else {
            return self.row(parent, None, Kind::Invalid, None);
        };
        let Ok(name) = names::open_name(keys, parent, &inflated) else {
            return self.row(parent, None, Kind::Invalid, None);
        };
        let stored = Stored::Short {
            deflated: text.to_owned(),
            inflated,
        };
        let (node, id) = self.node_kind(&node_dir, true);
        let mut row = self.row(parent, Some(stored), node, Some(name));
        row.node.dir_id = id;
        if node == Kind::File {
            row.size = info_in(&node_dir, OsStr::new(CONTENTS))
                .ok()
                .and_then(|i| content::plan(i.size).ok())
                .map(|p| p.plain);
        }
        row
    }

    /// Where a node's one object is: its folder and its name there.
    pub(crate) fn place_of(
        &self,
        folder: &File,
        stored: &Stored,
        kind: Kind,
    ) -> Result<(File, OsString), Error> {
        let marker = match kind {
            Kind::File => CONTENTS,
            Kind::Dir => DIR_FILE,
            Kind::Link => LINK_FILE,
            _ => return Err(Error::Open),
        };
        match (stored, kind) {
            (Stored::Plain(entry), Kind::File) => Ok((
                folder.try_clone().map_err(|e| io(&e))?,
                OsString::from(entry),
            )),
            _ => Ok((
                self.child_dir(folder, stored.entry())?,
                OsString::from(marker),
            )),
        }
    }

    pub(crate) fn place(&self, keys: &MasterKeys, node: &Node) -> Result<(File, OsString), Error> {
        let stored = node.stored.as_ref().ok_or(Error::Open)?;
        let folder = self.content_dir(keys, &node.parent)?;
        self.place_of(&folder, stored, node.kind)
    }

    /// What this Mac has counted of the encryption master key's budget (FIL-06.16).
    ///
    /// # Errors
    /// [`Error::Budget`] when the ledger does not prove itself; [`Error::Locked`].
    pub fn budget_report(&self) -> Result<BudgetReport, Error> {
        let turn = self.reading()?;
        self.budget.report(turn.keys()?)
    }

    pub(crate) fn node(
        &self,
        parent: &[u8],
        stored: Stored,
        kind: Kind,
        dir_id: Option<Vec<u8>>,
    ) -> Node {
        Node {
            generation: self.generation,
            parent: parent.to_vec(),
            stored: Some(stored),
            kind,
            dir_id,
        }
    }
}

#[cfg(feature = "fuzz-door")]
pub(crate) fn demo_keys() -> Result<MasterKeys, Error> {
    MasterKeys::new(
        SecretBytes::new(vec![0x11; 32]),
        SecretBytes::new(vec![0x22; 32]),
    )
}
