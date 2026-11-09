//! Sync with Larsal's own server (E16-S7a; SYN-03, SYN-04), larsal-ffi's `sync`
//! feature over larsal-sync: adding a server and pinning its certificate
//! (SYN-01.2, SYN-01.14), sign-up with a new device key (SYN-04.2,
//! LD-325 (5) (a)), putting a vault on the server (SYN-03.1) with its key-file
//! part (P7), taking a server vault to this Mac (SYN-03.2), each open vault's
//! runs on its schedule (SYN-03.4) with their status (SYN-03.13), and the
//! key-change cases (SYN-03.8, SYN-03.9; LD-264).
//!
//! Guarantees:
//! - Nothing runs by itself: Swift calls [`Session::sync_tick`] (off the
//!   main thread); a run starts only when the vault's schedule says so:
//!   after the unlock, 2 s after a save, every 60 s while unlocked and on
//!   Sync now, never while locked, saving, with unsaved changes, an open
//!   editor or a disk event pending.
//! - One lock order: a server's client lock, then a vault's save lock,
//!   then the session lock. The sync state's own lock is a leaf: nothing
//!   else is locked while it is held.
//! - The device key's label is 16 random bytes; sign-up registers the key
//!   made in that call, and each later open of the key compares its public
//!   key with the stored one (LD-325 (5) (a)). Tests never reach a keychain
//!   (LD-317 (2)): they use the test-seam key only.
//! - The state file holds no password, key, key-file part or token
//!   (SYN-03.3, SYN-04.6); the session token lives in larsal-sync's client.
//! - The key-file part lives in the device store and, while unlocked, in the
//!   saver's locked pages, never in a vault, the state file, a log or a request.
//!   It reaches the device store and its place reaches the state file before
//!   the vault's key changes, so a failure at any step leaves a vault that opens.
//!   Tests use a map in memory, never a keychain (LD-317 (2)).
//! - Only a file that passes SYN-03.5 step 2 goes up: every read of the file
//!   for an upload is [`Session::sync_read`]'s. It also needs the part and no
//!   field 12 (F-321, F-322).
//! - Every text here is Larsal's own (SYN-01.9).

use crate::session::{LarsalError, Session};
use crate::wizard::{self, Answer, Outcome};
use larsal_core::retired::Record;
use larsal_core::settings::{self, Changes, KeyChange, PasswordPart};
use larsal_core::{guard::newest, storage};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_format::keyfile::{KeyFileKey, read_key_file};
use larsal_format::limits::Limits;
use larsal_model::{FileVersion, Kdf, Time, Uuid, Vault};
use larsal_platform::device_key::{DeviceKey, KeyError};
use larsal_sync::client::{self, Fail, Server};
use larsal_sync::state::{Account, Link, Measures, Part, State, VaultId, part_label};
use larsal_sync::sync::{
    Clock, Local, Merge, Message, Report, Schedule, Status, SystemClock, Unproven,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

type Client = Server<DeviceKey>;

/// The key file's name in Vault Settings for a part Larsal made (SYN-03.12).
const PART_NAME: &str = "Kept for sync";

/// SYN-03.2: the root of a download's link and pointer until its first run
/// reads the root its unlock opened (the root is inside the encrypted file).
const UNKNOWN_ROOT: Uuid = Uuid([0; 16]);

/// SYN-03.12 (C1-A12): a key file typed in a sheet for a linked file that is
/// not its part.
pub(crate) const PART_OTHER: (&str, &str) = (
    "MSG-SYNC-PART-OTHER",
    "This vault is on a server, so it opens with its key file kept for sync. This key file is another one.",
);

/// SYN-03.12 (C1R2-02): a sheet, or a key file typed, for a linked file while
/// the device store gives no part: nothing can be checked against the part, so
/// nothing is taken (fail closed). The way back (C1R3B-02, C1R4-01): an unlock
/// with a typed factor and the saved key file of the file as it was last synced
/// stores the part again; or an unlock where the part is kept.
pub(crate) const PART_UNREAD: (&str, &str) = (
    "MSG-SYNC-PART-UNREAD",
    "This vault is on a server, and macOS did not give Larsal its key file kept for sync, so nothing was changed. To get it back, unlock the vault on a Mac that keeps that key file, or put back the vault file as it was last synced and unlock it with its password or hardware key and the key file you saved with Save as key file.",
);

/// SYN-03.12: a vault with a key-file part kept for sync keeps a typed factor:
/// a key change, or a copy's key in a sheet, with the part alone (C2bR3-1).
pub(crate) const TYPED_KEPT: (&str, &str) = (
    "MSG-SYNC-TYPED-KEPT",
    "This vault's key file is kept for sync, so it also needs a password or a hardware key.",
);

/// How the device store reads a key-file part, from [`Session::sync_start`] on.
/// ponytail: a pointer, not a plain call, only because `unlock` reaches it: a test
/// program never calls `sync_start`, so it links no keychain symbol (LD-325 (5d)).
/// Its ceiling: a launch that forgets `sync_start` fails unlocks until the first tick.
#[cfg(not(test))]
static PART_READ: std::sync::OnceLock<PartRead> = std::sync::OnceLock::new();

#[cfg(not(test))]
type PartRead = fn(&str) -> Result<SecretBytes, KeyError>;

/// How the way back at unlock (C1R3B-02) writes a part, from [`Session::sync_start`]
/// on: a pointer for the same reason as [`PART_READ`].
#[cfg(not(test))]
static PART_KEEP: std::sync::OnceLock<PartKeep> = std::sync::OnceLock::new();

#[cfg(not(test))]
type PartKeep = fn(&str, &SecretBytes) -> Result<(), KeyError>;

/// Whether a link of `links` names `file` and last synced the bytes `sha` hashes.
fn last_synced(links: &[Link], file: &str, sha: &[u8; 32]) -> bool {
    links
        .iter()
        .any(|l| l.file == file && larsal_crypto::secret::ct_eq(sha, &l.local_sha))
}

/// The measures the rollback guard compares (SYN-03.7) of `v`.
pub(crate) fn measures(v: &Vault) -> Measures {
    Measures {
        newest: newest(v, v.read_version),
        version: v.read_version.unwrap_or(FileVersion { major: 4, minor: 0 }),
        kdf: v.encryption.kdf,
    }
}

/// A link's status for the screens (SYN-03.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SyncStatus {
    /// The last run ended well (`synced_at`).
    Synced,
    /// A run is open.
    Syncing,
    /// No connection; the next trigger tries again, with no message box.
    Offline,
    /// The server copy opens with other credentials (SYN-03.8).
    NeedsPassword,
    /// The server copy uses a key this Mac replaced (SYN-03.9, E16-S7b).
    ReplacedPassword,
    /// Signed out of the server (`MSG-SYNC-SIGNED-OUT`).
    SignedOut,
    /// The last run failed; its message says why.
    Error,
}

/// One message of SYN-03 in Larsal's words.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncMessage {
    /// The message id, `MSG-SYNC-…`.
    pub id: String,
    /// The words of SYN-03's table.
    pub text: String,
}

/// The sync state of one open, linked vault.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncState {
    /// The open vault.
    pub vault: u64,
    /// SYN-03.13's status.
    pub status: SyncStatus,
    /// The time of the last run that ended well (ms since 1970).
    pub synced_at: Option<u64>,
    /// The last run's messages, in order.
    pub messages: Vec<SyncMessage>,
    /// SYN-03.8: show the unlock sheet for the server copy, with
    /// `sync_open_copy`. True once from [`Session::sync_tick`] after the first
    /// run that needs a password and after a run the user asked for: never for
    /// a 60-second tick (T18).
    pub ask_key: bool,
}

/// A vault on a server (`GET /v1/vaults`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncServerVault {
    /// The `vault_id`, 32 hex digits.
    pub id: String,
    /// The server's current version.
    pub version: u64,
    /// The size in bytes.
    pub size: u64,
    /// Linked to a vault on this Mac.
    pub linked: bool,
}

/// One open vault's sync.
#[derive(Debug)]
struct Open {
    path: PathBuf,
    root: Uuid,
    schedule: Schedule,
    report: Option<Report>,
    synced_at: Option<u64>,
    /// SYN-03 T51, T61: a Save As or an unlock landed during the open run: the
    /// run belongs to the file and the unlock the vault left, so it reads and
    /// merges nothing more and its report is not the new one's.
    left: bool,
    /// The next run is the unlock's or Sync now's, not a tick's (SYN-03.8).
    asked: bool,
    /// [`SyncState::ask_key`].
    ask_key: bool,
    /// SYN-03.2: the SHA-256 and the measures of the bytes this unlock opened;
    /// a download's link takes its root only when they are the downloaded ones.
    opened: Option<([u8; 32], Measures)>,
    /// SYN-03.9 (C1-A7b): after Merge anyway, the vault's measures from before
    /// it, so the copy's times reach no link record at the upload that follows.
    answered: Option<Measures>,
}

/// A local transfer owns its file/root or server vault until commit or cancellation.
struct Claim {
    path: PathBuf,
    root: Option<Uuid>,
    remote: Option<(String, larsal_sync::state::VaultId)>,
    /// C1R4-03: the links with no root yet (file, downloaded SHA-256) a download
    /// replaces; they stay until it commits.
    replaces: Vec<(String, [u8; 32])>,
}

impl Claim {
    fn replaces(&self, l: &Link) -> bool {
        l.root == UNKNOWN_ROOT
            && self
                .replaces
                .iter()
                .any(|(f, s)| *f == l.file && larsal_crypto::secret::ct_eq(s, &l.local_sha))
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.path == other.path
            || self.root.is_some_and(|root| other.root == Some(root))
            || self
                .remote
                .as_ref()
                .is_some_and(|remote| other.remote.as_ref() == Some(remote))
    }
}

/// Dropping an error or unwinding releases only this operation's claim.
struct Transfer<'a> {
    sync: &'a Syncs,
    claim: Arc<Claim>,
}

impl Transfer<'_> {
    fn release(&self, i: &mut Inner) {
        i.transfers.retain(|c| !Arc::ptr_eq(c, &self.claim));
    }

    fn ready(&self, i: &Inner) -> bool {
        i.transfers.iter().any(|c| Arc::ptr_eq(c, &self.claim))
            && !i.unavailable(&self.claim)
            && !i
                .transfers
                .iter()
                .any(|c| !Arc::ptr_eq(c, &self.claim) && c.overlaps(&self.claim))
    }
}

impl Drop for Transfer<'_> {
    fn drop(&mut self) {
        self.release(&mut self.sync.inner());
    }
}

struct Inner {
    clock: Arc<dyn Clock>,
    /// The state file it was read from (`Some(None)`: memory only).
    file: Option<Option<PathBuf>>,
    /// The file did not read: it is never written over (as F-241).
    unread: bool,
    state: State,
    servers: BTreeMap<String, Arc<Mutex<Client>>>,
    vaults: BTreeMap<u64, Open>,
    transfers: Vec<Arc<Claim>>,
    /// Servers whose certificate changed: no run until the user adds the
    /// server again (SYN-03.10).
    stopped: BTreeSet<String>,
    /// Tests: the clock's time at the start of each run of a linked vault.
    #[cfg(test)]
    runs: Vec<(u64, u64)>,
    /// Tests: the device store of the key-file parts, never a keychain
    /// (LD-317 (2)); `second`'s helper copies it (LD-266 (2)).
    #[cfg(test)]
    device_store: BTreeMap<String, SecretBytes>,
    /// Tests: the device store refuses every write and every read.
    #[cfg(test)]
    store_refuses: bool,
}

/// The sync of one session (Session's `sync` field).
pub(crate) struct Syncs(Mutex<Inner>);

impl Default for Syncs {
    fn default() -> Self {
        Self(Mutex::new(Inner {
            clock: Arc::new(SystemClock),
            file: None,
            unread: false,
            state: State::default(),
            servers: BTreeMap::new(),
            vaults: BTreeMap::new(),
            transfers: Vec::new(),
            stopped: BTreeSet::new(),
            #[cfg(test)]
            runs: Vec::new(),
            #[cfg(test)]
            device_store: BTreeMap::new(),
            #[cfg(test)]
            store_refuses: false,
        }))
    }
}

impl Syncs {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The vault `id` was unlocked from the bytes `opened` hashes and measures:
    /// its schedule starts (SYN-03.4).
    pub(crate) fn unlocked(
        &self,
        id: u64,
        path: &Path,
        root: Uuid,
        opened: Option<([u8; 32], Measures)>,
    ) {
        let mut i = self.inner();
        let now = i.clock.now_ms();
        let prior = i.vaults.remove(&id);
        // SYN-03 T63: a report belongs to its root, not to the slot.
        let (mut schedule, report) = prior
            .map(|o| (o.schedule, o.report.filter(|_| o.root == root)))
            .unwrap_or_default();
        schedule.unlocked(now);
        i.vaults.insert(
            id,
            Open {
                path: path.to_path_buf(),
                root,
                left: schedule.running(),
                schedule,
                report,
                synced_at: None,
                asked: true,
                ask_key: false,
                opened,
                answered: None,
            },
        );
    }

    /// The root group id vault `id` unlocked with.
    pub(crate) fn root(&self, id: u64) -> Option<Uuid> {
        self.inner().vaults.get(&id).map(|o| o.root)
    }

    /// APP-05.6 Save As: the vault `id` now lives at `path`. A link names
    /// one local file (SYN-03.3), so the new file has none: it syncs nothing
    /// under the old link, and the old file keeps its link. The new file has the
    /// vault's key, so it opens with the same key-file part.
    pub(crate) fn moved(&self, id: u64, path: &Path) {
        let mut i = self.inner();
        let Some(o) = i.vaults.get_mut(&id).filter(|o| o.path != path) else {
            return;
        };
        let old = std::mem::replace(&mut o.path, path.to_path_buf());
        o.report = None;
        o.left = o.schedule.running();
        let old = old.to_string_lossy();
        if let Some(part) = i.state.parts.iter().find(|p| p.file == old).cloned() {
            let file = path.to_string_lossy().into_owned();
            i.state.parts.retain(|p| p.file != file);
            i.state.parts.push(Part { file, ..part });
            i.save();
        }
    }

    /// Whether the open run of vault `id` began on a file or an unlock the
    /// vault has left (SYN-03 T51, T61).
    pub(crate) fn left(&self, id: u64) -> bool {
        self.inner().vaults.get(&id).is_some_and(|o| o.left)
    }

    /// The vault `id` (every vault for `None`) was locked or closed.
    pub(crate) fn locked(&self, id: Option<u64>) {
        let mut i = self.inner();
        for (vault, open) in &mut i.vaults {
            if id.is_none_or(|id| id == *vault) {
                open.schedule.locked();
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn set_clock(&self, clock: Arc<dyn Clock>) {
        self.inner().clock = clock;
    }
}

impl Inner {
    /// The state, loaded from `file` when it changed (the settings folder).
    fn load(&mut self, file: Option<PathBuf>) {
        if self.file.as_ref() == Some(&file) {
            return;
        }
        let loaded = file.as_deref().map(State::load);
        self.unread = matches!(loaded, Some(Err(_)));
        self.state = loaded.and_then(Result::ok).unwrap_or_default();
        self.file = Some(file);
    }

    fn save(&self) {
        if let (false, Some(Some(path))) = (self.unread, &self.file) {
            // ponytail: a failed write keeps the state in memory for this
            // run; the next change writes it again.
            let _ = self.state.save(path);
        }
    }

    /// SYN-03.1 step 2: `part` is where its file's key-file part lives, on disk
    /// before the file's key changes: a state that does not reach the disk stops
    /// the change, since the vault would not open after it. The labels no file
    /// uses now.
    fn keep_part(&mut self, part: Part) -> Result<Vec<String>, LarsalError> {
        let before = self.state.parts.clone();
        self.state.parts.retain(|p| p.file != part.file);
        self.state.parts.push(part);
        let saved = match &self.file {
            Some(Some(path)) if !self.unread => self.state.save(path).is_ok(),
            _ => false,
        };
        if !saved {
            self.state.parts = before;
            return Err(refused(
                "Larsal could not write its sync state. Nothing was changed or uploaded.",
            ));
        }
        Ok(before
            .into_iter()
            .map(|p| p.label)
            .filter(|label| !self.state.parts.iter().any(|p| &p.label == label))
            .collect())
    }

    fn unavailable(&self, claim: &Claim) -> bool {
        let links = || self.state.links.iter().filter(|l| !claim.replaces(l));
        links().any(|l| Path::new(&l.file) == claim.path || claim.root == Some(l.root))
            || claim.remote.as_ref().is_some_and(|(server, id)| {
                links().any(|l| l.server == *server && l.vault_id == *id)
            })
            || (claim.root.is_none() && self.vaults.values().any(|o| o.path == claim.path))
    }

    /// A run updates only its own file/root, and never rolls back the guard.
    fn write_back(&mut self, mut link: Link) {
        let at = self.state.links.iter().position(|l| {
            l.file == link.file
                && l.root == link.root
                && l.server == link.server
                && l.vault_id == link.vault_id
        });
        if let Some(at) = at {
            let current = &self.state.links[at];
            if link.highest < current.highest {
                return;
            }
            link.seen.newest = link.seen.newest.max(current.seen.newest);
            if *current != link {
                self.state.links[at] = link;
                self.save();
            }
        }
    }

    fn link_of(&self, open: &Open) -> Option<usize> {
        let file = open.path.to_string_lossy();
        self.state
            .links
            .iter()
            .position(|l| l.file == file && l.root == open.root && l.root != UNKNOWN_ROOT)
    }

    /// SYN-03.2, F-288: the download linked to the file of the open vault `id`
    /// takes the root its unlock opened, with that unlock's measures and the
    /// keys this Mac retired from that root (`records`), when that unlock
    /// opened the downloaded bytes and nothing else names the root or the
    /// server vault. Otherwise the link goes and the pointer stays, so the
    /// file still opens. The link's place.
    fn adopt(&mut self, id: u64, records: &[Record]) -> Option<usize> {
        let open = self.vaults.get(&id)?;
        let file = open.path.to_string_lossy().into_owned();
        let n = self
            .state
            .links
            .iter()
            .position(|l| l.file == file && l.root == UNKNOWN_ROOT)?;
        let link = &self.state.links[n];
        let (root, opened) = (open.root, open.opened);
        let taken = opened.filter(|(sha, _)| {
            root != UNKNOWN_ROOT
                && larsal_crypto::secret::ct_eq(sha, &link.local_sha)
                && !self.state.links.iter().enumerate().any(|(m, l)| {
                    m != n
                        && (l.root == root
                            || (l.server == link.server && l.vault_id == link.vault_id))
                })
                && !self.transfers.iter().any(|c| {
                    c.path == open.path
                        || c.root == Some(root)
                        || c.remote.as_ref().is_some_and(|(server, vault_id)| {
                            *server == link.server && *vault_id == link.vault_id
                        })
                })
        });
        let Some((_, seen)) = taken else {
            self.state.links.remove(n);
            self.save();
            return None;
        };
        let link = &mut self.state.links[n];
        link.root = root;
        link.seen = seen;
        for p in &mut self.state.parts {
            if p.file == file {
                p.root = root;
            }
        }
        self.state.keep_retired(root, records);
        self.save();
        Some(n)
    }
}

fn refused(text: impl Into<String>) -> LarsalError {
    LarsalError::Refused(text.into())
}

fn message(m: &Message, name: &str, address: &str) -> SyncMessage {
    SyncMessage {
        id: m.id().to_owned(),
        text: m.text(name, address),
    }
}

/// The failure of a call outside a run as an error with Larsal's words.
fn failure(f: Fail, address: &str) -> LarsalError {
    let m = match f {
        Fail::CertChanged => Message::CertChanged,
        Fail::SignedOut => Message::SignedOut,
        Fail::Offline | Fail::Limited(_) => {
            return refused(format!(
                "The server \"{address}\" cannot be reached. Try again later."
            ));
        }
        Fail::Address => return refused("This is not a server address Larsal can use."),
        Fail::Protocol | Fail::Key => Message::Error,
    };
    refused(m.text("", address))
}

fn report_error(r: &Report, address: &str) -> LarsalError {
    r.messages.first().map_or_else(
        || failure(Fail::Offline, address),
        |m| refused(m.text("", address)),
    )
}

/// LD-325 (5) (a): a new key under `label` in the login keychain (until
/// W-02 gives the Secure Enclave). Tests: the test-seam key, never a
/// keychain (LD-317 (2)).
#[cfg(not(test))]
fn make_key(label: &str) -> Result<DeviceKey, KeyError> {
    DeviceKey::make(larsal_platform::device_key::Store::LoginKeychain, label)
}

#[cfg(test)]
fn make_key(_label: &str) -> Result<DeviceKey, KeyError> {
    DeviceKey::test_seam()
}

/// LD-325 (5) (a): the key under `label` whose public key is `public`.
/// Tests: none (a test keeps its clients for the whole test).
#[cfg(not(test))]
fn open_key(label: &str, public: &[u8; 65]) -> Result<DeviceKey, KeyError> {
    DeviceKey::open(
        larsal_platform::device_key::Store::LoginKeychain,
        label,
        public,
    )
}

#[cfg(test)]
fn open_key(_label: &str, _public: &[u8; 65]) -> Result<DeviceKey, KeyError> {
    Err(KeyError::Missing)
}

/// The key of a key-file part: FMT-18's 32 bytes, used as they are.
fn part_key(part: &SecretBytes) -> Option<KeyFileKey> {
    read_key_file(std::io::Cursor::new(part.expose()), &Limits::DEFAULT).ok()
}

/// 32 hex digits of 16 bytes from larsal-crypto's random source.
fn random_hex() -> Result<String, LarsalError> {
    let mut b = [0u8; 16];
    larsal_crypto::random::fill(&mut b)
        .map_err(|_| refused("The random source failed. Try again."))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// The open vault a run syncs.
struct OpenVault<'a> {
    session: &'a Session,
    vault: u64,
}

impl Local for OpenVault<'_> {
    fn read(&self) -> Option<Result<(Vec<u8>, Measures), Unproven>> {
        // SYN-03.9 (C1-A7b): after Merge anyway, the measures from before it.
        let answered = self
            .session
            .sync_with(|i| i.vaults.get(&self.vault).and_then(|o| o.answered));
        let read = self.session.sync_read(self.vault)?;
        Some(read.map(|(bytes, measures)| (bytes, answered.unwrap_or(measures))))
    }

    fn merge(&self, server: &[u8], version: u64) -> Merge {
        self.session.merge_server(self.vault, server, version)
    }
}

impl Session {
    fn sync_state_file(&self) -> Option<PathBuf> {
        self.settings.folder().map(|d| {
            let suffix = if cfg!(debug_assertions) { "_debug" } else { "" };
            d.join(format!("sync-state{suffix}.json"))
        })
    }

    /// `f` on the sync state, loaded first; the lock is a leaf.
    fn sync_with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let file = self.sync_state_file();
        let mut i = self.sync.inner();
        i.load(file);
        f(&mut i)
    }

    /// SYN-03.2 (C1R2-03): drops each link with no root yet (a download before
    /// its first run) that no run can link any more: its file is gone or moved,
    /// or holds other bytes than the download. A download that a vault unlocked
    /// now opened from that file is never dropped (`adopt` takes it), and a file
    /// that does not read for a moment (permissions, busy) keeps its link
    /// (C1R3B-03). Its pointer stays, as `adopt` keeps it, so a file still opens.
    /// Such a link then blocks nothing: a new download of its server vault, the
    /// list and the next run.
    fn sync_drop_stale(&self) {
        let waiting: Vec<(String, [u8; 32])> = self.sync_with(|i| {
            i.state
                .links
                .iter()
                .filter(|l| l.root == UNKNOWN_ROOT)
                .map(|l| (l.file.clone(), l.local_sha))
                .collect()
        });
        let stale: Vec<(String, [u8; 32])> = waiting
            .into_iter()
            .filter(|(file, sha)| {
                let path = Path::new(file);
                match larsal_platform::macos::open_regular(&larsal_core::storage::real_path(path))
                    .map_err(|e| larsal_format::Error::Io(e.kind()))
                    .and_then(|f| larsal_format::detect::read_vault(f, &Limits::DEFAULT))
                {
                    Ok(bytes) => {
                        if larsal_crypto::secret::ct_eq(&larsal_sync::sync::hash(&bytes), sha) {
                            return false;
                        }
                    }
                    // Gone or moved; any other read failure is for a moment.
                    Err(larsal_format::Error::Io(kind)) if kind != std::io::ErrorKind::NotFound => {
                        return false;
                    }
                    Err(_) => {}
                }
                !self.sync_download_open(path, sha)
            })
            .collect();
        self.sync_drop_links(&stale);
    }

    /// Whether a vault unlocked now opened the downloaded bytes `sha` from the
    /// file `path` (SYN-03.2: `adopt` takes its link at the next run).
    fn sync_download_open(&self, path: &Path, sha: &[u8; 32]) -> bool {
        let opened: Vec<u64> = self.sync_with(|i| {
            i.vaults
                .iter()
                .filter(|(_, o)| {
                    o.path == path
                        && o.opened
                            .is_some_and(|(opened, _)| larsal_crypto::secret::ct_eq(&opened, sha))
                })
                .map(|(id, _)| *id)
                .collect()
        });
        // The session lock is taken outside the sync lock, a leaf.
        opened
            .into_iter()
            .any(|id| self.with_open(id, |_, p, _| Ok(p == path)).unwrap_or(false))
    }

    /// Drops the links with no root yet of `stale` (file and downloaded SHA-256);
    /// their pointers stay.
    fn sync_drop_links(&self, stale: &[(String, [u8; 32])]) {
        if stale.is_empty() {
            return;
        }
        self.sync_with(|i| {
            i.state.links.retain(|l| {
                l.root != UNKNOWN_ROOT
                    || !stale
                        .iter()
                        .any(|(f, s)| *f == l.file && larsal_crypto::secret::ct_eq(s, &l.local_sha))
            });
            i.save();
        });
    }

    fn sync_reserve(&self, claim: Claim) -> Result<Transfer<'_>, LarsalError> {
        self.sync_drop_stale();
        let claim = Arc::new(claim);
        self.sync_with(|i| {
            if i.unavailable(&claim) || i.transfers.iter().any(|c| c.overlaps(&claim)) {
                return Err(refused(
                    "This vault or destination is already linked or in use for sync.",
                ));
            }
            i.transfers.push(claim.clone());
            Ok(Transfer {
                sync: &self.sync,
                claim,
            })
        })
    }

    /// SYN-03.1 step 2: keeps `part` in the device store (the login keychain
    /// until W-02). Tests: a map, never a keychain (LD-317 (2)).
    #[cfg(not(test))]
    fn part_put(&self, label: &str, part: &SecretBytes) -> Result<(), KeyError> {
        larsal_platform::device_key::part_put(label, part)
    }

    #[cfg(test)]
    fn part_put(&self, label: &str, part: &SecretBytes) -> Result<(), KeyError> {
        self.sync_with(|i| {
            if i.store_refuses {
                return Err(KeyError::Missing);
            }
            let bytes = SecretBytes::new(part.expose().to_vec());
            i.device_store.insert(label.to_owned(), bytes);
            Ok(())
        })
    }

    #[cfg(not(test))]
    fn part_get(&self, label: &str) -> Option<SecretBytes> {
        PART_READ.get()?(label).ok()
    }

    /// Tests: `store_refuses` fails the read too, as a keychain that denies it.
    #[cfg(test)]
    fn part_get(&self, label: &str) -> Option<SecretBytes> {
        self.sync_with(|i| {
            i.device_store
                .get(label)
                .filter(|_| !i.store_refuses)
                .map(|part| SecretBytes::new(part.expose().to_vec()))
        })
    }

    #[cfg(not(test))]
    fn part_keep(&self, label: &str, part: &SecretBytes) -> Result<(), KeyError> {
        PART_KEEP.get().ok_or(KeyError::Missing)?(label, part)
    }

    #[cfg(test)]
    fn part_keep(&self, label: &str, part: &SecretBytes) -> Result<(), KeyError> {
        self.part_put(label, part)
    }

    #[cfg(not(test))]
    fn part_remove(&self, label: &str) {
        // ponytail: a part that macOS would not remove stays in the keychain,
        // where nothing names it; a keychain clean-up can come with Stop syncing.
        let _ = larsal_platform::device_key::part_remove(label);
    }

    #[cfg(test)]
    fn part_remove(&self, label: &str) {
        self.sync_with(|i| i.device_store.remove(label));
    }

    /// SYN-03.2: the key-file part of the file at `path`, when the state has a
    /// pointer for that file and the device store the part.
    pub(crate) fn sync_part(&self, path: &Path) -> Option<(KeyFileKey, String)> {
        let file = path.to_string_lossy();
        let label = self.sync_with(|i| {
            let part = i.state.parts.iter().find(|p| p.file == file);
            part.map(|p| p.label.clone())
        })?;
        let part = self.part_get(&label)?;
        Some((part_key(&part)?, PART_NAME.to_owned()))
    }

    /// C1R3B-01: whether `key` is a key-file part this Mac keeps for the vault
    /// `root`: its bytes equal, by a constant-time compare, a part the device
    /// store holds under a label of that root, from a pointer or a link in the
    /// sync state or from this Mac's vault state. So a Finder copy and a lost
    /// sync state still find it; a key file this Mac never kept is none.
    pub(crate) fn sync_root_part(&self, root: Uuid, key: &KeyFileKey) -> bool {
        self.root_labels(root)
            .iter()
            .filter_map(|label| self.part_get(label).as_ref().and_then(part_key))
            .any(|part| larsal_crypto::secret::ct_eq(part.key().expose(), key.key().expose()))
    }

    /// The labels this Mac knows for the vault `root`'s parts: its vault state's,
    /// and the sync state's pointers and links.
    fn root_labels(&self, root: Uuid) -> Vec<String> {
        let mut labels = self.part_labels(root);
        labels.extend(self.sync_with(|i| {
            let pointers = i.state.parts.iter().filter(|p| p.root == root);
            let links = i.state.links.iter().filter(|l| l.root == root);
            pointers
                .map(|p| p.label.clone())
                .chain(links.map(|l| part_label(&l.server, l.vault_id)))
                .collect::<Vec<_>>()
        }));
        labels.sort();
        labels.dedup();
        labels
    }

    /// SYN-03.12 (C1R4-04): whether the vault `root` has a part on this Mac that
    /// the device store gives none of, so a sheet for any copy of it (a Finder
    /// copy too) cannot check a typed key against the part.
    pub(crate) fn sync_root_unread(&self, root: Uuid) -> bool {
        let labels = self.root_labels(root);
        !labels.is_empty() && labels.iter().all(|label| self.part_get(label).is_none())
    }

    /// SYN-03.12 (C1R4-01): whether `sha` is the SHA-256 of the bytes a link of
    /// the file at `path` last synced. Those bytes went up keyed by the part, so a
    /// key file that opens them with the typed factor is the part.
    pub(crate) fn sync_last_synced(&self, path: &Path, sha: &[u8; 32]) -> bool {
        let file = path.to_string_lossy();
        self.sync_with(|i| last_synced(&i.state.links, &file, sha))
    }

    /// SYN-03.5 step 2 (C1R4-01): whether `key` is the part the device store
    /// holds for the file at `path`, by a constant-time compare.
    pub(crate) fn sync_is_part(&self, path: &Path, key: &KeyFileKey) -> bool {
        self.sync_part(path).is_some_and(|part| {
            larsal_crypto::secret::ct_eq(part.0.key().expose(), key.key().expose())
        })
    }

    /// C1R3B-02, C1R4-01: the unlock `id` opened its linked file with a typed
    /// factor and the typed key file `key` while the device store gave no part,
    /// from the bytes a link of that file last synced: the key file is the part,
    /// so the store keeps it again under the file's pointer.
    pub(crate) fn sync_restore_part(&self, id: u64, key: &KeyFileKey) {
        let label = self.sync_with(|i| {
            let o = i.vaults.get(&id)?;
            let file = o.path.to_string_lossy();
            let ours = o
                .opened
                .is_some_and(|(sha, _)| last_synced(&i.state.links, &file, &sha));
            let part = i.state.parts.iter().find(|p| p.file == file);
            part.filter(|_| ours).map(|p| p.label.clone())
        });
        if let Some(label) = label.filter(|l| self.part_get(l).is_none()) {
            // ponytail: a store that refuses the write leaves the unlock as it
            // is; the next unlock with the saved key file tries again.
            let _ = self.part_keep(&label, &SecretBytes::new(key.key().expose().to_vec()));
        }
    }

    /// SYN-03.12 (C2bR3-1): whether `key`, given with no typed factor for a copy
    /// of the vault `root` open from `path`, is the part alone of a vault with a
    /// part: `path` has a pointer, or `key` is a part this Mac keeps for `root`.
    pub(crate) fn sync_part_alone(
        &self,
        path: &Path,
        root: Uuid,
        key: Option<&KeyFileKey>,
    ) -> bool {
        key.is_some_and(|key| self.sync_has_part(path) || self.sync_root_part(root, key))
    }

    /// SYN-03.12 (C1-A1): whether the state has a key-file part pointer for the
    /// file at `path`, linked or not.
    pub(crate) fn sync_has_part(&self, path: &Path) -> bool {
        let file = path.to_string_lossy();
        self.sync_with(|i| i.state.parts.iter().any(|p| p.file == file))
    }

    /// SYN-03.12: the key file an unlock or a sheet uses for the file at `path`,
    /// given `typed`, the one the user typed. A file no link names takes
    /// `typed`, else its part when it has one. No sheet replaces the part of a
    /// linked file: `typed` is taken only when it is the part (C1-A12,
    /// `PART_OTHER`), and when the device store gives no part nothing is taken
    /// (C1R2-02, `PART_UNREAD`): a typed key file cannot be checked, and a
    /// password alone would give the vault a key without its part.
    pub(crate) fn sync_sheet_key(
        &self,
        path: &Path,
        typed: Option<(KeyFileKey, String)>,
    ) -> Result<Option<(KeyFileKey, String)>, (&'static str, &'static str)> {
        let file = path.to_string_lossy();
        if !self.sync_with(|i| i.state.links.iter().any(|l| l.file == file)) {
            return Ok(typed.or_else(|| self.sync_part(path)));
        }
        let Some(part) = self.sync_part(path) else {
            return Err(PART_UNREAD);
        };
        match typed {
            Some(t) if !larsal_crypto::secret::ct_eq(part.0.key().expose(), t.0.key().expose()) => {
                Err(PART_OTHER)
            }
            typed => Ok(Some(typed.unwrap_or(part))),
        }
    }

    /// Whether a link names the file `file` and the vault `root`.
    pub(crate) fn sync_links_file(&self, file: &Path, root: Uuid) -> bool {
        let file = file.to_string_lossy();
        self.sync_with(|i| {
            i.state
                .links
                .iter()
                .any(|l| l.file == file && l.root == root)
        })
    }

    /// Whether the open vault `vault` is linked (SYN-03.12).
    pub(crate) fn sync_linked(&self, vault: u64) -> bool {
        self.with_open(vault, |v, path, _| Ok((path.to_path_buf(), v.root.uuid)))
            .is_ok_and(|(path, root)| self.sync_links_file(&path, root))
    }

    /// LD-267 (2): the keys this Mac retired from the server vault `root`.
    pub(crate) fn sync_retired(&self, root: Uuid) -> Vec<Record> {
        self.sync_with(|i| i.state.retired.get(&root).cloned().unwrap_or_default())
    }

    /// LD-267 (2): this Mac retired a key of the vault `root`, kept in the state
    /// when that vault has a part or a link. Earlier ones come at the link.
    pub(crate) fn sync_retire(&self, root: Uuid, record: &Record) {
        self.sync_with(|i| {
            let ours = i.state.links.iter().any(|l| l.root == root)
                || i.state.parts.iter().any(|p| p.root == root);
            if ours && i.state.keep_retired(root, std::slice::from_ref(record)) {
                i.save();
            }
        });
    }

    /// SYN-03.1 steps 1 and 2, LD-427. The vault's `F` goes to the device store
    /// under `label` and its place to the state, before anything of the vault
    /// changes. A vault with a key file keeps it, with its name, its key and
    /// its `MasterKeyChanged`; any other gets a random 32-byte part through the
    /// credential change (MOD-12.10), and the key it had is retired. Field 12
    /// goes. The vault saves when either changed it; with neither, its file
    /// stays as it is.
    fn sync_key_part(
        &self,
        vault: u64,
        file: String,
        root: Uuid,
        label: String,
    ) -> Result<(), LarsalError> {
        let saver = self
            .with_edit_view(vault, |_, s| s.saver.clone())?
            .ok_or(LarsalError::Locked)?;
        let mut sv = crate::saving::locked(&saver);
        let fresh = sv.key_file.is_none();
        let part = match &sv.key_file {
            Some(key) => SecretBytes::new(key.key().expose().to_vec()),
            None => larsal_crypto::random::bytes(32)
                .map_err(|_| refused("The random source failed. Try again."))?,
        };
        let key = part_key(&part).ok_or_else(|| refused("The key part could not be made."))?;
        self.part_put(&label, &part)
            .map_err(|_| refused("macOS could not keep this vault's key part. Nothing changed."))?;
        let replaced = self.sync_with(|i| {
            i.keep_part(Part {
                file,
                root,
                label: label.clone(),
            })
        });
        let replaced = match replaced {
            Ok(replaced) => replaced,
            Err(e) => {
                self.part_remove(&label);
                return Err(e);
            }
        };
        for old in replaced {
            self.part_remove(&old);
        }
        self.keep_part_label(root, &label);
        // MOD-11.31: as `change_key`, none while an earlier change is unsaved.
        let pending = self.with_edit_view(vault, |_, s| s.disk.new_key)?;
        let retiring = if fresh && !pending {
            Some(self.record_of(&sv)?)
        } else {
            None
        };
        let changes = Changes {
            key: Some(KeyChange {
                password: PasswordPart::Untouched,
                had_password: sv.password.is_some(),
                key_file: true,
                hardware: sv.hardware.is_some(),
                min_quality: wizard::min_quality(self),
            }),
            confirmed: wizard::confirms(&[Answer::NoPassword]),
            ..Changes::default()
        };
        // LD-264: past every key time this Mac has seen for the vault.
        let floor = self.key_floor(root);
        let save = self.with_edit(vault, |v, _, _, s| {
            crate::saving::same(s, &saver)?;
            let mut save = !v.public_custom_data.is_empty();
            v.public_custom_data.clear();
            if fresh {
                // MOD-13.11 (C1-A15): the part is no change the user confirmed,
                // so a forced key change set before it stays.
                let forced = v.meta.master_key_change_force_once;
                let mut host = self.host.lock().unwrap_or_else(PoisonError::into_inner);
                settings::apply(
                    v,
                    &changes,
                    &mut host,
                    &Limits::DEFAULT.kdf,
                    crate::views::now(),
                )
                .map_err(|_| refused("The vault's key could not be changed. Nothing changed."))?;
                drop(host);
                v.meta.master_key_change_force_once = forced;
                v.meta.master_key_changed = v.meta.master_key_changed.max(floor);
                s.set_key(&mut sv, None, Some(Some((key, PART_NAME.to_owned()))));
                save = true;
            }
            if save {
                s.changes = s.changes.max(1);
            }
            Ok(save)
        })?;
        drop(sv);
        if let Some(record) = retiring {
            self.retire(root, record);
        }
        self.refresh_look(vault);
        if save && self.save_to(vault, None)?.changes > 0 {
            return Err(refused(
                "The vault could not be saved. Nothing was uploaded.",
            ));
        }
        Ok(())
    }

    /// The vault `id` was saved: a run 2 s later (SYN-03.4). A save after
    /// Merge anyway's measures them as the vault holds them (C1-A7b).
    pub(crate) fn sync_saved(&self, id: u64) {
        let mut i = self.sync.inner();
        let now = i.clock.now_ms();
        if let Some(o) = i.vaults.get_mut(&id) {
            o.schedule.saved(now);
            o.answered = None;
        }
    }

    /// The client of `address`, signed up: made from the stored entry and
    /// the device key when this session has none yet.
    fn sync_client(&self, address: &str) -> Result<Arc<Mutex<Client>>, LarsalError> {
        let entry = self.sync_with(|i| {
            if let Some(c) = i.servers.get(address) {
                return Ok(Err(c.clone()));
            }
            i.state
                .server(address)
                .cloned()
                .map(Ok)
                .ok_or_else(|| refused("Add this server first."))
        })?;
        let entry = match entry {
            Err(client) => return Ok(client),
            Ok(entry) => entry,
        };
        let mut c = Client::new(&entry.address, entry.pin).map_err(|f| failure(f, address))?;
        if let Some(a) = &entry.account {
            let key = open_key(&a.label, &a.public_key).map_err(|_| {
                refused("This Mac's sign-in key for this server is missing. Sign in again.")
            })?;
            c.set_device(a.device, key);
        }
        let c = Arc::new(Mutex::new(c));
        Ok(self.sync_with(|i| i.servers.entry(address.to_owned()).or_insert(c).clone()))
    }

    /// One run for vault `id` when it is linked.
    fn sync_run(&self, id: u64) {
        self.sync_drop_stale();
        // LD-267 (2): read before the sync lock, which is a leaf.
        let records = self
            .sync
            .root(id)
            .map(|root| self.retired_records(root))
            .unwrap_or_default();
        let link = self.sync_with(|i| {
            let open = i.vaults.get(&id)?;
            let n = i.link_of(open).or_else(|| i.adopt(id, &records))?;
            Some(i.state.links[n].clone())
        });
        let Some(mut link) = link else {
            self.sync_with(|i| {
                if let Some(o) = i.vaults.get_mut(&id) {
                    o.schedule.finished();
                    o.left = false;
                }
            });
            return;
        };
        // C1R3B-01: vault-state names the part too, for a lost sync state.
        self.keep_part_label(link.root, &part_label(&link.server, link.vault_id));
        let stopped = self.sync_with(|i| {
            #[cfg(test)]
            {
                let now = i.clock.now_ms();
                i.runs.push((id, now));
            }
            i.stopped.contains(&link.server)
        });
        let report = if stopped {
            Report {
                status: Some(Status::Error),
                messages: vec![Message::CertChanged],
            }
        } else {
            match self.sync_client(&link.server) {
                Ok(client) => {
                    let clock = self.sync_with(|i| i.clock.clone());
                    let mut c = client.lock().unwrap_or_else(PoisonError::into_inner);
                    let local = OpenVault {
                        session: self,
                        vault: id,
                    };
                    larsal_sync::sync::run(&mut c, &mut link, &local, &*clock)
                }
                Err(_) => Report {
                    status: Some(Status::SignedOut),
                    messages: vec![Message::SignedOut],
                },
            }
        };
        // SYN-03.8: the password given is for this run only.
        let _ = self.with_draft_state(id, |_, s| {
            s.sync_given = None;
            Ok(())
        });
        self.sync_with(|i| {
            if report.messages.contains(&Message::CertChanged) {
                i.stopped.insert(link.server.clone());
            }
            i.write_back(link);
            if let Some(o) = i.vaults.get_mut(&id) {
                o.schedule.finished();
                let asked = std::mem::take(&mut o.asked);
                if std::mem::take(&mut o.left) {
                    return;
                }
                if let Some(Status::Synced(t)) = report.status {
                    o.synced_at = Some(t);
                    o.answered = None;
                }
                // SYN-03.8: a 60-second tick does not show the sheet again.
                let was = o.report.as_ref().and_then(|old| old.status);
                o.ask_key = report.status == Some(Status::NeedsPassword)
                    && (asked || was != Some(Status::NeedsPassword));
                if report.status.is_some() || !report.messages.is_empty() {
                    let status = report
                        .status
                        .or_else(|| o.report.as_ref().and_then(|old| old.status))
                        .unwrap_or(Status::Error);
                    o.report = Some(Report {
                        status: Some(status),
                        ..report
                    });
                }
            }
        });
    }

    fn sync_view(&self, id: u64, open: &Open, address: Option<&str>) -> Option<SyncState> {
        let name = crate::session::file_name(&open.path);
        let address = address.unwrap_or("");
        let status = if open.schedule.running() {
            SyncStatus::Syncing
        } else {
            match open.report.as_ref()?.status? {
                Status::Synced(_) => SyncStatus::Synced,
                Status::Syncing => SyncStatus::Syncing,
                Status::Offline => SyncStatus::Offline,
                Status::NeedsPassword => SyncStatus::NeedsPassword,
                Status::ReplacedPassword => SyncStatus::ReplacedPassword,
                Status::SignedOut => SyncStatus::SignedOut,
                Status::Error => SyncStatus::Error,
            }
        };
        Some(SyncState {
            vault: id,
            status,
            synced_at: open.synced_at,
            messages: open
                .report
                .iter()
                .flat_map(|r| r.messages.iter())
                .map(|m| message(m, &name, address))
                .collect(),
            ask_key: open.ask_key,
        })
    }
}

#[uniffi::export]
impl Session {
    /// SYN-01.2: the fingerprint of the certificate the server at
    /// `address` shows, as 8 groups of 8 hex digits, for
    /// `MSG-SYNC-FINGERPRINT`. One handshake; no request is sent.
    ///
    /// # Errors
    /// `Refused` for an address Larsal cannot use or no handshake.
    pub fn sync_fingerprint(&self, address: String) -> Result<String, LarsalError> {
        client::fingerprint(&address)
            .map(|pin| client::printed(&pin))
            .map_err(|f| failure(f, &address))
    }

    /// SYN-01.2, SYN-01.14: after "They match", pins `fingerprint` for the
    /// server at `address` and asks `GET /v1/health`; only a Larsal sync
    /// server is stored.
    ///
    /// # Errors
    /// `Refused` with `MSG-SYNC-NOT-SERVER`, `MSG-SYNC-CERT-CHANGED` or a
    /// plain reason; nothing is stored then.
    pub fn sync_add_server(&self, address: String, fingerprint: String) -> Result<(), LarsalError> {
        let (base, _) =
            client::parse_address(&address).ok_or_else(|| failure(Fail::Address, &address))?;
        let pin = client::read_printed(&fingerprint)
            .ok_or_else(|| refused("This is not a certificate fingerprint."))?;
        let c = Client::new(&base, pin).map_err(|f| failure(f, &base))?;
        if !c.health().map_err(|f| failure(f, &base))? {
            return Err(refused(Message::NotServer.text("", &base)));
        }
        self.sync_with(|i| {
            match i.state.server_mut(&base) {
                Some(s) => s.pin = pin,
                None => i.state.servers.push(larsal_sync::state::Server {
                    address: base.clone(),
                    pin,
                    account: None,
                }),
            }
            i.stopped.remove(&base);
            i.servers.remove(&base);
            i.save();
        });
        Ok(())
    }

    /// SYN-04.2, LD-325 (5) (a): a new account on the server at `address`
    /// with a new device key under a random label; the account, the
    /// device, the label and the public key go into the state.
    ///
    /// # Errors
    /// `Refused` when the server is not added, already has this Mac's
    /// account, or refuses.
    pub fn sync_sign_up(&self, address: String) -> Result<(), LarsalError> {
        let (base, _) =
            client::parse_address(&address).ok_or_else(|| failure(Fail::Address, &address))?;
        let entry = self
            .sync_with(|i| i.state.server(&base).cloned())
            .ok_or_else(|| refused("Add this server first."))?;
        if entry.account.is_some() {
            return Err(refused("This Mac already has an account on this server."));
        }
        let label = random_hex()?;
        let key = make_key(&label)
            .map_err(|_| refused("macOS could not make this Mac's sign-in key."))?;
        let public_key = key
            .public_key()
            .map_err(|_| refused("macOS could not make this Mac's sign-in key."))?;
        let mut c = Client::new(&base, entry.pin).map_err(|f| failure(f, &base))?;
        let made = c.sign_up(key).map_err(|f| failure(f, &base))?;
        let account = Account {
            account: made.account_id,
            device: made.device_id,
            label,
            public_key,
        };
        self.sync_with(|i| {
            if let Some(s) = i.state.server_mut(&base) {
                s.account = Some(account);
            }
            i.servers.insert(base.clone(), Arc::new(Mutex::new(c)));
            i.save();
        });
        Ok(())
    }

    /// SYN-03.1: gives the saved vault `vault` its key-file part (P7) and takes
    /// its field 12 away (LD-427), saving it when either changed it, then
    /// uploads it to the server at `address` with `If-None-Match: *` under a new
    /// `vault_id`, and links it. Runs the KDF: call it off the main thread. A
    /// failed upload leaves the vault with its part, in the device store: it
    /// opens as before, and the next try sends the same part.
    ///
    /// # Errors
    /// `Refused` when the vault has unsaved changes or is linked, its file
    /// fails SYN-03.5 step 2 (`MSG-SYNC-LOCAL-FILE`, `MSG-SYNC-SAVE-FIRST`):
    /// nothing changed then; when the device store or the state refuses the
    /// part, or the upload failed: nothing is linked then.
    pub fn sync_put_vault(&self, vault: u64, address: String) -> Result<SyncState, LarsalError> {
        let (base, _) =
            client::parse_address(&address).ok_or_else(|| failure(Fail::Address, &address))?;
        let (path, root) = self.with_open(vault, |v, p, _| Ok((p.to_path_buf(), v.root.uuid)))?;
        let file = path.to_string_lossy().into_owned();
        let identity = storage::file_id(&path)
            .map_err(|_| refused("The local vault file is unavailable. Try again."))?;
        let unproven = |read: Option<Result<(Vec<u8>, Measures), Unproven>>| {
            read.ok_or_else(|| refused("Save the vault first, then try again."))?
                .map_err(|Unproven(message)| refused(message.text("", "")))
        };
        // Before the vault's key changes: a file that may not go up changes nothing.
        unproven(self.sync_read_file(vault, false))?;
        #[cfg(test)]
        tests::download_started();
        let transfer = self.sync_reserve(Claim {
            path: path.clone(),
            root: Some(root),
            remote: None,
            replaces: Vec::new(),
        })?;
        if storage::file_id(&path) != Ok(identity) {
            return Err(refused("The local vault file changed. Try again."));
        }
        let client = self.sync_client(&base)?;
        let mut id = [0u8; 16];
        larsal_crypto::random::fill(&mut id)
            .map_err(|_| refused("The random source failed. Try again."))?;
        let vault_id = VaultId::from_bytes(id);
        self.sync_key_part(vault, file.clone(), root, part_label(&base, vault_id))?;
        #[cfg(test)]
        tests::put_keyed();
        let identity = storage::file_id(&path)
            .map_err(|_| refused("The local vault file is unavailable. Try again."))?;
        let (bytes, seen) = unproven(self.sync_read(vault))?;
        let mut c = client.lock().unwrap_or_else(PoisonError::into_inner);
        let version = larsal_sync::sync::first_upload(&mut c, &vault_id, &bytes)
            .map_err(|r| report_error(&r, &base))?;
        drop(c);
        let sha = larsal_sync::sync::hash(&bytes);
        let records = self.retired_records(root);
        let link = Link {
            server: base,
            vault_id,
            file,
            root,
            highest: version,
            server_sha: sha,
            local_sha: sha,
            seen,
        };
        self.with_open(vault, |v, p, _| {
            if p != path || v.root.uuid != root {
                return Err(refused("The local vault changed. Try again."));
            }
            Ok(())
        })?;
        if storage::file_id(&path) != Ok(identity) {
            return Err(refused("The local vault file changed. Try again."));
        }
        self.sync_with(|i| {
            if !transfer.ready(i) {
                return Err(refused(
                    "This vault is already linked or its sync was cancelled.",
                ));
            }
            transfer.release(i);
            i.state.keep_retired(root, &records);
            i.state.links.push(link);
            i.save();
            let now = i.clock.now_ms();
            let open = i.vaults.get_mut(&vault).map(|o| {
                o.report = Some(Report {
                    status: Some(Status::Synced(now)),
                    messages: Vec::new(),
                });
                o.synced_at = Some(now);
            });
            Ok(SyncState {
                vault,
                status: SyncStatus::Synced,
                synced_at: open.map(|()| now),
                messages: Vec::new(),
                ask_key: false,
            })
        })
    }

    /// SYN-03.2, SYN-03.7: the vaults of this Mac's account on the server
    /// at `address`. A linked vault listed with a version lower than this
    /// Mac has seen is refused (`MSG-SYNC-ROLLBACK` on its open vault).
    ///
    /// # Errors
    /// `Refused` when the list fails.
    pub fn sync_server_vaults(&self, address: String) -> Result<Vec<SyncServerVault>, LarsalError> {
        let (base, _) =
            client::parse_address(&address).ok_or_else(|| failure(Fail::Address, &address))?;
        let client = self.sync_client(&base)?;
        let listed = client
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .list()
            .map_err(|f| failure(f, &base))?;
        self.sync_drop_stale();
        Ok(self.sync_with(|i| {
            let links: Vec<Link> = i
                .state
                .links
                .iter()
                .filter(|l| l.server == base)
                .cloned()
                .collect();
            for link in &links {
                if let Some(r) = larsal_sync::sync::check_listed(link, &listed) {
                    for o in i.vaults.values_mut() {
                        if o.path.to_string_lossy() == link.file && o.root == link.root {
                            o.report = Some(r.clone());
                        }
                    }
                }
            }
            listed
                .iter()
                .map(|v| SyncServerVault {
                    id: v.id.to_string(),
                    version: v.version,
                    size: v.size,
                    linked: links.iter().any(|l| l.vault_id == v.id),
                })
                .collect()
        }))
    }

    /// SYN-03.2: downloads the server vault `vault_id` to `path`, which the
    /// save panel gave; never over an existing file (mode 0600). Its link and
    /// its key-file part's pointer are written to the state at once, so the file
    /// opens after a restart too; the link takes the vault's root at the first
    /// run after an unlock of the downloaded bytes (F-288). A download whose
    /// bytes have more than the file's frame (SYN-03 T64) gets the pointer only:
    /// it opens and is not linked.
    ///
    /// # Errors
    /// `Refused` when the download fails or the file exists.
    pub fn sync_download(
        &self,
        address: String,
        vault_id: String,
        path: String,
    ) -> Result<(), LarsalError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let (base, _) =
            client::parse_address(&address).ok_or_else(|| failure(Fail::Address, &address))?;
        let id = larsal_sync::state::VaultId::parse(&vault_id)
            .ok_or_else(|| refused("This is not a vault on the server."))?;
        if path.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        let chosen = Path::new(&path);
        let path = chosen
            .parent()
            .and_then(|p| std::fs::canonicalize(p).ok())
            .zip(chosen.file_name())
            .map(|(parent, name)| parent.join(name))
            .ok_or_else(|| refused("The destination folder is unavailable."))?;
        // C1R3B-02: a link with no root yet of this server vault blocks no new
        // download unless a vault unlocked now opened its bytes (F-284): the new
        // download replaces it once it commits (C1R4-03); its pointer stays.
        let waiting: Vec<(String, [u8; 32])> = self.sync_with(|i| {
            i.state
                .links
                .iter()
                .filter(|l| l.root == UNKNOWN_ROOT && l.server == base && l.vault_id == id)
                .map(|l| (l.file.clone(), l.local_sha))
                .collect()
        });
        let replaces: Vec<(String, [u8; 32])> = waiting
            .into_iter()
            .filter(|(file, sha)| !self.sync_download_open(Path::new(file), sha))
            .collect();
        let transfer = self.sync_reserve(Claim {
            path: path.clone(),
            root: None,
            remote: Some((base.clone(), id)),
            replaces,
        })?;
        #[cfg(test)]
        tests::download_started();
        let client = self.sync_client(&base)?;
        let r = client
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id, 0)
            .map_err(|f| failure(f, &base))?;
        let (200, Some(version)) = (r.status, r.version) else {
            let m = if r.status == 404 {
                Message::Gone
            } else {
                Message::Error
            };
            return Err(refused(m.text("", &base)));
        };
        self.sync_with(|i| {
            if !transfer.ready(i) {
                return Err(refused(
                    "This server vault or destination is already linked or in use.",
                ));
            }
            Ok(())
        })?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| refused(format!("The vault could not be saved: {e}.")))?;
        #[cfg(test)]
        tests::server_opened();
        f.write_all(&r.body)
            .and_then(|()| f.sync_all())
            .map_err(|e| refused(format!("The vault could not be saved: {e}.")))?;
        use std::os::unix::fs::MetadataExt;
        let metadata = f
            .metadata()
            .map_err(|e| refused(format!("The vault could not be checked: {e}.")))?;
        let identity = (metadata.dev(), metadata.ino());
        let real = std::fs::canonicalize(&path)
            .map_err(|_| refused("The downloaded vault moved. Nothing was linked."))?;
        let on_disk = std::fs::symlink_metadata(&path)
            .map_err(|_| refused("The downloaded vault moved. Nothing was linked."))?;
        if real != path || !on_disk.is_file() || (on_disk.dev(), on_disk.ino()) != identity {
            return Err(refused(
                "The downloaded vault was replaced. Nothing was linked.",
            ));
        }
        let sha = larsal_sync::sync::hash(&r.body);
        let file = real.to_string_lossy().into_owned();
        let framed = larsal_format::integrity::exact_frame(&r.body, &Limits::DEFAULT);
        let link = Link {
            server: base.clone(),
            vault_id: id,
            file: file.clone(),
            root: UNKNOWN_ROOT,
            highest: version,
            server_sha: sha,
            local_sha: sha,
            // Nothing seen yet: the first run's unlock gives the measures.
            seen: Measures {
                newest: Time(0),
                version: FileVersion { major: 4, minor: 0 },
                kdf: Kdf::AesKdf { rounds: 0 },
            },
        };
        // A failed or cancelled write leaves its file for the user; never unlink a replacement.
        let result = self.sync_with(|i| {
            if !transfer.ready(i) {
                return Err(refused(
                    "This server vault or destination is already linked or in use.",
                ));
            }
            transfer.release(i);
            i.state.links.retain(|l| !transfer.claim.replaces(l));
            i.state.parts.retain(|p| p.file != file);
            i.state.parts.push(Part {
                file,
                root: UNKNOWN_ROOT,
                label: part_label(&base, id),
            });
            if framed {
                i.state.links.push(link);
            }
            i.save();
            Ok(())
        });
        #[cfg(test)]
        if result.is_ok() {
            tests::download_committed();
        }
        result
    }

    /// Sync now (SYN-03.4): the next tick runs the vault's sync; nothing
    /// while it is locked.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn sync_now(&self, vault: u64) -> Result<(), LarsalError> {
        self.sync_with(|i| {
            i.vaults
                .get_mut(&vault)
                .map(|o| {
                    o.schedule.sync_now();
                    o.asked = true;
                })
                .ok_or(LarsalError::UnknownVault)
        })
    }

    /// SYN-03.8, the sheet's Open: the next tick's run opens the server copy with
    /// `password` and this vault's key-file part and hardware key. Its status
    /// and messages say what came of it: `MSG-SYNC-OTHER-KEY` again,
    /// `MSG-SYNC-OLD-KEY`, `MSG-SYNC-OTHER-VAULT`, or Synced. The password goes
    /// into a secret type at once and lives until that run ends or the vault
    /// locks. Cancel calls nothing.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong`.
    pub fn sync_open_copy(&self, vault: u64, password: String) -> Result<(), LarsalError> {
        let password = SecretString::new(password);
        if password.len() > crate::session::MAX_TEXT {
            return Err(LarsalError::TooLong);
        }
        self.with_draft_state(vault, |_, s| {
            s.sync_given = Some(password);
            Ok(())
        })?;
        self.sync_now(vault)
    }

    /// SYN-03.9, the answer to `MSG-SYNC-OLD-KEY`. Skip (`merge_anyway` false)
    /// takes nothing of the copy; Merge anyway runs the content merge and saves.
    /// Either way the vault keeps this Mac's key, and the next tick's run uploads
    /// the vault over that copy's version. Runs the KDF with Merge anyway: call
    /// it off the main thread.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`; `Refused` when no copy waits, the vault is not
    /// linked, or the merge or its save failed: nothing goes up then.
    pub fn sync_old_key(&self, vault: u64, merge_anyway: bool) -> Result<(), LarsalError> {
        let before = self.with_vault(vault, |v| Ok(measures(v)))?;
        let (version, sha) = self.answer_old_key(vault, merge_anyway)?;
        self.sync_with(|i| {
            let open = i.vaults.get(&vault).ok_or(LarsalError::UnknownVault)?;
            let n = i
                .link_of(open)
                .ok_or_else(|| refused("This vault is not on a server."))?;
            // The copy's own measures are not recorded: they may be planted.
            let link = &mut i.state.links[n];
            if version >= link.highest {
                link.highest = version;
                link.server_sha = sha;
            }
            // The server does not hold this Mac's content: the next run uploads.
            link.local_sha = [0; 32];
            i.save();
            if let Some(o) = i.vaults.get_mut(&vault) {
                o.schedule.sync_now();
                o.report = Some(Report {
                    status: Some(Status::Syncing),
                    messages: Vec::new(),
                });
                // C1-A7b: the copy's times reach no link record.
                o.answered = merge_anyway.then_some(before);
            }
            Ok(())
        })
    }

    /// SYN-03.12: Save as key file. Writes the key-file part of a vault that is
    /// linked or has a part kept for sync (a first upload that failed) at
    /// `path` from the save panel, in the XML 2.0 layout of FMT-18.20, mode
    /// 0400, never over a file (FMT-18.22), and reads it back (FMT-18.23).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong`; `Refused` when the vault has no
    /// part kept for sync.
    pub fn sync_save_part(&self, vault: u64, path: String) -> Result<Outcome, LarsalError> {
        if path.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        let file = self.with_open(vault, |_, p, _| Ok(p.to_path_buf()))?;
        if !self.sync_linked(vault) && !self.sync_has_part(&file) {
            return Err(refused("This vault is not on a server."));
        }
        let saver = self
            .with_edit_view(vault, |_, s| s.saver.clone())?
            .ok_or(LarsalError::Locked)?;
        let part = crate::saving::locked(&saver)
            .key_file
            .as_ref()
            .map(KeyFileKey::duplicate)
            .ok_or_else(|| refused("This vault is not on a server."))?;
        let bytes: &[u8; 32] = part
            .key()
            .expose()
            .try_into()
            .map_err(|_| refused("The key part could not be read."))?;
        Ok(
            match wizard::write_key_file(Path::new(&path), Some(bytes)) {
                Ok((written, _))
                    if larsal_crypto::secret::ct_eq(
                        written.key().expose(),
                        part.key().expose(),
                    ) =>
                {
                    Outcome::Done
                }
                Ok(_) => {
                    let _ = std::fs::remove_file(&path);
                    wizard::refused("M07-25", "The key file did not read back the same.")
                }
                Err(outcome) => outcome,
            },
        )
    }

    /// SYN-03.2: connects the device store for the unlocks of linked vaults. Call
    /// it once at launch, before the first unlock; the first
    /// [`Session::sync_tick`] does it too. Before it, a linked vault does not open.
    pub fn sync_start(&self) {
        #[cfg(not(test))]
        let _ = PART_READ.set(larsal_platform::device_key::part_get);
        #[cfg(not(test))]
        let _ = PART_KEEP.set(larsal_platform::device_key::part_put);
    }

    /// Runs every run that is due now (SYN-03.4), one after another, and
    /// gives every linked open vault's state. Call it off the main thread,
    /// about once a second.
    pub fn sync_tick(&self) -> Vec<SyncState> {
        self.sync_start();
        let ids: Vec<u64> = self.sync_with(|i| i.vaults.keys().copied().collect());
        // SYN-03.4: busy is read from the session before the sync lock.
        let busy: Vec<(u64, bool)> = ids
            .into_iter()
            .map(|id| {
                let busy = self
                    .with_share(id, |slot| {
                        slot.vault.is_none()
                            || crate::saving::sync_busy(slot.edit, slot.share)
                            || slot
                                .edit
                                .saver
                                .as_ref()
                                .is_none_or(|k| k.try_lock().is_err())
                    })
                    .unwrap_or(true);
                (id, busy)
            })
            .collect();
        let due: Vec<u64> = self.sync_with(|i| {
            let now = i.clock.now_ms();
            busy.iter()
                .filter(|(id, busy)| {
                    i.vaults
                        .get_mut(id)
                        .is_some_and(|o| o.schedule.start(now, *busy))
                })
                .map(|(id, _)| *id)
                .collect()
        });
        for id in due {
            self.sync_run(id);
        }
        self.sync_with(|i| {
            let ids: Vec<u64> = i.vaults.keys().copied().collect();
            ids.into_iter()
                .filter_map(|id| {
                    let open = i.vaults.get(&id)?;
                    let n = i.link_of(open)?;
                    let address = i.state.links[n].server.clone();
                    let view = self.sync_view(id, open, Some(&address))?;
                    // SYN-03.8: the sheet is asked for once.
                    i.vaults.get_mut(&id)?.ask_key = false;
                    Some(view)
                })
                .collect()
        })
    }

    /// The sync state of vault `vault`; `None` when it is not linked or
    /// has not run.
    #[must_use]
    pub fn sync_state(&self, vault: u64) -> Option<SyncState> {
        self.sync_with(|i| {
            let open = i.vaults.get(&vault)?;
            let address = i.link_of(open).map(|n| i.state.links[n].server.clone());
            self.sync_view(vault, open, address.as_deref())
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
