//! Sync with App's own server (E16-S7a; SYN-03, SYN-04), app-ffi's `sync`
//! feature over app-sync: adding a server and pinning its certificate
//! (SYN-01.2, SYN-01.14), sign-up with a new device key (SYN-04.2,
//! LD-325 (5) (a)), putting a vault on the server (SYN-03.1 step 3),
//! taking a server vault to this Mac (SYN-03.2), and each open vault's runs
//! on its schedule (SYN-03.4) with their status (SYN-03.13).
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
//!   (SYN-03.3, SYN-04.6); the session token lives in app-sync's client.
//! - Every text here is App's own (SYN-01.9).

use crate::session::{AppError, Session};
use app_core::guard::newest;
use app_model::{FileVersion, Uuid, Vault};
use app_platform::device_key::{DeviceKey, KeyError};
use app_sync::client::{self, Fail, Server};
use app_sync::state::{Account, Link, Measures, State};
use app_sync::sync::{Clock, Local, Merge, Message, Report, Schedule, Status, SystemClock};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

type Client = Server<DeviceKey>;

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

/// One message of SYN-03 in App's words.
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
}

/// A download waiting for its unlock to be linked (SYN-03.2).
#[derive(Debug, Clone)]
struct Pending {
    server: String,
    vault_id: app_sync::state::VaultId,
    path: PathBuf,
    version: u64,
    sha: [u8; 32],
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
    pending: Vec<Pending>,
    /// Servers whose certificate changed: no run until the user adds the
    /// server again (SYN-03.10).
    stopped: BTreeSet<String>,
    /// Tests: the clock's time at the start of each run of a linked vault.
    #[cfg(test)]
    runs: Vec<(u64, u64)>,
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
            pending: Vec::new(),
            stopped: BTreeSet::new(),
            #[cfg(test)]
            runs: Vec::new(),
        }))
    }
}

impl Syncs {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The vault `id` was unlocked: its schedule starts (SYN-03.4).
    pub(crate) fn unlocked(&self, id: u64, path: &Path, root: Uuid) {
        let mut i = self.inner();
        let now = i.clock.now_ms();
        let mut schedule = Schedule::default();
        schedule.unlocked(now);
        let report = i.vaults.remove(&id).and_then(|o| o.report);
        i.vaults.insert(
            id,
            Open {
                path: path.to_path_buf(),
                root,
                schedule,
                report,
                synced_at: None,
            },
        );
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

    fn link_of(&self, open: &Open) -> Option<usize> {
        let file = open.path.to_string_lossy();
        self.state
            .links
            .iter()
            .position(|l| l.file == file && l.root == open.root)
    }
}

fn refused(text: impl Into<String>) -> AppError {
    AppError::Refused(text.into())
}

fn message(m: &Message, name: &str, address: &str) -> SyncMessage {
    SyncMessage {
        id: m.id().to_owned(),
        text: m.text(name, address),
    }
}

/// The failure of a call outside a run as an error with App's words.
fn failure(f: Fail, address: &str) -> AppError {
    let m = match f {
        Fail::CertChanged => Message::CertChanged,
        Fail::SignedOut => Message::SignedOut,
        Fail::Offline | Fail::Limited(_) => {
            return refused(format!(
                "The server \"{address}\" cannot be reached. Try again later."
            ));
        }
        Fail::Address => return refused("This is not a server address App can use."),
        Fail::Protocol | Fail::Key => Message::Error,
    };
    refused(m.text("", address))
}

fn report_error(r: &Report, address: &str) -> AppError {
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
    DeviceKey::make(app_platform::device_key::Store::LoginKeychain, label)
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
        app_platform::device_key::Store::LoginKeychain,
        label,
        public,
    )
}

#[cfg(test)]
fn open_key(_label: &str, _public: &[u8; 65]) -> Result<DeviceKey, KeyError> {
    Err(KeyError::Missing)
}

/// 32 hex digits of 16 bytes from app-crypto's random source.
fn random_hex() -> Result<String, AppError> {
    let mut b = [0u8; 16];
    app_crypto::random::fill(&mut b)
        .map_err(|_| refused("The random source failed. Try again."))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// The open vault a run syncs.
struct OpenVault<'a> {
    session: &'a Session,
    vault: u64,
}

impl Local for OpenVault<'_> {
    fn read(&self) -> Option<(Vec<u8>, Measures)> {
        self.session.sync_read(self.vault)
    }

    fn merge(&self, server: &[u8]) -> Merge {
        self.session.merge_server(self.vault, server)
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

    /// The vault `id` was saved: a run 2 s later (SYN-03.4).
    pub(crate) fn sync_saved(&self, id: u64) {
        let mut i = self.sync.inner();
        let now = i.clock.now_ms();
        if let Some(o) = i.vaults.get_mut(&id) {
            o.schedule.saved(now);
        }
    }

    /// The client of `address`, signed up: made from the stored entry and
    /// the device key when this session has none yet.
    fn sync_client(&self, address: &str) -> Result<Arc<Mutex<Client>>, AppError> {
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
        let (link, pending) = self.sync_with(|i| {
            let Some(open) = i.vaults.get(&id) else {
                return (None, None);
            };
            let link = i.link_of(open).map(|n| i.state.links[n].clone());
            let pending = link
                .is_none()
                .then(|| i.pending.iter().find(|p| p.path == open.path).cloned())
                .flatten();
            (link, pending)
        });
        let link = match (link, pending) {
            (Some(link), _) => Some(link),
            (None, Some(p)) => self.sync_link_download(id, &p),
            (None, None) => None,
        };
        let Some(mut link) = link else {
            self.sync_with(|i| {
                if let Some(o) = i.vaults.get_mut(&id) {
                    o.schedule.finished();
                }
            });
            return;
        };
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
                    app_sync::sync::run(&mut c, &mut link, &local, &*clock)
                }
                Err(_) => Report {
                    status: Some(Status::SignedOut),
                    messages: vec![Message::SignedOut],
                },
            }
        };
        self.sync_with(|i| {
            if report.messages.contains(&Message::CertChanged) {
                i.stopped.insert(link.server.clone());
            }
            let at = i
                .state
                .links
                .iter()
                .position(|l| l.vault_id == link.vault_id && l.server == link.server);
            if let Some(at) = at
                && i.state.links[at] != link
            {
                i.state.links[at] = link;
                i.save();
            }
            if let Some(o) = i.vaults.get_mut(&id) {
                o.schedule.finished();
                if let Some(Status::Synced(t)) = report.status {
                    o.synced_at = Some(t);
                }
                if report.status.is_some() {
                    o.report = Some(report);
                }
            }
        });
    }

    /// SYN-03.2: the downloaded vault `p` was unlocked as vault `id`: its
    /// link is written when the file is still the downloaded one.
    fn sync_link_download(&self, id: u64, p: &Pending) -> Option<Link> {
        let (bytes, seen) = self.sync_read(id)?;
        if app_sync::sync::hash(&bytes) != p.sha {
            return None;
        }
        let root = self.with_vault(id, |v| Ok(v.root.uuid)).ok()?;
        let link = Link {
            server: p.server.clone(),
            vault_id: p.vault_id,
            file: p.path.to_string_lossy().into_owned(),
            root,
            highest: p.version,
            server_sha: p.sha,
            local_sha: p.sha,
            seen,
        };
        self.sync_with(|i| {
            i.pending.retain(|q| q.path != p.path);
            i.state.links.push(link.clone());
            i.save();
        });
        Some(link)
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
    /// `Refused` for an address App cannot use or no handshake.
    pub fn sync_fingerprint(&self, address: String) -> Result<String, AppError> {
        client::fingerprint(&address)
            .map(|pin| client::printed(&pin))
            .map_err(|f| failure(f, &address))
    }

    /// SYN-01.2, SYN-01.14: after "They match", pins `fingerprint` for the
    /// server at `address` and asks `GET /v1/health`; only an App sync
    /// server is stored.
    ///
    /// # Errors
    /// `Refused` with `MSG-SYNC-NOT-SERVER`, `MSG-SYNC-CERT-CHANGED` or a
    /// plain reason; nothing is stored then.
    pub fn sync_add_server(&self, address: String, fingerprint: String) -> Result<(), AppError> {
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
                None => i.state.servers.push(app_sync::state::Server {
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
    pub fn sync_sign_up(&self, address: String) -> Result<(), AppError> {
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

    /// SYN-03.1 step 3: uploads the saved vault `vault` to the server at
    /// `address` with `If-None-Match: *` under a new `vault_id`, and links
    /// it. The key-file part of steps 1 and 2 comes with E16-S7b.
    ///
    /// # Errors
    /// `Refused` when the vault has unsaved changes or is linked, or the
    /// upload failed (nothing is linked then).
    pub fn sync_put_vault(&self, vault: u64, address: String) -> Result<SyncState, AppError> {
        let (base, _) =
            client::parse_address(&address).ok_or_else(|| failure(Fail::Address, &address))?;
        let (path, root) = self.with_open(vault, |v, p, _| Ok((p.to_path_buf(), v.root.uuid)))?;
        let file = path.to_string_lossy().into_owned();
        if self.sync_with(|i| i.state.links.iter().any(|l| l.file == file)) {
            return Err(refused("This vault is already on a server."));
        }
        let (bytes, seen) = self
            .sync_read(vault)
            .ok_or_else(|| refused("Save the vault first, then try again."))?;
        let client = self.sync_client(&base)?;
        let mut c = client.lock().unwrap_or_else(PoisonError::into_inner);
        let (vault_id, version) =
            app_sync::sync::first_upload(&mut c, &bytes).map_err(|r| report_error(&r, &base))?;
        drop(c);
        let sha = app_sync::sync::hash(&bytes);
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
        Ok(self.sync_with(|i| {
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
            SyncState {
                vault,
                status: SyncStatus::Synced,
                synced_at: open.map(|()| now),
                messages: Vec::new(),
            }
        }))
    }

    /// SYN-03.2, SYN-03.7: the vaults of this Mac's account on the server
    /// at `address`. A linked vault listed with a version lower than this
    /// Mac has seen is refused (`MSG-SYNC-ROLLBACK` on its open vault).
    ///
    /// # Errors
    /// `Refused` when the list fails.
    pub fn sync_server_vaults(&self, address: String) -> Result<Vec<SyncServerVault>, AppError> {
        let (base, _) =
            client::parse_address(&address).ok_or_else(|| failure(Fail::Address, &address))?;
        let client = self.sync_client(&base)?;
        let listed = client
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .list()
            .map_err(|f| failure(f, &base))?;
        Ok(self.sync_with(|i| {
            let links: Vec<Link> = i
                .state
                .links
                .iter()
                .filter(|l| l.server == base)
                .cloned()
                .collect();
            for link in &links {
                if let Some(r) = app_sync::sync::check_listed(link, &listed) {
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
    /// save panel gave; never over an existing file (mode 0600). The vault
    /// is linked when that file is unlocked in this session.
    ///
    /// # Errors
    /// `Refused` when the download fails or the file exists.
    pub fn sync_download(
        &self,
        address: String,
        vault_id: String,
        path: String,
    ) -> Result<(), AppError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let (base, _) =
            client::parse_address(&address).ok_or_else(|| failure(Fail::Address, &address))?;
        let id = app_sync::state::VaultId::parse(&vault_id)
            .ok_or_else(|| refused("This is not a vault on the server."))?;
        if path.len() > 4096 {
            return Err(AppError::TooLong);
        }
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
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| refused(format!("The vault could not be saved: {e}.")))?;
        f.write_all(&r.body)
            .and_then(|()| f.sync_all())
            .map_err(|e| refused(format!("The vault could not be saved: {e}.")))?;
        let real = std::fs::canonicalize(&path).unwrap_or_else(|_| PathBuf::from(&path));
        let pending = Pending {
            server: base,
            vault_id: id,
            path: real,
            version,
            sha: app_sync::sync::hash(&r.body),
        };
        self.sync_with(|i| i.pending.push(pending));
        Ok(())
    }

    /// Sync now (SYN-03.4): the next tick runs the vault's sync; nothing
    /// while it is locked.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn sync_now(&self, vault: u64) -> Result<(), AppError> {
        self.sync_with(|i| {
            i.vaults
                .get_mut(&vault)
                .map(|o| o.schedule.sync_now())
                .ok_or(AppError::UnknownVault)
        })
    }

    /// Runs every run that is due now (SYN-03.4), one after another, and
    /// gives every linked open vault's state. Call it off the main thread,
    /// about once a second.
    pub fn sync_tick(&self) -> Vec<SyncState> {
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
                    self.sync_view(id, open, Some(&address))
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
mod tests;
