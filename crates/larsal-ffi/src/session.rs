//! The session (E5-S2): the open vaults, locked or unlocked, and which one is
//! shown. Swift holds it as a handle (`Session`, a UniFFI Object) and asks
//! it for views without secrets (`views.rs`). Start-up and the instance
//! channel reach the app's one session through [`open`] and [`lock_all`]
//! (APP-09.12, APP-09.15).
//!
//! Guarantees:
//! - a password crosses from Swift once, when an unlock starts, and goes
//!   into a `SecretString` at once (APP-06.11); passwords, key file keys and
//!   opened vaults live only in wiping types and are wiped on lock, close and
//!   failure (APP-06.17, AT-E07);
//! - the session lock is never held during the KDF; a lock or close that
//!   arrives while an unlock runs wins, and the opened vault is dropped
//!   (APP-06.16);
//! - every export checks its ids and text sizes and answers with a typed
//!   [`LarsalError`] that holds no secret (AT-E03);
//! - every lock, lock-all and close first clears Larsal's clipboard copy while
//!   the clipboard still holds it (APP-03.15, SC-03).

use crate::edit::{EditState, Keep};
use crate::hwkey::{Choice, KeyPick};
use crate::messages::{self, Action, Message};
use crate::start::LarsalEvents;
use crate::views::Rated;
use larsal_crypto::kdf::{CostReport, Host};
use larsal_crypto::secret::SecretString;
use larsal_format::error::KeyFileReason;
use larsal_format::keyfile::{KeyFileKey, read_key_file};
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Error, Opened};
use larsal_model::Vault;
use larsal_platform::clipboard::Clipboard;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

/// The longest text any export takes (AT-E03): passwords, field names,
/// queries. Longer text is refused with [`LarsalError::TooLong`].
pub(crate) const MAX_TEXT: usize = 64 * 1024;
/// The longest path any export takes, in bytes.
const MAX_PATH: usize = 4096;

/// Errors of the session's exports. Each names what went wrong in plain
/// words and holds no secret (AT-E03, Rust rule 8).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum LarsalError {
    /// The vault id names no open vault.
    UnknownVault,
    /// The entry id names no entry of this vault.
    UnknownEntry,
    /// The group id names no group of this vault.
    UnknownGroup,
    /// The entry has no field of that name.
    UnknownField,
    /// The vault is locked.
    Locked,
    /// A text or path over [`MAX_TEXT`] or the path limit.
    TooLong,
    /// The clipboard could not be written; nothing was copied and no
    /// countdown runs (APP-03.21 `MSG-COPY-FAILED`).
    NotAvailable,
    /// M09-07 with the path as given (APP-09.15 (a)).
    CannotOpen(String),
    /// An edit or a save the vault refused, in plain words without any
    /// value (E5-S5: a field name, a size limit, the bin, a failed save).
    Refused(String),
}

impl std::fmt::Display for LarsalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownVault => f.write_str("This vault is no longer open."),
            Self::UnknownEntry => f.write_str("This entry is no longer in the vault."),
            Self::UnknownGroup => f.write_str("This group is no longer in the vault."),
            Self::UnknownField => f.write_str("This entry has no such field."),
            Self::Locked => f.write_str("This vault is locked."),
            Self::TooLong => f.write_str("The text is too long."),
            Self::NotAvailable => f.write_str("Could not copy to the clipboard. Try again."),
            Self::CannotOpen(v) => write!(
                f,
                "Could not open {v}. It does not exist or cannot be read."
            ),
            Self::Refused(v) => f.write_str(v),
        }
    }
}

impl std::error::Error for LarsalError {}

/// A message for the unlock form's error line (APP-06, UL-ERR).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnlockMessage {
    /// The table's ID, for example `M06-06`.
    pub id: String,
    /// The text, in our words; no secret, no file text (APP-06.18).
    pub text: String,
    /// M06-23's smaller second line.
    pub detail: Option<String>,
    /// M06-05: show the link "Unlock with a blank password" (APP-06.12).
    pub blank_password: bool,
    /// M06-02: show the button "Import…".
    pub import: bool,
    /// The message is about the key file: it gets the focus (APP-06.17).
    pub about_key_file: bool,
}

impl From<Message> for UnlockMessage {
    fn from(m: Message) -> Self {
        let n: u32 = m.id.trim_start_matches("M06-").parse().unwrap_or(0);
        Self {
            about_key_file: (7..=16).contains(&n) || n == 30,
            blank_password: m.action == Some(Action::BlankPassword),
            import: m.action == Some(Action::Import),
            id: m.id.to_owned(),
            text: m.text,
            detail: m.detail,
        }
    }
}

/// What an unlock attempt gave.
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UnlockResult {
    /// The vault is open in the session.
    Unlocked,
    /// The vault stays locked; show the message (APP-06.17).
    Failed {
        /// For UL-ERR.
        message: UnlockMessage,
    },
    /// M06-34 (APP-06.14): ask, then call `approve_unlock` or
    /// `cancel_unlock`. No KDF has run; the credentials wait in Rust.
    Ask {
        /// The alert's message.
        message: String,
        /// The alert's details.
        details: String,
    },
    /// Nothing happened: an unlock of this vault is already running, it is
    /// unlocked already, or a lock or close arrived during the attempt and
    /// its result was dropped (APP-06.10, APP-06.16).
    Ignored,
}

/// One open vault, as the vault switcher and the unlock view show it. No
/// vault content: the name is the file name (APP-06.2).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultInfo {
    /// The session's id for this vault.
    pub id: u64,
    /// The file name without `.larsalvault`, cleaned (APP-06.2, APP-06.18).
    pub name: String,
    /// The path with the home folder as `~` (UL-PATH).
    pub path: String,
    /// The tile's hue, 0 to 359, the same for a path on every show (UL-TILE).
    pub hue: u32,
    /// Locked (the unlock view shows) or unlocked.
    pub locked: bool,
    /// An unlock runs.
    pub unlocking: bool,
    /// The shown vault.
    pub shown: bool,
    /// The public colour of the header as `0xRRGGBB` (FMT-03.23), from the
    /// authenticated header once unlocked; `None` when unset or invalid.
    pub colour: Option<u32>,
    /// The public icon index of the header (FMT-03.23), 0 or more; -1 when
    /// unset or invalid. The screen checks it against Larsal's vault icon set.
    pub icon: i32,
    /// When it was last locked in this session (unix seconds); `None` when
    /// it was never unlocked.
    pub locked_at: Option<i64>,
    /// MOD-13.8: the forced key change prompt's words while this unlock
    /// waits for a new master key (window.rs); `None` otherwise. Meanwhile
    /// the vault counts as locked for Auto-Type and the SSH agents.
    pub key_change: Option<String>,
}

/// Credentials that wait for the M06-34 answer.
struct Pending {
    password: Option<SecretString>,
    key: Option<(KeyFileKey, String)>,
    hardware: Option<Choice>,
    report: CostReport,
}

struct Slot {
    id: u64,
    /// The canonical path (APP-09.15 (a)).
    path: PathBuf,
    vault: Option<Box<Vault>>,
    pending: Option<Pending>,
    unlocking: bool,
    /// Counts locks and closes, so an unlock that started before one drops
    /// its result (APP-06.16).
    epoch: u64,
    /// Counts the doors that may change the vault: every
    /// [`Session::with_edit`] (edits, reload, merge) and each share import.
    /// A share import tried on a copy swaps its result in only while this
    /// is what it was at the copy (F-165).
    version: u64,
    /// A message of an unlock with passed-in credentials, waiting for the
    /// user to show the vault (APP-06.24).
    message: Option<UnlockMessage>,
    /// The public colour and icon (FMT-03.23).
    look: (Option<u32>, i32),
    /// When the vault was last locked, unix seconds.
    locked_at: Option<i64>,
    /// Strength ratings and the Health Check of the unlocked vault (LD-137);
    /// no secret.
    rated: Rated,
    /// The editor's draft, what saving needs and the unsaved changes
    /// (edit.rs); wiped on lock.
    edit: EditState,
    /// The online breach check (reports.rs, FEA-06.12): dropped on lock
    /// and close, with every hash and count.
    breach: Option<crate::reports::Breach>,
    /// An unlock whose window notices are not taken yet (window.rs,
    /// MOD-09.7, MOD-13.7).
    fresh: bool,
    /// MOD-13.8: the forced prompt's words until the key is changed.
    forced: Option<String>,
    /// The shared groups' passes and what they last saw (share.rs).
    share: crate::share::State,
    /// INT-08.34: the key file of the last unlock, resolved; never one
    /// whose path holds a protected value (SR-12). Kept while the vault is
    /// locked: the file is still its key.
    key_file: Option<PathBuf>,
    /// The key file of the attempt under way; `key_file` takes it only when
    /// the vault opens, so a failed attempt changes nothing.
    trying_key: Option<Option<PathBuf>>,
}

impl Slot {
    fn lock(&mut self) {
        if self.vault.take().is_some() {
            self.locked_at = Some(unix_now());
        }
        self.pending = None;
        self.share = crate::share::State::default();
        self.rated = Rated::default();
        self.edit = EditState::default();
        self.breach = None;
        (self.fresh, self.forced) = (false, None);
        self.epoch = self.epoch.wrapping_add(1);
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The 12-byte name prefix of the public keys (FMT-03.23), as hex bytes
/// (AGENTS.md rule 1).
const PUBLIC_PREFIX: [u8; 12] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x5F,
];

/// FMT-03.23: the public colour (a String `#rrggbb`) and icon (an Int32 of
/// 0 or more); an invalid value is not shown.
pub(crate) fn public_look<'a>(
    items: impl Iterator<Item = (u8, &'a [u8], &'a [u8])>,
) -> (Option<u32>, i32) {
    use larsal_format::kdf_params::{INT32, STRING};
    let (mut colour, mut icon) = (None, -1);
    for (kind, name, value) in items {
        let Some(key) = name.strip_prefix(&PUBLIC_PREFIX[..]) else {
            continue;
        };
        if key == [0x43, 0x4F, 0x4C, 0x4F, 0x52] && kind == STRING {
            colour = value
                .strip_prefix(b"#")
                .filter(|hex| hex.len() == 6 && hex.iter().all(u8::is_ascii_hexdigit))
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u32::from_str_radix(hex, 16).ok());
        } else if key == [0x49, 0x43, 0x4F, 0x4E] && kind == INT32 {
            icon = <[u8; 4]>::try_from(value)
                .map(i32::from_le_bytes)
                .ok()
                .filter(|n| *n >= 0)
                .unwrap_or(-1);
        }
    }
    (colour, icon)
}

/// The look of a locked vault from the first bytes of its file: the outer
/// header read without a key (FMT-02.27), unauthenticated, shown only as
/// FMT-03.23 allows. Reads at most 64 KiB; a longer header gives no look.
fn header_look(path: &Path) -> (Option<u32>, i32) {
    use std::io::Read;
    // LD-277 (4), APP-05.24: a dataless file is never fetched for its look
    // (an instance-channel open, `vault_look`): it gives none.
    if larsal_platform::macos::dataless(path) {
        return (None, -1);
    }
    let mut head = Vec::new();
    // F-101: never waits on a FIFO swapped in at the vault's path.
    let read = larsal_platform::macos::open_regular(path)
        .and_then(|f| f.take(64 * 1024).read_to_end(&mut head));
    match read
        .ok()
        .and_then(|_| larsal_format::header::read_header(&head, &Limits::DEFAULT).ok())
    {
        Some(h) => public_look(
            h.public_custom_data
                .iter()
                .map(|m| (m.kind, m.name.as_slice(), m.value.as_slice())),
        ),
        None => (None, -1),
    }
}

#[derive(Default)]
struct State {
    slots: Vec<Slot>,
    shown: Option<u64>,
    next: u64,
    /// M09-07, shown once as a banner.
    banner: Option<String>,
}

impl State {
    fn slot(&mut self, id: u64) -> Result<&mut Slot, LarsalError> {
        self.slots
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or(LarsalError::UnknownVault)
    }
}

/// What share.rs reaches of one vault ([`Session::with_share`]).
pub(crate) struct ShareSlot<'a> {
    pub(crate) vault: Option<&'a mut Vault>,
    pub(crate) path: &'a Path,
    pub(crate) epoch: u64,
    pub(crate) version: &'a mut u64,
    pub(crate) rated: &'a mut Rated,
    pub(crate) edit: &'a mut EditState,
    pub(crate) share: &'a mut crate::share::State,
    pub(crate) open: Vec<PathBuf>,
    /// The key file each open vault was last unlocked with (INT-08.34).
    pub(crate) keys: Vec<PathBuf>,
}

/// The result of one open, before it is stored.
enum Attempt {
    Opened(Box<Vault>, Keep),
    Ask(Pending),
    Failed(UnlockMessage),
}

/// The open vaults (architecture, larsal-ffi `session.rs`). Swift holds it as a
/// handle; it never sees a vault, a key or a password.
#[derive(uniffi::Object)]
pub struct Session {
    state: Mutex<State>,
    pub(crate) open_copies: crate::open_copies::OpenCopies,
    /// This Mac for the KDF cost check; it keeps the calibration records.
    pub(crate) host: Mutex<Host>,
    /// Larsal's copy on the clipboard (APP-03): the general pasteboard for
    /// [`Session::shared`], a private one for [`Session::new`].
    pub(crate) clipboard: Clipboard,
    /// The generator's value and saved options (generator.rs, E5-S6).
    pub(crate) generator: Mutex<crate::generator::State>,
    /// This session, for work it starts on its own threads (ssh.rs).
    pub(crate) me: std::sync::Weak<Session>,
    /// The SSH agents (ssh.rs, E9-S2).
    pub(crate) ssh: crate::ssh::Ssh,
    /// Larsal's settings (larsal_settings.rs, E5-S9): the app's one store for
    /// [`Session::shared`], a memory-only one for [`Session::new`].
    pub(crate) settings: Arc<crate::larsal_settings::LarsalSettingsStore>,
    /// Global Auto-Type's picker, plan and remembered choice (autotype.rs).
    pub(crate) autotype: Mutex<crate::autotype::State>,
    /// APP-02.16's memory note (LD-224 (4)): the recovery copy names whose
    /// change an automatic lock kept in no copy this run; no vault content.
    pub(crate) lost: Mutex<std::collections::BTreeSet<String>>,
    /// This Mac's local state of its vaults, never synced (local_state.rs,
    /// E15-S4): retired keys and the rollback guard's values.
    pub(crate) local: crate::local_state::LocalState,
    /// Sync with Larsal's server (E16-S7a, `sync` feature): the state, the
    /// servers and each open vault's schedule (sync.rs).
    #[cfg(feature = "sync")]
    pub(crate) sync: crate::sync::Syncs,
}

static SHARED: OnceLock<Arc<Session>> = OnceLock::new();
static EVENTS: OnceLock<Arc<dyn LarsalEvents>> = OnceLock::new();

/// Called once the window exists: changes made off the main thread (a
/// channel `open`, a passed-in unlock) are announced to it.
pub(crate) fn set_events(events: Arc<dyn LarsalEvents>) {
    let _ = EVENTS.set(events);
}

#[cfg(test)]
thread_local! {
    /// Tests: how many times this thread announced a change.
    pub(crate) static CHANGED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub(crate) fn changed() {
    #[cfg(test)]
    CHANGED.set(CHANGED.get().saturating_add(1));
    if let Some(events) = EVENTS.get() {
        events.session_changed();
    }
}

/// Larsal comes to the front (INT-06.34's question); a hidden test launch
/// never does (Swift `Front.bring`).
pub(crate) fn front() {
    if let Some(events) = EVENTS.get() {
        events.bring_to_front();
    }
}

impl Session {
    #[cfg(test)]
    pub(crate) fn state_busy_for_test(&self) -> bool {
        self.state.try_lock().is_err()
    }

    fn with_clipboard(
        clipboard: Clipboard,
        settings: Arc<crate::larsal_settings::LarsalSettingsStore>,
        open_copies: crate::open_copies::OpenCopies,
    ) -> Arc<Self> {
        let processors = std::thread::available_parallelism().map_or(1, |n| n.get());
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            ssh: crate::ssh::Ssh::default(),
            settings,
            state: Mutex::default(),
            open_copies,
            host: Mutex::new(Host {
                physical_memory: larsal_platform::macos::physical_memory(),
                logical_processors: u64::try_from(processors).unwrap_or(1),
                argon2_record: None,
                aes_record: None,
            }),
            clipboard,
            generator: Mutex::default(),
            autotype: Mutex::default(),
            lost: Mutex::default(),
            local: crate::local_state::LocalState::default(),
            #[cfg(feature = "sync")]
            sync: crate::sync::Syncs::default(),
        })
    }

    /// Tests only: the session's clipboard, to look at a private one.
    #[doc(hidden)]
    #[must_use]
    pub fn clipboard(&self) -> &Clipboard {
        &self.clipboard
    }

    /// The vault `id` while unlocked, with the session lock held.
    pub(crate) fn with_vault<R>(
        &self,
        id: u64,
        f: impl FnOnce(&Vault) -> Result<R, LarsalError>,
    ) -> Result<R, LarsalError> {
        self.with_open(id, |vault, _, _| f(vault))
    }

    /// The vault `id` while unlocked, with its file path and its ratings,
    /// with the session lock held.
    pub(crate) fn with_open<R>(
        &self,
        id: u64,
        f: impl FnOnce(&Vault, &Path, &mut Rated) -> Result<R, LarsalError>,
    ) -> Result<R, LarsalError> {
        let mut state = self.state();
        let slot = state.slot(id)?;
        let vault = slot.vault.as_deref().ok_or(LarsalError::Locked)?;
        f(vault, &slot.path, &mut slot.rated)
    }

    /// The vault `id` while unlocked, for a change (edit.rs): the vault,
    /// its file path, its ratings and its edit state, with the session lock
    /// held. Counts as a change of the vault (F-165).
    pub(crate) fn with_edit<R>(
        &self,
        id: u64,
        f: impl FnOnce(&mut Vault, &Path, &mut Rated, &mut EditState) -> Result<R, LarsalError>,
    ) -> Result<R, LarsalError> {
        let mut state = self.state();
        let slot = state.slot(id)?;
        let vault = slot.vault.as_deref_mut().ok_or(LarsalError::Locked)?;
        // A look through this door counts too: a share import tried
        // meanwhile is only queued again.
        slot.version = slot.version.wrapping_add(1);
        let out = f(&mut *vault, &slot.path, &mut slot.rated, &mut slot.edit);
        slot.edit.qr_check(vault, &slot.path);
        out
    }

    /// The vault `id` while unlocked and its edit state, for a look only
    /// (the footer), with the session lock held: not a change, so a share
    /// import tried meanwhile still lands (F-165).
    pub(crate) fn with_edit_view<R>(
        &self,
        id: u64,
        f: impl FnOnce(&Vault, &EditState) -> R,
    ) -> Result<R, LarsalError> {
        let mut state = self.state();
        let slot = state.slot(id)?;
        let vault = slot.vault.as_deref().ok_or(LarsalError::Locked)?;
        Ok(f(vault, &slot.edit))
    }

    /// The vault `id` while unlocked, to read, and its edit state, to
    /// change (the editor's draft calls), with the session lock held: the
    /// vault does not change, so a share import tried meanwhile still lands
    /// (F-167).
    pub(crate) fn with_draft_state<R>(
        &self,
        id: u64,
        f: impl FnOnce(&Vault, &mut EditState) -> Result<R, LarsalError>,
    ) -> Result<R, LarsalError> {
        let mut state = self.state();
        let slot = state.slot(id)?;
        let vault = slot.vault.as_deref().ok_or(LarsalError::Locked)?;
        let out = f(vault, &mut slot.edit);
        slot.edit.qr_check(vault, &slot.path);
        out
    }

    /// The vault `id` while unlocked, to read, its file path and its edit
    /// state, for Show as QR Code (qr.rs), with the session lock held: not a
    /// change, and it checks its ticket itself.
    pub(crate) fn with_qr<R>(
        &self,
        id: u64,
        f: impl FnOnce(&Vault, &Path, &mut EditState) -> Result<R, LarsalError>,
    ) -> Result<R, LarsalError> {
        let mut state = self.state();
        let slot = state.slot(id)?;
        let vault = slot.vault.as_deref().ok_or(LarsalError::Locked)?;
        f(vault, &slot.path, &mut slot.edit)
    }

    /// The vault `id` while unlocked, with its breach check (reports.rs),
    /// with the session lock held.
    pub(crate) fn with_breach<R>(
        &self,
        id: u64,
        f: impl FnOnce(&Vault, &mut Option<crate::reports::Breach>) -> Result<R, LarsalError>,
    ) -> Result<R, LarsalError> {
        let mut state = self.state();
        let slot = state.slot(id)?;
        let vault = slot.vault.as_deref().ok_or(LarsalError::Locked)?;
        f(vault, &mut slot.breach)
    }

    /// share.rs: vault `id` (`None` while locked or behind the forced key
    /// change, MOD-13.8), its file, lock count, change count, ratings, edit
    /// state and share state, and every open vault's file (INT-08.34), with
    /// the session lock held.
    pub(crate) fn with_share<R>(
        &self,
        id: u64,
        f: impl FnOnce(ShareSlot<'_>) -> R,
    ) -> Result<R, LarsalError> {
        let mut state = self.state();
        let open = state.slots.iter().map(|s| s.path.clone()).collect();
        let keys = state
            .slots
            .iter()
            .filter_map(|s| s.key_file.clone())
            .collect();
        let slot = state.slot(id)?;
        let forced = slot.forced.is_some();
        let out = f(ShareSlot {
            vault: slot.vault.as_deref_mut().filter(|_| !forced),
            path: &slot.path,
            epoch: slot.epoch,
            version: &mut slot.version,
            rated: &mut slot.rated,
            edit: &mut slot.edit,
            share: &mut slot.share,
            open,
            keys,
        });
        if let Some(vault) = slot.vault.as_deref() {
            slot.edit.qr_check(vault, &slot.path);
        }
        Ok(out)
    }

    /// The edit state of vault `id`, locked or not (edit.rs test hooks);
    /// the default answer for an unknown vault.
    pub(crate) fn with_edit_state<R: Default>(
        &self,
        id: u64,
        f: impl FnOnce(&EditState) -> R,
    ) -> R {
        let state = self.state();
        state
            .slots
            .iter()
            .find(|s| s.id == id)
            .map(|s| f(&s.edit))
            .unwrap_or_default()
    }

    /// Every open vault (`None` while locked) with its path, and the shown
    /// one's id, with the session lock held (autotype.rs).
    pub(crate) fn with_slots<R>(
        &self,
        f: impl FnOnce(&[(u64, Option<&Vault>, &Path)], Option<u64>) -> R,
    ) -> R {
        let state = self.state();
        let slots: Vec<_> = state
            .slots
            .iter()
            // MOD-13.8: a vault behind the forced prompt counts as locked.
            .map(|s| {
                let vault = s.vault.as_deref().filter(|_| s.forced.is_none());
                (s.id, vault, s.path.as_path())
            })
            .collect();
        f(&slots, state.shown)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// APP-09.15 (a) to (c) for one path; the vault's id.
    fn open_path(&self, given: &Path) -> Result<u64, LarsalError> {
        let cannot = || LarsalError::CannotOpen(given.display().to_string());
        let path = std::fs::canonicalize(given).map_err(|_| cannot())?;
        // A folder or a special file is never read as a vault (APP-09.12).
        if !std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
            return Err(cannot());
        }
        let mut state = self.state();
        // macOS compares paths without letter case (APP-09.15 (b)).
        let key = path.to_string_lossy().to_lowercase();
        let found = state
            .slots
            .iter()
            .find(|s| s.path.to_string_lossy().to_lowercase() == key)
            .map(|s| s.id);
        let id = match found {
            Some(id) => id,
            None => {
                state.next = state.next.wrapping_add(1);
                let id = state.next;
                let look = header_look(&path);
                state.slots.push(Slot {
                    id,
                    path: path.clone(),
                    vault: None,
                    pending: None,
                    unlocking: false,
                    epoch: 0,
                    version: 0,
                    message: None,
                    look,
                    locked_at: None,
                    rated: Rated::default(),
                    edit: EditState::default(),
                    breach: None,
                    fresh: false,
                    forced: None,
                    share: crate::share::State::default(),
                    key_file: None,
                    trying_key: None,
                });
                id
            }
        };
        state.shown = Some(id);
        drop(state);
        // APP-01.14: the recent vaults (S-STATE-01).
        self.settings.note_opened(&path);
        Ok(id)
    }

    /// The open vaults' paths in tab order and the shown one's (APP-01.17).
    pub(crate) fn open_paths(&self) -> (Vec<PathBuf>, Option<PathBuf>) {
        let state = self.state();
        let shown = state
            .slots
            .iter()
            .find(|s| state.shown == Some(s.id))
            .map(|s| s.path.clone());
        (state.slots.iter().map(|s| s.path.clone()).collect(), shown)
    }

    /// APP-06.25 step 6 and MOD-08.31's vault link (auto_open.rs): opens
    /// `path` (APP-09.15); with `front` it becomes the shown vault, else the
    /// shown vault stays. The vault's id.
    pub(crate) fn open_beside(&self, path: &Path, front: bool) -> Result<u64, LarsalError> {
        let shown = self.state().shown;
        let id = self.open_path(path)?;
        if !front {
            self.state().shown = shown;
        }
        Ok(id)
    }

    /// APP-06.24: one unlock with passed-in credentials, on this thread,
    /// with the key slot remembered for the vault while S-START-08 is on
    /// (bullet 3; the challenge fails when that key is not plugged in).
    /// A failure's message waits for the user; a vault in the ask band
    /// stays locked with no question; an unlocked vault is left alone.
    /// `key_secret`: the key file path holds a protected value, so it is
    /// neither remembered nor named (rule 4, SR-12).
    pub(crate) fn unlock_passed(
        &self,
        id: u64,
        password: Option<SecretString>,
        key_file: Option<String>,
        key_secret: bool,
    ) {
        let path = self.state().slot(id).map(|s| s.path.clone());
        let hardware = path
            .ok()
            .and_then(|p| self.settings.remembered_keys(&p).1)
            .and_then(|text| Choice::parse(&text))
            .and_then(Choice::of);
        match self.unlock_inner(id, password, (key_file, key_secret), hardware, None) {
            Ok(UnlockResult::Failed { message }) => {
                if let Ok(slot) = self.state().slot(id) {
                    slot.message = Some(message);
                }
            }
            Ok(UnlockResult::Ask { .. }) => {
                let _ = self.cancel_unlock(id);
            }
            _ => {}
        }
    }

    /// Marks the start of an unlock; `None` when one runs, the vault is
    /// unlocked already (APP-06.10), or a lock or close came after the
    /// click that read `clicked` (APP-06.16, LD-277 (2)).
    fn begin(&self, id: u64, clicked: Option<u64>) -> Result<Option<(PathBuf, u64)>, LarsalError> {
        let mut state = self.state();
        let slot = state.slot(id)?;
        if slot.unlocking || slot.vault.is_some() || clicked.is_some_and(|e| e != slot.epoch) {
            return Ok(None);
        }
        slot.unlocking = true;
        slot.pending = None;
        slot.message = None;
        Ok(Some((slot.path.clone(), slot.epoch)))
    }

    /// Stores an attempt's result unless a lock or close came first.
    fn finish(&self, id: u64, epoch: u64, attempt: Attempt) -> Result<UnlockResult, LarsalError> {
        let mut state = self.state();
        // Closed meanwhile: the attempt drops here and wipes.
        let Ok(slot) = state.slot(id) else {
            return Ok(UnlockResult::Ignored);
        };
        slot.unlocking = false;
        if slot.epoch != epoch {
            return Ok(UnlockResult::Ignored);
        }
        Ok(match attempt {
            Attempt::Opened(vault, keep) => {
                if let Some(key) = slot.trying_key.take() {
                    slot.key_file = key;
                }
                // After unlock the look comes from the authenticated header.
                slot.look = public_look(
                    vault
                        .public_custom_data
                        .iter()
                        .map(|p| (p.kind, p.name.as_slice(), p.value.as_slice())),
                );
                // MOD-13.7, MOD-13.8: the check runs once per unlock; while
                // forced, no SSH key is added (end_forced adds them).
                slot.forced = crate::window::forced(&vault.meta);
                slot.fresh = true;
                // SYN-03.4: a run after the unlock.
                #[cfg(feature = "sync")]
                self.sync.unlocked(id, &slot.path, vault.root.uuid);
                slot.vault = Some(vault);
                slot.edit = EditState::opened(keep);
                if slot.forced.is_none() {
                    self.ssh_unlocked(id, vault_name(&slot.path));
                }
                UnlockResult::Unlocked
            }
            Attempt::Ask(pending) => {
                let (message, details) = messages::cost_question(&pending.report);
                slot.pending = Some(pending);
                UnlockResult::Ask { message, details }
            }
            Attempt::Failed(message) => UnlockResult::Failed { message },
        })
    }

    /// FMT-05.7 from step 1: reads the vault file again (APP-06.13) and opens
    /// it. Runs without the session lock; serialised on the host.
    fn run_open(
        &self,
        path: &Path,
        password: Option<SecretString>,
        (key, hardware): (Option<(KeyFileKey, String)>, Option<Choice>),
        approval: Option<&CostReport>,
    ) -> Attempt {
        let file = file_name(path);
        let key_name = key.as_ref().map_or(String::new(), |k| k.1.clone());
        let fail =
            |e: &Error| Attempt::Failed(messages::for_open_error(e, &file, &key_name).into());
        if password.is_none() && key.is_none() && hardware.is_none() {
            return fail(&Error::NoCredentials);
        }
        // F-101: a FIFO swapped in at the vault's path is refused at once.
        let bytes = match larsal_platform::macos::open_regular(path)
            .map_err(|e| Error::Io(e.kind()))
            .and_then(|f| larsal_format::detect::read_vault(f, &Limits::DEFAULT))
        {
            Ok(bytes) => bytes,
            Err(e) => return fail(&e),
        };
        // F-107: the chosen key is asked with the vault's seed (FMT-04.10).
        let part = hardware.map(Choice::part);
        let credentials = Credentials {
            password: password.as_ref(),
            key_file: key.as_ref().map(|k| &k.0),
            hardware_key: part.as_deref(),
        };
        let mut host = self.host.lock().unwrap_or_else(PoisonError::into_inner);
        let result =
            larsal_format::open(&bytes, &credentials, &mut host, &Limits::DEFAULT, approval);
        drop(host);
        match result {
            Ok(Opened::Vault(opened)) => {
                // APP-05.26: at unlock the rollback guard only warns; an
                // older file is never taken as seen.
                let verdict = self.guard(&opened.vault, &bytes);
                if !verdict.older {
                    self.seen(&opened.vault, &bytes, None);
                }
                let notice = messages::unlock_guard(&file, verdict.older, &verdict.weaker);
                let keep = Keep::new(password, key, opened.key, &bytes)
                    .with_hardware(hardware)
                    .with_notice(notice);
                Attempt::Opened(Box::new(opened.vault), keep)
            }
            Ok(Opened::Ask(report)) => Attempt::Ask(Pending {
                password,
                key,
                hardware,
                report,
            }),
            Err(e) => fail(&e),
        }
    }

    fn unlock_inner(
        &self,
        id: u64,
        password: Option<SecretString>,
        (key_file, key_secret): (Option<String>, bool),
        hardware: Option<Choice>,
        clicked: Option<u64>,
    ) -> Result<UnlockResult, LarsalError> {
        let Some((path, epoch)) = self.begin(id, clicked)? else {
            return Ok(UnlockResult::Ignored);
        };
        let key_file = key_file.filter(|k| !k.is_empty());
        // APP-01.16 (F-080): each attempt sets the remembered key parts; a
        // key file path holding a protected value is never kept (SR-12).
        if !key_secret {
            self.settings
                .note_keys(&path, key_file.clone(), hardware.map(Choice::remembered));
        }
        // ponytail: only the unlock's own key file. A key file from the
        // wizard or a key change this session has no path here; the file
        // rule of `container::write_share` still refuses it.
        let held = key_file.as_deref().map(|typed| key_path(&path, typed));
        self.state().slot(id)?.trying_key = (!key_secret).then_some(held);
        let attempt = match key_file {
            Some(typed) => {
                match read_key_as(&path, &typed, key_secret.then_some(larsal_core::refs::MASK)) {
                    Ok(key) => self.run_open(&path, password, (Some(key), hardware), None),
                    Err(message) => Attempt::Failed(message),
                }
            }
            None => self.run_open(&path, password, (None, hardware), None),
        };
        let result = self.finish(id, epoch, attempt);
        self.auto_open_after(id, result.as_ref());
        result
    }

    /// APP-06.22 step 8 (F-079): auto-open after an unlock, unless the
    /// forced key change waits (then after it, `end_forced`).
    fn auto_open_after(&self, id: u64, result: Result<&UnlockResult, &LarsalError>) {
        let forced = || self.state().slot(id).is_ok_and(|s| s.forced.is_some());
        if result == Ok(&UnlockResult::Unlocked) && !forced() {
            self.auto_open(id);
            // INT-08.15 step 1.
            self.share_unlocked(id);
        }
    }

    /// window.rs: `Some(first)` once after an unlock, when its notices are
    /// due (not while the forced prompt waits), with whether it was the
    /// first unlock since the vault was opened (MOD-09.7); `None` after.
    pub(crate) fn take_fresh(&self, id: u64) -> Result<Option<bool>, LarsalError> {
        let mut state = self.state();
        let slot = state.slot(id)?;
        if slot.vault.is_none() || slot.forced.is_some() || !std::mem::take(&mut slot.fresh) {
            return Ok(None);
        }
        Ok(Some(slot.locked_at.is_none()))
    }

    /// window.rs, MOD-13.8: ends the forced prompt once the key no longer
    /// needs a change, and adds the SSH keys the unlock held back; false
    /// while a change is still required.
    pub(crate) fn end_forced(&self, id: u64) -> Result<bool, LarsalError> {
        let mut state = self.state();
        let slot = state.slot(id)?;
        let vault = slot.vault.as_deref().ok_or(LarsalError::Locked)?;
        if slot.forced.is_none() {
            return Ok(true);
        }
        if crate::window::forced(&vault.meta).is_some() {
            return Ok(false);
        }
        slot.forced = None;
        let name = vault_name(&slot.path);
        // With the state lock held, as in `finish`: a later lock always
        // finds this vault's record (ssh.rs).
        self.ssh_unlocked(id, name);
        drop(state);
        // APP-06.22 step 8 waited for the key change (F-079).
        self.auto_open(id);
        self.share_unlocked(id);
        Ok(true)
    }

    pub(crate) fn set_banner(&self, text: String) {
        self.state().banner = Some(text);
    }

    /// APP-07.18 (E5-S8): a vault the new vault wizard just wrote to `path`
    /// joins the session unlocked, with its key parts kept for saving, and
    /// becomes the shown vault. The vault's id.
    ///
    /// # Errors
    /// `CannotOpen` when `path` no longer resolves to a regular file.
    pub(crate) fn adopt(
        &self,
        path: &Path,
        vault: Box<Vault>,
        keep: Keep,
    ) -> Result<u64, LarsalError> {
        let id = self.open_path(path)?;
        let mut state = self.state();
        let slot = state.slot(id)?;
        slot.lock();
        slot.look = public_look(
            vault
                .public_custom_data
                .iter()
                .map(|p| (p.kind, p.name.as_slice(), p.value.as_slice())),
        );
        // SYN-03.4, SYN-03.5 step 2: as an unlock: its schedule and its root.
        #[cfg(feature = "sync")]
        self.sync.unlocked(id, &slot.path, vault.root.uuid);
        slot.vault = Some(vault);
        slot.edit = EditState::opened(keep);
        slot.locked_at = None;
        Ok(id)
    }

    /// APP-05.6 Save As (E5-S10, saving.rs): the vault's file is now the
    /// canonical `path`. Called with the save lock held; the recent list
    /// follows after it (APP-06).
    pub(crate) fn set_path(&self, id: u64, path: &Path) {
        if let Ok(slot) = self.state().slot(id) {
            path.clone_into(&mut slot.path);
        }
        #[cfg(feature = "sync")]
        self.sync.moved(id, path);
    }

    /// MOD-12.4 (E5-S8): the tile follows a public colour the vault
    /// settings changed.
    pub(crate) fn refresh_look(&self, id: u64) {
        let mut state = self.state();
        if let Ok(slot) = state.slot(id)
            && let Some(v) = slot.vault.as_deref()
        {
            slot.look = public_look(
                v.public_custom_data
                    .iter()
                    .map(|p| (p.kind, p.name.as_slice(), p.value.as_slice())),
            );
        }
    }
}

#[uniffi::export]
impl Session {
    /// A new, empty session (tests). Its copies go to a private pasteboard
    /// of this process, never the user's clipboard. The app uses
    /// [`Session::shared`].
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Self::with_clipboard(
            Clipboard::private(),
            Arc::default(),
            crate::open_copies::OpenCopies::private(),
        )
    }

    /// The app's one session: the one start-up and the instance channel
    /// fill. Its copies go to the general pasteboard.
    #[uniffi::constructor]
    #[must_use]
    pub fn shared() -> Arc<Self> {
        SHARED
            .get_or_init(|| {
                Self::with_clipboard(
                    Clipboard::general(),
                    crate::larsal_settings::shared(),
                    crate::open_copies::OpenCopies::shared(),
                )
            })
            .clone()
    }

    /// The open vaults in the order they were opened; one is `shown`.
    #[must_use]
    pub fn vaults(&self) -> Vec<VaultInfo> {
        let state = self.state();
        state
            .slots
            .iter()
            .map(|s| VaultInfo {
                id: s.id,
                name: vault_name(&s.path),
                path: home_short(&s.path),
                hue: hue(&s.path),
                locked: s.vault.is_none(),
                unlocking: s.unlocking,
                shown: state.shown == Some(s.id),
                colour: s.look.0,
                icon: s.look.1,
                locked_at: s.locked_at,
                key_change: s.forced.clone(),
            })
            .collect()
    }

    /// APP-09.15: adds the file at `path` to the session, locked, and shows
    /// it; a file already open is only shown. Whether it is a vault is
    /// decided at unlock (format detection), never by its name.
    ///
    /// # Errors
    /// `CannotOpen` (M09-07) when the path does not resolve to a regular
    /// file; `TooLong` for a path over 4,096 bytes.
    pub fn open(&self, path: String) -> Result<u64, LarsalError> {
        if path.len() > MAX_PATH {
            return Err(LarsalError::TooLong);
        }
        self.open_path(Path::new(&path))
    }

    /// Shows vault `vault` (the vault switcher).
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn switch_to(&self, vault: u64) -> Result<(), LarsalError> {
        let mut state = self.state();
        state.slot(vault)?;
        state.shown = Some(vault);
        Ok(())
    }

    /// Locks vault `vault`: first Larsal's clipboard copy is cleared, whichever
    /// vault it came from (APP-03.15); then its contents and any waiting
    /// credentials are wiped; an unlock in progress drops its result
    /// (APP-06.16).
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn lock(&self, vault: u64) -> Result<(), LarsalError> {
        // D-02-5: the generator's value goes with any lock.
        self.drop_generated();
        let mut state = self.state();
        let slot = state.slot(vault)?;
        self.clipboard.clear();
        slot.lock();
        drop(state);
        self.ssh_locked(Some(vault));
        self.autotype_locked(Some(vault));
        // SYN-03.4: never a run while locked.
        #[cfg(feature = "sync")]
        self.sync.locked(Some(vault));
        Ok(())
    }

    /// Clears Larsal's clipboard copy (APP-03.15), then locks every open vault
    /// (APP-02, APP-09.12 `lock`).
    pub fn lock_all(&self) {
        self.drop_generated();
        let mut state = self.state();
        self.clipboard.clear();
        for slot in &mut state.slots {
            slot.lock();
        }
        drop(state);
        self.ssh_locked(None);
        self.autotype_locked(None);
        #[cfg(feature = "sync")]
        self.sync.locked(None);
    }

    /// APP-03.12: empties the clipboard if it still holds Larsal's last copy,
    /// else leaves it; stops the countdown. For quit (APP-03.15, SC-03),
    /// after the vaults are locked.
    pub fn clear_clipboard(&self) {
        self.clipboard.clear();
    }

    /// `copy.selection` (APP-03.7, APP-03.19, LD-219 (4)): text the user
    /// selected in the shown vault's view goes to the clipboard as every
    /// copy does (APP-03.2: markers, current host only, the countdown,
    /// cleared on lock, close and `clear_clipboard`). The text is already on
    /// screen; it is wiped here after the write. `Copied.label` is empty:
    /// the notice reads "Copied." (APP-03.21).
    ///
    /// # Errors
    /// `NotAvailable` when the clipboard could not be written.
    pub fn copy_selection(&self, text: String) -> Result<crate::views::Copied, LarsalError> {
        let text = SecretString::new(text);
        self.copy_value(String::new(), text.expose())
    }

    /// Tests (LD-206): the name of this session's private pasteboard;
    /// `None` for the app's session, whose copies go to the general one.
    #[must_use]
    pub fn pasteboard_name(&self) -> Option<String> {
        self.clipboard.name().map(str::to_owned)
    }

    /// Closes vault `vault`: Larsal's clipboard copy is cleared (closing locks
    /// first, APP-03.15), then the vault is removed and wiped; the vault
    /// before it (or the next) becomes the shown one.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn close(&self, vault: u64) -> Result<(), LarsalError> {
        self.drop_generated();
        let mut state = self.state();
        let at = state
            .slots
            .iter()
            .position(|s| s.id == vault)
            .ok_or(LarsalError::UnknownVault)?;
        self.clipboard.clear();
        state.slots.remove(at);
        if state.shown == Some(vault) {
            let next = at.saturating_sub(1);
            state.shown = state.slots.get(next).map(|s| s.id);
        }
        drop(state);
        self.ssh_locked(Some(vault));
        self.autotype_locked(Some(vault));
        // SYN-03.4: never a run while locked.
        #[cfg(feature = "sync")]
        self.sync.locked(Some(vault));
        Ok(())
    }

    /// APP-06.11 to APP-06.13: one unlock attempt. `password` is `None` for
    /// an empty field and `Some("")` for the blank password of M06-05's link
    /// (FMT-04.2); it goes into a secret type at once. A failed attempt
    /// wipes it; a successful one keeps it for saving (edit.rs `Keep`), in
    /// page-locked memory like `T` and `F` (SR-07, APP-11.9), until the vault
    /// locks or closes. `key_file` is a path as chosen or typed: `~/` is the
    /// home folder, a relative path is taken from the vault's folder
    /// (APP-06.7). Runs the KDF on the caller's thread: call it off the main
    /// thread.
    ///
    /// # Errors
    /// `UnknownVault`; `TooLong` for a password or path over the limits.
    pub fn unlock(
        &self,
        vault: u64,
        password: Option<String>,
        key_file: Option<String>,
    ) -> Result<UnlockResult, LarsalError> {
        let epoch = self.lock_epoch(vault)?;
        self.unlock_with_key(vault, password, key_file, None, epoch)
    }

    /// LD-277 (2): the vault's lock count now. The unlock form reads it at
    /// the click and passes it to [`Session::unlock_with_key`], so a lock
    /// or close between the click and the unlock's start stops it.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn lock_epoch(&self, vault: u64) -> Result<u64, LarsalError> {
        Ok(self.state().slot(vault)?.epoch)
    }

    /// [`Session::unlock`] with UL-HW's chosen key and slot (APP-06.11
    /// step 3, F-107): the challenge runs inside the open (APP-06.15); the
    /// choice is kept for every later save. A slot other than 1 or 2 is
    /// no hardware key. `epoch` is [`Session::lock_epoch`] as the click
    /// read it: when a lock or close came since, nothing runs, the
    /// password is wiped and the answer is `Ignored` (APP-06.16, LD-277 (2)).
    ///
    /// # Errors
    /// As [`Session::unlock`].
    pub fn unlock_with_key(
        &self,
        vault: u64,
        password: Option<String>,
        key_file: Option<String>,
        hardware: Option<KeyPick>,
        epoch: u64,
    ) -> Result<UnlockResult, LarsalError> {
        let password = password.map(SecretString::new);
        if password.as_ref().is_some_and(|p| p.len() > MAX_TEXT)
            || key_file.as_ref().is_some_and(|k| k.len() > MAX_PATH)
        {
            return Err(LarsalError::TooLong);
        }
        self.unlock_inner(
            vault,
            password,
            (key_file, false),
            hardware.and_then(Choice::of),
            Some(epoch),
        )
    }

    /// APP-06.9 (F-080, F-107): the key file path and the key and slot
    /// remembered for this vault (APP-01.16), while S-START-08 is on; the
    /// unlock screen pre-fills from them.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn remembered_keys(&self, vault: u64) -> Result<RememberedKeys, LarsalError> {
        let path = self.state().slot(vault)?.path.clone();
        let (key_file, hardware) = self.settings.remembered_keys(&path);
        Ok(RememberedKeys {
            key_file,
            hardware: hardware.as_deref().and_then(Choice::parse),
        })
    }

    /// APP-06.14 "Unlock": runs the waiting attempt once with the approval.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn approve_unlock(&self, vault: u64) -> Result<UnlockResult, LarsalError> {
        let (pending, path, epoch) = {
            let mut state = self.state();
            let slot = state.slot(vault)?;
            let Some(pending) = slot.pending.take() else {
                return Ok(UnlockResult::Ignored);
            };
            if slot.unlocking {
                return Ok(UnlockResult::Ignored);
            }
            slot.unlocking = true;
            (pending, slot.path.clone(), slot.epoch)
        };
        let Pending {
            password,
            key,
            hardware,
            report,
        } = pending;
        // With the approval the open never asks again (CRY-02.14).
        let attempt = self.run_open(&path, password, (key, hardware), Some(&report));
        let result = self.finish(vault, epoch, attempt);
        self.auto_open_after(vault, result.as_ref());
        result
    }

    /// APP-06.14 "Cancel": wipes the waiting credentials; no message.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn cancel_unlock(&self, vault: u64) -> Result<(), LarsalError> {
        self.state().slot(vault)?.pending = None;
        Ok(())
    }

    /// APP-06.3: reads the file's first bytes and outer header without a
    /// key; the message when that already fails, else `None`. Call it off
    /// the main thread when the unlock view shows.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn check_header(&self, vault: u64) -> Result<Option<UnlockMessage>, LarsalError> {
        let path = self.state().slot(vault)?.path.clone();
        let result = larsal_platform::macos::open_regular(&path)
            .map_err(|e| Error::Io(e.kind()))
            .and_then(|f| larsal_format::detect::read_vault(f, &Limits::DEFAULT))
            .and_then(|bytes| {
                larsal_format::detect::check(&bytes)?;
                larsal_format::header::read_header(&bytes, &Limits::DEFAULT)
            });
        Ok(result
            .err()
            .map(|e| messages::for_open_error(&e, &file_name(&path), "").into()))
    }

    /// The message of a failed unlock with passed-in credentials, once
    /// (APP-06.24).
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn take_message(&self, vault: u64) -> Result<Option<UnlockMessage>, LarsalError> {
        Ok(self.state().slot(vault)?.message.take())
    }

    /// M09-07 for a path that could not be opened, once.
    #[must_use]
    pub fn take_banner(&self) -> Option<String> {
        self.state().banner.take()
    }
}

/// APP-06.9: what the unlock screen pre-fills (APP-01.16); not secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RememberedKeys {
    /// The key file path as it was given.
    pub key_file: Option<String>,
    /// The key and slot; UL-HW chooses it when it is in the list.
    pub hardware: Option<KeyPick>,
}

/// Files to open: the file arguments of a first launch (with F05 and F06), or
/// the paths of a channel `open` or of Finder (no key file, no passwords).
pub struct OpenRequest {
    /// Absolute paths, in order.
    pub paths: Vec<PathBuf>,
    /// F05, for every path.
    pub key_file: Option<PathBuf>,
    /// F06, one per path in order; empty when F06 was not given.
    pub passwords: Vec<SecretString>,
}

/// APP-09.15 to APP-09.17, APP-09.19: opens each path in the app's session;
/// the last one is shown. With F05 or a non-empty F06 line, the unlock
/// starts at once on a worker thread (APP-06.24): its message waits for the
/// user, no question is asked. The window hears of every change.
pub fn open(request: OpenRequest) {
    let session = Session::shared();
    let OpenRequest {
        paths,
        key_file,
        passwords,
    } = request;
    let mut passwords = passwords.into_iter();
    let mut unlocks = Vec::new();
    for path in paths {
        // APP-09.16: an empty line means no password component.
        let password = passwords.next().filter(|p| !p.is_empty());
        match session.open_path(&path) {
            Ok(id) if password.is_some() || key_file.is_some() => {
                unlocks.push((id, password));
            }
            Ok(_) => {}
            Err(e) => session.set_banner(e.to_string()),
        }
    }
    changed();
    let key_file = key_file.map(|k| k.to_string_lossy().into_owned());
    passed_unlocks(&session, EVENTS.get().map(|e| &**e), unlocks, key_file);
}

/// APP-06.24 with LD-277 (4): each F06 unlock reads its vault file in a
/// coordinated read the window runs off the main thread, once the file is
/// on this Mac; with no window, on a worker thread of its own.
fn passed_unlocks(
    session: &Arc<Session>,
    events: Option<&dyn LarsalEvents>,
    unlocks: Vec<(u64, Option<SecretString>)>,
    key_file: Option<String>,
) {
    for (id, password) in unlocks {
        let Ok(path) = session.state().slot(id).map(|s| s.path.clone()) else {
            continue;
        };
        let (me, key_file) = (Arc::clone(session), key_file.clone());
        let work = Arc::new(FileWork(Mutex::new(Some(Box::new(move || {
            me.unlock_passed(id, password, key_file, false);
            changed();
        })))));
        match events {
            Some(events) => events.on_file(path.to_string_lossy().into_owned(), work),
            None => {
                // No thread: the vault stays locked and the user unlocks by
                // hand.
                let _ = std::thread::Builder::new()
                    .name("unlock".into())
                    .spawn(move || work.run());
            }
        }
    }
}

/// One file read Rust starts off the main thread and the window runs in a
/// coordinated read (LD-277 (4)). Dropped unrun, it wipes what it holds
/// (an F06 password).
#[derive(uniffi::Object)]
pub struct FileWork(Mutex<Option<Box<dyn FnOnce() + Send>>>);

#[uniffi::export]
impl FileWork {
    /// Runs the work once; later calls do nothing. It reads the file and
    /// runs the KDF: call it off the main thread.
    pub fn run(&self) {
        let work = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(work) = work {
            work();
        }
    }
}

/// Locks every open vault at once, with no save and no recovery copy: the
/// channel's `lock` (APP-09.12) only while no window has set its events
/// (tests); with a window it locks through `LarsalEvents::lock_all` (LD-217
/// (4)). Always succeeds.
#[must_use]
pub fn lock_all() -> bool {
    Session::shared().lock_all();
    changed();
    true
}

/// Tests (LD-206): the name of every pasteboard Rust wrote or cleared in
/// this process; names only. A test asserts it holds only private ones, so
/// the owner's clipboard was never touched (AGENTS.md rule 10).
#[uniffi::export]
#[must_use]
pub fn pasteboards_written() -> Vec<String> {
    Clipboard::written()
}

/// APP-06.7 and FMT-18: resolves a chosen or typed key file path, refuses
/// the vault itself (M06-30), and reads the key. A folder or special file is
/// refused before it is opened, so a FIFO never blocks the read.
pub(crate) fn read_key(vault: &Path, typed: &str) -> Result<(KeyFileKey, String), UnlockMessage> {
    read_key_as(vault, typed, None)
}

/// APP-06.7: the file a chosen or typed key file path names: `~/` is the
/// home folder, a relative path is beside the vault.
pub(crate) fn key_path(vault: &Path, typed: &str) -> PathBuf {
    match typed.strip_prefix("~/") {
        Some(rest) => home().map_or_else(|| PathBuf::from(typed), |h| h.join(rest)),
        None => vault
            .parent()
            .map_or_else(|| PathBuf::from(typed), |dir| dir.join(typed)),
    }
}

/// [`read_key`] with messages and the kept name using `shown` in place of
/// the file's name, when given.
fn read_key_as(
    vault: &Path,
    typed: &str,
    shown: Option<&str>,
) -> Result<(KeyFileKey, String), UnlockMessage> {
    let path = key_path(vault, typed);
    let name = shown.map_or_else(|| file_name(&path), str::to_owned);
    let fail = |reason: KeyFileReason| -> UnlockMessage {
        messages::for_open_error(&Error::KeyFile(reason), "", &name).into()
    };
    let meta = std::fs::metadata(&path).map_err(|e| fail(KeyFileReason::Io(e.kind())))?;
    if !meta.is_file() {
        return Err(fail(KeyFileReason::NotRegularFile));
    }
    if std::fs::canonicalize(&path).is_ok_and(|p| p == vault) {
        return Err(messages::vault_as_key_file().into());
    }
    let file = File::open(&path).map_err(|e| fail(KeyFileReason::Io(e.kind())))?;
    match read_key_file(file, &Limits::DEFAULT) {
        // F-072: the name as messages show it (APP-06.18).
        Ok(key) => Ok((key, messages::clean_name(&name))),
        Err(e) => Err(messages::for_open_error(&e, "", &name).into()),
    }
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// The file name as messages show it (APP-06.18 cleans it).
pub(crate) fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// APP-06.2: the file name without `.larsalvault`, cleaned.
fn vault_name(path: &Path) -> String {
    let name = file_name(path);
    let lower = name.to_lowercase();
    let stem = if lower.ends_with(".larsalvault") && name.len() > ".larsalvault".len() {
        name.get(..name.len().saturating_sub(".larsalvault".len()))
            .unwrap_or(&name)
    } else {
        &name
    };
    messages::clean_name(stem)
}

/// UL-PATH: the home folder written as `~`.
pub(crate) fn home_short(path: &Path) -> String {
    let full = path.to_string_lossy().into_owned();
    match home().and_then(|h| path.strip_prefix(h).ok().map(Path::to_path_buf)) {
        Some(rest) => format!("~/{}", rest.to_string_lossy()),
        None => full,
    }
}

/// UL-TILE: a hue from the path, the same on every show (FNV-1a).
fn hue(path: &Path) -> u32 {
    let mut h: u32 = 2_166_136_261;
    for b in path.to_string_lossy().bytes() {
        h = (h ^ u32::from(b)).wrapping_mul(16_777_619);
    }
    h % 360
}

/// How a vault file looks before it is opened (the welcome screen's recent
/// list): its name (APP-06.2), its path with the home folder as `~`, and the
/// unauthenticated public colour and icon of its header (FMT-02.27,
/// FMT-03.23). No vault content.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultLook {
    /// The file name without `.larsalvault`, cleaned.
    pub name: String,
    /// The path with the home folder written as `~`.
    pub path: String,
    /// The public colour as `0xRRGGBB`; `None` when unset or invalid.
    pub colour: Option<u32>,
    /// The public icon index; -1 when unset or invalid.
    pub icon: i32,
}

/// Takes a vault file path (at most 4,096 bytes; a longer one gives an
/// empty look); returns its [`VaultLook`]. Reads at most the first 64 KiB.
#[uniffi::export]
#[must_use]
pub fn vault_look(path: String) -> VaultLook {
    let path = Path::new(&path);
    // Only a regular file is read: a FIFO or a device would block or never
    // end (APP-09.12).
    let readable =
        path.as_os_str().len() <= MAX_PATH && std::fs::metadata(path).is_ok_and(|m| m.is_file());
    let (colour, icon) = if readable {
        header_look(path)
    } else {
        (None, -1)
    };
    VaultLook {
        name: vault_name(path),
        path: home_short(path),
        colour,
        icon,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keeps the work it is handed, as the window does until its
    /// coordinated read runs.
    #[derive(Default)]
    struct Window(Mutex<Vec<(String, Arc<FileWork>)>>);

    impl LarsalEvents for Window {
        fn bring_to_front(&self) {}
        fn session_changed(&self) {}
        fn lock_all(&self) {}
        fn on_file(&self, path: String, work: Arc<FileWork>) {
            self.0.lock().unwrap().push((path, work));
        }
    }

    /// LD-277 (4), APP-06.24: an F06 unlock reads its file only in the work
    /// the window runs inside a coordinated read; the vault stays locked
    /// until then, and a second run does nothing.
    #[test]
    fn ld277_4_a_passed_in_unlock_reads_inside_the_windows_coordinated_read() {
        let dir = crate::test_dir::TempDir::new("session-f06");
        let path = dir.join("Personal.larsalvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-personal.larsalvault"
            ),
            &path,
        )
        .unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        let window = Window::default();
        passed_unlocks(
            &s,
            Some(&window),
            vec![(v, Some(SecretString::new("demo-pass-7".to_owned())))],
            None,
        );
        assert!(s.vaults()[0].locked, "nothing read yet");
        let handed = std::mem::take(&mut *window.0.lock().unwrap());
        assert_eq!(handed.len(), 1);
        assert_eq!(Path::new(&handed[0].0), s.state().slot(v).unwrap().path);
        handed[0].1.run();
        assert!(!s.vaults()[0].locked, "unlocked by the work");
        s.lock(v).unwrap();
        handed[0].1.run();
        assert!(s.vaults()[0].locked, "the work runs once");
    }
}
