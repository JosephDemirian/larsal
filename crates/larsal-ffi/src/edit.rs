//! The entry editor and the vault changes of the window (E5-S5): the
//! editor's draft (MOD-01, MOD-03, MOD-05, MOD-06, MOD-07, MOD-09, FEA-04,
//! INT-04), commit and cancel, clone (MOD-10), the recycle bin (MOD-04),
//! new groups (MOD-02), QR symbols (FEA-04.23), and the save after each
//! change (APP-05).
//!
//! Guarantees:
//! - the draft lives here, in Rust; Swift gets views without secrets. The
//!   password goes in from Swift ([`Session::set_password`]) into a
//!   `SecretString`, and comes out only through the editor's Show
//!   ([`Session::draft_password`]) and the earlier version's Show
//!   ([`Session::show_version`]), one value each (AGENTS.md rule 4);
//! - nothing changes in the vault until [`Session::commit_edit`]; Cancel
//!   leaves no trace (MOD-01.25); a lock drops the draft (session.rs);
//! - every change of an entry drops its ratings and the Health Check runs
//!   again (LD-139);
//! - a save writes through larsal-core's safe save (APP-05.9 to APP-05.12)
//!   with a vault copy, off the session lock, so the window keeps reading
//!   while the KDF runs; a save that started before a lock keeps its
//!   result to itself;
//! - QR symbols are made here from the settings; Swift gets the module
//!   matrix only, never the secret text (FEA-04.23).

use crate::session::{LarsalError, MAX_TEXT, Session};
use crate::views::{
    AttachmentView, Copied, FAVORITE, PASSKEY, PasskeyView, Rated, Rating, SshKeyView, TotpView,
    count, custom_icon_name, find, hex, icon_number, is_protected, is_totp_field, now, parse_id,
    passkey, plain_in, ssh_key, ssh_type, totp_of, unix,
};
use larsal_core::health::{Level, entry_bits, score};
use larsal_core::storage::{self, Checksum};
use larsal_core::{
    Error, NameProblem, attachments, clone, edit, history, icons, recycle, tags, totp,
};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_format::keyfile::KeyFileKey;
use larsal_format::keys::TransformedKey;
use larsal_model::autotype::Association;
use larsal_model::entry::{Field, STANDARD_FIELDS};
use larsal_model::{Entry, Group, Icon, Time, Uuid, Vault, json};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

/// The name prefix of the additional URL fields (MOD-01.8, INT-03).
const EXTRA_URL: &str = "KP2A_URL";
/// The tag a passkey adds (MOD-07.11, INT-04.46).
const PASSKEY_TAG: &str = "Passkey";

// ---------------------------------------------------------------------------
// What a vault keeps for its saves, and the editor's state.

/// What saving needs from the unlock (the CLI's `Session` keeps the same):
/// the key parts, the last transformed key (CRY-03.16) and the checksum Larsal
/// last read or wrote (APP-05.10). Wiping types only; every key part sits
/// in page-locked memory while the vault is unlocked (SR-07, APP-11.9,
/// LD-199 (3)): `T` and `F` lock their own pages, the password's pages are
/// locked here. A lock or close drops it; a save that runs meanwhile holds
/// its own reference, finishes its write, then drops the key parts too.
/// With the key parts' non-secret facts for the edit state: whether there
/// is a password, the key file's name and the hardware key (F-126).
pub(crate) struct Keep(
    Arc<Mutex<Saver>>,
    bool,
    Option<String>,
    Option<crate::hwkey::Choice>,
    Option<String>,
);

pub(crate) struct Saver {
    // Declaration order is drop order: wipe the password, then unlock its
    // pages (as larsal-format's `LockedKey`).
    pub(crate) password: Option<SecretString>,
    #[cfg(target_os = "macos")]
    password_pages: Option<larsal_platform::memory::Locked>,
    pub(crate) key_file: Option<KeyFileKey>,
    /// F-107: the hardware key the vault was unlocked with; every save asks
    /// it again with the new seed (FMT-04.10), so the key part stays.
    pub(crate) hardware: Option<crate::hwkey::Choice>,
    pub(crate) key: TransformedKey,
    /// The last-known checksum of the pre-save check (APP-05.10).
    pub(crate) checksum: Checksum,
    /// The checksum the disk watch last saw (APP-05.24, saving.rs).
    pub(crate) watched: Checksum,
    /// SYN-03.5 step 2: the SHA-256 of the file this unlock last opened with
    /// its key parts or wrote. Only bytes that equal it go to a server. It
    /// moves with `checksum`, which reads the first 1,024 bytes and the
    /// length only.
    #[cfg(feature = "sync")]
    pub(crate) proven: [u8; 32],
}

impl Keep {
    /// After a successful unlock (or the new vault wizard's write, E5-S8)
    /// of the file `bytes`; the key file with its name.
    pub(crate) fn new(
        password: Option<SecretString>,
        key_file: Option<(KeyFileKey, String)>,
        key: TransformedKey,
        bytes: &[u8],
    ) -> Self {
        let (key_file, key_file_name) = key_file.unzip();
        let has_password = password.is_some();
        let saver = Saver {
            #[cfg(target_os = "macos")]
            password_pages: password
                .as_ref()
                .and_then(|p| larsal_platform::memory::lock(p.expose().as_bytes())),
            password,
            key_file,
            hardware: None,
            key,
            checksum: storage::checksum(bytes),
            watched: storage::checksum(bytes),
            #[cfg(feature = "sync")]
            proven: larsal_sync::sync::hash(bytes),
        };
        Self(
            Arc::new(Mutex::new(saver)),
            has_password,
            key_file_name,
            None,
            None,
        )
    }

    /// APP-05.26: the rollback guard's notice of the unlock read.
    pub(crate) fn with_notice(mut self, notice: Option<String>) -> Self {
        self.4 = notice;
        self
    }

    /// F-107: the hardware key part the vault opened with, kept for saves.
    pub(crate) fn with_hardware(mut self, hardware: Option<crate::hwkey::Choice>) -> Self {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .hardware = hardware;
        self.3 = hardware;
        self
    }
}

/// The editor's draft and the vault's save state; one per unlocked vault,
/// dropped (and wiped) on lock.
#[derive(Default)]
pub(crate) struct EditState {
    draft: Option<Draft>,
    pub(crate) saver: Option<Arc<Mutex<Saver>>>,
    /// Changes made since the last save (the footer's count).
    pub(crate) changes: u32,
    /// When Larsal last saved this vault in this session, unix seconds.
    pub(crate) saved_at: Option<i64>,
    /// Why the last save failed, in plain words; no secret.
    pub(crate) failure: Option<String>,
    /// The disk flags of APP-05 (saving.rs, E5-S10).
    pub(crate) disk: crate::saving::Disk,
    /// The key parts' facts for the vault settings (E5-S8), not secret:
    /// kept here so they are read without the save lock (one lock order,
    /// the save lock before the session lock, LD-199 (4)).
    has_password: bool,
    key_file_name: Option<String>,
    hardware: Option<crate::hwkey::Choice>,
    /// Attachment copies opened from the editor (MOD-05.12): wiped and
    /// removed when the editor closes, and when this state drops (lock,
    /// close, quit).
    opened: OpenCopies,
    /// MOD-11.31 (saving.rs): the disk version under a key this Mac
    /// retired, waiting for the `MSG-DISK-OLD-KEY` answer; dropped (and
    /// wiped) on lock.
    pub(crate) held: Option<Box<Vault>>,
    /// APP-05.17 (copies.rs): each listed copy not merged, by path, with
    /// the checksum of the bytes its coordinated read gave, and, under a
    /// key this Mac retired, the copy waiting for Merge anyway; and each
    /// copy merged or kept in this session with its checksum then, so it is
    /// not merged or listed again until it changes.
    pub(crate) held_copies:
        std::collections::HashMap<std::path::PathBuf, (Checksum, Option<Box<Vault>>)>,
    pub(crate) copies_seen: std::collections::HashMap<std::path::PathBuf, Checksum>,
    /// APP-05.26: the rollback guard's notice of the unlock read
    /// (`MSG-DISK-ROLLBACK-UNLOCK`, `MSG-DISK-WEAKER`), for `after_unlock`.
    pub(crate) notice: Option<String>,
    /// FEA-10.11 (qr.rs): the one live Show as QR Code request; a lock or
    /// close drops it.
    pub(crate) qr: Option<crate::qr::Ticket>,
    /// The newest request's number: a slower older one is dropped.
    pub(crate) qr_newest: u64,
}

/// Temporary attachment copies, wiped and removed on drop (MOD-05.12):
/// the attachment's name, the copy's path, and the SHA-256 of the content
/// Larsal wrote or the user last answered for (MOD-05.13).
#[derive(Default)]
struct OpenCopies(Vec<(String, std::path::PathBuf, SecretBytes)>);

impl OpenCopies {
    fn clear(&mut self) {
        for (_, path, _) in self.0.drain(..) {
            wipe_file(&path);
        }
    }
}

impl Drop for OpenCopies {
    fn drop(&mut self) {
        self.clear();
    }
}

impl EditState {
    /// A freshly unlocked vault: no change, the key parts kept for saving.
    pub(crate) fn opened(keep: Keep) -> Self {
        Self {
            saver: Some(keep.0),
            has_password: keep.1,
            key_file_name: keep.2,
            hardware: keep.3,
            notice: keep.4,
            ..Self::default()
        }
    }

    /// The entry editor is open (APP-05.25 keeps a disk event pending).
    pub(crate) fn editing(&self) -> bool {
        self.draft.is_some()
    }

    /// Changes not yet written to disk (FEA-07.15 `info.unsaved`).
    pub(crate) fn unsaved(&self) -> bool {
        self.changes > 0
    }

    /// One more unsaved change (the vault settings, E5-S8).
    pub(crate) fn count_change(&mut self) {
        self.changes = self.changes.saturating_add(1);
    }

    /// The key parts the next save uses (MOD-12.10): whether there is a
    /// password, and the key file's name. No secret.
    pub(crate) fn key_parts(&self) -> (bool, Option<String>) {
        (self.has_password, self.key_file_name.clone())
    }

    /// F-126: the hardware key part the next save uses. No secret.
    pub(crate) fn hardware(&self) -> Option<crate::hwkey::Choice> {
        self.hardware
    }

    /// F-126 (MOD-12.10, INT-07.25): the hardware key part for the next
    /// save, `None` removes it; as [`EditState::set_key`], `sv` locked by
    /// the caller first.
    pub(crate) fn set_hardware(&mut self, sv: &mut Saver, hardware: Option<crate::hwkey::Choice>) {
        (sv.hardware, self.hardware) = (hardware, hardware);
        self.disk.new_key = true;
    }

    /// MOD-12.10 step 8 (E5-S8): new key parts for the next save, which
    /// derives the key with them (CRY-03). `None` keeps a part as it is;
    /// `Some(None)` removes it. The old password is wiped before its pages
    /// are unlocked, and the new one's pages are locked (SR-07). `sv` is
    /// this vault's save lock, taken by the caller before the session lock
    /// (LD-199 (4)): the Saver is never locked inside `with_edit`.
    pub(crate) fn set_key(
        &mut self,
        sv: &mut Saver,
        password: Option<Option<SecretString>>,
        key_file: Option<Option<(KeyFileKey, String)>>,
    ) {
        if let Some(password) = password {
            self.has_password = password.is_some();
            #[cfg(target_os = "macos")]
            let old_pages = sv.password_pages.take();
            sv.password = password;
            #[cfg(target_os = "macos")]
            {
                drop(old_pages);
                sv.password_pages = sv
                    .password
                    .as_ref()
                    .and_then(|p| larsal_platform::memory::lock(p.expose().as_bytes()));
            }
        }
        if let Some(key_file) = key_file {
            (sv.key_file, self.key_file_name) = key_file.unzip();
        }
        // APP-05.33: the save that writes them lists the old copies.
        self.disk.new_key = true;
    }
}

/// One edit session (MOD-01.32): a copy of the entry, changed by the
/// screen, committed once.
struct Draft {
    entry: Entry,
    /// The entry as it was when the editor opened; `None` for a new one.
    original: Option<Entry>,
    /// The group it goes to on commit.
    group: Uuid,
    /// History items marked for deletion (MOD-03.13), by position.
    marked: Vec<usize>,
    all_marked: bool,
}

// ---------------------------------------------------------------------------
// Views.

/// A custom field on the editor's Advanced page (MOD-01.2, MOD-01.6). The
/// one-time password, passkey and additional URL fields have their own
/// places (FEA-04, INT-04 D-INT04-16, INT-03).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CustomFieldView {
    /// The name, exact.
    pub name: String,
    /// The value; empty when protected (Show gives it).
    pub value: String,
    /// The own protected flag.
    pub protected: bool,
}

/// A group the entry can go to (the editor's Group menu).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GroupChoice {
    /// 32 hex digits.
    pub id: String,
    /// The group name.
    pub name: String,
    /// 0 for the root group.
    pub depth: u32,
    /// The standard icon number; -1 for a custom icon.
    pub icon: i32,
}

/// The one-time password settings shown on the Entry page (FEA-04).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpInfo {
    /// Code length.
    pub digits: u32,
    /// Seconds per code.
    pub period: u32,
    /// `SHA-1`, `SHA-256` or `SHA-512`.
    pub algorithm: String,
    /// Steam's letters (FEA-04.13).
    pub steam: bool,
    /// Not the defaults (FEA-04.21).
    pub custom: bool,
    /// The settings cannot make a code.
    pub invalid: bool,
}

/// The setup screen's controls (FEA-04.22). `Debug` hides the secret
/// (Rust rule 3, F-062).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct TotpSetup {
    /// The current secret with every `=` removed; empty without settings.
    /// A secret: shown only in the setup screen the user opened.
    pub secret: String,
    /// `standard`, `steam` or `custom`.
    pub choice: String,
    /// Custom: the code size.
    pub digits: u32,
    /// The time step.
    pub period: u32,
    /// Custom: `SHA-1`, `SHA-256` or `SHA-512`.
    pub algorithm: String,
    /// `MSG-OTP-SETUP-INVALID` shows.
    pub invalid: bool,
}

impl std::fmt::Debug for TotpSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSetup")
            .field("secret", &"<hidden>")
            .field("choice", &self.choice)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("algorithm", &self.algorithm)
            .field("invalid", &self.invalid)
            .finish()
    }
}

/// The Auto-Type page (MOD-01.18, INT-05).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutoTypeView {
    /// Auto-Type may use this entry.
    pub enabled: bool,
    /// The entry's own sequence; empty means the group's.
    pub sequence: String,
    /// The sequence the group gives (MOD-02.16).
    pub group_sequence: String,
    /// Window associations in stored order.
    pub windows: Vec<WindowView>,
}

/// One window association: a title pattern and its sequence (empty: the
/// entry's).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WindowView {
    /// The window title pattern.
    pub window: String,
    /// The sequence; empty means the entry's.
    pub sequence: String,
}

/// One row of the History page (MOD-03.11): the current entry or an item.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistoryRow {
    /// The item's position; `None` for the current entry.
    pub index: Option<u32>,
    /// Its last modification time, unix seconds.
    pub saved: i64,
    /// What changed against the next older row, in plain words.
    pub change: String,
    /// The password differs from the next older row (or it is the oldest).
    pub password_changed: bool,
}

/// One custom data item (MOD-01.20): shown, deleted, never edited.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CustomDataView {
    /// The key.
    pub key: String,
    /// The value.
    pub value: String,
}

/// The editor's view of its draft: every page, no secret. The password and
/// every protected value (custom, standard, additional URL) are left out
/// (F-060); the password's length is not.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EditorView {
    /// The entry's id, 32 hex digits.
    pub id: String,
    /// The identifier as the Properties page shows it (8-4-4-4-12).
    pub identifier: String,
    /// A new entry, not yet in the vault (MOD-01.22).
    pub new: bool,
    /// `Title`; empty when protected (see `protected`).
    pub title: String,
    /// `UserName`; empty when protected.
    pub user: String,
    /// `URL`; empty when protected.
    pub url: String,
    /// The URL's host, for the logo; empty when `URL` is protected.
    pub host: String,
    /// `Notes`; empty when protected.
    pub notes: String,
    /// The standard text fields whose own protected flag is on: their
    /// values above are empty, `show_draft_field` gives one (F-060).
    pub protected: Vec<EditText>,
    /// The password's length in characters (LD-164); 0 when empty.
    pub password_chars: u32,
    /// The additional URLs (INT-03), in INT-03.2's order (`KP2A_URL`,
    /// `KP2A_URL_2`, `KP2A_URL_10`); a protected one's value is empty.
    pub urls: Vec<CustomFieldView>,
    /// INT-03.18: the note under each row of `urls`, in that order (MI03-01
    /// to MI03-03); empty when the value may fit or holds a reference.
    pub url_notes: Vec<String>,
    /// The custom fields of the Advanced page.
    pub custom: Vec<CustomFieldView>,
    /// The attachments, by name (MOD-05.1).
    pub attachments: Vec<AttachmentView>,
    /// The tags, without the favorite mark (FEA-08.9).
    pub tags: Vec<String>,
    /// The tag `Favorite` is set.
    pub favorite: bool,
    /// The group it is in, or goes to.
    pub group: String,
    /// That group's name.
    pub group_name: String,
    /// That group's standard icon; -1 for a custom icon.
    pub group_icon: i32,
    /// The vault's root group name ("Personal").
    pub root_name: String,
    /// The groups it may go to: the tree without the bin, root first.
    pub groups: Vec<GroupChoice>,
    /// `Expires` (MOD-09).
    pub expires: bool,
    /// `ExpiryTime`, unix seconds.
    pub expiry: i64,
    /// The standard icon number; -1 for a custom icon (MOD-06).
    pub icon: i32,
    /// The one-time password settings (FEA-04).
    pub totp: Option<TotpInfo>,
    /// The passkey (INT-04.51).
    pub passkey: Option<PasskeyView>,
    /// The SSH public key the attachments hold.
    pub ssh: Option<SshKeyView>,
    /// That key's OpenSSH line (type, base64, comment): public, never the
    /// private key.
    pub ssh_public_key: Option<String>,
    /// The Auto-Type page.
    pub auto_type: AutoTypeView,
    /// Times, unix seconds (Properties page).
    pub created: i64,
    /// The last modification time.
    pub modified: i64,
    /// The last access time.
    pub accessed: i64,
    /// `UsageCount`, as read (MOD-01.28).
    pub usage: i32,
    /// The History page, newest first; history items marked for deletion
    /// are left out.
    pub history: Vec<HistoryRow>,
    /// History items kept (after the marks).
    pub history_items: u32,
    /// Their size in bytes (MOD-03.7).
    pub history_size: u64,
    /// The vault's history limits (MOD-03.6): items, bytes; -1 no limit.
    pub history_max_items: i32,
    /// See `history_max_items`.
    pub history_max_size: i32,
    /// The custom data items (MOD-01.20); the site access item is listed
    /// as "Browser site access" (its stored key is the reference's).
    pub custom_data: Vec<CustomDataView>,
    /// The entry's custom icon name (Larsal's: "<symbol> <colour>").
    pub custom_icon: Option<String>,
    /// The group's custom icon name.
    pub group_custom_icon: Option<String>,
    /// The site access item's Allow and Deny hosts (INT-02.16).
    pub allow: Vec<String>,
    /// See `allow`.
    pub deny: Vec<String>,
    /// Hide, skip submit and only-HTTP (INT-02.14, INT-02.29), in that order.
    pub browser_options: Vec<BrowserOptionView>,
    /// `BrowserLastUse`, newest first (INT-02.29).
    pub browsers: Vec<BrowserUseView>,
    /// What the draft changed against the entry, in the card's order
    /// (MOD-03.11 labels); empty when nothing changed.
    pub changed: Vec<String>,
}

/// A standard text field of the Entry page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EditText {
    /// `Title`.
    Title,
    /// `UserName`.
    UserName,
    /// `URL`.
    Url,
    /// `Notes`.
    Notes,
}

impl EditText {
    fn name(self) -> &'static str {
        match self {
            Self::Title => "Title",
            Self::UserName => "UserName",
            Self::Url => "URL",
            Self::Notes => "Notes",
        }
    }
}

/// An earlier version as the "Earlier version" sheet shows it (MOD-03.12).
/// `Debug` hides the password (Rust rule 3, F-062).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct VersionView {
    /// The entry's title then; empty when protected (see `protected`).
    pub title: String,
    /// When it was saved, unix seconds.
    pub saved: i64,
    /// What the next newer version changed, as a sentence end ("the
    /// passkey was added").
    pub before: String,
    /// `UserName` then; empty when protected.
    pub user: String,
    /// `Password` then: the one Show value of this sheet.
    pub password: String,
    /// `URL` then; empty when protected.
    pub url: String,
    /// The standard text fields protected then: their values above are
    /// empty, `show_version_field` gives one (F-060).
    pub protected: Vec<EditText>,
}

impl std::fmt::Debug for VersionView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionView")
            .field("title", &self.title)
            .field("saved", &self.saved)
            .field("before", &self.before)
            .field("user", &self.user)
            .field("password", &"<hidden>")
            .field("url", &self.url)
            .field("protected", &self.protected)
            .finish()
    }
}

/// The save state the sidebar's footer shows (APP-05).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SaveStatus {
    /// Changes not saved yet.
    pub changes: u32,
    /// When Larsal last saved in this session, unix seconds.
    pub saved_at: Option<i64>,
    /// Why the last save failed, in plain words (`MSG-SAVE-FAILED`'s
    /// reason); `None` after a good save.
    pub failure: Option<String>,
    /// The save wrote nothing because the file changed on disk: ask
    /// (APP-05.28, saving.rs). Not a failure.
    pub on_disk: Option<crate::saving::DiskAsk>,
    /// APP-05.32: the save wrote nothing; show `MSG-SAVE-V4-NOTICE`, then
    /// `confirm_format_notice` and save again.
    pub format_notice: bool,
    /// A one-time line of this save: `MSG-SAVE-RECREATED`,
    /// `MSG-SAVE-BACKUP-FAILED` or `MSG-DISK-OVERWRITTEN`.
    pub notice: Option<String>,
    /// The vault's autosave delay in minutes, 0 when off (MOD-12.8,
    /// APP-05.3).
    pub autosave_minutes: u32,
    /// APP-05.14 (F-087): a safe save failed the third time in a row; ask
    /// `MSG-SAVE-UNSAFE-ASK`, and on Turn off call `turn_off_safe_save`
    /// and save again.
    pub ask_unsafe: bool,
    /// APP-05.33 (F-088): this save wrote new key parts; show
    /// `MSG-KEY-OLD-COPIES` with these files (all checked; empty: OK
    /// only). Paths of Larsal's own encrypted copies, no content.
    pub old_copies: Option<Vec<String>>,
    /// With `on_disk`: the rollback guard found the disk version older
    /// (APP-05.28, LD-267 (3)); the question adds the "went back in time"
    /// line.
    pub older: bool,
}

/// A QR symbol (FEA-04.23): `size` modules a side, the 4-module quiet zone
/// included, row by row; 1 is dark. A picture of the secret: `Debug`
/// hides the modules (Rust rule 3, F-062).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct Qr {
    /// Modules per side.
    pub size: u32,
    /// `size × size` values, 0 or 1.
    pub modules: Vec<u8>,
}

impl std::fmt::Debug for Qr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Qr")
            .field("size", &self.size)
            .field("modules", &"<hidden>")
            .finish()
    }
}

/// What a delete did (MOD-04.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct DeleteResult {
    /// Entries moved into the bin.
    pub to_bin: u32,
    /// Entries deleted for good.
    pub for_good: u32,
}

// ---------------------------------------------------------------------------
// Helpers.

/// A core refusal in plain words (no value, AT-E03).
pub(crate) fn refused(e: &Error) -> LarsalError {
    let text = match e {
        Error::NoSuchEntry => return LarsalError::UnknownEntry,
        Error::NoSuchGroup => return LarsalError::UnknownGroup,
        Error::FieldName(p) | Error::AttachmentName(p) => match p {
            NameProblem::Empty => "The name cannot be empty.",
            NameProblem::Standard => "That name belongs to a standard field.",
            NameProblem::Taken => "Another field has that name.",
        },
        Error::FieldTooLarge => "The field is too large to keep in the vault.",
        Error::TooLarge => "This is over the vault's size limit.",
        Error::InRecycleBin => "Nothing can be made in the Recycle Bin.",
        Error::TooDeep => "Groups cannot be nested that deep.",
        Error::NoSuchHistoryItem => "That earlier version is gone.",
        Error::RandomSource => "The system's random source failed. Try again.",
        Error::RootGroup | Error::Cycle => "A group cannot move there.",
    };
    LarsalError::Refused(text.to_owned())
}

fn text(value: &str) -> Result<(), LarsalError> {
    if value.len() > MAX_TEXT {
        Err(LarsalError::TooLong)
    } else {
        Ok(())
    }
}

/// The group that holds entry `id`, with its parents.
fn holder(vault: &Vault, id: Uuid) -> Option<&Group> {
    let mut chain = Vec::new();
    find(&vault.root, id, &mut chain)?;
    chain.last().copied()
}

fn group_by_id(vault: &Vault, id: Uuid) -> Option<&Group> {
    vault.root.subtree().into_iter().find(|g| g.uuid == id)
}

fn bin(vault: &Vault) -> Option<Uuid> {
    recycle::bin_id(vault)
}

fn groups(vault: &Vault) -> Vec<GroupChoice> {
    fn walk(g: &Group, depth: u32, bin: Option<Uuid>, out: &mut Vec<GroupChoice>) {
        if Some(g.uuid) == bin {
            return;
        }
        out.push(GroupChoice {
            id: hex(g.uuid),
            name: g.name.clone(),
            depth,
            icon: icon_number(g.icon),
        });
        for child in &g.groups {
            walk(child, depth.saturating_add(1), bin, out);
        }
    }
    let mut out = Vec::new();
    walk(&vault.root, 0, bin(vault), &mut out);
    out
}

/// An additional URL field: the field names the matcher reads (INT-03.2,
/// LD-322 (7)).
fn is_extra_url(name: &str) -> bool {
    name.starts_with(EXTRA_URL)
}

/// INT-03.18: the note under a website row, empty for none.
fn url_note(value: &str) -> String {
    match larsal_browser::note(value) {
        Some(larsal_browser::Note::RefusedPattern) => "This pattern can't be used: a `*` may not stand for a whole domain or its ending. Use a pattern like https://*.example.com.",
        Some(larsal_browser::Note::NoHost) => "This is not a website address Larsal can match.",
        Some(larsal_browser::Note::OtherScheme) => "Browsers only get entries for http and https addresses.",
        None => "",
    }
    .to_owned()
}

/// A custom field the Advanced page lists.
/// The standard text fields of `e` that are protected, by their own flag
/// or the vault's (F-060, LD-207).
fn protected_texts(v: &Vault, e: &Entry) -> Vec<EditText> {
    [
        EditText::Title,
        EditText::UserName,
        EditText::Url,
        EditText::Notes,
    ]
    .into_iter()
    .filter(|t| {
        e.field(t.name())
            .is_some_and(|f| is_protected(v, t.name(), f))
    })
    .collect()
}

/// A field the editor's Show gives (F-060): a custom field, an additional
/// URL or a standard text field; never the password (its own Show) nor the
/// one-time password or passkey fields (LD-170 (4)).
pub(crate) fn showable(name: &str) -> bool {
    listed(name) || is_extra_url(name) || ["Title", "UserName", "URL", "Notes"].contains(&name)
}

fn listed(name: &str) -> bool {
    !STANDARD_FIELDS.contains(&name)
        && !is_totp_field(name)
        && !name.starts_with(PASSKEY)
        && !is_extra_url(name)
}

fn algorithm_name(a: totp::Algorithm) -> &'static str {
    match a {
        totp::Algorithm::Sha1 => "SHA-1",
        totp::Algorithm::Sha256 => "SHA-256",
        totp::Algorithm::Sha512 => "SHA-512",
    }
}

fn identifier(id: Uuid) -> String {
    let h = hex(id);
    let part = |a: usize, b: usize| h.get(a..b).unwrap_or("");
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}

fn has_passkey(e: &Entry) -> bool {
    e.fields().any(|(n, _)| n.starts_with(PASSKEY))
}

/// The History page's words for what `newer` changed against `older`
/// (MOD-03.11 labels; a passkey that came or went is named as such).
fn change_words(newer: &Entry, older: &Entry) -> String {
    let mut labels: Vec<String> = history::difference(newer, older)
        .into_iter()
        .map(str::to_owned)
        .collect();
    match (has_passkey(newer), has_passkey(older)) {
        (true, false) => return "Passkey added".to_owned(),
        (false, true) => return "Passkey removed".to_owned(),
        _ => {}
    }
    if labels.is_empty() {
        return "No change".to_owned();
    }
    if labels.len() > 1 {
        let last = labels.pop().unwrap_or_default();
        return format!("{} and {last} changed", labels.join(", "));
    }
    format!("{} changed", labels.concat())
}

/// The History page's rows of `e`, leaving out the items marked for
/// deletion; each row keeps its position in `e.history`.
fn history_rows(e: &Entry, marked: &[usize], all: bool) -> Vec<HistoryRow> {
    let rows = history::rows(e);
    let version = |i: Option<usize>| i.and_then(|i| e.history.get(i)).unwrap_or(e);
    rows.iter()
        .enumerate()
        .filter(|(_, r)| r.index.is_none_or(|i| !all && !marked.contains(&i)))
        .map(|(k, r)| {
            let this = version(r.index);
            let older = rows.get(k.saturating_add(1)).map(|o| version(o.index));
            HistoryRow {
                index: r.index.map(count),
                saved: unix(r.last_modified),
                change: older.map_or_else(|| "Entry created".to_owned(), |o| change_words(this, o)),
                password_changed: older
                    .is_none_or(|o| o.value("Password") != this.value("Password")),
            }
        })
        .collect()
}

/// The rating of a password typed in the editor (FEA-05.7): the level, the
/// bits and the length; no notice texts.
fn rate(password: &str, e: &Entry) -> Option<Rating> {
    if password.is_empty() {
        return None;
    }
    let bits = entry_bits(password, e);
    let level = Level::of(score(bits));
    Some(Rating {
        level: level.name().to_owned(),
        word: level.name().to_owned(),
        segments: level.quality(),
        attention: false,
        expired: false,
        issue: String::new(),
        reasons: Vec::new(),
        chars: count(password.chars().count()),
        // `as` saturates; E is never negative.
        bits: bits.round() as u32,
    })
}

fn view(vault: &Vault, d: &Draft) -> EditorView {
    let e = &d.entry;
    let group = group_by_id(vault, d.group);
    let mut kept = e.duplicate(true);
    if d.all_marked {
        kept.history.clear();
    } else {
        let mut k = 0usize;
        kept.history.retain(|_| {
            let drop = d.marked.contains(&k);
            k = k.saturating_add(1);
            !drop
        });
    }
    let settings = totp::settings(e);
    let url = plain_in(vault, e, "URL");
    let unshown = |(n, f): (&str, &Field)| CustomFieldView {
        name: n.to_owned(),
        value: if is_protected(vault, n, f) {
            String::new()
        } else {
            f.value.expose().to_owned()
        },
        protected: is_protected(vault, n, f),
    };
    EditorView {
        id: hex(e.uuid),
        identifier: identifier(e.uuid),
        new: d.original.is_none(),
        title: plain_in(vault, e, "Title"),
        user: plain_in(vault, e, "UserName"),
        host: crate::views::host(&url),
        url,
        notes: plain_in(vault, e, "Notes"),
        protected: protected_texts(vault, e),
        password_chars: count(e.value("Password").chars().count()),
        urls: extra_urls(e).into_iter().map(unshown).collect(),
        url_notes: extra_urls(e)
            .into_iter()
            .map(|(_, f)| {
                if f.protected {
                    String::new()
                } else {
                    url_note(f.value.expose())
                }
            })
            .collect(),
        custom: e.fields().filter(|(n, _)| listed(n)).map(unshown).collect(),
        attachments: attachments::sorted(e)
            .into_iter()
            .map(|a| AttachmentView {
                name: a.name.clone(),
                size: u64::try_from(a.data.len()).unwrap_or(u64::MAX),
            })
            .collect(),
        tags: e
            .tags()
            .iter()
            .filter(|t| !t.eq_ignore_ascii_case(FAVORITE))
            .cloned()
            .collect(),
        favorite: e.tags().iter().any(|t| t.eq_ignore_ascii_case(FAVORITE)),
        group: hex(d.group),
        group_name: group.map(|g| g.name.clone()).unwrap_or_default(),
        group_icon: if d.group == vault.root.uuid {
            -1
        } else {
            group.map_or(-1, |g| icon_number(g.icon))
        },
        root_name: vault.root.name.clone(),
        groups: groups(vault),
        expires: e.times.expires,
        expiry: unix(e.times.expiry),
        icon: icon_number(e.icon),
        totp: settings.map(|s| TotpInfo {
            digits: s.digits,
            period: s.period,
            algorithm: algorithm_name(s.algorithm).to_owned(),
            steam: s.encoder == totp::Encoder::Steam,
            custom: s.is_custom(),
            invalid: s.problem().is_some(),
        }),
        passkey: passkey(vault, e),
        ssh: ssh_key(e),
        ssh_public_key: ssh_key(e).and_then(|_| {
            e.attachments.iter().find_map(|a| {
                let text = std::str::from_utf8(a.data.expose()).ok()?;
                (ssh_type(a.data.expose()).is_some() && text.len() <= 16 * 1024)
                    .then(|| text.lines().next().unwrap_or("").to_owned())
            })
        }),
        auto_type: AutoTypeView {
            enabled: e.auto_type.enabled,
            sequence: e.auto_type.default_sequence.clone(),
            group_sequence: edit::group_sequence(vault, d.group),
            windows: e
                .auto_type
                .associations
                .iter()
                .map(|a| WindowView {
                    window: a.window.clone(),
                    sequence: a.sequence.clone(),
                })
                .collect(),
        },
        created: unix(e.times.creation),
        modified: unix(e.times.last_modification),
        accessed: unix(e.times.last_access),
        usage: e.times.usage_count,
        history: if d.original.is_none() {
            Vec::new()
        } else {
            history_rows(e, &d.marked, d.all_marked)
        },
        history_items: count(kept.history.len()),
        history_size: kept.history.iter().map(history::size).sum(),
        history_max_items: vault.meta.history_max_items,
        history_max_size: vault.meta.history_max_size,
        custom_data: e
            .custom_data
            .items
            .iter()
            .filter(|i| !larsal_core::origin::ours(&i.key))
            .map(|i| CustomDataView {
                key: if i.key.as_bytes() == SITE_ACCESS {
                    "Browser site access".to_owned()
                } else {
                    i.key.clone()
                },
                value: i.value.expose().to_owned(),
            })
            .collect(),
        custom_icon: custom_icon_name(vault, e.icon),
        group_custom_icon: group
            .filter(|g| g.uuid != vault.root.uuid)
            .and_then(|g| custom_icon_name(vault, g.icon)),
        allow: site_access(e).0,
        deny: site_access(e).1,
        browser_options: browser_options(vault, d),
        browsers: browser_uses(e),
        changed: d.original.as_ref().map_or_else(Vec::new, |o| {
            let mut out: Vec<String> = history::difference(e, o)
                .into_iter()
                .map(str::to_owned)
                .collect();
            if d.group != holder(vault, o.uuid).map_or(d.group, |g| g.uuid) {
                out.push("Group".to_owned());
            }
            if d.all_marked || !d.marked.is_empty() {
                out.push("History".to_owned());
            }
            out
        }),
    }
}

/// The site access item's key (INT-02.16), as hex bytes of its ASCII
/// text (AGENTS.md rule 1).
const SITE_ACCESS: &[u8] = &[
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x58, 0x43, 0x2D, 0x42, 0x72, 0x6F, 0x77, 0x73, 0x65,
    0x72, 0x20, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x73,
];
/// The entry options of the Browser page (INT-02.14, INT-02.29).
const BROWSER_OPTIONS: [&str; 3] = [
    "BrowserHideEntry",
    "BrowserSkipAutoSubmit",
    "BrowserOnlyHttpAuth",
];
/// Most hosts per site access list (INT-02.16).
const MAX_SITES: usize = 1000;

/// One option of the Browser page: the entry's value, or the group's that
/// decides it (INT-02.14; the switch is then disabled with MI02-11).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserOptionView {
    /// The custom data key, for example `BrowserHideEntry`.
    pub key: String,
    /// On.
    pub on: bool,
    /// The group that decides it, when one does.
    pub group: Option<String>,
}

/// One browser that used the entry (`BrowserLastUse`, INT-02.9).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserUseView {
    /// The association name, for example "Firefox on MacBook".
    pub name: String,
    /// When, unix seconds; 0 when the stored time cannot be read.
    pub used: i64,
}

/// What Open did (MOD-05.12).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum OpenAttachment {
    /// The private copy to hand to the default app.
    Opened {
        /// Its path.
        path: String,
    },
    /// The file type can run code when opened: ask first, then call again
    /// with `confirmed` (MOD-05.12 rule 3).
    AskFirst,
}

pub(crate) fn custom_value<'a>(e: &'a Entry, key: &[u8]) -> Option<&'a str> {
    e.custom_data
        .items
        .iter()
        .find(|i| i.key.as_bytes() == key)
        .map(|i| i.value.expose())
}

fn set_custom(e: &mut Entry, key: &str, value: Option<String>) {
    let items = &mut e.custom_data.items;
    match (items.iter_mut().find(|i| i.key == key), value) {
        (Some(item), Some(v)) => item.value = SecretString::new(v),
        (Some(_), None) => items.retain(|i| i.key != key),
        (None, Some(v)) => items.push(larsal_model::CustomDataItem {
            key: key.to_owned(),
            value: SecretString::new(v),
            last_modified: None,
            unknown: Vec::new(),
        }),
        (None, None) => {}
    }
}

/// The additional URL fields of `e` in INT-03.2's order.
fn extra_urls(e: &Entry) -> Vec<(&str, &Field)> {
    let mut urls: Vec<(&str, &Field)> = e.fields().filter(|(n, _)| is_extra_url(n)).collect();
    urls.sort_by(|a, b| larsal_browser::extra_url_order(a.0, b.0));
    urls
}

/// The Allow and Deny lists of the site access item (INT-02.16): at most
/// 1 MiB read, hosts in ASCII form, a host in both counts as denied; an
/// unreadable item counts as absent.
pub(crate) fn site_access(e: &Entry) -> (Vec<String>, Vec<String>) {
    // One reader of the item: the bridge's (INT-02.16).
    let lists = larsal_browser::Lists::of(e);
    (lists.allow, lists.deny)
}

/// Writes the site access item (INT-02.16): compact, `Allow`, `Deny`,
/// `Realm` in that order, sorted lists of at most 1,000 hosts, `Realm` as
/// read.
fn write_site_access(e: &mut Entry, allow: &[String], deny: &[String]) {
    let Ok(key) = std::str::from_utf8(SITE_ACCESS) else {
        return;
    };
    let realm = custom_value(e, SITE_ACCESS)
        .and_then(|t| json::from_str(t).ok())
        .and_then(|v| {
            v.get("Realm")
                .and_then(json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let clip = |l: &[String]| -> Vec<String> {
        let mut l = l.to_vec();
        l.sort();
        l.dedup();
        l.truncate(MAX_SITES);
        l
    };
    // A JSON object keeps its members in key order; build the text in the
    // card's order instead.
    let text = format!(
        "{{\"Allow\":{},\"Deny\":{},\"Realm\":{}}}",
        json::Value::from(clip(allow)),
        json::Value::from(clip(deny)),
        json::Value::from(realm)
    );
    set_custom(e, key, Some(text));
}

/// The groups from the root down to `group`.
pub(crate) fn chain(vault: &Vault, group: Uuid) -> Vec<&Group> {
    fn walk<'a>(g: &'a Group, id: Uuid, out: &mut Vec<&'a Group>) -> bool {
        out.push(g);
        if g.uuid == id || g.groups.iter().any(|c| walk(c, id, out)) {
            return true;
        }
        out.pop();
        false
    }
    let mut out = Vec::new();
    walk(&vault.root, group, &mut out);
    out
}

fn browser_options(vault: &Vault, d: &Draft) -> Vec<BrowserOptionView> {
    let groups = chain(vault, d.group);
    BROWSER_OPTIONS
        .iter()
        .map(|key| {
            // INT-02.14: the first group from the entry's group up that has
            // the key decides; else the entry's own key.
            let decided = groups
                .iter()
                .rev()
                .find_map(|g| g.custom_data.get(key).map(|v| (g, v == "true")));
            match decided {
                Some((g, on)) => BrowserOptionView {
                    key: (*key).to_owned(),
                    on,
                    group: Some(g.name.clone()),
                },
                None => BrowserOptionView {
                    key: (*key).to_owned(),
                    on: custom_value(&d.entry, key.as_bytes()) == Some("true"),
                    group: None,
                },
            }
        })
        .collect()
}

/// `BrowserLastUse` (INT-02.9): names and times, newest first.
fn browser_uses(e: &Entry) -> Vec<BrowserUseView> {
    let Some(text) = custom_value(e, b"BrowserLastUse").filter(|t| t.len() <= 1 << 20) else {
        return Vec::new();
    };
    let Ok(json::Value::Object(map)) = json::from_str(text) else {
        return Vec::new();
    };
    let mut out: Vec<BrowserUseView> = map
        .iter()
        .map(|(name, t)| BrowserUseView {
            name: name.clone(),
            used: t.as_str().and_then(iso_utc).unwrap_or(0),
        })
        .collect();
    out.sort_by(|a, b| b.used.cmp(&a.used).then_with(|| a.name.cmp(&b.name)));
    out
}

/// `YYYY-MM-DDTHH:MM:SSZ` to unix seconds (ISO 8601 UTC, as Larsal writes).
pub(crate) fn iso_utc(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 20
        || b.get(4) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(19) != Some(&b'Z')
    {
        return None;
    }
    let n = |a: usize, z: usize| text.get(a..z)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    // Days from the civil date (proleptic Gregorian).
    let (y, m) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

/// Overwrites a copy with random bytes in 128-byte blocks (size ÷ 128,
/// plus one), then deletes it (MOD-05.12). Errors leave nothing to do.
fn wipe_file(path: &Path) {
    use std::io::Write;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.is_file()
        && let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path)
    {
        let blocks = meta.len() / 128 + 1;
        for _ in 0..blocks {
            match larsal_crypto::random::bytes(128) {
                Ok(b) => {
                    if f.write_all(b.expose()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = f.sync_all();
    }
    let _ = std::fs::remove_file(path);
}

/// Removes copies left in the private folder by a crash or forced quit
/// (MOD-05.12 rule 4): called once when the app's session starts. Only in
/// the session's checked folder (F-065, LD-344).
pub(crate) fn clean_open_copies(copies: &crate::open_copies::OpenCopies) {
    if let Ok(list) = copies.folder().and_then(std::fs::read_dir) {
        for item in list.flatten() {
            wipe_file(&item.path());
        }
    }
}

/// The copy's extension: the text after the last dot of the name, when it
/// has one, without path separators.
fn extension(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, ext)| {
            ext.chars()
                .filter(|c| !matches!(c, '/' | '\\' | ':'))
                .collect()
        })
        .unwrap_or_default()
}

/// The QR symbol of `text` (FEA-04.23): error correction H, byte mode,
/// the smallest version that fits, a quiet zone of 4 modules.
fn qr(text: &[u8]) -> Result<Qr, LarsalError> {
    symbol(text, None)
}

/// The QR symbol of Show as QR Code (FEA-10.8, LD-359): as [`qr`] with one
/// ECI designator 26 (UTF-8) before its one byte segment. Never a fallback
/// to another level, a truncation or a second segment. The product path is
/// larsal-qr `encode`, which makes this symbol; tests compare with it.
#[cfg(test)]
pub(crate) fn qr_eci26(text: &[u8]) -> Result<Qr, LarsalError> {
    symbol(text, Some(26))
}

/// The matrix of the one encoder the `larsal` tool shares (larsal-qr, E21-S3).
fn symbol(text: &[u8], eci: Option<u32>) -> Result<Qr, LarsalError> {
    larsal_qr::symbol(text, eci)
        .map(qr_of)
        .ok_or_else(|| LarsalError::Refused(larsal_qr::Refusal::Failed.message().to_owned()))
}

/// The record of a shared matrix: one copy of its modules, freed through this
/// library's zeroing allocator; the matrix itself is wiped when it drops here.
pub(crate) fn qr_of(m: larsal_qr::Matrix) -> Qr {
    Qr {
        size: count(m.size()),
        modules: m.modules().to_vec(),
    }
}

impl EditState {
    /// The open draft's entry, unsaved edits included (qr.rs).
    pub(crate) fn draft_entry(&self) -> Option<&Entry> {
        self.draft.as_ref().map(|d| &d.entry)
    }
}

impl Session {
    /// Runs `f` on the open draft of vault `vault`; the vault only reads,
    /// so it is not a change (F-167).
    fn with_draft<R>(
        &self,
        vault: u64,
        f: impl FnOnce(&Vault, &mut Draft) -> Result<R, LarsalError>,
    ) -> Result<R, LarsalError> {
        self.with_draft_state(vault, |v, state| {
            let d = state
                .draft
                .as_mut()
                .ok_or_else(|| LarsalError::Refused("The editor is not open.".to_owned()))?;
            f(v, d)
        })
    }

    /// Runs a vault change: counts it as one unsaved change and drops the
    /// ratings of `touched` (LD-139).
    pub(crate) fn change<R>(
        &self,
        vault: u64,
        f: impl FnOnce(&mut Vault, Time) -> Result<(R, Vec<Uuid>), LarsalError>,
    ) -> Result<R, LarsalError> {
        self.with_edit(vault, |v, _, rated, state| {
            let (out, touched) = f(v, now())?;
            if !touched.is_empty() {
                state.changes = state.changes.saturating_add(1);
                for id in touched {
                    rated.forget(id);
                }
            }
            Ok(out)
        })
    }
}

fn forget_all(rated: &mut Rated, ids: &[Uuid]) {
    for id in ids {
        rated.forget(*id);
    }
}

impl Session {
    /// Tests only: whether vault `vault` has an editor draft, read even
    /// while it is locked (a lock must have dropped it).
    #[doc(hidden)]
    #[must_use]
    pub fn has_draft(&self, vault: u64) -> bool {
        self.with_edit_state(vault, |s| s.draft.is_some())
    }

    /// Tests only: `Some(locked)` for the kept password's pages of vault
    /// `vault`; `None` when nothing is kept (locked, or no password).
    #[doc(hidden)]
    #[must_use]
    pub fn password_pages_locked(&self, vault: u64) -> Option<bool> {
        // The save lock after the session lock is released (LD-199 (4)).
        let saver = self.with_edit_state(vault, |s| s.saver.clone())?;
        let sv = saver.lock().unwrap_or_else(PoisonError::into_inner);
        sv.password.as_ref()?;
        #[cfg(target_os = "macos")]
        return Some(sv.password_pages.is_some());
        #[cfg(not(target_os = "macos"))]
        Some(false)
    }
}

#[uniffi::export]
impl Session {
    /// Opens the editor on entry `entry` of vault `vault` (MOD-01.32): a
    /// draft copy; nothing changes until [`Session::commit_edit`]. An
    /// editor already open is dropped.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `Refused` for an entry in
    /// the Recycle Bin.
    pub fn begin_edit(&self, vault: u64, entry: String) -> Result<EditorView, LarsalError> {
        self.with_edit(vault, |v, _, _, state| {
            let id = parse_id(&entry, LarsalError::UnknownEntry)?;
            let mut chain = Vec::new();
            let e = find(&v.root, id, &mut chain).ok_or(LarsalError::UnknownEntry)?;
            if recycle::entry_in_bin(v, id) {
                return Err(refused(&Error::InRecycleBin));
            }
            let group = chain.last().map_or(v.root.uuid, |g| g.uuid);
            let d = Draft {
                entry: e.duplicate(true),
                original: Some(e.duplicate(false)),
                group,
                marked: Vec::new(),
                all_marked: false,
            };
            let out = view(v, &d);
            // A new edit: copies opened from the last one go (MOD-05.12).
            state.opened.clear();
            state.draft = Some(d);
            Ok(out)
        })
    }

    /// Opens the editor on a new entry in group `group` (MOD-01.22), or in
    /// the root group when `None`: not yet in the vault.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup`; `Refused` inside the bin.
    pub fn begin_new(&self, vault: u64, group: Option<String>) -> Result<EditorView, LarsalError> {
        // APP-01.25 S-ENTRY-03: always a password (never a passphrase) from
        // the stored generator options, or the built-in fallback options
        // when they are invalid (FEA-02.19).
        let made = self
            .settings
            .flag("entry.autogen_password".to_owned())
            .then(|| {
                let options = crate::generator::password_options(&self.settings.generator());
                larsal_core::generator::password::for_new_entry(&options).ok()
            })
            .flatten();
        self.with_edit(vault, |v, _, _, state| {
            let group = match group {
                Some(g) => parse_id(&g, LarsalError::UnknownGroup)?,
                None => v.root.uuid,
            };
            let mut e = edit::new_entry(v, group, false).map_err(|e| refused(&e))?;
            if let Some(value) = made {
                let protected = e.field("Password").is_none_or(|f| f.protected);
                e.set_field("Password".to_owned(), Field { value, protected });
            }
            let d = Draft {
                entry: e,
                original: None,
                group,
                marked: Vec::new(),
                all_marked: false,
            };
            let out = view(v, &d);
            state.opened.clear();
            state.draft = Some(d);
            Ok(out)
        })
    }

    /// The editor's view of its draft.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`; `Refused` when no editor is open.
    pub fn editor(&self, vault: u64) -> Result<EditorView, LarsalError> {
        self.with_draft(vault, |v, d| Ok(view(v, d)))
    }

    /// Sets a standard text field of the draft. Line breaks in `Title`,
    /// `UserName` and `URL` become spaces at commit (MOD-01.5).
    ///
    /// # Errors
    /// `TooLong` over 64 KiB; `Refused` when no editor is open.
    pub fn set_text(&self, vault: u64, field: EditText, value: String) -> Result<(), LarsalError> {
        text(&value)?;
        self.with_draft(vault, |_, d| {
            let protected = d.entry.field(field.name()).is_some_and(|f| f.protected);
            d.entry.set_field(
                field.name().to_owned(),
                Field {
                    value: SecretString::new(value),
                    protected,
                },
            );
            Ok(())
        })
    }

    /// Sets the draft's password from the editor's field. The text goes into
    /// a `SecretString` at once; Swift keeps no copy. Returns its length in
    /// characters.
    ///
    /// # Errors
    /// `TooLong` over 64 KiB; `Refused` when no editor is open.
    pub fn set_password(&self, vault: u64, value: String) -> Result<u32, LarsalError> {
        text(&value)?;
        let value = SecretString::new(value);
        self.with_draft(vault, |_, d| {
            let chars = count(value.expose().chars().count());
            let protected = d.entry.field("Password").is_none_or(|f| f.protected);
            d.entry
                .set_field("Password".to_owned(), Field { value, protected });
            Ok(chars)
        })
    }

    /// The editor's Show: the draft's password as stored, unresolved (the
    /// edit fields show raw values, MOD-08.25). A crossing of LD-220: the
    /// Show value; Swift drops it on Hide, on leaving the editor and on lock.
    ///
    /// # Errors
    /// `Refused` when no editor is open.
    pub fn draft_password(&self, vault: u64) -> Result<String, LarsalError> {
        self.with_draft(vault, |_, d| Ok(d.entry.value("Password").to_owned()))
    }

    /// Rates the draft's password (FEA-05.7, LD-137): call it off the
    /// screen thread after typing pauses. `None` for an empty password.
    ///
    /// # Errors
    /// `Refused` when no editor is open.
    pub fn rate_draft(&self, vault: u64) -> Result<Option<Rating>, LarsalError> {
        // MOD-08.25: the meter rates the resolved password, in the context
        // of the live entry when there is one; resolved under the lock,
        // rated outside it.
        let (copy, password) = self.with_edit(vault, |v, path, _, s| {
            let d = s
                .draft
                .as_ref()
                .ok_or_else(|| LarsalError::Refused("The editor is not open.".to_owned()))?;
            let context = find(&v.root, d.entry.uuid, &mut Vec::new()).unwrap_or(&d.entry);
            let text = crate::views::resolved(v, path, context, d.entry.value("Password"));
            Ok((d.entry.duplicate(false), text))
        })?;
        Ok(rate(password.expose(), &copy))
    }

    /// Adds a custom field named `New field` (or the next free number,
    /// MOD-01.3), empty and unprotected. Returns its name.
    ///
    /// # Errors
    /// `Refused` past MOD-01.9's count or when no editor is open.
    pub fn add_field(&self, vault: u64) -> Result<String, LarsalError> {
        self.with_draft(vault, |_, d| {
            let custom = d
                .entry
                .fields()
                .count()
                .saturating_sub(STANDARD_FIELDS.len());
            if custom >= edit::MAX_CUSTOM {
                return Err(refused(&Error::FieldTooLarge));
            }
            let name = edit::new_field_name(&d.entry, edit::NEW_FIELD);
            d.entry.set_field(
                name.clone(),
                Field {
                    value: SecretString::new(String::new()),
                    protected: false,
                },
            );
            Ok(name)
        })
    }

    /// Renames custom field `old` to the typed name, trimmed (MOD-01.3).
    ///
    /// # Errors
    /// `Refused` (`msg.field_name_invalid`) for an empty, standard or
    /// taken name; `TooLong`.
    pub fn rename_field(&self, vault: u64, old: String, name: String) -> Result<(), LarsalError> {
        text(&name)?;
        self.with_draft(vault, |_, d| {
            if !listed(&old) {
                return Err(LarsalError::UnknownField);
            }
            edit::rename_field(&mut d.entry, &old, &name).map_err(|e| refused(&e))
        })
    }

    /// Sets custom field `name`'s value, keeping its flag (MOD-01.6).
    ///
    /// # Errors
    /// `UnknownField`; `TooLong`; `Refused` when no editor is open.
    pub fn set_field(&self, vault: u64, name: String, value: String) -> Result<(), LarsalError> {
        text(&value)?;
        self.with_draft(vault, |_, d| {
            let protected = d
                .entry
                .field(&name)
                .filter(|_| listed(&name))
                .ok_or(LarsalError::UnknownField)?
                .protected;
            d.entry.set_field(
                name,
                Field {
                    value: SecretString::new(value),
                    protected,
                },
            );
            Ok(())
        })
    }

    /// Turns custom field `name`'s own protected flag on or off; the value
    /// stays (MOD-01.6).
    ///
    /// # Errors
    /// `UnknownField`; `Refused` when no editor is open.
    pub fn protect_field(&self, vault: u64, name: String, on: bool) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            let f = d
                .entry
                .field(&name)
                .filter(|_| listed(&name))
                .ok_or(LarsalError::UnknownField)?;
            let value = f.duplicate().value;
            d.entry.set_field(
                name,
                Field {
                    value,
                    protected: on,
                },
            );
            Ok(())
        })
    }

    /// Shows field `name` of the draft: the Show value (LD-220). A custom field, an
    /// additional URL, or `Title`, `UserName`, `URL`, `Notes` (protected
    /// ones come empty in the view, F-060); never the password (its own
    /// Show) nor the one-time password or passkey fields (LD-170 (4)).
    ///
    /// # Errors
    /// `UnknownField`; `Refused` when no editor is open.
    pub fn show_draft_field(&self, vault: u64, name: String) -> Result<String, LarsalError> {
        self.with_draft(vault, |_, d| {
            d.entry
                .field(&name)
                .filter(|_| showable(&name))
                .map(|f| f.value.expose().to_owned())
                .ok_or(LarsalError::UnknownField)
        })
    }

    /// Removes custom field `name` (after the screen asked, MOD-01.3).
    ///
    /// # Errors
    /// `UnknownField`; `Refused` when no editor is open.
    pub fn remove_field(&self, vault: u64, name: String) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            if !listed(&name) || d.entry.remove_field(&name).is_none() {
                return Err(LarsalError::UnknownField);
            }
            Ok(())
        })
    }

    /// Adds an additional URL (MOD-01.8): field `KP2A_URL`, or
    /// `KP2A_URL_` and the first unused number.
    ///
    /// # Errors
    /// `TooLong`; `Refused` for an empty URL or when no editor is open.
    pub fn add_url(&self, vault: u64, url: String) -> Result<(), LarsalError> {
        text(&url)?;
        let url = edit::screen_line(url.trim());
        if url.is_empty() {
            return Err(LarsalError::Refused("Type a website address.".to_owned()));
        }
        self.with_draft(vault, |_, d| {
            let name = if d.entry.field(EXTRA_URL).is_none() {
                EXTRA_URL.to_owned()
            } else {
                (1u64..)
                    .map(|n| format!("{EXTRA_URL}_{n}"))
                    .find(|n| d.entry.field(n).is_none())
                    .unwrap_or_default()
            };
            d.entry.set_field(
                name,
                Field {
                    value: SecretString::new(url),
                    protected: false,
                },
            );
            Ok(())
        })
    }

    /// Removes the additional URL whose value is `url`.
    ///
    /// # Errors
    /// `UnknownField`; `Refused` when no editor is open.
    pub fn remove_url(&self, vault: u64, url: String) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            let name = d
                .entry
                .fields()
                .find(|(n, f)| is_extra_url(n) && f.value.expose() == url)
                .map(|(n, _)| n.to_owned())
                .ok_or(LarsalError::UnknownField)?;
            d.entry.remove_field(&name);
            Ok(())
        })
    }

    /// Sets the draft's tags from the chips (MOD-07.3): each cleaned, empty
    /// ones dropped; the favorite mark is kept as it was.
    ///
    /// # Errors
    /// `TooLong`; `Refused` when no editor is open.
    pub fn set_tags(&self, vault: u64, chips: Vec<String>) -> Result<(), LarsalError> {
        text(&chips.concat())?;
        self.with_draft(vault, |_, d| {
            let mut list = tags::from_chips(&chips);
            list.retain(|t| !t.eq_ignore_ascii_case(FAVORITE));
            list.extend(
                d.entry
                    .tags()
                    .iter()
                    .filter(|t| t.eq_ignore_ascii_case(FAVORITE))
                    .cloned(),
            );
            d.entry.set_tags(list);
            Ok(())
        })
    }

    /// Chooses the group the entry goes to on commit (a move, MOD-02.21).
    ///
    /// # Errors
    /// `UnknownGroup` (also for the bin and groups in it).
    pub fn set_group(&self, vault: u64, group: String) -> Result<(), LarsalError> {
        self.with_draft(vault, |v, d| {
            let id = parse_id(&group, LarsalError::UnknownGroup)?;
            if group_by_id(v, id).is_none() || recycle::group_in_bin(v, id) {
                return Err(LarsalError::UnknownGroup);
            }
            d.group = id;
            Ok(())
        })
    }

    /// Sets `Expires` and `ExpiryTime` (MOD-09); `at` in unix seconds, kept
    /// as it was when `None`.
    ///
    /// # Errors
    /// `Refused` when no editor is open.
    pub fn set_expiry(&self, vault: u64, on: bool, at: Option<i64>) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            // MOD-09.10: ticking the box sets the field to now.
            if on && !d.entry.times.expires && at.is_none() {
                d.entry.times.expiry = now();
            }
            d.entry.times.expires = on;
            if let Some(t) = at.and_then(Time::from_unix) {
                d.entry.times.expiry = t;
            }
            Ok(())
        })
    }

    /// The expiry preset `index` of MOD-09.11 (0 to 11) from now, in the
    /// local offset `utc_offset` seconds; turns `Expires` on. Returns the
    /// time, unix seconds.
    ///
    /// # Errors
    /// `Refused` for an index past the list or when no editor is open.
    pub fn expiry_preset(
        &self,
        vault: u64,
        index: u32,
        utc_offset: i32,
    ) -> Result<i64, LarsalError> {
        struct Fixed(i64);
        impl larsal_core::time::Zone for Fixed {
            fn offset(&self, _: Time) -> i64 {
                self.0
            }
        }
        let preset = larsal_core::expiry::PRESETS
            .get(index as usize)
            .copied()
            .ok_or_else(|| LarsalError::Refused("No such preset.".to_owned()))?;
        let at = preset
            .apply(now(), &Fixed(i64::from(utc_offset)))
            .ok_or_else(|| LarsalError::Refused("No such preset.".to_owned()))?;
        self.with_draft(vault, |_, d| {
            d.entry.times.expires = true;
            d.entry.times.expiry = at;
            Ok(unix(at))
        })
    }

    /// Chooses standard icon `number` (MOD-01.13, MOD-06): the custom icon
    /// is cleared.
    ///
    /// # Errors
    /// `Refused` for a number outside the standard set or when no editor is
    /// open.
    pub fn set_icon(&self, vault: u64, number: i32) -> Result<(), LarsalError> {
        if !(0..69).contains(&number) {
            return Err(LarsalError::Refused("No such icon.".to_owned()));
        }
        self.with_draft(vault, |_, d| {
            d.entry.icon = Icon::Standard(number);
            Ok(())
        })
    }

    /// The Auto-Type page (MOD-01.18): enabled, and the entry's own sequence
    /// (empty: the group's).
    ///
    /// # Errors
    /// `TooLong`; `Refused` when no editor is open.
    pub fn set_auto_type(
        &self,
        vault: u64,
        enabled: bool,
        sequence: String,
    ) -> Result<(), LarsalError> {
        text(&sequence)?;
        self.with_draft(vault, |_, d| {
            d.entry.auto_type.enabled = enabled;
            d.entry.auto_type.default_sequence = sequence;
            Ok(())
        })
    }

    /// Adds a window association (INT-05): a title pattern and a sequence
    /// (empty: the entry's).
    ///
    /// # Errors
    /// `TooLong`; `Refused` when no editor is open.
    pub fn add_window(
        &self,
        vault: u64,
        window: String,
        sequence: String,
    ) -> Result<(), LarsalError> {
        text(&window)?;
        text(&sequence)?;
        self.with_draft(vault, |_, d| {
            d.entry.auto_type.associations.push(Association {
                window,
                sequence,
                unknown: Vec::new(),
            });
            Ok(())
        })
    }

    /// Removes window association `index`.
    ///
    /// # Errors
    /// `Refused` for an index past the list or when no editor is open.
    pub fn remove_window(&self, vault: u64, index: u32) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            let list = &mut d.entry.auto_type.associations;
            if (index as usize) >= list.len() {
                return Err(LarsalError::Refused("No such window.".to_owned()));
            }
            list.remove(index as usize);
            Ok(())
        })
    }

    /// Adds the file at `path` as an attachment named after it (MOD-05.16,
    /// MOD-05.17); a same name gets the new content (the screen asked).
    ///
    /// # Errors
    /// `TooLong`; `CannotOpen` when the file cannot be read; `Refused` past
    /// the limits or when no editor is open.
    pub fn attach_file(&self, vault: u64, path: String) -> Result<(), LarsalError> {
        if path.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        let limits = attachments::Limits::DEFAULT;
        // Regular files only (MOD-05.6; links to files are followed): a
        // FIFO or device would block the read.
        if !std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
            return Err(LarsalError::CannotOpen(path));
        }
        let data = storage::read_limited(Path::new(&path), limits.one)
            .map_err(|_| LarsalError::CannotOpen(path.clone()))?;
        let name = attachments::name_from_path(&path).to_owned();
        self.with_draft(vault, |v, d| {
            let a =
                attachments::prepare(v, &d.entry, &name, data, &limits).map_err(|e| refused(&e))?;
            attachments::put(&mut d.entry, a);
            Ok(())
        })
    }

    /// Removes attachment `name` from the draft.
    ///
    /// # Errors
    /// `UnknownField` when there is none; `Refused` when no editor is open.
    pub fn remove_attachment(&self, vault: u64, name: String) -> Result<(), LarsalError> {
        self.with_edit(vault, |_, _, _, s| {
            let d = s
                .draft
                .as_mut()
                .ok_or_else(|| LarsalError::Refused("The editor is not open.".to_owned()))?;
            if attachments::remove(&mut d.entry, &[name.as_str()]) == 0 {
                return Err(LarsalError::UnknownField);
            }
            // MOD-05.11: its open copy is wiped and removed.
            if let Some(i) = s.opened.0.iter().position(|(n, ..)| *n == name) {
                let (_, copy, _) = s.opened.0.remove(i);
                wipe_file(&copy);
            }
            Ok(())
        })
    }

    /// Save… (MOD-05.14): writes attachment `name` of the draft into
    /// `folder` (made when missing) under its name with `/`, `\` and `:`
    /// removed, with 0600, replacing an existing file in one step without
    /// following a link. Returns false, writing nothing, when that file
    /// exists and `overwrite` is off: the screen asks, then calls again.
    ///
    /// # Errors
    /// `UnknownField`; `TooLong`; `Refused` for a name that leaves nothing
    /// usable, or when the file cannot be written.
    pub fn save_attachment(
        &self,
        vault: u64,
        name: String,
        folder: String,
        overwrite: bool,
    ) -> Result<bool, LarsalError> {
        if folder.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        let file: String = name
            .chars()
            .filter(|c| !matches!(c, '/' | '\\' | ':'))
            .collect();
        if file.is_empty() || file == "." || file == ".." {
            return Err(LarsalError::Refused(format!(
                "“{name}” cannot be saved under that name."
            )));
        }
        let data = self.with_draft(vault, |_, d| {
            attachments::find(&d.entry, &name)
                .map(|a| Arc::clone(&a.data))
                .ok_or(LarsalError::UnknownField)
        })?;
        let failed =
            |e: std::io::Error| LarsalError::Refused(format!("“{name}” could not be saved: {e}."));
        std::fs::create_dir_all(&folder).map_err(failed)?;
        let path = Path::new(&folder).join(&file);
        if !overwrite && std::fs::symlink_metadata(&path).is_ok() {
            return Ok(false);
        }
        storage::write_export(&path, data.expose()).map_err(failed)?;
        Ok(true)
    }

    /// Deletes custom data item `key` (MOD-01.20; the screen asked).
    ///
    /// # Errors
    /// `UnknownField`; `Refused` when no editor is open.
    pub fn remove_custom_data(&self, vault: u64, key: String) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            let items = &mut d.entry.custom_data.items;
            let before = items.len();
            items.retain(|i| i.key != key);
            if items.len() == before {
                return Err(LarsalError::UnknownField);
            }
            Ok(())
        })
    }

    /// The earlier version at history position `index` (MOD-03.12), with
    /// its password: the one Show value of the sheet (LD-220).
    ///
    /// # Errors
    /// `Refused` for a position past the list or when no editor is open.
    pub fn show_version(&self, vault: u64, index: u32) -> Result<VersionView, LarsalError> {
        self.with_draft(vault, |v, d| {
            let e = &d.entry;
            let item = e
                .history
                .get(index as usize)
                .ok_or_else(|| refused(&Error::NoSuchHistoryItem))?;
            let newer = e.history.get(index as usize + 1).unwrap_or(e);
            let before = match change_words(newer, item).as_str() {
                "Passkey added" => "the passkey was added".to_owned(),
                "Passkey removed" => "the passkey was removed".to_owned(),
                other => format!("the next change ({})", other.to_lowercase()),
            };
            Ok(VersionView {
                title: plain_in(v, item, "Title"),
                saved: unix(item.times.last_modification),
                before,
                user: plain_in(v, item, "UserName"),
                password: item.value("Password").to_owned(),
                url: plain_in(v, item, "URL"),
                protected: protected_texts(v, item),
            })
        })
    }

    /// Shows field `name` of the earlier version at history position
    /// `index`: the Show value (LD-220); the fields `show_draft_field` gives
    /// (F-060).
    ///
    /// # Errors
    /// `UnknownField`; `Refused` for a position past the list or when no
    /// editor is open.
    pub fn show_version_field(
        &self,
        vault: u64,
        index: u32,
        name: String,
    ) -> Result<String, LarsalError> {
        self.with_draft(vault, |_, d| {
            d.entry
                .history
                .get(index as usize)
                .ok_or_else(|| refused(&Error::NoSuchHistoryItem))?
                .field(&name)
                .filter(|_| showable(&name))
                .map(|f| f.value.expose().to_owned())
                .ok_or(LarsalError::UnknownField)
        })
    }

    /// Restore (MOD-03.12): every stored value of history item `index`
    /// goes into the draft; nothing changes until commit.
    ///
    /// # Errors
    /// `Refused` for a position past the list or when no editor is open.
    pub fn restore_version(&self, vault: u64, index: u32) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            let item = d
                .entry
                .history
                .get(index as usize)
                .ok_or_else(|| refused(&Error::NoSuchHistoryItem))?
                .duplicate(false);
            history::restore_into(&mut d.entry, &item);
            Ok(())
        })
    }

    /// Delete (MOD-03.13): marks history item `index` (or, with `None`,
    /// every item); removed at commit.
    ///
    /// # Errors
    /// `Refused` for a position past the list or when no editor is open.
    pub fn delete_version(&self, vault: u64, index: Option<u32>) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            match index {
                None => d.all_marked = true,
                Some(i) if (i as usize) < d.entry.history.len() => {
                    if !d.marked.contains(&(i as usize)) {
                        d.marked.push(i as usize);
                    }
                }
                Some(_) => return Err(refused(&Error::NoSuchHistoryItem)),
            }
            Ok(())
        })
    }

    /// The setup screen's controls for the draft (FEA-04.22). A crossing of
    /// LD-220: the setup secret, shown in the sheet the user opened.
    ///
    /// # Errors
    /// `Refused` when no editor is open.
    pub fn totp_setup(&self, vault: u64) -> Result<TotpSetup, LarsalError> {
        self.with_draft(vault, |_, d| {
            let s = totp::prefill(&d.entry);
            Ok(TotpSetup {
                secret: s.secret.expose().to_owned(),
                choice: match s.choice {
                    totp::Choice::Standard => "standard",
                    totp::Choice::Steam => "steam",
                    totp::Choice::Custom => "custom",
                }
                .to_owned(),
                digits: s.digits,
                period: s.period,
                algorithm: algorithm_name(s.algorithm).to_owned(),
                invalid: s.invalid,
            })
        })
    }

    /// Saves the setup screen into the draft (FEA-04.16, FEA-04.22): the
    /// secret is cleaned and checked; Standard when digits, period and
    /// algorithm are 6, 30 and SHA-1, else Custom. An empty secret removes
    /// the settings (the screen asked, `MSG-OTP-CONFIRM-REMOVE`).
    ///
    /// # Errors
    /// `Refused` with `MSG-OTP-BAD-SECRET`; `TooLong`.
    pub fn set_totp(
        &self,
        vault: u64,
        secret: String,
        digits: u32,
        period: u32,
        algorithm: String,
    ) -> Result<(), LarsalError> {
        text(&secret)?;
        let secret = SecretString::new(secret);
        // The setup screen also takes the otpauth:// link a site shows
        // (form U, FEA-04.17): kept as typed when it makes codes.
        let link = secret.expose().trim();
        if link
            .get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
        {
            if totp::from_text(link, "").is_none_or(|s| s.problem().is_some()) {
                return Err(LarsalError::Refused(
                    "This link can't be used for one-time codes.".to_owned(),
                ));
            }
            let link = SecretString::new(link.to_owned());
            return self.with_draft(vault, |_, d| {
                totp::remove(&mut d.entry);
                d.entry.set_field(
                    "otp".to_owned(),
                    Field {
                        value: link,
                        protected: true,
                    },
                );
                Ok(())
            });
        }
        let checked = totp::setup_secret(secret.expose()).map_err(|_| {
            LarsalError::Refused(
                "This secret key can't be used. It may hold only the letters A to Z and the digits 2 to 7, for example JBSWY3DPEHPK3PXP."
                    .to_owned(),
            )
        })?;
        let algorithm = match algorithm.as_str() {
            "SHA-256" => totp::Algorithm::Sha256,
            "SHA-512" => totp::Algorithm::Sha512,
            _ => totp::Algorithm::Sha1,
        };
        self.with_draft(vault, |_, d| {
            let Some(checked) = checked else {
                totp::remove(&mut d.entry);
                return Ok(());
            };
            let standard = digits == 6 && period == 30 && algorithm == totp::Algorithm::Sha1;
            let setup = totp::Setup {
                secret: SecretString::new(String::new()),
                choice: if standard {
                    totp::Choice::Standard
                } else {
                    totp::Choice::Custom
                },
                algorithm,
                period,
                digits,
                invalid: false,
            };
            let (title, user) = (
                d.entry.value("Title").to_owned(),
                d.entry.value("UserName").to_owned(),
            );
            totp::write(&mut d.entry, &checked, &setup, &title, &user);
            Ok(())
        })
    }

    /// The draft's current one-time code (FEA-04.14); `None` without
    /// settings. Ask once a second while the Entry page shows. A crossing of
    /// LD-220: the live code, never the secret.
    ///
    /// # Errors
    /// `Refused` when no editor is open.
    pub fn draft_code(&self, vault: u64) -> Result<Option<TotpView>, LarsalError> {
        self.with_draft(vault, |_, d| Ok(totp_of(&d.entry)))
    }

    /// The QR symbol of the draft's one-time password (FEA-04.23): the form
    /// U text built from the current settings, title and user name
    /// unresolved. A crossing of LD-220: Swift gets the QR matrix the user
    /// asked for, a lossless picture of the link; the text stays in Rust.
    ///
    /// # Errors
    /// `UnknownField` without settings; `Refused` (`MSG-OTP-QR-ERROR`) when
    /// it does not fit.
    pub fn totp_qr(&self, vault: u64) -> Result<Qr, LarsalError> {
        let uri = self.with_draft(vault, |_, d| {
            let s = totp::settings(&d.entry).ok_or(LarsalError::UnknownField)?;
            Ok(s.uri(d.entry.value("Title"), d.entry.value("UserName")))
        })?;
        qr(uri.expose().as_bytes())
    }

    /// Copies the draft's form U text (FEA-04.23's Copy) under the APP-03
    /// rules; the text never reaches Swift.
    ///
    /// # Errors
    /// `UnknownField` without settings; `NotAvailable` when the clipboard
    /// could not be written.
    pub fn copy_totp_link(&self, vault: u64) -> Result<Copied, LarsalError> {
        let uri = self.with_draft(vault, |_, d| {
            let s = totp::settings(&d.entry).ok_or(LarsalError::UnknownField)?;
            Ok(s.uri(d.entry.value("Title"), d.entry.value("UserName")))
        })?;
        self.copy_value("One-time password link".to_owned(), uri.expose())
    }

    /// Remove passkey from the editor (INT-04.46): every passkey field and
    /// the tag `Passkey` leave the draft; part of the edit session.
    ///
    /// # Errors
    /// `UnknownField` without a passkey; `Refused` when no editor is open.
    pub fn remove_passkey(&self, vault: u64) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            let names: Vec<String> = d
                .entry
                .fields()
                .map(|(n, _)| n)
                .filter(|n| n.starts_with(PASSKEY))
                .map(str::to_owned)
                .collect();
            if names.is_empty() {
                return Err(LarsalError::UnknownField);
            }
            for n in names {
                d.entry.remove_field(&n);
            }
            tags::remove_from(&mut d.entry, PASSKEY_TAG);
            Ok(())
        })
    }

    /// Commits the editor (MOD-01.25, MOD-01.32, MOD-03.13): a new entry
    /// joins its group; an existing one has its marked history items
    /// removed, then takes the draft in one edit session, then moves when
    /// its group changed. Counts one change when anything changed and drops
    /// the entry's ratings (LD-139). Returns the entry's id.
    ///
    /// # Errors
    /// `Refused` with the core's reason (the draft stays open), or when no
    /// editor is open.
    pub fn commit_edit(&self, vault: u64) -> Result<String, LarsalError> {
        self.with_edit(vault, |v, _, rated, state| {
            let d = state
                .draft
                .as_mut()
                .ok_or_else(|| LarsalError::Refused("The editor is not open.".to_owned()))?;
            for name in ["Title", "UserName", "URL"] {
                let value = d.entry.value(name);
                if value.contains(['\r', '\n']) {
                    let line = edit::screen_line(value);
                    let protected = d.entry.field(name).is_some_and(|f| f.protected);
                    d.entry.set_field(
                        name.to_owned(),
                        Field {
                            value: SecretString::new(line),
                            protected,
                        },
                    );
                }
            }
            let at = now();
            let id = d.entry.uuid;
            let changed = if d.original.is_none() {
                let e = d.entry.duplicate(false);
                let id = edit::add_entry(v, d.group, e, at).map_err(|e| refused(&e))?;
                // `add_entry` starts with no expiry and the expiry time at
                // creation; the editor's is kept only when Expires is on
                // (MOD-09.10), so the time stays the creation time when it
                // is off (MOD-01.25, MOD-09.1).
                let (expires, expiry) = (d.entry.times.expires, d.entry.times.expiry);
                if expires {
                    edit::change_entry(v, id, at, |e| {
                        (e.times.expires, e.times.expiry) = (expires, expiry)
                    })
                    .map_err(|e| refused(&e))?;
                }
                d.entry.uuid = id;
                true
            } else {
                let marks = if d.all_marked {
                    Some(history::Delete::All)
                } else if d.marked.is_empty() {
                    None
                } else {
                    Some(history::Delete::Items(d.marked.clone()))
                };
                let mut changed = false;
                if let Some(m) = marks {
                    changed |= history::delete_items(v, id, &m, at).map_err(|e| refused(&e))?;
                }
                let next = d.entry.duplicate(false);
                changed |= edit::edit_entry(v, id, at, |e| *e = next).map_err(|e| refused(&e))?;
                if holder(v, id).is_some_and(|g| g.uuid != d.group) {
                    changed |=
                        edit::move_entries(v, &[id], d.group, at).map_err(|e| refused(&e))? > 0;
                }
                changed
            };
            let id = d.entry.uuid;
            state.draft = None;
            state.opened.clear();
            if changed {
                state.changes = state.changes.saturating_add(1);
                rated.forget(id);
            }
            Ok(hex(id))
        })
    }

    /// Cancel (MOD-01.25): the draft goes; nothing changed.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn cancel_edit(&self, vault: u64) -> Result<(), LarsalError> {
        self.with_edit(vault, |_, _, _, state| {
            state.draft = None;
            state.opened.clear();
            Ok(())
        })
    }

    /// Adds a custom icon from the PNG the screen rendered for a symbol and
    /// a colour (LD-192 (1), MOD-06.10): decoded and scaled to at most
    /// 128 pixels (MOD-06.8), an equal icon reused (MOD-06.9), named
    /// `name`. A change of the vault. Returns its id.
    ///
    /// # Errors
    /// `TooLong` over 16 MiB or a long name; `Refused` when it is no
    /// image Larsal reads.
    pub fn add_custom_icon(
        &self,
        vault: u64,
        png: Vec<u8>,
        name: String,
    ) -> Result<String, LarsalError> {
        text(&name)?;
        let limits = icons::Limits::DEFAULT;
        if png.len() > limits.bytes {
            return Err(LarsalError::TooLong);
        }
        let data = icons::decode(&png, &icons::Images, &limits)
            .ok_or_else(|| LarsalError::Refused("The icon could not be read.".to_owned()))?;
        self.with_edit(vault, |v, _, _, s| {
            let (id, added) =
                icons::add_png(v, data, name, Some(now())).map_err(|e| refused(&e))?;
            if added {
                s.changes = s.changes.saturating_add(1);
            }
            Ok(hex(id))
        })
    }

    /// Chooses custom icon `icon` for the draft (MOD-01.13: the number
    /// becomes 0).
    ///
    /// # Errors
    /// `Refused` for an icon the vault does not hold, or no editor.
    pub fn set_custom_icon(&self, vault: u64, icon: String) -> Result<(), LarsalError> {
        let id = parse_id(&icon, LarsalError::Refused("No such icon.".to_owned()))?;
        self.with_draft(vault, |v, d| {
            if !v.meta.custom_icons.iter().any(|i| i.uuid == id) {
                return Err(LarsalError::Refused("No such icon.".to_owned()));
            }
            d.entry.icon = Icon::Custom(id);
            Ok(())
        })
    }

    /// Adds a host to the site access item's Allow list, or with `deny` to
    /// its Deny list (INT-02.29): the host of a typed host or URL in ASCII
    /// form; adding to one list removes it from the other. Written with the
    /// editor.
    ///
    /// # Errors
    /// `Refused` with MI02-10 when it gives no valid host; `TooLong`.
    pub fn add_site(&self, vault: u64, typed: String, deny: bool) -> Result<(), LarsalError> {
        text(&typed)?;
        let host = larsal_core::url::site_host(&typed).ok_or_else(|| {
            LarsalError::Refused("That is not a website address Larsal can use.".to_owned())
        })?;
        self.with_draft(vault, |_, d| {
            let (mut allow, mut denied) = site_access(&d.entry);
            allow.retain(|h| *h != host);
            denied.retain(|h| *h != host);
            if deny {
                denied.push(host);
            } else {
                allow.push(host);
            }
            write_site_access(&mut d.entry, &allow, &denied);
            Ok(())
        })
    }

    /// Removes `host` from the Allow list, or with `deny` from the Deny
    /// list (INT-02.29).
    ///
    /// # Errors
    /// `Refused` when no editor is open.
    pub fn remove_site(&self, vault: u64, host: String, deny: bool) -> Result<(), LarsalError> {
        self.with_draft(vault, |_, d| {
            let (mut allow, mut denied) = site_access(&d.entry);
            if deny {
                denied.retain(|h| *h != host);
            } else {
                allow.retain(|h| *h != host);
            }
            write_site_access(&mut d.entry, &allow, &denied);
            Ok(())
        })
    }

    /// Sets an entry option of the Browser page (INT-02.29): `true` for on,
    /// `false` for off, nothing for off when the entry had no key. A group
    /// that decides the option is not overridden here.
    ///
    /// # Errors
    /// `UnknownField` for a key outside the three; `Refused` without an
    /// editor.
    pub fn set_browser_option(&self, vault: u64, key: String, on: bool) -> Result<(), LarsalError> {
        if !BROWSER_OPTIONS.contains(&key.as_str()) {
            return Err(LarsalError::UnknownField);
        }
        self.with_draft(vault, |_, d| {
            let had = d
                .original
                .as_ref()
                .is_some_and(|o| custom_value(o, key.as_bytes()).is_some());
            let value = if on {
                Some("true".to_owned())
            } else {
                had.then(|| "false".to_owned())
            };
            set_custom(&mut d.entry, &key, value);
            Ok(())
        })
    }

    /// Open (MOD-05.12): writes attachment `name` of the draft to a private
    /// copy (`Larsal/open-attachments` in the user's temporary folder, 0700;
    /// the file 12 random characters plus the extension, created new with
    /// 0600) and returns its path for the default app. A type that can run
    /// code asks first. The copy is wiped and removed when the editor
    /// closes, and on lock, close and quit; leftovers at the next start.
    ///
    /// # Errors
    /// `UnknownField`; `Refused` with "could not open" and the reason.
    pub fn open_attachment(
        &self,
        vault: u64,
        name: String,
        confirmed: bool,
    ) -> Result<OpenAttachment, LarsalError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // F-104: the vault, the editor and the attachment first, so the
        // screen never asks about one that cannot be opened.
        let data = self.with_draft(vault, |_, d| {
            attachments::find(&d.entry, &name)
                .map(|a| Arc::clone(&a.data))
                .ok_or(LarsalError::UnknownField)
        })?;
        // F-103: Larsal's one ask-first list, read as the copy's extension.
        if !confirmed && attachments::risky(&name) {
            return Ok(OpenAttachment::AskFirst);
        }
        let ext = extension(&name);
        let failed =
            |e: std::io::Error| LarsalError::Refused(format!("Could not open “{name}”: {e}."));
        let dir = self.open_copies.folder().map_err(failed)?;
        let mut file_name = String::with_capacity(13 + ext.len());
        for _ in 0..12 {
            let n = larsal_crypto::random::below(36).map_err(|_| {
                LarsalError::Refused("The system's random source failed. Try again.".to_owned())
            })?;
            file_name.push(char::from_digit(n, 36).unwrap_or('x'));
        }
        if !ext.is_empty() {
            file_name.push('.');
            file_name.push_str(&ext);
        }
        let path = dir.join(file_name);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(failed)?;
        if let Err(e) = f.write_all(data.expose()).and_then(|()| f.sync_all()) {
            wipe_file(&path);
            return Err(failed(e));
        }
        let kept = self.with_edit(vault, |_, _, _, s| {
            // Opened again: the older copy goes.
            if let Some(i) = s.opened.0.iter().position(|(n, ..)| *n == name) {
                let (_, old, _) = s.opened.0.remove(i);
                wipe_file(&old);
            }
            let sum = larsal_crypto::hash::sha256(&[data.expose()]);
            s.opened.0.push((name.clone(), path.clone(), sum));
            Ok(())
        });
        // Not listed (a lock came meanwhile): the copy goes at once.
        if let Err(e) = kept {
            wipe_file(&path);
            return Err(e);
        }
        Ok(OpenAttachment::Opened {
            path: path.to_string_lossy().into_owned(),
        })
    }

    /// MOD-05.13 (F-086): the attachments whose open copy another app
    /// changed since Larsal wrote it or the user last answered: the SHA-256
    /// of the whole file, read up to the attachment limit, against the one
    /// kept. The screen calls it every 5 seconds while the editor is open
    /// and before it commits, and asks Save or Discard, one file at a time.
    /// A copy that is gone or cannot be read is not listed.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn changed_attachments(&self, vault: u64) -> Result<Vec<String>, LarsalError> {
        let paths = self.with_edit(vault, |_, _, _, s| {
            Ok(s.opened
                .0
                .iter()
                .map(|(_, p, _)| p.clone())
                .collect::<Vec<_>>())
        })?;
        let limit = attachments::Limits::DEFAULT.one;
        // Read off the session lock; compared under it.
        let now: Vec<_> = paths
            .iter()
            .map(|p| {
                storage::read_limited(p, limit)
                    .ok()
                    .map(|d| larsal_crypto::hash::sha256(&[d.expose()]))
            })
            .collect();
        self.with_edit(vault, |_, _, _, s| {
            Ok(s.opened
                .0
                .iter()
                .filter(|(_, p, kept)| {
                    paths.iter().position(|q| q == p).is_some_and(|i| {
                        now.get(i)
                            .and_then(Option::as_ref)
                            .is_some_and(|sum| sum.expose() != kept.expose())
                    })
                })
                .map(|(n, ..)| n.clone())
                .collect())
        })
    }

    /// The answer to MOD-05.13's question for attachment `name`: Save
    /// (`save`) reads the whole changed copy, up to the attachment limit,
    /// into the editor's draft (MOD-05.4); Discard keeps the draft. Either
    /// way the question comes again only after the next change of the copy.
    ///
    /// # Errors
    /// `UnknownField` without an open copy of that name; `Refused` with
    /// "saving the changed attachment failed" and the system's reason, past
    /// the limits, or when no editor is open.
    pub fn take_changed_attachment(
        &self,
        vault: u64,
        name: String,
        save: bool,
    ) -> Result<(), LarsalError> {
        let path = self.with_edit(vault, |_, _, _, s| {
            s.opened
                .0
                .iter()
                .find(|(n, ..)| *n == name)
                .map(|(_, p, _)| p.clone())
                .ok_or(LarsalError::UnknownField)
        })?;
        let limits = attachments::Limits::DEFAULT;
        let data = storage::read_limited(&path, limits.one).map_err(|e| {
            LarsalError::Refused(format!("Saving the changed “{name}” failed: {e}."))
        })?;
        let sum = larsal_crypto::hash::sha256(&[data.expose()]);
        self.with_edit(vault, |v, _, _, s| {
            if save {
                let d = s
                    .draft
                    .as_mut()
                    .ok_or_else(|| LarsalError::Refused("The editor is not open.".to_owned()))?;
                let a = attachments::prepare(v, &d.entry, &name, data, &limits)
                    .map_err(|e| refused(&e))?;
                attachments::put(&mut d.entry, a);
            }
            if let Some(copy) = s.opened.0.iter_mut().find(|(n, ..)| *n == name) {
                copy.2 = sum;
            }
            Ok(())
        })
    }

    /// Clone entry (MOD-10.1 to MOD-10.8): a copy in the same group with a
    /// new id and fresh times; with `suffix` the title gets ` - Clone`,
    /// with `refs` user name and password reference the original, with
    /// `history` the history is copied. Returns the clone's id.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `Refused` in the bin or
    /// past a count limit.
    pub fn clone_entry(
        &self,
        vault: u64,
        entry: String,
        suffix: bool,
        refs: bool,
        history: bool,
    ) -> Result<String, LarsalError> {
        let id = parse_id(&entry, LarsalError::UnknownEntry)?;
        self.change(vault, |v, at| {
            if recycle::entry_in_bin(v, id) {
                return Err(refused(&Error::InRecycleBin));
            }
            let options = clone::Options {
                suffix,
                refs,
                history,
            };
            let new = clone::clone_entry(v, id, options, &clone::Limits::DEFAULT, at)
                .map_err(|e| refused(&e))?;
            Ok((hex(new), vec![new]))
        })
    }

    /// Delete (MOD-04.4): entry `entry` moves into the bin while the bin is
    /// on and it is outside it; otherwise it is deleted for good. References
    /// to it in other entries are overwritten with their values (MOD-04.6's
    /// default answer).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`.
    pub fn delete_entry(&self, vault: u64, entry: String) -> Result<DeleteResult, LarsalError> {
        let id = parse_id(&entry, LarsalError::UnknownEntry)?;
        self.change(vault, |v, at| {
            let done = recycle::delete_entries(v, &[id], at, |_, _| recycle::References::Overwrite)
                .map_err(|e| refused(&e))?;
            let out = DeleteResult {
                to_bin: count(done.to_bin),
                for_good: count(done.for_good),
            };
            let touched = if done.to_bin + done.for_good > 0 {
                vec![id]
            } else {
                Vec::new()
            };
            Ok((out, touched))
        })
    }

    /// Restore (MOD-04.10): entry `entry` leaves the bin for its previous
    /// group, or the root group when that is gone. True when it went to the
    /// root group (the user is told once).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`.
    pub fn restore_entry(&self, vault: u64, entry: String) -> Result<bool, LarsalError> {
        let id = parse_id(&entry, LarsalError::UnknownEntry)?;
        self.change(vault, |v, at| {
            let r = recycle::restore_entries(v, &[id], at).map_err(|e| refused(&e))?;
            let touched = if r.restored > 0 { vec![id] } else { Vec::new() };
            Ok((r.to_root > 0, touched))
        })
    }

    /// Empty Recycle Bin (MOD-04.9): everything in the bin is deleted for
    /// good; the bin stays. Returns the entries deleted.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn empty_bin(&self, vault: u64) -> Result<u32, LarsalError> {
        self.with_edit(vault, |v, _, rated, state| {
            let Some(b) = bin(v) else { return Ok(0) };
            let ids: Vec<Uuid> = group_by_id(v, b)
                .map(|g| g.all_entries().map(|e| e.uuid).collect())
                .unwrap_or_default();
            if !recycle::empty_bin(v, now()).map_err(|e| refused(&e))? {
                return Ok(0);
            }
            state.changes = state.changes.saturating_add(1);
            forget_all(rated, &ids);
            Ok(count(ids.len()))
        })
    }

    /// New group (MOD-02.27): `name` (one line) with standard icon `icon`,
    /// added after the child groups of `parent` (the root group when
    /// `None`). Returns its id.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup`, `TooLong`; `Refused` for an
    /// empty name, inside the bin or too deep.
    pub fn add_group(
        &self,
        vault: u64,
        parent: Option<String>,
        name: String,
        icon: i32,
        custom_icon: Option<String>,
    ) -> Result<String, LarsalError> {
        text(&name)?;
        let name = edit::screen_line(name.trim());
        if name.is_empty() {
            return Err(refused(&Error::FieldName(NameProblem::Empty)));
        }
        self.with_edit(vault, |v, _, _, state| {
            let parent = match &parent {
                Some(p) => parse_id(p, LarsalError::UnknownGroup)?,
                None => v.root.uuid,
            };
            let mut g = edit::new_group(v).map_err(|e| refused(&e))?;
            g.name = name;
            if (0..69).contains(&icon) {
                g.icon = Icon::Standard(icon);
            }
            if let Some(c) = &custom_icon {
                let id = parse_id(c, LarsalError::Refused("No such icon.".to_owned()))?;
                if !v.meta.custom_icons.iter().any(|i| i.uuid == id) {
                    return Err(LarsalError::Refused("No such icon.".to_owned()));
                }
                g.icon = Icon::Custom(id);
            }
            let id = edit::add_group(v, parent, g, now()).map_err(|e| refused(&e))?;
            state.changes = state.changes.saturating_add(1);
            Ok(hex(id))
        })
    }

    /// The footer's save state (APP-05).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn save_status(&self, vault: u64) -> Result<SaveStatus, LarsalError> {
        self.with_edit_view(vault, crate::saving::status)
    }

    /// Saves vault `vault` to its own path (APP-05.9 to APP-05.22,
    /// saving.rs): a copy of the vault is taken under the session lock;
    /// the file is built (fresh salt and KDF, CRY-03) and written through
    /// larsal-core's save without it, with the backup and method of the
    /// settings, so the window keeps reading meanwhile. Saves of one vault
    /// run one at a time. Call it off the screen thread. A file changed on
    /// disk is never overwritten without the user's choice: the status then
    /// asks (`on_disk`, APP-05.28). A lock or close during a save lets the
    /// write finish; the save holds its own reference to the key parts and
    /// drops them after; the result is not recorded.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`. A failed save is not an error: its reason
    /// is in the returned state and the changes stay counted.
    pub fn save(&self, vault: u64) -> Result<SaveStatus, LarsalError> {
        // Saves of one vault run one at a time, and each copies the vault
        // only once it holds the save lock (LD-199 (4), saving.rs).
        #[cfg(test)]
        tests::SAVE_WAITS.store(true, std::sync::atomic::Ordering::SeqCst);
        self.save_to(vault, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// FEA-10.8: ECI 26 then one byte segment. FEA-10.7, FEA-04.23: the
    /// authenticator setup code keeps its byte-only bitstream. Each symbol is
    /// checked against the bitstream written out by hand here.
    #[test]
    fn fea_10_8_eci_26_before_one_byte_segment_and_fea_10_7_setup_code_has_none() {
        use qrcode::bits::Bits;
        use qrcode::{Color, EcLevel, QrCode, Version};
        let text = "caf\u{e9} demo".as_bytes();
        let by_hand = |eci: Option<u32>, header: &[u8]| {
            let version = Version::Normal(2);
            let mut bits = Bits::new(version);
            if let Some(designator) = eci {
                bits.push_eci_designator(designator).unwrap();
            }
            bits.push_byte_data(text).unwrap();
            let start: Vec<u8> = {
                let mut copy = Bits::new(version);
                if let Some(designator) = eci {
                    copy.push_eci_designator(designator).unwrap();
                }
                copy.push_byte_data(text).unwrap();
                copy.into_bytes()
            };
            assert_eq!(&start[..header.len()], header, "the header bits");
            bits.push_terminator(EcLevel::H).unwrap();
            QrCode::with_bits(bits, EcLevel::H).unwrap()
        };
        let modules = |code: &QrCode| -> Vec<u8> {
            code.to_colors()
                .iter()
                .map(|c| u8::from(*c == Color::Dark))
                .collect()
        };
        let inner = |symbol: &Qr| -> Vec<u8> {
            let size = usize::try_from(symbol.size).unwrap();
            symbol
                .modules
                .chunks_exact(size)
                .skip(4)
                .take(size - 8)
                .flat_map(|row| row[4..size - 4].to_vec())
                .collect()
        };
        // 0111, 00011010 (26), 0100, then the 8-bit count: 12 bytes.
        assert_eq!(text.len(), 10);
        let with = by_hand(Some(26), &[0x71, 0xA4, 0x0A]);
        assert_eq!(inner(&qr_eci26(text).unwrap()), modules(&with));
        // 0100, then the count, then the text from its high nibble.
        let without = by_hand(None, &[0x40, 0xA6]);
        assert_eq!(inner(&qr(text).unwrap()), modules(&without));
    }

    /// Set by `save` just before it waits for the save lock (test hook).
    pub(super) static SAVE_WAITS: AtomicBool = AtomicBool::new(false);

    /// LD-199 (4): a save that waits for the save lock copies the vault only
    /// once it holds it, so a change made while it waited is written and no
    /// change is left. Copying first (the old order) writes the older vault
    /// and leaves the change counted, every time.
    #[test]
    fn ld_199_4_a_waiting_save_writes_the_change_made_while_it_waited() {
        let dir =
            std::env::temp_dir().join(format!("larsal-ffi-save-order-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let wise = s
            .list(v, crate::views::ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .find(|r| r.title == "Wise")
            .unwrap()
            .id;
        // Hold the save lock, as another save would.
        let saver = s
            .with_edit(v, |_, _, _, st| Ok(st.saver.clone().unwrap()))
            .unwrap();
        let held = saver.lock().unwrap();
        SAVE_WAITS.store(false, Ordering::SeqCst);
        let waiting = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.save(v).unwrap())
        };
        while !SAVE_WAITS.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        // The change made while that save waits.
        s.begin_edit(v, wise.clone()).unwrap();
        s.set_text(v, EditText::Notes, "made while a save waited".into())
            .unwrap();
        s.commit_edit(v).unwrap();
        drop(held);
        let status = waiting.join().unwrap();
        assert_eq!(
            (status.changes, status.failure),
            (0, None),
            "the waiting save wrote the change"
        );
        let again = Session::new();
        let id = again.open(path.to_string_lossy().into_owned()).unwrap();
        again.unlock(id, Some("demo-pass-7".into()), None).unwrap();
        assert_eq!(
            again.show_field(id, wise, "Notes".into()).unwrap(),
            "made while a save waited"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// LD-199 (4) note: a lock and unlock while a save waits for the save
    /// lock gives the vault new key parts; the waiting save copies nothing
    /// and writes nothing.
    #[test]
    fn ld_199_4_a_save_waiting_across_a_lock_writes_nothing() {
        let dir =
            std::env::temp_dir().join(format!("larsal-ffi-save-relock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Personal.larsalvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-personal.larsalvault"
            ),
            &path,
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let saver = s
            .with_edit(v, |_, _, _, st| Ok(st.saver.clone().unwrap()))
            .unwrap();
        let held = saver.lock().unwrap();
        SAVE_WAITS.store(false, Ordering::SeqCst);
        let waiting = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.save(v))
        };
        while !SAVE_WAITS.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        s.lock(v).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        drop(held);
        assert_eq!(waiting.join().unwrap().unwrap_err(), LarsalError::Locked);
        assert!(std::fs::read(&path).unwrap() == before, "nothing written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A fresh copy of the Personal demo vault, unlocked in a new session.
    fn personal(tag: &str) -> (Arc<Session>, u64, std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("larsal-ffi-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let github = s
            .list(v, crate::views::ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .find(|r| r.title == "GitHub")
            .unwrap()
            .id;
        (s, v, path, github)
    }

    /// Changes entry `id` in the open vault directly, as a file made
    /// elsewhere would hold it.
    fn stored(s: &Session, v: u64, id: &str, change: impl FnOnce(&mut Entry)) {
        let uuid = parse_id(id, LarsalError::UnknownEntry).unwrap();
        s.with_edit(v, |vault, _, _, _| {
            edit::change_entry(vault, uuid, now(), change).map_err(|e| refused(&e))
        })
        .unwrap();
    }

    /// INT-03.18 (T84, T85, LD-322 (7)): website rows in INT-03.2's order,
    /// every field name the matcher reads, each with its note.
    #[test]
    fn t84_t85_int03_18_website_rows_in_matcher_order_with_their_notes() {
        let (s, v, _path, id) = personal("int0318");
        stored(&s, v, &id, |e| {
            for (name, value) in [
                ("KP2A_URL_10", "https://*.co.uk"),
                ("KP2A_URL_2", "mailto:alex@example.com"),
                ("KP2A_URL", "https://exa mple.com"),
                ("KP2A_URLx", "https://example.com"),
                ("KP2A_URL_3", "{REF:A@I:00000000000000000000000000000001}"),
            ] {
                e.set_field(
                    name.to_owned(),
                    Field {
                        value: SecretString::new(value.to_owned()),
                        protected: false,
                    },
                );
            }
        });
        let view = s.begin_edit(v, id).unwrap();
        let names: Vec<&str> = view.urls.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "KP2A_URL",
                "KP2A_URL_2",
                "KP2A_URL_3",
                "KP2A_URL_10",
                "KP2A_URLx"
            ]
        );
        assert_eq!(
            view.url_notes,
            [
                "This is not a website address Larsal can match.",
                "Browsers only get entries for http and https addresses.",
                "",
                "This pattern can't be used: a `*` may not stand for a whole domain or its ending. Use a pattern like https://*.example.com.",
                "",
            ]
        );
        // The Advanced page no longer lists a field the matcher reads.
        assert!(!view.custom.iter().any(|c| c.name.starts_with("KP2A_URL")));
    }

    /// F-060 (rule 4, LD-105): protected standard fields and additional
    /// URLs reach the editor view empty and flagged; Show gives each; an
    /// edit that leaves one alone keeps its value, a typed one stays
    /// protected.
    #[test]
    fn f_060_the_editor_view_holds_no_protected_standard_value() {
        let (s, v, path, id) = personal("f060");
        let fields = [
            ("Title", "protected-title-77"),
            ("UserName", "protected-user-77"),
            ("URL", "https://protected-url-77.example"),
            ("Notes", "protected-notes-77"),
            ("KP2A_URL", "https://protected-extra-77.example"),
        ];
        stored(&s, v, &id, |e| {
            for (name, value) in fields {
                e.set_field(
                    name.to_owned(),
                    Field {
                        value: SecretString::new(value.to_owned()),
                        protected: true,
                    },
                );
            }
        });
        let view = s.begin_edit(v, id.clone()).unwrap();
        let text = format!("{view:?}");
        for (_, value) in fields {
            assert!(!text.contains(value), "{value} reached the view");
        }
        assert_eq!(
            view.protected,
            [
                EditText::Title,
                EditText::UserName,
                EditText::Url,
                EditText::Notes
            ]
        );
        assert!(
            view.urls
                .iter()
                .any(|u| u.name == "KP2A_URL" && u.protected && u.value.is_empty())
        );
        for (name, value) in fields {
            assert_eq!(s.show_draft_field(v, name.to_owned()).unwrap(), value);
        }
        assert!(s.show_draft_field(v, "Password".into()).is_err());
        s.set_text(v, EditText::UserName, "typed-user-77".into())
            .unwrap();
        s.commit_edit(v).unwrap();
        assert_eq!(
            s.show_field(v, id.clone(), "Notes".into()).unwrap(),
            "protected-notes-77",
            "left alone, kept"
        );
        let view = s.begin_edit(v, id).unwrap();
        assert!(view.protected.contains(&EditText::UserName) && view.user.is_empty());
        assert_eq!(
            s.show_draft_field(v, "UserName".into()).unwrap(),
            "typed-user-77"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// F-060 for the "Earlier version" sheet (MOD-03.12): a version's
    /// protected Title, UserName and URL reach `VersionView` empty and
    /// flagged; `show_version_field` gives each, never the password, the
    /// one-time password or the passkey fields.
    #[test]
    fn f_060_an_earlier_version_holds_no_protected_standard_value() {
        let (s, v, path, id) = personal("f060v");
        let fields = [
            ("Title", "protected-title-78"),
            ("UserName", "protected-user-78"),
            ("URL", "https://protected-url-78.example"),
            ("Notes", "protected-notes-78"),
            ("KP2A_URL", "https://protected-extra-78.example"),
        ];
        stored(&s, v, &id, |e| {
            for (name, value) in fields {
                e.set_field(
                    name.to_owned(),
                    Field {
                        value: SecretString::new(value.to_owned()),
                        protected: true,
                    },
                );
            }
        });
        // An edit makes that state the newest history item.
        s.begin_edit(v, id.clone()).unwrap();
        s.set_text(v, EditText::Title, "GitHub".into()).unwrap();
        s.commit_edit(v).unwrap();
        let index = s.begin_edit(v, id).unwrap().history_items - 1;
        let version = s.show_version(v, index).unwrap();
        let text = format!("{version:?}");
        for (_, value) in fields {
            assert!(!text.contains(value), "{value} reached the version");
        }
        assert_eq!(
            version.protected,
            [
                EditText::Title,
                EditText::UserName,
                EditText::Url,
                EditText::Notes
            ]
        );
        for (name, value) in fields {
            assert_eq!(
                s.show_version_field(v, index, name.to_owned()).unwrap(),
                value
            );
        }
        let hidden: Vec<String> = s
            .with_draft(v, |_, d| {
                Ok(d.entry.history[index as usize]
                    .fields()
                    .map(|(n, _)| n.to_owned())
                    .filter(|n| n == "Password" || is_totp_field(n) || n.starts_with(PASSKEY))
                    .collect())
            })
            .unwrap();
        assert!(hidden.len() > 2, "password, one-time and passkey fields");
        for name in hidden {
            assert_eq!(
                s.show_version_field(v, index, name),
                Err(LarsalError::UnknownField)
            );
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// LD-207, MOD-01.7: with the vault's flags on and each field's own
    /// flag off (an entry made in Larsal), Title, UserName, URL and Notes
    /// reach no view: list rows, search results, the detail (and the rail
    /// it feeds), the editor and an earlier version.
    #[test]
    fn ld_207_vault_flags_hide_standard_fields_on_every_view() {
        let (s, v, path, _) = personal("ld207");
        let values = [
            (EditText::Title, "vault-flag-title"),
            (EditText::UserName, "vault-flag-user"),
            (EditText::Url, "https://vault-flag-url.example"),
            (EditText::Notes, "vault-flag-notes"),
        ];
        s.begin_new(v, None).unwrap();
        for (field, value) in values {
            s.set_text(v, field, value.into()).unwrap();
        }
        s.set_tags(v, vec!["ld207".into()]).unwrap();
        let id = s.commit_edit(v).unwrap();
        // An edit leaves that state in the history.
        s.begin_edit(v, id.clone()).unwrap();
        s.set_tags(v, vec!["ld207".into(), "again".into()]).unwrap();
        s.commit_edit(v).unwrap();
        let uuid = parse_id(&id, LarsalError::UnknownEntry).unwrap();
        let own = s
            .with_edit(v, |vault, _, _, _| {
                let m = &mut vault.meta.memory_protection;
                (m.title, m.user_name, m.url, m.notes) = (true, true, true, true);
                let e = find(&vault.root, uuid, &mut Vec::new()).unwrap();
                Ok(values.map(|(t, _)| e.field(t.name()).unwrap().protected))
            })
            .unwrap();
        assert_eq!(own, [false; 4], "own flags off");
        let all = s.list(v, crate::views::ListView::All).unwrap();
        let found = s
            .list(
                v,
                crate::views::ListView::Search {
                    query: "ld207".into(),
                },
            )
            .unwrap();
        assert!(found.rows.iter().any(|r| r.id == id), "the search finds it");
        let detail = s.entry(v, id.clone()).unwrap();
        let editor = s.begin_edit(v, id).unwrap();
        let version = s.show_version(v, editor.history_items - 1).unwrap();
        let text = format!("{all:?}{found:?}{detail:?}{editor:?}{version:?}");
        assert!(!text.contains("vault-flag-"), "a value reached a view");
        let four = [
            EditText::Title,
            EditText::UserName,
            EditText::Url,
            EditText::Notes,
        ];
        assert_eq!(
            (&editor.protected, &version.protected),
            (&four.to_vec(), &four.to_vec())
        );
        assert!(
            detail
                .fields
                .iter()
                .filter(|f| f.name != "Password")
                .all(|f| f.protected)
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// LD-205, MOD-01.14 "keep unknown": the colours (which the editor has
    /// no control for) and the report exclusion stay exactly as stored
    /// through a Title edit and a save.
    #[test]
    fn ld_205_colours_and_report_exclusion_survive_an_edit_and_a_save() {
        let (s, v, path, id) = personal("ld205");
        stored(&s, v, &id, |e| {
            e.foreground_color = "#GG0000".to_owned();
            e.background_color = "RED".to_owned();
            e.exclude_from_reports = true;
        });
        s.begin_edit(v, id.clone()).unwrap();
        s.set_text(v, EditText::Title, "GitHub renamed".into())
            .unwrap();
        s.commit_edit(v).unwrap();
        assert_eq!(s.save(v).unwrap().failure, None);
        let again = Session::new();
        let w = again.open(path.to_string_lossy().into_owned()).unwrap();
        again.unlock(w, Some("demo-pass-7".into()), None).unwrap();
        let uuid = parse_id(&id, LarsalError::UnknownEntry).unwrap();
        let kept = again
            .with_edit(w, |vault, _, _, _| {
                let e = find(&vault.root, uuid, &mut Vec::new()).unwrap();
                Ok((
                    e.value("Title").to_owned(),
                    e.foreground_color.clone(),
                    e.background_color.clone(),
                    e.exclude_from_reports,
                ))
            })
            .unwrap();
        assert_eq!(
            kept,
            (
                "GitHub renamed".to_owned(),
                "#GG0000".to_owned(),
                "RED".to_owned(),
                true
            )
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// APP-01.25, FEA-02.19: with S-ENTRY-03 on, a new entry gets a
    /// password from the stored options (b), never a passphrase, and the
    /// built-in fallback (32 characters) when the stored options are invalid.
    #[test]
    fn app01_25_s_entry_03_new_entry_password() {
        use crate::larsal_settings::{LarsalSetting, LarsalSettingValue};
        let set = |key: &str, value: LarsalSettingValue| LarsalSetting {
            key: key.to_owned(),
            value,
        };
        let on = |key: &str, on: bool| set(key, LarsalSettingValue::Flag { on });
        let dir = std::env::temp_dir().join(format!("larsal-ffi-autogen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let made = || {
            s.begin_new(v, None).unwrap();
            let value = s
                .with_edit(v, |_, _, _, st| {
                    let d = st.draft.as_ref().unwrap();
                    Ok(d.entry.value("Password").to_owned())
                })
                .unwrap();
            s.cancel_edit(v).unwrap();
            value
        };
        s.save_settings(vec![
            on("entry.autogen_password", true),
            set(
                "generator.password.length",
                LarsalSettingValue::Number { value: 16 },
            ),
            on("generator.password.upper", false),
            on("generator.password.special", false),
        ])
        .unwrap();
        let alnum = |p: &str| {
            p.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        };
        let b = made();
        assert!(
            b.chars().count() == 16 && alnum(&b),
            "APP-01.25 b: {}",
            b.len()
        );
        s.save_settings(vec![
            set("generator.kind", LarsalSettingValue::Number { value: 1 }),
            set(
                "generator.passphrase.words",
                LarsalSettingValue::Number { value: 3 },
            ),
        ])
        .unwrap();
        let kind = made();
        assert!(
            kind.chars().count() == 16 && alnum(&kind),
            "a password, not a phrase"
        );
        s.save_settings(vec![
            on("generator.password.lower", false),
            on("generator.password.digits", false),
        ])
        .unwrap();
        assert_eq!(made().chars().count(), 32, "the built-in fallback");
        s.save_settings(vec![on("entry.autogen_password", false)])
            .unwrap();
        assert_eq!(made(), "", "off: no password");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F-062 (Rust rule 3): the records that carry a live code, the
    /// one-time secret, an earlier password or a QR matrix print none of it
    /// with `{:?}`.
    #[test]
    fn f_062_secret_records_hide_their_secret_in_debug() {
        let code = crate::views::TotpView {
            code: "492 039".into(),
            seconds_left: 12,
            period: 30,
            problem: None,
        };
        let setup = TotpSetup {
            secret: "JBSWY3DPEHPK3PXP".into(),
            choice: "standard".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA-1".into(),
            invalid: false,
        };
        let version = VersionView {
            title: "GitHub".into(),
            saved: 0,
            before: String::new(),
            user: String::new(),
            password: "old-demo-pass-3".into(),
            url: String::new(),
            protected: Vec::new(),
        };
        let qr = Qr {
            size: 2,
            modules: vec![1, 0, 0, 1],
        };
        let text = format!("{code:?}{setup:?}{version:?}{qr:?}");
        for secret in [
            "492 039",
            "JBSWY3DPEHPK3PXP",
            "old-demo-pass-3",
            "[1, 0, 0, 1]",
        ] {
            assert!(!text.contains(secret), "{secret} printed: {text}");
        }
        assert_eq!(text.matches("<hidden>").count(), 4, "{text}");
        assert!(text.contains("GitHub") && text.contains("SHA-1"), "{text}");
    }

    /// The child half of the F-065 test: run with `TMPDIR` set elsewhere.
    #[test]
    #[ignore = "run by f_065_opened_attachments_live_in_the_users_own_temp_folder"]
    fn f_065_child() {
        println!(
            "folder {}",
            crate::open_copies::production_folder().unwrap().display()
        );
    }

    /// F-065 (S-53, MOD-05.12): the opened-attachment folder, which the
    /// start-up clean also reads, is in the per-user temp folder macOS
    /// reports, whatever `TMPDIR` says (`/tmp` or another shared folder is
    /// never used).
    #[test]
    fn f_065_opened_attachments_live_in_the_users_own_temp_folder() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "edit::tests::f_065_child", "--ignored"])
            .args(["--nocapture", "--test-threads=1"])
            .env("TMPDIR", "/nonexistent-tmpdir/")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}{stderr}");
        let own = larsal_platform::macos::user_temp_dir().unwrap();
        let want = format!(
            "folder {}",
            own.join(if cfg!(debug_assertions) {
                "Larsal-debug"
            } else {
                "Larsal"
            })
            .join("open-attachments")
            .display()
        );
        assert!(stdout.contains(&want), "{stdout}");
    }

    /// LD-344: the cleanup child uses the same stored selection as start-up,
    /// with a validated private fixture, never the real user folder.
    #[test]
    #[ignore = "run by f_065_start_up_clean_reads_only_the_users_own_folder"]
    fn f_065_clean_child() {
        let root = std::path::PathBuf::from(std::env::var_os("LARSAL_TEST_INSTANCE_DIR").unwrap());
        let copies = crate::open_copies::OpenCopies::fixture(&root);
        assert_eq!(
            copies.validate().unwrap(),
            std::fs::canonicalize(root).unwrap()
        );
        clean_open_copies(&copies);
    }

    /// LD-344: exercise real cleanup on its private fixture; a canary under
    /// hostile `TMPDIR` stays untouched. The separate path-only child
    /// proves the production resolver still ignores `TMPDIR` (F-065).
    #[test]
    fn f_065_start_up_clean_reads_only_the_users_own_folder() {
        // Keep F-133's in-binary serialization; LD-344 isolates the child too.
        let _folder = crate::test_dir::open_folder_lock();
        let shared = crate::test_dir::TempDir::new("f065-shared");
        let fixture = crate::open_copies::OpenCopies::private();
        let private = fixture
            .folder()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let own_canary = private.join("Larsal/open-attachments/own-demo.txt");
        std::fs::write(&own_canary, b"demo private").unwrap();
        let planted = shared.join("Larsal/open-attachments/planted-demo.txt");
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::write(&planted, b"demo bytes").unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "edit::tests::f_065_clean_child", "--ignored"])
            .arg("--test-threads=1")
            .env("TMPDIR", format!("{}/", shared.display()))
            .env("LARSAL_TEST_INSTANCE_DIR", private.as_os_str())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stderr}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "the child ran"
        );
        assert_eq!(std::fs::read(&planted).unwrap(), b"demo bytes");
        assert!(!own_canary.exists(), "private cleanup ran");
    }

    /// F-133: the start-up clean test waits for the opened-attachment
    /// folder's lock, so its child never wipes another test's copy.
    #[test]
    fn f_133_the_start_up_clean_test_waits_for_the_folder_lock() {
        crate::test_dir::waits_for_open_folder_lock(
            f_065_start_up_clean_reads_only_the_users_own_folder,
        );
    }
}
