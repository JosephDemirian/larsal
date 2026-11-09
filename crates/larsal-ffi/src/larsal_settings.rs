//! Larsal settings (APP-01, story E5-S9): every setting of the inventory with
//! its key, default and range; the two settings files; the screen's OK,
//! reset, import and export; the state Larsal keeps on its own (recent vaults,
//! the vaults to reopen, APP-09.20).
//!
//! Guarantees:
//! - Settings never hold a secret (D-01-6); nothing here logs a value.
//! - Every value read is checked against its definition: a number out of
//!   range is clamped, a value of the wrong type reads as the default
//!   (D-01-5, APP-01.13). Unknown keys are kept on write (D-01-1).
//! - Writes are atomic (temp file, then rename), the files 0600; a folder
//!   Larsal makes is 0700 (D-01-1, AT-I06).
//! - A file over 1 MiB or that is not a JSON object reads as the defaults;
//!   the file is renamed with `.bad` and one notice says so; never a crash.
//! - A store with no files (tests, a `Session::new`, before start-up) lives
//!   in memory only and never touches the disk.
//! - Nothing here sends anything: the update check (S-START-09) is off by
//!   default and has no request until Larsal's release feed exists (D-01-2).

use crate::SettingsFiles;
use crate::generator::{GeneratorOptions, WordCase};
use crate::session::Session;
use larsal_model::json::{self, Map, Value};
use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

/// A settings or import file larger than this is not read (D-01-1).
const MAX_FILE: u64 = 1024 * 1024;
/// The longest text value kept; a longer one reads as the default.
const MAX_TEXT: usize = 4096;
/// The most items of a list or map value.
const MAX_ITEMS: usize = 1000;
/// The export file's marker (D-01-11: Larsal imports only its own format).
const FORMAT: &str = "larsal-settings";
/// The generator's separator limit (D-03-5).
const MAX_SEPARATOR: usize = 64;

/// Where a value lives (APP-01.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// `settings.json`: moved by export and import.
    Portable,
    /// `state.json`: this Mac only ("Mac" in the card).
    Mac,
    /// `state.json`: kept by Larsal on its own, no control (S-STATE).
    State,
}

/// A value's type, range and default.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Flag(bool),
    /// Lowest, highest, default.
    Number(i64, i64, i64),
    Text(&'static str),
    /// The allowed words; the first is the default.
    Choice(&'static [&'static str]),
    /// Texts, newest first.
    List,
    /// Text to text.
    Map,
}

/// One row of APP-01: its id, key, scope and kind.
struct Def {
    id: &'static str,
    key: &'static str,
    scope: Scope,
    kind: Kind,
}

const fn d(id: &'static str, key: &'static str, scope: Scope, kind: Kind) -> Def {
    Def {
        id,
        key,
        scope,
        kind,
    }
}

use Kind::{Choice, Flag, List, Map as Pairs, Number, Text};
use Scope::{Mac as M, Portable as P, State as S};

/// Every setting Larsal stores (APP-01, the Larsal column B or D). Settings the
/// card skips (S) are not here: an old file's value for them is an unknown
/// key, kept but never read. S-START-02 lives in the OS and S-BRW-03 to -08
/// are browser files (INT-01), so neither is in the settings files.
const DEFS: &[Def] = &[
    // General › Startup.
    d("S-START-03", "window.start_minimized", P, Flag(false)),
    d("S-START-04", "window.minimize_after_unlock", P, Flag(false)),
    d("S-START-05", "recent.remember", P, Flag(true)),
    d("S-START-06", "recent.count", P, Number(1, 25, 5)),
    d("S-START-07", "recent.reopen_at_start", P, Flag(true)),
    d("S-START-08", "recent.remember_keys", P, Flag(false)),
    d("S-START-09", "update.check", P, Flag(false)),
    d("S-START-10", "update.include_beta", P, Flag(false)),
    d("S-START-11", "expiry.notice_on_unlock", P, Flag(true)),
    d("S-START-12", "expiry.notice_days", P, Number(0, 90, 3)),
    // General › File management.
    d("S-FILE-01", "save.after_every_change", P, Flag(true)),
    d("S-FILE-02", "save.on_lock", P, Flag(true)),
    d("S-FILE-03", "save.non_data_on_lock", P, Flag(true)),
    d("S-FILE-04", "save.reload_on_change", P, Flag(true)),
    d("S-FILE-05", "backup.enabled", P, Flag(true)),
    d(
        "S-FILE-06",
        "backup.pattern",
        P,
        Text("{FILE_NAME}.old.larsalvault"),
    ),
    d("S-FILE-07", "save.alternative", P, Flag(false)),
    d("S-FILE-08", "save.alternative.mode", M, Number(0, 1, 0)),
    // General › Entry management.
    d("S-ENTRY-01", "entry.autocomplete", P, Flag(true)),
    d("S-ENTRY-02", "entry.confirm_recycle", P, Flag(false)),
    d("S-ENTRY-03", "entry.autogen_password", P, Flag(false)),
    d("S-ENTRY-04", "list.copy_on_double_click", P, Flag(false)),
    d("S-ENTRY-05", "list.url_double_click", P, Number(0, 2, 0)),
    d("S-ENTRY-06", "entry.group_icon", P, Flag(true)),
    d("S-ENTRY-07", "window.minimize_on_open_url", P, Flag(false)),
    d("S-ENTRY-08", "window.hide_on_copy", P, Flag(false)),
    d(
        "S-ENTRY-09",
        "window.hide_on_copy.mode",
        P,
        Choice(&["minimize", "background"]),
    ),
    d("S-ENTRY-10", "icons.download_timeout", P, Number(1, 60, 10)),
    d("S-ENTRY-11", "icons.download", P, Flag(false)),
    // General › User interface.
    d("S-UI-01", "ui.language", P, Choice(&["system", "en"])),
    d("S-UI-04", "ui.font_size", M, Number(-2, 4, 0)),
    // LD-212 (5): on by default, as proven password managers colour them.
    d("S-UI-07", "display.color_passwords", P, Flag(true)),
    d("S-UI-08", "display.monospace_notes", P, Flag(false)),
    d("S-UI-09", "window.close_hides", P, Flag(false)),
    d("S-UI-10", "menubar_icon.show", P, Flag(false)),
    d(
        "S-UI-11",
        "menubar_icon.style",
        P,
        Choice(&["monochrome", "colorful"]),
    ),
    d("S-UI-12", "menubar_icon.minimize_to", P, Flag(false)),
    // General › Auto-Type.
    d("S-AT-01", "autotype.match_title", P, Flag(true)),
    d("S-AT-02", "autotype.match_url", P, Flag(true)),
    d("S-AT-03", "autotype.always_ask", P, Flag(true)),
    d("S-AT-04", "autotype.skip_ask_main_window", P, Flag(false)),
    d("S-AT-05", "autotype.hide_expired", P, Flag(false)),
    d("S-AT-06", "lock.relock_after_autotype", P, Flag(false)),
    d("S-AT-07", "autotype.global_shortcut", P, Text("⌃⌥V")),
    d("S-AT-08", "autotype.retype_seconds", P, Number(0, 60, 15)),
    d(
        "S-AT-09",
        "autotype.start_delay_ms",
        P,
        Number(100, 10_000, 500),
    ),
    d("S-AT-10", "autotype.key_delay_ms", P, Number(0, 500, 25)),
    // Security › Timeouts.
    d("S-TIME-01", "clipboard.clear.enabled", P, Flag(true)),
    d(
        "S-TIME-02",
        "clipboard.clear.seconds",
        P,
        Number(1, 999, 10),
    ),
    d("S-TIME-03", "lock.idle.enabled", P, Flag(true)),
    d("S-TIME-04", "lock.idle.seconds", P, Number(10, 43_200, 300)),
    d("S-TIME-05", "search.clear_when_idle", P, Flag(false)),
    d(
        "S-TIME-06",
        "search.clear_after_minutes",
        P,
        Number(1, 1_440, 5),
    ),
    // Security › Lock options.
    d("S-LOCK-01", "quick_unlock.enabled", M, Flag(true)),
    d("S-LOCK-02", "lock.on_screen_lock", P, Flag(true)),
    d("S-LOCK-03", "lock.on_user_switch", P, Flag(true)),
    d("S-LOCK-04", "lock.on_minimize", P, Flag(false)),
    // Security › Convenience and Privacy.
    d("S-CONV-01", "display.dots_for_empty", P, Flag(false)),
    d(
        "S-CONV-02",
        "display.hide_password_in_editor",
        P,
        Flag(true),
    ),
    d(
        "S-CONV-03",
        "display.hide_password_in_preview",
        P,
        Flag(true),
    ),
    d("S-CONV-04", "display.hide_totp_in_preview", P, Flag(false)),
    d("S-CONV-05", "display.hide_notes", P, Flag(false)),
    d("S-PRIV-01", "icons.use_service", P, Flag(false)),
    // Browser Integration.
    d("S-BRW-01", "browser.enabled", P, Flag(false)),
    d("S-BRW-02", "browser.safari", P, Flag(false)),
    d("S-BRW-09", "browser.notify", P, Flag(true)),
    d("S-BRW-10", "browser.unlock_on_request", P, Flag(true)),
    d("S-BRW-11", "browser.match_scheme", P, Flag(true)),
    d("S-BRW-12", "browser.best_match_only", P, Flag(false)),
    d("S-BRW-13", "browser.allow_expired", P, Flag(false)),
    d("S-BRW-14", "browser.search_all_vaults", P, Flag(false)),
    d("S-BRW-15", "browser.never_ask_access", P, Flag(false)),
    d("S-BRW-16", "browser.never_ask_update", P, Flag(false)),
    d("S-BRW-17", "browser.skip_http_auth_ask", P, Flag(false)),
    d("S-BRW-18", "browser.extra_fields", P, Flag(true)),
    d("S-BRW-19", "browser.passkeys_localhost", P, Flag(false)),
    d("S-BRW-21", "browser.rewrite_manifests", P, Flag(true)),
    d("S-BRW-23", "browser.custom_proxy", P, Flag(false)),
    d("S-BRW-24", "browser.custom_proxy.path", P, Text("")),
    // Shortcuts: only values that differ from the default (APP-01.29).
    d("S-KEYS-01", "shortcuts.custom", P, Pairs),
    // SSH Agent.
    d("S-SSH-01", "ssh.enabled", P, Flag(false)),
    d("S-SSH-02", "ssh.socket_override", M, Text("")),
    d("S-SSH-03", "ssh.sk_provider_override", M, Text("")),
    // Shared groups: the key pair is in the Keychain (D-01-6), only the
    // signer name is here.
    d("S-SHARE-01", "share.import", P, Flag(false)),
    d("S-SHARE-02", "share.export", P, Flag(false)),
    // INT-08.7 (D-INT08-10): success messages hidden by default.
    d("S-SHARE-03", "share.quiet", P, Flag(true)),
    d("S-SHARE-04", "share.identity", P, Text("")),
    // INT-08.31: the approved shares, each `run::Share::approval` (vault
    // id, group id, SHA-256 of mode and resolved path); this Mac only.
    d("S-SHARE-05", "share.approved", S, List),
    // INT-08.34: per share, the head of the last container it wrote
    // (`run::Share::written`, a colon, the head in hex); this Mac only.
    d("S-SHARE-06", "share.written", S, List),
    // View menu (classic in S-VIEW-01 and S-VIEW-02 are skipped, D-01-8).
    d(
        "S-VIEW-01",
        "ui.theme",
        P,
        Choice(&["auto", "light", "dark"]),
    ),
    d("S-VIEW-03", "ui.show_groups", P, Flag(true)),
    d("S-VIEW-04", "ui.show_preview", P, Flag(true)),
    d("S-VIEW-05", "window.always_on_top", M, Flag(false)),
    d("S-VIEW-06", "display.hide_usernames", P, Flag(false)),
    d("S-VIEW-07", "display.hide_passwords", P, Flag(true)),
    // Search field menu.
    d("S-SEARCH-01", "search.limit_to_group", P, Flag(false)),
    d("S-SEARCH-02", "search.enter_to_search", P, Flag(false)),
    // Generator (FEA-02, FEA-03).
    d("S-PWGEN-01", "generator.kind", P, Number(0, 1, 0)),
    d(
        "S-PWGEN-02",
        "generator.password.length",
        P,
        Number(1, 999, 20),
    ),
    d("S-PWGEN-03", "generator.password.lower", P, Flag(true)),
    d("S-PWGEN-04", "generator.password.upper", P, Flag(true)),
    d("S-PWGEN-05", "generator.password.digits", P, Flag(true)),
    d("S-PWGEN-06", "generator.password.special", P, Flag(true)),
    d("S-PWGEN-07", "generator.password.advanced", P, Flag(false)),
    d("S-PWGEN-08", "generator.password.signs", P, Flag(false)),
    d("S-PWGEN-09", "generator.password.brackets", P, Flag(false)),
    d(
        "S-PWGEN-10",
        "generator.password.punctuation",
        P,
        Flag(false),
    ),
    d("S-PWGEN-11", "generator.password.quotes", P, Flag(false)),
    d("S-PWGEN-12", "generator.password.dashes", P, Flag(false)),
    d("S-PWGEN-13", "generator.password.math", P, Flag(false)),
    d("S-PWGEN-14", "generator.password.extended", P, Flag(false)),
    d("S-PWGEN-15", "generator.password.extra", P, Text("")),
    d("S-PWGEN-16", "generator.password.excluded", P, Text("")),
    d(
        "S-PWGEN-17",
        "generator.password.exclude_lookalike",
        P,
        Flag(true),
    ),
    d(
        "S-PWGEN-18",
        "generator.password.every_group",
        P,
        Flag(true),
    ),
    d(
        "S-PWGEN-19",
        "generator.passphrase.words",
        P,
        Number(1, 100, 7),
    ),
    d("S-PWGEN-20", "generator.passphrase.separator", P, Text(" ")),
    d("S-PWGEN-21", "generator.passphrase.word_list", P, Text("")),
    d(
        "S-PWGEN-22",
        "generator.passphrase.case",
        P,
        Number(0, 3, 0),
    ),
    // Dialog flags (S-MSG-02 and -03 are skipped, D-01-8).
    d("S-MSG-01", "msg.no_old_keyfile_warning", P, Flag(false)),
    // State Larsal keeps on its own (all this-Mac).
    d("S-STATE-01", "state.recent", S, List),
    d("S-STATE-02", "state.key_files", S, Pairs),
    d("S-STATE-03", "state.hardware_keys", S, Pairs),
    d("S-STATE-04", "state.last_active", S, Text("")),
    d("S-STATE-05", "state.open_at_quit", S, List),
    d("S-STATE-06", "state.last_folders", S, Pairs),
    d("S-STATE-07", "state.window_frame", S, Text("")),
    d("S-STATE-08", "state.window_layout", S, Text("")),
    d("S-STATE-09", "state.columns", S, Text("")),
    d("S-STATE-10", "state.columns_search", S, Text("")),
    d("S-STATE-11", "state.split_preview", S, Text("")),
    d("S-STATE-12", "state.split_main", S, Text("")),
    d("S-STATE-13", "state.split_groups", S, Text("")),
    d(
        "S-STATE-14",
        "state.autotype_dialog_size",
        S,
        Text("600x250"),
    ),
    d(
        "S-STATE-15",
        "state.autotype_sort_column",
        S,
        Number(0, 100, 0),
    ),
    d(
        "S-STATE-16",
        "state.autotype_sort_order",
        S,
        Choice(&["ascending", "descending"]),
    ),
    d(
        "S-STATE-17",
        "state.update_next_check",
        S,
        Number(0, i64::MAX, 0),
    ),
    // MOD-08.31, LD-70 (F-080): the remembered Yes of command URLs, each
    // `url::remember_key` (vault file, entry id, SHA-256 of the command).
    d("S-STATE-18", "state.command_yes", S, List),
    // Values only in the settings file.
    d("S-CFG-01", "file.default_name", P, Text("")),
    d(
        "S-CFG-02",
        "security.min_master_quality",
        M,
        Number(0, 4, 0),
    ),
];

fn def(key: &str) -> Option<&'static Def> {
    DEFS.iter().find(|d| d.key == key)
}

fn default_of(kind: Kind) -> Value {
    match kind {
        Flag(on) => Value::Bool(on),
        Number(_, _, n) => Value::from(n),
        Text(t) => Value::from(t),
        Choice(words) => Value::from(words.first().copied().unwrap_or_default()),
        List => Value::Array(Vec::new()),
        Pairs => Value::Object(Map::new()),
    }
}

fn short_text(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| s.len() <= MAX_TEXT)
}

/// D-01-5: the value `raw` reads as: clamped to the range, the default for
/// a wrong type or a missing value.
fn effective(def: &Def, raw: Option<&Value>) -> Value {
    let default = default_of(def.kind);
    let Some(raw) = raw else { return default };
    let read = match def.kind {
        Flag(_) => raw.as_bool().map(Value::Bool),
        Number(lo, hi, _) => raw.as_i64().map(|n| Value::from(n.clamp(lo, hi))),
        Text(_) => short_text(raw).map(Value::from),
        Choice(words) => short_text(raw)
            .filter(|s| words.contains(s))
            .map(Value::from),
        List => raw
            .as_array()
            .filter(|a| a.len() <= MAX_ITEMS && a.iter().all(|v| short_text(v).is_some()))
            .map(|a| Value::Array(a.clone())),
        Pairs => raw
            .as_object()
            .filter(|m| {
                m.len() <= MAX_ITEMS
                    && m.iter()
                        .all(|(k, v)| k.len() <= MAX_TEXT && short_text(v).is_some())
            })
            .map(|m| Value::Object(m.clone())),
    };
    read.unwrap_or(default)
}

/// One value as the screen edits it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum LarsalSettingValue {
    /// On or off.
    Flag {
        /// On.
        on: bool,
    },
    /// A whole number.
    Number {
        /// The value.
        value: i64,
    },
    /// A text or one of a setting's words.
    Text {
        /// The value.
        text: String,
    },
}

/// A setting by its key (APP-01's Key column) and its value. No secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LarsalSetting {
    /// The key, for example `clipboard.clear.seconds`.
    pub key: String,
    /// The value.
    pub value: LarsalSettingValue,
}

/// An imported value that lowers protection (APP-01.11, LD-54).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SettingsWeakening {
    /// The setting's id, for example `S-TIME-03`.
    pub id: String,
    /// The value before, as `on`, `off`, a number or a text.
    pub before: String,
    /// The value after the import.
    pub after: String,
}

/// What an import did (APP-01.11).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SettingsImport {
    /// The values were imported. False when `weakened` waits for Apply.
    pub applied: bool,
    /// The settings the import lowers, with their old and new values.
    pub weakened: Vec<SettingsWeakening>,
}

/// Why a settings action did nothing. Each names a file or a key, never a
/// value (no setting is a secret, but a path is shown only as given).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum LarsalSettingsError {
    /// APP-01.12: the settings file cannot be written; nothing was stored.
    NotWritable(String),
    /// APP-01.11: an import file Larsal cannot read or that holds no values.
    NotSettingsFile(String),
    /// A value of the wrong type or out of range; nothing was stored.
    Invalid(String),
    /// APP-01.10: the export file could not be written.
    CannotWrite(String),
}

impl std::fmt::Display for LarsalSettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotWritable(v) => write!(
                f,
                "Larsal cannot save its settings in {v}. Check that this file and its folder can be written."
            ),
            Self::NotSettingsFile(v) => write!(f, "{v} is not a settings file Larsal can use."),
            Self::Invalid(v) => write!(f, "The setting {v} cannot take this value."),
            Self::CannotWrite(v) => write!(f, "Larsal could not write {v}."),
        }
    }
}

impl std::error::Error for LarsalSettingsError {}

/// The two settings files (D-01-1).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Files {
    /// `settings.json`: the portable values.
    portable: PathBuf,
    /// `state.json`: this Mac's values and the state.
    mac: PathBuf,
}

#[derive(Default)]
struct Inner {
    files: Option<Files>,
    portable: Map,
    mac: Map,
    /// The bad-file notice, shown once.
    notice: Option<String>,
}

impl Inner {
    fn raw(&self, def: &Def) -> Option<&Value> {
        match def.scope {
            Scope::Portable => self.portable.get(def.key),
            Scope::Mac | Scope::State => self.mac.get(def.key),
        }
    }

    fn get(&self, key: &str) -> Value {
        def(key).map_or(Value::Null, |d| effective(d, self.raw(d)))
    }

    fn flag(&self, key: &str) -> bool {
        self.get(key).as_bool().unwrap_or(false)
    }

    fn number(&self, key: &str) -> i64 {
        self.get(key).as_i64().unwrap_or(0)
    }

    fn text(&self, key: &str) -> String {
        self.get(key).as_str().unwrap_or_default().to_owned()
    }

    fn list(&self, key: &str) -> Vec<String> {
        self.get(key)
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn set(&mut self, key: &str, value: Value) {
        if let Some(d) = def(key) {
            match d.scope {
                Scope::Portable => self.portable.insert(d.key.to_owned(), value),
                Scope::Mac | Scope::State => self.mac.insert(d.key.to_owned(), value),
            };
        }
    }

    fn remove(&mut self, key: &str) {
        self.portable.remove(key);
        self.mac.remove(key);
    }

    /// The rules OK applies after the screen's edits (APP-01.6 to .8), so a
    /// stored set of values never breaks them.
    fn enforce(&mut self) {
        // APP-01.6: auto-save forces its partners on.
        if self.flag("save.after_every_change") {
            self.set("save.on_lock", Value::Bool(true));
            self.set("save.non_data_on_lock", Value::Bool(true));
        }
        // APP-01.7: forgetting.
        if !self.flag("recent.remember") {
            self.set("recent.reopen_at_start", Value::Bool(false));
            self.set("recent.remember_keys", Value::Bool(false));
            for key in ["state.recent", "state.last_active", "state.last_folders"] {
                self.remove(key);
            }
        }
        if !self.flag("recent.remember_keys") {
            for key in [
                "state.key_files",
                "state.hardware_keys",
                "state.last_folders",
            ] {
                self.remove(key);
            }
        }
        // APP-01.8: minimize after unlock excludes lock on minimize.
        if self.flag("window.minimize_after_unlock") {
            self.set("lock.on_minimize", Value::Bool(false));
        }
    }

    /// Writes both files; a memory-only store writes nothing.
    fn write(&self) -> Result<(), LarsalSettingsError> {
        let Some(files) = &self.files else {
            return Ok(());
        };
        for (path, map) in [(&files.portable, &self.portable), (&files.mac, &self.mac)] {
            // ponytail: two files, two renames; a failure on the second
            // leaves the first written (both hold valid values).
            write_json(path, &Value::Object(map.clone()))
                .map_err(|_| LarsalSettingsError::NotWritable(path.display().to_string()))?;
        }
        Ok(())
    }
}

/// Writes `value` to `path` atomically through larsal-core's safe export
/// write (F-111): an exclusive temp file with a random name in the same
/// folder, 0600 set on the open file, synced, then renamed over the old
/// file; a link at `path` is replaced, never followed. A missing folder is
/// made 0700.
pub(crate) fn write_json(path: &Path, value: &Value) -> std::io::Result<()> {
    let folder = path.parent().unwrap_or_else(|| Path::new("."));
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(folder)?;
    larsal_core::storage::write_export(path, json::to_string_pretty(value).as_bytes())
}

/// What reading one file gave.
enum Loaded {
    Map(Map),
    /// Over 1 MiB or not a JSON object: renamed to `.bad`.
    Bad,
    /// Exists but cannot be read (permissions).
    Unreadable,
}

fn read_json(path: &Path) -> Loaded {
    let mut bytes = Vec::new();
    // F-123: a FIFO or a device at the path is refused, never waited on.
    let read = larsal_platform::macos::open_regular(path).and_then(|f| {
        if f.metadata()?.len() > MAX_FILE {
            return Ok(false);
        }
        f.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
        Ok(true)
    });
    match read {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Map(Map::new()),
        Err(_) => Loaded::Unreadable,
        Ok(fits) => match json::from_slice(&bytes) {
            Ok(Value::Object(map)) if fits => Loaded::Map(map),
            _ => Loaded::Bad,
        },
    }
}

/// Larsal's settings: the values, their files and the bad-file notice. Swift
/// holds the app's one store through [`Session::settings`].
#[derive(Default, uniffi::Object)]
pub struct LarsalSettingsStore {
    inner: Mutex<Inner>,
}

static SHARED: OnceLock<Arc<LarsalSettingsStore>> = OnceLock::new();

/// The app's one store: the shared session's (start-up loads its files).
pub(crate) fn shared() -> Arc<LarsalSettingsStore> {
    SHARED.get_or_init(Arc::default).clone()
}

/// The normal settings folder: `~/Library/Application Support/Larsal`; in a
/// debug build started by a test, a folder inside the test's instance
/// folder, so a test launch never reads or writes the user's settings.
fn normal_folder() -> PathBuf {
    if crate::instance::started_by_test()
        && let Ok(dir) = crate::instance::dir()
    {
        return dir.join("settings");
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join("Library/Application Support/Larsal")
}

/// APP-09.5: F02 and F03 or the normal files; debug builds use their own
/// names (`_debug`), so they never touch release settings.
fn files_for(given: &SettingsFiles) -> Files {
    let suffix = if cfg!(debug_assertions) { "_debug" } else { "" };
    let folder = normal_folder();
    Files {
        portable: given
            .config
            .clone()
            .unwrap_or_else(|| folder.join(format!("settings{suffix}.json"))),
        mac: given
            .local_config
            .clone()
            .unwrap_or_else(|| folder.join(format!("state{suffix}.json"))),
    }
}

/// Start-up (APP-09.1 step 5's files, read by the primary): the shared
/// store reads its files once. A debug launch that hides its window for a
/// snapshot but names no test folder keeps its settings in memory only, so
/// it never writes the user's settings folder.
pub(crate) fn load_at_start(given: &SettingsFiles) {
    if crate::instance::hidden() && !crate::instance::started_by_test() {
        return;
    }
    shared().load(files_for(given));
}

impl LarsalSettingsStore {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The settings folder (the state file's), where APP-02.16 keeps its
    /// `recovery` folder (saving.rs, E5-S10); `None` for a memory-only store.
    pub(crate) fn folder(&self) -> Option<PathBuf> {
        let inner = self.inner();
        inner.files.as_ref()?.mac.parent().map(Path::to_path_buf)
    }

    /// Reads `files` (D-01-1): a missing file is empty; a bad one is
    /// renamed `.bad` and reads as empty, with one notice.
    fn load(&self, files: Files) {
        let mut inner = self.inner();
        let mut notices = Vec::new();
        let mut maps = [Map::new(), Map::new()];
        for (path, map) in [&files.portable, &files.mac].into_iter().zip(&mut maps) {
            match read_json(path) {
                Loaded::Map(m) => *map = m,
                Loaded::Bad => {
                    let mut bad = path.clone().into_os_string();
                    bad.push(".bad");
                    let kept = fs::rename(path, &bad).is_ok();
                    notices.push(notice(path, kept.then(|| PathBuf::from(bad))));
                }
                Loaded::Unreadable => notices.push(notice(path, None)),
            }
        }
        let [portable, mac] = maps;
        inner.portable = portable;
        inner.mac = mac;
        inner.files = Some(files);
        inner.notice = (!notices.is_empty()).then(|| notices.join(" "));
    }

    /// APP-01.3 OK: checks every change, applies the rules, writes the files
    /// and only then keeps the new values (APP-01.12: a failed write keeps
    /// the old ones).
    fn save(&self, changes: &[LarsalSetting]) -> Result<(), LarsalSettingsError> {
        let mut inner = self.inner();
        let mut next = Inner {
            files: inner.files.clone(),
            portable: inner.portable.clone(),
            mac: inner.mac.clone(),
            notice: None,
        };
        for change in changes {
            let value = checked(change)?;
            next.set(&change.key, value);
        }
        next.enforce();
        next.write()?;
        inner.portable = next.portable;
        inner.mac = next.mac;
        Ok(())
    }

    /// APP-01.9: every value back to its default, both scopes, the state
    /// too, except the Browser, SSH and shared-groups pages, which store
    /// again what they show. Keys Larsal does not know are kept (D-01-1).
    fn reset(&self) -> Result<(), LarsalSettingsError> {
        let mut inner = self.inner();
        let keep = |key: &String| {
            def(key).is_none()
                || ["browser.", "ssh.", "share."]
                    .iter()
                    .any(|p| key.starts_with(p))
        };
        let mut next = Inner {
            files: inner.files.clone(),
            portable: inner.portable.clone(),
            mac: inner.mac.clone(),
            notice: None,
        };
        next.portable.retain(|k, _| keep(k));
        next.mac.retain(|k, _| keep(k));
        next.write()?;
        inner.portable = next.portable;
        inner.mac = next.mac;
        Ok(())
    }

    /// Writes one state value now (recent vaults, the vaults open at quit,
    /// the generator); a failed write keeps the value in memory and is not
    /// reported: these are not edits of the screen.
    fn keep(&self, change: impl FnOnce(&mut Inner)) {
        let mut inner = self.inner();
        change(&mut inner);
        let _ = inner.write();
    }

    /// APP-01.14: a vault that has a file was opened.
    pub(crate) fn note_opened(&self, path: &Path) {
        let path = path.to_string_lossy().into_owned();
        self.keep(|inner| {
            if !inner.flag("recent.remember") {
                inner.remove("state.recent");
                return;
            }
            let count = usize::try_from(inner.number("recent.count")).unwrap_or(5);
            let mut list = inner.list("state.recent");
            list.retain(|p| *p != path);
            list.insert(0, path);
            list.truncate(count);
            inner.set("state.recent", Value::from(list));
        });
    }

    /// APP-01.16 (F-080, F-107): at each unlock attempt the vault's entries
    /// in S-STATE-02 and S-STATE-03 go, then come back with the key file
    /// path and the hardware key's `serial:slot` when those were used; only
    /// while S-START-08 is on (nothing is written while it is off).
    pub(crate) fn note_keys(
        &self,
        vault: &Path,
        key_file: Option<String>,
        hardware: Option<String>,
    ) {
        let vault = vault.to_string_lossy().into_owned();
        self.keep(|inner| {
            if !inner.flag("recent.remember_keys") {
                return;
            }
            for (key, value) in [
                ("state.key_files", key_file),
                ("state.hardware_keys", hardware),
            ] {
                let mut map = inner.get(key).as_object().cloned().unwrap_or_default();
                map.remove(&vault);
                if let Some(value) = value.filter(|v| v.len() <= MAX_TEXT)
                    && map.len() < MAX_ITEMS
                {
                    map.insert(vault.clone(), Value::from(value));
                }
                inner.set(key, Value::Object(map));
            }
        });
    }

    /// APP-06.9: the remembered key file path and hardware key `serial:slot`
    /// of the vault at `vault`, while S-START-08 is on.
    pub(crate) fn remembered_keys(&self, vault: &Path) -> (Option<String>, Option<String>) {
        let inner = self.inner();
        if !inner.flag("recent.remember_keys") {
            return (None, None);
        }
        let vault = vault.to_string_lossy();
        let of = |key: &str| {
            inner
                .get(key)
                .get(vault.as_ref())
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        (of("state.key_files"), of("state.hardware_keys"))
    }

    /// MOD-08.31 (LD-70): whether the user said Yes with "Remember my
    /// choice" to this command (`url::remember_key`).
    pub(crate) fn command_remembered(&self, key: &str) -> bool {
        self.inner()
            .list("state.command_yes")
            .iter()
            .any(|k| k == key)
    }

    /// INT-08.31: the approval records of shares (share.rs).
    pub(crate) fn share_approvals(&self) -> Vec<String> {
        self.inner().list("share.approved")
    }

    /// INT-08.31: approves a share (`run::Share::approval`); the oldest go
    /// past 1,000.
    pub(crate) fn approve_share(&self, key: String) {
        self.keep(|inner| {
            let mut list = inner.list("share.approved");
            list.retain(|k| *k != key);
            list.push(key);
            let over = list.len().saturating_sub(MAX_ITEMS);
            list.drain(..over);
            inner.set("share.approved", Value::from(list));
        });
    }

    /// INT-08.34: the head of the last container share `written` wrote
    /// (`run::Share::written`), in hex.
    pub(crate) fn share_written(&self, written: &str) -> Option<String> {
        let start = format!("{written}:");
        self.inner()
            .list("share.written")
            .iter()
            .find_map(|k| k.strip_prefix(&start).map(str::to_owned))
    }

    /// INT-08.34: `head` is the last container share `written` wrote; the
    /// oldest go past 1,000.
    pub(crate) fn note_share_written(&self, written: &str, head: &str) {
        let start = format!("{written}:");
        self.keep(|inner| {
            let mut list = inner.list("share.written");
            list.retain(|k| !k.starts_with(&start));
            list.push(format!("{start}{head}"));
            let over = list.len().saturating_sub(MAX_ITEMS);
            list.drain(..over);
            inner.set("share.written", Value::from(list));
        });
    }

    /// INT-08.31: Clear forgets every record of one share group
    /// (`run::records_of`).
    pub(crate) fn forget_share(&self, records: &str) {
        self.keep(|inner| {
            for key in ["share.approved", "share.written"] {
                let mut list = inner.list(key);
                list.retain(|k| !k.starts_with(records));
                inner.set(key, Value::from(list));
            }
        });
    }

    /// INT-08.34: each remembered key file with its vault (APP-01.16), open
    /// or not.
    pub(crate) fn remembered_key_files(&self) -> Vec<(String, String)> {
        let inner = self.inner();
        let files = inner.get("state.key_files");
        files.as_object().map_or_else(Vec::new, |map| {
            map.iter()
                .filter_map(|(vault, typed)| Some((vault.clone(), typed.as_str()?.to_owned())))
                .collect()
        })
    }

    /// INT-08.7: import allowed, export allowed, quiet success.
    pub(crate) fn share_flags(&self) -> (bool, bool, bool) {
        let inner = self.inner();
        (
            inner.flag("share.import"),
            inner.flag("share.export"),
            inner.flag("share.quiet"),
        )
    }

    /// MOD-08.31 (LD-70): remembers a Yes; the oldest go past 1,000.
    pub(crate) fn remember_command(&self, key: String) {
        if key.len() > MAX_TEXT {
            return;
        }
        self.keep(|inner| {
            let mut list = inner.list("state.command_yes");
            list.retain(|k| *k != key);
            list.push(key);
            let over = list.len().saturating_sub(MAX_ITEMS);
            list.drain(..over);
            inner.set("state.command_yes", Value::from(list));
        });
    }

    /// APP-01.17, APP-09.20: the vaults to open at start, in the saved
    /// order, then the one shown last, so it becomes the shown one. Files
    /// that no longer exist are left out.
    pub(crate) fn reopen(&self) -> Vec<PathBuf> {
        let inner = self.inner();
        if !inner.flag("recent.reopen_at_start") {
            return Vec::new();
        }
        let mut paths = inner.list("state.open_at_quit");
        let shown = inner.text("state.last_active");
        if !shown.is_empty() {
            paths.push(shown);
        }
        paths
            .into_iter()
            .map(PathBuf::from)
            .filter(|p| p.is_file())
            .collect()
    }

    /// APP-01.17 at quit: the open vaults in tab order and the shown one,
    /// or both deleted when reopening is off.
    fn remember_open(&self, open: Vec<PathBuf>, shown: Option<PathBuf>) {
        self.keep(|inner| {
            if !inner.flag("recent.reopen_at_start") {
                inner.remove("state.open_at_quit");
                inner.remove("state.last_active");
                return;
            }
            let text = |p: PathBuf| Value::from(p.to_string_lossy().into_owned());
            inner.set(
                "state.open_at_quit",
                Value::Array(open.into_iter().map(text).collect()),
            );
            match shown {
                Some(p) => inner.set("state.last_active", text(p)),
                None => inner.remove("state.last_active"),
            }
        });
    }

    /// APP-03 with S-TIME-01 and S-TIME-02: seconds until Larsal clears its
    /// copy, `None` when clearing is off.
    pub(crate) fn clipboard_clear(&self) -> Option<u32> {
        let inner = self.inner();
        inner
            .flag("clipboard.clear.enabled")
            .then(|| u32::try_from(inner.number("clipboard.clear.seconds")).unwrap_or(10))
    }

    /// FEA-02.18, LD-204: the stored generator options (S-PWGEN), the
    /// defaults where a stored one is not valid.
    pub(crate) fn generator(&self) -> GeneratorOptions {
        let i = self.inner();
        let count = |key: &str| u32::try_from(i.number(key)).unwrap_or(1);
        let separator = i.text("generator.passphrase.separator");
        GeneratorOptions {
            passphrase: i.number("generator.kind") == 1,
            length: count("generator.password.length"),
            upper: i.flag("generator.password.upper"),
            lower: i.flag("generator.password.lower"),
            digits: i.flag("generator.password.digits"),
            special: i.flag("generator.password.special"),
            extended: i.flag("generator.password.extended"),
            exclude_lookalike: i.flag("generator.password.exclude_lookalike"),
            every_group: i.flag("generator.password.every_group"),
            words: count("generator.passphrase.words"),
            separator: if separator.chars().count() > MAX_SEPARATOR {
                " ".to_owned()
            } else {
                separator
            },
            case: match i.number("generator.passphrase.case") {
                1 => WordCase::Upper,
                2 => WordCase::Title,
                3 => WordCase::Mixed,
                _ => WordCase::Lower,
            },
        }
    }

    /// Stores the generator's options (FEA-02.18: on Apply and when the
    /// window's generator closes).
    pub(crate) fn store_generator(&self, o: &GeneratorOptions) {
        self.keep(|i| {
            let case = match o.case {
                WordCase::Lower => 0,
                WordCase::Upper => 1,
                WordCase::Title => 2,
                WordCase::Mixed => 3,
            };
            let values = [
                ("generator.kind", Value::from(i64::from(o.passphrase))),
                ("generator.password.length", Value::from(o.length)),
                ("generator.password.upper", Value::Bool(o.upper)),
                ("generator.password.lower", Value::Bool(o.lower)),
                ("generator.password.digits", Value::Bool(o.digits)),
                ("generator.password.special", Value::Bool(o.special)),
                ("generator.password.extended", Value::Bool(o.extended)),
                (
                    "generator.password.exclude_lookalike",
                    Value::Bool(o.exclude_lookalike),
                ),
                ("generator.password.every_group", Value::Bool(o.every_group)),
                ("generator.passphrase.words", Value::from(o.words)),
                (
                    "generator.passphrase.separator",
                    Value::from(o.separator.clone()),
                ),
                ("generator.passphrase.case", Value::from(case)),
            ];
            for (key, value) in values {
                if let Some(d) = def(key) {
                    let value = effective(d, Some(&value));
                    i.set(key, value);
                }
            }
        });
    }

    /// S-SSH-01 to S-SSH-03 as `set_ssh_agent` takes them.
    fn ssh(&self) -> (bool, String, String) {
        let i = self.inner();
        (
            i.flag("ssh.enabled"),
            i.text("ssh.socket_override"),
            i.text("ssh.sk_provider_override"),
        )
    }

    /// Reads an import file (D-01-11): Larsal's own export format, at most
    /// 1 MiB, with at least one value.
    fn import_map(path: &Path) -> Result<Map, LarsalSettingsError> {
        let refuse = || LarsalSettingsError::NotSettingsFile(path.display().to_string());
        let Loaded::Map(file) = read_json_keep(path) else {
            return Err(refuse());
        };
        let marked = file.get("format").and_then(Value::as_str) == Some(FORMAT)
            && file.get("version").and_then(Value::as_i64) == Some(1);
        match file.get("settings") {
            Some(Value::Object(values)) if marked && !values.is_empty() => Ok(values.clone()),
            _ => Err(refuse()),
        }
    }
}

/// [`read_json`] without renaming anything: an import file is the user's.
fn read_json_keep(path: &Path) -> Loaded {
    let Ok(meta) = fs::metadata(path) else {
        return Loaded::Unreadable;
    };
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Loaded::Bad;
    }
    match fs::read(path).map(|b| json::from_slice(&b)) {
        Ok(Ok(Value::Object(map))) => Loaded::Map(map),
        Ok(_) => Loaded::Bad,
        Err(_) => Loaded::Unreadable,
    }
}

/// The bad-file notice (D-01-1), Larsal's own words; it names the file.
fn notice(path: &Path, kept: Option<PathBuf>) -> String {
    let mut text = format!(
        "Larsal could not read its settings file {}, so it uses the default settings.",
        path.display()
    );
    if let Some(kept) = kept {
        text.push_str(&format!(" The old file was kept as {}.", kept.display()));
    }
    text
}

/// A change from the screen, checked against its definition; settings Larsal
/// keeps on its own (S-STATE) are not the screen's.
fn checked(change: &LarsalSetting) -> Result<Value, LarsalSettingsError> {
    let invalid = || LarsalSettingsError::Invalid(change.key.clone());
    let d = def(&change.key)
        .filter(|d| d.scope != Scope::State)
        .ok_or_else(invalid)?;
    match (&d.kind, &change.value) {
        (Flag(_), LarsalSettingValue::Flag { on }) => Ok(Value::Bool(*on)),
        (Number(lo, hi, _), LarsalSettingValue::Number { value }) if (lo..=hi).contains(&value) => {
            Ok(Value::from(*value))
        }
        (Text(_), LarsalSettingValue::Text { text }) if text.len() <= MAX_TEXT => {
            Ok(Value::from(text.clone()))
        }
        (Choice(words), LarsalSettingValue::Text { text }) if words.contains(&text.as_str()) => {
            Ok(Value::from(text.clone()))
        }
        _ => Err(invalid()),
    }
}

/// A value as the weakening list shows it.
fn shown(v: &Value) -> String {
    match v {
        Value::Bool(true) => "on".to_owned(),
        Value::Bool(false) => "off".to_owned(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// APP-01.11 with LD-54 and LD-200 (3): the settings an import lowers.
fn weakened(before: &Inner, after: &Inner) -> Vec<SettingsWeakening> {
    let off = [
        "S-TIME-01",
        "S-TIME-03",
        "S-LOCK-02",
        "S-LOCK-03",
        "S-CONV-02",
        "S-CONV-03",
        "S-VIEW-07",
        "S-AT-03",
        "S-LOCK-04",
    ];
    let on = [
        "S-ENTRY-04",
        "S-START-08",
        "S-FILE-07",
        "S-BRW-15",
        "S-BRW-16",
        "S-BRW-17",
        "S-BRW-19",
        // A network feature turned on (LD-208 (1)).
        "S-START-09",
        "S-START-10",
        "S-PRIV-01",
        "S-ENTRY-11",
    ];
    let longer = ["S-TIME-02", "S-TIME-04"];
    let mut list = Vec::new();
    for d in DEFS {
        let (old, new) = (effective(d, before.raw(d)), effective(d, after.raw(d)));
        let id = d.id;
        let lowers = (off.contains(&id) && old == Value::Bool(true) && new == Value::Bool(false))
            || (on.contains(&id) && old == Value::Bool(false) && new == Value::Bool(true))
            || (longer.contains(&id) && new.as_i64() > old.as_i64())
            || (id == "S-FILE-08" && old != new && new.as_i64() == Some(1))
            || (id == "S-BRW-23" && old == Value::Bool(false) && new == Value::Bool(true))
            // An imported bridge path is never written into a manifest
            // without asking (INT-01.9).
            || (id == "S-BRW-24" && old != new && after.flag("browser.custom_proxy"));
        if lowers {
            list.push(SettingsWeakening {
                id: id.to_owned(),
                before: shown(&old),
                after: shown(&new),
            });
        }
    }
    list
}

#[uniffi::export]
impl LarsalSettingsStore {
    /// Tests and Mac QA: reads the settings of `folder` (`settings.json`
    /// and `state.json`) and writes there from now on; a throwaway folder,
    /// never the user's.
    pub fn use_folder(&self, folder: String) {
        let folder = PathBuf::from(folder);
        self.load(Files {
            portable: folder.join("settings.json"),
            mac: folder.join("state.json"),
        });
    }

    /// Every setting the screen shows or the app reads, with its effective
    /// value (D-01-5). The state Larsal keeps on its own is not listed.
    #[must_use]
    pub fn values(&self) -> Vec<LarsalSetting> {
        let inner = self.inner();
        DEFS.iter()
            .filter(|d| d.scope != Scope::State)
            .filter_map(|d| {
                let value = match effective(d, inner.raw(d)) {
                    Value::Bool(on) => LarsalSettingValue::Flag { on },
                    Value::Number(n) => LarsalSettingValue::Number { value: n.as_i64()? },
                    Value::String(text) => LarsalSettingValue::Text { text },
                    _ => return None,
                };
                Some(LarsalSetting {
                    key: d.key.to_owned(),
                    value,
                })
            })
            .collect()
    }

    /// The effective on/off value of `key`; false for an unknown key.
    #[must_use]
    pub fn flag(&self, key: String) -> bool {
        self.inner().flag(&key)
    }

    /// The effective number of `key`; 0 for an unknown key.
    #[must_use]
    pub fn number(&self, key: String) -> i64 {
        self.inner().number(&key)
    }

    /// The effective text of `key`; empty for an unknown key.
    #[must_use]
    pub fn text(&self, key: String) -> String {
        self.inner().text(&key)
    }

    /// The default of `key` (APP-01.2); `None` for an unknown key or one
    /// Larsal keeps on its own.
    #[must_use]
    pub fn default_value(&self, key: String) -> Option<LarsalSettingValue> {
        let d = def(&key).filter(|d| d.scope != Scope::State)?;
        Some(match default_of(d.kind) {
            Value::Bool(on) => LarsalSettingValue::Flag { on },
            Value::Number(n) => LarsalSettingValue::Number { value: n.as_i64()? },
            Value::String(text) => LarsalSettingValue::Text { text },
            _ => return None,
        })
    }

    /// APP-01.12: the error naming the settings file when it cannot be
    /// written now; `None` when it can, and for a memory-only store.
    #[must_use]
    pub fn check_writable(&self) -> Option<String> {
        let files = self.inner().files.clone()?;
        for path in [&files.portable, &files.mac] {
            let folder = path.parent().unwrap_or_else(|| Path::new("."));
            // F-123: the folder takes a new file (storage's probe: a fresh
            // random name made with create_new, so a planted link is never
            // followed) and the file, when there, has a write bit and is a
            // regular file, checked without an open that waits on a FIFO.
            let ok = DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(folder)
                .is_ok()
                && larsal_core::storage::is_writable(path)
                && (!path.exists() || larsal_platform::macos::open_regular(path).is_ok());
            if !ok {
                return Some(
                    LarsalSettingsError::NotWritable(path.display().to_string()).to_string(),
                );
            }
        }
        None
    }

    /// The notice of a settings file that could not be read at start, once.
    #[must_use]
    pub fn take_notice(&self) -> Option<String> {
        self.inner().notice.take()
    }

    /// S-STATE-01: the recent vaults, newest first (APP-01.14).
    #[must_use]
    pub fn recent_vaults(&self) -> Vec<String> {
        self.inner().list("state.recent")
    }

    /// APP-01.10: writes every stored portable value to `path` in Larsal's
    /// export format. Never a secret: no setting holds one (D-01-6).
    ///
    /// # Errors
    /// `CannotWrite` naming the file.
    pub fn export_to(&self, path: String) -> Result<(), LarsalSettingsError> {
        let inner = self.inner();
        let values: Map = DEFS
            .iter()
            .filter(|d| d.scope == Scope::Portable)
            .filter_map(|d| {
                let raw = inner.portable.get(d.key)?;
                Some((d.key.to_owned(), effective(d, Some(raw))))
            })
            .collect();
        let mut file = Map::new();
        file.insert("format".to_owned(), Value::from(FORMAT));
        file.insert("version".to_owned(), Value::from(1));
        file.insert("settings".to_owned(), Value::Object(values));
        write_json(Path::new(&path), &Value::Object(file))
            .map_err(|_| LarsalSettingsError::CannotWrite(path))
    }
}

#[uniffi::export]
impl Session {
    /// The settings this session uses: the app's one store for
    /// [`Session::shared`], a memory-only one for [`Session::new`].
    #[must_use]
    pub fn settings(&self) -> Arc<LarsalSettingsStore> {
        Arc::clone(&self.settings)
    }

    /// APP-01.3 OK: stores every change (APP-01.6 to .8 applied), then the
    /// parts that use them take them at once; the SSH agent through
    /// `set_ssh_agent` (APP-01.31). The clipboard and the generator read
    /// the store at each use; Swift restarts the lock timers.
    ///
    /// # Errors
    /// `NotWritable` naming the file (APP-01.12) or `Invalid`; nothing is
    /// stored then.
    pub fn save_settings(&self, changes: Vec<LarsalSetting>) -> Result<(), LarsalSettingsError> {
        let before = self.settings.ssh();
        let shares = self.settings.share_flags();
        self.settings.save(&changes)?;
        self.apply_ssh(&before);
        self.share_flags_changed(shares);
        Ok(())
    }

    /// APP-01.9 Reset to defaults, after the user confirmed; launch at
    /// login is the OS's and not touched.
    ///
    /// # Errors
    /// `NotWritable`; nothing changes then.
    pub fn reset_settings(&self) -> Result<(), LarsalSettingsError> {
        let before = self.settings.ssh();
        let shares = self.settings.share_flags();
        self.settings.reset()?;
        self.apply_ssh(&before);
        self.share_flags_changed(shares);
        Ok(())
    }

    /// APP-01.11 Import of `path`. With `apply` false an import that
    /// lowers protection changes nothing and returns the list for the
    /// question (Apply or Cancel, Cancel the default); with `apply` true, or
    /// when nothing is lowered, the portable values are replaced by the
    /// file's known ones (unknown names and this-Mac values ignored).
    ///
    /// # Errors
    /// `NotSettingsFile` naming the file; `NotWritable`.
    pub fn import_settings(
        &self,
        path: String,
        apply: bool,
    ) -> Result<SettingsImport, LarsalSettingsError> {
        let values = LarsalSettingsStore::import_map(Path::new(&path))?;
        let before_ssh = self.settings.ssh();
        let shares = self.settings.share_flags();
        let store = &self.settings;
        {
            let mut inner = store.inner();
            let mut next = Inner {
                files: inner.files.clone(),
                portable: Map::new(),
                mac: inner.mac.clone(),
                notice: None,
            };
            for d in DEFS.iter().filter(|d| d.scope == Scope::Portable) {
                if let Some(raw) = values.get(d.key) {
                    next.portable
                        .insert(d.key.to_owned(), effective(d, Some(raw)));
                }
            }
            next.enforce();
            let weakened = weakened(&inner, &next);
            if !apply && !weakened.is_empty() {
                return Ok(SettingsImport {
                    applied: false,
                    weakened,
                });
            }
            next.write()?;
            inner.portable = next.portable;
            inner.mac = next.mac;
        }
        self.apply_ssh(&before_ssh);
        self.share_flags_changed(shares);
        Ok(SettingsImport {
            applied: true,
            weakened: Vec::new(),
        })
    }

    /// APP-01.17 at quit, before the vaults lock: the open vaults in tab
    /// order and the shown one are kept for APP-09.20.
    pub fn remember_open_vaults(&self) {
        let (open, shown) = self.open_paths();
        self.settings.remember_open(open, shown);
    }
}

impl Session {
    /// S-SSH-01 to -03 changed: Larsal's agent follows (APP-01.31, INT-06.38).
    fn apply_ssh(&self, before: &(bool, String, String)) {
        let now = self.settings.ssh();
        if now != *before {
            let (on, socket, provider) = now;
            // The store's texts are at most 4 KiB: never `TooLong` here.
            let _ = self.set_ssh_agent(on, socket, provider);
        }
    }
}

/// Start-up (APP-09.1): turns Larsal's SSH agent on when S-SSH-01 is stored
/// on (INT-06.21: off by default, no agent contacted then).
pub(crate) fn start_ssh(session: &Session) {
    let (on, socket, provider) = session.settings.ssh();
    if on {
        let _ = session.set_ssh_agent(true, socket, provider);
    }
}

/// The SSH page's status row (APP-01.31): the socket in use and whether
/// the agent answers a key listing, or the agent's error in INT-06's words.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshAgentStatus {
    /// S-SSH-02 when set, else `SSH_AUTH_SOCK`; empty when neither is.
    pub socket: String,
    /// The agent listed its keys.
    pub connected: bool,
    /// MI06-01 when there is no socket, else the agent's error.
    pub message: Option<String>,
}

/// APP-01.31: asks the agent at S-SSH-02 (or `SSH_AUTH_SOCK`) for its keys.
/// Contacts the user's agent: the window calls it only while S-SSH-01 is on,
/// off the main thread; tests never call it.
#[uniffi::export]
#[must_use]
pub fn ssh_agent_status(socket_override: String) -> SshAgentStatus {
    ssh_status(
        &socket_override,
        std::env::var_os("SSH_AUTH_SOCK").as_deref(),
    )
}

fn ssh_status(socket_override: &str, auth_sock: Option<&OsStr>) -> SshAgentStatus {
    let names = larsal_sshagent::messages::Names {
        title: "",
        name: "",
        file: "",
    };
    match larsal_sshagent::Agent::choose(socket_override, auth_sock) {
        Err(e) => SshAgentStatus {
            socket: String::new(),
            connected: false,
            message: Some(e.message(&names)),
        },
        Ok(agent) => {
            let socket = agent.path().display().to_string();
            match agent.list() {
                Ok(_) => SshAgentStatus {
                    socket,
                    connected: true,
                    message: None,
                },
                Err(e) => SshAgentStatus {
                    socket,
                    connected: false,
                    message: Some(e.message(&names)),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A throwaway folder in the temp folder, removed when the test ends.
    struct Tmp(PathBuf);

    impl std::ops::Deref for Tmp {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<Path> for Tmp {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn folder(name: &str) -> Tmp {
        let dir = std::env::temp_dir().join(format!("larsal-e5s9-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Tmp(dir)
    }

    fn store(dir: &Path) -> LarsalSettingsStore {
        let s = LarsalSettingsStore::default();
        s.use_folder(dir.display().to_string());
        s
    }

    fn flag(key: &str, on: bool) -> LarsalSetting {
        LarsalSetting {
            key: key.to_owned(),
            value: LarsalSettingValue::Flag { on },
        }
    }

    fn number(key: &str, value: i64) -> LarsalSetting {
        LarsalSetting {
            key: key.to_owned(),
            value: LarsalSettingValue::Number { value },
        }
    }

    fn file(dir: &Path, name: &str) -> Value {
        json::from_slice(&fs::read(dir.join(name)).unwrap()).unwrap()
    }

    #[test]
    fn app01_1_empty_folder_reads_defaults_and_writes_nothing() {
        let dir = folder("a1");
        let s = store(&dir);
        assert_eq!(s.number("clipboard.clear.seconds".into()), 10);
        assert_eq!(s.number("recent.count".into()), 5);
        assert!(!dir.exists(), "no settings file has been created yet");
    }

    #[test]
    fn app01_2_app_defaults() {
        let s = LarsalSettingsStore::default();
        assert_eq!(s.number("lock.idle.seconds".into()), 300);
        assert!(!s.flag("recent.remember_keys".into()));
        assert!(!s.flag("update.check".into()));
        assert!(!s.flag("update.include_beta".into()));
        assert!(s.flag("backup.enabled".into()));
        assert_eq!(
            s.text("backup.pattern".into()),
            "{FILE_NAME}.old.larsalvault"
        );
        assert!(!s.flag("icons.download".into()));
        assert_eq!(s.text("ui.language".into()), "system");
    }

    #[test]
    fn app01_every_id_has_a_unique_key() {
        let mut keys: Vec<&str> = DEFS.iter().map(|d| d.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), DEFS.len());
        let mut ids: Vec<&str> = DEFS.iter().map(|d| d.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), DEFS.len());
    }

    #[test]
    fn app01_3_ok_stores_and_cancel_is_no_call() {
        let dir = folder("a3");
        let s = store(&dir);
        s.save(&[
            number("clipboard.clear.seconds", 30),
            number("lock.idle.seconds", 600),
        ])
        .unwrap();
        assert_eq!(s.clipboard_clear(), Some(30));
        assert_eq!(file(&dir, "settings.json")["lock.idle.seconds"], 600);
        // A second store reads what OK wrote (read once at start).
        assert_eq!(store(&dir).number("lock.idle.seconds".into()), 600);
    }

    #[test]
    fn d01_1_files_are_owner_only_atomic_and_keep_unknown_keys() {
        let dir = folder("d1");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("settings.json"),
            br#"{"X-99": 7, "ui.theme": "dark"}"#,
        )
        .unwrap();
        let s = store(&dir);
        assert_eq!(s.text("ui.theme".into()), "dark");
        s.save(&[flag("display.hide_notes", true)]).unwrap();
        let saved = file(&dir, "settings.json");
        assert_eq!(saved["X-99"], 7, "unknown keys are kept on write");
        assert_eq!(saved["display.hide_notes"], true);
        let mode = fs::metadata(dir.join("settings.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!dir.join(".settings.json.tmp").exists());
        let fresh = folder("d1-new");
        store(&fresh)
            .save(&[flag("display.hide_notes", true)])
            .unwrap();
        let mode = fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "a folder Larsal makes is 0700");
    }

    #[test]
    fn d01_1_bad_file_reads_defaults_renamed_bad_one_notice() {
        let dir = folder("bad");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("settings.json"), b"{ not json").unwrap();
        // Valid JSON over 1 MiB: refused for its size alone.
        let big = format!(r#"{{"ui.font_size":3,"x":"{}"}}"#, "a".repeat(1_048_577));
        fs::write(dir.join("state.json"), &big).unwrap();
        let s = store(&dir);
        assert_eq!(s.number("clipboard.clear.seconds".into()), 10);
        assert_eq!(s.number("ui.font_size".into()), 0, "the default");
        assert!(dir.join("settings.json.bad").exists());
        assert!(dir.join("state.json.bad").exists());
        let notice = s.take_notice().unwrap();
        assert!(notice.contains("settings.json"), "{notice}");
        assert_eq!(s.take_notice(), None, "one notice");
        // D-01-11: an import over 1 MiB is refused too, however valid.
        let session = session_in(&dir);
        let path = import_file(
            &dir,
            &format!(
                r#"{{"clipboard.clear.seconds":45,"x":"{}"}}"#,
                "a".repeat(1_048_577)
            ),
        );
        let refused = session.import_settings(path.clone(), true);
        assert_eq!(refused, Err(LarsalSettingsError::NotSettingsFile(path)));
        assert_eq!(session.settings().clipboard_clear(), Some(10));
    }

    #[test]
    fn app01_12_not_writable_names_the_file_and_stores_nothing() {
        let dir = folder("a12");
        let s = store(&dir);
        s.save(&[number("clipboard.clear.seconds", 20)]).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let error = s.check_writable().unwrap();
        assert!(error.contains(&dir.display().to_string()), "{error}");
        let failed = s.save(&[number("clipboard.clear.seconds", 30)]);
        assert!(matches!(failed, Err(LarsalSettingsError::NotWritable(_))));
        assert_eq!(s.clipboard_clear(), Some(20), "unchanged");
        assert!(matches!(
            s.reset(),
            Err(LarsalSettingsError::NotWritable(_))
        ));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(s.check_writable(), None);
    }

    /// F-123 (LD-228 (3)): a link planted at the old fixed probe name is
    /// never followed (the demo file keeps its text, the link stays), and a
    /// FIFO at the settings file is refused at once, at load and at the
    /// check, which names the file.
    #[test]
    fn f_123_check_writable_follows_no_planted_link_or_fifo() {
        let dir = folder("f123");
        fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.txt");
        fs::write(&victim, "victim, demo text").unwrap();
        let link = dir.join(".larsal-settings-check");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert_eq!(store(&dir).check_writable(), None);
        assert_eq!(fs::read_to_string(&victim).unwrap(), "victim, demo text");
        assert!(fs::symlink_metadata(&link).is_ok(), "the link is left");
        let fifo = dir.join("settings.json");
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let (tx, rx) = std::sync::mpsc::channel();
        let at = dir.to_path_buf();
        std::thread::spawn(move || {
            let s = store(&at);
            let _ = tx.send(s.check_writable());
        });
        let error = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("answered at once")
            .unwrap();
        assert!(error.contains("settings.json"), "{error}");
    }

    #[test]
    fn app01_13_bad_values_clamp_or_read_the_default() {
        let dir = folder("a13");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("settings.json"),
            br#"{"clipboard.clear.seconds": 0, "lock.idle.seconds": "abc", "ui.theme": "classic", "recent.count": 99, "lock.idle.enabled": "yes", "display.hide_usernames": 1}"#,
        )
        .unwrap();
        fs::write(dir.join("state.json"), br#"{"ui.font_size": 7}"#).unwrap();
        let s = store(&dir);
        assert_eq!(s.number("clipboard.clear.seconds".into()), 1);
        assert_eq!(s.number("lock.idle.seconds".into()), 300);
        assert_eq!(s.text("ui.theme".into()), "auto");
        assert_eq!(s.number("recent.count".into()), 25);
        assert_eq!(s.number("ui.font_size".into()), 4);
        // D-01-5: a flag of the wrong type reads as its default, either way.
        assert!(s.flag("lock.idle.enabled".into()));
        assert!(!s.flag("display.hide_usernames".into()));
    }

    #[test]
    fn app01_screen_values_are_checked() {
        let s = LarsalSettingsStore::default();
        for bad in [
            number("clipboard.clear.seconds", 1000),
            flag("clipboard.clear.seconds", true),
            flag("no.such.key", true),
            LarsalSetting {
                key: "ui.theme".into(),
                value: LarsalSettingValue::Text {
                    text: "classic".into(),
                },
            },
            LarsalSetting {
                key: "state.last_active".into(),
                value: LarsalSettingValue::Text { text: "/x".into() },
            },
        ] {
            assert!(matches!(
                s.save(&[bad]),
                Err(LarsalSettingsError::Invalid(_))
            ));
        }
    }

    #[test]
    fn app01_6_autosave_forces_its_partners() {
        let s = LarsalSettingsStore::default();
        s.save(&[
            flag("save.after_every_change", true),
            flag("save.on_lock", false),
            flag("save.non_data_on_lock", false),
        ])
        .unwrap();
        assert!(s.flag("save.on_lock".into()) && s.flag("save.non_data_on_lock".into()));
        s.save(&[
            flag("save.after_every_change", false),
            flag("save.on_lock", false),
        ])
        .unwrap();
        assert!(!s.flag("save.on_lock".into()));
    }

    #[test]
    fn app01_7_forgetting() {
        let dir = folder("a7");
        let s = store(&dir);
        s.save(&[flag("recent.remember_keys", true)]).unwrap();
        s.keep(|i| {
            i.set(
                "state.recent",
                Value::from(vec!["/tmp/spec-app01/a.larsalvault"]),
            );
            let mut keys = Map::new();
            keys.insert(
                "/tmp/spec-app01/a.larsalvault".into(),
                "/tmp/spec-app01/a.larsalkey".into(),
            );
            i.set("state.key_files", Value::Object(keys));
            let mut roles = Map::new();
            roles.insert("vault".into(), "/tmp/spec-app01".into());
            i.set("state.last_folders", Value::Object(roles));
        });
        // b: only S-START-08 off: key files and folders go, the list stays.
        s.save(&[flag("recent.remember_keys", false)]).unwrap();
        assert_eq!(s.recent_vaults().len(), 1);
        let state = file(&dir, "state.json");
        assert!(
            state.get("state.key_files").is_none() && state.get("state.last_folders").is_none()
        );
        // a: S-START-05 off switches -07 and -08 off and forgets the list.
        s.save(&[flag("recent.remember", false)]).unwrap();
        assert!(!s.flag("recent.reopen_at_start".into()));
        assert!(!s.flag("recent.remember_keys".into()));
        assert!(s.recent_vaults().is_empty());
    }

    #[test]
    fn app01_8_minimize_after_unlock_stores_lock_on_minimize_off() {
        let s = LarsalSettingsStore::default();
        s.save(&[flag("lock.on_minimize", true)]).unwrap();
        s.save(&[flag("window.minimize_after_unlock", true)])
            .unwrap();
        assert!(!s.flag("lock.on_minimize".into()));
    }

    #[test]
    fn app01_9_reset_keeps_browser_ssh_and_share() {
        let dir = folder("a9");
        let s = store(&dir);
        s.save(&[
            number("clipboard.clear.seconds", 30),
            flag("display.hide_passwords", false),
            flag("browser.enabled", true),
            flag("ssh.enabled", true),
            flag("share.import", true),
        ])
        .unwrap();
        s.keep(|i| i.set("state.recent", Value::from(vec!["/a", "/b"])));
        s.reset().unwrap();
        assert_eq!(s.clipboard_clear(), Some(10));
        assert!(s.flag("display.hide_passwords".into()));
        assert!(s.recent_vaults().is_empty());
        assert!(s.flag("browser.enabled".into()) && s.flag("share.import".into()));
        assert!(s.flag("ssh.enabled".into()));
        assert_eq!(file(&dir, "settings.json")["browser.enabled"], true);
    }

    #[test]
    fn app01_10_export_holds_portable_values_only() {
        let dir = folder("a10");
        let s = store(&dir);
        s.save(&[
            number("clipboard.clear.seconds", 30),
            LarsalSetting {
                key: "ssh.socket_override".into(),
                value: LarsalSettingValue::Text {
                    text: "/tmp/x.sock".into(),
                },
            },
        ])
        .unwrap();
        s.note_opened(Path::new("/tmp/spec-app01/a.larsalvault"));
        let out = dir.join("out.json");
        s.export_to(out.display().to_string()).unwrap();
        let text = fs::read_to_string(&out).unwrap();
        let exported: Value = json::from_str(&text).unwrap();
        assert_eq!(exported["settings"]["clipboard.clear.seconds"], 30);
        assert!(!text.contains("state.") && !text.contains("/tmp/x.sock"));
    }

    fn import_file(dir: &Path, settings: &str) -> String {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join("in.json");
        fs::write(
            &path,
            format!(r#"{{"format":"larsal-settings","version":1,"settings":{settings}}}"#),
        )
        .unwrap();
        path.display().to_string()
    }

    fn session_in(dir: &Path) -> Arc<Session> {
        let s = Session::new();
        s.settings().use_folder(dir.display().to_string());
        s
    }

    #[test]
    fn app01_11_a_empty_or_foreign_file_is_refused() {
        let dir = folder("a11a");
        let s = session_in(&dir);
        fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty.json");
        fs::write(&empty, b"").unwrap();
        let none = import_file(&dir, "{}");
        for path in [empty.display().to_string(), none] {
            let refused = s.import_settings(path.clone(), true);
            assert_eq!(refused, Err(LarsalSettingsError::NotSettingsFile(path)));
        }
    }

    #[test]
    fn app01_11_b_c_d_weakening_list_and_apply() {
        let dir = folder("a11b");
        let s = session_in(&dir);
        s.save_settings(vec![number("lock.idle.seconds", 600)])
            .unwrap();
        let path = import_file(
            &dir,
            r#"{"clipboard.clear.seconds":45,"X-99":true,"state.recent":["/a"],"ssh.socket_override":"/x"}"#,
        );
        let asked = s.import_settings(path.clone(), false).unwrap();
        assert!(!asked.applied);
        assert_eq!(asked.weakened.len(), 1);
        assert_eq!(
            asked.weakened[0],
            SettingsWeakening {
                id: "S-TIME-02".into(),
                before: "10".into(),
                after: "45".into()
            }
        );
        assert_eq!(
            s.settings().number("clipboard.clear.seconds".into()),
            10,
            "Cancel: nothing changed"
        );
        assert!(s.import_settings(path, true).unwrap().applied);
        let store = s.settings();
        assert_eq!(store.number("clipboard.clear.seconds".into()), 45);
        assert_eq!(
            store.number("lock.idle.seconds".into()),
            300,
            "missing reads as default"
        );
        assert_eq!(
            store.text("ssh.socket_override".into()),
            "",
            "this-Mac values ignored"
        );
        assert!(store.recent_vaults().is_empty());
        // c, d: S-TIME-03 off and S-BRW-15 on are listed, a shorter S-TIME-02 is not.
        let path = import_file(
            &dir,
            r#"{"lock.idle.enabled":false,"browser.never_ask_access":true,"clipboard.clear.seconds":5}"#,
        );
        s.reset_settings().unwrap();
        let ids: Vec<String> = s
            .import_settings(path.clone(), false)
            .unwrap()
            .weakened
            .into_iter()
            .map(|w| w.id)
            .collect();
        assert_eq!(ids, ["S-TIME-03", "S-BRW-15"]);
        s.import_settings(path, true).unwrap();
        assert!(
            !store.flag("lock.idle.enabled".into())
                && store.flag("browser.never_ask_access".into())
        );
    }

    #[test]
    fn app01_11_e_f_g_missing_values_network_and_proxy() {
        let dir = folder("a11e");
        let s = session_in(&dir);
        s.save_settings(vec![number("lock.idle.seconds", 60)])
            .unwrap();
        let only_colour = import_file(&dir, r#"{"display.color_passwords":true}"#);
        let listed = s
            .import_settings(only_colour.clone(), false)
            .unwrap()
            .weakened;
        assert_eq!(listed[0].id, "S-TIME-04");
        assert_eq!(
            (listed[0].before.as_str(), listed[0].after.as_str()),
            ("60", "300")
        );
        s.reset_settings().unwrap();
        let f = import_file(
            &dir,
            r#"{"display.color_passwords":true,"clipboard.clear.seconds":5}"#,
        );
        assert!(
            s.import_settings(f, false).unwrap().applied,
            "no list: applied at once"
        );
        assert_eq!(s.settings().number("clipboard.clear.seconds".into()), 5);
        s.reset_settings().unwrap();
        s.save_settings(vec![flag("lock.on_minimize", true)])
            .unwrap();
        let g = import_file(
            &dir,
            r#"{"lock.on_minimize":false,"icons.download":true,"browser.custom_proxy":true,"browser.custom_proxy.path":"/tmp/spec-app01/proxy"}"#,
        );
        let ids: Vec<String> = s
            .import_settings(g, false)
            .unwrap()
            .weakened
            .into_iter()
            .map(|w| w.id)
            .collect();
        assert_eq!(ids, ["S-ENTRY-11", "S-LOCK-04", "S-BRW-23", "S-BRW-24"]);
        assert!(
            s.settings().flag("lock.on_minimize".into()),
            "Cancel: nothing changed"
        );
    }

    #[test]
    fn app01_14_recent_vaults() {
        let s = LarsalSettingsStore::default();
        s.save(&[number("recent.count", 3)]).unwrap();
        for p in ["c", "a", "b"] {
            s.note_opened(Path::new(p));
        }
        s.note_opened(Path::new("a"));
        assert_eq!(s.recent_vaults(), ["a", "b", "c"]);
        s.note_opened(Path::new("d"));
        assert_eq!(s.recent_vaults(), ["d", "a", "b"]);
        s.keep(|i| i.set("recent.remember", Value::Bool(false)));
        s.note_opened(Path::new("e"));
        assert!(s.recent_vaults().is_empty());
    }

    #[test]
    fn app09_20_app01_17_reopen_in_saved_order_then_the_shown_one() {
        let dir = folder("a17");
        fs::create_dir_all(&dir).unwrap();
        let [a, b] = ["a.larsalvault", "b.larsalvault"].map(|n| {
            let p = dir.join(n);
            fs::write(&p, b"demo").unwrap();
            p
        });
        let s = store(&dir);
        s.remember_open(vec![a.clone(), b.clone()], Some(b.clone()));
        assert_eq!(store(&dir).reopen(), [a.clone(), b.clone(), b.clone()]);
        fs::remove_file(&a).unwrap();
        assert_eq!(
            store(&dir).reopen(),
            [b.clone(), b],
            "a deleted file is skipped"
        );
        s.save(&[flag("recent.reopen_at_start", false)]).unwrap();
        s.remember_open(vec![dir.join("b.larsalvault")], None);
        let state = file(&dir, "state.json");
        assert!(
            state.get("state.open_at_quit").is_none() && state.get("state.last_active").is_none()
        );
        assert!(s.reopen().is_empty());
    }

    #[test]
    fn app09_20_session_remembers_its_open_vaults_and_reopens_them() {
        let dir = folder("s20");
        fs::create_dir_all(&dir).unwrap();
        let paths = ["a.larsalvault", "b.larsalvault"].map(|n| {
            let p = dir.join(n);
            fs::write(&p, b"demo").unwrap();
            fs::canonicalize(p).unwrap()
        });
        let s = session_in(&dir);
        let a = s.open(paths[0].display().to_string()).unwrap();
        s.open(paths[1].display().to_string()).unwrap();
        s.switch_to(a).unwrap();
        s.remember_open_vaults();
        let again = session_in(&dir);
        assert_eq!(
            again.settings.reopen(),
            [paths[0].clone(), paths[1].clone(), paths[0].clone()]
        );
        // APP-01.14: opening put them on the recent list, newest first.
        assert_eq!(
            again.settings().recent_vaults(),
            [
                paths[1].display().to_string(),
                paths[0].display().to_string()
            ]
        );
    }

    #[test]
    fn app03_s_time_01_02_reach_the_copy() {
        let s = Session::new();
        s.save_settings(vec![number("clipboard.clear.seconds", 30)])
            .unwrap();
        assert_eq!(s.copy_value("Password".into(), "pw1").unwrap().seconds, 30);
        s.save_settings(vec![flag("clipboard.clear.enabled", false)])
            .unwrap();
        let copied = s.copy_value("Password".into(), "pw1").unwrap();
        assert_eq!((copied.seconds, copied.empty), (0, false));
        s.clear_clipboard();
    }

    #[test]
    fn ld204_generator_options_persist_in_the_store() {
        let dir = folder("gen");
        let s = session_in(&dir);
        let mut o = s.generator_options(None);
        assert_eq!(o, GeneratorOptions::default());
        o.length = 16;
        o.upper = false;
        o.special = false;
        o.case = WordCase::Title;
        s.close_generator(Some(o.clone()));
        let again = session_in(&dir);
        assert_eq!(again.generator_options(None), o);
        let saved = file(&dir, "settings.json");
        assert_eq!(saved["generator.password.length"], 16);
        assert_eq!(saved["generator.passphrase.case"], 2);
    }

    #[test]
    fn app01_31_ssh_status_without_and_with_a_dead_socket() {
        let none = ssh_status("", None);
        assert!(!none.connected && none.socket.is_empty());
        assert!(none.message.unwrap().contains("No SSH agent was found"));
        let dir = folder("ssh");
        let dead = ssh_status(&dir.join("agent.sock").display().to_string(), None);
        assert!(!dead.connected && dead.message.is_some());
        assert!(dead.socket.ends_with("agent.sock"));
    }

    #[test]
    fn s_ssh_01_ok_turns_apps_agent_on_and_off() {
        let dir = folder("sshon");
        let s = session_in(&dir);
        s.set_ssh_options(
            dir.join("agent.sock"),
            dir.join("known_hosts"),
            std::time::Duration::from_secs(1),
        );
        s.save_settings(vec![flag("ssh.enabled", true)]).unwrap();
        assert!(s.ssh_agent_info().is_some());
        s.save_settings(vec![flag("ssh.enabled", false)]).unwrap();
        assert!(s.ssh_agent_info().is_none());
        s.stop_ssh_agent();
    }

    #[test]
    fn app09_5_debug_builds_use_their_own_file_names_and_f02_f03_win() {
        let files = files_for(&SettingsFiles {
            config: None,
            local_config: Some(PathBuf::from("/tmp/spec-app09/s3")),
        });
        let name = files
            .portable
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            name,
            if cfg!(debug_assertions) {
                "settings_debug.json"
            } else {
                "settings.json"
            }
        );
        assert_eq!(files.mac, PathBuf::from("/tmp/spec-app09/s3"));
    }

    /// F-111 (APP-01.10, E13-S2 AT-I04, AT-I06): a link planted at the old
    /// fixed temp name, or at the export target itself, is never written
    /// through: the victim keeps its bytes and the target becomes Larsal's own
    /// new 0600 file. The store's own files take the same write.
    #[test]
    fn f_111_settings_export_follows_no_planted_link() {
        let dir = folder("f111");
        fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"victim\n").unwrap();
        let plant = |name: &str| std::os::unix::fs::symlink(&victim, dir.join(name)).unwrap();
        let is_own_file = |p: &Path| {
            let m = fs::symlink_metadata(p).unwrap();
            m.file_type().is_file() && m.permissions().mode() & 0o777 == 0o600
        };
        plant(".settings-export.json.tmp");
        let out = dir.join("settings-export.json");
        let s = store(&dir);
        s.export_to(out.display().to_string()).unwrap();
        assert!(is_own_file(&out));
        fs::remove_file(&out).unwrap();
        plant("settings-export.json");
        s.export_to(out.display().to_string()).unwrap();
        assert!(is_own_file(&out), "the link at the target is replaced");
        plant(".settings.json.tmp");
        s.save(&[number("clipboard.clear.seconds", 30)]).unwrap();
        assert!(is_own_file(&dir.join("settings.json")));
        assert_eq!(fs::read(&victim).unwrap(), b"victim\n");
    }
}
