//! The shared-group screens (E11-S5, INT-08.21 to INT-08.26, INT-08.31):
//! the Sharing page of the group editor, the share badges, the label under
//! the entry list and the vault settings' Shared Groups table, over
//! larsal-share and the runs of share.rs.
//!
//! Guarantees:
//! - the editor's changes live in a draft until Save; Save writes the share
//!   item into the group, or removes it after Clear, and approves the share
//!   as it now is (INT-08.21, INT-08.31); a change of Keep group structure
//!   alone starts no import (INT-08.15 step 2, T26);
//! - the share password stays in a `SecretString`: typed and generated
//!   values go into Rust, and it leaves only as the Show the user asked for
//!   (`share_edit_show`, LD-220); no view, warning or error holds it
//!   (INT-08.39);
//! - a badge says "active" only for a share that runs: approved on this
//!   Mac, not expired, importing with import allowed or exporting with
//!   export allowed (INT-08.24, LD-270 (3));
//! - the editor's warnings come in INT-08.23's order with MI08-17 first
//!   (LD-270 (3)); the path guard reads the disk without the session lock.

use crate::session::{LarsalError, MAX_TEXT, Session};
use crate::share::{guarded, is_key_file};
use crate::views::{custom_icon_name, hex, icon_number, now, parse_id};
use larsal_core::expiry::is_expired;
use larsal_core::health::{Level, score};
use larsal_core::time::Instant;
use larsal_crypto::secret::SecretString;
use larsal_format::share_item::{self, Item, Mode, Settings};
use larsal_model::{CustomData, CustomDataItem, Group, Time, Uuid, Vault};
use larsal_share::run;
use larsal_share::settings::resolve;
use std::path::{Path, PathBuf};

#[cfg(test)]
thread_local! { pub(crate) static SAVE_PREPARED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) }; }

/// The longest path the Sharing page takes, as `share_look` (bytes): the
/// longest the share item keeps (F-268).
const MAX_PATH: usize = share_item::MAX_PATH;

/// The container names Larsal can share (INT-08.23 case 1, D-INT08-2): its own
/// two, and the reference's vault and signed names, stored encoded
/// (AGENTS.md rule 1). Compared without letter case.
const EXTENSIONS: [&[u8]; 4] = [
    b".larsalvault",
    b".larsalshare",
    &[0x2E, 0x6B, 0x64, 0x62, 0x78],
    &[
        0x2E, 0x6B, 0x64, 0x62, 0x78, 0x2E, 0x73, 0x68, 0x61, 0x72, 0x65,
    ],
];

/// A share's Type (INT-08.21), in the Sharing page's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ShareMode {
    /// Not shared.
    Inactive,
    /// Reads the file into the group.
    Import,
    /// Writes the group to the file.
    Export,
    /// Both.
    Synchronize,
}

impl From<Mode> for ShareMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Inactive => Self::Inactive,
            Mode::Import => Self::Import,
            Mode::Export => Self::Export,
            Mode::Synchronize => Self::Synchronize,
        }
    }
}

/// The message slot under Path (INT-08.23, first match only, MI08-17 first
/// by LD-270 (3)); shown only while the Type is not Inactive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ShareWarning {
    /// MI08-17 (INT-08.34): the file of a vault open in Larsal.
    OpenVault,
    /// MI08-27 (INT-08.34): a key file this Mac knows.
    KeyFile,
    /// MI08-10: a name Larsal cannot share.
    Extension,
    /// MI08-11: another group exports to this file.
    OtherExports,
    /// MI08-12: another group imports this file.
    OtherImports,
    /// MI08-13: one group imports it, another exports it.
    ImportAndExport,
    /// MI08-14: import and export both off.
    BothOff,
    /// MI08-15: only import allowed.
    ExportOff,
    /// MI08-16: only export allowed.
    ImportOff,
}

/// The Sharing page (INT-08.21). No password: its length only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareEditView {
    /// The group, 32 hex digits.
    pub group: String,
    /// Its name.
    pub name: String,
    /// The Type.
    pub mode: ShareMode,
    /// The path as typed and stored (INT-08.5).
    pub path: String,
    /// "Full path": the resolved path; empty without a path.
    pub full_path: String,
    /// The share password's length, for the masked field's dots.
    pub password_chars: u32,
    /// Keep group structure.
    pub keep_groups: bool,
    /// The group has a share item (Clear is on).
    pub item: bool,
    /// The message under Path.
    pub warning: Option<ShareWarning>,
    /// MI08-23 under Share password: empty or below Good (FEA-05).
    pub weak: bool,
}

/// One change on the Sharing page.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ShareChange {
    /// A new Type.
    Mode {
        /// The Type chosen.
        mode: ShareMode,
    },
    /// The path typed or chosen with Browse.
    Path {
        /// As typed (at most 4,096 bytes).
        path: String,
    },
    /// Keep group structure.
    Keep {
        /// On or off.
        on: bool,
    },
    /// Clear: no share item and empty fields.
    Clear,
}

/// A share group's badge (INT-08.24): on its own tile only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareMark {
    /// The share group, 32 hex digits.
    pub group: String,
    /// "Share active" (else "Share inactive").
    pub active: bool,
}

/// What the label under the entry list says (INT-08.24, INT-08.31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ShareState {
    /// MI08-24, with MI08-16 and MI08-15 as they apply.
    Running,
    /// MI08-25: inactive, no path, in the bin, or unreadable.
    Off,
    /// MI08-18 with Approve: not approved on this Mac.
    Waiting,
}

/// The label of the selected group's nearest share below the root.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareLabel {
    /// The share group, 32 hex digits (Approve's).
    pub group: String,
    /// Its name (the Approve sheet's title).
    pub name: String,
    /// Which words.
    pub state: ShareState,
    /// The Type.
    pub mode: ShareMode,
    /// The path as stored (MI08-24).
    pub path: String,
    /// The resolved path (MI08-18 and the Approve sheet); empty when the
    /// share does not run at all.
    pub full_path: String,
    /// MI08-16: it imports and import is off.
    pub import_off: bool,
    /// MI08-15: it exports and export is off.
    pub export_off: bool,
}

/// One row of the vault settings' Shared Groups table (INT-08.25).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareRow {
    /// The share group, 32 hex digits.
    pub group: String,
    /// The group path without the root, joined by " > ".
    pub names: String,
    /// The Type.
    pub mode: ShareMode,
    /// The path as stored.
    pub path: String,
    /// The group's standard icon number; -1 for a custom one.
    pub icon: i32,
    /// The custom icon's name.
    pub custom_icon: Option<String>,
    /// Its badge.
    pub active: bool,
}

/// The Sharing page's draft of one group (in share.rs's state, wiped on
/// lock and close).
pub(crate) struct Draft {
    group: Uuid,
    settings: Settings,
    /// The group has a share item (none after Clear).
    item: bool,
    /// Clear ran on this page: Save forgets the group's records, also when
    /// a new path followed it (INT-08.31).
    cleared: bool,
    /// A field changed: Save writes the item.
    changed: bool,
    /// The path as the page opened with it.
    opened_path: String,
    /// The share as the page opened was approved on this Mac: a change of
    /// its Type may be approved on Save (INT-08.31).
    opened_approved: bool,
}

/// INT-08.23 case 1: the name ends in a name Larsal can share.
fn shareable(path: &str) -> bool {
    let lower = path.as_bytes().to_ascii_lowercase();
    EXTENSIONS.iter().any(|e| lower.ends_with(e))
}

/// INT-08.22: the name chosen with Browse; without a container name it
/// gets `.larsalvault`, with the dot only when it has none at its end.
#[uniffi::export]
#[must_use]
pub fn share_chosen_path(path: String) -> String {
    if shareable(&path) {
        return path;
    }
    let dot = if path.ends_with('.') { "" } else { "." };
    format!("{path}{dot}larsalvault")
}

/// INT-08.23 cases 1 to 5 for `s` in group `group` of `v`.
fn warning(v: &Vault, group: Uuid, s: &Settings, flags: (bool, bool)) -> Option<ShareWarning> {
    if s.mode() == Mode::Inactive {
        return None;
    }
    if !s.path.is_empty() {
        if !shareable(&s.path) {
            return Some(ShareWarning::Extension);
        }
        let others: Vec<Settings> = v
            .root
            .subtree()
            .into_iter()
            .filter(|g| g.uuid != group)
            .filter_map(|g| match share_item::of(g) {
                Some(Item::Settings(o)) if o.path == s.path => Some(o),
                _ => None,
            })
            .collect();
        let (imports, exports) = (s.importing(), s.exporting());
        if exports && others.iter().any(Settings::exporting) {
            return Some(ShareWarning::OtherExports);
        }
        if imports && others.iter().any(Settings::importing) {
            return Some(ShareWarning::OtherImports);
        }
        let crossed = others
            .iter()
            .any(|o| (imports && o.exporting()) || (exports && o.importing()));
        if crossed {
            return Some(ShareWarning::ImportAndExport);
        }
    }
    match flags {
        (false, false) => Some(ShareWarning::BothOff),
        (true, false) => Some(ShareWarning::ExportOff),
        (false, true) => Some(ShareWarning::ImportOff),
        (true, true) => None,
    }
}

/// MI08-23: an empty share password, or one below Good (FEA-05).
fn weak(s: &Settings) -> bool {
    let p = &s.password;
    p.is_empty() || Level::of(score(crate::generator::estimate(p))) < Level::Good
}

/// The page of draft `d`, without the path guard, and the resolved path
/// the guard checks.
fn view(
    v: &Vault,
    file: &Path,
    d: &Draft,
    flags: (bool, bool),
) -> (ShareEditView, Option<PathBuf>) {
    let s = &d.settings;
    let full = resolve(&s.path, Some(file));
    let on = s.mode() != Mode::Inactive;
    let name = v
        .root
        .find_group(d.group)
        .map(|g| g.name.clone())
        .unwrap_or_default();
    let view = ShareEditView {
        group: hex(d.group),
        name,
        mode: s.mode().into(),
        path: s.path.clone(),
        full_path: full
            .as_deref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        password_chars: u32::try_from(s.password.expose().chars().count()).unwrap_or(u32::MAX),
        keep_groups: s.keep_groups,
        item: d.item,
        warning: warning(v, d.group, s, flags),
        weak: on && weak(s),
    };
    (view, full.filter(|_| on))
}

/// Sets (`Some`) or removes (`None`) the share item of `cd`.
fn set_item(cd: &mut CustomData, key: &str, value: Option<SecretString>, at: Time) {
    let i = cd.items.iter().position(|i| i.key == key);
    match (i.and_then(|i| cd.items.get_mut(i)), value) {
        (Some(item), Some(v)) => {
            item.value = v;
            item.last_modified = Some(at);
        }
        (Some(_), None) => cd.items.retain(|i| i.key != key),
        (None, Some(v)) => cd.items.push(CustomDataItem {
            key: key.to_owned(),
            value: v,
            last_modified: Some(at),
            unknown: Vec::new(),
        }),
        (None, None) => {}
    }
}

/// The share groups of `v` that run (the "share active" badge, INT-08.24):
/// set up, approved, importing with import allowed or exporting with
/// export allowed, and not expired.
fn running(v: &Vault, file: &Path, approved: &[String], flags: (bool, bool)) -> Vec<Uuid> {
    let at = Instant::from(now());
    run::shares(v, Some(file))
        .into_iter()
        .filter(|s| approved.contains(&s.approval(v)))
        .filter(|s| (s.settings.importing() && flags.0) || (s.settings.exporting() && flags.1))
        .filter(|s| {
            v.root
                .find_group(s.group)
                .is_some_and(|g| !is_expired(&g.times, at))
        })
        .map(|s| s.group)
        .collect()
}

/// Every group of `v` that carries a share item, in tree order.
fn share_groups(v: &Vault) -> impl Iterator<Item = &Group> {
    v.root
        .subtree()
        .into_iter()
        .filter(|g| share_item::of(g).is_some())
}

impl Session {
    fn share_allowed(&self) -> (bool, bool) {
        let (import, export, _) = self.settings.share_flags();
        (import, export)
    }

    /// Runs `f` on vault `vault`'s draft; the page as it is after, with
    /// the path guard checked off the session lock.
    fn with_share_draft(
        &self,
        vault: u64,
        f: impl FnOnce(&mut Draft),
    ) -> Result<ShareEditView, LarsalError> {
        let flags = self.share_allowed();
        let (mut page, full, open, keys) = self.with_share(vault, |slot| {
            let v = slot.vault.ok_or(LarsalError::Locked)?;
            let d =
                slot.share.draft.as_mut().ok_or_else(|| {
                    LarsalError::Refused("The group editor is not open.".to_owned())
                })?;
            f(d);
            let (page, full) = view(v, slot.path, d, flags);
            Ok((page, full, slot.open, slot.keys))
        })??;
        if let Some(p) = full {
            if guarded(&p, &open, &self.backup_pattern()) {
                page.warning = Some(ShareWarning::OpenVault);
            } else if is_key_file(&p, &self.key_files(keys)) {
                page.warning = Some(ShareWarning::KeyFile);
            }
        }
        Ok(page)
    }
}

#[uniffi::export]
impl Session {
    /// INT-08.21: opens the Sharing page of group `group` (32 hex digits)
    /// with its share settings as stored; an unreadable item starts as new
    /// settings and keeps Clear on. One page per vault: a second call
    /// starts again.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup`.
    pub fn share_edit(&self, vault: u64, group: String) -> Result<ShareEditView, LarsalError> {
        let id = parse_id(&group, LarsalError::UnknownGroup)?;
        let approved = self.settings.share_approvals();
        self.with_share(vault, |slot| {
            let v = slot.vault.ok_or(LarsalError::Locked)?;
            let g = v.root.find_group(id).ok_or(LarsalError::UnknownGroup)?;
            let (settings, item) = match share_item::of(g) {
                Some(Item::Settings(s)) => (s, true),
                Some(Item::Invalid) => (Settings::new(), true),
                None => (Settings::new(), false),
            };
            let opened_approved = run::shares(v, Some(slot.path))
                .iter()
                .any(|s| s.group == id && approved.contains(&s.approval(v)));
            slot.share.draft = Some(Draft {
                group: id,
                opened_path: settings.path.clone(),
                opened_approved,
                settings,
                item,
                cleared: false,
                changed: false,
            });
            Ok(())
        })??;
        self.with_share_draft(vault, |_| ())
    }

    /// INT-08.21: one change on the Sharing page; a real change writes the
    /// item into the draft (Save stores it). Clear empties the fields and
    /// drops the item.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `Refused` (no page open), `TooLong` for a
    /// path over 4,096 bytes.
    pub fn share_edit_change(
        &self,
        vault: u64,
        change: ShareChange,
    ) -> Result<ShareEditView, LarsalError> {
        if matches!(&change, ShareChange::Path { path } if path.len() > MAX_PATH) {
            return Err(LarsalError::TooLong);
        }
        self.with_share_draft(vault, |d| {
            let s = &mut d.settings;
            let changed = match change {
                ShareChange::Mode { mode } => {
                    let (import, export) = match mode {
                        ShareMode::Inactive => (false, false),
                        ShareMode::Import => (true, false),
                        ShareMode::Export => (false, true),
                        ShareMode::Synchronize => (true, true),
                    };
                    let changed = (s.import, s.export) != (import, export);
                    (s.import, s.export) = (import, export);
                    changed
                }
                ShareChange::Path { path } => {
                    let changed = s.path != path;
                    s.path = path;
                    changed
                }
                ShareChange::Keep { on } => {
                    let changed = s.keep_groups != on;
                    s.keep_groups = on;
                    changed
                }
                ShareChange::Clear => {
                    *s = Settings::new();
                    d.changed |= d.item;
                    d.item = false;
                    d.cleared = true;
                    return;
                }
            };
            if changed {
                d.item = true;
                d.changed = true;
            }
        })
    }

    /// INT-08.21, INT-08.39: the share password typed in the masked field;
    /// it goes into a `SecretString` at once.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `Refused` (no page open), `TooLong` over
    /// 64 KiB.
    pub fn share_edit_password(
        &self,
        vault: u64,
        value: String,
    ) -> Result<ShareEditView, LarsalError> {
        if value.len() > MAX_TEXT {
            return Err(LarsalError::TooLong);
        }
        let value = SecretString::new(value);
        self.with_share_draft(vault, |d| {
            d.settings.password = value;
            d.item = true;
            d.changed = true;
        })
    }

    /// FEA-02 on the Sharing page: the generator's value becomes the share
    /// password; it never crosses to Swift here.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `Refused` (no value, or no page open).
    pub fn share_edit_generated(&self, vault: u64) -> Result<ShareEditView, LarsalError> {
        let value = self.generated()?;
        self.with_share_draft(vault, |d| {
            d.settings.password = value;
            d.item = true;
            d.changed = true;
        })
    }

    /// The Sharing page's Show (AGENTS.md rule 4, LD-220): the share
    /// password the user asked to see; Swift drops it on Hide, on leaving
    /// the page and on lock.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `Refused` (no page open).
    pub fn share_edit_show(&self, vault: u64) -> Result<String, LarsalError> {
        self.with_share(vault, |slot| {
            slot.vault.ok_or(LarsalError::Locked)?;
            slot.share
                .draft
                .as_ref()
                .map(|d| d.settings.password.expose().to_owned())
                .ok_or_else(|| LarsalError::Refused("The group editor is not open.".to_owned()))
        })?
    }

    /// INT-08.21, INT-08.31: Save. A changed draft writes the share item
    /// into the group (Clear removes it), counted as a change of the vault,
    /// and the share as it now is gets its approval on this Mac; a share
    /// approved only now imports at once, as Approve does. A change of Keep
    /// group structure alone starts no import (T26). The page closes.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup` (the group went),
    /// `Refused` when the random source fails.
    pub fn share_edit_save(&self, vault: u64) -> Result<(), LarsalError> {
        // A reload must not see a closed editor before its draft is committed.
        let saved = self.with_share(vault, |slot| -> Result<_, LarsalError> {
            let Some(d) = slot.share.draft.as_mut().filter(|d| d.changed) else {
                slot.share.draft = None;
                return Ok(None);
            };
            let v = slot.vault.ok_or(LarsalError::Locked)?;
            let refused =
                || LarsalError::Refused("The system's random source failed. Try again.".to_owned());
            let value = if d.item {
                Some(d.settings.write().map_err(|_| refused())?)
            } else {
                None
            };
            #[cfg(test)]
            SAVE_PREPARED.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook();
                }
            });
            let key = std::str::from_utf8(share_item::KEY).map_err(|_| refused())?;
            *slot.version = slot.version.wrapping_add(1);
            let at = now();
            let changed = larsal_core::edit::edit_group(v, d.group, at, |g| {
                set_item(&mut g.custom_data, key, value, at)
            })
            .map_err(|_| LarsalError::UnknownGroup)?;
            if changed {
                slot.edit.changes = slot.edit.changes.saturating_add(1);
            }
            // INT-08.31: Save approves what the user set up on this page;
            // a planted path that one other box changed still needs the sheet.
            let accepted = d.opened_approved || d.settings.path != d.opened_path;
            let cleared = (!d.item || d.cleared).then(|| run::records_of(v, d.group));
            let group = d.group;
            slot.share.draft = None;
            Ok(Some((group, accepted, cleared)))
        })?;
        let Some((group, accepted, cleared)) = saved? else {
            return Ok(());
        };
        if let Some(records) = cleared {
            self.settings.forget_share(&records);
        }
        if !accepted {
            return Ok(());
        }
        let approval = self.with_open(vault, |v, file, _| {
            Ok(run::shares(v, Some(file))
                .into_iter()
                .find(|s| s.group == group)
                .map(|s| s.approval(v)))
        })?;
        if approval.is_some_and(|a| !self.settings.share_approvals().contains(&a)) {
            self.approve_share(vault, hex(group))?;
        }
        Ok(())
    }

    /// Cancel: the Sharing page closes and its draft goes.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn share_edit_cancel(&self, vault: u64) -> Result<(), LarsalError> {
        self.with_share(vault, |slot| slot.share.draft = None)
    }

    /// INT-08.24: the badge of every group that carries a share item, in
    /// tree order.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn share_marks(&self, vault: u64) -> Result<Vec<ShareMark>, LarsalError> {
        let (approved, flags) = (self.settings.share_approvals(), self.share_allowed());
        self.with_open(vault, |v, file, _| {
            let on = running(v, file, &approved, flags);
            Ok(share_groups(v)
                .map(|g| ShareMark {
                    group: hex(g.uuid),
                    active: on.contains(&g.uuid),
                })
                .collect())
        })
    }

    /// INT-08.24, INT-08.31: the label under the entry list for group
    /// `group`: its nearest share below the root; `None` when there is
    /// none (a share of the root shows no label).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup` for an id that is not 32
    /// hex digits.
    pub fn share_label(
        &self,
        vault: u64,
        group: String,
    ) -> Result<Option<ShareLabel>, LarsalError> {
        let id = parse_id(&group, LarsalError::UnknownGroup)?;
        let (approved, (import, export)) = (self.settings.share_approvals(), self.share_allowed());
        self.with_open(vault, |v, file, _| {
            let Some(share) = share_item::share_group(v, id).filter(|s| *s != v.root.uuid) else {
                return Ok(None);
            };
            let Some(g) = v.root.find_group(share) else {
                return Ok(None);
            };
            let mut label = ShareLabel {
                group: hex(share),
                name: g.name.clone(),
                state: ShareState::Off,
                mode: ShareMode::Inactive,
                path: String::new(),
                full_path: String::new(),
                import_off: false,
                export_off: false,
            };
            if let Some(Item::Settings(s)) = share_item::of(g) {
                label.mode = s.mode().into();
                label.path.clone_from(&s.path);
            }
            if let Some(s) = run::shares(v, Some(file))
                .into_iter()
                .find(|s| s.group == share)
            {
                label.full_path = s.path.to_string_lossy().into_owned();
                label.state = if approved.contains(&s.approval(v)) {
                    ShareState::Running
                } else {
                    ShareState::Waiting
                };
                label.import_off = s.settings.importing() && !import;
                label.export_off = s.settings.exporting() && !export;
            }
            Ok(Some(label))
        })
    }

    /// INT-08.25: one row per group that carries a share item, in tree
    /// order; read only.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn share_rows(&self, vault: u64) -> Result<Vec<ShareRow>, LarsalError> {
        let (approved, flags) = (self.settings.share_approvals(), self.share_allowed());
        self.with_open(vault, |v, file, _| {
            let on = running(v, file, &approved, flags);
            Ok(share_groups(v)
                .map(|g| {
                    let (mode, path) = match share_item::of(g) {
                        Some(Item::Settings(s)) => (s.mode().into(), s.path.clone()),
                        _ => (ShareMode::Inactive, String::new()),
                    };
                    let chain = crate::edit::chain(v, g.uuid);
                    let names: Vec<&str> = chain.iter().skip(1).map(|c| c.name.as_str()).collect();
                    ShareRow {
                        group: hex(g.uuid),
                        names: if names.is_empty() {
                            g.name.clone()
                        } else {
                            names.join(" > ")
                        },
                        mode,
                        path,
                        icon: icon_number(g.icon),
                        custom_icon: custom_icon_name(v, g.icon),
                        active: on.contains(&g.uuid),
                    }
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::tests::{
        MAIN, SHARE, approved, base, change, flags, hex as hx, id, member, model, publish, read,
        save, session, set, set_share, settings, team, unlock, write,
    };
    use crate::test_dir::TempDir;
    use std::sync::Arc;

    /// T2 of INT-08's notation (2026-03-01), seconds since year 1.
    const T2: Time = Time(63_907_920_000);

    /// `vault` written to `dir/v.larsalvault` with its shares approved, opened
    /// and unlocked in a session with both allow settings on.
    fn open(dir: &Path, vault: &Vault) -> (Arc<Session>, u64) {
        let s = session(false);
        let v = approved(&s, &dir.join("v.larsalvault"), vault);
        unlock(&s, v);
        (s, v)
    }

    fn change_page(s: &Session, v: u64, c: ShareChange) -> ShareEditView {
        s.share_edit_change(v, c).unwrap()
    }

    fn mode(m: ShareMode) -> ShareChange {
        ShareChange::Mode { mode: m }
    }

    fn path(p: &str) -> ShareChange {
        ShareChange::Path { path: p.to_owned() }
    }

    fn item(s: &Session, v: u64, n: u8) -> Option<Item> {
        model(s, v, |m| share_item::of(m.root.find_group(id(n)).unwrap()))
    }

    fn stored(s: &Session, v: u64, n: u8) -> Settings {
        match item(s, v, n) {
            Some(Item::Settings(st)) => st,
            other => panic!("readable settings, got {other:?}"),
        }
    }

    fn changes(s: &Session, v: u64) -> u32 {
        s.save_status(v).unwrap().changes
    }

    #[test]
    fn t35_int08_21_a_new_share_starts_inactive_with_keep_on_and_no_item() {
        let dir = TempDir::new("share-edit-t35");
        let (s, v) = open(&dir, &base());
        let page = s.share_edit(v, hx(id(0x20))).unwrap();
        assert_eq!(page.name, "Team");
        assert_eq!(
            (page.mode, page.path.as_str(), page.keep_groups, page.item),
            (ShareMode::Inactive, "", true, false)
        );
        assert_eq!(
            (page.warning, page.weak),
            (None, false),
            "nothing while Inactive"
        );
        let page = change_page(&s, v, mode(ShareMode::Import));
        assert!(page.item, "a field change writes the item into the draft");
        assert!(page.weak, "MI08-23: the empty share password");
        let page = change_page(&s, v, path("team.larsalvault"));
        assert_eq!(
            page.full_path,
            dir.join("team.larsalvault").to_string_lossy()
        );
        assert_eq!(
            s.share_edit(v, hx(id(0x99))),
            Err(LarsalError::UnknownGroup)
        );
    }

    #[test]
    fn t36_int08_21_save_stores_the_item_cancel_drops_it_and_clear_removes_it() {
        let dir = TempDir::new("share-edit-t36");
        let (s, v) = open(&dir, &base());
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, mode(ShareMode::Export));
        change_page(&s, v, path("team.larsalvault"));
        s.share_edit_cancel(v).unwrap();
        s.share_edit_save(v).unwrap();
        assert!(item(&s, v, 0x20).is_none(), "Cancel stores nothing");
        assert_eq!(changes(&s, v), 0);
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, mode(ShareMode::Export));
        change_page(&s, v, path("team.larsalvault"));
        s.share_edit_password(v, SHARE.to_owned()).unwrap();
        s.share_edit_save(v).unwrap();
        let st = stored(&s, v, 0x20);
        assert_eq!(
            (st.mode(), st.path.as_str(), st.keep_groups),
            (Mode::Export, "team.larsalvault", true)
        );
        assert_eq!(st.password.expose(), SHARE);
        assert_eq!(
            changes(&s, v),
            1,
            "Save is a change of the vault (APP-05.2)"
        );
        // F-197: a change of the share password alone is a field change too.
        s.share_edit(v, hx(id(0x20))).unwrap();
        s.share_edit_password(v, "Kv7!mQ2#Ld9@Wx".to_owned())
            .unwrap();
        s.share_edit_save(v).unwrap();
        assert_eq!(
            stored(&s, v, 0x20).password.expose(),
            "Kv7!mQ2#Ld9@Wx",
            "the new password, not the old one"
        );
        assert_eq!(changes(&s, v), 2);
        // T36: Clear, then Save: no item, so no badge either.
        let page = s.share_edit(v, hx(id(0x20))).unwrap();
        assert!(page.item);
        let page = change_page(&s, v, ShareChange::Clear);
        assert_eq!(
            (
                page.mode,
                page.path.as_str(),
                page.password_chars,
                page.item
            ),
            (ShareMode::Inactive, "", 0, false)
        );
        s.share_edit_save(v).unwrap();
        assert!(item(&s, v, 0x20).is_none());
        assert!(s.share_marks(v).unwrap().is_empty());
    }

    /// INT-08.31: creating a share in Larsal's editor approves it, so the next
    /// save exports; a share item from anywhere else does not (T52).
    #[test]
    fn int08_31_a_share_made_in_the_editor_is_approved_and_exports_at_the_next_save() {
        let dir = TempDir::new("share-edit-31");
        let (s, v) = open(&dir, &base());
        assert!(s.settings.share_approvals().is_empty());
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, mode(ShareMode::Export));
        change_page(&s, v, path("team.larsalvault"));
        s.share_edit_password(v, SHARE.to_owned()).unwrap();
        s.share_edit_save(v).unwrap();
        assert_eq!(s.settings.share_approvals().len(), 1);
        save(&s, v);
        let c = read(&dir.join("team.larsalvault"), SHARE).expect("exported at the save");
        assert_eq!(c.root.uuid, id(0x20));
    }

    /// T26 (INT-08.15 step 2): a change of Keep group structure alone
    /// starts no import; a change of the Type does.
    #[test]
    fn t26_int08_15_a_keep_only_change_starts_no_import() {
        let dir = TempDir::new("share-edit-t26");
        let container = dir.join("team.larsalvault");
        publish(&container, &member());
        let mut vault = base();
        set_share(team(&mut vault), settings(true, false, "team.larsalvault"));
        let (s, v) = open(&dir, &vault);
        let mail = |s: &Session| {
            model(s, v, |m| {
                m.root
                    .all_entries()
                    .find(|e| e.uuid == id(0x0A))
                    .unwrap()
                    .value("Password")
                    .to_owned()
            })
        };
        assert_eq!(mail(&s), "pw-2", "the unlock imported");
        let mut next = member();
        let m = team(&mut next).entries.first_mut().unwrap();
        set(m, "Password", "pw-3", true);
        m.times.last_modification = T2;
        publish(&container, &next);
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, ShareChange::Keep { on: false });
        s.share_edit_save(v).unwrap();
        assert!(!stored(&s, v, 0x20).keep_groups);
        s.share_paths(v).unwrap();
        s.share_wait(v);
        assert_eq!(mail(&s), "pw-2", "Keep alone imported");
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, mode(ShareMode::Synchronize));
        s.share_edit_save(v).unwrap();
        s.share_paths(v).unwrap();
        s.share_wait(v);
        assert_eq!(mail(&s), "pw-3", "a new Type imports at once");
    }

    #[test]
    fn int08_23_t38_t39_t40_the_first_message_only_with_mi08_17_first() {
        let dir = TempDir::new("share-edit-23");
        let mut vault = base();
        let mut other = Group::new(id(0x22), "Other".into(), Time(0));
        set_share(&mut other, settings(false, true, "team.larsalvault"));
        vault.root.groups.push(other);
        let (s, v) = open(&dir, &vault);
        flags(&s, true, false, false);
        s.share_edit(v, hx(id(0x20))).unwrap();
        let w = |c| change_page(&s, v, c).warning;
        assert_eq!(
            w(mode(ShareMode::Synchronize)),
            Some(ShareWarning::ExportOff),
            "T40: MI08-15"
        );
        assert_eq!(
            w(path("team.txt")),
            Some(ShareWarning::Extension),
            "T38: MI08-10 only"
        );
        assert_eq!(
            w(path("team.larsalvault")),
            Some(ShareWarning::OtherExports),
            "T39: MI08-11"
        );
        assert_eq!(
            w(mode(ShareMode::Import)),
            Some(ShareWarning::ImportAndExport),
            "MI08-13"
        );
        change(&s, v, |m| {
            let o = m
                .root
                .groups
                .iter_mut()
                .find(|g| g.uuid == id(0x22))
                .unwrap();
            set_share(o, settings(true, false, "team.larsalvault"));
        });
        assert_eq!(
            w(mode(ShareMode::Synchronize)),
            Some(ShareWarning::OtherImports),
            "MI08-12"
        );
        assert_eq!(
            w(path("TEAM.LARSALVAULT")),
            Some(ShareWarning::ExportOff),
            "names case-blind, paths as stored"
        );
        let reference = String::from_utf8([b"x".as_slice(), EXTENSIONS[2]].concat()).unwrap();
        assert_eq!(
            w(path(&reference)),
            Some(ShareWarning::ExportOff),
            "the reference's name is shareable"
        );
        assert_eq!(
            w(path("v.larsalvault")),
            Some(ShareWarning::OpenVault),
            "INT-08.34: MI08-17 first"
        );
        assert_eq!(
            w(path("V.LARSALVAULT")),
            Some(ShareWarning::OpenVault),
            "macOS paths ignore case"
        );
        assert_eq!(w(mode(ShareMode::Inactive)), None, "nothing while Inactive");
        flags(&s, false, false, false);
        assert_eq!(w(path("x.larsalvault")), None);
        assert_eq!(
            w(mode(ShareMode::Import)),
            Some(ShareWarning::BothOff),
            "MI08-14"
        );
        flags(&s, false, true, false);
        assert_eq!(
            w(mode(ShareMode::Export)),
            Some(ShareWarning::ImportOff),
            "MI08-16"
        );
    }

    #[test]
    fn t37_int08_22_a_chosen_name_without_a_container_name_gets_larsalvault() {
        assert_eq!(
            share_chosen_path("/tmp/shared".into()),
            "/tmp/shared.larsalvault"
        );
        assert_eq!(
            share_chosen_path("/tmp/shared.".into()),
            "/tmp/shared.larsalvault"
        );
        assert_eq!(
            share_chosen_path("/tmp/a.txt".into()),
            "/tmp/a.txt.larsalvault"
        );
        for kept in ["/tmp/a.larsalvault", "/tmp/a.LARSALSHARE"] {
            assert_eq!(share_chosen_path(kept.into()), kept);
        }
        for e in &EXTENSIONS[2..] {
            let reference = String::from_utf8([b"/tmp/a".as_slice(), e].concat()).unwrap();
            assert_eq!(share_chosen_path(reference.clone()), reference);
        }
    }

    #[test]
    fn t63_int08_39_an_empty_or_weak_share_password_warns_and_still_saves() {
        let dir = TempDir::new("share-edit-t63");
        let (s, v) = open(&dir, &base());
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, mode(ShareMode::Import));
        assert!(change_page(&s, v, path("team.larsalvault")).weak, "empty");
        assert!(
            s.share_edit_password(v, "abc".into()).unwrap().weak,
            "below Good"
        );
        // The boundary: Weak (40 to 74 bits) still warns.
        let fair = "Kv7!mQ2#Ld";
        let bits = crate::generator::estimate(&SecretString::new(fair.to_owned()));
        assert_eq!(Level::of(score(bits)), Level::Weak, "{bits}");
        assert!(s.share_edit_password(v, fair.into()).unwrap().weak, "Weak");
        // F-177: Good (75 to 99 bits) is the first level with no warning.
        let good = "Kv7!mQ2#Ld9@Wx";
        let bits = crate::generator::estimate(&SecretString::new(good.to_owned()));
        assert_eq!(Level::of(score(bits)), Level::Good, "{bits}");
        assert!(!s.share_edit_password(v, good.into()).unwrap().weak, "Good");
        assert!(
            !s.share_edit_password(v, "M2ciPK%tX7UctF=AQMGf".into())
                .unwrap()
                .weak
        );
        assert!(s.share_edit_password(v, String::new()).unwrap().weak);
        s.share_edit_save(v).unwrap();
        let st = stored(&s, v, 0x20);
        assert!(st.password.is_empty(), "allowed, for parity");
        assert_eq!(st.mode(), Mode::Import);
    }

    /// INT-08.39, SR-14: the typed password reaches no view, label, row or
    /// error; it leaves Rust only as the Show the user asked for, and a
    /// lock drops the page.
    #[test]
    fn int08_39_sr_14_the_share_password_is_in_no_view_only_in_show() {
        let dir = TempDir::new("share-edit-39");
        let (s, v) = open(&dir, &base());
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, mode(ShareMode::Import));
        let page = s.share_edit_password(v, SHARE.to_owned()).unwrap();
        assert_eq!(page.password_chars, 12);
        assert!(!format!("{page:?}").contains(SHARE));
        assert_eq!(s.share_edit_show(v).unwrap(), SHARE);
        assert!(s.share_edit_password(v, "x".repeat(MAX_TEXT + 1)).is_err());
        s.share_edit_save(v).unwrap();
        let seen = format!(
            "{:?}{:?}{:?}",
            s.share_marks(v).unwrap(),
            s.share_label(v, hx(id(0x21))).unwrap(),
            s.share_rows(v).unwrap()
        );
        assert!(!seen.contains(SHARE), "{seen}");
        s.share_edit(v, hx(id(0x20))).unwrap();
        s.lock(v).unwrap();
        assert_eq!(s.share_edit_show(v), Err(LarsalError::Locked));
        unlock(&s, v);
        assert!(
            matches!(s.share_edit_show(v), Err(LarsalError::Refused(_))),
            "the page went with the lock"
        );
    }

    #[test]
    fn fea_02_the_generators_value_becomes_the_share_password() {
        let dir = TempDir::new("share-edit-gen");
        let (s, v) = open(&dir, &base());
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, mode(ShareMode::Export));
        change_page(&s, v, path("team.larsalvault"));
        s.share_edit_password(v, SHARE.to_owned()).unwrap();
        s.share_edit_save(v).unwrap();
        // F-197: on the saved share, the generated value alone is saved.
        s.share_edit(v, hx(id(0x20))).unwrap();
        let made = s.generate(s.generator_options(None));
        let page = s.share_edit_generated(v).unwrap();
        assert_eq!(
            page.password_chars,
            u32::try_from(made.value.chars().count()).unwrap()
        );
        assert_eq!(s.share_edit_show(v).unwrap(), made.value);
        s.close_generator(None);
        assert!(matches!(
            s.share_edit_generated(v),
            Err(LarsalError::Refused(_))
        ));
        s.share_edit_save(v).unwrap();
        assert_eq!(stored(&s, v, 0x20).password.expose(), made.value);
    }

    /// F-208, FEA-02.17: the popup from the share password starts at that
    /// field's length; with no page open, at the saved length.
    #[test]
    fn fea_02_17_the_popup_starts_at_the_share_passwords_length() {
        let dir = TempDir::new("share-edit-length");
        let (s, v) = open(&dir, &base());
        let saved = s.generator_options(None).length;
        assert_ne!(saved, 11);
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, mode(ShareMode::Export));
        change_page(&s, v, path("team.larsalvault"));
        s.share_edit_password(v, "abcdefghijk".to_owned()).unwrap();
        assert_eq!(s.generator_options(Some(v)).length, 11);
        s.share_edit_cancel(v).unwrap();
        assert_eq!(s.generator_options(Some(v)).length, saved);
    }

    /// T41: only the share group gets a badge; the label of a subgroup is
    /// its share's, with MI08-16 while import is off; an expired share is
    /// inactive.
    #[test]
    fn t41_int08_24_the_share_group_alone_gets_the_badge_and_its_label_reaches_its_subgroups() {
        let dir = TempDir::new("share-edit-t41");
        let mut vault = base();
        set_share(team(&mut vault), settings(true, false, "team.larsalvault"));
        let (s, v) = open(&dir, &vault);
        flags(&s, false, true, true);
        let mark = |active| {
            vec![ShareMark {
                group: hx(id(0x20)),
                active,
            }]
        };
        assert_eq!(s.share_marks(v).unwrap(), mark(false));
        let label = s.share_label(v, hx(id(0x21))).unwrap().unwrap();
        assert_eq!(
            (label.state, label.mode, label.path.as_str()),
            (ShareState::Running, ShareMode::Import, "team.larsalvault")
        );
        assert_eq!((label.import_off, label.export_off), (true, false));
        assert_eq!(label.name, "Team");
        flags(&s, true, false, true);
        assert_eq!(s.share_marks(v).unwrap(), mark(true));
        let label = s.share_label(v, hx(id(0x20))).unwrap().unwrap();
        assert_eq!(
            (label.import_off, label.export_off),
            (false, false),
            "F-177: an Import share with export off"
        );
        assert_eq!(
            s.share_label(v, hx(id(0x01))).unwrap(),
            None,
            "the root is not inside a share"
        );
        let mail = s.entry(v, hx(id(0x0A))).unwrap();
        assert_eq!(
            mail.group_id,
            hx(id(0x20)),
            "the Group field's tile takes the badge"
        );
        change(&s, v, |m| {
            let t = team(m);
            (t.times.expires, t.times.expiry) = (true, Time(63_902_822_400));
        });
        assert_eq!(s.share_marks(v).unwrap(), mark(false), "expired: inactive");
        change(&s, v, |m| {
            set_share(team(m), settings(false, true, "team.larsalvault"))
        });
        flags(&s, false, true, true);
        let label = s.share_label(v, hx(id(0x20))).unwrap().unwrap();
        assert_eq!(
            (label.mode, label.import_off, label.export_off),
            (ShareMode::Export, false, false),
            "F-177: an Export share with import off"
        );
    }

    /// F-178, APP-08.7: All entries is the root group, so its Sharing page
    /// opens from the sidebar's root id.
    #[test]
    fn f178_app_08_7_all_entries_opens_the_root_groups_sharing_page() {
        let dir = TempDir::new("share-edit-root");
        let (s, v) = open(&dir, &base());
        let root = s.sidebar(v).unwrap().root;
        assert_eq!(root, hx(id(0x01)));
        let page = s.share_edit(v, root).unwrap();
        assert_eq!(page.mode, ShareMode::Inactive);
    }

    /// F-268 (INT-08.4, AT-A08): a share item from outside Larsal with an
    /// 8 MiB path is invalid before any decoding, so the calls of each
    /// refresh never decode it: the label is MI08-25 and nothing runs. The
    /// longest item the editor writes still reads; a longer value or path
    /// does not.
    #[test]
    fn f268_int08_4_a_huge_share_item_is_invalid() {
        let dir = TempDir::new("share-edit-f268");
        let mut vault = base();
        set_share(
            team(&mut vault),
            settings(false, true, &"a/".repeat(4 << 20)),
        );
        let (s, v) = open(&dir, &vault);
        let label = s.share_label(v, hx(id(0x20))).unwrap().unwrap();
        assert_eq!(
            (
                label.state,
                label.mode,
                label.path.as_str(),
                label.full_path.as_str()
            ),
            (ShareState::Off, ShareMode::Inactive, "", "")
        );
        assert!(!s.share_marks(v).unwrap()[0].active);
        let mut g = Group::new(id(0x22), "Edge".into(), T2);
        let mut longest = settings(true, false, &"a".repeat(MAX_PATH));
        longest.password = SecretString::new("x".repeat(crate::session::MAX_TEXT));
        set_share(&mut g, longest);
        assert!(
            matches!(share_item::of(&g), Some(Item::Settings(_))),
            "the editor's longest"
        );
        let mut big = settings(true, false, "team.larsalvault");
        big.password = SecretString::new("x".repeat(share_item::MAX_VALUE));
        set_share(&mut g, big);
        assert!(
            matches!(share_item::of(&g), Some(Item::Invalid)),
            "value over the bound"
        );
        set_share(&mut g, settings(true, false, &"a".repeat(MAX_PATH + 1)));
        assert!(
            matches!(share_item::of(&g), Some(Item::Invalid)),
            "path over the bound"
        );
    }

    /// T42 and LD-270 (3): an inactive or unreadable share shows MI08-25; a
    /// share not approved on this Mac shows MI08-18 with its full path and
    /// the inactive badge until Approve; a share of the root shows no label.
    #[test]
    fn t42_ld_270_3_inactive_unreadable_and_waiting_shares() {
        let dir = TempDir::new("share-edit-t42");
        let mut vault = base();
        set_share(team(&mut vault), settings(false, false, "team.larsalvault"));
        let (s, v) = open(&dir, &vault);
        let off = s.share_label(v, hx(id(0x20))).unwrap().unwrap();
        assert_eq!(
            (off.state, off.mode),
            (ShareState::Off, ShareMode::Inactive)
        );
        change(&s, v, |m| {
            let key = std::str::from_utf8(share_item::KEY).unwrap();
            let t = team(m);
            t.custom_data
                .items
                .iter_mut()
                .find(|i| i.key == key)
                .unwrap()
                .value = larsal_crypto::secret::SecretString::new("x".into());
        });
        let bad = s.share_label(v, hx(id(0x20))).unwrap().unwrap();
        assert_eq!(
            (bad.state, bad.mode, bad.path.as_str()),
            (ShareState::Off, ShareMode::Inactive, "")
        );
        let page = s.share_edit(v, hx(id(0x20))).unwrap();
        assert!(page.item, "an unreadable item keeps Clear on");
        s.share_edit_save(v).unwrap();
        assert!(
            matches!(item(&s, v, 0x20), Some(Item::Invalid)),
            "an unchanged page writes nothing"
        );
        // Set up by another app: waiting for approval.
        change(&s, v, |m| {
            set_share(team(m), settings(true, false, "team.larsalvault"))
        });
        let wait = s.share_label(v, hx(id(0x21))).unwrap().unwrap();
        assert_eq!(wait.state, ShareState::Waiting);
        assert_eq!(
            wait.full_path,
            dir.join("team.larsalvault").to_string_lossy()
        );
        assert!(
            !s.share_marks(v).unwrap()[0].active,
            "LD-270 (3): inactive badge"
        );
        s.approve_share(v, wait.group).unwrap();
        s.share_wait(v);
        assert_eq!(
            s.share_label(v, hx(id(0x21))).unwrap().unwrap().state,
            ShareState::Running
        );
        assert!(s.share_marks(v).unwrap()[0].active);
        change(&s, v, |m| {
            let item = team(m).custom_data.items.pop().unwrap();
            m.root.custom_data.items.push(item);
        });
        assert_eq!(
            s.share_label(v, hx(id(0x21))).unwrap(),
            None,
            "a root share shows no label"
        );
    }

    #[test]
    fn t43_int08_25_one_row_per_share_in_tree_order() {
        let dir = TempDir::new("share-edit-t43");
        let mut vault = base();
        set_share(team(&mut vault), settings(true, true, "team.larsalvault"));
        let sub = team(&mut vault).groups.first_mut().unwrap();
        set_share(sub, settings(true, false, "/demo/x.larsalvault"));
        let (s, v) = open(&dir, &vault);
        let rows = s.share_rows(v).unwrap();
        let seen: Vec<_> = rows
            .iter()
            .map(|r| (r.names.as_str(), r.mode, r.path.as_str(), r.active))
            .collect();
        assert_eq!(
            seen,
            [
                ("Team", ShareMode::Synchronize, "team.larsalvault", true),
                ("Team > Sub", ShareMode::Import, "/demo/x.larsalvault", true),
            ]
        );
        assert_eq!(rows[0].group, hx(id(0x20)));
    }

    #[test]
    fn t65_int08_3_each_new_share_gets_its_own_group_id() {
        let dir = TempDir::new("share-edit-t65");
        let (s, v) = open(&dir, &base());
        for (n, p) in [(0x20, "a.larsalvault"), (0x21, "b.larsalvault")] {
            s.share_edit(v, hx(id(n))).unwrap();
            change_page(&s, v, mode(ShareMode::Import));
            change_page(&s, v, path(p));
            s.share_edit_save(v).unwrap();
        }
        let (a, b) = (stored(&s, v, 0x20).group, stored(&s, v, 0x21).group);
        assert_ne!(a, b);
        assert!(!a.is_zero() && !b.is_zero());
        write(&dir.join("unused.larsalvault"), &base(), MAIN);
    }

    #[test]
    fn failed_group_save_retains_the_changed_draft() {
        let dir = TempDir::new("share-edit-save-retains-draft");
        let (s, v) = open(&dir, &base());
        s.share_edit(v, hx(id(0x20))).unwrap();
        change_page(&s, v, path("pending.larsalvault"));
        change(&s, v, |m| {
            m.root.groups.retain(|g| g.uuid != id(0x20));
        });
        assert_eq!(s.share_edit_save(v), Err(LarsalError::UnknownGroup));
        let retained = s
            .with_share(v, |slot| {
                slot.share
                    .draft
                    .as_ref()
                    .map(|d| (d.group, d.settings.path.clone(), d.changed))
            })
            .unwrap();
        assert_eq!(
            retained,
            Some((id(0x20), "pending.larsalvault".into(), true)),
            "a refused Save keeps the user's changed draft"
        );
    }
}
