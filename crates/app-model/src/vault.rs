//! The vault: metadata, settings, protection flags, history limits, recycle
//! bin, the group tree, deleted objects and the encryption settings (FMT-10,
//! FMT-15, MOD-12, LD-82).

use crate::custom_data::CustomData;
use crate::group::Group;
use crate::icon::CustomIcon;
use crate::settings::{Encryption, PublicItem};
use crate::times::Time;
use crate::unknown::UnknownElement;
use crate::uuid::Uuid;

/// Name written as `Generator` for vaults App makes (FMT-10.22).
pub const GENERATOR: &str = "App";

/// The five vault-level field protection flags (FMT-10.17, MOD-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryProtection {
    /// `ProtectTitle`, default false.
    pub title: bool,
    /// `ProtectUserName`, default false.
    pub user_name: bool,
    /// `ProtectPassword`, default true.
    pub password: bool,
    /// `ProtectURL`, default false.
    pub url: bool,
    /// `ProtectNotes`, default false.
    pub notes: bool,
    /// Kept unknown children of `MemoryProtection`.
    pub unknown: Vec<UnknownElement>,
}

impl Default for MemoryProtection {
    /// Only the password protected.
    fn default() -> Self {
        MemoryProtection {
            title: false,
            user_name: false,
            password: true,
            url: false,
            notes: false,
            unknown: Vec::new(),
        }
    }
}

impl MemoryProtection {
    /// The vault flag for a standard field name, false for any other name.
    #[must_use]
    pub fn for_field(&self, name: &str) -> bool {
        match name {
            "Title" => self.title,
            "UserName" => self.user_name,
            "Password" => self.password,
            "URL" => self.url,
            "Notes" => self.notes,
            _ => false,
        }
    }
}

/// The vault metadata (the FMT-10.10 table, rows 1 and 3 to 28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// `Generator`: kept as read; `App` when missing or for a new vault.
    pub generator: String,
    /// `DatabaseName`.
    pub name: String,
    /// `DatabaseNameChanged`.
    pub name_changed: Time,
    /// `DatabaseDescription`.
    pub description: String,
    /// `DatabaseDescriptionChanged`.
    pub description_changed: Time,
    /// `DefaultUserName`.
    pub default_user_name: String,
    /// `DefaultUserNameChanged`.
    pub default_user_name_changed: Time,
    /// `MaintenanceHistoryDays`, default 365, carried.
    pub maintenance_history_days: i32,
    /// `Color`, kept as read.
    pub color: String,
    /// `MasterKeyChanged`.
    pub master_key_changed: Time,
    /// `MasterKeyChangeRec`, days, -1 off.
    pub master_key_change_rec: i32,
    /// `MasterKeyChangeForce`, days, -1 off.
    pub master_key_change_force: i32,
    /// `MasterKeyChangeForceOnce` (MOD-13.13, LD-62).
    pub master_key_change_force_once: bool,
    /// `MemoryProtection`.
    pub memory_protection: MemoryProtection,
    /// `CustomIcons`, in stored order.
    pub custom_icons: Vec<CustomIcon>,
    /// Kept unknown children of `CustomIcons`.
    pub custom_icons_unknown: Vec<UnknownElement>,
    /// `RecycleBinEnabled`, default true.
    pub recycle_bin_enabled: bool,
    /// `RecycleBinUUID`, resolved: names a group of the tree, or none.
    pub recycle_bin: Option<Uuid>,
    /// `RecycleBinChanged`.
    pub recycle_bin_changed: Time,
    /// `EntryTemplatesGroup`, resolved; carried only.
    pub entry_templates_group: Option<Uuid>,
    /// `EntryTemplatesGroupChanged`.
    pub entry_templates_group_changed: Time,
    /// `LastSelectedGroup`, resolved; carried only.
    pub last_selected_group: Option<Uuid>,
    /// `LastTopVisibleGroup`, resolved; carried only.
    pub last_top_visible_group: Option<Uuid>,
    /// `HistoryMaxItems`, -1 no limit, default 10.
    pub history_max_items: i32,
    /// `HistoryMaxSize`, bytes, -1 no limit, default 6,291,456.
    pub history_max_size: i32,
    /// `SettingsChanged`.
    pub settings_changed: Time,
    /// Vault custom data.
    pub custom_data: CustomData,
    /// Kept unknown children of `Meta`.
    pub unknown: Vec<UnknownElement>,
}

impl Meta {
    /// The FMT-10.10 defaults, every time `t` (creation time for a new vault,
    /// open time for a read without `Meta`).
    #[must_use]
    pub fn new(t: Time) -> Meta {
        Meta {
            generator: GENERATOR.to_owned(),
            name: String::new(),
            name_changed: t,
            description: String::new(),
            description_changed: t,
            default_user_name: String::new(),
            default_user_name_changed: t,
            maintenance_history_days: 365,
            color: String::new(),
            master_key_changed: t,
            master_key_change_rec: -1,
            master_key_change_force: -1,
            master_key_change_force_once: false,
            memory_protection: MemoryProtection::default(),
            custom_icons: Vec::new(),
            custom_icons_unknown: Vec::new(),
            recycle_bin_enabled: true,
            recycle_bin: None,
            recycle_bin_changed: t,
            entry_templates_group: None,
            entry_templates_group_changed: t,
            last_selected_group: None,
            last_top_visible_group: None,
            history_max_items: 10,
            history_max_size: 6_291_456,
            settings_changed: t,
            custom_data: CustomData::default(),
            unknown: Vec::new(),
        }
    }
}

/// One deleted-object record (FMT-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedObject {
    /// Id of the deleted group, entry or custom icon; never zero.
    pub uuid: Uuid,
    /// When it was deleted.
    pub deleted_at: Time,
    /// Kept unknown children of `DeletedObject`.
    pub unknown: Vec<UnknownElement>,
}

/// A file version: major and minor (FMT-01, FMT-16.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileVersion {
    /// 3 or 4.
    pub major: u16,
    /// Minor version as stored.
    pub minor: u16,
}

/// A whole vault.
///
/// Guarantees: exactly one root group and no group cycles, by construction;
/// the other invariants are checked by `invariants::check`.
#[derive(PartialEq, Eq)]
pub struct Vault {
    /// The metadata.
    pub meta: Meta,
    /// The root group.
    pub root: Group,
    /// Deleted-object records in stored order, never pruned (FMT-15.9).
    pub deleted_objects: Vec<DeletedObject>,
    /// Kept unknown children of the document's root element (FMT-10.20).
    pub unknown_document: Vec<UnknownElement>,
    /// Kept unknown children of `Root` (FMT-10.20).
    pub unknown_root: Vec<UnknownElement>,
    /// Kept unknown children of `DeletedObjects` (FMT-15.4).
    pub unknown_deleted_objects: Vec<UnknownElement>,
    /// The version of the file this vault was read from, if any. The writer
    /// keeps at least this version while unknown parts are kept (FMT-16.24).
    pub read_version: Option<FileVersion>,
    /// Cipher, KDF and compression (LD-82): read from the header, used by
    /// the writer.
    pub encryption: Encryption,
    /// Public custom data of the outer header, kept as stored (FMT-03.22).
    pub public_custom_data: Vec<PublicItem>,
}

impl Vault {
    /// A vault holding `root`, with the FMT-10.10 defaults at time `now`.
    #[must_use]
    pub fn new(root: Group, now: Time) -> Vault {
        Vault {
            meta: Meta::new(now),
            root,
            deleted_objects: Vec::new(),
            unknown_document: Vec::new(),
            unknown_root: Vec::new(),
            unknown_deleted_objects: Vec::new(),
            read_version: None,
            encryption: Encryption::default(),
            public_custom_data: Vec::new(),
        }
    }
}

impl Vault {
    /// A deep copy of the whole vault: metadata, tree with histories,
    /// deleted objects, kept unknown parts, settings (a merge dry run works
    /// on one, MOD-11.25).
    #[must_use]
    pub fn duplicate(&self) -> Vault {
        Vault {
            meta: self.meta.clone(),
            root: self.root.duplicate(),
            deleted_objects: self.deleted_objects.clone(),
            unknown_document: self.unknown_document.clone(),
            unknown_root: self.unknown_root.clone(),
            unknown_deleted_objects: self.unknown_deleted_objects.clone(),
            read_version: self.read_version,
            encryption: self.encryption,
            public_custom_data: self.public_custom_data.clone(),
        }
    }
}

/// Ids, counts and flags only, never user text (LD-88): logs and crash
/// reports can never carry vault content, even by mistake.
impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let groups = self.root.subtree();
        let entries: usize = groups.iter().map(|g| g.entries.len()).sum();
        let history: usize = groups
            .iter()
            .flat_map(|g| g.entries.iter())
            .map(|e| e.history.len())
            .sum();
        f.debug_struct("Vault")
            .field("root", &self.root.uuid)
            .field("groups", &groups.len())
            .field("entries", &entries)
            .field("history_items", &history)
            .field("custom_icons", &self.meta.custom_icons.len())
            .field("deleted_objects", &self.deleted_objects.len())
            .field("recycle_bin_enabled", &self.meta.recycle_bin_enabled)
            .field("read_version", &self.read_version)
            .field("encryption", &self.encryption)
            .field("public_custom_data", &self.public_custom_data.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_field_maps_every_standard_field() {
        // Each flag on alone turns on exactly its own field (MOD-12, FMT-09.19).
        let names = ["Title", "UserName", "Password", "URL", "Notes"];
        for (i, on) in names.iter().enumerate() {
            let mut mp = MemoryProtection {
                title: false,
                user_name: false,
                password: false,
                url: false,
                notes: false,
                unknown: Vec::new(),
            };
            match i {
                0 => mp.title = true,
                1 => mp.user_name = true,
                2 => mp.password = true,
                3 => mp.url = true,
                _ => mp.notes = true,
            }
            for (j, name) in names.iter().enumerate() {
                assert_eq!(mp.for_field(name), i == j, "flag {on}, field {name}");
            }
            assert!(!mp.for_field("Custom"));
            assert!(!mp.for_field("url"), "names are case-sensitive");
        }
    }

    // FMT-10.10 defaults of a new vault (model part).
    #[test]
    fn fmt_10_10_defaults() {
        let m = Meta::new(Time(7));
        assert_eq!(m.generator, "App");
        assert_eq!(m.maintenance_history_days, 365);
        assert_eq!(
            (m.master_key_change_rec, m.master_key_change_force),
            (-1, -1)
        );
        assert!(m.recycle_bin_enabled);
        assert_eq!((m.history_max_items, m.history_max_size), (10, 6_291_456));
        let p = &m.memory_protection;
        assert!(p.password && !p.title && !p.user_name && !p.url && !p.notes);
        assert!(m.recycle_bin.is_none() && m.entry_templates_group.is_none());
        assert!(m.last_selected_group.is_none() && m.last_top_visible_group.is_none());
        assert_eq!(m.settings_changed, Time(7));
        assert!(p.for_field("Password") && !p.for_field("password"));
    }
}
