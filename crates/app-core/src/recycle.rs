//! The recycle bin (MOD-04): which group it is, the delete decision, moving
//! into it, deleting for good with deleted-object records, emptying,
//! restoring, and turning it off.
//!
//! Guarantees: every delete for good adds the records of FMT-15.7 in its
//! order with one time; moving into the bin, restoring and emptying an
//! empty bin add none (FMT-15.8); metadata group references and last top
//! visible entries that named a removed item are cleared, so the vault
//! keeps its invariants and saves and reads back the same (MOD-02.28).

use crate::edit::{Position, find_ascii_ci, holds_reference};
use crate::{Error, edit, tree};
use app_model::entry::STANDARD_FIELDS;
use app_model::{DeletedObject, Field, Group, Icon, Switch, Time, Uuid, Vault};
use std::collections::HashSet;

/// The name of a new recycle bin (MOD-04.2, the App interface string).
pub const BIN_NAME: &str = "Recycle Bin";
/// The icon of a new recycle bin (MOD-04.2).
pub const BIN_ICON: i32 = 43;

/// The bin's id (MOD-04.1): `RecycleBinUUID` when it names a group of the
/// tree that is not the root (LD-76: a root bin means no bin).
#[must_use]
pub fn bin_id(vault: &Vault) -> Option<Uuid> {
    vault
        .meta
        .recycle_bin
        .filter(|&id| id != vault.root.uuid && tree::group(vault, id).is_some())
}

/// True when group `id` is the bin or lies inside it (MOD-02.18).
#[must_use]
pub fn group_in_bin(vault: &Vault, id: Uuid) -> bool {
    bin_id(vault).is_some_and(|bin| tree::within(vault, id, bin))
}

/// True when live entry `id` sits in the bin or a group inside it.
#[must_use]
pub fn entry_in_bin(vault: &Vault, id: Uuid) -> bool {
    tree::entry_group(vault, id).is_some_and(|g| group_in_bin(vault, g))
}

/// Whether new entries, new groups and clones may be made in `group`
/// (MOD-04.15: never inside the bin).
#[must_use]
pub fn can_create_in(vault: &Vault, group: Uuid) -> bool {
    tree::group(vault, group).is_some() && !group_in_bin(vault, group)
}

/// Whether Empty is offered (MOD-04.9, MOD-04.13): only while the bin is on
/// and exists.
#[must_use]
pub fn can_empty(vault: &Vault) -> bool {
    vault.meta.recycle_bin_enabled && bin_id(vault).is_some()
}

/// The bin, made when missing (MOD-04.2): a new last child of the root
/// named `Recycle Bin`, icon 43, searching and auto-type Off, all times
/// `now`; `RecycleBinUUID` names it and `RecycleBinChanged` is `now`. The
/// root's times do not move.
pub(crate) fn ensure_bin(vault: &mut Vault, now: Time) -> Result<Uuid, Error> {
    if let Some(id) = bin_id(vault) {
        return Ok(id);
    }
    let taken: HashSet<Uuid> = vault.root.subtree().iter().map(|g| g.uuid).collect();
    let id = tree::fresh_id(|u| taken.contains(&u))?;
    let mut bin = Group::new(id, BIN_NAME.to_owned(), now);
    bin.icon = Icon::Standard(BIN_ICON);
    bin.searching = Switch::Off;
    bin.auto_type = Switch::Off;
    vault.root.groups.push(bin);
    vault.meta.recycle_bin = Some(id);
    vault.meta.recycle_bin_changed = now;
    Ok(id)
}

/// The user's answer when an entry to delete for good is referenced by
/// other entries (MOD-04.6, MOD-08.27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum References {
    /// Overwrite each referencing field with the entry's value, then delete
    /// (the default).
    Overwrite,
    /// Keep this entry.
    Skip,
    /// Delete and leave the references dangling.
    Delete,
}

/// What a delete did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Deleted {
    /// Items moved into the bin.
    pub to_bin: usize,
    /// Items deleted for good.
    pub for_good: usize,
    /// Entries kept because the user chose Skip.
    pub skipped: usize,
}

/// `id` as 32 lower-case hex digits (an id, not a secret).
fn hex(id: Uuid) -> String {
    id.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// True when `value` holds a field reference and `hex` in any case. Reads
/// the value in place, so a secret is never copied (E4-B1).
fn refers_to(value: &str, hex: &str) -> bool {
    holds_reference(value) && find_ascii_ci(value.as_bytes(), hex.as_bytes()).is_some()
}

/// The live entries, outside `except`, whose standard field holds a
/// reference that contains `id`'s hex id in any case and whose search scope
/// holds `id` (MOD-08.27, MOD-08.32): an entry inside a share group that
/// refers to `id` outside it is left out, so Overwrite never copies a value
/// into the share (LD-284 (2)).
#[must_use]
pub fn referencing(vault: &Vault, id: Uuid, except: &[Uuid]) -> Vec<Uuid> {
    let hex = hex(id);
    let mut out = Vec::new();
    for g in vault.root.subtree() {
        for e in g
            .entries
            .iter()
            .filter(|e| e.uuid != id && !except.contains(&e.uuid))
        {
            if STANDARD_FIELDS.iter().any(|n| refers_to(e.value(n), &hex))
                && crate::refs::in_scope(vault, e, id)
            {
                out.push(e.uuid);
            }
        }
    }
    out
}

/// Deletes live entries (MOD-04.4): each one goes to the bin, or is deleted
/// for good when the bin is off or the entry is already in the bin, decided
/// per entry (L04-1). An id given twice counts once. Moving to the bin makes the bin when needed and sets
/// previous parent, location changed and, when the previous parent changes,
/// last modification and last access (MOD-04.5); no history item, no
/// record. Before an entry is deleted for good, entries outside the
/// selection that reference it are found and `ask(entry, count)` decides
/// (MOD-04.6); Overwrite puts the entry's raw value of the same field name
/// in each referencing field and moves those entries' modification and
/// access times. Each entry deleted for good adds one record (MOD-04.7).
/// Group times do not move (MOD-02.25, App column).
///
/// # Errors
/// `NoSuchEntry` for any id (nothing changes then); `RandomSource`.
pub fn delete_entries(
    vault: &mut Vault,
    ids: &[Uuid],
    now: Time,
    mut ask: impl FnMut(Uuid, usize) -> References,
) -> Result<Deleted, Error> {
    if ids.iter().any(|&id| tree::entry(vault, id).is_none()) {
        return Err(Error::NoSuchEntry);
    }
    let mut seen = HashSet::with_capacity(ids.len());
    let ids: Vec<Uuid> = ids.iter().copied().filter(|&id| seen.insert(id)).collect();
    let mut out = Deleted::default();
    for &id in &ids {
        if !vault.meta.recycle_bin_enabled || entry_in_bin(vault, id) {
            let refs = referencing(vault, id, &ids);
            if !refs.is_empty() {
                match ask(id, refs.len()) {
                    References::Skip => {
                        out.skipped = out.skipped.saturating_add(1);
                        continue;
                    }
                    References::Overwrite => overwrite_references(vault, id, &refs, now),
                    References::Delete => {}
                }
            }
            take_entry(vault, id, now)?;
            out.for_good = out.for_good.saturating_add(1);
        } else {
            let bin = ensure_bin(vault, now)?;
            edit::move_one_entry(vault, id, bin, now)?;
            out.to_bin = out.to_bin.saturating_add(1);
        }
    }
    if out.for_good > 0 {
        clean_references(vault, now);
    }
    Ok(out)
}

/// MOD-08.27 Overwrite: each standard field of a referencing entry that
/// holds a reference to `id` takes `id`'s raw value of the same field name;
/// no history item; modification and access times move.
fn overwrite_references(vault: &mut Vault, id: Uuid, refs: &[Uuid], now: Time) {
    let hex = hex(id);
    let Some(source) = tree::entry(vault, id) else {
        return;
    };
    let values: Vec<(&str, Field)> = STANDARD_FIELDS
        .iter()
        .map(|n| {
            (
                *n,
                source
                    .field(n)
                    .map(Field::duplicate)
                    .unwrap_or_else(Field::empty),
            )
        })
        .collect();
    for &r in refs {
        let Some(e) = tree::entry_mut(vault, r) else {
            continue;
        };
        let mut changed = false;
        for (n, f) in &values {
            if refers_to(e.value(n), &hex) {
                let protected = e.field(n).is_some_and(|x| x.protected);
                e.set_field(
                    (*n).to_owned(),
                    Field {
                        protected,
                        ..f.duplicate()
                    },
                );
                changed = true;
            }
        }
        if changed {
            e.times.last_modification = now;
            e.times.last_access = now;
        }
    }
}

/// Removes live entry `id` for good with its history, adding one record
/// (MOD-04.7, FMT-15.7), and clears last top visible entries naming it.
pub(crate) fn remove_entry_for_good(vault: &mut Vault, id: Uuid, now: Time) -> Result<(), Error> {
    take_entry(vault, id, now)?;
    clean_references(vault, now);
    Ok(())
}

/// [`remove_entry_for_good`] without the reference cleanup, for loops that
/// clean once at the end.
fn take_entry(vault: &mut Vault, id: Uuid, now: Time) -> Result<(), Error> {
    let (path, i) = tree::entry_place(&vault.root, id).ok_or(Error::NoSuchEntry)?;
    let g = tree::group_at_mut(&mut vault.root, &path).ok_or(Error::NoSuchGroup)?;
    if i >= g.entries.len() {
        return Err(Error::NoSuchEntry);
    }
    g.entries.remove(i);
    record(vault, id, now);
    Ok(())
}

fn record(vault: &mut Vault, id: Uuid, now: Time) {
    vault.deleted_objects.push(DeletedObject {
        uuid: id,
        deleted_at: now,
        unknown: Vec::new(),
    });
}

/// The FMT-15.7 group rule: the group's entries in stored order, then each
/// child group by the same rule, then the group itself.
fn group_records(g: &Group) -> Vec<Uuid> {
    enum Step<'a> {
        Open(&'a Group),
        Close(Uuid),
    }
    let mut out = Vec::new();
    let mut stack = vec![Step::Open(g)];
    while let Some(step) = stack.pop() {
        match step {
            Step::Close(id) => out.push(id),
            Step::Open(g) => {
                out.extend(g.entries.iter().map(|e| e.uuid));
                stack.push(Step::Close(g.uuid));
                stack.extend(g.groups.iter().rev().map(Step::Open));
            }
        }
    }
    out
}

/// Removes group `id` for good with everything inside (MOD-04.7, MOD-04.8):
/// records by the FMT-15.7 group rule; references to removed groups and
/// entries cleared; the parent's times do not move. Removing the bin sets
/// `RecycleBinChanged` to `now` (L04-6).
pub(crate) fn remove_group_for_good(vault: &mut Vault, id: Uuid, now: Time) -> Result<(), Error> {
    let path = tree::group_path(&vault.root, id).ok_or(Error::NoSuchGroup)?;
    let Some((&index, parent_path)) = path.split_last() else {
        return Err(Error::RootGroup);
    };
    let parent = tree::group_at_mut(&mut vault.root, parent_path).ok_or(Error::NoSuchGroup)?;
    if index >= parent.groups.len() {
        return Err(Error::NoSuchGroup);
    }
    let g = parent.groups.remove(index);
    for r in group_records(&g) {
        record(vault, r, now);
    }
    clean_references(vault, now);
    Ok(())
}

/// Clears what names a removed item (MOD-02.28, FMT-10.16, FMT-11.37):
/// metadata group references and groups' last top visible entries. One
/// walk of the tree; run once per operation.
pub(crate) fn clean_references(vault: &mut Vault, now: Time) {
    let groups: HashSet<Uuid> = vault.root.subtree().iter().map(|g| g.uuid).collect();
    let entries: HashSet<Uuid> = tree::all_entry_ids(vault).into_iter().collect();
    let m = &mut vault.meta;
    if m.recycle_bin.is_some_and(|b| !groups.contains(&b)) {
        m.recycle_bin = None;
        m.recycle_bin_changed = now;
    }
    for r in [
        &mut m.entry_templates_group,
        &mut m.last_selected_group,
        &mut m.last_top_visible_group,
    ] {
        if r.is_some_and(|g| !groups.contains(&g)) {
            *r = None;
        }
    }
    let mut stack = vec![&mut vault.root];
    while let Some(g) = stack.pop() {
        if g.last_top_visible_entry
            .is_some_and(|e| !entries.contains(&e))
        {
            g.last_top_visible_entry = None;
        }
        stack.extend(g.groups.iter_mut());
    }
}

/// Deletes group `id` (MOD-04.4): for good when the bin is off, the group is
/// in the bin (the bin itself included) or holds the bin below it; else it
/// moves to the end of the bin's child groups with previous parent, location
/// changed, last modification and last access set (MOD-04.5); the group it
/// left, the bin and everything inside keep their times.
///
/// # Errors
/// `NoSuchGroup`; `RootGroup`; `RandomSource`.
pub fn delete_group(vault: &mut Vault, id: Uuid, now: Time) -> Result<Deleted, Error> {
    if id == vault.root.uuid {
        return Err(Error::RootGroup);
    }
    if tree::group(vault, id).is_none() {
        return Err(Error::NoSuchGroup);
    }
    let holds_bin = bin_id(vault).is_some_and(|bin| tree::within(vault, bin, id));
    if !vault.meta.recycle_bin_enabled || group_in_bin(vault, id) || holds_bin {
        remove_group_for_good(vault, id, now)?;
        return Ok(Deleted {
            for_good: 1,
            ..Deleted::default()
        });
    }
    let bin = ensure_bin(vault, now)?;
    edit::move_group(vault, id, bin, Position::End, now)?;
    Ok(Deleted {
        to_bin: 1,
        ..Deleted::default()
    })
}

/// Empties the bin (MOD-04.9): each entry directly in it, then each child
/// group with everything inside, deleted for good with records; the bin
/// stays with its id, name, icon and flags. Only while the bin is on
/// (MOD-04.13). Returns whether anything was removed; an empty bin changes
/// nothing. About O(N + k): one find, one take, one cleanup.
///
/// # Errors
/// `NoSuchGroup` only if the tree changed under the call.
pub fn empty_bin(vault: &mut Vault, now: Time) -> Result<bool, Error> {
    if !can_empty(vault) {
        return Ok(false);
    }
    let Some(bin) = bin_id(vault) else {
        return Ok(false);
    };
    let g = tree::group_mut(vault, bin).ok_or(Error::NoSuchGroup)?;
    if g.entries.is_empty() && g.groups.is_empty() {
        return Ok(false);
    }
    let entries = std::mem::take(&mut g.entries);
    let groups = std::mem::take(&mut g.groups);
    for e in &entries {
        record(vault, e.uuid, now);
    }
    for g in &groups {
        for r in group_records(g) {
            record(vault, r, now);
        }
    }
    clean_references(vault, now);
    Ok(true)
}

/// What a restore did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Restored {
    /// Items moved back.
    pub restored: usize,
    /// Of them, items that went to the root group because their previous
    /// parent is missing or in the bin (L04-2: the user is told once).
    pub to_root: usize,
}

/// Restores entries from the bin (MOD-04.10): each selected entry that is in
/// the bin moves to its previous parent when that group exists and is not
/// in the bin, else to the root group; a move with the MOD-04.5 fields. No
/// history item, no record. Entries outside the bin are never moved.
///
/// # Errors
/// `NoSuchEntry` for any id (nothing moves then).
pub fn restore_entries(vault: &mut Vault, ids: &[Uuid], now: Time) -> Result<Restored, Error> {
    if ids.iter().any(|&id| tree::entry(vault, id).is_none()) {
        return Err(Error::NoSuchEntry);
    }
    let mut out = Restored::default();
    for &id in ids {
        if !entry_in_bin(vault, id) {
            continue;
        }
        let back = tree::entry(vault, id).and_then(|e| e.previous_parent);
        let target = match back {
            Some(g) if tree::group(vault, g).is_some() && !group_in_bin(vault, g) => g,
            _ => {
                out.to_root = out.to_root.saturating_add(1);
                vault.root.uuid
            }
        };
        edit::move_one_entry(vault, id, target, now)?;
        out.restored = out.restored.saturating_add(1);
    }
    Ok(out)
}

/// Restores a group from the bin (MOD-04.11, L04-3) by the rule of
/// [`restore_entries`], with the group's own previous parent; a parent that
/// would put the group inside itself counts as missing (it lies in the bin
/// with the group).
///
/// # Errors
/// `NoSuchGroup`; `RootGroup`.
pub fn restore_group(vault: &mut Vault, id: Uuid, now: Time) -> Result<Restored, Error> {
    let g = tree::group(vault, id).ok_or(Error::NoSuchGroup)?;
    if !group_in_bin(vault, id) || Some(id) == bin_id(vault) {
        return Ok(Restored::default());
    }
    let mut out = Restored {
        restored: 1,
        ..Restored::default()
    };
    let target = match g.previous_parent {
        Some(p) if tree::group(vault, p).is_some() && !group_in_bin(vault, p) => p,
        _ => {
            out.to_root = 1;
            vault.root.uuid
        }
    };
    edit::move_group(vault, id, target, Position::End, now)?;
    Ok(out)
}

/// The vault settings switch "use recycle bin" (MOD-04.12). Turning it off
/// while on: a bin that is not empty is deleted for good when
/// `delete_old_bin`, else it stays as a normal group with ` (old)` added to
/// its name and icon 48; an empty bin stays as it is; either way a group
/// that stops being the bin gets both switches Inherit (L04-4), and
/// `RecycleBinUUID` becomes none, `RecycleBinChanged` `now`. Turning it on
/// sets only the flag. Returns whether anything changed.
///
/// # Errors
/// `NoSuchGroup` only if the tree changed under the call.
pub fn set_bin_enabled(
    vault: &mut Vault,
    enabled: bool,
    delete_old_bin: bool,
    now: Time,
) -> Result<bool, Error> {
    if vault.meta.recycle_bin_enabled == enabled {
        return Ok(false);
    }
    vault.meta.recycle_bin_enabled = enabled;
    if enabled {
        return Ok(true);
    }
    if let Some(bin) = bin_id(vault) {
        let empty =
            tree::group(vault, bin).is_some_and(|g| g.entries.is_empty() && g.groups.is_empty());
        if !empty && delete_old_bin {
            remove_group_for_good(vault, bin, now)?;
        } else {
            edit::edit_group(vault, bin, now, |g| {
                if !empty {
                    g.name.push_str(" (old)");
                    g.icon = edit::default_group_icon();
                }
                g.searching = Switch::Inherit;
                g.auto_type = Switch::Inherit;
            })?;
        }
    }
    vault.meta.recycle_bin = None;
    vault.meta.recycle_bin_changed = now;
    Ok(true)
}

/// A browser-bridge delete request after the user confirmed (MOD-04.15):
/// with the bin on, the entry moves to the bin unless it is already in it
/// (then nothing happens); with the bin off it is deleted for good, the
/// references to it left as they are.
///
/// # Errors
/// `NoSuchEntry`; `RandomSource`.
pub fn delete_by_request(vault: &mut Vault, id: Uuid, now: Time) -> Result<Deleted, Error> {
    if vault.meta.recycle_bin_enabled && entry_in_bin(vault, id) {
        return if tree::entry(vault, id).is_some() {
            Ok(Deleted::default())
        } else {
            Err(Error::NoSuchEntry)
        };
    }
    delete_entries(vault, &[id], now, |_, _| References::Delete)
}
