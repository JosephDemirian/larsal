//! Cloning (MOD-10): one entry with options, and a group with everything
//! below it. Copies by drag inside one vault and between vaults are
//! `edit::copy_within`, `edit::copy_into` and `edit::move_into`
//! (MOD-10.11, MOD-10.12).
//!
//! Guarantees: a clone never reuses an id of the vault (fresh version 4
//! ids, CRY-03.11); the original is never changed; cloning never adds a
//! history item; a clone that would pass the reader's count limits is
//! refused and changes nothing (MOD-10 security notes).

use crate::edit::Position;
use crate::refs::reference;
use crate::{Error, origin, recycle, tree};
use larsal_model::custom_data::CustomData;
use larsal_model::{Entry, Field, Group, Time, Uuid, Vault};
use std::collections::HashSet;

/// The reader's count limits a clone must stay within (FMT-08.12; MOD-10
/// security notes). Tests lower them; a test ties the defaults to
/// larsal-format's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `groups`.
    pub groups: usize,
    /// `entries`.
    pub entries: usize,
    /// `entry elements`: live entries plus history items.
    pub entry_elements: usize,
}

impl Limits {
    /// The decided values.
    pub const DEFAULT: Self = Self {
        groups: 1_000_000,
        entries: 1_000_000,
        entry_elements: 4_000_000,
    };
}

/// The clone entry dialog's options (MOD-10.1). The default is the
/// dialog's: suffix on, references off, history on; it never remembers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// `clone.suffix`: the title gets ` - Clone` (MOD-10.4).
    pub suffix: bool,
    /// `clone.refs`: UserName and Password become references to the
    /// original (MOD-10.5).
    pub refs: bool,
    /// `clone.history`: the history is copied (MOD-10.6).
    pub history: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            suffix: true,
            refs: false,
            history: true,
        }
    }
}

/// The title suffix (MOD-10.4), in the UI language (English here).
pub const SUFFIX: &str = " - Clone";

/// Whether `entry.clone` is enabled (MOD-10 actions): exactly one entry
/// selected, and neither the current group nor that entry in the bin.
#[must_use]
pub fn can_clone_entry(vault: &Vault, selected: &[Uuid], current_group: Option<Uuid>) -> bool {
    match selected {
        [one] => {
            tree::entry(vault, *one).is_some()
                && !recycle::entry_in_bin(vault, *one)
                && !current_group.is_some_and(|g| recycle::group_in_bin(vault, g))
        }
        _ => false,
    }
}

/// Whether `group.clone` is enabled: neither the root nor the bin.
#[must_use]
pub fn can_clone_group(vault: &Vault, id: Uuid) -> bool {
    id != vault.root.uuid && Some(id) != recycle::bin_id(vault) && tree::group(vault, id).is_some()
}

/// Every group, live entry and entry element (live entries plus history
/// items) of the vault.
fn counts(vault: &Vault) -> (usize, usize, usize) {
    let groups = vault.root.subtree();
    let entries = groups.iter().map(|g| g.entries.len()).sum::<usize>();
    let items = groups
        .iter()
        .flat_map(|g| g.entries.iter())
        .map(|e| e.history.len().saturating_add(1))
        .sum::<usize>();
    (groups.len(), entries, items)
}

/// Refuses adding `groups`, `entries` and `items` when a count limit would
/// pass.
fn check_counts(
    vault: &Vault,
    limits: &Limits,
    groups: usize,
    entries: usize,
    items: usize,
) -> Result<(), Error> {
    let (g, e, i) = counts(vault);
    if g.saturating_add(groups) > limits.groups
        || e.saturating_add(entries) > limits.entries
        || i.saturating_add(items) > limits.entry_elements
    {
        return Err(Error::TooLarge);
    }
    Ok(())
}

/// Turns a copy into a clone: a new id not in `taken`, creation,
/// modification, access and location times `now`; expiry and usage count
/// kept (MOD-10.2); history items take the new id and keep their times
/// (MOD-10.6).
fn fresh(e: &mut Entry, taken: &mut HashSet<Uuid>, now: Time) -> Result<(), Error> {
    let id = tree::fresh_id(|u| taken.contains(&u))?;
    taken.insert(id);
    e.uuid = id;
    let t = &mut e.times;
    (
        t.creation,
        t.last_modification,
        t.last_access,
        t.location_changed,
    ) = (now, now, now, now);
    for h in &mut e.history {
        h.uuid = id;
    }
    Ok(())
}

/// Clones live entry `id` with the dialog's options (MOD-10.2 to MOD-10.8)
/// into the original's group, after its last entry. Every stored value is
/// copied, the previous parent included (MOD-10.3, LD-107); the suffix and
/// the references reach the clone's current version only, history items
/// are copied unchanged (MOD-10.7, D-10-1). Returns the clone's id.
///
/// # Errors
/// `NoSuchEntry`; `TooLarge` past a count limit; `RandomSource`.
pub fn clone_entry(
    vault: &mut Vault,
    id: Uuid,
    options: Options,
    limits: &Limits,
    now: Time,
) -> Result<Uuid, Error> {
    let original = tree::entry(vault, id).ok_or(Error::NoSuchEntry)?;
    let group = tree::entry_group(vault, id).ok_or(Error::NoSuchEntry)?;
    let mut clone = original.duplicate(options.history);
    // INT-08.32: a clone is a new object; no user's move or share brought it.
    origin::keep_own(&CustomData::default(), &mut clone.custom_data);
    check_counts(vault, limits, 0, 1, clone.history.len().saturating_add(1))?;
    let mut taken: HashSet<Uuid> = tree::all_entry_ids(vault).into_iter().collect();
    fresh(&mut clone, &mut taken, now)?;
    if options.suffix {
        let title = format!("{}{SUFFIX}", clone.value("Title"));
        let protected = clone.field("Title").is_some_and(|f| f.protected);
        clone.set_field("Title".into(), text_field(title, protected));
    }
    if options.refs {
        for (name, code) in [("UserName", 'U'), ("Password", 'P')] {
            let protected = clone.field(name).is_some_and(|f| f.protected);
            clone.set_field(name.into(), text_field(reference(code, id), protected));
        }
    }
    let new = clone.uuid;
    tree::group_mut(vault, group)
        .ok_or(Error::NoSuchGroup)?
        .entries
        .push(clone);
    Ok(new)
}

fn text_field(value: String, protected: bool) -> Field {
    Field {
        value: larsal_crypto::secret::SecretString::new(value),
        protected,
    }
}

/// Clones group `id` with everything below it (MOD-10.10), not yet in the
/// vault: every group gets a new id, all times `now` and ` - Clone` after
/// its name; every entry is cloned as MOD-10.2 and MOD-10.3 with its
/// history, no title suffix and no references. The group editor opens it;
/// [`add_group_clone`] commits it, dropping it is Cancel.
///
/// # Errors
/// `NoSuchGroup`; `RootGroup` for the root; `InRecycleBin` for the bin;
/// `TooLarge` past a count limit; `RandomSource`.
pub fn clone_group(vault: &Vault, id: Uuid, limits: &Limits, now: Time) -> Result<Group, Error> {
    if id == vault.root.uuid {
        return Err(Error::RootGroup);
    }
    if Some(id) == recycle::bin_id(vault) {
        return Err(Error::InRecycleBin);
    }
    let original = tree::group(vault, id).ok_or(Error::NoSuchGroup)?;
    let mut copy = original.duplicate();
    origin::clear_tree(&mut copy);
    let sub = copy.subtree();
    let (g, e) = (
        sub.len(),
        sub.iter().map(|x| x.entries.len()).sum::<usize>(),
    );
    let items = sub
        .iter()
        .flat_map(|x| x.entries.iter())
        .map(|x| x.history.len().saturating_add(1))
        .sum::<usize>();
    check_counts(vault, limits, g, e, items)?;
    let mut groups: HashSet<Uuid> = vault.root.subtree().iter().map(|x| x.uuid).collect();
    let mut entries: HashSet<Uuid> = tree::all_entry_ids(vault).into_iter().collect();
    let mut stack = vec![&mut copy];
    while let Some(c) = stack.pop() {
        c.uuid = tree::fresh_id(|u| groups.contains(&u))?;
        groups.insert(c.uuid);
        let t = &mut c.times;
        (
            t.creation,
            t.last_modification,
            t.last_access,
            t.location_changed,
        ) = (now, now, now, now);
        c.name.push_str(SUFFIX);
        c.last_top_visible_entry = None;
        for e in &mut c.entries {
            fresh(e, &mut entries, now)?;
        }
        stack.extend(c.groups.iter_mut());
    }
    Ok(copy)
}

/// Commits a group clone (MOD-10.10 OK): under the original's parent, after
/// its last child group. Ids that the vault took meanwhile are replaced.
///
/// # Errors
/// `NoSuchGroup` when the original or its parent is gone; `TooDeep`
/// (LD-106); `RandomSource`.
pub fn add_group_clone(
    vault: &mut Vault,
    original: Uuid,
    mut clone: Group,
    now: Time,
) -> Result<Uuid, Error> {
    let path = tree::group_path(&vault.root, original).ok_or(Error::NoSuchGroup)?;
    let parent_path = path.split_last().map(|(_, p)| p).ok_or(Error::RootGroup)?;
    let parent = tree::group_at(&vault.root, parent_path)
        .ok_or(Error::NoSuchGroup)?
        .uuid;
    let mut groups: HashSet<Uuid> = vault.root.subtree().iter().map(|x| x.uuid).collect();
    let mut entries: HashSet<Uuid> = tree::all_entry_ids(vault).into_iter().collect();
    let mut stack = vec![&mut clone];
    while let Some(c) = stack.pop() {
        if !groups.insert(c.uuid) {
            c.uuid = tree::fresh_id(|u| groups.contains(&u))?;
            groups.insert(c.uuid);
        }
        for e in &mut c.entries {
            if !entries.insert(e.uuid) {
                fresh(e, &mut entries, now)?;
            }
        }
        stack.extend(c.groups.iter_mut());
    }
    let id = clone.uuid;
    crate::edit::place_group(vault, parent, Position::End, clone)?;
    Ok(id)
}
