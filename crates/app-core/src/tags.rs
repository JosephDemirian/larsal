//! Tags (MOD-07): an entry's tag list, the vault tag list, adding one tag,
//! the tag menu for selected entries, removing a tag everywhere, and the
//! pure parts of the tag box.
//!
//! Guarantees: an entry's tags are always non-empty, trimmed, without a
//! separator, unique and sorted by UTF-16 code units (MOD-07.2); building
//! the vault tag list changes nothing (MOD-07.12); every change of tags is
//! a change batch: an entry that really changes gets a new modification
//! time and no history item (MOD-01.32).

use crate::edit::{change_entry, natural_cmp, starts_with_folded};
use crate::{Error, recycle, tree};
use app_model::{Entry, Time, Uuid, Vault};
use std::collections::HashSet;

pub use app_model::entry::parse_tags as from_text;

/// The tag separators (MOD-07 words): `,`, `;` and TAB.
const SEPARATORS: [char; 3] = [',', ';', '\t'];

/// The vault tag list (MOD-07.5): every tag of every live entry outside the
/// recycle bin, each text once, in the natural case-insensitive order of
/// D-07-1. History items and group tags are left out.
#[must_use]
pub fn vault_tags(vault: &Vault) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut list: Vec<String> = Vec::new();
    for g in vault.root.subtree() {
        if recycle::group_in_bin(vault, g.uuid) {
            continue;
        }
        for e in &g.entries {
            for t in e.tags() {
                if seen.insert(t.as_str()) {
                    list.push(t.clone());
                }
            }
        }
    }
    list.sort_by(|a, b| natural_cmp(a, b));
    list
}

/// One tag cleaned for adding (MOD-07.8): separators removed from inside
/// it, then white space trimmed; `None` when nothing is left.
#[must_use]
pub fn clean(tag: &str) -> Option<String> {
    let joined: String = tag.chars().filter(|c| !SEPARATORS.contains(c)).collect();
    let t = joined.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

/// Adds one tag to an entry's list (MOD-07.8), model only; returns whether
/// the list changed. Used by the tag menu, imports and features that add a
/// tag by themselves (MOD-07.11).
pub fn add_to(e: &mut Entry, tag: &str) -> bool {
    let Some(t) = clean(tag) else {
        return false;
    };
    if e.tags().contains(&t) {
        return false;
    }
    let mut tags = e.tags().to_vec();
    tags.push(t);
    e.set_tags(tags);
    true
}

/// Removes one tag (exact) from an entry's list, model only; returns
/// whether the list changed.
pub fn remove_from(e: &mut Entry, tag: &str) -> bool {
    if !e.tags().iter().any(|t| t == tag) {
        return false;
    }
    let tags = e.tags().iter().filter(|t| *t != tag).cloned().collect();
    e.set_tags(tags);
    true
}

/// One item of the tag menu for selected entries (MOD-07.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuItem {
    /// The tag.
    pub tag: String,
    /// At least one selected entry has it.
    pub checked: bool,
}

/// The tag menu (MOD-07.7): every tag of the vault tag list, checked when
/// at least one selected entry has it. Empty when the vault has no tags
/// (the screen then shows one disabled item, `msg.no_tags`).
#[must_use]
pub fn menu(vault: &Vault, selected: &[Uuid]) -> Vec<MenuItem> {
    let chosen: Vec<&Entry> = selected
        .iter()
        .filter_map(|&id| tree::entry(vault, id))
        .collect();
    vault_tags(vault)
        .into_iter()
        .map(|tag| MenuItem {
            checked: chosen.iter().any(|e| e.tags().contains(&tag)),
            tag,
        })
        .collect()
}

/// Chooses a menu item (MOD-07.7): an unchecked tag is added to every
/// selected entry, a checked one removed from every selected entry. One
/// change batch. Returns how many entries changed.
///
/// # Errors
/// `NoSuchEntry` for any id (nothing changes then).
pub fn choose(vault: &mut Vault, selected: &[Uuid], tag: &str, now: Time) -> Result<usize, Error> {
    if selected.iter().any(|&id| tree::entry(vault, id).is_none()) {
        return Err(Error::NoSuchEntry);
    }
    let checked = selected
        .iter()
        .filter_map(|&id| tree::entry(vault, id))
        .any(|e| e.tags().iter().any(|t| t == tag));
    let mut changed = 0usize;
    for &id in selected {
        let did = change_entry(vault, id, now, |e| {
            if checked {
                remove_from(e, tag);
            } else {
                add_to(e, tag);
            }
        })?;
        changed = changed.saturating_add(usize::from(did));
    }
    Ok(changed)
}

/// Removes a tag everywhere (MOD-07.9), after the user confirmed: from
/// every live entry of the vault, the recycle bin included; history items
/// keep it. One change batch. Returns how many entries changed.
pub fn remove_everywhere(vault: &mut Vault, tag: &str, now: Time) -> usize {
    let ids: Vec<Uuid> = vault
        .root
        .subtree()
        .iter()
        .flat_map(|g| g.entries.iter())
        .filter(|e| e.tags().iter().any(|t| t == tag))
        .map(|e| e.uuid)
        .collect();
    ids.into_iter()
        .filter(|&id| {
            change_entry(vault, id, now, |e| {
                remove_from(e, tag);
            })
            .unwrap_or(false)
        })
        .count()
}

/// The tag box (MOD-07.4): the text typed so far becomes a chip when a key
/// ends it, trimmed; `None` when it is empty.
#[must_use]
pub fn end_tag(typed: &str) -> Option<String> {
    let t = typed.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

/// The tag box: pasted text splits at `,` only; each trimmed, non-empty
/// piece becomes a chip (MOD-07.4).
#[must_use]
pub fn paste(text: &str) -> Vec<String> {
    text.split(',').filter_map(end_tag).collect()
}

/// The tag box on save: the chips joined and passed through MOD-07.3.
#[must_use]
pub fn from_chips(chips: &[String]) -> Vec<String> {
    from_text(&chips.join(","))
}

/// The tag box suggestions (MOD-07.4): the vault tag list filtered by a
/// case-insensitive prefix match on the text being typed.
#[must_use]
pub fn suggestions(list: &[String], typed: &str) -> Vec<String> {
    list.iter()
        .filter(|t| starts_with_folded(t, typed))
        .cloned()
        .collect()
}

/// One exact tag term for the search (MOD-07.6, LD-66): the tag itself,
/// matched exactly by FEA-01; no query text is built, so nothing needs
/// escaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagTerm(pub String);

/// The terms for the chosen sidebar tag rows (MOD-07.6): one exact term per
/// row, all required.
#[must_use]
pub fn sidebar_terms(rows: &[&str]) -> Vec<TagTerm> {
    rows.iter().map(|r| TagTerm((*r).to_owned())).collect()
}
