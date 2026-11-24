//! The rules every `Vault` keeps: unique ids, one root, at most one recycle
//! bin, no group cycles (MOD-02.1, MOD-04.1, FMT-11.33).
//!
//! One root and no cycles hold by construction: `Vault` owns exactly one root
//! `Group`, and each group owns its children, so a group can never be its own
//! ancestor. The reader turns a document that would make a cycle into
//! `Corrupt` (FMT-11.36, LD-26). [`check`] proves the rest.

use crate::entry::Entry;
use crate::uuid::Uuid;
use crate::vault::Vault;
use std::collections::HashSet;

/// The first rule a vault breaks. Holds ids only, never a field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// A group has the zero id.
    ZeroGroupId,
    /// Two groups share this id.
    DuplicateGroupId(Uuid),
    /// A live entry has the zero id.
    ZeroEntryId,
    /// Two live entries share this id (groups are a separate space).
    DuplicateEntryId(Uuid),
    /// A history item of this entry carries another id (FMT-11.32).
    HistoryIdMismatch(Uuid),
    /// A history item of this entry has history of its own (FMT-11.31).
    NestedHistory(Uuid),
    /// A metadata group reference names no group (FMT-10.16).
    DanglingGroupReference(Uuid),
    /// A custom icon has the zero id.
    ZeroCustomIconId,
    /// Two custom icons share this id (FMT-14.7).
    DuplicateCustomIconId(Uuid),
    /// Two attachments of this entry (or of one of its history items) share
    /// a name (MOD-05.1; the reader renames per FMT-13.13).
    DuplicateAttachmentName(Uuid),
    /// A deleted-object record has the zero id (FMT-15.4).
    ZeroDeletedObjectId,
}

/// Checks every rule. `Ok` means: group ids are non-zero and unique among
/// groups, live entry ids are non-zero and unique among live entries,
/// history items carry their owner's id and no history of their own, the
/// recycle bin (at most one: it is one id) and every other metadata group
/// reference names a group of the tree, custom icon ids are non-zero and
/// unique, attachment names are unique within each entry and each history
/// item, and deleted-object ids are non-zero. A file may name the root group
/// as the bin; the value is kept
/// (FMT-10.16) and MOD-04 decides how Larsal acts on it.
///
/// # Errors
/// The first [`Violation`] found.
pub fn check(vault: &Vault) -> Result<(), Violation> {
    let groups = vault.root.subtree();
    let mut group_ids = HashSet::with_capacity(groups.len());
    let mut entry_ids = HashSet::new();
    for g in &groups {
        if g.uuid.is_zero() {
            return Err(Violation::ZeroGroupId);
        }
        if !group_ids.insert(g.uuid) {
            return Err(Violation::DuplicateGroupId(g.uuid));
        }
        for e in &g.entries {
            check_entry(e)?;
            if !entry_ids.insert(e.uuid) {
                return Err(Violation::DuplicateEntryId(e.uuid));
            }
        }
    }
    let m = &vault.meta;
    let refs = [
        m.recycle_bin,
        m.entry_templates_group,
        m.last_selected_group,
        m.last_top_visible_group,
    ];
    if let Some(id) = refs
        .into_iter()
        .flatten()
        .find(|id| !group_ids.contains(id))
    {
        return Err(Violation::DanglingGroupReference(id));
    }
    let mut icon_ids = HashSet::new();
    for icon in &m.custom_icons {
        if icon.uuid.is_zero() {
            return Err(Violation::ZeroCustomIconId);
        }
        if !icon_ids.insert(icon.uuid) {
            return Err(Violation::DuplicateCustomIconId(icon.uuid));
        }
    }
    if vault.deleted_objects.iter().any(|d| d.uuid.is_zero()) {
        return Err(Violation::ZeroDeletedObjectId);
    }
    Ok(())
}

fn check_entry(e: &Entry) -> Result<(), Violation> {
    if e.uuid.is_zero() {
        return Err(Violation::ZeroEntryId);
    }
    unique_attachment_names(e)?;
    for h in &e.history {
        if h.uuid != e.uuid {
            return Err(Violation::HistoryIdMismatch(e.uuid));
        }
        if !h.history.is_empty() {
            return Err(Violation::NestedHistory(e.uuid));
        }
        unique_attachment_names(h)?;
    }
    Ok(())
}

fn unique_attachment_names(e: &Entry) -> Result<(), Violation> {
    let mut names = HashSet::with_capacity(e.attachments.len());
    if e.attachments.iter().all(|a| names.insert(a.name.as_str())) {
        Ok(())
    } else {
        Err(Violation::DuplicateAttachmentName(e.uuid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Group;
    use crate::icon::CustomIcon;
    use crate::times::Time;

    fn id(n: u8) -> Uuid {
        Uuid([n; 16])
    }

    fn vault() -> Vault {
        let mut root = Group::new(id(1), "R".into(), Time(0));
        let mut g = Group::new(id(2), "G".into(), Time(0));
        g.entries.push(Entry::new(id(10), Time(0)));
        root.groups.push(g);
        root.entries.push(Entry::new(id(11), Time(0)));
        Vault::new(root, Time(0))
    }

    #[test]
    fn a_valid_vault_passes() {
        assert_eq!(check(&vault()), Ok(()));
    }

    #[test]
    fn group_ids_are_unique() {
        let mut v = vault();
        v.root.groups.push(Group::new(id(2), "dup".into(), Time(0)));
        assert_eq!(check(&v), Err(Violation::DuplicateGroupId(id(2))));
        let mut v = vault();
        v.root.groups[0]
            .groups
            .push(Group::new(id(1), "root id".into(), Time(0)));
        assert_eq!(check(&v), Err(Violation::DuplicateGroupId(id(1))));
    }

    #[test]
    fn entry_ids_are_unique() {
        let mut v = vault();
        v.root.groups[0].entries.push(Entry::new(id(11), Time(0)));
        assert_eq!(check(&v), Err(Violation::DuplicateEntryId(id(11))));
    }

    // FMT-11.33: a group and an entry may carry the same id.
    #[test]
    fn group_and_entry_id_spaces_are_separate() {
        let mut v = vault();
        v.root.entries.push(Entry::new(id(2), Time(0)));
        assert_eq!(check(&v), Ok(()));
    }

    #[test]
    fn zero_ids_are_refused() {
        let mut v = vault();
        v.root.groups[0].uuid = Uuid::ZERO;
        assert_eq!(check(&v), Err(Violation::ZeroGroupId));
        let mut v = vault();
        v.root.entries[0].uuid = Uuid::ZERO;
        assert_eq!(check(&v), Err(Violation::ZeroEntryId));
    }

    #[test]
    fn history_items_carry_the_owner_id_and_no_history() {
        let mut v = vault();
        v.root.entries[0].history.push(Entry::new(id(12), Time(0)));
        assert_eq!(check(&v), Err(Violation::HistoryIdMismatch(id(11))));
        let mut v = vault();
        let mut h = Entry::new(id(11), Time(0));
        h.history.push(Entry::new(id(11), Time(0)));
        v.root.entries[0].history.push(h);
        assert_eq!(check(&v), Err(Violation::NestedHistory(id(11))));
    }

    // At most one recycle bin: one id, naming a group of the tree.
    #[test]
    fn at_most_one_recycle_bin() {
        let mut v = vault();
        v.meta.recycle_bin = Some(id(2));
        assert_eq!(check(&v), Ok(()));
        // The file may name the root (FMT-10.16): kept; MOD-04 owns behavior.
        v.meta.recycle_bin = Some(id(1));
        assert_eq!(check(&v), Ok(()));
        v.meta.recycle_bin = Some(id(9));
        assert_eq!(check(&v), Err(Violation::DanglingGroupReference(id(9))));
        v.meta.recycle_bin = None;
        v.meta.last_selected_group = Some(id(11)); // an entry id, not a group
        assert_eq!(check(&v), Err(Violation::DanglingGroupReference(id(11))));
    }

    #[test]
    fn custom_icon_ids_are_unique() {
        let icon = |n| CustomIcon {
            uuid: id(n),
            name: String::new(),
            last_modified: None,
            data: Vec::new(),
            unknown: Vec::new(),
        };
        let mut v = vault();
        v.meta.custom_icons = vec![icon(5), icon(5)];
        assert_eq!(check(&v), Err(Violation::DuplicateCustomIconId(id(5))));
        v.meta.custom_icons = vec![icon(0)];
        assert_eq!(check(&v), Err(Violation::ZeroCustomIconId));
    }

    #[test]
    fn attachment_names_are_unique_per_entry() {
        use crate::attachment::Attachment;
        use larsal_crypto::secret::SecretBytes;
        use std::sync::Arc;
        let att = |name: &str| Attachment {
            name: name.into(),
            data: Arc::new(SecretBytes::new(Vec::new())),
        };
        let mut v = vault();
        v.root.entries[0].attachments = vec![att("a"), att("b")];
        assert_eq!(check(&v), Ok(()));
        v.root.entries[0].attachments.push(att("a"));
        assert_eq!(check(&v), Err(Violation::DuplicateAttachmentName(id(11))));
        // In a history item too; the same name in two entries is fine.
        let mut v = vault();
        v.root.groups[0].entries[0].attachments = vec![att("a")];
        v.root.entries[0].attachments = vec![att("a")];
        assert_eq!(check(&v), Ok(()));
        let mut h = Entry::new(id(11), Time(0));
        h.attachments = vec![att("x"), att("x")];
        v.root.entries[0].history.push(h);
        assert_eq!(check(&v), Err(Violation::DuplicateAttachmentName(id(11))));
    }

    #[test]
    fn deleted_object_ids_are_non_zero() {
        use crate::vault::DeletedObject;
        let mut v = vault();
        let rec = |uuid| DeletedObject {
            uuid,
            deleted_at: Time(0),
            unknown: Vec::new(),
        };
        v.deleted_objects = vec![rec(id(7))];
        assert_eq!(check(&v), Ok(()));
        v.deleted_objects.push(rec(Uuid::ZERO));
        assert_eq!(check(&v), Err(Violation::ZeroDeletedObjectId));
    }

    // One root and no cycles: the root is a single owned value, so a cycle
    // cannot be written down. This compiles only because `groups` holds
    // owned values; moving the root into its own child would not compile.
    #[test]
    fn one_root_and_no_cycles_by_construction() {
        let v = vault();
        let all = v.root.subtree();
        assert_eq!(all.iter().filter(|g| g.uuid == v.root.uuid).count(), 1);
        assert_eq!(all.len(), 2);
    }
}
