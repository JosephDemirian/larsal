//! Finding groups and entries in the tree by id. Every walk is iterative,
//! so depth costs no stack.

use app_model::{Entry, Group, Uuid, Vault};

/// The child indexes from the root to the group `id`.
pub(crate) fn group_path(root: &Group, id: Uuid) -> Option<Vec<usize>> {
    let mut stack: Vec<(Vec<usize>, &Group)> = vec![(Vec::new(), root)];
    while let Some((path, g)) = stack.pop() {
        if g.uuid == id {
            return Some(path);
        }
        for (i, c) in g.groups.iter().enumerate() {
            let mut p = path.clone();
            p.push(i);
            stack.push((p, c));
        }
    }
    None
}

pub(crate) fn group_at<'a>(root: &'a Group, path: &[usize]) -> Option<&'a Group> {
    path.iter().try_fold(root, |g, &i| g.groups.get(i))
}

pub(crate) fn group_at_mut<'a>(root: &'a mut Group, path: &[usize]) -> Option<&'a mut Group> {
    path.iter().try_fold(root, |g, &i| g.groups.get_mut(i))
}

pub(crate) fn group(vault: &Vault, id: Uuid) -> Option<&Group> {
    group_at(&vault.root, &group_path(&vault.root, id)?)
}

pub(crate) fn group_mut(vault: &mut Vault, id: Uuid) -> Option<&mut Group> {
    let path = group_path(&vault.root, id)?;
    group_at_mut(&mut vault.root, &path)
}

/// The path of the group holding live entry `id`, and the entry's index.
pub(crate) fn entry_place(root: &Group, id: Uuid) -> Option<(Vec<usize>, usize)> {
    let mut stack: Vec<(Vec<usize>, &Group)> = vec![(Vec::new(), root)];
    while let Some((path, g)) = stack.pop() {
        if let Some(i) = g.entries.iter().position(|e| e.uuid == id) {
            return Some((path, i));
        }
        for (i, c) in g.groups.iter().enumerate() {
            let mut p = path.clone();
            p.push(i);
            stack.push((p, c));
        }
    }
    None
}

pub(crate) fn entry(vault: &Vault, id: Uuid) -> Option<&Entry> {
    let (path, i) = entry_place(&vault.root, id)?;
    group_at(&vault.root, &path)?.entries.get(i)
}

pub(crate) fn entry_mut(vault: &mut Vault, id: Uuid) -> Option<&mut Entry> {
    let (path, i) = entry_place(&vault.root, id)?;
    group_at_mut(&mut vault.root, &path)?.entries.get_mut(i)
}

/// The id of the group holding live entry `id`.
pub(crate) fn entry_group(vault: &Vault, id: Uuid) -> Option<Uuid> {
    let (path, _) = entry_place(&vault.root, id)?;
    group_at(&vault.root, &path).map(|g| g.uuid)
}

/// The ids from the group `id` up to the root, the group first.
pub(crate) fn ancestors(vault: &Vault, id: Uuid) -> Vec<Uuid> {
    let Some(path) = group_path(&vault.root, id) else {
        return Vec::new();
    };
    let mut out: Vec<Uuid> = (0..=path.len())
        .rev()
        .filter_map(|n| path.get(..n).and_then(|p| group_at(&vault.root, p)))
        .map(|g| g.uuid)
        .collect();
    out.dedup();
    out
}

/// The level of group `id`: 0 for the root group, 1 for its children.
pub(crate) fn level(vault: &Vault, id: Uuid) -> Option<usize> {
    group_path(&vault.root, id).map(|p| p.len())
}

/// How many group levels lie below `g`: 0 when it has no child groups.
pub(crate) fn height(g: &Group) -> usize {
    let mut max = 0;
    let mut stack = vec![(g, 0usize)];
    while let Some((g, d)) = stack.pop() {
        max = max.max(d);
        stack.extend(g.groups.iter().map(|c| (c, d.saturating_add(1))));
    }
    max
}

/// True when `id` is `ancestor` or lies in its subtree.
pub(crate) fn within(vault: &Vault, id: Uuid, ancestor: Uuid) -> bool {
    ancestors(vault, id).contains(&ancestor)
}

/// Every live entry id in the tree.
pub(crate) fn all_entry_ids(vault: &Vault) -> Vec<Uuid> {
    vault
        .root
        .subtree()
        .iter()
        .flat_map(|g| g.entries.iter().map(|e| e.uuid))
        .collect()
}

/// A fresh version 4 id not used by any `taken` id (CRY-03.11, MOD-01.12).
pub(crate) fn fresh_id(taken: impl Fn(Uuid) -> bool) -> Result<Uuid, crate::Error> {
    loop {
        let id = Uuid(app_crypto::random::uuid_v4().map_err(|_| crate::Error::RandomSource)?);
        if !taken(id) {
            return Ok(id);
        }
    }
}
