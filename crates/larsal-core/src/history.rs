//! Entry history (MOD-03): what an item holds, its size, pruning, the
//! history page rows, restoring into a draft and deleting items.
//!
//! Guarantees: sizes use 64-bit sums that never wrap (MOD-03.7); pruning
//! keeps the newest items and drops every older one once a limit is passed
//! (MOD-03.8), never more than 100,000 items (MOD-03.10); dropped items are
//! dropped whole, so their secret values are wiped by their secret types.

use crate::{Error, tree};
use larsal_model::entry::STANDARD_FIELDS;
use larsal_model::{Entry, Field, Time, Uuid, Vault};

/// The reader's ceiling on history items per entry (FMT-08.12 `history`).
pub const MAX_ITEMS: usize = 100_000;

/// The size of an entry or history item (MOD-03.7): UTF-8 bytes of every
/// field name and value (the standard ones always count), of every
/// attachment name plus its content in full, of every custom data key and
/// value, of every window association's title and sequence, and of every
/// tag. Nothing else counts.
#[must_use]
pub fn size(e: &Entry) -> u64 {
    let len = |s: &str| u64::try_from(s.len()).unwrap_or(u64::MAX);
    let mut n: u64 = 0;
    let mut add = |x: u64| n = n.saturating_add(x);
    for (name, field) in e.fields() {
        add(len(name));
        add(len(field.value.expose()));
    }
    for a in &e.attachments {
        add(len(&a.name));
        add(u64::try_from(a.data.len()).unwrap_or(u64::MAX));
    }
    for item in &e.custom_data.items {
        add(len(&item.key));
        add(len(item.value.expose()));
    }
    for a in &e.auto_type.associations {
        add(len(&a.window));
        add(len(&a.sequence));
    }
    for t in e.tags() {
        add(len(t));
    }
    n
}

/// Prunes one entry's history (MOD-03.8, MOD-03.10): keeps at most
/// `max_items` newest items (-1: no limit, but never more than 100,000),
/// then walks from the newest adding sizes and drops the item that passes
/// `max_size` (-1: no limit) together with every older one. Returns how
/// many items were dropped. Larsal's private items (INT-08.32) have their own budget
/// of the same two limits, so a value that lost a merge never pushes out the entry's
/// own versions; together they stay within 100,000, private items going first, oldest
/// first.
pub fn prune(e: &mut Entry, max_items: i32, max_size: i32) -> usize {
    let before = e.history.len();
    if e.history.iter().any(crate::origin::private_item) {
        let (own, plain): (Vec<_>, Vec<_>) = std::mem::take(&mut e.history)
            .into_iter()
            .enumerate()
            .partition(|(_, h)| crate::origin::private_item(h));
        let (at, items): (Vec<usize>, Vec<Entry>) = plain.into_iter().unzip();
        e.history = items;
        prune(e, max_items, max_size);
        let first = at.len().saturating_sub(e.history.len());
        let mut kept: Vec<(usize, Entry)> = at
            .into_iter()
            .skip(first)
            .zip(std::mem::take(&mut e.history))
            .collect();
        let room = MAX_ITEMS.saturating_sub(kept.len());
        kept.extend(prune_private(own, max_items, max_size, room));
        kept.sort_by_key(|(i, _)| *i);
        e.history = kept.into_iter().map(|(_, h)| h).collect();
        return before.saturating_sub(e.history.len());
    }
    let keep = match usize::try_from(max_items) {
        Ok(n) => n.min(MAX_ITEMS),
        Err(_) => MAX_ITEMS,
    };
    if e.history.len() > keep {
        let drop = e.history.len().saturating_sub(keep);
        e.history.drain(..drop);
    }
    if let Ok(max) = u64::try_from(max_size) {
        let mut total: u64 = 0;
        let mut first_kept = 0;
        for (i, item) in e.history.iter().enumerate().rev() {
            total = total.saturating_add(size(item));
            if total > max {
                first_kept = i.saturating_add(1);
                break;
            }
        }
        e.history.drain(..first_kept);
    }
    before.saturating_sub(e.history.len())
}

/// The private items that stay, newest first by position: the newest `max_items`, at
/// most `room`, and by size each that still fits, so one too big for the limit goes
/// alone.
fn prune_private(
    mut own: Vec<(usize, Entry)>,
    max_items: i32,
    max_size: i32,
    room: usize,
) -> Vec<(usize, Entry)> {
    let keep = usize::try_from(max_items).map_or(MAX_ITEMS, |n| n.min(MAX_ITEMS));
    own.drain(..own.len().saturating_sub(keep.min(room)));
    let Ok(max) = u64::try_from(max_size) else {
        return own;
    };
    let mut total: u64 = 0;
    own.reverse();
    own.retain(|(_, h)| {
        let more = total.saturating_add(size(h));
        let fits = more <= max;
        if fits {
            total = more;
        }
        fits
    });
    own
}

/// Appends `before` (the copy taken at the start of an edit session) to
/// the entry's history and prunes with the vault limits (MOD-03.2,
/// MOD-03.9 first row). The item carries the owner's id and no history.
pub(crate) fn push_item(e: &mut Entry, mut before: Entry, max_items: i32, max_size: i32) {
    before.history.clear();
    before.uuid = e.uuid;
    e.history.push(before);
    prune(e, max_items, max_size);
}

/// The vault settings screen applied new limits (MOD-03.9 second row):
/// when either differs from the stored value, both are stored and every
/// live entry, the recycle bin included, is pruned. Returns whether
/// anything was stored.
pub fn apply_limits(vault: &mut Vault, max_items: i32, max_size: i32) -> bool {
    let m = &mut vault.meta;
    if m.history_max_items == max_items && m.history_max_size == max_size {
        return false;
    }
    m.history_max_items = max_items;
    m.history_max_size = max_size;
    let mut stack = vec![&mut vault.root];
    while let Some(g) = stack.pop() {
        for e in &mut g.entries {
            prune(e, max_items, max_size);
        }
        stack.extend(g.groups.iter_mut());
    }
    true
}

/// One row of the history page (MOD-03.11). `index` is `None` for the
/// current entry, else the position in the history list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Position in the history list; `None` for the current entry.
    pub index: Option<usize>,
    /// The row's last modification time.
    pub last_modified: Time,
    /// What differs from the next older row, in the card's order.
    pub difference: Vec<&'static str>,
    /// The row's size (MOD-03.7).
    pub size: u64,
}

/// The history page rows (MOD-03.11): the current entry and every item,
/// newest first by last modification time, each with the labels of what
/// differs from the next older row (none on the oldest).
#[must_use]
pub fn rows(e: &Entry) -> Vec<Row> {
    let mut all: Vec<(Option<usize>, &Entry)> = e
        .history
        .iter()
        .enumerate()
        .map(|(i, h)| (Some(i), h))
        .collect();
    all.push((None, e));
    all.sort_by_key(|(_, x)| core::cmp::Reverse(x.times.last_modification));
    let mut out = Vec::with_capacity(all.len());
    for (k, (index, x)) in all.iter().enumerate() {
        let older = all.get(k.saturating_add(1)).map(|(_, o)| *o);
        out.push(Row {
            index: *index,
            last_modified: x.times.last_modification,
            difference: older.map_or_else(Vec::new, |o| difference(x, o)),
            size: size(x),
        });
    }
    out
}

/// The field names of the one-time password setup (FMT-14.22, FEA-04).
pub(crate) fn otp_field(name: &str) -> bool {
    name == "otp" || name == "TOTP Seed" || name == "TOTP Settings" || name.starts_with("TimeOtp-")
}

/// The difference labels between two versions (MOD-03.11), in this order:
/// Title, Username, Password, URL, Notes; "Custom attributes" only when no
/// standard field differs but other string fields do; Icon; Color;
/// Expiration; one-time password; Custom data; Attachments; Auto-Type; Tags.
#[must_use]
pub fn difference(a: &Entry, b: &Entry) -> Vec<&'static str> {
    let mut out = Vec::new();
    let labels = ["Title", "Username", "Password", "URL", "Notes"];
    let mut standard = false;
    for (name, label) in STANDARD_FIELDS.iter().zip(labels) {
        if a.field(name) != b.field(name) {
            out.push(label);
            standard = true;
        }
    }
    // Both field lists are sorted: compare them in place, so no value is
    // copied out of its secret type (E4-B1).
    fn other((n, _): &(&str, &Field)) -> bool {
        !STANDARD_FIELDS.contains(n) && !otp_field(n)
    }
    fn otp(e: &Entry) -> impl Iterator<Item = (&str, &str)> {
        e.fields()
            .filter(|(n, _)| otp_field(n))
            .map(|(n, f)| (n, f.value.expose()))
    }
    if !standard && !a.fields().filter(other).eq(b.fields().filter(other)) {
        out.push("Custom attributes");
    }
    if a.icon != b.icon {
        out.push("Icon");
    }
    if (&a.foreground_color, &a.background_color) != (&b.foreground_color, &b.background_color) {
        out.push("Color");
    }
    if (a.times.expires, a.times.expiry) != (b.times.expires, b.times.expiry) {
        out.push("Expiration");
    }
    if !otp(a).eq(otp(b)) {
        out.push("one-time password");
    }
    if !crate::origin::same_data(&a.custom_data, &b.custom_data) {
        out.push("Custom data");
    }
    if a.attachments != b.attachments {
        out.push("Attachments");
    }
    let (x, y) = (&a.auto_type, &b.auto_type);
    if (x.enabled, &x.default_sequence, &x.associations)
        != (y.enabled, &y.default_sequence, &y.associations)
    {
        out.push("Auto-Type");
    }
    if a.tags() != b.tags() {
        out.push("Tags");
    }
    out
}

/// Restore (MOD-03.12): copies every stored value of `item` into the
/// editor's `draft`, except the times, the id and the previous parent. The
/// vault does not change until the draft is committed as an edit session.
pub fn restore_into(draft: &mut Entry, item: &Entry) {
    let (uuid, times, previous_parent) = (draft.uuid, draft.times.clone(), draft.previous_parent);
    let history = std::mem::take(&mut draft.history);
    let mut copy = item.duplicate(false);
    copy.uuid = uuid;
    copy.times = times;
    // Expiry is a stored value of the version: it comes back with it.
    copy.times.expires = item.times.expires;
    copy.times.expiry = item.times.expiry;
    copy.previous_parent = previous_parent;
    copy.history = history;
    // INT-08.32: the stamp and marker stay as they are; a version never gives them.
    crate::origin::keep_own(&draft.custom_data, &mut copy.custom_data);
    *draft = copy;
}

/// Which history items to delete (MOD-03.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delete {
    /// The items at these positions.
    Items(Vec<usize>),
    /// Every item.
    All,
}

/// Deletes history items of live entry `id` at commit (MOD-03.13): no new
/// history item and no deleted-object record; when any item was removed,
/// the entry's last modification and last access times become `now`.
/// Returns whether any item was removed.
///
/// # Errors
/// `NoSuchEntry`; `NoSuchHistoryItem` for a position past the list
/// (nothing is removed then).
pub fn delete_items(vault: &mut Vault, id: Uuid, which: &Delete, now: Time) -> Result<bool, Error> {
    let e = tree::entry_mut(vault, id).ok_or(Error::NoSuchEntry)?;
    let before = e.history.len();
    match which {
        Delete::All => e.history.clear(),
        Delete::Items(positions) => {
            if positions.iter().any(|&p| p >= e.history.len()) {
                return Err(Error::NoSuchHistoryItem);
            }
            let mut keep = 0usize;
            e.history.retain(|_| {
                let drop = positions.contains(&keep);
                keep = keep.saturating_add(1);
                !drop
            });
        }
    }
    let removed = e.history.len() < before;
    if removed {
        e.times.last_modification = now;
        e.times.last_access = now;
    }
    Ok(removed)
}
