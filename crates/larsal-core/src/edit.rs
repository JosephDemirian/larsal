//! Entries and groups (MOD-01, MOD-02): create, edit, move, reorder, sort
//! and copy; what each change does to the times; inheritance down the tree.
//!
//! Guarantees: a refused operation changes nothing; setting a value it
//! already has is no change and moves no time (MOD-01.26, MOD-02.29); an
//! edit session makes at most one history item (MOD-03.2); a group never
//! moves into itself (MOD-02.20); group times move only for changes to the
//! group itself (MOD-02.25, Larsal column).

use crate::{Error, NameProblem, history, recycle, tree};
use core::cmp::Ordering;
use larsal_model::entry::{STANDARD_FIELDS, cmp_utf16};
use larsal_model::{
    CustomIcon, Entry, Field, Group, Icon, Switch, Time, Uuid, Vault, icon::GROUP_DEFAULT,
};
use std::collections::{HashMap, HashSet};

/// The base name of a new custom field (MOD-01.3).
pub const NEW_FIELD: &str = "New field";
/// The built-in default auto-type sequence (MOD-02.15).
pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
/// Most bytes of one field value (MOD-01.9, LD-56: base64 of it stays
/// under the 64 MiB text limit).
pub const MAX_VALUE: usize = 50_331_648;
/// Most bytes of one field name (MOD-01.9: the text limit).
pub const MAX_NAME: usize = 67_108_864;
/// Most custom fields in one entry (MOD-01.9: the writer adds 5 standard).
pub const MAX_CUSTOM: usize = 99_995;
/// The custom data key of a shared group, stored encoded (name rule;
/// FMT-13.17, INT-08); larsal-format's share item owns it.
pub const SHARED_KEY: &[u8] = larsal_format::share_item::KEY;

// ---------------------------------------------------------------------------
// Texts and names.

/// A single-line box's text (MOD-01.5, MOD-02.3): every line break (CR LF,
/// LF or CR; CR LF counts once) becomes one space. Applied by the edit
/// screen to `Title`, `UserName`, `URL` and group names only.
#[must_use]
pub fn screen_line(text: &str) -> String {
    text.replace("\r\n", " ").replace(['\r', '\n'], " ")
}

/// The Unicode White_Space set of FMT-11.26.
fn white(c: char) -> bool {
    matches!(c,
        '\u{9}'..='\u{D}' | ' ' | '\u{85}' | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}'
        | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}')
}

/// The name a new custom field gets (MOD-01.3): `base`, or `base` and a
/// space and the first of 1, 2, 3 … that no field of the entry has.
#[must_use]
pub fn new_field_name(e: &Entry, base: &str) -> String {
    if e.field(base).is_none() {
        return base.to_owned();
    }
    (1u64..)
        .map(|n| format!("{base} {n}"))
        .find(|name| e.field(name).is_none())
        .unwrap_or_default()
}

/// Renames the custom field `old` to the name the user typed (MOD-01.3):
/// leading and trailing white space is trimmed first; the name is refused
/// when it is then empty, a standard name, or another field's name. The
/// field keeps its value and protected flag.
///
/// # Errors
/// `FieldName` with the reason; `NoSuchEntry` when `old` is no custom field.
pub fn rename_field(e: &mut Entry, old: &str, typed: &str) -> Result<(), Error> {
    let name = typed.trim_matches(white);
    if STANDARD_FIELDS.contains(&old) {
        return Err(Error::FieldName(NameProblem::Standard));
    }
    if name.is_empty() {
        return Err(Error::FieldName(NameProblem::Empty));
    }
    if STANDARD_FIELDS.contains(&name) {
        return Err(Error::FieldName(NameProblem::Standard));
    }
    if name == old {
        return Ok(());
    }
    if e.field(name).is_some() {
        return Err(Error::FieldName(NameProblem::Taken));
    }
    if name.len() > MAX_NAME {
        return Err(Error::FieldTooLarge);
    }
    let field = e.remove_field(old).ok_or(Error::NoSuchEntry)?;
    e.set_field(name.to_owned(), field);
    Ok(())
}

/// Where the ASCII `needle` first starts in `hay`, ASCII case ignored. It
/// compares the bytes in place, so a secret value is never copied (E4-B1).
pub(crate) fn find_ascii_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// True when the text holds a field reference (MOD-08.24, MOD-08.13): a
/// `{`, `ref:` in any case, then `@`, then `:`, then `}`. Reads the text in
/// place. Only the first `{ref:` needs a look: the `@`, `:` and `}` of any
/// later one also come after it.
#[must_use]
pub fn holds_reference(text: &str) -> bool {
    let Some(at) = find_ascii_ci(text.as_bytes(), b"{ref:") else {
        return false;
    };
    let after: &[u8] = text
        .as_bytes()
        .get(at.saturating_add(5)..)
        .unwrap_or_default();
    after
        .iter()
        .position(|&c| c == b'@')
        .and_then(|a| after.get(a..))
        .and_then(|s| s.iter().position(|&c| c == b':').and_then(|c| s.get(c..)))
        .is_some_and(|s| s.contains(&b'}'))
}

/// Unicode simple case folding of one character, as far as the standard
/// library gives it: the lower case when that is one character.
// ponytail: `to_lowercase` stands in for simple case folding; a few
// characters (final sigma, Cherokee) fold differently. Add the fold table
// if a user's sort or tag order shows it.
fn fold(c: char) -> char {
    let mut l = c.to_lowercase();
    match (l.next(), l.next()) {
        (Some(x), None) => x,
        _ => c,
    }
}

/// Compares two texts code point by code point after case folding; a text
/// that is the start of the other comes first (MOD-02.26).
fn cmp_folded(a: &str, b: &str) -> Ordering {
    a.chars().map(fold).cmp(b.chars().map(fold))
}

/// True when `text` starts with `prefix`, case folded as [`natural_cmp`]
/// folds (MOD-07.4 suggestions).
pub(crate) fn starts_with_folded(text: &str, prefix: &str) -> bool {
    let mut t = text.chars().map(fold);
    prefix.chars().map(fold).all(|p| t.next() == Some(p))
}

/// The natural, case-insensitive order of MOD-07.5 (D-07-1): digit runs by
/// value and before other runs, other runs folded, then the UTF-16 order of
/// the original texts.
#[must_use]
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    natural_cmp_folded(a, b).then_with(|| cmp_utf16(a, b))
}

/// [`natural_cmp`] without its last tie-break: texts that differ only in
/// letter case (or in leading zeros) compare equal, so a caller can compare
/// another key before case (the Auto-Type picker, INT-05.26, LD-196).
#[must_use]
pub fn natural_cmp_folded(a: &str, b: &str) -> Ordering {
    fn runs(s: &str) -> Vec<(bool, &str)> {
        let mut out = Vec::new();
        let mut start = 0;
        let mut digit = None;
        for (i, c) in s.char_indices() {
            let d = c.is_ascii_digit();
            if digit.is_some_and(|x| x != d) {
                out.push((digit == Some(true), s.get(start..i).unwrap_or("")));
                start = i;
            }
            digit = Some(d);
        }
        if let Some(d) = digit {
            out.push((d, s.get(start..).unwrap_or("")));
        }
        out
    }
    let (ra, rb) = (runs(a), runs(b));
    for ((da, xa), (db, xb)) in ra.iter().zip(&rb) {
        let o = match (da, db) {
            (true, true) => {
                let (ta, tb) = (xa.trim_start_matches('0'), xb.trim_start_matches('0'));
                ta.len().cmp(&tb.len()).then_with(|| ta.cmp(tb))
            }
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => cmp_folded(xa, xb),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    ra.len().cmp(&rb.len())
}

// ---------------------------------------------------------------------------
// Entries.

/// The edit caps of MOD-01.9 (LD-56): no value over 48 MiB, no name over
/// 64 MiB, no more than 99,995 custom fields; and no two attachments with
/// one name (MOD-05.1), so the vault keeps its invariants; the joined tags
/// text within the text limit (MOD-07).
fn check_entry(e: &Entry) -> Result<(), Error> {
    let mut names = HashSet::with_capacity(e.attachments.len());
    if !e.attachments.iter().all(|a| names.insert(a.name.as_str())) {
        return Err(Error::AttachmentName(NameProblem::Taken));
    }
    let mut custom = 0usize;
    for (name, f) in e.fields() {
        if f.value.expose().len() > MAX_VALUE || name.len() > MAX_NAME {
            return Err(Error::FieldTooLarge);
        }
        if !STANDARD_FIELDS.contains(&name) {
            custom = custom.saturating_add(1);
        }
    }
    if custom > MAX_CUSTOM {
        return Err(Error::FieldTooLarge);
    }
    // The joined tags text is one text value (MOD-07 limits).
    let tags = e
        .tags()
        .iter()
        .fold(0usize, |n, t| n.saturating_add(t.len()).saturating_add(1));
    if tags.saturating_sub(1) > MAX_NAME {
        return Err(Error::FieldTooLarge);
    }
    Ok(())
}

/// A new entry for "Add entry" in `group`, not yet in the vault (MOD-01.22):
/// a fresh id no live entry has, `UserName` the vault's default user name,
/// and the group's icon when `group_icon` (setting `set.entry_group_icon`)
/// is on and the group has a custom icon or a standard one other than 48
/// and 49 (MOD-06.3); else icon 0.
///
/// # Errors
/// `NoSuchGroup`; `InRecycleBin` inside the bin (MOD-04.15); `RandomSource`.
pub fn new_entry(vault: &Vault, group: Uuid, group_icon: bool) -> Result<Entry, Error> {
    let g = tree::group(vault, group).ok_or(Error::NoSuchGroup)?;
    if recycle::group_in_bin(vault, group) {
        return Err(Error::InRecycleBin);
    }
    let taken: HashSet<Uuid> = tree::all_entry_ids(vault).into_iter().collect();
    let id = tree::fresh_id(|u| taken.contains(&u))?;
    let mut e = Entry::new(id, Time(0));
    if !vault.meta.default_user_name.is_empty() {
        let value = larsal_crypto::secret::SecretString::new(vault.meta.default_user_name.clone());
        e.set_field(
            "UserName".into(),
            Field {
                value,
                protected: false,
            },
        );
    }
    if group_icon {
        e.icon = match g.icon {
            Icon::Standard(n) if n != 48 && n != 49 => Icon::Standard(n),
            Icon::Custom(c) => Icon::Custom(c),
            Icon::Standard(_) => Icon::Standard(0),
        };
    }
    Ok(e)
}

/// Commits a new entry into `group` (MOD-01.25): appended after its
/// entries; creation, last modification, last access, location changed and
/// expiry time are `now`, expires false, usage count 0 (D-01-4). The
/// group's times do not move (MOD-02.25). An id a live entry already has is
/// replaced by a fresh one.
///
/// # Errors
/// `NoSuchGroup`; `InRecycleBin`; `FieldTooLarge` (MOD-01.9);
/// `AttachmentName`; `RandomSource`.
pub fn add_entry(vault: &mut Vault, group: Uuid, mut e: Entry, now: Time) -> Result<Uuid, Error> {
    if tree::group(vault, group).is_none() {
        return Err(Error::NoSuchGroup);
    }
    if recycle::group_in_bin(vault, group) {
        return Err(Error::InRecycleBin);
    }
    check_entry(&e)?;
    let taken: HashSet<Uuid> = tree::all_entry_ids(vault).into_iter().collect();
    if e.uuid.is_zero() || taken.contains(&e.uuid) {
        e.uuid = tree::fresh_id(|u| taken.contains(&u))?;
    }
    let t = &mut e.times;
    (
        t.creation,
        t.last_modification,
        t.last_access,
        t.location_changed,
        t.expiry,
    ) = (now, now, now, now, now);
    t.expires = false;
    t.usage_count = 0;
    e.history.clear();
    let id = e.uuid;
    tree::group_mut(vault, group)
        .ok_or(Error::NoSuchGroup)?
        .entries
        .push(e);
    Ok(id)
}

/// True when two versions hold the same stored values (MOD-01.26): every
/// field with its flag, attachments, custom data, icon, colors, override
/// URL, tags, expires flag and expiry time, auto-type, report exclusion,
/// previous parent, id and kept unknown elements. Other times, the usage
/// count and the history are not compared.
#[must_use]
pub fn same_stored(a: &Entry, b: &Entry) -> bool {
    a.uuid == b.uuid
        && a.fields().eq(b.fields())
        && a.attachments == b.attachments
        && a.custom_data == b.custom_data
        && a.icon == b.icon
        && (&a.foreground_color, &a.background_color, &a.override_url)
            == (&b.foreground_color, &b.background_color, &b.override_url)
        && a.tags() == b.tags()
        && (a.times.expires, a.times.expiry) == (b.times.expires, b.times.expiry)
        && a.auto_type == b.auto_type
        && a.exclude_from_reports == b.exclude_from_reports
        && a.previous_parent == b.previous_parent
        && a.unknown == b.unknown
}

/// An edit session on live entry `id` (MOD-01.32, MOD-03.2): `edit` changes
/// a draft copy. When any stored value then differs, the entry takes the
/// draft, its last modification and last access times become `now`
/// (MOD-01.26, MOD-01.27) and the copy taken before becomes a history item,
/// pruned by the vault limits (MOD-03.8). When nothing differs, nothing
/// changes and no time moves. Returns whether the entry changed.
///
/// The draft's id, history, creation and location times and usage count
/// are kept as they were whatever `edit` does to them (MOD-01.12,
/// MOD-01.28, MOD-01.29). A `URL` change removes `_EXEC_CMD` when it holds
/// exactly `1` or `0` (MOD-01.10).
///
/// # Errors
/// `NoSuchEntry`; `FieldTooLarge` (MOD-01.9) or `AttachmentName` (two
/// attachments with one name); nothing changes then.
pub fn edit_entry(
    vault: &mut Vault,
    id: Uuid,
    now: Time,
    edit: impl FnOnce(&mut Entry),
) -> Result<bool, Error> {
    apply_entry(vault, id, now, true, edit)
}

/// A change batch outside an edit session (MOD-01.32: tag menu, expire
/// now, icon download and the like): times as [`edit_entry`], no history
/// item.
///
/// # Errors
/// As [`edit_entry`].
pub fn change_entry(
    vault: &mut Vault,
    id: Uuid,
    now: Time,
    edit: impl FnOnce(&mut Entry),
) -> Result<bool, Error> {
    apply_entry(vault, id, now, false, edit)
}

fn apply_entry(
    vault: &mut Vault,
    id: Uuid,
    now: Time,
    session: bool,
    edit: impl FnOnce(&mut Entry),
) -> Result<bool, Error> {
    let (max_items, max_size) = (vault.meta.history_max_items, vault.meta.history_max_size);
    let e = tree::entry_mut(vault, id).ok_or(Error::NoSuchEntry)?;
    let mut draft = e.duplicate(false);
    edit(&mut draft);
    draft.uuid = e.uuid;
    let (expires, expiry) = (draft.times.expires, draft.times.expiry);
    draft.times = e.times.clone();
    (draft.times.expires, draft.times.expiry) = (expires, expiry);
    if e.value("URL") != draft.value("URL") && matches!(draft.value("_EXEC_CMD"), "1" | "0") {
        draft.remove_field("_EXEC_CMD");
    }
    check_entry(&draft)?;
    if same_stored(e, &draft) {
        return Ok(false);
    }
    draft.times.last_modification = now;
    draft.times.last_access = now;
    draft.history = std::mem::take(&mut e.history);
    if session {
        history::push_item(&mut draft, e.duplicate(false), max_items, max_size);
    }
    *e = draft;
    Ok(true)
}

/// The user name suggestions (MOD-01.23): the 10 most used `UserName`
/// values over all live entries (the recycle bin included), empty values,
/// field references and protected values (own flag, or the vault's
/// ProtectUserName; LD-105) left out; by count, highest first, ties by name
/// in UTF-16 code unit order.
#[must_use]
pub fn user_name_suggestions(vault: &Vault) -> Vec<String> {
    if vault.meta.memory_protection.user_name {
        return Vec::new();
    }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for g in vault.root.subtree() {
        for e in &g.entries {
            let Some(u) = e
                .field("UserName")
                .filter(|f| !f.protected)
                .map(|f| f.value.expose())
            else {
                continue;
            };
            if !u.is_empty() && !holds_reference(u) {
                let n = counts.entry(u).or_insert(0);
                *n = n.saturating_add(1);
            }
        }
    }
    let mut list: Vec<(&str, usize)> = counts.into_iter().collect();
    list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| cmp_utf16(a.0, b.0)));
    list.into_iter()
        .take(10)
        .map(|(u, _)| u.to_owned())
        .collect()
}

/// The field name suggestions for entry `id` (MOD-01.24): names of custom
/// fields of other live entries outside the recycle bin, passkey fields left
/// out, each once, minus the names the entry has; natural order (MOD-07.5).
#[must_use]
pub fn field_name_suggestions(vault: &Vault, id: Uuid) -> Vec<String> {
    let own: HashSet<&str> = tree::entry(vault, id)
        .map(|e| e.fields().map(|(n, _)| n).collect())
        .unwrap_or_default();
    let mut names: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for g in vault.root.subtree() {
        if recycle::group_in_bin(vault, g.uuid) {
            continue;
        }
        for e in g.entries.iter().filter(|e| e.uuid != id) {
            for (n, _) in e.fields() {
                if !STANDARD_FIELDS.contains(&n)
                    && !n.starts_with("KPEX_PASSKEY")
                    && !own.contains(n)
                    && seen.insert(n.to_owned())
                {
                    names.push(n.to_owned());
                }
            }
        }
    }
    names.sort_by(|a, b| natural_cmp(a, b));
    names
}

// ---------------------------------------------------------------------------
// Groups.

/// The deepest group level Larsal lets the user build (LD-106), the root group
/// at level 0. The reader's depth limit is 512 (FMT-08.12, counted as in
/// FMT-10.2: the document element 0, `Root` 1, the root group 2), so a group
/// at level L sits at depth L + 2. The deepest element a group can hold is
/// a history item's `Window` or custom data `Key`, at the group's depth + 6
/// (`Entry`, `History`, `Entry`, `AutoType`, `Association`, `Window`).
/// L + 8 <= 512 gives 504.
// ponytail: unknown elements kept from a file are not counted; a group
// moved down with deep ones fails its save with TooLarge(depth), losing
// nothing. Count them here if a real vault shows it.
pub const MAX_GROUP_LEVEL: usize = 504;

/// Refuses placing a group with `height` levels below it as a child of
/// `parent` when its deepest group would pass [`MAX_GROUP_LEVEL`].
fn check_depth(vault: &Vault, parent: Uuid, height: usize) -> Result<(), Error> {
    let level = tree::level(vault, parent).ok_or(Error::NoSuchGroup)?;
    if level.saturating_add(1).saturating_add(height) > MAX_GROUP_LEVEL {
        return Err(Error::TooDeep);
    }
    Ok(())
}

/// A copy of a group's own data, without entries and child groups.
fn own_copy(g: &Group) -> Group {
    Group {
        uuid: g.uuid,
        name: g.name.clone(),
        notes: g.notes.clone(),
        tags: g.tags.clone(),
        icon: g.icon,
        times: g.times.clone(),
        expanded: g.expanded,
        default_sequence: g.default_sequence.clone(),
        auto_type: g.auto_type,
        searching: g.searching,
        last_top_visible_entry: g.last_top_visible_entry,
        custom_data: g.custom_data.clone(),
        previous_parent: g.previous_parent,
        entries: Vec::new(),
        groups: Vec::new(),
        unknown: g.unknown.clone(),
    }
}

/// The group's own data that moves its times (MOD-02.29).
fn same_own(a: &Group, b: &Group) -> bool {
    (&a.name, &a.notes, a.icon, a.times.expires, a.times.expiry)
        == (&b.name, &b.notes, b.icon, b.times.expires, b.times.expiry)
        && (
            &a.default_sequence,
            a.auto_type,
            a.searching,
            &a.custom_data,
            a.previous_parent,
        ) == (
            &b.default_sequence,
            b.auto_type,
            b.searching,
            &b.custom_data,
            b.previous_parent,
        )
}

/// Changes group `id`'s own data (MOD-02.29): `edit` changes a copy without
/// children. A real change of name, notes, icon, expiry, default sequence,
/// a switch, custom data or previous parent sets last modification and
/// last access to `now`. The expanded flag is stored without moving a time
/// (MOD-02.5, MOD-02.25); the id, the times other than expiry, the last top
/// visible entry and group tags (they only come from files) stay whatever
/// `edit` does to them. Returns whether anything changed.
///
/// # Errors
/// `NoSuchGroup`.
pub fn edit_group(
    vault: &mut Vault,
    id: Uuid,
    now: Time,
    edit: impl FnOnce(&mut Group),
) -> Result<bool, Error> {
    let g = tree::group_mut(vault, id).ok_or(Error::NoSuchGroup)?;
    let mut draft = own_copy(g);
    edit(&mut draft);
    let own_changed = !same_own(g, &draft);
    let changed = own_changed || draft.expanded != g.expanded;
    if !changed {
        return Ok(false);
    }
    let times = g.times.clone();
    g.name = draft.name;
    g.notes = draft.notes;
    g.icon = draft.icon;
    g.expanded = draft.expanded;
    g.default_sequence = draft.default_sequence;
    g.auto_type = draft.auto_type;
    g.searching = draft.searching;
    g.custom_data = draft.custom_data;
    g.previous_parent = draft.previous_parent;
    g.times = times;
    (g.times.expires, g.times.expiry) = (draft.times.expires, draft.times.expiry);
    if own_changed {
        g.times.last_modification = now;
        g.times.last_access = now;
    }
    Ok(true)
}

/// A new group for "Add group", not yet in the vault (MOD-02.27): the
/// defaults of the MOD-02 table and a fresh id no group has.
///
/// # Errors
/// `RandomSource`.
pub fn new_group(vault: &Vault) -> Result<Group, Error> {
    let taken: HashSet<Uuid> = vault.root.subtree().iter().map(|g| g.uuid).collect();
    let id = tree::fresh_id(|u| taken.contains(&u))?;
    Ok(Group::new(id, String::new(), Time(0)))
}

/// Commits a new group (MOD-02.27): appended after `parent`'s child groups,
/// empty (any entries or child groups `g` carries are not taken), all five
/// times `now` (D-01-4), expires false, no previous parent. The parent's
/// times do not move (MOD-02.25). An id a group already has is replaced.
///
/// # Errors
/// `NoSuchGroup`; `InRecycleBin` (MOD-04.15); `TooDeep` past
/// [`MAX_GROUP_LEVEL`] (LD-106); `RandomSource`.
pub fn add_group(vault: &mut Vault, parent: Uuid, mut g: Group, now: Time) -> Result<Uuid, Error> {
    if tree::group(vault, parent).is_none() {
        return Err(Error::NoSuchGroup);
    }
    if recycle::group_in_bin(vault, parent) {
        return Err(Error::InRecycleBin);
    }
    check_depth(vault, parent, 0)?;
    g.entries.clear();
    g.groups.clear();
    g.last_top_visible_entry = None;
    let taken: HashSet<Uuid> = vault.root.subtree().iter().map(|g| g.uuid).collect();
    if g.uuid.is_zero() || taken.contains(&g.uuid) {
        g.uuid = tree::fresh_id(|u| taken.contains(&u))?;
    }
    let t = &mut g.times;
    (
        t.creation,
        t.last_modification,
        t.last_access,
        t.location_changed,
        t.expiry,
    ) = (now, now, now, now, now);
    t.expires = false;
    g.previous_parent = None;
    let id = g.uuid;
    tree::group_mut(vault, parent)
        .ok_or(Error::NoSuchGroup)?
        .groups
        .push(g);
    Ok(id)
}

/// Where a moved group goes among the target's child groups (MOD-02.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// After the last child group.
    End,
    /// This index in the child list after the move (past the end means End).
    At(usize),
}

/// Moves group `id` into `target` at `position` (MOD-02.20). Refused for the
/// root and for a target that is the group or lies in its subtree. Same
/// parent and same index is no change. Otherwise the group's previous
/// parent becomes the old parent when the parent changes, and its location
/// changed, last modification and last access times become `now`, also for
/// a pure reorder; no other group's times move. Returns whether it moved.
///
/// # Errors
/// `NoSuchGroup`; `RootGroup`; `Cycle`; `TooDeep` when the group's deepest
/// group would pass [`MAX_GROUP_LEVEL`] under a new parent (LD-106).
pub fn move_group(
    vault: &mut Vault,
    id: Uuid,
    target: Uuid,
    position: Position,
    now: Time,
) -> Result<bool, Error> {
    let path = tree::group_path(&vault.root, id).ok_or(Error::NoSuchGroup)?;
    if tree::group(vault, target).is_none() {
        return Err(Error::NoSuchGroup);
    }
    let Some((&index, parent_path)) = path.split_last() else {
        return Err(Error::RootGroup);
    };
    if tree::within(vault, target, id) {
        return Err(Error::Cycle);
    }
    let parent = tree::group_at(&vault.root, parent_path)
        .ok_or(Error::NoSuchGroup)?
        .uuid;
    if parent != target {
        let height = tree::group_at(&vault.root, &path).map_or(0, tree::height);
        check_depth(vault, target, height)?;
    }
    let count_after = tree::group(vault, target)
        .map(|t| t.groups.len().saturating_sub(usize::from(parent == target)))
        .unwrap_or(0);
    let final_index = match position {
        Position::End => count_after,
        Position::At(i) => i.min(count_after),
    };
    if parent == target && final_index == index {
        return Ok(false);
    }
    let from = tree::group_at_mut(&mut vault.root, parent_path).ok_or(Error::NoSuchGroup)?;
    if index >= from.groups.len() {
        return Err(Error::NoSuchGroup);
    }
    let mut g = from.groups.remove(index);
    if parent != target {
        g.previous_parent = Some(parent);
    }
    g.times.location_changed = now;
    g.times.last_modification = now;
    g.times.last_access = now;
    let to = tree::group_mut(vault, target).ok_or(Error::NoSuchGroup)?;
    let at = final_index.min(to.groups.len());
    to.groups.insert(at, g);
    Ok(true)
}

/// Moves live entries into `target`, in the given order, each appended
/// after its entries (MOD-02.21). An entry already in `target` stays. Per
/// moved entry: previous parent = the group it left; location changed =
/// `now`; last modification and last access = `now` when the previous
/// parent changed. No history item; group times do not move (MOD-02.25).
/// Returns how many entries moved.
///
/// # Errors
/// `NoSuchGroup`; `NoSuchEntry` for any id (nothing moves then).
pub fn move_entries(
    vault: &mut Vault,
    ids: &[Uuid],
    target: Uuid,
    now: Time,
) -> Result<usize, Error> {
    if tree::group(vault, target).is_none() {
        return Err(Error::NoSuchGroup);
    }
    if ids.iter().any(|&id| tree::entry(vault, id).is_none()) {
        return Err(Error::NoSuchEntry);
    }
    let mut moved = 0usize;
    for &id in ids {
        if move_one_entry(vault, id, target, now)? {
            moved = moved.saturating_add(1);
        }
    }
    Ok(moved)
}

/// One entry move with the MOD-02.21 / MOD-04.5 fields.
pub(crate) fn move_one_entry(
    vault: &mut Vault,
    id: Uuid,
    target: Uuid,
    now: Time,
) -> Result<bool, Error> {
    let (path, i) = tree::entry_place(&vault.root, id).ok_or(Error::NoSuchEntry)?;
    let from = tree::group_at_mut(&mut vault.root, &path).ok_or(Error::NoSuchGroup)?;
    if from.uuid == target {
        return Ok(false);
    }
    let old = from.uuid;
    if i >= from.entries.len() {
        return Err(Error::NoSuchEntry);
    }
    let mut e = from.entries.remove(i);
    e.times.location_changed = now;
    if e.previous_parent != Some(old) {
        e.previous_parent = Some(old);
        e.times.last_modification = now;
        e.times.last_access = now;
    }
    match tree::group_mut(vault, target) {
        Some(to) => {
            to.entries.push(e);
            Ok(true)
        }
        None => Err(Error::NoSuchGroup),
    }
}

/// Swaps live entry `id` with its neighbour in its group's stored order
/// (MOD-02.24): `up` towards the first. No time moves. Returns whether it
/// moved (the first entry cannot move up, the last not down).
///
/// # Errors
/// `NoSuchEntry`.
pub fn move_entry(vault: &mut Vault, id: Uuid, up: bool) -> Result<bool, Error> {
    let (path, i) = tree::entry_place(&vault.root, id).ok_or(Error::NoSuchEntry)?;
    let g = tree::group_at_mut(&mut vault.root, &path).ok_or(Error::NoSuchGroup)?;
    let j = if up {
        i.checked_sub(1)
    } else {
        i.checked_add(1).filter(|&j| j < g.entries.len())
    };
    match j {
        Some(j) => {
            g.entries.swap(i, j);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Sorts the child groups of `id` and of every group in its subtree by name
/// (MOD-02.26): folded code points, a name that starts the other first, no
/// numeric order; `descending` reverses. Ties keep their order (stable)
/// and the recycle bin stays last (MOD-04.16). No time moves (MOD-02.25).
///
/// # Errors
/// `NoSuchGroup`.
pub fn sort_groups(vault: &mut Vault, id: Uuid, descending: bool) -> Result<(), Error> {
    let bin = recycle::bin_id(vault);
    let g = tree::group_mut(vault, id).ok_or(Error::NoSuchGroup)?;
    let mut stack = vec![g];
    while let Some(g) = stack.pop() {
        g.groups.sort_by(|a, b| {
            let (ab, bb) = (Some(a.uuid) == bin, Some(b.uuid) == bin);
            ab.cmp(&bb).then_with(|| {
                let o = cmp_folded(&a.name, &b.name);
                if descending { o.reverse() } else { o }
            })
        });
        stack.extend(g.groups.iter_mut());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Inheritance.

fn resolve_switch(vault: &Vault, group: Uuid, get: impl Fn(&Group) -> Switch) -> Option<bool> {
    let chain = tree::ancestors(vault, group);
    if chain.is_empty() {
        return None;
    }
    for id in chain {
        match tree::group(vault, id).map(&get) {
            Some(Switch::On) => return Some(true),
            Some(Switch::Off) => return Some(false),
            _ => {}
        }
    }
    Some(true)
}

/// The group's effective search value (MOD-02.13): its own On or Off, else
/// its parent's, and so on; Inherit on the root is On. `None` for no group.
#[must_use]
pub fn searching_on(vault: &Vault, group: Uuid) -> Option<bool> {
    resolve_switch(vault, group, |g| g.searching)
}

/// The group's effective auto-type value (MOD-02.14), resolved like
/// [`searching_on`].
#[must_use]
pub fn auto_type_on(vault: &Vault, group: Uuid) -> Option<bool> {
    resolve_switch(vault, group, |g| g.auto_type)
}

/// The group's effective auto-type sequence (MOD-02.15): walking up, an Off
/// switch gives none (empty), the first non-empty default sequence is the
/// result, and past the root the built-in default.
#[must_use]
pub fn group_sequence(vault: &Vault, group: Uuid) -> String {
    for id in tree::ancestors(vault, group) {
        let Some(g) = tree::group(vault, id) else {
            break;
        };
        if g.auto_type == Switch::Off {
            return String::new();
        }
        if !g.default_sequence.is_empty() {
            return g.default_sequence.clone();
        }
    }
    DEFAULT_SEQUENCE.to_owned()
}

/// The entry's effective auto-type sequence (MOD-02.16): empty when its own
/// flag is off, it is in no group, or the group gives none; its own default
/// sequence when set; for the built-in group default, `{PASSWORD}{ENTER}`
/// without a user name or `{USERNAME}{ENTER}` without a password (raw
/// values); else the group's sequence.
#[must_use]
pub fn entry_sequence(vault: &Vault, entry: Uuid) -> String {
    let (Some(e), Some(group)) = (tree::entry(vault, entry), tree::entry_group(vault, entry))
    else {
        return String::new();
    };
    let from_group = group_sequence(vault, group);
    if !e.auto_type.enabled || from_group.is_empty() {
        return String::new();
    }
    if !e.auto_type.default_sequence.is_empty() {
        return e.auto_type.default_sequence.clone();
    }
    let (user, pass) = (e.value("UserName"), e.value("Password"));
    if from_group == DEFAULT_SEQUENCE && (!user.is_empty() || !pass.is_empty()) {
        return match (user.is_empty(), pass.is_empty()) {
            (true, _) => "{PASSWORD}{ENTER}".into(),
            (_, true) => "{USERNAME}{ENTER}".into(),
            _ => DEFAULT_SEQUENCE.into(),
        };
    }
    from_group
}

/// A browser option of a group (MOD-02.17): the value of the first group up
/// the tree that has the custom data `key` is on when exactly `true`; no
/// group with the key gives off.
#[must_use]
pub fn browser_option(vault: &Vault, group: Uuid, key: &str) -> bool {
    tree::ancestors(vault, group)
        .into_iter()
        .find_map(|id| {
            tree::group(vault, id).and_then(|g| g.custom_data.get(key).map(|v| v == "true"))
        })
        .unwrap_or(false)
}

/// The restrict-to-browser value of a group (MOD-02.17): the value of the
/// first group up the tree that has `key`, even an empty one; `None` (no
/// restriction) when no group has it or the value is empty.
#[must_use]
pub fn browser_restriction(vault: &Vault, group: Uuid, key: &str) -> Option<String> {
    tree::ancestors(vault, group)
        .into_iter()
        .find_map(|id| {
            tree::group(vault, id).and_then(|g| g.custom_data.get(key).map(str::to_owned))
        })
        .filter(|v| !v.is_empty())
}

/// True when the group or one above it carries the shared-group key
/// (MOD-02.18, INT-08).
#[must_use]
pub fn is_shared(vault: &Vault, group: Uuid) -> bool {
    let key = String::from_utf8_lossy(SHARED_KEY);
    tree::ancestors(vault, group)
        .into_iter()
        .any(|id| tree::group(vault, id).is_some_and(|g| g.custom_data.get(&key).is_some()))
}

// ---------------------------------------------------------------------------
// Copies (MOD-02.22).

/// What to copy or move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    /// A group with its subtree and entries.
    Group(Uuid),
    /// One live entry with its history.
    Entry(Uuid),
}

/// Gives a copied entry a new id and the copy times of MOD-02.22: creation,
/// modification, last access and location changed `now`; expiry and usage
/// count kept; history items keep their times and take the new id. The
/// previous parent stays inside one vault (LD-107, MOD-10.3) and is cleared,
/// history items included, for another vault (LD-68).
fn reset_entry(e: &mut Entry, id: Uuid, now: Time, same_vault: bool) {
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
    if !same_vault {
        e.previous_parent = None;
        for h in &mut e.history {
            h.previous_parent = None;
        }
    }
}

/// The custom icons `vault` uses in `group`'s subtree (live entries and
/// history included), or in one entry.
fn icons_used(g: Option<&Group>, e: Option<&Entry>) -> HashSet<Uuid> {
    let mut out = HashSet::new();
    let mut take = |i: Icon| {
        if let Icon::Custom(id) = i {
            out.insert(id);
        }
    };
    if let Some(e) = e {
        take(e.icon);
        e.history.iter().for_each(|h| take(h.icon));
    }
    if let Some(g) = g {
        for g in g.subtree() {
            take(g.icon);
            for e in &g.entries {
                take(e.icon);
                e.history.iter().for_each(|h| take(h.icon));
            }
        }
    }
    out
}

/// A finished copy, not yet placed.
enum Copied {
    Group(Group),
    Entry(Entry),
}

/// Copies `item` of `vault` with new ids not in `groups` and `entries`
/// (which take the new ids) and the copy times of MOD-02.22; previous
/// parents as [`reset_entry`]. Returns the copy, the custom icons it uses
/// and its new id.
fn make_copy(
    vault: &Vault,
    item: Item,
    groups: &mut HashSet<Uuid>,
    entries: &mut HashSet<Uuid>,
    now: Time,
    same_vault: bool,
) -> Result<(Copied, HashSet<Uuid>, Uuid), Error> {
    match item {
        Item::Entry(id) => {
            let e = tree::entry(vault, id).ok_or(Error::NoSuchEntry)?;
            let mut copy = e.duplicate(true);
            let new = tree::fresh_id(|u| entries.contains(&u))?;
            entries.insert(new);
            reset_entry(&mut copy, new, now, same_vault);
            Ok((Copied::Entry(copy), icons_used(None, Some(e)), new))
        }
        Item::Group(id) => {
            let g = tree::group(vault, id).ok_or(Error::NoSuchGroup)?;
            let icons = icons_used(Some(g), None);
            let mut copy = g.duplicate();
            let mut stack = vec![&mut copy];
            let mut first = None;
            while let Some(c) = stack.pop() {
                let new = tree::fresh_id(|u| groups.contains(&u))?;
                groups.insert(new);
                first.get_or_insert(new);
                c.uuid = new;
                let t = &mut c.times;
                (
                    t.creation,
                    t.last_modification,
                    t.last_access,
                    t.location_changed,
                ) = (now, now, now, now);
                if !same_vault {
                    c.previous_parent = None;
                }
                c.last_top_visible_entry = None;
                for e in &mut c.entries {
                    let new = tree::fresh_id(|u| entries.contains(&u))?;
                    entries.insert(new);
                    reset_entry(e, new, now, same_vault);
                }
                stack.extend(c.groups.iter_mut());
            }
            Ok((Copied::Group(copy), icons, first.unwrap_or(Uuid::ZERO)))
        }
    }
}

/// Places a copy: a group at `position` among `group`'s child groups, an
/// entry after its entries.
fn place(vault: &mut Vault, group: Uuid, position: Position, copy: Copied) -> Result<(), Error> {
    match copy {
        Copied::Entry(e) => tree::group_mut(vault, group)
            .ok_or(Error::NoSuchGroup)?
            .entries
            .push(e),
        Copied::Group(g) => place_group(vault, group, position, g)?,
    }
    Ok(())
}

/// Puts a group (with its ids already unique in the vault) at `position`
/// among `parent`'s child groups, not past [`MAX_GROUP_LEVEL`].
pub(crate) fn place_group(
    vault: &mut Vault,
    parent: Uuid,
    position: Position,
    g: Group,
) -> Result<(), Error> {
    check_depth(vault, parent, tree::height(&g))?;
    let to = tree::group_mut(vault, parent).ok_or(Error::NoSuchGroup)?;
    let at = match position {
        Position::End => to.groups.len(),
        Position::At(i) => i.min(to.groups.len()),
    };
    to.groups.insert(at, g);
    Ok(())
}

/// Copies `item` of `source` into group `group` of another open vault
/// (MOD-02.22): every group and live entry gets a new id and the copy times
/// (creation, modification, last access, location changed `now`; expiry and
/// usage count kept; history items keep their times and take the new id;
/// no previous parent, LD-68, LD-103); a group goes to `position`, an entry after
/// the group's entries; the custom icons it uses are added to `target` when
/// it lacks their id, with name and time (MOD-06.17, D-06-4). Returns the
/// new id.
///
/// # Errors
/// `NoSuchGroup`; `NoSuchEntry`; `TooDeep` (LD-106); `RandomSource`.
pub fn copy_into(
    source: &Vault,
    item: Item,
    target: &mut Vault,
    group: Uuid,
    position: Position,
    now: Time,
) -> Result<Uuid, Error> {
    if tree::group(target, group).is_none() {
        return Err(Error::NoSuchGroup);
    }
    let mut groups: HashSet<Uuid> = target.root.subtree().iter().map(|g| g.uuid).collect();
    let mut entries: HashSet<Uuid> = tree::all_entry_ids(target).into_iter().collect();
    let (copy, icons, new) = make_copy(source, item, &mut groups, &mut entries, now, false)?;
    place(target, group, position, copy)?;
    let have: HashSet<Uuid> = target.meta.custom_icons.iter().map(|i| i.uuid).collect();
    let mut add: Vec<CustomIcon> = source
        .meta
        .custom_icons
        .iter()
        .filter(|i| icons.contains(&i.uuid) && !have.contains(&i.uuid))
        .cloned()
        .collect();
    target.meta.custom_icons.append(&mut add);
    Ok(new)
}

/// Copies `item` inside the same vault (MOD-02.22, the Option key drag):
/// new ids and reset times as [`copy_into`], history included, no name
/// suffix; previous parents kept (LD-107). Not inside the recycle bin
/// (MOD-04.15). Returns the new id.
///
/// # Errors
/// `NoSuchGroup`; `NoSuchEntry`; `InRecycleBin`; `TooDeep` (LD-106);
/// `RandomSource`.
pub fn copy_within(
    vault: &mut Vault,
    item: Item,
    group: Uuid,
    position: Position,
    now: Time,
) -> Result<Uuid, Error> {
    if tree::group(vault, group).is_none() {
        return Err(Error::NoSuchGroup);
    }
    if recycle::group_in_bin(vault, group) {
        return Err(Error::InRecycleBin);
    }
    let mut groups: HashSet<Uuid> = vault.root.subtree().iter().map(|g| g.uuid).collect();
    let mut entries: HashSet<Uuid> = tree::all_entry_ids(vault).into_iter().collect();
    let (copy, _, new) = make_copy(vault, item, &mut groups, &mut entries, now, true)?;
    place(vault, group, position, copy)?;
    Ok(new)
}

/// Moves `item` into another open vault (MOD-02.22): [`copy_into`], then
/// the source item is deleted for good from `source`, which adds its
/// deleted-object records (FMT-15.7). Returns the new id.
///
/// # Errors
/// As [`copy_into`]; `RootGroup` for the root.
pub fn move_into(
    source: &mut Vault,
    item: Item,
    target: &mut Vault,
    group: Uuid,
    position: Position,
    now: Time,
) -> Result<Uuid, Error> {
    if let Item::Group(id) = item
        && id == source.root.uuid
    {
        return Err(Error::RootGroup);
    }
    let new = copy_into(source, item, target, group, position, now)?;
    match item {
        Item::Entry(id) => recycle::remove_entry_for_good(source, id, now)?,
        Item::Group(id) => recycle::remove_group_for_good(source, id, now)?,
    }
    Ok(new)
}

/// The default group icon, for callers that reset an icon (MOD-04.12).
#[must_use]
pub fn default_group_icon() -> Icon {
    GROUP_DEFAULT
}
