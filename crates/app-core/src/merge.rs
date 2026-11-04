//! Merge (MOD-11, story E4-S12): copies the changes of a source vault into
//! a target vault without losing data.
//!
//! Guarantees:
//! - Only the target changes; the source is read only. A dry run changes
//!   nothing and gives the change list the real merge gives (MOD-11.25).
//! - Keep-newer never drops a version: the older side's current version
//!   goes into the joined history (MOD-11.13, MOD-11.14). Only the deletion
//!   pass of FMT-15.11 removes an entry or group: in a same-vault merge over
//!   the whole vault, keeping every object changed or moved after the
//!   deletion (LD-265, LD-271 (2)); in a shared-group import only inside the
//!   shared group (D-11-9). No other merge erases anything (MOD-11.15).
//! - Work is linear in the objects walked; a group move that would make a
//!   cycle is skipped with a Conflict record, so every merge ends
//!   (MOD-11.9, AT-A08).
//! - A merge never lowers the cipher, the KDF cost or the protection flags.
//!   It takes the source's newer key on its own only in a same-vault merge
//!   after a change on disk, of a conflict copy or in server sync (LD-264),
//!   else only with the user's yes (MOD-11.19, LD-60); never from a share,
//!   the import wizard or a copy under a key this Mac retired (MOD-11.31).
//! - Change records hold kinds, paths, titles, ids and field names, never a
//!   field value, an attachment or a custom data value (MOD-11.24). A path
//!   is cut after [`PATH_BYTES`] bytes, so the records grow with the
//!   source's size, not with name length times items (F-164).

use crate::Error;
use crate::health::shown_title;
use crate::history;
use crate::recycle;
use app_model::custom_data::CustomDataItem;
use app_model::entry::STANDARD_FIELDS;
use app_model::{Entry, Field, Group, Kdf, Time, Uuid, Vault};
use std::collections::{HashMap, HashSet};

/// Which merge flow runs (MOD-11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Merge from another vault in the window (MOD-11.27): the preview,
    /// then the key question.
    Window,
    /// The command line tool's merge (MOD-11.28): no question.
    CommandLine,
    /// The merge after a change on disk (MOD-11.29), also the rollback
    /// guard's merge of an older disk version (APP-05.26): the vault in
    /// memory is the source, the disk version the target. The newer key is
    /// taken without a question (LD-264).
    ChangeOnDisk,
    /// A cloud conflict copy (APP-05.17): the copy is the source, the open
    /// vault the target. The newer key is taken without a question (LD-264).
    ConflictCopy,
    /// Server sync (SYN-03.5 step 3): the open vault is the source, the
    /// server copy the target, as after a change on disk. The newer key is
    /// taken without a question (LD-264).
    ServerSync,
    /// One direction of a remote sync (INT-09): no question.
    RemoteSync,
    /// A shared-group import (INT-08): synchronize mode, ids only inside
    /// the target start group (LD-61), no vault custom data.
    SharedImport,
    /// The import wizard into a new vault (FEA-08): no vault custom data;
    /// the new root takes the imported root's name and notes.
    ImportWizard,
}

/// What a merge is asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// The flow.
    pub kind: Kind,
    /// The user's yes to `merge.ask.key` (window merge only, MOD-11.19).
    pub take_key: bool,
    /// Compute the change list only (MOD-11.25).
    pub dry_run: bool,
    /// The source start group; `None` for the source root.
    pub source_start: Option<Uuid>,
    /// The target start group; `None` for the target root.
    pub target_start: Option<Uuid>,
    /// The source is a copy under a key this Mac retired, and the user
    /// chose Merge anyway (MOD-11.31, LD-269 (3)): the content merge only.
    /// It is never a same-vault merge, so it takes no key, no deletions and
    /// no metadata, and skips vault custom data; it drops this Mac's own
    /// deleted-objects item for each entry or group it adds (F-173). The
    /// caller passes this Mac's open vault as the target in every flow.
    pub retired: bool,
}

impl Options {
    /// A merge of `kind` from root to root, no key taken, not a dry run.
    #[must_use]
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            take_key: false,
            dry_run: false,
            source_start: None,
            target_start: None,
            retired: false,
        }
    }
}

/// The kind of one change record (MOD-11.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// MOD-11.5, MOD-11.6.
    Added,
    /// MOD-11.7, MOD-11.8.
    Moved,
    /// MOD-11.10, MOD-11.11.
    Modified,
    /// An erase by the deletion pass (FMT-15.11).
    Deleted,
    /// Vault metadata.
    Metadata,
    /// App only: a cycle, a same-time conflict, an id outside a shared
    /// group, a setting not lowered or a key not taken.
    Conflict,
}

/// What a record is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    /// An entry.
    Entry,
    /// A group.
    Group,
    /// The vault.
    Vault,
}

/// One change record. No value of a field, attachment or custom data item
/// ever goes in (MOD-11.24).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The kind.
    pub kind: ChangeKind,
    /// Entry, group or vault.
    pub object: Object,
    /// The group path (`/Root/G1`); empty for the vault.
    pub path: String,
    /// The entry title; empty for groups and the vault.
    pub title: String,
    /// The object's id; none for the vault.
    pub id: Option<Uuid>,
    /// Field names, counts or notes; never a value.
    pub details: Vec<String>,
}

impl Change {
    /// The command line text line (MOD-11.24): TAB, the kind, `: `, the
    /// path in quotes, `/` and the title in quotes for entries, the id in
    /// `[{…}]`, then the details in parentheses.
    #[must_use]
    pub fn line(&self) -> String {
        let kind = match self.kind {
            ChangeKind::Added => "Added",
            ChangeKind::Moved => "Moved",
            ChangeKind::Modified => "Modified",
            ChangeKind::Deleted => "Deleted",
            ChangeKind::Metadata => "Metadata",
            ChangeKind::Conflict => "Conflict",
        };
        let mut out = format!("\t{kind}: ");
        if self.object != Object::Vault {
            out.push_str(&format!("'{}'", self.path));
        }
        if self.object == Object::Entry {
            out.push_str(&format!("/'{}'", self.title));
        }
        if let Some(id) = self.id {
            out.push_str(&format!(" [{{{}}}]", dashed(id)));
        }
        if !self.details.is_empty() {
            out.push_str(&format!(" ({})", self.details.join(", ")));
        }
        out
    }
}

/// What a merge did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    /// The records in walk order (MOD-11.2, MOD-11.3); empty exactly when
    /// nothing changed (MOD-11.26).
    pub changes: Vec<Change>,
    /// The source's composite key must replace the target's: the caller
    /// moves the credentials, removes the vault's quick unlock data and
    /// derives the key at the next save (MOD-11.19 limit 2, MOD-12.10).
    pub key_taken: bool,
}

/// F-164: the bytes of a record's path, so each record costs about the
/// tree depth plus this, however long the group names a source holds (a
/// name may be 64 MiB, FMT-08.12).
pub const PATH_BYTES: usize = 1_024;

/// Adds `/` and `name` to a record path; past [`PATH_BYTES`] cuts it at a
/// character boundary, adds `…` and gives false.
fn push_name(out: &mut String, name: &str) -> bool {
    out.push('/');
    let room = PATH_BYTES.saturating_sub(out.len());
    if name.len() <= room {
        out.push_str(name);
        return true;
    }
    let mut cut = room;
    while !name.is_char_boundary(cut) {
        cut = cut.saturating_sub(1);
    }
    out.push_str(name.get(..cut).unwrap_or(""));
    out.push('…');
    false
}

/// The shared-group settings item of a group (MOD-11.10), as bytes (name
/// rule).
const SHARE_KEY: [u8; 18] = [
    0x4B, 0x65, 0x65, 0x53, 0x68, 0x61, 0x72, 0x65, 0x2F, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E,
    0x63, 0x65,
];
/// The browser association prefix (FMT-14.20), as bytes.
const BROWSER_PREFIX: [u8; 13] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x42, 0x52, 0x4F, 0x57, 0x53, 0x45, 0x52, 0x5F,
];
/// The remote sync settings key (FMT-14.20), as bytes.
const REMOTE_SYNC: [u8; 25] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x52, 0x45, 0x4D, 0x4F, 0x54, 0x45, 0x5F, 0x53, 0x59, 0x4E, 0x43,
    0x5F, 0x53, 0x45, 0x54, 0x54, 0x49, 0x4E, 0x47, 0x53,
];
/// The random padding key (FMT-14.21), as bytes.
const PADDING: [u8; 16] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x52, 0x41, 0x4E, 0x44, 0x4F, 0x4D, 0x5F, 0x53, 0x4C, 0x55, 0x47,
];
/// The prefix of the public display items (FMT-03.23), as bytes.
const PUBLIC_PREFIX: [u8; 12] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x5F,
];
const LAST_MODIFIED: &str = "_LAST_MODIFIED";

/// The three public display items MOD-11.19 merges: the prefix plus
/// `NAME`, `COLOR` or `ICON` (F-073). Other public items, such as the
/// public id, stay the target's.
fn display_item(i: &app_model::PublicItem) -> bool {
    i.name
        .strip_prefix(&PUBLIC_PREFIX[..])
        .is_some_and(|rest| matches!(rest, b"NAME" | b"COLOR" | b"ICON"))
}

/// Merges `source` into `target` (MOD-11). `now` is the merge time (new
/// bins, custom data item times).
///
/// # Errors
/// `RandomSource` when a recycle bin must be made and no fresh id can be
/// drawn; the target is then unchanged only in a dry run.
pub fn merge(target: &mut Vault, source: &Vault, o: &Options, now: Time) -> Result<Merged, Error> {
    if o.dry_run {
        let mut copy = target.duplicate();
        return Merger::new(&mut copy, source, o, now).run();
    }
    Merger::new(target, source, o, now).run()
}

/// Where every target object sits, kept up to date as the merge adds and
/// moves objects, so each lookup is a few map reads (linear merge work):
/// each group's parent and index in it, each live entry's group and index.
/// A moved or erased object leaves a placeholder with the zero id at its old
/// index, so no other index shifts; [`compact`] drops them at the end.
struct Index {
    root: Uuid,
    parent: HashMap<Uuid, Uuid>,
    gpos: HashMap<Uuid, usize>,
    epos: HashMap<Uuid, (Uuid, usize)>,
}

impl Index {
    fn new(root: &Group) -> Self {
        let mut ix = Self {
            root: root.uuid,
            parent: HashMap::new(),
            gpos: HashMap::new(),
            epos: HashMap::new(),
        };
        let mut stack = vec![root];
        while let Some(g) = stack.pop() {
            for (i, e) in g.entries.iter().enumerate() {
                ix.epos.entry(e.uuid).or_insert((g.uuid, i));
            }
            for (i, c) in g.groups.iter().enumerate() {
                if !ix.parent.contains_key(&c.uuid) && c.uuid != ix.root {
                    ix.parent.insert(c.uuid, g.uuid);
                    ix.gpos.insert(c.uuid, i);
                }
                stack.push(c);
            }
        }
        ix
    }

    fn has_group(&self, id: Uuid) -> bool {
        id == self.root || self.parent.contains_key(&id)
    }

    /// The ids from the root's child down to `id`; empty for the root.
    fn chain(&self, id: Uuid) -> Option<Vec<Uuid>> {
        let mut out = Vec::new();
        let mut at = id;
        while at != self.root {
            out.push(at);
            at = *self.parent.get(&at)?;
            if out.len() > self.parent.len() {
                return None;
            }
        }
        out.reverse();
        Some(out)
    }

    /// True when `id` is `ancestor` or lies below it.
    fn within(&self, id: Uuid, ancestor: Uuid) -> bool {
        if ancestor == self.root || id == ancestor {
            return true;
        }
        let mut at = id;
        for _ in 0..=self.parent.len() {
            match self.parent.get(&at) {
                Some(p) if *p == ancestor => return true,
                Some(p) => at = *p,
                None => return false,
            }
        }
        false
    }

    fn group<'a>(&self, root: &'a Group, id: Uuid) -> Option<&'a Group> {
        let mut g = root;
        for c in self.chain(id)? {
            g = g.groups.get(*self.gpos.get(&c)?).filter(|x| x.uuid == c)?;
        }
        Some(g)
    }

    fn group_mut<'a>(&self, root: &'a mut Group, id: Uuid) -> Option<&'a mut Group> {
        let mut g = root;
        for c in self.chain(id)? {
            g = g
                .groups
                .get_mut(*self.gpos.get(&c)?)
                .filter(|x| x.uuid == c)?;
        }
        Some(g)
    }

    fn entry_mut<'a>(&self, root: &'a mut Group, id: Uuid) -> Option<&'a mut Entry> {
        let (g, i) = *self.epos.get(&id)?;
        self.group_mut(root, g)?
            .entries
            .get_mut(i)
            .filter(|e| e.uuid == id)
    }
}

/// The placeholder a moved or erased group leaves (the zero id).
fn tomb_group() -> Group {
    Group::new(Uuid::default(), String::new(), Time(0))
}

/// An object's time in a same-vault merge: the later of its Mod and Loc,
/// so a move counts as a change (LD-265, LD-271 (2)).
fn later(t: &app_model::Times) -> Time {
    t.last_modification.max(t.location_changed)
}

/// The placeholder a moved or erased entry leaves (the zero id).
fn tomb_entry() -> Entry {
    Entry::new(Uuid::default(), Time(0))
}

/// Drops every placeholder; no real object has the zero id.
fn compact(root: &mut Group) {
    let mut stack = vec![root];
    while let Some(g) = stack.pop() {
        g.entries.retain(|e| e.uuid != Uuid::default());
        g.groups.retain(|c| c.uuid != Uuid::default());
        stack.extend(g.groups.iter_mut());
    }
}

/// A lookup result inside the merge's scope (LD-61).
enum Found {
    /// Not in the target.
    None,
    /// In the target, in scope: the group holding it (entries) or itself.
    Here(Uuid),
    /// In the target, outside the shared group: where it is.
    Outside(Uuid),
}

struct Merger<'t, 's> {
    t: &'t mut Vault,
    s: &'s Vault,
    o: Options,
    now: Time,
    ix: Index,
    changes: Vec<Change>,
    target_start: Uuid,
    source_start: Uuid,
    same_vault: bool,
    key_taken: bool,
    deferred: Vec<Move>,
    /// Entries and groups this merge added (MOD-11.5, MOD-11.6): one the
    /// whole-vault pass erases again leaves no record (MOD-11.15).
    added_entries: HashSet<Uuid>,
    added_groups: HashSet<Uuid>,
    /// F-154, LD-287 (2): the source copy's own later Mod or Loc of each
    /// matched entry, and of each matched group (not the roots or start
    /// groups); in a same-vault merge the deletion pass keeps an object
    /// either side changed or moved after its item (MOD-11.30). F-155,
    /// LD-288 (1): one map per kind, since an entry may share a group's id
    /// (MOD-11.22).
    source_times: HashMap<Uuid, Time>,
    source_group_times: HashMap<Uuid, Time>,
    /// LD-207, F-066: either vault's flag protects Titles, so records mask
    /// every Title; an entry's own flag masks its Title anyway.
    mask_titles: bool,
}

/// A group move the walk wants (MOD-11.8).
struct Move {
    id: Uuid,
    parent: Uuid,
    loc: Time,
}

#[derive(PartialEq, Eq)]
enum Moving {
    Moved,
    Stays,
    Cycle,
}

impl<'t, 's> Merger<'t, 's> {
    fn new(t: &'t mut Vault, s: &'s Vault, o: &Options, now: Time) -> Self {
        let target_start = o.target_start.unwrap_or(t.root.uuid);
        let source_start = o.source_start.unwrap_or(s.root.uuid);
        // MOD-11's Notation: the one meaning of a same-vault merge. That the
        // copy opened with this vault's key or with credentials the user
        // gave for it is the caller's: the merge only ever sees an open
        // copy. A copy under a key this Mac retired never is one (LD-267 (2)).
        let same_vault = s.root.uuid == t.root.uuid
            && target_start == t.root.uuid
            && source_start == s.root.uuid
            && !matches!(o.kind, Kind::SharedImport | Kind::ImportWizard)
            && !o.retired;
        let ix = Index::new(&t.root);
        let mask_titles = t.meta.memory_protection.for_field("Title")
            || s.meta.memory_protection.for_field("Title");
        Self {
            t,
            s,
            o: *o,
            now,
            ix,
            changes: Vec::new(),
            target_start,
            source_start,
            same_vault,
            key_taken: false,
            deferred: Vec::new(),
            added_entries: HashSet::new(),
            added_groups: HashSet::new(),
            source_times: HashMap::new(),
            source_group_times: HashMap::new(),
            mask_titles,
        }
    }

    fn synchronize(&self) -> bool {
        self.o.kind == Kind::SharedImport
    }

    /// LD-130: the recycle bins map only when both start groups are roots,
    /// never in a shared-group import.
    fn bins_map(&self) -> bool {
        self.o.kind != Kind::SharedImport
            && self.source_start == self.s.root.uuid
            && self.target_start == self.t.root.uuid
    }

    fn run(mut self) -> Result<Merged, Error> {
        let s = self.s;
        let Some(start) = s.root.find_group(self.source_start) else {
            return Err(Error::NoSuchGroup);
        };
        if !self.ix.has_group(self.target_start) {
            return Err(Error::NoSuchGroup);
        }
        if self.same_vault {
            // MOD-11.20: the two roots are a matched group.
            self.group_fields(start, self.target_start);
        }
        self.walk(start, self.target_start)?;
        self.retry_moves();
        if self.synchronize() || self.same_vault {
            self.deletions();
        } else if self.o.retired {
            // MOD-11.31 (F-173, LD-313): the user chose to keep what Merge
            // anyway added, so this Mac's own item for it goes; left beside
            // the object (FMT-15.5), it would let the next merge erase it or
            // decide differently a second time (MOD-11.30).
            let (e, g) = (&self.added_entries, &self.added_groups);
            self.t
                .deleted_objects
                .retain(|d| !e.contains(&d.uuid) && !g.contains(&d.uuid));
        }
        compact(&mut self.t.root);
        self.icons();
        if !matches!(self.o.kind, Kind::SharedImport | Kind::ImportWizard) && !self.o.retired {
            self.custom_data();
        }
        if self.same_vault {
            self.metadata();
        }
        if self.o.kind == Kind::ImportWizard
            && (self.t.root.name != start.name || self.t.root.notes != start.notes)
        {
            // MOD-11.1: the new root takes the imported root's name and notes.
            self.t.root.name.clone_from(&start.name);
            self.t.root.notes.clone_from(&start.notes);
            let path = format!("/{}", start.name);
            let id = self.t.root.uuid;
            self.record(
                ChangeKind::Modified,
                Object::Group,
                &path,
                "",
                Some(id),
                vec!["Name".into(), "Notes".into()],
            );
        }
        Ok(Merged {
            changes: self.changes,
            key_taken: self.key_taken,
        })
    }

    /// The real path of a target group: `/Root/G1` (LD-130), at most
    /// [`PATH_BYTES`] bytes and then `…` (F-164).
    fn path_of(&self, id: Uuid) -> String {
        let mut out = String::new();
        if !push_name(&mut out, &self.t.root.name) {
            return out;
        }
        let mut g = &self.t.root;
        for c in self.ix.chain(id).unwrap_or_default() {
            let Some(next) = self.ix.gpos.get(&c).and_then(|i| g.groups.get(*i)) else {
                break;
            };
            if !push_name(&mut out, &next.name) {
                break;
            }
            g = next;
        }
        out
    }

    fn record(
        &mut self,
        kind: ChangeKind,
        object: Object,
        path: &str,
        title: &str,
        id: Option<Uuid>,
        details: Vec<String>,
    ) {
        self.changes.push(Change {
            kind,
            object,
            path: path.to_owned(),
            title: title.to_owned(),
            id,
            details,
        });
    }

    fn in_scope(&self, group: Uuid) -> bool {
        !self.synchronize() || self.ix.within(group, self.target_start)
    }

    fn find_group(&self, id: Uuid) -> Found {
        if !self.ix.has_group(id) {
            return Found::None;
        }
        if self.in_scope(id) {
            Found::Here(id)
        } else {
            Found::Outside(id)
        }
    }

    fn find_entry(&self, id: Uuid) -> Found {
        match self.ix.epos.get(&id) {
            None => Found::None,
            Some((g, _)) if self.in_scope(*g) => Found::Here(*g),
            Some((g, _)) => Found::Outside(*g),
        }
    }

    /// MOD-11.3: the entries of `sg`, then each child group and its subtree.
    fn walk(&mut self, sg: &'s Group, tg: Uuid) -> Result<(), Error> {
        for e in &sg.entries {
            self.entry(e, tg);
        }
        for c in &sg.groups {
            if let Some(next) = self.group(c, tg)? {
                self.walk(c, next)?;
            }
        }
        Ok(())
    }

    /// Appends `g` to `parent` and indexes it.
    fn push_group(&mut self, parent: Uuid, g: Group) -> bool {
        let id = g.uuid;
        let Some(p) = self.ix.group_mut(&mut self.t.root, parent) else {
            return false;
        };
        p.groups.push(g);
        let at = p.groups.len().saturating_sub(1);
        self.ix.parent.insert(id, parent);
        self.ix.gpos.insert(id, at);
        true
    }

    /// A source child group (MOD-11.4, MOD-11.6, MOD-11.8 to MOD-11.10,
    /// MOD-11.16): the target group to walk into, or `None` to skip it.
    fn group(&mut self, c: &'s Group, parent: Uuid) -> Result<Option<Uuid>, Error> {
        match self.find_group(c.uuid) {
            Found::Outside(at) => {
                let path = self.path_of(at);
                self.record(
                    ChangeKind::Conflict,
                    Object::Group,
                    &path,
                    "",
                    Some(c.uuid),
                    vec!["outside the shared group".into()],
                );
                Ok(None)
            }
            // MOD-11.9, LD-130: the target root and the target start group
            // are never moved, renamed or rewritten here.
            Found::Here(id) if id == self.ix.root || id == self.target_start => Ok(Some(id)),
            Found::Here(id) => {
                self.source_group_times.insert(id, later(&c.times));
                self.group_move(c, id, parent);
                self.group_fields(c, id);
                Ok(Some(id))
            }
            Found::None => {
                if self.bins_map()
                    && recycle::bin_id(self.s) == Some(c.uuid)
                    && self.t.meta.recycle_bin_enabled
                {
                    // MOD-11.16 (D-11-4): the source bin maps to the target bin.
                    if let Some(bin) = recycle::bin_id(self.t) {
                        return Ok(Some(bin));
                    }
                    // None yet: made (MOD-04.2) with the source bin's id, so a
                    // dry run and the merge agree and later merges match it.
                    let mut bin = Group::new(c.uuid, recycle::BIN_NAME.to_owned(), self.now);
                    bin.icon = app_model::Icon::Standard(recycle::BIN_ICON);
                    bin.searching = app_model::Switch::Off;
                    bin.auto_type = app_model::Switch::Off;
                    let root = self.ix.root;
                    if self.push_group(root, bin) {
                        self.added_groups.insert(c.uuid);
                        self.t.meta.recycle_bin = Some(c.uuid);
                        self.t.meta.recycle_bin_changed = self.now;
                        let path = self.path_of(c.uuid);
                        self.record(
                            ChangeKind::Added,
                            Object::Group,
                            &path,
                            "",
                            Some(c.uuid),
                            vec!["recycle bin made".into()],
                        );
                    }
                    return Ok(Some(c.uuid));
                }
                if !self.push_group(parent, own_copy(c)) {
                    return Ok(None);
                }
                self.added_groups.insert(c.uuid);
                self.raise_version(!c.unknown.is_empty() || !c.times.unknown.is_empty());
                let path = self.path_of(c.uuid);
                self.record(
                    ChangeKind::Added,
                    Object::Group,
                    &path,
                    "",
                    Some(c.uuid),
                    vec![format!("{} entries", c.entries.len())],
                );
                Ok(Some(c.uuid))
            }
        }
    }

    /// MOD-11.8, MOD-11.9: move a matched group when the source's location
    /// time is newer and its parent differs; never into its own subtree.
    fn group_move(&mut self, c: &Group, id: Uuid, parent: Uuid) {
        let wanted = Move {
            id,
            parent,
            loc: c.times.location_changed,
        };
        if self.try_move(&wanted) == Moving::Cycle {
            // Tried again after the walk: a later move may undo the cycle.
            self.deferred.push(wanted);
        }
    }

    /// One group move (MOD-11.8); `Cycle` when it would put the group
    /// inside itself (MOD-11.9).
    fn try_move(&mut self, m: &Move) -> Moving {
        let Some(old_parent) = self.ix.parent.get(&m.id).copied() else {
            return Moving::Stays;
        };
        let Some(tg) = self.ix.group(&self.t.root, m.id) else {
            return Moving::Stays;
        };
        if tg.times.location_changed >= m.loc
            || old_parent == m.parent
            || !self.ix.has_group(m.parent)
        {
            return Moving::Stays;
        }
        if self.ix.within(m.parent, m.id) {
            return Moving::Cycle;
        }
        let previous = self.path_of(old_parent);
        let Some(at) = self.ix.gpos.get(&m.id).copied() else {
            return Moving::Stays;
        };
        let Some(slot) = self
            .ix
            .group_mut(&mut self.t.root, old_parent)
            .and_then(|from| from.groups.get_mut(at))
        else {
            return Moving::Stays;
        };
        let mut moved = core::mem::replace(slot, tomb_group());
        moved.times.location_changed = m.loc;
        moved.previous_parent = Some(old_parent);
        if !self.push_group(m.parent, moved) {
            return Moving::Stays;
        }
        let path = self.path_of(m.id);
        self.record(
            ChangeKind::Moved,
            Object::Group,
            &path,
            "",
            Some(m.id),
            vec![previous],
        );
        Moving::Moved
    }

    /// MOD-11.9: the moves the walk had to skip are tried again until none
    /// more succeeds; each left is one Conflict.
    fn retry_moves(&mut self) {
        loop {
            let pending = core::mem::take(&mut self.deferred);
            let before = pending.len();
            for m in pending {
                if self.try_move(&m) == Moving::Cycle {
                    self.deferred.push(m);
                }
            }
            if self.deferred.len() == before {
                break;
            }
        }
        for m in core::mem::take(&mut self.deferred) {
            let path = self.path_of(m.id);
            self.record(
                ChangeKind::Conflict,
                Object::Group,
                &path,
                "",
                Some(m.id),
                vec!["move would put the group inside itself".into()],
            );
        }
    }

    /// MOD-11.10 (D-11-3): every own field when the source's Mod is newer;
    /// never parent, Loc, children, previous parent, view state, the
    /// shared-group item, creation, access time or usage count.
    fn group_fields(&mut self, c: &Group, id: Uuid) {
        let Some(tg) = self.ix.group_mut(&mut self.t.root, id) else {
            return;
        };
        if c.times.last_modification <= tg.times.last_modification {
            return;
        }
        let mut labels: Vec<String> = Vec::new();
        let mut label = |differ: bool, name: &str| {
            if differ {
                labels.push(name.to_owned());
            }
        };
        label(tg.name != c.name, "Name");
        label(tg.notes != c.notes, "Notes");
        label(tg.icon != c.icon, "Icon");
        label(
            (tg.times.expires, tg.times.expiry) != (c.times.expires, c.times.expiry),
            "Expiry",
        );
        label(tg.tags != c.tags, "Tags");
        label(
            (tg.auto_type, &tg.default_sequence) != (c.auto_type, &c.default_sequence),
            "Auto-Type",
        );
        label(tg.searching != c.searching, "Search");
        let share = core::str::from_utf8(&SHARE_KEY).unwrap_or("");
        let mut data = c.custom_data.clone();
        data.items.retain(|i| i.key != share);
        if let Some(kept) = tg.custom_data.items.iter().find(|i| i.key == share) {
            data.items.push(kept.clone());
        }
        label(tg.custom_data != data, "Custom data");
        labels.push("Modification time".into());
        tg.name.clone_from(&c.name);
        tg.notes.clone_from(&c.notes);
        tg.icon = c.icon;
        tg.tags.clone_from(&c.tags);
        tg.times.expires = c.times.expires;
        tg.times.expiry = c.times.expiry;
        tg.auto_type = c.auto_type;
        tg.default_sequence.clone_from(&c.default_sequence);
        tg.searching = c.searching;
        tg.custom_data = data;
        tg.times.last_modification = c.times.last_modification;
        let path = self.path_of(id);
        self.record(
            ChangeKind::Modified,
            Object::Group,
            &path,
            "",
            Some(id),
            labels,
        );
    }

    /// MOD-11.23: copying an object with kept unknown parts raises the
    /// version the target remembers to at least the source's (LD-68).
    fn raise_version(&mut self, has_unknown: bool) {
        if has_unknown && self.s.read_version > self.t.read_version {
            self.t.read_version = self.s.read_version;
        }
    }

    /// A source entry (MOD-11.4, MOD-11.5, MOD-11.7, MOD-11.11 to
    /// MOD-11.14).
    fn entry(&mut self, e: &'s Entry, group: Uuid) {
        let title = shown_title(e, self.mask_titles);
        match self.find_entry(e.uuid) {
            Found::Outside(at) => {
                let path = self.path_of(at);
                // F-066: either copy flagging its Title masks the record.
                let theirs = self.ix.entry_mut(&mut self.t.root, e.uuid);
                let title = shown_title(e, self.mask_titles || theirs.is_some_and(|t| own_flag(t)));
                self.record(
                    ChangeKind::Conflict,
                    Object::Entry,
                    &path,
                    title,
                    Some(e.uuid),
                    vec!["outside the shared group".into()],
                );
            }
            Found::None => {
                let mut copy = e.duplicate(true);
                protect_passwords(&mut copy);
                let unknown = has_unknown(e);
                let Some(g) = self.ix.group_mut(&mut self.t.root, group) else {
                    return;
                };
                g.entries.push(copy);
                let at = g.entries.len().saturating_sub(1);
                self.ix.epos.insert(e.uuid, (group, at));
                self.added_entries.insert(e.uuid);
                self.raise_version(unknown);
                let path = self.path_of(group);
                self.record(
                    ChangeKind::Added,
                    Object::Entry,
                    &path,
                    title,
                    Some(e.uuid),
                    Vec::new(),
                );
            }
            Found::Here(at) => {
                self.source_times.insert(e.uuid, later(&e.times));
                self.entry_move(e, at, group);
                self.entry_conflict(e);
            }
        }
    }

    /// MOD-11.7: move a matched entry when the source's location time is
    /// newer and its group differs; it takes the source's Loc (D-11-8).
    fn entry_move(&mut self, e: &Entry, at: Uuid, group: Uuid) {
        if at == group || !self.ix.has_group(group) {
            return;
        }
        let Some(&(_, pos)) = self.ix.epos.get(&e.uuid) else {
            return;
        };
        let Some(slot) = self
            .ix
            .group_mut(&mut self.t.root, at)
            .and_then(|from| from.entries.get_mut(pos))
            .filter(|x| x.uuid == e.uuid && x.times.location_changed < e.times.location_changed)
        else {
            return;
        };
        let mut moved = core::mem::replace(slot, tomb_entry());
        let title = shown_title(e, self.mask_titles || own_flag(&moved));
        moved.times.location_changed = e.times.location_changed;
        moved.previous_parent = Some(at);
        let Some(to) = self.ix.group_mut(&mut self.t.root, group) else {
            return;
        };
        to.entries.push(moved);
        let new_pos = to.entries.len().saturating_sub(1);
        self.ix.epos.insert(e.uuid, (group, new_pos));
        let (previous, path) = (self.path_of(at), self.path_of(group));
        self.record(
            ChangeKind::Moved,
            Object::Entry,
            &path,
            title,
            Some(e.uuid),
            vec![previous],
        );
    }

    /// MOD-11.11 to MOD-11.14: who wins, and the joined history.
    fn entry_conflict(&mut self, e: &Entry) {
        let (max_items, max_size) = (self.t.meta.history_max_items, self.t.meta.history_max_size);
        let Some(&(at, _)) = self.ix.epos.get(&e.uuid) else {
            return;
        };
        let path = self.path_of(at);
        let Some(te) = self.ix.entry_mut(&mut self.t.root, e.uuid) else {
            return;
        };
        let source_newer = e.times.last_modification > te.times.last_modification;
        let tie = e.times.last_modification == te.times.last_modification && !same_version(te, e);
        let title = shown_title(te, self.mask_titles || own_flag(e)).to_owned();
        let mut labels: Vec<String> = differences(te, e).into_iter().map(str::to_owned).collect();
        let mut raise = false;
        let kind = if source_newer {
            let joined = join(
                &te.history,
                &e.history,
                te,
                e,
                &e.history,
                max_items,
                max_size,
            );
            let mut copy = e.duplicate(true);
            if let Some(h) = joined {
                copy.history = h;
            }
            // F-152: in a same-vault merge the entry keeps the later Loc, so
            // a move this side made after a deletion item still counts in
            // the deletion pass (MOD-11.30, LD-271 (2)); otherwise the
            // source's older Loc comes with it (LD-68).
            if self.same_vault {
                copy.times.location_changed =
                    copy.times.location_changed.max(te.times.location_changed);
            }
            protect_passwords(&mut copy);
            raise = has_unknown(e);
            *te = copy;
            labels.push("History".into());
            Some(ChangeKind::Modified)
        } else {
            let joined = join(
                &te.history,
                &e.history,
                e,
                te,
                &te.history,
                max_items,
                max_size,
            );
            let changed = joined.is_some();
            if let Some(mut h) = joined {
                for item in &mut h {
                    protect_passwords(item);
                }
                te.history = h;
                labels.push("History".into());
            }
            if tie && changed {
                labels = vec!["same time, different content".into()];
                Some(ChangeKind::Conflict)
            } else if changed {
                Some(ChangeKind::Modified)
            } else {
                None
            }
        };
        self.raise_version(raise);
        if let Some(kind) = kind {
            self.record(kind, Object::Entry, &path, &title, Some(e.uuid), labels);
        }
    }

    /// FMT-15.11, the deletion pass. In a same-vault merge it runs over the
    /// whole vault, and an object's time is the latest Mod or Loc that
    /// either side holds, so a move counts as a change (LD-265, LD-271 (2),
    /// LD-287 (2)); an object this merge added and the pass erases leaves
    /// no record (MOD-11.15). In a shared-group import (D-11-9) it erases
    /// only inside the target start group, by Mod; first each of the share's
    /// items dated after the import takes the import time (LD-271 (1)), and
    /// a share's item that names an object outside the shared group is
    /// dropped (SI-09).
    fn deletions(&mut self) {
        let whole = self.same_vault;
        let time = |t: &app_model::Times| {
            if whole { later(t) } else { t.last_modification }
        };
        // F-154, LD-287 (2): the source copy's own time counts too.
        let source_times = core::mem::take(&mut self.source_times);
        let source_group_times = core::mem::take(&mut self.source_group_times);
        let after = |m: &HashMap<Uuid, Time>, id: &Uuid, when: Time| {
            whole && m.get(id).is_some_and(|t| *t > when)
        };
        // Steps 1 and 2: first sight decides; later sights keep the earliest
        // time for the checks.
        let mut list: Vec<app_model::DeletedObject> = Vec::new();
        let mut entries: Vec<Uuid> = Vec::new();
        let mut groups: Vec<Uuid> = Vec::new();
        let mut earliest: HashMap<Uuid, Time> = HashMap::new();
        let mut seen: HashSet<Uuid> = HashSet::new();
        let share = self.synchronize();
        let now = self.now;
        let items: Vec<(bool, app_model::DeletedObject)> = self
            .t
            .deleted_objects
            .iter()
            .map(|d| (false, d.clone()))
            .chain(self.s.deleted_objects.iter().map(|d| {
                let mut d = d.clone();
                if share && d.deleted_at > now {
                    d.deleted_at = now;
                }
                (true, d)
            }))
            .collect();
        for (theirs, d) in items {
            if !seen.insert(d.uuid) {
                if let Some(t) = earliest.get_mut(&d.uuid) {
                    *t = (*t).min(d.deleted_at);
                }
                continue;
            }
            let entry_here = self
                .ix
                .epos
                .get(&d.uuid)
                .is_some_and(|(g, _)| self.ix.within(*g, self.target_start));
            let group_here = self.ix.has_group(d.uuid)
                && d.uuid != self.target_start
                && d.uuid != self.ix.root
                && self.ix.within(d.uuid, self.target_start);
            if entry_here {
                entries.push(d.uuid);
                earliest.insert(d.uuid, d.deleted_at);
            } else if group_here {
                groups.push(d.uuid);
                earliest.insert(d.uuid, d.deleted_at);
            } else if share
                && theirs
                && (self.ix.epos.contains_key(&d.uuid) || self.ix.has_group(d.uuid))
            {
                // MOD-11.15 (SI-09): the share's item names an object
                // outside the shared group on this Mac; it is dropped.
            } else {
                list.push(d);
            }
        }
        let mut erased = false;
        let (mut quiet_entries, mut quiet_groups) = (HashSet::new(), HashSet::new());
        // Step 3: entries.
        for id in entries {
            let Some(when) = earliest.get(&id).copied() else {
                continue;
            };
            let Some(&(g, _)) = self.ix.epos.get(&id) else {
                continue;
            };
            if after(&source_times, &id, when) {
                continue;
            }
            let path = self.path_of(g);
            let Some(slot) = self.ix.entry_mut(&mut self.t.root, id) else {
                continue;
            };
            if time(&slot.times) > when {
                continue;
            }
            let gone = core::mem::replace(slot, tomb_entry());
            self.ix.epos.remove(&id);
            erased = true;
            list.push(app_model::DeletedObject {
                uuid: id,
                deleted_at: when,
                unknown: Vec::new(),
            });
            if whole && self.added_entries.contains(&id) {
                quiet_entries.insert(id);
                continue;
            }
            self.record(
                ChangeKind::Deleted,
                Object::Entry,
                &path,
                shown_title(&gone, self.mask_titles),
                Some(id),
                vec!["deleted directly".into()],
            );
        }
        // Step 4: groups, children before parents.
        groups.sort_by_key(|id| core::cmp::Reverse(self.ix.chain(*id).map_or(0, |c| c.len())));
        for id in groups {
            let Some(when) = earliest.get(&id).copied() else {
                continue;
            };
            let Some(g) = self.ix.group(&self.t.root, id) else {
                continue;
            };
            let live = |x: &Uuid| *x != Uuid::default();
            let keep = time(&g.times) > when
                || after(&source_group_times, &id, when)
                || g.entries.iter().any(|e| live(&e.uuid))
                || g.groups.iter().any(|c| live(&c.uuid));
            if keep {
                continue;
            }
            let (Some(parent), Some(at)) = (
                self.ix.parent.get(&id).copied(),
                self.ix.gpos.get(&id).copied(),
            ) else {
                continue;
            };
            let path = self.path_of(id);
            let Some(slot) = self
                .ix
                .group_mut(&mut self.t.root, parent)
                .and_then(|p| p.groups.get_mut(at))
            else {
                continue;
            };
            *slot = tomb_group();
            self.ix.parent.remove(&id);
            self.ix.gpos.remove(&id);
            erased = true;
            list.push(app_model::DeletedObject {
                uuid: id,
                deleted_at: when,
                unknown: Vec::new(),
            });
            if whole && self.added_groups.contains(&id) {
                quiet_groups.insert(id);
                continue;
            }
            self.record(
                ChangeKind::Deleted,
                Object::Group,
                &path,
                "",
                Some(id),
                vec!["deleted directly".into()],
            );
        }
        // MOD-11.15: an object added and erased again leaves the target as
        // it was, so it leaves no record.
        if !quiet_entries.is_empty() || !quiet_groups.is_empty() {
            self.changes.retain(|c| {
                let quiet = match c.object {
                    Object::Entry => &quiet_entries,
                    Object::Group => &quiet_groups,
                    Object::Vault => return true,
                };
                c.kind != ChangeKind::Added || c.id.is_none_or(|id| !quiet.contains(&id))
            });
        }
        if erased {
            // FMT-10.16, FMT-11.37: nothing names an erased object, so the
            // vault still holds its invariants and can be saved.
            recycle::clean_references(self.t, self.now);
        }
        if !same_items(&list, &self.t.deleted_objects) {
            self.t.deleted_objects = list;
            self.record(
                ChangeKind::Metadata,
                Object::Vault,
                "",
                "",
                None,
                vec!["deleted objects changed".into()],
            );
        }
    }

    /// MOD-11.17: each source icon the target lacks is appended; an id on
    /// both sides keeps the target's image.
    fn icons(&mut self) {
        let mut have: std::collections::HashSet<Uuid> =
            self.t.meta.custom_icons.iter().map(|i| i.uuid).collect();
        for icon in &self.s.meta.custom_icons {
            if !have.insert(icon.uuid) {
                continue;
            }
            self.t.meta.custom_icons.push(icon.clone());
            self.record(
                ChangeKind::Metadata,
                Object::Vault,
                "",
                "",
                None,
                vec![format!("new icon {}", hex(icon.uuid))],
            );
        }
    }

    /// MOD-11.18 with FMT-14.24 (D-11-6: the stored container times).
    fn custom_data(&mut self) {
        let target_time = container_time(&self.t.meta.custom_data);
        let source_time = container_time(&self.s.meta.custom_data);
        let target_has_stamp = self.t.meta.custom_data.get(LAST_MODIFIED).is_some();
        let source_wins =
            !target_has_stamp || matches!((target_time, source_time), (Some(t), Some(s)) if t < s);
        if !source_wins {
            return;
        }
        let browser = |k: &str| k.as_bytes().starts_with(&BROWSER_PREFIX);
        let protected = |k: &str| {
            browser(k)
                || k == "_CREATED_"
                || k == "FDO_SECRETS_EXPOSED_GROUP"
                || k.as_bytes() == REMOTE_SYNC
        };
        let mut notes: Vec<String> = Vec::new();
        let source = &self.s.meta.custom_data;
        let source_keys: std::collections::HashSet<&str> =
            source.items.iter().map(|i| i.key.as_str()).collect();
        let target = &mut self.t.meta.custom_data;
        let mut removed: Vec<String> = Vec::new();
        target.items.retain(|i| {
            let gone = i.key != LAST_MODIFIED
                && !protected(&i.key)
                && !source_keys.contains(i.key.as_str());
            if gone {
                removed.push(i.key.clone());
            }
            !gone
        });
        for k in removed {
            notes.push(format!("custom data removed: {k}"));
        }
        let mut at: HashMap<String, usize> = target
            .items
            .iter()
            .enumerate()
            .map(|(i, x)| (x.key.clone(), i))
            .collect();
        for item in &source.items {
            let k = item.key.as_str();
            if k == LAST_MODIFIED || k.as_bytes() == PADDING || (browser(k) && !self.same_vault) {
                continue;
            }
            match at.get(k).and_then(|i| target.items.get_mut(*i)) {
                Some(i) if i.value == item.value => continue,
                Some(i) => {
                    i.value.clone_from(&item.value);
                    i.last_modified = Some(self.now);
                }
                None if item.value.is_empty() => continue,
                None => {
                    at.insert(item.key.clone(), target.items.len());
                    target.items.push(CustomDataItem {
                        key: item.key.clone(),
                        value: item.value.clone(),
                        last_modified: Some(self.now),
                        unknown: Vec::new(),
                    });
                }
            }
            notes.push(format!("custom data set: {k}"));
        }
        if notes.is_empty() {
            return;
        }
        let stamp = last_modified_text(self.now);
        match target.items.iter_mut().find(|i| i.key == LAST_MODIFIED) {
            Some(i) => i.value = stamp,
            None => target.items.push(CustomDataItem {
                key: LAST_MODIFIED.to_owned(),
                value: stamp,
                last_modified: None,
                unknown: Vec::new(),
            }),
        }
        for n in notes {
            self.record(ChangeKind::Metadata, Object::Vault, "", "", None, vec![n]);
        }
    }
    /// MOD-11.19 (LD-60): same-vault metadata by its times, with the two
    /// limits: no downgrade, and the key only with the user's yes or after
    /// a change on disk.
    fn metadata(&mut self) {
        // LD-185: the source's settings win only when its file stored their
        // change time (a version 3 file stores none: its reader fills in the
        // open time, so an old copy would always look newer), and only when
        // they differ: equal settings are no change.
        let stored = self.s.read_version.is_none_or(|v| v.major >= 4);
        let settings_win = stored
            && self.s.meta.settings_changed > self.t.meta.settings_changed
            && settings_differ(self.t, self.s);
        let (s, t) = (&self.s.meta, &mut self.t.meta);
        let mut notes: Vec<String> = Vec::new();
        let mut conflicts: Vec<String> = Vec::new();
        if s.name_changed > t.name_changed {
            t.name.clone_from(&s.name);
            t.name_changed = s.name_changed;
            notes.push("vault name".into());
        }
        if s.description_changed > t.description_changed {
            t.description.clone_from(&s.description);
            t.description_changed = s.description_changed;
            notes.push("vault description".into());
        }
        if s.default_user_name_changed > t.default_user_name_changed {
            t.default_user_name.clone_from(&s.default_user_name);
            t.default_user_name_changed = s.default_user_name_changed;
            notes.push("default user name".into());
        }
        let exists = |ix: &Index, g: Option<Uuid>| g.is_none_or(|g| ix.has_group(g));
        if s.recycle_bin_changed > t.recycle_bin_changed && exists(&self.ix, s.recycle_bin) {
            t.recycle_bin = s.recycle_bin;
            t.recycle_bin_changed = s.recycle_bin_changed;
            notes.push("recycle bin group".into());
        }
        if s.entry_templates_group_changed > t.entry_templates_group_changed
            && exists(&self.ix, s.entry_templates_group)
        {
            t.entry_templates_group = s.entry_templates_group;
            t.entry_templates_group_changed = s.entry_templates_group_changed;
            notes.push("templates group".into());
        }
        if settings_win {
            t.recycle_bin_enabled = s.recycle_bin_enabled;
            t.history_max_items = s.history_max_items;
            t.history_max_size = s.history_max_size;
            t.maintenance_history_days = s.maintenance_history_days;
            t.color.clone_from(&s.color);
            t.master_key_change_rec = s.master_key_change_rec;
            t.master_key_change_force = s.master_key_change_force;
            let (tp, sp) = (&mut t.memory_protection, &s.memory_protection);
            for (name, tf, sf) in [
                ("title protection", &mut tp.title, sp.title),
                ("user name protection", &mut tp.user_name, sp.user_name),
                ("password protection", &mut tp.password, sp.password),
                ("URL protection", &mut tp.url, sp.url),
                ("notes protection", &mut tp.notes, sp.notes),
            ] {
                if *tf && !sf {
                    conflicts.push(format!("{name} not lowered"));
                } else {
                    *tf = sf;
                }
            }
            t.settings_changed = s.settings_changed;
            let enc = &mut self.t.encryption;
            enc.cipher = self.s.encryption.cipher;
            enc.compression = self.s.encryption.compression;
            match kdf_change(&enc.kdf, &self.s.encryption.kdf) {
                KdfChange::Take => enc.kdf = self.s.encryption.kdf,
                KdfChange::Same => {}
                KdfChange::Lower => conflicts.push("key derivation not lowered".into()),
                // LD-132: a change of family needs the user (MOD-12.12).
                KdfChange::Family => conflicts.push("key derivation kind not changed".into()),
            }
            self.t.public_custom_data.retain(|i| !display_item(i));
            self.t.public_custom_data.extend(
                self.s
                    .public_custom_data
                    .iter()
                    .filter(|i| display_item(i))
                    .cloned(),
            );
            notes.push("vault settings".into());
        }
        let (s, t) = (&self.s.meta, &mut self.t.meta);
        if s.master_key_changed > t.master_key_changed {
            // Limit 2: the key, its time and the force-once flag travel
            // together (MOD-13.14).
            let take = match self.o.kind {
                // LD-264: the newer key, by the vault's own time.
                Kind::ChangeOnDisk | Kind::ConflictCopy | Kind::ServerSync => true,
                Kind::Window => self.o.take_key || self.o.dry_run,
                _ => false,
            };
            if take {
                if !(self.o.dry_run && self.o.kind == Kind::Window) {
                    t.master_key_changed = s.master_key_changed;
                    t.master_key_change_force_once = s.master_key_change_force_once;
                    self.key_taken = !self.o.dry_run;
                }
                notes.push("vault key from the source".into());
            } else {
                conflicts.push("vault key not taken".into());
            }
        } else if s.master_key_changed == t.master_key_changed
            && s.master_key_change_force_once
            && !t.master_key_change_force_once
        {
            // LD-62: on a tie the flag stays when either side has it.
            t.master_key_change_force_once = true;
            notes.push("key change required at the next unlock".into());
        }
        for n in notes {
            self.record(ChangeKind::Metadata, Object::Vault, "", "", None, vec![n]);
        }
        for c in conflicts {
            self.record(ChangeKind::Conflict, Object::Vault, "", "", None, vec![c]);
        }
    }
}

/// True when any value of the settings group (MOD-11.19, MOD-12.9) differs
/// between the two vaults: the general settings, the five protection flags,
/// the encryption settings and the public display items.
fn settings_differ(a: &Vault, b: &Vault) -> bool {
    let (x, y) = (&a.meta, &b.meta);
    let (px, py) = (&x.memory_protection, &y.memory_protection);
    let public = |v: &Vault| -> Vec<app_model::PublicItem> {
        v.public_custom_data
            .iter()
            .filter(|i| display_item(i))
            .cloned()
            .collect()
    };
    (
        x.recycle_bin_enabled,
        x.history_max_items,
        x.history_max_size,
    ) != (
        y.recycle_bin_enabled,
        y.history_max_items,
        y.history_max_size,
    ) || (x.maintenance_history_days, &x.color) != (y.maintenance_history_days, &y.color)
        || (x.master_key_change_rec, x.master_key_change_force)
            != (y.master_key_change_rec, y.master_key_change_force)
        || (px.title, px.user_name, px.password, px.url, px.notes)
            != (py.title, py.user_name, py.password, py.url, py.notes)
        || a.encryption != b.encryption
        || public(a) != public(b)
}

/// FMT-15.11 step 5: the rebuilt list replaces the old one only when it
/// holds other items; the same items in another order are no change, so a
/// second merge of the same source records nothing (MOD-11.30).
fn same_items(a: &[app_model::DeletedObject], b: &[app_model::DeletedObject]) -> bool {
    let key = |l: &[app_model::DeletedObject]| {
        let mut k: Vec<(Uuid, Time)> = l.iter().map(|d| (d.uuid, d.deleted_at)).collect();
        k.sort_unstable();
        k
    };
    a.len() == b.len() && key(a) == key(b)
}

/// A group's own fields without entries or children (MOD-11.6).
fn own_copy(c: &Group) -> Group {
    let mut g = c.duplicate();
    g.entries.clear();
    g.groups.clear();
    g
}

/// F-066: the entry's Title carries its own protected flag; either copy of
/// a matched entry having it masks the record's Title.
fn own_flag(e: &Entry) -> bool {
    e.field("Title").is_some_and(|f| f.protected)
}

fn has_unknown(e: &Entry) -> bool {
    !e.unknown.is_empty()
        || !e.times.unknown.is_empty()
        || e.history
            .iter()
            .any(|h| !h.unknown.is_empty() || !h.times.unknown.is_empty())
}

/// MOD-12.17: every `Password` field is protected, also when it arrives by
/// merge; history items too.
pub(crate) fn protect_passwords(e: &mut Entry) {
    let mark = |x: &mut Entry| {
        if let Some(f) = x
            .field("Password")
            .filter(|f| !f.protected)
            .map(Field::duplicate)
        {
            x.set_field(
                "Password".to_owned(),
                Field {
                    protected: true,
                    ..f
                },
            );
        }
    };
    mark(e);
    e.history.iter_mut().for_each(mark);
}

/// MOD-11.13: the same version: the same id and equal content in every
/// field, ignoring the access time, the usage count, the location time,
/// the previous parent and the history. A field's protection flag is not
/// content: App protects every password anyway (MOD-12.17).
#[must_use]
pub fn same_version(a: &Entry, b: &Entry) -> bool {
    a.uuid == b.uuid
        && a.times.last_modification == b.times.last_modification
        && a.times.creation == b.times.creation
        && (a.times.expires, a.times.expiry) == (b.times.expires, b.times.expiry)
        && a.fields()
            .map(|(n, f)| (n, f.value.expose()))
            .eq(b.fields().map(|(n, f)| (n, f.value.expose())))
        && a.attachments == b.attachments
        && a.custom_data == b.custom_data
        && a.icon == b.icon
        && (&a.foreground_color, &a.background_color, &a.override_url)
            == (&b.foreground_color, &b.background_color, &b.override_url)
        && a.tags() == b.tags()
        && a.auto_type == b.auto_type
        && a.exclude_from_reports == b.exclude_from_reports
        && a.unknown == b.unknown
}

/// Versions bucketed by modification time: `same_version` needs equal
/// times, so a lookup reads one bucket (linear history joins).
struct Versions<'a> {
    items: &'a [Entry],
    by_time: HashMap<Time, Vec<usize>>,
}

impl<'a> Versions<'a> {
    fn new(items: &'a [Entry]) -> Self {
        let mut by_time: HashMap<Time, Vec<usize>> = HashMap::new();
        for (i, x) in items.iter().enumerate() {
            by_time
                .entry(x.times.last_modification)
                .or_default()
                .push(i);
        }
        Self { items, by_time }
    }

    fn holds(&self, x: &Entry) -> bool {
        self.by_time
            .get(&x.times.last_modification)
            .is_some_and(|v| {
                v.iter()
                    .any(|i| self.items.get(*i).is_some_and(|y| same_version(x, y)))
            })
    }
}

/// The same versions in any order (MOD-11.30: a history whose clock went
/// back is not re-sorted by a merge that adds nothing).
fn same_versions(a: &[Entry], b: &[Entry]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let (va, vb) = (Versions::new(a), Versions::new(b));
    a.iter().all(|x| vb.holds(x)) && b.iter().all(|y| va.holds(y))
}

/// MOD-11.13: the joined history, or `None` when the winner's existing
/// history stays as it is (also after pruning).
fn join(
    target_hist: &[Entry],
    source_hist: &[Entry],
    loser: &Entry,
    winner: &Entry,
    existing: &[Entry],
    max_items: i32,
    max_size: i32,
) -> Option<Vec<Entry>> {
    let mut items: Vec<Entry> = target_hist.iter().map(|h| h.duplicate(false)).collect();
    let mut by_time: HashMap<Time, Vec<usize>> = HashMap::new();
    for (i, x) in items.iter().enumerate() {
        by_time
            .entry(x.times.last_modification)
            .or_default()
            .push(i);
    }
    let held = |items: &[Entry], by_time: &HashMap<Time, Vec<usize>>, x: &Entry| {
        by_time.get(&x.times.last_modification).is_some_and(|v| {
            v.iter()
                .any(|i| items.get(*i).is_some_and(|y| same_version(x, y)))
        })
    };
    for h in source_hist {
        if !held(&items, &by_time, h) {
            by_time
                .entry(h.times.last_modification)
                .or_default()
                .push(items.len());
            items.push(h.duplicate(false));
        }
    }
    if !same_version(loser, winner) && !held(&items, &by_time, loser) {
        let mut l = loser.duplicate(false);
        l.uuid = winner.uuid;
        items.push(l);
    }
    items.sort_by_key(|x| x.times.last_modification);
    if same_versions(&items, existing) {
        return None;
    }
    let mut holder = winner.duplicate(false);
    holder.history = items;
    history::prune(&mut holder, max_items, max_size);
    if same_versions(&holder.history, existing) {
        return None;
    }
    Some(holder.history)
}

/// MOD-11.24: the fields that differ, in the card's order; custom fields
/// whenever they differ (D-11-10).
fn differences(a: &Entry, b: &Entry) -> Vec<&'static str> {
    let mut out = Vec::new();
    let labels = ["Title", "Username", "Password", "URL", "Notes"];
    for (name, label) in STANDARD_FIELDS.iter().zip(labels) {
        if a.field(name) != b.field(name) {
            out.push(label);
        }
    }
    fn custom((n, _): &(&str, &Field)) -> bool {
        !STANDARD_FIELDS.contains(n) && !crate::history::otp_field(n)
    }
    if !a.fields().filter(custom).eq(b.fields().filter(custom)) {
        out.push("Custom attributes");
    }
    for label in crate::history::difference(a, b) {
        if !matches!(
            label,
            "Title" | "Username" | "Password" | "URL" | "Notes" | "Custom attributes"
        ) {
            out.push(label);
        }
    }
    out
}

/// What a merge does with the source's KDF (LD-60, LD-132).
#[derive(Debug, PartialEq, Eq)]
enum KdfChange {
    Same,
    Take,
    Lower,
    Family,
}

/// LD-132: another family is never taken silently; within a family, lower
/// memory, iterations, lanes or rounds are lower.
fn kdf_change(current: &Kdf, next: &Kdf) -> KdfChange {
    if current == next {
        return KdfChange::Same;
    }
    let raise = match (current, next) {
        (Kdf::AesKdf { rounds: a }, Kdf::AesKdf { rounds: b }) => b >= a,
        (
            Kdf::Argon2 {
                iterations: ia,
                memory_kib: ma,
                lanes: la,
                ..
            },
            Kdf::Argon2 {
                iterations: ib,
                memory_kib: mb,
                lanes: lb,
                ..
            },
        ) => ib >= ia && mb >= ma && lb >= la,
        _ => return KdfChange::Family,
    };
    if raise {
        KdfChange::Take
    } else {
        KdfChange::Lower
    }
}

/// FMT-14.24: a container's time: its `_LAST_MODIFIED` value, else the
/// newest item time; `None` when neither can be read.
fn container_time(cd: &app_model::CustomData) -> Option<Time> {
    match cd.get(LAST_MODIFIED) {
        Some(text) => parse_last_modified(text),
        None => cd.items.iter().filter_map(|i| i.last_modified).max(),
    }
}

const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// FMT-14.18: `Sat Oct 24 19:17:16 2026 GMT`.
#[must_use]
pub fn last_modified_text(t: Time) -> String {
    let Some(c) = t.to_civil() else {
        return String::new();
    };
    // 0001-01-01 was a Monday.
    let day = usize::try_from(t.0.div_euclid(86_400).rem_euclid(7)).unwrap_or(0);
    let month = usize::try_from(c.month)
        .ok()
        .and_then(|m| m.checked_sub(1))
        .unwrap_or(0);
    format!(
        "{} {} {} {:02}:{:02}:{:02} {} GMT",
        DAYS.get(day).unwrap_or(&"Mon"),
        MONTHS.get(month).unwrap_or(&"Jan"),
        c.day,
        c.hour,
        c.minute,
        c.second,
        c.year
    )
}

/// FMT-14.18's English form back to a time; `None` for any other text.
#[must_use]
pub fn parse_last_modified(text: &str) -> Option<Time> {
    let mut parts = text.split(' ');
    let (wd, mon, day, hms, year, gmt) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );
    if parts.next().is_some() || gmt != "GMT" || !DAYS.contains(&wd) {
        return None;
    }
    let month = MONTHS.iter().position(|m| *m == mon)?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(day) || day.starts_with('0') || !digits(year) || year.len() != 4 {
        return None;
    }
    let mut hms = hms.split(':');
    let (h, m, s) = (hms.next()?, hms.next()?, hms.next()?);
    if hms.next().is_some() || ![h, m, s].iter().all(|p| p.len() == 2 && digits(p)) {
        return None;
    }
    Time::from_civil(app_model::times::Civil {
        year: year.parse().ok()?,
        month: u32::try_from(month).ok()?.checked_add(1)?,
        day: day.parse().ok()?,
        hour: h.parse().ok()?,
        minute: m.parse().ok()?,
        second: s.parse().ok()?,
    })
}

fn hex(id: Uuid) -> String {
    id.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// `0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a`.
fn dashed(id: Uuid) -> String {
    let h = hex(id);
    let part = |a: usize, b: usize| h.get(a..b).unwrap_or("");
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}
