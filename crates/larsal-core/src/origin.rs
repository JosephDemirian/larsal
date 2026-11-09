//! What rule R6 of shared groups reads and writes (INT-08.32, MOD-11.15,
//! FMT-15.11): a share never wins by time, and only a user's stamped move brings
//! an object into a share across a merge. Five items of Larsal's own, inside the
//! vault under the vault's key, so they travel with the file to every Mac:
//!
//! - The **stamp** ([`STAMP`]), on an entry or group while it counts inside: the
//!   share group and the time of the user's move in.
//! - The **marker** ([`MARK`]), on an entry or group a share import added.
//! - The **known shares** ([`KNOWN`]), in the vault's custom data. [`known`] adds
//!   every group with a share item, so a share is known from its set-up on.
//! - The **rows** ([`SCOPES`]), in the vault's custom data: a share's deletion or
//!   a deletion of a copy that only counts inside (record id, share group, time).
//!   They never go in the vault's deleted-object list, which holds only a user's
//!   plain records. One row per share that held the object. At most [`ROW_CAP`]
//!   per share, the newest kept.
//! - The **private tag** ([`PRIVATE`]), on a history item: a value that lost a whole
//!   merge. It stays on this vault's Macs and never goes out through a share.
//!
//! Guarantees: a container cannot plant them. [`crate::merge::merge`] strips all
//! five from every source that is not a copy of this vault, a share's container
//! included, and an export strips them ([`strip_tree`]), a tagged item whole. Saves
//! keep them. A key that differs only by what a save removes counts as the key
//! everywhere ([`same_key`]). A value that cannot be read counts as not there. A
//! file from another app that drops custom data acts as a file without them; one
//! that keeps them and takes a container's unstripped is trusted (INT-08.32, limit 11).

use crate::{edit, recycle};
use larsal_crypto::secret::SecretString;
use larsal_model::custom_data::{CustomData, CustomDataItem, same_key};
use larsal_model::{Entry, Group, Time, Uuid, Vault};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::rc::Rc;

/// The key of the marker: an entry's or group's custom data; the share's id.
pub const MARK: &str = "app.larsal.share.origin";

/// The key of the stamp: an entry's or group's custom data; `id:time`.
pub const STAMP: &str = "app.larsal.share.moved";

/// The key of the known shares: the vault's custom data; ids, sorted.
pub const KNOWN: &str = "app.larsal.share.known";

/// The key of the rows: the vault's custom data. One part per share group, `;`
/// between parts: the group's id, `=`, then `id:time` rows with `,` between,
/// sorted, so two copies with one list write it the same.
pub const SCOPES: &str = "app.larsal.share.deleted";

/// The key of the private tag: a history item's custom data. Its value is not read.
pub const PRIVATE: &str = "app.larsal.share.private";

/// The most rows kept per share. A choice, not derived: rows past it are dropped,
/// oldest first, which can only let a deletion not reach (INT-08.32 limit 13).
pub const ROW_CAP: usize = 100_000;

/// A set of known shares, on one object's way up.
pub type Set = BTreeSet<Uuid>;

/// (record id, share group) to the row's time.
pub type Rows = BTreeMap<(Uuid, Uuid), Time>;

/// A user's move into a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// The innermost share the move brought the object into.
    pub group: Uuid,
    /// The move's time.
    pub at: Time,
}

fn push_hex(out: &mut String, id: Uuid) {
    for b in id.0 {
        let _ = write!(out, "{b:02x}");
    }
}

fn parse_id(hex: &[u8]) -> Option<Uuid> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (o, pair) in out.iter_mut().zip(hex.as_chunks::<2>().0) {
        *o = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(Uuid(out))
}

fn item(key: &str, value: String) -> CustomDataItem {
    CustomDataItem {
        key: key.to_owned(),
        value: SecretString::new(value),
        last_modified: None,
        unknown: Vec::new(),
    }
}

/// The one door for the five items: an item goes in only while `data` holds fewer than
/// the format's custom data items (FMT-08.12), so no write of this rule makes a vault
/// that cannot be saved (INT-08.32, at the item limit). True when it went in.
fn put(data: &mut CustomData, i: CustomDataItem) -> bool {
    let room = data.items.len() < larsal_format::limits::Limits::DEFAULT.custom_data_items;
    if room {
        data.items.push(i);
    }
    room
}

/// The value under `key`, or under a key that is `key` once a save cleans it.
fn get<'a>(data: &'a CustomData, key: &str) -> Option<&'a str> {
    data.items
        .iter()
        .find(|i| same_key(&i.key, key))
        .map(|i| i.value.expose())
}

/// True for the keys an object carries for this rule: they are not content, and the
/// editor's custom data list does not show them.
#[must_use]
pub fn ours(key: &str) -> bool {
    [MARK, STAMP, PRIVATE].iter().any(|k| same_key(key, k))
}

/// True for a history item only this vault's Macs may hold.
#[must_use]
pub fn private_item(h: &Entry) -> bool {
    h.custom_data
        .items
        .iter()
        .any(|i| same_key(&i.key, PRIVATE))
}

/// Tags a history item; false when it holds the item limit and cannot take the tag.
pub(crate) fn set_private(h: &mut Entry) -> bool {
    private_item(h) || put(&mut h.custom_data, item(PRIVATE, "1".to_owned()))
}

/// A version kept as private (INT-08.32 item 5): the stamp and marker go first, then
/// the tag; false when it still holds the item limit and cannot take it, and then the
/// caller drops it, never keeps it untagged.
pub(crate) fn make_private(h: &mut Entry) -> bool {
    strip_data(&mut h.custom_data);
    set_private(h)
}

/// The share group an object's marker names; `None` without a readable one.
#[must_use]
pub fn mark_of(data: &CustomData) -> Option<Uuid> {
    parse_id(get(data, MARK)?.as_bytes())
}

/// True when an object holds a marker: the rule reads only that it is there.
pub(crate) fn brought(data: &CustomData) -> bool {
    get(data, MARK).is_some()
}

/// Puts the marker of `group` on an object; none at the item limit.
pub fn set_mark(data: &mut CustomData, group: Uuid) {
    let mut text = String::with_capacity(32);
    push_hex(&mut text, group);
    data.items.retain(|i| !same_key(&i.key, MARK));
    put(data, item(MARK, text));
}

/// Takes the marker off an object.
pub fn clear_mark(data: &mut CustomData) {
    data.items.retain(|i| !same_key(&i.key, MARK));
}

/// The object's stamp; `None` without a readable one.
#[must_use]
pub fn stamp_of(data: &CustomData) -> Option<Stamp> {
    let (id, at) = get(data, STAMP)?.split_once(':')?;
    Some(Stamp {
        group: parse_id(id.as_bytes())?,
        at: Time(at.parse().ok()?),
    })
}

/// Sets or clears the object's stamp; at the item limit a new one is not written.
pub fn set_stamp(data: &mut CustomData, stamp: Option<Stamp>) {
    data.items.retain(|i| !same_key(&i.key, STAMP));
    if let Some(s) = stamp {
        let mut text = String::with_capacity(48);
        push_hex(&mut text, s.group);
        let _ = write!(text, ":{}", s.at.0);
        put(data, item(STAMP, text));
    }
}

/// `to` gets the stamp and marker `from` holds, or none: a history item and a
/// source's copy never give them, and a current copy holds no private tag. At the
/// item limit `to` takes what fits.
pub(crate) fn keep_own(from: &CustomData, to: &mut CustomData) {
    to.items.retain(|i| !ours(&i.key));
    for i in from.items.iter().filter(|i| ours(&i.key)) {
        put(to, i.clone());
    }
}

/// Equal custom data; the stamp, marker and tag are not content, so they never make
/// two versions differ or add a history item (MOD-11.13).
#[must_use]
pub fn same_data(a: &CustomData, b: &CustomData) -> bool {
    fn own(d: &CustomData) -> impl Iterator<Item = &CustomDataItem> {
        d.items.iter().filter(|i| !ours(&i.key))
    }
    a.unknown == b.unknown && own(a).eq(own(b))
}

/// The rows `data` holds; a part or row that cannot be read is left out.
#[must_use]
pub fn read_rows(data: &CustomData) -> Rows {
    let mut out = Rows::new();
    let Some(text) = get(data, SCOPES) else {
        return out;
    };
    for part in text.split(';') {
        let Some((group, rows)) = part.split_once('=') else {
            continue;
        };
        let Some(group) = parse_id(group.as_bytes()) else {
            continue;
        };
        for row in rows.split(',') {
            let Some((id, at)) = row.split_once(':') else {
                continue;
            };
            let (Some(id), Ok(at)) = (parse_id(id.as_bytes()), at.parse()) else {
                continue;
            };
            out.insert((id, group), Time(at));
        }
    }
    out
}

/// Stores `rows` in `data`, none when empty, each share's newest [`ROW_CAP`] only;
/// true when that changed it.
pub fn write_rows(data: &mut CustomData, rows: &Rows) -> bool {
    let mut parts: BTreeMap<Uuid, Vec<(Uuid, Time)>> = BTreeMap::new();
    for ((id, group), at) in rows {
        parts.entry(*group).or_default().push((*id, *at));
    }
    let mut text = String::new();
    for (group, mut rows) in parts {
        if rows.len() > ROW_CAP {
            rows.sort_unstable_by_key(|(id, at)| (core::cmp::Reverse(*at), *id));
            rows.truncate(ROW_CAP);
            rows.sort_unstable();
        }
        if !text.is_empty() {
            text.push(';');
        }
        push_hex(&mut text, group);
        text.push('=');
        for (i, (id, at)) in rows.into_iter().enumerate() {
            if i > 0 {
                text.push(',');
            }
            push_hex(&mut text, id);
            let _ = write!(text, ":{}", at.0);
        }
    }
    replace(data, SCOPES, text)
}

/// `key`'s item in the vault's own custom data now holds `text`, none when empty or at
/// the item limit; true when that changed `data`. The limit counts the two items each save
/// adds there when they are missing (FMT-14.18, FMT-14.21), so a vault that saved still
/// saves.
fn replace(data: &mut CustomData, key: &str, text: String) -> bool {
    let old = get(data, key);
    if old.unwrap_or("") == text {
        return false;
    }
    let had = old.is_some();
    data.items.retain(|i| !same_key(&i.key, key));
    let padding = String::from_utf8_lossy(larsal_format::document::write::PADDING_KEY);
    let save_adds = [padding.as_ref(), "_LAST_MODIFIED"]
        .iter()
        .filter(|k| !data.items.iter().any(|i| i.key == **k))
        .count();
    let room = data.items.len().saturating_add(save_adds)
        < larsal_format::limits::Limits::DEFAULT.custom_data_items;
    let wrote = !text.is_empty() && room && put(data, item(key, text));
    had || wrote
}

/// Adds rows to `v`: the latest per record and share.
pub(crate) fn add_rows(v: &mut Vault, new: &[(Uuid, Uuid, Time)]) {
    if new.is_empty() {
        return;
    }
    let mut rows = read_rows(&v.meta.custom_data);
    for (id, group, at) in new {
        let row = rows.entry((*id, *group)).or_insert(*at);
        *row = (*row).max(*at);
    }
    write_rows(&mut v.meta.custom_data, &rows);
}

/// Forgets every row naming one of `ids`.
pub(crate) fn drop_rows(v: &mut Vault, ids: &HashSet<Uuid>) {
    let mut rows = read_rows(&v.meta.custom_data);
    if rows.is_empty() {
        return;
    }
    rows.retain(|(id, _), _| !ids.contains(id));
    write_rows(&mut v.meta.custom_data, &rows);
}

/// The ids on `v`'s list of known shares.
#[must_use]
pub fn read_known(data: &CustomData) -> Set {
    let Some(text) = get(data, KNOWN) else {
        return Set::new();
    };
    text.as_bytes()
        .as_chunks::<32>()
        .0
        .iter()
        .filter_map(|x| parse_id(x))
        .collect()
}

/// Stores the list of known shares; true when that changed it.
pub fn write_known(data: &mut CustomData, known: &Set) -> bool {
    let mut text = String::with_capacity(known.len().saturating_mul(32));
    for id in known {
        push_hex(&mut text, *id);
    }
    replace(data, KNOWN, text)
}

/// The shares `v` knows: its list, and every group with a share item.
#[must_use]
pub fn known(v: &Vault) -> Set {
    let key = core::str::from_utf8(edit::SHARED_KEY).unwrap_or("");
    let mut out = read_known(&v.meta.custom_data);
    let mut stack = vec![&v.root];
    while let Some(g) = stack.pop() {
        if get(&g.custom_data, key).is_some() {
            out.insert(g.uuid);
        }
        stack.extend(g.groups.iter());
    }
    out
}

/// Sets of known shares, each kept once: hash-consed big-endian Patricia trees (Okasaki
/// and Gill, "Fast Mergeable Integer Maps", 1998). One set has one id, whatever tree of a
/// merge or order of adding built it, so two sets compare in one step, and a set one share
/// larger than another is the new nodes on the path down to that share, never a copy: about
/// the log of the set's size with random ids, up to about 128 (one per bit of an id) with
/// crafted ones (MOD-11 Limits, C2R6-02).
pub(crate) struct Store {
    nodes: Vec<Node>,
    ids: HashMap<Node, usize>,
}

/// One node of a [`Store`]: none, one share, or the shares that agree above `bit`, those
/// with `bit` clear (the smaller ids) on the left.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Node {
    Empty,
    Leaf(u128),
    Branch {
        prefix: u128,
        bit: u128,
        left: usize,
        right: usize,
    },
}

/// The bits above `bit`: what every key under a branch at `bit` agrees on.
fn above(k: u128, bit: u128) -> u128 {
    k & !(bit | bit.wrapping_sub(1))
}

/// An id as a key: its bytes big-endian, so the order is the ids' own.
fn key_of(g: Uuid) -> u128 {
    u128::from_be_bytes(g.0)
}

impl Store {
    fn new() -> Self {
        Self {
            nodes: vec![Node::Empty],
            ids: HashMap::from([(Node::Empty, 0)]),
        }
    }

    fn node(&self, t: usize) -> Node {
        self.nodes.get(t).copied().unwrap_or(Node::Empty)
    }

    fn make(&mut self, n: Node) -> usize {
        if let Some(&i) = self.ids.get(&n) {
            return i;
        }
        let i = self.nodes.len();
        self.nodes.push(n);
        self.ids.insert(n, i);
        i
    }

    /// The branch over `ta` (keys agreeing with `a`) and `tb` (with `b`), `a != b`.
    fn branch(&mut self, a: u128, ta: usize, b: u128, tb: usize) -> usize {
        let bit = 1u128.wrapping_shl(127u32.saturating_sub((a ^ b).leading_zeros()));
        let (left, right) = if a & bit == 0 { (ta, tb) } else { (tb, ta) };
        self.make(Node::Branch {
            prefix: above(a, bit),
            bit,
            left,
            right,
        })
    }

    /// The set `t` with `k` too.
    fn insert(&mut self, t: usize, k: u128) -> usize {
        match self.node(t) {
            Node::Empty => self.make(Node::Leaf(k)),
            Node::Leaf(j) if j == k => t,
            Node::Leaf(j) => {
                let leaf = self.make(Node::Leaf(k));
                self.branch(k, leaf, j, t)
            }
            Node::Branch {
                prefix,
                bit,
                left,
                right,
            } => {
                if above(k, bit) != prefix {
                    let leaf = self.make(Node::Leaf(k));
                    self.branch(k, leaf, prefix, t)
                } else if k & bit == 0 {
                    let left = self.insert(left, k);
                    self.make(Node::Branch {
                        prefix,
                        bit,
                        left,
                        right,
                    })
                } else {
                    let right = self.insert(right, k);
                    self.make(Node::Branch {
                        prefix,
                        bit,
                        left,
                        right,
                    })
                }
            }
        }
    }

    fn contains(&self, mut t: usize, k: u128) -> bool {
        loop {
            match self.node(t) {
                Node::Empty => return false,
                Node::Leaf(j) => return j == k,
                Node::Branch {
                    prefix,
                    bit,
                    left,
                    right,
                } => {
                    if above(k, bit) != prefix {
                        return false;
                    }
                    t = if k & bit == 0 { left } else { right };
                }
            }
        }
    }

    fn items(&self, t: usize) -> Vec<Uuid> {
        let mut out = Vec::new();
        let mut stack = vec![t];
        while let Some(x) = stack.pop() {
            match self.node(x) {
                Node::Empty => {}
                Node::Leaf(k) => out.push(Uuid(k.to_be_bytes())),
                Node::Branch { left, right, .. } => {
                    stack.push(right);
                    stack.push(left);
                }
            }
        }
        out
    }
}

/// The known shares an object counts in, as one tree of a merge reads them: an id in the
/// [`Store`] the merge's trees share ([`Places::sharing`]). Equal sets are equal ids while
/// no known share has gone in this merge; after one goes, [`Places::holds`],
/// [`Places::set_of`] and [`Shares::is_empty`] still read the set as it is now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Shares(usize);

impl Shares {
    /// No share.
    pub(crate) const NONE: Self = Self(0);

    /// True when the object counts in no share.
    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// One copy's group tree as the rule reads it, with the shares it knows. The bin
/// counts as the place an item came from (INT-08.32, `Set`).
pub(crate) struct Places {
    pub(crate) root: Uuid,
    pub(crate) bin: Option<Uuid>,
    up: HashMap<Uuid, (Uuid, Option<Uuid>)>,
    known: Set,
    store: Rc<RefCell<Store>>,
    /// Each group's innermost known share on its way up (`None`: it counts in none), kept
    /// while the tree stays: one look per group.
    heads: HashMap<Uuid, Option<Uuid>>,
    /// Each known share's set, from itself up, kept while the tree stays.
    sets: HashMap<Uuid, usize>,
    /// Each known share gone in this merge, and the next known share up from where it was:
    /// a group whose innermost share went now has that one, read through on each look and
    /// shortened as read. The sets kept stay as they were and are read without these.
    went: RefCell<HashMap<Uuid, Option<Uuid>>>,
    /// Each erased group, and what a bin item that named it names now: read through
    /// on each look ([`Self::named`]), each chain shortened as it is read, so an erase
    /// costs the same however many bin items name the group.
    renamed: RefCell<HashMap<Uuid, Option<Uuid>>>,
}

impl Places {
    pub(crate) fn new(v: &Vault, known: Set) -> Self {
        Self::with_store(v, known, Rc::new(RefCell::new(Store::new())))
    }

    /// As [`Self::new`], with the sets of `other`, so the two trees' [`Shares`] compare.
    pub(crate) fn sharing(v: &Vault, known: Set, other: &Self) -> Self {
        Self::with_store(v, known, Rc::clone(&other.store))
    }

    fn with_store(v: &Vault, known: Set, store: Rc<RefCell<Store>>) -> Self {
        let mut up = HashMap::new();
        let mut stack = vec![&v.root];
        while let Some(g) = stack.pop() {
            for c in &g.groups {
                if c.uuid != Uuid::default() {
                    up.insert(c.uuid, (g.uuid, c.previous_parent));
                }
            }
            stack.extend(g.groups.iter());
        }
        Self {
            root: v.root.uuid,
            bin: recycle::bin_id(v),
            up,
            known,
            store,
            heads: HashMap::new(),
            sets: HashMap::new(),
            went: RefCell::new(HashMap::new()),
            renamed: RefCell::new(HashMap::new()),
        }
    }

    /// The tree changed. New maps, not `clear`: that walks all they ever held.
    fn changed(&mut self) {
        self.heads = HashMap::new();
        self.sets = HashMap::new();
    }

    /// What a bin item's previous parent `p` names now that groups went: `p` itself
    /// unless it was erased, else what it handed on to, followed to a group that
    /// stayed (or to one that named itself).
    fn named(&self, p: Option<Uuid>) -> Option<Uuid> {
        let mut renamed = self.renamed.borrow_mut();
        let mut seen = Vec::new();
        let mut at = p;
        while let Some(x) = at {
            match renamed.get(&x) {
                Some(&next) if next != Some(x) && seen.len() <= renamed.len() => {
                    seen.push(x);
                    at = next;
                }
                _ => break,
            }
        }
        for x in seen {
            renamed.insert(x, at);
        }
        at
    }

    /// The known share `h` names now: `h`, or for one gone in this merge the next one up
    /// from where it was, followed to one that stays.
    fn live(&self, h: Option<Uuid>) -> Option<Uuid> {
        let mut went = self.went.borrow_mut();
        let mut seen = Vec::new();
        let mut at = h;
        while let Some(x) = at {
            match went.get(&x) {
                Some(&next) if next != Some(x) && seen.len() <= went.len() => {
                    seen.push(x);
                    at = next;
                }
                _ => break,
            }
        }
        for x in seen {
            went.insert(x, at);
        }
        at
    }

    pub(crate) fn has(&self, g: Uuid) -> bool {
        g == self.root || self.up.contains_key(&g)
    }

    /// Group `g`'s parent and previous parent, the latter as [`Self::named`] reads it
    /// for a group directly in the bin.
    pub(crate) fn place_of(&self, g: Uuid) -> Option<(Uuid, Option<Uuid>)> {
        let &(parent, prev) = self.up.get(&g)?;
        let prev = if Some(parent) == self.bin {
            self.named(prev)
        } else {
            prev
        };
        Some((parent, prev))
    }

    /// Group `g` now sits at `parent`, with `prev`. The same place again changes nothing.
    pub(crate) fn set_place(&mut self, g: Uuid, parent: Uuid, prev: Option<Uuid>) {
        if self.up.get(&g) == Some(&(parent, prev)) {
            return;
        }
        self.up.insert(g, (parent, prev));
        self.changed();
    }

    /// Group `g` is gone: a bin item that named it now names what this returns,
    /// its parent, or its previous parent if it was in the bin.
    pub(crate) fn gone(&mut self, g: Uuid) -> Option<Uuid> {
        let &(parent, prev) = self.up.get(&g)?;
        if self.known.contains(&g) {
            // A way up that led through `g` now steps over it to the same next group, so
            // only `g` leaves a set: what named it as the innermost names the next share
            // up, and the kept sets are read without it. So erasing is one pass, linear
            // in the groups (MOD-11.15).
            let next = self.next_share(g);
            self.went.get_mut().insert(g, next);
        }
        self.up.remove(&g);
        let to = if Some(parent) == self.bin {
            self.named(prev)
        } else {
            Some(parent)
        };
        // The bin items that named `g` are not touched: [`Self::named`] reads them on.
        self.renamed.get_mut().insert(g, to);
        self.heads.remove(&g);
        to
    }

    /// A count no walk up this tree passes.
    pub(crate) fn bound(&self) -> usize {
        self.up.len().saturating_add(3)
    }

    /// The bin is now `bin`.
    pub(crate) fn set_bin(&mut self, bin: Uuid) {
        self.bin = Some(bin);
        self.changed();
    }

    /// The next group on the way up from group `x` (not the root, not the bin): its
    /// parent, or for a group directly in the bin its previous parent while that is on
    /// the tree; never the bin. `None` where the way ends.
    fn step(&self, x: Uuid) -> Option<Uuid> {
        let (parent, prev) = self.place_of(x)?;
        if Some(parent) == self.bin {
            prev.filter(|p| *p != parent && self.has(*p))
        } else {
            Some(parent)
        }
    }

    /// The innermost known share from group `g` up, itself first, through a bin item's
    /// previous parent, the root on it; as kept, so possibly gone since ([`Self::live`]).
    /// Every group the walk passes keeps the answer, so each is walked once until the
    /// tree changes, and a cycle through previous parents ends.
    fn head(&mut self, g: Uuid) -> Option<Uuid> {
        if Some(g) == self.bin {
            return None;
        }
        let mut path = Vec::new();
        let mut seen = HashSet::new();
        let mut at = Some(g);
        let mut found = None;
        while let Some(x) = at {
            if self.known.contains(&x) {
                found = Some(x);
                break;
            }
            if let Some(&h) = self.heads.get(&x) {
                found = h;
                break;
            }
            if x == self.root || !seen.insert(x) {
                break;
            }
            path.push(x);
            at = self.step(x);
        }
        for x in path {
            self.heads.insert(x, found);
        }
        found
    }

    /// The next known share up from known share `k`, as it stands now.
    fn next_share(&mut self, k: Uuid) -> Option<Uuid> {
        if k == self.root {
            return None;
        }
        let h = self.step(k).and_then(|s| self.head(s));
        self.live(h)
    }

    /// The set of known share `k`: itself and every known share up from it, through a
    /// cycle of previous parents its whole ring. Each share's set is found once until
    /// the tree changes, from the one above it plus itself.
    fn set_from(&mut self, k: Uuid) -> usize {
        if let Some(&s) = self.sets.get(&k) {
            return s;
        }
        let mut chain: Vec<Uuid> = Vec::new();
        let mut seen: HashMap<Uuid, usize> = HashMap::new();
        let mut at = Some(k);
        let mut set = 0usize;
        while let Some(x) = at {
            if let Some(&s) = self.sets.get(&x) {
                set = s;
                break;
            }
            if let Some(&i) = seen.get(&x) {
                let ring = chain.split_off(i);
                let mut store = self.store.borrow_mut();
                for y in &ring {
                    set = store.insert(set, key_of(*y));
                }
                drop(store);
                for y in ring {
                    self.sets.insert(y, set);
                }
                break;
            }
            seen.insert(x, chain.len());
            chain.push(x);
            at = self.next_share(x);
        }
        for x in chain.into_iter().rev() {
            set = self.store.borrow_mut().insert(set, key_of(x));
            self.sets.insert(x, set);
        }
        self.sets.get(&k).copied().unwrap_or(set)
    }

    /// The known shares from group `g` up, itself first, through a bin item's previous
    /// parent, the root on it (a share of the whole vault): an object in `g` counts
    /// inside these.
    fn shares_from(&mut self, g: Uuid) -> Shares {
        let h = self.head(g);
        match self.live(h) {
            Some(k) => Shares(self.set_from(k)),
            None => Shares::NONE,
        }
    }

    /// `Set`: the shares an object at `parent`, with `prev`, counts inside. `me`
    /// is the object when it is a group.
    pub(crate) fn shares_at(
        &mut self,
        parent: Uuid,
        prev: Option<Uuid>,
        me: Option<Uuid>,
    ) -> Shares {
        if Some(parent) == self.bin {
            return match prev {
                Some(p) if p != parent && Some(p) != me && self.has(p) => self.shares_from(p),
                _ => Shares::NONE,
            };
        }
        self.shares_from(parent)
    }

    /// [`Self::shares_at`], each share named.
    pub(crate) fn set_at(&mut self, parent: Uuid, prev: Option<Uuid>, me: Option<Uuid>) -> Set {
        let s = self.shares_at(parent, prev, me);
        self.set_of(s)
    }

    /// The shares of `s`, but those gone in this merge.
    pub(crate) fn set_of(&self, s: Shares) -> Set {
        let went = self.went.borrow();
        let items = self.store.borrow().items(s.0);
        items
            .into_iter()
            .filter(|g| !went.contains_key(g))
            .collect()
    }

    /// True when `s` holds share `g`, one not gone in this merge.
    pub(crate) fn holds(&self, s: Shares, g: Uuid) -> bool {
        !self.went.borrow().contains_key(&g) && self.store.borrow().contains(s.0, key_of(g))
    }

    /// True when `g` is `ancestor` or lies below it on the tree.
    pub(crate) fn within(&self, g: Uuid, ancestor: Uuid) -> bool {
        if ancestor == self.root || g == ancestor {
            return true;
        }
        let mut at = g;
        for _ in 0..=self.up.len() {
            match self.up.get(&at) {
                Some((p, _)) if *p == ancestor => return true,
                Some((p, _)) => at = *p,
                None => return false,
            }
        }
        false
    }

    /// Each share `g` of `shares` that lies strictly inside the share of one of `rows`
    /// ([`Self::within`], `g` not that share), with the latest such row's time. One walk up
    /// per share, kept for the next: it stops where an earlier walk passed, at the top, or
    /// once it has passed every other row's share, so an object costs each group on its
    /// shares' ways up once, not once per row and share (MOD-11 Limits).
    pub(crate) fn rows_above(&self, shares: &Set, rows: &[(Uuid, Time)]) -> Vec<(Uuid, Time)> {
        let whole = rows
            .iter()
            .filter(|(r, _)| *r == self.root)
            .map(|(_, at)| *at)
            .max();
        let at: HashMap<Uuid, Time> = rows
            .iter()
            .copied()
            .filter(|(r, _)| *r != self.root)
            .collect();
        // The latest row strictly above each group walked, the root's aside.
        let mut above: HashMap<Uuid, Option<Time>> = HashMap::new();
        let mut out = Vec::new();
        for &g in shares {
            let need = at.len().saturating_sub(usize::from(at.contains_key(&g)));
            let (mut x, mut seen, mut path, mut best) = (g, 0usize, Vec::new(), None);
            for _ in 0..=self.up.len() {
                if let Some(&a) = above.get(&x) {
                    best = a;
                    break;
                }
                let Some(p) = self.up.get(&x).map(|(p, _)| *p).filter(|_| seen < need) else {
                    above.insert(x, None);
                    break;
                };
                seen = seen.saturating_add(usize::from(at.contains_key(&p)));
                path.push((x, p));
                x = p;
            }
            for (y, p) in path.into_iter().rev() {
                best = best.max(at.get(&p).copied());
                above.insert(y, best);
            }
            if g != self.root {
                best = best.max(whole);
            }
            out.extend(best.map(|t| (g, t)));
        }
        out
    }

    fn depth(&self, g: Uuid) -> usize {
        let mut d = 0usize;
        let mut at = g;
        while let Some((p, _)) = self.up.get(&at) {
            d = d.saturating_add(1);
            at = *p;
            if d > self.up.len() {
                break;
            }
        }
        d
    }

    /// The deepest of `set` on this tree; between equals the lowest id.
    pub(crate) fn innermost(&self, set: &Set) -> Option<Uuid> {
        let mut best: Option<(usize, Uuid)> = None;
        for g in set {
            let d = self.depth(*g);
            if best.is_none_or(|(b, _)| d > b) {
                best = Some((d, *g));
            }
        }
        best.map(|(_, g)| g)
    }

    /// True when `extra`, known shares, holds or is on the way up from the stamp's group.
    pub(crate) fn covers(&mut self, stamp: Option<Stamp>, extra: &Set) -> bool {
        stamp.is_some_and(|s| {
            let up = self.shares_from(s.group);
            extra.contains(&s.group) || extra.iter().any(|g| self.holds(up, *g))
        })
    }

    /// The groups whose way up leads through group `id`, itself included (none for the
    /// bin, which no way up passes): one pass over the groups, each step up read once.
    fn through(&self, id: Uuid) -> HashSet<Uuid> {
        if Some(id) == self.bin {
            return HashSet::new();
        }
        let mut below: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for x in self.up.keys().filter(|x| Some(**x) != self.bin) {
            if let Some(next) = self.step(*x) {
                below.entry(next).or_default().push(*x);
            }
        }
        let mut out = HashSet::from([id]);
        let mut todo = vec![id];
        while let Some(x) = todo.pop() {
            for y in below.remove(&x).unwrap_or_default() {
                if out.insert(y) {
                    todo.push(y);
                }
            }
        }
        out
    }

    /// R6 B: the stamp of one object a user's move carried. `new` is what the
    /// move added, `own` the object's set now.
    pub(crate) fn moved(&self, data: &mut CustomData, new: &Set, own: &Set, now: Time) {
        if let Some(group) = self.innermost(new) {
            // At the item limit the move stays unstamped ([`put`]), as a move on a Mac
            // that does not know the share (limit 2).
            set_stamp(data, Some(Stamp { group, at: now }));
        } else if own.is_empty() {
            set_stamp(data, None);
        } else if let Some(s) = stamp_of(data).filter(|s| !own.contains(&s.group)) {
            let group = self.innermost(own).unwrap_or(s.group);
            set_stamp(data, Some(Stamp { group, ..s }));
        }
    }
}

/// R6 B: group `id` moved and `new` is what that added to its set: each object
/// its way up leads through takes its stamp, bin items that would come back to it
/// included. `places` already holds the group's new place.
pub(crate) fn group_moved(v: &mut Vault, places: &mut Places, id: Uuid, new: &Set, now: Time) {
    let held = places.through(id);
    let bin = places.bin;
    let comes_back = |parent: Uuid, prev: Option<Uuid>| {
        if Some(parent) == bin {
            prev.is_some_and(|p| held.contains(&p))
        } else {
            held.contains(&parent)
        }
    };
    let mut stack = vec![&mut v.root];
    while let Some(g) = stack.pop() {
        let at = g.uuid;
        for e in &mut g.entries {
            if comes_back(at, e.previous_parent) {
                let own = places.set_at(at, e.previous_parent, None);
                places.moved(&mut e.custom_data, new, &own, now);
            }
        }
        for c in &mut g.groups {
            if c.uuid == id || comes_back(at, c.previous_parent) {
                let own = places.set_at(at, c.previous_parent, Some(c.uuid));
                places.moved(&mut c.custom_data, new, &own, now);
            }
        }
        stack.extend(g.groups.iter_mut());
    }
}

/// Groups went: an item directly in the bin that named one as its previous parent
/// now names what `gone` says, followed to one that stayed. One walk for all of them,
/// and each gone group's end found once, so erasing is linear in the objects
/// (MOD-11.15).
pub(crate) fn gone_groups(root: &mut Group, bin: Option<Uuid>, gone: &HashMap<Uuid, Option<Uuid>>) {
    let Some(bin) = bin.filter(|_| !gone.is_empty()) else {
        return;
    };
    let mut end: HashMap<Uuid, Option<Uuid>> = HashMap::new();
    let mut follow = |prev: &mut Option<Uuid>| {
        let mut seen = Vec::new();
        let mut at = *prev;
        while let Some(p) = at {
            if let Some(e) = end.get(&p) {
                at = *e;
                break;
            }
            match gone.get(&p) {
                Some(&to) if to != Some(p) && seen.len() <= gone.len() => {
                    seen.push(p);
                    at = to;
                }
                _ => break,
            }
        }
        for p in seen {
            end.insert(p, at);
        }
        *prev = at;
    };
    let mut stack = vec![root];
    while let Some(g) = stack.pop() {
        if g.uuid == bin {
            g.entries
                .iter_mut()
                .for_each(|e| follow(&mut e.previous_parent));
            g.groups
                .iter_mut()
                .for_each(|c| follow(&mut c.previous_parent));
            return;
        }
        stack.extend(g.groups.iter_mut());
    }
}

/// R6 D, the rows an export of `share` carries, as (id, time): the share's own, and a
/// row of a share nested in it (`inside`) only while the object counts in that share
/// on this Mac or this Mac does not hold it. So a member of a nested share cannot erase,
/// through this Mac, what this Mac holds in the outer share outside it, and still
/// reaches the outer share's members. When this Mac no longer holds the object the row
/// goes out though another Mac may have moved the object out of the nested share: a
/// stale member's deletion can then erase it there (INT-08.32 limit 18).
#[must_use]
pub fn export_rows(v: &Vault, share: Uuid, inside: &HashSet<Uuid>) -> Vec<(Uuid, Time)> {
    let rows = read_rows(&v.meta.custom_data);
    let nested: HashSet<Uuid> = rows
        .keys()
        .filter(|(_, g)| *g != share && inside.contains(g))
        .map(|(id, _)| *id)
        .collect();
    let mut counts: HashMap<Uuid, Set> = HashMap::new();
    if !nested.is_empty() {
        let mut places = Places::new(v, known(v));
        let mut stack = vec![&v.root];
        while let Some(g) = stack.pop() {
            for e in g.entries.iter().filter(|e| nested.contains(&e.uuid)) {
                let set = places.set_at(g.uuid, e.previous_parent, None);
                counts.entry(e.uuid).or_default().extend(set);
            }
            for c in &g.groups {
                if nested.contains(&c.uuid) {
                    let set = places.set_at(g.uuid, c.previous_parent, Some(c.uuid));
                    counts.entry(c.uuid).or_default().extend(set);
                }
                stack.push(c);
            }
        }
    }
    rows.into_iter()
        .filter(|((id, g), _)| {
            *g == share || (inside.contains(g) && counts.get(id).is_none_or(|set| set.contains(g)))
        })
        .map(|((id, _), at)| (id, at))
        .collect()
}

/// True for the keys in a vault's custom data.
pub(crate) fn vault_key(key: &str) -> bool {
    same_key(key, SCOPES) || same_key(key, KNOWN)
}

/// True when `v` holds any of the five items, history included.
#[must_use]
pub fn held(v: &Vault) -> bool {
    let own = |d: &CustomData| d.items.iter().any(|i| ours(&i.key));
    v.meta.custom_data.items.iter().any(|i| vault_key(&i.key))
        || v.root.subtree().iter().any(|g| {
            own(&g.custom_data)
                || g.entries
                    .iter()
                    .any(|e| own(&e.custom_data) || e.history.iter().any(|h| own(&h.custom_data)))
        })
}

/// Takes the stamp and marker off everything in `root`, history included, and every
/// tagged history item out.
pub fn strip_tree(root: &mut Group) {
    let mut stack = vec![root];
    while let Some(g) = stack.pop() {
        strip_data(&mut g.custom_data);
        g.entries.iter_mut().for_each(strip_entry);
        stack.extend(g.groups.iter_mut());
    }
}

/// Takes the stamp and marker off the objects of `root`, not the history: a copy
/// of them on this Mac (a clone), with its private items.
pub(crate) fn clear_tree(root: &mut Group) {
    let mut stack = vec![root];
    while let Some(g) = stack.pop() {
        strip_data(&mut g.custom_data);
        g.entries
            .iter_mut()
            .for_each(|e| strip_data(&mut e.custom_data));
        stack.extend(g.groups.iter_mut());
    }
}

/// Takes the stamp and marker off one entry, history included, and every tagged
/// history item out.
pub(crate) fn strip_entry(e: &mut Entry) {
    strip_data(&mut e.custom_data);
    e.history.retain(|h| !private_item(h));
    for h in &mut e.history {
        strip_data(&mut h.custom_data);
    }
}

fn strip_data(data: &mut CustomData) {
    data.items.retain(|i| !ours(&i.key));
}

/// Takes all five items out of `v` (INT-08.32).
pub fn strip(v: &mut Vault) {
    v.meta.custom_data.items.retain(|i| !vault_key(&i.key));
    strip_tree(&mut v.root);
}

/// INT-08.33 at the door as well as at the file: no group of an import keeps a share
/// item, whatever path brought the container.
pub fn strip_shares(root: &mut Group) {
    let key = core::str::from_utf8(edit::SHARED_KEY).unwrap_or("");
    let mut stack = vec![root];
    while let Some(g) = stack.pop() {
        g.custom_data.items.retain(|i| !same_key(&i.key, key));
        stack.extend(g.groups.iter_mut());
    }
}

/// R6 C1: no time of a share's container is later than the import: every object's
/// Mod, Loc and history times, and every record's time. A record's time is not below
/// zero, the file format's first time, so a row keeps its stated size.
pub fn clamp(v: &mut Vault, now: Time) {
    let cut = |t: &mut larsal_model::Times| {
        t.last_modification = t.last_modification.min(now);
        t.location_changed = t.location_changed.min(now);
    };
    let mut stack = vec![&mut v.root];
    while let Some(g) = stack.pop() {
        cut(&mut g.times);
        for e in &mut g.entries {
            cut(&mut e.times);
            for h in &mut e.history {
                h.times.last_modification = h.times.last_modification.min(now);
            }
        }
        stack.extend(g.groups.iter_mut());
    }
    for d in &mut v.deleted_objects {
        d.deleted_at = d.deleted_at.min(now).max(Time(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Uuid {
        Uuid([n; 16])
    }

    #[test]
    fn rows_round_trip_and_two_orders_write_one_text() {
        let mut a = Rows::new();
        a.insert((id(5), id(0x20)), Time(7));
        a.insert((id(6), id(0x20)), Time(8));
        a.insert((id(6), id(0x21)), Time(9));
        let (mut x, mut y) = (CustomData::default(), CustomData::default());
        assert!(write_rows(&mut x, &a));
        assert!(!write_rows(&mut x, &a), "the same list is no change");
        assert_eq!(read_rows(&x), a);
        let b: Rows = a.iter().rev().map(|(k, v)| (*k, *v)).collect();
        write_rows(&mut y, &b);
        assert_eq!(x.get(SCOPES), y.get(SCOPES));
        assert!(write_rows(&mut x, &Rows::new()));
        assert!(x.items.is_empty(), "an empty list leaves no item");
    }

    #[test]
    fn past_the_cap_the_newest_rows_stay_per_share() {
        let mut rows = Rows::new();
        for n in 0..=(ROW_CAP as u64) {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&n.to_le_bytes());
            rows.insert((Uuid(b), id(0x20)), Time(i64::try_from(n).unwrap()));
        }
        rows.insert((id(1), id(0x21)), Time(0));
        let mut d = CustomData::default();
        write_rows(&mut d, &rows);
        let kept = read_rows(&d);
        assert_eq!(kept.len(), ROW_CAP + 1, "the other share's row stays");
        let oldest = kept
            .iter()
            .filter(|((_, g), _)| *g == id(0x20))
            .map(|(_, t)| t.0)
            .min();
        assert_eq!(oldest, Some(1), "only the oldest went");
    }

    #[test]
    fn a_value_that_cannot_be_read_counts_as_not_there() {
        let mut d = CustomData::default();
        for bad in ["", "zz", "not hex at all, not hex at all!!", ";;;", "=:,"] {
            d.items = vec![
                item(SCOPES, bad.to_owned()),
                item(MARK, bad.to_owned()),
                item(STAMP, bad.to_owned()),
                item(KNOWN, bad.to_owned()),
            ];
            assert!(read_rows(&d).is_empty(), "{bad:?}");
            assert_eq!(mark_of(&d), None, "{bad:?}");
            assert_eq!(stamp_of(&d), None, "{bad:?}");
            assert!(read_known(&d).is_empty(), "{bad:?}");
        }
    }

    /// C1-07 (S3): two shares of one set at one depth, which needs a share group in the
    /// bin: the innermost is the lowest id of them, as the doc says, on every Mac.
    #[test]
    fn innermost_between_equals_is_the_lowest_id() {
        let mut root = Group::new(id(2), "R".into(), Time(0));
        let mut t = Group::new(id(0x30), "T".into(), Time(0));
        t.groups.push(Group::new(id(0x40), "S".into(), Time(0)));
        let mut bin = Group::new(id(0x5a), "Bin".into(), Time(0));
        let mut g = Group::new(id(0x31), "G".into(), Time(0));
        g.previous_parent = Some(id(0x40));
        bin.groups.push(g);
        root.groups.push(t);
        root.groups.push(bin);
        let mut v = Vault::new(root, Time(0));
        v.meta.recycle_bin_enabled = true;
        v.meta.recycle_bin = Some(id(0x5a));
        let places = Places::new(&v, Set::from([id(0x30), id(0x40), id(0x31)]));
        assert_eq!(
            places.innermost(&Set::from([id(0x30), id(0x40)])),
            Some(id(0x40))
        );
        assert_eq!(
            places.innermost(&Set::from([id(0x40), id(0x31)])),
            Some(id(0x31))
        );
    }

    /// C1-07 (T1, T2): a bin item whose previous parent is itself, or a group that is not
    /// there, counts in no share, though a known share has that id. Larsal writes neither;
    /// a file from another writer can.
    #[test]
    fn a_bin_item_naming_itself_or_no_group_counts_nowhere() {
        let mut root = Group::new(id(2), "R".into(), Time(0));
        let mut bin = Group::new(id(0x5a), "Bin".into(), Time(0));
        let mut g = Group::new(id(0x31), "G".into(), Time(0));
        g.previous_parent = Some(id(0x31));
        bin.groups.push(g);
        root.groups.push(bin);
        let mut v = Vault::new(root, Time(0));
        v.meta.recycle_bin_enabled = true;
        v.meta.recycle_bin = Some(id(0x5a));
        let mut places = Places::new(&v, Set::from([id(0x31), id(0x32)]));
        let bin = id(0x5a);
        assert_eq!(
            places.set_at(bin, Some(id(0x31)), Some(id(0x31))),
            Set::new()
        );
        assert_eq!(places.set_at(bin, Some(id(0x32)), None), Set::new());
        assert_eq!(
            places.set_at(bin, Some(id(0x31)), None),
            Set::from([id(0x31)])
        );
    }

    #[test]
    fn the_rows_or_the_list_alone_are_held() {
        let root = || Group::new(id(2), "R".into(), Time(0));
        let mut v = Vault::new(root(), Time(0));
        assert!(!held(&v));
        write_known(&mut v.meta.custom_data, &Set::from([id(0x20)]));
        assert!(held(&v));
        let mut v = Vault::new(root(), Time(0));
        let rows = Rows::from([((id(1), id(0x20)), Time(4))]);
        write_rows(&mut v.meta.custom_data, &rows);
        assert!(held(&v));
    }

    #[test]
    fn a_kept_unknown_part_is_content() {
        let (a, mut b) = (CustomData::default(), CustomData::default());
        assert!(same_data(&a, &b));
        b.unknown.push(larsal_model::unknown::UnknownElement {
            name: "Part".to_owned(),
            attributes: Vec::new(),
            content: Vec::new(),
        });
        assert!(!same_data(&a, &b));
    }

    #[test]
    fn a_history_item_holds_the_stamp_too() {
        let (mut e, mut h) = (Entry::new(id(1), Time(0)), Entry::new(id(1), Time(0)));
        set_mark(&mut h.custom_data, id(0x20));
        set_stamp(
            &mut h.custom_data,
            Some(Stamp {
                group: id(0x20),
                at: Time(4),
            }),
        );
        e.history.push(h);
        let mut root = Group::new(id(2), "R".into(), Time(0));
        root.entries.push(e);
        let mut v = Vault::new(root, Time(0));
        assert!(held(&v));
        strip(&mut v);
        assert!(!held(&v));
    }

    #[test]
    fn the_stamp_and_marker_are_not_content() {
        let (mut a, b) = (CustomData::default(), CustomData::default());
        set_mark(&mut a, id(0x20));
        let s = Stamp {
            group: id(0x20),
            at: Time(-3),
        };
        set_stamp(&mut a, Some(s));
        assert_eq!(mark_of(&a), Some(id(0x20)));
        assert_eq!(stamp_of(&a), Some(s));
        assert!(same_data(&a, &b));
        a.items.push(item("other", "x".to_owned()));
        assert!(!same_data(&a, &b));
    }

    #[test]
    fn known_reads_the_list_and_the_share_items() {
        let mut t = Group::new(id(3), "T".into(), Time(0));
        t.custom_data.items.push(item(
            core::str::from_utf8(edit::SHARED_KEY).unwrap(),
            String::new(),
        ));
        let mut root = Group::new(id(2), "R".into(), Time(0));
        root.groups.push(t);
        let mut v = Vault::new(root, Time(0));
        write_known(&mut v.meta.custom_data, &Set::from([id(9)]));
        assert_eq!(known(&v), Set::from([id(9), id(3)]));
    }

    /// A vault whose root holds `top` and a bin (0x5a) holding `in_bin`.
    fn with_bin(top: Vec<Group>, in_bin: Vec<Group>) -> Vault {
        let mut root = Group::new(id(2), "R".into(), Time(0));
        let mut bin = Group::new(id(0x5a), "Bin".into(), Time(0));
        bin.groups = in_bin;
        root.groups = top;
        root.groups.push(bin);
        let mut v = Vault::new(root, Time(0));
        v.meta.recycle_bin_enabled = true;
        v.meta.recycle_bin = Some(id(0x5a));
        v
    }

    fn group(n: u8, prev: Option<u8>) -> Group {
        let mut g = Group::new(id(n), "G".into(), Time(0));
        g.previous_parent = prev.map(id);
        g
    }

    /// C1R5-05, mutant 25: a known share that goes in a merge leaves every set whose way up
    /// led through it, those kept from before too. Bin group Y names bin group Z, which
    /// names known share K in the bin, which names P.
    #[test]
    fn a_known_share_that_goes_leaves_the_sets_kept_through_it() {
        let v = with_bin(
            vec![group(0x30, None)],
            vec![
                group(0x31, Some(0x30)),
                group(0x32, Some(0x31)),
                group(0x33, Some(0x32)),
            ],
        );
        let mut places = Places::new(&v, Set::from([id(0x31)]));
        let bin = id(0x5a);
        let s = places.shares_at(bin, Some(id(0x32)), Some(id(0x33)));
        assert_eq!(places.set_of(s), Set::from([id(0x31)]));
        assert!(places.holds(s, id(0x31)));
        assert_eq!(places.gone(id(0x31)), Some(id(0x30)));
        assert_eq!(
            places.set_at(bin, Some(id(0x32)), Some(id(0x33))),
            Set::new()
        );
        assert!(
            places
                .shares_at(bin, Some(id(0x32)), Some(id(0x33)))
                .is_empty()
        );
        assert!(!places.holds(s, id(0x31)));
        assert_eq!(places.set_of(s), Set::new());
    }

    /// Mutants 46 and 47: a group whose innermost share went in this merge counts in the next
    /// known share up from where that one was, read through `went`. Known share T holds
    /// known share K; bin group Y names K. Y's answer (K) is kept, then K goes.
    #[test]
    fn a_group_whose_share_went_counts_in_the_next_share_up() {
        let mut t = Group::new(id(0x20), "T".into(), Time(0));
        t.groups.push(group(0x31, None));
        let v = with_bin(vec![t], vec![group(0x33, Some(0x31))]);
        let mut places = Places::new(&v, Set::from([id(0x20), id(0x31)]));
        assert_eq!(places.head(id(0x33)), Some(id(0x31)));
        assert_eq!(places.gone(id(0x31)), Some(id(0x20)));
        assert_eq!(places.set_at(id(0x33), None, None), Set::from([id(0x20)]));
        assert_eq!(
            places.set_at(id(0x5a), Some(id(0x33)), None),
            Set::from([id(0x20)])
        );
    }

    /// C1R5-05, mutant 27: through a cycle of previous parents a share counts in its whole
    /// ring. Known bin groups A and B name each other.
    #[test]
    fn a_ring_of_known_bin_groups_counts_in_each_other() {
        let v = with_bin(
            vec![],
            vec![group(0x31, Some(0x32)), group(0x32, Some(0x31))],
        );
        let mut places = Places::new(&v, Set::from([id(0x31), id(0x32)]));
        let both = Set::from([id(0x31), id(0x32)]);
        assert_eq!(places.set_at(id(0x5a), Some(id(0x31)), None), both);
        assert_eq!(places.set_at(id(0x5a), Some(id(0x32)), None), both);
    }

    /// C1R5-05, mutant 29: a bin group whose previous parent is not on the tree counts in no
    /// share, though a known share has that id.
    #[test]
    fn a_bin_group_naming_a_known_share_not_there_counts_nowhere() {
        let v = with_bin(vec![], vec![group(0x31, Some(0x40))]);
        let mut places = Places::new(&v, Set::from([id(0x40)]));
        assert_eq!(places.set_at(id(0x5a), Some(id(0x31)), None), Set::new());
    }

    /// C1R5-05, mutant 30: a bin group naming the bin counts in no share, not even a share of
    /// the whole vault: no way up passes the bin.
    #[test]
    fn a_bin_group_naming_the_bin_counts_nowhere() {
        let v = with_bin(vec![], vec![group(0x31, Some(0x5a))]);
        let mut places = Places::new(&v, Set::from([id(2)]));
        assert_eq!(places.set_at(id(0x5a), Some(id(0x31)), None), Set::new());
        assert_eq!(places.set_at(id(2), None, None), Set::from([id(2)]));
    }

    /// One set, one id, in whatever order its shares were added; contains and items read
    /// back exactly what went in.
    #[test]
    fn a_set_has_one_id_whatever_the_order() {
        let mut st = Store::new();
        let ids: Vec<Uuid> = [0x01u8, 0x80, 0x7f, 0xfe, 0x40, 0x41, 0xff]
            .iter()
            .map(|n| id(*n))
            .chain([Uuid([0; 16]), Uuid([0xff; 16])])
            .collect();
        let mut a = 0;
        for g in &ids {
            a = st.insert(a, key_of(*g));
        }
        let mut b = 0;
        for g in ids.iter().rev() {
            b = st.insert(b, key_of(*g));
            b = st.insert(b, key_of(*g));
        }
        assert_eq!(a, b);
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(st.items(a), sorted);
        for g in &ids {
            assert!(st.contains(a, key_of(*g)));
        }
        assert!(!st.contains(a, key_of(id(0x42))));
        assert!(!st.contains(0, key_of(id(0x01))));
        let one = st.insert(0, key_of(id(0x01)));
        assert_ne!(one, a);
        assert_eq!(st.insert(one, key_of(id(0x01))), one);
    }

    /// C1R6-03, mutant c07: a group's move clears the kept sets. Known share S moves from
    /// inside known share T to inside known share U; an object in S then counts in S and U.
    #[test]
    fn a_move_clears_the_kept_sets() {
        let mut t = Group::new(id(0x30), "T".into(), Time(0));
        t.groups.push(group(0x31, None));
        let v = with_bin(vec![t, group(0x32, None)], vec![]);
        let mut places = Places::new(&v, Set::from([id(0x30), id(0x31), id(0x32)]));
        let s = id(0x31);
        assert_eq!(places.set_at(s, None, None), Set::from([id(0x30), s]));
        places.set_place(s, id(0x32), None);
        assert_eq!(places.set_at(s, None, None), Set::from([s, id(0x32)]));
    }

    /// C1R6-03, mutant c09: a bin group whose previous parent alone changes counts where it
    /// names now. Bin group Y names known share T, then known share U.
    #[test]
    fn a_new_previous_parent_alone_is_a_move() {
        let v = with_bin(
            vec![group(0x30, None), group(0x32, None)],
            vec![group(0x33, Some(0x30))],
        );
        let mut places = Places::new(&v, Set::from([id(0x30), id(0x32)]));
        let y = id(0x33);
        assert_eq!(places.set_at(y, None, None), Set::from([id(0x30)]));
        places.set_place(y, id(0x5a), Some(id(0x32)));
        assert_eq!(places.set_at(y, None, None), Set::from([id(0x32)]));
    }

    /// C1R6-01: `rows_above` gives each share what asking [`Places::within`] of every row
    /// gives, on random trees with a bin, groups gone and ids off the tree.
    #[test]
    fn rows_above_is_within_asked_of_every_row() {
        let mut seed = 20_261_108u64;
        let mut next = move |n: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % n
        };
        for _ in 0..400 {
            // Group 0x10 + i sits under the root, the bin or an earlier group.
            let n = 1 + next(14) as u8;
            let parent: Vec<u8> = (0..n)
                .map(|i| match next(4) {
                    0 => 2,
                    1 => 0x5a,
                    _ if i > 0 => 0x10 + next(u64::from(i)) as u8,
                    _ => 2,
                })
                .collect();
            let mut made: Vec<Option<Group>> =
                (0..n).map(|i| Some(group(0x10 + i, None))).collect();
            let (mut top, mut in_bin) = (Vec::new(), Vec::new());
            for i in (0..n).rev() {
                let g = made[usize::from(i)].take().unwrap();
                match parent[usize::from(i)] {
                    2 => top.push(g),
                    0x5a => in_bin.push(g),
                    p => made[usize::from(p - 0x10)].as_mut().unwrap().groups.push(g),
                }
            }
            let v = with_bin(top, in_bin);
            let pool: Vec<Uuid> = (0..n)
                .map(|i| id(0x10 + i))
                .chain([id(2), id(0x5a), id(0x7e)])
                .collect();
            let mut pick =
                |k: u64| -> Set { pool.iter().copied().filter(|_| next(k) == 0).collect() };
            let mut places = Places::new(&v, pick(2));
            for g in pick(5) {
                places.gone(g);
            }
            let shares = pick(2);
            let rows: Vec<(Uuid, Time)> = pick(2)
                .into_iter()
                .map(|r| (r, Time(next(5) as i64)))
                .collect();
            let want: Vec<(Uuid, Time)> = shares
                .iter()
                .filter_map(|g| {
                    let best = rows
                        .iter()
                        .filter(|(r, _)| r != g && places.within(*g, *r))
                        .map(|(_, at)| *at)
                        .max();
                    best.map(|t| (*g, t))
                })
                .collect();
            assert_eq!(places.rows_above(&shares, &rows), want, "{parent:x?}");
        }
    }
}
