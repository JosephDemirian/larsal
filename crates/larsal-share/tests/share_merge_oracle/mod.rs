//! The oracle of the fuzz target `share_merge` (E11-S6, RT-2, RT-10, INT-08.32,
//! MOD-11.15, rule R6), shared with `tests/share_merge.rs` so it runs on the pinned
//! toolchain too. Three copies of one vault with two shares: Mac A, Mac B and Mac C.
//! Any Mac imports, and a user moves and deletes. After every step and through a last
//! sweep of all six merge kinds, both ways on repeat rounds, it must never panic and
//! the model's I1, I2 and I5 hold:
//!
//! - I1: no export of either share holds the private value of an object no user moved
//!   into a share, and no export holds the rule's items, a private history item least
//!   of all (the model's I1t, round 4).
//! - I2: a copy held outside the shares stays there, with its value and its place,
//!   until a user acts on it. It is not erased, overwritten or pulled in or binned.
//! - I5: a move in is not undone by a deletion older than it.
//!
//! What a user acts on leaves I2's list as far as that act reaches: a move, a move in, a
//! deletion of a copy that counted outside, and so on down the group on every Mac. The
//! rule's stated limits are where the words below say so.
//!
//! Input: triples of bytes (what, id, time), id taken in a small range so the ids meet
//! the vault's. What, as a remainder of 11: 0 an entry in the container's root, 1 a
//! group there, 2 an entry in the last group, 3 a deleted item, 4 import it on Mac
//! `id % 3` into the share `time % 2`, 5 merge one Mac into another, 6 a user deletes
//! for good, 7 a user bins, 8 a user moves into a share, 9 a user moves to an outside
//! group, 10 one Mac exports and another imports that. A last import on Mac A lists
//! every id named before, dated after them all, so every input also tries the crossing
//! of two imports.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use larsal_core::edit::{self, Position};
use larsal_core::merge::{Kind, Options, merge};
use larsal_core::origin;
use larsal_core::recycle::{self, References};
use larsal_crypto::secret::SecretString;
use larsal_model::{DeletedObject, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};
use std::collections::{BTreeMap, BTreeSet};

const T0: Time = Time(63_902_822_400);
const LATE: Time = Time(63_907_920_000);
const NOW: Time = Time(63_910_000_000);
/// Every password a container brings.
const PLANTED: &str = "planted-demo";
/// Every password a Mac holds outside the shares.
const OUTSIDE: &str = "outside-demo";

const S: u8 = 0x20;
const U: u8 = 0x22;
const P: u8 = 0x30;
const G: u8 = 0x32;
const Q: u8 = 0x34;
const BIN: u8 = 0x5a;
/// What starts outside: the groups, and the entries with the private value.
const WATCHED: [Key; 6] = [
    (P, true),
    (0x31, false),
    (G, true),
    (0x33, false),
    (Q, true),
    (0x35, false),
];

/// An id and whether it names a group: a container can use one id for both (F8).
type Key = (u8, bool);

const KINDS: [Kind; 6] = [
    Kind::ChangeOnDisk,
    Kind::ConflictCopy,
    Kind::ServerSync,
    Kind::Window,
    Kind::CommandLine,
    Kind::RemoteSync,
];

fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}

fn with_password(n: u8, password: &str, at: Time) -> Entry {
    let mut e = Entry::new(id(n), at);
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new(password.to_owned()),
            protected: true,
        },
    );
    e
}

fn outside_group(n: u8, name: &str, entry: u8) -> Group {
    let mut g = Group::new(id(n), name.into(), T0);
    g.entries.push(with_password(entry, OUTSIDE, T0));
    g
}

/// The common vault: Root(01) -> S(20) -> X(21), U(22) -> Y(23), the bin. Both shares
/// known, as a set-up leaves them.
fn common() -> Vault {
    let mut s = Group::new(id(S), "S".into(), T0);
    s.entries.push(Entry::new(id(0x21), T0));
    let mut u = Group::new(id(U), "U".into(), T0);
    u.entries.push(Entry::new(id(0x23), T0));
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups = vec![s, u, Group::new(id(BIN), "Bin".into(), T0)];
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = false;
    v.meta.recycle_bin = Some(id(BIN));
    let known: BTreeSet<Uuid> = [id(S), id(U)].into_iter().collect();
    origin::write_known(&mut v.meta.custom_data, &known);
    v
}

/// Mac A holds Q{35} outside; Mac B P{31} and G{33}; Mac C P{31}.
fn macs() -> Vec<Vault> {
    let mut a = common();
    a.root.groups.push(outside_group(Q, "Q", 0x35));
    let mut b = common();
    b.root.groups.push(outside_group(P, "P", 0x31));
    b.root.groups.push(outside_group(G, "G", 0x33));
    let mut c = common();
    c.root.groups.push(outside_group(P, "P", 0x31));
    vec![a, b, c]
}

fn empty_container() -> Vault {
    let root = Group::new(id(0x66), "Share".into(), T0);
    Vault::new(root, T0)
}

/// One watched object on one copy.
struct Found {
    parent: Uuid,
    inside: bool,
    in_bin: bool,
    /// An entry's password, a group's name.
    value: String,
}

fn survey(g: &Group, inside: bool, in_bin: bool, out: &mut BTreeMap<Key, Found>) {
    let inside = inside || g.uuid == id(S) || g.uuid == id(U);
    let in_bin = in_bin || g.uuid == id(BIN);
    for e in &g.entries {
        out.insert(
            (e.uuid.0[0], false),
            Found {
                parent: g.uuid,
                inside,
                in_bin,
                value: e.value("Password").to_owned(),
            },
        );
    }
    for c in &g.groups {
        out.insert(
            (c.uuid.0[0], true),
            Found {
                parent: g.uuid,
                inside,
                in_bin,
                value: c.name.clone(),
            },
        );
        survey(c, inside, in_bin, out);
    }
}

fn surveyed(v: &Vault) -> BTreeMap<Key, Found> {
    let mut out = BTreeMap::new();
    survey(&v.root, false, false, &mut out);
    out
}

fn start_value(x: Key) -> &'static str {
    match x {
        (P, true) => "P",
        (G, true) => "G",
        (Q, true) => "Q",
        _ => OUTSIDE,
    }
}

struct World {
    macs: Vec<Vault>,
    /// Per Mac: each watched object it holds outside, with its parent.
    held: Vec<BTreeMap<Key, Uuid>>,
    /// A user moved it, or a group above it, somewhere.
    moved: BTreeSet<Key>,
    /// A user moved it, or a group above it, into a share.
    moved_in: BTreeSet<Key>,
    /// A user deleted a copy of it that counted outside: a plain record. A record names
    /// an id and no kind, so this holds both kinds (INT-08.32, F8).
    gone: BTreeSet<Key>,
    /// Mac that moved it in, while nothing newer can delete it (limit 4).
    stands: BTreeMap<Key, usize>,
    clock: i64,
}

impl World {
    fn new() -> Self {
        let mut w = Self {
            macs: macs(),
            held: vec![BTreeMap::new(); 3],
            moved: BTreeSet::new(),
            moved_in: BTreeSet::new(),
            gone: BTreeSet::new(),
            stands: BTreeMap::new(),
            clock: 0,
        };
        w.note_held();
        w
    }

    fn duplicate(&self) -> Self {
        Self {
            macs: self.macs.iter().map(Vault::duplicate).collect(),
            held: self.held.clone(),
            moved: self.moved.clone(),
            moved_in: self.moved_in.clone(),
            gone: self.gone.clone(),
            stands: self.stands.clone(),
            clock: self.clock,
        }
    }

    fn now(&mut self) -> Time {
        self.clock += 1;
        Time(NOW.0 + self.clock * 1000)
    }

    /// `x` and everything under it on any Mac. A bin item counts where its previous
    /// parent is, as the rule and the model's chain have it.
    fn reach(&self, x: Key) -> BTreeSet<Key> {
        fn links(g: &Group, out: &mut Vec<(Key, Uuid)>) {
            for e in &g.entries {
                out.push(((e.uuid.0[0], false), g.uuid));
                if let Some(p) = e.previous_parent {
                    out.push(((e.uuid.0[0], false), p));
                }
            }
            for c in &g.groups {
                out.push(((c.uuid.0[0], true), g.uuid));
                if let Some(p) = c.previous_parent {
                    out.push(((c.uuid.0[0], true), p));
                }
                links(c, out);
            }
        }
        let mut all = Vec::new();
        for v in &self.macs {
            links(&v.root, &mut all);
        }
        let mut out = BTreeSet::from([x]);
        let mut size = 0;
        while size != out.len() {
            size = out.len();
            for (k, up) in &all {
                if out.contains(&(up.0[0], true)) {
                    out.insert(*k);
                }
            }
        }
        out
    }

    fn note_held(&mut self) {
        for (m, v) in self.macs.iter().enumerate() {
            let now = surveyed(v);
            self.held[m] = WATCHED
                .iter()
                .filter_map(|x| {
                    let f = now.get(x)?;
                    let holds = !f.inside && !f.in_bin && f.value == start_value(*x);
                    holds.then_some((*x, f.parent))
                })
                .collect();
        }
    }

    /// I1, I2 and I5 on every copy.
    fn check(&mut self, what: &str) {
        for (m, v) in self.macs.iter().enumerate() {
            assert_eq!(larsal_model::invariants::check(v), Ok(()), "{what}");
            for share in [S, U] {
                let Ok(export) = container::build(id(share), true, v, NOW) else {
                    continue;
                };
                assert!(!origin::held(&export), "{what}: export holds a key");
                assert!(
                    export
                        .root
                        .all_entries()
                        .all(|e| !e.history.iter().any(origin::private_item)),
                    "I1t {what}: Mac {m} exports a private item"
                );
                for e in export.root.all_entries() {
                    let private = e.value("Password") == OUTSIDE
                        || e.history.iter().any(|h| h.value("Password") == OUTSIDE);
                    assert!(
                        !private || self.moved_in.contains(&(e.uuid.0[0], false)),
                        "I1 {what}: Mac {m} exports {:x}",
                        e.uuid.0[0]
                    );
                }
            }
            let now = surveyed(v);
            for (x, parent) in &self.held[m] {
                if self.gone.contains(x) || self.moved_in.contains(x) {
                    continue;
                }
                let f = now
                    .get(x)
                    .unwrap_or_else(|| panic!("I2b {what}: Mac {m} lost {x:x?}"));
                assert!(!f.inside, "I2c {what}: Mac {m}: {x:x?} pulled in");
                assert_eq!(f.value, start_value(*x), "I2a {what}: Mac {m}: {x:x?}");
                if !self.moved.contains(x) {
                    assert!(!f.in_bin, "I2c {what}: Mac {m}: {x:x?} binned");
                    assert_eq!(f.parent, *parent, "I2d {what}: Mac {m}: {x:x?}");
                }
            }
            for (x, by) in &self.stands {
                if *by == m && !self.gone.contains(x) {
                    assert!(now.contains_key(x), "I5 {what}: Mac {m} lost {x:x?}");
                }
            }
        }
        self.note_held();
    }

    fn merge_macs(&mut self, into: usize, from: usize, kind: Kind) {
        let now = self.now();
        let source = self.macs[from].duplicate();
        let o = Options::new(kind);
        merge(&mut self.macs[into], &source, &o, now).expect("a same-vault merge");
        self.check("merge");
    }

    fn import(&mut self, m: usize, share: u8, c: &Vault) {
        // The container is built here, so it may break what the reader enforces: the
        // merge only ever sees what `container::open` lets through.
        if larsal_model::invariants::check(c).is_err() {
            return;
        }
        for d in &c.deleted_objects {
            for kind in [false, true] {
                for x in self.reach((d.uuid.0[0], kind)) {
                    self.stands.remove(&x);
                }
            }
        }
        let now = self.now();
        let _ = run::merge_into(&mut self.macs[m], id(share), c, now);
        self.check("import");
    }

    /// What the user can act on with this id here, a group first. The share groups
    /// stay: their removal has its own tests (RF8c).
    fn acts_on(&self, m: usize, x: u8) -> Option<(Key, Found)> {
        if x == S || x == U {
            return None;
        }
        let mut all = surveyed(&self.macs[m]);
        [(x, true), (x, false)]
            .into_iter()
            .find_map(|k| all.remove(&k).map(|f| (k, f)))
    }

    fn delete(&mut self, m: usize, x: u8, bin: bool) {
        let Some((key, f)) = self.acts_on(m, x) else {
            return;
        };
        let counted_outside =
            (!f.inside && !f.in_bin) || self.moved.contains(&key) || self.moved_in.contains(&key);
        let reach = self.reach(key);
        let now = self.now();
        let v = &mut self.macs[m];
        v.meta.recycle_bin_enabled = bin;
        let done = if key.1 {
            recycle::delete_group(v, id(x), now).map(|_| ())
        } else {
            recycle::delete_entries(v, &[id(x)], now, |_, _| References::Delete).map(|_| ())
        };
        v.meta.recycle_bin_enabled = false;
        if done.is_err() {
            return;
        }
        let writes_record = !bin || f.in_bin;
        for y in reach {
            self.stands.remove(&y);
            if writes_record {
                // A record or a row names an id and no kind (INT-08.32, F8).
                self.stands.remove(&(y.0, !y.1));
            }
            if counted_outside {
                if writes_record {
                    self.gone.insert(y);
                    self.gone.insert((y.0, !y.1));
                } else {
                    self.moved.insert(y);
                }
            }
        }
        self.check("delete");
    }

    fn move_to(&mut self, m: usize, x: Key, to: u8) -> bool {
        let reach = self.reach(x);
        let now = self.now();
        let v = &mut self.macs[m];
        let done = if x.1 {
            edit::move_group(v, id(x.0), id(to), Position::End, now).is_ok()
        } else {
            edit::move_entries(v, &[id(x.0)], id(to), now).is_ok()
        };
        if done {
            self.moved.extend(reach);
        }
        done
    }

    fn move_in(&mut self, m: usize, x: u8, share: u8) {
        let Some((key, f)) = self.acts_on(m, x) else {
            return;
        };
        let reach = self.reach(key);
        let here = surveyed(&self.macs[m]);
        if self.move_to(m, key, share) {
            for y in reach {
                self.moved_in.insert(y);
                // From outside: from then on no older deletion undoes it.
                if here.contains_key(&y) && !f.inside && !f.in_bin {
                    self.stands.insert(y, m);
                }
            }
            self.check("move in");
        }
    }

    fn move_out(&mut self, m: usize, x: u8) {
        let Some((key, _)) = self.acts_on(m, x) else {
            return;
        };
        let all = surveyed(&self.macs[m]);
        let free = |g: &u8| all.get(&(*g, true)).is_some_and(|f| !f.inside && !f.in_bin);
        let Some(to) = [P, Q, G].into_iter().find(|g| (*g, true) != key && free(g)) else {
            return;
        };
        if self.move_to(m, key, to) {
            self.check("move out");
        }
    }

    /// One Mac's export, taken by another: a member's honest round.
    fn hand_over(&mut self, from: usize, to: usize, share: u8) {
        let now = self.now();
        if let Ok(c) = container::build(id(share), true, &self.macs[from], now) {
            self.import(to, share, &c);
        }
    }
}

/// Runs one input.
pub fn check(data: &[u8]) {
    let mut w = World::new();
    let mut c = empty_container();
    let mut named = Vec::new();
    for &[what, n, when] in data.as_chunks::<3>().0.iter().take(256) {
        let (what, plain) = (what % 11, n);
        let n = 0x20u8.saturating_add(n % 0x18);
        let at = Time(T0.0.saturating_add(i64::from(when).saturating_mul(86_400 * 30)));
        let mac = usize::from(when % 3);
        let share = if when % 2 == 0 { S } else { U };
        match what {
            0 => {
                let mut e = with_password(n, PLANTED, at);
                e.times.location_changed = at;
                c.root.entries.push(e);
            }
            1 => c.root.groups.push(Group::new(id(n), "N".into(), at)),
            2 => {
                if let Some(g) = c.root.groups.last_mut() {
                    g.entries.push(with_password(n, PLANTED, at));
                }
            }
            3 => c.deleted_objects.push(DeletedObject {
                uuid: id(n),
                deleted_at: at,
                unknown: Vec::new(),
            }),
            4 => {
                let done = std::mem::replace(&mut c, empty_container());
                w.import(usize::from(plain % 3), share, &done);
            }
            5 => {
                let into = usize::from(plain % 3);
                let from = (into + 1 + usize::from(when & 1)) % 3;
                w.merge_macs(into, from, KINDS[usize::from(when % 6)]);
            }
            6 => w.delete(mac, n, false),
            7 => w.delete(mac, n, true),
            8 => w.move_in(mac, n, if when & 8 == 0 { S } else { U }),
            9 => w.move_out(mac, n),
            _ => {
                let from = usize::from(plain % 3);
                let to = (from + 1 + usize::from(when & 1)) % 3;
                w.hand_over(from, to, if when & 8 == 0 { S } else { U });
            }
        }
        if what < 4 {
            named.push(n);
        }
    }
    w.import(0, S, &c);
    let mut last = empty_container();
    named.sort_unstable();
    named.dedup();
    last.deleted_objects = named
        .into_iter()
        .map(|n| DeletedObject {
            uuid: id(n),
            deleted_at: LATE,
            unknown: Vec::new(),
        })
        .collect();
    w.import(0, S, &last);
    for (k, kind) in KINDS.into_iter().enumerate() {
        let mut one = w.duplicate();
        for _ in 0..2 {
            for i in 0..3 {
                for j in 0..3 {
                    if i != j {
                        // Both orders of the pairs, by kind.
                        let (into, from) = if k % 2 == 0 { (i, j) } else { (j, i) };
                        one.merge_macs(into, from, kind);
                    }
                }
            }
        }
    }
}
