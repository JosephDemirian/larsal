//! Rule R6 of shared groups, flow by flow (INT-08.32). Every flow the model searched
//! and named runs here on real code and real saved files: each Mac's vault and each
//! container goes through its file after every step, so nothing lives only in
//! memory. Each flow runs across all six same-vault merge kinds and both merge orders
//! and ends with merges both ways to a fixed point. A test's name carries its flow.
//!
//! Notation: Macs A, B (and C); T share; S a group in T; U a plain group or a second
//! share; P plain group; E, F entries; O a group holding F. Plants name their times:
//! older, now or far; far is clamped to the import's time.
#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use larsal_core::edit::{self, Position};
use larsal_core::history;
use larsal_core::merge::{Kind, Options, merge};
use larsal_core::origin;
use larsal_core::recycle::{self, References};
use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved};
use larsal_model::custom_data::CustomDataItem;
use larsal_model::settings::Kdf;
use larsal_model::{DeletedObject, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const T0: Time = Time(63_902_822_400);
const KINDS: [Kind; 6] = [
    Kind::ChangeOnDisk,
    Kind::ConflictCopy,
    Kind::ServerSync,
    Kind::Window,
    Kind::CommandLine,
    Kind::RemoteSync,
];
const A: usize = 0;
const B: usize = 1;
const C: usize = 2;
const ROOT: u8 = 0x01;
const T: u8 = 0x20;
const S: u8 = 0x21;
const U: u8 = 0x22;
const P: u8 = 0x30;
const O: u8 = 0x31;
const BIN: u8 = 0x5a;
const E: u8 = 0x50;
const F: u8 = 0x51;
const SEED: &str = "seed-demo";
const PLANTED: &str = "planted-demo";
const OLD: &str = "planted-old-demo";
const PRIVATE: &str = "private-demo";
const MEMBER: &str = "member-demo";
const FAR: i64 = 3_000_000_000;

fn at(n: i64) -> Time {
    Time(T0.0 + n)
}

fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}

fn gm(g: &mut Group, n: u8) -> Option<&mut Group> {
    if g.uuid == id(n) {
        return Some(g);
    }
    g.groups.iter_mut().find_map(|c| gm(c, n))
}

fn with_password(e: &mut Entry, password: &str) {
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new(password.to_owned()),
            protected: true,
        },
    );
}

fn entry(n: u8, password: &str, m: Time, l: Time) -> Entry {
    let mut e = Entry::new(id(n), T0);
    with_password(&mut e, password);
    e.times.last_modification = m;
    e.times.location_changed = l;
    e
}

fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(SpeedRecord {
            count: 10_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 100,
        }),
    }
}

/// Who knows which share at the start, by its share item. A Mac's own list is empty:
/// a seed stands for a set-up.
#[derive(Clone, Copy)]
enum Shares {
    /// T on every Mac; U is a plain group.
    One,
    /// T and U on every Mac.
    Two,
    /// T only on Mac A.
    OnlyA,
}

/// What every Mac holds at the start (the model's seeds): `E` and `O{F}`, on which
/// Macs, in which group.
#[derive(Clone, Copy)]
enum Seed {
    /// E in P on every Mac.
    Out,
    /// E in T on every Mac.
    In,
    /// E in P on B only.
    OnB,
    /// E in T on B only.
    InB,
    /// E in T on A only.
    InA,
    /// E in P on A only.
    OutA,
    /// O{F} in T on every Mac.
    GIn,
    /// O{F} in P on every Mac.
    GOut,
    /// O{F} in P on B only.
    GOnB,
}

fn world(shares: Shares, mac: usize) -> Vault {
    let mut root = Group::new(id(ROOT), "Root".into(), T0);
    let mut t = Group::new(id(T), "T".into(), T0);
    t.groups.push(Group::new(id(S), "S".into(), T0));
    root.groups.push(Group::new(id(P), "P".into(), T0));
    root.groups.push(t);
    root.groups.push(Group::new(id(U), "U".into(), T0));
    root.groups.push(Group::new(id(BIN), "Bin".into(), T0));
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = true;
    v.meta.recycle_bin = Some(id(BIN));
    v.meta.history_max_items = -1;
    v.meta.history_max_size = -1;
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    let item = || CustomDataItem {
        key: core::str::from_utf8(edit::SHARED_KEY).unwrap().to_owned(),
        value: SecretString::new(String::new()),
        last_modified: None,
        unknown: Vec::new(),
    };
    if !matches!(shares, Shares::OnlyA) || mac == A {
        gm(&mut v.root, T).unwrap().custom_data.items.push(item());
    }
    if matches!(shares, Shares::Two) {
        gm(&mut v.root, U).unwrap().custom_data.items.push(item());
    }
    v
}

fn put_seed(v: &mut Vault, seed: Seed, mac: usize) {
    let e = || entry(E, SEED, at(1), at(1));
    let o = || {
        let mut o = Group::new(id(O), "O".into(), T0);
        o.times.last_modification = at(1);
        o.times.location_changed = at(1);
        o.entries.push(entry(F, SEED, at(1), at(1)));
        o
    };
    match seed {
        Seed::Out => gm(&mut v.root, P).unwrap().entries.push(e()),
        Seed::In => gm(&mut v.root, T).unwrap().entries.push(e()),
        Seed::OnB if mac == B => gm(&mut v.root, P).unwrap().entries.push(e()),
        Seed::InB if mac == B => gm(&mut v.root, T).unwrap().entries.push(e()),
        Seed::InA if mac == A => gm(&mut v.root, T).unwrap().entries.push(e()),
        Seed::OutA if mac == A => gm(&mut v.root, P).unwrap().entries.push(e()),
        Seed::GIn => gm(&mut v.root, T).unwrap().groups.push(o()),
        Seed::GOut => gm(&mut v.root, P).unwrap().groups.push(o()),
        Seed::GOnB if mac == B => gm(&mut v.root, P).unwrap().groups.push(o()),
        _ => {}
    }
}

/// One object of a planted container: id, parent, Mod and Loc, with a history item.
struct Plant {
    id: u8,
    parent: Option<u8>,
    time: i64,
    history: bool,
}

/// The Macs of one run of a flow, and the share files.
struct Lab {
    macs: Vec<Vault>,
    dir: PathBuf,
    clock: i64,
    kind: Kind,
    first: usize,
    what: String,
    files: BTreeMap<u8, PathBuf>,
    saves: usize,
}

static NEXT: AtomicUsize = AtomicUsize::new(0);
const PASSWORD: &str = "lab-demo";

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Lab {
    fn new(kind: Kind, first: usize, macs: usize, shares: Shares, seed: Seed) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "r6-flows-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut lab = Self {
            macs: (0..macs)
                .map(|m| {
                    let mut v = world(shares, m);
                    put_seed(&mut v, seed, m);
                    v
                })
                .collect(),
            dir,
            clock: 1,
            kind,
            first,
            what: format!("{kind:?}, first merge into Mac {first}"),
            files: BTreeMap::new(),
            saves: 0,
        };
        for m in 0..macs {
            lab.store(m);
        }
        lab
    }

    fn now(&mut self) -> Time {
        self.clock += 1;
        at(self.clock)
    }

    fn save_bytes(v: &Vault) -> Vec<u8> {
        let p = SecretString::new(PASSWORD.to_owned());
        let key = Credentials {
            password: Some(&p),
            ..Credentials::default()
        };
        let mut h = host();
        match larsal_format::save(v, &key, None, &mut h, &Limits::DEFAULT, None).unwrap() {
            Saved::File(f) => f.bytes,
            Saved::Ask(r) => {
                match larsal_format::save(v, &key, None, &mut h, &Limits::DEFAULT, Some(&r))
                    .unwrap()
                {
                    Saved::File(f) => f.bytes,
                    Saved::Ask(_) => panic!("asked twice"),
                }
            }
        }
    }

    /// Mac `m` saves its file and takes back what the file holds.
    fn store(&mut self, m: usize) {
        let path = self.dir.join(format!("mac-{m}.larsalvault"));
        let bytes = Self::save_bytes(&self.macs[m]);
        std::fs::write(&path, bytes).unwrap();
        self.saves += 1;
        self.macs[m] = Self::load(&path);
    }

    fn load(path: &std::path::Path) -> Vault {
        let bytes = std::fs::read(path).unwrap();
        let p = SecretString::new(PASSWORD.to_owned());
        let key = Credentials {
            password: Some(&p),
            ..Credentials::default()
        };
        match larsal_format::open(&bytes, &key, &mut host(), &Limits::DEFAULT, None).unwrap() {
            Opened::Vault(o) => o.vault,
            Opened::Ask(_) => panic!("asked"),
        }
    }

    /// Mac `t` merges the file of Mac `s`, and saves.
    fn merge(&mut self, t: usize, s: usize) {
        let from = Self::load(&self.dir.join(format!("mac-{s}.larsalvault")));
        let now = at(self.clock);
        merge(&mut self.macs[t], &from, &Options::new(self.kind), now).expect("a same-vault merge");
        self.store(t);
    }

    /// Merges both ways to a fixed point, then checks a repeat changes nothing.
    fn settle(&mut self) {
        let n = self.macs.len();
        let pairs: Vec<(usize, usize)> = (0..n)
            .flat_map(|i| (0..n).map(move |j| (i, j)))
            .filter(|(i, j)| i != j)
            .map(|(i, j)| ((i + self.first) % n, (j + self.first) % n))
            .collect();
        let shape = |v: &Vault| show(v);
        for _ in 0..12 {
            let before: Vec<String> = self.macs.iter().map(shape).collect();
            for (t, s) in &pairs {
                self.merge(*t, *s);
            }
            if self.macs.iter().map(shape).collect::<Vec<_>>() == before {
                return;
            }
        }
        panic!(
            "{}: no fixed point: {:?}",
            self.what,
            self.macs.iter().map(shape).collect::<Vec<_>>()
        );
    }

    // The user's operations.

    fn mv(&mut self, m: usize, x: u8, to: u8) {
        let now = self.now();
        if x == O {
            edit::move_group(&mut self.macs[m], id(x), id(to), Position::End, now).unwrap();
        } else {
            edit::move_entries(&mut self.macs[m], &[id(x)], id(to), now).unwrap();
        }
        self.store(m);
    }

    fn edit(&mut self, m: usize, x: u8, password: &str) {
        let now = self.now();
        edit::edit_entry(&mut self.macs[m], id(x), now, |d| {
            with_password(d, password)
        })
        .unwrap();
        self.store(m);
    }

    fn del(&mut self, m: usize, x: u8) {
        let now = self.now();
        let v = &mut self.macs[m];
        v.meta.recycle_bin_enabled = false;
        if x == O {
            recycle::delete_group(v, id(x), now).unwrap();
        } else {
            recycle::delete_entries(v, &[id(x)], now, |_, _| References::Delete).unwrap();
        }
        v.meta.recycle_bin_enabled = true;
        self.store(m);
    }

    fn bin(&mut self, m: usize, x: u8) {
        let now = self.now();
        let v = &mut self.macs[m];
        if x == O {
            recycle::delete_group(v, id(x), now).unwrap();
        } else {
            recycle::delete_entries(v, &[id(x)], now, |_, _| References::Delete).unwrap();
        }
        self.store(m);
    }

    fn empty(&mut self, m: usize) {
        let now = self.now();
        recycle::empty_bin(&mut self.macs[m], now).unwrap();
        self.store(m);
    }

    fn restore(&mut self, m: usize, x: u8) {
        let now = self.now();
        recycle::restore_entries(&mut self.macs[m], &[id(x)], now).unwrap();
        self.store(m);
    }

    /// The Restore button on the history item `item` of entry `x`.
    fn restore_version(&mut self, m: usize, x: u8, item: usize) {
        let now = self.now();
        let v = &mut self.macs[m];
        let old = find(v, x).unwrap().history[item].duplicate(false);
        edit::edit_entry(v, id(x), now, |d| history::restore_into(d, &old)).unwrap();
        self.store(m);
    }

    // Containers: each is a real file under the share password.

    fn write_container(&mut self, share: u8, c: &Vault) {
        let path = self.dir.join(format!("share-{share:x}.larsalvault"));
        let mut c = c.duplicate();
        c.encryption.kdf = Kdf::AesKdf { rounds: 1 };
        let password = SecretString::new(PASSWORD.to_owned());
        container::write_file(&path, &c, &password, &mut host(), &Limits::DEFAULT, &[]).unwrap();
        self.files.insert(share, path);
    }

    fn read_container(&self, share: u8) -> Vault {
        let password = SecretString::new(PASSWORD.to_owned());
        container::open_file(
            &self.files[&share],
            &password,
            &mut host(),
            &Limits::DEFAULT,
        )
        .unwrap()
        .vault
    }

    /// A member's hand-made container on Mac `m`'s share: `plants`, and `list` as its
    /// deleted list. Mac `m` imports it.
    fn plant(&mut self, m: usize, share: u8, plants: &[Plant], list: &[(u8, i64)]) {
        let now = self.now();
        let c = hand_made(plants, list);
        self.write_container(share, &c);
        self.import(m, share, now);
    }

    fn import(&mut self, m: usize, share: u8, now: Time) {
        let c = self.read_container(share);
        run::merge_into(&mut self.macs[m], id(share), &c, now).expect("import");
        self.store(m);
    }

    /// Mac `m` exports the share to its file.
    fn export(&mut self, m: usize, share: u8) {
        let now = at(self.clock);
        let c = container::build(id(share), true, &self.macs[m], now).unwrap();
        assert!(!origin::held(&c), "{}: the export holds a key", self.what);
        self.write_container(share, &c);
    }

    /// Mac `m` imports the share's file.
    fn take(&mut self, m: usize, share: u8) {
        let now = self.now();
        self.import(m, share, now);
    }

    /// A member changes the file.
    fn member(&mut self, share: u8, f: impl FnOnce(&mut Vault, Time)) {
        let now = self.now();
        let mut c = self.read_container(share);
        c.meta.recycle_bin_enabled = false;
        f(&mut c, now);
        self.write_container(share, &c);
    }

    fn member_edit(&mut self, share: u8, x: u8, password: &str) {
        self.member(share, |c, now| {
            edit::edit_entry(c, id(x), now, |d| with_password(d, password)).unwrap();
        });
    }

    fn member_move(&mut self, share: u8, x: u8, to: u8) {
        self.member(share, |c, now| {
            edit::move_entries(c, &[id(x)], id(to), now).unwrap();
        });
    }

    fn member_delete(&mut self, share: u8, x: u8) {
        self.member(share, |c, now| {
            recycle::delete_entries(c, &[id(x)], now, |_, _| References::Delete).unwrap();
        });
    }

    // What the flows end with.

    fn in_all(&self, x: u8, group: u8) {
        for (m, v) in self.macs.iter().enumerate() {
            assert_eq!(
                parent(v, x),
                Some(id(group)),
                "{}: {x:x} on Mac {m}: {}",
                self.what,
                show(v)
            );
        }
    }

    fn gone_all(&self, x: u8) {
        for (m, v) in self.macs.iter().enumerate() {
            assert_eq!(
                parent(v, x),
                None,
                "{}: {x:x} on Mac {m}: {}",
                self.what,
                show(v)
            );
        }
    }

    fn value_all(&self, x: u8, password: &str) {
        for (m, v) in self.macs.iter().enumerate() {
            assert_eq!(
                find(v, x)
                    .map(|e| e.value("Password").to_owned())
                    .as_deref(),
                Some(password),
                "{}: {x:x} on Mac {m}: {}",
                self.what,
                show(v)
            );
        }
    }

    fn exports_nothing(&self, share: u8) {
        for (m, v) in self.macs.iter().enumerate() {
            let c = container::build(id(share), true, v, at(self.clock)).unwrap();
            assert_eq!(
                c.root.all_entries().count(),
                0,
                "{}: Mac {m} exports: {}",
                self.what,
                show(v)
            );
        }
    }

    fn exports_value(&self, share: u8, password: &str) -> bool {
        self.macs.iter().all(|v| holds(v, share, password))
    }

    fn exported_by_none(&self, share: u8, password: &str) {
        for (m, v) in self.macs.iter().enumerate() {
            assert!(
                !holds(v, share, password),
                "{}: Mac {m}: {}",
                self.what,
                show(v)
            );
        }
    }
}

fn holds(v: &Vault, share: u8, password: &str) -> bool {
    container::build(id(share), true, v, T0).is_ok_and(|c| {
        c.root.all_entries().any(|e| {
            e.value("Password") == password
                || e.history.iter().any(|h| h.value("Password") == password)
        })
    })
}

fn hand_made(plants: &[Plant], list: &[(u8, i64)]) -> Vault {
    let mut c = Vault::new(Group::new(id(0x66), "Share".into(), T0), T0);
    c.meta.recycle_bin_enabled = false;
    c.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    for p in plants.iter().filter(|p| p.id == O) {
        let mut g = Group::new(id(O), "planted".into(), T0);
        g.times.last_modification = at(p.time);
        g.times.location_changed = at(p.time);
        c.root.groups.push(g);
    }
    for p in plants.iter().filter(|p| p.id != O) {
        let mut e = entry(p.id, PLANTED, at(p.time), at(p.time));
        if p.history {
            let mut h = entry(p.id, OLD, at(0), at(0));
            h.history.clear();
            e.history.push(h);
        }
        let home = match p.parent {
            Some(n) => gm(&mut c.root, n).unwrap(),
            None => &mut c.root,
        };
        home.entries.push(e);
    }
    c.deleted_objects = list
        .iter()
        .map(|(n, t)| DeletedObject {
            uuid: id(*n),
            deleted_at: at(*t),
            unknown: Vec::new(),
        })
        .collect();
    c
}

fn find(v: &Vault, x: u8) -> Option<&Entry> {
    v.root.all_entries().find(|e| e.uuid == id(x))
}

/// The group holding entry `x`, or the parent of group `x`.
fn parent(v: &Vault, x: u8) -> Option<Uuid> {
    let held = |g: &&Group| {
        g.entries.iter().any(|e| e.uuid == id(x)) || g.groups.iter().any(|c| c.uuid == id(x))
    };
    v.root.subtree().into_iter().find(held).map(|g| g.uuid)
}

/// What a fixed point compares, values included: the rule's items and every object.
fn show(v: &Vault) -> String {
    let mut out = Vec::new();
    for g in v.root.subtree() {
        for c in &g.groups {
            out.push(format!(
                "group {} in {} prev {:?} loc {} mod {} {:?} mark {:?}",
                c.name,
                g.name,
                c.previous_parent.map(|p| p.0[0]),
                c.times.location_changed.0 - T0.0,
                c.times.last_modification.0 - T0.0,
                origin::stamp_of(&c.custom_data).map(|s| (s.group.0[0], s.at.0 - T0.0)),
                origin::mark_of(&c.custom_data).map(|m| m.0[0]),
            ));
        }
        for e in &g.entries {
            out.push(format!(
                "entry {:x} in {} prev {:?} loc {} mod {} value {} history {:?} {:?} mark {:?}",
                e.uuid.0[0],
                g.name,
                e.previous_parent.map(|p| p.0[0]),
                e.times.location_changed.0 - T0.0,
                e.times.last_modification.0 - T0.0,
                e.value("Password"),
                e.history
                    .iter()
                    .map(|h| h.value("Password").to_owned())
                    .collect::<Vec<_>>(),
                origin::stamp_of(&e.custom_data).map(|s| (s.group.0[0], s.at.0 - T0.0)),
                origin::mark_of(&e.custom_data).map(|m| m.0[0]),
            ));
        }
    }
    out.sort();
    format!(
        "{out:?} records {:?} rows {:?}",
        v.deleted_objects
            .iter()
            .map(|d| d.uuid.0[0])
            .collect::<Vec<_>>(),
        origin::read_rows(&v.meta.custom_data)
            .iter()
            .map(|((i, g), t)| (i.0[0], g.0[0], t.0 - T0.0))
            .collect::<Vec<_>>(),
    )
}

/// Every merge kind, both merge orders.
fn all(macs: usize, shares: Shares, seed: Seed, flow: impl Fn(&mut Lab)) {
    for kind in KINDS {
        for first in [A, B] {
            flow(&mut Lab::new(kind, first, macs, shares, seed));
        }
    }
}

fn one(macs: usize, seed: Seed, flow: impl Fn(&mut Lab)) {
    all(macs, Shares::One, seed, flow);
}

fn e_at(time: i64) -> Plant {
    Plant {
        id: E,
        parent: None,
        time,
        history: false,
    }
}

/// O{F} planted, as the flows G1, G4, G5, S4 say.
fn o_f(time: i64) -> [Plant; 2] {
    [
        Plant {
            id: O,
            parent: None,
            time,
            history: false,
        },
        Plant {
            id: F,
            parent: Some(O),
            time,
            history: false,
        },
    ]
}

impl Lab {
    /// The first export a flow with files starts from.
    fn with_file(&mut self) {
        self.export(A, T);
    }
    fn plant_now(&mut self, m: usize, share: u8) {
        let t = self.clock + 1;
        self.plant(m, share, &[e_at(t)], &[]);
    }
    fn plant_older(&mut self, m: usize, share: u8) {
        self.plant(m, share, &[e_at(0)], &[]);
    }
    fn plant_far(&mut self, m: usize, share: u8) {
        self.plant(m, share, &[e_at(FAR)], &[]);
    }
    fn list_now(&mut self, m: usize, share: u8, x: u8) {
        let t = self.clock + 1;
        self.plant(m, share, &[], &[(x, t)]);
    }
}

// ---------------------------------------------------------------------------
// Honest flows.

#[test]
fn h1_a_move_in_reaches_all_and_goes_out() {
    one(2, Seed::Out, |l| {
        l.mv(A, E, T);
        l.settle();
        l.in_all(E, T);
        assert!(l.exports_value(T, SEED), "{}", l.what);
    });
}

#[test]
fn h1b_a_move_in_beats_an_older_private_edit() {
    one(2, Seed::Out, |l| {
        l.edit(B, E, PRIVATE);
        l.mv(A, E, T);
        l.settle();
        l.in_all(E, T);
        assert!(l.exports_value(T, PRIVATE), "{}", l.what);
    });
}

#[test]
fn h2_a_move_out_sticks() {
    one(2, Seed::In, |l| {
        l.mv(A, E, P);
        l.settle();
        l.in_all(E, P);
        l.exports_nothing(T);
    });
}

#[test]
fn h2b_a_move_out_beats_a_later_edit_inside_on_the_other_mac() {
    one(2, Seed::In, |l| {
        l.mv(A, E, P);
        l.edit(B, E, "late-demo");
        l.settle();
        l.in_all(E, P);
        l.value_all(E, SEED);
        l.exports_nothing(T);
    });
}

#[test]
fn h2c_a_move_out_beats_a_later_move_inside_on_the_other_mac() {
    one(2, Seed::In, |l| {
        l.mv(A, E, P);
        l.mv(B, E, S);
        l.settle();
        l.in_all(E, P);
        l.exports_nothing(T);
    });
}

#[test]
fn h3_a_members_edit_reaches_all() {
    one(2, Seed::In, |l| {
        l.with_file();
        l.member_edit(T, E, MEMBER);
        l.take(A, T);
        l.settle();
        l.in_all(E, T);
        l.value_all(E, MEMBER);
    });
}

#[test]
fn h3b_a_members_move_inside_reaches_all() {
    one(2, Seed::In, |l| {
        l.with_file();
        l.member_move(T, E, S);
        l.take(A, T);
        l.settle();
        l.in_all(E, S);
    });
}

#[test]
fn h4_an_honest_deletion_reaches_the_other_mac() {
    one(2, Seed::In, |l| {
        l.with_file();
        l.member_delete(T, E);
        l.take(A, T);
        l.settle();
        l.gone_all(E);
    });
}

#[test]
fn h4b_an_honest_deletion_with_a_newcomer_importing() {
    one(2, Seed::InB, |l| {
        l.list_now(A, T, E);
        l.settle();
        l.gone_all(E);
    });
}

#[test]
fn h5_a_users_own_deletion_sticks() {
    one(2, Seed::Out, |l| {
        l.del(A, E);
        l.settle();
        l.gone_all(E);
    });
}

#[test]
fn h5b_a_users_own_deletion_inside_sticks() {
    one(2, Seed::In, |l| {
        l.del(A, E);
        l.settle();
        l.gone_all(E);
    });
}

#[test]
fn h5c_bin_then_empty_sticks() {
    one(2, Seed::Out, |l| {
        l.bin(A, E);
        l.empty(A);
        l.settle();
        l.gone_all(E);
    });
}

#[test]
fn h5d_cr2_01_a_users_deletion_beside_a_shares_record_sticks() {
    one(2, Seed::OnB, |l| {
        l.list_now(A, T, E);
        l.merge(B, A);
        l.merge(A, B);
        l.del(B, E);
        l.settle();
        l.gone_all(E);
    });
}

#[test]
fn h9_a_move_out_then_a_move_back_in() {
    one(2, Seed::In, |l| {
        l.mv(B, E, P);
        l.merge(A, B);
        l.merge(B, A);
        l.mv(A, E, T);
        l.settle();
        l.in_all(E, T);
    });
}

#[test]
fn h10_a_later_container_adds_after_a_deletion() {
    one(2, Seed::In, |l| {
        l.del(A, E);
        l.merge(B, A);
        l.plant_now(A, T);
        l.settle();
        l.in_all(E, T);
        l.value_all(E, PLANTED);
    });
}

// ---------------------------------------------------------------------------
// Planted copies: the outside copy keeps its place and value on every Mac.

fn outside_kept(l: &Lab) {
    l.in_all(E, P);
    l.value_all(E, SEED);
    l.exported_by_none(T, SEED);
}

#[test]
fn h6_f2_deleting_a_planted_copy_with_the_bin_off() {
    one(2, Seed::OnB, |l| {
        l.plant_older(A, T);
        l.del(A, E);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h6b_f2_deleting_a_newer_planted_copy() {
    one(2, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.del(A, E);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h6c_f2_a_planted_copy_to_the_bin() {
    one(2, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.bin(A, E);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h6d_f2_a_planted_copy_to_the_bin_and_emptied() {
    one(2, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.bin(A, E);
        l.empty(A);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h7_cr2_04_restoring_a_history_version_of_a_planted_copy() {
    one(2, Seed::OnB, |l| {
        l.plant(
            A,
            T,
            &[Plant {
                id: E,
                parent: None,
                time: FAR,
                history: true,
            }],
            &[],
        );
        l.restore_version(A, E, 0);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h7b_cr2_05_a_planted_copy_to_the_bin_and_back() {
    one(2, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.bin(A, E);
        l.restore(A, E);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h8_c1_02_a_planted_copy_one_round() {
    one(2, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h8b_c1_01_planted_then_listed_two_rounds() {
    one(2, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.plant(A, T, &[], &[(E, FAR)]);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h11_a9_a_planted_copy_moved_out_does_not_overwrite() {
    one(2, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.mv(A, E, P);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h11b_a9_out_and_back_does_not_pull_the_outside_copy_in() {
    one(2, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.mv(A, E, P);
        l.mv(A, E, T);
        l.settle();
        outside_kept(l);
    });
}

#[test]
fn h12_a_brought_entry_moved_out_sticks() {
    one(2, Seed::InB, |l| {
        l.plant_now(A, T);
        l.merge(B, A);
        l.merge(A, B);
        l.mv(A, E, P);
        l.settle();
        l.in_all(E, P);
    });
}

#[test]
fn h12b_and_moved_back_in_sticks() {
    one(2, Seed::InB, |l| {
        l.plant_now(A, T);
        l.merge(B, A);
        l.merge(A, B);
        l.mv(A, E, P);
        l.merge(B, A);
        l.merge(A, B);
        l.mv(B, E, T);
        l.settle();
        l.in_all(E, T);
    });
}

// ---------------------------------------------------------------------------
// Shares and members.

#[test]
fn h13_one_shares_list_does_not_reach_another_share_by_an_export() {
    all(2, Shares::Two, Seed::In, |l| {
        l.list_now(A, U, E);
        l.export(A, T);
        l.take(B, T);
        l.settle();
        l.in_all(E, T);
    });
}

#[test]
fn h13b_the_same_when_the_exporting_mac_holds_no_copy() {
    all(2, Shares::Two, Seed::InB, |l| {
        l.list_now(A, U, E);
        l.export(A, T);
        l.take(B, T);
        l.settle();
        l.in_all(E, T);
        l.value_all(E, SEED);
    });
}

#[test]
fn f1_a_members_move_and_a_move_out_with_a_private_edit() {
    one(2, Seed::In, |l| {
        l.with_file();
        l.mv(B, E, P);
        l.edit(B, E, PRIVATE);
        l.member_move(T, E, S);
        l.take(A, T);
        l.settle();
        l.in_all(E, P);
        l.value_all(E, PRIVATE);
        l.exports_nothing(T);
    });
}

#[test]
fn f1b_a_members_edit_and_a_move_out_with_a_private_edit() {
    one(2, Seed::In, |l| {
        l.with_file();
        l.mv(B, E, P);
        l.edit(B, E, PRIVATE);
        l.member_edit(T, E, MEMBER);
        l.take(A, T);
        l.settle();
        l.in_all(E, P);
        l.value_all(E, PRIVATE);
        l.exports_nothing(T);
    });
}

// ---------------------------------------------------------------------------
// Groups.

fn o_f_outside(l: &Lab) {
    l.in_all(O, P);
    l.in_all(F, O);
    l.exports_nothing(T);
}

#[test]
fn g1_cr2_02_a_group_moved_out_with_a_private_edit() {
    one(2, Seed::GIn, |l| {
        l.mv(B, O, P);
        l.edit(B, F, PRIVATE);
        l.plant(A, T, &o_f(FAR), &[]);
        l.settle();
        o_f_outside(l);
        l.value_all(F, PRIVATE);
    });
}

#[test]
fn g2_a_group_move_in_reaches_all() {
    one(2, Seed::GOut, |l| {
        l.mv(A, O, T);
        l.settle();
        l.in_all(O, T);
        l.in_all(F, O);
        assert!(l.exports_value(T, SEED), "{}", l.what);
    });
}

#[test]
fn g3_f4_a_dormant_record_then_a_group_move_in() {
    one(2, Seed::GOnB, |l| {
        l.list_now(A, T, F);
        l.merge(B, A);
        l.merge(A, B);
        l.mv(B, O, T);
        l.settle();
        l.in_all(O, T);
        l.in_all(F, O);
    });
}

#[test]
fn g4_a_planted_group_on_a_held_group_one_round() {
    one(2, Seed::GOnB, |l| {
        l.plant(A, T, &o_f(FAR), &[]);
        l.settle();
        o_f_outside(l);
        l.value_all(F, SEED);
    });
}

#[test]
fn g5_a_group_planted_then_listed() {
    one(2, Seed::GOnB, |l| {
        l.plant(A, T, &o_f(FAR), &[]);
        l.plant(A, T, &[], &[(F, FAR), (O, FAR)]);
        l.settle();
        o_f_outside(l);
        l.value_all(F, SEED);
    });
}

#[test]
fn g6_a_group_in_and_a_later_private_edit_keeps_that_entry_out() {
    one(2, Seed::GOut, |l| {
        l.mv(A, O, T);
        l.edit(B, F, PRIVATE);
        l.settle();
        l.in_all(O, T);
        l.in_all(F, P);
        l.value_all(F, PRIVATE);
        l.exported_by_none(T, PRIVATE);
    });
}

#[test]
fn g7_a_group_out_reaches_all_with_a_members_edit() {
    one(2, Seed::GIn, |l| {
        l.with_file();
        l.mv(A, O, P);
        l.member_edit(T, F, MEMBER);
        l.take(B, T);
        l.settle();
        o_f_outside(l);
    });
}

// ---------------------------------------------------------------------------
// Found by the search: each one broke an earlier form of the rule.

#[test]
fn s1_own_deletion_a_container_adds_a_stale_mac_holds_the_old_copy() {
    one(2, Seed::Out, |l| {
        l.del(A, E);
        l.plant_now(A, T);
        l.settle();
        l.in_all(E, T);
        l.value_all(E, PLANTED);
        l.exported_by_none(T, SEED);
    });
}

#[test]
fn s2_three_copies_a_value_typed_on_a_planted_copy_moved_out() {
    one(3, Seed::OnB, |l| {
        l.merge(A, B);
        l.mv(B, E, T);
        l.plant_older(C, T);
        l.mv(C, E, P);
        l.edit(C, E, PRIVATE);
        l.settle();
        l.in_all(E, P);
        l.exports_nothing(T);
        if l.first == A {
            // The model's merge order, the only one its named flow checks.
            l.value_all(E, PRIVATE);
        } else {
            // Another order meets the unbrought copy last: it wins whole, and the value
            // typed on the brought copy stays as a history item (limit 10). Still one
            // value on all, nothing exported.
            l.value_all(E, SEED);
            for v in &l.macs {
                let e = find(v, E).unwrap();
                let kept = e.history.iter().any(|h| h.value("Password") == PRIVATE);
                assert!(kept, "{}: {}", l.what, show(v));
            }
        }
    });
}

#[test]
fn s3_own_deletion_a_members_edit_adds_the_user_moves_it_out() {
    one(2, Seed::Out, |l| {
        l.with_file();
        l.mv(A, E, T);
        l.export(A, T);
        l.del(A, E);
        l.member_edit(T, E, MEMBER);
        l.take(A, T);
        l.mv(A, E, P);
        l.settle();
        l.in_all(E, P);
        l.value_all(E, MEMBER);
    });
}

#[test]
fn s4_group_in_entry_deleted_a_container_adds_another_mac_edits() {
    one(2, Seed::GOut, |l| {
        l.mv(A, O, T);
        l.del(A, F);
        let t = l.clock + 1;
        l.plant(A, T, &o_f(t), &[]);
        l.edit(B, F, PRIVATE);
        l.settle();
        l.in_all(O, T);
        l.in_all(F, P);
        l.value_all(F, PRIVATE);
        l.exported_by_none(T, PRIVATE);
    });
}

#[test]
fn s5_group_in_and_the_entry_binned_later_on_the_other_mac() {
    one(2, Seed::GOut, |l| {
        l.mv(A, O, T);
        l.bin(B, F);
        l.settle();
        l.in_all(O, T);
        l.in_all(F, BIN);
        for v in &l.macs {
            assert_eq!(
                find(v, F).unwrap().previous_parent,
                Some(id(P)),
                "{}",
                l.what
            );
        }
    });
}

#[test]
fn s6_group_binned_entry_moved_in_edited_group_moved_in() {
    one(2, Seed::GOut, |l| {
        l.bin(A, O);
        l.mv(B, F, T);
        l.edit(A, F, PRIVATE);
        l.mv(B, O, T);
        l.settle();
        l.in_all(O, T);
        l.in_all(F, P);
    });
}

// ---------------------------------------------------------------------------
// Limits pinned (INT-08.32, the fourteen limits).

/// L1, limit 1: E in T on A only; A exports; A moves E to P; B imports; B moves E
/// into the other share. The move in on a copy a container brought loses. E in P on
/// all.
#[test]
fn l1_limit_1_a_move_in_on_a_brought_copy_loses_to_another_share() {
    all(2, Shares::Two, Seed::InA, |l| {
        l.export(A, T);
        l.mv(A, E, P);
        l.take(B, T);
        l.mv(B, E, U);
        l.settle();
        l.in_all(E, P);
    });
}

/// L1, limit 1: the same when B moves it out and back to T.
#[test]
fn l1_limit_1_a_move_in_on_a_brought_copy_loses_out_and_back() {
    one(2, Seed::InA, |l| {
        l.export(A, T);
        l.mv(A, E, P);
        l.take(B, T);
        l.mv(B, E, P);
        l.mv(B, E, T);
        l.settle();
        l.in_all(E, P);
    });
}

/// L2, limit 2: only A knows T; B's move in carries no stamp and is lost at the next
/// merge. Moving again after the merge counts.
#[test]
fn l2_limit_2_a_move_in_before_the_share_is_heard_of_is_lost() {
    all(2, Shares::OnlyA, Seed::Out, |l| {
        let moved_on_b = {
            l.mv(B, E, T);
            find(&l.macs[B], E).map(|e| origin::stamp_of(&e.custom_data))
        };
        assert_eq!(moved_on_b, Some(None), "{}: no stamp", l.what);
        l.settle();
        l.in_all(E, P);
        l.mv(B, E, T);
        l.settle();
        l.in_all(E, T);
    });
}

/// L3, limit 4: A moves E to T; B imports a list naming E now, before that move
/// reached B. Gone on all or in P on all, by merge order; never exported private.
#[test]
fn l3_limit_4_a_members_deletion_newer_than_a_move_in() {
    one(2, Seed::Out, |l| {
        l.mv(A, E, T);
        l.list_now(B, T, E);
        l.settle();
        let places: Vec<Option<Uuid>> = l.macs.iter().map(|v| parent(v, E)).collect();
        assert_eq!(places[0], places[1], "{}", l.what);
        assert!(
            places[0].is_none() || places[0] == Some(id(P)) || places[0] == Some(id(T)),
            "{}: {places:?}",
            l.what
        );
        if places[0] == Some(id(P)) {
            l.exported_by_none(T, SEED);
        }
    });
}

/// L4, limit 11: A imports a list naming E; another app saves A's file, dropping
/// stamps, markers and lists, and keeping the file's plain records. B's E stays.
#[test]
fn l4_limit_11_another_apps_save_drops_the_rule_and_erases_nothing() {
    one(2, Seed::OnB, |l| {
        l.list_now(A, T, E);
        origin::strip(&mut l.macs[A]);
        l.store(A);
        assert!(!origin::held(&l.macs[A]), "{}", l.what);
        l.settle();
        l.in_all(E, P);
        l.value_all(E, SEED);
    });
}

/// L5, limit 9: E on A only; A moves E to T; A exports; A moves E to P; B imports T;
/// B deletes; A imports T. A's E stays in P.
#[test]
fn l5_limit_9_deleting_an_unstamped_copy_removes_only_share_copies() {
    one(2, Seed::OutA, |l| {
        l.mv(A, E, T);
        l.export(A, T);
        l.mv(A, E, P);
        l.take(B, T);
        l.del(B, E);
        l.export(B, T);
        l.take(A, T);
        l.settle();
        l.in_all(E, P);
    });
}

/// Limit 3: a later edit on another Mac beats a move in; the user moves it again.
#[test]
fn l_limit_3_a_later_edit_undoes_a_move_in_and_a_new_move_counts() {
    one(2, Seed::Out, |l| {
        l.mv(A, E, T);
        l.edit(B, E, PRIVATE);
        l.settle();
        l.in_all(E, P);
        l.value_all(E, PRIVATE);
        l.mv(B, E, T);
        l.settle();
        l.in_all(E, T);
    });
}

/// Limit 5: after the user deletes an entry a container can add a copy in the share.
/// Only its value is there and the plain record stays, so a stale Mac stops.
#[test]
fn l_limit_5_a_container_adds_after_a_deletion_and_the_record_stays() {
    one(2, Seed::Out, |l| {
        l.del(A, E);
        l.plant_now(A, T);
        l.settle();
        l.in_all(E, T);
        for v in &l.macs {
            assert!(
                v.deleted_objects.iter().any(|d| d.uuid == id(E)),
                "{}: {}",
                l.what,
                show(v)
            );
            assert!(!holds(v, T, SEED), "{}", l.what);
        }
    });
}

/// Limit 6: two copies inside with one time keep their own value until the next edit.
#[test]
fn l_limit_6_two_copies_with_one_time_keep_their_own_value() {
    one(2, Seed::In, |l| {
        edit::edit_entry(&mut l.macs[A], id(E), at(5), |d| with_password(d, "a-demo")).unwrap();
        edit::edit_entry(&mut l.macs[B], id(E), at(5), |d| with_password(d, "b-demo")).unwrap();
        l.store(A);
        l.store(B);
        l.settle();
        l.in_all(E, T);
        let values: Vec<String> = l
            .macs
            .iter()
            .map(|v| find(v, E).unwrap().value("Password").to_owned())
            .collect();
        assert_eq!(values, ["a-demo", "b-demo"], "{}", l.what);
    });
}

/// Limit 7: moving a copy out takes its value, a member's newer value included, and
/// it overwrites an outside copy on another Mac.
#[test]
fn l_limit_7_moving_a_copy_out_takes_its_value() {
    one(2, Seed::Out, |l| {
        l.export(A, T);
        l.mv(A, E, T);
        l.export(A, T);
        l.member_edit(T, E, MEMBER);
        l.take(A, T);
        l.mv(A, E, P);
        l.settle();
        l.in_all(E, P);
        l.value_all(E, MEMBER);
    });
}

/// Limit 8: a member of T can place a value in a nested share, and its next export
/// carries it. Never a private value.
#[test]
fn l_limit_8_values_between_nested_shares() {
    for kind in KINDS {
        let mut l = Lab::new(kind, A, 2, Shares::One, Seed::In);
        let item = gm(&mut l.macs[A].root, T).unwrap().custom_data.items[0].clone();
        for m in [A, B] {
            gm(&mut l.macs[m].root, S)
                .unwrap()
                .custom_data
                .items
                .push(item.clone());
            l.store(m);
        }
        l.with_file();
        l.member(T, |c, now| {
            let mut e = entry(0x52, MEMBER, now, now);
            e.previous_parent = None;
            gm(&mut c.root, S).unwrap().entries.push(e);
        });
        l.take(A, T);
        l.settle();
        assert!(l.exports_value(S, MEMBER), "{}", l.what);
        l.exported_by_none(S, SEED);
    }
}

/// Limit 10: the losing copy's value stays as one history item on the winner, tagged
/// as Larsal's own; it is not exported while the winner is outside, nor after the user
/// moves it into a share.
#[test]
fn l_limit_10_a_losing_value_stays_as_one_history_item() {
    one(2, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.settle();
        outside_kept(l);
        for v in &l.macs {
            let e = find(v, E).unwrap();
            let kept: Vec<_> = e
                .history
                .iter()
                .filter(|h| h.value("Password") == PLANTED)
                .collect();
            assert_eq!(kept.len(), 1, "{}: {}", l.what, show(v));
            // Round 4 (C1-03, C1-04): the kept value is Larsal's private item.
            assert!(origin::private_item(kept[0]), "{}: {}", l.what, show(v));
            assert!(!holds(v, T, PLANTED), "{}", l.what);
        }
        l.mv(A, E, T);
        l.settle();
        // Named as changed in round 4: was `assert!(l.exports_value(T, PLANTED))`. An
        // export strips every tagged item, so the value stays on the Macs only.
        l.exported_by_none(T, PLANTED);
        for v in &l.macs {
            assert!(
                find(v, E)
                    .unwrap()
                    .history
                    .iter()
                    .any(|h| h.value("Password") == PLANTED && origin::private_item(h)),
                "{}: kept on the Mac",
                l.what
            );
        }
    });
}

/// Limit 12: no upgrade step. An object already inside has no stamp, so a stale
/// outside copy wins; a record an older import wrote counts as plain.
#[test]
fn l_limit_12_no_upgrade_step_a_stale_outside_copy_wins() {
    one(2, Seed::In, |l| {
        // Mac B holds E outside as it did before the object moved in.
        let e = {
            let t = gm(&mut l.macs[B].root, T).unwrap();
            t.entries.remove(0)
        };
        gm(&mut l.macs[B].root, P).unwrap().entries.push(e);
        l.store(B);
        l.settle();
        l.in_all(E, P);
    });
}

/// Limit 13: rows past the cap are dropped, the oldest first: a member's deletion may
/// not reach. Nothing else changes.
#[test]
fn l_limit_13_rows_past_the_cap_are_dropped_oldest_first() {
    let mut l = Lab::new(Kind::ChangeOnDisk, A, 1, Shares::One, Seed::In);
    let mut rows = origin::Rows::new();
    rows.insert((id(E), id(T)), at(0));
    for n in 0..origin::ROW_CAP {
        let mut b = [7u8; 16];
        b[..8].copy_from_slice(&(n as u64).to_le_bytes());
        rows.insert((Uuid(b), id(T)), at(1));
    }
    origin::write_rows(&mut l.macs[A].meta.custom_data, &rows);
    let kept = origin::read_rows(&l.macs[A].meta.custom_data);
    assert_eq!(kept.len(), origin::ROW_CAP);
    assert!(!kept.contains_key(&(id(E), id(T))), "the oldest row went");
}

/// Limit 14, clock skew: by reasoning, not by search. A Mac whose clock runs ahead
/// dates its stamp past a later private edit elsewhere, and the inside copy wins.
#[test]
fn l_limit_14_a_clock_ahead_beats_a_later_edit() {
    one(2, Seed::Out, |l| {
        edit::move_entries(&mut l.macs[A], &[id(E)], id(T), at(1_000)).unwrap();
        l.store(A);
        l.edit(B, E, PRIVATE);
        l.settle();
        l.in_all(E, T);
    });
}

// ---------------------------------------------------------------------------
// Calibration: expect the outside copy kept.

#[test]
fn calibration_cr2_02_held_a_move_out_with_an_edit_and_a_far_container() {
    one(2, Seed::In, |l| {
        l.mv(A, E, P);
        l.edit(A, E, PRIVATE);
        l.plant_far(B, T);
        l.settle();
        l.in_all(E, P);
        l.value_all(E, PRIVATE);
        l.exports_nothing(T);
    });
}

#[test]
fn calibration_cr2_03_two_shares_far_and_a_third_copy() {
    all(3, Shares::Two, Seed::OnB, |l| {
        l.plant_far(A, T);
        l.plant_far(C, U);
        l.settle();
        l.in_all(E, P);
        l.value_all(E, SEED);
        l.exported_by_none(T, SEED);
        l.exported_by_none(U, SEED);
    });
}

// ---------------------------------------------------------------------------
// No share: today's merge, and none of the rule's items.

#[test]
fn no_share_a_vault_with_no_share_holds_none_of_the_rules_items() {
    for kind in KINDS {
        let (mut a, mut b) = (world(Shares::OnlyA, B), world(Shares::OnlyA, B));
        put_seed(&mut a, Seed::Out, A);
        put_seed(&mut b, Seed::Out, B);
        edit::move_entries(&mut a, &[id(E)], id(U), at(2)).unwrap();
        recycle::delete_entries(&mut b, &[id(E)], at(3), |_, _| References::Delete).unwrap();
        let o = Options::new(kind);
        let from = a.duplicate();
        merge(&mut b, &from, &o, at(4)).unwrap();
        let from = b.duplicate();
        merge(&mut a, &from, &o, at(4)).unwrap();
        assert!(!origin::held(&a) && !origin::held(&b), "{kind:?}");
    }
}

// ---------------------------------------------------------------------------
// Sensitive Checker 2, round 3: planting by a key the writer normalises.
// FMT-12.24 reads U+007F to U+009F; FMT-12.25 removes them on write.
// ---------------------------------------------------------------------------

fn hex(n: u8) -> String {
    format!("{n:02x}").repeat(16)
}

fn near_item(key: &str, value: String) -> CustomDataItem {
    CustomDataItem {
        key: key.to_owned(),
        value: SecretString::new(value),
        last_modified: None,
        unknown: Vec::new(),
    }
}

/// What a hostile writer sends: the document of `c`, with text swapped. The reader
/// is the one `larsal_format::open` runs (`read_with`), only the file layers around
/// the document are not there.
fn hostile(c: &Vault, swap: &[(&str, &str)]) -> Vault {
    let w = larsal_format::document::write::write_plain(c).unwrap();
    let mut xml = String::from_utf8(w.xml().to_vec()).unwrap();
    for (a, b) in swap {
        assert!(xml.contains(a), "{a} is in the document");
        xml = xml.replace(a, b);
    }
    let limits = Limits::DEFAULT;
    let o = larsal_format::document::read::Options {
        open_time: T0,
        limits: &limits,
        v3_header: None,
    };
    larsal_format::document::read::read_plain(xml.as_bytes(), &o)
        .unwrap()
        .vault
}

/// The shape of CR2-02 and F1b on the file. Mac B moved E out and typed a private
/// value. A member edits E in the file and adds an item whose key is the stamp key
/// plus U+007F, with the id of T (the container root id tells it) and a far time.
/// The import keeps it, since it is not the stamp key. The save of A writes the key
/// without U+007F. From the next open it is a stamp.
#[test]
fn c2r3_01_a_near_key_item_becomes_a_stamp_at_the_save_and_pulls_a_private_value_out() {
    one(2, Seed::In, |l| {
        l.with_file();
        l.mv(B, E, P);
        l.edit(B, E, PRIVATE);
        let now = l.now();
        let mut c = l.read_container(T);
        c.meta.recycle_bin_enabled = false;
        edit::edit_entry(&mut c, id(E), now, |d| with_password(d, MEMBER)).unwrap();
        let far = at(FAR).0;
        for e in c.root.entries.iter_mut().filter(|e| e.uuid == id(E)) {
            e.custom_data
                .items
                .push(near_item("near-demo-key", format!("{}:{far}", hex(T))));
        }
        let c = hostile(&c, &[("near-demo-key", "app.larsal.share.moved&#x7F;")]);
        let got = c.root.entries.iter().find(|e| e.uuid == id(E)).unwrap();
        assert_eq!(
            got.custom_data.items.last().unwrap().key,
            // Named as changed in round 4: the reader cleans a key (FMT-14.10), so the
            // near key reads as the stamp key, and held() sees it.
            "app.larsal.share.moved"
        );
        assert!(
            origin::stamp_of(&got.custom_data).is_some(),
            "read as a stamp"
        );
        assert!(origin::held(&c), "held sees it");
        run::merge_into(&mut l.macs[A], id(T), &c, now).unwrap();
        l.store(A);
        let s = origin::stamp_of(&find(&l.macs[A], E).unwrap().custom_data);
        eprintln!(
            "C2R3-01 {}: stamp on A after its save and open: {:?}",
            l.what,
            s.map(|s| (s.group.0[0], s.at.0 - T0.0))
        );
        l.settle();
        eprintln!(
            "C2R3-01 {}: Mac B place {:x?}, private value exported by T: {}",
            l.what,
            parent(&l.macs[B], E).map(|p| p.0[0]),
            holds(&l.macs[B], T, PRIVATE)
        );
        // What INT-08.32 promises: E in P, the private value current, nothing exported.
        l.in_all(E, P);
        l.value_all(E, PRIVATE);
        l.exports_nothing(T);
    });
}

/// The group form, G1 and CR2-02 group: O{F} in T; B moves O out and edits F; the
/// member sends near-key stamps on O and F.
#[test]
fn c2r3_03_the_group_form() {
    one(2, Seed::GIn, |l| {
        l.with_file();
        l.mv(B, O, P);
        l.edit(B, F, PRIVATE);
        let now = l.now();
        let mut c = l.read_container(T);
        c.meta.recycle_bin_enabled = false;
        edit::edit_entry(&mut c, id(F), now, |d| with_password(d, MEMBER)).unwrap();
        let far = at(FAR).0;
        let o = gm(&mut c.root, O).unwrap();
        o.custom_data
            .items
            .push(near_item("near-demo-key", format!("{}:{far}", hex(T))));
        o.times.last_modification = now;
        for e in o.entries.iter_mut() {
            e.custom_data
                .items
                .push(near_item("near-demo-key", format!("{}:{far}", hex(T))));
        }
        let c = hostile(&c, &[("near-demo-key", "app.larsal.share.moved&#x7F;")]);
        run::merge_into(&mut l.macs[A], id(T), &c, now).unwrap();
        l.store(A);
        l.settle();
        eprintln!(
            "C2R3-03 {}: O under {:x?} on B, F value {:?}, private exported {}",
            l.what,
            parent(&l.macs[B], O).map(|p| p.0[0]),
            find(&l.macs[B], F).map(|e| e.value("Password").to_owned()),
            holds(&l.macs[B], T, PRIVATE)
        );
        l.in_all(O, P);
        l.value_all(F, PRIVATE);
        l.exports_nothing(T);
    });
}

/// A near-key stamp with a far time on a copy the user deletes: the deletion does
/// not stick while the time is ahead. CR2-01 by another road. Seed: E in T on all.
#[test]
fn c2r3_04_a_near_key_stamp_makes_an_entry_undeletable() {
    one(2, Seed::In, |l| {
        l.with_file();
        let now = l.now();
        let mut c = l.read_container(T);
        c.meta.recycle_bin_enabled = false;
        edit::edit_entry(&mut c, id(E), now, |d| with_password(d, MEMBER)).unwrap();
        let far = at(FAR).0;
        for e in c.root.entries.iter_mut().filter(|e| e.uuid == id(E)) {
            e.custom_data
                .items
                .push(near_item("near-demo-key", format!("{}:{far}", hex(T))));
        }
        let c = hostile(&c, &[("near-demo-key", "app.larsal.share.moved&#x7F;")]);
        run::merge_into(&mut l.macs[A], id(T), &c, now).unwrap();
        l.store(A);
        l.settle();
        l.del(A, E);
        l.settle();
        eprintln!(
            "C2R3-04 {}: after the delete and settle, E on A: {:x?}",
            l.what,
            parent(&l.macs[A], E).map(|p| p.0[0])
        );
        l.gone_all(E);
    });
}

/// INT-08.33: a near-key share item on a group below the container root. The item
/// has the path and mode the member wants. After the save it is a real share item
/// on a planted group. Pre-existing on Main; R6 reads it as a known share.
#[test]
fn c2r3_05_a_near_key_share_item_becomes_a_nested_share_item() {
    one(2, Seed::In, |l| {
        l.with_file();
        let now = l.now();
        let mut c = l.read_container(T);
        c.meta.recycle_bin_enabled = false;
        let mut g = Group::new(id(0x70), "planted".into(), now);
        g.custom_data
            .items
            .push(near_item("near-demo-key", "AAAA".to_owned()));
        g.times.last_modification = now;
        c.root.groups.push(g);
        let key = core::str::from_utf8(edit::SHARED_KEY).unwrap();
        let near = format!("{key}&#x7F;");
        let c = hostile(&c, &[("near-demo-key", near.as_str())]);
        run::merge_into(&mut l.macs[A], id(T), &c, now).unwrap();
        let before = origin::known(&l.macs[A]).contains(&id(0x70));
        l.store(A);
        let after = origin::known(&l.macs[A]).contains(&id(0x70));
        eprintln!(
            "C2R3-05 {}: planted group a known share: before the save {before}, after {after}",
            l.what
        );
        assert!(!after, "a container's group is not a share");
    });
}

/// A near-key known list and near-key rows in the container vault custom data, naming
/// P as a share and E in P as gone. Does the import take vault custom data at all?
#[test]
fn c2r3_06_near_key_known_and_rows_in_the_vault_custom_data() {
    one(2, Seed::In, |l| {
        l.with_file();
        l.mv(B, E, P);
        l.settle();
        let now = l.now();
        let mut c = l.read_container(T);
        c.meta.recycle_bin_enabled = false;
        c.meta
            .custom_data
            .items
            .push(near_item("near-known-key", hex(P)));
        c.meta.custom_data.items.push(near_item(
            "near-rows-key",
            format!("{}={}:{}", hex(P), hex(E), at(FAR).0),
        ));
        let c = hostile(
            &c,
            &[
                ("near-known-key", "app.larsal.share.known&#x7F;"),
                ("near-rows-key", "app.larsal.share.deleted&#x7F;"),
            ],
        );
        run::merge_into(&mut l.macs[A], id(T), &c, now).unwrap();
        l.store(A);
        eprintln!(
            "C2R3-06 {}: known {:x?}; rows {:x?}; keys {:?}",
            l.what,
            origin::known(&l.macs[A])
                .iter()
                .map(|g| g.0[0])
                .collect::<Vec<_>>(),
            origin::read_rows(&l.macs[A].meta.custom_data).len(),
            l.macs[A]
                .meta
                .custom_data
                .items
                .iter()
                .map(|i| i.key.clone())
                .collect::<Vec<_>>()
        );
        l.settle();
        l.in_all(E, P);
    });
}

/// A near-key marker on a held inside copy: from the save on it counts as brought.
#[test]
fn c2r3_07_near_key_marker_on_a_held_copy() {
    one(2, Seed::In, |l| {
        l.with_file();
        let now = l.now();
        let mut c = l.read_container(T);
        c.meta.recycle_bin_enabled = false;
        edit::edit_entry(&mut c, id(E), now, |d| with_password(d, MEMBER)).unwrap();
        for e in c.root.entries.iter_mut().filter(|e| e.uuid == id(E)) {
            e.custom_data.items.push(near_item("near-demo-key", hex(T)));
        }
        let c = hostile(&c, &[("near-demo-key", "app.larsal.share.origin&#x7F;")]);
        run::merge_into(&mut l.macs[A], id(T), &c, now).unwrap();
        l.store(A);
        eprintln!(
            "C2R3-07 {}: marker on A after the save: {:x?}",
            l.what,
            origin::mark_of(&find(&l.macs[A], E).unwrap().custom_data).map(|g| g.0[0])
        );
    });
}

/// Every kind, both orders, no stop at the first: how the plant of C2R3-01 ends on
/// each. Reports only.
#[test]
fn c2r3_08_the_plant_on_every_kind_and_order() {
    for kind in KINDS {
        for first in 0..2 {
            let mut l = Lab::new(kind, first, 2, Shares::One, Seed::In);
            l.with_file();
            l.mv(B, E, P);
            l.edit(B, E, PRIVATE);
            let now = l.now();
            let mut c = l.read_container(T);
            c.meta.recycle_bin_enabled = false;
            edit::edit_entry(&mut c, id(E), now, |d| with_password(d, MEMBER)).unwrap();
            let far = at(FAR).0;
            for e in c.root.entries.iter_mut().filter(|e| e.uuid == id(E)) {
                e.custom_data
                    .items
                    .push(near_item("near-demo-key", format!("{}:{far}", hex(T))));
            }
            let c = hostile(&c, &[("near-demo-key", "app.larsal.share.moved&#x7F;")]);
            run::merge_into(&mut l.macs[A], id(T), &c, now).unwrap();
            l.store(A);
            l.settle();
            eprintln!(
                "C2R3-08 {:?} first {first}: Mac B place {:x?}, value {:?}, private exported {}",
                kind,
                parent(&l.macs[B], E).map(|p| p.0[0]),
                find(&l.macs[B], E).map(|e| e.value("Password").to_owned()),
                holds(&l.macs[B], T, PRIVATE)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Round 4, C2R3-01: reader, strip, held() and save use one key-cleaning function
// (`custom_data::kept_char`). Every character a save removes, in every position, on
// real encrypted files, with real saves and opens, every kind and both orders.
// ---------------------------------------------------------------------------

const NEAR: &str = "near-demo-key";

/// Every character a save removes, as FMT-12.25 lists them (not from the code).
fn removed() -> Vec<char> {
    (0u32..=8)
        .chain([0xB, 0xC])
        .chain(0xE..=0x1F)
        .chain(0x7F..=0x84)
        .chain(0x86..=0x9F)
        .chain([0xFFFE, 0xFFFF])
        .map(|c| char::from_u32(c).unwrap())
        .collect()
}

/// The ones the reader takes (FMT-12.24); a file with any other is refused.
fn readable(c: char) -> bool {
    ('\u{7F}'..='\u{9F}').contains(&c)
}

/// `key` with `c` before it, in its middle or after it, as raw text or a reference.
fn near_text(key: &str, c: char, pos: usize, raw: bool) -> String {
    let ch = if raw {
        c.to_string()
    } else {
        format!("&#x{:X};", u32::from(c))
    };
    let cut = [0, key.len() / 2, key.len()][pos];
    format!("{}{ch}{}", &key[..cut], &key[cut..])
}

fn share_key() -> &'static str {
    core::str::from_utf8(edit::SHARED_KEY).unwrap()
}

/// A real encrypted file of `v` (AES-256, gzip, AES-KDF of one round, the lab's
/// password) whose document has `swaps` made: what a writer that keeps every
/// character sends. Built from the format's public parts only.
fn near_file(v: &Vault, swaps: &[(String, String)]) -> Vec<u8> {
    use larsal_crypto::cipher::{self, Cipher};
    use larsal_crypto::kdf::{self, KdfParams, Verdict};
    use larsal_crypto::secret::SecretBytes;
    use larsal_format::document::write::{SaveStamp, write};
    use larsal_format::header::{Compression, write_header};
    use larsal_format::integrity::{header_hmac, write_blocks};
    use larsal_format::keys::{composite_key, final_keys, password_part};
    let stream_key = SecretBytes::new((0u8..64).collect());
    let mut stream =
        larsal_crypto::stream::FieldStream::chacha20_from_stream_key(&stream_key).unwrap();
    let stamp = SaveStamp {
        padding_hex: "00".repeat(64),
        time: T0,
    };
    let w = write(v, 1, &mut stream, &stamp).unwrap();
    let mut xml = w.xml().to_vec();
    for (a, b) in swaps {
        let at = xml
            .windows(a.len())
            .position(|x| x == a.as_bytes())
            .unwrap_or_else(|| panic!("{a} is in the document"));
        xml = [&xml[..at], b.as_bytes(), &xml[at + a.len()..]].concat();
    }
    let mut inner = vec![1, 4, 0, 0, 0, 3, 0, 0, 0, 2, 64, 0, 0, 0];
    inner.extend_from_slice(stream_key.expose());
    inner.extend([0, 0, 0, 0, 0]);
    inner.extend(xml);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &inner).unwrap();
    let plain = gz.finish().unwrap();
    let (seed, iv) = ([0x11u8; 32], [0x22u8; 16]);
    let params = KdfParams::AesKdf {
        rounds: 1,
        seed: vec![0x4B; 32],
    };
    let header = write_header(
        1,
        Cipher::Aes256Cbc,
        Compression::Gzip,
        &seed,
        &iv,
        &params,
        &[],
    )
    .unwrap();
    let password = SecretString::new(PASSWORD.to_owned());
    let composite = composite_key(Some(&password_part(&password)), None, None);
    let Verdict::Run(cleared) =
        kdf::assess(&params, &mut host(), &Limits::DEFAULT.kdf, None).unwrap()
    else {
        panic!("one round runs at once")
    };
    let keys = final_keys(&seed, &kdf::derive(&composite, &cleared).unwrap());
    let sealed = cipher::encrypt(Cipher::Aes256Cbc, &keys.cipher_key, &iv, &plain).unwrap();
    let mut file = header.clone();
    file.extend_from_slice(larsal_crypto::hash::sha256(&[&header]).expose());
    file.extend_from_slice(header_hmac(&keys.hmac_key, &header).expose());
    file.extend(write_blocks(&sealed, &keys.hmac_key, 1 << 20).unwrap());
    file
}

fn open_bytes(file: &[u8]) -> Option<Vault> {
    let p = SecretString::new(PASSWORD.to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    match larsal_format::open(file, &key, &mut host(), &Limits::DEFAULT, None).ok()? {
        Opened::Vault(o) => Some(o.vault),
        Opened::Ask(_) => panic!("asked"),
    }
}

/// One item keyed `NEAR` with `value`, in `place`: 0 an entry, 1 a group, 2 a
/// history item, 3 the vault data.
fn with_item(place: usize, value: &str) -> Vault {
    let mut root = Group::new(id(ROOT), "Root".into(), T0);
    let mut g = Group::new(id(0x70), "G".into(), T0);
    let mut e = entry(E, SEED, at(1), at(1));
    let mut h = entry(E, OLD, at(0), at(0));
    let it = near_item(NEAR, value.to_owned());
    match place {
        0 => e.custom_data.items.push(it),
        1 => g.custom_data.items.push(it),
        2 => h.custom_data.items.push(it),
        _ => {}
    }
    e.history.push(h);
    g.entries.push(e);
    root.groups.push(g);
    let mut v = Vault::new(root, T0);
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    if place == 3 {
        v.meta
            .custom_data
            .items
            .push(near_item(NEAR, value.to_owned()));
    }
    v
}

/// The key of the item holding `value` in `place`; a tagged history item goes whole
/// at a strip.
fn key_at(v: &Vault, place: usize, value: &str) -> Option<String> {
    let g = &v.root.groups[0];
    let e = &g.entries[0];
    let data = match place {
        0 => &e.custom_data,
        1 => &g.custom_data,
        2 => &e.history.first()?.custom_data,
        _ => &v.meta.custom_data,
    };
    data.items
        .iter()
        .find(|i| i.value.expose() == value)
        .map(|i| i.key.clone())
}

/// The rule reads `key` in `place`: the items `held()` looks for.
fn rule_key_here(key: &str, place: usize) -> bool {
    match place {
        0..=2 => [origin::STAMP, origin::MARK, origin::PRIVATE].contains(&key),
        _ => [origin::KNOWN, origin::SCOPES].contains(&key),
    }
}

/// One key, every removed character, every position, raw and as a reference, every
/// place: the file opens with the key itself, held() sees it, strip takes it, and a
/// real save and open keeps it exact; or, for a character the reader refuses, the
/// file does not open.
fn near_key_on_real_files(key: &str) {
    let mut opened = 0;
    let mut refused = 0;
    for c in removed() {
        for pos in 0..3 {
            for raw in [true, false] {
                for place in 0..4 {
                    let value = format!("demo-value-{place}");
                    let v = with_item(place, &value);
                    let text = near_text(key, c, pos, raw);
                    let file = near_file(&v, &[(NEAR.to_owned(), text)]);
                    let what = format!(
                        "{key} U+{:04X} pos {pos} raw {raw} place {place}",
                        u32::from(c)
                    );
                    let Some(mut read) = open_bytes(&file) else {
                        assert!(!readable(c), "{what}: refused");
                        refused += 1;
                        continue;
                    };
                    assert!(readable(c), "{what}: opened");
                    opened += 1;
                    assert_eq!(key_at(&read, place, &value).as_deref(), Some(key), "{what}");
                    assert_eq!(origin::held(&read), rule_key_here(key, place), "{what}");
                    let again = Lab::load_bytes(&Lab::save_bytes(&read));
                    assert_eq!(
                        key_at(&again, place, &value).as_deref(),
                        Some(key),
                        "{what}"
                    );
                    origin::strip(&mut read);
                    assert_eq!(
                        key_at(&read, place, &value).is_none(),
                        rule_key_here(key, place),
                        "{what}: strip"
                    );
                }
            }
        }
    }
    assert_eq!((opened, refused), (32 * 3 * 2 * 4, 31 * 3 * 2 * 4));
}

impl Lab {
    fn load_bytes(bytes: &[u8]) -> Vault {
        open_bytes(bytes).unwrap()
    }

    /// The member writes `c` with `swaps` made in its document, as a real file.
    fn near_container(&mut self, share: u8, c: &Vault, swaps: &[(String, String)]) {
        let path = self.dir.join(format!("share-{share:x}.larsalvault"));
        let mut c = c.duplicate();
        c.encryption.kdf = Kdf::AesKdf { rounds: 1 };
        std::fs::write(&path, near_file(&c, swaps)).unwrap();
        self.files.insert(share, path);
    }
}

#[test]
fn r4_c2r3_01_the_set_is_the_cards() {
    let set = removed();
    for c in (0u32..=0x0010_FFFF).filter_map(char::from_u32) {
        assert_eq!(
            larsal_model::custom_data::kept_char(c),
            !set.contains(&c),
            "U+{:04X}",
            u32::from(c)
        );
    }
    assert_eq!(set.len(), 63);
}

#[test]
fn r4_c2r3_01_near_stamp_keys_on_real_files() {
    near_key_on_real_files(origin::STAMP);
}

#[test]
fn r4_c2r3_01_near_marker_keys_on_real_files() {
    near_key_on_real_files(origin::MARK);
}

#[test]
fn r4_c2r3_01_near_private_keys_on_real_files() {
    near_key_on_real_files(origin::PRIVATE);
}

#[test]
fn r4_c2r3_01_near_known_keys_on_real_files() {
    near_key_on_real_files(origin::KNOWN);
}

#[test]
fn r4_c2r3_01_near_row_keys_on_real_files() {
    near_key_on_real_files(origin::SCOPES);
}

#[test]
fn r4_c2r3_01_near_share_item_keys_on_real_files() {
    near_key_on_real_files(share_key());
}

/// Every plant of C2R3-01 at once, by near keys, in a real container file: a stamp
/// and a marker on E (whose private value B typed outside), a tagged history item, a
/// planted group with a stamp, a marker and a share item, and a known list and a row
/// in the vault data. After A's import and its real save and open, none is there; at
/// the end E is in P with B's value on every Mac, and T exports nothing.
fn near_plants(kind: Kind, first: usize, c: char, pos: usize) {
    let mut l = Lab::new(kind, first, 2, Shares::One, Seed::In);
    l.what = format!("{} U+{:04X} pos {pos}", l.what, u32::from(c));
    l.with_file();
    l.mv(B, E, P);
    l.edit(B, E, PRIVATE);
    let now = l.now();
    let mut ct = l.read_container(T);
    ct.meta.recycle_bin_enabled = false;
    edit::edit_entry(&mut ct, id(E), now, |d| with_password(d, MEMBER)).unwrap();
    let far = at(FAR).0;
    let keys = [
        origin::STAMP,
        origin::MARK,
        origin::PRIVATE,
        origin::STAMP,
        origin::MARK,
        share_key(),
        origin::KNOWN,
        origin::SCOPES,
    ];
    let slot = |n: usize| format!("{NEAR}-{n}");
    {
        let e = ct
            .root
            .entries
            .iter_mut()
            .find(|e| e.uuid == id(E))
            .unwrap();
        e.custom_data
            .items
            .push(near_item(&slot(0), format!("{}:{far}", hex(T))));
        e.custom_data.items.push(near_item(&slot(1), hex(P)));
        let mut h = entry(E, "planted-private-demo", at(0), at(0));
        h.custom_data
            .items
            .push(near_item(&slot(2), "1".to_owned()));
        e.history.push(h);
    }
    let mut g = Group::new(id(0x70), "planted".into(), now);
    g.custom_data
        .items
        .push(near_item(&slot(3), format!("{}:{far}", hex(T))));
    g.custom_data.items.push(near_item(&slot(4), hex(P)));
    g.custom_data
        .items
        .push(near_item(&slot(5), "AAAA".to_owned()));
    ct.root.groups.push(g);
    ct.meta.custom_data.items.push(near_item(&slot(6), hex(P)));
    ct.meta
        .custom_data
        .items
        .push(near_item(&slot(7), format!("{}={}:{far}", hex(P), hex(E))));
    let swaps: Vec<(String, String)> = keys
        .iter()
        .enumerate()
        .map(|(n, k)| (slot(n), near_text(k, c, pos, true)))
        .collect();
    l.near_container(T, &ct, &swaps);
    l.import(A, T, now);
    let a = &l.macs[A];
    let mut stack = vec![&a.root];
    while let Some(g) = stack.pop() {
        let far_stamp =
            |d: &larsal_model::CustomData| origin::stamp_of(d).is_some_and(|s| s.at.0 > now.0);
        let names_p = |d: &larsal_model::CustomData| origin::mark_of(d) == Some(id(P));
        assert!(
            !far_stamp(&g.custom_data) && !names_p(&g.custom_data),
            "{}",
            l.what
        );
        for e in &g.entries {
            assert!(
                !far_stamp(&e.custom_data) && !names_p(&e.custom_data),
                "{}",
                l.what
            );
            assert!(
                e.history
                    .iter()
                    .all(|h| h.value("Password") != "planted-private-demo"),
                "{}",
                l.what
            );
        }
        stack.extend(g.groups.iter());
    }
    let known = origin::known(a);
    assert!(
        !known.contains(&id(P)) && !known.contains(&id(0x70)),
        "{}",
        l.what
    );
    assert!(
        !origin::read_rows(&a.meta.custom_data).contains_key(&(id(E), id(P))),
        "{}",
        l.what
    );
    l.settle();
    l.in_all(E, P);
    l.value_all(E, PRIVATE);
    l.exports_nothing(T);
    l.exported_by_none(T, PRIVATE);
}

fn near_plants_every_character(kind: Kind) {
    for c in removed().into_iter().filter(|c| readable(*c)) {
        for pos in 0..3 {
            for first in [A, B] {
                near_plants(kind, first, c, pos);
            }
        }
    }
}

#[test]
fn r4_c2r3_01_near_plants_change_on_disk() {
    near_plants_every_character(Kind::ChangeOnDisk);
}

#[test]
fn r4_c2r3_01_near_plants_conflict_copy() {
    near_plants_every_character(Kind::ConflictCopy);
}

#[test]
fn r4_c2r3_01_near_plants_server_sync() {
    near_plants_every_character(Kind::ServerSync);
}

#[test]
fn r4_c2r3_01_near_plants_window() {
    near_plants_every_character(Kind::Window);
}

#[test]
fn r4_c2r3_01_near_plants_command_line() {
    near_plants_every_character(Kind::CommandLine);
}

#[test]
fn r4_c2r3_01_near_plants_remote_sync() {
    near_plants_every_character(Kind::RemoteSync);
}

// ---------------------------------------------------------------------------
// Round 4, C1-03, C1-04, C2R3-04: a losing value stays as Larsal's private history
// item (`origin::PRIVATE`). Exports strip it, imports strip it, merges carry it.
// ---------------------------------------------------------------------------

fn tag(h: &mut Entry) {
    h.custom_data
        .items
        .push(near_item(origin::PRIVATE, "1".to_owned()));
}

fn tagged_values(v: &Vault, x: u8) -> Vec<String> {
    find(v, x).map_or_else(Vec::new, |e| {
        e.history
            .iter()
            .filter(|h| origin::private_item(h))
            .map(|h| h.value("Password").to_owned())
            .collect()
    })
}

/// An export carries no tagged item, by value too; the Mac keeps it.
#[test]
fn r4_tag_an_export_strips_every_tagged_item() {
    one(2, Seed::In, |l| {
        let e = gm(&mut l.macs[A].root, T)
            .unwrap()
            .entries
            .iter_mut()
            .find(|e| e.uuid == id(E))
            .unwrap();
        let mut h = entry(E, "kept-private-demo", at(0), at(0));
        tag(&mut h);
        e.history.push(h);
        l.store(A);
        assert_eq!(
            tagged_values(&l.macs[A], E),
            ["kept-private-demo"],
            "{}",
            l.what
        );
        let c = container::build(id(T), true, &l.macs[A], at(l.clock)).unwrap();
        assert!(!origin::held(&c), "{}", l.what);
        assert!(!holds(&l.macs[A], T, "kept-private-demo"), "{}", l.what);
        l.settle();
        for v in &l.macs {
            assert_eq!(tagged_values(v, E), ["kept-private-demo"], "{}", l.what);
        }
    });
}

/// An import drops a tagged history item whole, and a tag anywhere else.
#[test]
fn r4_tag_an_import_strips_the_tag_and_every_tagged_item() {
    one(2, Seed::In, |l| {
        l.with_file();
        let now = l.now();
        let mut c = l.read_container(T);
        c.meta.recycle_bin_enabled = false;
        let e = c.root.entries.iter_mut().find(|e| e.uuid == id(E)).unwrap();
        let mut h = entry(E, "planted-private-demo", at(0), at(0));
        tag(&mut h);
        e.history.push(h);
        tag(e);
        l.write_container(T, &c);
        l.import(A, T, now);
        let e = find(&l.macs[A], E).unwrap();
        assert!(
            e.history
                .iter()
                .all(|h| h.value("Password") != "planted-private-demo"),
            "{}",
            l.what
        );
        assert!(!origin::private_item(e), "{}", l.what);
    });
}

/// Same-vault merges carry tagged items like other history, every kind and order,
/// through real files, and the tag stays on.
#[test]
fn r4_tag_merges_carry_tagged_items() {
    one(3, Seed::Out, |l| {
        let e = gm(&mut l.macs[C].root, P)
            .unwrap()
            .entries
            .iter_mut()
            .find(|e| e.uuid == id(E))
            .unwrap();
        let mut h = entry(E, "kept-private-demo", at(0), at(0));
        tag(&mut h);
        e.history.push(h);
        l.store(C);
        l.settle();
        for v in &l.macs {
            assert_eq!(tagged_values(v, E), ["kept-private-demo"], "{}", l.what);
        }
    });
}

/// Private on one copy is private on both: Mac B holds a history value private that
/// Mac A holds plain, nothing else differs. The merges tag it on both Macs, so a later
/// move into T does not export it.
#[test]
fn r4_tag_private_on_one_copy_is_private_on_both() {
    one(2, Seed::Out, |l| {
        for (m, private) in [(A, false), (B, true)] {
            let mut h = entry(E, "both-demo", at(0), at(0));
            if private {
                tag(&mut h);
            }
            gm(&mut l.macs[m].root, P)
                .unwrap()
                .entries
                .iter_mut()
                .find(|e| e.uuid == id(E))
                .unwrap()
                .history
                .push(h);
            l.store(m);
        }
        l.settle();
        for v in &l.macs {
            assert_eq!(
                tagged_values(v, E),
                ["both-demo"],
                "{}: {}",
                l.what,
                show(v)
            );
        }
        l.mv(A, E, T);
        l.settle();
        l.exported_by_none(T, "both-demo");
    });
}

/// Private on one copy is private on both, through a whole win too: Mac B holds a value
/// private that the winner, Mac A's copy the user moved into T, holds plain. After the
/// merges it is private on both Macs, and no export of T holds it.
#[test]
fn r4_tag_a_whole_win_keeps_the_losers_private_item_private() {
    one(2, Seed::Out, |l| {
        for (m, private) in [(A, false), (B, true)] {
            let mut h = entry(E, "both-demo", at(0), at(0));
            if private {
                tag(&mut h);
            }
            gm(&mut l.macs[m].root, P)
                .unwrap()
                .entries
                .iter_mut()
                .find(|e| e.uuid == id(E))
                .unwrap()
                .history
                .push(h);
            l.store(m);
        }
        l.mv(A, E, T);
        l.settle();
        l.in_all(E, T);
        for v in &l.macs {
            assert_eq!(
                tagged_values(v, E),
                ["both-demo"],
                "{}: {}",
                l.what,
                show(v)
            );
        }
        l.exported_by_none(T, "both-demo");
    });
}

/// The same between two shares, where R6 takes a copy whole (C1-04): E sits in T, Mac B
/// holds a value private that Mac A holds plain, and Mac A's user moves E into U. A's
/// copy wins whole; the value it holds plain is private on both Macs after, so neither
/// share exports it.
#[test]
fn r4_tag_a_whole_win_between_shares_makes_a_held_value_private() {
    all(2, Shares::Two, Seed::In, |l| {
        for (m, private) in [(A, false), (B, true)] {
            let mut h = entry(E, "both-demo", at(0), at(0));
            if private {
                tag(&mut h);
            }
            gm(&mut l.macs[m].root, T)
                .unwrap()
                .entries
                .iter_mut()
                .find(|e| e.uuid == id(E))
                .unwrap()
                .history
                .push(h);
            l.store(m);
        }
        l.mv(A, E, U);
        l.settle();
        l.in_all(E, U);
        for v in &l.macs {
            // B's current version, older than A's moved copy, is kept private too.
            assert!(
                tagged_values(v, E).contains(&"both-demo".to_owned()),
                "{}: {}",
                l.what,
                show(v)
            );
        }
        l.exported_by_none(U, "both-demo");
        l.exported_by_none(T, "both-demo");
    });
}

/// C1-09: a private item that is the entry's current version again (a merge with a copy
/// whose current it is) leaves the history, so the next edit holds that version once,
/// on every Mac. Before, Mac C kept it twice and the Macs never agreed (C1's CONV).
#[test]
fn r4_c1_09_a_private_item_current_again_leaves_the_history() {
    one(3, Seed::Out, |l| {
        l.edit(B, E, "newer-demo");
        let mut h = find(&l.macs[B], E).unwrap().duplicate(false);
        tag(&mut h);
        let e = gm(&mut l.macs[C].root, P)
            .unwrap()
            .entries
            .iter_mut()
            .find(|e| e.uuid == id(E))
            .unwrap();
        e.history.push(h);
        l.store(C);
        l.settle();
        for v in &l.macs {
            let e = find(v, E).unwrap();
            assert_eq!(e.value("Password"), "newer-demo", "{}", l.what);
            assert!(tagged_values(v, E).is_empty(), "{}: {}", l.what, show(v));
        }
        l.edit(C, E, "after-demo");
        l.settle();
        for v in &l.macs {
            let held = find(v, E)
                .unwrap()
                .history
                .iter()
                .filter(|h| h.value("Password") == "newer-demo")
                .count();
            assert_eq!(held, 1, "{}: {}", l.what, show(v));
        }
        assert!(
            l.macs.iter().all(|v| show(v) == show(&l.macs[A])),
            "{}",
            l.what
        );
    });
}

/// C2R3-04: private items have their own budget under the history limits, so a
/// losing value never pushes out the entry's own versions; pruning may drop private
/// items within their budget (a named limit).
#[test]
fn r4_tag_pruning_keeps_the_entrys_own_versions() {
    let mut e = entry(E, "now-demo", at(9), at(9));
    for n in 0..3 {
        e.history.push(entry(E, &format!("own-{n}"), at(n), at(n)));
    }
    for n in 0..3 {
        let mut h = entry(E, &format!("lost-{n}"), at(n + 4), at(n + 4));
        tag(&mut h);
        e.history.push(h);
    }
    history::prune(&mut e, 2, -1);
    let values: Vec<_> = e
        .history
        .iter()
        .map(|h| h.value("Password").to_owned())
        .collect();
    assert_eq!(values, ["own-1", "own-2", "lost-1", "lost-2"]);
    let mut big = entry(E, "now-demo", at(9), at(9));
    big.history.push(entry(E, "own-small", at(1), at(1)));
    let mut h = entry(E, &"x".repeat(4000), at(2), at(2));
    tag(&mut h);
    big.history.push(h);
    let limit = i32::try_from(history::size(&big.history[0]) + 10).unwrap();
    history::prune(&mut big, -1, limit);
    let values: Vec<_> = big
        .history
        .iter()
        .map(|h| h.value("Password").to_owned())
        .collect();
    assert_eq!(values, ["own-small"], "the big private item goes alone");
}

/// C2R3-03, limit 11 as a test (C2's cross-version run, restated in one tree): another
/// writer of this vault that keeps custom data and does not strip at its import keeps
/// a member's stamp item; a same-vault merge takes it as the user's move in. Here it
/// moves E into T with Mac B's private value in its history, and T's export holds that
/// value. This test pins the limit; a fix turns it red.
#[test]
fn r4_c2r3_03_limit_11_a_writer_that_keeps_items_passes_a_planted_stamp() {
    one(2, Seed::In, |l| {
        l.mv(B, E, P);
        l.edit(B, E, PRIVATE);
        // Mac A as that writer: its copy of E keeps the container's stamp item.
        let now = l.now();
        let e = gm(&mut l.macs[A].root, T)
            .unwrap()
            .entries
            .iter_mut()
            .find(|e| e.uuid == id(E))
            .unwrap();
        with_password(e, MEMBER);
        e.times.last_modification = now;
        e.custom_data.items.push(near_item(
            origin::STAMP,
            format!("{}:{}", hex(T), at(FAR).0),
        ));
        l.store(A);
        l.settle();
        l.in_all(E, T);
        l.value_all(E, MEMBER);
        assert!(l.exports_value(T, PRIVATE), "{}: limit 11", l.what);
    });
}

// ---------------------------------------------------------------------------
// Sensitive Checker 2, round 4, ported in round 5: the private tag. Every road a
// tagged history item could take out of this vault, plants by a container, other
// normalisation, and the history budget. Changed assertions say so where they stand:
// r4c2_01 holds the icon fix (C2R4-04), r4c2_04 pins limit 10 (C2R4-05), r4c2_05 pins
// limit 8 (C2R4-06), r4c2_06 and r4c2_09 hold the history cap (C2R4-02).
// ---------------------------------------------------------------------------
mod c2r4 {
    #![allow(clippy::all)]
    use super::*;
    use larsal_core::clone;
    use larsal_model::{Attachment, CustomIcon, Icon};
    use std::sync::Arc;

    const PX: &str = "c2r4-private-x";
    const ICON: u8 = 0x6c;

    /// A tagged history item of E whose every carrier names PX: title, password, notes,
    /// a custom field, a custom data value, an attachment and a custom icon.
    fn tagged_px(x: u8, at_: i64) -> Entry {
        let mut h = entry(x, &format!("{PX}-pw"), at(at_), at(at_));
        for (k, v) in [("Title", "title"), ("Notes", "notes"), ("Extra", "field")] {
            h.set_field(
                k.to_owned(),
                Field {
                    value: SecretString::new(format!("{PX}-{v}")),
                    protected: false,
                },
            );
        }
        h.custom_data
            .items
            .push(near_item("c2r4-own-key", format!("{PX}-cd")));
        h.attachments.push(Attachment {
            name: format!("{PX}-att.txt"),
            data: Arc::new(larsal_crypto::secret::SecretBytes::new(
                format!("{PX}-attdata").into_bytes(),
            )),
        });
        h.icon = Icon::Custom(id(ICON));
        tag(&mut h);
        h
    }

    fn add_icon(v: &mut Vault) {
        if !v.meta.custom_icons.iter().any(|i| i.uuid == id(ICON)) {
            v.meta.custom_icons.push(CustomIcon {
                uuid: id(ICON),
                name: format!("{PX}-icon"),
                last_modified: None,
                data: format!("{PX}-icondata").into_bytes(),
                unknown: Vec::new(),
            });
        }
    }

    /// Everything of `c` a member reads, as text: the plain document, every field of every
    /// entry and history item, attachment names and bytes, icon names and bytes.
    fn member_text(c: &Vault) -> String {
        let mut out = String::new();
        let w = larsal_format::document::write::write_plain(c).unwrap();
        out.push_str(&String::from_utf8_lossy(w.xml()));
        for e in c.root.all_entries() {
            for x in std::iter::once(e).chain(e.history.iter()) {
                for (n, f) in x.fields() {
                    out.push_str(&format!("|{n}={}", f.value.expose()));
                }
                for a in &x.attachments {
                    out.push_str(&format!(
                        "|att {} {}",
                        a.name,
                        String::from_utf8_lossy(a.data.expose())
                    ));
                }
                for i in &x.custom_data.items {
                    out.push_str(&format!("|cd {}={}", i.key, i.value.expose()));
                }
            }
        }
        for i in &c.meta.custom_icons {
            out.push_str(&format!(
                "|icon {} {}",
                i.name,
                String::from_utf8_lossy(&i.data)
            ));
        }
        out
    }

    /// What of PX an export of `share` from `v` carries, by carrier.
    fn leaks(v: &Vault, share: u8) -> Vec<String> {
        let Ok(c) = container::build(id(share), true, v, at(9_999)) else {
            return vec!["no export".into()];
        };
        let text = member_text(&c);
        let mut out: Vec<String> = [
            "pw", "title", "notes", "field", "cd", "att.txt", "attdata", "icon", "icondata",
        ]
        .iter()
        .filter(|w| text.contains(&format!("{PX}-{w}")))
        .map(|w| (*w).to_owned())
        .collect();
        if origin::held(&c) {
            out.push("rule item".into());
        }
        if text.contains("app.larsal.share") {
            out.push("rule key text".into());
        }
        out
    }

    fn e_mut(v: &mut Vault, x: u8) -> &mut Entry {
        let mut stack = vec![&mut v.root];
        while let Some(g) = stack.pop() {
            if let Some(i) = g.entries.iter().position(|e| e.uuid == id(x)) {
                return &mut g.entries[i];
            }
            stack.extend(g.groups.iter_mut());
        }
        panic!("no entry {x:x}")
    }

    fn inject(l: &mut Lab, m: usize, x: u8) {
        add_icon(&mut l.macs[m]);
        e_mut(&mut l.macs[m], x).history.push(tagged_px(x, 0));
        l.store(m);
        assert_eq!(
            tagged_values(&l.macs[m], x),
            [format!("{PX}-pw")],
            "{}: the tag survives a save",
            l.what
        );
    }

    fn none_out(l: &Lab, share: u8, road: &str) {
        for (m, v) in l.macs.iter().enumerate() {
            let got = leaks(v, share);
            assert!(got.is_empty(), "{} {road}: Mac {m} exports {got:?}", l.what);
        }
    }

    /// Roads 1-8 on one state: E in T on every Mac, A's copy holds a tagged item.
    #[test]
    fn r4c2_01_roads_of_a_tagged_item_in_a_share() {
        one(2, Seed::In, |l| {
            inject(l, A, E);
            none_out(l, T, "export");
            // Clone of the entry (history on): the clone sits in T with the tagged item.
            let now = l.now();
            let new = clone::clone_entry(
                &mut l.macs[A],
                id(E),
                clone::Options {
                    history: true,
                    suffix: true,
                    refs: false,
                },
                &clone::Limits::DEFAULT,
                now,
            )
            .unwrap();
            l.store(A);
            let c = l.macs[A]
                .root
                .all_entries()
                .find(|e| e.uuid == new)
                .unwrap();
            assert!(
                c.history.iter().any(origin::private_item),
                "{}: the clone keeps it",
                l.what
            );
            assert!(
                origin::stamp_of(&c.custom_data).is_none()
                    && origin::mark_of(&c.custom_data).is_none()
            );
            none_out(l, T, "clone");
            // Copy within the vault into T, and into S.
            let now = l.now();
            let cp = edit::copy_within(
                &mut l.macs[A],
                edit::Item::Entry(id(E)),
                id(S),
                Position::End,
                now,
            )
            .unwrap();
            l.store(A);
            let c = l.macs[A].root.all_entries().find(|e| e.uuid == cp).unwrap();
            assert!(
                !c.history.iter().any(origin::private_item),
                "{}: copy drops it",
                l.what
            );
            none_out(l, T, "copy within");
            // Copy into another vault, which has its own share on its root group.
            let mut other = world(Shares::One, A);
            other.root.uuid = id(0x77);
            let now = l.now();
            let oc = edit::copy_into(
                &l.macs[A],
                edit::Item::Entry(id(E)),
                &mut other,
                id(T),
                Position::End,
                now,
            )
            .unwrap();
            let other = Lab::load_bytes(&Lab::save_bytes(&other));
            let c = other.root.all_entries().find(|e| e.uuid == oc).unwrap();
            assert!(
                !c.history.iter().any(origin::private_item),
                "{}: copy into drops it",
                l.what
            );
            assert!(
                leaks(&other, T).is_empty(),
                "{}: other vault export {:?}",
                l.what,
                leaks(&other, T)
            );
            // C2R4-04: the icon set is the copy's after the strip, so the private item's
            // custom icon stays behind too.
            assert!(
                other.meta.custom_icons.is_empty(),
                "{}: copy into brought the private item's icon {:?}",
                l.what,
                other
                    .meta
                    .custom_icons
                    .iter()
                    .map(|i| i.name.clone())
                    .collect::<Vec<_>>()
            );
            // The same copy of a version the user did not make private brings its icon.
            let mut mine = world(Shares::One, A);
            mine.root.uuid = id(0x77);
            let mut src = l.macs[A].duplicate();
            e_mut(&mut src, E).icon = Icon::Custom(id(ICON));
            edit::copy_into(
                &src,
                edit::Item::Entry(id(E)),
                &mut mine,
                id(T),
                Position::End,
                now,
            )
            .unwrap();
            assert_eq!(
                mine.meta.custom_icons.len(),
                1,
                "{}: the entry's own icon goes",
                l.what
            );
            // Same-vault merges carry it; every Mac's export stays clean.
            l.settle();
            none_out(l, T, "after settle");
            assert!(
                tagged_values(&l.macs[B], E).contains(&format!("{PX}-pw")),
                "{}",
                l.what
            );
            // Bin and restore.
            l.bin(B, E);
            l.restore(B, E);
            l.settle();
            none_out(l, T, "bin and restore");
            // A user's move from T into S (nested) and back.
            l.mv(A, E, S);
            l.settle();
            none_out(l, T, "move into S");
            none_out(l, S, "move into S, S export");
            l.mv(B, E, T);
            l.settle();
            none_out(l, T, "move back");
            // A member edits, A imports, B imports: still clean.
            l.export(A, T);
            l.member_edit(T, E, "member-r4-demo");
            l.take(A, T);
            l.take(B, T);
            l.settle();
            none_out(l, T, "after member edit");
            assert!(
                tagged_values(&l.macs[A], E).contains(&format!("{PX}-pw")),
                "{}: still on the Mac",
                l.what
            );
        });
    }

    /// Road: a user's move into a share of an outside entry holding a tagged item, and of a
    /// group whose entry holds one; and between two shares.
    #[test]
    fn r4c2_02_moves_into_a_share_carry_no_tagged_item() {
        all(2, Shares::Two, Seed::Out, |l| {
            inject(l, B, E);
            l.settle();
            l.mv(A, E, T);
            l.settle();
            l.in_all(E, T);
            none_out(l, T, "move in");
            l.mv(B, E, U);
            l.settle();
            none_out(l, U, "move to U");
            none_out(l, T, "move to U, T export");
        });
        all(2, Shares::Two, Seed::GOut, |l| {
            inject(l, A, F);
            l.settle();
            l.mv(B, O, T);
            l.settle();
            l.in_all(O, T);
            none_out(l, T, "group move in");
        });
    }

    /// Road: clone of a group in a share keeps the item, the export does not carry it.
    #[test]
    fn r4c2_03_a_group_clone_in_a_share() {
        one(2, Seed::GIn, |l| {
            inject(l, A, F);
            let now = l.now();
            let copy = clone::clone_group(&l.macs[A], id(O), &clone::Limits::DEFAULT, now).unwrap();
            assert!(
                copy.entries[0].history.iter().any(origin::private_item),
                "{}",
                l.what
            );
            gm(&mut l.macs[A].root, T).unwrap().groups.push(copy);
            l.store(A);
            none_out(l, T, "group clone");
            l.settle();
            none_out(l, T, "group clone settled");
            // C2R4-04, the group form: a copy into another vault brings no private item's icon.
            let mut other = world(Shares::One, A);
            other.root.uuid = id(0x77);
            let now = l.now();
            edit::copy_into(
                &l.macs[A],
                edit::Item::Group(id(O)),
                &mut other,
                id(T),
                Position::End,
                now,
            )
            .unwrap();
            assert!(
                other.meta.custom_icons.is_empty(),
                "{}: group copy brought the icon",
                l.what
            );
        });
    }

    /// Limit 10 (C2R4-05): the user restores the tagged version. Its values are then the
    /// entry's own and go out with it, every one of them: the app does not mark a private
    /// version. The current copy and the next history item carry no tag. Pinned.
    #[test]
    fn r4c2_04_limit_10_restore_then_export() {
        one(2, Seed::In, |l| {
            inject(l, A, E);
            let i = find(&l.macs[A], E)
                .unwrap()
                .history
                .iter()
                .position(origin::private_item)
                .unwrap();
            l.restore_version(A, E, i);
            let e = find(&l.macs[A], E).unwrap();
            assert!(
                !origin::private_item(e),
                "{}: no tag on the current copy",
                l.what
            );
            let got = leaks(&l.macs[A], T);
            assert_eq!(
                got,
                [
                    "pw", "title", "notes", "field", "cd", "att.txt", "attdata", "icon", "icondata"
                ],
                "{}: limit 10 changed",
                l.what
            );
            l.edit(A, E, "after-restore-demo");
            let e = find(&l.macs[A], E).unwrap();
            let history: Vec<_> = e
                .history
                .iter()
                .map(|h| (h.value("Password").to_owned(), origin::private_item(h)))
                .collect();
            assert_eq!(
                history,
                [
                    (format!("{PX}-pw"), true),
                    (SEED.to_owned(), false),
                    (format!("{PX}-pw"), false)
                ],
                "{}: the original tagged item stays, the restored version is plain",
                l.what
            );
        });
    }

    /// Limit 8 (C2R4-06): the honest whole win between two shares with an outside value: B
    /// moved E out and typed; A, stale, moved E from T to U later. A's move wins: E ends in
    /// U with the seed value, and B's value typed outside joins U's history untagged, so U's
    /// export holds it; T's does not. Pinned.
    #[test]
    fn r4c2_05_limit_8_whole_win_after_a_move_out_and_a_later_move_between_shares() {
        all(2, Shares::Two, Seed::In, |l| {
            l.mv(B, E, P);
            l.edit(B, E, PRIVATE);
            l.mv(A, E, U);
            l.settle();
            for m in [A, B] {
                assert_eq!(parent(&l.macs[m], E), Some(id(U)), "{}", l.what);
                assert_eq!(
                    find(&l.macs[m], E).unwrap().value("Password"),
                    SEED,
                    "{}",
                    l.what
                );
                assert!(tagged_values(&l.macs[m], E).is_empty(), "{}", l.what);
                assert!(!holds(&l.macs[m], T, PRIVATE), "{}: T", l.what);
                assert!(holds(&l.macs[m], U, PRIVATE), "{}: limit 8 changed", l.what);
            }
        });
    }

    /// History budget (C2R4-02): with history limit -1 or 100,000 an entry holds the
    /// format's 100,000 own items and one private item more; pruning drops the private item
    /// and the vault saves. With 99,999 own items the private item stays.
    #[test]
    fn r4c2_06_private_budget_within_the_format_history_limit() {
        let n = Limits::DEFAULT.history;
        for limit in [-1, 100_000] {
            for own in [n, n - 1] {
                let mut v = world(Shares::One, A);
                v.meta.history_max_items = limit;
                let mut e = entry(E, SEED, at(200_000), at(200_000));
                for i in 0..own {
                    let mut h = Entry::new(id(E), T0);
                    h.times.last_modification = at(i64::try_from(i).unwrap());
                    e.history.push(h);
                }
                let mut p = Entry::new(id(E), T0);
                p.times.last_modification = at(150_000);
                tag(&mut p);
                e.history.push(p);
                let dropped =
                    history::prune(&mut e, v.meta.history_max_items, v.meta.history_max_size);
                let private = e.history.iter().filter(|h| origin::private_item(h)).count();
                assert_eq!(
                    (dropped, e.history.len(), private),
                    if own == n { (1, n, 0) } else { (0, n, 1) },
                    "limit {limit}, own {own}"
                );
                gm(&mut v.root, T).unwrap().entries.push(e);
                let p = SecretString::new("demo".to_owned());
                let key = Credentials {
                    password: Some(&p),
                    ..Credentials::default()
                };
                let saved =
                    larsal_format::save(&v, &key, None, &mut host(), &Limits::DEFAULT, None);
                assert!(
                    saved.is_ok(),
                    "limit {limit}, own {own}: {:?}",
                    saved.err().map(|e| e.to_string())
                );
            }
        }
    }

    /// Other normalisation, on real files: characters a save keeps, entity and section
    /// forms, around the private key and the stamp key, on a history item and an entry.
    /// The key read must be the key a save and open gives back, and the rule must see the
    /// item exactly when the key read is the rule's key.
    #[test]
    fn r4c2_07_other_normalisation_on_real_files() {
        let keys = [origin::PRIVATE, origin::STAMP, origin::MARK];
        let inserts: Vec<String> = [
            " ",
            "\t",
            "\n",
            "&#13;",
            "\r",
            "\r\n",
            "&#x85;",
            "\u{85}",
            "\u{A0}",
            "\u{200B}",
            "\u{FEFF}",
            "\u{2028}",
            "\u{FFFD}",
            "\u{AD}",
            "\u{34F}",
            "\u{E0001}",
            "\u{180E}",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let mut forms: Vec<(String, String)> = Vec::new();
        for k in keys {
            for ins in &inserts {
                for cut in [0, k.len() / 2, k.len()] {
                    forms.push((k.to_owned(), format!("{}{ins}{}", &k[..cut], &k[cut..])));
                }
            }
            forms.push((k.to_owned(), format!("&#x61;{}", &k[1..])));
            forms.push((k.to_owned(), format!("<![CDATA[{k}]]>")));
            forms.push((k.to_owned(), format!("{}<!-- c -->{}", &k[..3], &k[3..])));
            forms.push((k.to_owned(), format!("{}<?pi x?>{}", &k[..3], &k[3..])));
            forms.push((k.to_owned(), k.to_uppercase()));
            forms.push((k.to_owned(), k.replace('a', "\u{FF41}")));
            forms.push((k.to_owned(), k.replace('.', "\u{2024}")));
            forms.push((k.to_owned(), format!("{k}&#x7F;&#x9F;\u{80}")));
        }
        let mut stable = 0;
        let mut refused = 0;
        let mut rule = 0;
        for (k, text) in &forms {
            for place in [0usize, 2] {
                let v = with_item(place, "demo-value");
                let file = near_file(&v, &[(NEAR.to_owned(), text.clone())]);
                let Some(read) = open_bytes(&file) else {
                    refused += 1;
                    eprintln!("C2R4-07 refused: {k} {text:?} place {place}");
                    continue;
                };
                let k1 = key_at(&read, place, "demo-value").unwrap();
                let again = Lab::load_bytes(&Lab::save_bytes(&read));
                let k2 = key_at(&again, place, "demo-value").unwrap_or_default();
                assert_eq!(
                    k1, k2,
                    "{k} {text:?} place {place}: read {k1:?}, after a save {k2:?}"
                );
                let is_rule = larsal_model::custom_data::same_key(&k1, k);
                assert_eq!(
                    origin::held(&read),
                    is_rule,
                    "{k} {text:?} place {place}: held, key {k1:?}"
                );
                assert_eq!(
                    origin::held(&again),
                    is_rule,
                    "{k} {text:?} place {place}: held after save"
                );
                let mut s = read.duplicate();
                origin::strip(&mut s);
                assert_eq!(
                    key_at(&s, place, "demo-value").is_none(),
                    is_rule,
                    "{k} {text:?} strip"
                );
                if is_rule {
                    rule += 1;
                }
                stable += 1;
            }
        }
        eprintln!(
            "C2R4-07: forms {} x 2 places: stable {stable}, of them the rule's key {rule}, refused {refused}",
            forms.len()
        );
    }

    /// The same forms through a share import: a container's tagged history item whose tag
    /// key uses an entity, a section or a comment is dropped whole, and no outside value is
    /// kept tagged on A after its save and open.
    #[test]
    fn r4c2_08_tag_forms_through_an_import() {
        let k = origin::PRIVATE;
        let texts = [
            format!("&#x61;{}", &k[1..]),
            format!("<![CDATA[{k}]]>"),
            format!("{}<!-- c -->{}", &k[..3], &k[3..]),
            format!("{k}&#x7F;"),
            format!("\u{9F}{k}"),
        ];
        for text in texts {
            let mut l = Lab::new(Kind::ChangeOnDisk, A, 2, Shares::One, Seed::In);
            l.with_file();
            let now = l.now();
            let mut ct = l.read_container(T);
            ct.meta.recycle_bin_enabled = false;
            {
                let e = ct
                    .root
                    .entries
                    .iter_mut()
                    .find(|e| e.uuid == id(E))
                    .unwrap();
                let mut h = entry(E, "c2r4-planted-tagged", at(0), at(0));
                h.custom_data.items.push(near_item(NEAR, "1".to_owned()));
                e.history.push(h);
            }
            l.near_container(T, &ct, &[(NEAR.to_owned(), text.clone())]);
            l.import(A, T, now);
            let e = find(&l.macs[A], E).unwrap();
            let kept: Vec<_> = e
                .history
                .iter()
                .map(|h| (h.value("Password").to_owned(), origin::private_item(h)))
                .collect();
            eprintln!("C2R4-08 {text:?}: A's history after the import {kept:?}");
            assert!(
                kept.iter().all(|(v, _)| v != "c2r4-planted-tagged"),
                "{text:?}"
            );
        }
    }

    /// The same budget reached by a merge (C2R4-02): the user keeps every version (history
    /// items -1, a setting MOD-03.2 offers, or 100,000). E in T holds 100,000 versions on both
    /// Macs. B edits E in T; A's user moves E from T to U. A's copy wins whole; B's values
    /// would be private items past the format's limit, so they go first and A still saves.
    #[test]
    fn r4c2_09_a_whole_win_at_the_history_cap() {
        let n = Limits::DEFAULT.history;
        for limit in [-1, 100_000] {
            let mut macs: Vec<Vault> = (0..2)
                .map(|m| {
                    let mut v = world(Shares::Two, m);
                    v.meta.history_max_items = limit;
                    let mut e = entry(E, SEED, at(1_000_000), at(1));
                    for i in 0..n {
                        let mut h = Entry::new(id(E), T0);
                        h.times.last_modification = at(i64::try_from(i).unwrap());
                        e.history.push(h);
                    }
                    gm(&mut v.root, T).unwrap().entries.push(e);
                    v
                })
                .collect();
            edit::edit_entry(&mut macs[B], id(E), at(1_000_002), |d| {
                with_password(d, "typed-on-b-demo")
            })
            .unwrap();
            edit::move_entries(&mut macs[A], &[id(E)], id(U), at(1_000_003)).unwrap();
            let b = macs[B].duplicate();
            merge(
                &mut macs[A],
                &b,
                &Options::new(Kind::ChangeOnDisk),
                at(1_000_004),
            )
            .unwrap();
            let e = find(&macs[A], E).unwrap();
            let tagged = e.history.iter().filter(|h| origin::private_item(h)).count();
            assert_eq!(parent(&macs[A], E), Some(id(U)));
            assert_eq!((e.history.len(), tagged), (n, 0), "limit {limit}");
            let p = SecretString::new("demo".to_owned());
            let key = Credentials {
                password: Some(&p),
                ..Credentials::default()
            };
            let saved =
                larsal_format::save(&macs[A], &key, None, &mut host(), &Limits::DEFAULT, None);
            assert!(
                saved.is_ok(),
                "limit {limit}: {:?}",
                saved.err().map(|e| e.to_string())
            );
        }
    }

    /// Merges that are not same vault: a retired key's copy and another vault. A source's
    /// tagged items never arrive; the target keeps its own.
    #[test]
    fn r4c2_10_not_same_vault_merges_and_tags() {
        one(2, Seed::In, |l| {
            inject(l, A, E);
            // A copy under a retired key, holding the tagged item, merged into B.
            let src = l.macs[A].duplicate();
            let mut o = Options::new(Kind::Window);
            o.retired = true;
            let now = l.now();
            merge(&mut l.macs[B], &src, &o, now).unwrap();
            assert!(
                tagged_values(&l.macs[B], E).is_empty(),
                "{}: retired copy brought a tag",
                l.what
            );
            assert!(
                find(&l.macs[B], E)
                    .unwrap()
                    .history
                    .iter()
                    .all(|h| h.value("Password") != format!("{PX}-pw")),
                "{}: retired copy brought the private value untagged",
                l.what
            );
            // Another vault (other root id) merged into A: A keeps its own tagged item.
            let mut other = world(Shares::One, A);
            other.root.uuid = id(0x77);
            merge(&mut l.macs[A], &other, &Options::new(Kind::Window), now).unwrap();
            assert_eq!(
                tagged_values(&l.macs[A], E),
                [format!("{PX}-pw")],
                "{}",
                l.what
            );
        });
    }
}
