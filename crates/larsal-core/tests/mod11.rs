//! Story E4-S12, card MOD-11: merge. One test per rule (`mod11_NN_…`) with
//! the card's cases T01 to T59 on demo vaults built here, and the
//! 1,000-case property of MOD-11.30 (T45).
//!
//! The window and command line flows (MOD-11.27, MOD-11.28) are screens and
//! commands (E5, E12); their core parts are tested here: the preview is the
//! dry run, the key question is `take_key`, the text lines are
//! `Change::line`. A failed save after a merge is APP-05's (storage tests).

mod common;

use common::at;
use larsal_core::edit::{Position, edit_entry, edit_group, move_entries, move_group};
use larsal_core::merge::{Change, ChangeKind, Kind, Merged, Object, Options, merge, same_version};
use larsal_core::{history, recycle};
use larsal_crypto::secret::SecretString;
use larsal_model::{
    Argon2Kind, Cipher, CustomDataItem, CustomIcon, DeletedObject, Entry, Field, FileVersion,
    Group, Icon, Kdf, Time, UnknownElement, Uuid, Vault,
};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

fn t0() -> Time {
    at(2026, 1, 1, 0, 0, 0)
}
fn t1() -> Time {
    at(2026, 2, 1, 0, 0, 0)
}
fn t2() -> Time {
    at(2026, 3, 1, 0, 0, 0)
}
fn t3() -> Time {
    at(2026, 4, 1, 0, 0, 0)
}
fn t9() -> Time {
    at(2026, 9, 9, 9, 9, 9)
}

fn uid(b: u8) -> Uuid {
    Uuid([b; 16])
}

fn set(e: &mut Entry, name: &str, value: &str) {
    e.set_field(
        name.to_owned(),
        Field {
            value: SecretString::new(value.to_owned()),
            protected: name == "Password",
        },
    );
}

/// An entry with every time at `m`.
fn ent(b: u8, title: &str, pw: &str, m: Time) -> Entry {
    let mut e = Entry::new(uid(b), m);
    e.times.expiry = t0();
    set(&mut e, "Title", title);
    set(&mut e, "Password", pw);
    e
}

/// A history item of entry `b`.
fn item(b: u8, title: &str, pw: &str, m: Time) -> Entry {
    ent(b, title, pw, m)
}

fn grp(b: u8, name: &str, m: Time) -> Group {
    Group::new(uid(b), name.into(), m)
}

fn vault(root: Group) -> Vault {
    let mut v = Vault::new(root, t0());
    v.meta.recycle_bin_enabled = false;
    v
}

fn find(v: &Vault, b: u8) -> &Entry {
    v.root
        .all_entries()
        .find(|e| e.uuid == uid(b))
        .expect("entry")
}

fn group_of(v: &Vault, b: u8) -> Uuid {
    v.root
        .subtree()
        .into_iter()
        .find(|g| g.entries.iter().any(|e| e.uuid == uid(b)))
        .expect("entry")
        .uuid
}

fn pw(e: &Entry) -> &str {
    e.value("Password")
}

fn hist(e: &Entry) -> Vec<(&str, Time)> {
    e.history
        .iter()
        .map(|h| (pw(h), h.times.last_modification))
        .collect()
}

/// The deleted-objects list as (id, time) pairs.
fn listed(v: &Vault) -> Vec<(Uuid, Time)> {
    v.deleted_objects
        .iter()
        .map(|d| (d.uuid, d.deleted_at))
        .collect()
}

fn kinds(c: &[Change]) -> Vec<ChangeKind> {
    c.iter().map(|c| c.kind).collect()
}

/// Merge `b` into `a` with a dry run first: the dry run leaves `a` as it
/// was and gives the same records as the real merge (MOD-11.25).
fn run(a: &mut Vault, b: &Vault, o: Options) -> Merged {
    let before = a.duplicate();
    let dry = merge(a, b, &Options { dry_run: true, ..o }, t9()).unwrap();
    assert!(*a == before, "the dry run changed the target");
    let real = merge(a, b, &o, t9()).unwrap();
    assert_eq!(dry.changes, real.changes, "dry run and merge differ");
    real
}

fn window() -> Options {
    Options {
        take_key: true,
        ..Options::new(Kind::Window)
    }
}

fn cli() -> Options {
    Options::new(Kind::CommandLine)
}

/// root(01) → G1(02) → the given entries, and G2(03).
fn two_groups(g1: Vec<Entry>) -> Vault {
    let mut root = grp(0x01, "Root", t0());
    let mut a = grp(0x02, "G1", t0());
    a.entries = g1;
    root.groups.push(a);
    root.groups.push(grp(0x03, "G2", t0()));
    vault(root)
}

#[test]
fn mod11_01_kinds_and_options() {
    // T50: the import wizard into a new vault.
    let mut i_root = grp(0x65, "Import", t0());
    i_root.notes = "n".into();
    i_root.entries.push(ent(0x0a, "E", "p", t0()));
    let mut imported = vault(i_root);
    imported.meta.custom_data.items.push(CustomDataItem {
        key: "X".into(),
        value: larsal_crypto::secret::SecretString::new("1".into()),
        last_modified: Some(t0()),
        unknown: Vec::new(),
    });
    let mut new = vault(grp(0x01, "Root", t0()));
    run(&mut new, &imported, Options::new(Kind::ImportWizard));
    assert_eq!(new.root.entries.len(), 1);
    assert!(new.meta.custom_data.get("X").is_none());
    assert_eq!(
        (new.root.name.as_str(), new.root.notes.as_str()),
        ("Import", "n")
    );
    // A shared-group import is synchronize mode (T49 below), the others
    // keep-newer. A deleted-objects item of the source erases only in a
    // same-vault merge (LD-265): the same root group id, from the roots.
    let mut target = two_groups(vec![ent(0x0a, "X", "p", t0())]);
    let mut source = two_groups(vec![ent(0x0a, "X", "p", t0())]);
    source.deleted_objects.push(DeletedObject {
        uuid: uid(0x0a),
        deleted_at: t1(),
        unknown: Vec::new(),
    });
    source.root.groups[0].entries.clear();
    source.meta.custom_data.items.push(cd("X", "1"));
    let mut other = source.duplicate();
    other.root.uuid = uid(0x65);
    for kind in [
        Kind::Window,
        Kind::CommandLine,
        Kind::ChangeOnDisk,
        Kind::ConflictCopy,
        Kind::ServerSync,
        Kind::RemoteSync,
    ] {
        let mut t = target.duplicate();
        merge(&mut t, &other, &Options::new(kind), t9()).unwrap();
        assert_eq!(t.root.all_entries().count(), 1, "{kind:?}");
        assert!(t.deleted_objects.is_empty());
        let mut t = target.duplicate();
        merge(&mut t, &source, &Options::new(kind), t9()).unwrap();
        assert_eq!(t.root.all_entries().count(), 0, "same vault {kind:?}");
        assert_eq!(t.deleted_objects.len(), 1);
        assert!(t.meta.custom_data.get("X").is_some());
        // MOD-11.31: Merge anyway on a retired copy erases nothing and
        // takes no vault custom data.
        let mut t = target.duplicate();
        let o = Options {
            retired: true,
            ..Options::new(kind)
        };
        merge(&mut t, &source, &o, t9()).unwrap();
        assert_eq!(t.root.all_entries().count(), 1, "retired {kind:?}");
        assert!(t.deleted_objects.is_empty());
        assert!(t.meta.custom_data.get("X").is_none(), "retired {kind:?}");
    }
    let mut shared = target.duplicate();
    merge(
        &mut shared,
        &source,
        &Options {
            target_start: Some(uid(0x02)),
            ..Options::new(Kind::SharedImport)
        },
        t9(),
    )
    .unwrap();
    assert_eq!(shared.root.all_entries().count(), 0, "synchronize erases");
    let _ = &mut target;
}

#[test]
fn mod11_02_order_of_steps() {
    // Entries and groups, then deletions, then metadata (T49 and icons).
    let mut target = grp(0x01, "Root", t0());
    target.groups.push(grp(0x20, "S", t0()));
    let mut t = vault(target);
    let mut s_root = grp(0x66, "Share", t0());
    s_root.entries.push(ent(0x0a, "X", "p", t0()));
    let mut s = vault(s_root);
    s.deleted_objects.push(DeletedObject {
        uuid: uid(0x0a),
        deleted_at: t1(),
        unknown: Vec::new(),
    });
    s.meta.custom_icons.push(CustomIcon {
        uuid: uid(0x34),
        name: String::new(),
        last_modified: None,
        data: b"icon".to_vec(),
        unknown: Vec::new(),
    });
    let m = run(
        &mut t,
        &s,
        Options {
            target_start: Some(uid(0x20)),
            ..Options::new(Kind::SharedImport)
        },
    );
    assert_eq!(
        kinds(&m.changes),
        [
            ChangeKind::Added,
            ChangeKind::Deleted,
            ChangeKind::Metadata,
            ChangeKind::Metadata
        ]
    );
    assert!(t.root.all_entries().next().is_none());
}

#[test]
fn mod11_03_walk_order() {
    // T46.
    let mut root = grp(0x01, "Root", t0());
    root.entries.push(ent(0x11, "E1", "p", t0()));
    root.entries.push(ent(0x12, "E2", "p", t0()));
    let mut ga = grp(0x21, "Ga", t0());
    ga.entries.push(ent(0x13, "E3", "p", t0()));
    let mut gb = grp(0x22, "Gb", t0());
    gb.entries.push(ent(0x14, "E4", "p", t0()));
    root.groups.extend([ga, gb]);
    let b = vault(root);
    let mut a = vault(grp(0x01, "Root", t0()));
    let m = run(&mut a, &b, cli());
    let order: Vec<(ChangeKind, Uuid)> =
        m.changes.iter().map(|c| (c.kind, c.id.unwrap())).collect();
    use ChangeKind::Added;
    assert_eq!(
        order,
        [
            (Added, uid(0x11)),
            (Added, uid(0x12)),
            (Added, uid(0x21)),
            (Added, uid(0x13)),
            (Added, uid(0x22)),
            (Added, uid(0x14))
        ]
    );
}

#[test]
fn mod11_04_matching_by_id() {
    // T47: matched anywhere; no move when the target's Loc is newer.
    let mut e = ent(0x0a, "E", "p", t0());
    e.times.location_changed = t2();
    let mut a = two_groups(vec![e]);
    let mut eb = ent(0x0a, "E", "p2", t1());
    eb.times.location_changed = t0();
    let mut b = two_groups(vec![]);
    b.root.groups[1].entries.push(eb);
    run(&mut a, &b, cli());
    assert_eq!(group_of(&a, 0x0a), uid(0x02));
    assert_eq!(pw(find(&a, 0x0a)), "p2");
    assert_eq!(a.root.all_entries().count(), 1);
    // T52 (LD-61): a share matches ids only inside the shared group.
    let mut root = grp(0x01, "Root", t0());
    let mut s = grp(0x20, "S", t0());
    s.entries.push(ent(0x0a, "X", "x", t0()));
    let mut g = grp(0x03, "G", t0());
    g.entries.push(ent(0x0b, "Y", "y", t0()));
    root.groups.extend([s, g, grp(0x04, "H", t0())]);
    let mut target = vault(root);
    let mut share_root = grp(0x66, "Share", t0());
    share_root.entries.push(ent(0x0b, "Y", "evil", t2()));
    let mut h = grp(0x04, "H", t2());
    h.entries.push(ent(0x0c, "Z", "z", t2()));
    share_root.groups.push(h);
    let share = vault(share_root);
    let m = run(
        &mut target,
        &share,
        Options {
            target_start: Some(uid(0x20)),
            ..Options::new(Kind::SharedImport)
        },
    );
    assert_eq!(pw(find(&target, 0x0b)), "y");
    assert_eq!(group_of(&target, 0x0b), uid(0x03));
    assert!(target.root.all_entries().all(|e| e.uuid != uid(0x0c)));
    assert_eq!(
        m.changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Conflict)
            .count(),
        2,
        "Y and H"
    );
}

#[test]
fn mod11_05_new_entry() {
    // T03.
    let mut a = two_groups(vec![]);
    let b = two_groups(vec![ent(0x0d, "OnlyB", "p", t0())]);
    let m = run(&mut a, &b, cli());
    assert_eq!(group_of(&a, 0x0d), uid(0x02));
    assert_eq!(find(&a, 0x0d).times.last_modification, t0());
    assert_eq!(
        m.changes[0].line(),
        "\tAdded: '/Root/G1'/'OnlyB' [{0d0d0d0d-0d0d-0d0d-0d0d-0d0d0d0d0d0d}]"
    );
    // T04: the history is not cut to the target's limits.
    let mut a = two_groups(vec![]);
    a.meta.history_max_items = 2;
    let mut e = ent(0x0d, "NewWithHist", "p", t3());
    for d in 1..=4 {
        e.history.push(item(
            0x0d,
            "NewWithHist",
            &format!("h{d}"),
            at(2026, 1, d, 0, 0, 0),
        ));
    }
    let b = two_groups(vec![e]);
    run(&mut a, &b, cli());
    assert_eq!(find(&a, 0x0d).history.len(), 4);
    // A second merge stays empty (T51 b).
    assert!(run(&mut a, &b, cli()).changes.is_empty());
    assert_eq!(find(&a, 0x0d).history.len(), 4);
}

#[test]
fn mod11_06_new_group() {
    // T20: records in order, the new group takes the source's Loc.
    let mut a = vault(grp(0x01, "Root", t0()));
    let mut root = grp(0x01, "Root", t0());
    let mut ng = grp(0x06, "NewGroup", t0());
    ng.times.location_changed = t1();
    let mut child = grp(0x07, "NewChild", t0());
    child.entries.push(ent(0x0e, "Deep", "p", t0()));
    ng.groups.push(child);
    root.groups.push(ng);
    let b = vault(root);
    let m = run(&mut a, &b, cli());
    let rec: Vec<(ChangeKind, Uuid, Vec<String>)> = m
        .changes
        .iter()
        .map(|c| (c.kind, c.id.unwrap(), c.details.clone()))
        .collect();
    assert_eq!(
        rec,
        [
            (ChangeKind::Added, uid(0x06), vec!["0 entries".to_owned()]),
            (ChangeKind::Added, uid(0x07), vec!["1 entries".to_owned()]),
            (ChangeKind::Added, uid(0x0e), vec![])
        ]
    );
    let g = a.root.find_group(uid(0x06)).unwrap();
    assert_eq!(g.times.location_changed, t1());
    assert!(g.find_group(uid(0x07)).is_some());
}

#[test]
fn mod11_07_entry_moves() {
    // T12: moved, Mod untouched, Loc from the source (D-11-8).
    let mut a = two_groups(vec![ent(0x0a, "Mail", "p", t0())]);
    let mut moved = ent(0x0a, "Mail", "p", t0());
    moved.times.location_changed = t1();
    let mut b = two_groups(vec![]);
    b.root.groups[1].entries.push(moved);
    let m = run(&mut a, &b, cli());
    assert_eq!(group_of(&a, 0x0a), uid(0x03));
    let e = find(&a, 0x0a);
    assert_eq!(
        (e.times.last_modification, e.times.location_changed),
        (t0(), t1())
    );
    assert_eq!(e.previous_parent, Some(uid(0x02)));
    assert_eq!(m.changes[0].kind, ChangeKind::Moved);
    assert_eq!(m.changes[0].details, ["/Root/G1"]);
    // T13: the target moved later; the source wins on Mod and its older Loc
    // comes with it (LD-68); the entry stays where the target put it. B's
    // root id(65) keeps this merge from being a same-vault one.
    let t13 = |b_root: u8| {
        let mut root = grp(0x01, "Root", t0());
        root.groups.push(grp(0x02, "G1", t0()));
        let mut g3 = grp(0x04, "G3", t0());
        let mut te = ent(0x0a, "Mail", "p", t0());
        te.times.location_changed = t2();
        g3.entries.push(te);
        root.groups.push(g3);
        let mut a = vault(root);
        let mut se = ent(0x0a, "Mail", "p", t1());
        set(&mut se, "UserName", "username");
        se.times.location_changed = t0();
        let mut b = two_groups(vec![se]);
        b.root.uuid = uid(b_root);
        run(&mut a, &b, cli());
        assert_eq!(group_of(&a, 0x0a), uid(0x04));
        let e = find(&a, 0x0a);
        (e.value("UserName").to_owned(), e.times.location_changed)
    };
    assert_eq!(t13(0x65), ("username".to_owned(), t0()));
    // F-152: in a same-vault merge the entry keeps the later Loc, T2.
    assert_eq!(t13(0x01), ("username".to_owned(), t2()));
}

#[test]
fn mod11_08_group_moves() {
    // T14: moved once, then nothing.
    let mut root = grp(0x01, "Root", t0());
    let mut g1 = grp(0x02, "G1", t0());
    g1.groups.push(grp(0x04, "G3", t0()));
    root.groups.extend([g1, grp(0x03, "G2", t0())]);
    let mut a = vault(root);
    let mut root = grp(0x01, "Root", t0());
    let mut g2 = grp(0x03, "G2", t0());
    let mut g3 = grp(0x04, "G3", t0());
    g3.times.location_changed = t1();
    g2.groups.push(g3);
    root.groups.extend([grp(0x02, "G1", t0()), g2]);
    let b = vault(root);
    let m = run(&mut a, &b, cli());
    let g2 = a.root.find_group(uid(0x03)).unwrap();
    let g3 = g2.find_group(uid(0x04)).unwrap();
    assert_eq!(
        (g3.times.location_changed, g3.previous_parent),
        (t1(), Some(uid(0x02)))
    );
    assert_eq!(m.changes[0].kind, ChangeKind::Moved);
    assert_eq!(
        m.changes[0].details,
        ["/Root/G1"],
        "names the previous parent"
    );
    assert!(run(&mut a, &b, cli()).changes.is_empty());
}

#[test]
fn mod11_09_no_cycles_root_stays() {
    // T15: the move cycle finishes with one Conflict and nothing lost.
    let mut root = grp(0x01, "Root", t0());
    let mut x = grp(0x02, "X", t0());
    let mut p = grp(0x03, "P", t0());
    p.times.location_changed = at(2026, 6, 1, 0, 0, 0);
    p.entries.push(ent(0x0a, "InP", "p", t0()));
    x.entries.push(ent(0x0b, "InX", "p", t0()));
    x.groups.push(p);
    root.groups.push(x);
    let mut a = vault(root);
    let mut root = grp(0x01, "Root", t0());
    let mut p = grp(0x03, "P", t0());
    let mut x = grp(0x02, "X", t0());
    x.times.location_changed = t3();
    x.entries.push(ent(0x0b, "InX", "p", t0()));
    p.entries.push(ent(0x0a, "InP", "p", t0()));
    p.groups.push(x);
    root.groups.push(p);
    let b = vault(root);
    let started = std::time::Instant::now();
    let m = run(&mut a, &b, cli());
    assert!(started.elapsed().as_secs() < 1);
    let x = a
        .root
        .groups
        .iter()
        .find(|g| g.uuid == uid(0x02))
        .expect("X under root");
    assert!(
        x.groups.iter().any(|g| g.uuid == uid(0x03)),
        "root → X → P unchanged"
    );
    assert_eq!(
        m.changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Conflict)
            .count(),
        1
    );
    assert_eq!(a.root.all_entries().count(), 2);
    larsal_model::invariants::check(&a).unwrap();
    // T16: a source child group with the target root's id merges into the
    // root; the root is not moved and keeps its name.
    let mut a = vault(grp(0x01, "RootA", t0()));
    let mut root = grp(0x65, "Other", t1());
    let mut g = grp(0x01, "G", t2());
    g.entries.push(ent(0x0e, "Z", "p", t0()));
    root.groups.push(g);
    let b = vault(root);
    run(&mut a, &b, cli());
    assert_eq!(a.root.name, "RootA");
    assert!(a.root.entries.iter().any(|e| e.uuid == uid(0x0e)));
    assert_eq!(
        a.root
            .subtree()
            .iter()
            .filter(|g| g.uuid == uid(0x01))
            .count(),
        1
    );
}

#[test]
fn mod11_10_group_fields() {
    // T17 (Larsal, D-11-3).
    let mut a = two_groups(vec![]);
    let g = &mut a.root.groups[0];
    g.notes = "old".into();
    g.icon = Icon::Standard(5);
    g.times.last_modification = t1();
    g.tags = "x".into();
    g.custom_data.items.push(CustomDataItem {
        key: "k".into(),
        value: larsal_crypto::secret::SecretString::new("target".into()),
        last_modified: None,
        unknown: Vec::new(),
    });
    let mut b = two_groups(vec![]);
    let g = &mut b.root.groups[0];
    g.name = "G1-renamed".into();
    g.notes = "new".into();
    g.icon = Icon::Custom(uid(0x34));
    g.times.last_modification = t2();
    g.times.expires = true;
    g.times.expiry = t3();
    g.tags = "y".into();
    g.custom_data.items.push(CustomDataItem {
        key: "k".into(),
        value: larsal_crypto::secret::SecretString::new("source".into()),
        last_modified: None,
        unknown: Vec::new(),
    });
    let m = run(&mut a, &b, cli());
    let g = &a.root.groups[0];
    assert_eq!(
        (g.name.as_str(), g.notes.as_str(), g.icon),
        ("G1-renamed", "new", Icon::Custom(uid(0x34)))
    );
    assert_eq!(
        (g.times.expires, g.times.expiry, g.tags.as_str()),
        (true, t3(), "y")
    );
    assert_eq!(g.custom_data.get("k"), Some("source"));
    assert_eq!(g.times.last_modification, t2());
    assert_eq!(g.times.creation, t0(), "creation never copied");
    assert_eq!(m.changes[0].kind, ChangeKind::Modified);
    // T18: icon 0 is copied in Larsal.
    let mut a = two_groups(vec![]);
    a.root.groups[0].icon = Icon::Standard(7);
    let mut b = two_groups(vec![]);
    b.root.groups[0].icon = Icon::Standard(0);
    b.root.groups[0].times.last_modification = t1();
    run(&mut a, &b, cli());
    assert_eq!(a.root.groups[0].icon, Icon::Standard(0));
    // T19: the shared-group item never comes into an existing group.
    let share: String = [
        0x4Bu8, 0x65, 0x65, 0x53, 0x68, 0x61, 0x72, 0x65, 0x2F, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65,
        0x6E, 0x63, 0x65,
    ]
    .iter()
    .map(|b| char::from(*b))
    .collect();
    let mut a = two_groups(vec![]);
    let mut b = two_groups(vec![]);
    b.root.groups[0].custom_data.items.push(CustomDataItem {
        key: share.clone(),
        value: larsal_crypto::secret::SecretString::new("path".into()),
        last_modified: None,
        unknown: Vec::new(),
    });
    b.root.groups[0].name = "renamed".into();
    b.root.groups[0].times.last_modification = t1();
    run(&mut a, &b, cli());
    assert!(a.root.groups[0].custom_data.get(&share).is_none());
    assert_eq!(a.root.groups[0].name, "renamed");
    // Equal or older Mod: nothing.
    let mut a = two_groups(vec![]);
    let mut b = two_groups(vec![]);
    b.root.groups[0].name = "same time".into();
    assert!(run(&mut a, &b, cli()).changes.is_empty());
}

#[test]
fn mod11_11_entry_conflict() {
    // T01: source newer; the entry keeps its position (D-11-7).
    let mut a = two_groups(vec![
        ent(0x09, "First", "x", t0()),
        {
            let mut e = ent(0x0a, "Mail", "a1", t1());
            e.history.push(item(0x0a, "Mail", "a0", t0()));
            e
        },
        ent(0x0b, "Last", "x", t0()),
    ]);
    let mut e = ent(0x0a, "Mail", "a2", t2());
    e.history.push(item(0x0a, "Mail", "a0", t0()));
    let b = two_groups(vec![
        ent(0x09, "First", "x", t0()),
        e,
        ent(0x0b, "Last", "x", t0()),
    ]);
    let m = run(&mut a, &b, cli());
    let mail = find(&a, 0x0a);
    assert_eq!((pw(mail), mail.times.last_modification), ("a2", t2()));
    assert_eq!(hist(mail), [("a0", t0()), ("a1", t1())]);
    assert_eq!(a.root.groups[0].entries[1].uuid, uid(0x0a), "position kept");
    assert_eq!(m.changes.len(), 1);
    assert_eq!(m.changes[0].details, ["Password", "History"]);
    // T02: target newer.
    let mut te = ent(0x0b, "Bank", "b-target", t2());
    te.history.push(item(0x0b, "Bank", "b0", t0()));
    let mut a = two_groups(vec![te]);
    let mut se = ent(0x0b, "Bank", "b-source", t1());
    se.history.push(item(0x0b, "Bank", "b0", t0()));
    let b = two_groups(vec![se]);
    let m = run(&mut a, &b, cli());
    let bank = find(&a, 0x0b);
    assert_eq!((pw(bank), bank.times.last_modification), ("b-target", t2()));
    assert_eq!(hist(bank), [("b0", t0()), ("b-source", t1())]);
    assert_eq!(m.changes[0].details, ["Password", "History"]);
}

/// T05's vaults with the given item limit.
fn t05(limit: i32) -> (Vault, Vault) {
    let mut mail_a = ent(0x0a, "Mail", "a-target", t1());
    mail_a.history.push(item(0x0a, "Mail", "a0", t0()));
    let mut bank_a = ent(0x0b, "Bank", "b-target", t2());
    bank_a.history.push(item(0x0b, "Bank", "b0", t0()));
    let mut a = two_groups(vec![mail_a, bank_a]);
    a.meta.history_max_items = limit;
    let mut mail_b = ent(0x0a, "Mail", "a-source", t2());
    mail_b.history.push(item(0x0a, "Mail", "a0", t0()));
    let mut bank_b = ent(0x0b, "Bank", "b-source", t1());
    bank_b.history.push(item(0x0b, "Bank", "b0", t0()));
    (a, two_groups(vec![mail_b, bank_b]))
}

#[test]
fn mod11_12_reference_losses_fixed() {
    // T05's reference losses do not happen in Larsal, whatever the limit.
    for limit in [-1, 2, 10] {
        let (mut a, b) = t05(limit);
        run(&mut a, &b, cli());
        assert!(
            find(&a, 0x0a).history.iter().any(|h| pw(h) == "a-target"),
            "{limit}"
        );
        assert!(
            find(&a, 0x0b).history.iter().any(|h| pw(h) == "b-source"),
            "{limit}"
        );
    }
}

#[test]
fn mod11_13_history_join() {
    // T06, limit -1.
    let (mut a, b) = t05(-1);
    let m = run(&mut a, &b, cli());
    assert_eq!(pw(find(&a, 0x0a)), "a-source");
    assert_eq!(hist(find(&a, 0x0a)), [("a0", t0()), ("a-target", t1())]);
    assert_eq!(pw(find(&a, 0x0b)), "b-target");
    assert_eq!(hist(find(&a, 0x0b)), [("b0", t0()), ("b-source", t1())]);
    assert_eq!(m.changes.len(), 2);
    // T07, limit 1: cut from the oldest end; T51 a: a second merge is empty.
    let (mut a, b) = t05(1);
    run(&mut a, &b, cli());
    assert_eq!(hist(find(&a, 0x0a)), [("a-target", t1())]);
    assert_eq!(hist(find(&a, 0x0b)), [("b-source", t1())]);
    assert!(run(&mut a, &b, cli()).changes.is_empty());
    assert_eq!(hist(find(&a, 0x0a)), [("a-target", t1())]);
    // T08, limit 0: histories empty, both reported.
    let (mut a, b) = t05(0);
    let m = run(&mut a, &b, cli());
    assert_eq!(
        (pw(find(&a, 0x0a)), find(&a, 0x0a).history.len()),
        ("a-source", 0)
    );
    assert_eq!(
        (pw(find(&a, 0x0b)), find(&a, 0x0b).history.len()),
        ("b-target", 0)
    );
    assert_eq!(m.changes.len(), 2);
    // T09: access statistics do not make a second item.
    let mut x = ent(0x0a, "Mail", "x", t1());
    x.times.last_access = t3();
    x.times.usage_count = 5;
    let mut a = two_groups(vec![x]);
    let mut y = ent(0x0a, "Mail", "y", t2());
    y.history.push(item(0x0a, "Mail", "x", t1()));
    let b = two_groups(vec![y]);
    run(&mut a, &b, cli());
    let mail = find(&a, 0x0a);
    assert_eq!(pw(mail), "y");
    assert_eq!(hist(mail), [("x", t1())]);
    // T11: same-time history items are all kept, target items first.
    let mut ta = ent(0x0a, "Mail", "pw-target", t1());
    ta.history.push(item(0x0a, "Mail", "h-target", t0()));
    let mut a = two_groups(vec![ta]);
    let mut sb = ent(0x0a, "Mail", "pw-source", t2());
    sb.history.push(item(0x0a, "Mail", "h-source", t0()));
    let b = two_groups(vec![sb]);
    run(&mut a, &b, cli());
    assert_eq!(
        hist(find(&a, 0x0a)),
        [("h-target", t0()), ("h-source", t0()), ("pw-target", t1())]
    );
}

#[test]
fn mod11_14_same_time_different_content() {
    // T10.
    let mut ta = ent(0x0a, "Mail", "pw-target", t1());
    ta.history.push(item(0x0a, "Mail", "h-target", t0()));
    let mut a = two_groups(vec![ta]);
    let mut sb = ent(0x0a, "Mail", "pw-source", t1());
    sb.history.push(item(0x0a, "Mail", "h-source", t0()));
    let b = two_groups(vec![sb]);
    let m = run(&mut a, &b, cli());
    let mail = find(&a, 0x0a);
    assert_eq!(pw(mail), "pw-target");
    assert_eq!(
        hist(mail),
        [("h-target", t0()), ("h-source", t0()), ("pw-source", t1())]
    );
    assert_eq!(kinds(&m.changes), [ChangeKind::Conflict]);
    assert!(run(&mut a, &b, cli()).changes.is_empty(), "recorded once");
}

#[test]
fn mod11_15_missing_objects_and_deletions() {
    // T21 (LD-265): deleted for good in the target. A same-vault merge
    // keeps it deleted, with an empty change list (MOD-11.26); a copy
    // changed after the deletion comes back; another vault (root id(65))
    // brings it back and the item stays (the reference).
    let t21 = |m: Time| {
        let mut a = two_groups(vec![]);
        a.deleted_objects.push(DeletedObject {
            uuid: uid(0x0c),
            deleted_at: t1(),
            unknown: Vec::new(),
        });
        let mut b = two_groups(vec![]);
        b.root.groups[1]
            .entries
            .push(ent(0x0c, "DeletedInA", "p", m));
        (a, b)
    };
    let (mut a, b) = t21(t0());
    let before = a.duplicate();
    let m = run(&mut a, &b, cli());
    assert!(m.changes.is_empty(), "{:?}", m.changes);
    assert!(a == before, "A not changed");
    let (mut a, b) = t21(t2());
    let m = run(&mut a, &b, cli());
    assert_eq!(group_of(&a, 0x0c), uid(0x03));
    assert!(a.deleted_objects.is_empty());
    assert_eq!(kinds(&m.changes), [ChangeKind::Added, ChangeKind::Metadata]);
    let (mut a, mut b) = t21(t0());
    b.root.uuid = uid(0x65);
    run(&mut a, &b, cli());
    assert_eq!(group_of(&a, 0x0c), uid(0x03));
    assert_eq!(a.deleted_objects.len(), 1);
    // Target-only objects stay.
    let mut a = two_groups(vec![ent(0x0d, "OnlyA", "p", t0())]);
    let b = two_groups(vec![]);
    assert!(run(&mut a, &b, cli()).changes.is_empty());
    assert_eq!(a.root.all_entries().count(), 1);
    // T22: an entry in the target's bin moves out by a newer source Loc.
    let mut root = grp(0x01, "Root", t0());
    root.groups.push(grp(0x02, "G", t0()));
    let mut bin = grp(0x5a, "Recycle Bin", t0());
    let mut m = ent(0x0a, "Mail", "p", t0());
    m.times.location_changed = t1();
    bin.entries.push(m);
    root.groups.push(bin);
    let mut a = vault(root);
    a.meta.recycle_bin_enabled = true;
    a.meta.recycle_bin = Some(uid(0x5a));
    let mut root = grp(0x01, "Root", t0());
    let mut g = grp(0x02, "G", t0());
    g.entries.push(ent(0x0a, "Mail", "edited", t2()));
    root.groups.push(g);
    let b = vault(root);
    let m = run(&mut a, &b, cli());
    assert_eq!(group_of(&a, 0x0a), uid(0x02));
    assert_eq!(pw(find(&a, 0x0a)), "edited");
    assert_eq!(kinds(&m.changes), [ChangeKind::Moved, ChangeKind::Modified]);
    // T42: synchronize erases only inside the shared group.
    let mut root = grp(0x01, "Root", t0());
    let mut s = grp(0x20, "S", t0());
    s.entries.push(ent(0x0a, "X", "p", t0()));
    root.groups.push(s);
    root.entries.push(ent(0x0b, "Y", "p", t0()));
    let mut target = vault(root);
    let mut share = vault(grp(0x66, "Share", t0()));
    for b in [0x0a, 0x0b] {
        share.deleted_objects.push(DeletedObject {
            uuid: uid(b),
            deleted_at: t1(),
            unknown: Vec::new(),
        });
    }
    run(
        &mut target,
        &share,
        Options {
            target_start: Some(uid(0x20)),
            ..Options::new(Kind::SharedImport)
        },
    );
    assert!(target.root.all_entries().all(|e| e.uuid != uid(0x0a)));
    assert!(target.root.all_entries().any(|e| e.uuid == uid(0x0b)));
    // The share's item for Y, outside S, is dropped (SI-09, MOD-11.15).
    assert_eq!(listed(&target), [(uid(0x0a), t1())]);
    // The target's own item for Y, live outside S (FMT-15.5), stays as it
    // was in a share import (MOD-11.15, FMT-15.11).
    target.deleted_objects.insert(0, gone(0x0b, t1()));
    run(
        &mut target,
        &share,
        Options {
            target_start: Some(uid(0x20)),
            ..Options::new(Kind::SharedImport)
        },
    );
    assert!(has_entry(&target, 0x0b));
    assert_eq!(listed(&target), [(uid(0x0b), t1()), (uid(0x0a), t1())]);
    // FMT-15 15-16: a deleted group that still holds a newer entry stays.
    let mut root = grp(0x01, "Root", t0());
    let mut s = grp(0x20, "S", t0());
    let mut g = grp(0x05, "G", t0());
    g.entries.push(ent(0x0e, "Z", "p", t2()));
    s.groups.push(g);
    root.groups.push(s);
    let mut target = vault(root);
    let mut share = vault(grp(0x66, "Share", t0()));
    share.deleted_objects.push(DeletedObject {
        uuid: uid(0x05),
        deleted_at: t1(),
        unknown: Vec::new(),
    });
    run(
        &mut target,
        &share,
        Options {
            target_start: Some(uid(0x20)),
            ..Options::new(Kind::SharedImport)
        },
    );
    assert!(target.root.find_group(uid(0x05)).is_some());
    assert!(target.deleted_objects.is_empty());
}

#[test]
fn mod11_16_recycle_bins() {
    // T23: the source bin maps to the target bin (D-11-4).
    let mut root = grp(0x01, "Root", t0());
    let mut g = grp(0x02, "G", t0());
    g.entries.push(ent(0x0b, "Bank", "p", t0()));
    root.groups.extend([g, grp(0x5a, "Recycle Bin", t0())]);
    let mut a = vault(root);
    a.meta.recycle_bin_enabled = true;
    a.meta.recycle_bin = Some(uid(0x5a));
    let mut root = grp(0x01, "Root", t0());
    let mut bin = grp(0x5b, "Recycle Bin", t0());
    let mut bank = ent(0x0b, "Bank", "p", t0());
    bank.times.location_changed = t2();
    bin.entries.push(bank);
    root.groups.push(bin);
    let mut b = vault(root);
    b.meta.recycle_bin_enabled = true;
    b.meta.recycle_bin = Some(uid(0x5b));
    run(&mut a, &b, cli());
    assert!(a.root.find_group(uid(0x5b)).is_none());
    assert_eq!(group_of(&a, 0x0b), uid(0x5a));
    assert_eq!(a.meta.recycle_bin, Some(uid(0x5a)));
    // T24: a target with the bin on and no bin group gets one.
    let mut root = grp(0x01, "Root", t0());
    let mut g = grp(0x02, "G", t0());
    g.entries.push(ent(0x0b, "Bank", "p", t0()));
    root.groups.push(g);
    let mut a = vault(root);
    a.meta.recycle_bin_enabled = true;
    run(&mut a, &b, cli());
    let bin = recycle::bin_id(&a).expect("a bin was made");
    assert_eq!(group_of(&a, 0x0b), bin);
    // With the bin off, the source bin comes as a normal group.
    let mut root = grp(0x01, "Root", t0());
    let mut g = grp(0x02, "G", t0());
    g.entries.push(ent(0x0b, "Bank", "p", t0()));
    root.groups.push(g);
    let mut a = vault(root);
    run(&mut a, &b, cli());
    assert!(a.root.find_group(uid(0x5b)).is_some());
    assert_eq!(a.meta.recycle_bin, None);
}

fn icon(b: u8, data: &[u8]) -> CustomIcon {
    CustomIcon {
        uuid: uid(b),
        name: String::new(),
        last_modified: None,
        data: data.to_vec(),
        unknown: Vec::new(),
    }
}

#[test]
fn mod11_17_custom_icons() {
    // T25.
    let mut a = two_groups(vec![]);
    a.meta.custom_icons = vec![icon(0x32, b"png"), icon(0x33, b"AAA")];
    let mut b = two_groups(vec![]);
    b.meta.custom_icons = vec![icon(0x33, b"BBB"), icon(0x34, b"png")];
    let m = run(&mut a, &b, cli());
    let icons: Vec<(Uuid, &[u8])> = a
        .meta
        .custom_icons
        .iter()
        .map(|i| (i.uuid, i.data.as_slice()))
        .collect();
    assert_eq!(
        icons,
        [
            (uid(0x32), &b"png"[..]),
            (uid(0x33), b"AAA"),
            (uid(0x34), b"png")
        ]
    );
    assert_eq!(m.changes.len(), 1);
    // T36: the metadata line.
    assert_eq!(
        m.changes[0].line(),
        "\tMetadata:  (new icon 34343434343434343434343434343434)"
    );
}

fn cd(key: &str, value: &str) -> CustomDataItem {
    CustomDataItem {
        key: key.into(),
        value: larsal_crypto::secret::SecretString::new(value.into()),
        last_modified: None,
        unknown: Vec::new(),
    }
}

fn browser_key(name: &str) -> String {
    let mut k: String = [
        0x4Bu8, 0x50, 0x58, 0x43, 0x5F, 0x42, 0x52, 0x4F, 0x57, 0x53, 0x45, 0x52, 0x5F,
    ]
    .iter()
    .map(|b| char::from(*b))
    .collect();
    k.push_str(name);
    k
}

#[test]
fn mod11_18_vault_custom_data() {
    // T27: the stored times decide; the target is newer: nothing.
    let mut a = two_groups(vec![]);
    a.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2024 GMT"),
        cd("TargetOnly", "x"),
        cd("Shared", "t"),
        cd("_CREATED_demo", "d"),
    ];
    let mut b = two_groups(vec![]);
    b.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2018 GMT"),
        cd("SourceOnly", "y"),
        cd("Shared", "s"),
        cd("Empty", ""),
    ];
    for _ in 0..3 {
        assert!(run(&mut a, &b, cli()).changes.is_empty());
    }
    // T28: the source is newer; protected keys stay; no values recorded.
    let mut a = two_groups(vec![]);
    a.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2018 GMT"),
        cd("_CREATED_demo", "d"),
        cd(&browser_key("demo"), "pk"),
        cd("T-only", "t"),
    ];
    let mut b = two_groups(vec![]);
    b.root.uuid = uid(0x65);
    b.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2024 GMT"),
        cd("New", "n"),
        cd("Empty", ""),
    ];
    let m = run(&mut a, &b, cli());
    let data = &a.meta.custom_data;
    assert_eq!(data.get(&browser_key("demo")), Some("pk"));
    assert!(data.get("_CREATED_demo").is_none() && data.get("T-only").is_none());
    assert_eq!(data.get("New"), Some("n"));
    assert!(data.get("Empty").is_none());
    let new = data.items.iter().find(|i| i.key == "New").unwrap();
    assert_eq!(new.last_modified, Some(t9()));
    assert_eq!(
        data.get("_LAST_MODIFIED"),
        Some(larsal_core::merge::last_modified_text(t9()).as_str())
    );
    assert_eq!(m.changes.len(), 3);
    assert!(
        m.changes
            .iter()
            .all(|c| !c.line().contains("pk") && !c.line().contains("\"n\""))
    );
    // T29: the skip option (a shared import or the import wizard).
    let mut a2 = two_groups(vec![]);
    a2.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2018 GMT"),
        cd("T-only", "t"),
    ];
    b.meta.custom_icons.push(icon(0x34, b"png"));
    merge(&mut a2, &b, &Options::new(Kind::ImportWizard), t9()).unwrap();
    assert_eq!(a2.meta.custom_data.get("T-only"), Some("t"));
    assert_eq!(a2.meta.custom_icons.len(), 1, "icons still added");
    // T56: browser keys copy only in a same-vault merge.
    let mut a = two_groups(vec![]);
    a.meta.custom_data.items = vec![cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2018 GMT")];
    let mut b = two_groups(vec![]);
    b.root.uuid = uid(0x65);
    b.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2024 GMT"),
        cd(&browser_key("demo"), "pk"),
    ];
    let mut other = a.duplicate();
    run(&mut other, &b, cli());
    assert!(other.meta.custom_data.get(&browser_key("demo")).is_none());
    b.root.uuid = uid(0x01);
    run(&mut a, &b, window());
    assert_eq!(a.meta.custom_data.get(&browser_key("demo")), Some("pk"));
    // A target without `_LAST_MODIFIED`: the source wins.
    let mut a = two_groups(vec![]);
    a.meta.custom_data.items = vec![cd("Old", "o")];
    let mut b = two_groups(vec![]);
    b.meta.custom_data.items = vec![cd("Fresh", "f")];
    run(&mut a, &b, cli());
    assert_eq!(a.meta.custom_data.get("Fresh"), Some("f"));
    // The FMT-14.18 text form round-trips.
    let when = at(2026, 10, 4, 19, 17, 16);
    assert_eq!(
        larsal_core::merge::last_modified_text(when),
        "Sun Oct 4 19:17:16 2026 GMT"
    );
    assert_eq!(
        larsal_core::merge::parse_last_modified("Sun Oct 4 19:17:16 2026 GMT"),
        Some(when)
    );
    assert_eq!(
        larsal_core::merge::parse_last_modified("So. Okt. 4 19:17:16 2026 GMT"),
        None
    );
}

/// A same-vault pair: root id(01) on both sides.
fn same_vault_pair() -> (Vault, Vault) {
    (two_groups(vec![]), two_groups(vec![]))
}

#[test]
fn mod11_19_other_metadata() {
    // T30: different vaults keep the target's metadata.
    let (mut a, mut b) = same_vault_pair();
    a.meta.name = "Demo".into();
    a.meta.history_max_items = 10;
    b.root.uuid = uid(0x65);
    b.meta.name = "Renamed".into();
    b.meta.name_changed = t2();
    b.meta.history_max_items = 5;
    b.meta.settings_changed = t2();
    assert!(run(&mut a, &b, cli()).changes.is_empty());
    assert_eq!(
        (a.meta.name.as_str(), a.meta.history_max_items),
        ("Demo", 10)
    );
    // T31: same vault, each value by its own time.
    let (mut a, mut b) = same_vault_pair();
    a.meta.name = "Demo".into();
    a.meta.settings_changed = t1();
    a.meta.history_max_items = 10;
    b.meta.name = "Renamed".into();
    b.meta.name_changed = t2();
    b.meta.history_max_items = 5;
    let m = run(&mut a, &b, window());
    assert_eq!(
        (a.meta.name.as_str(), a.meta.name_changed),
        ("Renamed", t2())
    );
    assert_eq!(a.meta.history_max_items, 10);
    assert_eq!(m.changes.len(), 1);
    // T53: no downgrade (LD-60).
    let (mut a, mut b) = same_vault_pair();
    a.encryption.kdf = Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: 10,
        memory_kib: 65_536,
        lanes: 2,
    };
    a.meta.memory_protection.notes = true;
    a.meta.history_max_items = 10;
    b.encryption.kdf = Kdf::AesKdf { rounds: 60_000 };
    b.meta.memory_protection.notes = false;
    b.meta.memory_protection.url = true;
    b.meta.history_max_items = 5;
    b.meta.settings_changed = t2();
    let m = run(&mut a, &b, window());
    assert!(matches!(
        a.encryption.kdf,
        Kdf::Argon2 {
            iterations: 10,
            memory_kib: 65_536,
            ..
        }
    ));
    assert!(a.meta.memory_protection.notes && a.meta.memory_protection.url);
    assert_eq!(
        (a.meta.history_max_items, a.meta.settings_changed),
        (5, t2())
    );
    let conflicts: Vec<&Change> = m
        .changes
        .iter()
        .filter(|c| c.kind == ChangeKind::Conflict)
        .collect();
    assert_eq!(conflicts.len(), 2);
    assert!(
        conflicts
            .iter()
            .all(|c| c.object == Object::Vault && !c.line().contains("60000"))
    );
    assert!(
        run(&mut a, &b, window()).changes.is_empty(),
        "the next merge does not ask again"
    );
    // T54: a raise is taken.
    let (mut a, mut b) = same_vault_pair();
    a.encryption.kdf = Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: 10,
        memory_kib: 65_536,
        lanes: 2,
    };
    b.encryption.kdf = Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: 12,
        memory_kib: 131_072,
        lanes: 2,
    };
    b.encryption.cipher = Cipher::ChaCha20;
    b.meta.settings_changed = t2();
    let m = run(&mut a, &b, window());
    assert_eq!(a.encryption.kdf, b.encryption.kdf);
    assert_eq!(a.encryption.cipher, Cipher::ChaCha20);
    assert!(m.changes.iter().all(|c| c.kind != ChangeKind::Conflict));
    // T55 and T32: the key needs the user, or a change on disk.
    let key_pair = || {
        let (a, mut b) = same_vault_pair();
        b.meta.master_key_changed = t2();
        (a, b)
    };
    let (mut a, b) = key_pair();
    let m = run(&mut a, &b, window());
    assert!(m.key_taken);
    assert_eq!(a.meta.master_key_changed, t2());
    let (mut a, b) = key_pair();
    let no = merge(&mut a, &b, &Options::new(Kind::Window), t9()).unwrap();
    assert!(!no.key_taken && a.meta.master_key_changed == t0());
    assert_eq!(kinds(&no.changes), [ChangeKind::Conflict]);
    let (mut a, b) = key_pair();
    let line = run(&mut a, &b, cli());
    assert!(!line.key_taken && a.meta.master_key_changed == t0());
    let (mut a, b) = key_pair();
    let disk = run(&mut a, &b, Options::new(Kind::ChangeOnDisk));
    assert!(disk.key_taken && a.meta.master_key_changed == t2());
    // T58 (LD-62): equal times keep the flag when either side has it.
    for (fa, fb) in [(true, false), (false, true)] {
        let (mut a, mut b) = same_vault_pair();
        a.meta.master_key_change_force_once = fa;
        b.meta.master_key_change_force_once = fb;
        let m = run(&mut a, &b, window());
        assert!(a.meta.master_key_change_force_once && !m.key_taken);
    }
    // The recycle bin group needs to exist in the merged target.
    let (mut a, mut b) = same_vault_pair();
    b.meta.recycle_bin = Some(uid(0x77));
    b.meta.recycle_bin_changed = t2();
    run(&mut a, &b, window());
    assert_eq!(a.meta.recycle_bin, None);
}

#[test]
fn mod11_20_root_same_vault() {
    // T33.
    let (mut a, mut b) = same_vault_pair();
    b.root.name = "Home".into();
    b.root.times.last_modification = t1();
    run(&mut a, &b, window());
    assert_eq!(
        (a.root.name.as_str(), a.root.times.last_modification),
        ("Home", t1())
    );
    let (mut a, mut b) = same_vault_pair();
    b.root.uuid = uid(0x65);
    b.root.name = "Home".into();
    b.root.times.last_modification = t1();
    run(&mut a, &b, window());
    assert_eq!(a.root.name, "Root");
    // T57: a share whose root has the target root's id changes nothing of
    // the vault; its entries go into the shared group.
    let mut root = grp(0x01, "Root", t0());
    root.groups.push(grp(0x20, "S", t0()));
    let mut target = vault(root);
    target.meta.name = "Demo".into();
    let mut share_root = grp(0x01, "Evil", t3());
    share_root.entries.push(ent(0x0a, "E", "p", t0()));
    let mut share = vault(share_root);
    share.meta.name = "Evil".into();
    share.meta.name_changed = t3();
    share.meta.settings_changed = t3();
    share.meta.history_max_items = 1;
    share.meta.master_key_changed = t3();
    run(
        &mut target,
        &share,
        Options {
            target_start: Some(uid(0x20)),
            ..Options::new(Kind::SharedImport)
        },
    );
    assert_eq!(
        (target.root.name.as_str(), target.meta.name.as_str()),
        ("Root", "Demo")
    );
    assert_eq!(
        (
            target.meta.history_max_items,
            target.meta.master_key_changed
        ),
        (10, t0())
    );
    assert_eq!(group_of(&target, 0x0a), uid(0x20));
}

#[test]
fn mod11_21_times_untouched() {
    // T34: no object gets the merge time.
    let mut a = two_groups(vec![ent(0x0a, "Mail", "a1", t1())]);
    let mut b = two_groups(vec![
        ent(0x0a, "Mail", "a2", t2()),
        ent(0x0b, "New", "n", t0()),
    ]);
    b.root.groups[0].name = "renamed".into();
    b.root.groups[0].times.last_modification = t2();
    run(&mut a, &b, cli());
    for g in a.root.subtree() {
        assert!(
            g.times.last_modification != t9()
                && g.times.last_access != t9()
                && g.times.location_changed != t9()
        );
        for e in &g.entries {
            assert!(
                e.times.last_modification != t9()
                    && e.times.last_access != t9()
                    && e.times.location_changed != t9()
            );
        }
    }
    assert!(a.deleted_objects.is_empty());
}

#[test]
fn mod11_22_ids_of_the_other_kind() {
    // T43.
    let mut root = grp(0x01, "Root", t0());
    root.groups.push(grp(0x0a, "G", t0()));
    let mut a = vault(root);
    let mut root = grp(0x01, "Root", t0());
    root.entries.push(ent(0x0a, "E", "p", t0()));
    let b = vault(root);
    run(&mut a, &b, cli());
    assert_eq!(group_of(&a, 0x0a), uid(0x01));
    assert_eq!(a.root.find_group(uid(0x0a)).unwrap().name, "G");
    larsal_model::invariants::check(&a).unwrap();
}

#[test]
fn mod11_23_unknown_parts() {
    // T44 and T59: kept, and the remembered version rises (LD-68).
    let mut a = two_groups(vec![]);
    a.read_version = Some(FileVersion { major: 4, minor: 0 });
    let mut n = ent(0x0e, "N", "p", t0());
    n.unknown.push(UnknownElement {
        name: "Ext".into(),
        attributes: Vec::new(),
        content: vec![larsal_model::UnknownNode::Text("1".into())],
    });
    let mut b = two_groups(vec![n]);
    b.read_version = Some(FileVersion { major: 4, minor: 1 });
    run(&mut a, &b, cli());
    assert_eq!(find(&a, 0x0e).unknown.len(), 1);
    assert_eq!(a.read_version, Some(FileVersion { major: 4, minor: 1 }));
    // Without unknown parts the version stays.
    let mut a = two_groups(vec![]);
    a.read_version = Some(FileVersion { major: 4, minor: 0 });
    run(&mut a, &b.duplicate(), cli());
    let mut c = two_groups(vec![ent(0x0f, "Plain", "p", t0())]);
    c.read_version = Some(FileVersion { major: 4, minor: 1 });
    let mut d = two_groups(vec![]);
    d.read_version = Some(FileVersion { major: 4, minor: 0 });
    run(&mut d, &c, cli());
    assert_eq!(d.read_version, Some(FileVersion { major: 4, minor: 0 }));
}

#[test]
fn mod11_24_change_list() {
    // T35: the text line of a Modified entry; no value anywhere.
    let mut a = two_groups(vec![{
        let mut e = ent(0x0a, "Mail", "a1", t1());
        e.history.push(item(0x0a, "Mail", "a0", t0()));
        e
    }]);
    let mut e = ent(0x0a, "Mail", "a2", t2());
    e.history.push(item(0x0a, "Mail", "a0", t0()));
    let b = two_groups(vec![e]);
    let m = run(&mut a, &b, cli());
    let line = m.changes[0].line();
    assert_eq!(
        line,
        "\tModified: '/Root/G1'/'Mail' [{0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a}] (Password, History)"
    );
    assert!(!line.contains("a1") && !line.contains("a2"));
    // Custom fields are listed whenever they differ (D-11-10).
    let mut x = ent(0x0b, "X", "p", t0());
    set(&mut x, "Custom", "1");
    let mut a = two_groups(vec![x]);
    let mut y = ent(0x0b, "X", "q", t1());
    set(&mut y, "Custom", "2");
    let b = two_groups(vec![y]);
    let m = run(&mut a, &b, cli());
    assert_eq!(
        m.changes[0].details,
        ["Password", "Custom attributes", "History"]
    );
}

#[test]
fn mod11_25_dry_run() {
    // T37: the dry run changes nothing and lists the real merge's records
    // (every `run` call checks both); here explicitly.
    let mut a = two_groups(vec![ent(0x0a, "Mail", "a1", t1())]);
    let b = two_groups(vec![ent(0x0a, "Mail", "a2", t2())]);
    let before = a.duplicate();
    let dry = merge(
        &mut a,
        &b,
        &Options {
            dry_run: true,
            ..cli()
        },
        t9(),
    )
    .unwrap();
    assert!(a == before);
    assert_eq!(dry.changes.len(), 1);
    assert!(!dry.key_taken);
}

#[test]
fn mod11_26_no_change() {
    // T39: identical copies.
    let mut a = two_groups(vec![{
        let mut e = ent(0x0a, "Mail", "a1", t1());
        e.history.push(item(0x0a, "Mail", "a0", t0()));
        e
    }]);
    let b = a.duplicate();
    assert!(run(&mut a, &b, window()).changes.is_empty());
    assert!(a == b);
}

#[test]
fn mod11_27_28_window_and_command_line_flows() {
    // The preview is the dry run; its key record says the key will come
    // from the source; the answer is `take_key`. The command line never
    // takes it.
    let (mut a, mut b) = same_vault_pair();
    b.meta.master_key_changed = t2();
    let preview = merge(
        &mut a,
        &b,
        &Options {
            dry_run: true,
            ..window()
        },
        t9(),
    )
    .unwrap();
    assert_eq!(kinds(&preview.changes), [ChangeKind::Metadata]);
    assert!(preview.changes[0].details[0].contains("key"));
    assert_eq!(a.meta.master_key_changed, t0(), "the preview takes nothing");
    let lines: Vec<String> = merge(&mut a.duplicate(), &b, &cli(), t9())
        .unwrap()
        .changes
        .iter()
        .map(Change::line)
        .collect();
    assert_eq!(lines, ["\tConflict:  (vault key not taken)"]);
}

#[test]
fn mod11_29_change_on_disk() {
    // T41: the vault in memory (local new entry N, newer name) is the
    // source; the disk version (gained D) is the target.
    let mut disk = two_groups(vec![ent(0x0d, "D", "p", t1())]);
    disk.meta.name = "Demo".into();
    let mut memory = two_groups(vec![ent(0x0e, "N", "p", t2())]);
    memory.meta.name = "Local".into();
    memory.meta.name_changed = at(2026, 5, 1, 0, 0, 0);
    run(&mut disk, &memory, Options::new(Kind::ChangeOnDisk));
    assert!(disk.root.all_entries().any(|e| e.uuid == uid(0x0d)));
    assert!(disk.root.all_entries().any(|e| e.uuid == uid(0x0e)));
    assert_eq!(disk.meta.name, "Local");
}

// ---------------------------------------------------------------------------
// MOD-11.30 / T45: 1,000 random pairs from a common base.

/// One random change on one side.
#[derive(Debug, Clone)]
enum Op {
    Edit { entry: u8, value: u8, at: u8 },
    Move { entry: u8, group: u8, at: u8 },
    Delete { entry: u8, at: u8 },
    Add { group: u8, at: u8 },
    MoveGroup { group: u8, parent: u8, at: u8 },
    EditGroup { group: u8, value: u8, at: u8 },
    DeleteGroup { group: u8, at: u8 },
}

fn op() -> impl Strategy<Value = Op> {
    // A small time range makes same-second edits on both sides common.
    let at = 1u8..40;
    prop_oneof![
        4 => (0u8..10, any::<u8>(), at.clone()).prop_map(|(entry, value, at)| Op::Edit { entry, value, at }),
        2 => (0u8..10, 0u8..5, at.clone()).prop_map(|(entry, group, at)| Op::Move { entry, group, at }),
        1 => (0u8..10, at.clone()).prop_map(|(entry, at)| Op::Delete { entry, at }),
        1 => (0u8..5, at.clone()).prop_map(|(group, at)| Op::Add { group, at }),
        1 => (0u8..5, 0u8..5, at.clone()).prop_map(|(group, parent, at)| Op::MoveGroup { group, parent, at }),
        1 => (0u8..5, any::<u8>(), at.clone()).prop_map(|(group, value, at)| Op::EditGroup { group, value, at }),
        1 => (0u8..5, at).prop_map(|(group, at)| Op::DeleteGroup { group, at }),
    ]
}

const BIN: u8 = 0x5a;

/// root(01) → groups 0x02..0x06 (0x05 inside 0x04), the bin; entries
/// 0x10..0x19 with one history item each; item limit 10, no size limit.
fn base() -> Vault {
    let mut root = grp(0x01, "Root", t0());
    for g in 0x02..=0x06u8 {
        let mut group = grp(g, &format!("G{g}"), t0());
        for e in 0..2u8 {
            let id = 0x10 + (g - 2) * 2 + e;
            let mut x = ent(id, &format!("E{id}"), "base", t0());
            x.history.push(item(
                id,
                &format!("E{id}"),
                "older",
                at(2025, 12, 1, 0, 0, 0),
            ));
            group.entries.push(x);
        }
        if g == 0x05 {
            root.groups
                .iter_mut()
                .find(|x| x.uuid == uid(0x04))
                .unwrap()
                .groups
                .push(group);
        } else {
            root.groups.push(group);
        }
    }
    root.groups.push(grp(BIN, "Recycle Bin", t0()));
    let mut v = Vault::new(root, t0());
    v.meta.recycle_bin = Some(uid(BIN));
    v.meta.history_max_size = -1;
    v
}

fn apply(v: &mut Vault, side: u8, ops: &[Op]) {
    let when = |at: u8| Time(t1().0 + i64::from(at));
    let entry = |n: u8| uid(0x10 + n % 10);
    let group = |n: u8| uid(0x02 + n % 5);
    let mut added = 0u8;
    for op in ops {
        let _ = match *op {
            Op::Edit {
                entry: n,
                value,
                at,
            } => edit_entry(v, entry(n), when(at), |e| {
                set(e, "Password", &format!("p{value}"))
            })
            .map(|_| ()),
            Op::Move {
                entry: n,
                group: g,
                at,
            } => move_entries(v, &[entry(n)], group(g), when(at)).map(|_| ()),
            Op::Delete { entry: n, at } => {
                recycle::delete_entries(v, &[entry(n)], when(at), |_, _| {
                    recycle::References::Delete
                })
                .map(|_| ())
            }
            Op::Add { group: g, at } => {
                added = added.wrapping_add(1);
                let mut b = [side; 16];
                b[1] = added;
                let mut e = Entry::new(Uuid(b), when(at));
                set(&mut e, "Title", "added");
                larsal_core::edit::add_entry(v, group(g), e, when(at)).map(|_| ())
            }
            Op::MoveGroup {
                group: g,
                parent,
                at,
            } => move_group(
                v,
                group(g),
                if parent % 5 == 4 {
                    uid(0x01)
                } else {
                    group(parent)
                },
                Position::End,
                when(at),
            )
            .map(|_| ()),
            Op::EditGroup {
                group: g,
                value,
                at,
            } => edit_group(v, group(g), when(at), |x| x.name = format!("N{value}")).map(|_| ()),
            Op::DeleteGroup { group: g, at } => {
                recycle::delete_group(v, group(g), when(at)).map(|_| ())
            }
        };
    }
}

fn entries(v: &Vault) -> Vec<&Entry> {
    v.root.all_entries().collect()
}

fn group_ids(v: &Vault) -> Vec<Uuid> {
    v.root.subtree().iter().map(|g| g.uuid).collect()
}

/// The later of an object's Mod and Loc: the time the whole-vault pass
/// compares (LD-271 (2)).
fn changed(t: &larsal_model::Times) -> Time {
    t.last_modification.max(t.location_changed)
}

/// MOD-11.30 for one merge of `b` into a copy of `a`: `same` says whether
/// it is a same-vault merge (the deletion pass runs, LD-265).
fn no_data_lost(a: &Vault, b: &Vault, same: bool) -> Result<(), TestCaseError> {
    let mut r = a.duplicate();
    let o = window();
    let dry = merge(&mut r, b, &Options { dry_run: true, ..o }, t9()).unwrap();
    prop_assert!(r == *a);
    let m = merge(&mut r, b, &o, t9()).unwrap();
    prop_assert_eq!(&dry.changes, &m.changes);
    // The earliest deletion time of an id on either side.
    let mut deleted: std::collections::HashMap<Uuid, Time> = std::collections::HashMap::new();
    for d in a.deleted_objects.iter().chain(&b.deleted_objects) {
        let t = deleted.entry(d.uuid).or_insert(d.deleted_at);
        *t = (*t).min(d.deleted_at);
    }
    // Every entry and group of either side is in the result, unless a
    // same-vault merge erased it: deleted on one side no earlier than its
    // last change or move on every side that holds it.
    let erasable = |id: Uuid, times: Vec<Time>| {
        same && deleted
            .get(&id)
            .is_some_and(|t| times.iter().all(|x| x <= t))
    };
    let entry_times = |id: Uuid| -> Vec<Time> {
        [a, b]
            .iter()
            .filter_map(|v| v.root.all_entries().find(|e| e.uuid == id))
            .map(|e| changed(&e.times))
            .collect()
    };
    let group_times = |id: Uuid| -> Vec<Time> {
        [a, b]
            .iter()
            .filter_map(|v| v.root.find_group(id))
            .map(|g| changed(&g.times))
            .collect()
    };
    let ids: Vec<Uuid> = entries(&r).iter().map(|e| e.uuid).collect();
    for e in entries(a).into_iter().chain(entries(b)) {
        prop_assert!(
            ids.contains(&e.uuid) || erasable(e.uuid, entry_times(e.uuid)),
            "entry lost"
        );
    }
    let groups = group_ids(&r);
    // The source root itself is never copied (MOD-11.4).
    for g in group_ids(a)
        .into_iter()
        .chain(group_ids(b))
        .filter(|g| *g != b.root.uuid || same)
    {
        prop_assert!(
            groups.contains(&g) || erasable(g, group_times(g)),
            "group lost"
        );
    }
    if same {
        // No entry deleted for good on one side comes back unless one side
        // changed or moved it after the deletion (LD-265, LD-271 (2)); a
        // group also stays while it still holds something (FMT-15.11 step 4).
        for e in entries(&r) {
            if let Some(t) = deleted.get(&e.uuid) {
                prop_assert!(
                    entry_times(e.uuid).iter().any(|x| x > t),
                    "a deleted entry came back"
                );
            }
        }
        for g in r.root.subtree() {
            if let Some(t) = deleted.get(&g.uuid) {
                prop_assert!(
                    group_times(g.uuid).iter().any(|x| x > t)
                        || !g.entries.is_empty()
                        || !g.groups.is_empty(),
                    "a deleted group came back"
                );
            }
        }
    }
    // The newer side's current version is current (the target on ties);
    // the older side's current version is in the history unless the item
    // limit cut it as the oldest.
    for x in entries(&r) {
        let (Some(p), Some(q)) = (
            a.root.all_entries().find(|e| e.uuid == x.uuid),
            b.root.all_entries().find(|e| e.uuid == x.uuid),
        ) else {
            continue;
        };
        let (winner, loser) = if q.times.last_modification > p.times.last_modification {
            (q, p)
        } else {
            (p, q)
        };
        prop_assert!(same_version(x, winner), "the newer version is not current");
        if !same_version(loser, winner) {
            let kept = x.history.iter().any(|h| same_version(h, loser));
            let cut = x.history.len() == 10
                && x.history
                    .iter()
                    .all(|h| h.times.last_modification >= loser.times.last_modification);
            prop_assert!(kept || cut, "the older version is lost");
        }
    }
    prop_assert!(larsal_model::invariants::check(&r).is_ok());
    // A second merge records nothing, except the same move-cycle conflicts
    // again (the conflict stays until a user resolves it).
    let cycles: Vec<Change> = m
        .changes
        .iter()
        .filter(|c| c.kind == ChangeKind::Conflict && c.object == Object::Group)
        .cloned()
        .collect();
    let again = merge(&mut r, b, &o, t9()).unwrap();
    prop_assert_eq!(again.changes, cycles);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, ..ProptestConfig::default() })]

    /// T45 (MOD-11.30, LD-265, LD-271 (2)): 1,000 random pairs of copies of
    /// one vault, merged once as a same-vault merge and once with B's root
    /// id changed (not the same vault).
    #[test]
    fn mod11_30_no_data_lost(ops_a in prop::collection::vec(op(), 0..=20), ops_b in prop::collection::vec(op(), 0..=20)) {
        let mut a = base();
        apply(&mut a, 0xa0, &ops_a);
        let mut b = base();
        apply(&mut b, 0xb0, &ops_b);
        no_data_lost(&a, &b, true)?;
        b.root.uuid = uid(0x65);
        no_data_lost(&a, &b, false)?;
        let _ = history::size;
    }
}

// ---- Checker fix pass: LD-130, LD-132, MOD-11.26 and the survivors ----

/// The id of the group holding group `b`.
fn parent_of(v: &Vault, b: u8) -> Uuid {
    v.root
        .subtree()
        .into_iter()
        .find(|g| g.groups.iter().any(|c| c.uuid == uid(b)))
        .expect("group")
        .uuid
}

fn share() -> Options {
    Options {
        target_start: Some(uid(0x20)),
        ..Options::new(Kind::SharedImport)
    }
}

#[test]
fn mod11_16_share_bin_is_an_ordinary_group() {
    // LD-130: root(01) → S(20) with X(0A), and the real bin(5A) outside S.
    let mut root = grp(0x01, "Root", t0());
    let mut s = grp(0x20, "S", t0());
    s.entries.push(ent(0x0a, "X", "x", t0()));
    root.groups.push(s);
    root.groups.push(grp(0x5a, "Bin", t0()));
    let mut a = vault(root);
    a.meta.recycle_bin_enabled = true;
    a.meta.recycle_bin = Some(uid(0x5a));
    // The share moved X into its own bin(71) and added P(0B) there.
    let mut sb = grp(0x71, "Recycle Bin", t0());
    let mut x = ent(0x0a, "X", "x", t0());
    x.times.location_changed = t2();
    sb.entries.push(x);
    sb.entries.push(ent(0x0b, "Planted", "p", t1()));
    let mut sr = grp(0x70, "Share", t0());
    sr.groups.push(sb);
    let mut b = vault(sr);
    b.meta.recycle_bin_enabled = true;
    b.meta.recycle_bin = Some(uid(0x71));
    let m = run(&mut a, &b, share());
    let bin = a.root.find_group(uid(0x5a)).unwrap();
    assert!(
        bin.entries.is_empty() && bin.groups.is_empty(),
        "nothing in the real bin"
    );
    assert_eq!(parent_of(&a, 0x71), uid(0x20), "the share bin sits in S");
    assert_eq!(
        (group_of(&a, 0x0a), group_of(&a, 0x0b)),
        (uid(0x71), uid(0x71))
    );
    assert!(!m.changes.is_empty());
    for c in &m.changes {
        assert!(c.path.starts_with("/Root/S"), "real path: {}", c.line());
    }
    assert!(
        m.changes
            .iter()
            .any(|c| c.path == "/Root/S/Recycle Bin" && c.kind == ChangeKind::Added)
    );
}

#[test]
fn mod11_16_share_of_the_whole_vault_maps_no_bin() {
    // LD-130: a shared-group import at the target root (both starts roots):
    // the source bin is still an ordinary group, not the target's bin.
    let mut root = grp(0x01, "Root", t0());
    root.groups.push(grp(0x5a, "Bin", t0()));
    let mut a = vault(root);
    a.meta.recycle_bin_enabled = true;
    a.meta.recycle_bin = Some(uid(0x5a));
    let mut sb = grp(0x71, "Recycle Bin", t0());
    sb.entries.push(ent(0x0b, "Planted", "p", t1()));
    let mut sr = grp(0x70, "Share", t0());
    sr.groups.push(sb);
    let mut b = vault(sr);
    b.meta.recycle_bin_enabled = true;
    b.meta.recycle_bin = Some(uid(0x71));
    run(&mut a, &b, Options::new(Kind::SharedImport));
    assert!(a.root.find_group(uid(0x5a)).unwrap().entries.is_empty());
    assert_eq!(
        (parent_of(&a, 0x71), group_of(&a, 0x0b)),
        (uid(0x01), uid(0x71))
    );
}

#[test]
fn mod11_16_share_group_with_the_start_id() {
    // LD-130: a source group carrying S's id never renames S.
    let mut root = grp(0x01, "Root", t0());
    let mut s = grp(0x20, "S", t0());
    s.notes = "mine".into();
    root.groups.push(s);
    let mut a = vault(root);
    let mut evil = grp(0x20, "Renamed by share", t2());
    evil.notes = "theirs".into();
    evil.entries.push(ent(0x0c, "Inside", "i", t1()));
    let mut sr = grp(0x70, "Share", t0());
    sr.groups.push(evil);
    let b = vault(sr);
    let m = run(&mut a, &b, share());
    let s = a.root.find_group(uid(0x20)).unwrap();
    assert_eq!((s.name.as_str(), s.notes.as_str()), ("S", "mine"));
    assert_eq!(group_of(&a, 0x0c), uid(0x20));
    assert_eq!(kinds(&m.changes), vec![ChangeKind::Added]);
}

#[test]
fn mod11_26_bin_made_is_recorded() {
    let mut root = grp(0x01, "Root", t0());
    root.entries.push(ent(0x0a, "Mail", "a", t0()));
    let mut a = vault(root);
    a.meta.recycle_bin_enabled = true;
    let mut sroot = grp(0x01, "Root", t0());
    sroot.entries.push(ent(0x0a, "Mail", "a", t0()));
    sroot.groups.push(grp(0x5b, "Recycle Bin", t0()));
    let mut b = vault(sroot);
    b.meta.recycle_bin_enabled = true;
    b.meta.recycle_bin = Some(uid(0x5b));
    let m = run(&mut a, &b, cli());
    assert_eq!(a.meta.recycle_bin, Some(uid(0x5b)));
    assert_eq!(m.changes.len(), 1);
    assert_eq!(
        m.changes[0].line(),
        "\tAdded: '/Root/Recycle Bin' [{5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b}] (recycle bin made)"
    );
    assert!(run(&mut a, &b, cli()).changes.is_empty());
}

/// Same-vault metadata: the source's settings are newer.
fn kdf_merge(from: Kdf, to: Kdf) -> (Kdf, Vec<String>) {
    let mut a = vault(grp(0x01, "Root", t0()));
    a.encryption.kdf = from;
    let mut b = a.duplicate();
    b.encryption.kdf = to;
    b.meta.settings_changed = t2();
    let m = run(&mut a, &b, Options::new(Kind::ChangeOnDisk));
    let conflicts = m
        .changes
        .iter()
        .filter(|c| c.kind == ChangeKind::Conflict)
        .map(Change::line)
        .collect();
    (a.encryption.kdf, conflicts)
}

fn argon(iterations: u64, memory_kib: u64, lanes: u64) -> Kdf {
    Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations,
        memory_kib,
        lanes,
    }
}

#[test]
fn mod11_19_kdf_family_and_lower_costs() {
    // LD-132: AES-KDF 6,000,000 rounds to a tiny Argon2d: a Conflict.
    let aes = Kdf::AesKdf { rounds: 6_000_000 };
    let tiny = Kdf::Argon2 {
        kind: Argon2Kind::D,
        iterations: 1,
        memory_kib: 8,
        lanes: 1,
    };
    let (kdf, c) = kdf_merge(aes, tiny);
    assert_eq!(kdf, aes);
    assert_eq!(c, vec!["\tConflict:  (key derivation kind not changed)"]);
    let (kdf, c) = kdf_merge(argon(2, 65_536, 2), aes);
    assert_eq!((kdf, c.len()), (argon(2, 65_536, 2), 1));
    // Within a family: each lower cost is a Conflict, equal or higher is taken.
    let lower = "\tConflict:  (key derivation not lowered)";
    for to in [
        argon(2, 32_768, 2),
        argon(1, 65_536, 2),
        argon(2, 65_536, 1),
    ] {
        assert_eq!(
            kdf_merge(argon(2, 65_536, 2), to),
            (argon(2, 65_536, 2), vec![lower.to_owned()])
        );
    }
    for to in [
        argon(2, 65_536, 2),
        argon(3, 65_536, 2),
        argon(2, 131_072, 4),
    ] {
        assert_eq!(kdf_merge(argon(2, 65_536, 2), to), (to, Vec::new()));
    }
    let (kdf, c) = kdf_merge(aes, Kdf::AesKdf { rounds: 5_999_999 });
    assert_eq!((kdf, c), (aes, vec![lower.to_owned()]));
    let more = Kdf::AesKdf { rounds: 6_000_001 };
    assert_eq!(kdf_merge(aes, more), (more, Vec::new()));
    assert_eq!(kdf_merge(aes, aes), (aes, Vec::new()));
}

#[test]
fn mod11_19_metadata_only_for_the_same_vault_from_the_roots() {
    // MG01, MG02: equal root ids alone do not make a same-vault merge.
    let base = || {
        let mut v = two_groups(vec![]);
        v.meta.name = "Mine".into();
        v.meta.name_changed = t0();
        v
    };
    let mut newer = base();
    newer.meta.name = "Theirs".into();
    newer.meta.name_changed = t2();
    for o in [
        Options::new(Kind::ImportWizard),
        Options {
            target_start: Some(uid(0x02)),
            ..cli()
        },
        Options {
            source_start: Some(uid(0x02)),
            ..cli()
        },
    ] {
        let mut a = base();
        merge(&mut a, &newer, &o, t9()).unwrap();
        assert_eq!(a.meta.name, "Mine", "{o:?}");
    }
    let mut a = base();
    merge(&mut a, &newer, &cli(), t9()).unwrap();
    assert_eq!(a.meta.name, "Theirs");
}

#[test]
fn mod11_09_moves_retried_until_none_succeeds() {
    // MG05: the walk defers X (under px) and Y (under py); Q's move frees Y,
    // and Y's move frees X only in the second retry round.
    // Target: root → X → Y → [px, Q → py].
    let mut q = grp(0x13, "Q", t0());
    q.groups.push(grp(0x14, "py", t0()));
    let mut y = grp(0x11, "Y", t0());
    y.groups.push(grp(0x12, "px", t0()));
    y.groups.push(q);
    let mut x = grp(0x10, "X", t0());
    x.groups.push(y);
    let mut root = grp(0x01, "Root", t0());
    root.groups.push(x);
    let mut a = vault(root);
    // Source: root → [px → X, py → Y, Q]; X, Y and Q moved later.
    let later = |b: u8, name: &str| {
        let mut g = grp(b, name, t0());
        g.times.location_changed = t1();
        g
    };
    let mut px = grp(0x12, "px", t0());
    px.groups.push(later(0x10, "X"));
    let mut py = grp(0x14, "py", t0());
    py.groups.push(later(0x11, "Y"));
    let mut sroot = grp(0x01, "Root", t0());
    sroot.groups.extend([px, py, later(0x13, "Q")]);
    let b = vault(sroot);
    let m = run(&mut a, &b, cli());
    assert!(
        m.changes.iter().all(|c| c.kind == ChangeKind::Moved),
        "{:?}",
        m.changes
    );
    assert_eq!(m.changes.len(), 3);
    assert_eq!(
        (
            parent_of(&a, 0x10),
            parent_of(&a, 0x11),
            parent_of(&a, 0x13)
        ),
        (uid(0x12), uid(0x14), uid(0x01))
    );
}

#[test]
fn mod11_08_equal_location_time_stays() {
    // MG17: the same Loc on both sides: the target's place stays.
    let mut a = two_groups(vec![]);
    a.root.groups[0].groups.push(grp(0x04, "Sub", t0()));
    let mut b = two_groups(vec![]);
    b.root.groups[1].groups.push(grp(0x04, "Sub", t0()));
    assert!(run(&mut a, &b, cli()).changes.is_empty());
    assert_eq!(parent_of(&a, 0x04), uid(0x02));
}

#[test]
fn mod11_10_search_switch_copied() {
    // MG25.
    let mut a = two_groups(vec![]);
    let mut b = two_groups(vec![]);
    let g = &mut b.root.groups[0];
    g.searching = larsal_model::Switch::Off;
    g.times.last_modification = t2();
    let m = run(&mut a, &b, cli());
    assert_eq!(a.root.groups[0].searching, larsal_model::Switch::Off);
    assert!(m.changes[0].details.contains(&"Search".to_owned()));
}

/// An entry whose password is not marked protected.
fn bare(b: u8, pwd: &str, m: Time) -> Entry {
    let mut e = Entry::new(uid(b), m);
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new(pwd.to_owned()),
            protected: false,
        },
    );
    e
}

fn protected(e: &Entry) -> bool {
    e.field("Password").is_some_and(|f| f.protected)
}

#[test]
fn mod11_12_passwords_protected_on_both_paths() {
    // MG38: the newer source copy; MG39: the joined history of a newer target.
    let mut a = two_groups(vec![bare(0x0a, "old", t0())]);
    let b = two_groups(vec![bare(0x0a, "new", t1())]);
    run(&mut a, &b, cli());
    let e = find(&a, 0x0a);
    assert_eq!(pw(e), "new");
    assert!(protected(e) && e.history.iter().all(protected));
    let mut a = two_groups(vec![ent(0x0a, "T", "newer", t2())]);
    let b = two_groups(vec![bare(0x0a, "older", t1())]);
    run(&mut a, &b, cli());
    let e = find(&a, 0x0a);
    assert_eq!(hist(e), vec![("older", t1())]);
    assert!(e.history.iter().all(protected));
}

/// Root(01) → S(20) with the given entries and groups.
fn shared(entries: Vec<Entry>, groups: Vec<Group>) -> Vault {
    let mut s = grp(0x20, "S", t0());
    s.entries = entries;
    s.groups = groups;
    let mut root = grp(0x01, "Root", t0());
    root.groups.push(s);
    vault(root)
}

fn gone(b: u8, at: Time) -> DeletedObject {
    DeletedObject {
        uuid: uid(b),
        deleted_at: at,
        unknown: Vec::new(),
    }
}

#[test]
fn mod11_15_synchronize_erase_rules() {
    // MG42: an entry changed after the deletion stays.
    let mut a = shared(vec![ent(0x0a, "Kept", "k", t2())], vec![]);
    let mut b = vault(grp(0x70, "Share", t0()));
    b.deleted_objects.push(gone(0x0a, t1()));
    run(&mut a, &b, share());
    assert_eq!(find(&a, 0x0a).value("Title"), "Kept");
    // MG45: the earliest deletion time decides (target t3, source t1).
    let mut a = shared(vec![ent(0x0a, "Kept", "k", t2())], vec![]);
    a.deleted_objects.push(gone(0x0a, t3()));
    run(&mut a, &b, share());
    assert!(a.root.all_entries().any(|e| e.uuid == uid(0x0a)));
    // The same with both times before the change: erased.
    let mut a = shared(vec![ent(0x0a, "Old", "o", t0())], vec![]);
    a.deleted_objects.push(gone(0x0a, t3()));
    run(&mut a, &b, share());
    assert!(!a.root.all_entries().any(|e| e.uuid == uid(0x0a)));
    // MG47: the shared group itself is never erased, even empty.
    let mut a = shared(vec![], vec![]);
    let mut b = vault(grp(0x70, "Share", t0()));
    b.deleted_objects.push(gone(0x20, t3()));
    run(&mut a, &b, share());
    assert!(a.root.find_group(uid(0x20)).is_some());
}

/// A public display item name with the reserved prefix (as bytes).
fn public_name(rest: &str) -> Vec<u8> {
    let mut n = vec![
        0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x5F,
    ];
    n.extend_from_slice(rest.as_bytes());
    n
}

fn text(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}

#[test]
fn mod11_18_custom_data_survivors() {
    let stamp = |y: i32| format!("Mon Jan 1 00:00:00 {y} GMT");
    let remote = text(&[
        0x4B, 0x50, 0x58, 0x43, 0x5F, 0x52, 0x45, 0x4D, 0x4F, 0x54, 0x45, 0x5F, 0x53, 0x59, 0x4E,
        0x43, 0x5F, 0x53, 0x45, 0x54, 0x54, 0x49, 0x4E, 0x47, 0x53,
    ]);
    let padding = text(&[
        0x4B, 0x50, 0x58, 0x43, 0x5F, 0x52, 0x41, 0x4E, 0x44, 0x4F, 0x4D, 0x5F, 0x53, 0x4C, 0x55,
        0x47,
    ]);
    // MG49: equal container times: the target stays.
    let mut a = two_groups(vec![]);
    a.meta.custom_data.items = vec![cd("_LAST_MODIFIED", &stamp(2020)), cd("k", "t")];
    let mut b = two_groups(vec![]);
    b.meta.custom_data.items = vec![cd("_LAST_MODIFIED", &stamp(2020)), cd("k", "s")];
    assert!(run(&mut a, &b, cli()).changes.is_empty());
    assert_eq!(a.meta.custom_data.get("k"), Some("t"));
    // MG52, MG53, MG55, MG57: a newer source keeps the protected keys, does
    // not copy the padding and stamps an updated item.
    let mut a = two_groups(vec![]);
    a.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", &stamp(2018)),
        cd("_CREATED_", "c"),
        cd("FDO_SECRETS_EXPOSED_GROUP", "f"),
        cd(&remote, "r"),
        cd("k", "t"),
    ];
    b.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", &stamp(2024)),
        cd("k", "s"),
        cd(&padding, "pad"),
    ];
    run(&mut a, &b, cli());
    let data = &a.meta.custom_data;
    assert_eq!(
        (
            data.get("_CREATED_"),
            data.get("FDO_SECRETS_EXPOSED_GROUP"),
            data.get(&remote)
        ),
        (Some("c"), Some("f"), Some("r"))
    );
    assert!(data.get(&padding).is_none());
    let k = data.items.iter().find(|i| i.key == "k").unwrap();
    assert_eq!((k.value.expose(), k.last_modified), ("s", Some(t9())));
    // MG94: no stamp in the source: its newest item time is its time.
    let mut a = two_groups(vec![]);
    a.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2026 GMT"),
        cd("k", "t"),
    ];
    let mut b = two_groups(vec![]);
    let mut item = cd("k", "s");
    item.last_modified = Some(t2());
    b.meta.custom_data.items = vec![item.clone()];
    run(&mut a, &b, cli());
    assert_eq!(a.meta.custom_data.get("k"), Some("s"));
    let mut a2 = two_groups(vec![]);
    a2.meta.custom_data.items = vec![
        cd("_LAST_MODIFIED", "Mon Mar 2 00:00:00 2026 GMT"),
        cd("k", "t"),
    ];
    run(&mut a2, &b, cli());
    assert_eq!(a2.meta.custom_data.get("k"), Some("t"));
    // MG92: a wrong weekday name is not a time.
    assert!(larsal_core::merge::parse_last_modified("Xyz Jan 1 00:00:00 2026 GMT").is_none());
    assert!(larsal_core::merge::parse_last_modified("Thu Jan 1 00:00:00 2026 GMT").is_some());
}

#[test]
fn mod11_19_public_items_replaced() {
    // MG70: newer settings replace the public display items.
    let item = |n: &str, v: &[u8]| larsal_model::PublicItem {
        kind: 0x18,
        name: public_name(n),
        value: v.to_vec(),
    };
    let mut a = two_groups(vec![]);
    a.public_custom_data = vec![item("NAME", b"old"), item("COLOR", b"c")];
    let mut b = a.duplicate();
    b.public_custom_data = vec![item("NAME", b"new")];
    b.meta.settings_changed = t2();
    run(&mut a, &b, cli());
    assert_eq!(a.public_custom_data, vec![item("NAME", b"new")]);
}

#[test]
fn f_073_merge_leaves_the_public_id_alone() {
    // F-073: only the name, colour and icon are merged (MOD-11.19); the
    // public id item (prefix + UUID) stays the target's, in every kind.
    let id = larsal_model::PublicItem {
        kind: 0x42,
        name: public_name("UUID"),
        value: vec![7; 16],
    };
    for kind in [Kind::CommandLine, Kind::Window] {
        let mut a = two_groups(vec![]);
        let mut b = a.duplicate();
        b.public_custom_data = vec![id.clone()];
        b.meta.settings_changed = t2();
        let mut o = Options::new(kind);
        o.take_key = true;
        merge(&mut a, &b, &o, t9()).unwrap();
        assert!(a.public_custom_data.is_empty(), "{kind:?}");
        // Nor does it count as a settings difference by itself.
        let mut c = two_groups(vec![]);
        let mut d = c.duplicate();
        d.public_custom_data = vec![id.clone()];
        d.meta.settings_changed = t2();
        let merged = merge(&mut c, &d, &Options::new(kind), t9()).unwrap();
        assert!(
            !merged
                .changes
                .iter()
                .any(|ch| ch.line().contains("vault settings")),
            "{kind:?}"
        );
    }
}

#[test]
fn mod11_19_key_not_taken_in_a_dry_run() {
    // MG75.
    let mut a = two_groups(vec![]);
    let mut b = a.duplicate();
    b.meta.master_key_changed = t2();
    let o = Options::new(Kind::ChangeOnDisk);
    let dry = merge(&mut a, &b, &Options { dry_run: true, ..o }, t9()).unwrap();
    assert!(!dry.key_taken && !dry.changes.is_empty());
    assert!(merge(&mut a, &b, &o, t9()).unwrap().key_taken);
}

#[test]
fn mod11_13_same_version_parts() {
    // MG78, MG80, MG81: Mod, attachments and tags are content.
    let e = ent(0x0a, "T", "p", t1());
    let mut later = e.duplicate(true);
    later.times.last_modification = t2();
    assert!(same_version(&e, &e.duplicate(true)));
    assert!(!same_version(&e, &later));
    let mut file = e.duplicate(true);
    file.attachments.push(larsal_model::Attachment {
        name: "a.txt".into(),
        data: std::sync::Arc::new(larsal_crypto::secret::SecretBytes::new(b"demo".to_vec())),
    });
    assert!(!same_version(&e, &file));
    let mut tagged = e.duplicate(true);
    tagged.set_tags(vec!["work".into()]);
    assert!(!same_version(&e, &tagged));
}

// ---- Linear work (S12-B2): release builds only ----

/// An id from a number (first byte 0x80, never zero).
fn nid(i: u32, tag: u8) -> Uuid {
    let mut b = [0u8; 16];
    b[0] = 0x80;
    b[1..5].copy_from_slice(&i.to_be_bytes());
    b[15] = tag;
    Uuid(b)
}

const N: u32 = 100_000;
/// Far below quadratic (minutes at this size), with room for a busy machine.
const BUDGET_MS: u128 = 1_500;

fn timed(what: &str, a: &mut Vault, b: &Vault, o: Options) -> Merged {
    let t = std::time::Instant::now();
    let m = merge(a, b, &o, t9()).unwrap();
    let ms = t.elapsed().as_millis();
    println!("TIMING {what}: {ms} ms, {} records", m.changes.len());
    assert!(ms < BUDGET_MS, "{what}: {ms} ms");
    m
}

#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn mod11_linear_entries_in_one_group() {
    let side = |pwd: &str, m: Time| {
        let mut root = grp(0x01, "Root", t0());
        root.entries = (0..N)
            .map(|i| {
                let mut e = Entry::new(nid(i, 1), m);
                set(&mut e, "Password", pwd);
                e
            })
            .collect();
        vault(root)
    };
    let mut a = side("a", t0());
    let b = side("b", t1());
    let m = timed("100,000 entries, all newer", &mut a, &b, cli());
    assert_eq!(m.changes.len(), N as usize);
    // New entries and moves into a second group.
    let mut a = side("a", t0());
    a.root.entries.truncate(N as usize / 2);
    let mut b = side("a", t0());
    let mut g = grp(0x02, "G", t0());
    g.entries = core::mem::take(&mut b.root.entries);
    for e in &mut g.entries {
        e.times.location_changed = t1();
    }
    b.root.groups.push(g);
    a.root.groups.push(grp(0x02, "G", t0()));
    let m = timed("50,000 moved + 50,000 new", &mut a, &b, cli());
    assert_eq!(m.changes.len(), N as usize);
    assert_eq!(a.root.groups[0].entries.len(), N as usize);
}

#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn mod11_linear_history_items() {
    // 50,000 versions per side, 100,000 joined (the open limit per entry).
    let half = N / 2;
    let side = |odd: u32, now: Time| {
        let mut e = ent(0x0a, "T", "now", now);
        e.history = (0..half)
            .map(|i| item(0x0a, "T", "h", Time(1_000_000 + i64::from(i * 2 + odd))))
            .collect();
        let mut v = two_groups(vec![e]);
        v.meta.history_max_items = -1;
        v.meta.history_max_size = -1;
        v
    };
    let mut a = side(0, t1());
    let b = side(1, t2());
    timed("history 50,000 + 50,000", &mut a, &b, cli());
    // 100,001 versions with the target's current one, cut to the cap.
    let h = &find(&a, 0x0a).history;
    assert_eq!(h.len(), larsal_core::history::MAX_ITEMS);
    assert_eq!(pw(h.last().unwrap()), "now");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn mod11_linear_icons_groups_custom_data() {
    let icon_n = |i: u32| CustomIcon {
        uuid: nid(i, 2),
        name: String::new(),
        last_modified: None,
        data: vec![1],
        unknown: Vec::new(),
    };
    let mut a = two_groups(vec![]);
    a.meta.custom_icons = (0..N / 2).map(icon_n).collect();
    let mut b = two_groups(vec![]);
    b.meta.custom_icons = (0..N).map(icon_n).collect();
    timed("icons 100,000", &mut a, &b, cli());
    assert_eq!(a.meta.custom_icons.len(), N as usize);
    // Groups in one parent, half new, half moved.
    let mut a = two_groups(vec![]);
    a.root.groups[0].groups = (0..N / 2)
        .map(|i| Group::new(nid(i, 3), "G".into(), t0()))
        .collect();
    let mut b = two_groups(vec![]);
    b.root.groups[1].groups = (0..N)
        .map(|i| {
            let mut g = Group::new(nid(i, 3), "G".into(), t0());
            g.times.location_changed = t1();
            g
        })
        .collect();
    let m = timed("groups 50,000 moved + 50,000 new", &mut a, &b, cli());
    assert_eq!(m.changes.len(), N as usize);
    // Vault custom data items, all changed by a newer source.
    let mut a = two_groups(vec![]);
    let mut b = two_groups(vec![]);
    a.meta.custom_data.items = (0..N).map(|i| cd(&format!("k{i}"), "t")).collect();
    b.meta.custom_data.items = (0..N).map(|i| cd(&format!("k{i}"), "s")).collect();
    a.meta
        .custom_data
        .items
        .push(cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2018 GMT"));
    b.meta
        .custom_data
        .items
        .push(cd("_LAST_MODIFIED", "Mon Jan 1 00:00:00 2024 GMT"));
    let m = timed("custom data 100,000", &mut a, &b, cli());
    assert_eq!(m.changes.len(), N as usize);
    assert_eq!(a.meta.custom_data.get("k99999"), Some("s"));
}

#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn mod11_linear_synchronize_deletions() {
    let mut a = shared(
        (0..N).map(|i| Entry::new(nid(i, 4), t0())).collect(),
        vec![],
    );
    let mut b = vault(grp(0x70, "Share", t0()));
    b.deleted_objects = (0..N)
        .map(|i| DeletedObject {
            uuid: nid(i, 4),
            deleted_at: t1(),
            unknown: Vec::new(),
        })
        .collect();
    let m = timed("100,000 erased in a shared group", &mut a, &b, share());
    assert_eq!(m.changes.len(), N as usize + 1);
    assert!(a.root.groups[0].entries.is_empty());
}

/// LD-185 (Verify C19): a version 3 file stores no settings time, so its
/// settings never win; equal settings are no change.
#[test]
fn ld185_version_3_settings_never_win_and_equal_settings_are_no_change() {
    let v3 = Some(FileVersion { major: 3, minor: 1 });
    // The same version 3 vault opened twice: the later open looks newer.
    let (mut a, mut b) = same_vault_pair();
    a.read_version = v3;
    b.read_version = v3;
    a.meta.settings_changed = t1();
    b.meta.settings_changed = t2();
    for o in [cli(), window()] {
        let mut t = a.duplicate();
        assert!(run(&mut t, &b, o).changes.is_empty());
        assert!(t == a, "the target changed");
    }
    // An old version 3 copy never overwrites newer target settings.
    let (mut a, mut b) = same_vault_pair();
    a.meta.settings_changed = t1();
    a.meta.history_max_items = 10;
    b.read_version = v3;
    b.meta.settings_changed = t2();
    b.meta.history_max_items = 5;
    let m = run(&mut a, &b, cli());
    assert!(m.changes.is_empty(), "{:?}", m.changes);
    assert_eq!(a.meta.history_max_items, 10);
    // Version 4 sources still win by their time (MOD-11.19).
    b.read_version = Some(FileVersion { major: 4, minor: 0 });
    run(&mut a, &b, cli());
    assert_eq!(a.meta.history_max_items, 5);
    // Equal settings with a later time: no change.
    let (mut a, mut b) = same_vault_pair();
    a.meta.settings_changed = t1();
    b.meta.settings_changed = t2();
    assert!(run(&mut a, &b, cli()).changes.is_empty());
    assert_eq!(a.meta.settings_changed, t1());
}

/// F-066 (LD-207): a merge record never names a protected Title. The
/// entry's own flag or either vault's flag for the Title masks it in the
/// Added, Moved, Modified and Deleted records.
#[test]
fn f_066_merge_records_mask_protected_titles() {
    let mask = larsal_core::health::MASKED_TITLE;
    let titles = |m: &Merged| -> Vec<String> {
        let mut v: Vec<String> = m
            .changes
            .iter()
            .filter(|c| c.object == Object::Entry)
            .map(|c| c.title.clone())
            .collect();
        v.sort();
        v
    };
    // Alpha modified, Beta moved, Gamma added; Delta deleted in a shared
    // group import (the walk of mod11_02). `own`: every Title carries its
    // own protected flag.
    let pair = |own: bool| {
        let mk = |b: u8, title: &str, pw: &str, m: Time| {
            let mut e = ent(b, title, pw, m);
            if own {
                e.set_field(
                    "Title".into(),
                    Field {
                        value: SecretString::new(title.to_owned()),
                        protected: true,
                    },
                );
            }
            e
        };
        let target = two_groups(vec![
            mk(0x0a, "Alpha", "p", t0()),
            mk(0x0b, "Beta", "p", t0()),
        ]);
        let mut source = two_groups(vec![mk(0x0a, "Alpha", "q", t1())]);
        let mut beta = mk(0x0b, "Beta", "p", t0());
        beta.times.location_changed = t1();
        source.root.groups[1].entries.push(beta);
        source.root.groups[1]
            .entries
            .push(mk(0x0c, "Gamma", "p", t0()));
        let mut shared_t = vault(grp(0x01, "Root", t0()));
        shared_t.root.entries.push(mk(0x0d, "Delta", "p", t0()));
        let mut shared_s = vault(grp(0x66, "Share", t0()));
        shared_s.deleted_objects.push(DeletedObject {
            uuid: uid(0x0d),
            deleted_at: t1(),
            unknown: Vec::new(),
        });
        (target, source, shared_t, shared_s)
    };
    let shared = Options {
        target_start: Some(uid(0x01)),
        ..Options::new(Kind::SharedImport)
    };
    let all = |t: &mut Vault, s: &Vault, st: &mut Vault, ss: &Vault| {
        let mut v = titles(&run(t, s, cli()));
        v.extend(titles(&run(st, ss, shared)));
        v
    };
    let (mut t, s, mut st, ss) = pair(false);
    assert_eq!(
        all(&mut t, &s, &mut st, &ss),
        ["Alpha", "Beta", "Gamma", "Delta"]
    );
    for case in 0..3 {
        let (mut t, mut s, mut st, mut ss) = pair(case == 2);
        if case == 0 {
            t.meta.memory_protection.title = true;
            st.meta.memory_protection.title = true;
        } else if case == 1 {
            s.meta.memory_protection.title = true;
            ss.meta.memory_protection.title = true;
        }
        assert_eq!(all(&mut t, &s, &mut st, &ss), [mask; 4], "case {case}");
    }
    // Only one copy of each entry flags its Title, no vault flag: Alpha's
    // Modified and Beta's Moved record are masked either way; Gamma, new,
    // has only the source's copy.
    let (mut t, _, _, _) = pair(false);
    let (_, s, _, _) = pair(true);
    assert_eq!(titles(&run(&mut t, &s, cli())), [mask; 3]);
    let (mut t, _, _, _) = pair(true);
    let (_, s, _, _) = pair(false);
    assert_eq!(titles(&run(&mut t, &s, cli())), ["Gamma", mask, mask]);
}

/// F-066 (LD-207): the "outside the shared group" Conflict record masks the
/// Title when either copy flags it, as the Moved and Modified records do.
#[test]
fn f_066_outside_the_shared_group_record_masks_either_flag() {
    let mk = |own: bool| {
        let mut e = ent(0x0a, "Alpha", "p", t0());
        if own {
            e.set_field(
                "Title".into(),
                Field {
                    value: SecretString::new("Alpha".into()),
                    protected: true,
                },
            );
        }
        e
    };
    let shared = Options {
        target_start: Some(uid(0x03)),
        ..Options::new(Kind::SharedImport)
    };
    let record = |target_own: bool, source_own: bool| -> Vec<String> {
        let mut t = two_groups(vec![mk(target_own)]);
        let mut s = vault(grp(0x66, "Share", t0()));
        s.root.entries.push(mk(source_own));
        run(&mut t, &s, shared)
            .changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Conflict && c.object == Object::Entry)
            .map(|c| c.title.clone())
            .collect()
    };
    let mask = larsal_core::health::MASKED_TITLE;
    assert_eq!(record(false, false), ["Alpha"]);
    assert_eq!(record(true, false), [mask]);
    assert_eq!(record(false, true), [mask]);
}

// ---- E15-S2: the same-vault deletion pass, the newer key, retired keys ----

/// Merges `b` into `a` at `now`, with the dry run first (MOD-11.25).
fn run_at(a: &mut Vault, b: &Vault, o: Options, now: Time) -> Merged {
    let before = a.duplicate();
    let dry = merge(a, b, &Options { dry_run: true, ..o }, now).unwrap();
    assert!(*a == before, "the dry run changed the target");
    let real = merge(a, b, &o, now).unwrap();
    assert_eq!(dry.changes, real.changes, "dry run and merge differ");
    real
}

fn y2099() -> Time {
    at(2099, 1, 1, 0, 0, 0)
}

fn has_entry(v: &Vault, b: u8) -> bool {
    v.root.all_entries().any(|e| e.uuid == uid(b))
}

/// T60's vaults: A: G1 → Old(0C) T0, Kept(0D) T2; B: a copy without
/// them that lists both deleted at T1.
fn t60() -> (Vault, Vault) {
    let a = two_groups(vec![
        ent(0x0c, "Old", "o", t0()),
        ent(0x0d, "Kept", "k", t2()),
    ]);
    let mut b = two_groups(vec![]);
    b.deleted_objects = vec![gone(0x0c, t1()), gone(0x0d, t1())];
    (a, b)
}

#[test]
fn mod11_15_t60_source_deletions_in_a_same_vault_merge() {
    let (mut a, mut b) = t60();
    // An item for an id that names nothing, dated 2099: only a share
    // import clamps it (LD-271 (1), LD-273 (6)).
    b.deleted_objects.push(gone(0x40, y2099()));
    let m = run(&mut a, &b, cli());
    assert!(!has_entry(&a, 0x0c) && has_entry(&a, 0x0d));
    assert_eq!(listed(&a), [(uid(0x40), y2099()), (uid(0x0c), t1())]);
    assert_eq!(
        kinds(&m.changes),
        [ChangeKind::Deleted, ChangeKind::Metadata]
    );
    assert!(run(&mut a, &b, cli()).changes.is_empty(), "second merge");
}

#[test]
fn mod11_notation_t61_the_root_id_alone_is_not_the_same_vault() {
    let pair = || {
        let (mut a, mut b) = t60();
        a.root.groups.push(grp(0x20, "S", t0()));
        b.meta.name = "Evil".into();
        b.meta.name_changed = t3();
        b.meta.history_max_items = 1;
        b.meta.settings_changed = t3();
        b.meta.master_key_changed = t3();
        (a, b)
    };
    let check = |a: &Vault, what: &str| {
        assert!(has_entry(a, 0x0c) && has_entry(a, 0x0d), "{what}");
        assert!(a.deleted_objects.is_empty(), "{what}");
        assert_eq!(a.meta.name_changed, t0(), "{what}");
        assert_eq!(a.meta.master_key_changed, t0(), "{what}");
        assert_ne!(a.meta.history_max_items, 1, "{what}");
    };
    // (a) another root id.
    let (mut a, mut b) = pair();
    b.root.uuid = uid(0x65);
    assert!(!run(&mut a, &b, Options::new(Kind::ConflictCopy)).key_taken);
    check(&a, "another root id");
    // (b) a shared-group import of a container with the vault's root id.
    let (mut a, b) = pair();
    assert!(!run(&mut a, &b, share()).key_taken);
    check(&a, "share");
    // (c) the import wizard with the vault's root id.
    let (mut a, b) = pair();
    assert!(!run(&mut a, &b, Options::new(Kind::ImportWizard)).key_taken);
    check(&a, "import wizard");
}

#[test]
fn mod11_29_t63_credentials_the_user_gave_make_it_the_same_vault() {
    // A (in memory, the source) under `demo2` since T2; B on disk (the
    // target) under `demo`, which the user gave for it, deleted Mail at T3.
    let mut memory = two_groups(vec![ent(0x0a, "Mail", "m", t0())]);
    memory.meta.master_key_changed = t2();
    let mut disk = two_groups(vec![]);
    disk.deleted_objects = vec![gone(0x0a, t3())];
    let o = Options::new(Kind::ChangeOnDisk);
    let m = run(&mut disk, &memory, o);
    assert!(!has_entry(&disk, 0x0a), "Mail erased");
    assert_eq!(listed(&disk), [(uid(0x0a), t3())]);
    assert!(m.key_taken, "A's newer key stays");
    assert!(!larsal_core::retired::replaced_by_merge(&o, &m, true));
}

#[test]
fn mod11_15_t64_a_shares_item_for_an_object_outside_s_is_dropped() {
    for late in [false, true] {
        // T42's target: S(20) → X(0A), Y(0B) and the empty group H(0D) in
        // the root.
        let mut root = grp(0x01, "Root", t0());
        let mut s = grp(0x20, "S", t0());
        s.entries.push(ent(0x0a, "X", "p", t0()));
        root.groups.push(s);
        root.groups.push(grp(0x0d, "H", t0()));
        root.entries.push(ent(0x0b, "Y", "p", t0()));
        let mut target = vault(root);
        let b = target.duplicate();
        let mut share = vault(grp(0x66, "Share", t0()));
        let outside = if late { y2099() } else { t1() };
        share.deleted_objects = vec![gone(0x0a, t1()), gone(0x0b, outside), gone(0x0d, outside)];
        run(&mut target, &share, self::share());
        assert_eq!(listed(&target), [(uid(0x0a), t1())], "late {late}");
        let m = run(&mut target, &b, cli());
        assert!(has_entry(&target, 0x0b), "Y stays");
        assert!(target.root.find_group(uid(0x0d)).is_some(), "H stays");
        assert!(!has_entry(&target, 0x0a), "X stays erased");
        assert_eq!(listed(&target), [(uid(0x0a), t1())]);
        assert!(m.changes.is_empty(), "{:?}", m.changes);
    }
}

#[test]
fn mod11_15_t65_a_shares_item_takes_the_import_time_and_the_known_limit() {
    // A: S(20) → E(0E) T0, and P(03) outside S. The share lists E at 2099;
    // the import runs at T2. B: a copy of A with E moved into P.
    let a0 = |with_e: bool| {
        let mut root = grp(0x01, "Root", t0());
        let mut s = grp(0x20, "S", t0());
        if with_e {
            s.entries.push(ent(0x0e, "E", "p", t0()));
        }
        root.groups.push(s);
        root.groups.push(grp(0x03, "P", t0()));
        vault(root)
    };
    let b_moved = |loc: Time| {
        let mut b = a0(false);
        let mut e = ent(0x0e, "E", "p", t0());
        e.times.location_changed = loc;
        b.root.groups[1].entries.push(e);
        b
    };
    let mut container = vault(grp(0x66, "Share", t0()));
    container.deleted_objects = vec![gone(0x0e, y2099())];
    for (with_e, loc, stays) in [(true, t3(), true), (false, t3(), true), (true, t1(), false)] {
        let mut a = a0(with_e);
        run_at(&mut a, &container, share(), t2());
        assert_eq!(listed(&a), [(uid(0x0e), t2())], "stored at the import time");
        assert!(!has_entry(&a, 0x0e));
        let m = run(&mut a, &b_moved(loc), cli());
        assert_eq!(has_entry(&a, 0x0e), stays, "Loc {loc:?}");
        if stays {
            assert_eq!(group_of(&a, 0x0e), uid(0x03));
            assert!(a.deleted_objects.is_empty());
            assert_eq!(kinds(&m.changes), [ChangeKind::Added, ChangeKind::Metadata]);
        } else {
            // LD-271 (3): the accepted limit.
            assert_eq!(listed(&a), [(uid(0x0e), t2())]);
            assert!(m.changes.is_empty(), "{:?}", m.changes);
        }
    }
}

#[test]
fn mod11_15_t66_a_move_counts_as_a_change() {
    let pair = |loc: Time| {
        let mut a = two_groups(vec![]);
        a.deleted_objects = vec![gone(0x0c, t1()), gone(0x0d, t1())];
        let mut b = two_groups(vec![]);
        let mut e = ent(0x0c, "MovedLater", "p", t0());
        e.times.location_changed = loc;
        b.root.groups[1].entries.push(e);
        let mut h = grp(0x0d, "H", t0());
        h.times.location_changed = loc;
        b.root.groups.push(h);
        (a, b)
    };
    let (mut a, b) = pair(t2());
    run(&mut a, &b, cli());
    assert_eq!(group_of(&a, 0x0c), uid(0x03));
    assert!(a.root.find_group(uid(0x0d)).is_some());
    assert!(a.deleted_objects.is_empty());
    let (mut a, b) = pair(t0());
    let before = a.duplicate();
    assert!(run(&mut a, &b, cli()).changes.is_empty());
    assert!(a == before, "the T21 result");
}

#[test]
fn fmt15_14_a_merge_that_is_not_the_same_vault_reads_no_list() {
    // M1 holds E and F; M2 is a copy that deleted E for good.
    let m1 = || two_groups(vec![ent(0x0e, "E", "p", t0()), ent(0x0f, "F", "p", t0())]);
    let mut m2 = two_groups(vec![ent(0x0f, "F", "p", t0())]);
    m2.deleted_objects = vec![gone(0x0e, t1())];
    let mut other = m2.duplicate();
    other.root.uuid = uid(0x65);
    let retired = Options {
        retired: true,
        ..Options::new(Kind::ConflictCopy)
    };
    for (source, o) in [(&other, cli()), (&m2, retired)] {
        let mut a = m1();
        run(&mut a, source, o);
        assert!(has_entry(&a, 0x0e) && has_entry(&a, 0x0f));
        assert!(a.deleted_objects.is_empty());
    }
}

#[test]
fn fmt15_24_a_same_vault_merge_applies_the_copys_deletion() {
    for edited in [false, true] {
        let mut m1 = two_groups(vec![ent(0x0e, "E", "p", t0()), ent(0x0f, "F", "p", t0())]);
        if edited {
            edit_entry(&mut m1, uid(0x0e), t2(), |e| set(e, "Password", "q")).unwrap();
        }
        let mut m2 = two_groups(vec![ent(0x0f, "F", "p", t0())]);
        m2.deleted_objects = vec![gone(0x0e, t1())];
        run(&mut m1, &m2, cli());
        assert!(has_entry(&m1, 0x0f));
        if edited {
            assert_eq!(pw(find(&m1, 0x0e)), "q");
            assert!(m1.deleted_objects.is_empty());
        } else {
            assert!(!has_entry(&m1, 0x0e));
            assert_eq!(listed(&m1), [(uid(0x0e), t1())]);
        }
    }
}

#[test]
fn fmt15_25_a_share_with_the_vaults_root_id_runs_no_whole_vault_pass() {
    // V: X(0A) outside S(20). The container has V's root id and lists X
    // deleted after X's change; then a copy of V from before the import.
    let mut root = grp(0x01, "Root", t0());
    root.groups.push(grp(0x20, "S", t0()));
    root.entries.push(ent(0x0a, "X", "p", t0()));
    let mut v = vault(root);
    let copy = v.duplicate();
    let mut container = vault(grp(0x01, "Root", t0()));
    container.deleted_objects = vec![gone(0x0a, t1())];
    container.meta.master_key_changed = t3();
    container.meta.settings_changed = t3();
    container.meta.history_max_items = 1;
    let m = run(&mut v, &container, share());
    assert!(!m.key_taken);
    assert!(has_entry(&v, 0x0a) && v.deleted_objects.is_empty());
    run(&mut v, &copy, cli());
    assert!(has_entry(&v, 0x0a) && v.deleted_objects.is_empty());
    assert_eq!(v.meta.master_key_changed, t0());
    assert_ne!(v.meta.history_max_items, 1);
}

#[test]
fn fmt15_26_a_shares_item_is_clamped_to_the_import_time() {
    let mut v = shared(vec![ent(0x0a, "X", "p", t0())], vec![]);
    // The vault's own item, dated 2099, is not the share's: it stays as it
    // is (LD-273 (6) clamps the share's items only).
    v.deleted_objects = vec![gone(0x42, y2099())];
    let mut s = vault(grp(0x66, "Share", t0()));
    s.deleted_objects = vec![gone(0x0a, y2099()), gone(0x40, y2099()), gone(0x41, t1())];
    run_at(&mut v, &s, share(), t2());
    assert!(!has_entry(&v, 0x0a));
    assert_eq!(
        listed(&v),
        [
            (uid(0x42), y2099()),
            (uid(0x40), t2()),
            (uid(0x41), t1()),
            (uid(0x0a), t2())
        ]
    );
}

#[test]
fn fmt15_27_a_move_counts_as_a_change_in_the_whole_vault_pass_only() {
    let moved = || {
        let mut e = ent(0x0e, "E", "p", t0());
        e.times.location_changed = t2();
        let mut g = grp(0x07, "G", t0());
        g.times.location_changed = t2();
        (e, g)
    };
    // Same-vault merge: E and G stay, the list gains nothing.
    let (e, g) = moved();
    let mut m1 = two_groups(vec![e]);
    m1.root.groups.push(g);
    let mut m2 = two_groups(vec![]);
    m2.deleted_objects = vec![gone(0x0e, t1()), gone(0x07, t1())];
    run(&mut m1, &m2, cli());
    assert!(has_entry(&m1, 0x0e) && m1.root.find_group(uid(0x07)).is_some());
    assert!(m1.deleted_objects.is_empty());
    // A share import compares Mod only: both erased.
    let (e, g) = moved();
    let mut m3 = shared(vec![e], vec![g]);
    let mut s = vault(grp(0x66, "Share", t0()));
    s.deleted_objects = vec![gone(0x0e, t1()), gone(0x07, t1())];
    run_at(&mut m3, &s, share(), t3());
    assert!(!has_entry(&m3, 0x0e) && m3.root.find_group(uid(0x07)).is_none());
    assert_eq!(listed(&m3), [(uid(0x0e), t1()), (uid(0x07), t1())]);
}

#[test]
fn mod11_19_t55_d_the_newer_key_in_server_sync_and_conflict_copies() {
    // T32's vaults: A (this Mac) key time T0, B key time T2.
    let (a0, mut b0) = same_vault_pair();
    b0.meta.master_key_changed = t2();
    // Server sync: this Mac's vault is the source, the server copy the
    // target; a conflict copy is the source, this Mac's vault the target.
    let sync = Options::new(Kind::ServerSync);
    let mut server = b0.duplicate();
    let m = run(&mut server, &a0, sync);
    assert!(!m.key_taken && server.meta.master_key_changed == t2());
    assert!(m.changes.is_empty(), "no question, no Conflict");
    assert!(
        larsal_core::retired::replaced_by_merge(&sync, &m, true),
        "demo retired"
    );
    let copy = Options::new(Kind::ConflictCopy);
    let mut a = a0.duplicate();
    let m = run(&mut a, &b0, copy);
    assert!(m.key_taken && a.meta.master_key_changed == t2());
    assert!(m.changes.iter().all(|c| c.kind != ChangeKind::Conflict));
    assert!(larsal_core::retired::replaced_by_merge(&copy, &m, true));
    // A's key changed later (T3): A's key stays in both flows.
    let mut a3 = a0.duplicate();
    a3.meta.master_key_changed = t3();
    let mut server = b0.duplicate();
    let m = run(&mut server, &a3, sync);
    assert!(m.key_taken && server.meta.master_key_changed == t3());
    assert!(!larsal_core::retired::replaced_by_merge(&sync, &m, true));
    let mut a = a3.duplicate();
    let m = run(&mut a, &b0, copy);
    assert!(!m.key_taken && a.meta.master_key_changed == t3());
    assert!(m.changes.is_empty());
    // A copy under a key this Mac retired, key time 2099: Merge anyway
    // never takes it, in either flow (AT-A09).
    let mut b = b0.duplicate();
    b.meta.master_key_changed = y2099();
    for kind in [Kind::ServerSync, Kind::ConflictCopy, Kind::ChangeOnDisk] {
        let o = Options {
            retired: true,
            ..Options::new(kind)
        };
        let mut a = a0.duplicate();
        let m = run(&mut a, &b, o);
        assert!(
            !m.key_taken && a.meta.master_key_changed == t0(),
            "{kind:?}"
        );
        assert!(m.changes.is_empty(), "{kind:?}");
        assert!(!larsal_core::retired::replaced_by_merge(&o, &m, true));
    }
    // With one key nothing is retired, and a dry run replaces nothing.
    let mut a = a0.duplicate();
    let m = run(&mut a, &b0, copy);
    assert!(!larsal_core::retired::replaced_by_merge(&copy, &m, false));
    let dry = Options {
        dry_run: true,
        ..copy
    };
    assert!(!larsal_core::retired::replaced_by_merge(&dry, &m, true));
}

#[test]
fn sd03_at_i05_a_conflict_copy_keeps_every_entry_but_the_deleted_one() {
    // Two writers of one vault: A edits Mail, B edits Bank, adds New and
    // deletes Shop for good; Shop is edited on A before the deletion.
    let base = two_groups(vec![
        ent(0x0a, "Mail", "m", t0()),
        ent(0x0b, "Bank", "b", t0()),
        ent(0x0c, "Shop", "s", t0()),
    ]);
    let mut a = base.duplicate();
    edit_entry(&mut a, uid(0x0a), t1(), |e| set(e, "Password", "mine")).unwrap();
    edit_entry(&mut a, uid(0x0c), t1(), |e| set(e, "Password", "s1")).unwrap();
    let mut b = base.duplicate();
    edit_entry(&mut b, uid(0x0b), t1(), |e| set(e, "Password", "theirs")).unwrap();
    larsal_core::edit::add_entry(&mut b, uid(0x03), ent(0x0d, "New", "n", t1()), t1()).unwrap();
    b.meta.recycle_bin_enabled = false;
    recycle::delete_entries(&mut b, &[uid(0x0c)], t2(), |_, _| {
        recycle::References::Delete
    })
    .unwrap();
    assert_eq!(listed(&b), [(uid(0x0c), t2())]);
    let mut merged = a.duplicate();
    run(&mut merged, &b, Options::new(Kind::ConflictCopy));
    assert_eq!(pw(find(&merged, 0x0a)), "mine");
    assert_eq!(pw(find(&merged, 0x0b)), "theirs");
    assert!(has_entry(&merged, 0x0d) && !has_entry(&merged, 0x0c));
    assert_eq!(listed(&merged), [(uid(0x0c), t2())]);
    // Shop edited on A after B's deletion: a newer live entry stays.
    edit_entry(&mut a, uid(0x0c), t3(), |e| set(e, "Password", "s3")).unwrap();
    run(&mut a, &b, Options::new(Kind::ConflictCopy));
    assert_eq!(pw(find(&a, 0x0c)), "s3");
    assert!(a.deleted_objects.is_empty());
}

#[test]
fn si09_a_root_share_container_is_not_the_same_vault() {
    // The container has the vault's root id, a newer name, settings and
    // key time, and lists Y (outside S) and S's X deleted at T3.
    let mut a = shared(vec![ent(0x0a, "X", "p", t0())], vec![]);
    a.root.groups[0].entries.push(ent(0x0b, "Z", "p", t0()));
    a.root.entries.push(ent(0x0c, "Y", "p", t0()));
    let mut c = vault(grp(0x01, "Root", t1()));
    c.root.entries.push(ent(0x0b, "Z", "p", t0()));
    c.meta.name = "Evil".into();
    c.meta.name_changed = t3();
    c.meta.settings_changed = t3();
    c.meta.history_max_items = 1;
    c.meta.master_key_changed = t3();
    c.deleted_objects = vec![gone(0x0c, t3()), gone(0x0a, t3())];
    let m = run(&mut a, &c, share());
    assert!(!m.key_taken && a.meta.master_key_changed == t0());
    assert_eq!(a.meta.name_changed, t0());
    assert_ne!(a.meta.history_max_items, 1);
    assert!(has_entry(&a, 0x0c), "Y outside S stays");
    assert!(!has_entry(&a, 0x0a), "X inside S erased");
    assert_eq!(a.root.name, "Root");
    assert_eq!(listed(&a), [(uid(0x0a), t3())], "Y's item dropped");
}

#[test]
fn fmt10_16_an_erased_group_leaves_no_dangling_reference() {
    // B deleted group G3 for good and its recycle bin (turned off); A's
    // last selected, top visible and templates groups and bin name them.
    let mut a = two_groups(vec![]);
    a.root.groups.push(grp(0x07, "G3", t0()));
    a.root.groups.push(grp(0x5a, "Recycle Bin", t0()));
    a.meta.recycle_bin_enabled = true;
    a.meta.recycle_bin = Some(uid(0x5a));
    a.meta.last_selected_group = Some(uid(0x07));
    a.meta.last_top_visible_group = Some(uid(0x07));
    a.meta.entry_templates_group = Some(uid(0x07));
    let mut b = two_groups(vec![]);
    b.deleted_objects = vec![gone(0x07, t1()), gone(0x5a, t1())];
    let m = run(&mut a, &b, Options::new(Kind::ConflictCopy));
    assert!(a.root.find_group(uid(0x07)).is_none() && a.root.find_group(uid(0x5a)).is_none());
    assert_eq!(
        (
            a.meta.recycle_bin,
            a.meta.last_selected_group,
            a.meta.last_top_visible_group,
            a.meta.entry_templates_group
        ),
        (None, None, None, None)
    );
    assert!(larsal_model::invariants::check(&a).is_ok());
    assert_eq!(
        kinds(&m.changes),
        [
            ChangeKind::Deleted,
            ChangeKind::Deleted,
            ChangeKind::Metadata
        ]
    );
}

#[test]
fn mod11_30_a_rebuilt_list_in_another_order_is_no_change() {
    // A deleted x, B deleted y; the rebuilt list puts them in another
    // order on the second merge, which still records nothing.
    let mut a = two_groups(vec![ent(0x0b, "y", "p", t0())]);
    a.deleted_objects = vec![gone(0x0a, t1())];
    let mut b = two_groups(vec![ent(0x0a, "x", "p", t0())]);
    b.deleted_objects = vec![gone(0x0b, t1())];
    run(&mut a, &b, cli());
    assert!(!has_entry(&a, 0x0a) && !has_entry(&a, 0x0b));
    assert_eq!(listed(&a), [(uid(0x0a), t1()), (uid(0x0b), t1())]);
    assert!(run(&mut a, &b, cli()).changes.is_empty());
}

/// MOD-11.24, MOD-11.15 (LD-283 (1)): a share import that adds a group and
/// erases it in its deletion pass records both, Added then Deleted. Only a
/// same-vault merge keeps such an erase quiet.
#[test]
fn mod11_24_a_share_group_added_and_erased_is_recorded() {
    let mut t = shared(vec![], vec![]);
    let mut s_root = grp(0x66, "Share", t0());
    s_root.groups.push(grp(0x05, "G", t0()));
    let mut s = vault(s_root);
    s.deleted_objects = vec![gone(0x05, t1())];
    let m = run(&mut t, &s, share());
    assert!(t.root.find_group(uid(0x05)).is_none());
    assert_eq!(
        kinds(&m.changes),
        [ChangeKind::Added, ChangeKind::Deleted, ChangeKind::Metadata]
    );
}

/// FMT-15.11 step 2 (L15-3, LD-283 (1)): of two items for one id, the
/// earlier time decides. X changed at T2, after A's item (T1) and before
/// B's (T3), so X stays and the list drops both items.
#[test]
fn fmt15_11_the_earlier_of_two_items_for_one_id_decides() {
    let mut a = two_groups(vec![ent(0x0a, "X", "p", t2())]);
    a.deleted_objects = vec![gone(0x0a, t1())];
    let mut b = two_groups(vec![]);
    b.deleted_objects = vec![gone(0x0a, t3())];
    run(&mut a, &b, cli());
    assert!(has_entry(&a, 0x0a));
    assert!(a.deleted_objects.is_empty());
}

/// F-152 (MOD-11.30, MOD-11's FMT-15.5 edge case, LD-271 (2)): A moved E
/// after the deletion item; B wins on Mod with an older Loc. E stays, after
/// the merge and after a second merge of the same B, with the item in A's
/// list or in B's.
#[test]
fn mod11_30_an_entry_moved_after_its_item_stays_when_the_source_wins() {
    for kind in [Kind::ConflictCopy, Kind::Window, Kind::ServerSync] {
        for item_in_b in [false, true] {
            let mut moved = ent(0x0a, "E", "p", t0());
            moved.times.location_changed = t3();
            let mut a = two_groups(vec![]);
            a.root.groups[1].entries.push(moved);
            let mut newer = ent(0x0a, "E", "p2", t1());
            newer.times.location_changed = t0();
            let mut b = two_groups(vec![newer]);
            if item_in_b {
                b.deleted_objects = vec![gone(0x0a, t2())];
            } else {
                a.deleted_objects = vec![gone(0x0a, t2())];
            }
            run(&mut a, &b, Options::new(kind));
            assert!(has_entry(&a, 0x0a), "{kind:?}, item in B: {item_in_b}");
            assert_eq!(pw(find(&a, 0x0a)), "p2");
            run(&mut a, &b, Options::new(kind));
            assert!(
                has_entry(&a, 0x0a),
                "{kind:?}, item in B: {item_in_b}, again"
            );
        }
    }
}

/// F-154's entry cases, root id(01) on both sides: (case, A, B, A's
/// password after the merge). The target wins or ties on Mod, both copies
/// hold E in the same group, and only B moved E after the item at T2.
fn f154_cases() -> Vec<(&'static str, Vault, Vault, &'static str)> {
    let e = |pw: &str, m: Time, loc: Time| {
        let mut e = ent(0x0a, "E", pw, m);
        e.times.location_changed = loc;
        e
    };
    let held = |g: usize, e: Entry| {
        let mut v = two_groups(vec![]);
        v.root.groups[g].entries.push(e);
        v
    };
    vec![
        // P1: B moved E out of G1 and back at T3.
        (
            "P1",
            held(0, e("p-a", t1(), t0())),
            held(0, e("p", t0(), t3())),
            "p-a",
        ),
        // P2: both copies moved E into G2, B later.
        (
            "P2",
            held(1, e("p-a", t1(), t1())),
            held(1, e("p", t0(), t3())),
            "p-a",
        ),
        // P3: the same Mod and content, B's Loc later.
        (
            "P3",
            held(0, e("p", t0(), t0())),
            held(0, e("p", t0(), t3())),
            "p",
        ),
    ]
}

const F154_KINDS: [Kind; 4] = [
    Kind::ConflictCopy,
    Kind::Window,
    Kind::ServerSync,
    Kind::ChangeOnDisk,
];

/// F-154 (MOD-11.30, LD-271 (2), LD-287 (2)): in a same-vault merge an
/// entry that the source copy moved after its deletion item stays, also
/// when the target wins or ties on Mod: the deletion pass counts the
/// source's own later Mod or Loc. The item is in A's list or in B's, and a
/// second merge of the same B keeps E too.
#[test]
fn mod11_30_an_entry_the_source_moved_after_its_item_stays() {
    for kind in F154_KINDS {
        for item_in_b in [false, true] {
            for (case, mut a, mut b, kept) in f154_cases() {
                let item = vec![gone(0x0a, t2())];
                if item_in_b {
                    b.deleted_objects = item;
                } else {
                    a.deleted_objects = item;
                }
                for round in ["first", "again"] {
                    let at = format!("{case}, {kind:?}, item in B: {item_in_b}, {round}");
                    let m = run(&mut a, &b, Options::new(kind));
                    assert!(has_entry(&a, 0x0a), "{at}");
                    assert_eq!(pw(find(&a, 0x0a)), kept, "{at}");
                    assert!(!kinds(&m.changes).contains(&ChangeKind::Deleted), "{at}");
                }
            }
        }
    }
}

/// F-154 for groups (MOD-11.30, LD-287 (2)): an empty group H(04) under
/// the root, A: Mod T1, Loc T0; B moved it at T3 (Mod T0); the item at T2
/// in A's list or in B's. H stays, also after a second merge of the same B.
#[test]
fn mod11_30_an_empty_group_the_source_moved_after_its_item_stays() {
    let h = |m: Time, loc: Time| {
        let mut g = grp(0x04, "H", m);
        g.times.location_changed = loc;
        g
    };
    for kind in F154_KINDS {
        for item_in_b in [false, true] {
            let mut a = two_groups(vec![]);
            a.root.groups.push(h(t1(), t0()));
            let mut b = two_groups(vec![]);
            b.root.groups.push(h(t0(), t3()));
            let item = vec![gone(0x04, t2())];
            if item_in_b {
                b.deleted_objects = item;
            } else {
                a.deleted_objects = item;
            }
            for round in ["first", "again"] {
                let at = format!("{kind:?}, item in B: {item_in_b}, {round}");
                let m = run(&mut a, &b, Options::new(kind));
                assert!(a.root.find_group(uid(0x04)).is_some(), "{at}");
                assert!(!kinds(&m.changes).contains(&ChangeKind::Deleted), "{at}");
            }
        }
    }
}

/// F-155's copies (MOD-11.22): root(01) → G1(02) → E(0A) with Mod `m` and
/// Loc `loc`, G2(03), and H(0A), a group with E's id that holds F(0C) and
/// has Loc `h_loc`.
fn f155(m: Time, loc: Time, h_loc: Time) -> Vault {
    let mut e = ent(0x0a, "E", "p", m);
    e.times.location_changed = loc;
    let mut v = two_groups(vec![e]);
    let mut h = grp(0x0a, "H", t0());
    h.times.location_changed = h_loc;
    h.entries.push(ent(0x0c, "F", "f", t0()));
    v.root.groups.push(h);
    v
}

/// The item at T2 for each id in `ids`, in A's list or in B's.
fn f155_items(a: &mut Vault, b: &mut Vault, ids: &[u8], item_in_b: bool) {
    let items = ids.iter().map(|id| gone(*id, t2())).collect();
    if item_in_b {
        b.deleted_objects = items;
    } else {
        a.deleted_objects = items;
    }
}

/// F-155 Q1 (MOD-11.30, MOD-11.22, LD-288 (1)): B moved E after the item
/// at T2 (Loc T3); H, a group with E's id, did not move. E stays: the
/// deletion pass reads the source's time of the entry, not of the group.
/// The item is in A's list or in B's, and a second merge of the same B
/// keeps E too.
#[test]
fn mod11_30_an_entry_stays_when_a_group_shares_its_id() {
    for kind in F154_KINDS {
        for item_in_b in [false, true] {
            let mut a = f155(t1(), t0(), t0());
            let mut b = f155(t0(), t3(), t0());
            f155_items(&mut a, &mut b, &[0x0a], item_in_b);
            for round in ["first", "again"] {
                let at = format!("{kind:?}, item in B: {item_in_b}, {round}");
                let m = run(&mut a, &b, Options::new(kind));
                assert!(has_entry(&a, 0x0a), "{at}");
                assert!(a.root.find_group(uid(0x0a)).is_some(), "{at}");
                assert!(!kinds(&m.changes).contains(&ChangeKind::Deleted), "{at}");
            }
        }
    }
}

/// F-155 Q2 (MOD-11.30, MOD-11.22, LD-288 (1)): both copies hold E at
/// Mod T1, Loc T0; only B's H, a group with E's id, moved at T3. The item
/// at T2 erases E: the group's move does not keep the entry. H stays, as
/// it holds F. Also on a second merge of the same B.
#[test]
fn mod11_30_an_entry_is_erased_when_only_a_same_id_group_moved() {
    for kind in F154_KINDS {
        for item_in_b in [false, true] {
            let mut a = f155(t1(), t0(), t0());
            let mut b = f155(t1(), t0(), t3());
            f155_items(&mut a, &mut b, &[0x0a], item_in_b);
            for round in ["first", "again"] {
                let at = format!("{kind:?}, item in B: {item_in_b}, {round}");
                run(&mut a, &b, Options::new(kind));
                assert!(!has_entry(&a, 0x0a), "{at}");
                assert!(a.root.find_group(uid(0x0a)).is_some(), "{at}");
            }
        }
    }
}

/// F-155 Q3 (MOD-11.30, LD-288 (1)): the source's time keeps an object
/// only when it is after the item. A holds E(0A) and an empty group H(04)
/// at Mod T1, Loc T0; B moved both at T2, exactly the item time. Both are
/// erased, with the items in A's list or in B's, and stay erased on a
/// second merge of the same B.
#[test]
fn mod11_30_a_source_move_at_the_item_time_does_not_keep() {
    let held = |m: Time, loc: Time| {
        let mut e = ent(0x0a, "E", "p", m);
        e.times.location_changed = loc;
        let mut v = two_groups(vec![e]);
        let mut h = grp(0x04, "H", m);
        h.times.location_changed = loc;
        v.root.groups.push(h);
        v
    };
    for kind in F154_KINDS {
        for item_in_b in [false, true] {
            let mut a = held(t1(), t0());
            let mut b = held(t0(), t2());
            f155_items(&mut a, &mut b, &[0x0a, 0x04], item_in_b);
            for round in ["first", "again"] {
                let at = format!("{kind:?}, item in B: {item_in_b}, {round}");
                run(&mut a, &b, Options::new(kind));
                assert!(!has_entry(&a, 0x0a), "{at}");
                assert!(a.root.find_group(uid(0x04)).is_none(), "{at}");
            }
        }
    }
}

/// MOD-11.15 (D-11-9, LD-287 (2)): the source's own time counts only in a
/// same-vault merge. A shared-group import still erases by Mod: the
/// share's later Loc of E does not keep it.
#[test]
fn mod11_15_a_shared_group_import_still_erases_by_mod() {
    let mut a = shared(vec![ent(0x0a, "Old", "o", t0())], vec![]);
    let mut moved = ent(0x0a, "Old", "o", t0());
    moved.times.location_changed = t3();
    let mut root = grp(0x70, "Share", t0());
    root.entries.push(moved);
    let mut b = vault(root);
    b.deleted_objects.push(gone(0x0a, t1()));
    run(&mut a, &b, share());
    assert!(!has_entry(&a, 0x0a));
}
