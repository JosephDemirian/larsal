//! Checker 1, round 3: directed attacks on rule R6, ported in round 4. Demo data only.
//! Each test prints what it saw. Changed assertions say so where they stand: t3, t3b,
//! t3c and t14 pin limit 15 (C1-05), t7 pins limit 16 (C1-08), t25 holds a row for
//! every share that held the object (ruling 1).
#![allow(clippy::all, clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use larsal_core::edit::{self, Position};
use larsal_core::merge::{Kind, Options, merge};
use larsal_core::origin;
use larsal_core::recycle::{self, References};
use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved};
use larsal_model::settings::Kdf;
use larsal_model::{
    Attachment, CustomDataItem, CustomIcon, DeletedObject, Entry, Field, Group, Icon, Time, Uuid,
    Vault,
};
use larsal_share::{container, run};
use std::sync::Arc;

const T0: Time = Time(63_902_822_400);
const KINDS: [Kind; 6] = [
    Kind::ChangeOnDisk,
    Kind::ConflictCopy,
    Kind::ServerSync,
    Kind::Window,
    Kind::CommandLine,
    Kind::RemoteSync,
];
const ROOT: u8 = 0x01;
const T: u8 = 0x20;
const S: u8 = 0x21;
const U: u8 = 0x22;
const P: u8 = 0x30;
const O: u8 = 0x31;
const Q: u8 = 0x32;
const BIN: u8 = 0x5a;
const E: u8 = 0x50;
const F: u8 = 0x51;
const G: u8 = 0x52;

fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}
fn at(n: i64) -> Time {
    Time(T0.0 + n)
}
fn gm(g: &mut Group, n: u8) -> &mut Group {
    fn inner(g: &mut Group, n: u8) -> Option<&mut Group> {
        if g.uuid == id(n) {
            return Some(g);
        }
        g.groups.iter_mut().find_map(|c| inner(c, n))
    }
    inner(g, n).expect("group")
}
fn pw(e: &mut Entry, p: &str) {
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new(p.to_owned()),
            protected: true,
        },
    );
}
fn entry(n: u8, p: &str, m: Time, l: Time) -> Entry {
    let mut e = Entry::new(id(n), T0);
    pw(&mut e, p);
    e.times.last_modification = m;
    e.times.location_changed = l;
    e
}
fn item() -> CustomDataItem {
    CustomDataItem {
        key: core::str::from_utf8(edit::SHARED_KEY).unwrap().to_owned(),
        value: SecretString::new(String::new()),
        last_modified: None,
        unknown: Vec::new(),
    }
}
/// Root: P, T{S}, U, Q, Bin. Shares named by `shares`.
fn world(shares: &[u8]) -> Vault {
    let mut root = Group::new(id(ROOT), "Root".into(), T0);
    let mut t = Group::new(id(T), "T".into(), T0);
    t.groups.push(Group::new(id(S), "S".into(), T0));
    root.groups.push(Group::new(id(P), "P".into(), T0));
    root.groups.push(t);
    root.groups.push(Group::new(id(U), "U".into(), T0));
    root.groups.push(Group::new(id(Q), "Q".into(), T0));
    root.groups.push(Group::new(id(BIN), "Bin".into(), T0));
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = true;
    v.meta.recycle_bin = Some(id(BIN));
    v.meta.history_max_items = -1;
    v.meta.history_max_size = -1;
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    for s in shares {
        gm(&mut v.root, *s).custom_data.items.push(item());
    }
    v
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
/// Through a real file and back.
fn rt(v: &Vault) -> Vault {
    let p = SecretString::new("demo".to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    let mut h = host();
    let bytes = match larsal_format::save(v, &key, None, &mut h, &Limits::DEFAULT, None).unwrap() {
        Saved::File(f) => f.bytes,
        Saved::Ask(r) => {
            match larsal_format::save(v, &key, None, &mut h, &Limits::DEFAULT, Some(&r)).unwrap() {
                Saved::File(f) => f.bytes,
                Saved::Ask(_) => panic!("asked twice"),
            }
        }
    };
    match larsal_format::open(&bytes, &key, &mut host(), &Limits::DEFAULT, None).unwrap() {
        Opened::Vault(o) => o.vault,
        Opened::Ask(_) => panic!("asked"),
    }
}
fn cont(root: u8) -> Vault {
    let mut c = Vault::new(Group::new(id(root), "C".into(), T0), T0);
    c.meta.recycle_bin_enabled = false;
    c
}
fn m(t: &mut Vault, s: &Vault, kind: Kind, n: i64) -> usize {
    let source = rt(s);
    let got = merge(t, &source, &Options::new(kind), at(n)).unwrap();
    *t = rt(t);
    got.changes.len()
}
fn settle(a: &mut Vault, b: &mut Vault, kind: Kind, n: i64) {
    for k in 0..6 {
        m(a, b, kind, n + k);
        m(b, a, kind, n + k);
    }
}
fn walk_e<'a>(g: &'a Group, n: u8) -> Option<(Uuid, &'a Entry)> {
    for e in &g.entries {
        if e.uuid == id(n) {
            return Some((g.uuid, e));
        }
    }
    g.groups.iter().find_map(|c| walk_e(c, n))
}
fn show(v: &Vault, n: u8) -> String {
    match walk_e(&v.root, n) {
        None => "GONE".to_owned(),
        Some((p, e)) => format!(
            "in {:02x} pw {} hist [{}] loc {} mod {} stamp {:?} mark {}",
            p.0[0],
            e.value("Password"),
            e.history
                .iter()
                .map(|h| h.value("Password").to_owned())
                .collect::<Vec<_>>()
                .join(","),
            e.times.location_changed.0 - T0.0,
            e.times.last_modification.0 - T0.0,
            origin::stamp_of(&e.custom_data).map(|s| (s.group.0[0], s.at.0 - T0.0)),
            origin::mark_of(&e.custom_data).is_some()
        ),
    }
}
fn holds_value(g: &Group, val: &str) -> bool {
    g.entries
        .iter()
        .any(|e| e.value("Password") == val || e.history.iter().any(|h| h.value("Password") == val))
        || g.groups.iter().any(|c| holds_value(c, val))
}
fn any_value(v: &Vault, val: &str) -> bool {
    holds_value(&v.root, val)
}
fn rows(v: &Vault) -> String {
    let r = origin::read_rows(&v.meta.custom_data);
    let mut s: Vec<String> = r
        .iter()
        .map(|((i, g), t)| format!("{:02x}/{:02x}/{}", i.0[0], g.0[0], t.0 - T0.0))
        .collect();
    s.extend(
        v.deleted_objects
            .iter()
            .map(|d| format!("plain {:02x}/{}", d.uuid.0[0], d.deleted_at.0 - T0.0)),
    );
    s.join(" ")
}
fn del(v: &mut Vault, n: u8, now: Time) {
    let was = v.meta.recycle_bin_enabled;
    v.meta.recycle_bin_enabled = false;
    recycle::delete_entries(v, &[id(n)], now, |_, _| References::Delete).unwrap();
    v.meta.recycle_bin_enabled = was;
}
fn del_g(v: &mut Vault, n: u8, now: Time) {
    let was = v.meta.recycle_bin_enabled;
    v.meta.recycle_bin_enabled = false;
    recycle::delete_group(v, id(n), now).unwrap();
    v.meta.recycle_bin_enabled = was;
}

// -------- Honest values between nested and side by side shares --------

/// T1: B types a new password in T; later A, stale, moves E into nested share S.
#[test]
fn t1_nested_a_typed_password_survives_a_move_to_a_nested_share() {
    for kind in KINDS {
        let mut a = world(&[T, S]);
        gm(&mut a.root, T)
            .entries
            .push(entry(E, "seed-demo", at(1), at(1)));
        let mut b = a.duplicate();
        edit::edit_entry(&mut b, id(E), at(10), |d| pw(d, "typed-on-b-demo")).unwrap();
        edit::move_entries(&mut a, &[id(E)], id(S), at(20)).unwrap();
        settle(&mut a, &mut b, kind, 30);
        println!("{kind:?} t1: a {} | b {}", show(&a, E), show(&b, E));
        assert!(
            any_value(&a, "typed-on-b-demo") || any_value(&b, "typed-on-b-demo"),
            "the password the user typed on Mac B is gone on both Macs"
        );
    }
}

/// T1b: E in T, shares T and U. A moves E to U; B types a new password later. Both id orders.
#[test]
fn t1b_sibling_a_later_typed_password_survives() {
    for (from, to) in [(T, U), (U, T)] {
        let mut a = world(&[T, U]);
        gm(&mut a.root, from)
            .entries
            .push(entry(E, "seed-demo", at(1), at(1)));
        let mut b = a.duplicate();
        edit::move_entries(&mut a, &[id(E)], id(to), at(10)).unwrap();
        edit::edit_entry(&mut b, id(E), at(20), |d| pw(d, "typed-on-b-demo")).unwrap();
        settle(&mut a, &mut b, Kind::ChangeOnDisk, 30);
        println!(
            "t1b from {from:02x} to {to:02x}: a {} | b {}",
            show(&a, E),
            show(&b, E)
        );
        assert!(
            any_value(&a, "typed-on-b-demo") || any_value(&b, "typed-on-b-demo"),
            "from {from:02x} to {to:02x}: a later typed password is gone on both Macs"
        );
    }
}

/// T1c: E in S in T. A moves E up to T; B types a new password in S later.
#[test]
fn t1c_nested_up_a_later_typed_password_survives() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, S)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut b = a.duplicate();
    edit::move_entries(&mut a, &[id(E)], id(T), at(10)).unwrap();
    edit::edit_entry(&mut b, id(E), at(20), |d| pw(d, "typed-on-b-demo")).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 30);
    println!("t1c: a {} | b {}", show(&a, E), show(&b, E));
    assert!(
        any_value(&a, "typed-on-b-demo") || any_value(&b, "typed-on-b-demo"),
        "a later typed password is gone on both Macs"
    );
}

/// T1d: a whole loser keeps only one history item: its earlier versions go.
#[test]
fn t1d_a_whole_losers_earlier_versions() {
    let mut a = world(&[T]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut b = a.duplicate();
    edit::move_entries(&mut b, &[id(E)], id(P), at(10)).unwrap();
    edit::edit_entry(&mut a, id(E), at(20), |d| pw(d, "inside-later-demo")).unwrap();
    edit::edit_entry(&mut a, id(E), at(21), |d| pw(d, "inside-latest-demo")).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 30);
    println!("t1d: a {} | b {}", show(&a, E), show(&b, E));
    println!(
        "t1d: the earlier edit is kept: {}",
        any_value(&a, "inside-later-demo")
    );
}

// -------- A member of an inner share reaches the outer share --------

/// T2: H13's form with nested shares. E in T, not in S, on A and B. A member of S lists E.
/// A imports S and exports T; B imports T. The card: "a member of one share must not reach
/// another".
#[test]
fn t2_a_member_of_an_inner_share_does_not_erase_in_the_outer_share() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "t-only-demo", at(1), at(1)));
    let mut b = a.duplicate();
    let mut c = cont(S);
    c.deleted_objects.push(DeletedObject {
        uuid: id(E),
        deleted_at: at(5),
        unknown: Vec::new(),
    });
    run::merge_into(&mut a, id(S), &c, at(10)).unwrap();
    println!("t2 a after S import: {} rows {}", show(&a, E), rows(&a));
    let t_file = container::build(id(T), true, &a, at(11)).unwrap();
    let names: Vec<u8> = t_file.deleted_objects.iter().map(|d| d.uuid.0[0]).collect();
    println!("t2 T's export lists {names:02x?}");
    run::merge_into(&mut b, id(T), &t_file, at(12)).unwrap();
    println!("t2 b after T import: {} rows {}", show(&b, E), rows(&b));
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("t2 end: a {} | b {}", show(&a, E), show(&b, E));
    assert!(
        walk_e(&b.root, E).is_some(),
        "a member of nested S, not in T, erased an entry that sits in T outside S"
    );
}

// -------- A planted copy moved out and deleted --------

/// T3: B holds private E outside; A has no copy. A imports a planted E, moves it out, deletes it.
#[test]
fn t3_a_planted_copy_moved_out_and_deleted_leaves_mac_bs_private_entry() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    gm(&mut b.root, P)
        .entries
        .push(entry(E, "private-demo", at(1), at(1)));
    let mut c = cont(T);
    c.root.entries.push(entry(E, "planted-demo", at(5), at(5)));
    run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
    edit::move_entries(&mut a, &[id(E)], id(P), at(11)).unwrap();
    del(&mut a, E, at(12));
    println!("t3 a rows: {}", rows(&a));
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("t3 end: a {} | b {}", show(&a, E), show(&b, E));
    // Named as changed: limit 15 (C1-05) pins what happens; a fix turns this red.
    assert!(
        walk_e(&b.root, E).is_none(),
        "limit 15: a planted copy moved out and deleted erases Mac B's private entry"
    );
}

/// T3b: the same through the bin: move out, bin, empty the bin.
#[test]
fn t3b_a_planted_copy_moved_out_binned_and_emptied() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    gm(&mut b.root, P)
        .entries
        .push(entry(E, "private-demo", at(1), at(1)));
    let mut c = cont(T);
    c.root.entries.push(entry(E, "planted-demo", at(5), at(5)));
    run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
    edit::move_entries(&mut a, &[id(E)], id(P), at(11)).unwrap();
    recycle::delete_entries(&mut a, &[id(E)], at(12), |_, _| References::Delete).unwrap();
    recycle::empty_bin(&mut a, at(13)).unwrap();
    println!("t3b a rows: {}", rows(&a));
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("t3b end: a {} | b {}", show(&a, E), show(&b, E));
    // Named as changed: limit 15 (C1-05).
    assert!(
        walk_e(&b.root, E).is_none(),
        "limit 15: erased through move out, bin, empty"
    );
}

/// T3c: planted group moved out, deleted: its entries with a private id are erased on B.
#[test]
fn t3c_a_planted_group_moved_out_and_deleted() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    gm(&mut b.root, P)
        .entries
        .push(entry(E, "private-demo", at(1), at(1)));
    let mut c = cont(T);
    let mut o = Group::new(id(O), "planted".into(), at(5));
    o.entries.push(entry(E, "planted-demo", at(5), at(5)));
    c.root.groups.push(o);
    run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
    edit::move_group(&mut a, id(O), id(P), Position::End, at(11)).unwrap();
    del_g(&mut a, O, at(12));
    println!("t3c a rows: {}", rows(&a));
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("t3c end: a {} | b {}", show(&a, E), show(&b, E));
    // Named as changed: limit 15 (C1-05).
    assert!(
        walk_e(&b.root, E).is_none(),
        "limit 15: erased through a planted group moved out and deleted"
    );
}

// -------- The root share --------

/// T4: a root share. A bin item is not exported (INT-08.35). Can a container pull it out?
#[test]
fn t4a_a_root_shares_container_does_not_pull_a_recycled_value_out() {
    let mut a = world(&[ROOT]);
    gm(&mut a.root, BIN).entries.push({
        let mut e = entry(E, "recycled-demo", at(1), at(1));
        e.previous_parent = Some(id(P));
        e
    });
    let mut c = cont(ROOT);
    c.root.entries.push(entry(E, "planted-demo", at(5), at(50)));
    let got = run::merge_into(&mut a, id(ROOT), &c, at(100)).unwrap();
    println!(
        "t4a changed {} outside {} : {}",
        got.changed,
        got.outside,
        show(&a, E)
    );
    let file = container::build(id(ROOT), true, &a, at(101)).unwrap();
    println!(
        "t4a export holds the recycled value: {}",
        holds_value(&file.root, "recycled-demo")
    );
    assert!(
        !holds_value(&file.root, "recycled-demo"),
        "a recycled value left by a root export"
    );
}

#[test]
fn t4b_a_root_shares_container_does_not_touch_the_bin_group() {
    let mut a = world(&[ROOT]);
    let bin_before = gm(&mut a.root, BIN).name.clone();
    let mut c = cont(ROOT);
    let mut planted_bin = Group::new(id(BIN), "renamed-by-member".into(), at(5));
    planted_bin
        .entries
        .push(entry(F, "planted-demo", at(5), at(5)));
    c.root.groups.push(planted_bin);
    run::merge_into(&mut a, id(ROOT), &c, at(102)).unwrap();
    let name = gm(&mut a.root, BIN).name.clone();
    println!("t4b bin name now {} entry F {}", name, show(&a, F));
    assert_eq!(
        gm(&mut a.root, BIN).name,
        bin_before,
        "a container renamed the bin"
    );
}

// -------- Attachments --------

fn attach(e: &mut Entry, name: &str, data: &str) {
    e.attachments.push(Attachment {
        name: name.to_owned(),
        data: Arc::new(SecretBytes::new(data.as_bytes().to_vec())),
    });
}
fn export_has_attachment(c: &Vault, want: &str) -> bool {
    fn g_has(g: &Group, want: &str) -> bool {
        let e_has = |e: &Entry| {
            e.attachments
                .iter()
                .any(|a| a.data.expose() == want.as_bytes())
        };
        g.entries
            .iter()
            .any(|e| e_has(e) || e.history.iter().any(|h| e_has(h)))
            || g.groups.iter().any(|c| g_has(c, want))
    }
    g_has(&c.root, want)
}

/// T6: a private attachment on an outside copy never reaches an export; a planted attachment
/// never becomes the outside copy's current one.
#[test]
fn t6_attachments_do_not_cross() {
    for kind in KINDS {
        let mut a = world(&[T]);
        let mut b = a.duplicate();
        let mut e = entry(E, "private-demo", at(1), at(1));
        attach(&mut e, "doc", "private-attachment-demo");
        gm(&mut b.root, P).entries.push(e);
        let mut c = cont(T);
        let mut pl = entry(E, "planted-demo", at(5), at(5));
        attach(&mut pl, "doc", "planted-attachment-demo");
        c.root.entries.push(pl);
        run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
        settle(&mut a, &mut b, kind, 20);
        for v in [&a, &b] {
            let file = container::build(id(T), true, v, at(100)).unwrap();
            assert!(
                !export_has_attachment(&file, "private-attachment-demo"),
                "{kind:?}: leak"
            );
            let (p, e) = walk_e(&v.root, E).unwrap();
            assert_eq!(p, id(P), "{kind:?}");
            assert_eq!(
                e.attachments[0].data.expose(),
                b"private-attachment-demo",
                "{kind:?}"
            );
        }
    }
}

/// T6b: an attachment added after a move out and a member's attachment inside.
#[test]
fn t6b_a_move_out_with_an_attachment_added_inside_later() {
    let mut a = world(&[T]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut b = a.duplicate();
    edit::move_entries(&mut b, &[id(E)], id(P), at(10)).unwrap();
    edit::edit_entry(&mut b, id(E), at(11), |d| {
        attach(d, "x", "private-attachment-demo")
    })
    .unwrap();
    edit::edit_entry(&mut a, id(E), at(20), |d| {
        attach(d, "y", "member-attachment-demo")
    })
    .unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 30);
    let file = container::build(id(T), true, &a, at(100)).unwrap();
    println!("t6b {} | {}", show(&a, E), show(&b, E));
    assert!(!export_has_attachment(&file, "private-attachment-demo"));
    let (_, e) = walk_e(&a.root, E).unwrap();
    assert_eq!(e.attachments[0].data.expose(), b"private-attachment-demo");
}

// -------- Custom icons --------

/// T7: a planted entry naming a private icon id gets that icon's image in the export.
#[test]
fn t7_a_planted_entry_cannot_export_a_private_icon_it_names() {
    let mut a = world(&[T]);
    a.meta.custom_icons.push(CustomIcon {
        uuid: id(0x77),
        name: "private-icon".into(),
        last_modified: None,
        data: vec![0x89, 0x50, 0x4E, 0x47, 1, 2, 3],
        unknown: Vec::new(),
    });
    let mut c = cont(T);
    let mut pl = entry(F, "planted-demo", at(5), at(5));
    pl.icon = Icon::Custom(id(0x77));
    c.root.entries.push(pl);
    run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
    let file = container::build(id(T), true, &a, at(11)).unwrap();
    println!("t7 export icons {}", file.meta.custom_icons.len());
    // Named as changed: limit 16 (C1-08) pins it. An icon id names only an image the
    // vault holds; no value, name or note of an outside object goes with it.
    assert_eq!(
        file.meta.custom_icons.len(),
        1,
        "limit 16: a member who names a private icon id gets its image"
    );
}

/// T7b: a planted icon with a private group's id, purged.
#[test]
fn t7b_purging_an_icon_named_as_an_outside_group() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    let mut c = cont(T);
    c.meta.custom_icons.push(CustomIcon {
        uuid: id(P),
        name: String::new(),
        last_modified: None,
        data: vec![0x89, 0x50, 0x4E, 0x47],
        unknown: Vec::new(),
    });
    run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
    assert_eq!(larsal_core::icons::purge(&mut a, at(11)), 1);
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    assert!(a.root.find_group(id(P)).is_some());
    assert!(b.root.find_group(id(P)).is_some());
    println!("t7b rows {}", rows(&a));
}

// -------- Group fields --------

/// T8: every field of a planted group's copy stays off the outside group.
#[test]
fn t8_group_fields_of_a_planted_copy_never_reach_the_outside_group() {
    for kind in KINDS {
        for (mine, theirs) in [(0usize, 1usize), (1, 0)] {
            let mut macs = vec![world(&[T]), world(&[T])];
            let mut o = Group::new(id(O), "private-name".into(), at(1));
            o.notes = "private-notes".into();
            o.tags = "private-tag".into();
            o.default_sequence = "private-seq".into();
            o.times.last_modification = at(1);
            o.times.location_changed = at(1);
            let private_icon = o.icon;
            gm(&mut macs[1].root, P).groups.push(o);
            let mut c = cont(T);
            let mut pl = Group::new(id(O), "planted-name".into(), at(50));
            pl.notes = "planted-notes".into();
            pl.tags = "planted-tag".into();
            pl.default_sequence = "planted-seq".into();
            pl.icon = Icon::Custom(id(0x77));
            pl.custom_data.items.push(CustomDataItem {
                key: "planted-key".into(),
                value: SecretString::new("planted-value".to_owned()),
                last_modified: None,
                unknown: Vec::new(),
            });
            pl.times.last_modification = at(50);
            pl.times.location_changed = at(50);
            c.root.groups.push(pl);
            run::merge_into(&mut macs[0], id(T), &c, at(100)).unwrap();
            let s = macs[theirs].duplicate();
            m(&mut macs[mine], &s, kind, 101);
            let s = macs[mine].duplicate();
            m(&mut macs[theirs], &s, kind, 102);
            let s = macs[theirs].duplicate();
            m(&mut macs[mine], &s, kind, 103);
            for v in macs.iter_mut() {
                let o = gm(&mut v.root, O);
                assert_eq!(
                    (
                        o.name.as_str(),
                        o.notes.as_str(),
                        o.tags.as_str(),
                        o.default_sequence.as_str()
                    ),
                    (
                        "private-name",
                        "private-notes",
                        "private-tag",
                        "private-seq"
                    ),
                    "{kind:?}"
                );
                assert_eq!(o.icon, private_icon, "{kind:?}: icon");
                assert!(
                    o.custom_data.get("planted-key").is_none(),
                    "{kind:?}: custom data"
                );
                assert!(origin::mark_of(&o.custom_data).is_none(), "{kind:?}");
                let file = container::build(id(T), true, v, at(200)).unwrap();
                assert!(file.root.find_group(id(O)).is_none());
            }
        }
    }
}

/// T8b: an honest later edit of a group's fields on the inside copy, after a user's move out.
#[test]
fn t8b_a_groups_later_fields_on_a_stale_inside_copy() {
    let mut a = world(&[T]);
    let mut o = Group::new(id(O), "seed".into(), at(1));
    o.times.last_modification = at(1);
    o.times.location_changed = at(1);
    gm(&mut a.root, T).groups.push(o);
    let mut b = a.duplicate();
    edit::move_group(&mut a, id(O), id(P), Position::End, at(10)).unwrap();
    edit::edit_group(&mut b, id(O), at(20), |d| d.notes = "typed-on-b".into()).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 30);
    println!(
        "t8b a notes {:?} b notes {:?}",
        gm(&mut a.root, O).notes,
        gm(&mut b.root, O).notes
    );
}

// -------- History pruning --------

/// T9: flows with history pruned to few items. A planted value never reaches an outside copy's
/// current value and a private value never an export.
#[test]
fn t9_pruning_on_a_planted_copy_changes_nothing_outside() {
    for limit in [0, 1, 2] {
        for kind in KINDS {
            let mut a = world(&[T]);
            a.meta.history_max_items = limit;
            let mut b = a.duplicate();
            let mut e = entry(E, "private-demo", at(1), at(1));
            e.history.push(entry(E, "private-old-demo", at(0), at(0)));
            gm(&mut b.root, P).entries.push(e);
            let mut c = cont(T);
            let mut pl = entry(E, "planted-demo", at(5), at(5));
            pl.history.push(entry(E, "planted-h1-demo", at(4), at(4)));
            pl.history.push(entry(E, "planted-h2-demo", at(3), at(3)));
            c.root.entries.push(pl);
            run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
            settle(&mut a, &mut b, kind, 20);
            println!(
                "t9 limit {limit} {kind:?}: a {} | b {}",
                show(&a, E),
                show(&b, E)
            );
            for v in [&a, &b] {
                let (p, e) = walk_e(&v.root, E).unwrap();
                assert_eq!(p, id(P));
                assert_eq!(e.value("Password"), "private-demo");
                let file = container::build(id(T), true, v, at(100)).unwrap();
                assert!(!holds_value(&file.root, "private-demo"));
                assert!(!holds_value(&file.root, "private-old-demo"));
            }
        }
    }
}

/// T9b: S2 of the model with few history items. The history item with the later time is what
/// makes a stale stamp fail (Later reads history). With no history the stamp is valid.
#[test]
fn t9b_s2_with_pruning() {
    for limit in [-1, 0, 1, 2] {
        let mut m0 = world(&[T]);
        m0.meta.history_max_items = limit;
        let mut m2 = m0.duplicate();
        gm(&mut m0.root, P)
            .entries
            .push(entry(E, "seed-demo", at(1), at(1)));
        let mut m1 = m0.duplicate();
        edit::move_entries(&mut m1, &[id(E)], id(T), at(2)).unwrap();
        let mut c = cont(T);
        c.root.entries.push(entry(E, "planted-demo", at(0), at(0)));
        run::merge_into(&mut m2, id(T), &c, at(3)).unwrap();
        edit::move_entries(&mut m2, &[id(E)], id(P), at(4)).unwrap();
        edit::edit_entry(&mut m2, id(E), at(5), |d| pw(d, "typed-private-demo")).unwrap();
        let mut macs = vec![m0, m1, m2];
        for round in 0..4 {
            for (t, s) in [(0, 2), (2, 0), (0, 1), (1, 0), (1, 2), (2, 1)] {
                let src = macs[s].duplicate();
                m(&mut macs[t], &src, Kind::ChangeOnDisk, 10 + round);
            }
        }
        for (i, v) in macs.iter().enumerate() {
            let file = container::build(id(T), true, v, at(100)).unwrap();
            let leak = holds_value(&file.root, "typed-private-demo");
            println!("t9b limit {limit} mac {i}: {} leak {leak}", show(v, E));
            assert!(
                !leak,
                "limit {limit}: a value typed outside goes out with no move of it"
            );
        }
    }
}

// -------- Share group deletion and removal --------

/// T10: T deleted for good with rows, while Mac B moved an entry out of T: B's outside entry stays.
#[test]
fn t10_a_share_group_deleted_for_good() {
    for kind in KINDS {
        let mut a = world(&[T]);
        for (x, p) in [(E, "seed-demo"), (F, "seed-f-demo"), (G, "seed-g-demo")] {
            gm(&mut a.root, T).entries.push(entry(x, p, at(1), at(1)));
        }
        let mut b = a.duplicate();
        edit::move_entries(&mut b, &[id(E)], id(P), at(5)).unwrap();
        edit::edit_entry(&mut b, id(G), at(30), |d| pw(d, "later-g-demo")).unwrap();
        del_g(&mut a, T, at(20));
        println!("t10 a rows {}", rows(&a));
        settle(&mut a, &mut b, kind, 40);
        println!(
            "t10 {kind:?}: E a {} b {} | F a {} b {} | G a {} b {}",
            show(&a, E),
            show(&b, E),
            show(&a, F),
            show(&b, F),
            show(&a, G),
            show(&b, G)
        );
        println!(
            "t10 T on a {} on b {}",
            a.root.find_group(id(T)).is_some(),
            b.root.find_group(id(T)).is_some()
        );
        assert_eq!(walk_e(&a.root, E).map(|x| x.0), Some(id(P)), "{kind:?}");
        assert_eq!(walk_e(&b.root, E).map(|x| x.0), Some(id(P)), "{kind:?}");
        assert!(walk_e(&b.root, F).is_none(), "{kind:?}: F");
        assert!(walk_e(&a.root, F).is_none(), "{kind:?}: F");
        assert_eq!(
            walk_e(&a.root, G).map(|x| x.1.value("Password").to_owned()),
            Some("later-g-demo".into()),
            "{kind:?}"
        );
    }
}

/// T10b: a share item taken off, rows stay, then a move into the old group.
#[test]
fn t10b_a_share_removed_a_dormant_row_and_a_move_back() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    gm(&mut b.root, P)
        .entries
        .push(entry(E, "private-demo", at(1), at(1)));
    let mut c = cont(T);
    c.deleted_objects.push(DeletedObject {
        uuid: id(E),
        deleted_at: at(50),
        unknown: Vec::new(),
    });
    run::merge_into(&mut a, id(T), &c, at(100)).unwrap();
    gm(&mut a.root, T).custom_data.items.clear();
    gm(&mut b.root, T).custom_data.items.clear();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 101);
    println!(
        "t10b rows {} E on a {} b {}",
        rows(&a),
        show(&a, E),
        show(&b, E)
    );
    assert_eq!(walk_e(&b.root, E).map(|x| x.0), Some(id(P)));
    edit::move_entries(&mut b, &[id(E)], id(T), at(200)).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 201);
    println!("t10b after move in {} rows {}", show(&b, E), rows(&b));
    assert_eq!(walk_e(&b.root, E).map(|x| x.0), Some(id(T)));
}

/// T10c: a share's group in the bin on one Mac, an import on the other, then emptied.
#[test]
fn t10c_a_share_group_binned_on_one_mac_imported_on_the_other() {
    let mut a = world(&[T]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut b = a.duplicate();
    recycle::delete_group(&mut a, id(T), at(10)).unwrap();
    let mut c = cont(T);
    c.root.entries.push(entry(F, "member-demo", at(5), at(5)));
    run::merge_into(&mut b, id(T), &c, at(20)).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 30);
    println!(
        "t10c a {} {} | b {} {}",
        show(&a, E),
        show(&a, F),
        show(&b, E),
        show(&b, F)
    );
    println!(
        "t10c T in bin on a {} on b {}",
        recycle::group_in_bin(&a, id(T)),
        recycle::group_in_bin(&b, id(T))
    );
    assert!(walk_e(&a.root, F).is_some());
    recycle::empty_bin(&mut a, at(40)).unwrap();
    println!("t10c rows after empty {}", rows(&a));
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 50);
    println!(
        "t10c after empty: a {} {} | b {} {}",
        show(&a, E),
        show(&a, F),
        show(&b, E),
        show(&b, F)
    );
}

/// T11: moving a share group: T into U, B edited before the move. Share groups are fixed in
/// the model. No value lost, nothing outside touched.
#[test]
fn t11_a_share_group_moved_into_another_share_keeps_a_typed_value() {
    for kind in KINDS {
        let mut a = world(&[T, U]);
        gm(&mut a.root, T)
            .entries
            .push(entry(E, "seed-demo", at(1), at(1)));
        let mut b = a.duplicate();
        edit::edit_entry(&mut b, id(E), at(5), |d| pw(d, "typed-on-b-demo")).unwrap();
        edit::move_group(&mut a, id(T), id(U), Position::End, at(10)).unwrap();
        settle(&mut a, &mut b, kind, 20);
        println!("t11 {kind:?}: a {} | b {}", show(&a, E), show(&b, E));
        assert!(
            any_value(&a, "typed-on-b-demo"),
            "{kind:?}: value lost when a share group moved into another"
        );
    }
}

/// T11b: a plain group holding a share moved into a share, and back out.
#[test]
fn t11b_a_share_in_a_plain_group_moved_in_and_out() {
    let mut a = world(&[T, U]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    edit::move_group(&mut a, id(T), id(P), Position::End, at(5)).unwrap();
    let mut b = a.duplicate();
    edit::move_group(&mut a, id(P), id(U), Position::End, at(10)).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!(
        "t11b {} parent of P on b in U {}",
        show(&b, E),
        gm(&mut b.root, U).groups.iter().any(|g| g.uuid == id(P))
    );
    edit::move_group(&mut b, id(P), id(ROOT), Position::End, at(30)).unwrap();
    edit::edit_entry(&mut a, id(E), at(40), |d| pw(d, "later-demo")).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 50);
    println!("t11b after out: a {} | b {}", show(&a, E), show(&b, E));
    println!(
        "t11b P on root a {}",
        a.root.groups.iter().any(|g| g.uuid == id(P))
    );
}

// -------- A repeat merge says nothing --------

fn quiet_after_settle(a: &mut Vault, b: &mut Vault) {
    settle(a, b, Kind::ChangeOnDisk, 900);
    let n1 = m(a, b, Kind::ChangeOnDisk, 910);
    let n2 = m(b, a, Kind::ChangeOnDisk, 911);
    assert_eq!((n1, n2), (0, 0), "a settled pair still records changes");
}

#[test]
fn t12_settled_copies_record_nothing_in_the_corners() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut b = a.duplicate();
    edit::move_entries(&mut a, &[id(E)], id(S), at(20)).unwrap();
    edit::edit_entry(&mut b, id(E), at(10), |d| pw(d, "typed-on-b-demo")).unwrap();
    quiet_after_settle(&mut a, &mut b);
    // A bin item whose previous parent goes.
    let mut a = world(&[T]);
    let mut o = Group::new(id(O), "O".into(), at(1));
    o.entries.push(entry(E, "seed-demo", at(1), at(1)));
    gm(&mut a.root, T).groups.push(o);
    let mut b = a.duplicate();
    recycle::delete_entries(&mut a, &[id(E)], at(10), |_, _| References::Delete).unwrap();
    del_g(&mut b, O, at(20));
    println!(
        "t12 a {} b {} rows a {} b {}",
        show(&a, E),
        show(&b, E),
        rows(&a),
        rows(&b)
    );
    quiet_after_settle(&mut a, &mut b);
    println!("t12 end a {} b {}", show(&a, E), show(&b, E));
}

#[test]
fn t_helpers_are_used() {
    let _ = Q;
}

// -------- Second batch --------

/// One container through a real file: saved under a share password, read by the real open.
fn real(c: &Vault) -> Vault {
    let pass = SecretString::new("demo-share".to_owned());
    let key = container::credentials(&pass);
    let mut h = host();
    let bytes = match larsal_format::save(c, &key, None, &mut h, &Limits::DEFAULT, None).unwrap() {
        Saved::File(f) => f.bytes,
        Saved::Ask(r) => {
            match larsal_format::save(c, &key, None, &mut h, &Limits::DEFAULT, Some(&r)).unwrap() {
                Saved::File(f) => f.bytes,
                Saved::Ask(_) => panic!("asked twice"),
            }
        }
    };
    container::open(&bytes, &pass, &mut host(), &Limits::DEFAULT)
        .unwrap()
        .vault
}

/// T2r: T2 on real files, an honest form: E started in S; the user moved it up to T; a member
/// of S who still holds it deletes it. E is outside S now, in T, with Mac B a member of T.
#[test]
fn t2r_a_member_of_s_deletes_an_entry_the_user_moved_up_to_t() {
    for kind in KINDS {
        let mut a = world(&[T, S]);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "shared-demo", at(1), at(1)));
        // The member's file before the move: E in S.
        let s_file_with_e = container::build(id(S), true, &a, at(2)).unwrap();
        edit::move_entries(&mut a, &[id(E)], id(T), at(5)).unwrap();
        let mut b = a.duplicate();
        // The member deletes it in their stale copy, and writes the file.
        let mut member = s_file_with_e.duplicate();
        member.root.entries.clear();
        member.deleted_objects.push(DeletedObject {
            uuid: id(E),
            deleted_at: at(6),
            unknown: Vec::new(),
        });
        member.encryption.kdf = Kdf::AesKdf { rounds: 1 };
        run::merge_into(&mut a, id(S), &real(&member), at(10)).unwrap();
        println!(
            "t2r {kind:?} a after S import: {} rows {}",
            show(&a, E),
            rows(&a)
        );
        assert!(
            walk_e(&a.root, E).is_some(),
            "S's import alone stays out of T"
        );
        let mut t_file = container::build(id(T), true, &a, at(11)).unwrap();
        t_file.encryption.kdf = Kdf::AesKdf { rounds: 1 };
        let names: Vec<u8> = t_file.deleted_objects.iter().map(|d| d.uuid.0[0]).collect();
        println!("t2r T's export lists {names:02x?}");
        run::merge_into(&mut b, id(T), &real(&t_file), at(12)).unwrap();
        println!("t2r b after T import: {} rows {}", show(&b, E), rows(&b));
        settle(&mut a, &mut b, kind, 20);
        println!("t2r end: a {} | b {}", show(&a, E), show(&b, E));
        assert!(
            walk_e(&a.root, E).is_some() && walk_e(&b.root, E).is_some(),
            "{kind:?}: a member of S erased an entry the user had moved out of S, on both Macs"
        );
    }
}

/// T14: the F2 family through a stamp: a planted copy the user moves to another share, then
/// deletes. Mac B's private entry goes.
#[test]
fn t14_a_planted_copy_moved_to_another_share_and_deleted() {
    let mut a = world(&[T, U]);
    let mut b = a.duplicate();
    gm(&mut b.root, P)
        .entries
        .push(entry(E, "private-demo", at(1), at(1)));
    let mut c = cont(T);
    c.root.entries.push(entry(E, "planted-demo", at(5), at(5)));
    run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
    edit::move_entries(&mut a, &[id(E)], id(U), at(11)).unwrap();
    del(&mut a, E, at(12));
    println!("t14 a rows: {}", rows(&a));
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("t14 end: a {} | b {}", show(&a, E), show(&b, E));
    // Named as changed: limit 15 (C1-05), through a move to another share.
    assert!(
        walk_e(&b.root, E).is_none(),
        "limit 15: Mac B's private entry erased"
    );
}

/// T15: a member of T moves an entry to nested S in their file and edits it.
#[test]
fn t15_a_members_honest_move_to_the_nested_share_and_edit() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut b = a.duplicate();
    let mut f = container::build(id(T), true, &a, at(2)).unwrap();
    let mut e = f.root.entries.remove(0);
    pw(&mut e, "member-typed-demo");
    e.times.last_modification = at(5);
    e.times.location_changed = at(5);
    f.root
        .groups
        .iter_mut()
        .find(|g| g.uuid == id(S))
        .unwrap()
        .entries
        .push(e);
    run::merge_into(&mut a, id(T), &f, at(10)).unwrap();
    println!("t15 a after import: {}", show(&a, E));
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("t15 end: a {} | b {}", show(&a, E), show(&b, E));
    assert!(
        any_value(&a, "member-typed-demo"),
        "a member's honest edit and move are gone on every Mac"
    );
}

/// T16: one share, three Macs, no member: a value typed outside goes.
#[test]
fn t16_one_share_three_macs_a_value_typed_outside() {
    let mut m0 = world(&[T]);
    gm(&mut m0.root, P)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut m1 = m0.duplicate();
    let mut m2 = m0.duplicate();
    // Mac 0 types; Mac 2, stale, moves it in later; Mac 1, stale, types later still.
    edit::edit_entry(&mut m0, id(E), at(10), |d| pw(d, "typed-on-0-demo")).unwrap();
    edit::move_entries(&mut m2, &[id(E)], id(T), at(20)).unwrap();
    let src = m2.duplicate();
    m(&mut m0, &src, Kind::ChangeOnDisk, 21);
    println!("t16 m0 after m2: {}", show(&m0, E));
    edit::edit_entry(&mut m1, id(E), at(30), |d| pw(d, "typed-on-1-demo")).unwrap();
    let mut macs = vec![m0, m1, m2];
    for round in 0..4 {
        for (t, s) in [(0usize, 1usize), (1, 0), (2, 0), (0, 2), (1, 2), (2, 1)] {
            let src = macs[s].duplicate();
            m(&mut macs[t], &src, Kind::ChangeOnDisk, 40 + round);
        }
    }
    println!(
        "t16 end: {} | {} | {}",
        show(&macs[0], E),
        show(&macs[1], E),
        show(&macs[2], E)
    );
    assert!(
        any_value(&macs[0], "typed-on-0-demo"),
        "a value a user typed on an outside copy, no member anywhere, is on no Mac"
    );
}

/// T17: a user's earlier versions on a stale inside copy.
#[test]
fn t17_one_share_two_macs_inside_versions() {
    let mut m0 = world(&[T]);
    gm(&mut m0.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut m1 = m0.duplicate();
    // Mac 0 types twice in the share; Mac 1, stale, moves E out.
    edit::edit_entry(&mut m0, id(E), at(10), |d| pw(d, "typed-1-demo")).unwrap();
    edit::edit_entry(&mut m0, id(E), at(11), |d| pw(d, "typed-2-demo")).unwrap();
    edit::move_entries(&mut m1, &[id(E)], id(P), at(20)).unwrap();
    settle(&mut m0, &mut m1, Kind::ChangeOnDisk, 30);
    println!("t17 end: {} | {}", show(&m0, E), show(&m1, E));
    assert!(any_value(&m0, "typed-2-demo"), "the last value");
    assert!(
        any_value(&m0, "typed-1-demo"),
        "an earlier version typed by the user is on no Mac"
    );
}

/// T18: two Macs with two bins: a bin item whose previous parent is in T.
#[test]
fn t18_two_bins() {
    let mut a = world(&[T]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut b = a.duplicate();
    // Mac B has its own bin, id 0x5b.
    b.root.groups.retain(|g| g.uuid != id(BIN));
    b.root.groups.push(Group::new(id(0x5b), "Bin b".into(), T0));
    b.meta.recycle_bin = Some(id(0x5b));
    recycle::delete_entries(&mut a, &[id(E)], at(10), |_, _| References::Delete).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("t18 a {} | b {}", show(&a, E), show(&b, E));
    println!(
        "t18 in bin a {} b {}",
        recycle::entry_in_bin(&a, id(E)),
        recycle::entry_in_bin(&b, id(E))
    );
    let s = b.duplicate();
    let n1 = m(&mut a, &s, Kind::ChangeOnDisk, 900);
    let s = a.duplicate();
    let n2 = m(&mut b, &s, Kind::ChangeOnDisk, 901);
    assert_eq!((n1, n2), (0, 0), "settled pair records changes");
    let f = container::build(id(T), true, &a, at(902)).unwrap();
    assert!(!holds_value(&f.root, "seed-demo"), "bin item exported");
}

/// T19: the plain record of a private deletion is in every share's export.
#[test]
fn t19_a_private_deletion_in_every_export() {
    let mut a = world(&[T]);
    gm(&mut a.root, P)
        .entries
        .push(entry(E, "private-demo", at(1), at(1)));
    del(&mut a, E, at(10));
    let f = container::build(id(T), true, &a, at(11)).unwrap();
    let names: Vec<u8> = f.deleted_objects.iter().map(|d| d.uuid.0[0]).collect();
    println!("t19 T's export lists {names:02x?}: a private entry's id and when it went");
}

// -------- Third batch --------

/// T22: what an export says of a place outside the share.
#[test]
fn t22_an_export_names_the_private_group_an_entry_came_from() {
    let mut a = world(&[T]);
    gm(&mut a.root, P)
        .entries
        .push(entry(E, "own-demo", at(1), at(1)));
    edit::move_entries(&mut a, &[id(E)], id(T), at(5)).unwrap();
    let f = container::build(id(T), true, &a, at(6)).unwrap();
    let got = f.root.entries[0].previous_parent.map(|p| p.0[0]);
    println!("t22 the export's copy names previous parent {got:02x?} (P is 30)");
}

/// T24: a user deletes an entry that sits in nested share S. Does a member of S, who is not a
/// member of T, hear of it? The member's vault is another vault with S as its share.
#[test]
fn t24_a_users_deletion_in_a_nested_share_reaches_that_shares_member() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, S)
        .entries
        .push(entry(E, "in-s-demo", at(1), at(1)));
    // The member takes S's container into their own vault.
    let mut member = Vault::new(Group::new(id(0x70), "Member root".into(), T0), T0);
    member.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    let mut sm = Group::new(id(S), "S".into(), T0);
    sm.custom_data.items.push(item());
    member.root.groups.push(sm);
    let first = container::build(id(S), true, &a, at(2)).unwrap();
    run::merge_into(&mut member, id(S), &first, at(3)).unwrap();
    println!("t24 member after first import: {}", show(&member, E));
    assert!(walk_e(&member.root, E).is_some());
    // The user deletes it for good.
    del(&mut a, E, at(10));
    println!("t24 a rows: {}", rows(&a));
    let second = container::build(id(S), true, &a, at(11)).unwrap();
    let names: Vec<u8> = second.deleted_objects.iter().map(|d| d.uuid.0[0]).collect();
    println!("t24 S's export lists {names:02x?}");
    run::merge_into(&mut member, id(S), &second, at(12)).unwrap();
    println!("t24 member after second import: {}", show(&member, E));
    // The member's next export comes back.
    let back = container::build(id(S), true, &member, at(13)).unwrap();
    run::merge_into(&mut a, id(S), &back, at(14)).unwrap();
    println!("t24 a after the member's export: {}", show(&a, E));
    assert!(
        walk_e(&member.root, E).is_none(),
        "a user's deletion in S never reaches S's member"
    );
}

/// T24b: the same, S deleted from under T with the member of T as the other side.
#[test]
fn t24b_a_users_deletion_in_an_outer_share_reaches_its_member() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, S)
        .entries
        .push(entry(E, "in-s-demo", at(1), at(1)));
    let mut member = Vault::new(Group::new(id(0x70), "Member root".into(), T0), T0);
    member.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    let mut tm = Group::new(id(T), "T".into(), T0);
    tm.custom_data.items.push(item());
    member.root.groups.push(tm);
    let first = container::build(id(T), true, &a, at(2)).unwrap();
    run::merge_into(&mut member, id(T), &first, at(3)).unwrap();
    assert!(walk_e(&member.root, E).is_some());
    del(&mut a, E, at(10));
    let second = container::build(id(T), true, &a, at(11)).unwrap();
    run::merge_into(&mut member, id(T), &second, at(12)).unwrap();
    println!("t24b member after second import: {}", show(&member, E));
    assert!(walk_e(&member.root, E).is_none());
}

/// T25: three levels: T holds X (plain) holds S2 (a share). A user deletes an entry in S2:
/// one row for every share that held it (round 4, ruling 1; round 3 wrote one, for T).
#[test]
fn t25_three_levels_one_row_for_the_outermost() {
    let mut a = world(&[T]);
    let mut x = Group::new(id(0x24), "X".into(), T0);
    let mut s2 = Group::new(id(0x25), "S2".into(), T0);
    s2.custom_data.items.push(item());
    s2.entries.push(entry(E, "deep-demo", at(1), at(1)));
    x.groups.push(s2);
    gm(&mut a.root, T).groups.push(x);
    let mut b = a.duplicate();
    del(&mut a, E, at(10));
    println!("t25 a rows: {}", rows(&a));
    // Named as changed: was "50/20/10".
    assert_eq!(rows(&a), "50/20/10 50/25/10");
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    assert!(walk_e(&b.root, E).is_none());
    let _ = &mut b;
}

/// Round 4, the size cost (ruling 1): a deletion writes one row for each share that held
/// the object, so its cost is 45 bytes times the shares it counts in, plus 33 bytes the
/// first time a share has a row. Three nested shares, two deletions: 3 x 33 + 6 x 45,
/// less the last separator. Through a real save.
#[test]
fn r4_size_a_row_for_each_share_that_held_it() {
    let mut a = world(&[T, S]);
    let mut s3 = Group::new(id(0x26), "S3".into(), T0);
    s3.custom_data.items.push(item());
    s3.entries.push(entry(E, "deep-demo", at(1), at(1)));
    s3.entries.push(entry(F, "deep-demo", at(1), at(1)));
    gm(&mut a.root, S).groups.push(s3);
    del(&mut a, E, at(10));
    del(&mut a, F, at(11));
    let a = rt(&a);
    let text = a.meta.custom_data.get(origin::SCOPES).unwrap();
    assert_eq!(origin::read_rows(&a.meta.custom_data).len(), 6, "{text}");
    assert_eq!(text.len(), 3 * 33 + 6 * 45 - 1, "{text}");
}

/// A member's vault holding one share, `share`, under its own root.
fn member_of(share: u8, root: u8) -> Vault {
    let mut v = Vault::new(Group::new(id(root), "Member root".into(), T0), T0);
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    let mut g = Group::new(id(share), "Share".into(), T0);
    g.custom_data.items.push(item());
    v.root.groups.push(g);
    v
}

/// Round 4, X1 (C1-07): a deletion that came in through nested share S goes on through
/// the outer share T's export to a member of T only. This Mac no longer holds the
/// object, so T's export carries S's row (INT-08.32, export).
#[test]
fn r4_x1_a_nested_shares_deletion_reaches_a_member_of_the_outer_share() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, S)
        .entries
        .push(entry(E, "in-s-demo", at(1), at(1)));
    let mut ms = member_of(S, 0x70);
    let mut mt = member_of(T, 0x71);
    let s_out = container::build(id(S), true, &a, at(2)).unwrap();
    run::merge_into(&mut ms, id(S), &s_out, at(3)).unwrap();
    let t_out = container::build(id(T), true, &a, at(2)).unwrap();
    run::merge_into(&mut mt, id(T), &t_out, at(3)).unwrap();
    assert!(walk_e(&ms.root, E).is_some() && walk_e(&mt.root, E).is_some());
    // The member of S deletes it for good; the export of S brings that to the user.
    del(&mut ms, E, at(10));
    let back = container::build(id(S), true, &ms, at(11)).unwrap();
    run::merge_into(&mut a, id(S), &back, at(12)).unwrap();
    assert!(
        walk_e(&a.root, E).is_none(),
        "the deletion reaches the user"
    );
    // The next export of T takes the row of S along.
    let t_next = container::build(id(T), true, &a, at(13)).unwrap();
    run::merge_into(&mut mt, id(T), &t_next, at(14)).unwrap();
    assert!(
        walk_e(&mt.root, E).is_none(),
        "the member of T keeps it: rows {}",
        rows(&a)
    );
}

/// Round 4, X2 (C1-07): an export lists each deletion once, though the object counted
/// in two shares and so has a row for each, with one time.
#[test]
fn r4_x2_an_export_lists_each_deletion_once() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, S)
        .entries
        .push(entry(E, "in-s-demo", at(1), at(1)));
    del(&mut a, E, at(10));
    assert_eq!(rows(&a), "50/20/10 50/21/10");
    let c = container::build(id(T), true, &a, at(11)).unwrap();
    let listed: Vec<(u8, i64)> = c
        .deleted_objects
        .iter()
        .map(|d| (d.uuid.0[0], d.deleted_at.0 - T0.0))
        .collect();
    assert_eq!(listed, [(E, 10)]);
}

// -------- Round 4, C1-07: checker 1's surviving clauses that change an outcome --------

/// J2: two Macs move one entry into two different shares at one time. Both stamps are
/// valid and tie on time; the result does not hang on which Mac merges first.
#[test]
fn r4_c1_07_j2_a_tie_of_two_valid_stamps_does_not_hang_on_merge_order() {
    let mut ends = Vec::new();
    for a_first in [true, false] {
        let mut a = world(&[T, U]);
        gm(&mut a.root, P)
            .entries
            .push(entry(E, "seed-demo", at(1), at(1)));
        let mut b = a.duplicate();
        edit::move_entries(&mut a, &[id(E)], id(T), at(10)).unwrap();
        edit::move_entries(&mut b, &[id(E)], id(U), at(10)).unwrap();
        if a_first {
            m(&mut a, &b, Kind::ChangeOnDisk, 20);
        } else {
            m(&mut b, &a, Kind::ChangeOnDisk, 20);
        }
        settle(&mut a, &mut b, Kind::ChangeOnDisk, 30);
        println!(
            "j2 a first {a_first}: a {} | b {}",
            show(&a, E),
            show(&b, E)
        );
        assert_eq!(
            show(&a, E),
            show(&b, E),
            "a first {a_first}: the Macs differ"
        );
        ends.push(show(&a, E));
    }
    assert_eq!(ends[0], ends[1], "the order of merges decides the share");
}

/// J8: Mac A moves an entry into S, nested in T, and Mac B moves it into T, at one time.
/// A's move wins; both Macs end with one stamp, not each its own.
#[test]
fn r4_c1_07_j8_two_stamps_with_one_time_settle_to_one() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, P)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut b = a.duplicate();
    edit::move_entries(&mut a, &[id(E)], id(S), at(10)).unwrap();
    edit::move_entries(&mut b, &[id(E)], id(T), at(10)).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("j8: a {} | b {}", show(&a, E), show(&b, E));
    assert_eq!(walk_e(&a.root, E).map(|x| x.0), Some(id(S)));
    assert_eq!(show(&a, E), show(&b, E), "the Macs keep different stamps");
}

/// J8, the same sets: both copies sit in S, nested in T, one stamped S and one T, at one
/// time. A user's move restamps (a group's move too), so the state is planted here: the
/// clause keeps the merge deterministic whatever a file holds. The higher group id
/// settles it, on both Macs.
#[test]
fn r4_c1_07_j8b_two_stamps_of_one_time_in_one_set_settle_to_one() {
    let mut a = world(&[T, S]);
    let mut b = a.duplicate();
    for (v, g) in [(&mut a, T), (&mut b, S)] {
        let mut e = entry(E, "seed-demo", at(1), at(10));
        let stamp = origin::Stamp {
            group: id(g),
            at: at(10),
        };
        origin::set_stamp(&mut e.custom_data, Some(stamp));
        gm(&mut v.root, S).entries.push(e);
    }
    let stamp = |v: &Vault| walk_e(&v.root, E).and_then(|x| origin::stamp_of(&x.1.custom_data));
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("j8b: a {} | b {}", show(&a, E), show(&b, E));
    assert_eq!(stamp(&a), stamp(&b), "the Macs keep different stamps");
    assert_eq!(stamp(&a).map(|s| s.group), Some(id(S)));
}

/// S2: a user's move from outside into S, nested in T, stamps S, the innermost share it
/// entered, so it beats an earlier move into T on another Mac.
#[test]
fn r4_c1_07_s2_a_later_move_into_a_nested_share_beats_an_earlier_one_into_the_outer() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, P)
        .entries
        .push(entry(E, "seed-demo", at(1), at(1)));
    let mut b = a.duplicate();
    edit::move_entries(&mut b, &[id(E)], id(T), at(5)).unwrap();
    edit::move_entries(&mut a, &[id(E)], id(S), at(10)).unwrap();
    assert_eq!(
        walk_e(&a.root, E)
            .and_then(|x| origin::stamp_of(&x.1.custom_data))
            .map(|s| s.group),
        Some(id(S)),
        "the move names T"
    );
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    println!("s2: a {} | b {}", show(&a, E), show(&b, E));
    for v in [&a, &b] {
        assert_eq!(
            walk_e(&v.root, E).map(|x| x.0),
            Some(id(S)),
            "the later move lost"
        );
    }
}

/// Group `n`'s parent and previous parent.
fn place_of(g: &Group, n: u8) -> Option<(u8, Option<u8>)> {
    for c in &g.groups {
        if c.uuid == id(n) {
            return Some((g.uuid.0[0], c.previous_parent.map(|p| p.0[0])));
        }
    }
    g.groups.iter().find_map(|c| place_of(c, n))
}

/// A same-vault merge of `s` into `t`, through real files: the record lines it gives
/// object `n`. MOD-11.26: one record a change.
fn records_of(t: &mut Vault, s: &Vault, n: u8, when: i64) -> Vec<String> {
    let got = merge(t, &rt(s), &Options::new(Kind::ChangeOnDisk), at(when)).unwrap();
    *t = rt(t);
    got.changes
        .iter()
        .filter(|c| c.id == Some(id(n)))
        .map(|c| c.line())
        .collect()
}

/// P8: plain group P sits in share T. Mac B adds group N with an entry in P; Mac A moves
/// P out of T. N, which only B held, stays in T: no share is left by a merge. The merge
/// that adds it puts it there at once, with one record.
#[test]
fn r4_c1_07_p8_a_group_only_one_copy_holds_stays_in_its_share() {
    let mut a = world(&[T]);
    let p = a.root.groups.remove(0);
    assert_eq!(p.uuid, id(P));
    gm(&mut a.root, T).groups.push(p);
    let mut b = a.duplicate();
    let mut n = Group::new(id(0x40), "N".into(), at(5));
    n.entries
        .push(entry(F, "made-in-the-share-demo", at(5), at(5)));
    gm(&mut b.root, P).groups.push(n);
    edit::move_group(&mut a, id(P), id(ROOT), Position::End, at(10)).unwrap();
    let lines = records_of(&mut a, &b, 0x40, 15);
    println!("p8 records: {lines:?}");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("Added: '/Root/T/N'"), "{lines:?}");
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 20);
    for v in [&a, &b] {
        println!(
            "p8: P at {:?}, N at {:?}",
            place_of(&v.root, P),
            place_of(&v.root, 0x40)
        );
        assert_eq!(place_of(&v.root, P).map(|x| x.0), Some(ROOT));
        assert_eq!(
            place_of(&v.root, 0x40).map(|x| x.0),
            Some(T),
            "N left the share"
        );
    }
}

/// P10: Mac B made entry E in plain group P and binned it; Mac A, which never held E,
/// moves P into share T. B's private bin item does not come to count in T on A.
#[test]
fn r4_c1_07_p10_an_added_bin_entry_does_not_name_a_group_now_in_a_share() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    gm(&mut b.root, P)
        .entries
        .push(entry(E, "private-demo", at(1), at(1)));
    recycle::delete_entries(&mut b, &[id(E)], at(5), |_, _| References::Delete).unwrap();
    assert_eq!(
        walk_e(&b.root, E).map(|x| (x.0, x.1.previous_parent)),
        Some((id(BIN), Some(id(P))))
    );
    edit::move_group(&mut a, id(P), id(T), Position::End, at(10)).unwrap();
    m(&mut a, &b, Kind::ChangeOnDisk, 20);
    let (parent, e) = walk_e(&a.root, E).unwrap();
    println!(
        "p10: in {:02x} prev {:?}",
        parent.0[0],
        e.previous_parent.map(|p| p.0[0])
    );
    assert_eq!(parent, id(BIN));
    assert_ne!(
        e.previous_parent,
        Some(id(P)),
        "B's private bin item counts in T"
    );
}

/// P11: as P10, for a group, which the merge adds with its new previous parent at once:
/// one record.
#[test]
fn r4_c1_07_p11_an_added_bin_group_does_not_name_a_group_now_in_a_share() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    gm(&mut b.root, P)
        .groups
        .push(Group::new(id(0x40), "N".into(), at(1)));
    recycle::delete_group(&mut b, id(0x40), at(5)).unwrap();
    assert_eq!(place_of(&b.root, 0x40), Some((BIN, Some(P))));
    edit::move_group(&mut a, id(P), id(T), Position::End, at(10)).unwrap();
    let lines = records_of(&mut a, &b, 0x40, 20);
    println!("p11 records: {lines:?}");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("Added"), "{lines:?}");
    let got = place_of(&a.root, 0x40);
    println!("p11: {got:?}");
    assert_eq!(got.map(|x| x.0), Some(BIN));
    assert_ne!(
        got.and_then(|x| x.1),
        Some(P),
        "B's private bin group counts in T"
    );
}

fn plain(v: &mut Vault, n: u8, t: Time) {
    v.deleted_objects.push(DeletedObject {
        uuid: id(n),
        deleted_at: t,
        unknown: Vec::new(),
    });
}

/// D1: A user deleted E for good at 10. Mac B's copy in T was moved at 20, its Mod still
/// 1 (a move from a group its previous parent already named sets no Mod). A move after
/// the deletion keeps it: the record and the pass read Loc too.
#[test]
fn r4_c1_07_d1_a_copy_moved_after_a_deletion_is_not_dead() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    plain(&mut a, E, at(10));
    let mut e = entry(E, "moved-later-demo", at(1), at(20));
    e.previous_parent = Some(id(T));
    gm(&mut b.root, T).entries.push(e);
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 30);
    println!("d1: a {} | b {}", show(&a, E), show(&b, E));
    assert!(walk_e(&a.root, E).is_some() && walk_e(&b.root, E).is_some());
}

/// D4: two lists name E, at 10 and at 20. Mac A's copy, of 15, is no later than the later
/// record, so it is dead: its value does not reach the history of B's copy, of 25.
#[test]
fn r4_c1_07_d4_the_later_of_two_records_decides_a_dead_copy() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "between-demo", at(15), at(15)));
    plain(&mut a, E, at(10));
    gm(&mut b.root, T)
        .entries
        .push(entry(E, "later-demo", at(25), at(25)));
    plain(&mut b, E, at(20));
    m(&mut a, &b, Kind::ChangeOnDisk, 30);
    println!("d4: a {}", show(&a, E));
    assert_eq!(
        walk_e(&a.root, E).map(|x| x.1.value("Password").to_owned()),
        Some("later-demo".to_owned())
    );
    assert!(
        !any_value(&a, "between-demo"),
        "a value the user deleted came back"
    );
}

/// D6: Mac A's copy was moved into T at 10, the time of a user's record of 10 on Mac B:
/// no later than the record, so dead, and its value stays out of B's later copy.
#[test]
fn r4_c1_07_d6_a_stamp_as_old_as_the_record_is_dead() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    let mut e = entry(E, "stamped-demo", at(5), at(10));
    origin::set_stamp(
        &mut e.custom_data,
        Some(origin::Stamp {
            group: id(T),
            at: at(10),
        }),
    );
    gm(&mut a.root, T).entries.push(e);
    gm(&mut b.root, T)
        .entries
        .push(entry(E, "later-demo", at(25), at(25)));
    plain(&mut b, E, at(10));
    m(&mut a, &b, Kind::ChangeOnDisk, 30);
    println!("d6: a {}", show(&a, E));
    assert!(
        !any_value(&a, "stamped-demo"),
        "a value the user deleted came back"
    );
}

/// D2: Mac B's user deleted E, then held at 10, for good; a later copy came back inside T
/// on B. Mac A still holds the old copy outside. That copy is dead though it counts in no
/// share, as B's counts inside: it goes, and its value joins nothing.
#[test]
fn r4_c1_07_d2_a_dead_outside_copy_goes_when_the_other_counts_inside() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    gm(&mut a.root, P)
        .entries
        .push(entry(E, "old-outside-demo", at(5), at(5)));
    gm(&mut b.root, T)
        .entries
        .push(entry(E, "inside-later-demo", at(20), at(20)));
    plain(&mut b, E, at(10));
    m(&mut a, &b, Kind::ChangeOnDisk, 30);
    println!("d2: a {}", show(&a, E));
    assert_eq!(walk_e(&a.root, E).map(|x| x.0), Some(id(T)));
    assert!(
        !any_value(&a, "old-outside-demo"),
        "a value the user deleted came back"
    );
}

/// D5 and E8: a dead copy is the only object a merge erases. What named it is cleared, so
/// the vault keeps its invariants (FMT-10.16).
#[test]
fn r4_c1_07_d5_e8_an_erased_dead_copy_clears_what_names_it() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "old-demo", at(1), at(1)));
    gm(&mut a.root, T).last_top_visible_entry = Some(id(E));
    plain(&mut b, E, at(10));
    let source = rt(&b);
    merge(&mut a, &source, &Options::new(Kind::ChangeOnDisk), at(20)).unwrap();
    assert!(walk_e(&a.root, E).is_none());
    assert_eq!(
        gm(&mut a.root, T).last_top_visible_entry,
        None,
        "a group names an erased entry"
    );
}

/// E3: rows of one share for one id merge to the later time. Mac A's row of 20 erases a
/// copy of 15 that Mac B, with a row of 10, still holds.
#[test]
fn r4_c1_07_e3_two_rows_merge_to_the_later_time() {
    let mut a = world(&[T]);
    let mut b = a.duplicate();
    let row = |t| origin::Rows::from([((id(E), id(T)), t)]);
    origin::write_rows(&mut a.meta.custom_data, &row(at(20)));
    origin::write_rows(&mut b.meta.custom_data, &row(at(10)));
    gm(&mut b.root, T)
        .entries
        .push(entry(E, "back-demo", at(15), at(15)));
    m(&mut a, &b, Kind::ChangeOnDisk, 30);
    println!("e3: a {} rows {}", show(&a, E), rows(&a));
    assert!(
        walk_e(&a.root, E).is_none(),
        "a row of 20 left a copy of 15"
    );
}

/// T3: group G of share T and then its entry E went to the bin; Mac B deletes G for good.
/// When a merge erases G on Mac A, E names where G came from, T, as on Mac B.
#[test]
fn r4_c1_07_t3_a_binned_group_erased_by_a_merge_hands_on_its_previous_parent() {
    let mut a = world(&[T]);
    let mut g = Group::new(id(0x40), "G".into(), at(1));
    g.entries.push(entry(E, "inside-demo", at(1), at(1)));
    gm(&mut a.root, T).groups.push(g);
    recycle::delete_entries(&mut a, &[id(E)], at(2), |_, _| References::Delete).unwrap();
    recycle::delete_group(&mut a, id(0x40), at(3)).unwrap();
    assert_eq!(place_of(&a.root, 0x40), Some((BIN, Some(T))));
    let mut b = a.duplicate();
    recycle::delete_group(&mut b, id(0x40), at(4)).unwrap();
    let prev = |v: &Vault| walk_e(&v.root, E).and_then(|x| x.1.previous_parent);
    assert_eq!(prev(&b), Some(id(T)), "Mac B");
    m(&mut a, &b, Kind::ChangeOnDisk, 10);
    println!(
        "t3 (C1-07): G {:?}, E {}",
        place_of(&a.root, 0x40),
        show(&a, E)
    );
    assert_eq!(place_of(&a.root, 0x40), None);
    assert_eq!(prev(&a), Some(id(T)), "E no longer names where G came from");
}

/// U1: share S, in share T, and then its entry E went to the bin. Restoring E puts it in
/// T, the innermost share on its way up that is not in the bin.
#[test]
fn r4_c1_07_u1_a_restore_never_targets_a_group_in_the_bin() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, S)
        .entries
        .push(entry(E, "inside-demo", at(1), at(1)));
    recycle::delete_entries(&mut a, &[id(E)], at(2), |_, _| References::Delete).unwrap();
    recycle::delete_group(&mut a, id(S), at(3)).unwrap();
    assert_eq!(place_of(&a.root, S), Some((BIN, Some(T))));
    recycle::restore_entries(&mut a, &[id(E)], at(4)).unwrap();
    println!("u1: {}", show(&a, E));
    assert_eq!(walk_e(&a.root, E).map(|x| x.0), Some(id(T)));
}

/// U2: share K held group G; G went to the bin, and then K was moved into G there.
/// Restoring G never puts it inside itself: it goes to the root. (A group inside the
/// restored group lies in the bin with it, so the bin filter alone already leaves it out:
/// checker 1's U2 mutant is equivalent; this pins the outcome.)
#[test]
fn r4_c1_07_u2_a_restore_never_puts_a_group_inside_itself() {
    let mut a = world(&[]);
    let mut k = Group::new(id(0x41), "K".into(), at(1));
    k.custom_data.items.push(item());
    k.groups.push(Group::new(id(0x40), "G".into(), at(1)));
    a.root.groups.push(k);
    recycle::delete_group(&mut a, id(0x40), at(2)).unwrap();
    assert_eq!(place_of(&a.root, 0x40), Some((BIN, Some(0x41))));
    edit::move_group(&mut a, id(0x41), id(0x40), Position::End, at(3)).unwrap();
    let got = recycle::restore_group(&mut a, id(0x40), at(4));
    println!(
        "u2: restore {got:?}, G {:?}, K {:?}",
        place_of(&a.root, 0x40),
        place_of(&a.root, 0x41)
    );
    got.unwrap();
    assert_eq!(place_of(&a.root, 0x40).map(|x| x.0), Some(ROOT));
    assert_eq!(place_of(&a.root, 0x41).map(|x| x.0), Some(0x40));
}

/// E6: Mac B's user deletes group G of share T for good, with its child group K: a row
/// for each. On Mac A both go: the pass takes the deeper group first, so G holds nothing
/// when its turn comes (G's id is the lower).
#[test]
fn r4_c1_07_e6_a_group_and_its_child_both_go() {
    let mut a = world(&[T]);
    let mut g = Group::new(id(0x40), "G".into(), at(1));
    g.groups.push(Group::new(id(0x41), "K".into(), at(1)));
    gm(&mut a.root, T).groups.push(g);
    let mut b = a.duplicate();
    del_g(&mut b, 0x40, at(5));
    println!("e6: B's rows {}", rows(&b));
    m(&mut a, &b, Kind::ChangeOnDisk, 10);
    println!(
        "e6: G {:?}, K {:?}",
        place_of(&a.root, 0x40),
        place_of(&a.root, 0x41)
    );
    assert_eq!(place_of(&a.root, 0x41), None);
    assert_eq!(
        place_of(&a.root, 0x40),
        None,
        "an empty deleted group stays"
    );
}

/// Round 3's E5 clause, which round 3's replay witnessed and this round's re-cut corpus
/// no longer does: a whole win of one version still takes the winner's stamp and marker.
/// Planted: E outside on both Macs, one version, marked on Mac A only. Both Macs end
/// alike, unmarked: a marker stays only where both copies hold it.
#[test]
fn r4_e5_a_same_version_whole_win_takes_the_winners_marker() {
    for kind in KINDS {
        let mut a = world(&[T]);
        gm(&mut a.root, P)
            .entries
            .push(entry(E, "same-demo", at(1), at(1)));
        let b0 = a.duplicate();
        let e = gm(&mut a.root, P)
            .entries
            .iter_mut()
            .find(|e| e.uuid == id(E));
        origin::set_mark(&mut e.unwrap().custom_data, id(T));
        let mut b = b0;
        settle(&mut a, &mut b, kind, 10);
        println!("e5 {kind:?}: a {} | b {}", show(&a, E), show(&b, E));
        assert_eq!(show(&a, E), show(&b, E), "{kind:?}");
        assert!(
            show(&a, E).ends_with("mark false"),
            "{kind:?}: {}",
            show(&a, E)
        );
    }
}
