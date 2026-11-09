//! Rule R6 where the model does not reach: an entry and a group with one id (F8), a
//! group only one copy holds, the parts of a whole win, the icon route (F7), merges
//! that are not same-vault, and the rule's own items beside a bin. Demo data only.
#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use larsal_core::edit::{self, Position};
use larsal_core::merge::{ChangeKind, Kind, Options, merge};
use larsal_core::origin;
use larsal_core::recycle::{self, References};
use larsal_crypto::secret::SecretString;
use larsal_model::custom_data::CustomDataItem;
use larsal_model::unknown::UnknownElement;
use larsal_model::vault::FileVersion;
use larsal_model::{CustomIcon, DeletedObject, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};

const T0: Time = Time(63_902_822_400);
const NOW: Time = Time(63_910_000_000);
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
const U: u8 = 0x22;
const P: u8 = 0x30;
const O: u8 = 0x31;
const K: u8 = 0x32;
const E: u8 = 0x50;
const F: u8 = 0x51;
const BIN: u8 = 0x5a;

fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}

fn at(n: i64) -> Time {
    Time(T0.0 + n)
}

fn entry(n: u8, password: &str, when: Time) -> Entry {
    let mut e = Entry::new(id(n), T0);
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new(password.to_owned()),
            protected: true,
        },
    );
    e.times.last_modification = when;
    e.times.location_changed = when;
    e
}

fn gm(g: &mut Group, n: u8) -> &mut Group {
    fn inner(g: &mut Group, n: u8) -> Option<&mut Group> {
        if g.uuid == id(n) {
            return Some(g);
        }
        g.groups.iter_mut().find_map(|c| inner(c, n))
    }
    inner(g, n).expect("the group")
}

fn share_item() -> CustomDataItem {
    CustomDataItem {
        key: core::str::from_utf8(edit::SHARED_KEY).unwrap().to_owned(),
        value: SecretString::new(String::new()),
        last_modified: None,
        unknown: Vec::new(),
    }
}

/// Root(01) -> T(20, a share), U(22), P(30), the bin.
fn common() -> Vault {
    let mut root = Group::new(id(ROOT), "Root".into(), T0);
    let mut t = Group::new(id(T), "T".into(), T0);
    t.custom_data.items.push(share_item());
    root.groups = vec![
        t,
        Group::new(id(U), "U".into(), T0),
        Group::new(id(P), "P".into(), T0),
        Group::new(id(BIN), "Bin".into(), T0),
    ];
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = false;
    v.meta.recycle_bin = Some(id(BIN));
    v.meta.history_max_items = -1;
    v.meta.history_max_size = -1;
    v
}

fn container_of() -> Vault {
    let mut c = Vault::new(Group::new(id(0x66), "Share".into(), T0), T0);
    c.meta.recycle_bin_enabled = false;
    c
}

fn record(n: u8, when: Time) -> DeletedObject {
    DeletedObject {
        uuid: id(n),
        deleted_at: when,
        unknown: Vec::new(),
    }
}

fn parent_of_entry(v: &Vault, n: u8) -> Option<Uuid> {
    v.root
        .subtree()
        .into_iter()
        .find(|g| g.entries.iter().any(|e| e.uuid == id(n)))
        .map(|g| g.uuid)
}

fn parent_of_group(v: &Vault, n: u8) -> Option<Uuid> {
    v.root
        .subtree()
        .into_iter()
        .find(|g| g.groups.iter().any(|c| c.uuid == id(n)))
        .map(|g| g.uuid)
}

fn value(v: &Vault, n: u8) -> Option<String> {
    v.root
        .all_entries()
        .find(|e| e.uuid == id(n))
        .map(|e| e.value("Password").to_owned())
}

fn entry_of(v: &Vault, n: u8) -> &Entry {
    v.root.all_entries().find(|e| e.uuid == id(n)).unwrap()
}

/// What the two copies must agree on after they settle.
fn view(v: &Vault) -> String {
    let mut out = Vec::new();
    for g in v.root.subtree() {
        for c in &g.groups {
            out.push(format!("g {:x} in {:x}", c.uuid.0[0], g.uuid.0[0]));
        }
        for e in &g.entries {
            out.push(format!(
                "e {:x} in {:x} {}",
                e.uuid.0[0],
                g.uuid.0[0],
                e.value("Password")
            ));
        }
    }
    out.sort();
    let mut plain: Vec<u8> = v.deleted_objects.iter().map(|d| d.uuid.0[0]).collect();
    plain.sort_unstable();
    let rows: Vec<(u8, u8)> = origin::read_rows(&v.meta.custom_data)
        .keys()
        .map(|(x, g)| (x.0[0], g.0[0]))
        .collect();
    format!("{out:?} plain {plain:x?} rows {rows:x?}")
}

fn settle(a: &mut Vault, b: &mut Vault, kind: Kind) {
    let o = Options::new(kind);
    for round in 0..4 {
        let copy = b.duplicate();
        merge(a, &copy, &o, at(5000 + round)).unwrap();
        let copy = a.duplicate();
        merge(b, &copy, &o, at(5000 + round)).unwrap();
    }
}

/// F8. A container plants a group with an outside entry's id, and the group holds an
/// entry. The entry and the group are two objects: each settles by itself, in either
/// order, on all kinds, and the outside entry does not change.
#[test]
fn f8_a_group_with_an_outside_entrys_id_settles_and_changes_nothing_outside() {
    for kind in KINDS {
        for first in [false, true] {
            let mut a = common();
            let mut b = common();
            gm(&mut b.root, P)
                .entries
                .push(entry(E, "private-demo", at(10)));
            let mut c = container_of();
            let mut planted = Group::new(id(E), "N".into(), at(20));
            planted.entries.push(entry(F, "planted-demo", at(20)));
            c.root.groups.push(planted);
            run::merge_into(&mut a, id(T), &c, at(30)).unwrap();
            if first {
                settle(&mut a, &mut b, kind);
            } else {
                settle(&mut b, &mut a, kind);
            }
            assert_eq!(view(&a), view(&b), "{kind:?} {first}");
            for v in [&a, &b] {
                assert_eq!(value(v, E).as_deref(), Some("private-demo"), "{kind:?}");
                assert_eq!(parent_of_entry(v, E), Some(id(P)), "{kind:?}");
                assert_eq!(parent_of_group(v, E), Some(id(T)), "{kind:?}");
                assert_eq!(value(v, F).as_deref(), Some("planted-demo"), "{kind:?}");
                let export = container::build(id(T), true, v, NOW).unwrap();
                let private = export.root.all_entries().any(|x| x.uuid == id(E));
                assert!(!private, "{kind:?}: exported");
            }
        }
    }
}

/// F8 the other way: an entry with an outside group's id. The group stays with what
/// it holds; the planted entry stays inside.
#[test]
fn f8_an_entry_with_an_outside_groups_id_settles_and_changes_nothing_outside() {
    for kind in KINDS {
        let mut a = common();
        let mut b = common();
        let mut o = Group::new(id(O), "O".into(), at(10));
        o.entries.push(entry(F, "private-demo", at(10)));
        gm(&mut b.root, P).groups.push(o);
        let mut c = container_of();
        c.root.entries.push(entry(O, "planted-demo", at(20)));
        run::merge_into(&mut a, id(T), &c, at(30)).unwrap();
        settle(&mut a, &mut b, kind);
        assert_eq!(view(&a), view(&b), "{kind:?}");
        for v in [&a, &b] {
            assert_eq!(parent_of_group(v, O), Some(id(P)), "{kind:?}");
            assert_eq!(parent_of_entry(v, F), Some(id(O)), "{kind:?}");
            assert_eq!(parent_of_entry(v, O), Some(id(T)), "{kind:?}");
            assert_eq!(value(v, F).as_deref(), Some("private-demo"), "{kind:?}");
        }
    }
}

/// F8: a list that names the shared id erases the group inside and reaches nothing
/// outside: the row stays with its share, dormant beside the outside entry.
#[test]
fn f8_a_list_with_the_shared_id_erases_only_inside() {
    for kind in KINDS {
        let mut a = common();
        let mut b = common();
        gm(&mut b.root, P)
            .entries
            .push(entry(E, "private-demo", at(10)));
        let mut c = container_of();
        c.root.groups.push(Group::new(id(E), "N".into(), at(20)));
        run::merge_into(&mut a, id(T), &c, at(30)).unwrap();
        let mut list = container_of();
        list.deleted_objects.push(record(E, at(40)));
        run::merge_into(&mut a, id(T), &list, at(50)).unwrap();
        assert_eq!(parent_of_group(&a, E), None, "{kind:?}");
        settle(&mut a, &mut b, kind);
        assert_eq!(view(&a), view(&b), "{kind:?}");
        for v in [&a, &b] {
            assert_eq!(value(v, E).as_deref(), Some("private-demo"), "{kind:?}");
            assert_eq!(parent_of_group(v, E), None, "{kind:?}");
            let rows = origin::read_rows(&v.meta.custom_data);
            assert!(rows.contains_key(&(id(E), id(T))), "{kind:?}");
            assert!(v.deleted_objects.is_empty(), "{kind:?}: off the plain list");
        }
    }
}

/// F8: a user's record for an id on two objects, one kept by a later change and one
/// erased. The record stays while either needs it, so both orders settle and the
/// erased object does not come back from a copy that holds no record: the round 2 form
/// decided per id and lost it, which is where its 23 rounds came from.
#[test]
fn f8_a_users_record_for_an_id_on_a_kept_and_an_erased_object_stays() {
    for kind in KINDS {
        for (first, both) in [(false, false), (false, true), (true, false), (true, true)] {
            let mut a = common();
            gm(&mut a.root, P)
                .entries
                .push(entry(E, "private-demo", at(9000)));
            let mut b = common();
            gm(&mut b.root, P)
                .groups
                .push(Group::new(id(E), "N".into(), at(10)));
            a.deleted_objects.push(record(E, at(100)));
            if both {
                b.deleted_objects.push(record(E, at(100)));
            }
            if first {
                settle(&mut a, &mut b, kind);
            } else {
                settle(&mut b, &mut a, kind);
            }
            assert_eq!(view(&a), view(&b), "{kind:?} {first} {both}");
            for v in [&a, &b] {
                assert_eq!(value(v, E).as_deref(), Some("private-demo"), "{kind:?}");
                assert_eq!(
                    parent_of_group(v, E),
                    None,
                    "{kind:?} {first} {both}: the group goes"
                );
            }
        }
    }
}

/// R6 E4: a group only the target holds, under a group moved in: it was outside, so it
/// stays outside, at the nearest group on its way up that adds no share. What it holds
/// goes with it, and nothing of it is exported.
#[test]
fn a_group_only_the_target_holds_stays_out_when_the_group_above_moves_in() {
    let mut base = common();
    let o = Group::new(id(O), "O".into(), T0);
    gm(&mut base.root, P).groups.push(o);
    for kind in KINDS {
        let mut b = base.duplicate();
        edit::move_group(&mut b, id(O), id(T), Position::End, at(100)).unwrap();
        let mut a = base.duplicate();
        let mut k = Group::new(id(K), "K".into(), at(50));
        k.entries.push(entry(E, "private-demo", at(50)));
        gm(&mut a.root, O).groups.push(k);
        let merged = merge(&mut a, &b, &Options::new(kind), at(200)).unwrap();
        assert_eq!(parent_of_group(&a, O), Some(id(T)), "{kind:?}: the move in");
        assert_eq!(parent_of_group(&a, K), Some(id(P)), "{kind:?}: K stays out");
        assert_eq!(parent_of_entry(&a, E), Some(id(K)), "{kind:?}");
        let export = container::build(id(T), true, &a, NOW).unwrap();
        assert_eq!(export.root.all_entries().count(), 0, "{kind:?}: exported");
        let named = |c: &larsal_core::merge::Change| c.id == Some(id(K));
        assert!(
            merged.changes.iter().any(named),
            "{kind:?}: every change has a record"
        );
    }
}

fn unknown_part() -> UnknownElement {
    UnknownElement {
        name: "Later".into(),
        attributes: Vec::new(),
        content: Vec::new(),
    }
}

/// R6 E3: the outside copy of a group wins whole over one a share brought: its fields,
/// times and unknown parts all come with it, and the read version rises for them.
#[test]
fn a_whole_win_of_a_group_takes_its_unknown_parts_and_times_and_the_version() {
    let mut a = common();
    let mut c = container_of();
    c.root
        .groups
        .push(Group::new(id(O), "Planted".into(), at(900)));
    run::merge_into(&mut a, id(T), &c, at(950)).unwrap();
    let mut b = common();
    let mut o = Group::new(id(O), "Mine".into(), at(10));
    o.unknown.push(unknown_part());
    o.notes = "mine-demo".into();
    o.times.usage_count = 7;
    o.times.creation = at(3);
    gm(&mut b.root, P).groups.push(o);
    a.read_version = Some(FileVersion { major: 4, minor: 0 });
    b.read_version = Some(FileVersion { major: 4, minor: 1 });
    let want = b.read_version;
    merge(&mut a, &b, &Options::new(Kind::ConflictCopy), at(1000)).unwrap();
    let g = a.root.find_group(id(O)).unwrap();
    assert_eq!(parent_of_group(&a, O), Some(id(P)));
    assert_eq!(g.name, "Mine");
    assert_eq!(g.notes, "mine-demo");
    assert_eq!(g.unknown.len(), 1, "the unknown parts");
    assert_eq!(g.times.last_modification, at(10), "the winner's times");
    assert_eq!(g.times.usage_count, 7, "the winner's times");
    assert_eq!(g.times.creation, at(3), "the winner's times");
    assert_eq!(a.read_version, want, "the version rises for them");
}

/// R6 E3: on a whole win the target's share item stands and the source's does not
/// come: settings stay with this copy (INT-08.14).
#[test]
fn a_whole_win_of_a_group_keeps_the_targets_share_item() {
    let item = |v: &str| CustomDataItem {
        value: SecretString::new(v.to_owned()),
        ..share_item()
    };
    let shared = |g: &Group| {
        g.custom_data
            .items
            .iter()
            .find(|i| i.key.as_bytes() == edit::SHARED_KEY)
            .map(|i| i.value.expose().to_owned())
    };
    // The target's copy was brought; the source's outside copy wins whole.
    let mut a = common();
    let mut c = container_of();
    c.root
        .groups
        .push(Group::new(id(O), "Planted".into(), at(900)));
    run::merge_into(&mut a, id(T), &c, at(950)).unwrap();
    let mut with_item = a.duplicate();
    gm(&mut with_item.root, O)
        .custom_data
        .items
        .push(item("target-demo"));
    let mut b = common();
    let mut o = Group::new(id(O), "Mine".into(), at(10));
    o.custom_data.items.push(item("source-demo"));
    gm(&mut b.root, P).groups.push(o);
    let mut t = a.duplicate();
    merge(&mut t, &b, &Options::new(Kind::ConflictCopy), at(1000)).unwrap();
    assert_eq!(t.root.find_group(id(O)).unwrap().name, "Mine");
    assert_eq!(
        shared(t.root.find_group(id(O)).unwrap()),
        None,
        "the source's item does not come"
    );
    merge(
        &mut with_item,
        &b,
        &Options::new(Kind::ConflictCopy),
        at(1000),
    )
    .unwrap();
    assert_eq!(
        shared(with_item.root.find_group(id(O)).unwrap()).as_deref(),
        Some("target-demo"),
        "the target's item stands"
    );
}

/// R6 E3: the outside copy of an entry wins whole. Its passwords are protected in
/// the result, and the read version rises for unknown parts.
#[test]
fn a_whole_win_of_an_entry_protects_passwords_and_takes_the_version() {
    let mut a = common();
    let mut c = container_of();
    c.root.entries.push(entry(E, "planted-demo", at(900)));
    run::merge_into(&mut a, id(T), &c, at(950)).unwrap();
    let mut b = common();
    let mut own = entry(E, "private-demo", at(10));
    own.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new("private-demo".to_owned()),
            protected: false,
        },
    );
    own.unknown.push(unknown_part());
    gm(&mut b.root, P).entries.push(own);
    a.read_version = Some(FileVersion { major: 4, minor: 0 });
    b.read_version = Some(FileVersion { major: 4, minor: 1 });
    let want = b.read_version;
    let mut t = a.duplicate();
    merge(&mut t, &b, &Options::new(Kind::ConflictCopy), at(1000)).unwrap();
    let e = entry_of(&t, E);
    assert_eq!(e.value("Password"), "private-demo");
    assert!(
        e.field("Password").is_some_and(|f| f.protected),
        "protected in the result"
    );
    assert_eq!(e.unknown.len(), 1);
    assert_eq!(t.read_version, want);
    // The target's copy wins whole: the loser's history item is protected too.
    let mut b2 = b.duplicate();
    merge(&mut b2, &a, &Options::new(Kind::ConflictCopy), at(1000)).unwrap();
    let e = entry_of(&b2, E);
    assert_eq!(e.value("Password"), "private-demo");
    let h = e.history.last().unwrap();
    assert_eq!(h.value("Password"), "planted-demo");
    assert!(h.field("Password").is_some_and(|f| f.protected));
}

/// F7: with a share known, removing an icon writes no plain record, so an icon with
/// an outside entry's id erases nothing. A stale copy brings the icon back: the stated
/// cost. With no share known the record is there, as today.
#[test]
fn f7_an_icon_record_is_not_written_with_a_share_known_and_a_stale_copy_returns_it() {
    let icon = || CustomIcon {
        uuid: id(E),
        name: String::new(),
        last_modified: None,
        data: vec![0x89, 0x50, 0x4E, 0x47],
        unknown: Vec::new(),
    };
    let mut a = common();
    let mut b = common();
    gm(&mut b.root, P)
        .entries
        .push(entry(E, "private-demo", at(10)));
    let mut c = container_of();
    c.meta.custom_icons.push(icon());
    run::merge_into(&mut a, id(T), &c, at(20)).unwrap();
    let stale = a.duplicate();
    assert_eq!(larsal_core::icons::purge(&mut a, at(30)), 1);
    assert!(a.meta.custom_icons.is_empty());
    assert!(a.deleted_objects.is_empty(), "no plain record");
    merge(&mut b, &a, &Options::new(Kind::ChangeOnDisk), at(40)).unwrap();
    assert_eq!(value(&b, E).as_deref(), Some("private-demo"));
    merge(&mut a, &stale, &Options::new(Kind::ChangeOnDisk), at(50)).unwrap();
    assert_eq!(a.meta.custom_icons.len(), 1, "a stale copy brings it back");
    // No share known: today's record.
    let mut root = Group::new(id(ROOT), "Root".into(), T0);
    root.groups.push(Group::new(id(P), "P".into(), T0));
    let mut plain = Vault::new(root, T0);
    plain.meta.custom_icons.push(icon());
    assert_eq!(larsal_core::icons::purge(&mut plain, at(30)), 1);
    assert_eq!(plain.deleted_objects.len(), 1, "today's record");
}

fn stamped(v: &mut Vault, n: u8, share: u8, when: Time) {
    fn inner(g: &mut Group, n: u8) -> Option<&mut Entry> {
        if let Some(e) = g.entries.iter_mut().find(|e| e.uuid == id(n)) {
            return Some(e);
        }
        g.groups.iter_mut().find_map(|c| inner(c, n))
    }
    let e = inner(&mut v.root, n).unwrap();
    origin::set_stamp(
        &mut e.custom_data,
        Some(origin::Stamp {
            group: id(share),
            at: when,
        }),
    );
    origin::set_mark(&mut e.custom_data, id(share));
}

/// A limit past the fourteen: merges that are not same-vault run today's walk. The
/// source's own items do not come, and the target's stay. The source's Loc can move an
/// object into a share there: the user chose this merge, and the card says so.
fn other_merge(mut o: Options, source_root: u8) {
    let mut t = common();
    gm(&mut t.root, P)
        .entries
        .push(entry(E, "mine-demo", at(10)));
    stamped(&mut t, E, P, at(5));
    t.deleted_objects.clear();
    let mut rows = origin::Rows::new();
    rows.insert((id(F), id(T)), at(1));
    origin::write_rows(&mut t.meta.custom_data, &rows);
    let mut s = common();
    s.root.uuid = id(source_root);
    gm(&mut s.root, T)
        .entries
        .push(entry(E, "theirs-demo", at(100)));
    stamped(&mut s, E, T, at(100));
    let mut theirs = origin::Rows::new();
    theirs.insert((id(0x52), id(T)), at(2));
    origin::write_rows(&mut s.meta.custom_data, &theirs);
    o.source_start = None;
    merge(&mut t, &s, &o, at(200)).unwrap();
    assert_eq!(parent_of_entry(&t, E), Some(id(T)), "today's walk");
    assert_eq!(value(&t, E).as_deref(), Some("theirs-demo"));
    let stamp = origin::stamp_of(&entry_of(&t, E).custom_data);
    assert_eq!(
        stamp.map(|x| x.group),
        Some(id(P)),
        "the source's stamp does not come, the target's stays"
    );
    let rows = origin::read_rows(&t.meta.custom_data);
    assert!(rows.contains_key(&(id(F), id(T))), "the target's row stays");
    assert_eq!(rows.len(), 1, "the source's row does not come");
}

#[test]
fn limit_beyond_another_vaults_merge_is_todays_walk_and_takes_none_of_the_items() {
    other_merge(Options::new(Kind::ConflictCopy), 0x02);
}

#[test]
fn limit_beyond_a_retired_keys_merge_is_todays_walk_and_takes_none_of_the_items() {
    let mut o = Options::new(Kind::Window);
    o.retired = true;
    other_merge(o, ROOT);
}

/// An item in the bin counts where its previous parent is: moved in with its group, it
/// follows (the model's chain). It is not exported from the bin, and an import does not
/// touch it. A merge with a planted copy is then a merge of two inside copies: the later
/// wins and the other's value is a history item. The model counts that as the user's
/// move; the card says so.
#[test]
fn a_bin_item_counts_where_its_previous_parent_is() {
    let mut a = common();
    a.meta.recycle_bin_enabled = true;
    let mut o = Group::new(id(O), "O".into(), T0);
    o.entries.push(entry(E, "private-demo", at(10)));
    o.entries.push(entry(F, "keep-demo", at(10)));
    gm(&mut a.root, P).groups.push(o);
    let base = a.duplicate();
    recycle::delete_entries(&mut a, &[id(E)], at(20), |_, _| References::Delete).unwrap();
    assert_eq!(parent_of_entry(&a, E), Some(id(BIN)));
    let export = container::build(id(T), true, &a, NOW).unwrap();
    assert_eq!(export.root.all_entries().count(), 0);
    edit::move_group(&mut a, id(O), id(T), Position::End, at(30)).unwrap();
    let export = container::build(id(T), true, &a, NOW).unwrap();
    let ids: Vec<Uuid> = export.root.all_entries().map(|e| e.uuid).collect();
    assert_eq!(ids, vec![id(F)], "the bin item is not exported");
    let mut c = container_of();
    c.root.entries.push(entry(E, "planted-demo", at(40)));
    let mut b = a.duplicate();
    run::merge_into(&mut b, id(T), &c, at(50)).unwrap();
    assert_eq!(
        parent_of_entry(&b, E),
        Some(id(BIN)),
        "the import leaves it"
    );
    assert_eq!(value(&b, E).as_deref(), Some("private-demo"));
    // Another Mac, with no bin item, holds the planted copy.
    let mut d = base.duplicate();
    d.root
        .groups
        .iter_mut()
        .find(|g| g.uuid == id(P))
        .unwrap()
        .groups
        .clear();
    run::merge_into(&mut d, id(T), &c, at(50)).unwrap();
    merge(&mut d, &a, &Options::new(Kind::ConflictCopy), at(60)).unwrap();
    assert_eq!(parent_of_entry(&d, E), Some(id(T)));
    assert_eq!(value(&d, E).as_deref(), Some("planted-demo"));
    let e = entry_of(&d, E);
    assert!(
        e.history
            .iter()
            .any(|h| h.value("Password") == "private-demo")
    );
}

/// A merge records every change: a stamp's normal form with nothing else changing is
/// one too (MOD-11.26), and a repeat merge records nothing.
#[test]
fn a_repeat_merge_records_nothing() {
    for kind in KINDS {
        let mut a = common();
        let mut b = common();
        gm(&mut a.root, P)
            .entries
            .push(entry(E, "private-demo", at(10)));
        gm(&mut b.root, T)
            .entries
            .push(entry(F, "shared-demo", at(10)));
        let mut c = container_of();
        c.deleted_objects.push(record(0x52, at(5)));
        run::merge_into(&mut a, id(T), &c, at(20)).unwrap();
        let o = Options::new(kind);
        merge(&mut b, &a, &o, at(30)).unwrap();
        let again = merge(&mut b, &a, &o, at(31)).unwrap();
        assert!(
            again.changes.iter().all(|c| c.kind != ChangeKind::Conflict),
            "{kind:?}"
        );
        let once_more = b.duplicate();
        let last = merge(&mut b, &once_more, &o, at(32)).unwrap();
        assert!(
            last.changes.is_empty(),
            "{kind:?}: {:?}",
            last.changes.len()
        );
    }
}

/// T holds S, a share too.
const S: u8 = 0x21;

fn nested() -> Vault {
    let mut v = common();
    let mut s = Group::new(id(S), "S".into(), T0);
    s.custom_data.items.push(share_item());
    gm(&mut v.root, T).groups.push(s);
    v
}

/// T and U, side by side, are both shares.
fn side_by_side() -> Vault {
    let mut v = common();
    gm(&mut v.root, U).custom_data.items.push(share_item());
    v
}

fn in_group(v: &mut Vault, group: u8, e: Entry) {
    gm(&mut v.root, group).entries.push(e);
}

fn stamp_of(v: &Vault, n: u8) -> Option<origin::Stamp> {
    origin::stamp_of(&entry_of(v, n).custom_data)
}

fn the_stamp(group: u8, when: i64) -> origin::Stamp {
    origin::Stamp {
        group: id(group),
        at: at(when),
    }
}

fn em(g: &mut Group, n: u8) -> Option<&mut Entry> {
    if let Some(e) = g.entries.iter_mut().find(|e| e.uuid == id(n)) {
        return Some(e);
    }
    g.groups.iter_mut().find_map(|c| em(c, n))
}

fn set_stamp_on(v: &mut Vault, n: u8, s: origin::Stamp) {
    origin::set_stamp(&mut em(&mut v.root, n).unwrap().custom_data, Some(s));
}

fn history_values(v: &Vault, n: u8) -> Vec<String> {
    entry_of(v, n)
        .history
        .iter()
        .map(|h| h.value("Password").to_owned())
        .collect()
}

/// Round 4 (C1-03): what crosses is what an export carries. A losing value stays on
/// this Mac only as Larsal's private history item, and no share's export holds it.
fn crossed(v: &Vault, n: u8, value: &str) -> bool {
    let public = entry_of(v, n)
        .history
        .iter()
        .any(|h| h.value("Password") == value && !origin::private_item(h));
    let exported = [T, U].iter().any(|s| {
        container::build(id(*s), true, v, at(99)).is_ok_and(|c| {
            c.root.all_entries().any(|e| {
                e.value("Password") == value
                    || e.history.iter().any(|h| h.value("Password") == value)
            })
        })
    });
    public || exported
}

/// R6 E3: a stamp counts only for a share it names or one inside it. Here it names T,
/// and the difference between the copies is S, inside T: the user never moved it in.
#[test]
fn e3_a_stamp_counts_only_for_the_share_it_names() {
    for kind in KINDS {
        let (mut a, mut b) = (nested(), nested());
        in_group(&mut a, S, entry(E, "member-demo", at(1)));
        set_stamp_on(&mut a, E, the_stamp(T, 9));
        in_group(&mut b, T, entry(E, "demo", at(1)));
        settle(&mut a, &mut b, kind);
        assert_eq!(view(&a), view(&b), "{kind:?}");
        assert_eq!(parent_of_entry(&a, E), Some(id(T)), "{kind:?}");
    }
}

/// R6 E3: a stamp counts when nothing on the other copy is later: a change at the
/// stamp's own time is not later.
#[test]
fn e3_a_stamp_beats_a_change_at_its_own_time() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        in_group(&mut a, P, entry(E, "demo", at(1)));
        in_group(&mut b, P, entry(E, "demo", at(5)));
        edit::move_entries(&mut a, &[id(E)], id(T), at(5)).unwrap();
        settle(&mut a, &mut b, kind);
        assert_eq!(view(&a), view(&b), "{kind:?}");
        assert_eq!(parent_of_entry(&b, E), Some(id(T)), "{kind:?}");
    }
}

/// R6 E3: Later reads every history item of the other copy, not only its own times.
#[test]
fn e3_later_reads_the_history_items() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        in_group(&mut a, P, entry(E, "demo", at(1)));
        let mut mine = entry(E, "demo", at(1));
        mine.history.push(entry(E, "old-demo", at(9)));
        in_group(&mut b, P, mine);
        edit::move_entries(&mut a, &[id(E)], id(T), at(5)).unwrap();
        settle(&mut a, &mut b, kind);
        assert_eq!(view(&a), view(&b), "{kind:?}");
        assert_eq!(
            parent_of_entry(&a, E),
            Some(id(P)),
            "{kind:?}: the move in lost"
        );
    }
}

/// R6 E3: both stamps valid, the later stamp wins. A group's move stamps what it holds
/// without touching its times, so both of an entry's stamps can be valid.
#[test]
fn e3_both_stamps_valid_the_later_stamp_wins() {
    for kind in KINDS {
        let mut base = side_by_side();
        let mut o = Group::new(id(O), "O".into(), at(1));
        o.entries.push(entry(F, "demo", at(1)));
        gm(&mut base.root, P).groups.push(o);
        let (mut a, mut b) = (base.duplicate(), base.duplicate());
        edit::move_group(&mut a, id(O), id(T), Position::End, at(5)).unwrap();
        edit::move_group(&mut b, id(O), id(U), Position::End, at(6)).unwrap();
        settle(&mut a, &mut b, kind);
        assert_eq!(view(&a), view(&b), "{kind:?}");
        for v in [&a, &b] {
            assert_eq!(parent_of_group(v, O), Some(id(U)), "{kind:?}");
            assert_eq!(parent_of_entry(v, F), Some(id(O)), "{kind:?}");
            assert_eq!(stamp_of(v, F), Some(the_stamp(U, 6)), "{kind:?}");
        }
    }
}

/// R6 E3: neither copy holds a valid stamp, each in a share of its own: the lowest
/// share id wins whole, whatever the times, and the other value goes with nothing
/// joined.
#[test]
fn e3_neither_stamp_valid_the_lowest_share_id_wins_whole() {
    for kind in KINDS {
        for first in [false, true] {
            let (mut a, mut b) = (side_by_side(), side_by_side());
            let mut c = container_of();
            c.root.entries.push(entry(E, "t-demo", at(10)));
            run::merge_into(&mut a, id(T), &c, at(30)).unwrap();
            let mut c = container_of();
            c.root.entries.push(entry(E, "u-demo", at(20)));
            run::merge_into(&mut b, id(U), &c, at(30)).unwrap();
            if first {
                settle(&mut a, &mut b, kind);
            } else {
                settle(&mut b, &mut a, kind);
            }
            for v in [&a, &b] {
                assert_eq!(parent_of_entry(v, E), Some(id(T)), "{kind:?} {first}");
                assert_eq!(value(v, E).as_deref(), Some("t-demo"), "{kind:?} {first}");
                // Round 4, named as changed: the value may stay as a private item.
                assert!(
                    !crossed(v, E, "u-demo"),
                    "{kind:?} {first}: joined across two shares"
                );
            }
        }
    }
}

/// R6 E5: a user's move from one share to another takes the copy whole. The value the
/// other share held is dropped, in either direction: nothing crosses between shares.
#[test]
fn e5_a_move_between_shares_takes_the_copy_whole_and_joins_nothing() {
    for kind in KINDS {
        for first in [false, true] {
            let (mut a, mut b) = (side_by_side(), side_by_side());
            in_group(&mut a, T, entry(E, "t-demo", at(1)));
            in_group(&mut b, T, entry(E, "t-demo", at(1)));
            edit::move_entries(&mut b, &[id(E)], id(U), at(5)).unwrap();
            edit::edit_entry(&mut b, id(E), at(5), |d| {
                d.set_field(
                    "Password".to_owned(),
                    Field {
                        value: SecretString::new("u-demo".to_owned()),
                        protected: true,
                    },
                );
            })
            .unwrap();
            // The edit's own backup is the user's, not the merge's.
            em(&mut b.root, E).unwrap().history.clear();
            if first {
                settle(&mut a, &mut b, kind);
            } else {
                settle(&mut b, &mut a, kind);
            }
            for v in [&a, &b] {
                assert_eq!(parent_of_entry(v, E), Some(id(U)), "{kind:?} {first}");
                assert_eq!(value(v, E).as_deref(), Some("u-demo"), "{kind:?} {first}");
                // Round 4, named as changed: the value may stay as a private item.
                assert!(
                    !crossed(v, E, "t-demo"),
                    "{kind:?} {first}: joined across two shares"
                );
            }
        }
    }
}

/// R6 E6: outside there is no stamp, even a left-over one in a copy.
#[test]
fn e6_a_left_over_stamp_outside_goes_at_a_merge() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        in_group(&mut a, P, entry(E, "demo", at(1)));
        in_group(&mut b, P, entry(E, "demo", at(1)));
        set_stamp_on(&mut a, E, the_stamp(T, 3));
        settle(&mut a, &mut b, kind);
        for v in [&a, &b] {
            assert_eq!(stamp_of(v, E), None, "{kind:?}");
        }
    }
}

/// R6 E4: a place that would make a cycle does not fit, so the group goes where it fits
/// and takes the later Loc. Each copy moved one group into the other, inside T.
#[test]
fn e4_a_place_that_makes_a_cycle_does_not_fit() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        let group = |n: u8, when: i64| {
            let mut g = Group::new(id(n), "G".into(), at(1));
            g.times.location_changed = at(when);
            g
        };
        let mut k = group(K, 1);
        k.groups.push(group(O, 9));
        gm(&mut a.root, T).groups.push(k);
        let mut o = group(O, 1);
        o.groups.push(group(K, 9));
        gm(&mut b.root, T).groups.push(o);
        merge(&mut a, &b, &Options::new(kind), at(100)).unwrap();
        assert_eq!(parent_of_group(&a, O), Some(id(K)), "{kind:?}");
        assert_eq!(parent_of_group(&a, K), Some(id(T)), "{kind:?}");
        let g = a.root.find_group(id(K)).unwrap();
        assert_eq!(g.times.location_changed, at(9), "{kind:?}");
    }
}

/// R6 E5: the loser's value kept as a history item has its password protected, as every
/// password a merge writes (MOD-11.11).
#[test]
fn e5_a_losers_value_in_history_is_protected() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        in_group(&mut a, P, entry(E, "private-demo", at(1)));
        let mut member = entry(E, "member-demo", at(9));
        member.set_field(
            "Password".to_owned(),
            Field {
                value: SecretString::new("member-demo".to_owned()),
                protected: false,
            },
        );
        in_group(&mut b, T, member);
        merge(&mut a, &b, &Options::new(kind), at(100)).unwrap();
        assert_eq!(value(&a, E).as_deref(), Some("private-demo"), "{kind:?}");
        let item = entry_of(&a, E)
            .history
            .iter()
            .find(|h| h.value("Password") == "member-demo")
            .expect("the loser's value");
        assert!(item.field("Password").unwrap().protected, "{kind:?}");
    }
}

/// MOD-11.11, with a share known too: an entry a merge adds has its password protected.
#[test]
fn e_an_entry_a_merge_adds_has_its_password_protected() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        let mut e = entry(E, "demo", at(9));
        e.set_field(
            "Password".to_owned(),
            Field {
                value: SecretString::new("demo".to_owned()),
                protected: false,
            },
        );
        in_group(&mut b, P, e);
        merge(&mut a, &b, &Options::new(kind), at(100)).unwrap();
        let f = entry_of(&a, E).field("Password").unwrap().protected;
        assert!(f, "{kind:?}");
    }
}

/// MOD-11.26: a merge tries today's move, then the rule puts the object back: no record
/// of a move. Mac A moved K into T; Mac B moved O and E into K, outside on its side.
#[test]
fn records_a_move_tried_and_put_back_says_nothing() {
    for kind in KINDS {
        let mut base = common();
        base.root.groups.push(Group::new(id(K), "K".into(), T0));
        gm(&mut base.root, P)
            .groups
            .push(Group::new(id(O), "O".into(), at(1)));
        in_group(&mut base, P, entry(E, "demo", at(1)));
        let (mut a, mut b) = (base.duplicate(), base.duplicate());
        edit::move_group(&mut a, id(K), id(T), Position::End, at(9)).unwrap();
        edit::move_group(&mut b, id(O), id(K), Position::End, at(5)).unwrap();
        edit::move_entries(&mut b, &[id(E)], id(K), at(5)).unwrap();
        let m = merge(&mut a, &b, &Options::new(kind), at(100)).unwrap();
        assert_eq!(parent_of_group(&a, O), Some(id(P)), "{kind:?}");
        assert_eq!(parent_of_entry(&a, E), Some(id(P)), "{kind:?}");
        let moved: Vec<_> = m
            .changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Moved && (c.id == Some(id(O)) || c.id == Some(id(E))))
            .map(|c| c.line())
            .collect();
        assert!(moved.is_empty(), "{kind:?}: {moved:?}");
    }
}

/// R6 E2: a copy older than a plain record, with nothing inside, is not a dead copy: it
/// goes by today's pass, and here the other copy is newer, so its value joins history.
#[test]
fn e2_an_outside_copy_with_nothing_inside_merges_as_today() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        in_group(&mut a, P, entry(E, "old-demo", at(3)));
        a.deleted_objects.push(record(E, at(5)));
        in_group(&mut b, P, entry(E, "new-demo", at(7)));
        merge(&mut a, &b, &Options::new(kind), at(100)).unwrap();
        assert_eq!(value(&a, E).as_deref(), Some("new-demo"), "{kind:?}");
        assert!(
            history_values(&a, E).iter().any(|x| x == "old-demo"),
            "{kind:?}"
        );
    }
}

/// R6 E7: a stamp keeps a group as it keeps an entry. A move of the group above stamps
/// K, whose own times stay older than its row.
#[test]
fn e7_a_groups_stamp_keeps_it() {
    for kind in KINDS {
        let mut base = common();
        let mut o = Group::new(id(O), "O".into(), at(1));
        o.groups.push(Group::new(id(K), "K".into(), at(1)));
        gm(&mut base.root, P).groups.push(o);
        let (mut a, mut b) = (base.duplicate(), base.duplicate());
        origin::write_rows(
            &mut a.meta.custom_data,
            &origin::Rows::from([((id(K), id(T)), at(5))]),
        );
        edit::move_group(&mut b, id(O), id(T), Position::End, at(9)).unwrap();
        settle(&mut a, &mut b, kind);
        for v in [&a, &b] {
            assert_eq!(parent_of_group(v, K), Some(id(O)), "{kind:?}");
            assert_eq!(parent_of_group(v, O), Some(id(T)), "{kind:?}");
        }
    }
}

/// F-154 (LD-287 (2)) with a share known: the source copy's own time keeps an object
/// its record is older than, also when the target holds the older times.
#[test]
fn e7_the_sources_times_keep_an_entry_and_a_group() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        let mut mine = entry(E, "a-demo", at(3));
        mine.times.location_changed = at(1);
        in_group(&mut a, P, mine);
        let mut theirs = entry(E, "b-demo", at(2));
        theirs.times.location_changed = at(9);
        in_group(&mut b, P, theirs);
        let group = |modified: i64, loc: i64| {
            let mut g = Group::new(id(O), "O".into(), at(modified));
            g.times.location_changed = at(loc);
            g
        };
        gm(&mut a.root, P).groups.push(group(3, 1));
        gm(&mut b.root, P).groups.push(group(2, 9));
        a.deleted_objects.push(record(E, at(5)));
        a.deleted_objects.push(record(O, at(5)));
        merge(&mut a, &b, &Options::new(kind), at(100)).unwrap();
        assert_eq!(value(&a, E).as_deref(), Some("a-demo"), "{kind:?}");
        assert_eq!(parent_of_group(&a, O), Some(id(P)), "{kind:?}");
    }
}

/// R6 E7 and limit 5: a user's plain record stays while its object lives on inside a
/// share, so it goes on stopping a stale Mac.
#[test]
fn e7_a_kept_object_inside_keeps_the_plain_record() {
    for kind in KINDS {
        let (mut a, b) = (common(), common());
        in_group(&mut a, T, entry(E, "container-demo", at(9)));
        a.deleted_objects.push(record(E, at(5)));
        merge(&mut a, &b, &Options::new(kind), at(100)).unwrap();
        assert_eq!(value(&a, E).as_deref(), Some("container-demo"), "{kind:?}");
        assert_eq!(a.deleted_objects.len(), 1, "{kind:?}");
    }
}

/// R6 B: a group's move stamps what would come back to it: a group in the bin whose
/// previous parent it is, as it does an entry.
#[test]
fn b_a_groups_move_stamps_a_bin_group_that_would_come_back() {
    let mut a = common();
    a.meta.recycle_bin_enabled = true;
    let mut o = Group::new(id(O), "O".into(), at(1));
    o.groups.push(Group::new(id(K), "K".into(), at(1)));
    gm(&mut a.root, P).groups.push(o);
    recycle::delete_group(&mut a, id(K), at(2)).unwrap();
    assert_eq!(parent_of_group(&a, K), Some(id(BIN)));
    edit::move_group(&mut a, id(O), id(T), Position::End, at(9)).unwrap();
    let k = a.root.find_group(id(K)).unwrap();
    assert_eq!(
        origin::stamp_of(&k.custom_data),
        Some(the_stamp(T, 9)),
        "the bin's group"
    );
}

/// R6 B: as a group in the bin, so an entry in the bin.
#[test]
fn b_a_groups_move_stamps_a_bin_entry_that_would_come_back() {
    let mut a = common();
    a.meta.recycle_bin_enabled = true;
    let mut o = Group::new(id(O), "O".into(), at(1));
    let mut k = Group::new(id(K), "K".into(), at(1));
    k.entries.push(entry(E, "demo", at(1)));
    o.groups.push(k);
    gm(&mut a.root, P).groups.push(o);
    recycle::delete_entries(&mut a, &[id(E)], at(2), |_, _| References::Delete).unwrap();
    assert_eq!(parent_of_entry(&a, E), Some(id(BIN)));
    edit::move_group(&mut a, id(O), id(T), Position::End, at(9)).unwrap();
    assert_eq!(stamp_of(&a, E), Some(the_stamp(T, 9)));
}

/// R6 B: a group that goes for good hands its place to the bin items that name it, so
/// they go on counting where they did.
#[test]
fn b_a_group_that_goes_hands_its_place_to_the_bin_items_naming_it() {
    let mut a = common();
    a.meta.recycle_bin_enabled = true;
    let mut k = Group::new(id(K), "K".into(), at(1));
    k.entries.push(entry(E, "demo", at(1)));
    k.groups.push(Group::new(id(O), "O".into(), at(1)));
    gm(&mut a.root, T).groups.push(k);
    recycle::delete_entries(&mut a, &[id(E)], at(2), |_, _| References::Delete).unwrap();
    recycle::delete_group(&mut a, id(O), at(2)).unwrap();
    a.meta.recycle_bin_enabled = false;
    recycle::delete_group(&mut a, id(K), at(3)).unwrap();
    assert_eq!(entry_of(&a, E).previous_parent, Some(id(T)));
    let o = a.root.find_group(id(O)).unwrap();
    assert_eq!(o.previous_parent, Some(id(T)));
}

/// R6 B: a restore whose previous parent lies in the bin goes to the innermost share the
/// item counts in, not to the root.
#[test]
fn b_a_restore_goes_back_to_the_share_it_counts_in() {
    let mut a = common();
    a.meta.recycle_bin_enabled = true;
    let mut k = Group::new(id(K), "K".into(), at(1));
    k.entries.push(entry(E, "demo", at(1)));
    k.groups.push(Group::new(id(O), "O".into(), at(1)));
    gm(&mut a.root, T).groups.push(k);
    recycle::delete_entries(&mut a, &[id(E)], at(2), |_, _| References::Delete).unwrap();
    recycle::delete_group(&mut a, id(O), at(2)).unwrap();
    recycle::delete_group(&mut a, id(K), at(3)).unwrap();
    let out = recycle::restore_entries(&mut a, &[id(E)], at(4)).unwrap();
    assert_eq!(parent_of_entry(&a, E), Some(id(T)));
    assert_eq!(out.to_root, 0);
    let out = recycle::restore_group(&mut a, id(O), at(4)).unwrap();
    assert_eq!(parent_of_group(&a, O), Some(id(T)));
    assert_eq!(out.to_root, 0);
}

/// INT-08.32: a copy is a new object: no user's move and no share brought it, so it has
/// neither item.
#[test]
fn b_a_copy_has_neither_stamp_nor_marker() {
    let mut a = common();
    let mut e = entry(E, "demo", at(1));
    let mut h = entry(E, "old-demo", at(1));
    origin::set_mark(&mut h.custom_data, id(T));
    e.history.push(h);
    origin::set_mark(&mut e.custom_data, id(T));
    let mut o = Group::new(id(O), "O".into(), at(1));
    origin::set_mark(&mut o.custom_data, id(T));
    origin::set_stamp(&mut o.custom_data, Some(the_stamp(T, 2)));
    o.entries.push(e);
    gm(&mut a.root, T).groups.push(o);
    set_stamp_on(&mut a, E, the_stamp(T, 2));
    let own = |d: &larsal_model::CustomData| d.items.iter().any(|i| origin::ours(&i.key));
    let new = edit::copy_within(
        &mut a,
        edit::Item::Entry(id(E)),
        id(T),
        Position::End,
        at(5),
    )
    .unwrap();
    let copy = a.root.subtree().into_iter().find_map(|g| {
        g.entries
            .iter()
            .find(|e| e.uuid == new)
            .map(|e| e.duplicate(true))
    });
    let copy = copy.unwrap();
    assert!(!own(&copy.custom_data), "the entry's copy");
    let new = edit::copy_within(
        &mut a,
        edit::Item::Group(id(O)),
        id(T),
        Position::End,
        at(5),
    )
    .unwrap();
    let g = a.root.find_group(new).unwrap();
    assert!(!own(&g.custom_data), "the group's copy");
    for e in &g.entries {
        assert!(!own(&e.custom_data), "an entry of the group's copy");
        assert!(
            e.history.iter().all(|h| !own(&h.custom_data)),
            "its history"
        );
    }
}

/// A4: a row keeps its latest time, also when a clock runs back.
#[test]
fn a4_a_row_keeps_its_latest_time() {
    let mut a = common();
    in_group(&mut a, T, entry(E, "demo", at(1)));
    origin::write_rows(
        &mut a.meta.custom_data,
        &origin::Rows::from([((id(E), id(T)), at(9))]),
    );
    recycle::delete_entries(&mut a, &[id(E)], at(3), |_, _| References::Delete).unwrap();
    let rows = origin::read_rows(&a.meta.custom_data);
    assert_eq!(rows.get(&(id(E), id(T))), Some(&at(9)));
}

/// R6 C1: no time of a share's container is later than the import: a group's and a
/// history item's as well as an entry's.
#[test]
fn c1_an_import_cuts_a_groups_and_a_history_items_times() {
    let mut a = common();
    let mut c = container_of();
    let mut o = Group::new(id(O), "O".into(), at(9000));
    o.times.location_changed = at(9000);
    let mut e = entry(E, "demo", at(9000));
    e.history.push(entry(E, "old-demo", at(9000)));
    o.entries.push(e);
    c.root.groups.push(o);
    run::merge_into(&mut a, id(T), &c, at(50)).unwrap();
    let g = a.root.find_group(id(O)).unwrap();
    assert_eq!(g.times.last_modification, at(50), "the group");
    assert_eq!(g.times.location_changed, at(50), "the group");
    let h = &entry_of(&a, E).history;
    assert_eq!(h[0].times.last_modification, at(50), "the history item");
}

/// R6 C4: an import reaches no group outside its share, whatever record the vault holds.
#[test]
fn c4_an_import_reaches_no_group_outside_its_share() {
    let mut a = common();
    gm(&mut a.root, P)
        .groups
        .push(Group::new(id(O), "O".into(), at(1)));
    a.deleted_objects.push(record(O, at(5)));
    let mut c = container_of();
    c.root.entries.push(entry(E, "demo", at(10)));
    run::merge_into(&mut a, id(T), &c, at(50)).unwrap();
    assert_eq!(parent_of_group(&a, O), Some(id(P)));
}

/// D, and today's stale Macs: an export carries a user's plain records.
#[test]
fn d_an_export_carries_a_users_plain_records() {
    let mut a = common();
    a.deleted_objects.push(record(E, at(5)));
    let c = container::build(id(T), true, &a, NOW).unwrap();
    assert!(c.deleted_objects.iter().any(|d| d.uuid == id(E)));
}

/// D: another vault's rows or list, alone, come to nothing: neither item comes across.
#[test]
fn d_another_vaults_rows_or_list_alone_do_not_come() {
    for which in [false, true] {
        let mut t = Vault::new(Group::new(id(ROOT), "Root".into(), T0), T0);
        t.meta.recycle_bin_enabled = false;
        let mut s = Vault::new(Group::new(id(0x02), "Other".into(), T0), T0);
        s.meta.recycle_bin_enabled = false;
        if which {
            origin::write_known(&mut s.meta.custom_data, &origin::Set::from([id(T)]));
        } else {
            origin::write_rows(
                &mut s.meta.custom_data,
                &origin::Rows::from([((id(E), id(T)), at(5))]),
            );
        }
        let mut o = Options::new(Kind::ConflictCopy);
        o.source_start = None;
        merge(&mut t, &s, &o, at(100)).unwrap();
        assert!(
            origin::read_known(&t.meta.custom_data).is_empty(),
            "{which}"
        );
        assert!(origin::read_rows(&t.meta.custom_data).is_empty(), "{which}");
    }
}

/// R6 E3: the result keeps the later stamp, when both name the share.
#[test]
fn e3_the_result_keeps_the_later_stamp() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        in_group(&mut a, T, entry(E, "demo", at(1)));
        in_group(&mut b, T, entry(E, "demo", at(1)));
        set_stamp_on(&mut a, E, the_stamp(T, 3));
        set_stamp_on(&mut b, E, the_stamp(T, 4));
        settle(&mut a, &mut b, kind);
        for v in [&a, &b] {
            assert_eq!(stamp_of(v, E), Some(the_stamp(T, 4)), "{kind:?}");
        }
    }
}

/// R6 E6: a stamp names a share the object counts in, so a stamp for a share it left
/// names the one it is in.
#[test]
fn e6_a_stamp_names_a_share_the_object_counts_in() {
    for kind in KINDS {
        let (mut a, mut b) = (nested(), nested());
        in_group(&mut a, T, entry(E, "demo", at(1)));
        in_group(&mut b, T, entry(E, "demo", at(1)));
        set_stamp_on(&mut a, E, the_stamp(S, 3));
        settle(&mut a, &mut b, kind);
        for v in [&a, &b] {
            assert_eq!(stamp_of(v, E), Some(the_stamp(T, 3)), "{kind:?}");
        }
    }
}

/// R6 E4: inside one share, on one Loc, the lower group id.
#[test]
fn e4_on_one_loc_the_lower_group_id() {
    for kind in KINDS {
        for first in [false, true] {
            let mut base = common();
            gm(&mut base.root, T)
                .groups
                .push(Group::new(id(O), "O".into(), at(1)));
            gm(&mut base.root, T)
                .groups
                .push(Group::new(id(K), "K".into(), at(1)));
            let (mut a, mut b) = (base.duplicate(), base);
            let mut e = entry(E, "demo", at(1));
            e.times.location_changed = at(5);
            in_group(&mut a, K, e.duplicate(true));
            in_group(&mut b, O, e);
            if first {
                settle(&mut a, &mut b, kind);
            } else {
                settle(&mut b, &mut a, kind);
            }
            for v in [&a, &b] {
                assert_eq!(parent_of_entry(v, E), Some(id(O)), "{kind:?} {first}");
            }
        }
    }
}

/// R6 E5: a same version takes the winner's stamp all the same. The move stamped the
/// entry and changed nothing else.
#[test]
fn e5_a_same_version_takes_the_winners_stamp() {
    for kind in KINDS {
        let (mut a, mut b) = (side_by_side(), side_by_side());
        in_group(&mut a, U, entry(E, "demo", at(1)));
        in_group(&mut b, U, entry(E, "demo", at(1)));
        edit::move_entries(&mut b, &[id(E)], id(T), at(7)).unwrap();
        merge(&mut a, &b, &Options::new(kind), at(100)).unwrap();
        assert_eq!(parent_of_entry(&a, E), Some(id(T)), "{kind:?}");
        assert_eq!(stamp_of(&a, E), Some(the_stamp(T, 7)), "{kind:?}");
    }
}

/// R6 E: a group a merge adds keeps what the share brought it with.
#[test]
fn e_a_group_a_merge_adds_keeps_its_marker() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        let mut c = container_of();
        c.root.groups.push(Group::new(id(O), "O".into(), at(1)));
        run::merge_into(&mut a, id(T), &c, at(50)).unwrap();
        let g = a.root.find_group(id(O)).unwrap();
        assert!(origin::mark_of(&g.custom_data).is_some(), "the import's");
        merge(&mut b, &a, &Options::new(kind), at(100)).unwrap();
        let g = b.root.find_group(id(O)).unwrap();
        assert!(origin::mark_of(&g.custom_data).is_some(), "{kind:?}");
    }
}

/// MOD-11.26: a change of a group's own items alone is a change on record.
#[test]
fn records_a_change_of_a_groups_own_items_says_so() {
    for kind in KINDS {
        let group = || Group::new(id(O), "O".into(), at(1));
        let (mut a, mut b) = (common(), common());
        gm(&mut a.root, T).groups.push(group());
        let mut mine = group();
        origin::set_stamp(&mut mine.custom_data, Some(the_stamp(T, 5)));
        gm(&mut b.root, T).groups.push(mine);
        let m = merge(&mut a, &b, &Options::new(kind), at(100)).unwrap();
        let g = a.root.find_group(id(O)).unwrap();
        assert_eq!(
            origin::stamp_of(&g.custom_data),
            Some(the_stamp(T, 5)),
            "{kind:?}"
        );
        assert!(
            m.changes
                .iter()
                .any(|c| c.id == Some(id(O)) && c.kind == ChangeKind::Modified),
            "{kind:?}"
        );
    }
}

/// R6 E2 and E7: a stamp later than the record saves a copy the record is later than by
/// its own times: the user moved it in after the deletion.
#[test]
fn e2_a_later_stamp_saves_a_copy() {
    for kind in KINDS {
        let (mut a, mut b) = (common(), common());
        let group = || Group::new(id(O), "O".into(), at(1));
        gm(&mut a.root, P).groups.push(group());
        a.deleted_objects.push(record(F, at(3)));
        let mut o = group();
        o.entries.push(entry(F, "demo", at(1)));
        gm(&mut b.root, P).groups.push(o);
        edit::move_group(&mut b, id(O), id(T), Position::End, at(6)).unwrap();
        settle(&mut a, &mut b, kind);
        for v in [&a, &b] {
            assert_eq!(parent_of_entry(v, F), Some(id(O)), "{kind:?}");
        }
    }
}

/// F8's limit. A plain record names an id and no kind (FMT-15), so a user who moves a
/// brought group out of the share and deletes it for good also erases an older entry
/// with that id, as a deletion of the same kind would. It takes the user's two acts: a
/// deletion while the group counts inside is a row, and the entry stays.
#[test]
fn f8_limit_a_users_record_names_an_id_and_no_kind() {
    for kind in KINDS {
        for moved_out in [false, true] {
            let (mut a, mut b) = (common(), common());
            in_group(&mut b, P, entry(E, "private-demo", at(1)));
            let mut c = container_of();
            c.root.groups.push(Group::new(id(E), "N".into(), at(1)));
            run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
            if moved_out {
                edit::move_group(&mut a, id(E), id(P), Position::End, at(20)).unwrap();
            }
            recycle::delete_group(&mut a, id(E), at(30)).unwrap();
            settle(&mut a, &mut b, kind);
            for v in [&a, &b] {
                let want = if moved_out {
                    None
                } else {
                    Some("private-demo".to_owned())
                };
                assert_eq!(value(v, E), want, "{kind:?} {moved_out}");
                assert_eq!(parent_of_group(v, E), None, "{kind:?} {moved_out}");
            }
        }
    }
}

/// F8's limit, within a share. A row names an id and no kind too: a user who deletes a
/// brought group erases an older entry with that id in that share, one moved in included.
/// The outside copy on a Mac the move has not reached stays, and the entry comes back
/// from it: nothing outside changes.
#[test]
fn f8_limit_a_row_names_an_id_and_no_kind_within_its_share() {
    for kind in KINDS {
        let mut a = common();
        in_group(&mut a, P, entry(E, "private-demo", at(1)));
        let mut b = a.duplicate();
        edit::move_entries(&mut a, &[id(E)], id(T), at(8)).unwrap();
        let mut c = container_of();
        c.root.groups.push(Group::new(id(E), "N".into(), at(1)));
        run::merge_into(&mut a, id(T), &c, at(10)).unwrap();
        recycle::delete_group(&mut a, id(E), at(15)).unwrap();
        let rows = origin::read_rows(&a.meta.custom_data);
        assert_eq!(rows.get(&(id(E), id(T))), Some(&at(15)), "{kind:?}");
        let twin = a.duplicate();
        merge(&mut a, &twin, &Options::new(kind), at(100)).unwrap();
        assert_eq!(value(&a, E), None, "{kind:?}");
        settle(&mut a, &mut b, kind);
        for v in [&a, &b] {
            assert_eq!(parent_of_entry(v, E), Some(id(P)), "{kind:?}");
            assert_eq!(value(v, E).as_deref(), Some("private-demo"), "{kind:?}");
        }
    }
}
