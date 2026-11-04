//! E4-S3: the rules of MOD-04 (recycle bin). Each test names its rule and
//! checks the invariants afterwards.

mod common;

use app_core::Error;
use app_core::edit::{
    Item, Position, add_entry, add_group, change_entry, copy_within, move_group, new_entry,
    new_group, sort_groups,
};
use app_core::recycle::{
    BIN_ICON, BIN_NAME, References, bin_id, can_create_in, can_empty, delete_by_request,
    delete_entries, delete_group, empty_bin, entry_in_bin, group_in_bin, referencing,
    restore_entries, restore_group, set_bin_enabled,
};
use app_crypto::secret::SecretString;
use app_model::{Field, Group, Icon, Switch, Time, Uuid, Vault};
use common::*;

fn del(v: &mut Vault, ids: &[Uuid]) -> app_core::recycle::Deleted {
    delete_entries(v, ids, NOW, |_, _| References::Delete).unwrap()
}

fn bin(v: &Vault) -> &Group {
    group(v, bin_id(v).expect("a bin"))
}

fn records(v: &Vault) -> Vec<Uuid> {
    v.deleted_objects.iter().map(|d| d.uuid).collect()
}

#[test]
fn mod_04_1_which_group_is_the_bin() {
    let mut v = sample();
    assert_eq!(bin_id(&v), None);
    v.meta.recycle_bin = Some(id(0x77));
    assert_eq!(bin_id(&v), None, "a dangling id means no bin");
    v.meta.recycle_bin = Some(id(1));
    assert_eq!(bin_id(&v), None, "the root is never the bin (LD-76)");
    v.meta.recycle_bin = Some(id(3));
    assert_eq!(bin_id(&v), Some(id(3)), "wherever it sits");
    move_group(&mut v, id(3), id(4), Position::End, NOW).unwrap();
    assert_eq!(bin_id(&v), Some(id(3)), "a moved bin stays the bin");
    ok(&v);
}

#[test]
fn mod_04_2_creating_the_bin() {
    let mut v = sample();
    let root_times = v.root.times.clone();
    del(&mut v, &[id(0x10)]);
    let b = bin(&v);
    assert_eq!(
        (b.name.as_str(), b.icon, b.searching, b.auto_type),
        (BIN_NAME, Icon::Standard(43), Switch::Off, Switch::Off)
    );
    assert_eq!((b.uuid.0[6] >> 4, b.uuid.0[8] >> 6), (4, 0b10));
    let t = &b.times;
    assert_eq!(
        (
            t.creation,
            t.last_modification,
            t.last_access,
            t.location_changed,
            t.expiry,
            t.expires
        ),
        (NOW, NOW, NOW, NOW, NOW, false)
    );
    assert!(b.notes.is_empty() && b.expanded && b.default_sequence.is_empty());
    assert_eq!(
        v.root.groups.last().unwrap().uuid,
        b.uuid,
        "last child of the root"
    );
    assert_eq!(
        (v.meta.recycle_bin, v.meta.recycle_bin_changed),
        (Some(b.uuid), NOW)
    );
    assert_eq!(v.root.times, root_times);
    // A group that only looks like a bin is not reused.
    let mut w = sample();
    w.root.groups[1].name = BIN_NAME.into();
    w.root.groups[1].icon = Icon::Standard(BIN_ICON);
    del(&mut w, &[id(0x10)]);
    assert_ne!(bin_id(&w), Some(id(4)));
    ok(&v);
    ok(&w);
}

#[test]
fn mod_04_3_counts_for_the_question() {
    // L04-1: the question states both counts when they differ.
    let mut v = sample();
    del(&mut v, &[id(0x10)]);
    let d = del(&mut v, &[id(0x10), id(0x11)]);
    assert_eq!((d.to_bin, d.for_good), (1, 1));
    ok(&v);
}

#[test]
fn mod_04_4_bin_or_for_good() {
    let mut v = sample();
    assert_eq!(del(&mut v, &[id(0x10)]).to_bin, 1);
    assert_eq!(del(&mut v, &[id(0x10)]).for_good, 1, "already in the bin");
    assert_eq!(delete_group(&mut v, id(3), NOW).unwrap().to_bin, 1);
    assert_eq!(
        delete_group(&mut v, id(3), NOW).unwrap().for_good,
        1,
        "a group in the bin"
    );
    // A group that holds the bin.
    let mut w = sample();
    w.meta.recycle_bin = Some(id(3));
    assert_eq!(delete_group(&mut w, id(2), NOW).unwrap().for_good, 1);
    // The bin off.
    let mut x = sample();
    x.meta.recycle_bin_enabled = false;
    assert_eq!(del(&mut x, &[id(0x10)]).for_good, 1);
    assert_eq!(delete_group(&mut x, id(4), NOW).unwrap().for_good, 1);
    assert_eq!(delete_group(&mut x, id(1), NOW), Err(Error::RootGroup));
    for v in [&v, &w, &x] {
        ok(v);
    }
}

#[test]
fn mod_04_5_moving_into_the_bin() {
    let mut v = sample();
    del(&mut v, &[id(0x12)]);
    let e = find(&v, id(0x12));
    assert_eq!(holder(&v, id(0x12)), bin_id(&v).unwrap());
    assert_eq!(
        (
            e.previous_parent,
            e.times.location_changed,
            e.times.last_modification,
            e.times.last_access
        ),
        (Some(id(2)), NOW, NOW, NOW)
    );
    assert!(e.history.is_empty() && v.deleted_objects.is_empty());
    // A previous parent that already names the group left: only location moves.
    let mut w = sample();
    change_entry(&mut w, id(0x11), T0, |e| e.previous_parent = Some(id(1))).unwrap();
    del(&mut w, &[id(0x11)]);
    let e = find(&w, id(0x11));
    assert_eq!(
        (e.times.location_changed, e.times.last_modification),
        (NOW, T0)
    );
    // A group: last child of the bin, its contents untouched.
    delete_group(&mut w, id(2), NOW).unwrap();
    let g = group(&w, id(2));
    assert_eq!(bin(&w).groups.last().unwrap().uuid, id(2));
    assert_eq!(
        (
            g.previous_parent,
            g.times.location_changed,
            g.times.last_modification
        ),
        (Some(id(1)), NOW, NOW)
    );
    assert_eq!(find(&w, id(0x12)).times.last_modification, T0);
    assert_eq!(group(&w, id(3)).previous_parent, None);
    ok(&v);
    ok(&w);
}

fn with_reference(v: &mut Vault, from: Uuid, to: Uuid, field: &str) {
    let hex: String = to.0.iter().map(|b| format!("{b:02X}")).collect();
    change_entry(v, from, T0, |e| {
        e.set_field(
            field.into(),
            Field {
                value: SecretString::new(format!("{{REF:P@I:{hex}}}")),
                protected: false,
            },
        );
    })
    .unwrap();
}

#[test]
fn mod_04_6_references_on_delete_for_good() {
    let mut v = sample();
    v.meta.recycle_bin_enabled = false;
    change_entry(&mut v, id(0x10), T0, |e| {
        e.set_field(
            "Notes".into(),
            Field {
                value: SecretString::new("target notes".into()),
                protected: false,
            },
        );
    })
    .unwrap();
    with_reference(&mut v, id(0x11), id(0x10), "Notes");
    assert_eq!(referencing(&v, id(0x10), &[]), [id(0x11)]);
    // Skip keeps the entry.
    let d = delete_entries(&mut v, &[id(0x10)], NOW, |_, n| {
        assert_eq!(n, 1);
        References::Skip
    })
    .unwrap();
    assert_eq!(d.skipped, 1);
    find(&v, id(0x10));
    // Overwrite takes the same field name's raw value; no history item.
    delete_entries(&mut v, &[id(0x10)], NOW, |_, _| References::Overwrite).unwrap();
    let r = find(&v, id(0x11));
    assert_eq!(
        (r.value("Notes"), r.times.last_modification, r.history.len()),
        ("target notes", NOW, 0)
    );
    // Entries in the same selection are not asked about.
    let mut w = sample();
    w.meta.recycle_bin_enabled = false;
    with_reference(&mut w, id(0x11), id(0x10), "URL");
    let mut asked = false;
    delete_entries(&mut w, &[id(0x10), id(0x11)], NOW, |_, _| {
        asked = true;
        References::Skip
    })
    .unwrap();
    assert!(!asked);
    // Moving to the bin asks nothing.
    let mut x = sample();
    with_reference(&mut x, id(0x11), id(0x10), "URL");
    delete_entries(&mut x, &[id(0x10)], NOW, |_, _| panic!("no question")).unwrap();
    for v in [&v, &w, &x] {
        ok(v);
    }
}

#[test]
fn mod_04_7_deleting_for_good() {
    let mut v = sample();
    v.meta.recycle_bin_enabled = false;
    del(&mut v, &[id(0x10)]);
    assert_eq!(records(&v), [id(0x10)]);
    assert!(v.deleted_objects.iter().all(|d| d.deleted_at == NOW));
    delete_group(&mut v, id(2), NOW).unwrap();
    assert_eq!(
        records(&v),
        [id(0x10), id(0x12), id(0x13), id(3), id(2)],
        "entries, child groups, then the group"
    );
    // Group times: App moves none for entries leaving (MOD-02.25; see the
    // MOD-04.7 conflict raised with the lead).
    assert_eq!(v.root.times.last_modification, T0);
    ok(&v);
}

#[test]
fn mod_04_8_deleting_the_bin_itself() {
    let mut v = sample();
    del(&mut v, &[id(0x10)]);
    let old = bin_id(&v).unwrap();
    let later = Time(NOW.0 + 3);
    delete_group(&mut v, old, later).unwrap();
    assert_eq!(records(&v), [id(0x10), old]);
    assert_eq!(
        (v.meta.recycle_bin, v.meta.recycle_bin_changed),
        (None, later),
        "L04-6"
    );
    del(&mut v, &[id(0x11)]);
    assert_ne!(bin_id(&v), Some(old), "a new bin with a new id");
    ok(&v);
}

#[test]
fn mod_04_9_emptying() {
    let mut v = sample();
    assert!(!empty_bin(&mut v, NOW).unwrap(), "no bin: nothing");
    del(&mut v, &[id(0x10)]);
    delete_group(&mut v, id(2), NOW).unwrap();
    del(&mut v, &[id(0x11)]);
    let b = bin_id(&v).unwrap();
    assert!(empty_bin(&mut v, NOW).unwrap());
    assert_eq!(
        records(&v),
        [id(0x10), id(0x11), id(0x12), id(0x13), id(3), id(2)],
        "entries in order, then groups"
    );
    let g = bin(&v);
    assert_eq!(
        (g.uuid, g.entries.len(), g.groups.len()),
        (b, 0, 0),
        "the bin stays"
    );
    assert!(
        !empty_bin(&mut v, NOW).unwrap(),
        "an empty bin changes nothing"
    );
    assert_eq!(v.deleted_objects.len(), 6);
    ok(&v);
}

#[test]
fn mod_04_10_restore_entries() {
    let mut v = sample();
    del(&mut v, &[id(0x12), id(0x10)]);
    let later = Time(NOW.0 + 7);
    let r = restore_entries(&mut v, &[id(0x12), id(0x11)], later).unwrap();
    assert_eq!(
        (r.restored, r.to_root),
        (1, 0),
        "entries outside the bin never move"
    );
    assert_eq!(
        group(&v, id(2)).entries.last().unwrap().uuid,
        id(0x12),
        "after the group's entries"
    );
    let e = find(&v, id(0x12));
    assert_eq!(
        (
            e.previous_parent,
            e.times.location_changed,
            e.times.last_modification
        ),
        (bin_id(&v), later, later)
    );
    // A missing previous parent: to the root, counted.
    v.meta.recycle_bin_enabled = false;
    delete_group(&mut v, id(4), NOW).unwrap();
    v.meta.recycle_bin_enabled = true;
    change_entry(&mut v, id(0x10), NOW, |e| e.previous_parent = Some(id(4))).unwrap();
    let r = restore_entries(&mut v, &[id(0x10)], later).unwrap();
    assert_eq!((r.restored, r.to_root), (1, 1));
    assert_eq!(holder(&v, id(0x10)), id(1));
    assert!(find(&v, id(0x10)).history.is_empty() && records(&v) == [id(4)]);
    ok(&v);
}

#[test]
fn mod_04_11_restore_groups() {
    let mut v = sample();
    delete_group(&mut v, id(3), NOW).unwrap();
    let r = restore_group(&mut v, id(3), NOW).unwrap();
    assert_eq!((r.restored, r.to_root), (1, 0));
    assert_eq!(group(&v, id(2)).groups.last().unwrap().uuid, id(3));
    // A previous parent in the bin: to the root.
    delete_group(&mut v, id(2), NOW).unwrap();
    let b = bin_id(&v).unwrap();
    move_group(&mut v, id(3), b, Position::End, NOW).unwrap();
    group_mut(&mut v, id(3)).previous_parent = Some(id(2));
    let r = restore_group(&mut v, id(3), NOW).unwrap();
    assert_eq!(r.to_root, 1);
    assert_eq!(v.root.groups.last().unwrap().uuid, id(3));
    ok(&v);
}

fn group_mut(v: &mut Vault, uuid: Uuid) -> &mut Group {
    let mut stack = vec![&mut v.root];
    while let Some(g) = stack.pop() {
        if g.uuid == uuid {
            return g;
        }
        stack.extend(g.groups.iter_mut());
    }
    panic!("no group")
}

#[test]
fn mod_04_12_turning_the_bin_off() {
    // Not empty, keep: renamed, icon 48, switches inherit.
    let mut v = sample();
    del(&mut v, &[id(0x10)]);
    let b = bin_id(&v).unwrap();
    let later = Time(NOW.0 + 4);
    assert!(set_bin_enabled(&mut v, false, false, later).unwrap());
    let g = group(&v, b);
    assert_eq!(
        (g.name.as_str(), g.icon, g.searching, g.auto_type),
        (
            "Recycle Bin (old)",
            Icon::Standard(48),
            Switch::Inherit,
            Switch::Inherit
        )
    );
    assert_eq!(
        (
            v.meta.recycle_bin,
            v.meta.recycle_bin_changed,
            v.meta.recycle_bin_enabled
        ),
        (None, later, false)
    );
    // Not empty, delete: records.
    let mut w = sample();
    del(&mut w, &[id(0x10)]);
    let b2 = bin_id(&w).unwrap();
    set_bin_enabled(&mut w, false, true, later).unwrap();
    assert_eq!(records(&w), [id(0x10), b2]);
    // Empty: name and icon unchanged.
    let mut x = sample();
    del(&mut x, &[id(0x10)]);
    empty_bin(&mut x, NOW).unwrap();
    let b3 = bin_id(&x).unwrap();
    set_bin_enabled(&mut x, false, true, later).unwrap();
    assert_eq!(
        (group(&x, b3).name.as_str(), group(&x, b3).icon),
        (BIN_NAME, Icon::Standard(43))
    );
    // On again: only the flag; no group is made.
    let groups = x.root.subtree().len();
    assert!(set_bin_enabled(&mut x, true, false, later).unwrap());
    assert_eq!(
        (
            x.meta.recycle_bin_enabled,
            x.meta.recycle_bin,
            x.root.subtree().len()
        ),
        (true, None, groups)
    );
    for v in [&v, &w, &x] {
        ok(v);
    }
}

#[test]
fn mod_04_13_bin_off_with_an_id() {
    let mut v = sample();
    v.meta.recycle_bin = Some(id(4));
    v.meta.recycle_bin_enabled = false;
    move_group(&mut v, id(3), id(4), Position::End, NOW).unwrap();
    assert!(group_in_bin(&v, id(3)), "the group still counts as the bin");
    assert!(!can_empty(&v), "Empty is hidden");
    assert!(!empty_bin(&mut v, NOW).unwrap());
    assert_eq!(
        del(&mut v, &[id(0x11)]).for_good,
        1,
        "every delete is for good"
    );
    ok(&v);
}

#[test]
fn mod_04_14_left_out_elsewhere() {
    let mut v = sample();
    delete_group(&mut v, id(2), NOW).unwrap();
    group_mut(&mut v, id(2)).searching = Switch::On;
    assert!(
        entry_in_bin(&v, id(0x12)) && entry_in_bin(&v, id(0x13)),
        "whatever any group flag says"
    );
    assert!(!entry_in_bin(&v, id(0x10)));
    ok(&v);
}

#[test]
fn mod_04_15_actions_inside_the_bin() {
    let mut v = sample();
    delete_group(&mut v, id(2), NOW).unwrap();
    let b = bin_id(&v).unwrap();
    assert!(!can_create_in(&v, b) && !can_create_in(&v, id(3)) && can_create_in(&v, id(1)));
    assert_eq!(
        new_entry(&v, id(3), false).map(|_| ()),
        Err(Error::InRecycleBin)
    );
    // A browser request: an entry already in the bin stays.
    assert_eq!(
        delete_by_request(&mut v, id(0x13), NOW).unwrap(),
        app_core::recycle::Deleted::default()
    );
    assert_eq!(holder(&v, id(0x13)), id(3));
    assert_eq!(delete_by_request(&mut v, id(0x10), NOW).unwrap().to_bin, 1);
    v.meta.recycle_bin_enabled = false;
    assert_eq!(
        delete_by_request(&mut v, id(0x11), NOW).unwrap().for_good,
        1
    );
    ok(&v);
}

#[test]
fn mod_04_16_sorting_keeps_the_bin_last() {
    let mut v = sample();
    del(&mut v, &[id(0x10)]);
    v.root.groups.push(Group::new(id(0x50), "Zeta".into(), T0));
    v.root.groups.push(Group::new(id(0x51), "aaa".into(), T0));
    sort_groups(&mut v, id(1), false).unwrap();
    assert_eq!(v.root.groups.last().unwrap().uuid, bin_id(&v).unwrap());
    sort_groups(&mut v, id(1), true).unwrap();
    assert_eq!(v.root.groups.last().unwrap().uuid, bin_id(&v).unwrap());
    ok(&v);
}

#[test]
fn mod_04_17_deleted_objects() {
    let mut v = sample();
    del(&mut v, &[id(0x10)]);
    restore_entries(&mut v, &[id(0x10)], NOW).unwrap();
    empty_bin(&mut v, NOW).unwrap();
    assert!(
        v.deleted_objects.is_empty(),
        "moving, restoring and emptying an empty bin add none"
    );
    del(&mut v, &[id(0x10)]);
    del(&mut v, &[id(0x10)]);
    assert_eq!(records(&v), [id(0x10)]);
    ok(&v);
}

#[test]
fn mod_04_18_times_summary() {
    let mut v = sample();
    del(&mut v, &[id(0x12)]);
    let b = bin_id(&v).unwrap();
    // App: the groups left and entered keep their times (MOD-02.25); the
    // item moves as MOD-04.5 says; the bin's creation set RecycleBinChanged.
    assert_eq!(group(&v, id(2)).times.last_modification, T0);
    assert_eq!(group(&v, b).times.last_modification, NOW, "made now");
    assert_eq!(v.meta.recycle_bin_changed, NOW);
    let before = v.meta.recycle_bin_changed;
    delete_group(&mut v, id(4), Time(NOW.0 + 1)).unwrap();
    assert_eq!(
        v.meta.recycle_bin_changed, before,
        "only when the bin is made"
    );
    ok(&v);
}

/// E4 m1: an id given twice is deleted once.
#[test]
fn mod_04_4_an_id_given_twice_counts_once() {
    let mut v = sample();
    let d = del(&mut v, &[id(0x10), id(0x10)]);
    assert_eq!((d.to_bin, d.for_good), (1, 0));
    assert!(v.deleted_objects.is_empty());
    assert_eq!(holder(&v, id(0x10)), bin_id(&v).unwrap());
    ok(&v);
}

#[test]
fn mod_04_6_only_references_to_this_entry_count() {
    let mut v = sample();
    with_reference(&mut v, id(0x11), id(0x12), "URL");
    assert!(
        referencing(&v, id(0x10), &[]).is_empty(),
        "E2 names E3, not E1"
    );
    // The hex id and `{ref:` match in any case.
    v.root.entries.push(entry(0xAB, "X"));
    change_entry(&mut v, id(0x13), T0, |e| {
        let r = format!("{{ref:p@i:{}}}", "ab".repeat(16));
        e.set_field("Notes".into(), field(&r));
    })
    .unwrap();
    with_reference(&mut v, id(0x12), id(0xAB), "UserName");
    assert_eq!(referencing(&v, id(0xAB), &[]), [id(0x12), id(0x13)]);
    ok(&v);
}

#[test]
fn mod_04_10_a_previous_parent_in_the_bin_sends_to_the_root() {
    let mut v = sample();
    delete_group(&mut v, id(4), NOW).unwrap();
    del(&mut v, &[id(0x10)]);
    change_entry(&mut v, id(0x10), NOW, |e| e.previous_parent = Some(id(4))).unwrap();
    let r = restore_entries(&mut v, &[id(0x10)], NOW).unwrap();
    assert_eq!((r.restored, r.to_root), (1, 1));
    assert_eq!(holder(&v, id(0x10)), id(1));
    ok(&v);
}

#[test]
fn mod_04_11_a_parent_inside_the_group_sends_to_the_root() {
    let mut v = sample();
    delete_group(&mut v, id(2), NOW).unwrap();
    group_mut(&mut v, id(2)).previous_parent = Some(id(3));
    let r = restore_group(&mut v, id(2), NOW).unwrap();
    assert_eq!(r.to_root, 1);
    assert_eq!(v.root.groups.last().unwrap().uuid, id(2));
    ok(&v);
}

#[test]
fn mod_04_15_a_request_leaves_references_as_they_are() {
    let mut v = sample();
    v.meta.recycle_bin_enabled = false;
    with_reference(&mut v, id(0x11), id(0x10), "URL");
    let d = delete_by_request(&mut v, id(0x10), NOW).unwrap();
    assert_eq!((d.for_good, d.skipped), (1, 0));
    assert!(find(&v, id(0x11)).value("URL").starts_with("{REF:"));
    ok(&v);
}

#[test]
fn mod_04_15_no_adds_or_copies_into_the_bin() {
    let mut v = sample();
    delete_group(&mut v, id(4), NOW).unwrap();
    let e = new_entry(&v, id(1), false).unwrap();
    assert_eq!(add_entry(&mut v, id(4), e, NOW), Err(Error::InRecycleBin));
    let r = copy_within(&mut v, Item::Entry(id(0x10)), id(4), Position::End, NOW);
    assert_eq!(r, Err(Error::InRecycleBin));
    let g = new_group(&v).unwrap();
    assert_eq!(add_group(&mut v, id(4), g, NOW), Err(Error::InRecycleBin));
    ok(&v);
}

/// Emptying clears what named a removed item (MOD-02.28): metadata group
/// references and last top visible entries.
#[test]
fn mod_04_9_emptying_clears_references() {
    let mut v = sample();
    delete_group(&mut v, id(4), NOW).unwrap();
    del(&mut v, &[id(0x10)]);
    let b = bin_id(&v).unwrap();
    v.meta.last_selected_group = Some(id(4));
    group_mut(&mut v, b).last_top_visible_entry = Some(id(0x10));
    assert!(empty_bin(&mut v, NOW).unwrap());
    assert_eq!(v.meta.last_selected_group, None);
    assert_eq!(group(&v, b).last_top_visible_entry, None);
    ok(&v);
}
