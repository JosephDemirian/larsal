//! E4-S1: the rules of MOD-02 (groups, inheritance, moving, sorting, group
//! times). Each test names its rule and checks the invariants afterwards.

mod common;

use common::*;
use larsal_core::edit::change_entry;
use larsal_core::edit::{
    DEFAULT_SEQUENCE, Item, Position, add_entry, add_group, auto_type_on, browser_option,
    browser_restriction, copy_into, copy_within, edit_entry, edit_group, entry_sequence,
    group_sequence, is_shared, move_entries, move_entry, move_group, move_into, new_entry,
    new_group, screen_line, searching_on, sort_groups,
};
use larsal_core::{Error, recycle};
use larsal_model::{CustomDataItem, CustomIcon, Group, Icon, Switch, Time, Uuid, Vault};

fn cd(key: &str, value: &str) -> CustomDataItem {
    CustomDataItem {
        key: key.into(),
        value: value.into(),
        last_modified: None,
        unknown: Vec::new(),
    }
}

#[test]
fn mod_02_1_shape() {
    let mut v = sample();
    ok(&v);
    move_group(&mut v, id(3), id(1), Position::End, NOW).unwrap();
    move_entries(&mut v, &[id(0x10)], id(3), NOW).unwrap();
    sort_groups(&mut v, id(1), false).unwrap();
    ok(&v);
    assert_eq!(
        names(&v.root),
        ["G1", "G2", "G4"],
        "child group order is the stored order"
    );
}

#[test]
fn mod_02_2_root_group() {
    let mut v = sample();
    assert_eq!(
        move_group(&mut v, id(1), id(2), Position::End, NOW),
        Err(Error::RootGroup)
    );
    assert_eq!(
        recycle::delete_group(&mut v, id(1), NOW),
        Err(Error::RootGroup)
    );
    let mut other = sample();
    assert_eq!(
        move_into(
            &mut v,
            Item::Group(id(1)),
            &mut other,
            id(1),
            Position::End,
            NOW
        ),
        Err(Error::RootGroup)
    );
    assert!(
        edit_group(&mut v, id(1), NOW, |g| g.name = "Passwords".into()).unwrap(),
        "every other property is editable"
    );
    assert_eq!(v.root.previous_parent, None);
    ok(&v);
}

#[test]
fn mod_02_3_name_and_notes() {
    assert_eq!(screen_line("a\nb"), "a b");
    let mut v = sample();
    edit_group(&mut v, id(4), NOW, |g| {
        g.name = "a/b  ".into();
        g.notes = "l1\nl2".into();
    })
    .unwrap();
    edit_group(&mut v, id(2), NOW, |g| g.name = "a/b  ".into()).unwrap();
    assert_eq!(
        (
            group(&v, id(4)).name.as_str(),
            group(&v, id(4)).notes.as_str()
        ),
        ("a/b  ", "l1\nl2"),
        "kept exactly; duplicates allowed"
    );
    ok(&v);
}

#[test]
fn mod_02_4_icon() {
    let g = new_group(&sample()).unwrap();
    assert_eq!(g.icon, Icon::Standard(48));
}

#[test]
fn mod_02_5_expanded() {
    let mut v = sample();
    assert!(edit_group(&mut v, id(2), NOW, |g| g.expanded = false).unwrap());
    let g = group(&v, id(2));
    assert!(!g.expanded);
    assert_eq!(
        g.times.last_modification, T0,
        "view state moves no time (MOD-02.25)"
    );
    ok(&v);
}

#[test]
fn mod_02_6_default_sequence() {
    let mut v = sample();
    edit_group(&mut v, id(2), NOW, |g| g.default_sequence = String::new()).unwrap();
    assert_eq!(
        group_sequence(&v, id(2)),
        DEFAULT_SEQUENCE,
        "empty means inherit"
    );
    edit_group(&mut v, id(2), NOW, |g| {
        g.default_sequence = "{PASSWORD}".into()
    })
    .unwrap();
    assert_eq!(group_sequence(&v, id(3)), "{PASSWORD}");
    ok(&v);
}

#[test]
fn mod_02_7_switches() {
    let g = new_group(&sample()).unwrap();
    assert_eq!(
        (g.auto_type, g.searching),
        (Switch::Inherit, Switch::Inherit)
    );
    let mut v = sample();
    recycle::delete_entries(&mut v, &[id(0x10)], NOW, |_, _| recycle::References::Delete).unwrap();
    let bin = group(&v, recycle::bin_id(&v).unwrap());
    assert_eq!((bin.auto_type, bin.searching), (Switch::Off, Switch::Off));
    ok(&v);
}

#[test]
fn mod_02_8_group_tags_from_files_only() {
    let mut v = sample();
    v.root.groups[0].tags = "gt".into(); // as read
    edit_group(&mut v, id(2), NOW, |g| {
        g.tags = "changed".into();
        g.name = "n".into();
    })
    .unwrap();
    assert_eq!(group(&v, id(2)).tags, "gt", "no action changes them");
    ok(&v);
}

#[test]
fn mod_02_9_custom_data_delete() {
    let mut v = sample();
    v.root.groups[0].custom_data.items.push(cd("k", "v"));
    assert!(edit_group(&mut v, id(2), NOW, |g| g.custom_data.items.clear()).unwrap());
    assert_eq!(group(&v, id(2)).times.last_modification, NOW);
    ok(&v);
}

#[test]
fn mod_02_10_previous_parent_only_by_moves() {
    let mut v = sample();
    edit_group(&mut v, id(3), NOW, |g| g.name = "x".into()).unwrap();
    assert_eq!(group(&v, id(3)).previous_parent, None);
    move_group(&mut v, id(3), id(4), Position::End, NOW).unwrap();
    assert_eq!(group(&v, id(3)).previous_parent, Some(id(2)));
    ok(&v);
}

#[test]
fn mod_02_11_last_top_visible_entry_carried() {
    let mut v = sample();
    v.root.last_top_visible_entry = Some(id(0x11));
    edit_group(&mut v, id(1), NOW, |g| g.name = "x".into()).unwrap();
    assert_eq!(v.root.last_top_visible_entry, Some(id(0x11)));
    v.meta.recycle_bin_enabled = false;
    recycle::delete_entries(&mut v, &[id(0x11)], NOW, |_, _| recycle::References::Delete).unwrap();
    assert_eq!(
        v.root.last_top_visible_entry, None,
        "a removed entry no longer resolves"
    );
    ok(&v);
}

#[test]
fn mod_02_12_group_expiry() {
    let mut v = sample();
    assert!(
        edit_group(&mut v, id(2), NOW, |g| {
            g.times.expires = true;
            g.times.expiry = Time(5);
        })
        .unwrap()
    );
    let g = group(&v, id(2));
    assert!(g.times.expires && g.times.expiry == Time(5) && g.times.last_modification == NOW);
    assert!(
        !find(&v, id(0x12)).times.expires,
        "its entries are not made expired"
    );
    ok(&v);
}

#[test]
fn mod_02_13_search_switch() {
    let mut v = sample();
    assert_eq!(
        searching_on(&v, id(1)),
        Some(true),
        "Inherit on the root is On"
    );
    v.root.groups[0].searching = Switch::Off;
    assert_eq!(searching_on(&v, id(3)), Some(false), "Inherit below Off");
    v.root.groups[0].groups[0].searching = Switch::On;
    assert_eq!(searching_on(&v, id(3)), Some(true), "On below Off");
    assert_eq!(searching_on(&v, id(0x55)), None);
    ok(&v);
}

#[test]
fn mod_02_14_auto_type_switch() {
    let mut v = sample();
    assert_eq!(auto_type_on(&v, id(3)), Some(true));
    v.root.groups[0].auto_type = Switch::Off;
    assert_eq!(auto_type_on(&v, id(3)), Some(false));
    ok(&v);
}

#[test]
fn mod_02_15_group_sequence() {
    let mut v = sample();
    assert_eq!(
        group_sequence(&v, id(3)),
        DEFAULT_SEQUENCE,
        "past the root: the built-in default"
    );
    v.root.default_sequence = "{TITLE}".into();
    assert_eq!(group_sequence(&v, id(3)), "{TITLE}");
    v.root.groups[0].groups[0].auto_type = Switch::Off;
    assert_eq!(
        group_sequence(&v, id(3)),
        "",
        "an Off on a visited group gives none"
    );
    v.root.groups[0].groups[0].auto_type = Switch::Inherit;
    v.root.groups[0].groups[0].default_sequence = "{URL}".into();
    v.root.groups[0].auto_type = Switch::Off;
    assert_eq!(
        group_sequence(&v, id(3)),
        "{URL}",
        "an Off above the group with a sequence does not empty it"
    );
    ok(&v);
}

#[test]
fn mod_02_16_entry_sequence() {
    let mut v = sample();
    let set = |v: &mut Vault, user: &str, pass: &str| {
        edit_entry(v, id(0x10), NOW, |e| {
            e.set_field("UserName".into(), field(user));
            e.set_field("Password".into(), field(pass));
        })
        .unwrap();
    };
    set(&mut v, "", "p");
    assert_eq!(entry_sequence(&v, id(0x10)), "{PASSWORD}{ENTER}");
    set(&mut v, "u", "");
    assert_eq!(entry_sequence(&v, id(0x10)), "{USERNAME}{ENTER}");
    set(&mut v, "u", "p");
    assert_eq!(entry_sequence(&v, id(0x10)), DEFAULT_SEQUENCE);
    set(&mut v, "", "");
    assert_eq!(
        entry_sequence(&v, id(0x10)),
        DEFAULT_SEQUENCE,
        "no user name and no password: the group's"
    );
    edit_entry(&mut v, id(0x10), NOW, |e| {
        e.auto_type.default_sequence = "{X}".into()
    })
    .unwrap();
    assert_eq!(entry_sequence(&v, id(0x10)), "{X}");
    edit_entry(&mut v, id(0x10), NOW, |e| e.auto_type.enabled = false).unwrap();
    assert_eq!(entry_sequence(&v, id(0x10)), "");
    v.root.default_sequence = "{G}".into();
    assert_eq!(entry_sequence(&v, id(0x11)), "{G}");
    ok(&v);
}

#[test]
fn mod_02_17_browser_options() {
    let mut v = sample();
    assert!(
        !browser_option(&v, id(3), "BrowserHideEntry"),
        "no key anywhere: off"
    );
    v.root
        .custom_data
        .items
        .push(cd("BrowserHideEntry", "true"));
    assert!(browser_option(&v, id(3), "BrowserHideEntry"));
    v.root.groups[0]
        .custom_data
        .items
        .push(cd("BrowserHideEntry", "True"));
    assert!(
        !browser_option(&v, id(3), "BrowserHideEntry"),
        "only exactly `true` is on"
    );
    assert_eq!(browser_restriction(&v, id(3), "BrowserRestrictKey"), None);
    v.root
        .custom_data
        .items
        .push(cd("BrowserRestrictKey", "k1"));
    assert_eq!(
        browser_restriction(&v, id(3), "BrowserRestrictKey").as_deref(),
        Some("k1")
    );
    v.root.groups[0]
        .custom_data
        .items
        .push(cd("BrowserRestrictKey", ""));
    assert_eq!(
        browser_restriction(&v, id(3), "BrowserRestrictKey"),
        None,
        "an empty value up the tree means no restriction"
    );
    ok(&v);
}

#[test]
fn mod_02_18_recycled_and_shared() {
    let mut v = sample();
    recycle::delete_group(&mut v, id(2), NOW).unwrap();
    assert!(
        recycle::group_in_bin(&v, id(3)),
        "a group below the bin is recycled"
    );
    assert!(recycle::entry_in_bin(&v, id(0x13)));
    let key = String::from_utf8(larsal_core::edit::SHARED_KEY.to_vec()).unwrap();
    let g4 = v.root.groups.iter_mut().find(|g| g.uuid == id(4)).unwrap();
    g4.custom_data.items.push(cd(&key, "x"));
    assert!(is_shared(&v, id(4)) && !is_shared(&v, id(1)));
    ok(&v);
}

#[test]
fn mod_02_19_move_operations_are_one_batch() {
    let mut v = sample();
    move_entries(&mut v, &[id(0x10), id(0x11)], id(4), NOW).unwrap();
    assert_eq!(titles(group(&v, id(4))), ["E1", "E2"], "in the order given");
    assert!(
        group(&v, id(4))
            .entries
            .iter()
            .all(|e| e.times.location_changed == NOW),
        "one time"
    );
    ok(&v);
}

#[test]
fn mod_02_20_moving_a_group() {
    let mut v = sample();
    assert_eq!(
        move_group(&mut v, id(2), id(3), Position::End, NOW),
        Err(Error::Cycle)
    );
    assert_eq!(
        move_group(&mut v, id(2), id(2), Position::End, NOW),
        Err(Error::Cycle)
    );
    // Same parent, same index: no change.
    assert!(!move_group(&mut v, id(2), id(1), Position::At(0), NOW).unwrap());
    // Pure reorder: times move, no previous parent.
    assert!(move_group(&mut v, id(2), id(1), Position::End, NOW).unwrap());
    assert_eq!(names(&v.root), ["G4", "G1"]);
    let g = group(&v, id(2));
    assert_eq!(
        (
            g.times.location_changed,
            g.times.last_modification,
            g.times.last_access,
            g.previous_parent
        ),
        (NOW, NOW, NOW, None)
    );
    // To another parent at an index.
    let later = Time(NOW.0 + 5);
    assert!(move_group(&mut v, id(3), id(1), Position::At(1), later).unwrap());
    assert_eq!(names(&v.root), ["G4", "G2", "G1"]);
    assert_eq!(group(&v, id(3)).previous_parent, Some(id(2)));
    assert_eq!(v.root.times.last_modification, T0, "parents' times stay");
    assert_eq!(
        find(&v, id(0x13)).times.last_modification,
        T0,
        "contents' times stay"
    );
    ok(&v);
}

#[test]
fn mod_02_21_moving_entries() {
    let mut v = sample();
    assert_eq!(
        move_entries(&mut v, &[id(0x10), id(0x99)], id(4), NOW),
        Err(Error::NoSuchEntry)
    );
    assert_eq!(group(&v, id(4)).entries.len(), 0, "refused: nothing moved");
    assert_eq!(move_entries(&mut v, &[id(0x10)], id(1), NOW).unwrap(), 0);
    move_entries(&mut v, &[id(0x12)], id(1), NOW).unwrap();
    assert_eq!(titles(&v.root), ["E1", "E2", "E3"], "appended at the end");
    let e = find(&v, id(0x12));
    assert_eq!(
        (
            e.previous_parent,
            e.times.location_changed,
            e.times.last_modification
        ),
        (Some(id(2)), NOW, NOW)
    );
    assert!(e.history.is_empty(), "no history item");
    assert_eq!(
        group(&v, id(2)).times.last_modification,
        T0,
        "group times stay (MOD-02.25)"
    );
    ok(&v);
}

#[test]
fn mod_02_22_copies_into_another_vault() {
    let mut source = sample();
    source.meta.custom_icons.push(CustomIcon {
        uuid: id(0xA1),
        name: "n".into(),
        last_modified: Some(Time(3)),
        data: vec![1],
        unknown: Vec::new(),
    });
    source.root.groups[0].icon = Icon::Custom(id(0xA1));
    edit_entry(&mut source, id(0x12), NOW, |e| {
        e.set_field("Notes".into(), field("n"));
    })
    .unwrap();
    source.root.groups[0].entries[0].times.usage_count = 4;
    source.root.groups[0].previous_parent = Some(id(4));
    let mut target = sample();
    let later = Time(NOW.0 + 9);
    let new = copy_into(
        &source,
        Item::Group(id(2)),
        &mut target,
        id(4),
        Position::End,
        later,
    )
    .unwrap();
    let copy = group(&target, new);
    assert_ne!(new, id(2));
    assert_eq!((copy.times.creation, copy.previous_parent), (later, None));
    let e = &copy.entries[0];
    assert_ne!(e.uuid, id(0x12));
    assert_eq!(
        (e.times.creation, e.times.usage_count, e.previous_parent),
        (later, 4, None)
    );
    assert_eq!(e.history.len(), 1);
    assert_eq!(
        (e.history[0].uuid, e.history[0].times.last_modification),
        (e.uuid, T0),
        "history keeps its times, takes the new id"
    );
    assert_eq!(copy.groups[0].entries[0].value("Title"), "E4");
    assert!(
        target
            .meta
            .custom_icons
            .iter()
            .any(|i| i.uuid == id(0xA1) && i.name == "n" && i.last_modified == Some(Time(3)))
    );
    ok(&target);
    // An entry: new id, end of the group.
    let one = copy_into(
        &source,
        Item::Entry(id(0x10)),
        &mut target,
        id(1),
        Position::End,
        later,
    )
    .unwrap();
    assert_eq!(target.root.entries.last().unwrap().uuid, one);
    // Move: the source item is deleted for good with records.
    move_into(
        &mut source,
        Item::Group(id(2)),
        &mut target,
        id(1),
        Position::At(0),
        later,
    )
    .unwrap();
    assert!(source.root.groups.iter().all(|g| g.uuid != id(2)));
    let recs: Vec<_> = source.deleted_objects.iter().map(|d| d.uuid).collect();
    assert_eq!(recs, [id(0x12), id(0x13), id(3), id(2)]);
    ok(&source);
    ok(&target);
    // Copy inside one vault.
    let mut v = sample();
    let c = copy_within(&mut v, Item::Entry(id(0x10)), id(1), Position::End, later).unwrap();
    assert_eq!(find(&v, c).value("Title"), "E1", "no name suffix");
    ok(&v);
}

#[test]
fn mod_02_23_delete_goes_to_the_bin() {
    let mut v = sample();
    let d = recycle::delete_group(&mut v, id(4), NOW).unwrap();
    assert_eq!(d.to_bin, 1);
    ok(&v);
}

#[test]
fn mod_02_24_reordering_entries() {
    let mut v = sample();
    assert!(
        !move_entry(&mut v, id(0x10), true).unwrap(),
        "the first cannot move up"
    );
    assert!(
        !move_entry(&mut v, id(0x11), false).unwrap(),
        "the last cannot move down"
    );
    assert!(move_entry(&mut v, id(0x10), false).unwrap());
    assert_eq!(titles(&v.root), ["E2", "E1"]);
    assert_eq!(
        v.root.times.last_modification, T0,
        "no time moves (MOD-02.25)"
    );
    ok(&v);
}

#[test]
fn mod_02_25_what_moves_a_group_time() {
    let mut v = sample();
    let e = new_entry(&v, id(2), false).unwrap();
    add_entry(&mut v, id(2), e, NOW).unwrap();
    move_entries(&mut v, &[id(0x10)], id(2), NOW).unwrap();
    move_entry(&mut v, id(0x10), true).unwrap();
    edit_group(&mut v, id(2), NOW, |g| g.expanded = false).unwrap();
    sort_groups(&mut v, id(1), true).unwrap();
    let g = new_group(&v).unwrap();
    add_group(&mut v, id(2), g, NOW).unwrap();
    edit_entry(&mut v, id(0x12), NOW, |e| {
        e.set_field("Notes".into(), field("n"));
    })
    .unwrap();
    assert_eq!(
        group(&v, id(2)).times.last_modification,
        T0,
        "none of these move it in Larsal"
    );
    assert_eq!(v.root.times.last_modification, T0);
    edit_group(&mut v, id(2), NOW, |g| g.notes = "own".into()).unwrap();
    let t = &group(&v, id(2)).times;
    assert_eq!(
        (t.last_modification, t.last_access),
        (NOW, NOW),
        "own data moves it, and access with it"
    );
    ok(&v);
}

#[test]
fn mod_02_26_sorting() {
    let mut v = sample();
    let mk = |n: u8, name: &str| Group::new(id(n), name.into(), T0);
    for (n, name) in [
        (0x31, "item9"),
        (0x32, "alpha"),
        (0x33, "item10"),
        (0x34, "Alpha"),
        (0x35, "07x"),
        (0x36, "007"),
    ] {
        v.root.groups.push(mk(n, name));
    }
    recycle::delete_entries(&mut v, &[id(0x10)], NOW, |_, _| recycle::References::Delete).unwrap();
    sort_groups(&mut v, id(1), false).unwrap();
    assert_eq!(
        names(&v.root),
        [
            "007",
            "07x",
            "alpha",
            "Alpha",
            "G1",
            "G4",
            "item10",
            "item9",
            "Recycle Bin"
        ]
    );
    sort_groups(&mut v, id(1), true).unwrap();
    assert_eq!(
        names(&v.root),
        [
            "item9",
            "item10",
            "G4",
            "G1",
            "alpha",
            "Alpha",
            "07x",
            "007",
            "Recycle Bin"
        ],
        "ties keep their order; the bin stays last"
    );
    let bin = recycle::bin_id(&v);
    let others = v.root.groups.iter().filter(|g| Some(g.uuid) != bin);
    assert!(
        others
            .clone()
            .all(|g| g.times.location_changed == T0 && g.times.last_modification == T0),
        "no time moves"
    );
    ok(&v);
}

#[test]
fn mod_02_27_new_group() {
    let mut v = sample();
    let g = new_group(&v).unwrap();
    assert!(v.root.subtree().iter().all(|x| x.uuid != g.uuid));
    let uuid = add_group(&mut v, id(1), g, NOW).unwrap();
    assert_eq!(
        v.root.groups.last().unwrap().uuid,
        uuid,
        "end of the selected group's children"
    );
    let t = &group(&v, uuid).times;
    assert_eq!(
        (
            t.creation,
            t.last_modification,
            t.last_access,
            t.location_changed,
            t.expiry
        ),
        (NOW, NOW, NOW, NOW, NOW)
    );
    ok(&v);
}

#[test]
fn mod_02_28_templates_pointer() {
    let mut v = sample();
    v.meta.entry_templates_group = Some(id(4));
    v.meta.last_selected_group = Some(id(4));
    v.meta.recycle_bin_enabled = false;
    recycle::delete_group(&mut v, id(4), NOW).unwrap();
    assert_eq!(
        (v.meta.entry_templates_group, v.meta.last_selected_group),
        (None, None)
    );
    ok(&v);
}

#[test]
fn mod_02_29_own_data_changes() {
    type Change = fn(&mut Group);
    let changes: [(&str, Change); 9] = [
        ("name", |g| g.name = "n".into()),
        ("notes", |g| g.notes = "n".into()),
        ("icon", |g| g.icon = Icon::Standard(3)),
        ("expires", |g| g.times.expires = true),
        ("expiry", |g| g.times.expiry = Time(9)),
        ("sequence", |g| g.default_sequence = "{X}".into()),
        ("switch", |g| g.searching = Switch::Off),
        ("custom data", |g| g.custom_data.items.push(cd("k", "v"))),
        ("previous parent", |g| g.previous_parent = Some(id(4))),
    ];
    for (name, change) in changes {
        let mut v = sample();
        assert!(edit_group(&mut v, id(2), NOW, change).unwrap(), "{name}");
        let t = &group(&v, id(2)).times;
        assert_eq!((t.last_modification, t.last_access), (NOW, NOW), "{name}");
        ok(&v);
    }
    let mut v = sample();
    assert!(
        !edit_group(&mut v, id(2), NOW, |g| g.name = "G1".into()).unwrap(),
        "the same value is no change"
    );
    edit_group(&mut v, id(2), NOW, |g| g.times.usage_count = 9).unwrap();
    assert_eq!(
        group(&v, id(2)).times.usage_count,
        0,
        "usage count never changes"
    );
    ok(&v);
}

/// E4-B3: an edit never changes the group's id, so ids stay unique.
#[test]
fn mod_02_29_the_id_never_changes() {
    for new in [id(2), Uuid::ZERO] {
        let mut v = sample();
        assert_eq!(edit_group(&mut v, id(4), NOW, |g| g.uuid = new), Ok(false));
        assert_eq!(v.root.groups[1].uuid, id(4));
        assert_eq!(v.root.groups[1].times.last_modification, T0);
        ok(&v);
    }
    let mut v = sample();
    let r = edit_group(&mut v, id(4), NOW, |g| {
        g.uuid = id(2);
        g.name = "N".into();
    });
    assert_eq!(r, Ok(true));
    let g = &v.root.groups[1];
    assert_eq!((g.uuid, g.name.as_str()), (id(4), "N"));
    ok(&v);
}

#[test]
fn mod_02_27_a_new_group_starts_empty_without_previous_parent() {
    let mut v = sample();
    let mut g = new_group(&v).unwrap();
    g.previous_parent = Some(id(2));
    g.groups
        .push(Group::new(id(2), "would repeat an id".into(), T0));
    let new = add_group(&mut v, id(1), g, NOW).unwrap();
    let g = group(&v, new);
    assert_eq!((g.previous_parent, g.groups.len()), (None, 0));
    ok(&v);
}

#[test]
fn mod_02_20_the_last_group_to_the_end_is_no_move() {
    let mut v = sample();
    assert_eq!(
        move_group(&mut v, id(4), id(1), Position::End, NOW),
        Ok(false)
    );
    assert_eq!(group(&v, id(4)).times.last_modification, T0);
    ok(&v);
}

#[test]
fn mod_02_26_sorting_reaches_every_level() {
    let mut v = sample();
    let g2 = &mut v.root.groups[0].groups[0];
    g2.groups.push(Group::new(id(0x50), "b".into(), T0));
    g2.groups.push(Group::new(id(0x51), "a".into(), T0));
    sort_groups(&mut v, id(1), false).unwrap();
    assert_eq!(names(group(&v, id(3))), ["a", "b"]);
    ok(&v);
}

/// LD-107: copies inside one vault keep previous parents; copies into
/// another vault clear them, history items included (LD-68).
#[test]
fn mod_02_22_previous_parents_on_copies() {
    let mut v = sample();
    change_entry(&mut v, id(0x12), T0, |e| e.previous_parent = Some(id(4))).unwrap();
    edit_entry(&mut v, id(0x12), T0, |e| {
        e.set_field("Notes".into(), field("n"));
    })
    .unwrap();
    v.root.groups[0].previous_parent = Some(id(4));
    v.root.groups[0].last_top_visible_entry = Some(id(0x12));
    let c = copy_within(&mut v, Item::Entry(id(0x12)), id(1), Position::End, NOW).unwrap();
    let e = find(&v, c);
    assert_eq!(
        (e.previous_parent, e.history[0].previous_parent),
        (Some(id(4)), Some(id(4)))
    );
    let g = copy_within(&mut v, Item::Group(id(2)), id(4), Position::End, NOW).unwrap();
    let g = group(&v, g);
    assert_eq!(
        (g.previous_parent, g.entries[0].previous_parent),
        (Some(id(4)), Some(id(4)))
    );
    assert_eq!(g.last_top_visible_entry, None, "its entries have new ids");
    ok(&v);
    let mut t = sample();
    let c = copy_into(&v, Item::Entry(id(0x12)), &mut t, id(1), Position::End, NOW).unwrap();
    let e = find(&t, c);
    assert_eq!(
        (e.previous_parent, e.history[0].previous_parent),
        (None, None)
    );
    let g = copy_into(&v, Item::Group(id(2)), &mut t, id(1), Position::End, NOW).unwrap();
    assert_eq!(group(&t, g).previous_parent, None);
    ok(&t);
}

/// Moving an entry into another vault clears what named it in the source
/// (MOD-02.28): the group's last top visible entry.
#[test]
fn mod_02_22_moving_out_clears_references() {
    let mut source = sample();
    source.root.groups[0].last_top_visible_entry = Some(id(0x12));
    let mut target = sample();
    move_into(
        &mut source,
        Item::Entry(id(0x12)),
        &mut target,
        id(1),
        Position::End,
        NOW,
    )
    .unwrap();
    assert_eq!(source.root.groups[0].last_top_visible_entry, None);
    assert_eq!(source.deleted_objects.len(), 1);
    ok(&source);
    ok(&target);
}
