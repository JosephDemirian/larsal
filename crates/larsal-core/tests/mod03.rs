//! E4-S2: the rules of MOD-03 (history). Each test names its rule and
//! checks the invariants afterwards.

mod common;

use common::*;
use larsal_core::edit::{change_entry, edit_entry, move_entries, move_entry};
use larsal_core::history::{
    self, Delete, MAX_ITEMS, apply_limits, delete_items, difference, prune, restore_into, rows,
};
use larsal_core::{Error, recycle};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_model::{Association, Attachment, CustomDataItem, Entry, Field, Icon, Time};
use std::sync::Arc;

fn set(e: &mut Entry, name: &str, value: &str) {
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(value.into()),
            protected: false,
        },
    );
}

/// Edits entry 0x10's notes `n` times at times NOW, NOW+1, …
fn edits(v: &mut larsal_model::Vault, n: i64) {
    for i in 0..n {
        edit_entry(v, id(0x10), Time(NOW.0 + i), |e| {
            set(e, "Notes", &format!("v{i}"))
        })
        .unwrap();
    }
}

#[test]
fn mod_03_1_contents() {
    let mut v = sample();
    change_entry(&mut v, id(0x10), T0, |e| {
        set(e, "c", "custom");
        e.attachments.push(Attachment {
            name: "f".into(),
            data: Arc::new(SecretBytes::new(vec![1, 2])),
        });
        e.custom_data.items.push(CustomDataItem {
            key: "k".into(),
            value: "v".into(),
            last_modified: None,
            unknown: Vec::new(),
        });
        e.icon = Icon::Standard(9);
        e.foreground_color = "#010203".into();
        e.override_url = "o".into();
        e.set_tags(vec!["t".into()]);
        e.exclude_from_reports = true;
        e.previous_parent = Some(id(4));
        e.times.expires = true;
    })
    .unwrap();
    let before = find(&v, id(0x10)).duplicate(false);
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Title", "changed")).unwrap();
    let e = find(&v, id(0x10));
    let item = &e.history[0];
    assert!(
        larsal_core::edit::same_stored(item, &before),
        "every stored value"
    );
    assert_eq!(
        item.times, before.times,
        "the whole times block from before the session"
    );
    assert!(item.history.is_empty(), "no history of its own");
    assert_eq!(item.uuid, e.uuid, "the owner's id");
    ok(&v);
}

#[test]
fn mod_03_2_at_most_one_item() {
    let mut v = sample();
    assert!(!edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Title", "E1")).unwrap());
    assert!(
        find(&v, id(0x10)).history.is_empty(),
        "no change: the copy is thrown away"
    );
    assert_eq!(find(&v, id(0x10)).times.last_modification, T0);
    edit_entry(&mut v, id(0x10), NOW, |e| {
        set(e, "Title", "a");
        set(e, "UserName", "b");
        set(e, "Notes", "c");
    })
    .unwrap();
    assert_eq!(
        find(&v, id(0x10)).history.len(),
        1,
        "many changes, one item"
    );
    ok(&v);
}

#[test]
fn mod_03_3_times_on_a_change() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Notes", "n")).unwrap();
    let t = &find(&v, id(0x10)).times;
    assert_eq!((t.last_modification, t.last_access), (NOW, NOW));
    assert_eq!(
        (
            t.creation,
            t.location_changed,
            t.usage_count,
            t.expiry,
            t.expires
        ),
        (T0, T0, 0, T0, false)
    );
    ok(&v);
}

#[test]
fn mod_03_4_edit_sessions_make_items() {
    let mut v = sample();
    edits(&mut v, 3);
    assert_eq!(
        find(&v, id(0x10)).history.len(),
        3,
        "each commit is its own session"
    );
    ok(&v);
}

#[test]
fn mod_03_5_actions_without_items() {
    let mut v = sample();
    move_entries(&mut v, &[id(0x10)], id(4), NOW).unwrap();
    move_entries(&mut v, &[id(0x10)], id(1), NOW).unwrap();
    change_entry(&mut v, id(0x10), NOW, |e| e.times.expires = true).unwrap();
    move_entry(&mut v, id(0x10), false).unwrap();
    recycle::delete_entries(&mut v, &[id(0x10)], NOW, |_, _| recycle::References::Delete).unwrap();
    recycle::restore_entries(&mut v, &[id(0x10)], NOW).unwrap();
    assert!(find(&v, id(0x10)).history.is_empty());
    ok(&v);
}

#[test]
fn mod_03_6_limit_values() {
    let mut v = sample();
    v.meta.history_max_items = 0;
    edits(&mut v, 2);
    assert!(find(&v, id(0x10)).history.is_empty(), "0 keeps no history");
    v.meta.history_max_items = -1;
    v.meta.history_max_size = -1;
    edits(&mut v, 15);
    assert_eq!(find(&v, id(0x10)).history.len(), 15, "-1: no limit");
    let fresh = larsal_model::Vault::new(larsal_model::Group::new(id(1), "R".into(), T0), T0);
    assert_eq!(
        (fresh.meta.history_max_items, fresh.meta.history_max_size),
        (10, 6_291_456)
    );
    ok(&v);
}

#[test]
fn mod_03_7_size() {
    let mut e = Entry::new(id(9), T0);
    assert_eq!(history::size(&e), 29, "the five standard names alone");
    set(&mut e, "Title", "abc");
    set(&mut e, "é", "xy");
    e.attachments.push(Attachment {
        name: "f.txt".into(),
        data: Arc::new(SecretBytes::new(vec![0; 10])),
    });
    e.custom_data.items.push(CustomDataItem {
        key: "k".into(),
        value: "vv".into(),
        last_modified: Some(Time(1)),
        unknown: Vec::new(),
    });
    e.auto_type.associations.push(Association {
        window: "w".into(),
        sequence: "ss".into(),
        unknown: Vec::new(),
    });
    e.set_tags(vec!["tag".into()]);
    e.icon = Icon::Standard(5);
    e.override_url = "not counted".into();
    // 29 + 3 + (2 + 2) + (5 + 10) + (1 + 2) + (1 + 2) + 3
    assert_eq!(history::size(&e), 29 + 3 + 4 + 15 + 3 + 3 + 3);
}

#[test]
fn mod_03_8_pruning() {
    let mut e = Entry::new(id(9), T0);
    for i in 0..5u8 {
        let mut h = Entry::new(id(9), Time(i64::from(i)));
        set(&mut h, "Notes", &"x".repeat(usize::from(i) * 10));
        e.history.push(h);
    }
    assert_eq!(prune(&mut e, 3, -1), 2);
    let kept: Vec<i64> = e
        .history
        .iter()
        .map(|h| h.times.last_modification.0)
        .collect();
    assert_eq!(kept, [2, 3, 4], "the newest win");
    // Sizes 49, 59, 69 newest first 69: a total equal to the limit is kept.
    assert_eq!(prune(&mut e, -1, 69 + 59), 1);
    assert_eq!(e.history.len(), 2);
    // One item larger than the limit drops itself and everything older.
    let mut big = Entry::new(id(9), Time(9));
    set(&mut big, "Notes", &"x".repeat(1000));
    e.history.insert(1, big);
    prune(&mut e, -1, 100);
    assert_eq!(e.history.len(), 1, "only the newest small item stays");
}

#[test]
fn mod_03_9_when_pruning_runs() {
    let mut v = sample();
    v.meta.history_max_items = -1;
    edits(&mut v, 5);
    recycle::delete_entries(&mut v, &[id(0x10)], NOW, |_, _| recycle::References::Delete).unwrap();
    assert!(
        !apply_limits(&mut v, -1, 6_291_456),
        "unchanged limits: nothing runs"
    );
    assert_eq!(find(&v, id(0x10)).history.len(), 5);
    assert!(apply_limits(&mut v, 2, 6_291_456));
    assert_eq!(
        find(&v, id(0x10)).history.len(),
        2,
        "every live entry, the bin included"
    );
    // Deleting history items does not prune.
    v.meta.history_max_items = 1;
    delete_items(&mut v, id(0x10), &Delete::Items(vec![0]), NOW).unwrap();
    assert_eq!(find(&v, id(0x10)).history.len(), 1);
    ok(&v);
}

#[test]
fn mod_03_10_ceiling() {
    let mut e = Entry::new(id(9), T0);
    e.history = (0..MAX_ITEMS + 5)
        .map(|i| Entry::new(id(9), Time(i as i64)))
        .collect();
    prune(&mut e, -1, -1);
    assert_eq!(
        e.history.len(),
        MAX_ITEMS,
        "never more than 100,000, even with no limit"
    );
}

#[test]
fn mod_03_11_history_page_rows() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Title", "t2")).unwrap();
    edit_entry(&mut v, id(0x10), Time(NOW.0 + 1), |e| {
        set(e, "c", "x");
        e.icon = Icon::Standard(3);
        e.set_tags(vec!["t".into()]);
    })
    .unwrap();
    let e = find(&v, id(0x10));
    let r = rows(e);
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].index, None, "the current entry, newest");
    assert_eq!(r[0].difference, ["Custom attributes", "Icon", "Tags"]);
    assert_eq!(r[1].difference, ["Title"]);
    assert!(r[2].difference.is_empty(), "the oldest row");
    assert_eq!(r[0].size, history::size(e));
    let mut a = Entry::new(id(9), T0);
    let b = Entry::new(id(9), T0);
    set(&mut a, "Title", "x");
    set(&mut a, "c", "y");
    assert_eq!(
        difference(&a, &b),
        ["Title"],
        "custom attributes only without a standard difference"
    );
    set(&mut a, "otp", "otpauth://x");
    a.times.expires = true;
    a.background_color = "#000000".into();
    assert_eq!(
        difference(&a, &b),
        ["Title", "Color", "Expiration", "one-time password"]
    );
    ok(&v);
}

#[test]
fn mod_03_12_restore() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| {
        set(e, "Title", "new");
        e.icon = Icon::Standard(7);
    })
    .unwrap();
    let item = find(&v, id(0x10)).history[0].duplicate(false);
    let later = Time(NOW.0 + 5);
    edit_entry(&mut v, id(0x10), later, |draft| restore_into(draft, &item)).unwrap();
    let e = find(&v, id(0x10));
    assert_eq!((e.value("Title"), e.icon), ("E1", Icon::Standard(0)));
    assert_eq!(
        e.times.last_modification, later,
        "the commit is a normal session"
    );
    assert_eq!(
        e.history.len(),
        2,
        "the current state became an item; the restored one stays"
    );
    assert_eq!(e.times.creation, T0, "times are not copied");
    ok(&v);
}

#[test]
fn mod_03_13_delete_and_delete_all() {
    let mut v = sample();
    edits(&mut v, 3);
    let later = Time(NOW.0 + 50);
    assert_eq!(
        delete_items(&mut v, id(0x10), &Delete::Items(vec![9]), later),
        Err(Error::NoSuchHistoryItem)
    );
    assert!(delete_items(&mut v, id(0x10), &Delete::Items(vec![0]), later).unwrap());
    let e = find(&v, id(0x10));
    assert_eq!(
        (
            e.history.len(),
            e.times.last_modification,
            e.times.last_access
        ),
        (2, later, later)
    );
    assert!(v.deleted_objects.is_empty(), "no deleted-object record");
    assert!(delete_items(&mut v, id(0x10), &Delete::All, later).unwrap());
    assert!(find(&v, id(0x10)).history.is_empty());
    assert!(
        !delete_items(&mut v, id(0x10), &Delete::All, Time(later.0 + 1)).unwrap(),
        "nothing left: no time moves"
    );
    assert_eq!(find(&v, id(0x10)).times.last_modification, later);
    ok(&v);
}

#[test]
fn mod_03_14_attachments_in_history() {
    let mut v = sample();
    let data = Arc::new(SecretBytes::new(vec![7; 100]));
    change_entry(&mut v, id(0x10), T0, |e| {
        e.attachments.push(Attachment {
            name: "f".into(),
            data: Arc::clone(&data),
        })
    })
    .unwrap();
    edit_entry(&mut v, id(0x10), NOW, |e| e.attachments.clear()).unwrap();
    let e = find(&v, id(0x10));
    assert!(e.attachments.is_empty());
    assert!(
        Arc::ptr_eq(&e.history[0].attachments[0].data, &data),
        "the item keeps one shared copy"
    );
    assert_eq!(
        history::size(&e.history[0]),
        29 + 2 + 1 + 100,
        "title E1, name f, content in full"
    );
    ok(&v);
}

#[test]
fn mod_03_15_history_items_are_not_live() {
    let mut v = sample();
    edits(&mut v, 2);
    let e = find(&v, id(0x10));
    assert!(
        e.history
            .iter()
            .all(|h| h.uuid == e.uuid && h.history.is_empty())
    );
    assert_eq!(v.root.entries.len(), 2, "never listed in a group");
    assert_eq!(larsal_core::edit::user_name_suggestions(&v).len(), 0);
    ok(&v);
}

#[test]
fn mod_03_7_colors_and_override_url_do_not_count() {
    let mut e = entry(0x10, "E1");
    let before = history::size(&e);
    e.foreground_color = "#FF0000".into();
    e.background_color = "#00FF00".into();
    e.override_url = "cmd://demo".into();
    assert_eq!(history::size(&e), before);
}

#[test]
fn mod_03_12_restore_keeps_times_and_previous_parent() {
    let mut draft = entry(0x10, "now");
    (draft.times.creation, draft.times.last_modification) = (Time(400), Time(500));
    draft.previous_parent = Some(id(2));
    let mut item = entry(0x10, "then");
    (item.times.creation, item.times.last_modification) = (Time(50), Time(100));
    (item.times.expires, item.times.expiry) = (true, Time(900));
    item.previous_parent = Some(id(4));
    restore_into(&mut draft, &item);
    assert_eq!(draft.value("Title"), "then");
    let t = &draft.times;
    assert_eq!((t.creation, t.last_modification), (Time(400), Time(500)));
    assert_eq!((t.expires, t.expiry), (true, Time(900)), "expiry is data");
    assert_eq!(draft.previous_parent, Some(id(2)));
}

/// A changed one-time password value (same field name) is labelled; custom
/// field values are compared too, not only names.
#[test]
fn mod_03_11_changed_values_are_labelled() {
    let mut a = entry(0x10, "E1");
    let mut b = entry(0x10, "E1");
    set(&mut a, "otp", "otpauth://demo-1");
    set(&mut b, "otp", "otpauth://demo-2");
    assert_eq!(difference(&a, &b), ["one-time password"]);
    set(&mut b, "otp", "otpauth://demo-1");
    set(&mut a, "Demo", "x");
    set(&mut b, "Demo", "y");
    assert_eq!(difference(&a, &b), ["Custom attributes"]);
}
