//! E4-S7: the rules of MOD-10 (clone), on the card's entry "Mail". Each
//! test names its rule and checks the invariants afterwards.

mod common;

use app_core::clone::{
    Options, SUFFIX, add_group_clone, can_clone_entry, can_clone_group, clone_entry, clone_group,
};
use app_core::edit::{Item, Position, copy_into, copy_within, edit_entry, move_into};
use app_core::refs::{Context, resolve};
use app_crypto::secret::{SecretBytes, SecretString};
use app_model::{Attachment, CustomDataItem, CustomIcon, Field, Group, Icon, Time, Vault};
use common::*;
use std::sync::Arc;

fn protected(v: &str) -> Field {
    Field {
        value: SecretString::new(v.into()),
        protected: true,
    }
}

/// Group Work holds Mail (0x5a) and then Other (0x5b), under the root; a
/// group Home (0x62) beside it.
fn vault() -> Vault {
    let mut mail = entry(0x5a, "Mail");
    mail.set_field("UserName".into(), field("max"));
    mail.set_field("Password".into(), protected("pw-mail"));
    mail.set_field("URL".into(), field("https://mail.example"));
    mail.set_field("Pin".into(), protected("1234"));
    mail.attachments.push(Attachment {
        name: "a.txt".into(),
        data: Arc::new(SecretBytes::new(b"abc".to_vec())),
    });
    mail.set_tags(vec!["work".into()]);
    (mail.times.expires, mail.times.expiry) = (true, at(2027, 1, 1, 0, 0, 0));
    mail.times.usage_count = 4;
    mail.times.creation = at(2025, 1, 1, 0, 0, 0);
    mail.times.last_modification = at(2025, 6, 1, 0, 0, 0);
    mail.icon = Icon::Standard(19);
    mail.foreground_color = "#FF0000".into();
    mail.previous_parent = Some(id(0x62));
    mail.custom_data.items.push(CustomDataItem {
        key: "BrowserSitePermissions".into(),
        value: "demo".into(),
        last_modified: None,
        unknown: Vec::new(),
    });
    for (t, m) in [("Mail0", 2), ("Mail1", 3)] {
        let mut h = mail.duplicate(false);
        h.set_field("Title".into(), field(t));
        h.times.last_modification = at(2025, m, 1, 0, 0, 0);
        mail.history.push(h);
    }
    let mut work = Group::new(id(0x61), "Work".into(), T0);
    work.entries = vec![mail, entry(0x5b, "Other")];
    let home = Group::new(id(0x62), "Home".into(), T0);
    let mut root = Group::new(id(1), "Root".into(), T0);
    root.groups = vec![work, home];
    Vault::new(root, T0)
}

fn now() -> Time {
    at(2026, 10, 25, 9, 0, 0)
}

#[test]
fn mod_10_1_dialog_and_actions() {
    let o = Options::default();
    assert_eq!((o.suffix, o.refs, o.history), (true, false, true));
    let mut v = vault();
    assert!(can_clone_entry(&v, &[id(0x5a)], Some(id(0x61))));
    assert!(!can_clone_entry(&v, &[], None));
    assert!(!can_clone_entry(&v, &[id(0x5a), id(0x5b)], None));
    v.meta.recycle_bin = Some(id(0x62));
    v.root.groups[1].entries.push(entry(0x5c, "Binned"));
    assert!(
        !can_clone_entry(&v, &[id(0x5c)], None),
        "an entry in the bin, also from search"
    );
    assert!(
        !can_clone_entry(&v, &[id(0x5a)], Some(id(0x62))),
        "the bin is the current group"
    );
    assert!(!can_clone_group(&v, id(1)) && !can_clone_group(&v, id(0x62)));
    assert!(can_clone_group(&v, id(0x61)));
}

#[test]
fn mod_10_2_new_id_and_fresh_times() {
    let mut v = vault();
    let c = clone_entry(
        &mut v,
        id(0x5a),
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    assert_ne!(c, id(0x5a));
    assert_eq!((c.0[6] >> 4, c.0[8] >> 6), (4, 0b10), "version 4 id");
    let t = &find(&v, c).times;
    assert_eq!(
        (
            t.creation,
            t.last_modification,
            t.last_access,
            t.location_changed
        ),
        (now(), now(), now(), now())
    );
    assert_eq!(
        (t.expires, t.expiry, t.usage_count),
        (true, at(2027, 1, 1, 0, 0, 0), 4)
    );
    ok(&v);
}

#[test]
fn mod_10_3_always_copied() {
    let mut v = vault();
    let c = clone_entry(
        &mut v,
        id(0x5a),
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    let (a, b) = (find(&v, id(0x5a)), find(&v, c));
    for n in ["UserName", "Password", "URL", "Pin"] {
        assert_eq!(a.field(n), b.field(n), "{n}");
    }
    assert!(b.field("Password").unwrap().protected && b.field("Pin").unwrap().protected);
    assert!(
        Arc::ptr_eq(&a.attachments[0].data, &b.attachments[0].data),
        "same content, one copy"
    );
    assert_eq!(
        (b.tags(), b.icon, &b.foreground_color),
        (a.tags(), a.icon, &a.foreground_color)
    );
    assert_eq!(
        (&b.custom_data, &b.auto_type),
        (&a.custom_data, &a.auto_type)
    );
    assert_eq!(b.previous_parent, Some(id(0x62)), "LD-107");
    ok(&v);
}

#[test]
fn mod_10_4_title_suffix() {
    let mut v = vault();
    let c = clone_entry(
        &mut v,
        id(0x5a),
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    assert_eq!(find(&v, c).value("Title"), "Mail - Clone");
    let cc = clone_entry(
        &mut v,
        c,
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    assert_eq!(find(&v, cc).value("Title"), "Mail - Clone - Clone");
    let off = Options {
        suffix: false,
        ..Options::default()
    };
    let d = clone_entry(
        &mut v,
        id(0x5a),
        off,
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    assert_eq!(find(&v, d).value("Title"), "Mail");
    let e = clone_entry(
        &mut v,
        id(0x5b),
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    v.root.groups[0]
        .entries
        .last_mut()
        .unwrap()
        .set_field("Title".into(), field(""));
    let f = clone_entry(
        &mut v,
        e,
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    assert_eq!(find(&v, f).value("Title"), SUFFIX);
    ok(&v);
}

#[test]
fn mod_10_5_references() {
    let mut v = vault();
    let refs = Options {
        refs: true,
        ..Options::default()
    };
    let c = clone_entry(
        &mut v,
        id(0x5a),
        refs,
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    let hex = "5A".repeat(16);
    let e = find(&v, c);
    assert_eq!(e.value("UserName"), format!("{{REF:U@I:{hex}}}"));
    assert_eq!(e.value("Password"), format!("{{REF:P@I:{hex}}}"));
    assert!(e.field("Password").unwrap().protected);
    let pw = |v: &Vault, id| {
        let e = find(v, id);
        resolve(e.value("Password"), e, &Context::new(Some(v), now()))
            .text
            .expose()
            .to_owned()
    };
    assert_eq!(pw(&v, c), "pw-mail");
    // A clone of the clone points at its own source; both follow changes.
    let cc = clone_entry(&mut v, c, refs, &app_core::clone::Limits::DEFAULT, now()).unwrap();
    edit_entry(&mut v, id(0x5a), now(), |e| {
        e.set_field("Password".into(), protected("pw-new"));
    })
    .unwrap();
    assert_eq!((pw(&v, c), pw(&v, cc)), ("pw-new".into(), "pw-new".into()));
    // An empty field still gets the reference, which resolves to empty.
    let o = clone_entry(
        &mut v,
        id(0x5b),
        refs,
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    let e = find(&v, o);
    assert!(e.value("UserName").starts_with("{REF:U@I:"));
    assert_eq!(
        resolve(e.value("UserName"), e, &Context::new(Some(&v), now()))
            .text
            .expose(),
        ""
    );
    ok(&v);
}

#[test]
fn mod_10_6_history() {
    let mut v = vault();
    let c = clone_entry(
        &mut v,
        id(0x5a),
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    let h = &find(&v, c).history;
    assert_eq!(h.len(), 2);
    assert_eq!(
        (h[0].value("Title"), h[1].value("Title")),
        ("Mail0", "Mail1")
    );
    assert_eq!(
        (h[0].times.last_modification, h[1].times.last_modification),
        (at(2025, 2, 1, 0, 0, 0), at(2025, 3, 1, 0, 0, 0))
    );
    assert!(h.iter().all(|x| x.uuid == c));
    let off = Options {
        history: false,
        ..Options::default()
    };
    let d = clone_entry(
        &mut v,
        id(0x5a),
        off,
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    assert!(find(&v, d).history.is_empty());
    assert_eq!(find(&v, id(0x5a)).history.len(), 2);
    // Not trimmed at clone time; the next edit trims (10-12).
    let mut w = vault();
    for i in 0..10 {
        let mut h = find(&w, id(0x5a)).duplicate(false);
        h.times.last_modification = Time(i);
        w.root.groups[0].entries[0].history.push(h);
    }
    w.meta.history_max_items = 10;
    let c = clone_entry(
        &mut w,
        id(0x5a),
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    assert_eq!(find(&w, c).history.len(), 12);
    edit_entry(&mut w, c, now(), |e| {
        e.set_field("Notes".into(), field("n"));
    })
    .unwrap();
    assert_eq!(find(&w, c).history.len(), 10);
    ok(&v);
    ok(&w);
}

#[test]
fn mod_10_7_options_skip_history() {
    let mut v = vault();
    let all = Options {
        suffix: true,
        refs: true,
        history: true,
    };
    let c = clone_entry(
        &mut v,
        id(0x5a),
        all,
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    let h = &find(&v, c).history;
    assert_eq!(
        (h[0].value("Title"), h[1].value("Title")),
        ("Mail0", "Mail1")
    );
    assert_eq!(
        h[0].value("Password"),
        "pw-mail",
        "D-10-1: history unchanged"
    );
    ok(&v);
}

#[test]
fn mod_10_8_placement() {
    let mut v = vault();
    let before = find(&v, id(0x5a)).times.clone();
    let c = clone_entry(
        &mut v,
        id(0x5a),
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        now(),
    )
    .unwrap();
    assert_eq!(
        titles(group(&v, id(0x61))),
        ["Mail", "Other", "Mail - Clone"]
    );
    assert_eq!(v.root.groups[0].entries.last().unwrap().uuid, c);
    assert_eq!(
        find(&v, id(0x5a)).times,
        before,
        "the original is unchanged"
    );
    assert!(v.deleted_objects.is_empty());
    ok(&v);
}

#[test]
fn mod_10_9_cancel() {
    // The dialog is pure state: cancel is not calling clone_entry.
    let v = vault();
    let _dialog = Options::default();
    assert_eq!(group(&v, id(0x61)).entries.len(), 2);
    // A group clone dropped in the editor adds nothing (10-17).
    let g = clone_group(&v, id(0x61), &app_core::clone::Limits::DEFAULT, now()).unwrap();
    drop(g);
    assert_eq!(v.root.groups.len(), 2);
    ok(&v);
}

#[test]
fn mod_10_10_clone_group() {
    let mut v = vault();
    let mut sub = Group::new(id(0x63), "Sub".into(), T0);
    sub.entries.push(entry(0x5d, "S"));
    v.root.groups[0].groups.push(sub);
    let g = clone_group(&v, id(0x61), &app_core::clone::Limits::DEFAULT, now()).unwrap();
    assert_eq!(g.name, "Work - Clone");
    assert_eq!(g.groups[0].name, "Sub - Clone");
    assert_eq!(titles(&g), ["Mail", "Other"], "no title suffix on entries");
    assert_eq!(g.entries[0].history.len(), 2, "history kept");
    assert!(g.subtree().iter().all(|x| x.times.creation == now()));
    assert_ne!(g.uuid, id(0x61));
    let new = add_group_clone(&mut v, id(0x61), g, now()).unwrap();
    assert_eq!(names(&v.root), ["Work", "Home", "Work - Clone"]);
    assert_eq!(v.root.groups[2].uuid, new);
    assert_eq!(
        clone_group(&v, id(1), &app_core::clone::Limits::DEFAULT, now()).err(),
        Some(app_core::Error::RootGroup)
    );
    ok(&v);
}

#[test]
fn mod_10_11_copy_by_drag_inside_one_vault() {
    let mut v = vault();
    for e in [id(0x5a), id(0x5b)] {
        copy_within(&mut v, Item::Entry(e), id(0x62), Position::End, now()).unwrap();
    }
    let home = group(&v, id(0x62));
    assert_eq!(titles(home), ["Mail", "Other"]);
    assert_eq!(home.entries[0].history.len(), 2);
    assert!(home.entries.iter().all(|e| e.times.creation == now()));
    let g = copy_within(
        &mut v,
        Item::Group(id(0x61)),
        id(0x62),
        Position::End,
        now(),
    )
    .unwrap();
    assert_eq!(group(&v, g).name, "Work", "no suffix");
    assert_eq!(group(&v, id(0x61)).entries.len(), 2, "Work unchanged");
    let into_own = app_core::edit::move_group(&mut v, id(0x61), g, Position::End, now());
    assert_eq!(into_own, Ok(true), "a copy is a separate group");
    ok(&v);
}

#[test]
fn mod_10_12_drag_between_vaults() {
    let mut a = vault();
    a.meta.custom_icons.push(CustomIcon {
        uuid: id(0xc1),
        name: "k".into(),
        last_modified: Some(T0),
        data: vec![1, 2],
        unknown: Vec::new(),
    });
    a.root.groups[0].entries[0].icon = Icon::Custom(id(0xc1));
    let mut b = Vault::new(Group::new(id(0x90), "B".into(), T0), T0);
    let copied = copy_into(
        &a,
        Item::Entry(id(0x5a)),
        &mut b,
        id(0x90),
        Position::End,
        now(),
    )
    .unwrap();
    assert_eq!(b.meta.custom_icons.len(), 1);
    assert_eq!(find(&b, copied).history.len(), 2);
    assert!(a.deleted_objects.is_empty(), "a copy leaves the source");
    let moved = move_into(
        &mut a,
        Item::Entry(id(0x5a)),
        &mut b,
        id(0x90),
        Position::End,
        now(),
    )
    .unwrap();
    assert_ne!(moved, id(0x5a));
    assert_eq!(
        a.deleted_objects.iter().map(|d| d.uuid).collect::<Vec<_>>(),
        [id(0x5a)]
    );
    ok(&a);
    ok(&b);
}

/// MOD-10 security notes: the clone's count limits are the reader's
/// (FMT-08.12), tied here so they cannot drift.
#[test]
fn mod_10_count_limits_match_the_reader() {
    let l = app_format::limits::Limits::DEFAULT;
    let c = app_core::clone::Limits::DEFAULT;
    assert_eq!(
        (c.groups, c.entries, c.entry_elements),
        (l.groups, l.entries, l.entry_elements)
    );
}

/// MOD-10 security notes: a clone past a count limit is refused and
/// changes nothing (limits lowered to the vault's size).
#[test]
fn mod_10_clones_stay_within_the_limits() {
    use app_core::clone::Limits;
    let mut v = vault();
    // The vault: 3 groups, 2 entries, 4 entry elements (Mail's 2 history
    // items included).
    let full = |entries, elements, groups| Limits {
        groups,
        entries,
        entry_elements: elements,
    };
    let before = group(&v, id(0x61)).entries.len();
    let r = clone_entry(
        &mut v,
        id(0x5a),
        Options::default(),
        &full(2, 100, 100),
        now(),
    );
    assert_eq!(r, Err(app_core::Error::TooLarge), "entries");
    let r = clone_entry(
        &mut v,
        id(0x5a),
        Options::default(),
        &full(100, 6, 100),
        now(),
    );
    assert_eq!(r, Err(app_core::Error::TooLarge), "entry elements: 4 + 3");
    assert!(
        clone_entry(
            &mut v,
            id(0x5a),
            Options::default(),
            &full(3, 7, 100),
            now()
        )
        .is_ok(),
        "exactly at the limits"
    );
    assert_eq!(group(&v, id(0x61)).entries.len(), before + 1);
    let g = clone_group(&v, id(0x61), &full(100, 100, 3), now());
    assert_eq!(g.err(), Some(app_core::Error::TooLarge), "groups");
    // The recycle bin is never cloned.
    v.meta.recycle_bin = Some(id(0x62));
    assert_eq!(
        clone_group(&v, id(0x62), &Limits::DEFAULT, now()).err(),
        Some(app_core::Error::InRecycleBin)
    );
    ok(&v);
}
