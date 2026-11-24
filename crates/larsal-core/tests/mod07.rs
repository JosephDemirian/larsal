//! E4-S5: the rules of MOD-07 (tags). Each test names its rule and checks
//! the invariants where it changes the vault.

mod common;

use common::*;
use larsal_core::edit::{change_entry, edit_entry};
use larsal_core::tags::{
    MenuItem, TagTerm, add_to, choose, clean, end_tag, from_chips, from_text, menu, paste,
    remove_everywhere, sidebar_terms, suggestions, vault_tags,
};
use larsal_model::{Entry, Group, Vault};

fn tagged(n: u8, tags: &[&str]) -> Entry {
    let mut e = entry(n, "E");
    e.set_tags(tags.iter().map(|t| (*t).to_owned()).collect());
    e
}

/// Vault V: root R, group G holding E1 (0x10) and E2 (0x11), a recycle bin
/// (0x03).
fn vault(e1: &[&str], e2: &[&str]) -> Vault {
    let mut g = Group::new(id(2), "G".into(), T0);
    g.entries = vec![tagged(0x10, e1), tagged(0x11, e2)];
    let bin = Group::new(id(3), "Recycle Bin".into(), T0);
    let mut root = Group::new(id(1), "R".into(), T0);
    root.groups = vec![g, bin];
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin = Some(id(3));
    v
}

#[test]
fn mod_07_1_where_tags_live() {
    let mut v = vault(&["a"], &[]);
    v.root.groups[0].tags = "grp".into();
    let mut old = find(&v, id(0x10)).duplicate(false);
    old.set_tags(vec!["old".into()]);
    v.root.groups[0].entries[0].history.push(old);
    assert_eq!(vault_tags(&v), ["a"], "group tags and history left out");
    edit_entry(&mut v, id(0x10), NOW, |e| e.set_tags(Vec::new())).unwrap();
    let e = find(&v, id(0x10));
    assert!(e.tags().is_empty());
    assert_eq!(e.history[0].tags(), ["old"]);
    assert_eq!(
        e.history[1].tags(),
        ["a"],
        "the new history item holds the tags before"
    );
    assert_eq!(group(&v, id(2)).tags, "grp");
    ok(&v);
}

#[test]
fn mod_07_2_entry_tag_list() {
    assert_eq!(
        from_text("b;B, a ,A\t_x;10;9;b;é;Z"),
        ["10", "9", "A", "B", "Z", "_x", "a", "b", "é"]
    );
    // Setting an equal list is no change.
    let mut v = vault(&["a", "b"], &[]);
    let changed = edit_entry(&mut v, id(0x10), NOW, |e| {
        e.set_tags(vec!["b".into(), "a".into()])
    })
    .unwrap();
    assert!(!changed);
    let e = find(&v, id(0x10));
    assert_eq!((e.times.last_modification, e.history.len()), (T0, 0));
    ok(&v);
}

#[test]
fn mod_07_3_setting_tags_from_text() {
    assert_eq!(
        from_text("zeta; alpha,beta\talpha ,Alpha"),
        ["Alpha", "alpha", "beta", "zeta"]
    );
    assert_eq!(from_text("a, ,b;;c"), ["a", "b", "c"]);
    assert_eq!(from_text("   "), Vec::<String>::new(), "never an empty tag");
}

#[test]
fn mod_07_4_tag_box() {
    // Keys end a tag: `Work`, `,`, `Mail`, Enter, save.
    let chips: Vec<String> = ["Work", "Mail"].iter().filter_map(|t| end_tag(t)).collect();
    assert_eq!(from_chips(&chips), ["Mail", "Work"]);
    assert_eq!(end_tag("   "), None, "spaces only add nothing");
    assert_eq!(paste("x;y,z"), ["x;y", "z"]);
    assert_eq!(from_chips(&paste("x;y,z")), ["x", "y", "z"]);
    let list = ["Bank".to_owned(), "banking".into(), "Work".into()];
    assert_eq!(suggestions(&list, "ban"), ["Bank", "banking"]);
}

#[test]
fn mod_07_5_vault_tag_list() {
    let mut v = vault(&["b", "A"], &["a10", "a9", "Work"]);
    v.root
        .entries
        .push(tagged(0x12, &["work", "_x", "10", "9"]));
    v.root.groups[1].entries.push(tagged(0x13, &["Old"]));
    let mut h = find(&v, id(0x10)).duplicate(false);
    h.set_tags(vec!["Hist".into()]);
    v.root.groups[0].entries[0].history.push(h);
    v.root.groups[0].tags = "grp".into();
    assert_eq!(
        vault_tags(&v),
        ["9", "10", "_x", "A", "a9", "a10", "b", "Work", "work"]
    );
    // Rebuilt right after a change.
    let mut w = vault(&["a"], &[]);
    choose(&mut w, &[id(0x10)], "z", NOW).unwrap();
    assert_eq!(vault_tags(&w), ["a", "z"]);
    ok(&v);
}

#[test]
fn mod_07_6_sidebar_terms() {
    assert_eq!(
        sidebar_terms(&["say \"hi\""]),
        [TagTerm("say \"hi\"".into())]
    );
    assert_eq!(sidebar_terms(&["dir\\"]), [TagTerm("dir\\".into())]);
    assert_eq!(
        sidebar_terms(&["a", "b"]),
        [TagTerm("a".into()), TagTerm("b".into())]
    );
}

#[test]
fn mod_07_7_tag_menu() {
    let w = vault(&["a"], &["b"]);
    assert_eq!(
        menu(&w, &[id(0x10), id(0x11)]),
        [
            MenuItem {
                tag: "a".into(),
                checked: true
            },
            MenuItem {
                tag: "b".into(),
                checked: true
            }
        ]
    );
    // Add to the selection.
    let mut w = vault(&["a"], &[]);
    w.root.entries.push(tagged(0x12, &["x"]));
    assert_eq!(choose(&mut w, &[id(0x10), id(0x11)], "x", NOW), Ok(2));
    assert_eq!(find(&w, id(0x10)).tags(), ["a", "x"]);
    assert_eq!(find(&w, id(0x11)).tags(), ["x"]);
    for n in [0x10, 0x11] {
        let e = find(&w, id(n));
        assert_eq!((e.times.last_modification, e.history.len()), (NOW, 0));
    }
    // Remove from the selection (checked).
    let mut w = vault(&["a"], &[]);
    assert_eq!(choose(&mut w, &[id(0x10), id(0x11)], "a", NOW), Ok(1));
    assert!(find(&w, id(0x10)).tags().is_empty());
    assert_eq!(find(&w, id(0x11)).times.last_modification, T0);
    assert!(
        menu(&vault(&[], &[]), &[id(0x10)]).is_empty(),
        "no tags: msg.no_tags"
    );
    ok(&w);
}

#[test]
fn mod_07_8_adding_one_tag() {
    let mut e = tagged(0x10, &[]);
    assert!(add_to(&mut e, "  a,b  "));
    assert_eq!(e.tags(), ["ab"]);
    assert!(!add_to(&mut e, " , "), "empty adds nothing");
    assert!(!add_to(&mut e, "ab"), "already there");
    assert_eq!(clean("x;\ty"), Some("xy".into()));
}

#[test]
fn mod_07_9_remove_everywhere() {
    let mut w = vault(&["x"], &["x", "y"]);
    w.root.groups[1].entries.push(tagged(0x13, &["x"]));
    let mut h = find(&w, id(0x10)).duplicate(false);
    h.set_tags(vec!["x".into()]);
    w.root.groups[0].entries[0].history.push(h);
    assert_eq!(remove_everywhere(&mut w, "x", NOW), 3);
    assert!(find(&w, id(0x10)).tags().is_empty());
    assert_eq!(find(&w, id(0x11)).tags(), ["y"]);
    assert!(find(&w, id(0x13)).tags().is_empty(), "the bin too");
    assert_eq!(find(&w, id(0x10)).history.len(), 1, "no history items");
    assert_eq!(
        find(&w, id(0x10)).history[0].tags(),
        ["x"],
        "history keeps it"
    );
    assert_eq!(find(&w, id(0x13)).times.last_modification, NOW);
    assert_eq!(vault_tags(&w), ["y"]);
    ok(&w);
}

#[test]
fn mod_07_10_no_rename() {
    // The tag row offers only remove-everywhere (D-07-2): larsal-core has no
    // rename; "remove T, add U" on the same entries is the later path.
    let mut w = vault(&["t"], &[]);
    let holders = vec![id(0x10)];
    remove_everywhere(&mut w, "t", NOW);
    choose(&mut w, &holders, "u", NOW).unwrap();
    assert_eq!(find(&w, id(0x10)).tags(), ["u"]);
    ok(&w);
}

#[test]
fn mod_07_11_tags_app_adds() {
    let mut e = tagged(0x10, &[]);
    assert!(add_to(&mut e, "Passkey"));
    assert_eq!(e.tags(), ["Passkey"]);
    assert!(larsal_core::tags::remove_from(&mut e, "Passkey"));
    assert!(e.tags().is_empty());
}

#[test]
fn mod_07_12_tag_changes_move_times() {
    let mut w = vault(&["a"], &[]);
    let before = vault_tags(&w);
    assert_eq!(
        find(&w, id(0x10)).times.last_modification,
        T0,
        "building the list changes nothing"
    );
    edit_entry(&mut w, id(0x10), NOW, |e| {
        add_to(e, "b");
    })
    .unwrap();
    let e = find(&w, id(0x10));
    assert_eq!((e.times.last_modification, e.history.len()), (NOW, 1));
    assert_eq!(e.history[0].tags(), ["a"]);
    assert_eq!(before, ["a"]);
    // The joined tags text must fit the text limit (as MOD-01.9).
    let long = "t".repeat(larsal_core::edit::MAX_NAME + 1);
    let r = change_entry(&mut w, id(0x10), NOW, |e| e.set_tags(vec![long]));
    assert_eq!(r, Err(larsal_core::Error::FieldTooLarge));
    ok(&w);
}
