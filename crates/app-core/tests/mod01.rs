//! E4-S1: the rules of MOD-01 (entry fields and entry times). Each test
//! names its rule; every test checks the invariants after the operation.

mod common;

use app_core::edit::{
    MAX_CUSTOM, MAX_VALUE, NEW_FIELD, add_entry, change_entry, edit_entry, field_name_suggestions,
    holds_reference, move_entries, move_entry, natural_cmp, new_entry, new_field_name,
    rename_field, screen_line, user_name_suggestions,
};
use app_core::{Error, NameProblem, recycle};
use app_crypto::secret::SecretBytes;
use app_crypto::secret::SecretString;
use app_model::entry::STANDARD_FIELDS;
use app_model::{Attachment, CustomDataItem, Field, Icon, Time, Uuid};
use common::*;
use core::cmp::Ordering;
use std::sync::Arc;

fn set(e: &mut app_model::Entry, name: &str, value: &str) {
    let protected = e.field(name).is_some_and(|f| f.protected);
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(value.into()),
            protected,
        },
    );
}

#[test]
fn mod_01_1_standard_fields() {
    let mut v = sample();
    let e = find(&v, id(0x10));
    let names: Vec<&str> = e.fields().map(|(n, _)| n).collect();
    for s in STANDARD_FIELDS {
        assert!(names.contains(&s));
    }
    edit_entry(&mut v, id(0x10), NOW, |e| {
        assert!(
            e.remove_field("Title").is_none(),
            "a standard field cannot be removed"
        );
    })
    .unwrap();
    let mut e = app_model::Entry::new(id(9), T0);
    assert_eq!(
        rename_field(&mut e, "Title", "Name"),
        Err(Error::FieldName(NameProblem::Standard))
    );
    ok(&v);
}

#[test]
fn mod_01_2_custom_field_names_are_exact() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| {
        for n in ["title", "Username", " Title", "URL "] {
            set(e, n, "x");
        }
    })
    .unwrap();
    let e = find(&v, id(0x10));
    for n in ["title", "Username", " Title", "URL ", "Title", "URL"] {
        assert!(e.field(n).is_some(), "{n:?}");
    }
    assert_eq!(e.fields().count(), 9);
    ok(&v);
}

#[test]
fn mod_01_3_add_and_rename() {
    let mut e = app_model::Entry::new(id(9), T0);
    assert_eq!(new_field_name(&e, NEW_FIELD), "New field");
    e.set_field("New field".into(), field(""));
    assert_eq!(new_field_name(&e, NEW_FIELD), "New field 1");
    e.set_field("New field 1".into(), field(""));
    assert_eq!(new_field_name(&e, NEW_FIELD), "New field 2");
    e.set_field(
        "a".into(),
        Field {
            value: SecretString::new("v".into()),
            protected: true,
        },
    );
    assert_eq!(
        rename_field(&mut e, "a", "  \u{3000}"),
        Err(Error::FieldName(NameProblem::Empty))
    );
    assert_eq!(
        rename_field(&mut e, "a", "Password"),
        Err(Error::FieldName(NameProblem::Standard))
    );
    assert_eq!(
        rename_field(&mut e, "a", "New field"),
        Err(Error::FieldName(NameProblem::Taken))
    );
    assert!(
        e.field("a").is_some(),
        "a refused rename keeps the old name"
    );
    rename_field(&mut e, "a", "  b  ").unwrap();
    let b = e.field("b").unwrap();
    assert_eq!(
        (b.value.expose(), b.protected),
        ("v", true),
        "trimmed; value and flag kept"
    );
}

#[test]
fn mod_01_4_names_from_a_file_are_kept() {
    let r = String::from_utf8(vec![
        0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6C, 0x65,
    ])
    .unwrap();
    let xml = format!(
        "<{r}><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Entry><UUID>EBAQEBAQEBAQEBAQEBAQEA==</UUID><String><Key/><Value>e</Value></String><String><Key>  sp  </Key><Value>s</Value></String></Entry></Group></Root></{r}>"
    );
    let lim = app_format::limits::Limits::DEFAULT;
    let key = app_crypto::secret::SecretBytes::new(vec![0; 64]);
    let mut stream = app_crypto::stream::FieldStream::chacha20_from_stream_key(&key).unwrap();
    let opts = app_format::document::Options {
        open_time: T0,
        limits: &lim,
        v3_header: None,
    };
    let mut v = app_format::document::read(xml.as_bytes(), &mut stream, &[], &opts)
        .unwrap()
        .vault;
    // Editing something else never renames them.
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Notes", "n")).unwrap();
    let e = find(&v, id(0x10));
    assert_eq!(e.value(""), "e");
    assert_eq!(e.value("  sp  "), "s");
    ok(&v);
}

#[test]
fn mod_01_5_single_line_boxes() {
    assert_eq!(screen_line("a\r\nb\nc"), "a b c");
    assert_eq!(screen_line("a\rb"), "a b");
    assert_eq!(screen_line("a\n\nb"), "a  b", "each break is one space");
    // Notes, Password and custom values keep their breaks: edits store them as given.
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Notes", "l1\nl2")).unwrap();
    assert_eq!(find(&v, id(0x10)).value("Notes"), "l1\nl2");
    ok(&v);
}

#[test]
fn mod_01_6_own_protected_flag() {
    let e = app_model::Entry::new(id(9), T0);
    assert!(e.fields().all(|(_, f)| !f.protected), "off for a new entry");
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| {
        e.set_field(
            "pin".into(),
            Field {
                value: SecretString::new("1".into()),
                protected: true,
            },
        );
    })
    .unwrap();
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "pin", "2")).unwrap();
    assert!(
        find(&v, id(0x10)).field("pin").unwrap().protected,
        "a value change keeps the flag"
    );
    let mut e = find(&v, id(0x10)).duplicate(false);
    rename_field(&mut e, "pin", "code").unwrap();
    assert!(
        e.field("code").unwrap().protected,
        "a rename keeps the flag"
    );
    ok(&v);
}

#[test]
fn mod_01_7_secrets_stay_in_secret_types() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| {
        set(e, "Password", "demo-secret-1")
    })
    .unwrap();
    edit_entry(&mut v, id(0x10), Time(NOW.0 + 1), |e| {
        set(e, "Password", "demo-secret-2")
    })
    .unwrap();
    let e = find(&v, id(0x10));
    // History items hold their values in secret types, and no Debug output
    // of the vault, a group or an entry carries a value (LD-88).
    let text = format!("{v:?} {e:?} {:?}", e.history[0]);
    assert!(!text.contains("demo-secret"));
    let _: &SecretString = &e.history[0].field("Password").unwrap().value;
    ok(&v);
}

#[test]
fn mod_01_8_names_with_a_meaning() {
    let mut v = sample();
    edit_entry(&mut v, id(0x11), NOW, |e| {
        set(e, "KPEX_PASSKEY_USERNAME", "u");
        set(e, "otp", "otpauth://totp/demo");
        set(e, "Shared", "x");
    })
    .unwrap();
    let names = field_name_suggestions(&v, id(0x10));
    assert!(names.contains(&"otp".to_owned()) && names.contains(&"Shared".to_owned()));
    assert!(
        !names.iter().any(|n| n.starts_with("KPEX_PASSKEY")),
        "passkey fields are left out"
    );
    ok(&v);
}

#[test]
fn mod_01_9_limits() {
    let mut v = sample();
    let big = "a".repeat(MAX_VALUE + 1);
    assert_eq!(
        edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Notes", &big)),
        Err(Error::FieldTooLarge)
    );
    assert_eq!(find(&v, id(0x10)).value("Notes"), "", "nothing changed");
    let at = "a".repeat(MAX_VALUE);
    assert_eq!(
        edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Notes", &at)),
        Ok(true)
    );
    let r = edit_entry(&mut v, id(0x11), NOW, |e| {
        for i in 0..=MAX_CUSTOM {
            e.set_field(format!("f{i}"), field(""));
        }
    });
    assert_eq!(r, Err(Error::FieldTooLarge));
    ok(&v);
}

#[test]
fn mod_01_10_url_change_drops_the_command_choice() {
    let mut v = sample();
    for (value, kept) in [("1", false), ("0", false), ("ask", true)] {
        change_entry(&mut v, id(0x10), NOW, |e| set(e, "_EXEC_CMD", value)).unwrap();
        edit_entry(&mut v, id(0x10), NOW, |e| {
            let url = format!("{}x", e.value("URL"));
            set(e, "URL", &url);
        })
        .unwrap();
        assert_eq!(
            find(&v, id(0x10)).field("_EXEC_CMD").is_some(),
            kept,
            "{value}"
        );
    }
    // A change that leaves the URL alone keeps the field.
    change_entry(&mut v, id(0x11), NOW, |e| set(e, "_EXEC_CMD", "1")).unwrap();
    edit_entry(&mut v, id(0x11), NOW, |e| set(e, "Notes", "n")).unwrap();
    assert!(find(&v, id(0x11)).field("_EXEC_CMD").is_some());
    ok(&v);
}

#[test]
fn mod_01_11_carried_properties() {
    let mut v = sample();
    change_entry(&mut v, id(0x10), T0, |e| {
        e.override_url = "cmd://demo".into();
    })
    .unwrap();
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Title", "new")).unwrap();
    let e = find(&v, id(0x10));
    assert_eq!(e.override_url, "cmd://demo");
    ok(&v);
}

#[test]
fn mod_01_12_id() {
    let v = sample();
    let a = new_entry(&v, id(1), false).unwrap();
    let b = new_entry(&v, id(1), false).unwrap();
    assert_ne!(a.uuid, b.uuid);
    for e in [&a, &b] {
        assert_eq!(
            (e.uuid.0[6] >> 4, e.uuid.0[8] >> 6),
            (4, 0b10),
            "version 4 id"
        );
        assert!(!e.uuid.is_zero());
    }
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| {
        e.uuid = Uuid([0x77; 16]);
        set(e, "Title", "t");
    })
    .unwrap();
    assert!(
        v.root.entries.iter().any(|e| e.uuid == id(0x10)),
        "the id never changes on edit"
    );
    ok(&v);
}

#[test]
fn mod_01_13_icon() {
    let mut v = sample();
    assert!(edit_entry(&mut v, id(0x10), NOW, |e| e.icon = Icon::Custom(id(0xA1))).unwrap());
    assert!(
        !edit_entry(&mut v, id(0x10), NOW, |e| e.icon = Icon::Custom(id(0xA1))).unwrap(),
        "the same icon is no change"
    );
    assert!(edit_entry(&mut v, id(0x10), NOW, |e| e.icon = Icon::Standard(5)).unwrap());
    assert_eq!(
        find(&v, id(0x10)).icon,
        Icon::Standard(5),
        "a standard number clears the custom icon"
    );
    ok(&v);
}

#[test]
fn mod_01_14_colors() {
    let mut v = sample();
    change_entry(&mut v, id(0x10), T0, |e| e.foreground_color = "red".into()).unwrap();
    edit_entry(&mut v, id(0x10), NOW, |e| {
        e.background_color = format!("#{:02x}{:02x}{:02x}", 0x1A, 0x2B, 0x3C);
    })
    .unwrap();
    let e = find(&v, id(0x10));
    assert_eq!(
        (e.foreground_color.as_str(), e.background_color.as_str()),
        ("red", "#1a2b3c"),
        "an unchanged color stays as stored"
    );
    ok(&v);
}

#[test]
fn mod_01_15_override_url_carried() {
    let mut v = sample();
    change_entry(&mut v, id(0x10), T0, |e| e.override_url = "cmd://x".into()).unwrap();
    edit_entry(&mut v, id(0x10), NOW, |e| {
        set(e, "URL", "https://example.com")
    })
    .unwrap();
    assert_eq!(find(&v, id(0x10)).override_url, "cmd://x");
    ok(&v);
}

#[test]
fn mod_01_16_tags() {
    let mut v = sample();
    assert!(
        change_entry(&mut v, id(0x10), NOW, |e| e
            .set_tags(vec!["b".into(), "a".into()]))
        .unwrap()
    );
    assert_eq!(find(&v, id(0x10)).tags(), ["a", "b"]);
    assert_eq!(find(&v, id(0x10)).times.last_modification, NOW);
    ok(&v);
}

#[test]
fn mod_01_17_expiry_is_data() {
    let mut v = sample();
    assert!(edit_entry(&mut v, id(0x10), NOW, |e| e.times.expires = true).unwrap());
    assert!(
        edit_entry(&mut v, id(0x10), Time(NOW.0 + 1), |e| e.times.expiry =
            Time(5))
        .unwrap()
    );
    let e = find(&v, id(0x10));
    assert!(e.times.expires && e.times.expiry == Time(5));
    assert_eq!(e.history.len(), 2);
    ok(&v);
}

#[test]
fn mod_01_18_auto_type_defaults() {
    let e = new_entry(&sample(), id(1), false).unwrap();
    assert!(e.auto_type.enabled && e.auto_type.obfuscation == 0);
    assert!(e.auto_type.default_sequence.is_empty() && e.auto_type.associations.is_empty());
}

#[test]
fn mod_01_19_report_exclusion() {
    let mut v = sample();
    assert!(!new_entry(&v, id(1), false).unwrap().exclude_from_reports);
    assert!(edit_entry(&mut v, id(0x10), NOW, |e| e.exclude_from_reports = true).unwrap());
    ok(&v);
}

#[test]
fn mod_01_20_custom_data_delete_is_a_change() {
    let mut v = sample();
    change_entry(&mut v, id(0x10), T0, |e| {
        e.custom_data.items.push(CustomDataItem {
            key: "k".into(),
            value: "v".into(),
            last_modified: None,
            unknown: Vec::new(),
        });
    })
    .unwrap();
    assert!(edit_entry(&mut v, id(0x10), NOW, |e| e.custom_data.items.clear()).unwrap());
    assert_eq!(find(&v, id(0x10)).times.last_modification, NOW);
    ok(&v);
}

#[test]
fn mod_01_21_previous_parent_only_by_moves() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Title", "x")).unwrap();
    assert_eq!(find(&v, id(0x10)).previous_parent, None);
    move_entries(&mut v, &[id(0x10)], id(4), NOW).unwrap();
    assert_eq!(find(&v, id(0x10)).previous_parent, Some(id(1)));
    ok(&v);
}

#[test]
fn mod_01_22_new_entry() {
    let mut v = sample();
    v.meta.default_user_name = "demo".into();
    let e = new_entry(&v, id(1), true).unwrap();
    assert_eq!(e.value("UserName"), "demo");
    assert_eq!(
        e.icon,
        Icon::Standard(0),
        "group icon 48 gives 0 (MOD-06.3)"
    );
    v.root.groups[1].icon = Icon::Standard(7);
    assert_eq!(new_entry(&v, id(4), true).unwrap().icon, Icon::Standard(7));
    assert_eq!(
        new_entry(&v, id(4), false).unwrap().icon,
        Icon::Standard(0),
        "setting off"
    );
    v.root.groups[1].icon = Icon::Custom(id(0xA1));
    assert_eq!(
        new_entry(&v, id(4), true).unwrap().icon,
        Icon::Custom(id(0xA1))
    );
    v.meta.default_user_name.clear();
    assert_eq!(new_entry(&v, id(1), false).unwrap().value("UserName"), "");
    // Not yet in the vault until committed.
    assert_eq!(v.root.entries.len(), 2);
    ok(&v);
}

#[test]
fn mod_01_23_user_name_suggestions() {
    let mut v = sample();
    let users = [
        (0x10, "bob"),
        (0x11, "alice"),
        (0x12, "bob"),
        (0x13, "{REF:U@I:00112233445566778899AABBCCDDEEFF}"),
    ];
    for (n, u) in users {
        change_entry(&mut v, id(n), T0, |e| set(e, "UserName", u)).unwrap();
    }
    assert_eq!(
        user_name_suggestions(&v),
        ["bob", "alice"],
        "by count, references and empty left out"
    );
    for i in 0..12u8 {
        let mut e = entry(0x40 + i, "x");
        set(&mut e, "UserName", &format!("u{i:02}"));
        v.root.entries.push(e);
    }
    let list = user_name_suggestions(&v);
    assert_eq!(list.len(), 10);
    assert_eq!(list[0], "bob");
    assert_eq!(
        list[2..4],
        ["u00".to_owned(), "u01".to_owned()],
        "ties by name"
    );
    ok(&v);
}

#[test]
fn mod_01_24_field_name_suggestions() {
    let mut v = sample();
    change_entry(&mut v, id(0x11), T0, |e| {
        set(e, "a10", "");
        set(e, "a9", "");
        set(e, "Mine", "");
    })
    .unwrap();
    change_entry(&mut v, id(0x10), T0, |e| set(e, "Mine", "")).unwrap();
    recycle::delete_entries(&mut v, &[id(0x12)], NOW, |_, _| recycle::References::Delete).unwrap();
    change_entry(&mut v, id(0x12), T0, |e| set(e, "Binned", "")).unwrap();
    let names = field_name_suggestions(&v, id(0x10));
    assert_eq!(
        names,
        ["a9", "a10"],
        "natural order; own names and bin entries left out"
    );
    ok(&v);
}

#[test]
fn mod_01_25_commit_times() {
    let mut v = sample();
    let before = group(&v, id(1)).times.clone();
    let e = new_entry(&v, id(1), false).unwrap();
    let uuid = add_entry(&mut v, id(1), e, NOW).unwrap();
    let t = &find(&v, uuid).times;
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
    assert!(!t.expires && t.usage_count == 0);
    assert_eq!(
        v.root.entries.last().unwrap().uuid,
        uuid,
        "appended after the group's entries"
    );
    assert_eq!(
        group(&v, id(1)).times,
        before,
        "the group's times stay (MOD-02.25)"
    );
    ok(&v);
}

#[test]
fn mod_01_26_last_modification_time() {
    type Change = fn(&mut app_model::Entry);
    let changes: [(&str, Change); 14] = [
        ("value", |e| set(e, "Notes", "n")),
        ("flag", |e| {
            e.set_field(
                "Notes".into(),
                Field {
                    value: SecretString::new(String::new()),
                    protected: true,
                },
            );
        }),
        ("custom added", |e| set(e, "c", "")),
        ("attachment", |e| {
            e.attachments.push(Attachment {
                name: "f".into(),
                data: Arc::new(app_crypto::secret::SecretBytes::new(vec![1])),
            })
        }),
        ("custom data", |e| {
            e.custom_data.items.push(CustomDataItem {
                key: "k".into(),
                value: String::new(),
                last_modified: None,
                unknown: Vec::new(),
            })
        }),
        ("icon", |e| e.icon = Icon::Standard(3)),
        ("color", |e| e.foreground_color = "#000000".into()),
        ("override", |e| e.override_url = "x".into()),
        ("tags", |e| e.set_tags(vec!["t".into()])),
        ("expires", |e| e.times.expires = true),
        ("expiry", |e| e.times.expiry = Time(1)),
        ("auto-type", |e| e.auto_type.obfuscation = 1),
        ("report", |e| e.exclude_from_reports = true),
        ("previous parent", |e| e.previous_parent = Some(id(2))),
    ];
    for (name, change) in changes {
        let mut v = sample();
        assert!(
            change_entry(&mut v, id(0x10), NOW, change).unwrap(),
            "{name}"
        );
        assert_eq!(find(&v, id(0x10)).times.last_modification, NOW, "{name}");
        ok(&v);
    }
    // Setting a value it already has changes nothing.
    let mut v = sample();
    assert!(!edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Title", "E1")).unwrap());
    assert_eq!(find(&v, id(0x10)).times.last_modification, T0);
    // One batch, one time.
    edit_entry(&mut v, id(0x10), NOW, |e| {
        set(e, "Title", "a");
        set(e, "Notes", "b");
    })
    .unwrap();
    assert_eq!(find(&v, id(0x10)).history.len(), 1);
    // A move whose previous parent already names the old group moves no time.
    change_entry(&mut v, id(0x11), T0, |e| e.previous_parent = Some(id(1))).unwrap();
    let before = find(&v, id(0x11)).times.last_modification;
    move_entries(&mut v, &[id(0x11)], id(4), NOW).unwrap();
    assert_eq!(find(&v, id(0x11)).times.last_modification, before);
    ok(&v);
}

#[test]
fn mod_01_27_last_access_moves_with_modification_only() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Notes", "n")).unwrap();
    let t = &find(&v, id(0x10)).times;
    assert_eq!((t.last_modification, t.last_access), (NOW, NOW));
    // Reading does not move it: looking at the entry changes nothing.
    let _ = find(&v, id(0x11)).value("Password");
    assert_eq!(find(&v, id(0x11)).times.last_access, T0);
    ok(&v);
}

#[test]
fn mod_01_28_usage_count_never_changes() {
    let mut v = sample();
    v.root.entries[0].times.usage_count = -7; // as read from a file
    edit_entry(&mut v, id(0x10), NOW, |e| {
        e.times.usage_count = 3;
        set(e, "Notes", "n");
    })
    .unwrap();
    move_entries(&mut v, &[id(0x10)], id(4), NOW).unwrap();
    assert_eq!(
        find(&v, id(0x10)).times.usage_count,
        -7,
        "kept as read; no action changes it"
    );
    ok(&v);
}

#[test]
fn mod_01_29_location_changed() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Notes", "n")).unwrap();
    assert_eq!(
        find(&v, id(0x10)).times.location_changed,
        T0,
        "an edit never moves it"
    );
    assert_eq!(
        move_entries(&mut v, &[id(0x10)], id(1), NOW).unwrap(),
        0,
        "same group: no move"
    );
    assert_eq!(find(&v, id(0x10)).times.location_changed, T0);
    move_entries(&mut v, &[id(0x10)], id(4), NOW).unwrap();
    assert_eq!(find(&v, id(0x10)).times.location_changed, NOW);
    let later = Time(NOW.0 + 10);
    recycle::delete_entries(&mut v, &[id(0x10)], later, |_, _| {
        recycle::References::Delete
    })
    .unwrap();
    assert_eq!(
        find(&v, id(0x10)).times.location_changed,
        later,
        "into the bin"
    );
    let restore = Time(NOW.0 + 20);
    recycle::restore_entries(&mut v, &[id(0x10)], restore).unwrap();
    assert_eq!(
        find(&v, id(0x10)).times.location_changed,
        restore,
        "restored"
    );
    ok(&v);
}

#[test]
fn mod_01_30_creation_time_set_once() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| {
        e.times.creation = Time(1);
        set(e, "Notes", "n");
    })
    .unwrap();
    move_entries(&mut v, &[id(0x10)], id(4), NOW).unwrap();
    assert_eq!(find(&v, id(0x10)).times.creation, T0);
    ok(&v);
}

#[test]
fn mod_01_31_changes_that_move_no_entry_time() {
    let mut v = sample();
    move_entry(&mut v, id(0x11), true).unwrap();
    assert_eq!(titles(&v.root), ["E2", "E1"]);
    for e in &v.root.entries {
        assert_eq!(
            e.times.last_modification, T0,
            "a reorder moves no entry time"
        );
    }
    app_core::edit::edit_group(&mut v, id(1), NOW, |g| g.name = "Root".into()).unwrap();
    assert!(
        v.root
            .entries
            .iter()
            .all(|e| e.times.last_modification == T0),
        "a change to the group moves none"
    );
    ok(&v);
}

#[test]
fn mod_01_32_which_changes_make_a_history_item() {
    let mut v = sample();
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Notes", "n")).unwrap();
    assert_eq!(find(&v, id(0x10)).history.len(), 1, "an edit session");
    change_entry(&mut v, id(0x10), NOW, |e| e.set_tags(vec!["t".into()])).unwrap();
    move_entries(&mut v, &[id(0x10)], id(4), NOW).unwrap();
    assert_eq!(
        find(&v, id(0x10)).history.len(),
        1,
        "a tag click and a move make none"
    );
    assert!(
        find(&v, id(0x10)).history[0].value("Notes").is_empty(),
        "the copy from before the session"
    );
    ok(&v);
}

#[test]
fn mod_01_33_no_templates() {
    let mut v = sample();
    v.meta.entry_templates_group = Some(id(4));
    edit_entry(&mut v, id(0x10), NOW, |e| set(e, "Notes", "n")).unwrap();
    assert_eq!(v.meta.entry_templates_group, Some(id(4)), "carried only");
    ok(&v);
}

#[test]
fn mod_01_9_exactly_the_most_custom_fields() {
    let mut v = sample();
    let r = edit_entry(&mut v, id(0x11), NOW, |e| {
        for i in 0..MAX_CUSTOM {
            e.set_field(format!("f{i:06}"), field(""));
        }
    });
    assert_eq!(r, Ok(true), "99,995 custom fields are allowed");
    ok(&v);
}

#[test]
fn mod_01_22_group_icon_49_gives_0() {
    let mut v = sample();
    v.root.groups[1].icon = Icon::Standard(49);
    assert_eq!(new_entry(&v, id(4), true).unwrap().icon, Icon::Standard(0));
    ok(&v);
}

/// LD-105: a protected user name is never offered.
#[test]
fn mod_01_23_protected_user_names_left_out() {
    let mut v = sample();
    change_entry(&mut v, id(0x10), T0, |e| {
        e.set_field(
            "UserName".into(),
            Field {
                value: SecretString::new("demo-hidden".into()),
                protected: true,
            },
        );
    })
    .unwrap();
    change_entry(&mut v, id(0x11), T0, |e| set(e, "UserName", "demo-shown")).unwrap();
    assert_eq!(user_name_suggestions(&v), ["demo-shown"], "own flag");
    v.meta.memory_protection.user_name = true;
    assert!(user_name_suggestions(&v).is_empty(), "the vault's flag");
    ok(&v);
}

/// MOD-07.5 (the order of field name suggestions): digit runs come first.
#[test]
fn mod_01_24_digits_before_text() {
    assert_eq!(natural_cmp("1", "a"), Ordering::Less);
    assert_eq!(natural_cmp("a", "1"), Ordering::Greater);
    assert_eq!(natural_cmp("x 2", "x a"), Ordering::Less);
}

/// E4-B3: an edit never leaves two attachments with one name.
#[test]
fn mod_01_32_attachment_names_stay_unique() {
    let twins = || {
        [1u8, 2]
            .into_iter()
            .map(|b| Attachment {
                name: "a".into(),
                data: Arc::new(SecretBytes::new(vec![b])),
            })
            .collect()
    };
    let mut v = sample();
    let r = edit_entry(&mut v, id(0x10), NOW, |e| e.attachments = twins());
    assert_eq!(r, Err(Error::AttachmentName(NameProblem::Taken)));
    assert!(find(&v, id(0x10)).attachments.is_empty(), "nothing changed");
    let mut e = new_entry(&v, id(1), false).unwrap();
    e.attachments = twins();
    assert_eq!(
        add_entry(&mut v, id(1), e, NOW),
        Err(Error::AttachmentName(NameProblem::Taken))
    );
    ok(&v);
}

/// MOD-01.23 leaves out field references (MOD-08.24): `{`, `ref:` in any
/// case, then `@`, then `:`, then `}`.
#[test]
fn mod_01_23_what_counts_as_a_reference() {
    for yes in [
        "{REF:P@I:0011}",
        "{ref:u@t:demo}",
        "x{Ref:A@B:C}y",
        "{REF:x} and {REF:P@I:00}",
    ] {
        assert!(holds_reference(yes), "{yes}");
    }
    for no in [
        "",
        "{REF:P@I:0011",
        "{REF:PI:00}",
        "{REF:P@I00}",
        "REF:P@I:00}",
        "}:@{REF:",
        "{REF P@I:00}",
    ] {
        assert!(!holds_reference(no), "{no}");
    }
}
