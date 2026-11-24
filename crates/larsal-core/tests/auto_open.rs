//! F-079 (SR-10): APP-06.25's choice of vaults to auto-open and APP-06.26's
//! shared-group skip (LD-97), on demo entries.

mod common;

use common::*;
use larsal_core::auto_open::{GROUP, device_allows, targets};
use larsal_model::{CustomDataItem, Entry, Group, Vault};

fn mk(n: u8, fields: &[(&str, &str)]) -> Entry {
    let mut e = entry(n, "auto");
    for (k, v) in fields {
        e.set_field((*k).into(), field(v));
    }
    e
}

fn vault(entries: Vec<Entry>) -> Vault {
    let mut v = sample();
    let mut g = Group::new(id(9), GROUP.into(), T0);
    g.entries = entries;
    v.root.groups.push(g);
    v
}

fn paths(v: &Vault, host: &str) -> Vec<(String, Option<String>, Option<String>)> {
    targets(v, "/tmp/f079", host, NOW)
        .into_iter()
        .map(|t| {
            let pw = t.password.map(|p| p.expose().to_owned());
            (t.path, t.key_file, pw)
        })
        .collect()
}

#[test]
fn f_079_device_rule() {
    assert!(device_allows("!work-mac", "home.local"));
    assert!(!device_allows("!work-mac", "WORK-MAC"));
    assert!(device_allows("alice-mac, !work-mac", "bob.local"));
    assert!(!device_allows("alice-mac, !work-mac", "work-mac"));
    assert!(device_allows(" Alice-Mac ", "alice-mac"));
    assert!(!device_allows("alice-mac", "bob"));
    assert!(!device_allows("", "bob"));
    // A matching `!name` ends the rule: a later plain match does not undo it.
    assert!(!device_allows("!work-mac, work-mac", "work-mac"));
}

#[test]
fn f_079_auto_open_targets_follow_app_06_25() {
    let link = String::from_utf8(larsal_core::url::VAULT_LINK.to_vec()).unwrap();
    let v = vault(vec![
        // A relative path with a key file and a password resolved from a
        // placeholder.
        mk(
            0x20,
            &[
                ("URL", "b.larsalvault"),
                ("UserName", "b.larsalkey"),
                ("Password", "{TITLE}x"),
                ("Title", "pw"),
            ],
        ),
        // The vault link prefix and a file URL.
        mk(
            0x21,
            &[
                ("URL", &format!("{link}/tmp/other/c.larsalvault")),
                ("Password", "demo"),
            ],
        ),
        mk(
            0x22,
            &[
                ("URL", "file:///tmp/my%20d.larsalvault"),
                ("UserName", "/k.larsalkey"),
            ],
        ),
        // Skipped: no user name and no password; no URL.
        mk(0x23, &[("URL", "e.larsalvault")]),
        mk(0x24, &[("Password", "demo")]),
        // The device rule.
        mk(
            0x25,
            &[
                ("URL", "f.larsalvault"),
                ("Password", "demo"),
                ("IfDevice", "!this-mac"),
            ],
        ),
        mk(
            0x26,
            &[
                ("URL", "g.larsalvault"),
                ("Password", "demo"),
                ("IfDevice", "this-mac"),
            ],
        ),
    ]);
    assert_eq!(
        paths(&v, "This-Mac"),
        [
            (
                "/tmp/f079/b.larsalvault".into(),
                Some("/tmp/f079/b.larsalkey".into()),
                Some("pwx".into())
            ),
            ("/tmp/other/c.larsalvault".into(), None, Some("demo".into())),
            (
                "/tmp/my d.larsalvault".into(),
                Some("/k.larsalkey".into()),
                None
            ),
            ("/tmp/f079/g.larsalvault".into(), None, Some("demo".into())),
        ]
    );
    assert_eq!(paths(&v, "other-mac").len(), 4, "f opens, g does not");
}

#[test]
fn f_079_only_the_first_auto_open_group_under_the_root() {
    let mut v = vault(vec![mk(
        0x20,
        &[("URL", "a.larsalvault"), ("Password", "x")],
    )]);
    let mut second = Group::new(id(0x0a), GROUP.into(), T0);
    second
        .entries
        .push(mk(0x21, &[("URL", "b.larsalvault"), ("Password", "x")]));
    v.root.groups.push(second);
    // A deeper group of that name and another letter case count for nothing.
    let mut lower = Group::new(id(0x0b), "autoopen".into(), T0);
    lower
        .entries
        .push(mk(0x22, &[("URL", "c.larsalvault"), ("Password", "x")]));
    v.root.groups[0].groups.push(lower);
    assert_eq!(paths(&v, "m").len(), 1);
    assert_eq!(paths(&v, "m")[0].0, "/tmp/f079/a.larsalvault");
}

/// LD-97 (APP-06.26): an `AutoOpen` group that is, or lies in, a share
/// opens nothing.
#[test]
fn f_079_shared_auto_open_group_is_skipped() {
    let key = String::from_utf8(vec![
        0x4B, 0x65, 0x65, 0x53, 0x68, 0x61, 0x72, 0x65, 0x2F, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65,
        0x6E, 0x63, 0x65,
    ])
    .unwrap();
    let item = CustomDataItem {
        key,
        value: larsal_crypto::secret::SecretString::new("x".into()),
        last_modified: None,
        unknown: Vec::new(),
    };
    let base = || {
        vault(vec![mk(
            0x20,
            &[("URL", "a.larsalvault"), ("Password", "x")],
        )])
    };
    assert_eq!(paths(&base(), "m").len(), 1);
    let mut v = base();
    let share = item.clone();
    v.root
        .groups
        .last_mut()
        .unwrap()
        .custom_data
        .items
        .push(share);
    assert!(paths(&v, "m").is_empty(), "the group is a share");
    let mut v = base();
    v.root.custom_data.items.push(item);
    assert!(paths(&v, "m").is_empty(), "the whole vault is a share");
}
