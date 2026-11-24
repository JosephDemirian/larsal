//! E11-S3: MOD-08.32, a reference inside a share group finds only what that
//! share sends (LD-279 (2), LD-284, F-142), and MOD-08.27's scope sentence
//! (LD-284 (2)). Rows 08-63 to 08-73 of MOD-08, on INT-08's vault V as a
//! share member B holds it (S). Each test names its row.

mod common;

use common::*;
use core::cell::Cell;
use larsal_core::recycle::{References, delete_entries};
use larsal_core::refs::{Context, EntryIndex, copy_context, reference, resolve};
use larsal_core::search::run::{Options, search};
use larsal_crypto::secret::SecretString;
use larsal_format::share_item::{KEY, Settings};
use larsal_model::{CustomDataItem, Entry, Field, Group, Vault};

fn set(e: &mut Entry, name: &str, value: &str) {
    let protected = name == "Password";
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(value.into()),
            protected,
        },
    );
}

fn mk(n: u8, title: &str, fields: &[(&str, &str)]) -> Entry {
    let mut e = entry(n, title);
    for (k, v) in fields {
        set(&mut e, k, v);
    }
    e
}

/// A share item: Synchronize to `team.larsalvault` with `demo-share-1`.
fn sync(keep_groups: bool) -> SecretString {
    let mut s = Settings {
        import: true,
        export: true,
        path: "team.larsalvault".into(),
        password: SecretString::new("demo-share-1".into()),
        keep_groups,
        ..Settings::new()
    };
    s.write().unwrap()
}

fn inactive(keep_groups: bool) -> SecretString {
    let mut s = Settings {
        keep_groups,
        ..Settings::new()
    };
    s.write().unwrap()
}

/// Gives `g` the share item `value` (replacing one it has).
fn put(g: &mut Group, value: SecretString) {
    let key = String::from_utf8(KEY.to_vec()).unwrap();
    g.custom_data.items.retain(|i| i.key != key);
    g.custom_data.items.push(CustomDataItem {
        key,
        value,
        last_modified: None,
        unknown: Vec::new(),
    });
}

fn group_mut(v: &mut Vault, n: u8) -> &mut Group {
    let mut stack = vec![&mut v.root];
    while let Some(g) = stack.pop() {
        if g.uuid == id(n) {
            return g;
        }
        stack.extend(g.groups.iter_mut());
    }
    panic!("group {n:02x}");
}

/// S of 08-63: V (Team(20) with an approved Synchronize item, keep on;
/// Mail(0A) ann/pw-1, Bank(0B) pw-b, Sub(21) with Wiki(0C) pw-w), the
/// imported Team wiki(44), and Home(30) outside Team with Gmail(0F).
fn s() -> Vault {
    let mut sub = Group::new(id(0x21), "Sub".into(), T0);
    sub.entries.push(mk(0x0C, "Wiki", &[("Password", "pw-w")]));
    let mut team = Group::new(id(0x20), "Team".into(), T0);
    team.entries.push(mk(
        0x0A,
        "Mail",
        &[("UserName", "ann"), ("Password", "pw-1")],
    ));
    team.entries.push(mk(0x0B, "Bank", &[("Password", "pw-b")]));
    team.entries.push(mk(
        0x44,
        "Team wiki",
        &[
            ("Password", "{REF:P@U:ann@example.com}"),
            ("URL", "https://evil.example/login"),
        ],
    ));
    team.groups.push(sub);
    put(&mut team, sync(true));
    let mut home = Group::new(id(0x30), "Home".into(), T0);
    home.entries.push(mk(
        0x0F,
        "Gmail",
        &[
            ("UserName", "ann@example.com"),
            ("Password", "gmail-secret-demo"),
        ],
    ));
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups.push(team);
    root.groups.push(home);
    Vault::new(root, T0)
}

/// 08-64's additions: Alias(0D), Team wiki 2(45), Team wiki 3(46).
fn s64() -> Vault {
    let mut v = s();
    let team = group_mut(&mut v, 0x20);
    team.entries.push(mk(
        0x0D,
        "Alias",
        &[("Password", "{REF:P@I:0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B}")],
    ));
    team.entries
        .push(mk(0x45, "Team wiki 2", &[("Password", "{REF:P@U:ann}")]));
    team.entries
        .push(mk(0x46, "Team wiki 3", &[("Password", "{REF:P@T:Wiki}")]));
    v
}

/// The full resolution of Copy (MOD-08.25). It also resolves through one
/// index, as search and Auto-Type do, and checks that both give the same
/// text (F-156: the index holds each entry's share scope).
fn copy(v: &Vault, n: u8, field: &str) -> String {
    let e = find(v, id(n));
    let meter = Cell::new(larsal_core::refs::COPY_BUDGET);
    let walked = resolve(e.value(field), e, &copy_context(v, "", NOW, &meter));
    let index = EntryIndex::new(v);
    let meter = Cell::new(larsal_core::refs::COPY_BUDGET);
    let ctx = Context {
        index: Some(&index),
        ..copy_context(v, "", NOW, &meter)
    };
    let indexed = resolve(e.value(field), e, &ctx);
    assert_eq!(
        indexed.text.expose(),
        walked.text.expose(),
        "{n:02x} {field}"
    );
    walked.text.expose().to_owned()
}

/// The preview's display resolution (MOD-08.23).
fn shown(v: &Vault, n: u8, field: &str) -> String {
    let e = find(v, id(n));
    let ctx = Context {
        display: true,
        ..Context::new(Some(v), NOW)
    };
    resolve(e.value(field), e, &ctx).text.expose().to_owned()
}

/// F-142 (LD-279 (2)): the planted reference never reads the member's own
/// Gmail password, by copy or by the preview; the search for that password
/// lists Gmail and not Team wiki (MOD-08.15).
#[test]
fn mod08_63_f142_a_planted_reference_finds_nothing_outside_the_share() {
    let v = s();
    assert_eq!(
        find(&v, id(0x44)).value("Password"),
        "{REF:P@U:ann@example.com}"
    );
    assert_eq!(copy(&v, 0x44, "Password"), "");
    assert_eq!(shown(&v, 0x44, "Password"), "");
    let found = search(&v, "pw:gmail-secret-demo", &Options::new(NOW)).unwrap();
    assert_eq!(found.ids, [id(0x0F)]);
    // An entry outside every share group still finds Gmail.
    let mut w = s();
    group_mut(&mut w, 0x30).entries.push(mk(
        0x31,
        "Outside",
        &[("Password", "{REF:P@U:ann@example.com}")],
    ));
    assert_eq!(copy(&w, 0x31, "Password"), "gmail-secret-demo");
}

#[test]
fn mod08_64_the_shares_own_references_still_work() {
    let v = s64();
    assert_eq!(copy(&v, 0x0D, "Password"), "pw-b");
    assert_eq!(copy(&v, 0x45, "Password"), "pw-1");
    assert_eq!(copy(&v, 0x46, "Password"), "pw-w");
}

#[test]
fn mod08_65_a_group_inside_the_share_group_searches_the_share() {
    let mut v = s();
    group_mut(&mut v, 0x21).entries.push(mk(
        0x47,
        "Sub ref",
        &[
            ("Password", "{REF:P@T:Mail}"),
            ("Notes", "{REF:P@U:ann@example.com}"),
        ],
    ));
    assert_eq!(copy(&v, 0x47, "Password"), "pw-1");
    assert_eq!(copy(&v, 0x47, "Notes"), "");
}

#[test]
fn mod08_66_the_innermost_share_group_wins() {
    let mut v = s64();
    let mut inner = Settings {
        import: true,
        path: "x.larsalvault".into(),
        password: SecretString::new("p".into()),
        ..Settings::new()
    };
    let sub = group_mut(&mut v, 0x21);
    put(sub, inner.write().unwrap());
    sub.entries.push(mk(
        0x47,
        "Sub ref",
        &[
            ("Password", "{REF:P@T:Mail}"),
            ("UserName", "{REF:P@T:Wiki}"),
        ],
    ));
    assert_eq!(copy(&v, 0x47, "Password"), "");
    assert_eq!(copy(&v, 0x47, "UserName"), "pw-w");
    assert_eq!(copy(&v, 0x46, "Password"), "pw-w");
}

#[test]
fn mod08_67_each_chain_step_keeps_its_own_scope() {
    let mut v = s64();
    group_mut(&mut v, 0x20)
        .entries
        .push(mk(0x48, "Chain", &[("Password", "{REF:P@T:Team wiki}")]));
    group_mut(&mut v, 0x30).entries.push(mk(
        0x31,
        "Outside",
        &[
            ("Password", "{REF:P@T:Mail}"),
            ("UserName", "{REF:P@T:Team wiki}"),
        ],
    ));
    assert_eq!(copy(&v, 0x48, "Password"), "");
    assert_eq!(copy(&v, 0x31, "Password"), "pw-1");
    assert_eq!(copy(&v, 0x31, "UserName"), "");
}

#[test]
fn mod08_68_any_share_item_counts() {
    let mut v = s();
    put(group_mut(&mut v, 0x20), inactive(true));
    assert_eq!(copy(&v, 0x44, "Password"), "");
    put(
        group_mut(&mut v, 0x20),
        SecretString::new("not base64 !!".into()),
    );
    assert_eq!(copy(&v, 0x44, "Password"), "");
    // An Import item that arrived by merge and was never approved: the
    // scope does not ask for approval (INT-08.31).
    let mut merged = Settings {
        import: true,
        path: "elsewhere.larsalvault".into(),
        keep_groups: true,
        ..Settings::new()
    };
    put(group_mut(&mut v, 0x20), merged.write().unwrap());
    assert_eq!(copy(&v, 0x44, "Password"), "");
}

#[test]
fn mod08_69_a_root_share_leaves_the_recycle_bin_out() {
    let mut bin = Group::new(id(0x50), "Recycle Bin".into(), T0);
    bin.entries.push(mk(
        0x0F,
        "Gmail",
        &[
            ("UserName", "ann@example.com"),
            ("Password", "gmail-secret-demo"),
        ],
    ));
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.entries.push(mk(
        0x44,
        "Planted",
        &[("Password", "{REF:P@U:ann@example.com}")],
    ));
    root.groups.push(bin);
    let mut export = Settings {
        export: true,
        path: "all.larsalvault".into(),
        keep_groups: true,
        ..Settings::new()
    };
    put(&mut root, export.write().unwrap());
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = true;
    v.meta.recycle_bin = Some(id(0x50));
    assert_eq!(copy(&v, 0x44, "Password"), "");
    // Restored to the root: now in what the share sends.
    let gmail = v.root.groups[0].entries.remove(0);
    v.root.entries.push(gmail);
    assert_eq!(copy(&v, 0x44, "Password"), "gmail-secret-demo");
}

/// 08-70's S: Team's item keep off (still Synchronize); Sub holds
/// Private(49); Team holds Team note(4A).
fn s70() -> Vault {
    let mut v = s64();
    put(group_mut(&mut v, 0x20), sync(false));
    group_mut(&mut v, 0x21).entries.push(mk(
        0x49,
        "Private",
        &[("UserName", "pat"), ("Password", "private-demo")],
    ));
    group_mut(&mut v, 0x20).entries.push(mk(
        0x4A,
        "Team note",
        &[
            ("Password", "{REF:P@U:pat}"),
            ("URL", "https://evil.example/login"),
        ],
    ));
    v
}

#[test]
fn mod08_70_keep_off_sends_only_the_share_groups_own_entries() {
    let mut v = s70();
    for _ in 0..2 {
        assert_eq!(copy(&v, 0x4A, "Password"), "");
        assert_eq!(shown(&v, 0x4A, "Password"), "");
        assert_eq!(copy(&v, 0x46, "Password"), "");
        assert_eq!(copy(&v, 0x0D, "Password"), "pw-b");
        // The mode does not change the scope.
        put(group_mut(&mut v, 0x20), inactive(false));
    }
    put(group_mut(&mut v, 0x20), inactive(true));
    assert_eq!(copy(&v, 0x4A, "Password"), "private-demo");
    assert_eq!(copy(&v, 0x46, "Password"), "pw-w");
}

#[test]
fn mod08_71_an_entry_below_a_keep_off_share_group() {
    let mut v = s();
    put(group_mut(&mut v, 0x20), sync(false));
    let sub = group_mut(&mut v, 0x21);
    sub.entries.push(mk(
        0x47,
        "Sub ref",
        &[
            ("Password", "{REF:P@T:Mail}"),
            ("Notes", "{REF:P@U:ann@example.com}"),
        ],
    ));
    sub.entries.push(mk(
        0x4B,
        "Sib",
        &[
            ("Password", "{REF:P@T:Wiki}"),
            ("UserName", "{REF:T@I:{UUID}}"),
        ],
    ));
    assert_eq!(copy(&v, 0x47, "Password"), "pw-1");
    assert_eq!(copy(&v, 0x47, "Notes"), "");
    assert_eq!(copy(&v, 0x4B, "Password"), "");
    assert_eq!(copy(&v, 0x4B, "UserName"), "");
}

#[test]
fn mod08_72_a_share_item_that_cannot_be_read() {
    let mut v = s64();
    let wrong_root = larsal_crypto::base64::encode(
        larsal_crypto::base64::Form::Padded,
        b"<?xml version=\"1.0\"?><X><KeepGroups>True</KeepGroups></X>",
    );
    for value in ["not base64 !!".to_owned(), wrong_root] {
        put(group_mut(&mut v, 0x20), SecretString::new(value));
        assert_eq!(copy(&v, 0x46, "Password"), "");
        assert_eq!(copy(&v, 0x0D, "Password"), "pw-b");
        assert_eq!(copy(&v, 0x44, "Password"), "");
    }
}

#[test]
fn mod08_73_delete_never_counts_a_reference_from_inside_a_share() {
    let gmail_ref = "{REF:P@I:0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F}";
    let mut first = s();
    // Deleted for good at once (MOD-04.4), so MOD-08.27 runs.
    first.meta.recycle_bin_enabled = false;
    group_mut(&mut first, 0x20)
        .entries
        .push(mk(0x4C, "Y", &[("Password", gmail_ref)]));
    let mut second = first.duplicate();
    group_mut(&mut second, 0x30)
        .entries
        .push(mk(0x32, "Z", &[("Password", gmail_ref)]));
    // First copy: Y is not counted, so nothing is asked.
    let mut asked = Vec::new();
    delete_entries(&mut first, &[id(0x0F)], NOW, |_, n| {
        asked.push(n);
        References::Overwrite
    })
    .unwrap();
    assert!(asked.is_empty());
    let y = find(&first, id(0x4C));
    assert_eq!(y.value("Password"), gmail_ref);
    assert_eq!(y.times.last_modification, T0);
    assert_eq!(copy(&first, 0x4C, "Password"), "");
    // Second copy: Z only is counted and overwritten.
    let mut asked = Vec::new();
    delete_entries(&mut second, &[id(0x0F)], NOW, |_, n| {
        asked.push(n);
        References::Overwrite
    })
    .unwrap();
    assert_eq!(asked, [1]);
    assert_eq!(
        find(&second, id(0x32)).value("Password"),
        "gmail-secret-demo"
    );
    assert_eq!(find(&second, id(0x4C)).value("Password"), gmail_ref);
    let team = second.root.find_group(id(0x20)).unwrap();
    assert!(team.all_entries().all(|e| {
        e.fields()
            .all(|(_, f)| !f.value.expose().contains("gmail-secret-demo"))
    }));
}

/// F-156's vault: 3 groups of 1,000 entries under `top`; entry 0 of the
/// first group has UserName `alexander` and every other entry the
/// UserName `{REF:U@I:<entry 0>}`, or, with `last`, entry 0 is the last
/// entry of the last group.
fn many(mut top: Group, last: bool) -> Vault {
    let target = larsal_model::Uuid([0xEE; 16]);
    let mut n = 0u32;
    for g in 0..3u8 {
        let mut group = Group::new(id(0x60 + g), format!("G{g}"), T0);
        for _ in 0..1_000 {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&n.to_be_bytes());
            bytes[4] = 0x77;
            let mut e = Entry::new(larsal_model::Uuid(bytes), T0);
            set(&mut e, "UserName", &reference('U', target));
            group.entries.push(e);
            n += 1;
        }
        top.groups.push(group);
    }
    let at = if last { (2, 999) } else { (0, 0) };
    let e = &mut top.groups[at.0].entries[at.1];
    e.uuid = target;
    set(e, "UserName", "alexander");
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups.push(top);
    Vault::new(root, T0)
}

/// F-156 (FEA-01.32, LD-126 (3)): with no share group, a search that
/// resolves 3,000 id references looks each one up in the index and never
/// walks the vault to find a scope, so it finds every entry within its
/// budget and shows no limit notice.
#[test]
fn f156_id_references_with_no_share_group_search_within_the_budget() {
    let v = many(Group::new(id(0x20), "Top".into(), T0), false);
    let found = search(&v, "user:alexander", &Options::new(NOW)).unwrap();
    assert_eq!(found.ids.len(), 3_000);
    assert!(!found.invalid);
}

/// F-156 inside a share group (MOD-08.32, Keep group structure on): the id
/// is still one lookup, checked against the scope, also when the entry it
/// finds is the share's last.
#[test]
fn f156_id_references_inside_a_share_group_search_within_the_budget() {
    let mut team = Group::new(id(0x20), "Team".into(), T0);
    put(&mut team, sync(true));
    let v = many(team, true);
    let found = search(&v, "user:alexander", &Options::new(NOW)).unwrap();
    assert_eq!(found.ids.len(), 3_000);
    assert!(!found.invalid);
}

/// MOD-08.32 with an id two entries hold (FMT-11.35): the root's copy of
/// Bank's id comes first in the vault, but Alias inside Team finds Team's
/// Bank, and an entry outside every share group finds the root's copy.
#[test]
fn mod08_64_a_repeated_id_finds_the_entry_inside_the_share() {
    let mut v = s64();
    v.root
        .entries
        .push(mk(0x0B, "Root copy", &[("Password", "root-dup")]));
    group_mut(&mut v, 0x30).entries.push(mk(
        0x31,
        "Outside",
        &[("Password", "{REF:P@I:0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B}")],
    ));
    assert_eq!(copy(&v, 0x0D, "Password"), "pw-b");
    assert_eq!(copy(&v, 0x31, "Password"), "root-dup");
}

/// MOD-08.32 with keep off on a share item the recycle bin itself carries:
/// the scope is the share group's own entries, so an entry in the bin finds
/// the bin's other entries (the bin is left out only with keep on).
#[test]
fn mod08_32_keep_off_on_the_recycle_bin_searches_its_own_entries() {
    let mut bin = Group::new(id(0x50), "Recycle Bin".into(), T0);
    bin.entries.push(mk(
        0x0F,
        "Gmail",
        &[
            ("UserName", "ann@example.com"),
            ("Password", "gmail-secret-demo"),
        ],
    ));
    bin.entries.push(mk(
        0x44,
        "Planted",
        &[("Password", "{REF:P@U:ann@example.com}")],
    ));
    put(&mut bin, inactive(false));
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups.push(bin);
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = true;
    v.meta.recycle_bin = Some(id(0x50));
    assert_eq!(copy(&v, 0x44, "Password"), "gmail-secret-demo");
}

/// MOD-08.32 with LD-281 (4) and keep on, on a share item the recycle bin
/// itself carries: the bin's subtree is left out of what the share sends,
/// so an entry in the bin finds nothing, by the walk and by the index alike
/// (F-159 K2).
#[test]
fn mod08_32_keep_on_on_the_recycle_bin_leaves_the_bin_out() {
    let mut bin = Group::new(id(0x50), "Recycle Bin".into(), T0);
    bin.entries.push(mk(
        0x0F,
        "Gmail",
        &[
            ("UserName", "ann@example.com"),
            ("Password", "gmail-secret-demo"),
        ],
    ));
    bin.entries.push(mk(
        0x44,
        "Planted",
        &[("Password", "{REF:P@U:ann@example.com}")],
    ));
    put(&mut bin, sync(true));
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups.push(bin);
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = true;
    v.meta.recycle_bin = Some(id(0x50));
    assert_eq!(copy(&v, 0x44, "Password"), "");
}
