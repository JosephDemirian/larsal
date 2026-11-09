//! Checker 1, round 4: directed attacks on rule R6 at more depth than the model, ported in
//! round 5. Demo data only. Each test prints what it saw. Changed assertions say so where
//! they stand: b1 and b2 hold the rows an import now writes (C1R4-01); f1, f2 and f3 pin
//! limit 18 (C1R4-02); g1, g2 and the item-limit tests hold the guards (C1R4-03, C1R4-04);
//! q1 pins a finding older than R6 (C1R4-07); the cycle pins limit 19 (C1R4-06).
#![allow(clippy::all, clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use larsal_core::edit::{self, Position};
use larsal_core::merge::{Kind, Options, merge};
use larsal_core::origin;
use larsal_core::recycle::{self, References};
use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved};
use larsal_model::settings::Kdf;
use larsal_model::{CustomDataItem, DeletedObject, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};
use std::collections::BTreeMap;

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
const S2: u8 = 0x22;
const S3: u8 = 0x23;
const V: u8 = 0x24;
const P: u8 = 0x30;
const BIN: u8 = 0x5a;
const E: u8 = 0x50;

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
fn entry(n: u8, p: &str, m: Time) -> Entry {
    let mut e = Entry::new(id(n), T0);
    pw(&mut e, p);
    e.times.last_modification = m;
    e.times.location_changed = m;
    e
}
fn plain_item(key: String) -> CustomDataItem {
    CustomDataItem {
        key,
        value: SecretString::new(String::new()),
        last_modified: None,
        unknown: Vec::new(),
    }
}
fn share_item() -> CustomDataItem {
    plain_item(core::str::from_utf8(edit::SHARED_KEY).unwrap().to_owned())
}
/// `n` custom data items of the owner's own, none of the rule's.
fn fill(e: &mut Entry, n: usize) {
    for i in 0..n {
        e.custom_data.items.push(plain_item(format!("k{i}")));
    }
}
/// Root: P, T{S{S2{S3}}, V}, Bin. Shares named by `shares`.
fn world(shares: &[u8]) -> Vault {
    let mut root = Group::new(id(ROOT), "Root".into(), T0);
    let mut t = Group::new(id(T), "T".into(), T0);
    let mut s = Group::new(id(S), "S".into(), T0);
    let mut s2 = Group::new(id(S2), "S2".into(), T0);
    s2.groups.push(Group::new(id(S3), "S3".into(), T0));
    s.groups.push(s2);
    t.groups.push(s);
    t.groups.push(Group::new(id(V), "V".into(), T0));
    root.groups.push(Group::new(id(P), "P".into(), T0));
    root.groups.push(t);
    root.groups.push(Group::new(id(BIN), "Bin".into(), T0));
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = true;
    v.meta.recycle_bin = Some(id(BIN));
    v.meta.history_max_items = -1;
    v.meta.history_max_size = -1;
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    for s in shares {
        gm(&mut v.root, *s).custom_data.items.push(share_item());
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
fn save_bytes(v: &Vault) -> Result<Vec<u8>, String> {
    let p = SecretString::new("demo".to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    let mut h = host();
    match larsal_format::save(v, &key, None, &mut h, &Limits::DEFAULT, None)
        .map_err(|e| format!("{e:?}"))?
    {
        Saved::File(f) => Ok(f.bytes),
        Saved::Ask(r) => {
            match larsal_format::save(v, &key, None, &mut h, &Limits::DEFAULT, Some(&r))
                .map_err(|e| format!("{e:?}"))?
            {
                Saved::File(f) => Ok(f.bytes),
                Saved::Ask(_) => Err("asked twice".into()),
            }
        }
    }
}
fn rt(v: &Vault) -> Vault {
    let bytes = save_bytes(v).unwrap();
    let p = SecretString::new("demo".to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    match larsal_format::open(&bytes, &key, &mut host(), &Limits::DEFAULT, None).unwrap() {
        Opened::Vault(o) => o.vault,
        Opened::Ask(_) => panic!("asked"),
    }
}
fn m(t: &mut Vault, s: &Vault, kind: Kind, n: i64) {
    let source = rt(s);
    merge(t, &source, &Options::new(kind), at(n)).unwrap();
    *t = rt(t);
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
fn has(v: &Vault, n: u8) -> bool {
    walk_e(&v.root, n).is_some()
}
fn show(v: &Vault, n: u8) -> String {
    match walk_e(&v.root, n) {
        None => "GONE".to_owned(),
        Some((p, e)) => format!(
            "in {:02x} pw {} hist [{}]",
            p.0[0],
            e.value("Password"),
            e.history
                .iter()
                .map(|h| format!(
                    "{}{}",
                    h.value("Password"),
                    if origin::private_item(h) { "!" } else { "" }
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
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
/// A member's vault holding one share, `share`, under its own root.
fn member_of(share: u8, root: u8) -> Vault {
    let mut v = Vault::new(Group::new(id(root), "Member root".into(), T0), T0);
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    v.meta.recycle_bin_enabled = false;
    let mut g = Group::new(id(share), "Share".into(), T0);
    g.custom_data.items.push(share_item());
    v.root.groups.push(g);
    v
}
fn export(v: &Vault, share: u8, n: i64) -> Vault {
    let mut c = container::build(id(share), true, v, at(n)).unwrap();
    c.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    c
}
fn listed(c: &Vault) -> Vec<u8> {
    c.deleted_objects.iter().map(|d| d.uuid.0[0]).collect()
}
fn import(v: &mut Vault, share: u8, c: &Vault, n: i64) {
    run::merge_into(v, id(share), c, at(n)).unwrap();
}
/// A container written to a real file and read back, as a member's file arrives.
fn through_a_file(c: &Vault) -> Vault {
    let p = SecretString::new("demo-share".to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    let bytes =
        match larsal_format::save(c, &key, None, &mut host(), &Limits::DEFAULT, None).unwrap() {
            Saved::File(f) => f.bytes,
            Saved::Ask(_) => panic!("asked"),
        };
    container::open(&bytes, &p, &mut host(), &Limits::DEFAULT)
        .unwrap()
        .vault
}

// ---------------- Rows at depth ----------------

/// A1: a chain of four nested shares; the user deletes for good an entry in the innermost.
/// One row per share; each share's export lists it; each share's member erases it.
#[test]
fn a1_depth_four_a_users_deletion_reaches_a_member_of_every_share() {
    let mut a = world(&[T, S, S2, S3]);
    gm(&mut a.root, S3)
        .entries
        .push(entry(E, "deep-demo", at(1)));
    let shares = [T, S, S2, S3];
    let mut members: Vec<Vault> = shares
        .iter()
        .enumerate()
        .map(|(i, s)| member_of(*s, 0x70 + i as u8))
        .collect();
    for (i, s) in shares.iter().enumerate() {
        let c = export(&a, *s, 2);
        import(&mut members[i], *s, &c, 3);
        assert!(has(&members[i], E), "member of {s:02x} holds E");
    }
    del(&mut a, E, at(10));
    println!("a1 rows: {}", rows(&a));
    assert_eq!(
        origin::read_rows(&a.meta.custom_data).len(),
        4,
        "{}",
        rows(&a)
    );
    let a = rt(&a);
    let text = a.meta.custom_data.get(origin::SCOPES).unwrap().to_owned();
    assert_eq!(text.len(), 4 * 33 + 4 * 45 - 1, "{text}");
    for (i, s) in shares.iter().enumerate() {
        let c = export(&a, *s, 11);
        println!("a1 export of {s:02x} lists {:02x?}", listed(&c));
        assert_eq!(listed(&c), vec![E], "export of {s:02x}");
        import(&mut members[i], *s, &c, 12);
        assert!(!has(&members[i], E), "member of {s:02x} keeps E");
    }
}

/// A2: a member of the innermost share deletes; the user's Mac passes it on to the member of
/// every outer share, one export each.
#[test]
fn a2_depth_four_an_inner_members_deletion_reaches_every_outer_member() {
    let mut a = world(&[T, S, S2, S3]);
    gm(&mut a.root, S3)
        .entries
        .push(entry(E, "deep-demo", at(1)));
    let shares = [T, S, S2, S3];
    let mut members: Vec<Vault> = shares
        .iter()
        .enumerate()
        .map(|(i, s)| member_of(*s, 0x70 + i as u8))
        .collect();
    for (i, s) in shares.iter().enumerate() {
        let c = export(&a, *s, 2);
        import(&mut members[i], *s, &c, 3);
    }
    del(&mut members[3], E, at(10));
    let back = export(&members[3], S3, 11);
    import(&mut a, S3, &back, 12);
    println!("a2 a rows: {} | a {}", rows(&a), show(&a, E));
    assert!(!has(&a, E));
    for (i, s) in shares.iter().enumerate().take(3) {
        let c = export(&a, *s, 13);
        import(&mut members[i], *s, &c, 14);
        println!("a2 member of {s:02x}: {}", show(&members[i], E));
        assert!(!has(&members[i], E), "member of {s:02x} keeps E");
    }
}

/// A3: C1-01 at depth. E sits in S (not in S2 or S3) on both Macs. A member of S3 lists E.
/// Nothing in T, S or S2 may erase it.
#[test]
fn a3_depth_a_member_of_the_innermost_cannot_erase_in_an_outer_share() {
    for kind in KINDS {
        let mut a = world(&[T, S, S2, S3]);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut b = a.duplicate();
        let shares = [T, S, S2];
        let mut members: Vec<Vault> = shares
            .iter()
            .enumerate()
            .map(|(i, s)| member_of(*s, 0x70 + i as u8))
            .collect();
        for (i, s) in shares.iter().enumerate() {
            let c = export(&a, *s, 2);
            import(&mut members[i], *s, &c, 3);
        }
        let mut cont = Vault::new(Group::new(id(S3), "C".into(), T0), T0);
        cont.meta.recycle_bin_enabled = false;
        cont.deleted_objects.push(DeletedObject {
            uuid: id(E),
            deleted_at: at(5),
            unknown: Vec::new(),
        });
        import(&mut a, S3, &cont, 10);
        assert!(has(&a, E));
        for (i, s) in shares.iter().enumerate() {
            let c = export(&a, *s, 11);
            assert!(
                !listed(&c).contains(&E),
                "{kind:?} export of {s:02x} lists E"
            );
            import(&mut members[i], *s, &c, 12);
            if *s != S2 {
                assert!(has(&members[i], E), "{kind:?} member of {s:02x} lost E");
            }
        }
        settle(&mut a, &mut b, kind, 20);
        assert!(
            has(&a, E) && has(&b, E),
            "{kind:?}: a {} b {}",
            show(&a, E),
            show(&b, E)
        );
    }
}

/// A4: side by side inside an outer share: T holds S and V. A member of V lists E, which is
/// in S. Neither T's nor S's export may carry it.
#[test]
fn a4_side_by_side_inside_t() {
    let mut a = world(&[T, S, V]);
    gm(&mut a.root, S)
        .entries
        .push(entry(E, "in-s-demo", at(1)));
    let mut cont = Vault::new(Group::new(id(V), "C".into(), T0), T0);
    cont.meta.recycle_bin_enabled = false;
    cont.deleted_objects.push(DeletedObject {
        uuid: id(E),
        deleted_at: at(5),
        unknown: Vec::new(),
    });
    import(&mut a, V, &cont, 10);
    println!("a4 rows {}", rows(&a));
    assert!(has(&a, E));
    for s in [T, S] {
        let c = export(&a, s, 11);
        assert!(!listed(&c).contains(&E), "export of {s:02x} lists E");
    }
}

// ---------------- Outer member's deletion and a nested share's member ----------------

/// B1 (C1R4-01): a member of the outer share T deletes E, which sits in nested S. The
/// user's Mac erases it at the import of T's file and writes a row for S too, as the
/// user's own delete does, so the member of S, who is not a member of T, hears of it.
#[test]
fn b1_an_outer_members_deletion_in_a_nested_share_reaches_its_member() {
    for kind in KINDS {
        let mut a = world(&[T, S]);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut b = a.duplicate();
        let mut ms = member_of(S, 0x70);
        let mut mt = member_of(T, 0x71);
        import(&mut ms, S, &export(&a, S, 2), 3);
        import(&mut mt, T, &export(&a, T, 2), 3);
        assert!(has(&ms, E) && has(&mt, E));
        del(&mut mt, E, at(6));
        let back = export(&mt, T, 7);
        assert_eq!(listed(&back), vec![E]);
        import(&mut a, T, &back, 8);
        println!(
            "b1 {kind:?} a after T import: {} rows {}",
            show(&a, E),
            rows(&a)
        );
        assert!(!has(&a, E), "the member of T's deletion reaches the user");
        assert_eq!(
            rows(&a),
            "50/20/6 50/21/6",
            "one row per share E counted in"
        );
        // The other Mac of the user hears of it through a same-vault merge and passes it
        // on to S's member as well.
        settle(&mut a, &mut b, kind, 9);
        for (who, v) in [("a", &a), ("b", &b)] {
            let s_out = export(v, S, 30);
            assert_eq!(listed(&s_out), vec![E], "{kind:?}: S's export from {who}");
        }
        import(&mut ms, S, &export(&b, S, 31), 32);
        let s_back = export(&ms, S, 33);
        import(&mut a, S, &s_back, 34);
        println!("b1 {kind:?} end: ms {} | a {}", show(&ms, E), show(&a, E));
        assert!(
            !has(&ms, E),
            "{kind:?}: a member of T deleted E in S; the member of S keeps it"
        );
        assert!(!has(&a, E) && !has(&b, E));
    }
}

/// B2 (C1R4-01): as B1 at depth four: a member of T deletes E in S3; the members of S, S2
/// and S3 each hear of it.
#[test]
fn b2_depth_four_an_outer_members_deletion_reaches_inner_members() {
    let mut a = world(&[T, S, S2, S3]);
    gm(&mut a.root, S3)
        .entries
        .push(entry(E, "deep-demo", at(1)));
    let shares = [T, S, S2, S3];
    let mut members: Vec<Vault> = shares
        .iter()
        .enumerate()
        .map(|(i, s)| member_of(*s, 0x70 + i as u8))
        .collect();
    for (i, s) in shares.iter().enumerate() {
        let c = export(&a, *s, 2);
        import(&mut members[i], *s, &c, 3);
    }
    del(&mut members[0], E, at(6));
    import(&mut a, T, &export(&members[0], T, 7), 8);
    assert!(!has(&a, E));
    assert_eq!(rows(&a), "50/20/6 50/21/6 50/22/6 50/23/6");
    let mut kept = Vec::new();
    for (i, s) in shares.iter().enumerate().skip(1) {
        let c = export(&a, *s, 9);
        import(&mut members[i], *s, &c, 10);
        if has(&members[i], E) {
            kept.push(*s);
        }
    }
    println!("b2 members that keep E: {kept:02x?}");
    assert!(
        kept.is_empty(),
        "members of {kept:02x?} keep E a member of T deleted"
    );
}

/// B3 (C1R4-01): the rows an import writes are for shares inside the imported one only.
/// A member of S deletes E in S3; the import of S's file writes rows for S, S2 and S3, none
/// for T, which holds S: T's member hears through T's own rule (the nested row while the
/// Mac does not hold E).
#[test]
fn b3_an_import_writes_rows_inside_the_imported_share_only() {
    let mut a = world(&[T, S, S2, S3]);
    gm(&mut a.root, S3)
        .entries
        .push(entry(E, "deep-demo", at(1)));
    let mut ms = member_of(S, 0x70);
    import(&mut ms, S, &export(&a, S, 2), 3);
    del(&mut ms, E, at(6));
    import(&mut a, S, &export(&ms, S, 7), 8);
    assert!(!has(&a, E));
    assert_eq!(rows(&a), "50/21/6 50/22/6 50/23/6");
    assert_eq!(listed(&export(&a, T, 9)), vec![E]);
}

// ---------------- Limit 18: the not-held relay (C1R4-02) ----------------

/// F1, limit 18: all Macs hold E in S. Mac B moves E up to T. Before Mac A hears of the
/// move, a member of S deletes E; A takes S's file and erases its copy. A then exports T:
/// A no longer holds E, so T's export carries S's row, and the member of T, who holds E in
/// T outside S from B's export, erases it. Pinned: the user's Macs keep E, the member of T
/// does not; base does the same (C1R4-02).
#[test]
fn f1_limit_18_a_stale_nested_members_deletion_relayed_by_a_mac_not_holding_it() {
    for kind in KINDS {
        let mut a = world(&[T, S]);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut b = a.duplicate();
        let mut ms = member_of(S, 0x70);
        let mut mt = member_of(T, 0x71);
        import(&mut ms, S, &export(&a, S, 2), 3);
        import(&mut mt, T, &export(&a, T, 2), 3);
        edit::move_entries(&mut b, &[id(E)], id(T), at(5)).unwrap();
        import(&mut mt, T, &export(&b, T, 6), 7);
        del(&mut ms, E, at(8));
        import(&mut a, S, &export(&ms, S, 9), 10);
        let t_out = export(&a, T, 11);
        assert_eq!(listed(&t_out), vec![E], "{kind:?}: the relay");
        import(&mut mt, T, &t_out, 12);
        settle(&mut a, &mut b, kind, 20);
        import(&mut mt, T, &export(&a, T, 40), 41);
        import(&mut mt, T, &export(&b, T, 42), 43);
        let holders = [has(&a, E), has(&b, E), has(&mt, E)];
        println!("f1 {kind:?} a, b, mt hold E = {holders:?}");
        assert_eq!(holders, [true, true, false], "{kind:?}: limit 18 changed");
    }
}

/// F2, limit 18: F1, then the member of T exports T back and the user's Macs take it. The
/// stale deletion of a member of S then erases E in T outside S on every Mac. Control: B,
/// which heard of its own move, takes S's file first and keeps E.
#[test]
fn f2_limit_18_the_relay_round_trip_erases_everywhere() {
    for kind in KINDS {
        let mut a = world(&[T, S]);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut b = a.duplicate();
        let mut ms = member_of(S, 0x70);
        let mut mt = member_of(T, 0x71);
        import(&mut ms, S, &export(&a, S, 2), 3);
        import(&mut mt, T, &export(&a, T, 2), 3);
        edit::move_entries(&mut b, &[id(E)], id(T), at(5)).unwrap();
        import(&mut mt, T, &export(&b, T, 6), 7);
        del(&mut ms, E, at(8));
        let mut b_ctl = b.duplicate();
        import(&mut b_ctl, S, &export(&ms, S, 9), 10);
        assert!(has(&b_ctl, E), "{kind:?} control: B keeps E in T outside S");
        import(&mut a, S, &export(&ms, S, 9), 10);
        import(&mut mt, T, &export(&a, T, 11), 12);
        settle(&mut a, &mut b, kind, 20);
        import(&mut mt, T, &export(&a, T, 40), 41);
        import(&mut mt, T, &export(&b, T, 42), 43);
        let back = export(&mt, T, 50);
        assert_eq!(listed(&back), vec![E]);
        import(&mut a, T, &back, 51);
        import(&mut b, T, &back, 52);
        settle(&mut a, &mut b, kind, 60);
        import(&mut mt, T, &export(&a, T, 80), 81);
        let end = [has(&a, E), has(&b, E), has(&mt, E)];
        println!("f2 {kind:?} after the round trip a, b, mt hold E = {end:?}");
        assert_eq!(end, [false, false, false], "{kind:?}: limit 18 changed");
    }
}

/// F3, limit 18: side by side shares in T: E sits in V; the user, on B, moves E into its
/// sibling S. A stale member of V deletes E; Mac A, not yet told of the move, takes V's
/// file and relays. E goes on every Mac and on S's member.
#[test]
fn f3_limit_18_the_side_by_side_relay() {
    for kind in KINDS {
        let mut a = world(&[T, S, V]);
        gm(&mut a.root, V)
            .entries
            .push(entry(E, "in-v-demo", at(1)));
        let mut b = a.duplicate();
        let mut mv = member_of(V, 0x70);
        let mut mt = member_of(T, 0x71);
        let mut ms = member_of(S, 0x72);
        import(&mut mv, V, &export(&a, V, 2), 3);
        import(&mut mt, T, &export(&a, T, 2), 3);
        edit::move_entries(&mut b, &[id(E)], id(S), at(5)).unwrap();
        import(&mut mt, T, &export(&b, T, 6), 7);
        import(&mut ms, S, &export(&b, S, 6), 7);
        del(&mut mv, E, at(8));
        import(&mut a, V, &export(&mv, V, 9), 10);
        import(&mut mt, T, &export(&a, T, 11), 12);
        settle(&mut a, &mut b, kind, 20);
        let back = export(&mt, T, 50);
        import(&mut a, T, &back, 51);
        import(&mut b, T, &back, 52);
        settle(&mut a, &mut b, kind, 60);
        import(&mut mt, T, &export(&a, T, 80), 81);
        import(&mut ms, S, &export(&a, S, 82), 83);
        let end = [has(&a, E), has(&b, E), has(&mt, E), has(&ms, E)];
        println!("f3 {kind:?} a, b, mt, ms hold E = {end:?}");
        assert_eq!(end, [false; 4], "{kind:?}: limit 18 changed");
    }
}

// ---------------- Bin chains and pruning (mutants 4, 5, 17, 31, 34) ----------------

/// M17: group G1 in T, group G2 in the bin binned from G1. A member's list names both;
/// Mac B takes it, Mac A merges B. Both go in that one merge on A: G2 counts in T
/// through G1, and G1's erase hands G2 on to T (MOD-11.15).
#[test]
fn m17_a_bin_group_whose_old_group_goes_in_the_same_merge() {
    for kind in KINDS {
        let mut a = world(&[T]);
        gm(&mut a.root, T)
            .groups
            .push(Group::new(id(0x41), "G1".into(), T0));
        let mut g2 = Group::new(id(0x42), "G2".into(), T0);
        g2.previous_parent = Some(id(0x41));
        gm(&mut a.root, BIN).groups.push(g2);
        let mut b = a.duplicate();
        let mut c = Vault::new(Group::new(id(T), "T".into(), T0), T0);
        c.meta.recycle_bin_enabled = false;
        for n in [0x41u8, 0x42] {
            c.deleted_objects.push(DeletedObject {
                uuid: id(n),
                deleted_at: at(10),
                unknown: Vec::new(),
            });
        }
        import(&mut b, T, &c, 11);
        let src = b.duplicate();
        merge(&mut a, &src, &Options::new(kind), at(20)).unwrap();
        let left: Vec<u8> = [0x41u8, 0x42]
            .into_iter()
            .filter(|n| a.root.find_group(id(*n)).is_some())
            .collect();
        println!(
            "m17 {kind:?} rows on b {} | groups left on a {left:02x?}",
            rows(&b)
        );
        assert!(
            left.is_empty(),
            "{kind:?}: left on A after one merge: {left:02x?}"
        );
    }
}

/// M4, M5: pruning with private items keeps the history in time order.
#[test]
fn m4_m5_pruning_keeps_the_history_in_time_order() {
    let tag = |h: &mut Entry| {
        h.custom_data.items.push(CustomDataItem {
            key: origin::PRIVATE.to_owned(),
            value: SecretString::new("1".to_owned()),
            last_modified: None,
            unknown: Vec::new(),
        })
    };
    let mut e = entry(E, "now-demo", at(10));
    for (i, private) in [
        (1, false),
        (2, true),
        (3, false),
        (4, false),
        (5, true),
        (6, false),
    ] {
        let mut h = entry(E, &format!("v{i}"), at(i));
        h.history.clear();
        if private {
            tag(&mut h);
        }
        e.history.push(h);
    }
    larsal_core::history::prune(&mut e, 2, -1);
    let order: Vec<String> = e
        .history
        .iter()
        .map(|h| {
            format!(
                "{}{}",
                h.value("Password"),
                if origin::private_item(h) { "!" } else { "" }
            )
        })
        .collect();
    println!("m45 kept {order:?}");
    assert_eq!(order, ["v2!", "v4", "v5!", "v6"]);
}

/// M31, M34: G0 in T, G1 in G0, bin group G2 binned from G1. A member's list names G0 and
/// G1 (and, in the first case, G2). On the importing Mac and on a Mac that merges it: with
/// G2 named, all three go; without, G2 stays in the bin and names T, the group its old
/// groups' chain ends in (MOD-11.15), not a gone group. The importing Mac keeps its bin
/// item (an import touches nothing outside the share group; C1R4-10, limit 15).
#[test]
fn m31_m34_a_bin_group_whose_old_chain_goes_in_one_merge() {
    for named in [true, false] {
        let mut a = world(&[T]);
        let mut g0 = Group::new(id(0x41), "G0".into(), T0);
        g0.groups.push(Group::new(id(0x43), "G1".into(), T0));
        gm(&mut a.root, T).groups.push(g0);
        let mut g2 = Group::new(id(0x44), "G2".into(), T0);
        g2.previous_parent = Some(id(0x43));
        gm(&mut a.root, BIN).groups.push(g2);
        let mut b = a.duplicate();
        let mut c = Vault::new(Group::new(id(T), "T".into(), T0), T0);
        c.meta.recycle_bin_enabled = false;
        let list: &[u8] = if named {
            &[0x41, 0x43, 0x44]
        } else {
            &[0x41, 0x43]
        };
        for n in list {
            c.deleted_objects.push(DeletedObject {
                uuid: id(*n),
                deleted_at: at(10),
                unknown: Vec::new(),
            });
        }
        import(&mut b, T, &c, 11);
        let src = b.duplicate();
        merge(&mut a, &src, &Options::new(Kind::ChangeOnDisk), at(20)).unwrap();
        let state = |v: &Vault| -> (Vec<u8>, Option<u8>) {
            let left = [0x41u8, 0x43, 0x44]
                .into_iter()
                .filter(|n| v.root.find_group(id(*n)).is_some())
                .collect();
            let prev = v
                .root
                .find_group(id(0x44))
                .and_then(|g| g.previous_parent)
                .map(|p| p.0[0]);
            (left, prev)
        };
        println!(
            "m31 named {named}: b {:02x?} | a {:02x?}",
            state(&b),
            state(&a)
        );
        let want = if named {
            (vec![], None)
        } else {
            (vec![0x44u8], Some(T))
        };
        assert_eq!(state(&b), (vec![0x44u8], Some(T)), "named {named}: Mac B");
        assert_eq!(state(&a), want, "named {named}: Mac A");
    }
}

// ---------------- Private items (mutant 28, C1R4-03, C1R4-04) ----------------

/// G1 (C1R4-03): a stale inside edit loses to the user's move out. The losing copy carries
/// as many custom data items as one object may hold, so its version cannot take the
/// private tag: it is dropped (INT-08.32, at the item limit), never kept untagged, and the
/// vault still saves. A version below the limit stays, private.
#[test]
fn g1_a_private_tag_at_the_custom_data_item_limit() {
    let limit = Limits::DEFAULT.custom_data_items;
    for (have, kept) in [(limit, false), (limit - 1, true)] {
        let mut a = world(&[T]);
        gm(&mut a.root, T)
            .entries
            .push(entry(E, "seed-demo", at(1)));
        let mut b = a.duplicate();
        edit::edit_entry(&mut b, id(E), at(10), |d| {
            pw(d, "inside-demo");
            fill(d, have);
        })
        .unwrap();
        assert!(save_bytes(&b).is_ok(), "B saves at {have}");
        edit::move_entries(&mut a, &[id(E)], id(P), at(20)).unwrap();
        let src = b.duplicate();
        merge(&mut a, &src, &Options::new(Kind::ChangeOnDisk), at(30)).unwrap();
        println!("g1 {have}: a {}", show(&a, E));
        let saved = save_bytes(&a);
        assert!(
            saved.is_ok(),
            "{have}: the vault cannot be saved: {saved:?}"
        );
        let e = walk_e(&a.root, E).unwrap().1;
        let inside: Vec<bool> = e
            .history
            .iter()
            .filter(|h| h.value("Password") == "inside-demo")
            .map(origin::private_item)
            .collect();
        assert_eq!(inside, if kept { vec![true] } else { vec![] }, "{have}");
    }
}

/// G2 (C1R4-04): with history limit -1 or 100,000 an entry's own versions fill the format's
/// 100,000; one whole merge would add a private item. Private items go first: the next
/// save stays within the history limit.
#[test]
fn g2_private_items_never_pass_the_formats_history_limit() {
    for limit in [-1, 100_000] {
        let mut a = world(&[T]);
        a.meta.history_max_items = limit;
        let mut e = entry(E, "seed-demo", at(1));
        let n = Limits::DEFAULT.history;
        for i in 0..n {
            let mut h = entry(E, &format!("old-{i}"), Time(T0.0 - 1_000_000 + i as i64));
            h.history.clear();
            e.history.push(h);
        }
        gm(&mut a.root, T).entries.push(e);
        let mut b = a.duplicate();
        edit::edit_entry(&mut b, id(E), at(10), |d| pw(d, "inside-demo")).unwrap();
        edit::move_entries(&mut a, &[id(E)], id(P), at(20)).unwrap();
        let src = b.duplicate();
        merge(&mut a, &src, &Options::new(Kind::ChangeOnDisk), at(30)).unwrap();
        let h = &walk_e(&a.root, E).unwrap().1.history;
        let private = h.iter().filter(|x| origin::private_item(x)).count();
        println!(
            "g2 {limit}: a history {} of which private {private}",
            h.len()
        );
        assert_eq!((h.len(), private), (n, 0), "{limit}");
        assert!(save_bytes(&a).is_ok(), "{limit}: over the history limit");
    }
}

/// G3: a private item never goes out, also after the user moves the entry into a nested
/// share and a member of the outer share edits it.
#[test]
fn g3_private_items_stay_through_nested_moves() {
    let mut a = world(&[T, S]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1)));
    let mut b = a.duplicate();
    edit::edit_entry(&mut b, id(E), at(10), |d| pw(d, "inside-demo")).unwrap();
    edit::move_entries(&mut a, &[id(E)], id(P), at(20)).unwrap();
    edit::edit_entry(&mut a, id(E), at(21), |d| pw(d, "outside-private-demo")).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 30);
    edit::move_entries(&mut a, &[id(E)], id(S), at(50)).unwrap();
    settle(&mut a, &mut b, Kind::ChangeOnDisk, 60);
    println!("g3 moved into S: a {} | b {}", show(&a, E), show(&b, E));
    for s in [T, S] {
        for v in [&a, &b] {
            let c = export(v, s, 80);
            for e in c.root.all_entries() {
                assert!(!e.history.iter().any(origin::private_item), "tag in export");
                assert!(
                    e.history
                        .iter()
                        .all(|h| h.value("Password") != "inside-demo"),
                    "a private value in the export of {s:02x}"
                );
            }
        }
    }
}

/// G4 (mutant 28): a near-key private tag in a container's history item, in memory (not
/// through the reader). The import drops the item whole.
#[test]
fn g4_a_near_key_private_tag_in_memory_is_dropped_at_import() {
    let mut a = world(&[T]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1)));
    let mut c = export(&a, T, 2);
    for e in c.root.entries.iter_mut() {
        let mut h = e.duplicate(false);
        pw(&mut h, "member-tagged-demo");
        h.times.last_modification = at(0);
        h.custom_data.items.push(CustomDataItem {
            key: format!("{}\u{80}", origin::PRIVATE),
            value: SecretString::new("1".to_owned()),
            last_modified: None,
            unknown: Vec::new(),
        });
        e.history.push(h);
        e.custom_data.items.push(CustomDataItem {
            key: format!("\u{9f}{}", origin::STAMP),
            value: SecretString::new(format!("{}:{}", "20".repeat(16), at(99_999).0)),
            last_modified: None,
            unknown: Vec::new(),
        });
    }
    import(&mut a, T, &c, 5);
    let e = walk_e(&a.root, E).unwrap().1;
    println!("g4 a: {}", show(&a, E));
    assert!(
        origin::stamp_of(&e.custom_data).is_none(),
        "a near-key stamp got in"
    );
    assert!(
        !e.history
            .iter()
            .any(|h| h.value("Password") == "member-tagged-demo"),
        "a tagged item got in"
    );
}

// ---------------- The item limit on real files (C1R4-03) ----------------

/// A container's new entry, read from a real file, holds as many custom data items as one
/// object may. The import's marker does not fit: the entry comes in without it, the app's
/// trial import (`run::fits`) takes it, and the vault saves, as base does. One item below
/// the limit the marker goes in.
#[test]
fn mark_a_new_entry_at_the_custom_data_item_limit() {
    let limit = Limits::DEFAULT.custom_data_items;
    for (have, marked) in [(limit, false), (limit - 1, true)] {
        let mut v = world(&[T]);
        let mut c = Vault::new(Group::new(id(T), "T".into(), T0), T0);
        c.meta.recycle_bin_enabled = false;
        c.encryption.kdf = Kdf::AesKdf { rounds: 1 };
        let mut e = Entry::new(id(E), T0);
        fill(&mut e, have);
        c.root.entries.push(e);
        let c = through_a_file(&c);
        let trial = run::fits(v.duplicate(), id(T), &c, at(10), &mut host());
        assert!(
            matches!(trial, Ok((_, Some(_)))),
            "{have}: the app's import refuses the file"
        );
        import(&mut v, T, &c, 10);
        let e = walk_e(&v.root, E).unwrap().1;
        println!("mark {have}: items {}", e.custom_data.items.len());
        assert_eq!(origin::mark_of(&e.custom_data).is_some(), marked, "{have}");
        assert!(e.custom_data.items.len() <= limit);
        assert!(
            save_bytes(&v).is_ok(),
            "{have}: the import made the vault unsavable"
        );
    }
}

/// A container's newer copy of an entry the user moved into the share (so this Mac's copy
/// holds a stamp) arrives at the item limit, from a real file. The import keeps this Mac's
/// stamp only where it fits: here it does not, so the entry holds the container's items
/// alone, the trial import takes the file and the vault saves, as base does.
#[test]
fn an_imported_newer_copy_at_the_item_limit_keeps_no_stamp() {
    let limit = Limits::DEFAULT.custom_data_items;
    for (have, stamped) in [(limit, false), (limit - 1, true)] {
        let mut v = world(&[T]);
        gm(&mut v.root, P)
            .entries
            .push(entry(E, "seed-demo", at(1)));
        edit::move_entries(&mut v, &[id(E)], id(T), at(2)).unwrap();
        assert!(origin::stamp_of(&walk_e(&v.root, E).unwrap().1.custom_data).is_some());
        let mut c = export(&v, T, 3);
        for e in c.root.entries.iter_mut() {
            pw(e, "member-demo");
            e.times.last_modification = at(4);
            fill(e, have);
        }
        let c = through_a_file(&c);
        let trial = run::fits(v.duplicate(), id(T), &c, at(5), &mut host());
        assert!(
            matches!(trial, Ok((_, Some(_)))),
            "{have}: the app's import refuses the file"
        );
        import(&mut v, T, &c, 5);
        let e = walk_e(&v.root, E).unwrap().1;
        println!(
            "stamp {have}: {} items {}",
            show(&v, E),
            e.custom_data.items.len()
        );
        assert_eq!(e.value("Password"), "member-demo");
        assert_eq!(
            origin::stamp_of(&e.custom_data).is_some(),
            stamped,
            "{have}"
        );
        assert!(e.custom_data.items.len() <= limit);
        assert!(
            save_bytes(&v).is_ok(),
            "{have}: the import made the vault unsavable"
        );
    }
}

// ---------------- Pinned findings ----------------

fn hist(v: &Vault, n: u8) -> String {
    match walk_e(&v.root, n) {
        None => "GONE".into(),
        Some((_, e)) => format!(
            "cur {}@{} hist [{}]",
            e.value("Password"),
            e.times.last_modification.0 - T0.0,
            e.history
                .iter()
                .map(|h| format!(
                    "{}@{}{}",
                    h.value("Password"),
                    h.times.last_modification.0 - T0.0,
                    if origin::private_item(h) { "!" } else { "" }
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// Q1, a finding older than R6 (C1R4-07): history limit 1; a container brings an entry and
/// a history item dated in the future, both clamped to the import time; a member edits;
/// three Macs settle. Their histories differ, and a merge of a settled pair still records
/// a history change. Pinned as it is.
#[test]
fn q1_finding_a_settled_pair_with_history_limit_one_is_not_quiet() {
    let mut w = world(&[T]);
    w.meta.history_max_items = 1;
    gm(&mut w.root, T)
        .groups
        .push(Group::new(id(0x2f), "Sub".into(), T0));
    gm(&mut w.root, 0x2f)
        .entries
        .push(entry(0x63, "seed-share-63", at(1)));
    let mut macs = vec![w.duplicate(), w.duplicate(), w.duplicate()];
    let mut c = Vault::new(Group::new(id(T), "C".into(), T0), T0);
    c.meta.recycle_bin_enabled = false;
    let mut e = entry(0x63, "planted-1", at(11 + 100_000));
    e.history
        .push(entry(0x63, "planted-h-1", at(11 + 100_000 - 1)));
    c.root.entries.push(e);
    import(&mut macs[1], T, &c, 11);
    let mut c = export(&macs[1], T, 12);
    fn find_em(g: &mut Group, want: Uuid) -> Option<&mut Entry> {
        if let Some(i) = g.entries.iter().position(|e| e.uuid == want) {
            return g.entries.get_mut(i);
        }
        g.groups.iter_mut().find_map(|c| find_em(c, want))
    }
    if let Some(e) = find_em(&mut c.root, id(0x63)) {
        let d = e.duplicate(false);
        e.history.push(d);
        pw(e, "member-63-2");
        e.times.last_modification = at(12);
    }
    let c = through_a_file(&c);
    import(&mut macs[1], T, &c, 12);
    let src = macs[1].duplicate();
    merge(&mut macs[2], &src, &Options::new(Kind::CommandLine), at(13)).unwrap();
    for round in 0..6 {
        for t in 0..3 {
            for s in 0..3 {
                if t != s {
                    let src = macs[s].duplicate();
                    merge(
                        &mut macs[t],
                        &src,
                        &Options::new(Kind::ChangeOnDisk),
                        at(14 + round),
                    )
                    .unwrap();
                }
            }
        }
    }
    let settled: Vec<String> = macs.iter().map(|v| hist(v, 0x63)).collect();
    println!("q1 settled {settled:?}");
    assert_eq!(
        settled,
        [
            "cur member-63-2@12 hist [planted-h-1@11]",
            "cur member-63-2@12 hist [planted-h-1@11,planted-1@11]",
            "cur member-63-2@12 hist [planted-1@11]",
        ]
    );
    let src = macs[1].duplicate();
    let got = merge(
        &mut macs[0],
        &src,
        &Options::new(Kind::ChangeOnDisk),
        at(120),
    )
    .unwrap();
    println!("q1 0<-1 changes {}", got.changes.len());
    assert_eq!(got.changes.len(), 1, "C1R4-07 changed");
    assert_eq!(
        hist(&macs[0], 0x63),
        "cur member-63-2@12 hist [planted-1@11]"
    );
}

fn places(v: &Vault) -> BTreeMap<u8, u8> {
    let mut out = BTreeMap::new();
    let mut stack = vec![&v.root];
    while let Some(g) = stack.pop() {
        for e in &g.entries {
            out.insert(e.uuid.0[0], g.uuid.0[0]);
        }
        for c in &g.groups {
            out.insert(c.uuid.0[0], g.uuid.0[0]);
            stack.push(c);
        }
    }
    out
}

/// Limit 19 (C1R4-06): two Macs move two nested groups into each other, a cycle; three Macs
/// settle and never agree, with or without shares (base: MOD-11.9 takes the later move and
/// the merged tree keeps a copy's place where the cycle would close). With all five groups
/// shared R6 also moves objects nobody moved: S2 from S into V on Macs 0 and 1, and the
/// entry from V into S on Mac 2. Pinned as it is.
#[test]
fn cycle_limit_19_two_groups_moved_into_each_other_three_macs_settle() {
    const W: u8 = 0x26;
    const X: u8 = 0x67;
    let world = |shared: bool| {
        let mut root = Group::new(id(ROOT), "Root".into(), T0);
        let mut t = Group::new(id(T), "T".into(), T0);
        let mut s = Group::new(id(S), "S".into(), T0);
        let mut s2 = Group::new(id(0x24), "S2".into(), T0);
        s2.groups.push(Group::new(id(0x25), "S3".into(), T0));
        s.groups.push(s2);
        t.groups.push(s);
        let mut w = Group::new(id(W), "V".into(), T0);
        w.entries.push(entry(X, "seed-share-67", at(1)));
        t.groups.push(w);
        root.groups.push(t);
        root.groups.push(Group::new(id(BIN), "Bin".into(), T0));
        let mut v = Vault::new(root, T0);
        v.meta.recycle_bin_enabled = true;
        v.meta.recycle_bin = Some(id(BIN));
        if shared {
            for g in [T, S, 0x24, 0x25, W] {
                gm(&mut v.root, g).custom_data.items.push(share_item());
            }
        }
        v
    };
    let map = |pairs: &[(u8, u8)]| -> BTreeMap<u8, u8> { pairs.iter().copied().collect() };
    let base_ab = map(&[
        (T, ROOT),
        (S, T),
        (0x24, S),
        (0x25, 0x24),
        (W, S),
        (BIN, ROOT),
        (X, W),
    ]);
    let base_c = map(&[
        (T, ROOT),
        (S, W),
        (0x24, S),
        (0x25, 0x24),
        (W, T),
        (BIN, ROOT),
        (X, W),
    ]);
    for shared in [true, false] {
        for kind in [Kind::ChangeOnDisk, Kind::ServerSync, Kind::Window] {
            let base = world(shared);
            let mut macs = vec![base.duplicate(), base.duplicate(), base.duplicate()];
            edit::move_group(&mut macs[2], id(S), id(W), Position::End, at(11)).unwrap();
            edit::move_group(&mut macs[0], id(W), id(S), Position::End, at(12)).unwrap();
            for round in 0..6i64 {
                for t in 0..3 {
                    for s in 0..3 {
                        if t != s {
                            let src = macs[s].duplicate();
                            merge(&mut macs[t], &src, &Options::new(kind), at(20 + round)).unwrap();
                        }
                    }
                }
            }
            let p: Vec<BTreeMap<u8, u8>> = macs.iter().map(places).collect();
            println!("cycle shared {shared} {kind:?}: {p:02x?}");
            let (mut ab, mut c) = (base_ab.clone(), base_c.clone());
            if shared {
                ab.insert(0x24, W);
                c.insert(X, S);
            }
            assert_eq!(
                p,
                [ab.clone(), ab, c],
                "shared {shared} {kind:?}: limit 19 changed"
            );
        }
    }
}

/// Every custom data item of the vault model: the vault's, each group's, each entry's
/// and each history item's.
fn items_in_all(v: &Vault) -> usize {
    let mut n = v.meta.custom_data.items.len();
    let mut stack = vec![&v.root];
    while let Some(g) = stack.pop() {
        n += g.custom_data.items.len();
        for e in &g.entries {
            n += e.custom_data.items.len();
            n += e
                .history
                .iter()
                .map(|h| h.custom_data.items.len())
                .sum::<usize>();
        }
        stack.extend(g.groups.iter());
    }
    n
}

/// The save of `v` with the format's limit on custom data items in all set to `all`.
fn save_with_all(v: &Vault, all: usize) -> Result<(), String> {
    let lim = Limits {
        custom_data_items_all: all,
        ..Limits::DEFAULT
    };
    let p = SecretString::new("demo".to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    larsal_format::save(v, &key, None, &mut host(), &lim, None)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Limit 20: the rule's writes count each object's own custom data items, not the
/// format's limit on all of them. With that limit lowered to the least the vault saves
/// under, the user's move into the share adds its stamp and the next save refuses,
/// naming that limit; nothing is lost, and one more item of room saves. Pinned.
#[test]
fn limit_20_the_vault_wide_item_count_is_not_checked() {
    let mut v = world(&[T]);
    gm(&mut v.root, P)
        .entries
        .push(entry(E, "seed-demo", at(1)));
    let all = (0..64)
        .find(|k| save_with_all(&v, *k).is_ok())
        .expect("saves");
    assert!(save_with_all(&v, all.saturating_sub(1)).is_err() || all == 0);
    let n = items_in_all(&v);
    edit::move_entries(&mut v, &[id(E)], id(T), at(2)).unwrap();
    assert_eq!(items_in_all(&v), n + 1, "the stamp");
    let got = save_with_all(&v, all);
    println!("limit 20 at {all}: {got:?}");
    assert!(
        got.as_ref()
            .is_err_and(|e| e.contains("custom data items in all")),
        "limit 20 changed: {got:?}"
    );
    assert_eq!(walk_e(&v.root, E).unwrap().0, id(T));
    assert_eq!(save_with_all(&v, all + 1), Ok(()));
}

/// The vault's own custom data at the format's item limit (C1R4-03, round 5): a vault
/// that saves, as a file holds it (with the two items each save writes there) and as a
/// vault never saved (without them), filled so its next save writes exactly the limit or
/// one less. A user's delete for good in a share then writes no rows item at the limit,
/// so that deletion does not reach (as limit 13), and one below it writes the row; the
/// vault saves either way.
#[test]
fn rows_at_the_vaults_custom_data_item_limit() {
    let limit = Limits::DEFAULT.custom_data_items;
    for through_file in [false, true] {
        for below in [0usize, 1] {
            let mut v = world(&[T]);
            gm(&mut v.root, T)
                .entries
                .push(entry(E, "seed-demo", at(1)));
            if through_file {
                v = rt(&v);
            }
            let save_adds = if through_file { 0 } else { 2 };
            let fill = limit - save_adds - below - v.meta.custom_data.items.len();
            for i in 0..fill {
                v.meta.custom_data.items.push(plain_item(format!("k{i}")));
            }
            assert_eq!(save_bytes(&v).map(|_| ()), Ok(()), "the vault saves before");
            del(&mut v, E, at(2));
            let saved = save_bytes(&v).map(|_| ());
            println!(
                "file {through_file} below {below}: items {} rows [{}] save {saved:?}",
                v.meta.custom_data.items.len(),
                rows(&v)
            );
            assert!(!has(&v, E));
            assert_eq!(rows(&v), if below == 0 { "" } else { "50/20/2" });
            assert_eq!(
                saved,
                Ok(()),
                "file {through_file} below {below}: the vault saves"
            );
        }
    }
}
