//! Checker 1, round 5: who hears an outer member's deletion, at depth and through a relay,
//! and the custom data item limit through a join, ported in round 6. Demo data only. Each
//! test prints what it saw. m1, x1, x1b, x1r, x3 and x4 hold C1R5-01 (the rows a merge of
//! any kind writes for the shares inside the one whose row erased an object); j1 and m8
//! hold item 5 (C1R5-04); h11 pins limit 7 and k2 pins limit 20 (C1R5-03, C1R5-07).
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
use larsal_model::{CustomDataItem, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};

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
const G: u8 = 0x40;
const F: u8 = 0x41;
const CHAIN: [u8; 4] = [T, S, S2, S3];

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
fn item(k: &str, v: &str) -> CustomDataItem {
    CustomDataItem {
        key: k.to_owned(),
        value: SecretString::new(v.to_owned()),
        last_modified: None,
        unknown: Vec::new(),
    }
}
fn share_item() -> CustomDataItem {
    item(core::str::from_utf8(edit::SHARED_KEY).unwrap(), "")
}
fn fill(e: &mut Entry, n: usize) {
    for i in 0..n {
        e.custom_data.items.push(item(&format!("k{i}"), "x"));
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
fn has(v: &Vault, n: u8) -> bool {
    v.root.all_entries().any(|e| e.uuid == id(n))
}
fn has_group(v: &Vault, n: u8) -> bool {
    fn walk(g: &Group, n: u8) -> bool {
        g.uuid == id(n) || g.groups.iter().any(|c| walk(c, n))
    }
    walk(&v.root, n)
}
fn entry_of(v: &Vault, n: u8) -> Option<&Entry> {
    v.root.all_entries().find(|e| e.uuid == id(n))
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
fn del_group(v: &mut Vault, n: u8, now: Time) {
    let was = v.meta.recycle_bin_enabled;
    v.meta.recycle_bin_enabled = false;
    recycle::delete_group(v, id(n), now).unwrap();
    v.meta.recycle_bin_enabled = was;
}
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

/// One cell of the matrix: a chain of four nested shares T > S > S2 > S3; E sits in the
/// share at depth `d`; a member of the share at depth `k <= d` deletes E. Held: the user's
/// Mac A holds E when it imports that member's file. Relay: only the user's Mac B holds E;
/// A imports the member's file, then A and B settle (same-vault merges of `kind`). Then every
/// other member of a share holding E takes that share's export from A and from B. Returns
/// the shares whose member keeps E.
fn m1_cell(relay: bool, d: usize, k: usize, kind: Kind) -> (bool, bool, Vec<u8>) {
    let mut a = world(&CHAIN);
    let mut b;
    if relay {
        b = a.duplicate();
        gm(&mut b.root, CHAIN[d])
            .entries
            .push(entry(E, "matrix-demo", at(1)));
    } else {
        gm(&mut a.root, CHAIN[d])
            .entries
            .push(entry(E, "matrix-demo", at(1)));
        b = a.duplicate();
    }
    let holder = if relay { b.duplicate() } else { a.duplicate() };
    let mut members: Vec<Vault> = CHAIN
        .iter()
        .enumerate()
        .map(|(i, s)| member_of(*s, 0x70 + i as u8))
        .collect();
    for j in 0..=d {
        import(&mut members[j], CHAIN[j], &export(&holder, CHAIN[j], 2), 3);
        assert!(has(&members[j], E));
    }
    del(&mut members[k], E, at(6));
    let back = export(&members[k], CHAIN[k], 7);
    import(&mut a, CHAIN[k], &back, 8);
    settle(&mut a, &mut b, kind, 9);
    let mut kept = Vec::new();
    for j in 0..=d {
        if j == k {
            continue;
        }
        import(&mut members[j], CHAIN[j], &export(&a, CHAIN[j], 30), 31);
        import(&mut members[j], CHAIN[j], &export(&b, CHAIN[j], 32), 33);
        if has(&members[j], E) {
            kept.push(CHAIN[j]);
        }
    }
    (has(&a, E), has(&b, E), kept)
}

fn m1(relay: bool) {
    let mut fails = Vec::new();
    for d in 0..4usize {
        for k in 0..=d {
            for kind in KINDS {
                let (ha, hb, kept) = m1_cell(relay, d, k, kind);
                let line = format!(
                    "m1 {} E at depth {d} ({:02x}), deleter member of {:02x}, {kind:?}: a {ha} b {hb} | members that keep E {kept:02x?}",
                    if relay { "relay" } else { "held " },
                    CHAIN[d],
                    CHAIN[k],
                );
                println!("{line}");
                if ha || hb || !kept.is_empty() {
                    fails.push(line);
                }
            }
        }
    }
    assert!(
        fails.is_empty(),
        "a member keeps E a member deleted:\n{}",
        fails.join("\n")
    );
}

/// C1R5-01, every cell of depth and deleter, every merge kind: the user's Mac A holds E.
#[test]
fn m1_held_every_member_of_every_share_hears_a_members_deletion() {
    m1(false);
}

/// C1R5-01, the relay: only Mac B holds E; A imports the member's file and the user's Macs
/// settle in same-vault merges. The row of each inner share is written where the erase is.
#[test]
fn m1_relay_every_member_of_every_share_hears_a_members_deletion() {
    m1(true);
}

/// X1, the smallest relay: E in S on the user's Mac B only. A member of T deletes it; Mac A,
/// which does not hold E yet, imports T's file; A and B settle; S's member takes S's export.
#[test]
fn x1_relay_through_a_same_vault_merge() {
    let mut fails = Vec::new();
    for kind in KINDS {
        let mut a = world(&[T, S]);
        let mut b = a.duplicate();
        gm(&mut b.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut ms = member_of(S, 0x70);
        let mut mt = member_of(T, 0x71);
        import(&mut ms, S, &export(&b, S, 2), 3);
        import(&mut mt, T, &export(&b, T, 2), 3);
        del(&mut mt, E, at(6));
        let back = export(&mt, T, 7);
        assert_eq!(listed(&back), vec![E]);
        import(&mut a, T, &back, 8);
        settle(&mut a, &mut b, kind, 9);
        let (sa, sb) = (export(&a, S, 30), export(&b, S, 30));
        import(&mut ms, S, &sa, 31);
        import(&mut ms, S, &sb, 32);
        let back_s = export(&ms, S, 33);
        import(&mut a, S, &back_s, 34);
        import(&mut b, S, &back_s, 34);
        let line = format!(
            "x1 {kind:?}: S's export lists a {:02x?} b {:02x?} | a {} b {} ms {}",
            listed(&sa),
            listed(&sb),
            has(&a, E),
            has(&b, E),
            has(&ms, E)
        );
        println!("{line}");
        if has(&ms, E) || has(&a, E) || has(&b, E) {
            fails.push(line);
        }
    }
    assert!(
        fails.is_empty(),
        "the member of S keeps E:\n{}",
        fails.join("\n")
    );
}

/// X1b, as the app runs it: both of the user's Macs watch T's file. A imports it first and
/// saves; B takes A's vault (a same-vault merge) before B's own watcher reads T's file; then
/// B imports that same file too. Then S's member takes S's export from both Macs.
#[test]
fn x1b_both_macs_import_the_file_b_after_the_merge() {
    let mut fails = Vec::new();
    for kind in KINDS {
        let mut a = world(&[T, S]);
        let mut b = a.duplicate();
        gm(&mut b.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut ms = member_of(S, 0x70);
        let mut mt = member_of(T, 0x71);
        import(&mut ms, S, &export(&b, S, 2), 3);
        import(&mut mt, T, &export(&b, T, 2), 3);
        del(&mut mt, E, at(6));
        let back = export(&mt, T, 7);
        import(&mut a, T, &back, 8);
        m(&mut b, &a, kind, 9);
        import(&mut b, T, &back, 10);
        settle(&mut a, &mut b, kind, 11);
        import(&mut ms, S, &export(&a, S, 30), 31);
        import(&mut ms, S, &export(&b, S, 32), 33);
        let line = format!(
            "x1b {kind:?}: a {} b {} ms {}",
            has(&a, E),
            has(&b, E),
            has(&ms, E)
        );
        println!("{line}");
        if has(&ms, E) {
            fails.push(line);
        }
    }
    assert!(
        fails.is_empty(),
        "the member of S keeps E:\n{}",
        fails.join("\n")
    );
}

/// X1 with the rows: the same-vault merge that erases B's copy by T's row writes S's row,
/// on both Macs once they settle, and S's export from either lists E.
#[test]
fn x1r_the_same_vault_erase_writes_the_inner_row() {
    let mut fails = Vec::new();
    for kind in KINDS {
        let mut a = world(&[T, S]);
        let mut b = a.duplicate();
        gm(&mut b.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut ms = member_of(S, 0x70);
        let mut mt = member_of(T, 0x71);
        import(&mut ms, S, &export(&b, S, 2), 3);
        import(&mut mt, T, &export(&b, T, 2), 3);
        del(&mut mt, E, at(6));
        import(&mut a, T, &export(&mt, T, 7), 8);
        let after_import = rows(&a);
        settle(&mut a, &mut b, kind, 9);
        let (sa, sb) = (export(&a, S, 30), export(&b, S, 30));
        let line = format!(
            "x1r {kind:?}: a rows after import [{after_import}] | settled a [{}] b [{}] | holds a {} b {} | S's export lists a {:02x?} b {:02x?}",
            rows(&a),
            rows(&b),
            has(&a, E),
            has(&b, E),
            listed(&sa),
            listed(&sb)
        );
        println!("{line}");
        let s_row =
            |v: &Vault| origin::read_rows(&v.meta.custom_data).contains_key(&(id(E), id(S)));
        if !s_row(&a) || !s_row(&b) || listed(&sa) != vec![E] || listed(&sb) != vec![E] {
            fails.push(line);
        }
        import(&mut ms, S, &sa, 31);
        import(&mut ms, S, &sb, 32);
        assert!(!has(&ms, E), "{kind:?}");
    }
    assert!(fails.is_empty(), "no row for S:\n{}", fails.join("\n"));
}

/// X3: the user's Mac A holds E in T itself; Mac B moved E down into S (a user's move). A
/// member of T, who has E from B's export, deletes it. A imports T's file and erases its copy,
/// which counted in T only; A and B settle and B's copy in S goes too. S's member hears.
#[test]
fn x3_a_copy_in_the_outer_share_on_the_importing_mac() {
    let mut fails = Vec::new();
    for kind in KINDS {
        let mut a = world(&[T, S]);
        gm(&mut a.root, T)
            .entries
            .push(entry(E, "in-t-demo", at(1)));
        let mut b = a.duplicate();
        edit::move_entries(&mut b, &[id(E)], id(S), at(4)).unwrap();
        let mut ms = member_of(S, 0x70);
        let mut mt = member_of(T, 0x71);
        import(&mut ms, S, &export(&b, S, 5), 5);
        import(&mut mt, T, &export(&b, T, 5), 5);
        assert!(has(&ms, E) && has(&mt, E));
        del(&mut mt, E, at(6));
        import(&mut a, T, &export(&mt, T, 7), 8);
        settle(&mut a, &mut b, kind, 9);
        import(&mut ms, S, &export(&a, S, 30), 31);
        import(&mut ms, S, &export(&b, S, 32), 33);
        let line = format!(
            "x3 {kind:?}: a {} b {} ms {}",
            has(&a, E),
            has(&b, E),
            has(&ms, E)
        );
        println!("{line}");
        if has(&ms, E) || has(&a, E) || has(&b, E) {
            fails.push(line);
        }
    }
    assert!(
        fails.is_empty(),
        "S's member keeps E the user's Macs erased:\n{}",
        fails.join("\n")
    );
}

/// X4: as X1 with a group: G holding F sits in S on Mac B only. A member of T deletes G.
#[test]
fn x4_a_group_relay() {
    let mut fails = Vec::new();
    for kind in KINDS {
        let mut a = world(&[T, S]);
        let mut b = a.duplicate();
        let mut g = Group::new(id(G), "G".into(), at(1));
        g.entries.push(entry(F, "in-g-demo", at(1)));
        gm(&mut b.root, S).groups.push(g);
        let mut ms = member_of(S, 0x70);
        let mut mt = member_of(T, 0x71);
        import(&mut ms, S, &export(&b, S, 2), 3);
        import(&mut mt, T, &export(&b, T, 2), 3);
        assert!(has(&ms, F) && has_group(&mt, G));
        del_group(&mut mt, G, at(6));
        let back = export(&mt, T, 7);
        println!("x4 T's export from the member lists {:02x?}", listed(&back));
        import(&mut a, T, &back, 8);
        settle(&mut a, &mut b, kind, 9);
        import(&mut ms, S, &export(&a, S, 30), 31);
        import(&mut ms, S, &export(&b, S, 32), 33);
        let line = format!(
            "x4 {kind:?}: a G {} F {} | b G {} F {} | ms G {} F {}",
            has_group(&a, G),
            has(&a, F),
            has_group(&b, G),
            has(&b, F),
            has_group(&ms, G),
            has(&ms, F)
        );
        println!("{line}");
        if has(&ms, F) || has_group(&ms, G) {
            fails.push(line);
        }
    }
    assert!(
        fails.is_empty(),
        "S's member keeps what T's member deleted:\n{}",
        fails.join("\n")
    );
}

/// Y1: the inner rows never erase outside. E sits in S on Mac A; Mac B moved E out of T to
/// P (later than anything). A stale member of T deletes E; A imports T's file and erases its
/// stale copy. After A and B settle, E is in P on both, and S's round trip keeps it.
#[test]
fn y1_an_erase_never_reaches_a_copy_moved_out() {
    for kind in KINDS {
        let mut a = world(&[T, S]);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut b = a.duplicate();
        let mut mt = member_of(T, 0x71);
        let mut ms = member_of(S, 0x70);
        import(&mut mt, T, &export(&a, T, 2), 3);
        import(&mut ms, S, &export(&a, S, 2), 3);
        edit::move_entries(&mut b, &[id(E)], id(P), at(4)).unwrap();
        del(&mut mt, E, at(6));
        import(&mut a, T, &export(&mt, T, 7), 8);
        settle(&mut a, &mut b, kind, 9);
        println!("y1 {kind:?}: a {} b {}", has(&a, E), has(&b, E));
        assert!(
            has(&a, E) && has(&b, E),
            "{kind:?}: the user's copy outside the shares went"
        );
        import(&mut ms, S, &export(&a, S, 30), 31);
        import(&mut a, S, &export(&ms, S, 32), 33);
        assert!(
            has(&a, E),
            "{kind:?}: S's round trip erased the copy outside"
        );
    }
}

/// Y2: side by side inside T. A member of T deletes E in S; V's member never held E and V's
/// export never lists it; S's member hears.
#[test]
fn y2_side_by_side_inside_the_imported_share() {
    let mut a = world(&[T, S, V]);
    gm(&mut a.root, S)
        .entries
        .push(entry(E, "in-s-demo", at(1)));
    gm(&mut a.root, V)
        .entries
        .push(entry(F, "in-v-demo", at(1)));
    let mut mt = member_of(T, 0x71);
    let mut ms = member_of(S, 0x70);
    let mut mv = member_of(V, 0x72);
    import(&mut mt, T, &export(&a, T, 2), 3);
    import(&mut ms, S, &export(&a, S, 2), 3);
    import(&mut mv, V, &export(&a, V, 2), 3);
    del(&mut mt, E, at(6));
    import(&mut a, T, &export(&mt, T, 7), 8);
    assert!(!has(&a, E) && has(&a, F));
    let sv = export(&a, V, 9);
    let ss = export(&a, S, 9);
    println!(
        "y2 V's export lists {:02x?}, S's lists {:02x?}",
        listed(&sv),
        listed(&ss)
    );
    assert!(listed(&sv).is_empty());
    import(&mut mv, V, &sv, 10);
    import(&mut ms, S, &ss, 10);
    assert!(has(&mv, F));
    assert!(!has(&ms, E), "S's member keeps E");
}

/// H11 at the item limit (C1R5-07): E sits in P on Mac B only; a member plants a copy of E
/// (same id, far times) in T's file holding `have` custom data items of its own; Mac A imports
/// it; the user on A moves that copy out to P. One below the limit the import adds the marker
/// and B's value stays. At the limit the import adds no marker (INT-08.32, the one door), so
/// the planted copy counts as the user's and B's value is overwritten: limit 7 names this
/// exact case, and base does the same.
#[test]
fn h11_limit_7_a_planted_copy_at_the_item_limit_moved_out() {
    let limit = Limits::DEFAULT.custom_data_items;
    for have in [limit - 1, limit] {
        for kind in [Kind::ServerSync, Kind::ChangeOnDisk] {
            let mut a = world(&[T]);
            let mut b = a.duplicate();
            gm(&mut b.root, P)
                .entries
                .push(entry(E, "private-demo", at(1)));
            let mut plant = entry(E, "plant-demo", at(9_000_000));
            fill(&mut plant, have);
            let mut cont = Vault::new(Group::new(id(T), "C".into(), T0), T0);
            cont.meta.recycle_bin_enabled = false;
            cont.encryption.kdf = Kdf::AesKdf { rounds: 1 };
            cont.root.entries.push(plant);
            import(&mut a, T, &cont, 5);
            let mut a = rt(&a);
            edit::move_entries(&mut a, &[id(E)], id(P), at(6)).unwrap();
            settle(&mut a, &mut b, kind, 10);
            let val = |v: &Vault| {
                entry_of(v, E)
                    .map(|e| e.value("Password").to_owned())
                    .unwrap_or_else(|| "GONE".into())
            };
            println!("h11 have {have} {kind:?}: a {} b {}", val(&a), val(&b));
            if have < limit {
                assert_eq!(val(&b), "private-demo", "{kind:?}");
            } else {
                assert_eq!(val(&b), "plant-demo", "{kind:?}: limit 7 as pinned");
            }
        }
    }
}

/// K2, limit 20 (C1R5-03): the rule's items count toward the format's 100,000 custom data
/// items per object. (a) Mac A imports an entry holding 99,999 items of its own: with the
/// marker it holds 100,000 and saves. (b) The user moves an entry holding 99,999 items of its
/// own into the share: with the stamp it holds 100,000 and saves. Either way the user's next
/// own item makes the save refuse with the format's too-large error, where base saves;
/// nothing is lost (the vault in memory keeps every value), and the app's undo, which puts
/// back the vault from before the step, saves again.
#[test]
fn k2_limit_20_a_users_own_item_beside_the_rules_item_at_the_limit() {
    let limit = Limits::DEFAULT.custom_data_items;
    let one_more = |d: &mut Entry| d.custom_data.items.push(item("users-own-item", "y"));
    // (a) imported.
    let mut a = world(&[T]);
    let mut e = entry(E, "imported-demo", at(1));
    fill(&mut e, limit - 1);
    let mut cont = Vault::new(Group::new(id(T), "C".into(), T0), T0);
    cont.meta.recycle_bin_enabled = false;
    cont.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    cont.root.entries.push(e);
    import(&mut a, T, &cont, 5);
    let mut a = rt(&a);
    assert_eq!(entry_of(&a, E).unwrap().custom_data.items.len(), limit);
    let before = a.duplicate();
    edit::edit_entry(&mut a, id(E), at(6), one_more).unwrap();
    let got = save_bytes(&a).map(|_| ());
    println!("k2a imported, after the user's item: save {got:?}");
    assert_eq!(got, Err("TooLarge(CustomDataItems)".to_owned()));
    assert_eq!(entry_of(&a, E).unwrap().value("Password"), "imported-demo");
    assert_eq!(entry_of(&a, E).unwrap().custom_data.items.len(), limit + 1);
    assert!(save_bytes(&before).is_ok(), "undoing the user's item saves");
    // (b) moved in.
    let mut b = world(&[T]);
    let mut e = entry(E, "moved-demo", at(1));
    fill(&mut e, limit - 1);
    gm(&mut b.root, P).entries.push(e);
    edit::move_entries(&mut b, &[id(E)], id(T), at(2)).unwrap();
    assert_eq!(entry_of(&b, E).unwrap().custom_data.items.len(), limit);
    assert!(save_bytes(&b).is_ok());
    let before = b.duplicate();
    edit::edit_entry(&mut b, id(E), at(3), one_more).unwrap();
    let got = save_bytes(&b).map(|_| ());
    println!("k2b moved in, after the user's item: save {got:?}");
    assert_eq!(got, Err("TooLarge(CustomDataItems)".to_owned()));
    assert_eq!(entry_of(&b, E).unwrap().value("Password"), "moved-demo");
    assert!(save_bytes(&before).is_ok(), "undoing the user's item saves");
}

/// K1: the vault's own custom data at the format's limit through a real file: a member's
/// deletion imported (the rows item), then a save. Base saves this vault; so does this one.
#[test]
fn k1_vault_data_at_the_limit_import_and_save() {
    let limit = Limits::DEFAULT.custom_data_items;
    for below in [0usize, 1, 2, 3] {
        let mut a = world(&[T, S]);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut mt = member_of(T, 0x71);
        import(&mut mt, T, &export(&a, T, 2), 3);
        let mut a = rt(&a);
        let fill = limit - below - a.meta.custom_data.items.len();
        for i in 0..fill {
            a.meta.custom_data.items.push(item(&format!("k{i}"), "x"));
        }
        let mut a = rt(&a);
        del(&mut mt, E, at(6));
        import(&mut a, T, &export(&mt, T, 7), 8);
        let saved = save_bytes(&a).map(|_| ());
        println!(
            "k1 below {below}: rows [{}] holds {} save {saved:?}",
            rows(&a),
            has(&a, E)
        );
        assert!(!has(&a, E));
        assert_eq!(saved, Ok(()), "below {below}");
    }
}

/// J1 (C1R5-04): the target's copy of a version the source holds as private takes the tag in
/// the join, as a whole win's loser does: the rule's marker goes first. A version that still
/// cannot take it at the item limit is dropped, never kept untagged. Either way, after the
/// user moves E into T, T's export never carries that value.
#[test]
fn j1_a_join_at_the_item_limit_never_exports_the_private_value() {
    let limit = Limits::DEFAULT.custom_data_items;
    // own: the target copy's own items; marked: it also holds the marker.
    for (own, marked) in [(limit - 1, true), (limit, false)] {
        let mut a = world(&[T]);
        let mut e = entry(E, "current-demo", at(5));
        let mut y = entry(E, "lost-elsewhere-demo", at(2));
        fill(&mut y, own);
        if marked {
            origin::set_mark(&mut y.custom_data, id(T));
        }
        assert_eq!(y.custom_data.items.len(), limit);
        e.history.push(y);
        gm(&mut a.root, P).entries.push(e);
        let mut b = a.duplicate();
        {
            let be = gm(&mut b.root, P)
                .entries
                .iter_mut()
                .find(|x| x.uuid == id(E))
                .unwrap();
            let h = &mut be.history[0];
            h.custom_data.items.retain(|i| i.key != origin::MARK);
            h.custom_data.items.push(item(origin::PRIVATE, "1"));
            assert!(origin::private_item(h));
        }
        assert!(save_bytes(&a).is_ok());
        for kind in [Kind::ServerSync, Kind::ChangeOnDisk] {
            let mut t = rt(&a);
            merge(&mut t, &b, &Options::new(kind), at(10)).unwrap();
            let he = entry_of(&t, E).unwrap();
            let tags: Vec<(String, bool, usize)> = he
                .history
                .iter()
                .map(|h| {
                    (
                        h.value("Password").to_owned(),
                        origin::private_item(h),
                        h.custom_data.items.len(),
                    )
                })
                .collect();
            println!("j1 own {own} marked {marked} {kind:?}: history after the join {tags:?}");
            assert!(save_bytes(&t).is_ok(), "{kind:?}");
            let lost: Vec<&(String, bool, usize)> = tags
                .iter()
                .filter(|(v, _, _)| v == "lost-elsewhere-demo")
                .collect();
            if marked {
                assert!(lost.len() == 1 && lost[0].1, "{kind:?}: tagged: {tags:?}");
            } else {
                assert!(
                    lost.is_empty(),
                    "{kind:?}: dropped, never kept untagged: {tags:?}"
                );
            }
            edit::move_entries(&mut t, &[id(E)], id(T), at(20)).unwrap();
            let c = export(&t, T, 21);
            let out: Vec<String> = c
                .root
                .all_entries()
                .filter(|x| x.uuid == id(E))
                .flat_map(|x| x.history.iter().map(|h| h.value("Password").to_owned()))
                .collect();
            println!("j1 {kind:?}: T's export carries history values {out:?}");
            assert!(
                !out.iter().any(|v| v == "lost-elsewhere-demo"),
                "{kind:?}: {out:?}"
            );
        }
    }
}

/// Checker 1's kill of mutant 8: as g1, but the losing copy's version at the item limit is
/// an older one, in its history. B fills E to the limit and types one password, then clears
/// the items and types another. The user moves E out on A; B's copy loses whole. Item 5: a
/// version that cannot take the tag is dropped, never kept untagged.
#[test]
fn m8_a_losers_older_version_at_the_item_limit_is_dropped() {
    let limit = Limits::DEFAULT.custom_data_items;
    let mut a = world(&[T]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1)));
    let mut b = a.duplicate();
    edit::edit_entry(&mut b, id(E), at(10), |d| {
        pw(d, "inside-old-demo");
        for i in 0..limit {
            d.custom_data.items.push(item(&format!("k{i}"), "x"));
        }
    })
    .unwrap();
    edit::edit_entry(&mut b, id(E), at(11), |d| {
        pw(d, "inside-demo");
        d.custom_data.items.clear();
    })
    .unwrap();
    edit::move_entries(&mut a, &[id(E)], id(P), at(20)).unwrap();
    merge(&mut a, &b, &Options::new(Kind::ChangeOnDisk), at(30)).unwrap();
    let e = entry_of(&a, E).unwrap();
    let hist: Vec<(String, bool, usize)> = e
        .history
        .iter()
        .map(|h| {
            (
                h.value("Password").to_owned(),
                origin::private_item(h),
                h.custom_data.items.len(),
            )
        })
        .collect();
    println!("m8: a history {hist:?}");
    assert!(
        hist.iter()
            .all(|(v, tagged, _)| v != "inside-old-demo" || *tagged),
        "an older losing version stays untagged: {hist:?}"
    );
    assert!(
        hist.iter()
            .any(|(v, tagged, _)| v == "inside-demo" && *tagged),
        "{hist:?}"
    );
}

/// Kills round 6's mutant 52: a whole win takes the stamp and marker out of a losing version
/// before the tag (item 5), so a version whose marker holds the last free slot stays, tagged.
/// B's copy of E in T keeps an older version with its own items one under the limit and T's
/// marker; A moves E out, and B's copy loses whole.
#[test]
fn w52_a_whole_win_takes_the_marker_out_before_the_tag() {
    let limit = Limits::DEFAULT.custom_data_items;
    let mut a = world(&[T]);
    gm(&mut a.root, T)
        .entries
        .push(entry(E, "seed-demo", at(1)));
    let mut b = a.duplicate();
    edit::edit_entry(&mut b, id(E), at(11), |d| pw(d, "inside-demo")).unwrap();
    {
        let be = gm(&mut b.root, T)
            .entries
            .iter_mut()
            .find(|x| x.uuid == id(E))
            .unwrap();
        let mut y = entry(E, "marked-old-demo", at(10));
        fill(&mut y, limit - 1);
        origin::set_mark(&mut y.custom_data, id(T));
        assert_eq!(y.custom_data.items.len(), limit);
        be.history.push(y);
    }
    edit::move_entries(&mut a, &[id(E)], id(P), at(20)).unwrap();
    merge(&mut a, &b, &Options::new(Kind::ChangeOnDisk), at(30)).unwrap();
    let e = entry_of(&a, E).unwrap();
    let hist: Vec<(String, bool, bool, usize)> = e
        .history
        .iter()
        .map(|h| {
            (
                h.value("Password").to_owned(),
                origin::private_item(h),
                origin::mark_of(&h.custom_data).is_some(),
                h.custom_data.items.len(),
            )
        })
        .collect();
    println!("w52: a history {hist:?}");
    assert!(
        hist.iter()
            .any(|(v, tagged, marked, n)| v == "marked-old-demo"
                && *tagged
                && !*marked
                && *n == limit),
        "the marked version stays, tagged, its marker out: {hist:?}"
    );
    assert!(save_bytes(&a).is_ok());
}

/// A known share that goes in a merge leaves the set of every group whose way up led through
/// it (the restated mutant 25): bin group Y names bin group Z, which names the known share K
/// in the bin. A row of K for Y waits there. Mac B deletes K for good; on Mac A's merge K goes
/// first (the lower id), and Y then counts in no share, so K's row does not reach it.
#[test]
fn m25_a_known_share_that_goes_leaves_the_sets_through_it() {
    const K: u8 = 0x31;
    const Z: u8 = 0x32;
    const Y: u8 = 0x33;
    for kind in KINDS {
        let mut a = world(&[T]);
        let mut k = Group::new(id(K), "K".into(), T0);
        k.custom_data.items.push(share_item());
        k.previous_parent = Some(id(P));
        let mut z = Group::new(id(Z), "Z".into(), T0);
        z.previous_parent = Some(id(K));
        let mut y = Group::new(id(Y), "Y".into(), T0);
        y.previous_parent = Some(id(Z));
        let bin = gm(&mut a.root, BIN);
        bin.groups.push(k);
        bin.groups.push(z);
        bin.groups.push(y);
        let mut b = rt(&a);
        del_group(&mut b, K, at(10));
        let mut r = origin::read_rows(&a.meta.custom_data);
        r.insert((id(Y), id(K)), at(10));
        origin::write_rows(&mut a.meta.custom_data, &r);
        let mut a = rt(&a);
        merge(&mut a, &b, &Options::new(kind), at(20)).unwrap();
        println!(
            "m25 {kind:?}: K {} Z {} Y {} rows [{}]",
            has_group(&a, K),
            has_group(&a, Z),
            has_group(&a, Y),
            rows(&a)
        );
        assert!(!has_group(&a, K), "{kind:?}: B's delete for good");
        assert!(
            has_group(&a, Y),
            "{kind:?}: Y counts in no share once K went"
        );
    }
}

// ---------------------------------------------------------------------------
// Checker 2, round 5 (c2r5x.rs), ported in round 6: a share moved out of the outer share
// on one Mac while a stale member of the outer share deletes in it. Red on round 5 and on
// base, green on round 4; limit 21 names it and these pin today's behaviour, with the
// controls that hold.
// ---------------------------------------------------------------------------

/// E in S inside T on both Macs; B moves `what` (S, or E itself) to P at `move_at`; a member
/// of T who never heard deletes E at `del_at`; Mac A imports that file at 10; the Macs
/// settle. Per kind: does A, does B hold E.
fn moved_out(shares: &[u8], what: u8, move_at: i64, del_at: i64) -> Vec<(bool, bool)> {
    let mut out = Vec::new();
    for kind in KINDS {
        let mut a = world(shares);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut b = a.duplicate();
        let mut mt = member_of(T, 0x71);
        import(&mut mt, T, &export(&a, T, 2), 3);
        if what == S {
            edit::move_group(&mut b, id(S), id(P), Position::End, at(move_at)).unwrap();
        } else {
            edit::move_entries(&mut b, &[id(E)], id(P), at(move_at)).unwrap();
        }
        del(&mut mt, E, at(del_at));
        import(&mut a, T, &export(&mt, T, del_at + 1), 10);
        settle(&mut a, &mut b, kind, 20);
        println!(
            "moved out {what:02x} at {move_at}, deleted at {del_at}, {kind:?}: a {} b {} | rows a [{}]",
            has(&a, E),
            has(&b, E),
            rows(&a)
        );
        out.push((has(&a, E), has(&b, E)));
    }
    out
}

/// Limit 21: the nested share S moved out of T on B before a stale member of T deletes E
/// in S. A, still holding S in T, erases E and writes S's row; that row erases E in S,
/// outside T, on both Macs.
#[test]
fn x1a_limit_21_a_nested_share_moved_out_before_an_outer_members_stale_deletion() {
    assert!(
        moved_out(&[T, S], S, 5, 8)
            .iter()
            .all(|g| *g == (false, false))
    );
}

/// Limit 21, the move after the deletion and before A's import.
#[test]
fn x1b_limit_21_a_nested_share_moved_out_after_an_outer_members_deletion() {
    assert!(
        moved_out(&[T, S], S, 9, 8)
            .iter()
            .all(|g| *g == (false, false))
    );
}

/// Control: S a plain group, moved out of T: E stays (T's row does not apply outside T).
#[test]
fn x1c_a_plain_group_moved_out_keeps_the_entry() {
    assert!(moved_out(&[T], S, 5, 8).iter().all(|g| *g == (true, true)));
}

/// Control: E itself moved out of T: E stays (LD-271 (2)).
#[test]
fn x1d_the_entry_itself_moved_out_stays() {
    assert!(
        moved_out(&[T, S], E, 5, 8)
            .iter()
            .all(|g| *g == (true, true))
    );
}

/// Limit 21, S's member: after X1a, B's export of S (now outside T) lists E, and S's member
/// erases its copy.
#[test]
fn x2_limit_21_the_nested_shares_member_after_the_share_left_t() {
    for kind in KINDS {
        let mut a = world(&[T, S]);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut b = a.duplicate();
        let mut mt = member_of(T, 0x71);
        let mut ms = member_of(S, 0x72);
        import(&mut mt, T, &export(&a, T, 2), 3);
        import(&mut ms, S, &export(&a, S, 2), 3);
        edit::move_group(&mut b, id(S), id(P), Position::End, at(5)).unwrap();
        del(&mut mt, E, at(8));
        import(&mut a, T, &export(&mt, T, 9), 10);
        settle(&mut a, &mut b, kind, 20);
        let s_out = export(&b, S, 40);
        import(&mut ms, S, &s_out, 41);
        println!(
            "x2 {kind:?}: S's export lists {:02x?}, ms {}",
            listed(&s_out),
            has(&ms, E)
        );
        assert_eq!(listed(&s_out), vec![E], "{kind:?}");
        assert!(!has(&ms, E), "{kind:?}: limit 21 as pinned");
    }
}

/// Limit 21 at depth: T{S{S2}}, S2 moved out of T on B; a stale member of T deletes E in S2.
#[test]
fn x3_limit_21_depth_three_inner_share_moved_out() {
    for kind in KINDS {
        let mut a = world(&[T, S, S2]);
        gm(&mut a.root, S2)
            .entries
            .push(entry(E, "in-s2-demo", at(1)));
        let mut b = a.duplicate();
        let mut mt = member_of(T, 0x71);
        import(&mut mt, T, &export(&a, T, 2), 3);
        edit::move_group(&mut b, id(S2), id(P), Position::End, at(5)).unwrap();
        del(&mut mt, E, at(8));
        import(&mut a, T, &export(&mt, T, 9), 10);
        settle(&mut a, &mut b, kind, 20);
        println!("x3 limit 21 {kind:?}: a {} b {}", has(&a, E), has(&b, E));
        assert!(!has(&a, E) && !has(&b, E), "{kind:?}: limit 21 as pinned");
    }
}

/// Control of the bound: S moved by B into the side by side share V, still inside T: the
/// member of T's deletion erases E.
#[test]
fn x4_moved_within_t_the_deletion_reaches() {
    for kind in KINDS {
        let mut a = world(&[T, S, V]);
        gm(&mut a.root, S)
            .entries
            .push(entry(E, "in-s-demo", at(1)));
        let mut b = a.duplicate();
        let mut mt = member_of(T, 0x71);
        import(&mut mt, T, &export(&a, T, 2), 3);
        edit::move_group(&mut b, id(S), id(V), Position::End, at(5)).unwrap();
        del(&mut mt, E, at(8));
        import(&mut a, T, &export(&mt, T, 9), 10);
        settle(&mut a, &mut b, kind, 20);
        assert!(!has(&a, E) && !has(&b, E), "{kind:?}");
    }
}
