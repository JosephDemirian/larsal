//! Sensitive Checker 2, round 3: the rule's own state. Demo data only.
#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use larsal_core::clone;
use larsal_core::edit;
use larsal_core::merge::{Kind, Options, merge};
use larsal_core::origin;
use larsal_core::recycle;
use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved};
use larsal_model::custom_data::CustomDataItem;
use larsal_model::settings::Kdf;
use larsal_model::{DeletedObject, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};

const T0: Time = Time(63_902_822_400);
const NOW: Time = Time(63_910_000_000);
const T: u8 = 0x20;
const P: u8 = 0x30;
const E: u8 = 0x50;

fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}

fn big(n: u64, tag: u8) -> Uuid {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&n.to_be_bytes());
    b[15] = tag;
    b[14] = 0xA5;
    Uuid(b)
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

fn save_bytes(v: &Vault) -> Result<Vec<u8>, larsal_format::Error> {
    let p = SecretString::new("demo".to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    let mut h = host();
    let mut save = |a: Option<&larsal_crypto::kdf::CostReport>| {
        larsal_format::save(v, &key, None, &mut h, &Limits::DEFAULT, a)
    };
    match save(None)? {
        Saved::File(f) => Ok(f.bytes),
        Saved::Ask(r) => match save(Some(&r))? {
            Saved::File(f) => Ok(f.bytes),
            Saved::Ask(_) => panic!("asked twice"),
        },
    }
}

fn reopen(v: &Vault) -> Vault {
    let b = save_bytes(v).unwrap();
    let p = SecretString::new("demo".to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    match larsal_format::open(&b, &key, &mut host(), &Limits::DEFAULT, None).unwrap() {
        Opened::Vault(o) => o.vault,
        Opened::Ask(_) => panic!("asked"),
    }
}

fn pw(n: u8, password: &str, m: Time, l: Time) -> Entry {
    let mut e = Entry::new(id(n), T0);
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new(password.to_owned()),
            protected: true,
        },
    );
    e.times.last_modification = m;
    e.times.location_changed = l;
    e
}

fn item(key: &str, value: &str) -> CustomDataItem {
    CustomDataItem {
        key: key.to_owned(),
        value: SecretString::new(value.to_owned()),
        last_modified: None,
        unknown: Vec::new(),
    }
}

fn world() -> Vault {
    let mut root = Group::new(id(1), "Root".into(), T0);
    root.groups.push(Group::new(id(0x5a), "Bin".into(), T0));
    root.groups.push(Group::new(id(P), "P".into(), T0));
    let mut t = Group::new(id(T), "T".into(), T0);
    t.custom_data
        .items
        .push(item(core::str::from_utf8(edit::SHARED_KEY).unwrap(), ""));
    root.groups.push(t);
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = true;
    v.meta.recycle_bin = Some(id(0x5a));
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    v
}

fn gm(g: &mut Group, x: u8) -> Option<&mut Group> {
    if g.uuid == id(x) {
        return Some(g);
    }
    g.groups.iter_mut().find_map(|c| gm(c, x))
}

fn container0() -> Vault {
    let mut c = Vault::new(Group::new(id(T), "T".into(), T0), T0);
    c.meta.recycle_bin_enabled = false;
    c.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    c
}

fn entry_of(v: &Vault, x: u8) -> &Entry {
    v.root.all_entries().find(|e| e.uuid == id(x)).unwrap()
}

fn stamp_text(group: u8, at: i64) -> String {
    format!("{}:{at}", format!("{group:02x}").repeat(16))
}

/// Direct plants of all four, on entry, history, group and root, through a real file.
#[test]
fn p1_direct_plants_are_stripped_through_a_real_file() {
    let mut c = container0();
    let mut e = pw(E, "planted-demo", NOW, NOW);
    let mut h = pw(E, "planted-old-demo", T0, T0);
    h.custom_data
        .items
        .push(item(origin::STAMP, &stamp_text(T, NOW.0 * 2)));
    h.custom_data.items.push(item(origin::MARK, "x"));
    e.history.push(h);
    e.custom_data
        .items
        .push(item(origin::STAMP, &stamp_text(T, NOW.0 * 2)));
    let mut g = Group::new(id(0x70), "planted".into(), T0);
    g.custom_data
        .items
        .push(item(origin::STAMP, &stamp_text(T, NOW.0 * 2)));
    g.entries.push(e);
    c.root.groups.push(g);
    c.root
        .custom_data
        .items
        .push(item(origin::STAMP, &stamp_text(T, NOW.0 * 2)));
    c.meta
        .custom_data
        .items
        .push(item(origin::KNOWN, &"ab".repeat(16)));
    let scope = format!("{}={}:{}", "ab".repeat(16), "cd".repeat(16), NOW.0);
    c.meta.custom_data.items.push(item(origin::SCOPES, &scope));
    let path = std::env::temp_dir().join("c2r3-p1.larsalvault");
    let password = SecretString::new("share-demo".to_owned());
    container::write_file(&path, &c, &password, &mut host(), &Limits::DEFAULT, &[]).unwrap();
    let opened = container::open_file(&path, &password, &mut host(), &Limits::DEFAULT)
        .unwrap()
        .vault;
    std::fs::remove_file(&path).unwrap();
    let mut v = world();
    run::merge_into(&mut v, id(T), &opened, NOW).unwrap();
    let v = reopen(&v);
    let e = entry_of(&v, E);
    assert_eq!(origin::stamp_of(&e.custom_data), None);
    assert_eq!(
        origin::mark_of(&e.custom_data),
        Some(id(T)),
        "the import's own marker"
    );
    assert_eq!(origin::stamp_of(&e.history[0].custom_data), None);
    assert!(e.history[0].custom_data.get(origin::MARK).is_none());
    let g = v.root.find_group(id(0x70)).unwrap();
    assert_eq!(origin::stamp_of(&g.custom_data), None);
    assert_eq!(
        origin::read_known(&v.meta.custom_data).len(),
        1,
        "T only: {:?}",
        v.meta.custom_data.get(origin::KNOWN)
    );
    assert!(origin::read_known(&v.meta.custom_data).contains(&id(T)));
    assert!(origin::read_rows(&v.meta.custom_data).is_empty());
    assert!(
        gm(&mut v.duplicate().root, T)
            .unwrap()
            .custom_data
            .get(origin::STAMP)
            .is_none()
    );
    assert!(
        v.root
            .find_group(id(T))
            .unwrap()
            .custom_data
            .get(origin::STAMP)
            .is_none()
    );
}

/// An export after a real history of the items holds none, by the bytes of its
/// document. It does hold outside ids: the previous parent and the plain list.
#[test]
fn p2_what_an_export_says_of_the_outside() {
    let mut v = world();
    gm(&mut v.root, P)
        .unwrap()
        .entries
        .push(pw(E, "private-demo", T0, T0));
    let moved = Time(T0.0 + 5);
    edit::move_entries(&mut v, &[id(E)], id(T), moved).unwrap();
    assert!(origin::stamp_of(&entry_of(&v, E).custom_data).is_some());
    gm(&mut v.root, P)
        .unwrap()
        .entries
        .push(pw(0x51, "outside-demo", T0, T0));
    v.meta.recycle_bin_enabled = false;
    recycle::delete_entries(&mut v, &[id(0x51)], moved, |_, _| {
        recycle::References::Delete
    })
    .unwrap();
    let c = container::build(id(T), true, &v, NOW).unwrap();
    let w = larsal_format::document::write::write_plain(&c).unwrap();
    let xml = String::from_utf8(w.xml().to_vec()).unwrap();
    assert!(!xml.contains("app.larsal.share"), "no item of the rule");
    assert!(!xml.contains("outside-demo"));
    eprintln!(
        "C2R3 P2: previous parent in the export {:x?}; records {:x?}",
        c.root.entries[0].previous_parent.map(|p| p.0[0]),
        c.deleted_objects
            .iter()
            .map(|d| d.uuid.0[0])
            .collect::<Vec<_>>()
    );
}

/// History: a member's big value evicts the outside copy's own history items.
#[test]
fn p3_a_losing_value_pushes_out_an_outside_copys_history() {
    let mut b = world();
    let mut e = pw(E, "private-now", Time(T0.0 + 10), T0);
    for i in 0..5 {
        let mut h = pw(E, &format!("private-old-{i}"), Time(T0.0 + i), T0);
        h.history.clear();
        e.history.push(h);
    }
    gm(&mut b.root, P).unwrap().entries.push(e);
    // Real default limits.
    eprintln!(
        "C2R3 P3 limits items {} size {}",
        b.meta.history_max_items, b.meta.history_max_size
    );
    let mut a = world();
    let mut c = container0();
    let mut planted = pw(E, "planted-demo", NOW, NOW);
    planted.set_field(
        "Notes".to_owned(),
        Field {
            value: SecretString::new("x".repeat(7 << 20)),
            protected: false,
        },
    );
    c.root.entries.push(planted);
    run::merge_into(&mut a, id(T), &c, NOW).unwrap();
    merge(&mut b, &a, &Options::new(Kind::ChangeOnDisk), NOW).unwrap();
    let e = entry_of(&b, E);
    // Added in round 4 (C2R3-04): the entry's own versions stay.
    let own = |e: &Entry| {
        (0..5).all(|i| {
            e.history
                .iter()
                .any(|h| h.value("Password") == format!("private-old-{i}"))
        })
    };
    assert!(
        own(e),
        "the losing value pushed out the entry's own history"
    );
    eprintln!(
        "C2R3 P3 size: place {:x?} value {} history {:?}",
        b.root
            .subtree()
            .iter()
            .find(|g| g.entries.iter().any(|x| x.uuid == id(E)))
            .map(|g| g.uuid.0[0]),
        e.value("Password"),
        e.history
            .iter()
            .map(|h| h.value("Password").to_owned())
            .collect::<Vec<_>>()
    );

    // By count: ten imports, each a new value, on the default limit of items.
    let mut b = world();
    let mut e = pw(E, "private-now", Time(T0.0 + 10), T0);
    for i in 0..5 {
        let mut h = pw(E, &format!("private-old-{i}"), Time(T0.0 + i), T0);
        h.history.clear();
        e.history.push(h);
    }
    gm(&mut b.root, P).unwrap().entries.push(e);
    let mut a = world();
    for n in 0..12i64 {
        let now = Time(NOW.0 + n);
        let mut c = container0();
        c.root
            .entries
            .push(pw(E, &format!("planted-{n}"), now, now));
        run::merge_into(&mut a, id(T), &c, now).unwrap();
        merge(&mut b, &a, &Options::new(Kind::ChangeOnDisk), now).unwrap();
        merge(&mut a, &b, &Options::new(Kind::ChangeOnDisk), now).unwrap();
    }
    let e = entry_of(&b, E);
    eprintln!(
        "C2R3 P3 count: value {} history {:?}",
        e.value("Password"),
        e.history
            .iter()
            .map(|h| h.value("Password").to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(e.value("Password"), "private-now");
    // Added in round 4 (C2R3-04).
    assert!(
        own(e),
        "twelve losing values pushed out the entry's own history"
    );
}

/// A clone keeps stamp and marker; the copy route does not.
#[test]
fn p4_a_clone_keeps_the_stamp_and_the_marker() {
    let mut v = world();
    gm(&mut v.root, P)
        .unwrap()
        .entries
        .push(pw(E, "private-demo", T0, T0));
    edit::move_entries(&mut v, &[id(E)], id(T), Time(T0.0 + 5)).unwrap();
    let new = clone::clone_entry(
        &mut v,
        id(E),
        clone::Options {
            history: true,
            suffix: true,
            refs: false,
        },
        &clone::Limits::DEFAULT,
        NOW,
    )
    .unwrap();
    let c = v.root.all_entries().find(|e| e.uuid == new).unwrap();
    eprintln!(
        "C2R3 P4: clone stamp {:?}, marker {:?}",
        origin::stamp_of(&c.custom_data).map(|s| s.at.0 - T0.0),
        origin::mark_of(&c.custom_data).map(|m| m.0[0])
    );
    // Added in round 4 (C2R3-08): a clone is a new object of this Mac, so it carries
    // neither; its history keeps any private item.
    assert!(
        origin::stamp_of(&c.custom_data).is_none(),
        "clone keeps the stamp"
    );
    assert!(
        origin::mark_of(&c.custom_data).is_none(),
        "clone keeps the marker"
    );
    let mut c2 = container0();
    c2.root.entries.push(pw(0x52, "planted-demo", NOW, NOW));
    run::merge_into(&mut v, id(T), &c2, NOW).unwrap();
    let new2 = clone::clone_entry(
        &mut v,
        id(0x52),
        clone::Options {
            history: true,
            suffix: true,
            refs: false,
        },
        &clone::Limits::DEFAULT,
        NOW,
    )
    .unwrap();
    let c = v.root.all_entries().find(|e| e.uuid == new2).unwrap();
    eprintln!(
        "C2R3 P4: clone of a brought entry, marker {:?}",
        origin::mark_of(&c.custom_data).map(|m| m.0[0])
    );
    assert!(
        origin::mark_of(&c.custom_data).is_none(),
        "added in round 4"
    );
}

/// Round 4 (C2R3-08, the group form of p4): a group clone carries no stamp and no
/// marker, on the group or anything in it: a group the user moved into T, and a group
/// a container brought.
#[test]
fn r4_p4b_a_group_clone_carries_no_stamp_and_no_marker() {
    let mut v = world();
    let mut g = Group::new(id(0x40), "Moved".into(), T0);
    g.entries.push(pw(E, "private-demo", T0, T0));
    gm(&mut v.root, P).unwrap().groups.push(g);
    edit::move_group(&mut v, id(0x40), id(T), edit::Position::End, Time(T0.0 + 5)).unwrap();
    let mut c = container0();
    let mut b = Group::new(id(0x41), "Brought".into(), NOW);
    b.entries.push(pw(0x52, "planted-demo", NOW, NOW));
    c.root.groups.push(b);
    run::merge_into(&mut v, id(T), &c, NOW).unwrap();
    let marked = |g: &Group| {
        g.subtree().iter().any(|x| {
            origin::stamp_of(&x.custom_data).is_some() || origin::mark_of(&x.custom_data).is_some()
        }) || g.all_entries().any(|e| {
            origin::stamp_of(&e.custom_data).is_some() || origin::mark_of(&e.custom_data).is_some()
        })
    };
    for x in [0x40, 0x41] {
        let original = v.root.find_group(id(x)).unwrap();
        assert!(
            marked(original),
            "{x:x}: the original carries a stamp or marker"
        );
        let copy = clone::clone_group(&v, id(x), &clone::Limits::DEFAULT, NOW).unwrap();
        assert!(!marked(&copy), "{x:x}: the clone keeps a stamp or a marker");
    }
}

/// An entry at the custom data limit less one: the marker fits. A user's move in adds
/// a stamp, and the vault no longer saves.
#[test]
fn p5_a_stamp_past_the_item_limit_blocks_the_save() {
    let mut v = world();
    let mut c = container0();
    let mut e = pw(E, "planted-demo", NOW, NOW);
    for i in 0..Limits::DEFAULT.custom_data_items - 1 {
        e.custom_data.items.push(item(&format!("k{i}"), ""));
    }
    c.root.entries.push(e);
    run::merge_into(&mut v, id(T), &c, NOW).unwrap();
    assert!(save_bytes(&v).is_ok(), "marker fits");
    edit::move_entries(&mut v, &[id(E)], id(P), Time(NOW.0 + 1)).unwrap();
    assert!(save_bytes(&v).is_ok(), "moved out, stamp gone");
    edit::move_entries(&mut v, &[id(E)], id(T), Time(NOW.0 + 2)).unwrap();
    let saved = save_bytes(&v);
    eprintln!(
        "C2R3 P5: save after the move in: {:?}",
        saved.as_ref().map(|b| b.len()).map_err(|e| e.to_string())
    );
    // Added in round 4 (C2R3-06): at the item limit the move writes no stamp, and the
    // vault saves (the move in may then be undone, as limit 2).
    assert!(saved.is_ok(), "a stamp past the item limit blocks the save");
}

/// Rows at far negative times: 54 bytes a row, not 45, and they survive a real save.
#[test]
fn p6_row_size_at_extreme_times() {
    let mut v = world();
    let mut c = container0();
    c.deleted_objects = (0..10u64)
        .map(|i| DeletedObject {
            uuid: big(i, 7),
            deleted_at: Time(i64::MIN + 1),
            unknown: Vec::new(),
        })
        .collect();
    c.deleted_objects.push(DeletedObject {
        uuid: big(99, 7),
        deleted_at: Time(i64::MAX),
        unknown: Vec::new(),
    });
    run::merge_into(&mut v, id(T), &c, NOW).unwrap();
    let v2 = reopen(&v);
    let text = v2.meta.custom_data.get(origin::SCOPES).unwrap();
    eprintln!(
        "C2R3 P6: row text {} bytes for 11 rows; {}",
        text.len(),
        &text[..120]
    );
    let rows = origin::read_rows(&v2.meta.custom_data);
    assert_eq!(rows.len(), 11);
    assert!(
        rows.values().all(|t| *t <= NOW),
        "no row is later than the import"
    );
    // Added in round 4 (C2R3-05): no row is earlier than the format's first time, so
    // a row keeps its stated size of 45 bytes.
    assert!(rows.values().all(|t| t.0 >= 0), "a row below time zero");
    assert!(
        text.len() <= 33 + 11 * 45,
        "{} bytes for 11 rows",
        text.len()
    );
    let b = container::build(id(T), true, &v2, NOW).unwrap();
    assert!(save_bytes(&b).is_ok(), "the export saves");
}

/// A list at the limit of 1,000,000 plain records plus one row: the vault saves, and the
/// export of the share saves with its list cut at the format's limit. In the default
/// suite since round 5 (C1R4-08: it is the check that the cut is there and exact; 10 s
/// in a test build).
#[test]
fn p7_a_full_plain_list_and_one_row_block_the_export() {
    let mut v = world();
    v.deleted_objects = (0..Limits::DEFAULT.deleted_objects as u64)
        .map(|i| DeletedObject {
            uuid: big(i, 8),
            deleted_at: T0,
            unknown: Vec::new(),
        })
        .collect();
    let mut c = container0();
    c.deleted_objects = vec![DeletedObject {
        uuid: big(0, 9),
        deleted_at: T0,
        unknown: Vec::new(),
    }];
    run::merge_into(&mut v, id(T), &c, NOW).unwrap();
    eprintln!(
        "C2R3 P7: vault save {:?}",
        save_bytes(&v).map(|b| b.len()).map_err(|e| e.to_string())
    );
    let b = container::build(id(T), true, &v, NOW).unwrap();
    eprintln!(
        "C2R3 P7: export list {} save {:?}",
        b.deleted_objects.len(),
        save_bytes(&b).map(|x| x.len()).map_err(|e| e.to_string())
    );
    // Added in round 4 (C2R3-07): the export's list stops at the format's limit, so it
    // saves; what is cut is the rows after the plain records, in the export only.
    assert_eq!(b.deleted_objects.len(), Limits::DEFAULT.deleted_objects);
    assert!(save_bytes(&b).is_ok(), "the export saves");
}

/// A file that keeps the items and moves objects without touching them, as another
/// app or an older Larsal does: E moved in by a user, stamped; the other app moves
/// the copy out and edits it, stamp kept. Nothing leaks, nothing erased.
#[test]
fn p8_another_app_that_keeps_the_items() {
    let mut a = world();
    gm(&mut a.root, P)
        .unwrap()
        .entries
        .push(pw(E, "seed-demo", T0, T0));
    edit::move_entries(&mut a, &[id(E)], id(T), Time(T0.0 + 5)).unwrap();
    let mut other = a.duplicate();
    // The other app moves it out with no rule: stamp stays, Loc and Mod move.
    let mut e = gm(&mut other.root, T).unwrap().entries.remove(0);
    e.times.location_changed = Time(T0.0 + 9);
    e.times.last_modification = Time(T0.0 + 9);
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new("private-demo".to_owned()),
            protected: true,
        },
    );
    gm(&mut other.root, P).unwrap().entries.push(e);
    let other = reopen(&other);
    assert!(
        origin::stamp_of(&entry_of(&other, E).custom_data).is_some(),
        "kept by the file"
    );
    let mut x = a.duplicate();
    merge(&mut x, &other, &Options::new(Kind::ChangeOnDisk), NOW).unwrap();
    let mut y = other.duplicate();
    merge(&mut y, &a, &Options::new(Kind::ChangeOnDisk), NOW).unwrap();
    for v in [&x, &y] {
        let place = v
            .root
            .subtree()
            .iter()
            .find(|g| g.entries.iter().any(|e| e.uuid == id(E)))
            .map(|g| g.uuid);
        assert_eq!(place, Some(id(P)));
        assert_eq!(entry_of(v, E).value("Password"), "private-demo");
        assert!(
            origin::stamp_of(&entry_of(v, E).custom_data).is_none(),
            "normal form"
        );
    }
}

/// Negative times through a real file, and how many shares at the cap fit.
#[test]
#[ignore = "heavy"]
fn p9_rows_at_extreme_times_through_a_real_file_and_the_text_limit() {
    let mut root = Group::new(id(1), "Root".into(), T0);
    let shares: Vec<u8> = (0..16u8).map(|i| 0x80 + i).collect();
    for s in &shares {
        let mut t = Group::new(id(*s), "T".into(), T0);
        t.custom_data
            .items
            .push(item(core::str::from_utf8(edit::SHARED_KEY).unwrap(), ""));
        root.groups.push(t);
    }
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = false;
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    let password = SecretString::new("share-demo".to_owned());
    let path = std::env::temp_dir().join("c2r3-p9.larsalvault");
    for (i, s) in shares.iter().enumerate() {
        let mut c = Vault::new(Group::new(id(*s), "T".into(), T0), T0);
        c.meta.recycle_bin_enabled = false;
        c.encryption.kdf = Kdf::AesKdf { rounds: 1 };
        c.deleted_objects = (0..100_000u64)
            .map(|n| DeletedObject {
                uuid: big(n + (i as u64) * 1_000_000, 7),
                deleted_at: Time(i64::MIN + 1),
                unknown: Vec::new(),
            })
            .collect();
        container::write_file(&path, &c, &password, &mut host(), &Limits::DEFAULT, &[]).unwrap();
        let opened = container::open_file(&path, &password, &mut host(), &Limits::DEFAULT);
        let opened = match opened {
            Ok(o) => o.vault,
            Err(e) => {
                eprintln!("C2R3 P9: share {i}: the file does not open: {e}");
                break;
            }
        };
        if i == 0 {
            eprintln!(
                "C2R3 P9: time read back {:?}",
                opened.deleted_objects.first().map(|d| d.deleted_at.0)
            );
        }
        run::merge_into(&mut v, id(*s), &opened, NOW).unwrap();
        let text = v.meta.custom_data.get(origin::SCOPES).map_or(0, str::len);
        let saved = save_bytes(&v).map(|b| b.len()).map_err(|e| e.to_string());
        eprintln!(
            "C2R3 P9: {} shares at the cap: row text {text} bytes, save {saved:?}",
            i + 1
        );
        if saved.is_err() {
            break;
        }
    }
    std::fs::remove_file(&path).ok();
}
