//! The second checker's model-level probes of round 2, ported to rule R6: printed
//! there, asserted here. Demo data only. The scale tests are run by hand.
#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use larsal_core::merge::{Kind, Options, merge};
use larsal_core::origin;
use larsal_core::recycle::{self, References};
use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved};
use larsal_model::settings::Kdf;
use larsal_model::{DeletedObject, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};
use std::time::Instant;

const T0: Time = Time(63_902_822_400);
const NOW: Time = Time(63_910_000_000);
const FAR: Time = Time(66_910_000_000);
const KINDS: [Kind; 6] = [
    Kind::ChangeOnDisk,
    Kind::ConflictCopy,
    Kind::ServerSync,
    Kind::Window,
    Kind::CommandLine,
    Kind::RemoteSync,
];

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

fn pw(n: Uuid, password: &str, at: Time) -> Entry {
    let mut e = Entry::new(n, at);
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new(password.to_owned()),
            protected: true,
        },
    );
    e
}

fn with(mut e: Entry, modified: Time, moved: Time) -> Entry {
    e.times.last_modification = modified;
    e.times.location_changed = moved;
    e
}

fn record(uuid: Uuid, deleted_at: Time) -> DeletedObject {
    DeletedObject {
        uuid,
        deleted_at,
        unknown: Vec::new(),
    }
}

fn empty_container() -> Vault {
    let root = Group::new(id(0x66), "Share".into(), T0);
    let mut c = Vault::new(root, T0);
    c.meta.recycle_bin_enabled = false;
    c
}

fn where_is(v: &Vault, x: Uuid) -> Option<String> {
    v.root
        .subtree()
        .iter()
        .find(|g| g.entries.iter().any(|e| e.uuid == x))
        .map(|g| g.name.clone())
}

fn value(v: &Vault, x: Uuid) -> Option<String> {
    v.root
        .all_entries()
        .find(|e| e.uuid == x)
        .map(|e| e.value("Password").to_owned())
}

fn export_holds(v: &Vault, group: Uuid, secret: &str) -> bool {
    let c = container::build(group, true, v, NOW).unwrap();
    assert!(!origin::held(&c), "an export holds none of the four");
    c.root.all_entries().any(|e| {
        e.value("Password") == secret || e.history.iter().any(|h| h.value("Password") == secret)
    })
}

fn group_mut(g: &mut Group, x: Uuid) -> Option<&mut Group> {
    if g.uuid == x {
        return Some(g);
    }
    g.groups.iter_mut().find_map(|c| group_mut(c, x))
}

fn delete(v: &mut Vault, x: Uuid, at: Time) {
    recycle::delete_entries(v, &[x], at, |_, _| References::Delete).unwrap();
}

/// CR2-03: two shares, three copies, a hostile member of both. Mac A imports S1 and
/// Mac C imports S2, each far ahead. Mac B's outside E keeps its place and value.
#[test]
fn cr2_03_two_shares_and_a_third_copy_keep_mac_bs_value() {
    let (s1, s2) = (id(0x20), id(0x22));
    let mut base_root = Group::new(id(0x01), "Root".into(), T0);
    base_root.groups.push(Group::new(s1, "S1".into(), T0));
    base_root.groups.push(Group::new(s2, "S2".into(), T0));
    let common = Vault::new(base_root, T0);
    let mut mac_a = common.duplicate();
    let mut mac_c = common.duplicate();
    let mut mac_b = common.duplicate();
    let mut p = Group::new(id(0x30), "P".into(), T0);
    let at = Time(T0.0 + 1000);
    p.entries.push(with(pw(id(0x50), "mac-b-demo", T0), at, at));
    mac_b.root.groups.push(p);
    let mut c1 = empty_container();
    c1.root
        .entries
        .push(with(pw(id(0x50), "planted-one", T0), FAR, FAR));
    let mut c2 = empty_container();
    c2.root
        .entries
        .push(with(pw(id(0x50), "planted-two", T0), FAR, FAR));
    run::merge_into(&mut mac_a, s1, &c1, NOW).unwrap();
    run::merge_into(&mut mac_c, s2, &c2, NOW).unwrap();
    for kind in KINDS {
        let o = Options::new(kind);
        let mut merged = mac_a.duplicate();
        merge(&mut merged, &mac_c, &o, NOW).unwrap();
        let mut b = mac_b.duplicate();
        merge(&mut b, &merged, &o, NOW).unwrap();
        assert_eq!(
            value(&b, id(0x50)).as_deref(),
            Some("mac-b-demo"),
            "{kind:?}"
        );
        assert_eq!(where_is(&b, id(0x50)).as_deref(), Some("P"), "{kind:?}");
        for s in [s1, s2] {
            assert!(!export_holds(&b, s, "mac-b-demo"), "{kind:?}");
        }
    }
    // And Mac B against A alone, as control.
    let mut b = mac_b.duplicate();
    merge(&mut b, &mac_a, &Options::new(Kind::ConflictCopy), NOW).unwrap();
    assert_eq!(value(&b, id(0x50)).as_deref(), Some("mac-b-demo"));
}

/// CR2-01: a row of the share, and then the user's own deletion of that id.
#[test]
fn cr2_01_a_users_own_deletion_beside_a_row_reaches_the_other_mac() {
    let s = id(0x20);
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups.push(Group::new(s, "S".into(), T0));
    let mut common = Vault::new(root, T0);
    common.meta.recycle_bin_enabled = false;
    let mut mac_a = common.duplicate();
    let mut mac_b = common.duplicate();
    let mut p = Group::new(id(0x30), "P".into(), T0);
    p.entries.push(pw(id(0x50), "mac-b-demo", T0));
    mac_b.root.groups.push(p);
    let mac_c = mac_b.duplicate();
    let mut c = empty_container();
    c.deleted_objects.push(record(id(0x50), FAR));
    run::merge_into(&mut mac_a, s, &c, NOW).unwrap();
    let o = Options::new(Kind::ConflictCopy);
    merge(&mut mac_b, &mac_a, &o, NOW).unwrap();
    assert_eq!(value(&mac_b, id(0x50)).as_deref(), Some("mac-b-demo"));
    assert_eq!(mac_b.deleted_objects.len(), 0, "a row, off the list");
    assert_eq!(origin::read_rows(&mac_b.meta.custom_data).len(), 1);
    // The user deletes E for good on Mac B (the bin is off).
    let later = Time(NOW.0 + 1000);
    delete(&mut mac_b, id(0x50), later);
    assert_eq!(value(&mac_b, id(0x50)), None);
    assert_eq!(mac_b.deleted_objects.len(), 1, "the user's plain record");
    // Mac C still holds E, unchanged since before the user's deletion.
    let mut c2 = mac_c.duplicate();
    merge(&mut c2, &mac_b, &o, Time(NOW.0 + 2000)).unwrap();
    assert_eq!(value(&c2, id(0x50)), None, "Mac C after merging B");
    let mut b2 = mac_b.duplicate();
    merge(&mut b2, &mac_c, &o, Time(NOW.0 + 2000)).unwrap();
    assert_eq!(value(&b2, id(0x50)), None, "Mac B after merging C");
    // Control: the same with no row.
    let mut b3 = mac_c.duplicate();
    let mut c3 = mac_c.duplicate();
    delete(&mut b3, id(0x50), later);
    merge(&mut c3, &b3, &o, Time(NOW.0 + 2000)).unwrap();
    assert_eq!(value(&c3, id(0x50)), None, "control");
}

/// None of the four items reaches an export, in the model of it or in its file. A
/// history item with the marker too.
#[test]
fn c2_the_file_of_an_export_holds_none_of_the_rules_items() {
    let s = id(0x20);
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups.push(Group::new(s, "S".into(), T0));
    let mut v = Vault::new(root, T0);
    v.encryption.kdf = Kdf::AesKdf { rounds: 1000 };
    let mut c = empty_container();
    c.root.entries.push(pw(id(0x50), "demo", T0));
    let mut g = Group::new(id(0x31), "G".into(), T0);
    g.entries.push(pw(id(0x51), "demo", T0));
    c.root.groups.push(g);
    c.deleted_objects.push(record(id(0x52), T0));
    run::merge_into(&mut v, s, &c, NOW).unwrap();
    let e = v.root.groups[0]
        .entries
        .iter_mut()
        .find(|e| e.uuid == id(0x50))
        .unwrap();
    let h = e.duplicate(false);
    e.history.push(h);
    origin::set_stamp(
        &mut e.custom_data,
        Some(origin::Stamp { group: s, at: NOW }),
    );
    assert!(origin::held(&v));
    let export = container::build(s, true, &v, NOW).unwrap();
    assert!(!origin::held(&export), "the model of the export");
    let bytes = save_bytes(&cheap(export), "demo");
    let pw_ = SecretString::new("demo".to_owned());
    let key = Credentials {
        password: Some(&pw_),
        ..Credentials::default()
    };
    match larsal_format::open(&bytes, &key, &mut host(), &Limits::DEFAULT, None).unwrap() {
        Opened::Vault(o) => {
            assert!(!origin::held(&o.vault), "the file of the export");
            assert_eq!(
                o.vault.deleted_objects.len(),
                1,
                "the list a member needs still goes"
            );
        }
        Opened::Ask(_) => panic!("asked"),
    }
}

/// Attack A of the second checker, at model level: E and group H moved out on Mac B
/// with private values. The container moves both inside the share, far ahead.
#[test]
fn cr2_02_a_holders_entry_and_group_stay_out_with_their_values() {
    let common = || {
        let mut s = Group::new(id(0x20), "S".into(), T0);
        s.entries.push(pw(id(0x50), "was-shared-demo", T0));
        let mut h = Group::new(id(0x31), "H".into(), T0);
        h.entries.push(pw(id(0x51), "was-shared-demo", T0));
        s.groups.push(h);
        let mut root = Group::new(id(0x01), "Root".into(), T0);
        root.groups = vec![s, Group::new(id(0x30), "P".into(), T0)];
        Vault::new(root, T0)
    };
    let move_at = Time(T0.0 + 1000);
    let mut b = common();
    larsal_core::edit::move_entries(&mut b, &[id(0x50)], id(0x30), move_at).unwrap();
    larsal_core::edit::move_group(
        &mut b,
        id(0x31),
        id(0x30),
        larsal_core::edit::Position::End,
        move_at,
    )
    .unwrap();
    let e = group_mut(&mut b.root, id(0x30))
        .unwrap()
        .entries
        .iter_mut()
        .find(|e| e.uuid == id(0x50))
        .unwrap();
    e.times.last_modification = Time(T0.0 + 2000);
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new("mac-b-private-demo".to_owned()),
            protected: true,
        },
    );
    group_mut(&mut b.root, id(0x31)).unwrap().entries.push(pw(
        id(0x52),
        "mac-b-private-in-group-demo",
        T0,
    ));
    let mut a = common();
    let mut c = Vault::new(Group::new(id(0x66), "Share".into(), T0), T0);
    let mut new_home = Group::new(id(0x41), "Moved".into(), T0);
    let mut pe = pw(id(0x50), "was-shared-demo", T0);
    pe.times.location_changed = FAR;
    new_home.entries.push(pe);
    let mut ph = Group::new(id(0x31), "H".into(), T0);
    ph.times.location_changed = FAR;
    ph.entries.push(pw(id(0x51), "was-shared-demo", T0));
    new_home.groups.push(ph);
    c.root.groups.push(new_home);
    run::merge_into(&mut a, id(0x20), &c, NOW).unwrap();
    for kind in KINDS {
        let mut t = b.duplicate();
        merge(&mut t, &a, &Options::new(kind), NOW).unwrap();
        assert_eq!(where_is(&t, id(0x50)).as_deref(), Some("P"), "{kind:?}");
        assert_eq!(
            value(&t, id(0x50)).as_deref(),
            Some("mac-b-private-demo"),
            "{kind:?}"
        );
        assert!(
            t.root.groups[0].find_group(id(0x31)).is_none(),
            "{kind:?}: H stays out"
        );
        assert_eq!(where_is(&t, id(0x51)).as_deref(), Some("H"), "{kind:?}");
        assert!(
            !export_holds(&t, id(0x20), "mac-b-private-demo"),
            "{kind:?}"
        );
        assert!(
            !export_holds(&t, id(0x20), "mac-b-private-in-group-demo"),
            "{kind:?}"
        );
    }
}

/// CR2-01 at model level, also on the base: a row beside a copy kept outside the
/// share, then the user deletes that copy for good. It stays deleted on repeat rounds.
#[test]
fn cr2_01_a_holders_later_deletion_stays() {
    let mut s = Group::new(id(0x20), "S".into(), T0);
    s.entries.push(pw(id(0x50), "was-shared-demo", T0));
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups = vec![s, Group::new(id(0x30), "P".into(), T0)];
    let mut common = Vault::new(root, T0);
    common.meta.recycle_bin_enabled = false;
    let mut b = common.duplicate();
    larsal_core::edit::move_entries(&mut b, &[id(0x50)], id(0x30), Time(T0.0 + 1000)).unwrap();
    let mut a = common.duplicate();
    let mut c = empty_container();
    c.deleted_objects.push(record(id(0x50), Time(T0.0 + 500)));
    run::merge_into(&mut a, id(0x20), &c, NOW).unwrap();
    let opts = || Options::new(Kind::ChangeOnDisk);
    merge(&mut b, &a, &opts(), NOW).unwrap();
    merge(&mut a, &b, &opts(), NOW).unwrap();
    assert_eq!(where_is(&b, id(0x50)).as_deref(), Some("P"), "settled");
    assert_eq!(where_is(&a, id(0x50)).as_deref(), Some("P"), "settled");
    delete(&mut b, id(0x50), Time(NOW.0 + 900));
    assert_eq!(b.deleted_objects.len(), 1);
    for round in 0..2 {
        let later = Time(NOW.0 + 1000 + round);
        merge(&mut a, &b, &opts(), later).unwrap();
        merge(&mut b, &a, &opts(), later).unwrap();
        assert_eq!(where_is(&a, id(0x50)), None, "round {round}");
        assert_eq!(where_is(&b, id(0x50)), None, "round {round}");
    }
}

/// C2-2 again: the first container brings E and G{F} and no item; the second lists
/// them. Mac A never held them; Mac B holds them outside the share.
#[test]
fn c2_2_two_imports_crossing_leave_mac_b_alone() {
    let mut s = Group::new(id(0x20), "S".into(), T0);
    s.groups.push(Group::new(id(0x31), "H".into(), T0));
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups = vec![s, Group::new(id(0x30), "P".into(), T0)];
    let common = Vault::new(root, T0);
    let mut b = common.duplicate();
    let late = Time(T0.0 + 9000);
    let mut own = pw(id(0x70), "mac-b-e-demo", T0);
    own.times.last_modification = late;
    let mut g = Group::new(id(0x71), "G".into(), T0);
    g.times.last_modification = late;
    let mut own_f = pw(id(0x72), "mac-b-f-demo", T0);
    own_f.times.last_modification = late;
    g.entries.push(own_f);
    {
        let p = group_mut(&mut b.root, id(0x30)).unwrap();
        p.entries.push(own);
        p.groups.push(g);
    }
    let mut a = common.duplicate();
    let mut first = empty_container();
    first.root.entries.push(pw(id(0x70), "planted-e-demo", T0));
    let mut pg = Group::new(id(0x71), "G".into(), T0);
    pg.entries.push(pw(id(0x72), "planted-f-demo", T0));
    first.root.groups.push(pg);
    run::merge_into(&mut a, id(0x20), &first, NOW).unwrap();
    let mut second = empty_container();
    for n in [0x70u8, 0x71, 0x72] {
        second.deleted_objects.push(record(id(n), FAR));
    }
    run::merge_into(&mut a, id(0x20), &second, Time(NOW.0 + 1)).unwrap();
    assert_eq!(where_is(&a, id(0x70)), None, "erased on A");
    assert_eq!(where_is(&a, id(0x72)), None, "erased on A");
    assert_eq!(a.deleted_objects.len(), 0, "rows, off the list");
    assert_eq!(origin::read_rows(&a.meta.custom_data).len(), 3);
    for kind in KINDS {
        let mut t = b.duplicate();
        for round in 0..2 {
            merge(&mut t, &a, &Options::new(kind), Time(NOW.0 + 2 + round)).unwrap();
        }
        assert_eq!(
            value(&t, id(0x70)).as_deref(),
            Some("mac-b-e-demo"),
            "{kind:?}"
        );
        assert_eq!(
            value(&t, id(0x72)).as_deref(),
            Some("mac-b-f-demo"),
            "{kind:?}"
        );
        assert_eq!(where_is(&t, id(0x70)).as_deref(), Some("P"), "{kind:?}");
        assert_eq!(where_is(&t, id(0x72)).as_deref(), Some("G"), "{kind:?}");
    }
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

fn save_bytes(v: &Vault, pass: &str) -> Vec<u8> {
    let p = SecretString::new(pass.to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    let mut h = host();
    let mut save = |a: Option<&larsal_crypto::kdf::CostReport>| {
        larsal_format::save(v, &key, None, &mut h, &Limits::DEFAULT, a)
    };
    match save(None).unwrap() {
        Saved::File(f) => f.bytes,
        Saved::Ask(r) => match save(Some(&r)).unwrap() {
            Saved::File(f) => f.bytes,
            Saved::Ask(_) => panic!("asked twice"),
        },
    }
}

fn n_env() -> usize {
    std::env::var("R6_N")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(1000)
}

fn timed<R>(what: &str, n: usize, f: impl FnOnce() -> R) -> R {
    let t = Instant::now();
    let r = f();
    eprintln!("R6 SCALE {what} n={n}: {:.3} s", t.elapsed().as_secs_f64());
    r
}

fn cheap(mut v: Vault) -> Vault {
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    v
}

/// A hostile container with N items that name nothing. Import, trial, saves and
/// same-vault merges. Run once per N, so the peak memory of the process is N's.
#[test]
#[ignore = "scale"]
fn scale_rows() {
    let n = n_env();
    let s = id(0x20);
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups.push(Group::new(s, "S".into(), T0));
    let common = cheap(Vault::new(root, T0));
    let mut c = empty_container();
    c.deleted_objects = (0..n as u64).map(|i| record(big(i, 1), T0)).collect();
    let mut a = common.duplicate();
    timed("import merge", n, || {
        run::merge_into(&mut a, s, &c, NOW).unwrap()
    });
    let rows = a.meta.custom_data.get(origin::SCOPES).map_or(0, str::len);
    eprintln!("R6 SCALE row bytes n={n}: {rows}");
    assert!(origin::read_rows(&a.meta.custom_data).len() <= origin::ROW_CAP);
    let mut h = host();
    let fits = timed("import with trial save", n, || {
        run::fits(common.duplicate(), s, &c, NOW, &mut h).map(|x| x.1.is_some())
    });
    eprintln!("R6 SCALE fits n={n}: {fits:?}");
    let bytes = timed("save", n, || save_bytes(&a, "demo"));
    eprintln!("R6 SCALE file bytes n={n}: {}", bytes.len());
    let p = SecretString::new("demo".to_owned());
    let key = Credentials {
        password: Some(&p),
        ..Credentials::default()
    };
    timed("open", n, || {
        larsal_format::open(&bytes, &key, &mut host(), &Limits::DEFAULT, None).map(|_| ())
    })
    .unwrap();
    let mut b = common.duplicate();
    let o = Options::new(Kind::ConflictCopy);
    timed("same-vault merge, new rows", n, || {
        merge(&mut b, &a, &o, NOW).unwrap()
    });
    timed("same-vault merge again", n, || {
        merge(&mut b, &a, &o, NOW).unwrap()
    });
    let mut c2 = empty_container();
    c2.deleted_objects = (0..n as u64).map(|i| record(big(i, 2), T0)).collect();
    let mut d = common.duplicate();
    run::merge_into(&mut d, s, &c2, NOW).unwrap();
    timed("same-vault merge two lists", n, || {
        merge(&mut d, &a, &o, NOW).unwrap()
    });
    eprintln!(
        "R6 SCALE union bytes n={n}: {}",
        d.meta.custom_data.get(origin::SCOPES).map_or(0, str::len)
    );
}

/// N planted entries on Mac A, the same ids outside on Mac B, under a deep chain.
#[test]
#[ignore = "scale"]
fn scale_planted() {
    let n = n_env();
    let depth: usize = std::env::var("R6_D")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let s = id(0x20);
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups.push(Group::new(s, "S".into(), T0));
    let common = cheap(Vault::new(root, T0));
    let mut mac_a = common.duplicate();
    let mut mac_b = common.duplicate();
    let mut bottom = Group::new(big(0, 9), "bottom".into(), T0);
    bottom.entries = (0..n as u64)
        .map(|i| pw(big(i, 3), "mac-b-demo", T0))
        .collect();
    let mut top = bottom;
    for d in 1..=depth as u64 {
        let mut g = Group::new(big(d, 9), "chain".into(), T0);
        g.groups.push(top);
        top = g;
    }
    let mut p = Group::new(id(0x30), "P".into(), T0);
    p.groups.push(top);
    mac_b.root.groups.push(p);
    let mut cb = Group::new(big(0, 8), "bottom".into(), T0);
    cb.entries = (0..n as u64)
        .map(|i| with(pw(big(i, 3), "planted-demo", T0), FAR, FAR))
        .collect();
    let mut ct = cb;
    for d in 1..=depth as u64 {
        let mut g = Group::new(big(d, 8), "chain".into(), T0);
        g.groups.push(ct);
        ct = g;
    }
    let mut c = empty_container();
    c.root.groups.push(ct);
    timed("import planted", n, || {
        run::merge_into(&mut mac_a, s, &c, NOW).unwrap()
    });
    let o = Options::new(Kind::ConflictCopy);
    let mut b = mac_b.duplicate();
    timed("merge A into B, the target stays", n, || {
        merge(&mut b, &mac_a, &o, NOW).unwrap()
    });
    let mut a = mac_a.duplicate();
    timed("merge B into A, the source whole", n, || {
        merge(&mut a, &mac_b, &o, NOW).unwrap()
    });
    let mut again = a.duplicate();
    timed("merge B into A again", n, || {
        merge(&mut again, &mac_b, &o, NOW).unwrap()
    });
    assert_eq!(value(&b, big(0, 3)).as_deref(), Some("mac-b-demo"));
    assert_eq!(value(&a, big(0, 3)).as_deref(), Some("mac-b-demo"));
}

/// CR2-07: each share's rows at the cap, enough shares to pass the text limit. The
/// import's trial save refuses with MI08-02 and nothing is lost: the copy from before
/// the refused import still saves.
#[test]
#[ignore = "scale"]
fn cr2_07_rows_past_the_text_limit_refuse_the_import() {
    let groups: Vec<Uuid> = (0..20u8).map(|n| id(0x80 + n)).collect();
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    for x in &groups {
        root.groups.push(Group::new(*x, "S".into(), T0));
    }
    let common = cheap(Vault::new(root, T0));
    let mut c = empty_container();
    c.deleted_objects = (0..origin::ROW_CAP as u64)
        .map(|i| record(big(i, 1), T0))
        .collect();
    let mut h = host();
    let mut now = common.duplicate();
    let mut refused = None;
    for (i, g) in groups.iter().enumerate() {
        match run::fits(now.duplicate(), *g, &c, NOW, &mut h) {
            Ok((_, Some(next))) => now = next,
            Ok((_, None)) => panic!("the import changed nothing"),
            Err(e) => {
                refused = Some((i, e.to_string()));
                break;
            }
        }
        eprintln!(
            "R6 CR2-07 share {i}: row text {} bytes",
            now.meta.custom_data.get(origin::SCOPES).map_or(0, str::len)
        );
    }
    eprintln!("R6 CR2-07 refused at {refused:?}");
    assert!(refused.is_some(), "twenty shares pass the text limit");
    assert!(!save_bytes(&now, "demo").is_empty(), "the kept copy saves");
}
