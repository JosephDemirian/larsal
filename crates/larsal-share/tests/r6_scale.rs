//! Checker 2, round 3, ported in round 4: size and time under a hostile container. Demo data.
//! Builds on both trees: nothing here names rule R6's items. Run by hand: one size
//! per process, `C2_N`, so the peak memory of the process is that size's.
#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use larsal_core::merge::{Kind, Options, merge};
use larsal_core::recycle;
use larsal_crypto::secret::SecretString;
use larsal_model::custom_data::CustomDataItem;
use larsal_model::{DeletedObject, Entry, Field, Group, Time, Uuid, Vault};
use larsal_share::{container, run};
use std::time::Instant;

const T0: Time = Time(63_902_822_400);
const NOW: Time = Time(63_910_000_000);

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

fn n_env() -> usize {
    std::env::var("C2_N")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(1000)
}

fn timed<R>(what: &str, n: usize, f: impl FnOnce() -> R) -> R {
    let t = Instant::now();
    let r = f();
    eprintln!("C2 SCALE {what} n={n}: {:.3} s", t.elapsed().as_secs_f64());
    r
}

fn share_item() -> CustomDataItem {
    CustomDataItem {
        key: core::str::from_utf8(larsal_core::edit::SHARED_KEY)
            .unwrap()
            .to_owned(),
        value: SecretString::new(String::new()),
        last_modified: None,
        unknown: Vec::new(),
    }
}

/// Root holds the bin first, then P, then share T: a walk that stops at the bin
/// reaches it last.
fn world() -> Vault {
    let mut root = Group::new(id(1), "Root".into(), T0);
    root.groups.push(Group::new(id(0x5a), "Bin".into(), T0));
    root.groups.push(Group::new(id(0x30), "P".into(), T0));
    let mut t = Group::new(id(0x20), "T".into(), T0);
    t.custom_data.items.push(share_item());
    root.groups.push(t);
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = true;
    v.meta.recycle_bin = Some(id(0x5a));
    v
}

fn empty_container() -> Vault {
    let mut c = Vault::new(Group::new(id(0x20), "T".into(), T0), T0);
    c.meta.recycle_bin_enabled = false;
    c
}

fn t_mut(v: &mut Vault) -> &mut Group {
    v.root
        .groups
        .iter_mut()
        .find(|g| g.uuid == id(0x20))
        .unwrap()
}

/// A hostile container that lists `n` groups a first one planted. The groups are
/// flat in T and empty. Each is erased by the list.
#[test]
#[ignore = "scale"]
fn a_list_erases_n_planted_groups() {
    let n = n_env();
    let mut first = empty_container();
    for i in 0..n as u64 {
        first
            .root
            .groups
            .push(Group::new(big(i, 2), "g".into(), T0));
    }
    let mut v = world();
    timed("plant groups import", n, || {
        run::merge_into(&mut v, id(0x20), &first, NOW).unwrap();
    });
    let stale = v.duplicate();
    let mut second = empty_container();
    second.deleted_objects = (0..n as u64)
        .map(|i| DeletedObject {
            uuid: big(i, 2),
            deleted_at: Time(NOW.0 + 1),
            unknown: Vec::new(),
        })
        .collect();
    timed("list erases groups import", n, || {
        run::merge_into(&mut v, id(0x20), &second, Time(NOW.0 + 2)).unwrap();
    });
    let left = v.root.subtree().len();
    eprintln!("C2 SCALE left {left} groups");
    // The stale copy of the same vault: a merge erases them again.
    let mut s = stale;
    timed("same-vault merge erases groups", n, || {
        merge(
            &mut s,
            &v,
            &Options::new(Kind::ChangeOnDisk),
            Time(NOW.0 + 3),
        )
        .unwrap();
    });
    eprintln!("C2 SCALE left {} groups", s.root.subtree().len());
}

/// `n` groups moved inside the share on one copy (a member's move): a same-vault
/// merge moves them on the other.
#[test]
#[ignore = "scale"]
fn a_same_vault_merge_moves_n_groups() {
    let n = n_env();
    let mut a = world();
    {
        let t = t_mut(&mut a);
        let mut s1 = Group::new(id(0x41), "S1".into(), T0);
        for i in 0..n as u64 {
            s1.groups.push(Group::new(big(i, 2), "g".into(), T0));
        }
        t.groups.push(s1);
        t.groups.push(Group::new(id(0x42), "S2".into(), T0));
    }
    let mut b = a.duplicate();
    {
        let t = t_mut(&mut b);
        let moved = core::mem::take(&mut t.groups[0].groups);
        t.groups[1].groups = moved
            .into_iter()
            .map(|mut g| {
                g.times.location_changed = NOW;
                g.previous_parent = Some(id(0x41));
                g
            })
            .collect();
    }
    timed("same-vault merge moves groups", n, || {
        merge(
            &mut a,
            &b,
            &Options::new(Kind::ChangeOnDisk),
            Time(NOW.0 + 3),
        )
        .unwrap();
    });
}

/// `n` entries at depth `C2_D`, hostile list naming them all.
#[test]
#[ignore = "scale"]
fn a_list_at_depth() {
    let n = n_env();
    let d: usize = std::env::var("C2_D")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(400);
    let mut c = empty_container();
    {
        let mut top = Group::new(big(0, 3), "d".into(), T0);
        {
            let mut at = &mut top;
            for i in 1..d as u64 {
                at.groups.push(Group::new(big(i, 3), "d".into(), T0));
                at = at.groups.last_mut().unwrap();
            }
            for i in 0..n as u64 {
                let mut e = Entry::new(big(i, 4), T0);
                e.times.last_modification = T0;
                at.entries.push(e);
            }
        }
        c.root.groups.push(top);
    }
    let mut v = world();
    timed("plant entries at depth import", n, || {
        run::merge_into(&mut v, id(0x20), &c, NOW).unwrap();
    });
    let stale = v.duplicate();
    let mut l = empty_container();
    l.deleted_objects = (0..n as u64)
        .map(|i| DeletedObject {
            uuid: big(i, 4),
            deleted_at: Time(NOW.0 + 1),
            unknown: Vec::new(),
        })
        .collect();
    timed("list erases entries at depth import", n, || {
        run::merge_into(&mut v, id(0x20), &l, Time(NOW.0 + 2)).unwrap();
    });
    let mut s = stale;
    timed("same-vault merge erases entries at depth", n, || {
        merge(
            &mut s,
            &v,
            &Options::new(Kind::ChangeOnDisk),
            Time(NOW.0 + 3),
        )
        .unwrap();
    });
}

/// A user's deletion for good of a group holding `n` groups, while `n` planted groups
/// stay elsewhere in the share, the bin on.
#[test]
#[ignore = "scale"]
fn a_delete_for_good_of_n_groups_beside_n_groups() {
    let n = n_env();
    let mut v = world();
    {
        let t = t_mut(&mut v);
        for i in 0..n as u64 {
            t.groups.push(Group::new(big(i, 5), "keep".into(), T0));
        }
    }
    let mut doomed = Group::new(id(0x44), "doomed".into(), T0);
    for i in 0..n as u64 {
        doomed.groups.push(Group::new(big(i, 6), "g".into(), T0));
    }
    // Already in the bin: a delete there is for good.
    doomed.previous_parent = Some(id(0x30));
    v.root.groups[0].groups.push(doomed);
    timed("delete for good of a group in the bin", n, || {
        recycle::delete_group(&mut v, id(0x44), NOW).unwrap();
    });
    eprintln!("C2 SCALE left {} groups", v.root.subtree().len());
}

/// What the export of a list this size costs, and how large its item is.
#[test]
#[ignore = "scale"]
fn rows_and_a_save() {
    let n = n_env();
    let mut c = empty_container();
    c.deleted_objects = (0..n as u64)
        .map(|i| DeletedObject {
            uuid: big(i, 7),
            deleted_at: Time(NOW.0 - 5),
            unknown: Vec::new(),
        })
        .collect();
    let mut v = world();
    timed("rows import", n, || {
        run::merge_into(&mut v, id(0x20), &c, NOW).unwrap();
    });
    let b = timed("build the export", n, || {
        container::build(id(0x20), true, &v, NOW).unwrap()
    });
    eprintln!("C2 SCALE export list {}", b.deleted_objects.len());
    let mut e = Entry::new(id(0x50), T0);
    e.set_field(
        "Password".to_owned(),
        Field {
            value: SecretString::new("demo".to_owned()),
            protected: true,
        },
    );
    t_mut(&mut v).entries.push(e);
    timed("one delete for good with rows held", n, || {
        v.meta.recycle_bin_enabled = false;
        recycle::delete_entries(&mut v, &[id(0x50)], NOW, |_, _| recycle::References::Delete)
            .unwrap();
    });
}

fn scale_host() -> larsal_crypto::kdf::Host {
    larsal_crypto::kdf::Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(larsal_crypto::kdf::SpeedRecord {
            count: 10_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 100,
        }),
    }
}

fn through_a_file(what: &str, c: &Vault) -> Vault {
    use larsal_format::limits::Limits;
    let path = std::env::temp_dir().join("c2-scale.larsalvault");
    let password = SecretString::new("share-demo".to_owned());
    let mut c = c.duplicate();
    c.encryption.kdf = larsal_model::settings::Kdf::AesKdf { rounds: 1 };
    container::write_file(
        &path,
        &c,
        &password,
        &mut scale_host(),
        &Limits::DEFAULT,
        &[],
    )
    .unwrap();
    let size = std::fs::metadata(&path).unwrap().len();
    eprintln!("C2 SCALE {what} file {size} bytes");
    let v = container::open_file(&path, &password, &mut scale_host(), &Limits::DEFAULT)
        .unwrap()
        .vault;
    std::fs::remove_file(&path).unwrap();
    v
}

/// Two real container files: `n` empty groups; a list naming them. Only the import of
/// the list is timed.
#[test]
#[ignore = "scale"]
fn a_real_files_list_erases_n_groups() {
    let n = n_env();
    let mut first = empty_container();
    for i in 0..n as u64 {
        first
            .root
            .groups
            .push(Group::new(big(i, 2), "g".into(), T0));
    }
    let first = through_a_file("plant", &first);
    let mut v = world();
    timed("real file plant import", n, || {
        run::merge_into(&mut v, id(0x20), &first, NOW).unwrap();
    });
    let mut second = empty_container();
    second.deleted_objects = (0..n as u64)
        .map(|i| DeletedObject {
            uuid: big(i, 2),
            deleted_at: Time(NOW.0 + 1),
            unknown: Vec::new(),
        })
        .collect();
    let second = through_a_file("list", &second);
    timed("real file list import", n, || {
        run::merge_into(&mut v, id(0x20), &second, Time(NOW.0 + 2)).unwrap();
    });
    eprintln!("C2 SCALE left {} groups", v.root.subtree().len());
}

/// No share at all: a same-vault merge whose copy holds a record for each of `n` groups,
/// and a delete for good of a group holding `n`, beside `n`.
#[test]
#[ignore = "scale"]
fn a_no_share_vault() {
    let n = n_env();
    let mut v = world();
    t_mut(&mut v).custom_data.items.clear();
    {
        let t = t_mut(&mut v);
        for i in 0..n as u64 {
            t.groups.push(Group::new(big(i, 5), "keep".into(), T0));
        }
    }
    let mut stale = v.duplicate();
    let mut s = v.duplicate();
    {
        let t = t_mut(&mut s);
        t.groups.clear();
        s.deleted_objects = (0..n as u64)
            .map(|i| DeletedObject {
                uuid: big(i, 5),
                deleted_at: NOW,
                unknown: Vec::new(),
            })
            .collect();
    }
    timed("no share, merge erases groups", n, || {
        merge(&mut stale, &s, &Options::new(Kind::ChangeOnDisk), NOW).unwrap();
    });
    let mut doomed = Group::new(id(0x44), "doomed".into(), T0);
    for i in 0..n as u64 {
        doomed.groups.push(Group::new(big(i, 6), "g".into(), T0));
    }
    doomed.previous_parent = Some(id(0x30));
    v.root.groups[0].groups.push(doomed);
    timed("no share, delete for good of a group", n, || {
        recycle::delete_group(&mut v, id(0x44), NOW).unwrap();
    });
}

/// A container moves `n` groups, each holding an entry, from S1 to S2 in the share.
#[test]
#[ignore = "scale"]
fn a_import_moves_n_groups_with_entries() {
    let n = n_env();
    let mut first = empty_container();
    let mut s1 = Group::new(id(0x41), "S1".into(), T0);
    for i in 0..n as u64 {
        let mut g = Group::new(big(i, 2), "g".into(), T0);
        g.entries.push(Entry::new(big(i, 4), T0));
        s1.groups.push(g);
    }
    let mut second = first.duplicate();
    first.root.groups.push(s1.duplicate());
    first
        .root
        .groups
        .push(Group::new(id(0x42), "S2".into(), T0));
    let mut v = world();
    run::merge_into(&mut v, id(0x20), &first, NOW).unwrap();
    let mut s2 = Group::new(id(0x42), "S2".into(), T0);
    s2.groups = core::mem::take(&mut s1.groups)
        .into_iter()
        .map(|mut g| {
            g.times.location_changed = NOW;
            g
        })
        .collect();
    second.root.groups.push(s1);
    second.root.groups.push(s2);
    timed("import moves groups", n, || {
        run::merge_into(&mut v, id(0x20), &second, Time(NOW.0 + 2)).unwrap();
    });
}

// ---------------------------------------------------------------------------
// Round 4 checkers, ported in round 5: chains of groups in the bin, each naming the
// next as its previous parent (C1R4-05, C2R4-01). By hand: `C2_N` bin items, `C2_D`
// chain depth. Two run by default, at a size where a walk per group up the chain
// takes minutes and one pass takes well under a second.
// ---------------------------------------------------------------------------

fn d_env() -> usize {
    std::env::var("C2_D")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(1)
}

fn bin(v: &mut Vault) -> &mut Group {
    v.root
        .groups
        .iter_mut()
        .find(|g| g.uuid == id(0x5a))
        .unwrap()
}

/// `d` groups in the bin, the i-th naming the (i+1)-th as its previous parent and the
/// last naming P; `n` bin entries name the first.
fn bin_chain(v: &mut Vault, d: usize, n: usize) {
    for i in 0..d as u64 {
        let mut g = Group::new(big(i, 3), "b".into(), T0);
        g.previous_parent = Some(if i + 1 < d as u64 {
            big(i + 1, 3)
        } else {
            id(0x30)
        });
        bin(v).groups.push(g);
    }
    for i in 0..n as u64 {
        let mut e = Entry::new(big(i, 4), T0);
        e.previous_parent = Some(big(0, 3));
        bin(v).entries.push(e);
    }
}

/// A same-vault merge with a share known beside a bin chain of `d` groups, that erases
/// nothing (the other copy edited one entry in P). Seconds.
fn merge_beside_a_bin_chain(d: usize) -> f64 {
    let mut v = world();
    bin_chain(&mut v, d, 0);
    let mut e = Entry::new(id(0x44), T0);
    e.times.last_modification = T0;
    v.root.groups[1].entries.push(e);
    let mut other = v.duplicate();
    other.root.groups[1].entries[0].times.last_modification = NOW;
    let t = Instant::now();
    merge(
        &mut v,
        &other,
        &Options::new(Kind::ChangeOnDisk),
        Time(NOW.0 + 1),
    )
    .unwrap();
    let secs = t.elapsed().as_secs_f64();
    assert_eq!(bin(&mut v).groups.len(), d);
    secs
}

/// A same-vault merge that erases a bin chain of `d` groups the other copy deleted for
/// good, `n` bin entries naming its first group. Seconds; the entries then name P.
fn merge_erasing_a_bin_chain(d: usize, n: usize) -> f64 {
    let mut v = world();
    bin_chain(&mut v, d, n);
    let mut other = v.duplicate();
    bin(&mut other).groups.clear();
    other.deleted_objects = (0..d as u64)
        .map(|i| DeletedObject {
            uuid: big(i, 3),
            deleted_at: NOW,
            unknown: Vec::new(),
        })
        .collect();
    let t = Instant::now();
    merge(
        &mut v,
        &other,
        &Options::new(Kind::ChangeOnDisk),
        Time(NOW.0 + 1),
    )
    .unwrap();
    let secs = t.elapsed().as_secs_f64();
    let b = bin(&mut v);
    assert!(b.groups.is_empty(), "the chain goes in one merge");
    assert!(
        b.entries
            .iter()
            .all(|e| e.previous_parent == Some(id(0x30)))
    );
    secs
}

/// C2R4-01 by default: 20,000 groups in a bin chain beside a merge that erases nothing.
/// Round 4's code took 23 s in a release build (a walk per group up the chain, base
/// 0.01 s); one pass takes a fraction of a second in a test build.
#[test]
fn a_merge_beside_a_bin_chain_is_one_pass() {
    let secs = merge_beside_a_bin_chain(20_000);
    eprintln!("C2 SCALE merge beside a bin chain d=20000: {secs:.3} s");
    assert!(secs < 15.0, "{secs:.3} s: not linear in the chain");
}

/// C1R4-05 by default: a merge erases a bin chain of 16,000 groups, 16,000 bin entries
/// naming its first group (checker 1's shape). Round 4's code took 52 s in a release
/// build (each erase handed every waiting item on, each entry walked the chain); one
/// pass takes a fraction of a second in a test build.
#[test]
fn a_merge_erasing_a_bin_chain_is_one_pass() {
    let secs = merge_erasing_a_bin_chain(16_000, 16_000);
    eprintln!("C2 SCALE merge erasing a bin chain d=16000 n=16000: {secs:.3} s");
    assert!(secs < 15.0, "{secs:.3} s: not linear in the chain");
}

/// By hand, beside base: `C2_D` groups in the chain, nothing erased.
#[test]
#[ignore = "scale"]
fn same_vault_merge_beside_a_bin_chain_erasing_nothing() {
    let d = d_env();
    let secs = merge_beside_a_bin_chain(d);
    eprintln!("C2 SCALE merge beside a bin chain d={d}: {secs:.3} s");
}

/// By hand, beside base: `C2_D` groups in the chain erased, `C2_N` bin entries.
#[test]
#[ignore = "scale"]
fn same_vault_merge_erases_a_bin_chain() {
    let (d, n) = (d_env(), n_env());
    let secs = merge_erasing_a_bin_chain(d, n);
    eprintln!("C2 SCALE merge erasing a bin chain d={d} n={n}: {secs:.3} s");
}

/// By hand: the user's own move of one entry into the share beside the same bin chain.
#[test]
#[ignore = "scale"]
fn a_move_into_the_share_beside_a_bin_chain() {
    let d = d_env();
    let mut v = world();
    bin_chain(&mut v, d, 0);
    v.root.groups[1].entries.push(Entry::new(id(0x44), T0));
    timed("a move into the share beside a bin chain", d, || {
        larsal_core::edit::move_entries(&mut v, &[id(0x44)], id(0x20), NOW).unwrap();
    });
}

/// By hand: the user's delete for good of a chain's top in the bin, `C2_N` bin entries
/// naming its deepest group.
#[test]
#[ignore = "scale"]
fn delete_for_good_of_a_chain_with_bin_items_naming_the_deepest() {
    let (n, d) = (n_env(), d_env());
    let mut v = world();
    let mut top = Group::new(big(0, 3), "d".into(), T0);
    {
        let mut at = &mut top;
        for i in 1..d as u64 {
            at.groups.push(Group::new(big(i, 3), "d".into(), T0));
            at = at.groups.last_mut().unwrap();
        }
    }
    top.previous_parent = Some(id(0x20));
    bin(&mut v).groups.push(top);
    for i in 0..n as u64 {
        let mut e = Entry::new(big(i, 4), T0);
        e.previous_parent = Some(big(d as u64 - 1, 3));
        bin(&mut v).entries.push(e);
    }
    timed("delete for good of a chain in the bin", d, || {
        recycle::delete_group(&mut v, big(0, 3), NOW).unwrap();
    });
}

// ---------------------------------------------------------------------------
// Round 5's checker, ported in round 6 (C1R5-02): the same bin chain, each group in it a
// known share (a share item on each). Two run by default at 4,000 groups, where round 5's
// code took 66.8 s and 1.15 GB in a release build (a copied set per group, each as long as
// the chain); one pass takes well under a second in a test build. By hand: `C2_D`.
// ---------------------------------------------------------------------------

/// The bin chain of [`bin_chain`], `d` groups, each a known share.
fn known_chain(d: usize) -> Vault {
    let mut v = world();
    bin_chain(&mut v, d, 0);
    for g in &mut bin(&mut v).groups {
        g.custom_data.items.push(share_item());
    }
    let mut e = Entry::new(id(0x44), T0);
    e.times.last_modification = T0;
    v.root.groups[1].entries.push(e);
    v
}

/// A same-vault merge beside a chain of `d` known shares that erases nothing (`erase`
/// false: the other copy edited one entry in P), or that erases the whole chain, which
/// the other copy deleted for good. Seconds.
fn merge_with_a_known_chain(d: usize, erase: bool) -> f64 {
    let mut v = known_chain(d);
    let mut other = v.duplicate();
    if erase {
        bin(&mut other).groups.clear();
        other.deleted_objects = (0..d as u64)
            .map(|i| DeletedObject {
                uuid: big(i, 3),
                deleted_at: NOW,
                unknown: Vec::new(),
            })
            .collect();
    } else {
        other.root.groups[1].entries[0].times.last_modification = NOW;
    }
    let t = Instant::now();
    merge(
        &mut v,
        &other,
        &Options::new(Kind::ChangeOnDisk),
        Time(NOW.0 + 1),
    )
    .unwrap();
    let secs = t.elapsed().as_secs_f64();
    assert_eq!(bin(&mut v).groups.len(), if erase { 0 } else { d });
    secs
}

/// C1R5-02 by default: a merge beside a chain of 4,000 known shares, erasing nothing.
#[test]
fn a_merge_beside_a_chain_of_known_shares_is_one_pass() {
    let secs = merge_with_a_known_chain(4_000, false);
    eprintln!("C2 SCALE merge beside a known chain d=4000: {secs:.3} s");
    assert!(secs < 15.0, "{secs:.3} s: not linear in the chain");
}

/// C1R5-02 by default: a merge erasing a chain of 4,000 known shares.
#[test]
fn a_merge_erasing_a_chain_of_known_shares_is_one_pass() {
    let secs = merge_with_a_known_chain(4_000, true);
    eprintln!("C2 SCALE merge erasing a known chain d=4000: {secs:.3} s");
    assert!(secs < 15.0, "{secs:.3} s: not linear in the chain");
}

/// By hand: `C2_D` known shares in the chain; `C2_ERASE=1` erases them.
#[test]
#[ignore = "scale"]
fn same_vault_merge_with_a_chain_of_known_shares() {
    let d = d_env();
    let erase = std::env::var("C2_ERASE").is_ok_and(|x| x == "1");
    let secs = merge_with_a_known_chain(d, erase);
    eprintln!("C2 SCALE merge with a known chain d={d} erase={erase}: {secs:.3} s");
}

// ---------------------------------------------------------------------------
// Round 6's checker 2, ported in round 7 (C2R6-01, C1R6-01): the inner rows an erase
// writes. A chain of `d` nested known shares, `m` entries in the innermost, which the
// other copy deleted for good: a row for each share per entry, each erasing the entry.
// Round 6's code took 21.9 s at d=400, m=50 in a release build (each row and share
// asked its way up). One runs by default at that size. By hand: `C2_D`, `C2_N`.
// ---------------------------------------------------------------------------

/// `d` nested known shares under the root, `m` entries in the innermost, no bin.
fn nested_known_chain(d: usize, m: usize) -> (Vault, Vec<Uuid>) {
    let xs: Vec<Uuid> = (0..m as u64).map(|j| big(j, 7)).collect();
    let mut g = Group::new(big(d as u64, 5), "s".into(), T0);
    for x in &xs {
        let mut e = Entry::new(*x, T0);
        e.times.last_modification = T0;
        g.entries.push(e);
    }
    for i in (0..d as u64).rev() {
        g.custom_data.items.push(share_item());
        if i > 0 {
            let mut p = Group::new(big(i, 5), "s".into(), T0);
            p.groups.push(g);
            g = p;
        }
    }
    let mut root = Group::new(id(0x20), "Root".into(), T0);
    root.groups.push(g);
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin_enabled = false;
    v.meta.recycle_bin = None;
    (v, xs)
}

/// A same-vault merge taking the other copy's delete for good of the `m` entries. Seconds.
fn merge_erasing_by_rows(d: usize, m: usize) -> f64 {
    let (mut v, xs) = nested_known_chain(d, m);
    let mut other = v.duplicate();
    recycle::delete_entries(&mut other, &xs, NOW, |_, _| recycle::References::Delete).unwrap();
    let t = Instant::now();
    merge(
        &mut v,
        &other,
        &Options::new(Kind::ChangeOnDisk),
        Time(NOW.0 + 1),
    )
    .unwrap();
    let secs = t.elapsed().as_secs_f64();
    assert_eq!(v.root.all_entries().count(), 0);
    secs
}

/// C2R6-01 by default: 50 entries erased by rows in a chain of 400 nested known shares;
/// each erased object walks its way up once (`Places::rows_above`), not once per row and share.
#[test]
fn a_merge_erasing_by_rows_in_a_nested_chain_walks_each_object_up_once() {
    let secs = merge_erasing_by_rows(400, 50);
    eprintln!("C2 SCALE merge erasing by rows, nested d=400 m=50: {secs:.3} s");
    assert!(secs < 15.0, "{secs:.3} s: a walk per row and share is back");
}

/// By hand: `C2_D` nested known shares, `C2_N` entries.
#[test]
#[ignore = "scale"]
fn same_vault_merge_erasing_by_rows_in_a_nested_chain() {
    let (d, m) = (d_env(), n_env());
    let secs = merge_erasing_by_rows(d, m);
    eprintln!("C2 SCALE merge erasing by rows, nested d={d} m={m}: {secs:.3} s");
}
