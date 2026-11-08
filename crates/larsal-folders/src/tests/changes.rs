//! FIL-04-T10 crash boundaries, FIL-06-T06, T07, T10 to T14: every change, and every way
//! a change can stop.

use super::common::*;
use super::{Fx, SWAP_UNSUPPORTED, fx};
use crate::error::{Error, io};
use crate::limits::RECOVERY_CEILING;
use crate::recovery::{OpKind, OpState};
use crate::seam;
use crate::{Kept, Node, Outcome};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

fn raw_path(fx: &Fx, parent: &[u8], name: &str) -> PathBuf {
    fx.path
        .join(dir_path(&ENC, &MAC, parent))
        .join(raw_name(&ENC, &MAC, parent, name))
}

fn top_raw(fx: &Fx, name: &str) -> PathBuf {
    raw_path(fx, b"", name)
}

fn staging_dirs(path: &std::path::Path) -> Vec<PathBuf> {
    fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".larsal-staging-")
        })
        .map(|e| e.path())
        .collect()
}

fn recovery_dir(fx: &Fx) -> PathBuf {
    let keys = crate::keys::MasterKeys::new(
        larsal_crypto::secret::SecretBytes::new(ENC.to_vec()),
        larsal_crypto::secret::SecretBytes::new(MAC.to_vec()),
    )
    .unwrap();
    fx.stores_path
        .join("recovery")
        .join(keys.store_id().unwrap())
}

fn record_dirs(fx: &Fx) -> Vec<PathBuf> {
    fs::read_dir(recovery_dir(fx))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("op-"))
        .collect()
}

/// FIL-06.6: while a change is on its way to being published, both versions are durable
/// in the local store: base and new, whole, under digests the journal names.
#[test]
fn fil06_t06_old_and_new_are_durable_before_publish() {
    let fx = fx("durable");
    let root = fx.root();
    let node = fx.write(&root, "file.bin", b"old content");
    let base = fx.digest(&node);
    let old_raw = fs::read(top_raw(&fx, "file.bin")).unwrap();
    let probe = recovery_dir(&fx);
    let old_copy = old_raw.clone();
    let checked = std::rc::Rc::new(std::cell::Cell::new(false));
    let saw = checked.clone();
    let target = top_raw(&fx, "file.bin");
    seam::at_every_point(move |point| {
        if point != "update.before_swap" {
            return;
        }
        // The newest record holds base and new; the folder still holds the old file.
        let mut found = false;
        for entry in fs::read_dir(&probe).unwrap() {
            let dir = entry.unwrap().path();
            if dir.join("base").is_file() && dir.join("new").is_file() {
                assert_eq!(fs::read(dir.join("base")).unwrap(), old_copy);
                assert_eq!(fs::metadata(dir.join("new")).unwrap().len(), 68 + 11 + 28);
                assert_eq!(
                    fs::metadata(dir.join("new")).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                assert_eq!(
                    fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                    0o700
                );
                found = true;
            }
        }
        assert!(found);
        assert_eq!(fs::read(&target).unwrap(), old_copy);
        saw.set(true);
    });
    let saved = fx
        .vault
        .update_file(&node, &base, &mut &b"new content"[..], 11, &mut |_, _| true)
        .unwrap();
    seam::clear();
    assert!(checked.get());
    assert_eq!(saved.outcome, Outcome::Replaced);
    assert_eq!(fx.read(&node), b"new content");
    let item = fx
        .vault
        .recovery_items()
        .unwrap()
        .into_iter()
        .find(|i| i.base == Some(base))
        .unwrap();
    assert_eq!(item.state, Some(OpState::Done));
    assert_eq!(item.new, Some(saved.digest));
    // Both versions can be read back through custody.
    let mut old = Vec::new();
    fx.vault
        .capture_recovery(&item.id, Kept::Base, &mut |_, _| true)
        .unwrap()
        .validate(&mut |_, _| true)
        .unwrap()
        .write_to(&mut old, &mut |_, _| true)
        .unwrap();
    assert_eq!(old, b"old content");
    assert!(fx.no_staging_left());
}

/// FIL-06.6: create never replaces; an existing name stays exactly as it was, whether it
/// was there at the look or arrived after it.
#[test]
fn fil06_t06_create_never_replaces_a_sentinel() {
    let fx = fx("sentinel");
    let root = fx.root();
    let existing = fx.write(&root, "taken.txt", b"sentinel");
    let before = fs::read(top_raw(&fx, "taken.txt")).unwrap();
    assert_eq!(
        fx.vault
            .create_file(&root, "taken.txt", &mut &b"x"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Exists)
    );
    assert_eq!(fs::read(top_raw(&fx, "taken.txt")).unwrap(), before);
    assert_eq!(fx.read(&existing), b"sentinel");
    // Arrives between the look and the publish, at a plain name and at a long one.
    for name in ["arrives.txt".to_owned(), format!("{}.txt", "l".repeat(220))] {
        let raw = raw_name(&ENC, &MAC, b"", &name);
        let is_long = raw.len() > 220;
        let at = if is_long {
            fx.path.join(dir_path(&ENC, &MAC, b"")).join(deflated(&raw))
        } else {
            top_raw(&fx, &name)
        };
        let planted = at.clone();
        let inflated = raw.clone();
        seam::at_every_point(move |point| {
            if point == "create.after_stage" {
                if is_long {
                    fs::create_dir(&planted).unwrap();
                    fs::write(planted.join("name.c9s"), inflated.as_bytes()).unwrap();
                    fs::write(planted.join("contents.c9r"), b"another writer").unwrap();
                } else {
                    fs::write(&planted, b"another writer").unwrap();
                }
            }
        });
        let got = fx
            .vault
            .create_file(&root, &name, &mut &b"mine"[..], 4, &mut |_, _| true);
        seam::clear();
        assert_eq!(got.err(), Some(Error::Exists), "{name}");
        let kept = if is_long {
            fs::read(at.join("contents.c9r")).unwrap()
        } else {
            fs::read(&at).unwrap()
        };
        assert_eq!(kept, b"another writer", "{name}");
        // Mine is in recovery, for review.
        let items = fx.vault.recovery_items().unwrap();
        assert!(
            items
                .iter()
                .any(|i| i.state == Some(OpState::Aborted) && i.new.is_some())
        );
        assert!(fx.no_staging_left(), "{name}");
    }
}

/// FIL-06.6: a stale base: storage's version stays, the edit is kept beside it.
#[test]
fn fil06_t06_a_stale_base_replaces_nothing() {
    let fx = fx("stale");
    let root = fx.root();
    let node = fx.write(&root, "file.txt", b"first");
    let base = fx.digest(&node);
    let other = seal_plain(&ENC, b"another writer's");
    fs::write(top_raw(&fx, "file.txt"), &other).unwrap();
    let saved = fx
        .vault
        .update_file(&node, &base, &mut &b"my edit"[..], 7, &mut |_, _| true)
        .unwrap();
    assert_eq!(saved.outcome, Outcome::KeptBoth);
    let names = fx.names(&root);
    assert_eq!(names.len(), 2);
    let mut versions: Vec<Vec<u8>> = fx.rows(&root).iter().map(|r| fx.read(&r.node)).collect();
    versions.sort();
    assert_eq!(
        versions,
        [b"another writer's".to_vec(), b"my edit".to_vec()]
    );
    // Gone altogether: the edit takes the name; nothing was deleted by it.
    let node = fx.write(&root, "gone.txt", b"first");
    let base = fx.digest(&node);
    fs::remove_file(top_raw(&fx, "gone.txt")).unwrap();
    let saved = fx
        .vault
        .update_file(&node, &base, &mut &b"my edit"[..], 7, &mut |_, _| true)
        .unwrap();
    assert_eq!(saved.outcome, Outcome::Replaced);
    assert_eq!(fx.read(&node), b"my edit");
    assert!(fx.no_staging_left());
}

/// FIL-06.6: input that does not match what was checked stops, with no change.
#[test]
fn fil06_t06_a_short_or_long_input_is_no_success() {
    let fx = fx("short");
    let root = fx.root();
    let node = fx.write(&root, "file.bin", b"old");
    let base = fx.digest(&node);
    let before = raw_tree(&fx.path);
    for (bytes, expected) in [(&b"12345"[..], 6u64), (&b"1234567"[..], 6u64)] {
        assert_eq!(
            fx.vault
                .update_file(&node, &base, &mut &bytes[..], expected, &mut |_, _| true)
                .err(),
            Some(Error::Input)
        );
        assert_eq!(
            fx.vault
                .create_file(&root, "new.bin", &mut &bytes[..], expected, &mut |_, _| {
                    true
                })
                .err(),
            Some(Error::Input)
        );
        assert_eq!(raw_tree(&fx.path), before);
    }
    // A reader that fails is an I/O error, with no change.
    struct Fails;
    impl std::io::Read for Fails {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("no"))
        }
    }
    assert_eq!(
        fx.vault
            .update_file(&node, &base, &mut Fails, 6, &mut |_, _| true)
            .err(),
        Some(Error::Io)
    );
    assert_eq!(raw_tree(&fx.path), before);
    assert_eq!(fx.read(&node), b"old");
}

/// FIL-06.6, F-341 not repeated: a full disk says it is a full disk, even after cleanup.
/// A sync or close fault is an I/O error and no false success. The old version stays.
#[test]
fn fil06_t06_write_faults_keep_their_cause_and_the_old_version() {
    let fx = fx("faults");
    let root = fx.root();
    let node = fx.write(&root, "file.bin", b"old");
    let base = fx.digest(&node);
    let before = raw_tree(&fx.path);
    assert_eq!(
        io(&std::io::Error::from(std::io::ErrorKind::StorageFull)),
        Error::Space
    );
    assert_eq!(
        io(&std::io::Error::from_raw_os_error(28)),
        Error::Space,
        "ENOSPC"
    );
    assert_eq!(
        io(&std::io::Error::from_raw_os_error(69)),
        Error::Space,
        "EDQUOT"
    );
    assert_eq!(io(&std::io::Error::from_raw_os_error(5)), Error::Io, "EIO");
    for (point, cause) in [
        ("write.chunk", Error::Space),
        ("write.chunk", Error::Io),
        ("write.before_sync", Error::Space),
        ("write.before_sync", Error::Io),
    ] {
        seam::fail_at(point, cause);
        let got = fx
            .vault
            .update_file(&node, &base, &mut &b"new"[..], 3, &mut |_, _| true);
        assert_eq!(got.err(), Some(cause), "{point}");
        seam::fail_at(point, cause);
        let got = fx
            .vault
            .create_file(&root, "n.bin", &mut &b"new"[..], 3, &mut |_, _| true);
        assert_eq!(got.err(), Some(cause), "{point}");
        seam::clear();
        assert_eq!(raw_tree(&fx.path), before, "{point}");
        assert_eq!(fx.read(&node), b"old");
    }
    // The swap itself fails: the version stays, for review, and nothing was replaced.
    seam::fail_at("update.swap", Error::Io);
    let got = fx
        .vault
        .update_file(&node, &base, &mut &b"new"[..], 3, &mut |_, _| true);
    seam::clear();
    assert_eq!(got.err(), Some(Error::Io));
    assert_eq!(fx.read(&node), b"old");
    let items = fx.vault.recovery_items().unwrap();
    assert!(
        items
            .iter()
            .any(|i| i.state == Some(OpState::Aborted) && i.new.is_some())
    );
    // Published but not confirmed: never a success, and nothing is lost.
    let base = fx.digest(&node);
    seam::fail_at("update.after_old_removed", Error::Io);
    let got = fx
        .vault
        .update_file(&node, &base, &mut &b"new"[..], 3, &mut |_, _| true);
    seam::clear();
    assert_eq!(got.err(), Some(Error::Uncertain));
    assert_eq!(fx.read(&node), b"new");
    seam::fail_at("create.after_publish", Error::Io);
    let got = fx
        .vault
        .create_file(&root, "uncertain.bin", &mut &b"new"[..], 3, &mut |_, _| {
            true
        });
    seam::clear();
    assert!(got.is_err());
}

/// FIL-06.6: where the swap call does not exist, the way round is still two exclusive
/// moves, never a replace or a truncate; a swap call that fails for any other reason never
/// goes that way.
#[test]
fn fil06_t06_a_volume_without_swap_goes_round_by_exclusive_moves() {
    use std::os::unix::fs::MetadataExt;
    let fx = fx("no-swap");
    let root = fx.root();
    let node = fx.write(&root, "file.bin", b"old");
    let base = fx.digest(&node);
    let path = top_raw(&fx, "file.bin");
    let inode = fs::metadata(&path).unwrap().ino();
    seam::fail_at("update.swap", Error::Io);
    SWAP_UNSUPPORTED.with(|s| s.set(true));
    let saved = fx
        .vault
        .update_file(&node, &base, &mut &b"new"[..], 3, &mut |_, _| true)
        .unwrap();
    SWAP_UNSUPPORTED.with(|s| s.set(false));
    seam::clear();
    assert_eq!(saved.outcome, Outcome::Replaced);
    assert_eq!(fx.read(&node), b"new");
    assert!(fx.no_staging_left());
    assert_ne!(
        fs::metadata(&path).unwrap().ino(),
        inode,
        "never written in place"
    );
}

/// FIL-06.11: the version storage holds changes after the copy was made, at each step up
/// to the publish: nothing is lost, and the other writer's bytes stay whole.
#[test]
fn fil06_t11_a_change_at_any_step_keeps_every_version() {
    for point in [
        "update.after_base",
        "update.after_stage",
        "update.before_swap",
        "update.swap",
    ] {
        let fx = fx("late-change");
        let root = fx.root();
        let node = fx.write(&root, "file.txt", b"first");
        let base = fx.digest(&node);
        let path = top_raw(&fx, "file.txt");
        let theirs = seal_plain(&ENC, b"another writer's");
        let raw = theirs.clone();
        seam::at_every_point(move |at| {
            if at == point {
                // A whole new object, as a sync client's move would leave it.
                let next = path.with_extension("incoming");
                fs::write(&next, &raw).unwrap();
                fs::rename(&next, &path).unwrap();
            }
        });
        let saved = fx
            .vault
            .update_file(&node, &base, &mut &b"my edit"[..], 7, &mut |_, _| true)
            .unwrap();
        seam::clear();
        assert_eq!(saved.outcome, Outcome::KeptBoth, "{point}");
        let mut got: Vec<Vec<u8>> = fx.rows(&root).iter().map(|r| fx.read(&r.node)).collect();
        got.sort();
        assert_eq!(
            got,
            [b"another writer's".to_vec(), b"my edit".to_vec()],
            "{point}"
        );
        assert!(fx.no_staging_left(), "{point}");
    }
}

fn permutations(items: &[usize]) -> Vec<Vec<usize>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut all = Vec::new();
    for (i, first) in items.iter().enumerate() {
        let rest: Vec<usize> = items
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, v)| *v)
            .collect();
        for tail in permutations(&rest) {
            let mut one = vec![*first];
            one.extend(tail);
            all.push(one);
        }
    }
    all
}

/// FIL-06.10: every arrival order of two and of three versions ends with the same objects:
/// the smallest digest under the name, every other under its reserved name; byte-identical
/// versions are one.
#[test]
fn fil06_t10_every_arrival_order_converges() {
    let versions: Vec<Vec<u8>> = [&b"version A"[..], b"version B", b"version C"]
        .iter()
        .map(|p| seal_plain(&ENC, p))
        .collect();
    let digests: Vec<String> = versions.iter().map(|v| sha256_hex(v)).collect();
    let run = |order: &[usize], twice: bool| {
        let fx = fx("orders");
        let root = fx.root();
        for i in order {
            let raw = &versions[*i];
            let saved = fx
                .vault
                .admit_version(
                    &root,
                    "same.txt",
                    &mut &raw[..],
                    raw.len() as u64,
                    &mut |_, _| true,
                )
                .unwrap();
            assert_eq!(saved.digest.hex(), digests[*i]);
            if twice {
                let again = fx
                    .vault
                    .admit_version(
                        &root,
                        "same.txt",
                        &mut &raw[..],
                        raw.len() as u64,
                        &mut |_, _| true,
                    )
                    .unwrap();
                assert_eq!(again.outcome, Outcome::Identical);
            }
        }
        assert!(fx.no_staging_left());
        let mut objects: Vec<(String, String)> = fx
            .rows(&root)
            .iter()
            .map(|r| {
                let name = r.name.as_ref().unwrap().expose().to_owned();
                (name, fx.digest(&r.node).hex())
            })
            .collect();
        objects.sort();
        objects
    };
    for set in [vec![0, 1], vec![1, 2], vec![0, 2], vec![0, 1, 2]] {
        let mut ordered: Vec<String> = digests
            .iter()
            .enumerate()
            .filter(|(i, _)| set.contains(i))
            .map(|(_, d)| d.clone())
            .collect();
        ordered.sort();
        let mut want: Vec<(String, String)> = ordered
            .iter()
            .enumerate()
            .map(|(i, d)| {
                if i == 0 {
                    ("same.txt".to_owned(), d.clone())
                } else {
                    (format!("conflict-{d}.bin"), d.clone())
                }
            })
            .collect();
        want.sort();
        for (n, order) in permutations(&set).into_iter().enumerate() {
            assert_eq!(run(&order, n == 0), want, "{order:?}");
        }
    }
}

/// FIL-06.10: the reserved name holding different data stops the publish, leaves that data
/// alone, and keeps the version in recovery.
#[test]
fn fil06_t10_a_reserved_name_with_other_data_is_a_collision() {
    let fx = fx("collision");
    let root = fx.root();
    let (a, b) = (
        seal_plain(&ENC, b"version A"),
        seal_plain(&ENC, b"version B"),
    );
    let (small, big) = if sha256_hex(&a) < sha256_hex(&b) {
        (a, b)
    } else {
        (b, a)
    };
    fx.vault
        .admit_version(
            &root,
            "same.txt",
            &mut &small[..],
            small.len() as u64,
            &mut |_, _| true,
        )
        .unwrap();
    let squatter = seal_plain(&ENC, b"squatter");
    let reserved = format!("conflict-{}.bin", sha256_hex(&big));
    let path = top_raw(&fx, &reserved);
    fs::write(&path, &squatter).unwrap();
    let got = fx.vault.admit_version(
        &root,
        "same.txt",
        &mut &big[..],
        big.len() as u64,
        &mut |_, _| true,
    );
    assert_eq!(got.err(), Some(Error::Conflict));
    assert_eq!(fs::read(&path).unwrap(), squatter, "untouched");
    assert_eq!(fs::read(top_raw(&fx, "same.txt")).unwrap(), small);
    // The refused version is whole, in the local store.
    let item = fx
        .vault
        .recovery_items()
        .unwrap()
        .into_iter()
        .find(|i| {
            i.new.is_some_and(|d| d.hex() == sha256_hex(&big)) && i.state == Some(OpState::Aborted)
        })
        .unwrap();
    assert_eq!(
        fx.vault
            .capture_recovery(&item.id, Kept::New, &mut |_, _| true)
            .unwrap()
            .digest()
            .hex(),
        sha256_hex(&big)
    );
    assert!(fx.no_staging_left());
}

/// FIL-06.10, F-340: when the version at the name is already kept as its conflict copy, the
/// duplicate goes, and only after it was moved aside and proven identical there. A version
/// another writer puts at the name in that moment is never removed: it stays, whole.
#[test]
fn fil06_t10_a_duplicate_goes_only_when_proven_aside() {
    let big = seal_plain(&ENC, b"version B");
    let small = (0u64..)
        .map(|k| {
            let key: [u8; 32] = larsal_crypto::hash::sha256(&[&k.to_be_bytes()])
                .expose()
                .try_into()
                .unwrap();
            seal_with(&ENC, &key, b"version A", false)
        })
        .find(|v| sha256_hex(v) < sha256_hex(&big))
        .unwrap();
    let reserved = format!("conflict-{}.bin", sha256_hex(&big));
    let theirs = seal_plain(&ENC, b"another writer, at the worst moment");
    for planted in [false, true] {
        let fx = fx("duplicate");
        let root = fx.root();
        // A sync left the big version at the name and its kept copy beside it.
        fs::write(top_raw(&fx, "same.txt"), &big).unwrap();
        fs::write(top_raw(&fx, &reserved), &big).unwrap();
        let (at, raw) = (top_raw(&fx, "same.txt"), theirs.clone());
        seam::at_every_point(move |point| {
            if planted && point == "admit.before_duplicate" {
                let next = at.with_extension("incoming");
                fs::write(&next, &raw).unwrap();
                fs::rename(&next, &at).unwrap();
            }
        });
        let got = fx.vault.admit_version(
            &root,
            "same.txt",
            &mut &small[..],
            small.len() as u64,
            &mut |_, _| true,
        );
        seam::clear();
        assert_eq!(fs::read(top_raw(&fx, &reserved)).unwrap(), big);
        if planted {
            assert_eq!(got.err(), Some(Error::Conflict));
            assert_eq!(
                fs::read(top_raw(&fx, "same.txt")).unwrap(),
                theirs,
                "the other writer's version stays"
            );
        } else {
            assert_eq!(got.unwrap().outcome, Outcome::KeptBoth);
            assert_eq!(fs::read(top_raw(&fx, "same.txt")).unwrap(), small);
            assert_eq!(fx.rows(&root).len(), 2, "the duplicate is gone");
        }
        assert!(fx.no_staging_left());
    }
}

/// FIL-06.11: a provider's conflict copy is believed only if it proves itself: a suffix is
/// nothing, and a bad copy is neither kept nor removed by this.
#[test]
fn fil06_t11_a_candidate_version_must_prove_itself() {
    let fx = fx("candidate");
    let root = fx.root();
    fx.write(&root, "file.txt", b"good");
    let before = raw_tree(&fx.path);
    let mut bad = seal_plain(&ENC, b"changed in transit");
    let at = bad.len() - 1;
    bad[at] ^= 1;
    let got = fx.vault.admit_version(
        &root,
        "file.txt",
        &mut &bad[..],
        bad.len() as u64,
        &mut |_, _| true,
    );
    assert_eq!(got.err(), Some(Error::Open));
    let got = fx
        .vault
        .admit_version(&root, "file.txt", &mut &b"nothing"[..], 7, &mut |_, _| true);
    assert_eq!(got.err(), Some(Error::Open));
    let other_key = seal_plain(&[9; 32], b"another vault's");
    let got = fx.vault.admit_version(
        &root,
        "file.txt",
        &mut &other_key[..],
        other_key.len() as u64,
        &mut |_, _| true,
    );
    assert_eq!(got.err(), Some(Error::Open));
    assert_eq!(raw_tree(&fx.path), before);
    assert!(fx.no_staging_left());
}

/// FIL-06.11: two Macs, each with its own stores and its own copy of the folder, edit one
/// base. Each keeps base and new. When either later sees the other's version, both are
/// there. A branch never seen is not claimed: the set is what arrived, no more.
#[test]
fn fil06_t11_two_offline_macs_keep_both() {
    let top = fresh("two-macs");
    let path_a = top.join("mac-a");
    make_folder(&path_a, PASSWORD);
    let stores_a = crate::Stores::open(&top.join("stores-a")).unwrap();
    let a = crate::Vault::unlock(&path_a, &secret(PASSWORD), &stores_a, &mut |_, _| true).unwrap();
    let root_a = a.root_dir().unwrap();
    let node_a = a
        .create_file(&root_a, "shared.txt", &mut &b"base"[..], 4, &mut |_, _| {
            true
        })
        .unwrap();
    let path_b = top.join("mac-b");
    copy_all(&path_a, &path_b);
    let stores_b = crate::Stores::open(&top.join("stores-b")).unwrap();
    let b = crate::Vault::unlock(&path_b, &secret(PASSWORD), &stores_b, &mut |_, _| true).unwrap();
    let root_b = b.root_dir().unwrap();
    let node_b = b.lookup(&root_b, "shared.txt").unwrap().unwrap().node;
    let base = a.capture(&node_a, &mut |_, _| true).unwrap().digest();

    let saved_a = a
        .update_file(&node_a, &base, &mut &b"edit from A"[..], 11, &mut |_, _| {
            true
        })
        .unwrap();
    let saved_b = b
        .update_file(&node_b, &base, &mut &b"edit from B"[..], 11, &mut |_, _| {
            true
        })
        .unwrap();
    assert_eq!(saved_a.outcome, Outcome::Replaced);
    assert_eq!(saved_b.outcome, Outcome::Replaced);
    for (vault, new) in [(&a, saved_a.digest), (&b, saved_b.digest)] {
        let items = vault.recovery_items().unwrap();
        let item = items.iter().find(|i| i.new == Some(new)).unwrap();
        assert_eq!(
            item.base,
            Some(base),
            "each keeps its base and its new version"
        );
    }
    let raw = |path: &std::path::Path| {
        fs::read(
            path.join(dir_path(&ENC, &MAC, b""))
                .join(raw_name(&ENC, &MAC, b"", "shared.txt")),
        )
        .unwrap()
    };
    let (raw_a, raw_b) = (raw(&path_a), raw(&path_b));

    // Each sees the other's: the same two objects, by digest.
    let sa = a
        .admit_version(
            &root_a,
            "shared.txt",
            &mut &raw_b[..],
            raw_b.len() as u64,
            &mut |_, _| true,
        )
        .unwrap();
    let sb = b
        .admit_version(
            &root_b,
            "shared.txt",
            &mut &raw_a[..],
            raw_a.len() as u64,
            &mut |_, _| true,
        )
        .unwrap();
    assert_eq!(
        (sa.outcome, sb.outcome),
        (Outcome::KeptBoth, Outcome::KeptBoth)
    );
    let tree = |path: &std::path::Path| {
        let mut t = raw_tree(path);
        t.retain(|p, _| p.starts_with("d/") && !p.ends_with('/') && !p.ends_with("dirid.c9r"));
        t
    };
    assert_eq!(tree(&path_a), tree(&path_b));
    assert_eq!(
        tree(&path_a).len(),
        2,
        "the set is what arrived: a withheld third is not claimed"
    );
    let rows = |v: &crate::Vault, root: &Node| {
        let mut l = v.open_listing(root).unwrap();
        let mut out = Vec::new();
        for row in l.next_page(256).unwrap() {
            let mut bytes = Vec::new();
            v.read_to(&row.node, &mut bytes, &mut |_, _| true).unwrap();
            out.push(bytes);
        }
        out.sort();
        out
    };
    assert_eq!(
        rows(&a, &root_a),
        [b"edit from A".to_vec(), b"edit from B".to_vec()]
    );
    assert_eq!(
        rows(&b, &root_b),
        [b"edit from A".to_vec(), b"edit from B".to_vec()]
    );
}

fn copy_all(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    fs::set_permissions(to, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_all(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// FIL-06.12: delete against an edit: the edit stays, the deletion is pending.
#[test]
fn fil06_t12_delete_meets_edit() {
    let fx = fx("delete-edit");
    let root = fx.root();
    let node = fx.write(&root, "file.txt", b"first");
    let base = fx.digest(&node);
    let path = top_raw(&fx, "file.txt");
    let edited = seal_plain(&ENC, b"edited elsewhere");
    fs::write(&path, &edited).unwrap();
    assert_eq!(
        fx.vault.delete_file(&node, &base).err(),
        Some(Error::DeleteConflict)
    );
    assert_eq!(fs::read(&path).unwrap(), edited);
    let item = fx
        .vault
        .recovery_items()
        .unwrap()
        .into_iter()
        .find(|i| i.kind == Some(OpKind::Delete))
        .unwrap();
    assert_eq!(item.state, Some(OpState::Pending));
    assert_eq!(
        item.base.unwrap().hex(),
        sha256_hex(&edited),
        "what was seen is durable"
    );

    // The edit comes after the copy, before the move: it goes back where it was.
    let base = fx.digest(&node);
    let late = seal_plain(&ENC, b"edited at the worst moment");
    let (at, raw) = (path.clone(), late.clone());
    seam::at_every_point(move |point| {
        if point == "delete.after_base" {
            let next = at.with_extension("incoming");
            fs::write(&next, &raw).unwrap();
            fs::rename(&next, &at).unwrap();
        }
    });
    assert_eq!(
        fx.vault.delete_file(&node, &base).err(),
        Some(Error::DeleteConflict)
    );
    seam::clear();
    assert_eq!(fs::read(&path).unwrap(), late);
    assert!(fx.no_staging_left());

    // A true delete: the file is gone from storage, and durable here.
    let base = fx.digest(&node);
    fx.vault.delete_file(&node, &base).unwrap();
    assert!(fx.vault.lookup(&root, "file.txt").unwrap().is_none());
    let item = fx
        .vault
        .recovery_items()
        .unwrap()
        .into_iter()
        .find(|i| i.kind == Some(OpKind::Delete) && i.state == Some(OpState::Done))
        .unwrap();
    let mut back = Vec::new();
    fx.vault
        .capture_recovery(&item.id, Kept::Base, &mut |_, _| true)
        .unwrap()
        .validate(&mut |_, _| true)
        .unwrap()
        .write_to(&mut back, &mut |_, _| true)
        .unwrap();
    assert_eq!(back, b"edited at the worst moment");
    // Already gone: said, not a success.
    assert_eq!(
        fx.vault.delete_file(&node, &base).err(),
        Some(Error::Changed)
    );
    assert!(fx.no_staging_left());
}

/// FIL-06.12: rename against an edit, and two renames: every version stays reachable.
#[test]
fn fil06_t12_rename_meets_edit_and_rename() {
    let fx = fx("rename-edit");
    let root = fx.root();
    let node = fx.write(&root, "file.txt", b"first");
    let base = fx.digest(&node);
    // This Mac renames; the edit started from the old name.
    let renamed = fx.vault.rename(&node, &root, "renamed.txt").unwrap();
    let saved = fx
        .vault
        .update_file(&node, &base, &mut &b"my edit"[..], 7, &mut |_, _| true)
        .unwrap();
    assert_eq!(saved.outcome, Outcome::Replaced, "the old name was free");
    assert_eq!(fx.read(&renamed), b"first");
    assert_eq!(fx.read(&node), b"my edit");
    // A second rename from the same old handle finds nothing there: said.
    let gone = fx.write(&root, "twice.txt", b"twice");
    let first = fx.vault.rename(&gone, &root, "one.txt").unwrap();
    assert_eq!(
        fx.vault.rename(&gone, &root, "two.txt").err(),
        Some(Error::Changed)
    );
    assert_eq!(fx.read(&first), b"twice");
    assert!(fx.vault.lookup(&root, "two.txt").unwrap().is_none());
    // A rename never replaces, even when the target arrived after the look. A plain
    // name's move is one exclusive step with no point before it: go by a long one.
    let target = top_raw(&fx, "b.txt");
    let planted = target.clone();
    seam::at_every_point(move |point| {
        if point == "rename.after_partial" {
            fs::write(&planted, b"arrived").unwrap();
        }
    });
    let long = format!("{}.txt", "r".repeat(200));
    let long_node = fx.write(&root, &long, b"long");
    let got = fx.vault.rename(&long_node, &root, "b.txt");
    seam::clear();
    assert_eq!(got.err(), Some(Error::Exists));
    assert_eq!(fs::read(&target).unwrap(), b"arrived");
    assert_eq!(fx.read(&long_node), b"long", "the source stays reachable");
}

/// FIL-06.12: a tree delete: every file durable first; a change on the way stops there,
/// and what has not been reached stays; a folder is not removed before its contents.
#[test]
fn fil06_t12_tree_delete_and_a_change_on_the_way() {
    let fx = fx("tree");
    let root = fx.root();
    let top = fx.vault.make_dir(&root, "top").unwrap();
    let sub = fx.vault.make_dir(&top, "sub").unwrap();
    fx.write(&top, "one.txt", b"one");
    let two = fx.write(&sub, "two.txt", b"two");
    let long = format!("{}.txt", "t".repeat(200));
    fx.write(&sub, &long, b"three");
    fx.vault.make_dir(&sub, "empty").unwrap();
    // A non-empty folder alone is refused.
    assert_eq!(fx.vault.delete_dir(&top).err(), Some(Error::DeleteConflict));
    assert_eq!(fx.read(&two), b"two");

    // The version of `two` changes after the look: the walk stops at it.
    let id = sub.dir_id.clone().unwrap();
    let path = raw_path(&fx, &id, "two.txt");
    let edited = seal_plain(&ENC, b"edited");
    let (at, raw) = (path.clone(), edited.clone());
    let mut armed = true;
    seam::at_every_point(move |point| {
        if armed && point.starts_with("delete.") {
            armed = false;
            let next = at.with_extension("incoming");
            fs::write(&next, &raw).unwrap();
            fs::rename(&next, &at).unwrap();
        }
    });
    let got = fx.vault.delete_tree(&top);
    seam::clear();
    // Whichever file the walk reached first, the edited one stays and the folder too.
    assert!(matches!(got, Err(Error::DeleteConflict)), "{got:?}");
    assert_eq!(fs::read(&path).unwrap(), edited);
    assert!(fx.vault.lookup(&root, "top").unwrap().is_some());
    assert!(fx.no_staging_left());

    // Now whole: everything goes, and everything is durable here.
    let top = fx.find(&root, "top").node;
    fx.vault.delete_tree(&top).unwrap();
    assert!(fx.vault.lookup(&root, "top").unwrap().is_none());
    let content = raw_tree(&fx.path);
    assert_eq!(
        content.keys().filter(|p| p.ends_with("/dirid.c9r")).count(),
        1,
        "only the top folder's own backup is left"
    );
    let deletes = fx.vault.recovery_items().unwrap();
    let done = deletes
        .iter()
        .filter(|i| i.kind == Some(OpKind::Delete) && i.state == Some(OpState::Done))
        .count();
    assert_eq!(done, 3);
    assert!(fx.no_staging_left());
}

/// FIL-06.7, C1-F1: a folder moved into itself, into its child or below a deep descendant
/// is refused with its own words, as POSIX rename refuses it with EINVAL, and nothing
/// changes: no byte, no record, no staging. Moving it below another folder still works.
#[test]
fn fil06_t07_a_folder_never_moves_into_itself_or_below_itself() {
    let fx = fx("inside");
    let root = fx.root();
    let a = fx.vault.make_dir(&root, "a").unwrap();
    let b = fx.vault.make_dir(&a, "b").unwrap();
    let c = fx.vault.make_dir(&b, "c").unwrap();
    let d = fx.vault.make_dir(&c, "d").unwrap();
    fx.write(&a, "keep.txt", b"keep");
    fx.write(&d, "deep.txt", b"deep");
    let before = raw_tree(&fx.path);
    let records = record_dirs(&fx).len();
    let long = format!("{}-moved", "m".repeat(200));
    for (target, what) in [(&a, "itself"), (&b, "its child"), (&d, "a deep descendant")] {
        for name in ["moved", long.as_str()] {
            assert_eq!(
                fx.vault.rename(&a, target, name).err(),
                Some(Error::Inside),
                "{what}"
            );
            assert_eq!(raw_tree(&fx.path), before, "{what}");
        }
    }
    assert_eq!(record_dirs(&fx).len(), records, "no record begun");
    assert!(fx.no_staging_left());
    let other = fx.vault.make_dir(&root, "other").unwrap();
    let moved = fx.vault.rename(&a, &other, "a").unwrap();
    let mut at = moved;
    for step in ["b", "c", "d"] {
        at = fx.find(&at, step).node;
    }
    assert_eq!(fx.read(&fx.find(&at, "deep.txt").node), b"deep");
}

/// FIL-06.12, C1-F2: two renames of one folder on two Macs leave two folder nodes with one
/// directory ID, and both are kept. A tree delete of one never follows that ID: the other
/// still lists and reads all of it, and only the deleted node goes, after a crash too. A
/// twin deep in the subtree is the same, while the rest of the subtree goes as usual.
#[test]
fn fil06_t12_a_tree_delete_never_follows_an_id_another_folder_uses() {
    let mut fx = fx("shared-id");
    let root = fx.root();
    let p = fx.vault.make_dir(&root, "p").unwrap();
    let q = fx.vault.make_dir(&root, "q").unwrap();
    let x = fx.vault.make_dir(&p, "x").unwrap();
    fx.write(&x, "f.txt", b"the shared file");
    let (p_id, x_id) = (p.dir_id.clone().unwrap(), x.dir_id.clone().unwrap());
    // This Mac moves p/x to q/x; another Mac renamed p/x to p/y, and its node arrives.
    fx.vault.rename(&x, &q, "x").unwrap();
    let arrived = raw_path(&fx, &p_id, "y");
    fs::create_dir(&arrived).unwrap();
    fs::write(arrived.join("dir.c9r"), &x_id).unwrap();
    let y = fx.find(&p, "y").node;
    let qx = fx.find(&q, "x").node;
    assert_eq!(fx.names(&y), fx.names(&qx), "both renames kept");
    let shared = fx.path.join(dir_path(&ENC, &MAC, &x_id));
    let shared_before = raw_tree(&shared);
    fx.vault.delete_tree(&y).unwrap();
    assert!(
        fx.vault.lookup(&p, "y").unwrap().is_none(),
        "this node goes"
    );
    assert_eq!(raw_tree(&shared), shared_before, "the shared content stays");
    assert_eq!(fx.read(&fx.find(&qx, "f.txt").node), b"the shared file");

    // The same with a crash once the node is aside: the restart finishes it, and its
    // record names no content to remove.
    let again = raw_path(&fx, &p_id, "z");
    fs::create_dir(&again).unwrap();
    fs::write(again.join("dir.c9r"), &x_id).unwrap();
    let z = fx.find(&p, "z").node;
    seam::crash_at("rmdir.after_aside");
    assert!(fx.vault.delete_tree(&z).is_err());
    seam::clear();
    fx.reopen();
    let root = fx.root();
    let (p, q) = (fx.find(&root, "p").node, fx.find(&root, "q").node);
    assert!(fx.vault.lookup(&p, "z").unwrap().is_none());
    assert_eq!(
        raw_tree(&shared),
        shared_before,
        "no content after a restart"
    );
    assert!(fx.no_staging_left());

    // A twin deep in the subtree: p/top/sub and q/s share an ID.
    let top = fx.vault.make_dir(&p, "top").unwrap();
    fx.write(&top, "own.txt", b"top's own");
    let sub = fx.vault.make_dir(&top, "sub").unwrap();
    fx.write(&sub, "inner.txt", b"inner");
    let s_id = sub.dir_id.clone().unwrap();
    let twin = raw_path(&fx, q.dir_id.as_ref().unwrap(), "s");
    fs::create_dir(&twin).unwrap();
    fs::write(twin.join("dir.c9r"), &s_id).unwrap();
    let inner = fx.path.join(dir_path(&ENC, &MAC, &s_id));
    let inner_before = raw_tree(&inner);
    fx.vault.delete_tree(&top).unwrap();
    assert!(fx.vault.lookup(&p, "top").unwrap().is_none());
    let top_content = fx
        .path
        .join(dir_path(&ENC, &MAC, top.dir_id.as_ref().unwrap()));
    assert!(!top_content.exists(), "the subtree's own content goes");
    assert_eq!(raw_tree(&inner), inner_before, "the twin's content stays");
    assert!(fx.no_staging_left());

    // After a restart nothing comes back to remove it.
    fx.reopen();
    let root = fx.root();
    let q = fx.find(&root, "q").node;
    let s = fx.find(&q, "s").node;
    assert_eq!(fx.read(&fx.find(&s, "inner.txt").node), b"inner");
    let x = fx.find(&q, "x").node;
    assert_eq!(fx.read(&fx.find(&x, "f.txt").node), b"the shared file");
    assert_eq!(raw_tree(&inner), inner_before);
}

/// FIL-06.12: an item that arrives while an empty folder is being removed keeps the
/// folder, its node, and the item.
#[test]
fn fil06_t12_an_item_arriving_during_rmdir_keeps_the_folder() {
    let fx = fx("rmdir-late");
    let root = fx.root();
    let dir = fx.vault.make_dir(&root, "dir").unwrap();
    let id = dir.dir_id.clone().unwrap();
    let late = raw_path(&fx, &id, "late.txt");
    let (at, raw) = (late.clone(), seal_plain(&ENC, b"late"));
    seam::at_every_point(move |point| {
        if point == "rmdir.after_aside" {
            fs::write(&at, &raw).unwrap();
        }
    });
    assert_eq!(fx.vault.delete_dir(&dir).err(), Some(Error::DeleteConflict));
    seam::clear();
    assert_eq!(fx.read(&fx.find(&dir, "late.txt").node), b"late");
    assert_eq!(fx.find(&root, "dir").kind, crate::Kind::Dir);
    assert!(fx.no_staging_left());
    fs::remove_file(late).unwrap();
    fx.vault.delete_dir(&dir).unwrap();
    assert!(fx.vault.lookup(&root, "dir").unwrap().is_none());
    assert!(fx.no_staging_left());
}

/// A folder node made by hand that holds `id`, as a sync merge brings one in.
fn plant_node(fx: &Fx, parent: &[u8], name: &str, id: &[u8]) {
    let at = raw_path(fx, parent, name);
    fs::create_dir(&at).unwrap();
    fs::write(at.join("dir.c9r"), id).unwrap();
}

fn content_of(fx: &Fx, id: &[u8]) -> PathBuf {
    fx.path.join(dir_path(&ENC, &MAC, id))
}

fn id_of(node: &Node) -> Vec<u8> {
    node.dir_id.clone().unwrap()
}

/// FIL-06.8, C1R2-F1: a folder handle is bound to the node it named. A handle whose name
/// another folder now holds moves nothing, deletes nothing and writes nothing, as a node, as
/// a parent, and as a file handle: each write reads the node again and says the item
/// changed, and not one byte changes. A node another writer swaps in while a folder delete
/// runs goes back where it was.
#[test]
fn fil06_t08_a_stale_folder_handle_changes_nothing() {
    let fx = fx("stale-handle");
    let root = fx.root();
    let p = fx.vault.make_dir(&root, "p").unwrap();
    let q = fx.vault.make_dir(&root, "q").unwrap();
    // p/a deleted and made again with a child: the old handle moved into that child would
    // take the new a below itself.
    let a = fx.vault.make_dir(&p, "a").unwrap();
    fx.vault.delete_dir(&a).unwrap();
    let a2 = fx.vault.make_dir(&p, "a").unwrap();
    let c = fx.vault.make_dir(&a2, "c").unwrap();
    fx.write(&c, "f.txt", b"inside the new a");
    // p/e (empty) and p/t (with a file) moved to q, and new ones made at the old names.
    let e = fx.vault.make_dir(&p, "e").unwrap();
    fx.vault.rename(&e, &q, "e").unwrap();
    let e2 = fx.vault.make_dir(&p, "e").unwrap();
    fx.write(&e2, "new.txt", b"the new e's file");
    let t = fx.vault.make_dir(&p, "t").unwrap();
    fx.write(&t, "old.txt", b"the moved t's file");
    fx.vault.rename(&t, &q, "t").unwrap();
    let t2 = fx.vault.make_dir(&p, "t").unwrap();
    fx.write(&t2, "new.txt", b"the new t's file");
    // p/g.txt deleted, and a folder made at its name.
    let g = fx.write(&p, "g.txt", b"gone");
    let g_base = fx.digest(&g);
    fx.vault.delete_file(&g, &g_base).unwrap();
    fx.vault.make_dir(&p, "g.txt").unwrap();
    let before = raw_tree(&fx.path);
    let records = record_dirs(&fx).len();
    assert_eq!(fx.vault.rename(&a, &c, "moved").err(), Some(Error::Changed));
    assert_eq!(fx.vault.delete_dir(&e).err(), Some(Error::Changed));
    assert_eq!(fx.vault.delete_tree(&t).err(), Some(Error::Changed));
    // As a parent too: nothing lands in the moved folder through its old place.
    assert_eq!(fx.vault.make_dir(&e, "x").err(), Some(Error::Changed));
    assert_eq!(
        fx.vault
            .create_file(&t, "x.txt", &mut &b"x"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Changed)
    );
    assert_eq!(fx.vault.rename(&c, &t, "c").err(), Some(Error::Changed));
    assert_eq!(
        fx.vault
            .admit_version(&t, "x.txt", &mut &b"x"[..], 1, &mut |_, _| true)
            .err(),
        Some(Error::Changed)
    );
    // A file handle whose name a folder now holds.
    assert_eq!(
        fx.vault
            .update_file(&g, &g_base, &mut &b"edit"[..], 4, &mut |_, _| true)
            .err(),
        Some(Error::Changed)
    );
    assert_eq!(
        fx.vault.delete_file(&g, &g_base).err(),
        Some(Error::Changed)
    );
    assert_eq!(fx.vault.rename(&g, &q, "g.txt").err(), Some(Error::Changed));
    assert_eq!(raw_tree(&fx.path), before, "not one byte changed");
    assert_eq!(record_dirs(&fx).len(), records, "no record begun");
    assert!(fx.no_staging_left());
    assert_eq!(fx.read(&fx.find(&c, "f.txt").node), b"inside the new a");
    let qt = fx.find(&q, "t").node;
    assert_eq!(
        fx.read(&fx.find(&qt, "old.txt").node),
        b"the moved t's file"
    );

    // Another writer swaps in a node with another ID while the delete runs: it goes back.
    let s = fx.vault.make_dir(&p, "s").unwrap();
    let s_node = raw_path(&fx, &id_of(&p), "s");
    let q_id = id_of(&q);
    let (at, other) = (s_node.clone(), q_id.clone());
    seam::at_every_point(move |point| {
        if point == "rmdir.before_aside" {
            fs::write(at.join("dir.c9r"), &other).unwrap();
        }
    });
    let got = fx.vault.delete_dir(&s);
    seam::clear();
    assert_eq!(got.err(), Some(Error::Changed));
    assert_eq!(
        fs::read(s_node.join("dir.c9r")).unwrap(),
        q_id,
        "back in place"
    );
    assert!(
        content_of(&fx, &id_of(&s)).is_dir(),
        "s's own content stays"
    );
    assert!(fx.no_staging_left());
}

/// FIL-06.3, C1R2-F2: work is below the selected root, and no card asks to delete the top
/// folder itself. A tree delete of it is refused before any walk, with nothing changed.
#[test]
fn fil06_t12_a_tree_delete_of_the_top_folder_is_refused() {
    let fx = fx("top-tree");
    let root = fx.root();
    let p = fx.vault.make_dir(&root, "p").unwrap();
    let x = fx.vault.make_dir(&p, "x").unwrap();
    let top = fx.write(&root, "top.txt", b"at the top");
    let deep = fx.write(&x, "f.txt", b"two levels down");
    let before = raw_tree(&fx.path);
    let records = record_dirs(&fx).len();
    assert_eq!(fx.vault.delete_tree(&root).err(), Some(Error::Open));
    assert_eq!(fx.vault.delete_dir(&root).err(), Some(Error::Open));
    assert_eq!(raw_tree(&fx.path), before);
    assert_eq!(record_dirs(&fx).len(), records);
    assert!(fx.no_staging_left());
    assert_eq!(fx.read(&top), b"at the top");
    assert_eq!(fx.read(&deep), b"two levels down");
}

/// Fills folder `id` with `n` plain items made by hand.
fn fill(fx: &Fx, id: &[u8], n: usize) {
    let folder = content_of(fx, id);
    for i in 0..n {
        fs::write(
            folder.join(raw_name(&ENC, &MAC, id, &format!("f{i}"))),
            b"short",
        )
        .unwrap();
    }
}

/// FIL-06.3, FIL-06.12, C1R2-F3: the walk that finds the IDs used outside a delete, and the
/// walk below a moved folder, fail closed. Past the node limit, or with one folder anywhere
/// past 10,000 items, every tree delete, every folder delete and the move of a folder that
/// holds it are refused, with nothing changed; at the limit they all work.
#[test]
fn fil06_t03_a_walk_limit_anywhere_refuses_deletes_and_moves() {
    let fx = fx("walk-limits");
    let root = fx.root();
    let p = fx.vault.make_dir(&root, "p").unwrap();
    let x = fx.vault.make_dir(&p, "x").unwrap();
    fx.write(&x, "f.txt", b"small");
    let e = fx.vault.make_dir(&p, "e").unwrap();
    let a = fx.vault.make_dir(&root, "a").unwrap();
    let big = fx.vault.make_dir(&a, "big").unwrap();
    fx.write(&a, "h.txt", b"beside big");
    let q = fx.vault.make_dir(&root, "q").unwrap();
    let refused_whole = |fx: &Fx| {
        let before = raw_tree(&fx.path);
        assert_eq!(fx.vault.delete_tree(&x).err(), Some(Error::Open));
        assert_eq!(fx.vault.delete_dir(&e).err(), Some(Error::Open));
        assert_eq!(fx.vault.rename(&a, &q, "a").err(), Some(Error::Open));
        assert_eq!(raw_tree(&fx.path), before);
        assert!(fx.no_staging_left());
    };
    // The node limit, lowered for the test: one node is past it everywhere but in the
    // deleted folder's own look (x holds one item).
    fx.vault.node_limit.store(1, Ordering::SeqCst);
    refused_whole(&fx);
    fx.vault
        .node_limit
        .store(crate::limits::MAX_NODES, Ordering::SeqCst);
    // One folder past 10,000 items, elsewhere for the deletes, below the moved folder.
    fill(&fx, &id_of(&big), crate::limits::MAX_CHILDREN + 1);
    refused_whole(&fx);
    // At the limit everything works.
    let one = content_of(&fx, &id_of(&big)).join(raw_name(&ENC, &MAC, &id_of(&big), "f0"));
    fs::remove_file(one).unwrap();
    fx.vault.delete_tree(&x).unwrap();
    fx.vault.delete_dir(&e).unwrap();
    fx.vault.rename(&a, &q, "a").unwrap();
    assert!(fx.vault.lookup(&p, "x").unwrap().is_none());
    assert!(fx.vault.lookup(&p, "e").unwrap().is_none());
}

/// FIL-06.12, C1R2-F4: the walk outside a tree delete skips only the deleted node's own
/// entry, so a twin beside it keeps its content; two nodes with one ID inside the subtree
/// still stop the whole delete when a third is outside; and a folder node with no content
/// folder behind it, anywhere, holds nothing below and stops nothing.
#[test]
fn fil06_t12_the_outside_walk_sees_every_twin_and_skips_only_the_deleted_node() {
    let fx = fx("outside-walk");
    let root = fx.root();
    let p = fx.vault.make_dir(&root, "p").unwrap();
    let q = fx.vault.make_dir(&root, "q").unwrap();
    // A twin beside the deleted folder: p/top/sub and p/s2.
    let top = fx.vault.make_dir(&p, "top").unwrap();
    fx.write(&top, "own.txt", b"top's own");
    let sub = fx.vault.make_dir(&top, "sub").unwrap();
    fx.write(&sub, "inner.txt", b"inner");
    plant_node(&fx, &id_of(&p), "s2", &id_of(&sub));
    let inner = raw_tree(&content_of(&fx, &id_of(&sub)));
    fx.vault.delete_tree(&top).unwrap();
    assert!(fx.vault.lookup(&p, "top").unwrap().is_none());
    assert_eq!(raw_tree(&content_of(&fx, &id_of(&sub))), inner);
    let s2 = fx.find(&p, "s2").node;
    assert_eq!(fx.read(&fx.find(&s2, "inner.txt").node), b"inner");

    // Three nodes, one ID: two inside the subtree, one outside. Nothing changes.
    let t = fx.vault.make_dir(&p, "t").unwrap();
    let ta = fx.vault.make_dir(&t, "a").unwrap();
    fx.write(&ta, "f.txt", b"shared three ways");
    plant_node(&fx, &id_of(&t), "b", &id_of(&ta));
    plant_node(&fx, &id_of(&q), "x", &id_of(&ta));
    let before = raw_tree(&fx.path);
    assert_eq!(fx.vault.delete_tree(&t).err(), Some(Error::Open));
    assert_eq!(raw_tree(&fx.path), before);

    // Folder nodes whose ID has no content folder: one at the top, one in a moved folder.
    plant_node(&fx, b"", "dangling", b"no-content-here");
    let m = fx.vault.make_dir(&root, "m").unwrap();
    plant_node(&fx, &id_of(&m), "dangling", b"no-content-either");
    let w = fx.vault.make_dir(&p, "w").unwrap();
    fx.write(&w, "g.txt", b"goes");
    let v = fx.vault.make_dir(&p, "v").unwrap();
    fx.vault.delete_tree(&w).unwrap();
    fx.vault.delete_dir(&v).unwrap();
    fx.vault.rename(&m, &q, "m").unwrap();
    assert!(fx.vault.lookup(&p, "w").unwrap().is_none());
    assert!(fx.vault.lookup(&p, "v").unwrap().is_none());
    assert!(fx.no_staging_left());
}

/// FIL-06.7, FIL-06.12, C1R2-F5: a folder delete a crash stopped once the node was aside is
/// finished at the next unlock as the live path finishes it: an item that arrived in the
/// meantime keeps the folder, its node comes back, and the deletion is pending. With
/// nothing arrived, the delete finishes. A node aside that holds another ID (FIL-06.8) goes
/// back to its place, and nothing is removed.
#[test]
fn fil06_t07_an_rmdir_resume_keeps_an_item_that_arrived() {
    let mut fx = fx("rmdir-resume");
    let root = fx.root();
    let e = fx.vault.make_dir(&root, "e").unwrap();
    let e_id = id_of(&e);
    seam::crash_at("rmdir.after_aside");
    assert!(fx.vault.delete_dir(&e).is_err());
    seam::clear();
    assert!(
        fx.vault.lookup(&root, "e").unwrap().is_none(),
        "the node is aside"
    );
    // Another Mac's file arrives in e before the restart.
    fs::write(
        raw_path(&fx, &e_id, "late.txt"),
        seal_plain(&ENC, b"arrived late"),
    )
    .unwrap();
    fx.reopen();
    let root = fx.root();
    let e = fx.find(&root, "e").node;
    assert_eq!(e.dir_id.as_deref(), Some(&e_id[..]), "the node is back");
    assert_eq!(fx.read(&fx.find(&e, "late.txt").node), b"arrived late");
    assert!(
        fx.vault
            .recovery_items()
            .unwrap()
            .iter()
            .any(|i| { i.kind == Some(OpKind::Rmdir) && i.state == Some(OpState::Pending) })
    );
    assert!(fx.no_staging_left());

    let f = fx.vault.make_dir(&root, "f").unwrap();
    let f_id = id_of(&f);
    seam::crash_at("rmdir.after_aside");
    assert!(fx.vault.delete_dir(&f).is_err());
    seam::clear();
    fx.reopen();
    let root = fx.root();
    assert!(fx.vault.lookup(&root, "f").unwrap().is_none());
    assert!(
        !content_of(&fx, &f_id).exists(),
        "nothing arrived: the content goes"
    );
    assert!(fx.no_staging_left());

    // The node aside holds another folder's ID when the unlock comes: it goes back to its
    // place as it is, the record ends Aborted, and g's own content is not removed.
    let g = fx.vault.make_dir(&root, "g").unwrap();
    let g_id = id_of(&g);
    let other = id_of(&fx.vault.make_dir(&root, "other").unwrap());
    seam::crash_at("rmdir.after_aside");
    assert!(fx.vault.delete_dir(&g).is_err());
    seam::clear();
    let staging = fs::read_dir(&fx.path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".larsal-staging-")
        })
        .unwrap();
    fs::write(staging.join("node").join("dir.c9r"), &other).unwrap();
    fx.reopen();
    let root = fx.root();
    assert_eq!(
        fx.find(&root, "g").node.dir_id,
        Some(other),
        "back at its place"
    );
    assert!(content_of(&fx, &g_id).is_dir(), "nothing removed");
    assert!(
        fx.vault
            .recovery_items()
            .unwrap()
            .iter()
            .any(|i| { i.kind == Some(OpKind::Rmdir) && i.state == Some(OpState::Aborted) })
    );
    assert!(fx.no_staging_left());
}

/// FIL-06.12, C1R2-F6: deleting an empty folder whose ID another live folder uses removes
/// only its own node. The other still lists, takes a new folder, and can be deleted, and
/// then, alone, its content goes too.
#[test]
fn fil06_t12_delete_dir_of_a_shared_empty_folder_removes_only_its_node() {
    let fx = fx("shared-empty");
    let root = fx.root();
    let p = fx.vault.make_dir(&root, "p").unwrap();
    let q = fx.vault.make_dir(&root, "q").unwrap();
    let x = fx.vault.make_dir(&q, "x").unwrap();
    plant_node(&fx, &id_of(&p), "y", &id_of(&x));
    let y = fx.find(&p, "y").node;
    let shared = content_of(&fx, &id_of(&x));
    let before = raw_tree(&shared);
    fx.vault.delete_dir(&y).unwrap();
    assert!(fx.vault.lookup(&p, "y").unwrap().is_none());
    assert_eq!(raw_tree(&shared), before, "the shared content stays");
    assert!(fx.rows(&x).is_empty(), "the other still lists");
    let child = fx.vault.make_dir(&x, "child").unwrap();
    fx.vault.delete_dir(&child).unwrap();
    fx.vault.delete_dir(&x).unwrap();
    assert!(fx.vault.lookup(&q, "x").unwrap().is_none());
    assert!(!shared.exists(), "alone now: its content goes");
    assert!(fx.no_staging_left());
}

/// One step of a change, for the crash matrix, set up over `top.txt`, a long name and `dir`.
type Op = fn(&Fx, &Node, &Node, &Node, &crate::Digest, &[u8]) -> Result<(), Error>;

fn long_name() -> String {
    format!("{}.bin", "c".repeat(200))
}

struct Case {
    point: &'static str,
    op: Op,
    /// What the session must find after the crash and an unlock.
    expect: fn(&Fx),
    state: OpState,
    kind: OpKind,
}

fn old_top(fx: &Fx) {
    assert_eq!(fx.read(&fx.find(&fx.root(), "top.txt").node), b"old");
}
fn new_top(fx: &Fx) {
    assert_eq!(fx.read(&fx.find(&fx.root(), "top.txt").node), b"new");
}
fn no_new_file(fx: &Fx) {
    assert!(
        fx.vault
            .lookup(&fx.root(), "created.txt")
            .unwrap()
            .is_none()
    );
}
fn has_new_file(fx: &Fx) {
    assert_eq!(fx.read(&fx.find(&fx.root(), "created.txt").node), b"new");
}
fn no_new_dir(fx: &Fx) {
    assert!(fx.vault.lookup(&fx.root(), "made").unwrap().is_none());
}
fn has_new_dir(fx: &Fx) {
    let dir = fx.find(&fx.root(), "made");
    assert_eq!(dir.kind, crate::Kind::Dir);
    assert!(fx.rows(&dir.node).is_empty());
}
fn long_at_new_name(fx: &Fx) {
    assert_eq!(fx.read(&fx.find(&fx.root(), "moved.bin").node), b"long");
    assert!(fx.vault.lookup(&fx.root(), &long_name()).unwrap().is_none());
}
fn top_gone(fx: &Fx) {
    assert!(fx.vault.lookup(&fx.root(), "top.txt").unwrap().is_none());
}
fn dir_gone(fx: &Fx) {
    assert!(fx.vault.lookup(&fx.root(), "dir").unwrap().is_none());
}
fn both_versions(fx: &Fx) {
    let mut got: Vec<Vec<u8>> = fx
        .rows(&fx.root())
        .iter()
        .filter(|r| {
            r.name.as_ref().is_some_and(|n| {
                let n = n.expose();
                n == "top.txt" || n.starts_with("conflict-")
            })
        })
        .map(|r| fx.read(&r.node))
        .collect();
    got.sort();
    assert_eq!(got, [b"another".to_vec(), b"old".to_vec()]);
}

fn do_create(
    fx: &Fx,
    root: &Node,
    _: &Node,
    _: &Node,
    _: &crate::Digest,
    _: &[u8],
) -> Result<(), Error> {
    fx.vault
        .create_file(root, "created.txt", &mut &b"new"[..], 3, &mut |_, _| true)
        .map(|_| ())
}
fn do_update(
    fx: &Fx,
    _: &Node,
    top: &Node,
    _: &Node,
    base: &crate::Digest,
    _: &[u8],
) -> Result<(), Error> {
    fx.vault
        .update_file(top, base, &mut &b"new"[..], 3, &mut |_, _| true)
        .map(|_| ())
}
fn do_admit(
    fx: &Fx,
    root: &Node,
    _: &Node,
    _: &Node,
    _: &crate::Digest,
    raw: &[u8],
) -> Result<(), Error> {
    fx.vault
        .admit_version(
            root,
            "top.txt",
            &mut &raw[..],
            raw.len() as u64,
            &mut |_, _| true,
        )
        .map(|_| ())
}
fn do_mkdir(
    fx: &Fx,
    root: &Node,
    _: &Node,
    _: &Node,
    _: &crate::Digest,
    _: &[u8],
) -> Result<(), Error> {
    fx.vault.make_dir(root, "made").map(|_| ())
}
fn do_rename(
    fx: &Fx,
    root: &Node,
    _: &Node,
    _: &Node,
    _: &crate::Digest,
    _: &[u8],
) -> Result<(), Error> {
    let long = fx.find(root, &long_name()).node;
    fx.vault.rename(&long, root, "moved.bin").map(|_| ())
}
fn do_delete(
    fx: &Fx,
    _: &Node,
    top: &Node,
    _: &Node,
    base: &crate::Digest,
    _: &[u8],
) -> Result<(), Error> {
    fx.vault.delete_file(top, base)
}
fn do_rmdir(
    fx: &Fx,
    _: &Node,
    _: &Node,
    dir: &Node,
    _: &crate::Digest,
    _: &[u8],
) -> Result<(), Error> {
    fx.vault.delete_dir(dir)
}

fn crash_cases() -> Vec<Case> {
    use OpKind as K;
    use OpState as S;
    let case = |point, op: Op, expect: fn(&Fx), state, kind| Case {
        point,
        op,
        expect,
        state,
        kind,
    };
    vec![
        case(
            "create.after_journal",
            do_create,
            no_new_file,
            S::Aborted,
            K::Create,
        ),
        case("write.chunk", do_create, no_new_file, S::Aborted, K::Create),
        case(
            "write.before_sync",
            do_create,
            no_new_file,
            S::Aborted,
            K::Create,
        ),
        case(
            "create.after_stage",
            do_create,
            no_new_file,
            S::Aborted,
            K::Create,
        ),
        case(
            "create.after_publish",
            do_create,
            has_new_file,
            S::Done,
            K::Create,
        ),
        case(
            "update.after_base",
            do_update,
            old_top,
            S::Aborted,
            K::Update,
        ),
        case("write.chunk", do_update, old_top, S::Aborted, K::Update),
        case(
            "write.before_sync",
            do_update,
            old_top,
            S::Aborted,
            K::Update,
        ),
        case(
            "update.after_stage",
            do_update,
            old_top,
            S::Aborted,
            K::Update,
        ),
        case(
            "update.before_swap",
            do_update,
            old_top,
            S::Aborted,
            K::Update,
        ),
        case("update.swap", do_update, old_top, S::Aborted, K::Update),
        case("update.after_swap", do_update, new_top, S::Done, K::Update),
        case(
            "update.after_old_removed",
            do_update,
            new_top,
            S::Done,
            K::Update,
        ),
        case(
            "admit.after_stage",
            do_admit,
            both_versions,
            S::Done,
            K::Admit,
        ),
        case(
            "admit.after_move_old",
            do_admit,
            both_versions,
            S::Done,
            K::Admit,
        ),
        case(
            "mkdir.after_content",
            do_mkdir,
            no_new_dir,
            S::Aborted,
            K::Mkdir,
        ),
        case("mkdir.after_link", do_mkdir, has_new_dir, S::Done, K::Mkdir),
        case(
            "rename.after_partial",
            do_rename,
            long_at_new_name,
            S::Done,
            K::Rename,
        ),
        case(
            "rename.after_switch",
            do_rename,
            long_at_new_name,
            S::Done,
            K::Rename,
        ),
        case(
            "delete.after_base",
            do_delete,
            old_top,
            S::Aborted,
            K::Delete,
        ),
        case(
            "delete.after_aside",
            do_delete,
            top_gone,
            S::Done,
            K::Delete,
        ),
        case("rmdir.after_aside", do_rmdir, dir_gone, S::Done, K::Rmdir),
        case("rmdir.after_content", do_rmdir, dir_gone, S::Done, K::Rmdir),
    ]
}

/// A crash at `case.point`, then a new session; `plant` runs on the leftovers first.
fn crash_then_unlock(case: &Case, plant: impl FnOnce(&Fx)) -> Fx {
    let mut fx = fx("crash");
    let root = fx.root();
    let top = fx.write(&root, "top.txt", b"old");
    let base = fx.digest(&top);
    fx.write(&root, &long_name(), b"long");
    let dir = fx.vault.make_dir(&root, "dir").unwrap();
    // Each content key gives another digest. A version that sorts first moves the old one
    // aside; one that sorts after goes straight to its reserved name.
    let wants_first = case.point == "admit.after_move_old";
    // The base digest is random: search until one falls on the wanted side, however near
    // the end the base sits (256 keys missed it about once in 257 runs per case).
    let raw = (0u64..)
        .map(|k| {
            let key: [u8; 32] = larsal_crypto::hash::sha256(&[&k.to_be_bytes()])
                .expose()
                .try_into()
                .unwrap();
            seal_with(&ENC, &key, b"another", false)
        })
        .find(|raw| (sha256_hex(raw) < base.hex()) == wants_first)
        .unwrap();
    seam::crash_at(case.point);
    let got = (case.op)(&fx, &root, &top, &dir, &base, &raw);
    assert!(got.is_err(), "{} did not stop", case.point);
    assert!(seam::crashed(), "{} was not reached", case.point);
    seam::clear();
    plant(&fx);
    fx.reopen();
    fx
}

/// FIL-06.7, FIL-04-T10: at every step of every change, a crash then an unlock finds a
/// whole folder, in the state the step says, with a finished record for it, no staging
/// left, and the versions the record names durable here. A second unlock changes nothing.
#[test]
fn fil06_t07_a_crash_at_every_step_recovers_whole() {
    for case in crash_cases() {
        let mut fx = crash_then_unlock(&case, |_| {});
        (case.expect)(&fx);
        assert!(fx.no_staging_left(), "{}: staging left", case.point);
        let items = fx.vault.recovery_items().unwrap();
        // The crashed record: the one in the state the step says, of the step's own kind.
        let item = items
            .iter()
            .find(|i| i.kind == Some(case.kind) && i.state == Some(case.state))
            .unwrap_or_else(|| panic!("{}: {items:?}", case.point));
        assert!(item.proven);
        assert!(
            items.iter().all(|i| matches!(
                i.state,
                Some(OpState::Done | OpState::Aborted | OpState::Pending)
            )),
            "{}: {items:?}",
            case.point
        );
        if let Some(digest) = item.new {
            let copy = fx
                .vault
                .capture_recovery(&item.id, Kept::New, &mut |_, _| true)
                .unwrap();
            assert_eq!(copy.digest(), digest, "{}", case.point);
        }
        if let Some(digest) = item.base {
            let copy = fx
                .vault
                .capture_recovery(&item.id, Kept::Base, &mut |_, _| true)
                .unwrap();
            assert_eq!(copy.digest(), digest, "{}", case.point);
        }
        let tree = raw_tree(&fx.path);
        fx.reopen();
        assert_eq!(
            raw_tree(&fx.path),
            tree,
            "{}: a second unlock does nothing",
            case.point
        );
        let root = fx.root();
        fx.write(&root, "after.txt", b"after");
        assert_eq!(fx.read(&fx.find(&root, "after.txt").node), b"after");
    }
}

/// FIL-06.7: after a crash, a replacement at any name the record knows, or an unknown file
/// in its staging, is another writer's. It is not deleted or overwritten: it stays, or it
/// is kept by the rule, byte for byte.
#[test]
fn fil06_t07_a_planted_replacement_is_never_removed() {
    let at = |point: &str| {
        crash_cases()
            .into_iter()
            .find(|c| c.point == point)
            .unwrap()
    };
    // Staging: an unknown name. The folder stays, with it, and the session still opens.
    let fx1 = crash_then_unlock(&at("update.after_swap"), |fx| {
        let staging = staging_dirs(&fx.path).pop().unwrap();
        fs::write(staging.join("foreign"), b"foreign bytes").unwrap();
    });
    let staging = staging_dirs(&fx1.path)
        .pop()
        .expect("a folder with another's file stays");
    assert_eq!(fs::read(staging.join("foreign")).unwrap(), b"foreign bytes");
    new_top(&fx1);

    // The staged name itself: another writer's object where the old version came out.
    let foreign = seal_plain(&ENC, b"foreign version");
    let raw = foreign.clone();
    let fx2 = crash_then_unlock(&at("update.after_swap"), move |fx| {
        let staging = staging_dirs(&fx.path).pop().unwrap();
        fs::remove_file(staging.join("new")).unwrap();
        fs::write(staging.join("new"), &raw).unwrap();
    });
    let digest = sha256_hex(&foreign);
    let mut holders = Vec::new();
    for row in fx2
        .rows(&fx2.root())
        .into_iter()
        .filter(|r| r.kind == crate::Kind::File)
    {
        if fx2.digest(&row.node).hex() == digest {
            holders.push(row.name.unwrap().expose().to_owned());
        }
    }
    assert_eq!(
        holders.len(),
        1,
        "its bytes are still there, by the rule: {holders:?}"
    );

    // The aside node after a delete: not the version kept. It goes back.
    let foreign = seal_plain(&ENC, b"foreign version");
    let raw = foreign.clone();
    let fx3 = crash_then_unlock(&at("delete.after_aside"), move |fx| {
        let staging = staging_dirs(&fx.path).pop().unwrap();
        fs::remove_file(staging.join("node")).unwrap();
        fs::write(staging.join("node"), &raw).unwrap();
    });
    assert_eq!(fs::read(top_raw(&fx3, "top.txt")).unwrap(), foreign);
    let item = fx3
        .vault
        .recovery_items()
        .unwrap()
        .into_iter()
        .find(|i| i.kind == Some(OpKind::Delete))
        .unwrap();
    assert_eq!(item.state, Some(OpState::Pending));

    // A delete's name reused by a new file after the crash: not touched.
    let replacement = seal_plain(&ENC, b"a new file with that name");
    let raw = replacement.clone();
    let fx4 = crash_then_unlock(&at("delete.after_aside"), move |fx| {
        fs::write(top_raw(fx, "top.txt"), &raw).unwrap();
    });
    assert_eq!(fs::read(top_raw(&fx4, "top.txt")).unwrap(), replacement);

    // A created name taken by another after the crash, whatever the record says.
    let replacement = seal_plain(&ENC, b"another writer");
    let raw = replacement.clone();
    let fx5 = crash_then_unlock(&at("create.after_stage"), move |fx| {
        fs::write(top_raw(fx, "created.txt"), &raw).unwrap();
    });
    assert_eq!(fs::read(top_raw(&fx5, "created.txt")).unwrap(), replacement);
}

/// FIL-06.7, F-340 not repeated: cleanup after a failure removes only the object this
/// operation made. Another object at that name, or anything else in the folder, stays,
/// and the answer is the uncertain one, never a plain failure or a success.
#[test]
fn fil06_t07_failure_cleanup_is_bound_to_what_was_made() {
    // Same name, another object: a replaced staged file.
    let fx_a = fx("cleanup-a");
    let root = fx_a.root();
    let node = fx_a.write(&root, "file.bin", b"old");
    let base = fx_a.digest(&node);
    let folder = fx_a.path.clone();
    seam::at_every_point(move |point| {
        if point == "write.before_sync" {
            let staging = staging_dirs(&folder).pop().unwrap();
            fs::remove_file(staging.join("new")).unwrap();
            fs::write(staging.join("new"), b"another writer's object").unwrap();
        }
    });
    seam::fail_at("write.before_sync", Error::Io);
    let got = fx_a
        .vault
        .update_file(&node, &base, &mut &b"new"[..], 3, &mut |_, _| true);
    seam::clear();
    assert_eq!(got.err(), Some(Error::Uncertain));
    let staging = staging_dirs(&fx_a.path).pop().unwrap();
    assert_eq!(
        fs::read(staging.join("new")).unwrap(),
        b"another writer's object"
    );
    assert_eq!(fx_a.read(&node), b"old");

    // Something else in the folder.
    let fx_b = fx("cleanup-b");
    let root = fx_b.root();
    let folder = fx_b.path.clone();
    seam::at_every_point(move |point| {
        if point == "write.before_sync" {
            let staging = staging_dirs(&folder).pop().unwrap();
            fs::write(staging.join("planted"), b"planted").unwrap();
        }
    });
    seam::fail_at("write.before_sync", Error::Space);
    let got = fx_b
        .vault
        .create_file(&root, "new.bin", &mut &b"new"[..], 3, &mut |_, _| true);
    seam::clear();
    assert_eq!(
        got.err(),
        Some(Error::Uncertain),
        "said, even over the first cause"
    );
    let staging = staging_dirs(&fx_b.path).pop().unwrap();
    assert_eq!(fs::read(staging.join("planted")).unwrap(), b"planted");
    assert!(!staging.join("new").exists(), "what it made is gone");

    // A cancel: the same care, and a clean folder when nothing interferes.
    let fx_c = fx("cleanup-c");
    let root = fx_c.root();
    let before = raw_tree(&fx_c.path);
    let plain = demo_bytes(CHUNK * 5, 1);
    let got = fx_c.vault.create_file(
        &root,
        "new.bin",
        &mut &plain[..],
        plain.len() as u64,
        &mut |_, _| false,
    );
    assert_eq!(got.err(), Some(Error::Cancelled));
    assert_eq!(raw_tree(&fx_c.path), before);
    assert!(
        record_dirs(&fx_c).is_empty(),
        "an incomplete record holds nothing to review"
    );
}

/// FIL-06.10, FIL-06.13, FIL-06.14: no clear name in any raw object, record, journal or
/// file name, in the folder or the stores; after an unlock the record gives back the name
/// and the versions.
#[test]
fn fil06_t10_no_clear_marker_in_raw_objects_and_it_comes_back_after_unlock() {
    let mut fx = fx("marker");
    let root = fx.root();
    let name = "DEMO-UNIQUE-NAME-MARKER.txt";
    let marker = b"DEMO-UNIQUE-NAME-MARKER";
    let body = b"DEMO-UNIQUE-BODY-MARKER";
    let node = fx.write(&root, name, body);
    let base = fx.digest(&node);
    let saved = fx
        .vault
        .update_file(
            &node,
            &base,
            &mut &b"DEMO-UNIQUE-BODY-MARKER 2"[..],
            25,
            &mut |_, _| true,
        )
        .unwrap();
    let theirs = seal_plain(&ENC, b"DEMO-UNIQUE-BODY-MARKER 3");
    fx.vault
        .admit_version(
            &root,
            name,
            &mut &theirs[..],
            theirs.len() as u64,
            &mut |_, _| true,
        )
        .unwrap();
    let long = format!("DEMO-UNIQUE-NAME-MARKER-{}.txt", "l".repeat(200));
    let long_node = fx.write(&root, &long, b"long");
    fx.vault.rename(&long_node, &root, "elsewhere.txt").unwrap();
    let dir = fx
        .vault
        .make_dir(&root, "DEMO-UNIQUE-NAME-MARKER-dir")
        .unwrap();
    fx.vault.delete_dir(&dir).unwrap();
    let current = fx.digest(&node);
    seam::crash_at("update.after_stage");
    let _ = fx.vault.update_file(
        &node,
        &current,
        &mut &b"DEMO-UNIQUE-BODY-MARKER 4"[..],
        25,
        &mut |_, _| true,
    );
    seam::clear();
    fx.vault.lock();
    for tree in [&fx.path, &fx.stores_path] {
        assert!(!tree_holds(tree, marker), "{tree:?}");
        assert!(!tree_holds(tree, body), "{tree:?}");
        assert!(!tree_holds(tree, hex(marker).as_bytes()), "not in hex");
    }
    fx.reopen();
    let again = fx.vault.recovery_items().unwrap();
    let with_name = again
        .iter()
        .filter(|i| i.name.as_ref().is_some_and(|n| n.expose() == name))
        .count();
    assert!(with_name >= 3);
    let saved_item = again.iter().find(|i| i.new == Some(saved.digest)).unwrap();
    assert_eq!(saved_item.name.as_ref().unwrap().expose(), name);
    assert!(
        again
            .iter()
            .any(|i| i.name.as_ref().is_some_and(|n| n.expose() == long))
    );
    let mut back = Vec::new();
    fx.vault
        .capture_recovery(&saved_item.id, Kept::New, &mut |_, _| true)
        .unwrap()
        .validate(&mut |_, _| true)
        .unwrap()
        .write_to(&mut back, &mut |_, _| true)
        .unwrap();
    assert_eq!(back, b"DEMO-UNIQUE-BODY-MARKER 2");
    // The stores' own objects are private, down to each copy.
    for path in record_dirs(&fx) {
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for entry in fs::read_dir(&path).unwrap() {
            let meta = entry.unwrap().metadata().unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }
    fx.vault.lock();
    assert_eq!(fx.vault.recovery_items().err(), Some(Error::Locked));
}

/// FIL-06.13: the ceiling, and what one change needs, before anything changes. Nothing is
/// pruned to fit. A read is never stopped by it.
#[test]
fn fil06_t13_recovery_ceiling_below_at_and_over() {
    let fx = fx("ceiling");
    let root = fx.root();
    let node = fx.write(&root, "file.bin", &demo_bytes(1000, 1));
    let base = fx.digest(&node);
    let used = |fx: &Fx| fx.vault.recovery_used.load(Ordering::SeqCst);
    let journal = 16_384u64;
    let plain = demo_bytes(2000, 2);
    let stored_new = 68 + 2000 + 28;
    let stored_old = 68 + 1000 + 28;
    let records_before = record_dirs(&fx).len();
    let before = raw_tree(&fx.path);

    // An edit needs the base, the new version and a journal.
    let need = stored_old + stored_new + journal;
    fx.vault
        .ceiling
        .store(used(&fx) + need - 1, Ordering::SeqCst);
    assert_eq!(
        fx.vault
            .update_file(&node, &base, &mut &plain[..], 2000, &mut |_, _| true)
            .err(),
        Some(Error::Recovery)
    );
    // A create needs the new version and a journal.
    fx.vault
        .ceiling
        .store(used(&fx) + stored_new + journal - 1, Ordering::SeqCst);
    assert_eq!(
        fx.vault
            .create_file(&root, "n.bin", &mut &plain[..], 2000, &mut |_, _| true)
            .err(),
        Some(Error::Recovery)
    );
    // A rename needs only a journal; a delete, the base too.
    fx.vault
        .ceiling
        .store(used(&fx) + journal - 1, Ordering::SeqCst);
    assert_eq!(
        fx.vault.rename(&node, &root, "r.bin").err(),
        Some(Error::Recovery)
    );
    fx.vault
        .ceiling
        .store(used(&fx) + journal + stored_old - 1, Ordering::SeqCst);
    assert_eq!(
        fx.vault.delete_file(&node, &base).err(),
        Some(Error::Recovery)
    );
    assert_eq!(raw_tree(&fx.path), before, "stopped before any change");
    assert_eq!(
        record_dirs(&fx).len(),
        records_before,
        "no half-kept record, none pruned"
    );

    // At the ceiling exactly: it goes, and nothing older was given up.
    fx.vault.ceiling.store(used(&fx) + need, Ordering::SeqCst);
    let saved = fx
        .vault
        .update_file(&node, &base, &mut &plain[..], 2000, &mut |_, _| true)
        .unwrap();
    assert_eq!(saved.outcome, Outcome::Replaced);
    assert_eq!(record_dirs(&fx).len(), records_before + 1);
    // Now full: every change stops, every read goes on.
    assert_eq!(fx.vault.make_dir(&root, "d").err(), Some(Error::Recovery));
    assert_eq!(fx.read(&node), plain);
    assert_eq!(fx.rows(&root).len(), 1);

    // A reviewed discard makes room; only that.
    let item = fx
        .vault
        .recovery_items()
        .unwrap()
        .into_iter()
        .find(|i| i.new == Some(saved.digest))
        .unwrap();
    fx.vault
        .recovery_discard(&item.id, item.base, item.new)
        .unwrap();
    assert_eq!(record_dirs(&fx).len(), records_before);
    fx.vault.make_dir(&root, "d").unwrap();
}

/// FIL-06.13, S3's settling of the matrix: with the proposed 10 GiB ceiling and real sizes,
/// what each large change needs (the local copies, before any byte is written).
#[test]
fn fil06_t13_the_large_file_matrix_against_the_ceiling() {
    let mut fx = fx("matrix");
    fx.vault.ceiling.store(RECOVERY_CEILING, Ordering::SeqCst);
    let gb4 = 4u64 * 1000 * 1000 * 1000;
    let gib10 = 10u64 << 30;
    let stored = crate::content::stored_len(gb4).unwrap();
    // A 4 GB create: one copy. A 4 GB edit: two copies. Both fit one at a time.
    assert!(stored * 2 < gib10);
    fx.vault.recovery_used.store(0, Ordering::SeqCst);
    assert!(
        !matches!(fx.vault.preflight(stored, stored), Err(Error::Recovery)),
        "create"
    );
    assert!(
        !matches!(fx.vault.preflight(stored * 2, stored), Err(Error::Recovery)),
        "edit"
    );
    // After a 4 GB edit is kept, another stops until copies are reviewed: not pruned.
    fx.vault.recovery_used.store(stored * 2, Ordering::SeqCst);
    assert_eq!(fx.vault.preflight(stored * 2, stored), Err(Error::Recovery));
    assert!(
        !matches!(fx.vault.preflight(0, 16_384), Err(Error::Recovery)),
        "a rename goes"
    );
    // A single change past the ceiling: the refusal, whatever is free.
    fx.vault.recovery_used.store(0, Ordering::SeqCst);
    assert_eq!(fx.vault.preflight(gib10, 0), Err(Error::Recovery));
    let root = fx.root();
    assert_eq!(
        fx.vault
            .create_file(
                &root,
                "huge.bin",
                &mut std::io::empty(),
                gib10 + 1,
                &mut |_, _| true
            )
            .err(),
        Some(Error::Recovery)
    );
    // Past what the disk has, under a ceiling that allows it: free space says so.
    fx.vault.ceiling.store(u64::MAX, Ordering::SeqCst);
    assert_eq!(
        fx.vault
            .create_file(
                &root,
                "huge.bin",
                &mut std::io::empty(),
                1 << 60,
                &mut |_, _| true
            )
            .err(),
        Some(Error::Space)
    );
    assert!(fx.no_staging_left());
    assert!(fx.vault.lookup(&root, "huge.bin").unwrap().is_none());
    // The count comes back from what is really kept, after a restart.
    fx.vault.recovery_used.store(0, Ordering::SeqCst);
    fx.write(&root, "real.bin", &demo_bytes(5000, 2));
    let used = fx.vault.recovery_used.load(Ordering::SeqCst);
    fx.reopen();
    assert_eq!(fx.vault.recovery_used.load(Ordering::SeqCst), used);
}

/// FIL-06.14: only an exact owned record goes. Each kind of substitution stops the discard,
/// with every byte in place.
#[test]
fn fil06_t14_discard_only_an_exact_owned_record() {
    let fx = fx("discard");
    let root = fx.root();
    let node = fx.write(&root, "file.bin", b"one");
    let base = fx.digest(&node);
    let saved = fx
        .vault
        .update_file(&node, &base, &mut &b"two"[..], 3, &mut |_, _| true)
        .unwrap();
    let item = fx
        .vault
        .recovery_items()
        .unwrap()
        .into_iter()
        .find(|i| i.new == Some(saved.digest))
        .unwrap();
    let dir = recovery_dir(&fx).join(&item.id);
    let good = raw_tree(&dir);
    let (b, n) = (item.base, item.new);

    // Wrong expectations.
    assert_eq!(
        fx.vault.recovery_discard(&item.id, None, n).err(),
        Some(Error::Input)
    );
    assert_eq!(
        fx.vault.recovery_discard(&item.id, b, None).err(),
        Some(Error::Input)
    );
    assert_eq!(
        fx.vault.recovery_discard("../escape", b, n).err(),
        Some(Error::Input)
    );
    assert_eq!(
        fx.vault.recovery_discard("op-none", b, n).err(),
        Some(Error::Input)
    );
    // A replaced copy.
    let keep = fs::read(dir.join("base")).unwrap();
    fs::write(dir.join("base"), b"replaced").unwrap();
    assert_eq!(
        fx.vault.recovery_discard(&item.id, b, n).err(),
        Some(Error::Uncertain)
    );
    assert_eq!(fs::read(dir.join("base")).unwrap(), b"replaced");
    // A link for a copy.
    fs::remove_file(dir.join("base")).unwrap();
    let outside = fx.top.join("outside");
    fs::write(&outside, &keep).unwrap();
    symlink(&outside, dir.join("base")).unwrap();
    assert_eq!(
        fx.vault.recovery_discard(&item.id, b, n).err(),
        Some(Error::Uncertain)
    );
    assert_eq!(fs::read(&outside).unwrap(), keep);
    fs::remove_file(dir.join("base")).unwrap();
    fs::write(dir.join("base"), &keep).unwrap();
    fs::set_permissions(dir.join("base"), fs::Permissions::from_mode(0o600)).unwrap();
    // An unknown file beside them.
    fs::write(dir.join("unknown"), b"unknown").unwrap();
    assert_eq!(
        fx.vault.recovery_discard(&item.id, b, n).err(),
        Some(Error::Uncertain)
    );
    assert_eq!(fs::read(dir.join("unknown")).unwrap(), b"unknown");
    fs::remove_file(dir.join("unknown")).unwrap();
    // A bad mode on the record.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        fx.vault.recovery_discard(&item.id, b, n).err(),
        Some(Error::Input)
    );
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    // A forged journal: one word of the state.
    let journal = fs::read(dir.join("journal")).unwrap();
    let forged = String::from_utf8(journal.clone())
        .unwrap()
        .replace("state=done", "state=aborted");
    fs::write(dir.join("journal"), &forged).unwrap();
    assert_eq!(
        fx.vault.recovery_discard(&item.id, b, n).err(),
        Some(Error::Input)
    );
    let row = fx
        .vault
        .recovery_items()
        .unwrap()
        .into_iter()
        .find(|i| i.id == item.id)
        .unwrap();
    assert!(!row.proven, "shown, says nothing");
    assert!(row.name.is_none() && row.kind.is_none());
    assert_eq!(
        fs::read(dir.join("journal")).unwrap(),
        forged.as_bytes(),
        "stays"
    );
    fs::write(dir.join("journal"), &journal).unwrap();
    // A journal linked from elsewhere.
    fs::remove_file(dir.join("journal")).unwrap();
    let elsewhere = fx.top.join("journal-elsewhere");
    fs::write(&elsewhere, &journal).unwrap();
    symlink(&elsewhere, dir.join("journal")).unwrap();
    assert_eq!(
        fx.vault.recovery_discard(&item.id, b, n).err(),
        Some(Error::Input)
    );
    assert!(elsewhere.is_file());
    fs::remove_file(dir.join("journal")).unwrap();
    fs::write(dir.join("journal"), &journal).unwrap();
    fs::set_permissions(dir.join("journal"), fs::Permissions::from_mode(0o600)).unwrap();
    // A reused record: another record's right journal in this folder.
    let reused = recovery_dir(&fx).join("op-reused");
    fs::create_dir(&reused).unwrap();
    fs::set_permissions(&reused, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(reused.join("journal"), &journal).unwrap();
    assert_eq!(
        fx.vault.recovery_discard("op-reused", b, n).err(),
        Some(Error::Input)
    );
    let row = fx
        .vault
        .recovery_items()
        .unwrap()
        .into_iter()
        .find(|i| i.id == "op-reused")
        .unwrap();
    assert!(!row.proven);
    assert!(reused.join("journal").is_file());
    // The real one, exactly: gone, and only it.
    assert_eq!(raw_tree(&dir).len(), good.len());
    fx.vault.recovery_discard(&item.id, b, n).unwrap();
    assert!(!dir.exists());
    assert!(reused.is_dir());
    assert!(!fx.vault.recovery_items().unwrap().is_empty());
}

/// FIL-06.14: the store's own mode is proven on unlock; a store not private stops it. A
/// foreign thing in the store is left alone by every restart.
#[test]
fn fil06_t14_a_store_not_private_stops_and_foreign_things_stay() {
    let mut fx = fx("store-mode");
    let root = fx.root();
    fx.write(&root, "a.bin", b"a");
    let store = recovery_dir(&fx);
    fs::write(store.join("not-a-record"), b"foreign").unwrap();
    fs::create_dir(store.join("op-foreign")).unwrap();
    fs::write(store.join("op-foreign").join("journal"), b"not ours").unwrap();
    fs::write(store.join("op-foreign").join("base"), b"not ours").unwrap();
    fx.reopen();
    assert_eq!(fs::read(store.join("not-a-record")).unwrap(), b"foreign");
    assert_eq!(
        fs::read(store.join("op-foreign").join("journal")).unwrap(),
        b"not ours"
    );
    assert_eq!(
        fs::read(store.join("op-foreign").join("base")).unwrap(),
        b"not ours"
    );
    fx.vault.lock();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
    let again = crate::Vault::unlock(&fx.path, &secret(PASSWORD), &fx.stores, &mut |_, _| true);
    assert_eq!(again.err(), Some(Error::Input));
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    // A link as the store.
    fx.vault =
        crate::Vault::unlock(&fx.path, &secret(PASSWORD), &fx.stores, &mut |_, _| true).unwrap();
    fx.vault.lock();
    let elsewhere = fx.top.join("recovery-elsewhere");
    fs::rename(&store, &elsewhere).unwrap();
    symlink(&elsewhere, &store).unwrap();
    let again = crate::Vault::unlock(&fx.path, &secret(PASSWORD), &fx.stores, &mut |_, _| true);
    assert_eq!(again.err(), Some(Error::Input));
    // Stores that are not private at all, or a link.
    let open_dir = fx.top.join("open-stores");
    fs::create_dir(&open_dir).unwrap();
    fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(crate::Stores::open(&open_dir).err(), Some(Error::Input));
    let link = fx.top.join("link-stores");
    symlink(&fx.stores_path, &link).unwrap();
    assert_eq!(crate::Stores::open(&link).err(), Some(Error::Input));
}
