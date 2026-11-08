//! FIL-04-T13, FIL-06-T08, T17: revocation, lock, cancel and busy, with no late effect.

use super::common::*;
use super::fx;
use crate::error::Error;
use crate::{Digest, Kept, Node, Phase, Vault, seam};
use std::fs;
use std::rc::Rc;
use std::sync::{Arc, Barrier};

/// FIL-06.8: after revoke, every way in says Locked, nothing changes on disk, and old
/// handles do not come back with a new session.
#[test]
fn fil06_t08_every_way_in_is_denied_after_revoke() {
    let mut fx = fx("revoked");
    let root = fx.root();
    let file = fx.write(&root, "file.txt", b"file");
    let dir = fx.vault.make_dir(&root, "dir").unwrap();
    let base = fx.digest(&file);
    let mut listing = fx.vault.open_listing(&root).unwrap();
    let items = fx.vault.recovery_items().unwrap();
    let id = items[0].id.clone();
    let before = raw_tree(&fx.path);
    let stored = fs::read(
        fx.path
            .join(dir_path(&ENC, &MAC, b""))
            .join(raw_name(&ENC, &MAC, b"", "file.txt")),
    )
    .unwrap();

    let snapshot = fx.vault.capture(&file, &mut |_, _| true).unwrap();
    let validated = fx
        .vault
        .capture(&file, &mut |_, _| true)
        .unwrap()
        .validate(&mut |_, _| true)
        .unwrap();

    fx.vault.revoke();
    let go = &mut |_: Phase, _: u64| true;
    let v = &fx.vault;
    let mut out = Vec::new();
    assert_eq!(v.root_dir().err(), Some(Error::Locked));
    assert_eq!(v.open_listing(&root).err(), Some(Error::Locked));
    assert_eq!(listing.next_page(10).err(), Some(Error::Locked));
    assert_eq!(v.lookup(&root, "file.txt").err(), Some(Error::Locked));
    assert_eq!(
        v.create_file(&root, "x", &mut &b"x"[..], 1, go).err(),
        Some(Error::Locked)
    );
    assert_eq!(
        v.update_file(&file, &base, &mut &b"x"[..], 1, go).err(),
        Some(Error::Locked)
    );
    assert_eq!(
        v.admit_version(&root, "x", &mut &stored[..], stored.len() as u64, go)
            .err(),
        Some(Error::Locked)
    );
    assert_eq!(v.make_dir(&root, "x").err(), Some(Error::Locked));
    assert_eq!(v.rename(&file, &root, "x").err(), Some(Error::Locked));
    assert_eq!(v.delete_file(&file, &base).err(), Some(Error::Locked));
    assert_eq!(v.delete_dir(&dir).err(), Some(Error::Locked));
    assert_eq!(v.delete_tree(&dir).err(), Some(Error::Locked));
    assert_eq!(v.capture(&file, go).err(), Some(Error::Locked));
    assert_eq!(
        v.capture_recovery(&id, Kept::New, go).err(),
        Some(Error::Locked)
    );
    assert_eq!(v.read_to(&file, &mut out, go).err(), Some(Error::Locked));
    assert_eq!(v.recovery_items().err(), Some(Error::Locked));
    assert_eq!(
        v.recovery_discard(&id, None, None).err(),
        Some(Error::Locked)
    );
    assert_eq!(v.budget_report().err(), Some(Error::Locked));
    // What was already in custody cannot release anything.
    assert_eq!(snapshot.validate(go).err(), Some(Error::Locked));
    assert_eq!(validated.write_to(&mut out, go).err(), Some(Error::Locked));
    assert!(out.is_empty());
    assert_eq!(raw_tree(&fx.path), before);

    // A lock wipes; a new session does not take an old handle.
    fx.vault.lock();
    assert!(fx.vault.keys_are_gone(), "the keys are gone");
    fx.reopen();
    let mut out = Vec::new();
    assert_eq!(
        fx.vault.read_to(&file, &mut out, &mut |_, _| true).err(),
        Some(Error::Locked)
    );
    assert_eq!(fx.vault.open_listing(&dir).err(), Some(Error::Locked));
    assert_eq!(
        fx.vault
            .rename(&file, &fx.vault.root_dir().unwrap(), "x")
            .err(),
        Some(Error::Locked)
    );
    assert!(out.is_empty());
}

/// FIL-06.8: revoke during a chunk: the next boundary stops, no later plaintext goes out,
/// and a write stopped this way leaves nothing behind.
#[test]
fn fil06_t08_revoke_during_a_chunk_stops_at_the_next_boundary() {
    let fx = fx("mid-chunk");
    let root = fx.root();
    let plain = demo_bytes(CHUNK * 30, 2);
    let node = fx.write(&root, "big.bin", &plain);
    let name = raw_name(&ENC, &MAC, b"", "big.bin");
    let raw = fx.path.join(dir_path(&ENC, &MAC, b"")).join(name);
    let before = fs::read(&raw).unwrap();

    // During the second pass: only what was released before the revoke, in order.
    let mut out = Vec::new();
    let got = {
        let v = &fx.vault;
        v.read_to(&node, &mut out, &mut |p, done| {
            if p == Phase::Write && done >= CHUNK as u64 * 2 {
                v.revoke();
            }
            true
        })
    };
    assert_eq!(got.err(), Some(Error::Locked));
    assert!(out.len() < plain.len());
    assert_eq!(out, plain[..out.len()], "a true prefix, nothing after");
    assert_eq!(
        fx.vault
            .read_to(&node, &mut Vec::new(), &mut |_, _| true)
            .err(),
        Some(Error::Locked)
    );
    assert_eq!(fs::read(&raw).unwrap(), before);
}

#[test]
fn fil06_t08_revoke_during_validate_releases_nothing() {
    let fx = fx("mid-validate");
    let root = fx.root();
    let node = fx.write(&root, "big.bin", &demo_bytes(CHUNK * 30, 2));
    let mut out = Vec::new();
    let v = &fx.vault;
    let got = v.read_to(&node, &mut out, &mut |p, _| {
        if p == Phase::Validate {
            v.revoke();
        }
        true
    });
    assert_eq!(got.err(), Some(Error::Locked));
    assert!(out.is_empty());
}

#[test]
fn fil06_t08_revoke_during_encrypt_leaves_the_old_version() {
    let fx = fx("mid-write");
    let root = fx.root();
    let node = fx.write(&root, "file.bin", b"old version");
    let base = fx.digest(&node);
    let before = raw_tree(&fx.path);
    let plain = demo_bytes(CHUNK * 30, 2);
    let v = &fx.vault;
    let got = v.update_file(
        &node,
        &base,
        &mut &plain[..],
        plain.len() as u64,
        &mut |p, _| {
            if p == Phase::Encrypt {
                v.revoke();
            }
            true
        },
    );
    assert_eq!(got.err(), Some(Error::Locked));
    assert_eq!(raw_tree(&fx.path), before, "no new object, no staging");
}

/// FIL-06.8: no change takes effect after a revoke, whichever step the revoke falls before.
/// A short file has one chunk, so the last gate is the only gate: the revoke that comes with
/// it still publishes nothing, and an old version stays.
#[test]
fn fil06_t08_no_change_is_published_after_a_revoke() {
    type Work = fn(&Vault, &Node, &Node, &Node, &Digest) -> Result<(), Error>;
    const WORK: [(&str, Work); 6] = [
        ("create.after_stage", |v, r, _, _, _| {
            v.create_file(r, "new.bin", &mut &b"n"[..], 1, &mut |_, _| true)
                .map(|_| ())
        }),
        ("update.before_swap", |v, _, f, _, b| {
            v.update_file(f, b, &mut &b"edit"[..], 4, &mut |_, _| true)
                .map(|_| ())
        }),
        ("delete.after_base", |v, _, f, _, b| v.delete_file(f, b)),
        ("rmdir.before_aside", |v, _, _, d, _| v.delete_dir(d)),
        ("rename.before_switch", |v, r, f, _, _| {
            v.rename(f, r, "moved.bin").map(|_| ())
        }),
        ("mkdir.after_content", |v, r, _, _, _| {
            v.make_dir(r, "made").map(|_| ())
        }),
    ];
    for (point, work) in WORK {
        let fx = fx("after-revoke");
        let root = fx.root();
        let file = fx.write(&root, "file.bin", b"old version");
        fx.vault.make_dir(&root, "empty").unwrap();
        let base = fx.digest(&file);
        let before = raw_tree(&fx.path);
        let vault = Rc::new(session(&fx));
        let (root, file, empty) = (
            vault.root_dir().unwrap(),
            fx_node(&vault, "file.bin"),
            fx_node(&vault, "empty"),
        );
        let handle = Rc::clone(&vault);
        seam::at_every_point(move |at| {
            if at == point {
                handle.revoke();
            }
        });
        let got = work(&vault, &root, &file, &empty, &base);
        seam::clear();
        assert_eq!(got.err(), Some(Error::Locked), "{point}");
        assert_eq!(
            raw_tree(&fx.path),
            before,
            "{point}: the folder is as it was"
        );
    }

    // With the last gate of a one-chunk file: nothing published, nothing left to review.
    let fx = fx("after-revoke-last");
    let root = fx.root();
    let file = fx.write(&root, "file.bin", b"old version");
    let base = fx.digest(&file);
    let before = raw_tree(&fx.path);
    let vault = session(&fx);
    let root = vault.root_dir().unwrap();
    let mut control = |p, _| {
        if p == Phase::Encrypt {
            vault.revoke();
        }
        true
    };
    let got = vault.create_file(&root, "new.bin", &mut &b"n"[..], 1, &mut control);
    assert_eq!(got.err(), Some(Error::Locked));
    assert_eq!(raw_tree(&fx.path), before);
    let vault = session(&fx);
    let file = fx_node(&vault, "file.bin");
    let mut control = |p, _| {
        if p == Phase::Encrypt {
            vault.revoke();
        }
        true
    };
    let got = vault.update_file(&file, &base, &mut &b"edit"[..], 4, &mut control);
    assert_eq!(got.err(), Some(Error::Locked));
    assert_eq!(raw_tree(&fx.path), before);
}

fn session(fx: &super::Fx) -> Vault {
    Vault::unlock(&fx.path, &secret(PASSWORD), &fx.stores, &mut |_, _| true).unwrap()
}

fn fx_node(vault: &Vault, name: &str) -> Node {
    let root = vault.root_dir().unwrap();
    vault.lookup(&root, name).unwrap().unwrap().node
}

/// FIL-06.8: lock takes the right at once and waits for what is running: a lock from
/// another thread during a pass returns only when the pass has stopped, and then the keys
/// are gone, so nothing can come late.
#[test]
fn fil04_t13_lock_during_a_pass_waits_and_then_nothing_comes_late() {
    let fx = fx("lock-during");
    let root = fx.root();
    let plain = demo_bytes(CHUNK * 60, 3);
    let node = fx.write(&root, "big.bin", &plain);
    let barrier = Arc::new(Barrier::new(2));
    let mut out = Vec::new();
    let vault = &fx.vault;
    let released = std::thread::scope(|s| {
        let reach = barrier.clone();
        let locker = s.spawn(move || {
            reach.wait();
            vault.lock();
            assert!(vault.keys_are_gone());
        });
        let mut hit = false;
        let got = vault.read_to(&node, &mut out, &mut |p, _| {
            if p == Phase::Write && !hit {
                hit = true;
                barrier.wait();
                // Give the locker time to be waiting on this pass.
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            true
        });
        locker.join().unwrap();
        got
    });
    assert_eq!(released.err(), Some(Error::Locked));
    assert!(out.len() < plain.len(), "stopped");
    assert_eq!(out, plain[..out.len()]);
    assert_eq!(
        vault
            .read_to(&node, &mut Vec::new(), &mut |_, _| true)
            .err(),
        Some(Error::Locked)
    );
}

/// FIL-06.1, FIL-06.8: one content or change operation at a time, and a second is told so
/// and has no effect. Cancel is a stop at a safe point with nothing kept.
#[test]
fn fil06_t08_one_operation_at_a_time_and_cancel_stops_it() {
    let fx = fx("busy");
    let root = fx.root();
    let plain = demo_bytes(CHUNK * 10, 4);
    let node = fx.write(&root, "file.bin", &plain);
    let before = raw_tree(&fx.path);
    let v = &fx.vault;
    let mut seen_busy = 0;
    let mut out = Vec::new();
    let got = v.read_to(&node, &mut out, &mut |p, _| {
        if p == Phase::Validate && seen_busy == 0 {
            seen_busy += 1;
            assert_eq!(
                v.create_file(&root, "x", &mut &b"x"[..], 1, &mut |_, _| true)
                    .err(),
                Some(Error::Busy)
            );
            assert_eq!(v.make_dir(&root, "x").err(), Some(Error::Busy));
            assert_eq!(
                v.read_to(&node, &mut Vec::new(), &mut |_, _| true).err(),
                Some(Error::Busy)
            );
        }
        true
    });
    assert_eq!(got, Ok(plain.len() as u64));
    assert_eq!(out, plain);
    assert_eq!(seen_busy, 1);
    assert_eq!(raw_tree(&fx.path), before);

    // A cancel in each phase says cancelled, with no plaintext after it and no change.
    for phase in [Phase::Capture, Phase::Validate, Phase::Write] {
        let mut out = Vec::new();
        let got = v.read_to(&node, &mut out, &mut |p, _| p != phase);
        assert_eq!(got.err(), Some(Error::Cancelled), "{phase:?}");
        if phase != Phase::Write {
            assert!(out.is_empty());
        }
    }
    assert_eq!(
        fs::read_dir(fx.stores_path.join("scratch"))
            .unwrap()
            .count(),
        0
    );
    // A failed sink stops, and it is an I/O error, not a cancel.
    struct Full;
    impl std::io::Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        v.read_to(&node, &mut Full, &mut |_, _| true).err(),
        Some(Error::Space)
    );
}

/// FIL-06.17, the local part: a cancel reaches a pass from the first chunk, and a reader's
/// progress never waits behind any lock of the pass.
#[test]
fn fil06_t17_progress_and_cancel_come_at_chunk_boundaries() {
    let fx = fx("progress");
    let root = fx.root();
    let plain = demo_bytes(CHUNK * 9 + 1, 5);
    let node = fx.write(&root, "file.bin", &plain);
    let mut seen: Vec<(Phase, u64)> = Vec::new();
    let mut out = Vec::new();
    fx.vault
        .read_to(&node, &mut out, &mut |p, n| {
            seen.push((p, n));
            true
        })
        .unwrap();
    for phase in [Phase::Validate, Phase::Write] {
        let of: Vec<u64> = seen
            .iter()
            .filter(|(p, _)| *p == phase)
            .map(|(_, n)| *n)
            .collect();
        assert_eq!(of.len(), 10, "{phase:?}: one call per chunk");
        assert!(of.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(*of.last().unwrap(), plain.len() as u64);
    }
    // Cancel at the first call: nothing further was asked for.
    let mut calls = 0;
    let got = fx.vault.read_to(&node, &mut Vec::new(), &mut |_, _| {
        calls += 1;
        false
    });
    assert_eq!(got.err(), Some(Error::Cancelled));
    assert_eq!(calls, 1);
}
