//! Rule 4 for the keys New SSH Key makes (E24-S2, lead rulings (9) and (10)
//! of round 3; INT-06.E24.02: the key draft stays wipeable in Rust). A made
//! private key never moves by value outside the thread that makes it: once
//! `new_key` gave a key of each kind back and it was dropped, no copy of its
//! Ed25519 seed or ECDSA scalar d is left in this process's writable memory,
//! the calling thread's stack among it (Checker 2's C2R2-F1 found 3 such
//! copies after the drop in a debug build and 3 to 4 in release).
//!
//! The global allocator is the one the Mac app installs (larsal-ffi
//! `lib.rs`, LD-133), so freed blocks are wiped and a count shows what is
//! still alive or left on a stack. A count reads all writable memory and
//! needs the process to itself: each test starts this program again for its
//! one child test (`--exact`, one test thread). Markers: the seed, or d in
//! big-endian order (as ssh-key keeps it) and little-endian order, each byte
//! XOR a mask so that the search holds no copy itself.

use larsal_crypto::ssh::{NewKeyKind, new_key};
use larsal_platform::memory::{Zeroing, copies_in_memory};
use ssh_key::PrivateKey;
use std::alloc::System;
use std::process::Command;

#[global_allocator]
static ALLOC: Zeroing<System> = Zeroing(System);

const MASK: u8 = 0x5a;
/// Set only in the process a test starts for its child.
const CHILD: &str = "LARSAL_E24_STACK_CHILD";

/// The masked private values of a key text, named. Worked out on a thread
/// of their own that has ended (its stack is gone) before any count.
fn markers(text: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    std::thread::scope(|s| {
        s.spawn(|| {
            let key = PrivateKey::from_openssh(text).expect("the key text");
            let masked = |b: &[u8]| -> Vec<u8> { b.iter().map(|x| x ^ MASK).collect() };
            if let Some(pair) = key.key_data().ed25519() {
                return vec![("seed", masked(pair.private.as_ref()))];
            }
            let pair = key.key_data().ecdsa().expect("an ECDSA key");
            let be = masked(pair.private_key_bytes());
            let mut le = be.clone();
            le.reverse();
            vec![("d big-endian", be), ("d little-endian", le)]
        })
        .join()
        .expect("the markers")
    })
}

fn count(markers: &[(&str, Vec<u8>)]) -> Vec<usize> {
    markers
        .iter()
        .map(|(_, m)| copies_in_memory(m, MASK))
        .collect()
}

/// The child: a key of `kind` made by `new_key` on this thread, held, then
/// dropped; each marker's copies while it lives and after the drop. Prints
/// one row; fails when a copy is left.
fn made_and_dropped(kind: NewKeyKind) {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let key = new_key(kind, "demo@larsal").expect("a key");
    let markers = markers(key.private().expose());
    let live = count(&markers);
    drop(key);
    let left = count(&markers);
    let row: Vec<String> = markers
        .iter()
        .zip(live.iter().zip(&left))
        .map(|((name, _), (l, d))| format!("{name}: live {l}, after drop {d}"))
        .collect();
    println!("ROW {} new_key: {}", kind.label(), row.join("; "));
    assert!(live[0] > 0, "the markers find the live key");
    assert!(
        left.iter().all(|&n| n == 0),
        "{}: copies left after the drop: {row:?}",
        kind.label()
    );
}

/// Runs `child` alone in a new process of this program.
fn alone(child: &str) {
    let out = Command::new(std::env::current_exe().expect("this program"))
        .args([
            "--exact",
            child,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .output()
        .expect("the child starts");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("{text}");
    assert!(
        out.status.success() && text.contains("1 passed") && text.contains("ROW "),
        "{child}:\n{text}"
    );
}

#[test]
#[ignore = "a child of e24_s02_rule4_int06_e24_02_ed25519_seed_leaves_no_copy_after_drop"]
fn child_ed25519() {
    made_and_dropped(NewKeyKind::Ed25519);
}

#[test]
#[ignore = "a child of e24_s02_rule4_int06_e24_02_p256_scalar_leaves_no_copy_after_drop"]
fn child_p256() {
    made_and_dropped(NewKeyKind::EcdsaP256);
}

#[test]
#[ignore = "a child of e24_s02_rule4_int06_e24_02_p384_scalar_leaves_no_copy_after_drop"]
fn child_p384() {
    made_and_dropped(NewKeyKind::EcdsaP384);
}

#[test]
#[ignore = "a child of e24_s02_rule4_int06_e24_02_p521_scalar_leaves_no_copy_after_drop"]
fn child_p521() {
    made_and_dropped(NewKeyKind::EcdsaP521);
}

/// E24-S02, rule 4, INT-06.E24.02: an Ed25519 key from `new_key`, dropped,
/// leaves no copy of its seed on the calling thread's stack or anywhere.
#[test]
fn e24_s02_rule4_int06_e24_02_ed25519_seed_leaves_no_copy_after_drop() {
    alone("child_ed25519");
}

/// E24-S02, rule 4, INT-06.E24.02: the same for an ECDSA P-256 key's d.
#[test]
fn e24_s02_rule4_int06_e24_02_p256_scalar_leaves_no_copy_after_drop() {
    alone("child_p256");
}

/// E24-S02, rule 4, INT-06.E24.02: the same for an ECDSA P-384 key's d.
#[test]
fn e24_s02_rule4_int06_e24_02_p384_scalar_leaves_no_copy_after_drop() {
    alone("child_p384");
}

/// E24-S02, rule 4, INT-06.E24.02: the same for an ECDSA P-521 key's d.
#[test]
fn e24_s02_rule4_int06_e24_02_p521_scalar_leaves_no_copy_after_drop() {
    alone("child_p521");
}
