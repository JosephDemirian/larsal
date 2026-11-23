//! CRY-05.17, AGENTS.md rule 4, E17-S1, the way larsal-crypto's wipe tests
//! work. All memory (tests/pq_wipe.rs's search): after the account's
//! sign-up (and its second run, through the 412 path, with the kept keys),
//! two recovery sign-ins, a restore by kit with the right password and one
//! with a wrong one, and the kit's text and reading, `S_acct`, the identity
//! private key, the receiving seed and the blob plaintext are only in their
//! owners (this Mac's device store item and the kit), and the recovery seed,
//! `A`, `K_wrap`, the account password and the kit's secret line are
//! nowhere in this process's writable memory (heap, freed blocks and
//! stacks); once the owners are dropped, none is anywhere. Freed blocks
//! (tests/sync_wipe.rs's probe): the kit's text and reading free no block
//! that holds `S_acct` or the kit's secret.
//!
//! The freed-block probe is not used on the calls that go through the
//! network: its own 8-byte needle (a local of `Probe::dealloc`) reaches heap
//! blocks there through copies of stack bytes never written, so a needle that
//! no code uses is counted as often as a secret's (a proposed finding on the
//! probe tool; NOTES.txt). The search of all memory looks for whole spans
//! kept XOR a mask, so it never finds its own needle.
//!
//! One test only: the probes count every block this process frees and read
//! all of its memory, larsal-server's (in process) included, so nothing else
//! may run beside it. The stack figures are printed for information:
//! larsal-crypto's calls scrub their own stack; larsal-sync's frames are not
//! scrubbed (a proposed finding).

use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{kdf, wrap};
use larsal_platform::device_key::DeviceKey;
use larsal_platform::memory::{Probe, Seen, copies_in_memory, set_needle, zero_stack_words_after};
use larsal_proto::account::AccountKeys;
use larsal_sync::account::{Keep, Kit};
use larsal_sync::client::Server;
use larsal_sync::test_server::{Memory, Scripted, larsal_server_strict};
use std::alloc::System;
use std::hint::black_box;
use std::sync::atomic::Ordering::Relaxed;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const PASSWORD: &str = "E17demoP-account-pw";
/// Every span this test searches all memory for is kept XOR this mask, so
/// the search never finds its own needle.
const MASK: u8 = 0x5a;
/// An 8-byte needle no code uses: the freed-block probe's control.
const UNUSED: [u8; 8] = *b"E17ctrl!";

fn masked(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| b ^ MASK).collect()
}

fn first8_unmasked(masked: &[u8]) -> [u8; 8] {
    let mut out = [0; 8];
    for (o, m) in out.iter_mut().zip(masked) {
        *o = m ^ MASK;
    }
    out
}

fn needle_blocks() -> usize {
    SEEN.with_needle.load(Relaxed)
}

/// The account's secrets, each masked: worked out on a thread of its own
/// that has ended before any count (as tests/pq_wipe.rs's `masked_k`), from
/// this Mac's device store item, the kit and the blob's salt.
fn learn(keep: &Memory, label: &str, kit: &Kit, salt: &[u8; 32]) -> Vec<(&'static str, Vec<u8>)> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(4 << 20)
            .spawn_scoped(scope, || {
                let item = keep.get(label).unwrap();
                let x = item.expose();
                assert_eq!(x.len(), 128);
                let account = kit.account_id();
                let s_acct = SecretBytes::new(x[..32].to_vec());
                let seed_r =
                    wrap::hkdf_sha256(account.as_bytes(), &s_acct, b"sync-recovery-key-v1")
                        .unwrap();
                let a = kdf::import_argon2id(
                    &SecretBytes::new(PASSWORD.as_bytes().to_vec()),
                    salt,
                    3,
                    64,
                    4,
                    32,
                )
                .unwrap();
                let password = SecretString::new(String::from(PASSWORD));
                let k_wrap =
                    wrap::account_key(&password, salt, &s_acct, account.as_bytes()).unwrap();
                let text = kit.text();
                let line = text
                    .expose()
                    .lines()
                    .find(|l| l.starts_with("Secret: "))
                    .unwrap();
                vec![
                    ("S_acct", masked(&x[..32])),
                    ("the identity private key", masked(&x[32..96])),
                    ("the receiving seed", masked(&x[96..])),
                    ("the blob plaintext", masked(&x[32..])),
                    ("the recovery seed", masked(seed_r.expose())),
                    ("A", masked(a.expose())),
                    ("K_wrap", masked(k_wrap.expose())),
                    ("the account password", masked(PASSWORD.as_bytes())),
                    ("the kit's secret line", masked(line.as_bytes())),
                ]
            })
            .unwrap()
            .join()
            .unwrap()
    })
}

#[test]
#[allow(clippy::too_many_lines)]
fn e17s1_account_calls_leave_no_secret_in_memory() {
    let password = || SecretString::new(String::from(PASSWORD));
    let app = larsal_server_strict();
    let t0 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut minute = 0;
    let mut later = || {
        minute += 1;
        app.seams.set_clock(t0 + 61 * minute);
    };
    let proxy = Scripted::proxy(&app);
    let keep = Memory::default();

    // Sign-up (201), then again with the kept keys (the 412 path, the keys
    // read back and checked); this Mac's client is then dropped.
    let mut c = Server::new(&proxy.address(), proxy.pin).unwrap();
    c.sign_for_port(app.port);
    let made = c.sign_up(DeviceKey::test_seam().unwrap()).unwrap();
    let account = made.account_id;
    let kit = c.sign_up_account(&account, &password(), &keep).unwrap();
    let label = format!("{} account {account}", c.address());
    let again = c.sign_up_account(&account, &password(), &keep).unwrap();
    drop(again);
    drop(c);
    let put = proxy
        .seen
        .lock()
        .unwrap()
        .iter()
        .find(|(q, _)| q.method == "PUT" && q.path == "/v1/account/keys")
        .map(|(q, _)| q.body.clone())
        .unwrap();
    let salt: [u8; 32] = AccountKeys::read(&put).unwrap().blob[2..34]
        .try_into()
        .unwrap();
    let needles = learn(&keep, &label, &kit, &salt);

    let mut counts = Vec::new();
    let mut count = |after: &'static str, owners: &'static str| {
        let found: Vec<usize> = needles
            .iter()
            .map(|(_, span)| copies_in_memory(span, MASK))
            .collect();
        println!("RESIDUE after {after} ({owners}): {found:?}");
        counts.push((after, owners, found));
    };
    count("sign-up, its 412 run and the client dropped", "item, kit");

    // Two recovery sign-ins (SYN-06.12) by a new client, then a restore with
    // the right password and one with a wrong one; that client and its
    // device store are then dropped.
    let mut n = Server::new(&proxy.address(), proxy.pin).unwrap();
    n.sign_for_port(app.port);
    for _ in 0..2 {
        later();
        n.recover(&kit, DeviceKey::test_seam().unwrap()).unwrap();
    }
    count("two recovery sign-ins", "item, kit");
    let n_keep = Memory::default();
    n.restore(&kit, &password(), &n_keep).unwrap();
    let wrong = SecretString::new(String::from("E17demoP-account-pv"));
    assert!(n.restore(&kit, &wrong, &n_keep).is_err());
    drop(wrong);
    let restored = n_keep.get(&format!("{} account {account}", n.address()));
    assert_eq!(
        restored.as_ref().map(SecretBytes::expose),
        keep.get(&label).as_ref().map(SecretBytes::expose),
        "the restore kept this account's secrets"
    );
    drop(restored);
    drop(n);
    drop(n_keep);
    count(
        "a restore, a wrong-password restore and both dropped",
        "item, kit",
    );

    // Freed blocks: the kit's text and its reading. The control: a copy that
    // is not wiped is seen, and a needle no code uses is not.
    let s_acct8 = first8_unmasked(&needles[0].1);
    let secret8 = first8_unmasked(&needles[8].1[8..]);
    set_needle(s_acct8);
    SEEN.reset();
    drop(black_box(
        needles[0].1.iter().map(|b| b ^ MASK).collect::<Vec<u8>>(),
    ));
    assert!(needle_blocks() > 0, "the probe saw no unwiped copy");
    for (what, needle) in [
        ("S_acct", s_acct8),
        ("the kit's secret", secret8),
        ("a needle no code uses", UNUSED),
    ] {
        set_needle(needle);
        SEEN.reset();
        let t = kit.text();
        let back = Kit::read(&t).unwrap();
        drop(back);
        drop(t);
        assert!(SEEN.freed.load(Relaxed) > 0);
        assert_eq!(needle_blocks(), 0, "the kit: a freed block held {what}");
    }
    set_needle([0; 8]);
    let text = kit.text();
    let stack = [
        (
            "Kit::text",
            zero_stack_words_after(|| drop(black_box(kit.text()))),
        ),
        (
            "Kit::read",
            zero_stack_words_after(|| drop(black_box(Kit::read(&text)))),
        ),
    ];
    drop(text);
    println!(
        "E17-S1 stack figures, zero words below each call (for information; larsal-sync's frames are not scrubbed): {stack:?}"
    );
    count("the kit's text and reading", "item, kit");
    drop(kit);
    drop(keep);
    count("the kit and the device store dropped", "none");

    // Every count was printed before any is checked.
    let names: Vec<&str> = needles.iter().map(|(name, _)| *name).collect();
    println!("RESIDUE needles: {names:?}");
    for (after, owners, found) in counts {
        let want: &[usize] = if owners == "none" {
            &[0; 9]
        } else {
            &[2, 1, 1, 1, 0, 0, 0, 0, 0]
        };
        assert_eq!(found, want, "copies after {after} (owners: {owners})");
    }
}
