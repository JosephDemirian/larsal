//! CRY-05.17, CRY-05 T27, F-070 style (as tests/pq_wipe.rs): after E25-S3's
//! secret calls return (an account's keys drawn, its binding made, a wrap
//! record made and opened, the blob's plaintext written and the keys
//! restored from it), no copy of the ML-DSA-65 expanded key's K is left
//! anywhere in this process's writable memory (stacks included), `S_acct`
//! and each seed are only in the one `SecretBytes` that holds them, and no
//! freed heap block holds a wrapped key, `S_acct` or the blob's plaintext.
//!
//! One test only: the probes count every block the process frees and read
//! all of its memory, so nothing else may run beside it.

use larsal_crypto::account::AccountKeys;
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::wrap_record;
use larsal_platform::memory::{Probe, Seen, copies_in_memory, set_needle};
use ml_dsa::{ExpandedSigningKey, MlDsa65};
use std::alloc::System;
use std::hint::black_box;
use std::sync::atomic::Ordering::Relaxed;
use zeroize::Zeroize;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const MARKER: [u8; 8] = *b"E25s3keY";
/// Every span this test searches for is kept XOR this mask, so the search
/// never finds its own needle.
const MASK: u8 = 0x5a;

fn needle_blocks() -> usize {
    SEEN.with_needle.load(Relaxed)
}

fn masked(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| b ^ MASK).collect()
}

/// K of the ML-DSA-65 key expanded from `masked_seed` unmasked, itself
/// masked; worked out on a thread of its own that has ended before any count
/// (as tests/pq_wipe.rs does).
fn masked_k(masked_seed: &[u8]) -> Vec<u8> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(4 << 20)
            .spawn_scoped(scope, || {
                let mut seed = [0u8; 32];
                for (b, m) in seed.iter_mut().zip(masked_seed) {
                    *b = m ^ MASK;
                }
                let key = ExpandedSigningKey::<MlDsa65>::from_seed((&seed).into());
                seed.zeroize();
                #[allow(deprecated)]
                let expanded = key.to_expanded();
                masked(&expanded[32..64])
            })
            .unwrap()
            .join()
            .unwrap()
    })
}

fn copy_of(secret: &SecretBytes) -> SecretBytes {
    SecretBytes::new(secret.expose().to_vec())
}

#[test]
fn cry05_17_t27_e25s3_secret_calls_leave_no_copy() {
    let account = AccountKeys::new().unwrap();
    let identity = account.identity_private_key();
    let k = masked_k(&masked(&identity.expose()[..32]));
    let needles = [
        masked(account.account_secret().expose()),
        masked(&identity.expose()[..32]),
        masked(&identity.expose()[32..]),
        masked(account.kem_seed().expose()),
    ];

    // All memory: no K anywhere, and S_acct, the ML-DSA-65 seed, the Ed25519
    // seed and the receiving seed each only in the account's own
    // SecretBytes. Every count is printed before any is checked.
    let mut counts = Vec::new();
    let mut count = |after: &'static str| {
        let k_copies = copies_in_memory(&k, MASK);
        let copies: Vec<usize> = needles
            .iter()
            .map(|needle| copies_in_memory(needle, MASK))
            .collect();
        println!("RESIDUE after {after}: K {k_copies}, S_acct and seeds {copies:?}");
        counts.push((after, k_copies, copies));
    };
    count("AccountKeys::new");
    drop(black_box(account.kem_signature(&[7; 16])));
    count("kem_signature");
    let record =
        wrap_record::make(account.kem_public_key(), b"i", b"demo", [3; 16], identity).unwrap();
    drop(black_box(wrap_record::open(
        &record,
        account.identity_public_key(),
        b"i",
        account.kem_seed(),
    )));
    count("wrap_record::make and open");
    {
        let blob = account.blob_plaintext();
        let restored = AccountKeys::from_blob(copy_of(account.account_secret()), &blob).unwrap();
        drop(black_box(restored.kem_signature(&[7; 16])));
        drop(restored);
        drop(blob);
    }
    count("blob_plaintext and from_blob, dropped");
    for (after, k_copies, copies) in counts {
        assert_eq!(k_copies, 0, "copies of K after {after}");
        assert_eq!(
            copies,
            [1, 1, 1, 1],
            "copies of S_acct and each seed after {after}"
        );
    }

    // Heap 1: a wrapped key through make and open, a good and a bad record.
    set_needle(MARKER);
    SEEN.reset();
    {
        let key = SecretBytes::new(MARKER.repeat(4));
        let mut record = wrap_record::make(
            account.kem_public_key(),
            b"i",
            key.expose(),
            [3; 16],
            identity,
        )
        .unwrap();
        let opened = wrap_record::open(
            &record,
            account.identity_public_key(),
            b"i",
            account.kem_seed(),
        )
        .unwrap();
        assert_eq!(opened.expose(), key.expose());
        record.ct[0] ^= 1;
        assert!(
            wrap_record::open(
                &record,
                account.identity_public_key(),
                b"i",
                account.kem_seed()
            )
            .is_err()
        );
    }
    assert!(SEEN.freed.load(Relaxed) > 0);
    assert_eq!(
        needle_blocks(),
        0,
        "a freed block still held the wrapped key"
    );

    // Heap 2: S_acct, and 8 bytes from inside each key of the blob's
    // plaintext (the ML-DSA-65 seed, the Ed25519 seed, the receiving seed)
    // and from where its two keys meet, through a restore, used and dropped.
    let blob = account.blob_plaintext();
    let part = |at: usize| -> [u8; 8] { blob.expose()[at..at + 8].try_into().unwrap() };
    let parts = [
        ("the blob's ML-DSA-65 seed", part(16)),
        ("the blob's Ed25519 seed", part(40)),
        ("the blob's plaintext where its keys meet", part(60)),
        ("the blob's receiving seed", part(72)),
    ];
    drop(blob);
    let s_acct: [u8; 8] = account.account_secret().expose()[..8].try_into().unwrap();
    for (what, needle) in [("S_acct", s_acct)].into_iter().chain(parts) {
        set_needle(needle);
        SEEN.reset();
        {
            let blob = account.blob_plaintext();
            let restored =
                AccountKeys::from_blob(copy_of(account.account_secret()), &blob).unwrap();
            drop(black_box(restored.kem_signature(&[7; 16])));
        }
        assert_eq!(needle_blocks(), 0, "a freed block still held {what}");
    }
    set_needle([0; 8]);
}
