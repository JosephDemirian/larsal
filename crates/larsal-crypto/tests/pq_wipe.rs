//! CRY-05.17, F-070 style (as tests/sync_wipe.rs): after the E25-S2 secret
//! calls return, no copy of the ML-DSA-65 expanded key's K is left anywhere
//! in this process's writable memory (stacks included), each seed is only in
//! its own `SecretBytes`, and no freed heap block holds a plaintext, the
//! X-Wing seed or either half of a composite private key.
//!
//! Each secret call runs its vendored work on a worker thread of its own,
//! zeroed and ended before the call returns (secret.rs, `scrubbed_thread`).
//! With the work on the caller's thread under round 1's 256 KiB wipe, this
//! test counts K 1, 1, 2 and 2 times at its four counts in a debug build
//! and 2 times at each in release (mutant N01). ml-dsa is built without
//! `alloc`, so its expanded keys never reach the heap. One test only: the
//! probes count every block the process frees and read all of its memory,
//! so nothing else may run beside it.

use larsal_crypto::pq;
use larsal_crypto::secret::SecretBytes;
use larsal_platform::memory::{Probe, Seen, copies_in_memory, set_needle};
use ml_dsa::{ExpandedSigningKey, MlDsa65};
use std::alloc::System;
use std::hint::black_box;
use std::sync::atomic::Ordering::Relaxed;
use zeroize::Zeroize;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const MARKER: [u8; 8] = *b"E25demoP";
/// Every span this test searches for is kept XOR this mask, so the search
/// never finds its own needle.
const MASK: u8 = 0x5a;

fn needle_blocks() -> usize {
    SEEN.with_needle.load(Relaxed)
}

fn masked(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| b ^ MASK).collect()
}

/// K (FIPS 204 skEncode: ρ ‖ K ‖ tr ‖ ...) of the ML-DSA-65 key expanded
/// from `masked_seed` unmasked, itself masked. Worked out on a thread of its
/// own that has ended before any count, so this test leaves no copy of the
/// seed or of K behind.
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

#[test]
fn e25s2_secret_calls_wipe_stack_and_heap() {
    let (seed, pk) = pq::xwing_keypair().unwrap();
    let (sk, ipk) = pq::identity_keypair().unwrap();
    let k = masked_k(&masked(&sk.expose()[..32]));
    let seeds = [
        masked(seed.expose()),
        masked(&sk.expose()[..32]),
        masked(&sk.expose()[32..]),
    ];

    // All memory: no K anywhere, and each seed (the X-Wing seed, the
    // ML-DSA-65 seed, the Ed25519 seed) only in its own SecretBytes. Every
    // count is printed before any is checked, so a failure shows them all.
    let mut counts = Vec::new();
    let mut count = |after: &'static str| {
        let k_copies = copies_in_memory(&k, MASK);
        let seed_copies: Vec<usize> = seeds
            .iter()
            .map(|needle| copies_in_memory(needle, MASK))
            .collect();
        println!("RESIDUE after {after}: K {k_copies}, seeds {seed_copies:?}");
        counts.push((after, k_copies, seed_copies));
    };
    count("the key pairs");
    drop(black_box(pq::identity_public(&sk)));
    count("identity_public");
    let sig = pq::composite_sign(&sk, b"m").unwrap();
    count("composite_sign");
    let (enc, ct) = pq::seal(&pk, b"i", b"demo").unwrap();
    drop(black_box(pq::xwing_public(&seed)));
    drop(black_box(pq::open(&seed, &enc, b"i", &ct)));
    count("xwing_public, seal and open");
    for (after, k_copies, seed_copies) in counts {
        assert_eq!(k_copies, 0, "copies of K after {after}");
        assert_eq!(seed_copies, [1, 1, 1], "copies of each seed after {after}");
    }
    assert_eq!(pq::composite_verify(&ipk, b"m", &sig), Ok(()));

    // Heap 1: a plaintext through seal and open, a good and a bad one.
    set_needle(MARKER);
    SEEN.reset();
    {
        let pt = SecretBytes::new(MARKER.repeat(100));
        let (enc, mut ct) = pq::seal(&pk, b"i", pt.expose()).unwrap();
        let a = pq::open(&seed, &enc, b"i", &ct).unwrap();
        ct[0] ^= 1;
        assert!(pq::open(&seed, &enc, b"i", &ct).is_err());
        assert_eq!(a.expose(), pt.expose());
    }
    assert!(SEEN.freed.load(Relaxed) > 0);
    assert_eq!(needle_blocks(), 0, "a freed block still held the plaintext");

    // Heap 2: the X-Wing seed, used and dropped.
    set_needle(seed.expose()[..8].try_into().unwrap());
    SEEN.reset();
    let (enc, ct) = pq::seal(&pk, b"i", b"demo").unwrap();
    drop(pq::open(&seed, &enc, b"i", &ct).unwrap());
    drop(pq::xwing_public(&seed).unwrap());
    drop(seed);
    assert_eq!(needle_blocks(), 0, "a freed block still held the seed");

    // Heap 3: each half of the composite private key, used and dropped.
    let halves: [[u8; 8]; 2] = [
        sk.expose()[..8].try_into().unwrap(),
        sk.expose()[32..40].try_into().unwrap(),
    ];
    for (what, needle) in [
        ("the ML-DSA seed", halves[0]),
        ("the Ed25519 seed", halves[1]),
    ] {
        set_needle(needle);
        SEEN.reset();
        drop(pq::composite_sign(&sk, b"m").unwrap());
        drop(pq::identity_public(&sk).unwrap());
        assert_eq!(needle_blocks(), 0, "a freed block still held {what}");
    }
    set_needle(halves[0]);
    SEEN.reset();
    drop(sk);
    assert_eq!(
        needle_blocks(),
        0,
        "a freed block still held the private key"
    );
    set_needle([0; 8]);
}
