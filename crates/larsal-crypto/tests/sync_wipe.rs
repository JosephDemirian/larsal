//! CRY-04.10, LD-261 (4), F-070 style: the E16-S2 secret calls wipe the
//! stack they used, and no freed heap block holds a plaintext, the X25519
//! private key, A or K_wrap after they return. One test only: the probes
//! count every block the process frees and read this thread's stack.

use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{hpke, kdf, sign, wrap};
use larsal_platform::memory::{Probe, Seen, set_needle, zero_stack_words_after};
use std::alloc::System;
use std::hint::black_box;
use std::sync::atomic::Ordering::Relaxed;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const MARKER: [u8; 8] = *b"E16demoP";
/// A wiped call leaves close to 2,048 zero words (32 KiB) below it.
const WIPED: usize = 1024;

fn needle_blocks() -> usize {
    SEEN.with_needle.load(Relaxed)
}

#[test]
fn e16s2_secret_calls_wipe_stack_and_heap() {
    let (sk, pk) = hpke::x25519_keypair().unwrap();
    let seed = SecretBytes::new(vec![0x11; 32]);
    let spk = sign::ed25519_public(&seed).unwrap();
    let key = SecretBytes::new(vec![0x42; 32]);
    let password = || SecretString::new(String::from("E16demoP-demo-password"));

    // Stack: every secret call runs under secret::scrubbed.
    let control = zero_stack_words_after(|| drop(black_box(sign::field_list(&[b"demo"]))));
    assert!(
        control < WIPED,
        "the probe saw a wipe where there is none: {control}"
    );
    let (enc, ct) = hpke::seal(&pk, b"i", b"demo").unwrap();
    let rec = hpke::make_wrap(&pk, b"i", b"demo", [3; 16], &seed).unwrap();
    let w = wrap::seal(&key, b"ad", b"demo").unwrap();
    let seen = [
        (
            "x25519_keypair",
            zero_stack_words_after(|| drop(black_box(hpke::x25519_keypair()))),
        ),
        (
            "hpke::seal",
            zero_stack_words_after(|| drop(black_box(hpke::seal(&pk, b"i", b"demo")))),
        ),
        (
            "hpke::open",
            zero_stack_words_after(|| drop(black_box(hpke::open(&sk, &enc, b"i", &ct)))),
        ),
        (
            "make_wrap",
            zero_stack_words_after(|| {
                drop(black_box(hpke::make_wrap(
                    &pk, b"i", b"demo", [3; 16], &seed,
                )))
            }),
        ),
        (
            "open_wrap",
            zero_stack_words_after(|| drop(black_box(hpke::open_wrap(&rec, &spk, b"i", &sk)))),
        ),
        (
            "ed25519_public",
            zero_stack_words_after(|| {
                let _ = black_box(sign::ed25519_public(&seed));
            }),
        ),
        (
            "ed25519_sign",
            zero_stack_words_after(|| {
                let _ = black_box(sign::ed25519_sign(&seed, b"m"));
            }),
        ),
        (
            "wrap::seal",
            zero_stack_words_after(|| drop(black_box(wrap::seal(&key, b"ad", b"demo")))),
        ),
        (
            "wrap::open",
            zero_stack_words_after(|| drop(black_box(wrap::open(&key, b"ad", &w)))),
        ),
        (
            "hkdf_sha256",
            zero_stack_words_after(|| drop(black_box(wrap::hkdf_sha256(b"s", &key, b"i")))),
        ),
        (
            "account_key",
            zero_stack_words_after(|| {
                drop(black_box(wrap::account_key(
                    &password(),
                    &[1; 32],
                    &key,
                    &[3; 16],
                )))
            }),
        ),
    ];
    let unwiped: Vec<_> = seen.iter().filter(|(_, n)| *n < WIPED).collect();
    assert!(
        unwiped.is_empty(),
        "calls that left their stack unwiped: {unwiped:?}"
    );

    // Heap 1: a plaintext through every seal and open, a good and a bad one.
    set_needle(MARKER);
    SEEN.reset();
    {
        let pt = SecretBytes::new(MARKER.repeat(100));
        let (enc, mut ct) = hpke::seal(&pk, b"i", pt.expose()).unwrap();
        let a = hpke::open(&sk, &enc, b"i", &ct).unwrap();
        ct[0] ^= 1;
        assert!(hpke::open(&sk, &enc, b"i", &ct).is_err());
        let rec = hpke::make_wrap(&pk, b"i", pt.expose(), [3; 16], &seed).unwrap();
        let b = hpke::open_wrap(&rec, &spk, b"i", &sk).unwrap();
        let mut w = wrap::seal(&key, b"ad", pt.expose()).unwrap();
        let c = wrap::open(&key, b"ad", &w).unwrap();
        w[20] ^= 1;
        assert!(wrap::open(&key, b"ad", &w).is_err());
        assert_eq!(
            (a.expose(), b.expose(), c.expose()),
            (pt.expose(), pt.expose(), pt.expose())
        );
    }
    assert!(SEEN.freed.load(Relaxed) > 0);
    assert_eq!(needle_blocks(), 0, "a freed block still held the plaintext");

    // Heap 2: the X25519 private key, used and dropped.
    set_needle(sk.expose()[..8].try_into().unwrap());
    SEEN.reset();
    let (enc, ct) = hpke::seal(&pk, b"i", b"demo").unwrap();
    drop(hpke::open(&sk, &enc, b"i", &ct).unwrap());
    drop(sk);
    assert_eq!(
        needle_blocks(),
        0,
        "a freed block still held the private key"
    );

    // Heap 3: the password, A and K_wrap (learned in a first run, then
    // looked for in a second).
    let a = kdf::import_argon2id(
        &SecretBytes::new(b"E16demoP-demo-password".to_vec()),
        &[1; 32],
        3,
        64,
        4,
        32,
    )
    .unwrap();
    let k = wrap::account_key(&password(), &[1; 32], &key, &[3; 16]).unwrap();
    for (what, needle) in [
        ("the password", MARKER),
        ("A", a.expose()[..8].try_into().unwrap()),
        ("K_wrap", k.expose()[..8].try_into().unwrap()),
    ] {
        set_needle(needle);
        SEEN.reset();
        drop(wrap::account_key(&password(), &[1; 32], &key, &[3; 16]).unwrap());
        assert_eq!(needle_blocks(), 0, "a freed block still held {what}");
    }
    set_needle([0; 8]);
}
