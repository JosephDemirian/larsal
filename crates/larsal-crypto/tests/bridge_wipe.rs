//! INT-01.47, Rust rule 3, F-190 (as F-170 for E16-S2): the channel's secret
//! calls (bridge.rs) wipe the stack they used, and no freed heap block holds
//! an opened content, an X25519 result or a channel key after they return. A
//! `Secret` is one `SecretBytes`, so moving it copies no key byte. One test
//! only: the probes count every block the process frees and read this
//! thread's stack.

use larsal_crypto::bridge::{self, NONCE, Secret};
use larsal_crypto::secret::SecretBytes;
use larsal_platform::memory::{Probe, Seen, set_needle, zero_stack_words_after};
use std::alloc::System;
use std::hint::black_box;
use std::sync::atomic::Ordering::Relaxed;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const MARKER: [u8; 8] = *b"E7S1demo";
/// A wiped call leaves close to 2,048 zero words (32 KiB) below it.
const WIPED: usize = 1024;
const N: [u8; NONCE] = [7; NONCE];

fn needle_blocks() -> usize {
    SEEN.with_needle.load(Relaxed)
}

fn needle(bytes: &SecretBytes) -> [u8; 8] {
    bytes.expose()[..8].try_into().unwrap()
}

#[test]
fn int01_47_channel_secret_calls_wipe_stack_and_heap() {
    // A Secret holds only its SecretBytes' pointer, length and capacity.
    assert_eq!(size_of::<Secret>(), size_of::<SecretBytes>());

    let (a, c) = (Secret::generate().unwrap(), Secret::generate().unwrap());
    let (app, client) = (a.public(), c.public());
    let z = a.agree(&client).unwrap();
    let key = bridge::request_key(&z, &client, &app).unwrap();
    let sealed = bridge::seal(&key, &N, b"demo").unwrap();

    // Stack: every secret call runs under secret::scrubbed.
    let control = zero_stack_words_after(|| drop(black_box(vec![1u8; 64])));
    assert!(
        control < WIPED,
        "the probe saw a wipe where there is none: {control}"
    );
    let seen = [
        (
            "Secret::generate",
            zero_stack_words_after(|| drop(black_box(Secret::generate()))),
        ),
        (
            "Secret::public",
            zero_stack_words_after(|| {
                let _ = black_box(a.public());
            }),
        ),
        (
            "Secret::agree",
            zero_stack_words_after(|| drop(black_box(a.agree(&client)))),
        ),
        (
            "request_key",
            zero_stack_words_after(|| drop(black_box(bridge::request_key(&z, &client, &app)))),
        ),
        (
            "reply_key",
            zero_stack_words_after(|| drop(black_box(bridge::reply_key(&z, &client, &app)))),
        ),
        (
            "proof_key",
            zero_stack_words_after(|| {
                drop(black_box(bridge::proof_key(&z, &client, &app, &client)))
            }),
        ),
        (
            "seal",
            zero_stack_words_after(|| drop(black_box(bridge::seal(&key, &N, b"demo")))),
        ),
        (
            "open",
            zero_stack_words_after(|| drop(black_box(bridge::open(&key, &N, &sealed)))),
        ),
    ];
    let unwiped: Vec<_> = seen.iter().filter(|(_, n)| *n < WIPED).collect();
    assert!(
        unwiped.is_empty(),
        "calls that left their stack unwiped: {unwiped:?}"
    );

    // Heap 1: an opened content, through a good and a changed box.
    set_needle(MARKER);
    SEEN.reset();
    {
        let content = SecretBytes::new(MARKER.repeat(100));
        let mut boxed = bridge::seal(&key, &N, content.expose()).unwrap();
        let opened = bridge::open(&key, &N, &boxed).unwrap();
        assert_eq!(opened.expose(), content.expose());
        boxed[0] ^= 1;
        assert!(bridge::open(&key, &N, &boxed).is_err());
    }
    assert!(SEEN.freed.load(Relaxed) > 0);
    assert_eq!(needle_blocks(), 0, "a freed block still held the content");

    // Heap 2: the X25519 result and the request key, made again, used and
    // dropped.
    for (what, bytes) in [("the X25519 result", &z), ("the request key", &key)] {
        set_needle(needle(bytes));
        SEEN.reset();
        {
            let z = a.agree(&client).unwrap();
            let request = bridge::request_key(&z, &client, &app).unwrap();
            let reply = bridge::reply_key(&z, &client, &app).unwrap();
            let boxed = bridge::seal(&request, &N, b"demo").unwrap();
            drop(bridge::open(&request, &N, &boxed).unwrap());
            drop((z, request, reply));
        }
        assert!(SEEN.freed.load(Relaxed) > 0);
        assert_eq!(needle_blocks(), 0, "a freed block still held {what}");
    }
    set_needle([0; 8]);
}
