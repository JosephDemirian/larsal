//! FIL-01.18, Rust rule 3, as F-170 and F-190: the new primitives of the file
//! format wipe the stack they used, and no freed heap block holds a password,
//! a key, a plaintext or an identity's text after they return. One test only:
//! the probes count every block the process frees and read this thread's
//! stack.

use larsal_crypto::secret::SecretBytes;
use larsal_crypto::{aead, bech32, bridge::Secret, kdf};
use larsal_platform::memory::{Probe, Seen, set_needle, zero_stack_words_after};
use std::alloc::System;
use std::hint::black_box;
use std::sync::atomic::Ordering::Relaxed;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const MARKER: [u8; 8] = *b"E22demoP";
/// A wiped call leaves close to 2,048 zero words (32 KiB) below it.
const WIPED: usize = 1024;

fn needle_blocks() -> usize {
    SEEN.with_needle.load(Relaxed)
}

fn needle(bytes: &SecretBytes) -> [u8; 8] {
    bytes.expose()[..8].try_into().unwrap()
}

#[test]
fn fil01_t18_file_primitives_wipe_stack_and_heap() {
    let key = SecretBytes::new(vec![0x42; aead::KEY]);
    let nonce = [9; aead::NONCE];
    let mut sealed = *b"demo plaintext..";
    let tag = aead::seal_in_place(&key, &nonce, b"", &mut sealed).unwrap();
    let id = SecretBytes::new(vec![0x31; 32]);
    let text = bech32::encode_upper_secret("demo-", &id).unwrap();

    // Stack: every secret call runs under secret::scrubbed.
    let control = zero_stack_words_after(|| drop(black_box(vec![1u8; 64])));
    assert!(
        control < WIPED,
        "the probe saw a wipe where there is none: {control}"
    );
    let seen = [
        (
            "seal_in_place",
            zero_stack_words_after(|| {
                let mut d = *b"demo";
                let _ = black_box(aead::seal_in_place(&key, &nonce, b"", &mut d));
            }),
        ),
        (
            "open_in_place",
            zero_stack_words_after(|| {
                let mut d = sealed;
                let _ = black_box(aead::open_in_place(&key, &nonce, b"", &mut d, &tag));
            }),
        ),
        (
            "scrypt",
            zero_stack_words_after(|| {
                drop(black_box(kdf::scrypt(b"demo", b"salt", 4, 8, 1, 32)));
            }),
        ),
        (
            "bech32 decode",
            zero_stack_words_after(|| {
                drop(black_box(bech32::decode("demo-", text.expose(), 32)));
            }),
        ),
        (
            "bech32 encode_upper_secret",
            zero_stack_words_after(|| {
                drop(black_box(bech32::encode_upper_secret("demo-", &id)));
            }),
        ),
    ];
    let unwiped: Vec<_> = seen.iter().filter(|(_, n)| *n < WIPED).collect();
    assert!(
        unwiped.is_empty(),
        "calls that left their stack unwiped: {unwiped:?}"
    );

    // Heap 1: a plaintext in a wiping buffer, sealed and opened in place.
    set_needle(MARKER);
    SEEN.reset();
    {
        let mut pt = SecretBytes::new(MARKER.repeat(100));
        let tag = aead::seal_in_place(&key, &nonce, b"", pt.expose_mut()).unwrap();
        aead::open_in_place(&key, &nonce, b"", pt.expose_mut(), &tag).unwrap();
        assert_eq!(&pt.expose()[..8], MARKER);
    }
    assert!(SEEN.freed.load(Relaxed) > 0);
    assert_eq!(needle_blocks(), 0, "a freed block still held the plaintext");

    // Heap 2: the password and the derived key of scrypt.
    let derived = kdf::scrypt(&MARKER.repeat(4), b"salt", 4, 8, 1, 32).unwrap();
    for (what, needle) in [("the password", MARKER), ("the key", needle(&derived))] {
        set_needle(needle);
        SEEN.reset();
        {
            let pw = SecretBytes::new(MARKER.repeat(4));
            drop(kdf::scrypt(pw.expose(), b"salt", 4, 8, 1, 32).unwrap());
        }
        assert!(SEEN.freed.load(Relaxed) > 0);
        assert_eq!(needle_blocks(), 0, "a freed block still held {what}");
    }

    // Heap 3: the identity's bytes and its text.
    let text_needle: [u8; 8] = text.expose().as_bytes()[8..16].try_into().unwrap();
    for (what, needle) in [("the bytes", needle(&id)), ("the text", text_needle)] {
        set_needle(needle);
        SEEN.reset();
        {
            let t = bech32::encode_upper_secret("demo-", &id).unwrap();
            drop(bech32::decode("demo-", t.expose(), 32).unwrap());
        }
        assert!(SEEN.freed.load(Relaxed) > 0);
        assert_eq!(needle_blocks(), 0, "a freed block still held {what}");
    }

    // Heap 4: an X25519 key taken over by from_bytes, used and dropped.
    let secret = SecretBytes::new(vec![0x37; 32]);
    set_needle(needle(&secret));
    SEEN.reset();
    {
        let s = Secret::from_bytes(secret).unwrap();
        let _ = s.public();
        drop(s.agree(&[9; 32]).unwrap());
    }
    assert!(SEEN.freed.load(Relaxed) > 0);
    assert_eq!(
        needle_blocks(),
        0,
        "a freed block still held the X25519 key"
    );
    set_needle([0; 8]);
}
