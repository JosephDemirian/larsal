//! LD-261 (4): app-crypto's base64 secret calls and every cipher call wipe
//! the stack they used. `secret::scrubbed` zeroes 32 KiB of stack below each
//! of them when it returns (Verify V-02, AT-C01, Checker 2 of E0-S7 step 3d).
//! app-crypto forbids unsafe code, so the probe that paints and reads the
//! stack is app-platform's test tool (feature `test-memory`), as the heap
//! probes of memory_hygiene.rs are. The test fails when one of these calls
//! stops running under `scrubbed`. One test only, so no other test thread
//! shares the measurement.

use app_crypto::base64::{self, Form};
use app_crypto::cipher::{self, Cipher, Decryptor, Encryptor};
use app_crypto::secret::SecretBytes;
use app_platform::memory::zero_stack_words_after;
use std::hint::black_box;

/// A wiped call leaves close to 2,048 zero words (32 KiB) below it; one
/// that is not wiped leaves the paint.
const WIPED: usize = 1024;

const TEXT: &[u8] = b"demo-secret-bytes for the stack wipe check, 64 bytes long......";

#[test]
fn ld261_secret_calls_wipe_the_stack_they_used() {
    // Control: base64::encode does the same work as encode_secret without
    // the wipe, so the probe can tell a wiped call from one that is not.
    let control = zero_stack_words_after(|| drop(black_box(base64::encode(Form::Padded, TEXT))));
    println!("control base64::encode: {control} zero words");
    assert!(
        control < WIPED,
        "the probe saw a wipe where there is none: {control} words"
    );

    let encoded = base64::encode(Form::Padded, TEXT);
    let mut seen = vec![
        (
            "base64::encode_secret".to_owned(),
            zero_stack_words_after(|| drop(black_box(base64::encode_secret(Form::Padded, TEXT)))),
        ),
        (
            "base64::decode_secret".to_owned(),
            zero_stack_words_after(|| {
                drop(black_box(base64::decode_secret(Form::Padded, &encoded)))
            }),
        ),
    ];

    let key = SecretBytes::new(vec![0x42; cipher::KEY_LEN]);
    for c in [Cipher::Aes256Cbc, Cipher::Twofish256Cbc, Cipher::ChaCha20] {
        let iv = vec![0x24; c.iv_len()];
        let sealed = cipher::encrypt(c, &key, &iv, TEXT).unwrap();
        let mut probe = |call: &str, f: &mut dyn FnMut()| {
            seen.push((format!("{c:?} {call}"), zero_stack_words_after(f)));
        };
        probe("encrypt", &mut || {
            drop(black_box(cipher::encrypt(c, &key, &iv, TEXT)))
        });
        probe("decrypt", &mut || {
            drop(black_box(cipher::decrypt(c, &key, &iv, &sealed)))
        });

        let mut enc = None;
        probe("Encryptor::new", &mut || {
            enc = Some(Encryptor::new(c, &key, &iv).unwrap())
        });
        let mut enc = enc.unwrap();
        probe("Encryptor::update", &mut || {
            drop(black_box(enc.update(TEXT)))
        });
        let mut enc = Some(enc);
        probe("Encryptor::finish", &mut || {
            drop(black_box(enc.take().unwrap().finish()))
        });

        let mut dec = None;
        probe("Decryptor::new", &mut || {
            dec = Some(Decryptor::new(c, &key, &iv).unwrap())
        });
        let mut dec = dec.unwrap();
        probe("Decryptor::update", &mut || {
            drop(black_box(dec.update(&sealed)))
        });
        let mut dec = Some(dec);
        probe("Decryptor::finish", &mut || {
            drop(black_box(dec.take().unwrap().finish()))
        });

        let mut dec = Some(Decryptor::new(c, &key, &iv).unwrap());
        drop(dec.as_mut().unwrap().update(&sealed));
        probe("Decryptor::finish_unpadded", &mut || {
            drop(black_box(dec.take().unwrap().finish_unpadded()));
        });
    }

    for (call, words) in &seen {
        println!("{call}: {words} zero words");
    }
    let unwiped: Vec<_> = seen.iter().filter(|(_, words)| *words < WIPED).collect();
    assert!(
        unwiped.is_empty(),
        "calls that left their stack unwiped: {unwiped:?}"
    );
}
