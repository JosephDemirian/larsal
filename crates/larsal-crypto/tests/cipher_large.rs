//! Spec CRY-01 T20, CRY-01.12 (story E2-S4): 1 GiB of demo bytes through
//! streaming encryption and decryption, one test per cipher. Nothing larger
//! than one chunk is ever held, so memory stays flat; peak memory is measured
//! from outside with `/usr/bin/time -l` on the release test binary.
//!
//! Run all: cargo test -p larsal-crypto --release --test cipher_large -- --ignored
//! The Twofish test takes about 12 minutes: the approved twofish crate runs
//! at about 3 MB/s on this Mac (measured 712 s for 1 GiB each way).

use larsal_crypto::cipher::{BLOCK_LEN, Cipher, Decryptor, Encryptor};
use larsal_crypto::secret::SecretBytes;
use sha2::{Digest, Sha256};

const TOTAL: usize = 1 << 30;
/// Not a multiple of 16, so chunks keep splitting blocks.
const CHUNK: usize = (1 << 20) + 7;

fn one_gib_round_trip(c: Cipher) {
    let key = SecretBytes::new(vec![0x42; 32]);
    let iv = vec![0x24; c.iv_len()];
    let mut enc = Encryptor::new(c, &key, &iv).unwrap();
    let mut dec = Decryptor::new(c, &key, &iv).unwrap();
    let (mut fed, mut got) = (Sha256::new(), Sha256::new());
    let mut chunk = vec![0u8; CHUNK];
    let (mut left, mut ct_len, mut round) = (TOTAL, 0usize, 0u8);
    while left > 0 {
        let n = left.min(CHUNK);
        chunk.fill(round);
        chunk[0] = !round;
        round = round.wrapping_add(1);
        fed.update(&chunk[..n]);
        let ct = enc.update(&chunk[..n]).unwrap();
        ct_len += ct.len();
        got.update(dec.update(&ct).unwrap().expose());
        left -= n;
    }
    let ct = enc.finish();
    ct_len += ct.len();
    got.update(dec.update(&ct).unwrap().expose());
    got.update(dec.finish().unwrap().expose());
    let want_len = if c == Cipher::ChaCha20 {
        TOTAL
    } else {
        TOTAL + BLOCK_LEN
    };
    assert_eq!(ct_len, want_len, "{c:?} ciphertext length");
    assert_eq!(fed.finalize(), got.finalize(), "{c:?} round trip");
}

#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn one_gib_streams_through_aes256_cbc_with_flat_memory() {
    one_gib_round_trip(Cipher::Aes256Cbc);
}

#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn one_gib_streams_through_twofish256_cbc_with_flat_memory() {
    one_gib_round_trip(Cipher::Twofish256Cbc);
}

#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn one_gib_streams_through_chacha20_with_flat_memory() {
    one_gib_round_trip(Cipher::ChaCha20);
}
