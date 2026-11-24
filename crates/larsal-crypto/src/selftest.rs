//! The crypto self-test at start (APP-11.10, D-APP11-3): known answers from
//! public standards, run through this crate's own functions before any vault
//! is read (window app: APP-09.1 step 9).
//!
//! Guarantees:
//! - the checks run in the card's order (SHA-256, SHA-512, AES-256-CBC,
//!   AES-KDF, Twofish-256-CBC, Salsa20, ChaCha20, then HMAC-SHA-256 and
//!   Argon2id); the first wrong answer stops the run and is returned;
//! - every cipher check encrypts, compares, then decrypts and compares with
//!   the plaintext; an error from a crypto function counts as a wrong answer;
//! - only the public test values below go in: no key, password or vault byte.

use crate::cipher::{Cipher, Decryptor, Encryptor};
use crate::kdf::{self, Argon2Settings, Argon2Type};
use crate::secret::SecretBytes;
use crate::stream::FieldStream;
use crate::{hash, mac};

/// One check of the self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// FIPS 180-2 Appendix B.2 (the two-block 448-bit message).
    Sha256,
    /// The same 448-bit message; not a FIPS example, its value checked with
    /// Python, OpenSSL and libgcrypt (Verify, 2026-10-28).
    Sha512,
    /// NIST SP 800-38A F.2.5, blocks 1 and 2, no padding.
    Aes256Cbc,
    /// One AES-KDF round: FIPS-197 C.3.
    AesKdf,
    /// The AES-256-CBC inputs through Twofish.
    Twofish256Cbc,
    /// Salsa20/20, 8-byte zero nonce.
    Salsa20,
    /// RFC 7539 A.1, vector 1.
    ChaCha20,
    /// RFC 4231 test case 1.
    HmacSha256,
    /// RFC 9106 section 5.3.
    Argon2id,
}

impl Check {
    /// Every check, in the order [`run`] runs them.
    pub const ALL: [Self; 9] = [
        Self::Sha256,
        Self::Sha512,
        Self::Aes256Cbc,
        Self::AesKdf,
        Self::Twofish256Cbc,
        Self::Salsa20,
        Self::ChaCha20,
        Self::HmacSha256,
        Self::Argon2id,
    ];

    /// The name M11-02 shows, for example `SHA-256`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Aes256Cbc => "AES-256-CBC",
            Self::AesKdf => "AES-KDF",
            Self::Twofish256Cbc => "Twofish-256-CBC",
            Self::Salsa20 => "Salsa20",
            Self::ChaCha20 => "ChaCha20",
            Self::HmacSha256 => "HMAC-SHA-256",
            Self::Argon2id => "Argon2id",
        }
    }
}

/// Runs every check of APP-11.10 in order.
///
/// # Errors
/// The first check that gave a wrong answer; later checks do not run.
pub fn run() -> Result<(), Check> {
    run_with(None)
}

/// `wrong`: the test-only fault hook; that check is fed a wrong expected value.
fn run_with(wrong: Option<Check>) -> Result<(), Check> {
    for check in Check::ALL {
        if !passes(check, wrong == Some(check)) {
            return Err(check);
        }
    }
    Ok(())
}

/// The 56 bytes of the FIPS 180-2 multi-block example.
const FIPS_TEXT: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
/// NIST SP 800-38A F.2.5 key, IV and plaintext blocks 1 and 2.
const CBC_KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
const CBC_PLAIN: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";

fn passes(check: Check, wrong: bool) -> bool {
    let want = |expected: &str| {
        let mut bytes = hex(expected);
        if wrong && let Some(first) = bytes.first_mut() {
            *first ^= 1;
        }
        bytes
    };
    match check {
        Check::Sha256 => {
            hash::sha256(&[FIPS_TEXT]).expose()
                == want("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        }
        Check::Sha512 => {
            hash::sha512(&[FIPS_TEXT]).expose()
                == want(concat!(
                    "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335",
                    "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
                ))
        }
        Check::Aes256Cbc => cbc(
            Cipher::Aes256Cbc,
            &want("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"),
        ),
        Check::AesKdf => {
            let seed = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let mut block = hex("00112233445566778899aabbccddeeff");
            kdf::aes_rounds(&seed, 1, &mut block).is_ok()
                && block == want("8ea2b7ca516745bfeafc49904b496089")
        }
        Check::Twofish256Cbc => cbc(
            Cipher::Twofish256Cbc,
            &want("e0227c3cc80f3cb1b2ed847cc6f57d3c657b1e7960b30fb7c8d62e72ae37c3a0"),
        ),
        Check::Salsa20 => keystream(
            || {
                let key = "f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112";
                FieldStream::salsa20(&SecretBytes::new(hex(key)), &[0; 8])
            },
            &want("b4c0afa503be7fc29a62058166d56f8f"),
        ),
        Check::ChaCha20 => keystream(
            || FieldStream::chacha20(&SecretBytes::zeroed(32), &[0; 12]),
            &want(concat!(
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
                "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
            )),
        ),
        Check::HmacSha256 => mac::hmac_sha256(&[0x0b; 20], &[b"Hi There"]).is_ok_and(|tag| {
            tag.expose() == want("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        }),
        Check::Argon2id => {
            // RFC 9106 section 5 inputs: m = 32 KiB, t = 3, p = 4, version
            // 0x13, password 32 × 01, salt 16 × 02, secret 8 × 03, associated
            // data 12 × 04, tag 32 bytes.
            let settings = Argon2Settings {
                kind: Argon2Type::Id,
                version: 0x13,
                iterations: 3,
                memory_kib: 32,
                lanes: 4,
            };
            let mut tag = [0; 32];
            kdf::argon2_into(&settings, &[1; 32], &[2; 16], &[3; 8], &[4; 12], &mut tag).is_ok()
                && tag.as_slice()
                    == want("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        }
    }
}

/// CBC with no padding: encrypt the two blocks, compare with `want`, decrypt
/// `want` and compare with the plaintext.
fn cbc(cipher: Cipher, want: &[u8]) -> bool {
    let key = SecretBytes::new(hex(CBC_KEY));
    let (iv, plain) = (hex(CBC_IV), hex(CBC_PLAIN));
    // Whole blocks only, so update returns them all and finish (which pads) is never called.
    let encrypted = Encryptor::new(cipher, &key, &iv).and_then(|mut e| e.update(&plain));
    if encrypted.as_deref() != Ok(want) {
        return false;
    }
    let decrypted = Decryptor::new(cipher, &key, &iv).and_then(|mut d| {
        let head = d.update(want)?;
        let tail = d.finish_unpadded()?;
        Ok([head.expose(), tail.expose()].concat())
    });
    decrypted == Ok(plain)
}

/// XOR the keystream onto zeros and compare with `want`; a fresh stream on
/// `want` must give the zeros back.
fn keystream(make: impl Fn() -> Result<FieldStream, crate::Error>, want: &[u8]) -> bool {
    let apply = |data: &mut [u8]| make().and_then(|mut stream| stream.apply(data)).is_ok();
    let mut data = vec![0; want.len()];
    if !apply(&mut data) || data != want {
        return false;
    }
    apply(&mut data) && data.iter().all(|&b| b == 0)
}

/// Hex text to bytes; a bad constant gives a value no check can match.
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn app11_10_d_every_check_passes() {
        assert_eq!(run(), Ok(()));
    }

    #[test]
    fn app11_10_each_wrong_answer_stops_the_run_at_that_check() {
        for check in Check::ALL {
            assert_eq!(run_with(Some(check)), Err(check), "{}", check.name());
        }
    }

    #[test]
    fn app11_10_the_whole_test_takes_under_10_ms() {
        // Fastest of five, so a busy Mac does not fail it.
        let fastest = (0..5)
            .map(|_| {
                let t = Instant::now();
                assert_eq!(run(), Ok(()));
                t.elapsed()
            })
            .min()
            .unwrap();
        assert!(fastest < Duration::from_millis(10), "{fastest:?}");
    }
}
