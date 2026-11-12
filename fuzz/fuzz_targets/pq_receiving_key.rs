//! Fuzz target `pq_receiving_key` (E25-S2, CRY-05.3): an X-Wing receiving
//! public key from arbitrary bytes, through `pq::seal`. Never a panic; a key is
//! taken exactly when it is 1,216 bytes and every ML-KEM-768 coefficient of its
//! first 1,152 bytes is below 3,329 (FIPS 203 section 7.2's modulus check).
#![no_main]

use larsal_crypto::{Error, pq};
use libfuzzer_sys::fuzz_target;

/// FIPS 203 ByteDecode_12 over t (3 x 384 bytes): every coefficient below q.
fn coefficients_below_q(key: &[u8]) -> bool {
    key[..1152].chunks_exact(3).all(|b| {
        let (b0, b1, b2) = (u16::from(b[0]), u16::from(b[1]), u16::from(b[2]));
        (b0 | (b1 & 0x0f) << 8) < 3329 && (b1 >> 4 | b2 << 4) < 3329
    })
}

fuzz_target!(|data: &[u8]| {
    match pq::seal(data, b"fuzz info", b"demo") {
        Ok((enc, ct)) => {
            assert_eq!(data.len(), pq::PUBLIC_KEY);
            assert!(coefficients_below_q(data), "a key over q was taken");
            assert_eq!((enc.len(), ct.len()), (pq::ENC, 4 + 16));
        }
        Err(Error::KeyLength) => assert_ne!(data.len(), pq::PUBLIC_KEY),
        Err(Error::WrapInvalid) => {
            assert_eq!(data.len(), pq::PUBLIC_KEY);
            assert!(!coefficients_below_q(data), "a good key was refused");
        }
        Err(e) => panic!("unexpected {e:?}"),
    }
});
