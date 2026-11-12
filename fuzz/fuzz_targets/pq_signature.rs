//! Fuzz target `pq_signature` (E25-S2, CRY-05.5): arbitrary bytes as a
//! composite ML-DSA-65 + Ed25519 signature over RFC 10073's message, checked
//! with that RFC's id-MLDSA65-Ed25519-SHA512 public key (the tree's test
//! vector). Never a panic; only the vector's empty-ctx signature verifies
//! (both halves are strongly unforgeable), every other input is
//! `SignatureInvalid`.
#![no_main]

use larsal_crypto::{Error, pq};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// RFC 10073 Appendix E, id-MLDSA65-Ed25519-SHA512: the line of the tree's
/// test data (crates/larsal-crypto/tests/data/pq/README.md), read once.
struct Vector {
    m: Vec<u8>,
    pk: Vec<u8>,
    s: Vec<u8>,
}

fn rfc10073() -> &'static Vector {
    static V: OnceLock<Vector> = OnceLock::new();
    V.get_or_init(|| {
        let text =
            include_str!("../../crates/larsal-crypto/tests/data/pq/composite-mldsa65-ed25519.txt");
        let line = text.lines().find(|l| l.starts_with("composite ")).unwrap();
        let field = |k: &str| -> Vec<u8> {
            let v = line
                .split(' ')
                .find_map(|p| p.strip_prefix(k)?.strip_prefix('='))
                .unwrap();
            (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                .collect()
        };
        Vector {
            m: field("m"),
            pk: field("pk"),
            s: field("s"),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let v = rfc10073();
    match pq::composite_verify(&v.pk, &v.m, data) {
        Ok(()) => assert_eq!(data, v.s.as_slice(), "another signature verified"),
        Err(e) => {
            assert_eq!(e, Error::SignatureInvalid);
            assert_ne!(data, v.s.as_slice(), "the vector's signature was refused");
        }
    }
});
