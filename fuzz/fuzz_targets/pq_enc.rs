//! Fuzz target `pq_enc` (E25-S2, CRY-05.3): arbitrary bytes as the enc of a
//! hybrid HPKE ciphertext, through `pq::open` with the right key, info and ct.
//! Never a panic; only the enc that `pq::seal` made opens, every other one is
//! `WrapInvalid` (a wrong length before decapsulation, any other change at the
//! tag after ML-KEM's implicit rejection).
#![no_main]

use larsal_crypto::secret::SecretBytes;
use larsal_crypto::{Error, pq};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

struct Fixed {
    seed: SecretBytes,
    enc: Vec<u8>,
    ct: Vec<u8>,
}

fn fixed() -> &'static Fixed {
    static FIXED: OnceLock<Fixed> = OnceLock::new();
    FIXED.get_or_init(|| {
        let (seed, pk) = pq::xwing_keypair().unwrap();
        let (enc, ct) = pq::seal(&pk, b"fuzz info", b"demo plaintext").unwrap();
        Fixed { seed, enc, ct }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixed();
    match pq::open(&f.seed, data, b"fuzz info", &f.ct) {
        Ok(pt) => {
            assert_eq!(data, f.enc.as_slice(), "another enc opened");
            assert_eq!(pt.expose(), b"demo plaintext");
        }
        Err(e) => {
            assert_eq!(e, Error::WrapInvalid);
            assert_ne!(data, f.enc.as_slice(), "the sealed enc was refused");
        }
    }
});
