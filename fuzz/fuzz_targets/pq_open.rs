//! Fuzz target `pq_open` (E25-S2, CRY-05.3): the whole hybrid HPKE open
//! (suite [0x647a, 1, 3]) on arbitrary enc, info and ct with the right key.
//! Input: two bytes of enc length and two of info length (big endian, each
//! taken modulo a bound past its limit), then enc, info and the rest as ct.
//! Never a panic; only the sealed triple opens, everything else is
//! `WrapInvalid`.
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

const INFO: &[u8] = b"fuzz info";
const PLAINTEXT: &[u8] = b"demo plaintext";

fn fixed() -> &'static Fixed {
    static FIXED: OnceLock<Fixed> = OnceLock::new();
    FIXED.get_or_init(|| {
        let (seed, pk) = pq::xwing_keypair().unwrap();
        let (enc, ct) = pq::seal(&pk, INFO, PLAINTEXT).unwrap();
        Fixed { seed, enc, ct }
    })
}

fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, rest) = data.split_at(n.min(data.len()));
    *data = rest;
    head
}

fuzz_target!(|data: &[u8]| {
    let f = fixed();
    let mut rest = data;
    let lens = take(&mut rest, 4);
    let lens = [0, 1, 2, 3].map(|i| usize::from(lens.get(i).copied().unwrap_or(0)));
    let enc = take(&mut rest, (lens[0] << 8 | lens[1]) % (pq::ENC + 64));
    let info = take(&mut rest, (lens[2] << 8 | lens[3]) % (pq::MAX_INFO + 64));
    let ct = rest;
    let sealed = enc == f.enc.as_slice() && info == INFO && ct == f.ct.as_slice();
    match pq::open(&f.seed, enc, info, ct) {
        Ok(pt) => {
            assert!(sealed, "another triple opened");
            assert_eq!(pt.expose(), PLAINTEXT);
        }
        Err(e) => {
            assert_eq!(e, Error::WrapInvalid);
            assert!(!sealed, "the sealed triple was refused");
        }
    }
});
