//! Fuzz target `vault_open` (E3-S10): the whole open of a vault file, both
//! layouts, with a fixed demo password (`demo-pass`) and cheap key settings,
//! so inputs get past the key step. Must never panic, hang or allocate from
//! an unchecked length (AT-A10), and every vault it returns must hold the
//! model invariants.
//!
//! The first input byte picks the mode:
//! - bit 7 clear: the input is a whole file (seeds: demo vaults resealed
//!   under the password with AES-KDF at 100 rounds);
//! - bit 7 set: the rest is a payload, sealed here under the fixed key so
//!   the checks of FMT-05 to FMT-07 pass and the fuzzer reaches the payload,
//!   gzip, inner header and document: version 3 when bit 6 is set (start
//!   bytes and hashed blocks), else version 4 (header HMAC and HMAC blocks);
//!   bit 0 is the compression flag written in the header. In this mode
//!   `@R` stands for the document root element name (see `expand`).
#![no_main]

use app_crypto::cipher::{self, Cipher};
use app_crypto::hash::sha256;
use app_crypto::kdf::{self, Host, KdfParams, SpeedRecord, Verdict};
use app_crypto::secret::{SecretBytes, SecretString};
use app_format::header::{Compression, write_header};
use app_format::integrity::{header_hmac, write_blocks};
use app_format::keys::{Credentials, cipher_key_v3, composite_key, final_keys, password_part};
use app_format::limits::Limits;
use app_format::{Opened, open};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const SEED: [u8; 32] = [0x11; 32];
const KDF_SEED: [u8; 32] = [0x4B; 32];
const IV: [u8; 16] = [0x22; 16];
const ROUNDS: u64 = 100;
const START: [u8; 32] = [0x39; 32];
const STREAM_KEY: [u8; 32] = [0x38; 32];

/// The document root element name, stored encoded (name rule).
const ROOT_NAME: &[u8] = &[
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6C, 0x65,
];

/// `data` with every `@R` replaced by the root element name: the stored
/// seeds hold the placeholder, so no seed file carries the name as text
/// (AGENTS.md rule 1); inputs without `@R` pass unchanged.
fn expand(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut rest = data;
    while let Some(at) = rest.windows(2).position(|w| w == b"@R") {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(ROOT_NAME);
        rest = &rest[at + 2..];
    }
    out.extend_from_slice(rest);
    out
}

fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: Some(SpeedRecord {
            count: 100,
            memory_kib: 8 << 10,
            lanes: 1,
            ms: 100,
        }),
        aes_record: Some(SpeedRecord {
            count: 10_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 100,
        }),
    }
}

fn password() -> SecretString {
    SecretString::new("demo-pass".to_owned())
}

/// `T` of the fixed key: the password part through AES-KDF, 100 rounds.
fn transformed() -> &'static SecretBytes {
    static T: OnceLock<SecretBytes> = OnceLock::new();
    T.get_or_init(|| {
        let params = KdfParams::AesKdf {
            rounds: ROUNDS,
            seed: KDF_SEED.to_vec(),
        };
        let composite = composite_key(Some(&password_part(&password())), None, None);
        let Ok(Verdict::Run(c)) = kdf::assess(&params, &mut host(), &Limits::DEFAULT.kdf, None)
        else {
            panic!("100 rounds need no question")
        };
        kdf::derive(&composite, &c).unwrap()
    })
}

/// A version 4 file around `plain` (FMT-05.9, FMT-06.8, FMT-08.10).
fn seal_v4(plain: &[u8], gzip: bool) -> Vec<u8> {
    let compression = if gzip {
        Compression::Gzip
    } else {
        Compression::None
    };
    let params = KdfParams::AesKdf {
        rounds: ROUNDS,
        seed: KDF_SEED.to_vec(),
    };
    let head = write_header(1, Cipher::Aes256Cbc, compression, &SEED, &IV, &params, &[]).unwrap();
    let keys = final_keys(&SEED, transformed());
    let ct = cipher::encrypt(Cipher::Aes256Cbc, &keys.cipher_key, &IV, plain).unwrap();
    let mut file = head.clone();
    file.extend_from_slice(sha256(&[&head]).expose());
    file.extend_from_slice(header_hmac(&keys.hmac_key, &head).expose());
    file.extend(write_blocks(&ct, &keys.hmac_key, 1 << 20).unwrap());
    file
}

/// A version 3 field: id, 2-byte length, data (FMT-17.3).
fn field3(out: &mut Vec<u8>, id: u8, data: &[u8]) {
    out.push(id);
    out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
    out.extend_from_slice(data);
}

/// A version 3.1 file around the document stream `plain` (FMT-17): the
/// start bytes, then `plain` as one hashed block and the final block.
fn seal_v3(plain: &[u8], gzip: bool) -> Vec<u8> {
    let mut head = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 0, 3, 0];
    field3(
        &mut head,
        2,
        &app_format::header::cipher_id(Cipher::Aes256Cbc),
    );
    field3(&mut head, 3, &u32::from(gzip).to_le_bytes());
    field3(&mut head, 4, &SEED);
    field3(&mut head, 5, &KDF_SEED);
    field3(&mut head, 6, &ROUNDS.to_le_bytes());
    field3(&mut head, 7, &IV);
    field3(&mut head, 8, &STREAM_KEY);
    field3(&mut head, 9, &START);
    field3(&mut head, 10, &2u32.to_le_bytes());
    field3(&mut head, 0, b"\r\n\r\n");
    let mut stream = START.to_vec();
    stream.extend_from_slice(&0u32.to_le_bytes());
    stream.extend_from_slice(sha256(&[plain]).expose());
    stream.extend_from_slice(&u32::try_from(plain.len()).unwrap().to_le_bytes());
    stream.extend_from_slice(plain);
    stream.extend_from_slice(&1u32.to_le_bytes());
    stream.extend_from_slice(&[0; 32]);
    stream.extend_from_slice(&0u32.to_le_bytes());
    let key = cipher_key_v3(&SEED, None, transformed());
    let ct = cipher::encrypt(Cipher::Aes256Cbc, &key, &IV, &stream).unwrap();
    [head, ct].concat()
}

fuzz_target!(|data: &[u8]| {
    let file = match data.split_first() {
        Some((&mode, rest)) if mode & 0x80 != 0 && rest.len() < 1 << 20 => {
            let rest = expand(rest);
            if mode & 0x40 != 0 {
                seal_v3(&rest, mode & 1 == 1)
            } else {
                seal_v4(&rest, mode & 1 == 1)
            }
        }
        _ => data.to_vec(),
    };
    let mut lim = Limits::DEFAULT;
    lim.total_file = 16 << 20;
    lim.total = 16 << 20;
    lim.document = 16 << 20;
    lim.model = 128 << 20;
    // Anything costing more than about 50 ms is a question, never a run.
    lim.kdf.ask_ms = 50;
    lim.kdf.ask_memory_kib = 8 << 10;
    let password = password();
    let creds = Credentials {
        password: Some(&password),
        ..Default::default()
    };
    if let Ok(Opened::Vault(v)) = open(&file, &creds, &mut host(), &lim, None) {
        assert_eq!(app_model::invariants::check(&v.vault), Ok(()));
    }
});
