//! Fuzz target `v1_import` (E4-S13): the version 1 import (FEA-08 section
//! G). Must never panic, hang or allocate by a hostile number (FEA-08.55:
//! every field size is checked before the field is read). A result keeps
//! the model invariants.
//!
//! Input: a mode byte, then the rest. Mode bit 0 clear: the rest is the
//! file, read with a speed record that makes every derivation a question
//! (no key derivation runs; header checks only). Set: two count bytes
//! (groups, entries), then the plaintext records, which the target
//! encrypts under a 1-round demo key (bit 1: Twofish), so the record
//! parser, tree and Auto-Type lines are reached. With bit 2 the rest is
//! split at byte 0x1E into the records, a custom icons blob and a tree
//! state blob, and the target appends the two meta records (FEA-08.58)
//! with those blobs; their markers live here as hex only (name rule).
#![no_main]

use app_core::import::{Context, v1};
use app_core::time::Utc;
use app_crypto::cipher::{self, Cipher};
use app_crypto::hash::sha256;
use app_crypto::kdf::{self, Ceilings, Host, KdfParams, SpeedRecord, Verdict};
use app_crypto::secret::{SecretBytes, SecretString};
use app_model::Time;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::AtomicBool;

const CEILINGS: Ceilings = Ceilings {
    refuse_iterations: 1_000_000_000,
    ask_memory_kib: 1_048_576,
    ask_lanes: 128,
    ask_ms: 10_000,
};

fn host(count: u64, ms: u64) -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(SpeedRecord {
            count,
            memory_kib: 0,
            lanes: 1,
            ms,
        }),
    }
}

/// The meta record markers, stored encoded (name rule).
const TREE: &[u8] = &[
    0x4B, 0x50, 0x58, 0x5F, 0x47, 0x52, 0x4F, 0x55, 0x50, 0x5F, 0x54, 0x52, 0x45, 0x45, 0x5F, 0x53,
    0x54, 0x41, 0x54, 0x45,
];
const ICONS: &[u8] = &[
    0x4B, 0x50, 0x58, 0x5F, 0x43, 0x55, 0x53, 0x54, 0x4F, 0x4D, 0x5F, 0x49, 0x43, 0x4F, 0x4E, 0x53,
    0x5F, 0x34,
];

/// A meta entry record (FEA-08.58) with notes `marker` and attachment `blob`.
fn meta(marker: &[u8], blob: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    let mut field = |kind: u16, data: &[u8]| {
        r.extend(kind.to_le_bytes());
        r.extend((data.len() as u32).to_le_bytes());
        r.extend(data);
    };
    let text = |t: &[u8]| [t, &[0]].concat();
    field(3, &0u32.to_le_bytes());
    field(4, &text(b"Meta-Info"));
    field(5, &text(b"$"));
    field(6, &text(b"SYSTEM"));
    field(8, &text(marker));
    field(13, &text(b"bin-stream"));
    field(14, blob);
    field(0xFFFF, &[]);
    r
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let cancel = AtomicBool::new(false);
    let ctx = Context::new(Time(63_900_000_000), &Utc, &cancel);
    let pw = SecretString::new("demo-v1-pass".into());
    let keys = v1::Keys {
        password: Some(&pw),
        key_file: None,
    };
    if mode & 1 == 0 {
        // One round costs 100 s by this record: every derivation asks.
        let out = v1::read(rest, &keys, &mut host(1, 100_000), &CEILINGS, None, &ctx);
        assert!(!matches!(out, Ok(v1::Outcome::Imported(_))));
        return;
    }
    let [groups, entries, body @ ..] = rest else {
        return;
    };
    let mut parts = body.split(|&b| b == 0x1E);
    let mut plain = if mode & 4 != 0 {
        parts.next().unwrap_or(&[]).to_vec()
    } else {
        body.to_vec()
    };
    let mut entries = u32::from(*entries);
    if mode & 4 != 0 {
        let icons = parts.next().unwrap_or(&[]);
        let tree = parts.next().unwrap_or(&[]);
        plain.extend(meta(ICONS, icons));
        plain.extend(meta(TREE, tree));
        entries += 2;
    }
    let plain = plain.as_slice();
    let master = [1u8; 16];
    let iv = [2u8; 16];
    let seed = [3u8; 32];
    let params = KdfParams::AesKdf {
        rounds: 1,
        seed: seed.to_vec(),
    };
    let mut fast = host(100_000_000, 1_000);
    let Ok(Verdict::Run(c)) = kdf::assess(&params, &mut fast, &CEILINGS, None) else {
        return;
    };
    let t = kdf::derive(&sha256(&[b"demo-v1-pass"]), &c).unwrap();
    let key: SecretBytes = sha256(&[&master, t.expose()]);
    let twofish = mode & 2 != 0;
    let cipher = if twofish {
        Cipher::Twofish256Cbc
    } else {
        Cipher::Aes256Cbc
    };
    let mut file = vec![0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5];
    file.extend(if twofish { 8u32 } else { 2u32 }.to_le_bytes());
    file.extend(0x0003_0004u32.to_le_bytes());
    file.extend(master);
    file.extend(iv);
    file.extend(u32::from(*groups).to_le_bytes());
    file.extend(entries.to_le_bytes());
    file.extend(sha256(&[plain]).expose());
    file.extend(seed);
    file.extend(1u32.to_le_bytes());
    file.extend(cipher::encrypt(cipher, &key, &iv, plain).unwrap());
    let started = std::time::Instant::now();
    if let Ok(v1::Outcome::Imported(r)) = v1::read(&file, &keys, &mut fast, &CEILINGS, None, &ctx) {
        assert_eq!(app_model::invariants::check(&r.vault), Ok(()));
    }
    assert!(started.elapsed().as_secs() < 2, "too slow");
});
