//! Fuzz target `share_container` (E11-S2): reading a share container by its
//! first bytes, through larsal-core's ZIP reader and the vault reader, with
//! the fixed share password `demo-share-1` and cheap key settings
//! (INT-08.9, INT-08.36; AT-A06, AT-A08, AT-A10). Must never panic, hang
//! or allocate from an unchecked length; every vault it returns holds the
//! model invariants and no share item below its root (INT-08.33).
//!
//! Input: a mode byte, then the rest, split at byte 0x1E into parts.
//! - Bit 6 set: the first part is a document, sealed here as a version 3.1
//!   file under the share password (AES-KDF, 100 rounds) so the reader
//!   reaches it; `@R` stands for the document root element name and `@K`
//!   for the share item key (see `expand`). Clear: the first part as is.
//! - Bit 7 clear: the first part is the container. Set: the target zips
//!   the parts: the first as the vault entry (bit 0: deflated), the next
//!   as the signature entry and others (bit 1: the second also named as
//!   the vault entry).
#![no_main]

use larsal_core::edit::SHARED_KEY;
use larsal_crypto::cipher::{self, Cipher};
use larsal_crypto::hash::sha256;
use larsal_crypto::kdf::{self, Host, KdfParams, SpeedRecord, Verdict};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_format::keys::{cipher_key_v3, composite_key, password_part};
use larsal_format::limits::Limits;
use larsal_share::container::{self, VAULT_ENTRY};
use libfuzzer_sys::fuzz_target;
use std::io::Write;
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

/// `data` with every `@R` replaced by the root element name and every `@K`
/// by the share item key: the stored seeds hold the placeholders, so no
/// seed file carries either as text (AGENTS.md rule 1).
fn expand(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut rest = data;
    while let Some(at) = rest.windows(2).position(|w| w == b"@R" || w == b"@K") {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(if rest[at + 1] == b'R' {
            ROOT_NAME
        } else {
            SHARED_KEY
        });
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
    SecretString::new("demo-share-1".to_owned())
}

/// `T` of the share key: the password part through AES-KDF, 100 rounds.
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

/// A version 3 field: id, 2-byte length, data (FMT-17.3).
fn field3(out: &mut Vec<u8>, id: u8, data: &[u8]) {
    out.push(id);
    out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
    out.extend_from_slice(data);
}

/// A version 3.1 file around the document `plain` (FMT-17), no gzip.
fn seal_v3(plain: &[u8]) -> Vec<u8> {
    let mut head = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 0, 3, 0];
    field3(
        &mut head,
        2,
        &larsal_format::header::cipher_id(Cipher::Aes256Cbc),
    );
    field3(&mut head, 3, &0u32.to_le_bytes());
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

fn zip(members: &[(&[u8], &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, content, deflate) in members {
        let body = if *deflate {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(content).unwrap();
            e.finish().unwrap()
        } else {
            content.to_vec()
        };
        let mut crc = flate2::Crc::new();
        crc.update(content);
        let method: u16 = if *deflate { 8 } else { 0 };
        let offset = out.len() as u32;
        let head = |v: &mut Vec<u8>| {
            v.extend(method.to_le_bytes());
            v.extend([0u8; 4]);
            v.extend(crc.sum().to_le_bytes());
            v.extend((body.len() as u32).to_le_bytes());
            v.extend((content.len() as u32).to_le_bytes());
            v.extend((name.len() as u16).to_le_bytes());
            v.extend(0u16.to_le_bytes());
        };
        out.extend(0x0403_4b50u32.to_le_bytes());
        out.extend([20, 0, 0, 0]);
        head(&mut out);
        out.extend(*name);
        out.extend(&body);
        cd.extend(0x0201_4b50u32.to_le_bytes());
        cd.extend([20, 0, 20, 0, 0, 0]);
        head(&mut cd);
        cd.extend([0u8; 10]);
        cd.extend(offset.to_le_bytes());
        cd.extend(*name);
    }
    let cd_offset = out.len() as u32;
    out.extend(&cd);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((cd.len() as u32).to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend([0u8; 2]);
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if rest.len() >= 1 << 20 {
        return;
    }
    let mut parts = rest.split(|&b| b == 0x1E);
    let first = parts.next().unwrap_or(&[]);
    let first = if mode & 0x40 != 0 {
        seal_v3(&expand(first))
    } else {
        first.to_vec()
    };
    let file = if mode & 0x80 == 0 {
        first
    } else {
        let others: Vec<&[u8]> = parts.take(6).collect();
        let names: Vec<Vec<u8>> = (0..others.len())
            .map(|i| match i {
                0 if mode & 2 != 0 => VAULT_ENTRY.to_vec(),
                0 => b"container.share.signature".to_vec(),
                n => format!("other{n}.txt").into_bytes(),
            })
            .collect();
        let mut members = vec![(VAULT_ENTRY, first.as_slice(), mode & 1 != 0)];
        members.extend(
            names
                .iter()
                .zip(&others)
                .map(|(n, c)| (n.as_slice(), *c, false)),
        );
        zip(&members)
    };
    let mut lim = Limits::DEFAULT;
    lim.total_file = 16 << 20;
    lim.total = 16 << 20;
    lim.document = 16 << 20;
    lim.model = 128 << 20;
    // Anything costing more than about 50 ms is a question, never a run.
    lim.kdf.ask_ms = 50;
    lim.kdf.ask_memory_kib = 8 << 10;
    if let Ok(v) = container::open(&file, &password(), &mut host(), &lim) {
        assert_eq!(larsal_model::invariants::check(&v.vault), Ok(()));
        for g in v.vault.root.subtree().into_iter().skip(1) {
            assert!(
                g.custom_data
                    .items
                    .iter()
                    .all(|i| i.key.as_bytes() != SHARED_KEY)
            );
        }
    }
});
