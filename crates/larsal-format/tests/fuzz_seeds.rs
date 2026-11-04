//! E3-S10: writes the seed corpus of the fuzz targets in fuzz/corpus/ from
//! the demo vaults in testdata/, so no seed is made by hand. Ignored by
//! default because it writes files; run it once after the demo vaults or
//! the targets change:
//! `cargo test -p larsal-format --test fuzz_seeds -- --ignored`
//!
//! The vault seeds are resealed under the fixed password of the
//! `vault_open` target (`demo-pass`) with AES-KDF at 100 rounds, so the
//! fuzzer gets past the key step: version 4 written by Larsal (compressed and
//! not, the three ciphers), version 3 by the test-only builder (compressed
//! and not), and payloads for the target's sealed modes. The document seeds
//! use the `document` target's stream key S4 = 00 01 … 3F.
//!
//! No seed may hold an outside product name as text (AGENTS.md rule 1), so
//! every plaintext seed is cleaned: the root element name becomes the
//! placeholder `@R` (the targets expand it), the padding item key and the
//! `Generator` text are replaced. The name guard then runs on the seeds and
//! any seed it flags is left out.

mod format_common;
mod write_common;

use format_common::DemoV3;
use larsal_crypto::kdf::{Argon2Type, KdfParams};
use larsal_crypto::secret::SecretString;
use larsal_format::document::write::{self, SaveStamp};
use larsal_format::kdf_params::{MapEntry, write_kdf, write_map};
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::payload::{Open, open_payload};
use larsal_format::{Opened, open};
use larsal_model::{Compression, Kdf, Time, Vault};
use std::path::PathBuf;
use write_common::{chacha, host, inner_len, parts, save_pw};

fn root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// The demo vaults used as seeds, with their credentials. The key file
/// vaults all hold the same content, so one of them is enough; the
/// 10,000-entry vault is left out to keep each fuzz run fast.
const SEEDS: [(&str, Option<&str>, Option<&str>); 5] = [
    ("password-only", Some("demo-pass-1"), None),
    ("keyfile-xml-v2", None, Some("key-xml-v2")),
    ("default-time", Some("demo-pass-3"), None),
    ("rich-v3", Some("demo-pass-4"), None),
    ("rich-v4", Some("demo-pass-5"), None),
];

fn put(target: &str, name: &str, bytes: &[u8]) {
    let dir = root().join("fuzz/corpus").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("seed-{name}")), bytes).unwrap();
}

/// Opens a demo vault; returns the opened vault and the raw document.
fn demo(
    name: &str,
    password: Option<&str>,
    key: Option<&str>,
) -> (Box<larsal_format::OpenedVault>, Vec<u8>) {
    let file = std::fs::read(root().join(format!("testdata/{name}.larsalvault"))).unwrap();
    let pw = password.map(|p| SecretString::new(p.to_owned()));
    let kf = key.map(|k| {
        let bytes = std::fs::read(root().join(format!("testdata/{k}.larsalkey"))).unwrap();
        larsal_format::keyfile::read_key_file(std::io::Cursor::new(bytes), &Limits::DEFAULT)
            .unwrap()
    });
    let creds = Credentials {
        password: pw.as_ref(),
        key_file: kf.as_ref(),
        ..Default::default()
    };
    let Ok(Opened::Vault(v)) = open(&file, &creds, &mut host(), &Limits::DEFAULT, None) else {
        panic!("{name} opens")
    };
    let Ok(Open::Opened(p)) = open_payload(&file, &creds, &mut host(), &Limits::DEFAULT, None)
    else {
        panic!("{name} payload")
    };
    (v, p.xml.bytes().to_vec())
}

fn with(v: &mut Vault, cipher: larsal_model::Cipher, compression: Compression) {
    v.encryption.kdf = Kdf::AesKdf { rounds: 100 };
    v.encryption.cipher = cipher;
    v.encryption.compression = compression;
}

#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_fuzz_seeds() {
    for (name, password, key) in SEEDS {
        let (opened, original_doc) = demo(name, password, key);
        let mut v = opened.vault;
        // vault_open, version 4: Larsal's own writer.
        let mut variants = vec![
            ("gzip", larsal_model::Cipher::Aes256, Compression::Gzip),
            ("plain", larsal_model::Cipher::Aes256, Compression::None),
        ];
        if name == "rich-v4" {
            variants.push((
                "chacha20",
                larsal_model::Cipher::ChaCha20,
                Compression::Gzip,
            ));
            variants.push((
                "twofish",
                larsal_model::Cipher::Twofish256,
                Compression::None,
            ));
        }
        for (label, cipher, compression) in variants {
            with(&mut v, cipher, compression);
            let saved = save_pw(&v, "demo-pass").bytes;
            put("vault_open", &format!("{name}-v4-{label}"), &saved);
            let p = parts(&saved, "demo-pass");
            // inner_header and the sealed version 4 mode: the decompressed
            // payload, cleaned, plain and as a gzip member.
            if label == "plain" {
                let u = clean(&p.inner_and_doc);
                let packed = format_common::gzip(&u);
                put("inner_header", &format!("{name}-u"), &u);
                put("inner_header", &format!("{name}-gzip"), &packed);
                put(
                    "vault_open",
                    &format!("{name}-sealed4-plain"),
                    &[&[0x80][..], &u].concat(),
                );
                put(
                    "vault_open",
                    &format!("{name}-sealed4-gzip"),
                    &[&[0x81][..], &packed].concat(),
                );
                let inner = &p.inner_and_doc[..inner_len(&p.inner_and_doc)];
                put("inner_header", &format!("{name}-inner"), inner);
                put(
                    "kdf_map",
                    &format!("{name}-aes"),
                    &write_kdf(&p.header.kdf).unwrap(),
                );
            }
        }
        // vault_open, version 3: the original document resealed by the
        // test-only builder, with the original stream key, and the sealed
        // version 3 mode.
        if opened.header.major == 3 {
            let stream_key = opened.header.v3.as_ref().unwrap().stream_key.clone();
            // The header hash in the document names the old header (FMT-10.21).
            let doc = without_header_hash(&original_doc);
            let cleaned = clean(&doc);
            put(
                "vault_open",
                &format!("{name}-sealed3-plain"),
                &[&[0xC0][..], &cleaned].concat(),
            );
            let packed = format_common::gzip(&cleaned);
            put(
                "vault_open",
                &format!("{name}-sealed3-gzip"),
                &[&[0xC1][..], &packed].concat(),
            );
            for gzip in [true, false] {
                let file = DemoV3 {
                    password: Some("demo-pass".into()),
                    rounds: 100,
                    stream_key: stream_key.clone(),
                    xml: doc.clone(),
                    gzip,
                    ..DemoV3::new()
                }
                .build();
                let label = if gzip { "gzip" } else { "plain" };
                put("vault_open", &format!("{name}-v3-{label}"), &file);
            }
        }
        // document: the original document and Larsal's writing of it with S4.
        put(
            "document",
            &format!("{name}-original.xml"),
            &clean(&original_doc),
        );
        let stamp = SaveStamp {
            padding_hex: "a5".repeat(64),
            time: Time(63_928_466_236),
        };
        let key: Vec<u8> = (0u8..64).collect();
        let w = write::write(&v, write::minor_version(&v), &mut chacha(&key), &stamp).unwrap();
        put("document", &format!("{name}-written.xml"), &clean(w.xml()));
    }
    // key_file: every demo key file.
    for e in std::fs::read_dir(root().join("testdata")).unwrap() {
        let path = e.unwrap().path();
        if path.extension().is_some_and(|x| x == "larsalkey") {
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            put("key_file", &stem, &std::fs::read(&path).unwrap());
        }
    }
    // kdf_map: both Argon2 types, and typed maps of public custom data.
    for (label, kind) in [("argon2d", Argon2Type::D), ("argon2id", Argon2Type::Id)] {
        let p = KdfParams::Argon2 {
            kind,
            version: 0x13,
            iterations: 2,
            memory_kib: 65_536,
            lanes: 4,
            salt: (0u8..32).collect(),
        };
        put("kdf_map", label, &write_kdf(&p).unwrap());
    }
    let entry = |kind: u8, name: &[u8], value: &[u8]| MapEntry {
        kind,
        name: name.to_vec(),
        value: value.to_vec(),
    };
    let public = [
        entry(0x04, b"u32", &[1, 0, 0, 0]),
        entry(0x05, b"u64", &[2, 0, 0, 0, 0, 0, 0, 0]),
        entry(0x08, b"bool", &[1]),
        entry(0x0C, b"i32", &[0xFF, 0xFF, 0xFF, 0xFF]),
        entry(0x0D, b"i64", &[0xFE; 8]),
        entry(0x18, b"text", "Demo vault".as_bytes()),
        entry(0x42, b"bytes", &[0xAB, 0xCD]),
    ];
    put("kdf_map", "public", &write_map(&public).unwrap());
    guard_filter();
    for (target, at_least) in [
        ("vault_open", 20),
        ("document", 6),
        ("inner_header", 8),
        ("key_file", 6),
        ("kdf_map", 4),
    ] {
        let n = std::fs::read_dir(root().join("fuzz/corpus").join(target))
            .unwrap()
            .count();
        assert!(n >= at_least, "{target}: {n} seeds");
    }
}

/// `xml` with the root element name as `@R`, the padding item key and the
/// `Generator` text replaced by neutral words (module docs).
fn clean(xml: &[u8]) -> Vec<u8> {
    let root_name: &[u8] = &[
        0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6C, 0x65,
    ];
    let mut out = replace(xml, root_name, b"@R");
    out = replace(
        &out,
        larsal_format::document::write::PADDING_KEY,
        b"PaddingItem",
    );
    if let (Some(a), Some(b)) = (find(&out, b"<Generator>"), find(&out, b"</Generator>")) {
        out = [&out[..a + 11], b"Demo".as_slice(), &out[b..]].concat();
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn replace(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut rest = hay;
    while let Some(at) = find(rest, from) {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(to);
        rest = &rest[at + from.len()..];
    }
    out.extend_from_slice(rest);
    out
}

/// Runs the name guard on the seeds (copied beside a copy of AGENTS.md, as
/// the guard needs) and deletes every seed it flags. The guard prints file
/// names and word numbers only.
fn guard_filter() {
    let targets = [
        "vault_open",
        "document",
        "inner_header",
        "key_file",
        "kdf_map",
    ];
    let tmp = std::env::temp_dir().join(format!("larsal-seed-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::copy(root().join("AGENTS.md"), tmp.join("AGENTS.md")).unwrap();
    for target in targets {
        let to = tmp.join(target);
        std::fs::create_dir_all(&to).unwrap();
        for e in std::fs::read_dir(root().join("fuzz/corpus").join(target)).unwrap() {
            let path = e.unwrap().path();
            std::fs::copy(&path, to.join(path.file_name().unwrap())).unwrap();
        }
    }
    let out = std::process::Command::new(root().join("scripts/check-names.sh"))
        .arg(&tmp)
        .output()
        .unwrap();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        for target in targets {
            let marker = format!("/{target}/");
            if let Some(at) = line.find(&marker) {
                let file = line[at + marker.len()..].split(':').next().unwrap();
                let path = root().join("fuzz/corpus").join(target).join(file);
                if path.exists() {
                    eprintln!("name guard: left out {target}/{file}");
                    std::fs::remove_file(path).unwrap();
                }
            }
        }
    }
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// `doc` without its `HeaderHash` element.
fn without_header_hash(doc: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(doc.to_vec()).unwrap();
    match (text.find("<HeaderHash>"), text.find("</HeaderHash>")) {
        (Some(a), Some(b)) => [&text[..a], &text[b + "</HeaderHash>".len()..]]
            .concat()
            .into_bytes(),
        _ => doc.to_vec(),
    }
}
