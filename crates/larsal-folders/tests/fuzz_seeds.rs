//! E23-S3: writes the seed corpus of the `folder_readers` fuzz target, from the same
//! independent writer the tests use, so no seed is made by hand. Ignored by default because
//! it writes files; run it once after the target changes:
//! `cargo test -p larsal-folders --test fuzz_seeds -- --ignored`
//! It writes to LARSAL_FUZZ_SEEDS when set (a guarded run cannot write the source tree),
//! else to fuzz/corpus/folder_readers.
//!
//! A seed is the target's mode byte, then its input (fuzz/fuzz_targets/folder_readers.rs).

mod common;

use common::{
    CHUNK, CLAIMS, ENC, HEADER, KeySettings, MAC, deflated, jws, key_file, raw_name, seal_with,
};
use std::fs;
use std::path::{Path, PathBuf};

/// The demo keys of the crate's fuzz door, the same bytes as its `demo_keys`.
const DEMO_ENC: [u8; 32] = [0x11; 32];
const DEMO_MAC: [u8; 32] = [0x22; 32];

#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_folder_reader_seeds() {
    let dir = std::env::var_os("LARSAL_FUZZ_SEEDS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/folder_readers"),
        PathBuf::from,
    );
    fs::create_dir_all(&dir).unwrap();
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    let mut with_mode = |mode: u8, bytes: &[u8]| seeds.push([&[mode][..], bytes].concat());

    // Mode 0: configurations, right ones and each way of being wrong.
    with_mode(0, jws(&DEMO_ENC, &DEMO_MAC, HEADER, CLAIMS).as_bytes());
    with_mode(0, jws(&ENC, &MAC, HEADER, CLAIMS).as_bytes());
    with_mode(
        0,
        jws(
            &DEMO_ENC,
            &DEMO_MAC,
            &HEADER.replace("HS256", "HS512"),
            CLAIMS,
        )
        .as_bytes(),
    );
    with_mode(
        0,
        jws(
            &DEMO_ENC,
            &DEMO_MAC,
            &HEADER.replace("HS256", "none"),
            CLAIMS,
        )
        .as_bytes(),
    );
    with_mode(
        0,
        jws(
            &DEMO_ENC,
            &DEMO_MAC,
            &HEADER.replace("masterkeyfile:masterkey.cryptomator", "hub+https://x"),
            CLAIMS,
        )
        .as_bytes(),
    );
    with_mode(
        0,
        jws(
            &DEMO_ENC,
            &DEMO_MAC,
            HEADER,
            &CLAIMS.replace("SIV_GCM", "SIV_CTRMAC"),
        )
        .as_bytes(),
    );
    with_mode(
        0,
        jws(
            &DEMO_ENC,
            &DEMO_MAC,
            HEADER,
            &CLAIMS.replace("220", "99999999999999999999"),
        )
        .as_bytes(),
    );
    with_mode(0, b"a.b.c");
    with_mode(0, b"..");

    // Mode 1: key files.
    let key = key_file("demo", &KeySettings::default());
    with_mode(1, key.as_bytes());
    with_mode(
        1,
        key.replace("\"scryptCostParam\":16", "\"scryptCostParam\":65536")
            .replace("\"scryptBlockSize\":8", "\"scryptBlockSize\":1")
            .as_bytes(),
    );
    with_mode(
        1,
        key.replace(
            "\"scryptCostParam\":16",
            "\"scryptCostParam\":18446744073709551616",
        )
        .as_bytes(),
    );
    with_mode(1, key.replacen('{', "{\"version\":999,", 1).as_bytes());
    with_mode(1, b"{}");
    with_mode(1, b"[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]");

    // Mode 2: stored names under the demo keys: the parent's length byte, the parent, the name.
    let name_seed = |parent: &[u8], name: &str| {
        let mut seed = vec![parent.len() as u8];
        seed.extend_from_slice(parent);
        seed.extend_from_slice(raw_name(&DEMO_ENC, &DEMO_MAC, parent, name).as_bytes());
        seed
    };
    with_mode(2, &name_seed(b"", "hello.txt"));
    with_mode(
        2,
        &name_seed(b"11111111-2222-3333-4444-555555555555", "caf\u{e9}.txt"),
    );
    with_mode(2, &name_seed(b"", "con"));
    with_mode(2, &[0, b'A', b'A', b'=', b'=', b'.', b'c', b'9', b'r']);

    // Mode 3: new clear names.
    for name in [
        "hello.txt",
        "a/b",
        "..",
        "CON",
        "cafe\u{301}.txt",
        "x\u{202e}y",
        "",
    ] {
        with_mode(3, name.as_bytes());
    }

    // Mode 4: shortened nodes: the name's length byte, the node's name, then the mapping.
    let long = raw_name(&DEMO_ENC, &DEMO_MAC, b"", &"l".repeat(200));
    let right = deflated(&long);
    let short_seed = |node: &str, inner: &str| {
        let mut seed = vec![node.len() as u8];
        seed.extend_from_slice(node.as_bytes());
        seed.extend_from_slice(inner.as_bytes());
        seed
    };
    with_mode(4, &short_seed(&right, &long));
    with_mode(4, &short_seed(&right, "short.c9r"));
    with_mode(4, &short_seed("wrong.c9s", &long));

    // Mode 5: stored content under the demo keys, with its worker count in the mode's next
    // byte: every boundary, and each way of being wrong.
    let content = |plain_len: usize, workers: u8| {
        let plain: Vec<u8> = (0..plain_len).map(|i| i as u8).collect();
        let mut seed = vec![workers];
        seed.extend(seal_with(&DEMO_ENC, &[7; 32], &plain, false));
        seed
    };
    for len in [0, 1, 100, CHUNK - 1, CHUNK, CHUNK + 1] {
        with_mode(5, &content(len, 1));
    }
    with_mode(5, &content(CHUNK * 2 + 5, 4));
    let mut bad = content(100, 2);
    let end = bad.len() - 1;
    bad[end] ^= 1;
    with_mode(5, &bad);
    with_mode(5, &content(100, 1)[..60]);
    let mut with_empty = vec![1u8];
    with_empty.extend(seal_with(&DEMO_ENC, &[7; 32], b"", true));
    with_mode(5, &with_empty);

    for (i, seed) in seeds.iter().enumerate() {
        fs::write(dir.join(format!("seed-{i:02}")), seed).unwrap();
    }
}
