//! E22-S3: writes the seed corpus of the `file_decrypt` fuzz target in fuzz/corpus/
//! from the derived vectors, so no seed is made by hand. Ignored by default because
//! it writes files; run it once after the vectors or the target change:
//! `cargo test -p larsal-files --test fuzz_seeds -- --ignored`
//!
//! A seed is the target's mode byte, then its input (fuzz/fuzz_targets/file_decrypt.rs).

use std::fs;
use std::path::Path;

fn body_of(vector: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/derived")
        .join(vector);
    let raw = fs::read(path).unwrap();
    let at = raw.windows(2).position(|w| w == b"\n\n").unwrap();
    raw[at + 2..].to_vec()
}

#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_file_decrypt_seeds() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/file_decrypt");
    fs::create_dir_all(&dir).unwrap();
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    let mut with_mode = |mode: u8, bytes: &[u8]| {
        seeds.push([&[mode][..], bytes].concat());
    };
    // Whole files, from every stage of the flow.
    for vector in [
        "x25519_basic",
        "x25519_two_recipients",
        "x25519_unknown_stanza",
        "x25519_unknown_body_full_line",
        "x25519_low_order_share",
        "payload_0",
        "stanza_noncanonical_body",
        "footer_noncanonical_mac",
        "mac_flip",
        "no_final_flag",
        "trailing_one_byte",
        "armor_basic",
        "armor_crlf",
        "armor_no_padding",
    ] {
        with_mode(0, &body_of(vector));
    }
    // After a BEGIN line.
    let armored = body_of("armor_basic");
    let after_begin = armored.iter().position(|b| *b == b'\n').unwrap() + 1;
    with_mode(1, &armored[after_begin..]);
    with_mode(1, b"-----END AGE ENCRYPTED FILE-----\n");
    // Chunk lists: right ones, then each way of being wrong.
    with_mode(2, &[0, 1]);
    with_mode(2, &[1, 1]);
    with_mode(2, &[3, 1]);
    with_mode(2, &[3, 0, 2, 1]);
    with_mode(2, &[3, 0, 3, 0, 1, 1]);
    with_mode(2, &[3, 0, 0, 1]);
    with_mode(2, &[1, 0, 1, 1]);
    with_mode(2, &[3, 2, 1, 1]);
    with_mode(2, &[1, 5]);
    with_mode(2, &[1, 0]);
    // Lists and recipient text.
    with_mode(
        3,
        b"# demo\n\nAGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE\n",
    );
    with_mode(
        3,
        b"age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72",
    );
    // A low cost passphrase file, and shapes around it.
    with_mode(4, &body_of("scrypt_basic"));
    with_mode(4, &body_of("scrypt_and_x25519"));
    with_mode(4, &body_of("scrypt_cost_21"));
    for (i, seed) in seeds.iter().enumerate() {
        fs::write(dir.join(format!("seed-{i:02}")), seed).unwrap();
    }
}
