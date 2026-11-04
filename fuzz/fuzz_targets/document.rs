//! Fuzz target `document` (E3-S10): the vault document reader on arbitrary
//! XML, with a ChaCha20 field stream and an empty pool. Must never panic,
//! hang or allocate past the limits (AT-A10, AT-A07); every vault it reads
//! must hold the model invariants, and App must read back what it writes
//! of it (FMT-08.12: App never writes what it would refuse to read).
//! `@R` in the input stands for the root element name (see `expand`).
#![no_main]

use app_crypto::secret::SecretBytes;
use app_crypto::stream::FieldStream;
use app_format::document::write::{SaveStamp, minor_version, write};
use app_format::document::{Options, read};
use app_format::limits::Limits;
use app_model::Time;
use libfuzzer_sys::fuzz_target;

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

fuzz_target!(|data: &[u8]| {
    let mut lim = Limits::DEFAULT;
    lim.depth = 64;
    lim.text = 1 << 20;
    lim.model = 64 << 20;
    let key = SecretBytes::new((0u8..64).collect());
    let stream = || FieldStream::chacha20_from_stream_key(&key).unwrap();
    let opts = Options {
        open_time: Time(0),
        limits: &lim,
        v3_header: None,
    };
    let data = expand(data);
    let Ok(doc) = read(&data, &mut stream(), &[], &opts) else {
        return;
    };
    assert_eq!(app_model::invariants::check(&doc.vault), Ok(()));
    let stamp = SaveStamp {
        padding_hex: "a5".repeat(64),
        time: Time(0),
    };
    let w = write(&doc.vault, minor_version(&doc.vault), &mut stream(), &stamp).unwrap();
    let pool: Vec<&[u8]> = w.pool.iter().map(|p| p.expose()).collect();
    let default = Limits::DEFAULT;
    let again = Options {
        limits: &default,
        ..opts
    };
    let back = read(w.xml(), &mut stream(), &pool, &again).expect("App reads what it writes");
    assert_eq!(app_model::invariants::check(&back.vault), Ok(()));
});
