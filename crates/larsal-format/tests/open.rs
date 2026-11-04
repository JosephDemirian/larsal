//! Open-flow rows: FMT-01 (frame on whole files), FMT-04.10 to FMT-04.21,
//! FMT-05.7 and FMT-05.8 (open order, wrong key), FMT-06 on vaults, FMT-08
//! (payload), FMT-09 and FMT-13 (inner header and pool), and the testdata/
//! demo vaults. One test per card row, named after it.

mod format_common;

use format_common::*;
use larsal_crypto::cipher::{self, Cipher};
use larsal_crypto::kdf::{ARGON2D_ID, ARGON2ID_ID};
use larsal_crypto::secret::SecretBytes;
use larsal_format::Error;
use larsal_format::detect::read_vault;
use larsal_format::error::{HardwareKeyReason, KeyFileReason};
use larsal_format::header::read_header;
use larsal_format::inner::{StreamAlgorithm, read_inner};
use larsal_format::integrity::read_blocks;
use larsal_format::keyfile::read_key_file;
use larsal_format::keys::{ChallengeResponse, Credentials};
use larsal_format::limits::{Limit, Limits};
use larsal_format::payload::{Open, gunzip, open_payload, probe};
use std::cell::Cell;

const L: Limits = Limits::DEFAULT;

fn xml_of(r: Result<Open, Error>) -> Vec<u8> {
    opened(r).xml.bytes().to_vec()
}

/// A hardware key that is not there, counting how often it was asked.
struct Absent(Cell<usize>);

impl ChallengeResponse for Absent {
    fn challenge(&self, _: &[u8; 64]) -> Result<SecretBytes, HardwareKeyReason> {
        self.0.set(self.0.get() + 1);
        Err(HardwareKeyReason::Missing)
    }
}

fn with_password_and<'a>(
    p: &'a larsal_crypto::secret::SecretString,
    hw: &'a dyn ChallengeResponse,
) -> Credentials<'a> {
    Credentials {
        password: Some(p),
        key_file: None,
        hardware_key: Some(hw),
    }
}

// ---------------------------------------------------------------------------
// testdata/

#[test]
fn testdata_rich_v4_opens_down_to_the_xml() {
    let r = rich();
    assert_eq!(&r.xml[..5], b"<?xml");
    assert!(
        r.xml
            .windows(11)
            .any(|w| w == hex("4B 65 65 50 61 73 73 46 69 6C 65"))
    );
    assert_eq!(
        r.pool.len(),
        4,
        "four distinct attachment contents (FMT-01.18)"
    );
}

#[test]
fn testdata_rich_v4_wrong_password_is_wrong_key() {
    let _ = probe::take();
    assert_eq!(
        kind(open(&testdata("rich-v4.larsalvault"), "demo-pass-6")),
        Error::WrongKey
    );
    let c = probe::take();
    assert_eq!(
        (c.kdf, c.decrypt, c.inflate),
        (1, 0, 0),
        "nothing is decrypted"
    );
}

// ---------------------------------------------------------------------------
// FMT-01 on whole files

fn rich_header(minor: Option<u16>, extra: &[u8], kdf_id: Option<[u8; 16]>) -> Vec<u8> {
    let r = rich();
    let mut h = r.file[..r.header_len].to_vec();
    if let Some(m) = minor {
        h[8..10].copy_from_slice(&m.to_le_bytes());
    }
    if let Some(id) = kdf_id {
        h[0x79..0x89].copy_from_slice(&id);
    }
    let end = h.len() - 9;
    h.splice(end..end, extra.iter().copied());
    h
}

fn rich_resealed(header: &[u8]) -> Vec<u8> {
    let r = rich();
    reseal(&r.file, r.header_len, header, &r.hmac_key)
}

#[test]
fn fmt_01_10_unknown_minor() {
    for minor in [2u16, 65535] {
        let file = rich_resealed(&rich_header(Some(minor), &[], None));
        let p = opened(open(&file, "demo-pass-5"));
        assert_eq!(p.header.minor, minor);
        assert_eq!(p.xml.bytes(), rich().xml.as_slice());
    }
}

#[test]
fn fmt_01_12_whole_file() {
    let r = rich();
    let stream = &r.file[r.header_len + 64..];
    let blocks = read_blocks(stream, &r.hmac_key, &L).unwrap();
    let walked: usize = blocks.iter().map(|b| 36 + b.len()).sum::<usize>() + 36;
    assert_eq!(
        r.header_len + 64 + walked,
        r.file.len(),
        "the final block is the last 36 bytes"
    );
    assert_eq!(&r.file[r.file.len() - 4..], [0, 0, 0, 0]);
    assert_eq!(
        blocks.iter().map(|b| b.len()).sum::<usize>() % 16,
        0,
        "ciphertext is a multiple of 16 (FMT-01.18)"
    );
}

#[test]
fn fmt_01_15_legacy_field_in_version_4() {
    let file = rich_resealed(&rich_header(None, &field(9, &[0; 32]), None));
    let _ = probe::take();
    assert_eq!(kind(open(&file, "demo-pass-5")), Error::Corrupt);
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_01_15_unknown_fields_in_version_4() {
    for f in [field(1, b"12345"), field(13, b"abc"), field(99, b"xyz")] {
        let file = rich_resealed(&rich_header(None, &f, None));
        assert_eq!(xml_of(open(&file, "demo-pass-5")), rich().xml);
    }
}

#[test]
fn fmt_01_17_checks_cover_the_version() {
    let mut file = testdata("rich-v4.larsalvault");
    file[8..12].copy_from_slice(&[0x02, 0x00, 0x04, 0x00]);
    let _ = probe::take();
    assert_eq!(kind(open(&file, "demo-pass-5")), Error::Corrupt);
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_01_18_nesting() {
    let file = testdata("rich-v4.larsalvault");
    let p = opened(open(&file, "demo-pass-5"));
    assert_eq!(p.inner.stream, StreamAlgorithm::ChaCha20);
    assert_eq!(p.inner.stream_key.len(), 64);
    assert_eq!(p.inner.pool.len(), 4);
    let xml = p.xml.bytes();
    let start = xml.iter().position(|&b| b == b'<').unwrap();
    assert_eq!(&xml[start..start + 5], b"<?xml");
    let root = xml
        .windows(12)
        .position(|w| w == [b"<".as_slice(), &hex("4B 65 65 50 61 73 73 46 69 6C 65")].concat())
        .unwrap();
    assert!(root > 0, "the root element follows the declaration");
}

#[test]
fn fmt_01_20_appended_bytes() {
    let d = Demo::rich_content();
    let base = d.build();
    let want = xml_of(open(&base, "demo-pass"));
    for n in [1usize, 16, 4096] {
        let tail: Vec<u8> = (0..n).map(|i| (i * 131 + 7) as u8).collect();
        assert_eq!(
            xml_of(open(&[base.clone(), tail].concat(), "demo-pass")),
            want,
            "{n}"
        );
    }
    let real = [testdata("rich-v4.larsalvault"), vec![0xA5; 4096]].concat();
    assert_eq!(xml_of(open(&real, "demo-pass-5")), rich().xml);
}

#[test]
fn fmt_01_20_cut_stays_corrupt() {
    let file = testdata("rich-v4.larsalvault");
    assert_eq!(
        kind(open(&file[..file.len() - 36], "demo-pass-5")),
        Error::Corrupt
    );
}

#[test]
fn fmt_01_27_newer_aes_kdf_id() {
    let file = rich_resealed(&rich_header(
        None,
        &[],
        Some(larsal_crypto::kdf::AES_KDF_NEW_ID),
    ));
    assert_eq!(xml_of(open(&file, "demo-pass-5")), rich().xml);
}

#[test]
fn fmt_01_31_at_the_limit() {
    let lim = Limits {
        total_file: 4096,
        ..L
    };
    let file = testdata("rich-v4.larsalvault");
    assert_eq!(
        kind(open_lim(&file[..4096], "demo-pass-5", &lim)),
        Error::Corrupt
    );
    let _ = probe::take();
    assert_eq!(
        kind(open_lim(&file[..4097], "demo-pass-5", &lim)),
        Error::TooLarge(Limit::TotalFile)
    );
    assert_eq!(
        read_vault(&file[..4097], &lim),
        Err(Error::TooLarge(Limit::TotalFile))
    );
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_01_32_read_model() {
    let r = rich();
    let mut file = r.file.clone();
    let first = read_blocks(&file[r.header_len + 64..], &r.hmac_key, &L).unwrap()[0].len();
    file[r.header_len + 64 + 36 + first - 1] ^= 0x01;
    let _ = probe::take();
    assert_eq!(kind(open(&file, "demo-pass-5")), Error::Corrupt);
    let c = probe::take();
    assert_eq!((c.decrypt, c.inflate), (0, 0));
}

// ---------------------------------------------------------------------------
// FMT-04 open rows

fn hw_demo() -> Demo {
    Demo {
        hardware: Some(b"Larsal demo HMAC key".to_vec()),
        ..Demo::new()
    }
}

#[test]
fn fmt_04_hardware_key_vault_opens() {
    let file = hw_demo().build();
    let p = pw("demo-pass");
    let key = soft_key(b"Larsal demo HMAC key");
    assert_eq!(
        xml_of(open_creds(&file, &with_password_and(&p, &key))),
        DEMO_XML
    );
}

#[test]
fn fmt_04_10_a_no_device() {
    let file = hw_demo().build();
    let p = pw("demo-pass");
    let absent = Absent(Cell::new(0));
    let _ = probe::take();
    assert_eq!(
        kind(open_creds(&file, &with_password_and(&p, &absent))),
        Error::HardwareKey(HardwareKeyReason::Missing)
    );
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_04_10_c_other_device_is_wrong_key() {
    let file = hw_demo().build();
    let p = pw("demo-pass");
    let other = soft_key(b"another demo secret!");
    assert_eq!(
        kind(open_creds(&file, &with_password_and(&p, &other))),
        Error::WrongKey
    );
}

#[test]
fn fmt_04_16_b_no_credentials() {
    let _ = probe::take();
    assert_eq!(
        kind(open_creds(&Demo::new().build(), &Credentials::default())),
        Error::NoCredentials
    );
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_04_20_a_short_aes_kdf_seed() {
    for n in [16, 8] {
        let mut d = Demo::new();
        d.kdf_map = aes_kdf_map(1_000, &vec![0x4B; n]);
        let mut h = d.header();
        h.extend_from_slice(larsal_crypto::hash::sha256(&[&h]).expose());
        h.extend([0; 32 + 72]);
        let _ = probe::take();
        assert_eq!(kind(open(&h, "demo-pass")), Error::Unsupported);
        assert_eq!(probe::take().kdf, 0);
    }
}

/// A header with a valid SHA-256 and a dummy HMAC and payload: enough for
/// every check before the KDF.
fn header_only_file(d: &Demo) -> Vec<u8> {
    let mut f = d.header();
    f.extend_from_slice(larsal_crypto::hash::sha256(&[&f]).expose());
    f.extend([0; 32 + 72]);
    f
}

#[test]
fn fmt_04_21_a_refused_before_the_device() {
    let mut d = hw_demo();
    d.kdf_map = argon2_map(ARGON2ID_ID, 1_000_000_001, 8 << 10, 1, &[1; 32], 0x13);
    let p = pw("demo-pass");
    let absent = Absent(Cell::new(0));
    assert_eq!(
        kind(open_creds(
            &header_only_file(&d),
            &with_password_and(&p, &absent)
        )),
        Error::TooLarge(Limit::KdfCost)
    );
    assert_eq!(absent.0.get(), 0, "the device is never asked");
}

#[test]
fn fmt_04_21_b_ask_then_decline_then_approve() {
    let mut d = Demo::new();
    d.kdf_map = argon2_map(ARGON2ID_ID, 1, 1032 << 10, 129, &[1; 32], 0x13);
    let file = d.build();
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    let _ = probe::take();
    let Ok(Open::Ask(report)) = open_payload(&file, &creds, &mut host(), &L, None) else {
        panic!("ask expected")
    };
    assert!(report.over_lanes() && !report.over_memory());
    assert_eq!(
        (report.lanes(), report.work(), report.memory_bytes()),
        (129, 1, 1032 << 10)
    );
    assert_eq!(probe::take().kdf, 0, "declining: nothing ran");
    let p2 = opened(open_payload(&file, &creds, &mut host(), &L, Some(&report)));
    assert_eq!(p2.xml.bytes(), DEMO_XML);
    assert_eq!(probe::take().kdf, 1);
}

#[test]
fn fmt_04_21_c_key_file_error_then_wrong_password() {
    assert_eq!(
        read_key_file(std::io::Cursor::new(Vec::new()), &L).unwrap_err(),
        Error::KeyFile(KeyFileReason::Empty)
    );
    assert_eq!(
        kind(open(&Demo::new().build(), "wrong-pass")),
        Error::WrongKey
    );
}

// ---------------------------------------------------------------------------
// FMT-05 open order

fn flip(mut v: Vec<u8>, at: usize) -> Vec<u8> {
    v[at] ^= 0x01;
    v
}

const SEED_AT: usize = 0x2F + 3; // inside the master seed data

#[test]
fn fmt_05_7_damaged_header_hash_checked_before_the_kdf() {
    let file = flip(Demo::new().build(), SEED_AT);
    let _ = probe::take();
    assert_eq!(kind(open(&file, "demo-pass")), Error::Corrupt);
    assert_eq!(kind(open(&file, "wrong-pass")), Error::Corrupt);
    assert_eq!(probe::take().kdf, 0);
}

struct Failing;

impl std::io::Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::NotFound.into())
    }
}

#[test]
fn fmt_05_7_read_step_before_credentials() {
    assert_eq!(
        read_vault(Failing, &L),
        Err(Error::Io(std::io::ErrorKind::NotFound))
    );
}

#[test]
fn fmt_05_7_twelve_byte_look_of_the_read_step() {
    let lim = Limits {
        total_file: 100,
        ..L
    };
    let full = Demo::new().build();
    let zeros = vec![0u8; 200];
    let v5 = [hex("03D9A29A67FB4BB500000500"), vec![0; 188]].concat();
    let _ = probe::take();
    assert_eq!(
        read_vault(&full[..], &lim),
        Err(Error::TooLarge(Limit::TotalFile))
    );
    assert_eq!(
        kind(open_lim(&full, "demo-pass", &lim)),
        Error::TooLarge(Limit::TotalFile)
    );
    assert_eq!(kind(open_lim(&zeros, "demo-pass", &lim)), Error::NotAVault);
    assert_eq!(kind(open_lim(&v5, "demo-pass", &lim)), Error::Unsupported);
    assert!(read_vault(&zeros[..], &lim).is_ok() && read_vault(&v5[..], &lim).is_ok());
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_05_7_key_file_error_comes_first() {
    // The key file is read (and fails) before open_payload is called, so no
    // vault byte is parsed and no KDF runs.
    let _ = probe::take();
    assert_eq!(
        read_key_file(std::io::Cursor::new(Vec::new()), &L).unwrap_err(),
        Error::KeyFile(KeyFileReason::Empty)
    );
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_05_7_header_hash_before_the_cost_check() {
    let mut d = Demo::new();
    d.kdf_map = argon2_map(ARGON2D_ID, 2, 2 << 30, 2, &[1; 32], 0x13);
    let file = header_only_file(&d);
    let _ = probe::take();
    let Ok(Open::Ask(report)) = open(&file, "demo-pass") else {
        panic!("ask expected")
    };
    assert!(report.over_memory());
    assert_eq!(
        kind(open(&flip(file, SEED_AT), "demo-pass")),
        Error::Corrupt
    );
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_05_7_hardware_key_after_the_hash_before_the_kdf() {
    let good = hw_demo().build();
    let p = pw("demo-pass");
    let absent = Absent(Cell::new(0));
    let _ = probe::take();
    assert_eq!(
        kind(open_creds(
            &flip(good.clone(), SEED_AT),
            &with_password_and(&p, &absent)
        )),
        Error::Corrupt
    );
    assert_eq!(absent.0.get(), 0);
    assert_eq!(
        kind(open_creds(&good, &with_password_and(&p, &absent))),
        Error::HardwareKey(HardwareKeyReason::Missing)
    );
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_05_7_damaged_stored_hash_and_5_8_damaged_stored_hmac() {
    let file = Demo::new().build();
    let h = read_header(&file, &L).unwrap().len;
    assert_eq!(
        kind(open(&flip(file.clone(), h + 3), "demo-pass")),
        Error::Corrupt
    );
    assert_eq!(
        kind(open(&flip(file, h + 38), "demo-pass")),
        Error::WrongKey
    );
}

#[test]
fn fmt_05_8_tamper_with_fixed_hash() {
    let mut file = flip(Demo::new().build(), SEED_AT);
    let h = read_header(&file, &L).unwrap().len;
    let hash = larsal_crypto::hash::sha256(&[&file[..h]]);
    file[h..h + 32].copy_from_slice(hash.expose());
    assert_eq!(kind(open(&file, "demo-pass")), Error::WrongKey);
}

#[test]
fn fmt_05_7_cut_inside_hash_or_hmac() {
    let file = Demo::new().build();
    let h = read_header(&file, &L).unwrap().len;
    let _ = probe::take();
    assert_eq!(kind(open(&file[..h + 40], "demo-pass")), Error::Corrupt);
    assert_eq!(kind(open(&file[..h], "demo-pass")), Error::Corrupt);
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_05_7_5_8_cut_right_after_the_hmac() {
    let file = Demo::new().build();
    let h = read_header(&file, &L).unwrap().len;
    assert_eq!(kind(open(&file[..h + 64], "demo-pass")), Error::Corrupt);
    assert_eq!(kind(open(&file[..h + 64], "wrong-pass")), Error::WrongKey);
}

#[test]
fn fmt_05_8_wrong_password_decrypts_nothing() {
    let _ = probe::take();
    assert_eq!(
        kind(open(&Demo::new().build(), "wrong-pass")),
        Error::WrongKey
    );
    let c = probe::take();
    assert_eq!((c.kdf, c.decrypt), (1, 0));
}

// ---------------------------------------------------------------------------
// FMT-06 on vaults

#[test]
fn fmt_06_1_position_in_a_file() {
    let file = Demo::rich_content().build();
    let h = read_header(&file, &L).unwrap().len;
    let k = Demo::rich_content().keys().hmac_key;
    let blocks = read_blocks(&file[h + 64..], &k, &L).unwrap();
    assert_eq!(
        h + 64 + blocks.iter().map(|b| 36 + b.len()).sum::<usize>() + 36,
        file.len()
    );
}

#[test]
fn fmt_06_10_large_blocks_accepted() {
    let mut d = Demo::new();
    d.gzip = false;
    d.xml = [
        b"<?xml version=\"1.0\"?><D>".as_slice(),
        &vec![b'a'; 1_502_224],
        b"</D>",
    ]
    .concat();
    d.block = 2 << 20;
    let file = d.build();
    assert_eq!(xml_of(open(&file, "demo-pass")).len(), d.xml.len());
}

#[test]
fn fmt_06_7_small_blocks_accepted() {
    for block in [1, 17, 64] {
        let d = Demo {
            block,
            ..Demo::new()
        };
        assert_eq!(xml_of(open(&d.build(), "demo-pass")), DEMO_XML, "{block}");
    }
}

#[test]
fn fmt_06_12_sync_tool_leftovers() {
    let file = Demo::new().build();
    for n in [1usize, 16, 4096] {
        let tail: Vec<u8> = (0..n).map(|i| (i * 7919 % 251) as u8).collect();
        assert_eq!(
            xml_of(open(&[file.clone(), tail].concat(), "demo-pass")),
            DEMO_XML
        );
    }
}

/// CBC ciphertext of `plain` with no padding added: encrypt with PKCS#7,
/// then drop the padding block (len must be a multiple of 16).
fn cbc_raw(d: &Demo, plain: &[u8]) -> Vec<u8> {
    assert_eq!(plain.len() % 16, 0);
    let mut c = d.encrypt(plain);
    c.truncate(plain.len());
    c
}

#[test]
fn fmt_06_13_t08_04_bad_padding_is_corrupt() {
    let mut d = Demo::new();
    d.gzip = false;
    let u = d.plaintext();
    let pad = 16 - u.len() % 16;
    let good = [u.clone(), vec![pad as u8; pad]].concat();
    assert_eq!(
        xml_of(open(
            &d.build_with_ciphertext(&cbc_raw(&d, &good)),
            "demo-pass"
        )),
        DEMO_XML,
        "control"
    );
    let zeros = [u.clone(), vec![0; pad]].concat();
    assert_eq!(
        kind(open(
            &d.build_with_ciphertext(&cbc_raw(&d, &zeros)),
            "demo-pass"
        )),
        Error::Corrupt
    );
    let full_zero = [good.clone(), vec![0; 16]].concat();
    assert_eq!(
        kind(open(
            &d.build_with_ciphertext(&cbc_raw(&d, &full_zero)),
            "demo-pass"
        )),
        Error::Corrupt
    );
    let mut last_changed = d.encrypt(&u);
    *last_changed.last_mut().unwrap() ^= 0x01;
    assert_eq!(
        kind(open(&d.build_with_ciphertext(&last_changed), "demo-pass")),
        Error::Corrupt
    );
}

// ---------------------------------------------------------------------------
// FMT-08

const G: &str = "1F 8B 08 00 00 00 00 00 00 13 CB 48 CD C9 C9 07 00 86 A6 10 36 05 00 00 00";

#[test]
fn t08_01_t08_02_t08_03_cipher_vectors() {
    let k = SecretBytes::new((0u8..32).collect());
    let iv: Vec<u8> = (0xA0..=0xAF).collect();
    let ct = hex(
        "B9 94 AC 0F EC A7 00 C7 CF 21 10 83 F9 3A 67 F2 50 CE 69 12 25 E0 10 04 BC 56 F0 4F C4 6A 11 63",
    );
    assert_eq!(
        cipher::decrypt(Cipher::Aes256Cbc, &k, &iv, &ct)
            .unwrap()
            .expose(),
        hex(G)
    );
    let nonce: Vec<u8> = (0xC0..=0xCB).collect();
    let ct = hex("1A B9 7D E8 D0 61 2B 20 DF D5 0F FC BB DD 0D AC 60 A9 C9 C9 25 19 8D F6 B0");
    assert_eq!(
        cipher::decrypt(Cipher::ChaCha20, &k, &nonce, &ct)
            .unwrap()
            .expose(),
        hex(G)
    );
    let out = cipher::encrypt(Cipher::Aes256Cbc, &k, &iv, b"0123456789abcdef").unwrap();
    assert_eq!(
        out,
        hex(
            "CE 1C F3 A4 E3 B8 7B 13 9B A3 CF F1 0A CE 35 B6 06 D9 6B 2E 18 4B F2 2B 73 D3 1B A4 BE 14 D8 C9"
        )
    );
}

#[test]
fn t08_05_ciphertext_not_a_multiple_of_16() {
    let d = Demo::new();
    let c = [d.encrypt(&d.plaintext()), vec![1, 2, 3, 4, 5]].concat();
    assert_eq!(
        kind(open(&d.build_with_ciphertext(&c), "demo-pass")),
        Error::Corrupt
    );
}

#[test]
fn t08_06_t08_07_t08_26_compression_field() {
    let d = Demo::new();
    let set = |data: &[u8]| {
        let mut h = d.header();
        h.splice(0x21..0x2A, field(3, data));
        let mut f = h.clone();
        f.extend_from_slice(larsal_crypto::hash::sha256(&[&h]).expose());
        f.extend([0; 104]);
        f
    };
    let _ = probe::take();
    assert_eq!(
        kind(open(&set(&[2, 0, 0, 0]), "demo-pass")),
        Error::Unsupported
    );
    assert_eq!(kind(open(&set(&[1, 0]), "demo-pass")), Error::Corrupt);
    let mut h = d.header();
    h.splice(0x21..0x2A, []);
    let f = [
        h.clone(),
        larsal_crypto::hash::sha256(&[&h]).expose().to_vec(),
        vec![0; 104],
    ]
    .concat();
    assert_eq!(kind(open(&f, "demo-pass")), Error::Corrupt);
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn t08_08_to_t08_11_gunzip() {
    let g = hex(G);
    assert_eq!(gunzip(&g, 1 << 20).unwrap().expose(), b"hello");
    assert_eq!(flate2::Crc::new().sum(), 0);
    let mut crc = flate2::Crc::new();
    crc.update(b"hello");
    assert_eq!(crc.sum(), 0x3610A686);
    let mut bad = g.clone();
    bad[17] = 0x87;
    assert_eq!(gunzip(&bad, 1 << 20).unwrap_err(), Error::Corrupt);
    let mut bad = g.clone();
    bad[21] = 0x04;
    assert_eq!(gunzip(&bad, 1 << 20).unwrap_err(), Error::Corrupt);
    assert_eq!(
        gunzip(&g[..g.len() - 8], 1 << 20).unwrap_err(),
        Error::Corrupt
    );
}

/// A gzip member of `data` with FLG `1E` (FEXTRA, FNAME, FCOMMENT, FHCRC),
/// MTIME 123456, XFL 2, OS FF, and the header CRC16 (bad when `bad_crc`).
fn gzip_flagged(data: &[u8], bad_crc: bool) -> Vec<u8> {
    let plain = gzip(data);
    let body = &plain[10..];
    let mut h = vec![0x1F, 0x8B, 0x08, 0x1E];
    h.extend(123_456u32.to_le_bytes());
    h.extend([2, 0xFF]);
    h.extend([4, 0, b'a', b'b', b'c', b'd']);
    h.extend(b"name\0comment\0");
    let mut crc = flate2::Crc::new();
    crc.update(&h);
    let c16 = (crc.sum() & 0xFFFF) as u16 ^ u16::from(bad_crc);
    h.extend(c16.to_le_bytes());
    [h, body.to_vec()].concat()
}

#[test]
fn t08_12_t08_13_gzip_header_variants() {
    let d = Demo::new();
    let u = [d.inner.clone(), d.xml.clone()].concat();
    assert_eq!(
        xml_of(open(
            &d.build_with_plaintext(&gzip_flagged(&u, false)),
            "demo-pass"
        )),
        DEMO_XML
    );
    assert_eq!(
        kind(open(
            &d.build_with_plaintext(&gzip_flagged(&u, true)),
            "demo-pass"
        )),
        Error::Corrupt
    );
    let mut reserved = gzip(&u);
    reserved[3] = 0x20;
    assert_eq!(
        kind(open(&d.build_with_plaintext(&reserved), "demo-pass")),
        Error::Corrupt
    );
    let mut cm = gzip(&u);
    cm[2] = 0x07;
    assert_eq!(
        kind(open(&d.build_with_plaintext(&cm), "demo-pass")),
        Error::Corrupt
    );
}

#[test]
fn t08_14_t08_15_t08_16_zlib_junk_two_members() {
    let d = Demo::new();
    let u = [d.inner.clone(), d.xml.clone()].concat();
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut z, &u).unwrap();
    assert_eq!(
        kind(open(
            &d.build_with_plaintext(&z.finish().unwrap()),
            "demo-pass"
        )),
        Error::Corrupt
    );
    let junk = [gzip(&u), b"GARBAGE-AFTER-MEMBER".to_vec()].concat();
    assert_eq!(
        kind(open(&d.build_with_plaintext(&junk), "demo-pass")),
        Error::Corrupt
    );
    let split = u.len() / 2;
    let two = [gzip(&u[..split]), gzip(&u[split..])].concat();
    assert_eq!(
        kind(open(&d.build_with_plaintext(&two), "demo-pass")),
        Error::Corrupt
    );
}

#[test]
fn t08_17_the_flag_is_trusted() {
    let d = Demo::new();
    let plain = [d.inner.clone(), d.xml.clone()].concat();
    assert_eq!(
        kind(open(&d.build_with_plaintext(&plain), "demo-pass")),
        Error::Corrupt
    );
    let off = Demo {
        gzip: false,
        ..Demo::new()
    };
    assert_eq!(
        kind(open(&off.build_with_plaintext(&gzip(&plain)), "demo-pass")),
        Error::Corrupt
    );
}

#[test]
fn t08_20_damaged_last_block_mac() {
    let d = Demo {
        block: 64,
        ..Demo::rich_content()
    };
    let mut file = d.build();
    let h = read_header(&file, &L).unwrap().len;
    let blocks = read_blocks(&file[h + 64..], &d.keys().hmac_key, &L).unwrap();
    let last_data = h + 64 + (blocks.len() - 1) * (36 + 64);
    file[last_data] ^= 1;
    let _ = probe::take();
    assert_eq!(kind(open(&file, "demo-pass")), Error::Corrupt);
    assert_eq!(probe::take().decrypt, 0);
}

#[test]
fn t08_22_payload_exactly_at_the_limit() {
    let d = Demo::new();
    let u_len = d.inner.len() + d.xml.len();
    let file = d.build();
    assert!(open_lim(&file, "demo-pass", &Limits { total: u_len, ..L }).is_ok());
    assert_eq!(
        kind(open_lim(
            &file,
            "demo-pass",
            &Limits {
                total: u_len - 1,
                ..L
            }
        )),
        Error::TooLarge(Limit::Total)
    );
    let off = Demo {
        gzip: false,
        ..Demo::new()
    }
    .build();
    assert!(open_lim(&off, "demo-pass", &Limits { total: u_len, ..L }).is_ok());
    assert_eq!(
        kind(open_lim(
            &off,
            "demo-pass",
            &Limits {
                total: u_len - 1,
                ..L
            }
        )),
        Error::TooLarge(Limit::Total)
    );
}

#[test]
fn t08_25_error_text_holds_no_secret() {
    // Every kind an open can give prints a fixed text; none carries bytes.
    for e in [
        Error::NotAVault,
        Error::OldFormat,
        Error::Unsupported,
        Error::Corrupt,
        Error::NoCredentials,
        Error::TooLarge(Limit::Total),
        Error::WrongKey,
    ] {
        let (d, s) = (format!("{e:?}"), e.to_string());
        assert!(
            !d.chars().any(|c| c.is_ascii_digit()) && !s.chars().any(|c| c.is_ascii_digit()),
            "{d} / {s}"
        );
    }
}

#[test]
fn t08_27_only_a_padding_block() {
    let d = Demo::new();
    assert_eq!(
        kind(open(&d.build_with_ciphertext(&d.encrypt(b"")), "demo-pass")),
        Error::Corrupt
    );
}

#[test]
fn t08_28_iv_lengths() {
    let mut aes = Demo::new();
    aes.iv = vec![0x22; 12];
    let _ = probe::take();
    assert_eq!(
        kind(open(&header_only_file(&aes), "demo-pass")),
        Error::Unsupported
    );
    for n in [8, 16, 24] {
        let mut c = Demo::new().with_cipher(Cipher::ChaCha20);
        c.iv = vec![0x22; n];
        assert_eq!(
            kind(open(&header_only_file(&c), "demo-pass")),
            Error::Unsupported,
            "{n}"
        );
    }
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn t08_29_minor_versions_decode_the_same() {
    for minor in [0, 1] {
        assert_eq!(
            xml_of(open(
                &Demo {
                    minor,
                    ..Demo::new()
                }
                .build(),
                "demo-pass"
            )),
            DEMO_XML
        );
    }
}

#[test]
fn t08_31_inner_header_counts_only_toward_total() {
    let lim = Limits {
        document: 1 << 20,
        total: 64 << 20,
        ..L
    };
    let a = Demo {
        xml: [
            b"<?xml version=\"1.0\"?><D>".as_slice(),
            &vec![b'a'; 2 << 20],
            b"</D>",
        ]
        .concat(),
        ..Demo::new()
    };
    assert_eq!(
        kind(open_lim(&a.build(), "demo-pass", &lim)),
        Error::TooLarge(Limit::Document)
    );
    let big = vec![0u8; 2 << 20];
    let b = Demo {
        inner: inner_header(3, &s4(), &[(1, &big)]),
        ..Demo::new()
    };
    let p = opened(open_lim(&b.build(), "demo-pass", &lim));
    assert_eq!(p.inner.pool[0].range.len(), 2 << 20);
}

#[test]
fn fmt_08_4_every_cipher_kdf_and_compression() {
    // Table A cells A08 to A25 built by our own code (plan (b) before the
    // reference re-save): every cipher, KDF and compression opens.
    let kdfs = [
        aes_kdf_map(1_000, &[0x4B; 32]),
        argon2_map(ARGON2D_ID, 2, 64 << 10, 2, &[0x5A; 32], 0x13),
        argon2_map(ARGON2ID_ID, 2, 64 << 10, 2, &[0x5A; 32], 0x13),
        argon2_map(ARGON2D_ID, 1, 64 << 10, 1, &[0x5A; 16], 0x10),
    ];
    for c in [Cipher::Aes256Cbc, Cipher::Twofish256Cbc, Cipher::ChaCha20] {
        for kdf_map in &kdfs {
            for gzip in [true, false] {
                let d = Demo {
                    kdf_map: kdf_map.clone(),
                    gzip,
                    ..Demo::new().with_cipher(c)
                };
                assert_eq!(
                    xml_of(open(&d.build(), "demo-pass")),
                    DEMO_XML,
                    "{c:?} {gzip}"
                );
                assert_eq!(kind(open(&d.build(), "demo-pass-x")), Error::WrongKey);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FMT-09 and FMT-13: the inner header and the pool

fn inner(u: &[u8]) -> Result<larsal_format::inner::InnerHeader, Error> {
    read_inner(u, &L)
}

#[test]
fn t09_01_parse() {
    let u = [
        hex("01 04 00 00 00 03 00 00 00 02 40 00 00 00"),
        s4(),
        hex("03 03 00 00 00 01 68 69 00 00 00 00 00 3C 3F 78 6D 6C"),
    ]
    .concat();
    let h = inner(&u).unwrap();
    assert_eq!(
        (h.stream, h.stream_key.expose(), h.len),
        (StreamAlgorithm::ChaCha20, s4().as_slice(), 91)
    );
    assert_eq!(
        (
            h.pool.len(),
            h.pool[0].protected,
            &u[h.pool[0].range.clone()]
        ),
        (1, true, &b"hi"[..])
    );
}

#[test]
fn t09_03_chacha20_keystream() {
    let h = inner(&inner_header(3, &s4(), &[])).unwrap();
    let mut ks = [0u8; 128];
    h.field_stream().unwrap().apply(&mut ks).unwrap();
    assert_eq!(to_hex(&ks[..16]), "8ce8bc610ac05ff2e3dd88b49a1404c2");
    assert_eq!(to_hex(&ks[64..80]), "3a3218fc0306b095a7e705df6cb03ffc");
    assert_eq!(to_hex(&ks[112..]), "e378be36e898db366a2d6f28555d76e1");
}

#[test]
fn t09_05_salsa20_in_version_4() {
    let h = inner(&inner_header(2, &s4(), &[])).unwrap();
    assert_eq!(h.stream, StreamAlgorithm::Salsa20);
    let mut ks = [0u8; 16];
    h.field_stream().unwrap().apply(&mut ks).unwrap();
    assert_eq!(
        ks,
        hex("0F 49 B2 BD 13 92 F3 03 C0 2E EF 12 4C D0 FD A0")[..]
    );
}

#[test]
fn t09_21_t09_22_t09_23_t09_24_bad_fields() {
    let key = field(2, &s4());
    assert_eq!(
        inner(&[field(1, &[3, 0]), key.clone(), vec![0; 5]].concat()).unwrap_err(),
        Error::Corrupt
    );
    for id in [1u32, 4] {
        assert_eq!(
            inner(&[field(1, &id.to_le_bytes()), key.clone(), vec![0; 5]].concat()).unwrap_err(),
            Error::Unsupported
        );
    }
    let ok = [field(1, &[3, 0, 0, 0]), key.clone()].concat();
    assert_eq!(
        inner(&[ok.clone(), hex("0300000000"), vec![0; 5]].concat()).unwrap_err(),
        Error::Corrupt
    );
    assert_eq!(inner(&ok).unwrap_err(), Error::Corrupt);
}

#[test]
fn t09_25_t13_25_huge_declared_length() {
    let u = [
        field(1, &[3, 0, 0, 0]),
        field(2, &s4()),
        hex("03 F0 FF FF FF 01 02 03 04 05 06"),
    ]
    .concat();
    assert_eq!(inner(&u).unwrap_err(), Error::TooLarge(Limit::Total));
    let u = [
        field(1, &[3, 0, 0, 0]),
        field(2, &s4()),
        hex("03 00 00 00 80 01 02 03"),
    ]
    .concat();
    assert_eq!(inner(&u).unwrap_err(), Error::TooLarge(Limit::Total));
}

#[test]
fn t09_26_t09_27_required_and_repeated_fields() {
    let f1 = field(1, &[3, 0, 0, 0]);
    let end = vec![0; 5];
    for u in [
        [f1.clone(), end.clone()].concat(),
        [field(2, &s4()), end.clone()].concat(),
        [f1.clone(), hex("0200000000"), end.clone()].concat(),
        [f1.clone(), field(2, &s4()), hex("0200000000"), end.clone()].concat(),
    ] {
        assert_eq!(inner(&u).unwrap_err(), Error::Corrupt);
    }
    let k2 = vec![0x77; 64];
    let h = inner(&[f1, field(2, &s4()), field(2, &k2), end].concat()).unwrap();
    assert_eq!(h.stream_key.expose(), k2.as_slice());
}

#[test]
fn t09_28_unknown_field_any_order() {
    let u = [
        hex("03 02 00 00 00 01 41"),
        field(1, &[3, 0, 0, 0]),
        hex("09 03 00 00 00 78 79 7A"),
        field(2, &s4()),
        hex("00 04 00 00 00 0D 0A 0D 0A"),
    ]
    .concat();
    let h = inner(&u).unwrap();
    assert_eq!((h.pool.len(), h.len), (1, u.len()));
    let d = Demo {
        inner: u,
        ..Demo::new()
    };
    assert_eq!(xml_of(open(&d.build(), "demo-pass")), DEMO_XML);
}

#[test]
fn t09_39_repeated_field_1() {
    let tail = [field(2, &s4()), vec![0; 5]].concat();
    let a = [
        hex("01 04 00 00 00 01 00 00 00 01 04 00 00 00 03 00 00 00"),
        tail.clone(),
    ]
    .concat();
    assert_eq!(inner(&a).unwrap_err(), Error::Unsupported);
    let b = [
        hex("01 02 00 00 00 03 00 01 04 00 00 00 03 00 00 00"),
        tail.clone(),
    ]
    .concat();
    assert_eq!(inner(&b).unwrap_err(), Error::Corrupt);
    let c = [
        hex("01 04 00 00 00 03 00 00 00 01 04 00 00 00 02 00 00 00"),
        tail,
    ]
    .concat();
    assert_eq!(inner(&c).unwrap().stream, StreamAlgorithm::Salsa20);
}

#[test]
fn t09_40_limit_before_truncation() {
    let lim = Limits { total: 4096, ..L };
    let head = [field(1, &[3, 0, 0, 0]), field(2, &s4())].concat();
    assert_eq!(head.len(), 78);
    let a = [head.clone(), hex("03 AD 0F 00 00 01 02 03 04 05 06")].concat();
    assert_eq!(read_inner(&a, &lim).unwrap_err(), Error::Corrupt);
    let b = [head, hex("03 AE 0F 00 00 01 02 03 04 05 06")].concat();
    assert_eq!(
        read_inner(&b, &lim).unwrap_err(),
        Error::TooLarge(Limit::Total)
    );
}

#[test]
fn t13_01_t13_02_pool_items() {
    let rec = hex("03 12 00 00 00 01 68 65 6C 6C 6F 20 61 74 74 61 63 68 6D 65 6E 74 0A");
    let u = [field(1, &[3, 0, 0, 0]), field(2, &s4()), rec, vec![0; 5]].concat();
    assert_eq!(
        &u[inner(&u).unwrap().pool[0].range.clone()],
        b"hello attachment\n"
    );
    let u = [
        field(1, &[3, 0, 0, 0]),
        field(2, &s4()),
        field(3, b"\x01A"),
        field(9, b"x"),
        field(3, b"\x01B"),
        vec![0; 5],
    ]
    .concat();
    let pool = inner(&u).unwrap().pool;
    assert_eq!(
        (&u[pool[0].range.clone()], &u[pool[1].range.clone()]),
        (&b"A"[..], &b"B"[..])
    );
}

#[test]
fn t13_03_t13_04_flags_and_empty_items() {
    let h = inner(&inner_header(
        3,
        &s4(),
        &[(0x00, b"a"), (0xFE, b"b"), (0x01, b"")],
    ))
    .unwrap();
    assert_eq!(
        h.pool
            .iter()
            .map(|i| (i.protected, i.range.len()))
            .collect::<Vec<_>>(),
        [(false, 1), (false, 1), (true, 0)]
    );
    let u = [
        field(1, &[3, 0, 0, 0]),
        field(2, &s4()),
        hex("03 00 00 00 00"),
        vec![0; 5],
    ]
    .concat();
    assert_eq!(inner(&u).unwrap_err(), Error::Corrupt);
}

#[test]
fn t13_24_t08_34_pool_item_count() {
    let items: Vec<(u8, &[u8])> = vec![(1, b""); 3];
    let lim = Limits { pool_items: 3, ..L };
    assert_eq!(
        read_inner(&inner_header(3, &s4(), &items), &lim)
            .unwrap()
            .pool
            .len(),
        3
    );
    let four: Vec<(u8, &[u8])> = vec![(1, b""); 4];
    assert_eq!(
        read_inner(&inner_header(3, &s4(), &four), &lim).unwrap_err(),
        Error::TooLarge(Limit::PoolItems)
    );
    let many: Vec<(u8, &[u8])> = vec![(1, b""); 1_000_001];
    assert_eq!(
        inner(&inner_header(3, &s4(), &many)).unwrap_err(),
        Error::TooLarge(Limit::PoolItems)
    );
}

#[test]
fn fmt_13_20_attachment_byte_limits() {
    let a = vec![0u8; 100];
    let lim = Limits {
        one_attachment: 99,
        ..L
    };
    assert_eq!(
        read_inner(&inner_header(3, &s4(), &[(1, &a)]), &lim).unwrap_err(),
        Error::TooLarge(Limit::OneAttachment)
    );
    let lim = Limits {
        all_attachments: 150,
        ..L
    };
    assert_eq!(
        read_inner(&inner_header(3, &s4(), &[(1, &a), (1, &a)]), &lim).unwrap_err(),
        Error::TooLarge(Limit::AllAttachments)
    );
    assert!(read_inner(&inner_header(3, &s4(), &[(1, &a)]), &lim).is_ok());
}

// ---------------------------------------------------------------------------
// E3 fix pass

#[test]
fn fmt_05_7_no_credentials_before_a_header_fault() {
    // Step 0 (credentials) comes before step 1 (header fields).
    let mut file = Demo::new().build();
    file[0x26] = 0x02; // compression 2: Unsupported at step 1
    assert_eq!(kind(open(&file, "demo-pass")), Error::Unsupported);
    assert_eq!(
        kind(open_creds(&file, &Credentials::default())),
        Error::NoCredentials
    );
    assert_eq!(
        kind(open_creds(&file[..20], &Credentials::default())),
        Error::NoCredentials
    );
}

#[test]
fn fmt_13_20_inner_header_exact_limits() {
    let a = vec![0u8; 100];
    let one = |n: usize| Limits {
        one_attachment: n,
        ..L
    };
    assert!(read_inner(&inner_header(3, &s4(), &[(1, &a)]), &one(100)).is_ok());
    assert_eq!(
        read_inner(&inner_header(3, &s4(), &[(1, &a)]), &one(99)).unwrap_err(),
        Error::TooLarge(Limit::OneAttachment)
    );
    let all = |n: usize| Limits {
        all_attachments: n,
        ..L
    };
    assert!(read_inner(&inner_header(3, &s4(), &[(1, &a), (1, &a)]), &all(200)).is_ok());
    assert_eq!(
        read_inner(&inner_header(3, &s4(), &[(1, &a), (1, &a)]), &all(199)).unwrap_err(),
        Error::TooLarge(Limit::AllAttachments)
    );
}

#[test]
fn xml_is_a_view_of_the_payload() {
    // The document is handed out without a copy; it is the bytes after the
    // inner header, with or without compression.
    for gzip in [true, false] {
        let d = Demo {
            gzip,
            ..Demo::new()
        };
        assert_eq!(opened(open(&d.build(), "demo-pass")).xml.bytes(), DEMO_XML);
    }
}
