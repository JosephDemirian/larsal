//! E3-S7 writer rows of the file layers: FMT-01, FMT-02, FMT-03, FMT-04,
//! FMT-05, FMT-06, FMT-08, FMT-09, FMT-17 and FMT-18. Each test names its
//! card row.

mod format_common;
mod write_common;

use app_crypto::cipher::Cipher;
use app_crypto::kdf::{AES_KDF_ID, ARGON2ID_ID, Argon2Type, KdfParams};
use app_crypto::secret::SecretBytes;
use app_format::header::{Compression, write_header};
use app_format::kdf_params::{MapEntry, parse_map, write_kdf, write_map};
use app_format::keys::{ChallengeResponse, Credentials, SlotMode, SoftwareKey};
use app_format::limits::{Limit, Limits};
use app_format::payload::probe;
use app_format::{Error, Opened, Saved, open, save};
use app_model::{Kdf, PublicItem};
use format_common::{Demo, DemoV3, argon2_map, field, hex, inner_header, s4};
use write_common::*;

/// H4min of FMT-02 (207 bytes).
fn h4min() -> Vec<u8> {
    hex(concat!(
        "03 D9 A2 9A 67 FB 4B B5 01 00 04 00 02 10 00 00",
        "00 31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A",
        "FF 03 04 00 00 00 01 00 00 00 04 20 00 00 00 11",
        "11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11",
        "11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 07",
        "10 00 00 00 22 22 22 22 22 22 22 22 22 22 22 22",
        "22 22 22 22 0B 5D 00 00 00 00 01 42 05 00 00 00",
        "24 55 55 49 44 10 00 00 00 C9 D9 F3 9A 62 8A 44",
        "60 BF 74 0D 08 C1 8A 4F EA 05 01 00 00 00 52 08",
        "00 00 00 40 42 0F 00 00 00 00 00 42 01 00 00 00",
        "53 20 00 00 00 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B",
        "4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B",
        "4B 4B 4B 4B 4B 00 00 04 00 00 00 0D 0A 0D 0A"
    ))
}

/// M3 of FMT-03 (70 bytes).
fn m3() -> Vec<u8> {
    hex(concat!(
        "00 01",
        "0C 03 00 00 00 43 44 31 04 00 00 00 7B 00 00 00",
        "08 03 00 00 00 43 44 32 01 00 00 00 01",
        "18 03 00 00 00 43 44 33 09 00 00 00 61 62 63 C3 A4 C3 B6 C3 BC",
        "42 03 00 00 00 43 44 34 05 00 00 00 AB AB A1 23 FF",
        "00"
    ))
}

fn m1() -> Vec<u8> {
    argon2_map(
        ARGON2ID_ID,
        2,
        64 << 20,
        4,
        &(0u8..32).collect::<Vec<u8>>(),
        0x13,
    )
}

fn aes(rounds: u64, seed: &[u8]) -> KdfParams {
    KdfParams::AesKdf {
        rounds,
        seed: seed.to_vec(),
    }
}

/// Header field ids in order, from offset 12.
fn field_ids(header: &[u8]) -> Vec<u8> {
    let mut pos = 12;
    let mut ids = Vec::new();
    loop {
        let id = header[pos];
        let len = u32::from_le_bytes(header[pos + 1..pos + 5].try_into().unwrap()) as usize;
        ids.push(id);
        if id == 0 {
            return ids;
        }
        pos += 5 + len;
    }
}

/// The data of header field `id`.
fn field_data(header: &[u8], id: u8) -> Option<Vec<u8>> {
    let mut pos = 12;
    loop {
        let f = header[pos];
        let len = u32::from_le_bytes(header[pos + 1..pos + 5].try_into().unwrap()) as usize;
        if f == id {
            return Some(header[pos + 5..pos + 5 + len].to_vec());
        }
        if f == 0 {
            return None;
        }
        pos += 5 + len;
    }
}

/// A version 4 demo file (password `demo-pass`) holding `xml`.
fn v4(xml: &str) -> Vec<u8> {
    Demo {
        xml: xml.as_bytes().to_vec(),
        ..Demo::new()
    }
    .build()
}

fn testdata(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../testdata/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

// -- FMT-01 -----------------------------------------------------------------

#[test]
fn fmt_01_16_write_order() {
    let mut v = cheap_vault(&g(""));
    let file = save_pw(&v, "demo-pass").bytes;
    let h = &file[..read_header_len(&file)];
    assert_eq!(field_ids(h), [2, 3, 4, 7, 11, 0]);
    assert_eq!(field_data(h, 0).unwrap(), [0x0D, 0x0A, 0x0D, 0x0A]);
    v.public_custom_data.push(PublicItem {
        kind: 0x04,
        name: b"n".to_vec(),
        value: vec![1, 0, 0, 0],
    });
    let file = save_pw(&v, "demo-pass").bytes;
    assert_eq!(
        field_ids(&file[..read_header_len(&file)]),
        [2, 3, 4, 7, 11, 12, 0]
    );
}

fn read_header_len(file: &[u8]) -> usize {
    app_format::header::read_header(file, &Limits::DEFAULT)
        .unwrap()
        .len
}

#[test]
fn fmt_01_20_app_never_writes_a_tail() {
    let mut file = testdata("rich-v4.appvault");
    let tail: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    file.extend_from_slice(&tail);
    let mut v = open_pw(&file, "demo-pass-5").vault;
    cheap(&mut v);
    let saved = save_pw(&v, "demo-pass").bytes;
    let last = &saved[saved.len() - 36..];
    assert_eq!(
        &last[32..],
        &[0, 0, 0, 0],
        "the last 36 bytes are a block of size 0"
    );
    assert!(!saved.windows(64).any(|w| w == &tail[..64]));
}

#[test]
fn fmt_01_23_read_and_write_set() {
    let file = DemoV3 {
        xml: g("").into_bytes(),
        ..DemoV3::new()
    }
    .build();
    let mut v = open_pw(&file, "demo-pass").vault;
    cheap(&mut v);
    let saved = save_pw(&v, "demo-pass");
    assert_eq!(saved.version.major, 4);
    assert_eq!(&saved.bytes[8..12], &[0, 0, 4, 0]);
}

#[test]
fn fmt_01_26_resave_keeps_the_variant() {
    let file = Demo {
        xml: g("").into_bytes(),
        ..Demo::new().with_cipher(Cipher::Twofish256Cbc)
    }
    .build();
    let first = open_pw(&file, "demo-pass");
    let saved = save_pw(&first.vault, "demo-pass").bytes;
    let back = open_pw(&saved, "demo-pass");
    let (a, b) = (&first.header, &back.header);
    assert_eq!((a.cipher, a.compression), (b.cipher, b.compression));
    assert_eq!(first.vault.encryption, back.vault.encryption);
    assert!(matches!(b.kdf, KdfParams::AesKdf { rounds: 1_000, .. }));
    assert_ne!(a.master_seed, b.master_seed);
    assert_ne!(a.iv, b.iv);
}

// -- FMT-02 -----------------------------------------------------------------

#[test]
fn c09_fmt_02_6_fmt_02_29() {
    let out = write_header(
        1,
        Cipher::Aes256Cbc,
        Compression::Gzip,
        &[0x11; 32],
        &[0x22; 16],
        &aes(1_000_000, &[0x4B; 32]),
        &[],
    )
    .unwrap();
    assert_eq!(out, h4min());
}

#[test]
fn c22_fmt_02_13() {
    let entries = parse_map(&m3()).unwrap();
    assert_eq!(entries.len(), 4);
    let out = write_header(
        1,
        Cipher::Aes256Cbc,
        Compression::Gzip,
        &[0x11; 32],
        &[0x22; 16],
        &aes(1_000_000, &[0x4B; 32]),
        &entries,
    )
    .unwrap();
    assert_eq!(field_ids(&out), [2, 3, 4, 7, 11, 12, 0]);
    assert_eq!(field_data(&out, 12).unwrap(), m3());
}

#[test]
fn c25_fmt_02_13() {
    let entries = parse_map(&hex("00 01 00")).unwrap();
    assert!(entries.is_empty());
    let out = write_header(
        1,
        Cipher::Aes256Cbc,
        Compression::Gzip,
        &[0x11; 32],
        &[0x22; 16],
        &aes(1_000_000, &[0x4B; 32]),
        &entries,
    )
    .unwrap();
    assert!(field_data(&out, 12).is_none());
}

#[test]
fn c37_fmt_02_21() {
    let comment = field(0x01, b"demo comment");
    let file = Demo {
        extra: vec![comment],
        xml: g("").into_bytes(),
        ..Demo::new()
    }
    .build();
    let saved = resave(&file);
    assert!(!field_ids(&saved[..read_header_len(&saved)]).contains(&1));
}

#[test]
fn c51_fmt_02_29() {
    let v = cheap_vault(&g(""));
    let a = save_pw(&v, "demo-pass").bytes;
    let b = save_pw(&v, "demo-pass").bytes;
    let (ha, hb) = (&a[..read_header_len(&a)], &b[..read_header_len(&b)]);
    for id in [4u8, 7, 11] {
        assert_ne!(field_data(ha, id), field_data(hb, id), "field {id}");
    }
    assert_eq!(field_data(ha, 4).unwrap().len(), 32);
    assert_eq!(field_data(ha, 7).unwrap().len(), 16);
    let p = parts(&a, "demo-pass");
    assert_eq!(salt_of(&p.header).len(), 32);
}

// -- FMT-03 -----------------------------------------------------------------

#[test]
fn d05_fmt_03_21() {
    let p = KdfParams::Argon2 {
        kind: Argon2Type::Id,
        version: 0x13,
        iterations: 2,
        memory_kib: 65_536,
        lanes: 4,
        salt: (0u8..32).collect(),
    };
    let out = write_kdf(&p).unwrap();
    assert_eq!(out.len(), 139);
    assert_eq!(out, m1());
}

#[test]
fn d06_fmt_03_21() {
    let out = write_kdf(&aes(1_000_000, &[0x4B; 32])).unwrap();
    assert_eq!(out.len(), 93);
    assert_eq!(out, h4min()[0x69..0xC6].to_vec());
    assert_eq!(&out[16..32], &AES_KDF_ID);
}

#[test]
fn d10_fmt_03_22() {
    let e = parse_map(&m3()).unwrap();
    assert_eq!(write_map(&e).unwrap(), m3());
}

#[test]
fn d20_fmt_03_22() {
    let m = hex("00 01 04 00 00 00 00 04 00 00 00 01 00 00 00 00");
    assert_eq!(write_map(&parse_map(&m).unwrap()).unwrap(), m);
}

#[test]
fn d23_fmt_03_22() {
    let e = parse_map(&hex("00 01 00")).unwrap();
    let out = write_header(
        1,
        Cipher::Aes256Cbc,
        Compression::Gzip,
        &[0x11; 32],
        &[0x22; 16],
        &aes(1_000_000, &[0x4B; 32]),
        &e,
    )
    .unwrap();
    assert!(field_data(&out, 12).is_none());
}

#[test]
fn d31_fmt_03_13() {
    let mut m = m1();
    m[60..68].copy_from_slice(&hex("05 00 10 00 00 00 00 00"));
    let p = app_format::kdf_params::parse_kdf(&m).unwrap();
    assert!(matches!(
        p,
        KdfParams::Argon2 {
            memory_kib: 1_024,
            ..
        }
    ));
    let out = write_kdf(&p).unwrap();
    assert_eq!(&out[60..68], &hex("00 00 10 00 00 00 00 00")[..]);
}

#[test]
fn d45_fmt_03_19() {
    let mut m = m1();
    m.splice(138..138, hex("04 01 00 00 00 58 04 00 00 00 07 00 00 00"));
    let p = app_format::kdf_params::parse_kdf(&m).unwrap();
    assert_eq!(write_kdf(&p).unwrap(), m1());
}

#[test]
fn d47_fmt_03_22() {
    let input = hex(
        "00 01 05 04 00 00 00 7A 65 74 61 08 00 00 00 05 00 00 00 00 00 00 00 04 05 00 00 00 41 6C 70 68 61 04 00 00 00 01 00 00 00 0D 04 00 00 00 62 65 74 61 08 00 00 00 FE FF FF FF FF FF FF FF 18 02 00 00 00 5F 78 00 00 00 00 00",
    );
    let want = hex(
        "00 01 04 05 00 00 00 41 6C 70 68 61 04 00 00 00 01 00 00 00 18 02 00 00 00 5F 78 00 00 00 00 0D 04 00 00 00 62 65 74 61 08 00 00 00 FE FF FF FF FF FF FF FF 05 04 00 00 00 7A 65 74 61 08 00 00 00 05 00 00 00 00 00 00 00 00",
    );
    assert_eq!(write_map(&parse_map(&input).unwrap()).unwrap(), want);
}

#[test]
fn d48_fmt_03_23() {
    let m = hex(
        "00 01 42 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 55 55 49 44 10 00 00 00 A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF 00",
    );
    let e = parse_map(&m).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(write_map(&e).unwrap(), m);
}

/// The sorted field 12 of D50 (100 bytes).
fn d50_sorted() -> Vec<u8> {
    hex(
        "00 01 18 11 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 43 4F 4C 4F 52 07 00 00 00 23 31 61 32 62 33 63 0C 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 49 43 4F 4E 04 00 00 00 05 00 00 00 18 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 4E 41 4D 45 0A 00 00 00 44 65 6D 6F 20 76 61 75 6C 74 00",
    )
}

#[test]
fn d50_fmt_03_23() {
    let sorted = parse_map(&d50_sorted()).unwrap();
    assert_eq!(d50_sorted().len(), 100);
    // The input order of the row: name, icon, colour.
    let unsorted: Vec<MapEntry> = vec![sorted[2].clone(), sorted[1].clone(), sorted[0].clone()];
    assert_eq!(write_map(&unsorted).unwrap(), d50_sorted());
}

#[test]
fn d51_fmt_03_21() {
    let mut m = m1();
    m[134] = 0x10;
    let p = app_format::kdf_params::parse_kdf(&m).unwrap();
    assert!(matches!(p, KdfParams::Argon2 { version: 0x10, .. }));
    let model = app_format::header::encryption_of(&header_with_kdf(&p));
    let (_, _, out) = app_format::header::header_settings(&model, (0u8..32).collect());
    assert_eq!(write_kdf(&out).unwrap(), m1(), "written as 0x13 (LD-17)");
    // A save derives with version 1.3: the saved file opens with it.
    let mut v = cheap_vault(&g(""));
    v.encryption.kdf = Kdf::Argon2 {
        kind: app_model::Argon2Kind::Id,
        iterations: 1,
        memory_kib: 8,
        lanes: 1,
    };
    let saved = save_pw(&v, "demo-pass").bytes;
    assert!(matches!(
        open_pw(&saved, "demo-pass").header.kdf,
        KdfParams::Argon2 { version: 0x13, .. }
    ));
}

/// A parsed H4min header with its KDF replaced.
fn header_with_kdf(p: &KdfParams) -> app_format::header::Header {
    let mut h = app_format::header::read_header(&h4min(), &Limits::DEFAULT).unwrap();
    h.kdf = p.clone();
    h
}

#[test]
fn d52_fmt_03_8() {
    let m = hex("00 01 08 01 00 00 00 42 01 00 00 00 02 00");
    assert_eq!(write_map(&parse_map(&m).unwrap()).unwrap(), m);
}

#[test]
fn d54_fmt_03_23() {
    let m = hex(
        "00 01 18 11 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 43 4F 4C 4F 52 09 00 00 00 23 31 61 32 62 33 63 3B 7D 18 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 49 43 4F 4E 01 00 00 00 35 18 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 4E 41 4D 45 08 00 00 00 3C 62 3E 78 3C 2F 62 3E 00",
    );
    let file = Demo {
        extra: vec![field(12, &m)],
        xml: g("").into_bytes(),
        ..Demo::new()
    }
    .build();
    let saved = resave(&file);
    assert_eq!(
        field_data(&saved[..read_header_len(&saved)], 12).unwrap(),
        m
    );
}

#[test]
fn d55_fmt_03_21() {
    let short = argon2_map(
        ARGON2ID_ID,
        2,
        64 << 20,
        4,
        &(0u8..16).collect::<Vec<u8>>(),
        0x13,
    );
    assert_eq!(short.len(), 123);
    let p = app_format::kdf_params::parse_kdf(&short).unwrap();
    let model = app_format::header::encryption_of(&header_with_kdf(&p));
    let (_, _, out) = app_format::header::header_settings(&model, (0u8..32).collect());
    assert_eq!(write_kdf(&out).unwrap(), m1());
}

#[test]
fn d58_fmt_03_23() {
    // The colour picker is E4 (MOD-12); it stores `#rrggbb` lowercase as a
    // String, and the writer writes it as D50 shows.
    let name: Vec<u8> = hex("4B 50 58 43 5F 50 55 42 4C 49 43 5F 43 4F 4C 4F 52");
    let colour = format!("#{:02x}{:02x}{:02x}", 0x1A, 0x2B, 0x3C);
    let e = MapEntry {
        kind: 0x18,
        name,
        value: colour.into_bytes(),
    };
    let out = write_map(&[e]).unwrap();
    assert!(out.windows(7).any(|w| w == hex("23 31 61 32 62 33 63")));
}

// -- FMT-04 -----------------------------------------------------------------

#[test]
fn fmt_04_16_a_no_credentials() {
    let v = cheap_vault(&g(""));
    let _ = probe::take();
    let r = save(
        &v,
        &Credentials::default(),
        None,
        &mut host(),
        &Limits::DEFAULT,
        None,
    );
    assert_eq!(r.unwrap_err(), Error::NoCredentials);
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn fmt_04_17_a_fresh_keys() {
    let v = cheap_vault(&g(""));
    let a = save_pw(&v, "demo-pass");
    let b = save_pw(&v, "demo-pass");
    let (pa, pb) = (parts(&a.bytes, "demo-pass"), parts(&b.bytes, "demo-pass"));
    assert_ne!(pa.header.master_seed, pb.header.master_seed);
    assert_ne!(salt_of(&pa.header), salt_of(&pb.header));
    assert_ne!(pa.raw, pb.raw);
    open_pw(&a.bytes, "demo-pass");
    open_pw(&b.bytes, "demo-pass");
    // A 16-byte Argon2 salt read is written as 32 bytes (LD-15).
    let file = Demo {
        kdf_map: argon2_map(ARGON2ID_ID, 1, 8 << 10, 1, &[7; 16], 0x13),
        xml: g("").into_bytes(),
        ..Demo::new()
    }
    .build();
    let back = open_pw(&file, "demo-pass");
    assert_eq!(salt_of(&back.header).len(), 16);
    let saved = save_pw(&back.vault, "demo-pass").bytes;
    assert_eq!(salt_of(&open_pw(&saved, "demo-pass").header).len(), 32);
}

#[test]
fn fmt_04_17_b_key_file_changed_on_disk() {
    let dir = std::env::temp_dir().join(format!("app-write-17b-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("demo.appkey");
    std::fs::write(&path, [0x41u8; 32]).unwrap();
    let read = |p: &std::path::Path| {
        app_format::keyfile::read_key_file(std::fs::File::open(p).unwrap(), &Limits::DEFAULT)
            .unwrap()
    };
    let h = read(&path);
    let v = cheap_vault(&g(""));
    let creds = Credentials {
        key_file: Some(&h),
        ..Default::default()
    };
    let Saved::File(saved) = save(&v, &creds, None, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!()
    };
    std::fs::write(&path, [0x42u8; 32]).unwrap();
    let changed = read(&path);
    let with = |k: &app_format::keyfile::KeyFileKey| {
        open(
            &saved.bytes,
            &Credentials {
                key_file: Some(k),
                ..Default::default()
            },
            &mut host(),
            &Limits::DEFAULT,
            None,
        )
    };
    assert!(matches!(with(&h), Ok(Opened::Vault(_))));
    assert_eq!(with(&changed).unwrap_err(), Error::WrongKey);
    std::fs::remove_dir_all(&dir).ok();
}

/// A hardware key that is gone.
struct Removed;
impl ChallengeResponse for Removed {
    fn challenge(&self, _: &[u8; 64]) -> Result<SecretBytes, app_format::error::HardwareKeyReason> {
        Err(app_format::error::HardwareKeyReason::Missing)
    }
}

#[test]
fn fmt_04_17_c_hardware_key_removed() {
    let v = cheap_vault(&g(""));
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        hardware_key: Some(&Removed),
        ..Default::default()
    };
    let r = save(&v, &creds, None, &mut host(), &Limits::DEFAULT, None);
    assert_eq!(
        r.unwrap_err(),
        Error::HardwareKey(app_format::error::HardwareKeyReason::Missing)
    );
}

#[test]
fn fmt_04_18_a_version_3_hardware_key_moves_into_the_composite() {
    let secret = b"demo hardware secret".to_vec();
    let file = DemoV3 {
        hardware: Some(secret.clone()),
        xml: g("").into_bytes(),
        ..DemoV3::new()
    }
    .build();
    let key = SoftwareKey {
        secret: SecretBytes::new(secret),
        mode: SlotMode::Variable,
    };
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        hardware_key: Some(&key),
        ..Default::default()
    };
    let Ok(Opened::Vault(first)) = open(&file, &creds, &mut host(), &Limits::DEFAULT, None) else {
        panic!("the version 3 vault opens")
    };
    let mut v = first.vault;
    cheap(&mut v);
    let Saved::File(saved) = save(&v, &creds, None, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!()
    };
    let h = app_format::header::read_header(&saved.bytes, &Limits::DEFAULT).unwrap();
    assert_eq!((h.major, salt_of(&h).len()), (4, 32));
    assert!(matches!(
        open(&saved.bytes, &creds, &mut host(), &Limits::DEFAULT, None),
        Ok(Opened::Vault(_))
    ));
    let no_key = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    assert_eq!(
        open(&saved.bytes, &no_key, &mut host(), &Limits::DEFAULT, None).unwrap_err(),
        Error::WrongKey
    );
}

#[test]
fn fmt_04_19_a_no_key_in_debug_output() {
    let v = cheap_vault(&g(&entry(0x10, &s("Password", "demo-secret-1"))));
    let saved = save_pw(&v, "demo-pass");
    let text = format!("{saved:?} {:?}", saved.key);
    assert!(!text.contains("demo-secret-1") && !text.contains("demo-pass"));
    assert!(text.contains("[hidden]"));
}

// -- FMT-05 -----------------------------------------------------------------

#[test]
fn fmt_05_9_write() {
    let v = cheap_vault(&g(""));
    let file = save_pw(&v, "demo-pass").bytes;
    let h = read_header_len(&file);
    assert_eq!(
        &file[h..h + 32],
        app_crypto::hash::sha256(&[&file[..h]]).expose()
    );
    // The HMAC with this file's own S and T, from the card formulas.
    let p = parts(&file, "demo-pass");
    let kdf_map = write_kdf(&p.header.kdf).unwrap();
    let t =
        format_common::transformed(&kdf_map, &app_format::keys::password_part(&pw("demo-pass")));
    let keys = app_format::keys::final_keys(&p.header.master_seed, &t);
    assert_eq!(
        &file[h + 32..h + 64],
        app_format::integrity::header_hmac(&keys.hmac_key, &file[..h]).expose()
    );
}

#[test]
fn fmt_05_9_no_header_hash_element_in_version_4() {
    let file = save_pw(&cheap_vault(&g("")), "demo-pass").bytes;
    assert!(!saved_doc(&file, "demo-pass").contains("HeaderHash"));
}

#[test]
fn fmt_05_9_header_hash_element_ignored_in_version_4() {
    let xml = doc(
        "<HeaderHash>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</HeaderHash>",
        &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
    );
    let saved = resave(&v4(&xml));
    assert!(!saved_doc(&saved, "demo-pass").contains("HeaderHash"));
}

// -- FMT-06 -----------------------------------------------------------------

#[test]
fn fmt_06_1_position_in_any_file() {
    let file = save_pw(&cheap_vault(&g("")), "demo-pass").bytes;
    let h = read_header_len(&file);
    let mut pos = h + 64;
    loop {
        let size = u32::from_le_bytes(file[pos + 32..pos + 36].try_into().unwrap()) as usize;
        pos += 36 + size;
        if size == 0 {
            break;
        }
    }
    assert_eq!(pos, file.len(), "the final block ends at the last byte");
}

#[test]
fn fmt_06_8_writer_sizes_in_a_save() {
    // One byte over a block: 1 MiB + 1 of payload gives blocks of 1 MiB,
    // then the rest, then the final block (FMT-06.8).
    let mut v = cheap_vault(&g(&entry(0x10, "")));
    v.encryption.compression = app_model::Compression::None;
    v.root.entries[0].attachments.push(app_model::Attachment {
        name: "big".into(),
        data: std::sync::Arc::new(SecretBytes::new(vec![0x5A; 1_500_000])),
    });
    let file = save_pw(&v, "demo-pass").bytes;
    let mut pos = read_header_len(&file) + 64;
    let mut sizes = Vec::new();
    loop {
        let size = u32::from_le_bytes(file[pos + 32..pos + 36].try_into().unwrap()) as usize;
        sizes.push(size);
        pos += 36 + size;
        if size == 0 {
            break;
        }
    }
    assert_eq!(sizes.len(), 3);
    assert_eq!(sizes[0], 1 << 20);
    assert!(sizes[1] > 0 && sizes[2] == 0);
}

#[test]
fn fmt_06_12_sync_tool_leftovers_then_save() {
    let clean = v4(&g(&entry(0x10, &s("Title", "T"))));
    for n in [1usize, 16, 4096] {
        let mut f = clean.clone();
        f.extend(std::iter::repeat_n(0xA5u8, n));
        assert_eq!(
            open_pw(&f, "demo-pass").vault,
            open_pw(&clean, "demo-pass").vault
        );
        let saved = resave(&f);
        let last = &saved[saved.len() - 36..];
        assert_eq!(&last[32..], &[0, 0, 0, 0]);
        assert!(!saved.ends_with(&[0xA5; 4]));
    }
}

// -- FMT-08 -----------------------------------------------------------------

#[test]
fn t08_18_fmt_08_9_gzip_on_write() {
    let file = save_pw(&cheap_vault(&g("")), "demo-pass").bytes;
    let p = parts(&file, "demo-pass");
    assert_eq!(
        &p.raw[..10],
        &[0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13]
    );
    assert_eq!(p.header.compression, Compression::Gzip);
    assert_eq!(p.inner_and_doc[0], 0x01);
}

#[test]
fn t08_19_fmt_08_10_compression_off() {
    let mut v = cheap_vault(&g(""));
    v.encryption.compression = app_model::Compression::None;
    let file = save_pw(&v, "demo-pass").bytes;
    let h = &file[..read_header_len(&file)];
    assert_eq!(field_data(h, 3).unwrap(), [0, 0, 0, 0]);
    assert_eq!(parts(&file, "demo-pass").raw[0], 0x01);
}

#[test]
fn t08_35_fmt_08_12_save_over_a_limit() {
    let mut v = cheap_vault(&g(&entry(0x10, "")));
    v.root.entries[0].attachments.push(app_model::Attachment {
        name: "big".into(),
        data: std::sync::Arc::new(SecretBytes::new(vec![0; 2 << 20])),
    });
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    let lim = Limits {
        total: 1 << 20,
        ..Limits::DEFAULT
    };
    let r = save(&v, &creds, None, &mut host(), &lim, None);
    assert_eq!(r.unwrap_err(), Error::TooLarge(Limit::Total));
}

// -- FMT-09 -----------------------------------------------------------------

#[test]
fn t09_02_fmt_09_4_inner_header_on_write() {
    let v = cheap_vault(&g(""));
    let (a, b) = (
        save_pw(&v, "demo-pass").bytes,
        save_pw(&v, "demo-pass").bytes,
    );
    for f in [&a, &b] {
        let u = parts(f, "demo-pass").inner_and_doc;
        assert_eq!(
            &u[..14],
            &hex("01 04 00 00 00 03 00 00 00 02 40 00 00 00")[..]
        );
        assert_eq!(&u[78..83], &[0, 0, 0, 0, 0]);
    }
    assert_ne!(
        saved_stream_key(&a, "demo-pass"),
        saved_stream_key(&b, "demo-pass")
    );
}

const FOOBAR_PW: &str = "<FooBar Protected=\"True\">QUJD</FooBar><String><Key>Password</Key><Value Protected=\"True\">/J+RDmSl</Value></String>";

#[test]
fn t09_15_fmt_09_14_kept_raw_on_save() {
    let file = v4(&g(&entry(0x10, FOOBAR_PW)));
    let first = open_pw(&file, "demo-pass");
    assert_eq!(first.vault.root.entries[0].value("Password"), "pw-one");
    let saved = resave(&file);
    let d = saved_doc(&saved, "demo-pass");
    assert!(d.contains("\t\t\t\t<FooBar Protected=\"True\">QUJD</FooBar>\n"));
    let key = saved_stream_key(&saved, "demo-pass");
    let b64 = d
        .split("<Key>Password</Key>")
        .nth(1)
        .unwrap()
        .split("Protected=\"True\">")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap();
    assert_eq!(dec(&key, 0, b64), b"pw-one");
    assert_eq!(
        open_pw(&saved, "demo-pass").vault.root.entries[0].value("Password"),
        "pw-one"
    );
}

#[test]
fn t09_28_fmt_09_3_unknown_inner_field() {
    let mut inner = field(3, b"\x01AAA");
    inner.extend(field(1, &[3, 0, 0, 0]));
    inner.extend(hex("09 03 00 00 00 78 79 7A"));
    inner.extend(field(2, &s4()));
    inner.extend(field(0, &[0x0D, 0x0A, 0x0D, 0x0A]));
    let file = Demo {
        inner,
        xml: g("").into_bytes(),
        ..Demo::new()
    }
    .build();
    let saved = resave(&file);
    let ids = saved_inner_ids(&saved, "demo-pass");
    assert!(!ids.contains(&9));
    let u = parts(&saved, "demo-pass").inner_and_doc;
    let end = inner_len(&u);
    assert_eq!(&u[end - 5..end], &[0, 0, 0, 0, 0]);
}

#[test]
fn t09_30_fmt_09_19_new_vault_protection() {
    let mut v = app_model::Vault::new(app_model::Group::new(id(1), "R".into(), SAVE), SAVE);
    cheap(&mut v);
    let mut e = app_model::Entry::new(id(0x10), SAVE);
    e.set_field(
        "Title".into(),
        app_model::Field {
            value: app_crypto::secret::SecretString::new("t".into()),
            protected: false,
        },
    );
    e.set_field(
        "Custom".into(),
        app_model::Field {
            value: app_crypto::secret::SecretString::new("c".into()),
            protected: true,
        },
    );
    e.set_field(
        "Password".into(),
        app_model::Field {
            value: app_crypto::secret::SecretString::new("p".into()),
            protected: false,
        },
    );
    v.root.entries.push(e);
    let d = saved_doc(&save_pw(&v, "demo-pass").bytes, "demo-pass");
    let value = |k: &str| {
        d.split(&format!("<Key>{k}</Key>"))
            .nth(1)
            .unwrap()
            .lines()
            .nth(1)
            .unwrap()
            .trim()
            .to_owned()
    };
    assert!(value("Password").starts_with("<Value Protected=\"True\">"));
    assert!(value("Custom").starts_with("<Value Protected=\"True\">"));
    for k in ["Title", "URL", "UserName", "Notes"] {
        assert!(!value(k).contains("Protected"), "{k}");
    }
}

#[test]
fn t09_31_fmt_09_19_own_flag_on_save() {
    let xml = doc(
        "<MemoryProtection><ProtectNotes>False</ProtectNotes></MemoryProtection>",
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(
                0x10,
                &format!(
                    "<String><Key>Notes</Key><Value Protected=\"True\">{}</Value></String>",
                    enc(&s4(), 0, b"n")
                )
            )
        ),
    );
    let d = saved_doc(&resave(&v4(&xml)), "demo-pass");
    assert!(d.contains("<Key>Notes</Key>\n\t\t\t\t\t<Value Protected=\"True\">"));
}

#[test]
fn t09_37_fmt_09_14_unknown_with_child() {
    let pw_xml = "<FooBar><Value Protected=\"True\">QUJD</Value></FooBar><String><Key>Password</Key><Value Protected=\"True\">/J+RDmSl</Value></String>";
    let file = v4(&g(&entry(0x10, pw_xml)));
    assert_eq!(
        open_pw(&file, "demo-pass").vault.root.entries[0].value("Password"),
        "pw-one"
    );
    let saved = resave(&file);
    let d = saved_doc(&saved, "demo-pass");
    assert!(d.contains(
        "\t\t\t\t<FooBar>\n\t\t\t\t\t<Value Protected=\"True\">QUJD</Value>\n\t\t\t\t</FooBar>\n"
    ));
    assert_eq!(
        open_pw(&saved, "demo-pass").vault.root.entries[0].value("Password"),
        "pw-one"
    );
}

// -- FMT-17 and FMT-18 ------------------------------------------------------

#[test]
fn fmt_17_24_app_never_writes_3x() {
    let file = testdata("password-only.appvault");
    let first = open_pw(&file, "demo-pass-1");
    let KdfParams::AesKdf { rounds, seed } = &first.header.kdf else {
        panic!()
    };
    let (rounds, seed) = (*rounds, seed.clone());
    let saved = save_pw(&first.vault, "demo-pass-1");
    assert_eq!(&saved.bytes[8..12], &[0, 0, 4, 0], "version 4.0");
    let h = app_format::header::read_header(&saved.bytes, &Limits::DEFAULT).unwrap();
    assert!(h.v3.is_none());
    let KdfParams::AesKdf {
        rounds: r2,
        seed: s2,
    } = &h.kdf
    else {
        panic!("AES-KDF")
    };
    assert_eq!(*r2, rounds);
    assert_eq!(s2.len(), 32);
    assert_ne!(*s2, seed);
    let map = field_data(&saved.bytes[..h.len], 11).unwrap();
    assert_eq!(&map[16..32], &AES_KDF_ID);
}

#[test]
fn fmt_18_25_a_key_file_untouched_by_saves() {
    let dir = std::env::temp_dir().join(format!("app-write-1825-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("demo.appkey");
    std::fs::write(&path, [0x41u8; 64]).unwrap();
    let before = (
        std::fs::read(&path).unwrap(),
        std::fs::metadata(&path).unwrap().modified().unwrap(),
    );
    let key =
        app_format::keyfile::read_key_file(std::fs::File::open(&path).unwrap(), &Limits::DEFAULT)
            .unwrap();
    let v = cheap_vault(&g(""));
    let creds = Credentials {
        key_file: Some(&key),
        ..Default::default()
    };
    let mut file = Vec::new();
    for _ in 0..3 {
        let Saved::File(f) = save(&v, &creds, None, &mut host(), &Limits::DEFAULT, None).unwrap()
        else {
            panic!()
        };
        file = f.bytes;
    }
    assert!(matches!(
        open(&file, &creds, &mut host(), &Limits::DEFAULT, None),
        Ok(Opened::Vault(_))
    ));
    let after = (
        std::fs::read(&path).unwrap(),
        std::fs::metadata(&path).unwrap().modified().unwrap(),
    );
    assert_eq!(before, after);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inner_header_helper_matches_the_writer() {
    // The test builder's inner header and App's writer agree on layout.
    let v = cheap_vault(&g(""));
    let f = save_pw(&v, "demo-pass").bytes;
    let key = saved_stream_key(&f, "demo-pass");
    let u = parts(&f, "demo-pass").inner_and_doc;
    assert_eq!(&u[..inner_len(&u)], &inner_header(3, &key, &[])[..]);
}

#[test]
fn fmt_08_12_save_runs_the_reader_limits() {
    // App never writes what it would refuse to read: each limit the reader
    // checks stops the save, naming it, and nothing is returned.
    let v = cheap_vault(&g(&format!(
        "<Group><UUID>{}</UUID></Group>{}",
        idt(2),
        entry(0x10, &s("Title", "abcdef"))
    )));
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    let try_with = |lim: Limits| save(&v, &creds, None, &mut host(), &lim, None).unwrap_err();
    assert_eq!(
        try_with(Limits {
            groups: 1,
            ..Limits::DEFAULT
        }),
        Error::TooLarge(Limit::Groups)
    );
    assert_eq!(
        try_with(Limits {
            text: 5,
            ..Limits::DEFAULT
        }),
        Error::TooLarge(Limit::Text)
    );
    assert_eq!(
        try_with(Limits {
            model: 1_000,
            ..Limits::DEFAULT
        }),
        Error::TooLarge(Limit::Model)
    );
    assert_eq!(
        try_with(Limits {
            document: 100,
            ..Limits::DEFAULT
        }),
        Error::TooLarge(Limit::Document)
    );
    let mut big = cheap_vault(&g(""));
    big.public_custom_data.push(PublicItem {
        kind: 0x42,
        name: b"b".to_vec(),
        value: vec![0; 2_000],
    });
    let r = save(
        &big,
        &creds,
        None,
        &mut host(),
        &Limits {
            header: 1_024,
            ..Limits::DEFAULT
        },
        None,
    );
    assert_eq!(r.unwrap_err(), Error::TooLarge(Limit::Header));
    assert!(matches!(
        save(&v, &creds, None, &mut host(), &Limits::DEFAULT, None),
        Ok(Saved::File(_))
    ));
}

#[test]
fn t09_43_fmt_09_17_leading_byte_order_mark() {
    // One extra EF BB BF before a value that starts with U+FEFF, so both
    // apps read it back unchanged (FMT-09.17, FMT-09.15).
    let mut v = read_doc(&g(&entry(0x10, "")));
    v.root.entries[0].set_field(
        "Password".into(),
        app_model::Field {
            value: app_crypto::secret::SecretString::new("\u{FEFF}A".into()),
            protected: true,
        },
    );
    let xml = write_with(&v, &s4());
    assert!(
        xml.contains(
            "<Key>Password</Key>\n\t\t\t\t\t<Value Protected=\"True\">Y1MDjrF/Hg==</Value>"
        )
    );
    assert_eq!(
        dec(&s4(), 0, "Y1MDjrF/Hg=="),
        [0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF, 0x41]
    );
    assert_eq!(
        read_with(&xml, &s4(), &[]).root.entries[0].value("Password"),
        "\u{FEFF}A"
    );
}

#[test]
fn fmt_08_12_save_checks_header_and_file_size() {
    // App never writes what it would refuse to read (FMT-02.25, FMT-01.31).
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    let mut big = cheap_vault(&g(""));
    big.public_custom_data.push(PublicItem {
        kind: 0x42,
        name: b"b".to_vec(),
        value: vec![0; 2_000],
    });
    // Both over: the header check comes first.
    let lim = Limits {
        header: 1_024,
        total_file: 2_000,
        ..Limits::DEFAULT
    };
    assert_eq!(
        save(&big, &creds, None, &mut host(), &lim, None).unwrap_err(),
        Error::TooLarge(Limit::Header)
    );
    // Only the file over: `total file`.
    let small = cheap_vault(&g(""));
    let size = save_pw(&small, "demo-pass").bytes.len();
    let lim = Limits {
        total_file: 1_000,
        ..Limits::DEFAULT
    };
    assert!(
        size > 1_000 + 128 * 2,
        "the test file is well over the lowered limit"
    );
    assert_eq!(
        save(&small, &creds, None, &mut host(), &lim, None).unwrap_err(),
        Error::TooLarge(Limit::TotalFile)
    );
    // A header App would refuse to read (a UInt32 item of 3 bytes) is never
    // written: the final read of the header stops it.
    let mut odd = cheap_vault(&g(""));
    odd.public_custom_data.push(PublicItem {
        kind: 0x04,
        name: b"u".to_vec(),
        value: vec![1, 2, 3],
    });
    assert_eq!(
        save(&odd, &creds, None, &mut host(), &Limits::DEFAULT, None).unwrap_err(),
        Error::Corrupt
    );
}

#[test]
fn cry_02_14_save_over_the_refuse_ceiling() {
    let mut v = cheap_vault(&g(""));
    v.encryption.kdf = Kdf::Argon2 {
        kind: app_model::Argon2Kind::Id,
        iterations: 1_000_000_001,
        memory_kib: 8,
        lanes: 1,
    };
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    let _ = probe::take();
    let r = save(&v, &creds, None, &mut host(), &Limits::DEFAULT, None);
    assert_eq!(r.unwrap_err(), Error::TooLarge(Limit::KdfCost));
    assert_eq!(probe::take().kdf, 0);
}

#[test]
fn save_refuses_a_broken_model() {
    // Two live entries sharing an id break an invariant: `Corrupt`, before
    // any key work.
    let mut v = cheap_vault(&g(&format!("{}{}", entry(0x10, ""), entry(0x11, ""))));
    v.root.entries[1].uuid = id(0x10);
    let _ = probe::take();
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    assert_eq!(
        save(&v, &creds, None, &mut host(), &Limits::DEFAULT, None).unwrap_err(),
        Error::Corrupt
    );
    assert_eq!(probe::take().kdf, 0);
}
