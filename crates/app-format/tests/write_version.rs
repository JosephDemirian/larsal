//! E3-S7 writer rows of FMT-16 (the version App writes) and CRY-03 (fresh
//! random values on every save, AT-B03). Each test names its card row.

mod format_common;
mod write_common;

use app_crypto::cipher::Cipher;
use app_crypto::kdf::{AES_KDF_ID, ARGON2D_ID, ARGON2ID_ID, KdfParams};
use app_crypto::secret::SecretBytes;
use app_format::document::write::{self, PADDING_KEY};
use app_format::keys::{ChallengeResponse, Credentials, SlotMode, SoftwareKey};
use app_format::limits::Limits;
use app_format::payload::probe;
use app_format::{Error, Opened, Saved, open, save};
use app_model::{CustomDataItem, FileVersion, Time, Vault};
use format_common::{Demo, DemoV3, argon2_map, field};
use std::collections::HashSet;
use write_common::*;

fn testdata(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../testdata/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// A version 4 demo file (password `demo-pass`) with header minor `minor`.
fn v4(xml: &str, minor: u16) -> Vec<u8> {
    Demo {
        minor,
        xml: xml.as_bytes().to_vec(),
        ..Demo::new()
    }
    .build()
}

fn saved_version(file: &[u8]) -> (u16, u16) {
    let h = app_format::header::read_header(file, &Limits::DEFAULT).unwrap();
    (h.major, h.minor)
}

fn item(key: &str, value: &str, t: Option<Time>) -> CustomDataItem {
    CustomDataItem {
        key: key.into(),
        value: value.into(),
        last_modified: t,
        unknown: Vec::new(),
    }
}

// -- FMT-16 -----------------------------------------------------------------

#[test]
fn fmt_16_10_app_any_time_counts() {
    for (text, want) in [
        ("", "AAAAAAAAAAA="),
        ("sflu4g4AAAA=", "sflu4g4AAAA="),
        ("/////////38=", "/////////38="),
    ] {
        let meta = format!(
            "<CustomIcons><Icon><UUID>{}</UUID><LastModificationTime>{text}</LastModificationTime><Data>AA==</Data></Icon></CustomIcons>",
            idt(0xA1)
        );
        let v = read_doc(&doc(
            &meta,
            &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
        ));
        assert_eq!(write::minor_version(&v), 1, "{text:?}");
        let xml = write_doc(&v);
        assert!(
            xml.contains(&format!(
                "<LastModificationTime>{want}</LastModificationTime>"
            )),
            "{text:?}"
        );
    }
}

#[test]
fn fmt_16_13_group_and_entry_item_times() {
    let mut v = cheap_vault(&g(&entry(0x10, "")));
    v.root.entries[0]
        .custom_data
        .items
        .push(item("k", "v", Some(Time(63_416_885_093))));
    let first = save_pw(&v, "demo-pass");
    assert_eq!(first.version.minor, 0);
    let back = open_pw(&first.bytes, "demo-pass").vault;
    assert_eq!(
        back.root.entries[0].custom_data.items[0].last_modified, None,
        "left out at 4.0"
    );
    v.root
        .groups
        .push(app_model::Group::new(id(2), "G".into(), SAVE));
    v.root.groups[0].tags = "t".into();
    let second = save_pw(&v, "demo-pass");
    assert_eq!(second.version.minor, 1);
    let back = open_pw(&second.bytes, "demo-pass").vault;
    assert_eq!(
        back.root.entries[0].custom_data.items[0].last_modified,
        Some(Time(63_416_885_093))
    );
}

#[test]
fn fmt_16_18_app_writes_version_4_only() {
    let file = DemoV3 {
        minor: 0,
        password: Some("a".into()),
        xml: g("").into_bytes(),
        ..DemoV3::new()
    }
    .build();
    let mut v = open_pw(&file, "a").vault;
    cheap(&mut v);
    let saved = save_pw(&v, "a").bytes;
    assert_eq!(&saved[8..12], &[0x00, 0x00, 0x04, 0x00]);
    assert!(
        app_format::header::read_header(&saved, &Limits::DEFAULT)
            .unwrap()
            .v3
            .is_none()
    );
}

#[test]
fn fmt_16_19_app_4_0_or_4_1() {
    let child = format!("<Group><UUID>{}</UUID></Group>", idt(2));
    let icon = |inner: &str| {
        doc(
            &format!(
                "<CustomIcons><Icon><UUID>{}</UUID>{inner}<Data>AA==</Data></Icon></CustomIcons>",
                idt(0xA1)
            ),
            &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
        )
    };
    let cases = [
        ("16.6 group tags", g("<Tags>t</Tags>")),
        (
            "16.7 group previous parent",
            g(&format!(
                "<Group><UUID>{}</UUID><PreviousParentGroup>{}</PreviousParentGroup></Group>{child}",
                idt(3),
                idt(2)
            )),
        ),
        (
            "16.8 excluded entry",
            g(&entry(0x10, "<QualityCheck>False</QualityCheck>")),
        ),
        (
            "16.8 legacy key",
            g(&entry(
                0x10,
                "<CustomData><Item><Key>KnownBad</Key><Value>true</Value></Item></CustomData>",
            )),
        ),
        (
            "16.9 entry previous parent",
            g(&format!(
                "{}{child}",
                entry(
                    0x10,
                    &format!("<PreviousParentGroup>{}</PreviousParentGroup>", idt(2))
                )
            )),
        ),
        ("16.10 icon name", icon("<Name>abc</Name>")),
        (
            "16.10 icon time",
            icon("<LastModificationTime>Zd/www4AAAA=</LastModificationTime>"),
        ),
    ];
    for (name, xml) in cases {
        assert_eq!(write::minor_version(&read_doc(&xml)), 1, "{name}");
    }
    let none = g(&format!(
        "{}<CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>{child}",
        entry(0x10, &s("Title", "T"))
    ));
    assert_eq!(write::minor_version(&read_doc(&none)), 0);
}

fn history_excluded(extra: &str) -> String {
    let item = entry(
        0x10,
        &format!(
            "{}<QualityCheck>False</QualityCheck>",
            s("Title", "Demo login")
        ),
    );
    g(&format!(
        "{extra}{}",
        entry(
            0x10,
            &format!("{}<History>{item}</History>", s("Title", "Demo login"))
        )
    ))
}

#[test]
fn fmt_16_19_history_exclusion_kept() {
    for extra in [
        "",
        "<CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>",
    ] {
        let v = cheap_vault(&history_excluded(extra));
        let saved = save_pw(&v, "demo-pass");
        assert_eq!(saved.version.minor, 1, "{extra:?}");
        let back = open_pw(&saved.bytes, "demo-pass").vault;
        assert!(back.root.entries[0].history[0].exclude_from_reports);
    }
}

#[test]
fn fmt_16_19_history_previous_parent_kept() {
    let item = entry(
        0x10,
        &format!(
            "{}<PreviousParentGroup>{}</PreviousParentGroup>",
            s("Title", "Demo login"),
            idt(2)
        ),
    );
    let xml = g(&format!(
        "{}<Group><UUID>{}</UUID><Name>Demo</Name></Group>",
        entry(
            0x10,
            &format!("{}<History>{item}</History>", s("Title", "Demo login"))
        ),
        idt(2)
    ));
    let saved = save_pw(&cheap_vault(&xml), "demo-pass");
    assert_eq!(saved.version.minor, 1);
    let back = open_pw(&saved.bytes, "demo-pass").vault;
    assert_eq!(back.root.entries[0].history[0].previous_parent, Some(id(2)));
}

#[test]
fn fmt_16_19_dangling_previous_parent_kept() {
    let dangling = app_format::document::encode::base64_encode(&(1u8..=16).collect::<Vec<u8>>());
    let xml = g(&entry(
        0x10,
        &format!(
            "{}<PreviousParentGroup>{dangling}</PreviousParentGroup>",
            s("Title", "Demo login")
        ),
    ));
    let saved = save_pw(&cheap_vault(&xml), "demo-pass");
    assert_eq!(saved.version.minor, 1);
    let back = open_pw(&saved.bytes, "demo-pass").vault;
    assert_eq!(
        back.root.entries[0].previous_parent,
        Some(app_model::Uuid(core::array::from_fn(|i| i as u8 + 1)))
    );
}

#[test]
fn fmt_16_19_item_times_never_raise() {
    let mut v = cheap_vault(&g(""));
    v.meta
        .custom_data
        .items
        .push(item("k", "v", Some(Time(63_416_885_093))));
    let saved = save_pw(&v, "demo-pass");
    assert_eq!(saved.version.minor, 0);
    let back = open_pw(&saved.bytes, "demo-pass").vault;
    assert_eq!(
        back.meta
            .custom_data
            .items
            .iter()
            .find(|i| i.key == "k")
            .unwrap()
            .last_modified,
        None
    );
}

#[test]
fn fmt_16_20_no_recorded_version() {
    for minor in [1u16, 2] {
        let saved = resave(&v4(&g(""), minor));
        assert_eq!(saved_version(&saved), (4, 0), "stamped 4.{minor}");
    }
}

#[test]
fn fmt_16_21_app_instead_of_3_1() {
    let first = open_pw(&testdata("default-time.appvault"), "demo-pass-3");
    assert_eq!(first.header.major, 3);
    let saved = save_pw(&first.vault, "demo-pass-3");
    assert_eq!(saved.version, FileVersion { major: 4, minor: 0 });
    let h = app_format::header::read_header(&saved.bytes, &Limits::DEFAULT).unwrap();
    let KdfParams::AesKdf { rounds, seed } = &h.kdf else {
        panic!("AES-KDF")
    };
    assert_eq!((*rounds, seed.len()), (1_000_000, 32));
    assert_ne!(seed, &salt_of(&first.header));
    let u = parts(&saved.bytes, "demo-pass-3").inner_and_doc;
    assert_eq!(
        &u[..9],
        &[0x01, 0x04, 0, 0, 0, 0x03, 0, 0, 0],
        "ChaCha20 inner stream"
    );
    let back = open_pw(&saved.bytes, "demo-pass-3");
    let (mut a, mut b) = (first.vault, back.vault);
    for v in [&mut a, &mut b] {
        let pk = String::from_utf8(PADDING_KEY.to_vec()).unwrap();
        v.meta
            .custom_data
            .items
            .retain(|i| i.key != pk && i.key != "_LAST_MODIFIED");
        v.read_version = None;
    }
    assert!(a == b, "reopens with the same content");
}

#[test]
fn fmt_16_21_3x_to_4_1() {
    let first = open_pw(&testdata("rich-v3.appvault"), "demo-pass-4");
    let KdfParams::AesKdf { rounds, .. } = first.header.kdf else {
        panic!()
    };
    let mut v = first.vault;
    v.root.tags = "demo-tag".into();
    let saved = save_pw(&v, "demo-pass-4");
    assert_eq!(saved.version, FileVersion { major: 4, minor: 1 });
    let h = app_format::header::read_header(&saved.bytes, &Limits::DEFAULT).unwrap();
    let KdfParams::AesKdf { rounds: r2, seed } = &h.kdf else {
        panic!("AES-KDF")
    };
    assert_eq!((*r2, seed.len()), (rounds, 32));
}

#[test]
fn fmt_16_22_app_and_3x_minors() {
    for (major, minor) in [(3u16, 2u16), (2, 1)] {
        let file = DemoV3 {
            major,
            minor,
            rounds: 6_000,
            password: Some("a".into()),
            xml: g("").into_bytes(),
            ..DemoV3::new()
        }
        .build();
        let first = open_pw(&file, "a");
        let saved = save_pw(&first.vault, "a").bytes;
        assert_eq!(saved_version(&saved), (4, 0), "{major}.{minor}");
        let h = app_format::header::read_header(&saved, &Limits::DEFAULT).unwrap();
        assert!(matches!(h.kdf, KdfParams::AesKdf { rounds: 6_000, .. }));
    }
}

fn foobar(meta: bool) -> String {
    doc(
        if meta { "<FooBar/>" } else { "" },
        &format!(
            "<Group><UUID>{}</UUID>{}</Group>",
            idt(1),
            entry(0x10, &s("Title", "Demo login"))
        ),
    )
}

#[test]
fn fmt_16_24_kept_unknown_part_4_1() {
    for (case, minor, foo, want) in [("a", 1u16, true, 1), ("b", 1, false, 0), ("c", 0, true, 0)] {
        let saved = resave(&v4(&foobar(foo), minor));
        assert_eq!(saved_version(&saved), (4, want), "case {case}");
        assert_eq!(
            saved_doc(&saved, "demo-pass").contains("\t\t<FooBar/>\n"),
            foo,
            "case {case}"
        );
    }
}

#[test]
fn fmt_16_24_kept_unknown_part_4_2() {
    let saved = resave(&v4(&foobar(true), 2));
    assert_eq!(&saved[8..12], &[0x02, 0x00, 0x04, 0x00]);
    assert!(saved_doc(&saved, "demo-pass").contains("\t\t<FooBar/>\n"));
    open_pw(&saved, "demo-pass");
    assert_eq!(saved_version(&resave(&v4(&foobar(false), 2))), (4, 0));
}

#[test]
fn fmt_16_24_parts_removed() {
    let xml = g(&entry(
        0x10,
        &format!("{}<FooBar/>", s("Title", "Demo login")),
    ));
    let mut v = open_pw(&v4(&xml, 1), "demo-pass").vault;
    assert_eq!(write::minor_version(&v), 1);
    v.root.entries.clear();
    cheap(&mut v);
    assert_eq!(save_pw(&v, "demo-pass").version.minor, 0);
}

#[test]
fn fmt_16_23_never_lowers() {
    let file = Demo {
        kdf_map: argon2_map(ARGON2ID_ID, 3, 64 << 20, 1, &[9; 32], 0x13),
        xml: g("").into_bytes(),
        ..Demo::new()
    }
    .build();
    let first = open_pw(&file, "demo-pass");
    let saved = save_pw(&first.vault, "demo-pass").bytes;
    let back = open_pw(&saved, "demo-pass");
    match (&first.header.kdf, &back.header.kdf) {
        (
            KdfParams::Argon2 {
                kind: k1,
                iterations: i1,
                memory_kib: m1,
                lanes: p1,
                salt: s1,
                ..
            },
            KdfParams::Argon2 {
                kind: k2,
                iterations: i2,
                memory_kib: m2,
                lanes: p2,
                salt: s2,
                ..
            },
        ) => {
            assert_eq!((k1, i1, m1, p1), (k2, i2, m2, p2));
            assert_eq!((*i2, *m2), (3, 65_536));
            assert_ne!(s1, s2);
        }
        _ => panic!("Argon2 kept"),
    }
    let h = back.header.len;
    assert_eq!(
        saved[h..h + 32],
        *app_crypto::hash::sha256(&[&saved[..h]]).expose()
    );
    assert!(
        saved.len() > h + 64 + 36,
        "HMAC blocks follow the header HMAC"
    );
}

#[test]
fn fmt_16_12_hardware_key_kept() {
    let secret = b"demo hw".to_vec();
    let key_file = vec![0x77u8; 32];
    let file = DemoV3 {
        hardware: Some(secret.clone()),
        key_file: Some(key_file.clone()),
        xml: g("<CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>").into_bytes(),
        ..DemoV3::new()
    }
    .build();
    let hw = SoftwareKey {
        secret: SecretBytes::new(secret),
        mode: SlotMode::Variable,
    };
    let kf = app_format::keyfile::read_key_file(std::io::Cursor::new(key_file), &Limits::DEFAULT)
        .unwrap();
    let p = pw("demo-pass");
    let full = Credentials {
        password: Some(&p),
        key_file: Some(&kf),
        hardware_key: Some(&hw),
    };
    let Ok(Opened::Vault(first)) = open(&file, &full, &mut host(), &Limits::DEFAULT, None) else {
        panic!("opens")
    };
    let mut v = first.vault;
    cheap(&mut v);
    let Saved::File(saved) = save(&v, &full, None, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        open(&saved.bytes, &full, &mut host(), &Limits::DEFAULT, None),
        Ok(Opened::Vault(_))
    ));
    let no_hw = Credentials {
        hardware_key: None,
        ..full
    };
    assert_eq!(
        open(&saved.bytes, &no_hw, &mut host(), &Limits::DEFAULT, None).unwrap_err(),
        Error::WrongKey
    );
}

#[test]
fn fmt_16_14_highest_wins() {
    let v = read_doc(&g(
        "<Tags>t</Tags><CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>",
    ));
    assert_eq!(write::minor_version(&v), 1);
}

// -- CRY-03 -----------------------------------------------------------------

fn header_of(file: &[u8]) -> app_format::header::Header {
    app_format::header::read_header(file, &Limits::DEFAULT).unwrap()
}

#[test]
fn cry_03_t1_seed_and_iv() {
    let v = cheap_vault(&g(""));
    let (a, b) = (
        header_of(&save_pw(&v, "demo-pass").bytes),
        header_of(&save_pw(&v, "demo-pass").bytes),
    );
    assert_ne!(a.master_seed, b.master_seed);
    assert_eq!((a.iv.len(), b.iv.len()), (16, 16));
    assert_ne!(a.iv, b.iv);
}

#[test]
fn cry_03_t2_chacha20_nonce() {
    let mut v = cheap_vault(&g(""));
    v.encryption.cipher = app_model::Cipher::ChaCha20;
    let (a, b) = (
        header_of(&save_pw(&v, "demo-pass").bytes),
        header_of(&save_pw(&v, "demo-pass").bytes),
    );
    assert_eq!(a.cipher, Cipher::ChaCha20);
    assert_eq!((a.iv.len(), b.iv.len()), (12, 12));
    assert_ne!(a.iv, b.iv);
}

#[test]
fn cry_03_t3_salt() {
    for map in [
        argon2_map(ARGON2D_ID, 1, 8 << 10, 1, &[3; 32], 0x13),
        argon2_map(ARGON2ID_ID, 1, 8 << 10, 1, &[3; 32], 0x13),
        format_common::aes_kdf_map(1_000, &[3; 32]),
    ] {
        let first = open_pw(
            &Demo {
                kdf_map: map,
                xml: g("").into_bytes(),
                ..Demo::new()
            }
            .build(),
            "demo-pass",
        );
        let a = save_pw(&first.vault, "demo-pass").bytes;
        let b = save_pw(&first.vault, "demo-pass").bytes;
        let (ha, hb) = (header_of(&a), header_of(&b));
        assert_ne!(salt_of(&ha), salt_of(&hb));
        assert_eq!(
            app_format::header::encryption_of(&ha),
            app_format::header::encryption_of(&hb)
        );
        open_pw(&a, "demo-pass");
        open_pw(&b, "demo-pass");
    }
}

#[test]
fn cry_03_t4_kdf_runs_once_on_save() {
    let v = cheap_vault(&g(""));
    let _ = probe::take();
    save_pw(&v, "demo-pass");
    assert_eq!(probe::take().kdf, 1);
}

#[test]
fn cry_03_t5_salt_length() {
    let file = Demo {
        kdf_map: argon2_map(ARGON2ID_ID, 1, 8 << 10, 1, &[5; 16], 0x13),
        xml: g("").into_bytes(),
        ..Demo::new()
    }
    .build();
    let saved = save_pw(&open_pw(&file, "demo-pass").vault, "demo-pass").bytes;
    assert_eq!(salt_of(&header_of(&saved)).len(), 32);
    open_pw(&saved, "demo-pass");
}

#[test]
fn cry_03_t6_field_stream_key() {
    let v = cheap_vault(&g(&entry(0x10, &s("Password", "demo-secret-1"))));
    let (a, b) = (
        save_pw(&v, "demo-pass").bytes,
        save_pw(&v, "demo-pass").bytes,
    );
    let (ka, kb) = (
        saved_stream_key(&a, "demo-pass"),
        saved_stream_key(&b, "demo-pass"),
    );
    assert_eq!((ka.len(), kb.len()), (64, 64));
    assert_ne!(ka, kb);
    let ct = |f: &[u8]| {
        let d = saved_doc(f, "demo-pass");
        d.split("<Value Protected=\"True\">")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned()
    };
    assert_ne!(ct(&a), ct(&b));
    assert_eq!(dec(&ka, 0, &ct(&a)), b"demo-secret-1");
    assert_eq!(dec(&kb, 0, &ct(&b)), b"demo-secret-1");
    for f in [&a, &b] {
        assert_eq!(
            &parts(f, "demo-pass").inner_and_doc[5..9],
            &[3, 0, 0, 0],
            "stream id 3"
        );
    }
}

/// A hardware key that records every challenge.
struct Recorder(std::cell::RefCell<Vec<[u8; 64]>>, SoftwareKey);
impl ChallengeResponse for Recorder {
    fn challenge(
        &self,
        padded: &[u8; 64],
    ) -> Result<SecretBytes, app_format::error::HardwareKeyReason> {
        self.0.borrow_mut().push(*padded);
        self.1.challenge(padded)
    }
}

#[test]
fn cry_03_t7_challenge() {
    let rec = Recorder(
        std::cell::RefCell::new(Vec::new()),
        SoftwareKey {
            secret: SecretBytes::new(b"hw".to_vec()),
            mode: SlotMode::Fixed,
        },
    );
    let v = cheap_vault(&g(""));
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        hardware_key: Some(&rec),
        ..Default::default()
    };
    let mut salts = Vec::new();
    for _ in 0..2 {
        let Saved::File(f) = save(&v, &creds, None, &mut host(), &Limits::DEFAULT, None).unwrap()
        else {
            panic!()
        };
        salts.push(salt_of(&header_of(&f.bytes)));
    }
    let seen = rec.0.borrow();
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0], seen[1]);
    for (c, s) in seen.iter().zip(&salts) {
        assert_eq!(s.len(), 32);
        assert_eq!(&c[..32], s.as_slice(), "the challenge is this save's S");
    }
}

#[test]
fn cry_03_t8_padding_item() {
    let v = cheap_vault(&g(""));
    let key = String::from_utf8(PADDING_KEY.to_vec()).unwrap();
    let mut seen = HashSet::new();
    let mut lengths = HashSet::new();
    for _ in 0..30 {
        let back = open_pw(&save_pw(&v, "demo-pass").bytes, "demo-pass").vault;
        let value = back.meta.custom_data.get(&key).unwrap().to_owned();
        lengths.insert(value.len());
        let first = &value[..2];
        assert!(
            value.as_bytes().chunks(2).any(|b| b != first.as_bytes()),
            "the bytes are random, not one value repeated"
        );
        assert!((128..=1022).contains(&value.len()) && value.len().is_multiple_of(2));
        assert!(
            value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert!(seen.insert(value), "differs every time");
    }
    assert!(
        lengths.len() > 1,
        "the length L is drawn on every save (CRY-03.7)"
    );
}

/// AT-B03 / CRY-03 T10 / T09-32: 10,000 saves with a cheap KDF; no master
/// seed, IV, salt or stream key repeats, within a set or across sets.
#[test]
fn cry_03_t10_at_b03_ten_thousand_saves() {
    let v = cheap_vault(&g(""));
    let p = pw("demo-pass");
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    let mut h = host();
    let (mut seeds, mut ivs, mut salts, mut keys) = (
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
    );
    for _ in 0..10_000 {
        let Saved::File(f) = save(&v, &creds, None, &mut h, &Limits::DEFAULT, None).unwrap() else {
            panic!()
        };
        let hd = header_of(&f.bytes);
        assert!(seeds.insert(hd.master_seed.to_vec()));
        assert!(ivs.insert(hd.iv.clone()));
        assert!(salts.insert(salt_of(&hd)));
        assert!(keys.insert(saved_stream_key(&f.bytes, "demo-pass")));
    }
    let mut all: HashSet<Vec<u8>> = HashSet::new();
    for set in [&seeds, &ivs, &salts, &keys] {
        for v in set.iter() {
            assert!(all.insert(v.clone()), "no value in two sets");
        }
    }
    assert_eq!(all.len(), 40_000);
}

/// Words that name a random source in Rust code outside app-crypto's
/// random module (CRY-03 T11, AT-B04, F-100).
const RANDOM_RUST: [&str; 17] = [
    "getrandom",
    "rand_core",
    "OsRng",
    "thread_rng",
    "rand::",
    "arc4random",
    "getentropy",
    "SecRandomCopyBytes",
    "CCRandom",
    "RandomState",
    "/dev/urandom",
    "/dev/random",
    "drand48",
    "libc::rand",
    "rand48",
    "fn rand(",
    " rand(",
];

/// The same for the Swift app (F-100).
const RANDOM_SWIFT: [&str; 17] = [
    ".random(",
    "SystemRandomNumberGenerator",
    "randomElement(",
    "shuffle",
    "UUID()",
    "arc4random",
    "getentropy",
    "SecRandomCopyBytes",
    "CCRandom",
    "/dev/urandom",
    "/dev/random",
    "drand48",
    "random()",
    "rand48",
    " rand(",
    "GKRandom",
    "RandomSource",
];

/// F-100 (E13-S2 AT-B04, RT-B3): the guard's words catch the system's own
/// random calls, in Rust and in Swift, not only the Rust random crates.
#[test]
fn f_100_the_guard_catches_the_systems_own_random_calls() {
    let caught = |words: &[&str], line: &str| words.iter().any(|w| line.contains(w));
    for line in [
        "unsafe { libc::arc4random_buf(buf.as_mut_ptr().cast(), buf.len()) }",
        "unsafe { libc::getentropy(buf.as_mut_ptr().cast(), buf.len()) }",
        "SecRandomCopyBytes(kSecRandomDefault, n, p)",
        "CCRandomGenerateBytes(p, n)",
        "let s = std::collections::hash_map::RandomState::new();",
        "let mut f = std::fs::File::open(\"/dev/urandom\")?;",
        "let mut f = std::fs::File::open(\"/dev/random\")?;",
        "let x = unsafe { libc::drand48() };",
        "let n = unsafe { libc::rand() };",
        // F-100 Verify round 2 (LD-246): the other 48 family and a
        // hand-declared extern.
        "let x = unsafe { libc::lrand48() };",
        "unsafe extern \"C\" { fn rand() -> i32; }",
        "let n = unsafe { rand() };",
    ] {
        assert!(caught(&RANDOM_RUST, line), "{line}");
    }
    for line in [
        "let n = Int.random(in: 0..<10)",
        "var g = SystemRandomNumberGenerator()",
        "let c = letters.randomElement()",
        "let s = items.shuffled()",
        "let id = UUID()",
        "let n = arc4random_uniform(10)",
        "_ = SecRandomCopyBytes(kSecRandomDefault, n, &bytes)",
        "getentropy(&bytes, n)",
        "let h = FileHandle(forReadingAtPath: \"/dev/urandom\")",
        "let h = FileHandle(forReadingAtPath: \"/dev/random\")",
        "let x = drand48() * 2",
        "let n = random() % 10",
        // F-100 Verify round 2 (LD-246).
        "let n = rand() % 10",
        "let x = lrand48()",
        "let g = GKRandomSource.sharedRandom()",
        "let g = GKMersenneTwisterRandomSource(seed: 1)",
    ] {
        assert!(caught(&RANDOM_SWIFT, line), "{line}");
    }
}

#[test]
fn cry_03_t11_one_random_source() {
    // AT-B04: no random generator outside app-crypto's random module, in
    // the Rust crates and in the Swift app (F-100: the system's own random
    // calls too; AppTests may use them).
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let (rust, swift) = (RANDOM_RUST, RANDOM_SWIFT);
    let mut checked = [0, 0];
    let mut stack = vec![
        root.join("crates"),
        root.join("macos/App"),
        root.join("macos/AppCore"),
    ];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let path = e.unwrap().path();
            let ext = path.extension().and_then(|x| x.to_str());
            if path.is_dir() {
                if !path.ends_with("target") && !path.ends_with("tests") {
                    stack.push(path);
                }
            } else if ext == Some("rs") && path.to_string_lossy().contains("/src/") {
                if path.ends_with("app-crypto/src/random.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for b in rust {
                    assert!(!text.contains(b), "{b} in {}", path.display());
                }
                checked[0] += 1;
            } else if ext == Some("swift") {
                let text = std::fs::read_to_string(&path).unwrap();
                for b in swift {
                    assert!(!text.contains(b), "{b} in {}", path.display());
                }
                checked[1] += 1;
            }
        }
    }
    assert!(
        checked[0] > 50 && checked[1] > 50,
        "files checked: {checked:?}"
    );
}

#[test]
fn cry_03_t14_new_vault() {
    let root = app_model::Uuid(app_crypto::random::uuid_v4().unwrap());
    let mut v = Vault::new(app_model::Group::new(root, "Root".into(), SAVE), SAVE);
    cheap(&mut v);
    let saved = save_pw(&v, "demo-pass").bytes;
    let back = open_pw(&saved, "demo-pass");
    let u = back.vault.root.uuid.0;
    assert_eq!((u[6] >> 4, u[8] >> 6), (4, 0b10));
    assert_eq!(salt_of(&back.header).len(), 32);
    assert_eq!(saved_stream_key(&saved, "demo-pass").len(), 64);
    assert!(
        back.vault
            .meta
            .custom_data
            .get(core::str::from_utf8(PADDING_KEY).unwrap())
            .is_some()
    );
}

#[test]
fn cry_03_t15_kept_values() {
    let public = field(
        12,
        &format_common::hex(
            "00 01 42 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 55 55 49 44 10 00 00 00 A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF 00",
        ),
    );
    let file = Demo {
        kdf_map: argon2_map(ARGON2ID_ID, 7, 64 << 20, 4, &[1; 32], 0x13),
        extra: vec![public],
        xml: doc(
            "<CustomData><Item><Key>demo-key</Key><Value>demo-value</Value></Item></CustomData>",
            &format!("<Group><UUID>{}</UUID></Group>", idt(1)),
        )
        .into_bytes(),
        ..Demo::new()
    }
    .build();
    let first = open_pw(&file, "demo-pass");
    let saved = save_pw(&first.vault, "demo-pass").bytes;
    let back = open_pw(&saved, "demo-pass");
    assert_eq!(first.vault.encryption, back.vault.encryption);
    assert_eq!(
        first.vault.public_custom_data,
        back.vault.public_custom_data
    );
    assert_eq!(
        first.header.public_custom_data,
        back.header.public_custom_data
    );
    assert_eq!(
        back.vault.meta.custom_data.get("demo-key"),
        Some("demo-value")
    );
    assert!(matches!(
        back.header.kdf,
        KdfParams::Argon2 {
            iterations: 7,
            memory_kib: 65_536,
            lanes: 4,
            ..
        }
    ));
}

#[test]
fn cry_03_t16_gzip_time() {
    let p = parts(
        &save_pw(&cheap_vault(&g("")), "demo-pass").bytes,
        "demo-pass",
    );
    assert_eq!(&p.raw[4..8], &[0, 0, 0, 0]);
}

#[test]
fn cry_03_t9_padding_length_draw() {
    // The unbiased draw (`random::below`, exhaustively tested in app-crypto,
    // ignored as slow) gives L in 64..=511: 30 saves stay in range above;
    // here the bounds of the hex value are checked on many saves.
    let v = cheap_vault(&g(""));
    let key = String::from_utf8(PADDING_KEY.to_vec()).unwrap();
    for _ in 0..50 {
        let back = open_pw(&save_pw(&v, "demo-pass").bytes, "demo-pass").vault;
        let n = back.meta.custom_data.get(&key).unwrap().len() / 2;
        assert!((64..=511).contains(&n));
    }
    assert_eq!(&AES_KDF_ID[..2], &[0xC9, 0xD9]);
}
