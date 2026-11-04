//! E3-S6 check against testdata/: every demo vault matches its JSON.
//!
//! `export_documents_round_trip` rebuilds each export document from its JSON,
//! reads it with the document reader, and turns the vault back into JSON
//! with the `vault_json` helper: this proves the reader and the helper agree
//! with the reference's export shape for every file, 3.1 and 4.1.
//! `every_vault_opens_and_matches_its_json` opens all 12 `.larsalvault` files
//! (version 3.1 and 4.1) with their passwords and key files and compares.

mod vault_json;

use larsal_crypto::secret::SecretBytes;
use larsal_crypto::stream::FieldStream;
use larsal_format::document::{Options, read};
use larsal_format::limits::Limits;
use larsal_model::{Time, json};
use std::path::PathBuf;
use vault_json::{Shape, first_diff, json_to_xml, normalize_expected, vault_to_json};

fn testdata() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata"))
}

/// The file version of each demo vault (testdata/README.md, Vaults table).
fn shape(name: &str) -> Shape {
    let (major, minor) = if name == "rich-v4" { (4, 1) } else { (3, 1) };
    Shape {
        major,
        minor,
        compressed: true,
    }
}

#[test]
fn export_documents_round_trip() {
    let mut names: Vec<String> = std::fs::read_dir(testdata())
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension()? == "json").then(|| p.file_stem()?.to_str().map(str::to_owned))?
        })
        .collect();
    names.sort();
    assert_eq!(names.len(), 12, "every demo vault has its JSON");
    for name in names {
        let text = std::fs::read_to_string(testdata().join(format!("{name}.json"))).unwrap();
        let raw = json::from_str(&text).unwrap();
        let xml = json_to_xml(&raw);
        let expected = normalize_expected(raw);
        let mut stream =
            FieldStream::chacha20_from_stream_key(&SecretBytes::new(vec![0; 64])).unwrap();
        let lim = Limits::DEFAULT;
        let opts = Options {
            open_time: Time(0),
            limits: &lim,
            v3_header: None,
        };
        let doc = read(xml.as_bytes(), &mut stream, &[], &opts)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(
            larsal_model::invariants::check(&doc.vault),
            Ok(()),
            "{name}"
        );
        let got = vault_to_json(&doc.vault, shape(&name));
        if let Some(d) = first_diff(&got, &expected, "") {
            panic!("{name}: first difference (ours vs expected) at {d}");
        }
    }
}

/// Each demo vault with its credentials (testdata/README.md, Vaults table).
const DEMOS: [(&str, Option<&str>, Option<&str>); 12] = [
    ("password-only", Some("demo-pass-1"), None),
    ("keyfile-binary32", None, Some("key-binary32")),
    ("keyfile-hex64", None, Some("key-hex64")),
    ("keyfile-hashed", None, Some("key-hashed")),
    ("keyfile-xml-v1", None, Some("key-xml-v1")),
    ("keyfile-xml-v2", None, Some("key-xml-v2")),
    ("keyfile-cli-made", None, Some("key-cli-made")),
    (
        "password-and-keyfile",
        Some("demo-pass-2"),
        Some("key-hex64"),
    ),
    ("default-time", Some("demo-pass-3"), None),
    ("rich-v3", Some("demo-pass-4"), None),
    ("rich-v4", Some("demo-pass-5"), None),
    ("big-10000", Some("demo-pass-6"), None),
];

/// The attachment bytes of the rich vaults (scripts/testdata/make_inputs.py
/// `ATTACHMENTS`; the 4.1 export leaves them out, README "Attachments in 4.1").
fn rich_attachment(name: &str) -> Vec<u8> {
    match name {
        "notes.txt" => b"demo attachment one\n".to_vec(),
        "empty.bin" => Vec::new(),
        "shared.txt" => b"shared demo content\n".to_vec(),
        "bytes.bin" => (0..=255).collect(),
        other => panic!("unexpected attachment {other}"),
    }
}

#[test]
fn every_vault_opens_and_matches_its_json() {
    use larsal_crypto::kdf::{Host, SpeedRecord};
    use larsal_crypto::secret::SecretString;
    use larsal_format::header::Compression;
    use larsal_format::keys::Credentials;
    use larsal_format::{Opened, open};
    for (name, password, key_file) in DEMOS {
        let file = std::fs::read(testdata().join(format!("{name}.larsalvault"))).unwrap();
        let pw = password.map(|p| SecretString::new(p.to_owned()));
        let key = key_file.map(|k| {
            let bytes = std::fs::read(testdata().join(format!("{k}.larsalkey"))).unwrap();
            larsal_format::keyfile::read_key_file(std::io::Cursor::new(bytes), &Limits::DEFAULT)
                .unwrap()
        });
        let creds = Credentials {
            password: pw.as_ref(),
            key_file: key.as_ref(),
            ..Default::default()
        };
        // A speed record, so the AES-KDF cost check needs no calibration run.
        let mut host = Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: None,
            aes_record: Some(SpeedRecord {
                count: 100_000_000,
                memory_kib: 0,
                lanes: 1,
                ms: 1000,
            }),
        };
        let result = open(&file, &creds, &mut host, &Limits::DEFAULT, None);
        let opened = match result.unwrap_or_else(|e| panic!("{name}: {e:?}")) {
            Opened::Vault(v) => v,
            Opened::Ask(r) => panic!("{name}: cost question {r:?}"),
        };
        let vault = &opened.vault;
        assert_eq!(larsal_model::invariants::check(vault), Ok(()), "{name}");
        let h = &opened.header;
        let read = vault.read_version.unwrap();
        assert_eq!((read.major, read.minor), (h.major, h.minor));
        let shape = Shape {
            major: h.major,
            minor: h.minor,
            compressed: h.compression == Compression::Gzip,
        };
        let text = std::fs::read_to_string(testdata().join(format!("{name}.json"))).unwrap();
        let expected = normalize_expected(json::from_str(&text).unwrap());
        let got = vault_to_json(vault, shape);
        if let Some(d) = first_diff(&got, &expected, "") {
            panic!("{name}: first difference (ours vs expected) at {d}");
        }
        if name == "rich-v4" {
            let mut seen = 0;
            for e in vault.root.all_entries() {
                for a in &e.attachments {
                    assert_eq!(
                        a.data.expose(),
                        rich_attachment(&a.name).as_slice(),
                        "{}",
                        a.name
                    );
                    seen += 1;
                }
            }
            assert_eq!(
                seen, 5,
                "three attachments on one entry, one on each shared entry"
            );
            assert!(opened.warnings.is_empty(), "{:?}", opened.warnings);
        }
    }
}

/// LD-88 (F-040): the `Debug` of an opened vault prints ids, counts and
/// flags only. No demo text of rich-v4 (names, notes, tags, custom data,
/// sequences, field names, URLs) appears in it.
#[test]
fn ld88_debug_holds_no_demo_text() {
    use larsal_crypto::kdf::{Host, SpeedRecord};
    use larsal_crypto::secret::SecretString;
    use larsal_format::keys::Credentials;
    use larsal_format::{Opened, open};
    let file = std::fs::read(testdata().join("rich-v4.larsalvault")).unwrap();
    let pw = SecretString::new("demo-pass-5".to_owned());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let mut host = Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1000,
        }),
    };
    let Ok(Opened::Vault(v)) = open(&file, &creds, &mut host, &Limits::DEFAULT, None) else {
        panic!("rich-v4 opens")
    };
    let debug = format!("{v:?} {:?} {:?}", v.vault, v.vault.root);
    // Every text value of the expected export, but ids, times, flags and
    // numbers, which the Debug output may hold in its own form.
    fn texts(v: &json::Value, out: &mut Vec<String>) {
        match v {
            json::Value::String(s) => out.push(s.clone()),
            json::Value::Array(a) => a.iter().for_each(|x| texts(x, out)),
            json::Value::Object(o) => o.values().for_each(|x| texts(x, out)),
            _ => {}
        }
    }
    let json =
        json::from_str(&std::fs::read_to_string(testdata().join("rich-v4.json")).unwrap()).unwrap();
    let mut all = Vec::new();
    texts(&json, &mut all);
    let user_text = |s: &&String| {
        s.chars().count() >= 4
            && !s.starts_with("hex:")
            && s.chars().any(char::is_alphabetic)
            && !matches!(s.as_str(), "True" | "False" | "null" | "normalized")
            && !larsal_format::document::encode::has_base64_shape(s)
            && !s.ends_with('Z')
    };
    let checked: Vec<&String> = all.iter().filter(user_text).collect();
    assert!(checked.len() > 30, "the export holds demo text to look for");
    for s in checked {
        assert!(
            !debug.contains(s.as_str()),
            "Debug prints the demo text {s:?}"
        );
    }
    assert!(
        debug.contains("entries"),
        "the Debug output still says something: {debug}"
    );
}

/// A host with an AES-KDF speed record, so no calibration run is needed.
fn quick_host() -> larsal_crypto::kdf::Host {
    larsal_crypto::kdf::Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(larsal_crypto::kdf::SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1000,
        }),
    }
}

/// Removes what every save sets (the padding item, `_LAST_MODIFIED`,
/// FMT-14.21, FMT-14.18 (c)) and the read version, so two models of one
/// vault compare equal.
fn without_save_stamp(v: &mut larsal_model::Vault) {
    let padding = String::from_utf8(larsal_format::document::write::PADDING_KEY.to_vec()).unwrap();
    v.meta
        .custom_data
        .items
        .retain(|i| i.key != padding && i.key != "_LAST_MODIFIED");
    v.read_version = None;
}

/// E3-S7: open, save, open again gives the same model for all 12 demo
/// vaults; version 3.1 vaults save as version 4 (FMT-16.18, FMT-16.21,
/// FMT-01.23, FMT-17.24, FMT-13.19).
#[test]
fn every_vault_round_trips_as_version_4() {
    use larsal_crypto::kdf::KdfParams;
    use larsal_crypto::secret::SecretString;
    use larsal_format::keys::Credentials;
    use larsal_format::{Opened, Saved, open, save};
    for (name, password, key_file) in DEMOS {
        let file = std::fs::read(testdata().join(format!("{name}.larsalvault"))).unwrap();
        let pw = password.map(|p| SecretString::new(p.to_owned()));
        let key = key_file.map(|k| {
            let bytes = std::fs::read(testdata().join(format!("{k}.larsalkey"))).unwrap();
            larsal_format::keyfile::read_key_file(std::io::Cursor::new(bytes), &Limits::DEFAULT)
                .unwrap()
        });
        let creds = Credentials {
            password: pw.as_ref(),
            key_file: key.as_ref(),
            ..Default::default()
        };
        let mut host = quick_host();
        let open_one = |bytes: &[u8], host: &mut larsal_crypto::kdf::Host| match open(
            bytes,
            &creds,
            host,
            &Limits::DEFAULT,
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: {e:?}"))
        {
            Opened::Vault(v) => v,
            Opened::Ask(r) => panic!("{name}: cost question {r:?}"),
        };
        let first = open_one(&file, &mut host);
        let saved = match save(
            &first.vault,
            &creds,
            Some(&first.key),
            &mut host,
            &Limits::DEFAULT,
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: save {e:?}"))
        {
            Saved::File(f) => f,
            Saved::Ask(r) => panic!("{name}: cost question {r:?}"),
        };
        assert_eq!(saved.version.major, 4, "{name}");
        let second = open_one(&saved.bytes, &mut host);
        let h = &second.header;
        assert_eq!(
            (h.major, h.minor),
            (saved.version.major, saved.version.minor)
        );
        assert!(h.v3.is_none(), "{name}: version 4 layout");
        // Same KDF kind and cost, a fresh 32-byte salt (FMT-16.21, LD-15).
        match (&first.header.kdf, &h.kdf) {
            (
                KdfParams::AesKdf {
                    rounds: a,
                    seed: s1,
                },
                KdfParams::AesKdf {
                    rounds: b,
                    seed: s2,
                },
            ) => {
                assert_eq!(a, b, "{name}");
                assert_eq!(s2.len(), 32);
                assert_ne!(s1, s2);
            }
            (a, b) => panic!("{name}: KDF changed kind: {a:?} -> {b:?}"),
        }
        assert_eq!(first.vault.encryption, second.vault.encryption, "{name}");
        let (mut a, mut b) = (first.vault, second.vault);
        without_save_stamp(&mut a);
        without_save_stamp(&mut b);
        let shape = Shape {
            major: first.header.major,
            minor: first.header.minor,
            compressed: true,
        };
        if let Some(d) = first_diff(&vault_to_json(&b, shape), &vault_to_json(&a, shape), "") {
            panic!("{name}: first difference (reopened vs first open) at {d}");
        }
        assert!(a == b, "{name}: the models differ");
    }
}
