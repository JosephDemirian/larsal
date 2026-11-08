//! E23-S3 check 2: vaults the peer tools made, opened by Larsal.
//!
//! The first test runs by default: a vault the public desktop app made, committed under
//! testdata/ with its notice, with its names and content hashes pinned.
//!
//! The ignored tests read vaults that may not be committed, from
//! `LARSAL_PEER_VAULTS` (a folder holding `vault-gcm`, `vault-gcm.json`, `vault-ctrmac`),
//! and write a Larsal vault for a later peer run to `LARSAL_PEER_EXPORT`.
//! Larsal's vaults opening in the peer tool is NOT proven by anything in this file.

mod common;

use common::{fresh, hex, secret, sha256_hex};
use larsal_folders::{Error, Kind, Node, Refused, Stores, Vault};
use larsal_model::json::{self, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// What one row of a whole tree came to.
#[derive(Debug, PartialEq, Eq)]
enum Found {
    Dir,
    File { size: u64, sha256: String },
    Link(Vec<u8>),
}

fn read_all(vault: &Vault, node: &Node) -> Vec<u8> {
    let mut out = Vec::new();
    vault.read_to(node, &mut out, &mut |_, _| true).unwrap();
    out
}

fn walk(vault: &Vault, dir: &Node, prefix: &str, out: &mut BTreeMap<String, Found>) {
    let mut listing = vault.open_listing(dir).unwrap();
    loop {
        let page = listing.next_page(256).unwrap();
        if page.is_empty() {
            return;
        }
        for row in page {
            let name = row
                .name
                .as_ref()
                .expect("every peer name proves itself")
                .expose()
                .to_owned();
            assert!(row.safe, "{name}");
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            match row.kind {
                Kind::File => {
                    let bytes = read_all(vault, &row.node);
                    assert_eq!(row.size, Some(bytes.len() as u64), "{path}");
                    out.insert(
                        path,
                        Found::File {
                            size: bytes.len() as u64,
                            sha256: sha256_hex(&bytes),
                        },
                    );
                }
                Kind::Dir => {
                    walk(vault, &row.node, &path, out);
                    out.insert(path, Found::Dir);
                }
                Kind::Link => {
                    out.insert(path, Found::Link(read_all(vault, &row.node)));
                }
                other => panic!("{path}: {other:?}"),
            }
        }
    }
}

fn open(path: &Path, password: &str) -> Vault {
    let stores = Stores::open(&fresh("peer-stores").join("stores")).unwrap();
    Vault::unlock(path, &secret(password), &stores, &mut |_, _| true).unwrap()
}

fn desktop_vault() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/desktop-vault")
}

/// The vault the desktop app made: opens, and is what it was. Read only: the test folder
/// is unchanged afterwards.
#[test]
fn peer_desktop_made_vault_opens_with_names_and_hashes_pinned() {
    let path = desktop_vault();
    let before = common::raw_tree(&path);
    let files: BTreeMap<String, String> = before
        .iter()
        .filter(|(_, sha)| !sha.is_empty())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let source: BTreeMap<String, String> = DESKTOP_FILES
        .iter()
        .map(|(name, sha)| ((*name).to_owned(), (*sha).to_owned()))
        .collect();
    assert_eq!(
        files, source,
        "the committed files are the source's, by SHA-256 (testdata/SOURCE.md)"
    );
    let vault = open(&path, "cryptomator-vault-sync");
    assert!(
        vault.weak_kdf(),
        "its key file costs less than a new folder's"
    );
    let mut found = BTreeMap::new();
    walk(&vault, &vault.root_dir().unwrap(), "", &mut found);
    vault.lock();
    let pinned = BTreeMap::from([
        (
            PINNED_NAME_A.to_owned(),
            Found::File {
                size: PINNED_SIZE_A,
                sha256: PINNED_SHA_A.to_owned(),
            },
        ),
        (
            PINNED_NAME_B.to_owned(),
            Found::File {
                size: PINNED_SIZE_B,
                sha256: PINNED_SHA_B.to_owned(),
            },
        ),
    ]);
    assert_eq!(found, pinned);
    assert_eq!(
        common::raw_tree(&path),
        before,
        "opening and reading changes nothing"
    );
    assert_eq!(
        Vault::unlock(
            &path,
            &secret("not the password"),
            &Stores::open(&fresh("peer-stores").join("stores")).unwrap(),
            &mut |_, _| true
        )
        .err(),
        Some(Error::Open)
    );
}

/// The source's files, as testdata/SOURCE.md lists them.
const DESKTOP_FILES: [(&str, &str); 8] = [
    (
        "IMPORTANT.rtf",
        "d1194c5dddda2ad2d9d10ea7e43b670c181b650b070bcba096f57614df7dbadd",
    ),
    (
        "d/WN/WA7DFYE4SWMC3FAXOQKQUOZZ2YN2K5/BqCPA4XuGE1TGcVHmhDsUmgeZtQSTPT0MOB4.c9r",
        "103355364c9128613cec68d6dcfe66f6864b457175b5d3a4ba3a8e63016e9af8",
    ),
    (
        "d/WN/WA7DFYE4SWMC3FAXOQKQUOZZ2YN2K5/LUQY1IVDNu3Z9TEcPCMJrbWXZs7MRJZ57ea93ZVHlh8=.c9r",
        "c1384a52bbcf0baacc79055e13e412cc2b05d88b7b27fa0a01d5c5f9732f8c94",
    ),
    (
        "d/WN/WA7DFYE4SWMC3FAXOQKQUOZZ2YN2K5/dirid.c9r",
        "a4af9cd9151990d5cebc45f51fee5fbb97b75999565e3cb85e9688e44c28b9a8",
    ),
    (
        "masterkey.cryptomator",
        "5c0cf15a40ba04fd158a855b8ce49c2c7a131ec01d75e610cdcb4c05ed96ea6f",
    ),
    (
        "masterkey.cryptomator.5C0CF15A.bkup",
        "5c0cf15a40ba04fd158a855b8ce49c2c7a131ec01d75e610cdcb4c05ed96ea6f",
    ),
    (
        "vault.cryptomator",
        "ad47c1844724a4fe4c7d8bd01e5682a6c5f94ed67f4226acbfa7c35df01ada01",
    ),
    (
        "vault.cryptomator.AD47C184.bkup",
        "ad47c1844724a4fe4c7d8bd01e5682a6c5f94ed67f4226acbfa7c35df01ada01",
    ),
];

const PINNED_NAME_A: &str = "MySecretFile.txt";
const PINNED_SIZE_A: u64 = 36;
const PINNED_SHA_A: &str = "33e2d40b1841dbfa6afd962ca18960aa9cb00e22cb17cd33fbf32e9edfd157b2";
const PINNED_NAME_B: &str = "WELCOME.rtf";
const PINNED_SIZE_B: u64 = 471;
const PINNED_SHA_B: &str = "1286c35d9352296431945ec8a08d28db2cc7474d233d891aff1eaf148b4cb43f";

/// FIL-04-T16: the old key file's backup beside the vault still opens it: a password
/// rewrap could never reach these copies. Disclosed by S6; this crate has no rewrap.
#[test]
fn fil04_t16_a_retained_key_backup_still_opens_the_vault() {
    let source = desktop_vault();
    let copy = fresh("backup").join("copy");
    copy_tree(&source, &copy);
    let backup = fs::read(copy.join("masterkey.cryptomator.5C0CF15A.bkup")).unwrap();
    assert_eq!(
        backup,
        fs::read(copy.join("masterkey.cryptomator")).unwrap()
    );
    fs::write(copy.join("masterkey.cryptomator"), b"{}").unwrap();
    let stores = Stores::open(&fresh("peer-stores").join("stores")).unwrap();
    assert!(
        Vault::unlock(
            &copy,
            &secret("cryptomator-vault-sync"),
            &stores,
            &mut |_, _| true
        )
        .is_err()
    );
    fs::write(copy.join("masterkey.cryptomator"), backup).unwrap();
    assert!(
        Vault::unlock(
            &copy,
            &secret("cryptomator-vault-sync"),
            &stores,
            &mut |_, _| true
        )
        .is_ok()
    );
}

/// A write into a copy of the desktop-made vault reads back and leaves its own objects
/// byte-identical: the same keys, the same names (Larsal to Larsal, not the peer tool).
#[test]
fn peer_desktop_made_copy_takes_a_new_file_and_keeps_the_rest() {
    let copy = fresh("copy").join("copy");
    copy_tree(&desktop_vault(), &copy);
    let before = common::raw_tree(&copy);
    let vault = open(&copy, "cryptomator-vault-sync");
    let root = vault.root_dir().unwrap();
    let node = vault
        .create_file(
            &root,
            "new from larsal.txt",
            &mut &b"new"[..],
            3,
            &mut |_, _| true,
        )
        .unwrap();
    assert_eq!(read_all(&vault, &node), b"new");
    let after = common::raw_tree(&copy);
    for (path, hash) in &before {
        assert_eq!(after.get(path), Some(hash), "{path}");
    }
    assert_eq!(after.len(), before.len() + 1);
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn outside_vaults() -> PathBuf {
    PathBuf::from(std::env::var_os("LARSAL_PEER_VAULTS").expect("set LARSAL_PEER_VAULTS"))
}

/// The vault the public library made: every entry equal to its manifest, long names
/// included; the link is listed, its target bytes readable, and it is never followed
/// (FIL-04.11). A second session finds the same thing.
#[test]
#[ignore = "reads a vault that may not be committed: set LARSAL_PEER_VAULTS"]
fn peer_library_made_gcm_vault_every_entry_equals_its_manifest() {
    let folder = outside_vaults();
    let manifest =
        json::from_slice_unique(&fs::read(folder.join("vault-gcm.json")).unwrap()).unwrap();
    assert_eq!(
        manifest.get("cipherCombo").and_then(Value::as_str),
        Some("SIV_GCM")
    );
    let password = manifest.get("password").and_then(Value::as_str).unwrap();
    let entries = manifest.get("entries").and_then(Value::as_object).unwrap();
    let path = folder.join("vault-gcm");
    let before = common::raw_tree(&path);
    let vault = open(&path, password);
    let mut found = BTreeMap::new();
    walk(&vault, &vault.root_dir().unwrap(), "", &mut found);
    let mut want = BTreeMap::new();
    for (entry, about) in entries {
        let kind = about.get("type").and_then(Value::as_str).unwrap();
        let row = match kind {
            "dir" => Found::Dir,
            "file" => Found::File {
                size: about.get("size").and_then(Value::as_u64).unwrap(),
                sha256: about
                    .get("sha256")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_owned(),
            },
            "link" => Found::Link(
                about
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            ),
            other => panic!("{other}"),
        };
        want.insert(entry.clone(), row);
    }
    assert_eq!(found.len(), 12);
    assert_eq!(found, want);
    vault.lock();
    assert_eq!(common::raw_tree(&path), before, "read only");
    // No operating system link came to exist.
    assert!(common::raw_tree(&path).values().all(|v| v != "special"));
}

/// What a directory backup holds, read by hand from the library-made vault: each
/// `dirid.c9r` opens under the encryption key and holds the ID of the folder it stands
/// in, not its parent's. The public page reads the other way (proposed-cards.md); the
/// real vaults decide, and Larsal writes what they hold.
#[test]
#[ignore = "reads a vault that may not be committed: set LARSAL_PEER_VAULTS"]
fn peer_library_made_dir_backups_hold_their_own_folder_id() {
    use larsal_crypto::secret::SecretBytes;
    use larsal_crypto::{base64, gcm, kdf, keywrap};
    let folder = outside_vaults();
    let manifest =
        json::from_slice_unique(&fs::read(folder.join("vault-gcm.json")).unwrap()).unwrap();
    let password = manifest.get("password").and_then(Value::as_str).unwrap();
    let path = folder.join("vault-gcm");
    let key =
        json::from_slice_unique(&fs::read(path.join("masterkey.cryptomator")).unwrap()).unwrap();
    let b64 = |n: &str| {
        base64::decode(
            base64::Form::Padded,
            key.get(n).and_then(Value::as_str).unwrap(),
        )
        .unwrap()
    };
    let log_n = key
        .get("scryptCostParam")
        .and_then(Value::as_u64)
        .unwrap()
        .trailing_zeros() as u8;
    let r = key.get("scryptBlockSize").and_then(Value::as_u64).unwrap() as u32;
    let kek = kdf::scrypt(password.as_bytes(), &b64("scryptSalt"), log_n, r, 1, 32).unwrap();
    let enc = keywrap::unwrap(&kek, &b64("primaryMasterKey")).unwrap();
    let mac_key = keywrap::unwrap(&kek, &b64("hmacMasterKey")).unwrap();
    let enc32: [u8; 32] = enc.expose().try_into().unwrap();
    let mac32: [u8; 32] = mac_key.expose().try_into().unwrap();
    let mut folders = 0;
    for (object, _) in common::raw_tree(&path) {
        let Some(place) = object.strip_suffix("/dirid.c9r") else {
            continue;
        };
        let raw = fs::read(path.join(&object)).unwrap();
        let mut head = raw[12..52].to_vec();
        let enc_key = SecretBytes::new(enc32.to_vec());
        let nonce: [u8; 12] = raw[..12].try_into().unwrap();
        gcm::open_in_place(
            &enc_key,
            &nonce,
            b"",
            &mut head,
            raw[52..68].try_into().unwrap(),
        )
        .unwrap();
        let ck = SecretBytes::new(head[8..].to_vec());
        let chunk = &raw[68..];
        let mut body = chunk[12..chunk.len() - 16].to_vec();
        let mut aad = 0u64.to_be_bytes().to_vec();
        aad.extend_from_slice(&nonce);
        gcm::open_in_place(
            &ck,
            chunk[..12].try_into().unwrap(),
            &aad,
            &mut body,
            chunk[chunk.len() - 16..].try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(common::dir_path(&enc32, &mac32, &body), place, "{place}");
        folders += 1;
    }
    assert_eq!(folders, 4, "the top folder and the three of the manifest");
}

/// The same library's other cipher: refused by name, never a success.
#[test]
#[ignore = "reads a vault that may not be committed: set LARSAL_PEER_VAULTS"]
fn peer_library_made_ctrmac_vault_is_refused_by_name() {
    let folder = outside_vaults();
    let manifest =
        json::from_slice_unique(&fs::read(folder.join("vault-ctrmac.json")).unwrap()).unwrap();
    assert_eq!(
        manifest.get("cipherCombo").and_then(Value::as_str),
        Some("SIV_CTRMAC")
    );
    let password = manifest.get("password").and_then(Value::as_str).unwrap();
    let stores = Stores::open(&fresh("peer-stores").join("stores")).unwrap();
    let got = Vault::unlock(
        &folder.join("vault-ctrmac"),
        &secret(password),
        &stores,
        &mut |_, _| true,
    );
    assert_eq!(got.err(), Some(Error::Profile(Refused::SivCtrMac)));
}

/// The way back, for a later peer run: makes a vault with Larsal holding the FIL-04.14
/// sizes and names, and writes the exact tree and hashes beside it. This test proves only
/// that Larsal reopens what it wrote; opening it in the peer tool stays OPEN
/// (PEER-RUN.md names the steps).
#[test]
#[ignore = "writes a vault for a later peer run: set LARSAL_PEER_EXPORT"]
fn peer_export_a_larsal_vault_for_the_later_peer_run() {
    let export =
        PathBuf::from(std::env::var_os("LARSAL_PEER_EXPORT").expect("set LARSAL_PEER_EXPORT"));
    fs::create_dir_all(&export).unwrap();
    let path = export.join("larsal-made-vault");
    let password = "demo password for the peer run \u{2713}";
    let stores = Stores::open(&fresh("peer-stores").join("stores")).unwrap();
    let vault = Vault::create(&path, &secret(password), &stores, &mut |_, _| true).unwrap();
    let root = vault.root_dir().unwrap();
    let mut want = BTreeMap::new();
    let long = format!("{}.txt", "long-name-".repeat(25));
    let sizes: [(&str, usize); 6] = [
        ("size-0.bin", 0),
        ("size-1.bin", 1),
        ("size-32767.bin", 32_767),
        ("size-32768.bin", 32_768),
        ("size-32769.bin", 32_769),
        ("size-65536.bin", 65_536),
    ];
    let mut put = |parent: &Node, prefix: &str, name: &str, bytes: &[u8]| {
        vault
            .create_file(
                parent,
                name,
                &mut &bytes[..],
                bytes.len() as u64,
                &mut |_, _| true,
            )
            .unwrap();
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        want.insert(
            path,
            Found::File {
                size: bytes.len() as u64,
                sha256: sha256_hex(bytes),
            },
        );
    };
    for (name, size) in sizes {
        put(&root, "", name, &common::demo_bytes(size, 17));
    }
    put(&root, "", &long, b"a long name");
    put(
        &root,
        "",
        "Zaz\u{307}o\u{301}\u{142}c\u{301} composed on the way in \u{2713}.txt",
        b"unicode name",
    );
    let nested = vault.make_dir(&root, "nested folder").unwrap();
    let inner = vault.make_dir(&nested, "inner").unwrap();
    put(&inner, "nested folder/inner", "deep.txt", b"deep");
    vault.make_dir(&root, "empty folder").unwrap();
    // 207 bytes: within the 255 of FIL-06.2, and its stored name is past the threshold.
    let long_dir = format!("{}-folder", "long-name-".repeat(20));
    let long_node = vault.make_dir(&root, &long_dir).unwrap();
    put(
        &long_node,
        &long_dir.clone(),
        "inside.txt",
        b"inside a long folder",
    );
    for dir in [
        "nested folder",
        "nested folder/inner",
        "empty folder",
        long_dir.as_str(),
    ] {
        want.insert(dir.to_owned(), Found::Dir);
    }
    // The rest of the CRUD matrix of FIL-04.14, so the peer reads their results: a file
    // written again, one renamed into another folder, one deleted, one folder deleted.
    let edited = vault
        .create_file(&root, "edited.txt", &mut &b"first"[..], 5, &mut |_, _| true)
        .unwrap();
    let base = vault.capture(&edited, &mut |_, _| true).unwrap().digest();
    vault
        .update_file(
            &edited,
            &base,
            &mut &b"second version"[..],
            14,
            &mut |_, _| true,
        )
        .unwrap();
    want.insert(
        "edited.txt".to_owned(),
        Found::File {
            size: 14,
            sha256: sha256_hex(b"second version"),
        },
    );
    let moved = vault
        .create_file(
            &root,
            "before rename.txt",
            &mut &b"moved"[..],
            5,
            &mut |_, _| true,
        )
        .unwrap();
    vault.rename(&moved, &nested, "after rename.txt").unwrap();
    want.insert(
        "nested folder/after rename.txt".to_owned(),
        Found::File {
            size: 5,
            sha256: sha256_hex(b"moved"),
        },
    );
    let gone = vault
        .create_file(&root, "deleted.txt", &mut &b"gone"[..], 4, &mut |_, _| true)
        .unwrap();
    let base = vault.capture(&gone, &mut |_, _| true).unwrap().digest();
    vault.delete_file(&gone, &base).unwrap();
    let gone_dir = vault.make_dir(&root, "deleted folder").unwrap();
    vault.delete_dir(&gone_dir).unwrap();
    let mut want_nfc = BTreeMap::new();
    for (k, v) in want {
        want_nfc.insert(
            larsal_crypto::text::nfc_bounded(&k, 8192)
                .unwrap()
                .expose()
                .to_owned(),
            v,
        );
    }
    let mut found = BTreeMap::new();
    walk(&vault, &root, "", &mut found);
    assert_eq!(
        found, want_nfc,
        "Larsal reads back what it wrote; the peer tool's read is OPEN"
    );
    vault.lock();

    let mut out = String::from("{\n  \"status\": \"OPEN: not yet opened by any peer tool\",\n");
    out.push_str(&format!("  \"password\": {},\n", Value::from(password)));
    out.push_str("  \"entries\": {\n");
    let rows: Vec<String> = found
        .iter()
        .map(|(path, row)| {
            let about = match row {
                Found::Dir => "{\"type\":\"dir\"}".to_owned(),
                Found::File { size, sha256 } => {
                    format!("{{\"type\":\"file\",\"size\":{size},\"sha256\":\"{sha256}\"}}")
                }
                Found::Link(target) => format!("{{\"type\":\"link\",\"hex\":\"{}\"}}", hex(target)),
            };
            format!("    {}: {about}", Value::from(path.as_str()))
        })
        .collect();
    out.push_str(&rows.join(",\n"));
    out.push_str("\n  },\n  \"rawObjects\": {\n");
    let raw: Vec<String> = common::raw_tree(&path)
        .iter()
        .map(|(object, sha)| {
            format!(
                "    {}: {}",
                Value::from(object.as_str()),
                Value::from(sha.as_str())
            )
        })
        .collect();
    out.push_str(&raw.join(",\n"));
    out.push_str("\n  }\n}\n");
    fs::write(export.join("larsal-made-vault.json"), out).unwrap();
}
