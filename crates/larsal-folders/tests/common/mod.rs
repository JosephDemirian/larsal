//! Test helpers: an independent writer of the public format, through larsal-crypto only,
//! so a test folder is not made by the code it checks and costs little to make. Demo data
//! only.
#![allow(dead_code)]
#![allow(clippy::arithmetic_side_effects)]

use larsal_crypto::base64::{self, Form};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{gcm, hash, kdf, keywrap, mac, siv};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const PASSWORD: &str = "demo password for folders";
pub const ENC: [u8; 32] = [0xE1; 32];
pub const MAC: [u8; 32] = [0xA7; 32];
pub const CHUNK: usize = 32_768;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh private folder under this run's temporary folder.
pub fn fresh(tag: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lf-{tag}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

pub fn secret(text: &str) -> SecretString {
    SecretString::new(text.to_owned())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(hash::sha256(&[bytes]).expose())
}

pub fn siv_key(enc: &[u8; 32], mac_key: &[u8; 32]) -> SecretBytes {
    SecretBytes::new([&mac_key[..], &enc[..]].concat())
}

fn base32(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = String::new();
    for b in bytes {
        bits.push_str(&format!("{b:08b}"));
    }
    bits.as_bytes()
        .chunks(5)
        .map(|c| {
            let text = std::str::from_utf8(c).unwrap();
            let v = usize::from_str_radix(&format!("{text:0<5}"), 2).unwrap();
            char::from(A[v])
        })
        .collect()
}

/// The path below `d/` of a directory ID.
pub fn dir_path(enc: &[u8; 32], mac_key: &[u8; 32], id: &[u8]) -> String {
    let none: [&[u8]; 0] = [];
    let sealed = siv::seal(&siv_key(enc, mac_key), &none, id).unwrap();
    let text = base32(hash::sha1(&[&sealed]).expose());
    format!("d/{}/{}", &text[..2], &text[2..32])
}

pub fn raw_name(enc: &[u8; 32], mac_key: &[u8; 32], parent: &[u8], name: &str) -> String {
    let sealed = siv::seal(&siv_key(enc, mac_key), &[parent], name.as_bytes()).unwrap();
    format!("{}.c9r", base64::encode(Form::UrlPadded, &sealed))
}

pub fn deflated(stored: &str) -> String {
    format!(
        "{}.c9s",
        base64::encode(Form::UrlPadded, hash::sha1(&[stored.as_bytes()]).expose())
    )
}

/// A stored file with a known content key and nonces, made by hand.
pub fn seal_with(
    enc: &[u8; 32],
    content_key: &[u8; 32],
    plain: &[u8],
    one_empty_chunk: bool,
) -> Vec<u8> {
    let key = SecretBytes::new(enc.to_vec());
    let nonce: [u8; 12] = hash::sha256(&[content_key, b"nonce"]).expose()[..12]
        .try_into()
        .unwrap();
    let mut payload = vec![0xFFu8; 8];
    payload.extend_from_slice(content_key);
    let tag = gcm::seal_in_place(&key, &nonce, b"", &mut payload).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&payload);
    out.extend_from_slice(&tag);
    let ck = SecretBytes::new(content_key.to_vec());
    let mut chunks: Vec<&[u8]> = plain.chunks(CHUNK).collect();
    if chunks.is_empty() && one_empty_chunk {
        chunks.push(b"");
    }
    for (i, part) in chunks.iter().enumerate() {
        let n: [u8; 12] = hash::sha256(&[content_key, &(i as u64).to_be_bytes()]).expose()[..12]
            .try_into()
            .unwrap();
        let mut aad = (i as u64).to_be_bytes().to_vec();
        aad.extend_from_slice(&nonce);
        let mut data = part.to_vec();
        let t = gcm::seal_in_place(&ck, &n, &aad, &mut data).unwrap();
        out.extend_from_slice(&n);
        out.extend_from_slice(&data);
        out.extend_from_slice(&t);
    }
    out
}

pub fn seal_plain(enc: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let key: [u8; 32] = hash::sha256(&[plain, b"demo content key"])
        .expose()
        .try_into()
        .unwrap();
    seal_with(enc, &key, plain, false)
}

pub fn jws(enc: &[u8; 32], mac_key: &[u8; 32], header: &str, claims: &str) -> String {
    let input = format!(
        "{}.{}",
        base64::encode(Form::Url, header.as_bytes()),
        base64::encode(Form::Url, claims.as_bytes())
    );
    let raw = [&enc[..], &mac_key[..]].concat();
    let tag = if header.contains("HS384") {
        mac::hmac_sha384(&raw, &[input.as_bytes()]).unwrap()
    } else if header.contains("HS512") {
        mac::hmac_sha512(&raw, &[input.as_bytes()]).unwrap()
    } else {
        mac::hmac_sha256(&raw, &[input.as_bytes()]).unwrap()
    };
    format!("{input}.{}", base64::encode(Form::Url, tag.expose()))
}

pub const HEADER: &str =
    r#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWT","alg":"HS256"}"#;
pub const CLAIMS: &str = r#"{"format":8,"shorteningThreshold":220,"jti":"ce976f7a-7b92-4cc0-b4c1-c74a6aa17cf5","cipherCombo":"SIV_GCM"}"#;

pub struct KeySettings {
    pub log_n: u8,
    pub r: u32,
    pub salt: Vec<u8>,
    pub version: u32,
}

impl Default for KeySettings {
    fn default() -> Self {
        Self {
            log_n: 4,
            r: 8,
            salt: vec![0x5A; 16],
            version: 999,
        }
    }
}

pub fn key_file(password: &str, s: &KeySettings) -> String {
    let normal = larsal_crypto::text::nfc_bounded(password, 1 << 20).unwrap();
    let kek = kdf::scrypt(normal.expose().as_bytes(), &s.salt, s.log_n, s.r, 1, 32).unwrap();
    let w = |k: &[u8; 32]| keywrap::wrap(&kek, &SecretBytes::new(k.to_vec())).unwrap();
    let version_mac = mac::hmac_sha256(&MAC, &[&s.version.to_be_bytes()]).unwrap();
    format!(
        r#"{{"version":{},"scryptSalt":"{}","scryptCostParam":{},"scryptBlockSize":{},"primaryMasterKey":"{}","hmacMasterKey":"{}","versionMac":"{}"}}"#,
        s.version,
        base64::encode(Form::Padded, &s.salt),
        1u64 << s.log_n,
        s.r,
        base64::encode(Form::Padded, &w(&ENC)),
        base64::encode(Form::Padded, &w(&MAC)),
        base64::encode(Form::Padded, version_mac.expose()),
    )
}

/// A whole small folder by hand: low key cost, the demo keys, an empty top folder.
pub fn make_folder(path: &Path, password: &str) {
    make_folder_with(
        path,
        &key_file(password, &KeySettings::default()),
        &jws(&ENC, &MAC, HEADER, CLAIMS),
    );
}

pub fn make_folder_with(path: &Path, key: &str, config: &str) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path.join("masterkey.cryptomator"), key).unwrap();
    fs::write(path.join("vault.cryptomator"), config).unwrap();
    let root = path.join(dir_path(&ENC, &MAC, b""));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("dirid.c9r"),
        seal_with(&ENC, &[0x77; 32], b"", true),
    )
    .unwrap();
}

/// Every raw object below `root`, by relative path, with its SHA-256; a folder as
/// `<path>/` with no hash.
pub fn raw_tree(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let kind = fs::symlink_metadata(&path).unwrap().file_type();
            if kind.is_dir() {
                out.insert(format!("{rel}/"), String::new());
                walk(root, &path, out);
            } else if kind.is_file() {
                out.insert(rel, sha256_hex(&fs::read(&path).unwrap()));
            } else {
                out.insert(rel, "special".to_owned());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// True when any file below `root` holds `marker`, or any name does.
pub fn tree_holds(root: &Path, marker: &[u8]) -> bool {
    raw_tree(root).keys().any(|name| {
        let path = root.join(name.trim_end_matches('/'));
        name.as_bytes().windows(marker.len()).any(|w| w == marker)
            || fs::symlink_metadata(&path).is_ok_and(|m| m.is_file())
                && fs::read(&path)
                    .unwrap()
                    .windows(marker.len())
                    .any(|w| w == marker)
    })
}

/// Bytes that are not all alike, with a seed.
pub fn demo_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i % 251) as u8).wrapping_mul(3).wrapping_add(seed))
        .collect()
}
