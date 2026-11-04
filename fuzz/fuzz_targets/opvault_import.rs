//! Fuzz target `opvault_import` (E4-S13): the OPVault import (FEA-08
//! section D). Must never panic, hang or allocate by a hostile number
//! (FEA-08.34: opdata01 sizes are checked before any allocation). A result
//! keeps the model invariants, also after placement into an open vault.
//!
//! Input: a mode byte, then the rest split at byte 0x1E. Mode bit 0
//! clear: the parts are the files `profile.js`, `folders.js`,
//! `band_0.js`, `band_F.js` and one attachment, read without a password
//! (layout checks only: the PBKDF2 cost comes from the file). Set: the
//! parts are plaintexts the target encrypts into a valid vault with fixed
//! keys and 1 PBKDF2 round: an item's overview and details JSON, a folder
//! overview, an attachment's metadata JSON and content, so items,
//! sections, folders and attachments are reached. Mode bits 1 to 3 pick
//! the category, bit 4 trashes the item, bit 5 makes the folder smart.
#![no_main]

use app_core::import::opvault::{self, Folder};
use app_core::import::{self, Context, ImportError, Limit};
use app_core::time::Utc;
use app_crypto::cipher::{Cipher, Encryptor};
use app_crypto::hash::sha512;
use app_crypto::kdf::{self, Prf};
use app_crypto::mac::hmac_sha256;
use app_crypto::secret::{SecretBytes, SecretString};
use app_model::{Group, Time, Uuid, Vault};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::AtomicBool;

struct Mem(Vec<(String, Vec<u8>)>);

impl Folder for Mem {
    fn file(&self, name: &str, max: u64, over: Limit) -> Result<Option<SecretBytes>, ImportError> {
        match self.0.iter().find(|(n, _)| n == name) {
            None => Ok(None),
            Some((_, b)) if b.len() as u64 > max => Err(ImportError::TooLarge(over)),
            Some((_, b)) => Ok(Some(SecretBytes::new(b.clone()))),
        }
    }
    fn names(&self) -> Result<Vec<String>, ImportError> {
        Ok(self.0.iter().map(|(n, _)| n.clone()).collect())
    }
}

struct Keys {
    enc: SecretBytes,
    mac: SecretBytes,
}

fn split(b: &[u8]) -> Keys {
    Keys {
        enc: SecretBytes::new(b[..32].to_vec()),
        mac: SecretBytes::new(b[32..64].to_vec()),
    }
}

fn b64(b: &[u8]) -> String {
    app_crypto::base64::encode(app_crypto::base64::Form::Padded, b)
}

fn cbc(key: &SecretBytes, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut e = Encryptor::new(Cipher::Aes256Cbc, key, iv).unwrap();
    e.update(data).unwrap() // whole blocks only: no padding
}

fn opdata(plain: &[u8], k: &Keys) -> Vec<u8> {
    let p = 16 - plain.len() % 16;
    let iv = [9u8; 16];
    let mut data = vec![7u8; p];
    data.extend(plain);
    let mut out = b"opdata01".to_vec();
    out.extend((plain.len() as u64).to_le_bytes());
    out.extend(iv);
    out.extend(cbc(&k.enc, &iv, &data));
    let tag = hmac_sha256(k.mac.expose(), &[&out]).unwrap();
    out.extend(tag.expose());
    out
}

/// A JSON string literal of `s`.
fn js(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn ctx_run(mem: &Mem, pw: Option<&SecretString>) {
    let cancel = AtomicBool::new(false);
    let now = Time(63_900_000_000);
    let ctx = Context::new(now, &Utc, &cancel);
    let Ok(r) = opvault::read(mem, "fuzz.opvault", pw, &ctx) else {
        return;
    };
    assert_eq!(app_model::invariants::check(&r.vault), Ok(()));
    let _ = import::preview(&r);
    let mut root = Group::new(Uuid([1; 16]), "Root".into(), now);
    root.groups
        .push(Group::new(Uuid([2; 16]), "Work".into(), now));
    let mut target = Vault::new(root, now);
    if import::into_group(&mut target, Uuid([2; 16]), r, now).is_ok() {
        assert_eq!(app_model::invariants::check(&target), Ok(()));
    }
}

const ID: &str = "00000000000000000000000000000001";

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let parts: Vec<&[u8]> = rest.split(|&b| b == 0x1E).take(5).collect();
    let part = |i: usize| parts.get(i).copied().unwrap_or(&[]);
    if mode & 1 == 0 {
        let names = ["profile.js", "folders.js", "band_0.js", "band_F.js"];
        let mut files: Vec<(String, Vec<u8>)> = names
            .iter()
            .enumerate()
            .map(|(i, n)| ((*n).to_owned(), part(i).to_vec()))
            .collect();
        files.push((format!("{ID}_A.attachment"), part(4).to_vec()));
        ctx_run(&Mem(files), None);
        return;
    }
    let pw = SecretString::new("demo-opv-pass".into());
    let salt = [5u8; 16];
    let derived = kdf::pbkdf2(
        Prf::Sha512,
        &SecretBytes::new(pw.expose().as_bytes().to_vec()),
        &salt,
        1,
        64,
    )
    .unwrap();
    let derived = split(derived.expose());
    let (master_raw, overview_raw) = ([3u8; 256], [4u8; 64]);
    let master = split(sha512(&[&master_raw]).expose());
    let overview = split(sha512(&[&overview_raw]).expose());
    let profile = format!(
        "var profile={{\"salt\":\"{}\",\"iterations\":1,\"masterKey\":\"{}\",\"overviewKey\":\"{}\",\"uuid\":\"E4F7000000000000000000000000A4EE\",\"createdAt\":1587218949}};",
        b64(&salt),
        b64(&opdata(&master_raw, &derived)),
        b64(&opdata(&overview_raw, &derived)),
    );
    let item_raw = [6u8; 64];
    let item_keys = split(&item_raw);
    let kiv = [8u8; 16];
    let kct = cbc(&master.enc, &kiv, &item_raw);
    let mut k = kiv.to_vec();
    k.extend(&kct);
    k.extend(hmac_sha256(master.mac.expose(), &[&k]).unwrap().expose());
    let categories = ["001", "002", "003", "005", "099", "111", "999", ""];
    let category = categories[usize::from((mode >> 1) & 7)];
    let trashed = mode & 16 != 0;
    // The item's members as LD-45's check reads them: (key, text, JSON).
    let mut members: Vec<(&str, String, String)> = vec![
        ("category", category.to_owned(), js(category)),
        ("created", "1600000000".to_owned(), "1600000000".to_owned()),
        ("d", b64(&opdata(part(1), &item_keys)), String::new()),
        ("k", b64(&k), String::new()),
        ("o", b64(&opdata(part(0), &overview)), String::new()),
        (
            "trashed",
            if trashed { "1" } else { "0" }.to_owned(),
            trashed.to_string(),
        ),
        ("updated", "1600000100".to_owned(), "1600000100".to_owned()),
        ("uuid", ID.to_owned(), js(ID)),
    ];
    for m in &mut members {
        if m.2.is_empty() {
            m.2 = js(&m.1);
        }
    }
    let mut msg = Vec::new();
    for (key, text, _) in &members {
        msg.extend(key.as_bytes());
        msg.extend(text.as_bytes());
    }
    let check = b64(hmac_sha256(overview.mac.expose(), &[&msg])
        .unwrap()
        .expose());
    let mut item: Vec<String> = members
        .iter()
        .map(|(k, _, j)| format!("{}:{j}", js(k)))
        .collect();
    item.push(format!("\"hmac\":{}", js(&check)));
    let band = format!("ld({{\"x\":{{{}}}}});", item.join(","));
    let smart = if mode & 32 != 0 {
        ",\"smart\":true,\"predicate_b64\":\"AQID\""
    } else {
        ""
    };
    let folders = format!(
        "loadFolders({{\"f\":{{\"uuid\":\"F0000000000000000000000000000001\",\"overview\":\"{}\"{smart}}}}});",
        b64(&opdata(part(2), &overview))
    );
    let meta = part(3);
    let icon = opdata(b"icon", &item_keys);
    let mut attachment = b"OPCLDAT\x01".to_vec();
    attachment.extend((meta.len().min(65_535) as u16).to_le_bytes());
    attachment.extend([0, 0]);
    attachment.extend((icon.len() as u32).to_le_bytes());
    attachment.extend(&meta[..meta.len().min(65_535)]);
    attachment.extend(&icon);
    attachment.extend(opdata(part(4), &item_keys));
    let files = vec![
        ("profile.js".to_owned(), profile.into_bytes()),
        ("folders.js".to_owned(), folders.into_bytes()),
        ("band_0.js".to_owned(), band.into_bytes()),
        (format!("{ID}_AAAA.attachment"), attachment),
    ];
    ctx_run(&Mem(files), Some(&pw));
});
