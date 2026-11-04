//! Shared helpers for the app-share tests: the card's demo vault V, a
//! fixed host, zip archives and a throwaway folder.
#![allow(dead_code)]

use app_core::edit::SHARED_KEY;
use app_crypto::kdf::{Host, SpeedRecord};
use app_crypto::secret::SecretString;
use app_model::{CustomDataItem, Entry, Field, Group, Kdf, Time, Uuid, Vault};
use app_share::settings::Settings;
use std::io::Write;
use std::path::{Path, PathBuf};

/// T0 = 2026-01-01T00:00:00Z (INT-08 notation), in seconds since 0001-01-01.
pub const T0: Time = Time(63_902_822_400);
/// T2 = 2026-03-01T00:00:00Z: the time of the export under test.
pub const NOW: Time = Time(63_907_920_000);
/// The share password of the card's cases.
pub const SHARE_PASSWORD: &str = "demo-share-1";

/// id(xx): 16 bytes of `n`.
pub fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}

pub fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

pub fn field(v: &str, protected: bool) -> Field {
    Field {
        value: secret(v),
        protected,
    }
}

pub fn entry(n: u8, title: &str, user: &str, password: &str) -> Entry {
    let mut e = Entry::new(id(n), T0);
    e.set_field("Title".into(), field(title, false));
    e.set_field("UserName".into(), field(user, false));
    e.set_field("Password".into(), field(password, true));
    e
}

/// The share item key as text.
pub fn share_key() -> String {
    String::from_utf8(SHARED_KEY.to_vec()).unwrap()
}

/// Puts `s` as the share item of `g`.
pub fn set_share(g: &mut Group, s: &mut Settings) {
    let value = s.write().unwrap();
    g.custom_data.items.push(CustomDataItem {
        key: share_key(),
        value,
        last_modified: None,
        unknown: Vec::new(),
    });
}

/// Export settings for `path` with the card's share password.
pub fn export_to(path: &str) -> Settings {
    Settings {
        export: true,
        path: path.to_owned(),
        password: secret(SHARE_PASSWORD),
        ..Settings::new()
    }
}

/// V (INT-08 Test cases): root(01) → Team(20) → Mail(0A) {Mail, ann,
/// pw-1, history pw-0}, Bank(0B) {pw-b}; Team → Sub(21) → Wiki(0C)
/// {pw-w}. Team shares to `team.appvault`. Cheap AES-KDF, so tests are
/// quick.
pub fn v() -> Vault {
    let mut mail = entry(0x0A, "Mail", "ann", "pw-1");
    let mut old = mail.duplicate(false);
    old.set_field("Password".into(), field("pw-0", true));
    mail.history.push(old);
    let mut sub = Group::new(id(0x21), "Sub".into(), T0);
    sub.entries.push(entry(0x0C, "Wiki", "", "pw-w"));
    let mut team = Group::new(id(0x20), "Team".into(), T0);
    team.entries.push(mail);
    team.entries.push(entry(0x0B, "Bank", "", "pw-b"));
    team.groups.push(sub);
    set_share(&mut team, &mut export_to("team.appvault"));
    let mut root = Group::new(id(0x01), "Root".into(), T0);
    root.groups.push(team);
    let mut v = Vault::new(root, T0);
    v.meta.name = "V".into();
    v.encryption.kdf = Kdf::AesKdf { rounds: 1_000 };
    v
}

/// A host with fixed speed records and 16 GiB (CRY-02.14 test hooks).
pub fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: Some(SpeedRecord {
            count: 3,
            memory_kib: 65_536,
            lanes: 4,
            ms: 300,
        }),
        aes_record: Some(SpeedRecord {
            count: 10_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 100,
        }),
    }
}

/// The group `uuid` of `v`.
pub fn group(v: &Vault, uuid: Uuid) -> &Group {
    v.root.find_group(uuid).expect("group present")
}

/// The live entry `uuid` of `v`.
pub fn find(v: &Vault, uuid: Uuid) -> &Entry {
    v.root
        .all_entries()
        .find(|e| e.uuid == uuid)
        .expect("entry present")
}

/// Titles of a group's entries, in stored order.
pub fn titles(g: &Group) -> Vec<&str> {
    g.entries.iter().map(|e| e.value("Title")).collect()
}

/// One zip member: name bytes, content, deflated or stored, and the
/// uncompressed size the headers declare (`None`: the real one).
pub struct Member<'a> {
    pub name: &'a [u8],
    pub content: &'a [u8],
    pub deflate: bool,
    pub declared: Option<u32>,
}

/// A zip archive of `members`: local headers, central directory, end
/// record; no extra fields, no ZIP64.
pub fn zip(members: &[Member<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for m in members {
        let body = if m.deflate {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(m.content).unwrap();
            e.finish().unwrap()
        } else {
            m.content.to_vec()
        };
        let mut crc = flate2::Crc::new();
        crc.update(m.content);
        let method: u16 = if m.deflate { 8 } else { 0 };
        let size = m.declared.unwrap_or(m.content.len() as u32);
        let offset = out.len() as u32;
        let head = |v: &mut Vec<u8>| {
            v.extend(method.to_le_bytes());
            v.extend([0u8; 4]);
            v.extend(crc.sum().to_le_bytes());
            v.extend((body.len() as u32).to_le_bytes());
            v.extend(size.to_le_bytes());
            v.extend((m.name.len() as u16).to_le_bytes());
            v.extend(0u16.to_le_bytes());
        };
        out.extend(0x0403_4b50u32.to_le_bytes());
        out.extend([20, 0, 0, 0]);
        head(&mut out);
        out.extend(m.name);
        out.extend(&body);
        cd.extend(0x0201_4b50u32.to_le_bytes());
        cd.extend([20, 0, 20, 0, 0, 0]);
        head(&mut cd);
        cd.extend([0u8; 10]);
        cd.extend(offset.to_le_bytes());
        cd.extend(m.name);
    }
    let cd_offset = out.len() as u32;
    out.extend(&cd);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((cd.len() as u32).to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend([0u8; 2]);
    out
}

/// A member with its real size.
pub fn member<'a>(name: &'a [u8], content: &'a [u8], deflate: bool) -> Member<'a> {
    Member {
        name,
        content,
        deflate,
        declared: None,
    }
}

/// The reference-made containers of E11-S1 (INT-08 "Reference-made
/// containers"), kept in app-core's test data.
pub fn reference_file(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../app-core/tests/data/int08")
        .join(name);
    let bytes = std::fs::read(&path).unwrap();
    if !name.ends_with(".hex") {
        return bytes;
    }
    String::from_utf8(bytes)
        .unwrap()
        .split_ascii_whitespace()
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect()
}

/// Lowercase hex of `b`.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A fresh folder under the system's temp folder, removed on drop.
pub struct Dir(pub PathBuf);

impl Dir {
    pub fn new(tag: &str) -> Dir {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("app-share-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
