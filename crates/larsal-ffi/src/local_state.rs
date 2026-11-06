//! This Mac's local state of its vaults (E15-S4), kept in Larsal's settings
//! folder and never synced, never in a vault, never next to one: per vault,
//! by its root group id, the keys this Mac retired (MOD-11.31; LD-267 (2),
//! LD-269 (2), LD-288 (2)) and the rollback guard's values (APP-05.26;
//! LD-267 (3), LD-269 (4); spec/research/sync-server.md P18 (6)): the
//! newest change time seen, the SHA-256 of the last bytes read or written,
//! the newest file version and the strongest KDF settings seen.
//!
//! Guarantees: the file holds salts, salted digests, public KDF settings,
//! times and checksums only, never a key or password byte; it is written
//! 0600 through larsal-core's safe export write; a memory-only settings store
//! keeps the state in memory only, and so does a run that found the file
//! unreadable, too large or bad, or holding a value that does not read or
//! a key it does not know: that file is never written over (F-225, F-236,
//! F-241), only a missing file starts empty. The guard's values only move
//! up, except that a change the user makes in Vault Settings sets the
//! stored KDF settings and file version to the new ones (APP-05.26).

use crate::session::Session;
use larsal_core::guard::{kdf_json, kdf_of};
use larsal_core::retired::Record;
use larsal_crypto::kdf::{Argon2Type, KdfParams};
use larsal_model::json::{self, Map, Value};
use larsal_model::{FileVersion, Kdf, Time, Uuid, Vault};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

/// The largest state file Larsal reads (as the settings files).
const MAX_FILE: u64 = 1 << 20;

/// What this Mac keeps of one vault.
#[derive(Clone, Default)]
pub(crate) struct Seen {
    /// The keys this Mac retired (MOD-11.31).
    pub(crate) retired: Vec<Record>,
    /// The newest change time seen over every version read or written.
    pub(crate) newest: Option<Time>,
    /// The SHA-256 of the last bytes Larsal read from or wrote to the file.
    pub(crate) sha: Option<[u8; 32]>,
    /// The newest file version seen (FMT-16).
    pub(crate) version: Option<FileVersion>,
    /// The strongest KDF settings seen (MOD-11.19 limit 1).
    pub(crate) kdf: Option<Kdf>,
}

/// The rollback guard's compare of one version of a vault (APP-05.26).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Verdict {
    /// Its newest change time is earlier than the stored one.
    pub(crate) older: bool,
    /// The settings it is weaker in, by name, never a value.
    pub(crate) weaker: Vec<&'static str>,
}

/// The state, loaded from its file on first use.
#[derive(Default)]
pub(crate) struct LocalState(Mutex<Inner>);

#[derive(Default)]
struct Inner {
    /// The file the map came from; `None` before the first load and for a
    /// memory-only settings store.
    file: Option<Option<PathBuf>>,
    /// The file exists but could not be read: never written in this run.
    unread: bool,
    vaults: BTreeMap<Uuid, Seen>,
}

pub(crate) use larsal_core::guard::{kdf_lower, newest};

fn sha(bytes: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(larsal_crypto::hash::sha256(&[bytes]).expose()).unwrap_or_default()
}

impl Seen {
    /// APP-05.26: the compare of a version of the vault read as `bytes`;
    /// bytes equal to the stored SHA-256 need none.
    fn compare(&self, v: &Vault, bytes: &[u8]) -> Verdict {
        if self
            .sha
            .is_some_and(|seen| larsal_crypto::secret::ct_eq(&seen, &sha(bytes)))
        {
            return Verdict::default();
        }
        let mut weaker = Vec::new();
        // The major version only: the minor one follows the content
        // (FMT-16.20), so a 4.1 vault whose last 4.1 element went is saved
        // as 4.0 by any Mac; a 3.x file after a 4.x one is the downgrade.
        if let (Some(stored), Some(read)) = (self.version, v.read_version)
            && read.major < stored.major
        {
            weaker.push("file format version");
        }
        if self
            .kdf
            .as_ref()
            .is_some_and(|k| kdf_lower(k, &v.encryption.kdf))
        {
            weaker.push("key derivation");
        }
        Verdict {
            older: self.newest.is_some_and(|n| newest(v, v.read_version) < n),
            weaker,
        }
    }

    /// The values move up with a version Larsal accepted or wrote.
    fn up(&mut self, v: &Vault, bytes: &[u8], version: Option<FileVersion>) {
        let n = newest(v, version);
        self.newest = Some(self.newest.map_or(n, |s| s.max(n)));
        self.sha = Some(sha(bytes));
        if let Some(read) = version
            && self
                .version
                .is_none_or(|s| (read.major, read.minor) > (s.major, s.minor))
        {
            self.version = Some(read);
        }
        if self
            .kdf
            .as_ref()
            .is_none_or(|k| !kdf_lower(k, &v.encryption.kdf))
        {
            self.kdf = Some(v.encryption.kdf);
        }
    }
}

impl Session {
    /// `f` on this Mac's state, loaded from the settings folder's file when
    /// that folder changed (tests and Mac QA move it); written back when
    /// `f` says it changed something.
    fn local<R>(&self, f: impl FnOnce(&mut BTreeMap<Uuid, Seen>) -> (R, bool)) -> R {
        let file = self.settings.folder().map(|d| {
            let suffix = if cfg!(debug_assertions) { "_debug" } else { "" };
            d.join(format!("vault-state{suffix}.json"))
        });
        let mut inner = self.local.0.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.file.as_ref() != Some(&file) {
            let loaded = file.as_deref().map(load);
            inner.unread = matches!(loaded, Some(None));
            inner.vaults = loaded.flatten().unwrap_or_default();
            inner.file = Some(file.clone());
        }
        let (out, changed) = f(&mut inner.vaults);
        if changed
            && !inner.unread
            && let Some(path) = &file
        {
            // ponytail: a failed write keeps the state in memory for this
            // run only; the next write tries again.
            let _ = crate::larsal_settings::write_json(path, &Value::Object(save(&inner.vaults)));
        }
        out
    }

    /// MOD-11.31: the keys this Mac retired from the vault `root`.
    pub(crate) fn retired_records(&self, root: Uuid) -> Vec<Record> {
        self.local(|m| {
            (
                m.get(&root).map(|s| s.retired.clone()).unwrap_or_default(),
                false,
            )
        })
    }

    /// MOD-11.31: this Mac retired a key of the vault `root`.
    pub(crate) fn retire(&self, root: Uuid, record: Record) {
        self.local(|m| {
            m.entry(root).or_default().retired.push(record);
            ((), true)
        });
    }

    /// APP-05.26: the guard's compare of `v`, read as `bytes`.
    pub(crate) fn guard(&self, v: &Vault, bytes: &[u8]) -> Verdict {
        self.local(|m| {
            (
                m.get(&v.root.uuid)
                    .map(|s| s.compare(v, bytes))
                    .unwrap_or_default(),
                false,
            )
        })
    }

    /// APP-05.26: Larsal accepted `v`, read as `bytes` (an unlock, a reload
    /// or a merge's disk version), or wrote it with `version`.
    pub(crate) fn seen(&self, v: &Vault, bytes: &[u8], version: Option<FileVersion>) {
        self.local(|m| {
            m.entry(v.root.uuid)
                .or_default()
                .up(v, bytes, version.or(v.read_version));
            ((), true)
        });
    }

    /// APP-05.26 (MOD-12.12): the user changed the encryption settings in
    /// Vault Settings: the stored KDF settings are the new ones, and the
    /// next save sets the file version.
    pub(crate) fn settings_set(&self, root: Uuid, kdf: Kdf) {
        self.local(|m| {
            let s = m.entry(root).or_default();
            s.kdf = Some(kdf);
            s.version = None;
            ((), true)
        });
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn unhex32(v: &Value) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(unhex(v.as_str()?)?).ok()
}

fn kind_name(d: bool) -> &'static str {
    if d { "d" } else { "id" }
}

fn params_json(k: &KdfParams) -> Value {
    let mut m = Map::new();
    match k {
        KdfParams::AesKdf { rounds, seed } => {
            m.insert("aes".into(), (*rounds).into());
            m.insert("seed".into(), hex(seed).into());
        }
        KdfParams::Argon2 {
            kind,
            version,
            iterations,
            memory_kib,
            lanes,
            salt,
        } => {
            m.insert("argon2".into(), kind_name(*kind == Argon2Type::D).into());
            m.insert("v".into(), (*version).into());
            m.insert("i".into(), (*iterations).into());
            m.insert("m".into(), (*memory_kib).into());
            m.insert("p".into(), (*lanes).into());
            m.insert("salt".into(), hex(salt).into());
        }
    }
    Value::Object(m)
}

fn params_of(v: &Value) -> Option<KdfParams> {
    if let Some(rounds) = v["aes"].as_u64() {
        return Some(KdfParams::AesKdf {
            rounds,
            seed: unhex(v["seed"].as_str()?)?,
        });
    }
    Some(KdfParams::Argon2 {
        kind: match v["argon2"].as_str()? {
            "d" => Argon2Type::D,
            "id" => Argon2Type::Id,
            _ => return None,
        },
        version: v["v"].as_u64()?,
        iterations: v["i"].as_u64()?,
        memory_kib: v["m"].as_u64()?,
        lanes: v["p"].as_u64()?,
        salt: unhex(v["salt"].as_str()?)?,
    })
}

/// True when every key of the object `v` is one of `keys` (F-241: `save`
/// writes no other, so a key it does not know is a bad byte, or a file of
/// a newer Larsal, and is never dropped without a word).
fn only(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.keys().all(|k| keys.contains(&k.as_str())))
}

fn record_of(v: &Value) -> Option<Record> {
    if !only(v, &["salt", "digest", "alone", "kdf", "v4"]) {
        return None;
    }
    Some(Record {
        salt: unhex32(&v["salt"])?,
        digest: unhex32(&v["digest"])?,
        alone: match &v["alone"] {
            Value::Null => None,
            a => Some(unhex32(a)?),
        },
        kdf: params_of(&v["kdf"])?,
        v4: v["v4"].as_bool()?,
    })
}

fn save(vaults: &BTreeMap<Uuid, Seen>) -> Map {
    let mut out = Map::new();
    for (root, s) in vaults {
        let mut m = Map::new();
        let records: Vec<Value> = s
            .retired
            .iter()
            .map(|r| {
                let mut o = Map::new();
                o.insert("salt".into(), hex(&r.salt).into());
                o.insert("digest".into(), hex(&r.digest).into());
                if let Some(a) = r.alone {
                    o.insert("alone".into(), hex(&a).into());
                }
                o.insert("kdf".into(), params_json(&r.kdf));
                o.insert("v4".into(), r.v4.into());
                Value::Object(o)
            })
            .collect();
        m.insert("retired".into(), records.into());
        if let Some(n) = s.newest {
            m.insert("newest".into(), n.0.into());
        }
        if let Some(h) = s.sha {
            m.insert("sha256".into(), hex(&h).into());
        }
        if let Some(v) = s.version {
            m.insert(
                "version".into(),
                [u32::from(v.major), u32::from(v.minor)].into(),
            );
        }
        if let Some(k) = &s.kdf {
            m.insert("kdf".into(), kdf_json(k));
        }
        out.insert(hex(&root.0), Value::Object(m));
    }
    out
}

/// A value that is there must read: `Some(None)` for an absent or null
/// value, `None` for one that is there but does not read (F-236).
fn there<T>(v: &Value, f: impl FnOnce(&Value) -> Option<T>) -> Option<Option<T>> {
    if matches!(v, Value::Null) {
        Some(None)
    } else {
        f(v).map(Some)
    }
}

/// Reads the state file: a missing file reads as empty; `None` for a file
/// that cannot be read, is too large or is bad (F-225), holds a value that
/// is there but does not read (F-236), or a key it does not know (F-241),
/// so its records are never written over.
fn load(path: &std::path::Path) -> Option<BTreeMap<Uuid, Seen>> {
    let mut bytes = Vec::new();
    let read = larsal_platform::macos::open_regular(path).and_then(|f| {
        if f.metadata()?.len() > MAX_FILE {
            return Ok(false);
        }
        f.take(MAX_FILE).read_to_end(&mut bytes)?;
        Ok(true)
    });
    match read {
        Ok(true) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(BTreeMap::new()),
        _ => return None,
    }
    let Ok(Value::Object(map)) = json::from_slice(&bytes) else {
        return None;
    };
    map.iter()
        .map(|(root, v)| {
            let root = Uuid(<[u8; 16]>::try_from(unhex(root)?).ok()?);
            if !only(v, &["retired", "newest", "sha256", "version", "kdf"]) {
                return None;
            }
            let seen = Seen {
                retired: there(&v["retired"], |a| {
                    a.as_array()?.iter().map(record_of).collect::<Option<_>>()
                })?
                .unwrap_or_default(),
                newest: there(&v["newest"], |n| n.as_i64().map(Time))?,
                sha: there(&v["sha256"], unhex32)?,
                version: there(&v["version"], |v| match v.as_array()?.as_slice() {
                    [major, minor] => Some(FileVersion {
                        major: u16::try_from(major.as_u64()?).ok()?,
                        minor: u16::try_from(minor.as_u64()?).ok()?,
                    }),
                    _ => None,
                })?,
                kdf: there(&v["kdf"], kdf_of)?,
            };
            Some((root, seen))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use larsal_model::{Argon2Kind, Group};

    /// The state round-trips through its file: records with one and two
    /// digests, both KDF kinds, the guard's values; the file is 0600 and
    /// holds no key bytes beyond the salts and digests it names.
    #[test]
    fn e15s4_local_state_round_trips_through_its_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_dir::TempDir::new("local-state");
        let r1 = Record {
            salt: [1; 32],
            digest: [2; 32],
            alone: Some([3; 32]),
            kdf: KdfParams::Argon2 {
                kind: Argon2Type::Id,
                version: 0x13,
                iterations: 2,
                memory_kib: 65_536,
                lanes: 2,
                salt: vec![4; 32],
            },
            v4: true,
        };
        let r2 = Record {
            salt: [5; 32],
            digest: [6; 32],
            alone: None,
            kdf: KdfParams::AesKdf {
                rounds: 7,
                seed: vec![8; 32],
            },
            v4: false,
        };
        let mut m = BTreeMap::new();
        m.insert(
            Uuid([9; 16]),
            Seen {
                retired: vec![r1.clone(), r2.clone()],
                newest: Some(Time(63_000_000_000)),
                sha: Some([10; 32]),
                version: Some(FileVersion { major: 4, minor: 1 }),
                kdf: Some(Kdf::Argon2 {
                    kind: Argon2Kind::D,
                    iterations: 3,
                    memory_kib: 1024,
                    lanes: 1,
                }),
            },
        );
        let path = dir.join("vault-state.json");
        crate::larsal_settings::write_json(&path, &Value::Object(save(&m))).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let back = load(&path).unwrap();
        let s = back.get(&Uuid([9; 16])).unwrap();
        assert!(s.retired == vec![r1, r2]);
        assert_eq!(s.newest, Some(Time(63_000_000_000)));
        assert_eq!(s.sha, Some([10; 32]));
        assert_eq!(s.version, Some(FileVersion { major: 4, minor: 1 }));
        assert_eq!(s.kdf, m[&Uuid([9; 16])].kdf);
        std::fs::write(&path, b"not json").unwrap();
        assert!(load(&path).is_none(), "a bad file is never read as empty");
        std::fs::remove_file(&path).unwrap();
        assert!(load(&path).is_some_and(|m| m.is_empty()), "a missing file");
    }

    /// LD-320 (1) (F-236): a value that is there must read, or the whole
    /// file reads as bad (`None`, so it is never written over); an absent
    /// or null value reads as absent.
    #[test]
    fn f236_a_value_that_is_there_must_read() {
        let dir = crate::test_dir::TempDir::new("local-state-f236");
        let path = dir.join("vault-state.json");
        let root = "09".repeat(16);
        let read = |text: String| {
            std::fs::write(&path, text).unwrap();
            load(&path)
        };
        let nulls = r#"{"retired":null,"newest":null,"sha256":null,"version":null,"kdf":null}"#;
        let empty = read(format!(r#"{{"{root}":{nulls}}}"#)).unwrap();
        let s = &empty[&Uuid([9; 16])];
        assert!(s.retired.is_empty() && s.newest.is_none() && s.sha.is_none());
        assert!(s.version.is_none() && s.kdf.is_none());
        assert!(read(format!(r#"{{"{root}":{{}}}}"#)).is_some());
        for bad in [
            r#"{"xyz":{}}"#.to_string(),
            format!(r#"{{"{root}":5}}"#),
            format!(r#"{{"{root}":{{"retired":[{{}}]}}}}"#),
            format!(r#"{{"{root}":{{"retired":{{}}}}}}"#),
            format!(r#"{{"{root}":{{"newest":"x"}}}}"#),
            format!(r#"{{"{root}":{{"sha256":"zz"}}}}"#),
            format!(r#"{{"{root}":{{"version":[4]}}}}"#),
            format!(r#"{{"{root}":{{"kdf":{{"argon2":"q"}}}}}}"#),
        ] {
            assert!(read(bad.clone()).is_none(), "{bad}");
        }
    }

    /// F-241 (LD-324 (3)): a key `save` never writes, in a vault entry or a
    /// retired-key record, makes the whole file bad (`None`, never written
    /// over), so one bad byte in a key name drops no value.
    #[test]
    fn f241_load_refuses_a_key_it_does_not_know() {
        let dir = crate::test_dir::TempDir::new("local-state-f241");
        let path = dir.join("vault-state.json");
        let root = "09".repeat(16);
        let hex = "0a".repeat(32);
        let record = format!(
            r#"{{"salt":"{hex}","digest":"{hex}","kdf":{{"aes":7,"seed":"{hex}"}},"v4":true}}"#
        );
        let read = |text: String| {
            std::fs::write(&path, text).unwrap();
            load(&path)
        };
        let good = read(format!(
            r#"{{"{root}":{{"retired":[{record}],"newest":5}}}}"#
        ));
        assert_eq!(good.unwrap()[&Uuid([9; 16])].retired.len(), 1);
        for bad in [
            format!(r#"{{"{root}":{{"retirfd":[{record}],"newest":5}}}}"#),
            format!(r#"{{"{root}":{{"retired":[{record}],"newesu":5}}}}"#),
            format!(
                r#"{{"{root}":{{"retired":[{}]}}}}"#,
                record.replace("\"v4\"", "\"v5\"")
            ),
            format!(
                r#"{{"{root}":{{"retired":[{}]}}}}"#,
                record.replace("\"digest\"", "\"digesu\"")
            ),
            format!(r#"{{"{root}":{{"kdf":{{"aes":7,"m":1}}}}}}"#),
        ] {
            assert!(read(bad.clone()).is_none(), "{bad}");
        }
    }

    /// MOD-11.19 limit 1 as the guard reads it.
    #[test]
    fn app05_26_weaker_kdf_settings() {
        let argon = |i, m| Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: i,
            memory_kib: m,
            lanes: 2,
        };
        assert!(kdf_lower(&argon(2, 65_536), &argon(2, 16_384)));
        assert!(kdf_lower(&argon(2, 65_536), &argon(1, 65_536)));
        assert!(!kdf_lower(&argon(2, 65_536), &argon(2, 65_536)));
        assert!(!kdf_lower(&argon(2, 65_536), &argon(3, 131_072)));
        assert!(kdf_lower(&argon(1, 1024), &Kdf::AesKdf { rounds: 1 << 30 }));
        assert!(!kdf_lower(&Kdf::AesKdf { rounds: 9 }, &argon(1, 1024)));
        assert!(kdf_lower(
            &Kdf::AesKdf { rounds: 9 },
            &Kdf::AesKdf { rounds: 8 }
        ));
    }

    /// APP-05.26 (F-184): a lower major file version is weaker; a lower
    /// minor one is not (it follows the content, FMT-16.20).
    #[test]
    fn app05_26_c1_a_lower_file_version_is_weaker() {
        let seen = Seen {
            version: Some(FileVersion { major: 4, minor: 1 }),
            ..Seen::default()
        };
        let mut v = Vault::new(Group::new(Uuid([1; 16]), "Root".into(), Time(0)), Time(0));
        v.read_version = Some(FileVersion { major: 3, minor: 1 });
        assert_eq!(seen.compare(&v, b"3.1").weaker, ["file format version"]);
        v.read_version = Some(FileVersion { major: 4, minor: 0 });
        assert!(seen.compare(&v, b"4.0").weaker.is_empty());
    }

    /// APP-05.26, LD-269 (4): the stored file version and KDF settings only
    /// move up. A weaker version Larsal accepted (a reload, an unlock) leaves
    /// them as they were, so the next weaker version still warns.
    #[test]
    fn app05_26_the_stored_version_and_kdf_only_move_up() {
        let argon = |m| Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 2,
            memory_kib: m,
            lanes: 1,
        };
        let mut v = Vault::new(Group::new(Uuid([1; 16]), "Root".into(), Time(0)), Time(0));
        let mut seen = Seen::default();
        v.encryption.kdf = argon(2048);
        seen.up(&v, b"4.0", Some(FileVersion { major: 4, minor: 0 }));
        v.encryption.kdf = argon(1024);
        v.read_version = Some(FileVersion { major: 3, minor: 1 });
        seen.up(&v, b"3.1, first", v.read_version);
        assert_eq!(
            seen.compare(&v, b"3.1, second").weaker,
            ["file format version", "key derivation"]
        );
    }
}
