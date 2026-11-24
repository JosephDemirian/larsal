//! This Mac's sync state (SYN-03.3; P4): never synced, never in or next to
//! a vault; kept in Larsal's settings folder.
//!
//! Per server: its address and pinned certificate (SYN-01.2), and once
//! signed up the account and device ids, the device key's label and its
//! public key (LD-325 (5) (a)). Per linked vault: the server, the
//! `vault_id`, the local file and the vault's root group id, the highest
//! version seen with the SHA-256 of its server bytes, the newest change
//! time, file version and KDF settings of the last server version this Mac
//! accepted or uploaded (SYN-03.7), and the SHA-256 of the local file after
//! the last run.
//!
//! Guarantees: the file holds ids, versions, times, public KDF settings,
//! hashes, a public key and a key label: never a password, a key, a
//! key-file part or a session token (SYN-04.6). It is written atomically
//! (a temp file, then a rename) with mode 0600. A file that does not read,
//! is over 1 MiB, or holds a key or value this reader does not know is
//! [`Error::Bad`] and is never written over by the caller (as F-241's
//! state file); only a missing file reads as empty.

use larsal_core::guard::{kdf_json, kdf_of};
use larsal_model::json::{self, Map, Value};
use larsal_model::{FileVersion, Kdf, Time, Uuid};
pub use larsal_proto::messages::{AccountId, DeviceId, VaultId};
use std::io::Read;
use std::path::Path;

/// The largest state file read.
const MAX_FILE: u64 = 1 << 20;

/// The measures of one version of a vault that the rollback guard compares
/// (SYN-03.7; APP-05.26's measures).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measures {
    /// The newest change time (larsal-core `guard::newest`).
    pub newest: Time,
    /// The file version.
    pub version: FileVersion,
    /// The KDF settings.
    pub kdf: Kdf,
}

/// This Mac's account on one server (SYN-04.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The account id.
    pub account: AccountId,
    /// This Mac's device id.
    pub device: DeviceId,
    /// The device key's label in its store: 32 hex digits of 16 random
    /// bytes (LD-325 (5) (a)).
    pub label: String,
    /// The device key's public key, compared on every open of the key.
    pub public_key: [u8; 65],
}

/// One server Larsal was told to use (SYN-01.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// `https://<host>:<port>`.
    pub address: String,
    /// The SHA-256 of its certificate, pinned after "They match".
    pub pin: [u8; 32],
    /// This Mac's account there, after sign-up.
    pub account: Option<Account>,
}

/// One local vault linked to one server vault (SYN-03.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The server's address (its entry in [`State::servers`]).
    pub server: String,
    /// The server vault.
    pub vault_id: VaultId,
    /// The local file's path.
    // ponytail: a path, not yet a security-scoped bookmark; the sandbox
    // bookmark comes with the screens (E16-S9).
    pub file: String,
    /// The vault's root group id.
    pub root: Uuid,
    /// The highest version seen; only moves up.
    pub highest: u64,
    /// The SHA-256 of the server bytes of that version.
    pub server_sha: [u8; 32],
    /// The SHA-256 of the local file after the last run that left the
    /// server and this Mac with the same content.
    pub local_sha: [u8; 32],
    /// The last server version this Mac accepted or uploaded; its newest
    /// change time only moves up.
    pub seen: Measures,
}

/// The whole state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// The servers, in the order they were added.
    pub servers: Vec<Server>,
    /// The links, one per server vault.
    pub links: Vec<Link>,
}

/// Why a state file was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// It exists but cannot be read (permissions, a FIFO, a folder).
    Unreadable,
    /// Over 1 MiB, not JSON, or a key or value this reader does not know.
    Bad,
}

impl State {
    /// The server entry for `address`.
    #[must_use]
    pub fn server(&self, address: &str) -> Option<&Server> {
        self.servers.iter().find(|s| s.address == address)
    }

    /// The server entry for `address`, to change.
    pub fn server_mut(&mut self, address: &str) -> Option<&mut Server> {
        self.servers.iter_mut().find(|s| s.address == address)
    }

    /// The state read from `path`; a missing file is the empty state.
    ///
    /// # Errors
    /// [`Error::Unreadable`] or [`Error::Bad`]: the caller keeps the state
    /// in memory and never writes over that file.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        // A FIFO or a device at the path is refused, never waited on.
        let read = larsal_platform::macos::open_regular(path).and_then(|f| {
            if f.metadata()?.len() > MAX_FILE {
                return Ok(false);
            }
            f.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
            Ok(true)
        });
        match read {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => Err(Error::Unreadable),
            Ok(false) => Err(Error::Bad),
            Ok(true) => Self::read(&bytes).ok_or(Error::Bad),
        }
    }

    /// Writes the state to `path` atomically, mode 0600, making its folder
    /// (0700) when missing.
    ///
    /// # Errors
    /// The system's error; the old file is then unchanged.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        if let Some(folder) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(folder)?;
        }
        larsal_core::storage::write_export(path, json::to_string_pretty(&self.to_json()).as_bytes())
    }

    /// The state as its JSON record.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let servers = self.servers.iter().map(server_json).collect();
        let links = self.links.iter().map(link_json).collect();
        let mut m = Map::new();
        m.insert("servers".into(), Value::Array(servers));
        m.insert("links".into(), Value::Array(links));
        Value::Object(m)
    }

    /// The state of a file's bytes; `None` for anything this reader does
    /// not know, a duplicate key included.
    #[must_use]
    pub fn read(bytes: &[u8]) -> Option<Self> {
        let v = json::from_slice_unique(bytes).ok()?;
        let m = only(&v, &["servers", "links"])?;
        let servers = m
            .get("servers")?
            .as_array()?
            .iter()
            .map(server_of)
            .collect::<Option<Vec<_>>>()?;
        let links = m
            .get("links")?
            .as_array()?
            .iter()
            .map(link_of)
            .collect::<Option<Vec<_>>>()?;
        Some(Self { servers, links })
    }
}

/// `v` as an object whose keys are all in `keys`.
fn only<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Map> {
    let m = v.as_object()?;
    m.keys().all(|k| keys.contains(&k.as_str())).then_some(m)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(v: &Value) -> Option<[u8; N]> {
    let text = v.as_str()?;
    if text.len() != N.checked_mul(2)?
        || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn id_of(v: &Value) -> Option<VaultId> {
    VaultId::parse(v.as_str()?)
}

fn server_json(s: &Server) -> Value {
    let mut m = Map::new();
    m.insert("address".into(), s.address.clone().into());
    m.insert("pin".into(), hex(&s.pin).into());
    if let Some(a) = &s.account {
        let mut am = Map::new();
        am.insert("account".into(), a.account.to_string().into());
        am.insert("device".into(), a.device.to_string().into());
        am.insert("label".into(), a.label.clone().into());
        am.insert("public_key".into(), hex(&a.public_key).into());
        m.insert("account".into(), Value::Object(am));
    }
    Value::Object(m)
}

fn server_of(v: &Value) -> Option<Server> {
    let m = only(v, &["address", "pin", "account"])?;
    let account = match m.get("account") {
        None => None,
        Some(a) => {
            let am = only(a, &["account", "device", "label", "public_key"])?;
            let label = am.get("label")?.as_str()?;
            unhex::<16>(am.get("label")?)?;
            Some(Account {
                account: id_of(am.get("account")?)?,
                device: id_of(am.get("device")?)?,
                label: label.to_owned(),
                public_key: unhex(am.get("public_key")?)?,
            })
        }
    };
    Some(Server {
        address: m.get("address")?.as_str()?.to_owned(),
        pin: unhex(m.get("pin")?)?,
        account,
    })
}

fn link_json(l: &Link) -> Value {
    let mut m = Map::new();
    m.insert("server".into(), l.server.clone().into());
    m.insert("vault_id".into(), l.vault_id.to_string().into());
    m.insert("file".into(), l.file.clone().into());
    m.insert("root".into(), hex(&l.root.0).into());
    m.insert("highest".into(), l.highest.into());
    m.insert("server_sha".into(), hex(&l.server_sha).into());
    m.insert("local_sha".into(), hex(&l.local_sha).into());
    m.insert("newest".into(), l.seen.newest.0.into());
    m.insert(
        "version".into(),
        format!("{}.{}", l.seen.version.major, l.seen.version.minor).into(),
    );
    m.insert("kdf".into(), kdf_json(&l.seen.kdf));
    Value::Object(m)
}

fn link_of(v: &Value) -> Option<Link> {
    let keys = [
        "server",
        "vault_id",
        "file",
        "root",
        "highest",
        "server_sha",
        "local_sha",
        "newest",
        "version",
        "kdf",
    ];
    let m = only(v, &keys)?;
    let (major, minor) = m.get("version")?.as_str()?.split_once('.')?;
    let version = FileVersion {
        major: major.parse().ok()?,
        minor: minor.parse().ok()?,
    };
    Some(Link {
        server: m.get("server")?.as_str()?.to_owned(),
        vault_id: id_of(m.get("vault_id")?)?,
        file: m.get("file")?.as_str()?.to_owned(),
        root: Uuid(unhex(m.get("root")?)?),
        highest: m.get("highest")?.as_u64().filter(|h| *h >= 1)?,
        server_sha: unhex(m.get("server_sha")?)?,
        local_sha: unhex(m.get("local_sha")?)?,
        seen: Measures {
            newest: Time(m.get("newest")?.as_i64()?),
            version,
            kdf: kdf_of(m.get("kdf")?)?,
        },
    })
}

#[cfg(test)]
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn sample() -> State {
        State {
            servers: vec![
                Server {
                    address: "https://127.0.0.1:8443".into(),
                    pin: [7; 32],
                    account: Some(Account {
                        account: AccountId::from_bytes([1; 16]),
                        device: DeviceId::from_bytes([2; 16]),
                        label: "0123456789abcdef0123456789abcdef".into(),
                        public_key: [4; 65],
                    }),
                },
                Server {
                    address: "https://localhost:9443".into(),
                    pin: [8; 32],
                    account: None,
                },
            ],
            links: vec![Link {
                server: "https://127.0.0.1:8443".into(),
                vault_id: VaultId::from_bytes([3; 16]),
                file: "/tmp/demo.larsalvault".into(),
                root: Uuid([5; 16]),
                highest: 3,
                server_sha: [6; 32],
                local_sha: [9; 32],
                seen: Measures {
                    newest: Time(63_900_000_000),
                    version: FileVersion { major: 4, minor: 1 },
                    kdf: Kdf::Argon2 {
                        kind: larsal_model::Argon2Kind::Id,
                        iterations: 2,
                        memory_kib: 65_536,
                        lanes: 2,
                    },
                },
            }],
        }
    }

    /// SYN-03.3, SYN-03 T26: the state round-trips through its file, which
    /// has mode 0600; a server with no link keeps its address and pin.
    #[test]
    fn syn03_3_state_round_trips_with_mode_0600() {
        let dir = std::env::temp_dir().join(format!("larsal-sync-state-{}", std::process::id()));
        let path = dir.join("sync-state.json");
        let s = sample();
        s.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(State::load(&path).unwrap(), s);
        assert_eq!(
            State::load(&dir.join("missing.json")).unwrap(),
            State::default()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SYN-03.3 (as F-241): a key or value this reader does not know is a
    /// bad file, never read as empty or in part.
    #[test]
    fn syn03_3_state_refuses_a_key_or_value_it_does_not_know() {
        let good = json::to_string(&sample().to_json());
        assert!(State::read(good.as_bytes()).is_some());
        for (from, to) in [
            (r#""links":"#, r#""x":1,"links":"#),
            (r#""highest":3"#, r#""highest":3,"token":"a""#),
            (r#""highest":3"#, r#""highest":0"#),
            (
                r#""label":"0123456789abcdef0123456789abcdef""#,
                r#""label":"x""#,
            ),
            (r#""public_key":""#, r#""secret":"00","public_key":""#),
            (r#""version":"4.1""#, r#""version":"4""#),
            (r#""pin":"07"#, r#""pin":"7"#),
        ] {
            assert!(good.contains(from), "{from}");
            let bad = good.replacen(from, to, 1);
            assert_eq!(State::read(bad.as_bytes()), None, "{to}");
        }
        assert_eq!(
            State::read(br#"{"servers":[],"servers":[],"links":[]}"#),
            None
        );
    }
}
