//! E9-S2: keys from entries, Larsal's records, the lock, and Larsal's own agent,
//! against throwaway `ssh-agent` processes in /tmp, `ssh-add`, `ssh-keygen
//! -Y sign` and `ssh -G` pointed at Larsal's socket, and demo keys made by
//! `ssh-keygen`. Never the user's own agent (see `common`). Test names carry
//! the case IDs of spec INT-06 (T-numbers) or the rule.

mod common;

use common::*;
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_model::{Attachment, Entry, Field, Group, Time, Uuid, Vault};
use larsal_sshagent::messages::{Names, text};
use larsal_sshagent::{
    Asker, EntryKey, Error, Keyring, Options, OwnAgent, Place, Question, SETTINGS_NAME, Session,
    Settings, Source, SshKey, has_ssh_key, key_path, unlock_plan,
};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- helpers

/// A scripted question: each `ask` takes the next answer; `None` never
/// answers and, once cancelled, says Allow (a late answer Larsal must ignore).
#[derive(Default)]
struct Script {
    answers: Mutex<VecDeque<Option<bool>>>,
    asked: Mutex<Vec<(Question, Instant)>>,
    cancelled: Mutex<Vec<(u64, Instant)>>,
}

impl Script {
    fn answer(&self, a: Option<bool>) {
        self.answers.lock().unwrap().push_back(a);
    }
    fn asked(&self) -> Vec<Question> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .map(|(q, _)| q.clone())
            .collect()
    }
    fn wait_asked(&self, n: usize) {
        let t0 = Instant::now();
        while self.asked.lock().unwrap().len() < n {
            assert!(t0.elapsed() < Duration::from_secs(10), "no question");
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Asker for Script {
    fn ask(&self, q: &Question) -> bool {
        self.asked.lock().unwrap().push((q.clone(), Instant::now()));
        let next = self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Some(false));
        match next {
            Some(a) => a,
            None => {
                let t0 = Instant::now();
                while !self
                    .cancelled
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(i, _)| *i == q.id)
                    && t0.elapsed() < Duration::from_secs(30)
                {
                    thread::sleep(Duration::from_millis(5));
                }
                true
            }
        }
    }
    fn cancel(&self, id: u64) {
        self.cancelled.lock().unwrap().push((id, Instant::now()));
    }
}

/// Larsal's own agent in its own /tmp folder, with a keyring pointed at
/// `system` (or at no agent), and a scripted question.
struct Larsal {
    dir: Dir,
    agent: Option<OwnAgent>,
    keyring: Arc<Keyring>,
    asker: Arc<Script>,
    sock: PathBuf,
}

fn app(system: Option<&Throwaway>, question_time: Duration) -> Larsal {
    let dir = Dir::new("o");
    let keyring = Arc::new(Keyring::new());
    // A missing socket as the override: never the user's SSH_AUTH_SOCK.
    let none = dir.join("no-agent");
    let path = system.map_or(none.as_path(), |t| t.agent.path());
    keyring.set_agent_settings(path.to_str().unwrap(), None);
    let asker = Arc::new(Script::default());
    let options = Options {
        socket: dir.join("Larsal/agent.sock"),
        known_hosts: dir.join("known_hosts"),
        question_time,
    };
    let sock = options.socket.clone();
    let agent = OwnAgent::start(options, Arc::clone(&keyring), asker.clone()).unwrap();
    Larsal {
        dir,
        agent: Some(agent),
        keyring,
        asker,
        sock,
    }
}

impl Larsal {
    /// A tool from /usr/bin talking to Larsal's socket.
    fn tool(&self, name: &str) -> std::process::Command {
        let mut cmd = tool(name, &self.dir.0);
        cmd.env("SSH_AUTH_SOCK", &self.sock);
        cmd
    }

    /// `ssh-add -l` through Larsal's socket: the comments in order.
    fn listed(&self) -> Vec<String> {
        let out = self.tool("ssh-add").arg("-l").output().unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .filter(|l| {
                l.split(' ')
                    .nth(1)
                    .is_some_and(|f| f.starts_with("SHA256:"))
            })
            .filter_map(|l| l.split(' ').nth(2).map(str::to_owned))
            .collect()
    }

    fn client(&self) -> Client {
        Client::at(&self.sock)
    }
}

/// One raw connection.
struct Client(UnixStream);

impl Client {
    fn at(path: &Path) -> Self {
        let s = UnixStream::connect(path).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        Self(s)
    }
    /// Sends one message body, returns the reply body.
    fn call(&mut self, body: &[u8]) -> Vec<u8> {
        self.0
            .write_all(&(body.len() as u32).to_be_bytes())
            .unwrap();
        self.0.write_all(body).unwrap();
        read_msg(&mut self.0)
    }
    /// True when Larsal closed the connection (EOF or reset).
    fn closed(&mut self) -> bool {
        let mut b = [0u8; 1];
        matches!(self.0.read(&mut b), Ok(0) | Err(_))
    }
}

fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
    [&[13u8][..], &s(blob), &s(data), &0u32.to_be_bytes()].concat()
}

fn session(id: u64, name: &str) -> Session {
    Session {
        id,
        name: name.into(),
    }
}

fn blob(file: &str) -> Vec<u8> {
    keys().key(file).public_blob().to_vec()
}

fn att(name: &str, bytes: Vec<u8>) -> Attachment {
    Attachment {
        name: name.into(),
        data: Arc::new(SecretBytes::new(bytes)),
    }
}

fn settings_att(s: &Settings) -> Attachment {
    att(
        std::str::from_utf8(&SETTINGS_NAME).unwrap(),
        s.write().unwrap(),
    )
}

/// Settings: allow, add on unlock, key in attachment `name`.
fn s_att(name: &str) -> Settings {
    Settings {
        allow: true,
        add_at_open: true,
        source: Source::Attachment,
        attachment_name: name.into(),
        ..Settings::default()
    }
}

fn entry(n: u8, title: &str, user: &str, password: &str, atts: Vec<Attachment>) -> Entry {
    let mut e = Entry::new(Uuid([n; 16]), Time(0));
    for (k, v) in [("Title", title), ("UserName", user), ("Password", password)] {
        e.set_field(
            k.into(),
            Field {
                value: SecretString::new(v.into()),
                protected: k == "Password",
            },
        );
    }
    e.attachments = atts;
    e
}

/// A vault: `entries` in the root, `binned` in the recycle bin.
fn vault(entries: Vec<Entry>, binned: Vec<Entry>) -> Vault {
    let mut root = Group::new(Uuid([100; 16]), "Root".into(), Time(0));
    root.entries = entries;
    let mut bin = Group::new(Uuid([101; 16]), "Bin".into(), Time(0));
    bin.entries = binned;
    root.groups.push(bin);
    let mut v = Vault::new(root, Time(0));
    v.meta.recycle_bin = Some(Uuid([101; 16]));
    v
}

fn e_of(v: &Vault, n: u8) -> &Entry {
    v.root
        .all_entries()
        .find(|e| e.uuid == Uuid([n; 16]))
        .unwrap()
}

/// Reads, unlocks and loads entry `n` of `v` by hand (INT-06.27).
fn load(k: &Keyring, sess: &Session, v: &Vault, n: u8) -> Result<Place, Error> {
    let e = e_of(v, n);
    let settings = Settings::of(e).unwrap().unwrap();
    let key = EntryKey::read(v, e, settings, Path::new("/tmp"))?;
    let unlocked = key.unlock(v, e, Path::new("/tmp"))?;
    k.load(sess, &key, unlocked)
}

fn plain_k1() -> Vec<u8> {
    K1.as_bytes().to_vec()
}

/// E1 "Server root · web-01": K1e as `id_ed25519`, password `PASS`.
fn e1(settings: Settings) -> Entry {
    entry(
        1,
        "Server root · web-01",
        "root",
        PASS,
        vec![
            att("id_ed25519", keys().bytes("k1e")),
            settings_att(&settings),
        ],
    )
}

fn no_env(_: &str) -> Option<OsString> {
    None
}

// ------------------------------------------------- keys from entries

#[test]
fn t09_entries_with_an_ssh_key() {
    let e1 = e1(s_att("id_ed25519"));
    let e5 = entry(
        5,
        "Binned",
        "",
        "",
        vec![att("k", keys().bytes("k2")), settings_att(&s_att("k"))],
    );
    let e6 = entry(
        6,
        "No settings",
        "",
        "",
        vec![att("id_ecdsa", keys().bytes("k2"))],
    );
    let off = entry(
        7,
        "Switch off",
        "",
        "",
        vec![settings_att(&Settings {
            allow: false,
            ..s_att("k")
        })],
    );
    let bad = entry(
        8,
        "T04",
        "",
        "",
        vec![att(
            std::str::from_utf8(&SETTINGS_NAME).unwrap(),
            b"<Settings/>".to_vec(),
        )],
    );
    let v = vault(vec![e1, e6, off, bad], vec![e5]);
    assert!(has_ssh_key(&v, e_of(&v, 1)).is_some());
    for n in [5, 6, 7, 8] {
        assert!(has_ssh_key(&v, e_of(&v, n)).is_none(), "E{n}");
    }
    assert_eq!(Settings::of(e_of(&v, 8)), Err(Error::SettingsUnreadable));
    assert_eq!(Error::SettingsUnreadable.id(), "MI06-24");
    // T04: no add for the unreadable settings either.
    let titles: Vec<String> = unlock_plan(&v, Path::new("/tmp"))
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert_eq!(titles, ["Server root · web-01"]);
}

#[test]
fn t11_t12_t13_file_path_expansion() {
    let home = Path::new("/tmp/h");
    let vdir = Path::new("/tmp/v");
    let env = |n: &str| match n {
        "HOME" => Some(OsString::from("/tmp/h")),
        "LOOP" => Some(OsString::from("$LOOP")),
        _ => None,
    };
    assert_eq!(
        key_path("~/keys/k2", home, vdir, &env),
        Path::new("/tmp/h/keys/k2")
    );
    assert_eq!(
        key_path("$HOME/keys/k2", home, vdir, &env),
        Path::new("/tmp/h/keys/k2")
    );
    assert_eq!(key_path("$NOPE/k2", home, vdir, &env), Path::new("/k2"));
    // T12: one pass; text from an expansion is not expanded again.
    let t0 = Instant::now();
    assert_eq!(
        key_path("$LOOP/k", home, vdir, &env),
        Path::new("/tmp/v/$LOOP/k")
    );
    assert!(t0.elapsed() < Duration::from_millis(50));
    // ${NAME}, %NAME%, a lone $ and a digit after $ stay as written.
    assert_eq!(
        key_path("/a/${HOME}/%HOME%/$/$1x/$HOME_2", home, vdir, &env),
        Path::new("/a/${HOME}/%HOME%/$/$1x/")
    );
    // T13: a relative name comes from the vault's folder.
    assert_eq!(
        key_path("k2rel", home, vdir, &env),
        Path::new("/tmp/v/k2rel")
    );

    // The same through EntryKey::read_with, with real files.
    let d = Dir::new("t11");
    fs::create_dir_all(d.join("keys")).unwrap();
    fs::copy(keys().path("k2"), d.join("keys/k2")).unwrap();
    fs::copy(keys().path("k2"), d.join("k2rel")).unwrap();
    let file = |name: &str| Settings {
        allow: true,
        file_name: name.into(),
        ..Settings::default()
    };
    let e = entry(3, "File key", "", "", vec![]);
    let v = vault(vec![], vec![]);
    for stored in ["~/keys/k2", "k2rel"] {
        let k = EntryKey::read_with(&v, &e, file(stored), &d.0, &d.0, &no_env).unwrap();
        assert_eq!(k.key().type_label(), "ECDSA");
        assert_eq!(k.key().fingerprint(), keys().key("k2").fingerprint());
    }
    let err = EntryKey::read_with(&v, &e, file("$NOPE/k2"), &d.0, &d.0, &no_env).unwrap_err();
    assert_eq!(err, Error::CannotOpen { path: "/k2".into() });
    assert_eq!(
        err.message(&Names::default()),
        "Larsal can't open the key file /k2."
    );
}

#[test]
fn t14_t15_attachment_and_file_errors() {
    let d = Dir::new("t14");
    let with = |a: Attachment| {
        entry(
            1,
            "Server root · web-01",
            "",
            "",
            vec![a, settings_att(&s_att("k"))],
        )
    };
    let v = vault(vec![], vec![]);
    let read = |e: &Entry, s: Settings| EntryKey::read_with(&v, e, s, &d.0, &d.0, &no_env);
    let big = with(att("k", vec![b'a'; 1_048_577]));
    assert_eq!(read(&big, s_att("k")).unwrap_err(), Error::TooLarge);
    let empty = with(att("k", vec![]));
    assert_eq!(read(&empty, s_att("k")).unwrap_err(), Error::Empty);
    let folder = Settings {
        allow: true,
        file_name: d.0.to_str().unwrap().into(),
        ..Settings::default()
    };
    assert_eq!(read(&empty, folder).unwrap_err().id(), "MI06-07");
    let mut big_file = Settings::default();
    fs::write(d.join("big"), vec![b'a'; 1_048_577]).unwrap();
    big_file.file_name = "big".into();
    assert_eq!(read(&empty, big_file).unwrap_err(), Error::TooLarge);
    // T15: no attachment of that name; the settings attachment is never a key.
    let e = with(att("id_ed25519", keys().bytes("k1e")));
    let err = read(&e, s_att("id_missing")).unwrap_err();
    assert_eq!(err, Error::NoAttachment);
    let names = Names {
        title: "Server root · web-01",
        name: "id_missing",
        ..Names::default()
    };
    assert_eq!(
        err.message(&names),
        "“Server root · web-01” has no attachment named id_missing."
    );
    let own = std::str::from_utf8(&SETTINGS_NAME).unwrap();
    assert_eq!(read(&e, s_att(own)).unwrap_err(), Error::NoAttachment);
}

#[test]
fn t19_t39_unlock_adds_in_tree_order() {
    let a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    // K1 with its comment removed, as `ssh-keygen -c -C ""` leaves it.
    let d = Dir::new("t39");
    fs::write(d.join("k1"), K1).unwrap();
    fs::set_permissions(d.join("k1"), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(run(
        tool("ssh-keygen", &d.0).args(["-q", "-c", "-C", "", "-f", "k1"])
    ));
    let e2 = entry(
        2,
        "Plain key",
        "alex",
        "",
        vec![
            att("id_plain", fs::read(d.join("k1")).unwrap()),
            settings_att(&s_att("id_plain")),
        ],
    );
    let e3 = entry(
        3,
        "File key",
        "",
        "",
        vec![settings_att(&Settings {
            allow: true,
            file_name: keys().path("k2").to_str().unwrap().into(),
            ..Settings::default()
        })],
    );
    let e4 = entry(
        4,
        "Old key",
        "",
        PASS,
        vec![
            att("id_rsa", keys().bytes("kp")),
            settings_att(&s_att("id_rsa")),
        ],
    );
    let e5 = entry(
        5,
        "Binned",
        "",
        "",
        vec![att("k", keys().bytes("k2")), settings_att(&s_att("k"))],
    );
    let v = vault(
        vec![
            e1(Settings {
                remove_at_close: true,
                ..s_att("id_ed25519")
            }),
            e2,
            e3,
            e4,
        ],
        vec![e5],
    );
    let refused = k.add_on_unlock(
        &session(1, "V"),
        &v,
        Path::new("/tmp"),
        &AtomicBool::new(false),
    );
    let titles: Vec<&str> = refused.iter().map(|r| r.title.as_str()).collect();
    assert_eq!(titles, ["Old key"]);
    assert_eq!(refused[0].error, Error::OldFormat);
    let listed = a.agent.list().unwrap();
    assert_eq!(listed.len(), 1, "one key: E1 and E2 hold the same K1");
    assert_eq!(listed[0].blob, blob("k1"));
    assert_eq!(
        listed[0].comment, "alex@id_plain",
        "T19, the later add wins"
    );
}

#[test]
fn t23_password_reference_unlocks_the_key() {
    let a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let mut e = e1(s_att("id_ed25519"));
    e.set_field(
        "Password".into(),
        Field {
            value: SecretString::new("{REF:P@T:Shared}".into()),
            protected: true,
        },
    );
    let shared = entry(9, "Shared", "", PASS, vec![]);
    let v = vault(vec![e, shared], vec![]);
    assert_eq!(load(&k, &session(1, "V"), &v, 1), Ok(Place::System));
    assert_eq!(a.blobs(), vec![blob("k1")]);
}

#[test]
fn t37_lifetime_0_refused_before_anything_is_sent() {
    let a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let v = vault(
        vec![e1(Settings {
            use_lifetime: true,
            lifetime: 0,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    let err = load(&k, &session(1, "V"), &v, 1).unwrap_err();
    assert_eq!(
        err.message(&Names::default()),
        "The time limit must be at least 1 minute."
    );
    assert!(a.blobs().is_empty());
    assert_eq!(k.place_of(&blob("k1")), None);
}

/// LD-207 on a vault in memory, where the vault's Title flag can be on
/// while the field's own flag is off (a saved file marks the field too):
/// either flag masks the plan's title and the key's, and the question names
/// the key by its comment; neither flag keeps the title.
#[test]
fn ld207_either_flag_masks_the_title_and_the_question_names_the_comment() {
    let mask = larsal_core::health::MASKED_TITLE;
    for (own, vault_flag, title, name) in [
        (true, false, mask, "demo@app"),
        (false, true, mask, "demo@app"),
        (false, false, "Server root · web-01", "Server root · web-01"),
    ] {
        let mut e = e1(s_att("id_ed25519"));
        let value = SecretString::new("Server root · web-01".into());
        e.set_field(
            "Title".into(),
            Field {
                value,
                protected: own,
            },
        );
        let mut v = vault(vec![e], vec![]);
        v.meta.memory_protection.title = vault_flag;
        let mut plan = unlock_plan(&v, Path::new("/tmp"));
        assert_eq!(plan.len(), 1);
        let step = plan.remove(0);
        assert_eq!(step.title, title, "{own} {vault_flag}");
        let key = step.key.unwrap();
        assert_eq!(key.title(), title);
        let unlocked = key.unlock(&v, e_of(&v, 1), Path::new("/tmp")).unwrap();
        assert_eq!(key.question_name(&unlocked), name);
    }
}

/// LD-213 (2), INT-06.8 on a vault in memory: a protected UserName (its
/// own flag or the vault's, LD-207) is left out of the fallback comment
/// with its `@`, in the system agent and in Larsal's own, as `ssh-add -l`
/// lists them; with neither flag the card's `alex@id_plain` stays.
#[test]
fn ld213_a_protected_user_name_never_reaches_a_key_comment() {
    let a = Throwaway::start();
    let app = app(Some(&a), Duration::from_secs(5));
    // K1 with its comment removed, as in T19.
    let d = Dir::new("ld213");
    fs::write(d.join("k1"), K1).unwrap();
    fs::set_permissions(d.join("k1"), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(run(
        tool("ssh-keygen", &d.0).args(["-q", "-c", "-C", "", "-f", "k1"])
    ));
    let bytes = fs::read(d.join("k1")).unwrap();
    for (own, vault_flag, want) in [
        (true, false, "id_plain"),
        (false, true, "id_plain"),
        (false, false, "alex@id_plain"),
    ] {
        for confirm in [false, true] {
            let settings = Settings {
                confirm,
                remove_at_close: true,
                ..s_att("id_plain")
            };
            let mut e = entry(
                2,
                "Plain key",
                "",
                "",
                vec![att("id_plain", bytes.clone()), settings_att(&settings)],
            );
            e.set_field(
                "UserName".into(),
                Field {
                    value: pass("alex"),
                    protected: own,
                },
            );
            let mut v = vault(vec![e], vec![]);
            v.meta.memory_protection.user_name = vault_flag;
            load(&app.keyring, &session(1, "V"), &v, 2).unwrap();
            let mut list = if confirm {
                app.tool("ssh-add")
            } else {
                a.tool("ssh-add")
            };
            let out = list.arg("-l").output().unwrap();
            let out = String::from_utf8(out.stdout).unwrap();
            let comments: Vec<&str> = out.lines().filter_map(|l| l.split(' ').nth(2)).collect();
            assert_eq!(
                comments,
                [want],
                "own {own}, vault {vault_flag}, asks {confirm}"
            );
            assert!(app.keyring.lock(1).is_empty());
        }
    }
}

// ------------------------------------------------- records and locks

#[test]
fn t40_t41_other_vault_refused_then_free_after_lock() {
    let a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let v = vault(vec![e1(s_att("id_ed25519"))], vec![]);
    assert_eq!(load(&k, &session(1, "V"), &v, 1), Ok(Place::System));
    let err = load(&k, &session(2, "W"), &v, 1).unwrap_err();
    assert_eq!(err, Error::OtherVault("V".into()));
    assert_eq!(
        err.message(&Names::default()),
        "This key is already loaded from another open vault, V. Lock that vault or remove the key there first."
    );
    // Remove-on-lock off: the key stays, the record goes (T40).
    assert!(k.lock(1).is_empty());
    assert_eq!(a.blobs(), vec![blob("k1")]);
    assert_eq!(load(&k, &session(3, "V"), &v, 1), Ok(Place::System));
}

#[test]
fn t42_at_h01_lock_removes_marked_keys_within_1s() {
    let _timed = timed();
    let a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let e3 = entry(
        3,
        "File key",
        "",
        "",
        vec![att("k2", keys().bytes("k2")), settings_att(&s_att("k2"))],
    );
    let v = vault(
        vec![
            e1(Settings {
                remove_at_close: true,
                ..s_att("id_ed25519")
            }),
            e3,
        ],
        vec![],
    );
    let sess = session(1, "V");
    load(&k, &sess, &v, 1).unwrap();
    load(&k, &sess, &v, 3).unwrap();
    assert_eq!(a.blobs().len(), 2);
    let t0 = Instant::now();
    assert!(k.lock(1).is_empty());
    let left = a.blobs();
    let took = t0.elapsed();
    assert_eq!(left, vec![blob("k2")], "K1 gone, K2 stays");
    assert!(took < Duration::from_secs(1), "AT-H01: {took:?}");
    assert_eq!(k.place_of(&blob("k1")), None);
    assert_eq!(k.place_of(&blob("k2")), None, "no record of V is left");
}

#[test]
fn t43_lock_finishes_when_the_agent_is_gone() {
    let mut a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let v = vault(
        vec![e1(Settings {
            remove_at_close: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&k, &session(1, "V"), &v, 1).unwrap();
    a.child.kill().unwrap();
    a.child.wait().unwrap();
    let t0 = Instant::now();
    let refused = k.lock(1);
    assert!(t0.elapsed() < Duration::from_secs(3));
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].title, "Server root · web-01");
    assert_eq!(k.place_of(&blob("k1")), None);
    assert!(text("MI06-19").unwrap().contains("‹title›"));
}

#[test]
fn t46_turn_off_removes_apps_keys_only() {
    let a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let e3 = entry(
        3,
        "File key",
        "",
        "",
        vec![att("k2", keys().bytes("k2")), settings_att(&s_att("k2"))],
    );
    let v = vault(
        vec![
            e1(Settings {
                remove_at_close: true,
                ..s_att("id_ed25519")
            }),
            e3,
        ],
        vec![],
    );
    load(&k, &session(1, "V"), &v, 1).unwrap();
    load(&k, &session(1, "V"), &v, 3).unwrap();
    assert!(
        run(a.tool("ssh-add").arg(keys().path("k384"))),
        "K9 by another program"
    );
    assert!(k.turn_off().is_empty());
    assert_eq!(a.blobs(), vec![blob("k384")], "LD-63: K9 stays");
}

/// F-106: after S-SSH-02 moves from agent A to agent B, the lock, Remove
/// from SSH Agent, a second load and the turn-off take the key out of A,
/// where it went; A gone, the lock names the key for MI06-19.
#[test]
fn f_106_keys_leave_the_agent_they_went_to_after_the_socket_changed() {
    let a = Throwaway::start();
    let b = Throwaway::start();
    let k = Keyring::new();
    let to = |t: &Throwaway| k.set_agent_settings(t.agent.path().to_str().unwrap(), None);
    let v = vault(
        vec![e1(Settings {
            remove_at_close: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    to(&a);
    load(&k, &session(1, "V"), &v, 1).unwrap();
    to(&b);
    assert!(k.lock(1).is_empty());
    assert!(a.blobs().is_empty(), "lock: the key stayed in A");
    to(&a);
    load(&k, &session(2, "V"), &v, 1).unwrap();
    to(&b);
    assert_eq!(k.unload(&blob("k1")), Ok(true));
    assert!(a.blobs().is_empty(), "remove: the key stayed in A");
    to(&a);
    load(&k, &session(3, "V"), &v, 1).unwrap();
    to(&b);
    load(&k, &session(3, "V"), &v, 1).unwrap();
    assert!(a.blobs().is_empty(), "load again: the key is in two agents");
    assert_eq!(b.blobs(), vec![blob("k1")]);
    assert!(k.lock(3).is_empty());
    assert!(b.blobs().is_empty());
    to(&a);
    load(&k, &session(4, "V"), &v, 1).unwrap();
    to(&b);
    assert!(k.turn_off().is_empty());
    assert!(a.blobs().is_empty(), "turn-off: the key stayed in A");
    to(&a);
    load(&k, &session(5, "V"), &v, 1).unwrap();
    to(&b);
    let path = a.agent.path().to_owned();
    let mut a = a;
    a.child.kill().unwrap();
    a.child.wait().unwrap();
    let refused = k.lock(5);
    assert_eq!(refused.len(), 1, "MI06-19 when A cannot be reached");
    assert_eq!(refused[0].title, "Server root · web-01");
    assert_eq!(
        refused[0].error,
        Error::Unreachable {
            path,
            why: larsal_sshagent::Failure::Connect
        }
    );
}

/// F-108: a system agent that never answers costs a lock one wait of
/// [`larsal_sshagent::TIMEOUT`], not one per key: after the first removal
/// times out the agent is not asked again, and MI06-19 names every marked
/// key.
#[test]
fn f_108_a_silent_agent_costs_the_lock_one_wait_not_one_per_key() {
    let _timed = timed();
    let mut a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let marked = |name: &str| {
        settings_att(&Settings {
            remove_at_close: true,
            ..s_att(name)
        })
    };
    let e3 = entry(
        3,
        "File key",
        "",
        "",
        vec![att("k2", keys().bytes("k2")), marked("k2")],
    );
    let e4 = entry(
        4,
        "P-384 key",
        "",
        "",
        vec![att("k384", keys().bytes("k384")), marked("k384")],
    );
    let first = e1(Settings {
        remove_at_close: true,
        ..s_att("id_ed25519")
    });
    let v = vault(vec![first, e3, e4], vec![]);
    for n in [1, 3, 4] {
        load(&k, &session(1, "V"), &v, n).unwrap();
    }
    assert_eq!(a.blobs().len(), 3);
    let path = a.agent.path().to_owned();
    a.child.kill().unwrap();
    a.child.wait().unwrap();
    let _ = fs::remove_file(&path);
    let hung = silent(&path);
    let t0 = Instant::now();
    let refused = k.lock(1);
    let took = t0.elapsed();
    assert_eq!(hung.connections(), 1, "the silent agent was asked again");
    let titles: Vec<&str> = refused.iter().map(|r| r.title.as_str()).collect();
    assert_eq!(titles, ["Server root · web-01", "File key", "P-384 key"]);
    let timeout = Error::Unreachable {
        path,
        why: larsal_sshagent::Failure::Timeout,
    };
    assert!(refused.iter().all(|r| r.error == timeout), "{refused:?}");
    assert!(took < Duration::from_millis(3500), "{took:?}");
}

/// F-108: an add already running when the vault locks puts its key in
/// after [`Keyring::leave`]; [`Keyring::remove_left`] waits for it and
/// takes that key out too, so no record of the locked vault stays.
#[test]
fn f_108_an_add_running_at_the_lock_leaves_too() {
    let dir = Dir::new("w");
    let path = dir.join("s");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let (got, add_seen) = std::sync::mpsc::channel();
    // Answers the add 500 ms late, then the remove at once.
    let server = thread::spawn(move || {
        let mut seen = Vec::new();
        for n in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            seen.push(read_msg(&mut stream)[0]);
            if n == 0 {
                got.send(()).unwrap();
                thread::sleep(Duration::from_millis(500));
            }
            stream.write_all(&OK).unwrap();
            // As `fake`: open until Larsal closes (INT-06.12).
            let _ = stream.read_to_end(&mut Vec::new());
        }
        seen
    });
    let k = Keyring::new();
    k.set_agent_settings(path.to_str().unwrap(), None);
    let v = vault(
        vec![e1(Settings {
            remove_at_close: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    thread::scope(|sc| {
        let adding = sc.spawn(|| load(&k, &session(1, "V"), &v, 1));
        add_seen.recv_timeout(Duration::from_secs(10)).unwrap();
        let leaving = k.leave(1);
        assert!(k.remove_left(leaving).is_empty());
        assert_eq!(adding.join().unwrap(), Ok(Place::System));
    });
    assert_eq!(
        k.place_of(&blob("k1")),
        None,
        "a record of the locked vault stayed"
    );
    assert_eq!(server.join().unwrap(), [17, 18], "add, then remove");
}

/// F-108: a key a later unlock added again before the lock's removals ran
/// stays in the agent, with the new unlock's record.
#[test]
fn f_108_a_key_added_again_before_the_removals_stays() {
    let a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let v = vault(
        vec![e1(Settings {
            remove_at_close: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&k, &session(1, "V"), &v, 1).unwrap();
    let leaving = k.leave(1);
    load(&k, &session(2, "V"), &v, 1).unwrap();
    assert!(k.remove_left(leaving).is_empty());
    assert_eq!(
        a.blobs(),
        vec![blob("k1")],
        "the new unlock's key was removed"
    );
    assert_eq!(k.place_of(&blob("k1")), Some(Place::System));
}

#[test]
fn t48_remove_on_lock_changes_at_once() {
    let a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let v = vault(
        vec![e1(Settings {
            remove_at_close: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&k, &session(1, "V"), &v, 1).unwrap();
    k.set_remove_on_lock(&blob("k1"), false);
    assert!(k.lock(1).is_empty());
    assert_eq!(a.blobs(), vec![blob("k1")]);
}

#[test]
fn t50_t71_lifetimes_end_in_both_agents() {
    let _timed = timed();
    let a = Throwaway::start();
    let app = app(Some(&a), Duration::from_secs(5));
    let lifetime = |s: Settings| Settings {
        use_lifetime: true,
        lifetime: 2,
        ..s
    };
    let e3 = entry(
        3,
        "File key",
        "",
        "",
        vec![
            att("k2", keys().bytes("k2")),
            settings_att(&lifetime(s_att("k2"))),
        ],
    );
    let v = vault(
        vec![
            e1(lifetime(Settings {
                confirm: true,
                ..s_att("id_ed25519")
            })),
            e3,
        ],
        vec![],
    );
    let sess = session(1, "V");
    assert_eq!(load(&app.keyring, &sess, &v, 1), Ok(Place::Own));
    assert_eq!(load(&app.keyring, &sess, &v, 3), Ok(Place::System));
    assert_eq!(app.listed(), ["demo@app", "ecdsa@app"]);
    thread::sleep(Duration::from_secs(3));
    assert!(
        app.listed().is_empty(),
        "INT-06.35 and the agent's own lifetime"
    );
    assert_eq!(app.keyring.is_loaded(&blob("k1")), Ok(false));
    assert_eq!(app.keyring.is_loaded(&blob("k2")), Ok(false));
}

#[test]
fn t70_remove_all_empties_both_agents() {
    let a = Throwaway::start();
    let app = app(Some(&a), Duration::from_secs(5));
    let e3 = entry(
        3,
        "File key",
        "",
        "",
        vec![att("k2", keys().bytes("k2")), settings_att(&s_att("k2"))],
    );
    let v = vault(
        vec![
            e1(Settings {
                confirm: true,
                ..s_att("id_ed25519")
            }),
            e3,
        ],
        vec![],
    );
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    load(&app.keyring, &session(1, "V"), &v, 3).unwrap();
    app.keyring.remove_all().unwrap();
    assert!(a.blobs().is_empty());
    assert!(app.listed().is_empty());
    assert_eq!(app.keyring.place_of(&blob("k1")), None);
    assert!(app.keyring.lock(1).is_empty(), "nothing left to remove");
}

#[test]
fn t74_r06_1_ask_first_key_always_leaves_at_lock() {
    let a = Throwaway::start();
    let app = app(Some(&a), Duration::from_secs(5));
    let s = Settings {
        confirm: true,
        remove_at_close: false,
        ..s_att("id_ed25519")
    };
    let v = vault(vec![e1(s.clone())], vec![]);
    let e = e_of(&v, 1);
    let key = EntryKey::read(&v, e, s, Path::new("/tmp")).unwrap();
    assert!(key.remove_on_lock(), "R06-1: shown on, stored value kept");
    assert!(!key.settings().remove_at_close);
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    assert_eq!(app.listed(), ["demo@app"]);
    assert!(app.keyring.lock(1).is_empty());
    assert!(app.listed().is_empty());
    assert!(
        a.blobs().is_empty(),
        "AT-H02 (b): never in the system agent"
    );
}

// ------------------------------------------------- Larsal's own agent

#[test]
fn t51_r06_5_asking_entry_wins_either_order() {
    let a = Throwaway::start();
    assert!(
        run(a.tool("ssh-add").arg(keys().path("k2"))),
        "a key of the system agent"
    );
    let app = app(Some(&a), Duration::from_secs(5));
    let asks = Settings {
        confirm: true,
        ..s_att("id_ed25519")
    };
    let e2 = entry(
        2,
        "Plain key",
        "alex",
        "",
        vec![att("k1", plain_k1()), settings_att(&s_att("k1"))],
    );
    // Tree order: E1 (asks) then E2; and E2 first in a second vault.
    let v = vault(vec![e1(asks.clone()), e2], vec![]);
    let refused = app.keyring.add_on_unlock(
        &session(1, "V"),
        &v,
        Path::new("/tmp"),
        &AtomicBool::new(false),
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(a.blobs(), vec![blob("k2")], "K1 is not in the system agent");
    assert_eq!(
        app.listed(),
        ["demo@app", "ecdsa@app"],
        "Larsal's keys, then the system agent's"
    );
    // Loading E2 by hand: the asking entry still wins.
    assert_eq!(load(&app.keyring, &session(1, "V"), &v, 2), Ok(Place::Own));
    assert_eq!(a.blobs(), vec![blob("k2")]);
    app.keyring.lock(1);

    // E2 (does not ask) first by hand, then E1 (asks): K1 moves to Larsal's agent.
    assert_eq!(
        load(&app.keyring, &session(2, "V"), &v, 2),
        Ok(Place::System)
    );
    assert!(a.blobs().contains(&blob("k1")));
    assert_eq!(load(&app.keyring, &session(2, "V"), &v, 1), Ok(Place::Own));
    assert_eq!(a.blobs(), vec![blob("k2")]);
    assert_eq!(app.keyring.place_of(&blob("k1")), Some(Place::Own));
}

#[test]
fn t52_socket_modes_and_what_is_in_the_way() {
    let app = app(None, Duration::from_secs(5));
    let mode = |p: &Path| fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&app.sock), 0o600);
    assert_eq!(mode(app.sock.parent().unwrap()), 0o700);
    // A stale socket of the user is replaced; anything else stays and stops the start.
    let d = Dir::new("t52");
    let stale = d.join("Larsal/agent.sock");
    fs::create_dir_all(stale.parent().unwrap()).unwrap();
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
    let opts = |socket: PathBuf| Options {
        socket,
        known_hosts: d.join("kh"),
        question_time: Duration::from_secs(1),
    };
    let keyring = Arc::new(Keyring::new());
    let started = OwnAgent::start(
        opts(stale.clone()),
        keyring.clone(),
        Arc::new(Script::default()),
    );
    assert!(started.is_ok());
    started.unwrap().stop();
    assert!(!stale.exists(), "INT-06.32: the socket goes at stop");
    fs::write(&stale, b"keep").unwrap();
    assert!(
        OwnAgent::start(
            opts(stale.clone()),
            keyring.clone(),
            Arc::new(Script::default())
        )
        .is_err()
    );
    assert_eq!(fs::read(&stale).unwrap(), b"keep");
    let long = PathBuf::from(format!("/tmp/{}", "x".repeat(99)));
    assert!(OwnAgent::start(opts(long), keyring, Arc::new(Script::default())).is_err());
}

/// `ssh-keygen -Y sign` through Larsal's socket with only the public key.
fn keygen_sign(app: &Larsal, file: &str) -> bool {
    fs::write(app.dir.join("data"), b"demo data").unwrap();
    let _ = fs::remove_file(app.dir.join("data.sig"));
    fs::copy(
        keys().path(&format!("{file}.pub")),
        app.dir.join(&format!("{file}.pub")),
    )
    .unwrap();
    run(app.tool("ssh-keygen").args([
        "-Y",
        "sign",
        "-n",
        "file",
        "-f",
        &format!("{file}.pub"),
        "data",
    ]))
}

/// `ssh-keygen -Y verify` of `data.sig` against the public key.
fn keygen_verify(app: &Larsal, file: &str, who: &str) -> bool {
    let line = fs::read_to_string(keys().path(&format!("{file}.pub"))).unwrap();
    let mut parts = line.split(' ');
    fs::write(
        app.dir.join("signers"),
        format!(
            "{who} {} {}\n",
            parts.next().unwrap(),
            parts.next().unwrap()
        ),
    )
    .unwrap();
    let mut cmd = tool("ssh-keygen", &app.dir.0);
    cmd.args([
        "-Y", "verify", "-f", "signers", "-I", who, "-n", "file", "-s", "data.sig",
    ])
    .stdin(fs::File::open(app.dir.join("data")).unwrap());
    run(&mut cmd)
}

#[test]
fn t53_sign_asks_allow_signs_deny_fails() {
    let a = Throwaway::start();
    let app = app(Some(&a), Duration::from_secs(10));
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    assert_eq!(load(&app.keyring, &session(1, "V"), &v, 1), Ok(Place::Own));
    assert!(
        a.blobs().is_empty(),
        "AT-H02 (b): the key never reaches the system agent"
    );
    app.asker.answer(Some(true));
    assert!(keygen_sign(&app, "k1"), "Allow Once signs");
    assert!(
        keygen_verify(&app, "k1", "demo@app"),
        "a valid Ed25519 signature"
    );
    app.asker.answer(Some(false));
    assert!(!keygen_sign(&app, "k1"), "Deny fails");
    let asked = app.asker.asked();
    assert_eq!(asked.len(), 2, "one question per signature");
    assert_eq!(asked[0].title, "Server root · web-01");
    assert_eq!(asked[0].comment, "demo@app");
    assert_eq!(asked[0].fingerprint, K1_FINGERPRINT);
    assert_eq!(asked[0].host, None);
    assert_ne!(asked[0].id, asked[1].id);
}

#[test]
fn t54_p256_signs_rsa_cannot_ask() {
    let app = app(None, Duration::from_secs(10));
    let asks = |name: &str| Settings {
        confirm: true,
        ..s_att(name)
    };
    let e = entry(
        3,
        "ECDSA",
        "",
        "",
        vec![
            att("k2", keys().bytes("k2")),
            att("kr", keys().bytes("kr")),
            settings_att(&asks("k2")),
        ],
    );
    let v = vault(vec![e], vec![]);
    assert_eq!(load(&app.keyring, &session(1, "V"), &v, 3), Ok(Place::Own));
    app.asker.answer(Some(true));
    assert!(keygen_sign(&app, "k2"));
    assert!(
        keygen_verify(&app, "k2", "ecdsa@app"),
        "a valid P-256 signature"
    );
    let e = e_of(&v, 3);
    let kr = EntryKey::read(&v, e, asks("kr"), Path::new("/tmp")).unwrap();
    let unlocked = kr.unlock(&v, e, Path::new("/tmp")).unwrap();
    let err = app
        .keyring
        .load(&session(1, "V"), &kr, unlocked)
        .unwrap_err();
    assert_eq!(err, Error::CannotAsk);
    assert_eq!(
        err.message(&Names::default()),
        "Asking before each use works with Ed25519 and ECDSA P-256 keys."
    );
}

#[test]
fn t55_list_and_add_through_apps_socket() {
    let a = Throwaway::start();
    assert!(run(a.tool("ssh-add").arg(keys().path("k2"))));
    let app = app(Some(&a), Duration::from_secs(5));
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    assert_eq!(app.listed(), ["demo@app", "ecdsa@app"]);
    assert!(
        run(app.tool("ssh-add").arg(keys().path("k384"))),
        "forwarded add"
    );
    assert_eq!(
        a.blobs(),
        vec![blob("k2"), blob("k384")],
        "K9 lands in the system agent"
    );
    assert_eq!(app.listed(), ["demo@app", "ecdsa@app", "p384@app"]);
    // A system agent key signs through Larsal's socket without a question.
    assert!(keygen_sign(&app, "k2"));
    assert!(app.asker.asked().is_empty());
}

#[test]
fn r06_3_remove_and_lock_requests_on_apps_socket() {
    let a = Throwaway::start();
    assert!(run(a.tool("ssh-add").arg(keys().path("k2"))));
    let app = app(Some(&a), Duration::from_secs(5));
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    let sess = session(1, "V");
    load(&app.keyring, &sess, &v, 1).unwrap();
    fs::copy(keys().path("k1.pub"), app.dir.join("k1.pub")).unwrap();
    assert!(
        run(app.tool("ssh-add").args(["-d", "k1.pub"])),
        "18 removes Larsal's key"
    );
    assert_eq!(app.listed(), ["ecdsa@app"]);
    assert_eq!(
        app.keyring.place_of(&blob("k1")),
        None,
        "its record went too"
    );
    load(&app.keyring, &sess, &v, 1).unwrap();
    // 22 and 23 get 5 and do not reach the system agent.
    let mut c = app.client();
    assert_eq!(c.call(&[&[22u8][..], &s(b"pw")].concat()), [5]);
    assert_eq!(c.call(&[&[23u8][..], &s(b"pw")].concat()), [5]);
    assert_eq!(
        a.blobs(),
        vec![blob("k2")],
        "the system agent is not locked"
    );
    assert!(run(app.tool("ssh-add").arg("-D")), "19 empties both");
    assert!(app.listed().is_empty());
    assert!(a.blobs().is_empty());
}

#[test]
fn r06_4_apps_socket_as_system_agent_counts_as_none() {
    let app = app(None, Duration::from_millis(500));
    app.keyring
        .set_agent_settings(app.sock.to_str().unwrap(), None);
    let e3 = entry(
        3,
        "File key",
        "",
        "",
        vec![att("k2", keys().bytes("k2")), settings_att(&s_att("k2"))],
    );
    let v = vault(
        vec![
            e1(Settings {
                confirm: true,
                ..s_att("id_ed25519")
            }),
            e3,
        ],
        vec![],
    );
    let err = load(&app.keyring, &session(1, "V"), &v, 3).unwrap_err();
    assert_eq!(err, Error::NoAgent);
    assert_eq!(err.id(), "MI06-01");
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    let t0 = Instant::now();
    let mut c = app.client();
    assert_eq!(
        c.call(&sign_request(&blob("k2"), b"x")),
        [5],
        "no loop, no hang"
    );
    assert_eq!(
        c.call(&[11]).len(),
        5 + 4 + blob("k1").len() + 4 + 8,
        "Larsal's key only"
    );
    assert_eq!(c.call(&[&[17u8][..], &s(b"ssh-ed25519")].concat()), [5]);
    assert!(t0.elapsed() < Duration::from_secs(1));
}

/// A session binding signed by a throwaway agent holding the host key.
fn binding(host: &Throwaway, host_key: &[u8], id: &[u8], forwarded: bool) -> Vec<u8> {
    let mut c = Client::at(host.agent.path());
    // Flags 4: rsa-sha2-512 for the RSA host key; other types ignore them.
    let mut req = sign_request(host_key, id);
    let n = req.len();
    req[n - 1] = 4;
    let reply = c.call(&req);
    assert_eq!(reply[0], 14, "the host agent signed");
    let sig = &reply[5..];
    [
        &[27u8][..],
        &s(b"session-bind@openssh.com"),
        &s(host_key),
        &s(id),
        &s(sig),
        &[u8::from(forwarded)],
    ]
    .concat()
}

#[test]
fn t57_session_binding_names_the_host() {
    let a = Throwaway::start();
    let hosts = Throwaway::start();
    // Host keys: Ed25519 (`kh`, made here), P-256 (`k2`), RSA (`kr`).
    let d = Dir::new("t57");
    assert!(run(
        tool("ssh-keygen", &d.0).args(["-q", "-t", "ed25519", "-N", "", "-f", "kh"])
    ));
    for f in [d.join("kh"), keys().path("k2"), keys().path("kr")] {
        assert!(run(hosts.tool("ssh-add").arg(f)));
    }
    let kh = SshKey::read(&fs::read(d.join("kh")).unwrap())
        .unwrap()
        .public_blob()
        .to_vec();
    let app = app(Some(&a), Duration::from_secs(10));
    let kh_line = fs::read_to_string(d.join("kh.pub")).unwrap();
    let k2_line = fs::read_to_string(keys().path("k2.pub")).unwrap();
    fs::write(
        app.dir.join("known_hosts"),
        format!("|1|aGFzaA==|aGFzaA== {kh_line}web01.example {kh_line}db.example {k2_line}"),
    )
    .unwrap();
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    let k1 = blob("k1");

    // Ed25519 host key: bound, checked by Larsal and by the system agent.
    let mut c = app.client();
    assert_eq!(c.call(&binding(&hosts, &kh, b"session-1", false)), [6]);
    app.asker.answer(Some(false));
    let sign = sign_request(&k1, &userauth(b"session-1", &k1, None));
    assert_eq!(c.call(&sign), [5], "Deny (Escape) is failure");
    let q = app.asker.asked().pop().unwrap();
    assert_eq!(q.host.as_deref(), Some("web01.example"));
    assert_eq!(
        q.heading(),
        "Allow a program to use “Server root · web-01”?"
    );
    assert_eq!(
        q.text(),
        "A program wants to sign in to web01.example with this key."
    );

    // P-256 host key, forwarded.
    let mut c = app.client();
    assert_eq!(
        c.call(&binding(&hosts, &blob("k2"), b"session-2", true)),
        [6]
    );
    app.asker.answer(Some(true));
    let data = userauth(b"session-2", &k1, Some(&blob("k2")));
    let reply = c.call(&sign_request(&k1, &data));
    assert_eq!(reply[0], 14, "Allow Once signs");
    let sig = &reply[5..];
    assert_eq!(larsal_crypto::ssh::verify(&k1, &data, sig), Some(true));
    let q = app.asker.asked().pop().unwrap();
    assert_eq!(q.host.as_deref(), Some("db.example"));
    assert!(q.forwarded);
    assert_eq!(
        q.text(),
        "A program wants to sign in to db.example through a forwarded connection."
    );

    // A bad signature is refused; an RSA host key leaves the host unknown.
    let mut c = app.client();
    let mut bad = binding(&hosts, &kh, b"session-3", false);
    let n = bad.len();
    bad[n - 2] ^= 1;
    assert_eq!(c.call(&bad), [5]);
    let mut c = app.client();
    assert_eq!(
        c.call(&binding(&hosts, &blob("kr"), b"session-4", false)),
        [6],
        "the system agent took it"
    );
    app.asker.answer(Some(false));
    let sign = sign_request(&k1, &userauth(b"session-4", &k1, None));
    assert_eq!(c.call(&sign), [5]);
    assert_eq!(app.asker.asked().pop().unwrap().host, None);
    // A binding with a key Larsal cannot check and no system agent: 5.
    let lone = self::app(None, Duration::from_secs(1));
    assert_eq!(
        lone.client()
            .call(&binding(&hosts, &blob("kr"), b"s", false)),
        [5]
    );
    assert_eq!(lone.client().call(&binding(&hosts, &kh, b"s", false)), [6]);
}

/// The data `ssh` signs to sign in (RFC 4252 section 7): session ID, 50,
/// user, service, method, TRUE, algorithm, key; the host-bound form adds
/// the server's host key.
fn userauth(session: &[u8], key: &[u8], hostbound: Option<&[u8]>) -> Vec<u8> {
    let method: &[u8] = match hostbound {
        Some(_) => b"publickey-hostbound-v00@openssh.com",
        None => b"publickey",
    };
    [
        s(session),
        vec![50],
        s(b"root"),
        s(b"ssh-connection"),
        s(method),
        vec![1],
        s(b"ssh-ed25519"),
        s(key),
        hostbound.map(s).unwrap_or_default(),
    ]
    .concat()
}

/// LD-203 (2): a bound session names the host only for a sign-in request
/// that carries that session ID (and, host-bound, that host key) for the
/// key being used; any other data leaves the host unknown (MI06-31).
#[test]
fn t57_ld203_2_other_data_on_a_bound_session_names_no_host() {
    let hosts = Throwaway::start();
    let d = Dir::new("ld203");
    assert!(run(
        tool("ssh-keygen", &d.0).args(["-q", "-t", "ed25519", "-N", "", "-f", "kh"])
    ));
    assert!(run(hosts.tool("ssh-add").arg(d.join("kh"))));
    let kh = SshKey::read(&fs::read(d.join("kh")).unwrap())
        .unwrap()
        .public_blob()
        .to_vec();
    let app = app(None, Duration::from_secs(10));
    let kh_line = fs::read_to_string(d.join("kh.pub")).unwrap();
    fs::write(
        app.dir.join("known_hosts"),
        format!("web01.example {kh_line}"),
    )
    .unwrap();
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    let k1 = blob("k1");
    let mut c = app.client();
    assert_eq!(c.call(&binding(&hosts, &kh, b"session-1", false)), [6]);
    let other_key = blob("k2");
    for data in [
        b"some other data".to_vec(),
        userauth(b"session-0", &k1, None),
        userauth(b"session-1", &other_key, None),
        userauth(b"session-1", &k1, Some(&other_key)),
        [userauth(b"session-1", &k1, None), vec![0]].concat(),
    ] {
        app.asker.answer(Some(false));
        assert_eq!(c.call(&sign_request(&k1, &data)), [5]);
        let q = app.asker.asked().pop().unwrap();
        assert_eq!(q.host, None, "{data:?}");
        assert_eq!(q.text(), "A program wants to sign with this key.");
    }
    for data in [
        userauth(b"session-1", &k1, None),
        userauth(b"session-1", &k1, Some(&kh)),
    ] {
        app.asker.answer(Some(false));
        assert_eq!(c.call(&sign_request(&k1, &data)), [5]);
        let q = app.asker.asked().pop().unwrap();
        assert_eq!(q.host.as_deref(), Some("web01.example"));
    }
}

/// LD-203 (5): the passphrase resolves in Copy's context, so `{S:otp}`
/// gives nothing (LD-170 (4)) and the protected key is MI06-14.
#[test]
fn ld203_5_hidden_otp_field_as_passphrase_is_mi06_14() {
    let mut e = e1(s_att("id_ed25519"));
    for (name, value) in [("Password", "{S:otp}"), ("otp", PASS)] {
        e.set_field(
            name.into(),
            Field {
                value: SecretString::new(value.into()),
                protected: true,
            },
        );
    }
    let v = vault(vec![e], vec![]);
    let k = Keyring::new();
    let err = load(&k, &session(1, "V"), &v, 1).unwrap_err();
    assert_eq!(err, Error::NoPassphrase);
    assert_eq!(err.id(), "MI06-14");
}

#[test]
fn t58_one_question_at_a_time_and_no_answer_is_deny() {
    let _timed = timed();
    let app = app(None, Duration::from_secs(1));
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    app.asker.answer(None);
    app.asker.answer(None);
    let t0 = Instant::now();
    let sock = app.sock.clone();
    let both: Vec<_> = (0..2)
        .map(|_| {
            let sock = sock.clone();
            thread::spawn(move || Client::at(&sock).call(&sign_request(&blob("k1"), b"x")))
        })
        .collect();
    for h in both {
        assert_eq!(
            h.join().unwrap(),
            [5],
            "no answer within the time is Deny, a late Allow is ignored"
        );
    }
    let took = t0.elapsed();
    let asked = app.asker.asked.lock().unwrap().clone();
    let cancelled = app.asker.cancelled.lock().unwrap().clone();
    assert_eq!(asked.len(), 2);
    assert_eq!(cancelled.len(), 2);
    assert_eq!(cancelled[0].0, asked[0].0.id);
    assert!(
        asked[1].1 >= cancelled[0].1,
        "the second question shows after the first ended"
    );
    assert!(
        took >= Duration::from_secs(2) && took < Duration::from_secs(4),
        "{took:?}"
    );
}

#[test]
fn t59_lock_closes_the_open_question() {
    let app = app(None, Duration::from_secs(30));
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    app.asker.answer(None);
    let sock = app.sock.clone();
    let req = thread::spawn(move || Client::at(&sock).call(&sign_request(&blob("k1"), b"x")));
    app.asker.wait_asked(1);
    let t0 = Instant::now();
    app.keyring.lock(1);
    assert_eq!(req.join().unwrap(), [5]);
    assert!(t0.elapsed() < Duration::from_secs(1), "SR-16");
    let id = app.asker.asked()[0].id;
    assert_eq!(
        app.asker.cancelled.lock().unwrap()[0].0,
        id,
        "the dialog is told to close"
    );
    assert!(app.listed().is_empty());
}

#[test]
fn t72_setup_line_is_read_back_by_ssh() {
    let app = app(None, Duration::from_secs(1));
    let line = app.agent.as_ref().unwrap().setup_line();
    assert_eq!(line, format!("IdentityAgent \"{}\"", app.sock.display()));
    // A path with a space and a %, as ~/Library/Application Support has.
    let odd = PathBuf::from("/tmp/Larsal Support/50%/agent.sock");
    for (path, want) in [(app.sock.clone(), app.sock.clone()), (odd.clone(), odd)] {
        fs::write(
            app.dir.join("config"),
            format!("Host demo\n  {}\n", larsal_sshagent::setup_line(&path)),
        )
        .unwrap();
        let out = tool("ssh", &app.dir.0)
            .args(["-F", "config", "-G", "demo"])
            .output()
            .unwrap();
        let shown = String::from_utf8(out.stdout).unwrap();
        let got = shown
            .lines()
            .find_map(|l| l.strip_prefix("identityagent "))
            .unwrap();
        assert_eq!(Path::new(got.trim_matches('"')), want);
    }
}

#[test]
fn int06_32_stop_removes_the_socket_keys_stay_until_turned_off() {
    let mut app = app(None, Duration::from_secs(1));
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    app.agent.take().unwrap().stop();
    assert!(!app.sock.exists());
    assert_eq!(app.keyring.is_loaded(&blob("k1")), Ok(true));
    app.keyring.turn_off();
    assert_eq!(app.keyring.place_of(&blob("k1")), None);
}

// ------------------------------------------------- hostile clients

/// Panics on Larsal's agent threads (named `larsal-agent…`) so far in this run
/// (LD-202 note): a dead client thread is otherwise only a closed socket.
fn agent_panics() -> usize {
    static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static HOOK: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    HOOK.get_or_init(|| {
        let old = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if thread::current()
                .name()
                .is_some_and(|n| n.starts_with("larsal-agent"))
            {
                COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            old(info);
        }));
    });
    COUNT.load(std::sync::atomic::Ordering::SeqCst)
}

#[test]
fn hostile_clients_never_hang_or_panic() {
    let _timed = timed();
    let panics = agent_panics();
    let a = Throwaway::start();
    let app = app(Some(&a), Duration::from_millis(200));
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    // Over 256 KiB, and zero length: closed.
    for len in [262_145u32, 0, u32::MAX] {
        let mut c = app.client();
        c.0.write_all(&len.to_be_bytes()).unwrap();
        assert!(c.closed(), "{len}");
    }
    // A message that never completes: closed within the 2 s bound.
    let mut c = app.client();
    c.0.write_all(&[0, 0]).unwrap();
    let t0 = Instant::now();
    assert!(c.closed());
    let took = t0.elapsed();
    assert!(
        took > Duration::from_millis(1500) && took < Duration::from_secs(3),
        "{took:?}"
    );
    // Truncated and odd requests get 5 (or the system agent's answer).
    let k1 = blob("k1");
    let mut c = app.client();
    for body in [
        vec![13],
        [&[13u8][..], &s(&k1)].concat(),
        [&[13u8][..], &s(&k1), &s(b"d")].concat(),
        vec![18, 0, 0, 0, 9],
        vec![27],
        [&[27u8][..], &s(b"session-bind@openssh.com"), &s(b"x")].concat(),
        vec![99],
    ] {
        let reply = c.call(&body);
        assert_eq!(reply, [5], "{body:?}");
    }
    // Random messages of every type: a reply or a close, never a panic.
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for n in 0..400 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let len = 1 + (seed % 300) as usize;
        let mut body: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
        body[0] = (n % 30) as u8;
        if body[0] == 13 || body[0] == 19 {
            body[0] = 12; // a sign would wait for the question; 19 empties Larsal's agent
        }
        let mut c = app.client();
        c.0.write_all(&(len as u32).to_be_bytes()).unwrap();
        c.0.write_all(&body).unwrap();
        let mut head = [0u8; 4];
        let _ = c.0.read(&mut head);
    }
    assert!(
        app.listed().contains(&"demo@app".to_owned()),
        "still serving"
    );
    assert_eq!(
        agent_panics(),
        panics,
        "LD-202: no panic on Larsal's agent threads"
    );
}

#[test]
fn max_clients_one_more_is_closed_at_once() {
    let app = app(None, Duration::from_secs(1));
    let mut idle: Vec<Client> = (0..larsal_sshagent::MAX_CLIENTS)
        .map(|_| app.client())
        .collect();
    // Each idle client is admitted: it gets an answer, then stays connected.
    for c in &mut idle {
        assert_eq!(c.call(&[11]), [12, 0, 0, 0, 0]);
    }
    let mut first = Client::at(&app.sock);
    let t0 = Instant::now();
    assert!(first.closed(), "client 33 is closed");
    assert!(t0.elapsed() < Duration::from_secs(1));
    drop(idle);
    thread::sleep(Duration::from_millis(200));
    let mut again = app.client();
    assert_eq!(
        again.call(&[11])[0],
        12,
        "served again once the others left"
    );
}

// ------------------------------------------------- ssh end to end

/// A throwaway `sshd` on 127.0.0.1 (this user only, no PAM), stopped by
/// its PID on drop. It lets in only `authorized`.
struct Sshd {
    child: std::process::Child,
    port: u16,
    host_key_line: String,
    _dir: Dir,
}

impl Sshd {
    fn start(authorized: &str) -> Self {
        let dir = Dir::new("sshd");
        assert!(run(
            tool("ssh-keygen", &dir.0).args(["-q", "-t", "ed25519", "-N", "", "-f", "hk"])
        ));
        fs::write(dir.join("authorized_keys"), authorized).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let d = dir.0.display();
        fs::write(
            dir.join("cfg"),
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/hk\nPidFile {d}/pid\nUsePAM no\n\
                 StrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
                 AuthorizedKeysFile {d}/authorized_keys\n"
            ),
        )
        .unwrap();
        let child = std::process::Command::new("/usr/sbin/sshd")
            .env_clear()
            .args(["-D", "-e", "-f"])
            .arg(dir.join("cfg"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let host_key_line = fs::read_to_string(dir.join("hk.pub")).unwrap();
        // Built before the wait, so a failed start drops it and kills sshd
        // (F-132): a test run never leaves a process behind (rule 11).
        let sshd = Self {
            child,
            port,
            host_key_line,
            _dir: dir,
        };
        let t0 = Instant::now();
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(t0.elapsed() < Duration::from_secs(5), "sshd did not start");
            thread::sleep(Duration::from_millis(20));
        }
        sshd
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn t53_t57_ssh_signs_in_through_apps_socket() {
    let a = Throwaway::start();
    assert!(
        run(a.tool("ssh-add").arg(keys().path("k2"))),
        "a key Larsal does not hold"
    );
    let app = app(Some(&a), Duration::from_secs(20));
    let v = vault(
        vec![e1(Settings {
            confirm: true,
            ..s_att("id_ed25519")
        })],
        vec![],
    );
    load(&app.keyring, &session(1, "V"), &v, 1).unwrap();
    let sshd = Sshd::start(&fs::read_to_string(keys().path("k1.pub")).unwrap());
    let mut key = sshd.host_key_line.split(' ');
    let (kind, b64) = (key.next().unwrap(), key.next().unwrap());
    // ssh's own file names the host by address; Larsal's names it web01.example.
    fs::write(
        app.dir.join("ssh_known"),
        format!("[127.0.0.1]:{} {kind} {b64}\n", sshd.port),
    )
    .unwrap();
    fs::write(
        app.dir.join("known_hosts"),
        format!("web01.example {kind} {b64}\n"),
    )
    .unwrap();
    // LD-203 (6): a throwaway config and no identity files, so ssh never
    // reads the owner's ~/.ssh (it takes ~ from the user database, not HOME).
    fs::write(
        app.dir.join("ssh_config"),
        format!(
            "Host *\n  BatchMode yes\n  UserKnownHostsFile {d}/ssh_known\n  \
             GlobalKnownHostsFile /dev/null\n  IdentityAgent \"{sock}\"\n",
            d = app.dir.0.display(),
            sock = app.sock.display()
        ),
    )
    .unwrap();
    let ssh_cmd = |extra: &[&str]| {
        let mut cmd = tool("ssh", &app.dir.0);
        cmd.args(["-F", "ssh_config", "-o", "IdentityFile=none"])
            .args(extra)
            .args([
                "-p",
                &sshd.port.to_string(),
                "127.0.0.1",
                "echo",
                "signed-in",
            ]);
        cmd
    };
    let shown = String::from_utf8(ssh_cmd(&["-G"]).output().unwrap().stdout).unwrap();
    assert!(shown.lines().any(|l| l == "identityfile none"), "{shown}");
    assert!(!shown.contains(".ssh/"), "nothing from ~/.ssh: {shown}");
    let agent_line = format!("identityagent {}", app.sock.display());
    assert!(shown.lines().any(|l| l == agent_line), "{shown}");
    let ssh = || {
        let out = ssh_cmd(&[]).output().unwrap();
        String::from_utf8(out.stdout).unwrap().contains("signed-in")
    };
    app.asker.answer(Some(true));
    assert!(ssh(), "Allow Once: ssh signs in with Larsal's key");
    let q = app.asker.asked().pop().unwrap();
    assert_eq!(
        q.host.as_deref(),
        Some("web01.example"),
        "ssh sent a session binding Larsal checked"
    );
    assert!(!q.forwarded);
    assert_eq!(q.fingerprint, K1_FINGERPRINT);
    app.asker.answer(Some(false));
    assert!(
        !ssh(),
        "Deny: no sign-in (K2 from the system agent is not let in)"
    );
    assert_eq!(app.asker.asked().len(), 2);
}

/// LD-209: OpenSSH stores K2s's private scalar in 31 bytes. Larsal reads the
/// key plain and with its passphrase, adds it to the system agent and signs
/// with it through Larsal's own agent (upstream ssh-key refused it: MI06-10
/// for the plain key, MI06-15 for the protected one).
#[test]
fn ld209_a_p256_key_with_a_31_byte_scalar_reads_adds_and_signs() {
    use larsal_crypto::base64::{Form, decode};
    let body: String = K2S.lines().filter(|l| !l.starts_with("-----")).collect();
    let raw = decode(Form::Padded, body).unwrap();
    let public = decode(Form::Padded, K2S_PUBLIC.split(' ').nth(1).unwrap()).unwrap();
    // The private part: the curve point, then the scalar as an `mpint`.
    let point = s(&public[39..104]);
    let at = raw.windows(point.len()).rposition(|w| w == point).unwrap() + point.len();
    assert_eq!(
        raw[at..at + 4],
        31u32.to_be_bytes(),
        "the test key's scalar"
    );

    let read = |file: &str, password: &str| {
        let key = SshKey::read(&keys().bytes(file))?;
        assert_eq!(key.public_blob(), &public[..], "{file}");
        assert_eq!(key.fingerprint(), K2S_FINGERPRINT, "{file}");
        key.unlock(&pass(password)).map(|_| ())
    };
    assert_eq!(
        [read("k2s", ""), read("k2se", PASS)],
        [Ok(()), Ok(())],
        "plain, and with its passphrase"
    );

    // The plain key through an entry, to a throwaway system agent.
    let a = Throwaway::start();
    let k = Keyring::new();
    k.set_agent_settings(a.agent.path().to_str().unwrap(), None);
    let plain = entry(
        2,
        "Short",
        "",
        "",
        vec![
            att("id_ecdsa", keys().bytes("k2s")),
            settings_att(&s_att("id_ecdsa")),
        ],
    );
    let v = vault(vec![plain], vec![]);
    assert_eq!(load(&k, &session(1, "V"), &v, 2), Ok(Place::System));
    let out = a.tool("ssh-add").arg("-l").output().unwrap();
    let listed = String::from_utf8(out.stdout).unwrap();
    assert!(
        listed.contains(&format!("{K2S_FINGERPRINT} short@app (ECDSA)")),
        "{listed}"
    );

    // The protected key through an entry, asking first: Larsal's agent signs.
    let app = app(None, Duration::from_secs(10));
    let protected = entry(
        3,
        "Short asks",
        "",
        PASS,
        vec![
            att("id_ecdsa", keys().bytes("k2se")),
            settings_att(&Settings {
                confirm: true,
                ..s_att("id_ecdsa")
            }),
        ],
    );
    let v = vault(vec![protected], vec![]);
    assert_eq!(load(&app.keyring, &session(1, "V"), &v, 3), Ok(Place::Own));
    app.asker.answer(Some(true));
    assert!(keygen_sign(&app, "k2s"), "Allow Once signs");
    assert!(
        keygen_verify(&app, "k2s", "short@app"),
        "a valid P-256 signature"
    );
}
