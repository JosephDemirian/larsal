//! E9-S2 wiring: the session's SSH agent work (spec INT-06) through
//! app-ffi's exports, on demo vaults made here, against throwaway
//! `ssh-agent` processes and fake agents in /tmp (each stopped by its PID).
//! Never the user's own agent: S-SSH-02 always names a throwaway or a
//! missing socket, so `SSH_AUTH_SOCK` is never read; App's own agent gets a
//! /tmp socket and a throwaway `known_hosts`. Test names carry the rule.

#[path = "../../app-sshagent/tests/common/mod.rs"]
mod common;

use app_crypto::kdf::Host;
use app_crypto::secret::{SecretBytes, SecretString};
use app_ffi::session::{Session, UnlockResult};
use app_ffi::ssh::SshFailure;
use app_format::keys::Credentials;
use app_format::limits::Limits;
use app_format::{Saved, save};
use app_model::entry::Field;
use app_model::{Argon2Kind, Attachment, Encryption, Entry, Group, Kdf, Time, Uuid, Vault};
use app_sshagent::{SETTINGS_NAME, Settings, Source, SshKey};
use common::{Dir, K1, PASS, Throwaway, read_msg, run, s, silent, timed, tool};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const VAULT_PASS: &str = "demo-ssh-vault";
const E1: &str = "Server root · web-01";

/// K1e (K1 protected with `PASS`) and K2 (ECDSA P-256), made by
/// `ssh-keygen` in `dir`.
fn keys(dir: &Dir) -> (Vec<u8>, Vec<u8>) {
    std::fs::write(dir.join("k1e"), K1).unwrap();
    std::fs::set_permissions(dir.join("k1e"), PermissionsExt::from_mode(0o600)).unwrap();
    let keygen = |args: &[&str]| assert!(run(tool("ssh-keygen", &dir.0).args(args)), "{args:?}");
    keygen(&["-q", "-p", "-P", "", "-N", PASS, "-f", "k1e"]);
    keygen(&[
        "-q",
        "-t",
        "ecdsa",
        "-b",
        "256",
        "-N",
        "",
        "-C",
        "ecdsa@app",
        "-f",
        "k2",
    ]);
    (
        std::fs::read(dir.join("k1e")).unwrap(),
        std::fs::read(dir.join("k2")).unwrap(),
    )
}

fn blob(key: &[u8]) -> Vec<u8> {
    SshKey::read(key).unwrap().public_blob().to_vec()
}

fn att(name: &str, bytes: Vec<u8>) -> Attachment {
    Attachment {
        name: name.into(),
        data: Arc::new(SecretBytes::new(bytes)),
    }
}

/// An entry whose attachment `id_key` holds `key`, with `settings` (allow,
/// add on unlock, key in `id_key`, then `edit`) and `fields`.
fn ssh_entry(
    n: u8,
    title: &str,
    password: &str,
    key: Vec<u8>,
    edit: impl FnOnce(&mut Settings),
) -> Entry {
    let mut settings = Settings {
        allow: true,
        add_at_open: true,
        source: Source::Attachment,
        attachment_name: "id_key".into(),
        ..Settings::default()
    };
    edit(&mut settings);
    let mut e = Entry::new(Uuid([n; 16]), Time::from_unix(1_700_000_000).unwrap());
    for (name, value) in [
        ("Title", title),
        ("UserName", "root"),
        ("Password", password),
    ] {
        let field = Field {
            value: SecretString::new(value.to_owned()),
            protected: name == "Password",
        };
        e.set_field(name.to_owned(), field);
    }
    e.attachments = vec![
        att("id_key", key),
        att(
            std::str::from_utf8(&SETTINGS_NAME).unwrap(),
            settings.write().unwrap(),
        ),
    ];
    e
}

/// The vault file in `dir` (password `VAULT_PASS`, a fast KDF).
fn vault_file(dir: &Dir, entries: Vec<Entry>) -> String {
    vault_file_with(dir, entries, |_| {})
}

/// [`vault_file`] with `edit` applied to the vault first.
fn vault_file_with(dir: &Dir, entries: Vec<Entry>, edit: impl FnOnce(&mut Vault)) -> String {
    let now = Time::from_unix(1_700_000_000).unwrap();
    let mut root = Group::new(Uuid([0x01; 16]), "Demo".to_owned(), now);
    root.entries = entries;
    let mut vault = Vault::new(root, now);
    edit(&mut vault);
    vault.encryption = Encryption {
        kdf: Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 2,
            memory_kib: 1024,
            lanes: 1,
        },
        ..Encryption::default()
    };
    let password = SecretString::new(VAULT_PASS.to_owned());
    let credentials = Credentials {
        password: Some(&password),
        key_file: None,
        hardware_key: None,
    };
    let mut host = Host {
        physical_memory: 8 << 30,
        logical_processors: 4,
        argon2_record: None,
        aes_record: None,
    };
    let Ok(Saved::File(saved)) = save(
        &vault,
        &credentials,
        None,
        &mut host,
        &Limits::DEFAULT,
        None,
    ) else {
        panic!("save the demo vault");
    };
    let path = dir.join("ssh-demo.appvault");
    std::fs::write(&path, &saved.bytes).unwrap();
    path.to_string_lossy().into_owned()
}

/// A test session with the feature on: the system agent at `agent`, App's
/// own agent at `dir/App/agent.sock` with a throwaway `known_hosts`.
fn session(dir: &Dir, agent: &Path, question_time: Duration) -> Arc<Session> {
    let session = Session::new();
    session.set_ssh_options(
        dir.join("App/agent.sock"),
        dir.join("known_hosts"),
        question_time,
    );
    session
        .set_ssh_agent(true, agent.to_string_lossy().into_owned(), String::new())
        .unwrap();
    session
}

fn unlock(session: &Session, path: &str) -> u64 {
    let id = session.open(path.to_owned()).unwrap();
    assert_eq!(
        session.unlock(id, Some(VAULT_PASS.into()), None),
        Ok(UnlockResult::Unlocked)
    );
    id
}

/// One raw connection to App's socket.
fn call(stream: &mut UnixStream, body: &[u8]) -> Vec<u8> {
    stream
        .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
    read_msg(stream)
}

/// Sends a sign request for `key` on App's socket from another thread.
fn sign_later(dir: &Dir, key: &[u8]) -> thread::JoinHandle<Vec<u8>> {
    let mut stream = UnixStream::connect(dir.join("App/agent.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let body = [&[13u8][..], &s(key), &s(b"demo data"), &0u32.to_be_bytes()].concat();
    thread::spawn(move || call(&mut stream, &body))
}

/// The question once the window can read it.
fn question(session: &Session) -> app_ffi::ssh::SshQuestion {
    let t0 = Instant::now();
    loop {
        if let Some(q) = session.ssh_question() {
            return q;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "no question");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn int06_22_unlock_adds_off_the_calling_thread_and_mi06_18_names_the_failures() {
    let _t = timed();
    let dir = Dir::new("f");
    let (k1e, _) = keys(&dir);
    // A fake agent that answers the add only after the unlock returned
    // (F-092: an event, not a wall-clock bound that a busy Mac breaks). An
    // unlock that waited for the agent gives up after the agent client's
    // 2 s `TIMEOUT` (app-sshagent agent.rs) and closes the socket, so the
    // fake's late answer fails and the test fails at `fake.join()`.
    let listener = UnixListener::bind(dir.join("slow")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let answered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&answered);
    let fake = thread::spawn(move || {
        let t0 = Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                // Nobody came: no add was sent.
                Err(_) if t0.elapsed() > Duration::from_secs(10) => return 0,
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        };
        stream.set_nonblocking(false).unwrap();
        let _ = wait.recv_timeout(Duration::from_secs(30));
        let msg = read_msg(&mut stream);
        seen.store(true, std::sync::atomic::Ordering::SeqCst);
        stream.write_all(&[0, 0, 0, 1, 6]).unwrap();
        // Open until App closes, as an agent does.
        let _ = stream.read_to_end(&mut Vec::new());
        msg[0]
    });
    let path = vault_file(
        &dir,
        vec![
            ssh_entry(1, E1, PASS, k1e, |_| {}),
            ssh_entry(2, "Old key", "", b"not a key".to_vec(), |_| {}),
        ],
    );
    let session = session(&dir, &dir.join("slow"), Duration::from_secs(60));
    unlock(&session, &path);
    assert!(
        !answered.load(std::sync::atomic::Ordering::SeqCst),
        "unlock waited for the agent"
    );
    let _ = go.send(());
    session.ssh_settled();
    assert_eq!(fake.join().unwrap(), 17, "K1e was added (message 17)");
    let failures = session.take_ssh_failures();
    assert_eq!(
        failures,
        [SshFailure {
            title: "Old key".into(),
            id: "MI06-10".into(),
            message: "id_key is not an SSH private key App can read.".into(),
        }]
    );
    assert_eq!(
        session.take_banner().as_deref(),
        Some("Some SSH keys were not loaded: Old key.")
    );
}

#[test]
fn ld203_5_otp_field_as_key_passphrase_gives_mi06_14() {
    let _t = timed();
    let dir = Dir::new("o");
    let (k1e, _) = keys(&dir);
    let system = Throwaway::start();
    let mut e = ssh_entry(1, E1, "{S:otp}", k1e, |_| {});
    e.set_field(
        "otp".into(),
        Field {
            value: SecretString::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()),
            protected: true,
        },
    );
    let path = vault_file(&dir, vec![e]);
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    unlock(&session, &path);
    session.ssh_settled();
    let failures = session.take_ssh_failures();
    assert_eq!(
        failures.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        ["MI06-14"],
        "{failures:?}"
    );
    assert!(system.blobs().is_empty());
}

#[test]
fn int06_24_lock_removes_marked_keys_within_1_s_and_keeps_the_rest() {
    let _t = timed();
    let dir = Dir::new("l");
    let (k1e, k2) = keys(&dir);
    let system = Throwaway::start();
    let path = vault_file(
        &dir,
        vec![
            ssh_entry(1, E1, PASS, k1e.clone(), |s| s.remove_at_close = true),
            ssh_entry(2, "File key", "", k2.clone(), |_| {}),
        ],
    );
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    let id = unlock(&session, &path);
    session.ssh_settled();
    assert_eq!(system.blobs(), [blob(&k1e), blob(&k2)]);
    let t0 = Instant::now();
    session.lock(id).unwrap();
    // F-108: the removals run on their own thread; within 1 s all the same.
    session.ssh_settled();
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
    assert_eq!(system.blobs(), [blob(&k2)], "AT-H01");
    // The records went with the lock: a second lock removes nothing.
    system
        .agent
        .add(
            &common::k1_unlocked(),
            "again",
            &app_sshagent::Limits::default(),
        )
        .unwrap();
    session.lock(id).unwrap();
    session.ssh_settled();
    assert_eq!(system.blobs().len(), 2);
}

#[test]
fn int06_24_close_and_lock_all_do_the_same() {
    let _t = timed();
    let dir = Dir::new("c");
    let (k1e, _) = keys(&dir);
    let system = Throwaway::start();
    let path = vault_file(
        &dir,
        vec![ssh_entry(1, E1, PASS, k1e, |s| s.remove_at_close = true)],
    );
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    let id = unlock(&session, &path);
    session.ssh_settled();
    assert_eq!(system.blobs().len(), 1);
    session.close(id).unwrap();
    session.ssh_settled();
    assert!(system.blobs().is_empty(), "close");
    unlock(&session, &path);
    session.ssh_settled();
    assert_eq!(system.blobs().len(), 1);
    session.lock_all();
    session.ssh_settled();
    assert!(system.blobs().is_empty(), "lock all");
}

/// F-108: a system agent that never answers does not hold the lock, which
/// the window calls on the main thread: the vault locks at once, the marked
/// keys' removal ends on its own thread (one 2 s wait for both keys), and
/// MI06-19 names them.
#[test]
fn f_108_a_silent_agent_never_holds_the_lock() {
    let _t = timed();
    let dir = Dir::new("h");
    let (k1e, k2) = keys(&dir);
    let mut system = Throwaway::start();
    let path = vault_file(
        &dir,
        vec![
            ssh_entry(1, E1, PASS, k1e, |s| s.remove_at_close = true),
            ssh_entry(2, "File key", "", k2, |s| s.remove_at_close = true),
        ],
    );
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    let id = unlock(&session, &path);
    session.ssh_settled();
    assert_eq!(system.blobs().len(), 2);
    let socket = system.agent.path().to_owned();
    system.child.kill().unwrap();
    system.child.wait().unwrap();
    let _ = std::fs::remove_file(&socket);
    let hung = silent(&socket);
    let t0 = Instant::now();
    session.lock(id).unwrap();
    let took = t0.elapsed();
    assert!(took < Duration::from_secs(1), "the lock waited: {took:?}");
    assert!(session.vaults().iter().all(|v| v.locked));
    session.ssh_settled();
    assert_eq!(hung.connections(), 1);
    let banner = session.take_banner().unwrap_or_default();
    assert!(
        banner.contains(E1) && banner.contains("File key"),
        "{banner}"
    );
}

/// F-108, INT-06.25: quit waits for the lock's removals, so App never ends
/// before the marked keys leave the system agent: when `stop_ssh_agent`
/// returns, the silent agent's MI06-19 is already set.
#[test]
fn f_108_quit_waits_for_the_locks_removals() {
    let _t = timed();
    let dir = Dir::new("w");
    let (_, k2) = keys(&dir);
    let mut system = Throwaway::start();
    let path = vault_file(
        &dir,
        vec![ssh_entry(2, "File key", "", k2, |s| {
            s.remove_at_close = true
        })],
    );
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    unlock(&session, &path);
    session.ssh_settled();
    let socket = system.agent.path().to_owned();
    system.child.kill().unwrap();
    system.child.wait().unwrap();
    let _ = std::fs::remove_file(&socket);
    let _hung = silent(&socket);
    // Quit as the window does it, with no ssh_settled.
    session.lock_all();
    session.stop_ssh_agent();
    let banner = session.take_banner().unwrap_or_default();
    assert!(
        banner.contains("File key"),
        "quit did not wait for the removal: {banner:?}"
    );
}

#[test]
fn int06_25_quit_keeps_unmarked_keys_and_removes_apps_socket() {
    let _t = timed();
    let dir = Dir::new("q");
    let (k1e, k2) = keys(&dir);
    let system = Throwaway::start();
    let path = vault_file(
        &dir,
        vec![
            ssh_entry(1, E1, PASS, k1e, |s| s.confirm = true),
            ssh_entry(2, "File key", "", k2.clone(), |_| {}),
        ],
    );
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    unlock(&session, &path);
    session.ssh_settled();
    assert!(dir.join("App/agent.sock").exists());
    // Quit as the window does it: lock every vault, then stop App's agent.
    session.lock_all();
    session.stop_ssh_agent();
    assert_eq!(system.blobs(), [blob(&k2)]);
    assert!(!dir.join("App/agent.sock").exists());
}

#[test]
fn int06_21_feature_off_contacts_no_agent_and_opens_no_socket() {
    let _t = timed();
    let dir = Dir::new("n");
    let (k1e, _) = keys(&dir);
    let listener = UnixListener::bind(dir.join("count")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let path = vault_file(&dir, vec![ssh_entry(1, E1, PASS, k1e, |_| {})]);
    let session = Session::new();
    session.set_ssh_options(
        dir.join("App/agent.sock"),
        dir.join("known_hosts"),
        Duration::from_secs(60),
    );
    session
        .set_ssh_agent(
            false,
            dir.join("count").to_string_lossy().into(),
            String::new(),
        )
        .unwrap();
    let id = unlock(&session, &path);
    session.ssh_settled();
    session.lock(id).unwrap();
    assert!(listener.accept().is_err(), "an agent was contacted");
    assert!(!dir.join("App/agent.sock").exists());
    assert_eq!(session.ssh_agent_info(), None);
}

#[test]
fn int06_26_turning_off_removes_every_key_app_added_and_stops_apps_agent() {
    let _t = timed();
    let dir = Dir::new("t");
    let (k1e, k2) = keys(&dir);
    let system = Throwaway::start();
    let path = vault_file(
        &dir,
        vec![ssh_entry(1, E1, PASS, k1e.clone(), |s| {
            s.remove_at_close = true
        })],
    );
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    let info = session.ssh_agent_info().unwrap();
    assert_eq!(info.error, None, "Ready");
    assert_eq!(
        info.setup_line,
        format!("IdentityAgent \"{}\"", dir.join("App/agent.sock").display())
    );
    unlock(&session, &path);
    session.ssh_settled();
    // K2 comes from another program (LD-63): it stays.
    assert!(run(system.tool("ssh-add").arg(dir.join("k2"))));
    assert_eq!(system.blobs().len(), 2);
    session
        .set_ssh_agent(
            false,
            system.agent.path().to_string_lossy().into(),
            String::new(),
        )
        .unwrap();
    assert_eq!(system.blobs(), [blob(&k2)]);
    assert!(!dir.join("App/agent.sock").exists());
}

/// E1 asks before each use; App's agent holds it once the vault unlocks.
fn asking(tag: &str, question_time: Duration) -> (Dir, Throwaway, Arc<Session>, u64, Vec<u8>) {
    let dir = Dir::new(tag);
    let (k1e, _) = keys(&dir);
    let system = Throwaway::start();
    let path = vault_file(
        &dir,
        vec![ssh_entry(1, E1, PASS, k1e.clone(), |s| s.confirm = true)],
    );
    let session = session(&dir, system.agent.path(), question_time);
    let id = unlock(&session, &path);
    session.ssh_settled();
    assert!(
        system.blobs().is_empty(),
        "INT-06.31: never in the system agent"
    );
    (dir, system, session, id, blob(&k1e))
}

#[test]
fn int06_34_the_window_answers_allow_once_signs_and_deny_refuses() {
    let _t = timed();
    let (dir, _system, session, _, key) = asking("a", Duration::from_secs(60));
    let reply = sign_later(&dir, &key);
    let q = question(&session);
    assert_eq!(q.heading, format!("Allow a program to use “{E1}”?"));
    assert_eq!(q.text, "A program wants to sign with this key.");
    session.answer_ssh_question(q.id, true);
    assert_eq!(reply.join().unwrap()[0], 14, "a signature");
    assert_eq!(session.ssh_question(), None, "the dialog closes");
    let reply = sign_later(&dir, &key);
    let q = question(&session);
    session.answer_ssh_question(q.id, false);
    assert_eq!(reply.join().unwrap(), [5]);
    // A late or wrong answer is ignored.
    session.answer_ssh_question(q.id, true);
    assert_eq!(session.ssh_question(), None);
}

#[test]
fn int06_34_sr16_lock_closes_the_question_as_deny() {
    let _t = timed();
    let (dir, _system, session, id, key) = asking("k", Duration::from_secs(60));
    let reply = sign_later(&dir, &key);
    question(&session);
    let t0 = Instant::now();
    session.lock(id).unwrap();
    assert_eq!(reply.join().unwrap(), [5]);
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
    assert_eq!(session.ssh_question(), None);
}

/// SR-16 then a turn-off and a turn-on: the new App's agent asks again
/// after the lock ended the old agent's question (question ids rise across
/// agents, so the old cancel never ends a new question).
#[test]
fn int06_34_a_new_agent_asks_again_after_a_lock_ended_a_question() {
    let _t = timed();
    let (dir, system, session, id, key) = asking("r", Duration::from_secs(60));
    let reply = sign_later(&dir, &key);
    question(&session);
    session.lock(id).unwrap();
    assert_eq!(reply.join().unwrap(), [5]);
    let agent = system.agent.path().to_string_lossy().into_owned();
    session
        .set_ssh_agent(false, agent.clone(), String::new())
        .unwrap();
    session.set_ssh_agent(true, agent, String::new()).unwrap();
    assert_eq!(
        session.unlock(id, Some(VAULT_PASS.into()), None),
        Ok(UnlockResult::Unlocked)
    );
    session.ssh_settled();
    let reply = sign_later(&dir, &key);
    let q = question(&session);
    session.answer_ssh_question(q.id, true);
    assert_eq!(reply.join().unwrap()[0], 14, "a signature");
}

#[test]
fn int06_34_no_answer_within_the_question_time_is_deny() {
    let _t = timed();
    let (dir, _system, session, _, key) = asking("w", Duration::from_secs(1));
    let reply = sign_later(&dir, &key);
    let q = question(&session);
    let t0 = Instant::now();
    assert_eq!(reply.join().unwrap(), [5]);
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    assert_eq!(session.ssh_question(), None);
    session.answer_ssh_question(q.id, true);
    assert_eq!(session.ssh_question(), None);
}

/// AT-H01 and INT-06.31 while a key decrypts: K1 protected with 200 bcrypt
/// rounds (`edit` picks its agent), and `end` (a lock or the turn-off; it
/// gets the system agent's socket) lands 300 ms after the unlock, while App decrypts it. The test then
/// decrypts the same key itself, which ends after App's own decryption, and
/// waits 0.5 s more for an add that should not come.
fn end_while_decrypting(
    tag: &str,
    edit: impl FnOnce(&mut Settings),
    end: impl FnOnce(&Session, u64, &Path),
) -> (Dir, Throwaway, Arc<Session>) {
    let dir = Dir::new(tag);
    keys(&dir);
    let rounds = ["-q", "-p", "-P", PASS, "-N", PASS, "-a", "200", "-f", "k1e"];
    assert!(run(tool("ssh-keygen", &dir.0).args(rounds)));
    let slow = std::fs::read(dir.join("k1e")).unwrap();
    let system = Throwaway::start();
    let path = vault_file(&dir, vec![ssh_entry(1, E1, PASS, slow.clone(), edit)]);
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    let id = unlock(&session, &path);
    thread::sleep(Duration::from_millis(300));
    end(&session, id, system.agent.path());
    let t0 = Instant::now();
    SshKey::read(&slow)
        .unwrap()
        .unlock(&common::pass(PASS))
        .unwrap();
    assert!(
        t0.elapsed() > Duration::from_millis(600),
        "the key decrypts too fast to land the lock inside: {:?}",
        t0.elapsed()
    );
    thread::sleep(Duration::from_millis(500));
    (dir, system, session)
}

/// The number of keys App's own agent lists (request 11).
fn own_count(dir: &Dir) -> u32 {
    let mut stream = UnixStream::connect(dir.join("App/agent.sock")).unwrap();
    let reply = call(&mut stream, &[11]);
    assert_eq!(reply[0], 12);
    u32::from_be_bytes(reply[1..5].try_into().unwrap())
}

#[test]
fn int06_24_at_h01_a_lock_during_decryption_adds_nothing_to_the_system_agent() {
    let _t = timed();
    let (_dir, system, _session) = end_while_decrypting(
        "ds",
        |s| s.remove_at_close = true,
        |session, id, _| session.lock(id).unwrap(),
    );
    assert!(system.blobs().is_empty(), "AT-H01: added after the lock");
}

#[test]
fn int06_31_a_lock_during_decryption_adds_nothing_to_apps_agent() {
    let _t = timed();
    let (dir, _system, _session) = end_while_decrypting(
        "do",
        |s| s.confirm = true,
        |session, id, _| session.lock(id).unwrap(),
    );
    assert_eq!(own_count(&dir), 0, "AT-C01: a key of a locked vault");
}

#[test]
fn int06_26_turning_off_during_decryption_adds_nothing() {
    let _t = timed();
    let (_dir, system, _session) = end_while_decrypting(
        "dt",
        |_| {},
        |session, _, agent| {
            // The throwaway stays named, so a late add would reach it.
            let agent = agent.to_string_lossy().into_owned();
            session.set_ssh_agent(false, agent, String::new()).unwrap();
        },
    );
    assert!(system.blobs().is_empty(), "added after the turn-off");
}

/// LD-207: three entries whose Title is protected by its own flag (`own`)
/// or by the vault's flag (a saved vault marks the field too, so the flag
/// alone is tested on a vault in memory in app-sshagent): one whose key attachment is missing (MI06-06),
/// one that asks (`ask`, its key and password; App calls the key `name`),
/// and one marked remove-on-lock in the system agent. The failure, MI06-18,
/// the question and MI06-19 carry the mask, never a title.
fn protected_titles(tag: &str, own: bool, edit_keys: impl FnOnce(&Dir)) {
    let mask = app_core::health::MASKED_TITLE;
    let dir = Dir::new(tag);
    keys(&dir);
    edit_keys(&dir);
    let k1e = std::fs::read(dir.join("k1e")).unwrap();
    let k2 = std::fs::read(dir.join("k2")).unwrap();
    let (ask, ask_pass, file, file_pass, name) = if own {
        (k1e, PASS, k2, "", "demo@app".to_owned())
    } else {
        let name = SshKey::read(&k2).unwrap().fingerprint().to_owned();
        (k2, "", k1e, PASS, name)
    };
    let titled = |mut e: Entry, title: &str| {
        let value = SecretString::new(title.to_owned());
        e.set_field(
            "Title".into(),
            Field {
                value,
                protected: own,
            },
        );
        e
    };
    let entries = vec![
        titled(
            ssh_entry(1, E1, "", b"x".to_vec(), |s| {
                s.attachment_name = "missing".into()
            }),
            "Secret bad title",
        ),
        titled(
            ssh_entry(2, E1, ask_pass, ask.clone(), |s| s.confirm = true),
            "Secret ask title",
        ),
        titled(
            ssh_entry(3, E1, file_pass, file, |s| s.remove_at_close = true),
            "Secret file title",
        ),
    ];
    let path = vault_file_with(&dir, entries, |v| v.meta.memory_protection.title = !own);
    let mut system = Throwaway::start();
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    let id = unlock(&session, &path);
    session.ssh_settled();
    let failures = session.take_ssh_failures();
    assert_eq!(
        failures,
        [SshFailure {
            title: mask.into(),
            id: "MI06-06".into(),
            message: format!("“{mask}” has no attachment named missing."),
        }]
    );
    let loaded = session.take_banner().unwrap_or_default();
    assert_eq!(loaded, format!("Some SSH keys were not loaded: {mask}."));
    let reply = sign_later(&dir, &blob(&ask));
    let q = question(&session);
    assert_eq!(q.heading, format!("Allow a program to use “{name}”?"));
    session.answer_ssh_question(q.id, false);
    assert_eq!(reply.join().unwrap(), [5]);
    // The system agent stops (by its PID), so the marked key can't leave.
    system.child.kill().unwrap();
    system.child.wait().unwrap();
    session.lock(id).unwrap();
    session.ssh_settled();
    let not_removed = session.take_banner().unwrap_or_default();
    assert_eq!(
        not_removed,
        format!(
            "App couldn't take the key of “{mask}” out of the SSH agent. Use Remove All Keys \
             from SSH Agent… to clear it."
        )
    );
    let seen = format!("{failures:?} {loaded} {q:?} {not_removed}");
    assert!(!seen.contains("Secret"), "{seen}");
}

#[test]
fn ld207_a_title_protected_by_its_own_flag_never_reaches_the_window() {
    let _t = timed();
    protected_titles("pf", true, |_| {});
}

#[test]
fn ld207_a_vault_saved_with_the_title_flag_never_shows_a_title() {
    let _t = timed();
    // K2 without a comment: the question names it by its fingerprint.
    protected_titles("pv", false, |dir| {
        let args = ["-q", "-c", "-C", "", "-P", "", "-f", "k2"];
        assert!(run(tool("ssh-keygen", &dir.0).args(args)));
    });
}

#[test]
fn mod13_8_a_forced_key_change_adds_no_key_until_the_key_is_changed() {
    let _t = timed();
    let dir = Dir::new("k");
    let (_, k2) = keys(&dir);
    let system = Throwaway::start();
    let entries = vec![ssh_entry(2, "File key", "", k2.clone(), |_| {})];
    let path = vault_file_with(&dir, entries, |v| {
        v.meta.master_key_change_force_once = true;
    });
    let session = session(&dir, system.agent.path(), Duration::from_secs(60));
    let id = unlock(&session, &path);
    session.ssh_settled();
    assert!(system.blobs().is_empty(), "no key behind the forced prompt");
    // Change now (MOD-12.10), then the prompt ends: the held-back keys go.
    let vs = app_ffi::vault_settings::VaultSettings::new(Arc::clone(&session), id);
    vs.set_password("orchid-meteor-pine-quartz-41".into())
        .unwrap();
    vs.set_repeat("orchid-meteor-pine-quartz-41".into())
        .unwrap();
    assert_eq!(
        vs.change_password(vec![]).unwrap(),
        app_ffi::wizard::Outcome::Done
    );
    assert!(session.end_key_change(id).unwrap());
    session.ssh_settled();
    assert_eq!(system.blobs(), [blob(&k2)]);
}
