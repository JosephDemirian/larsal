//! E9-S1 against throwaway `ssh-agent` processes and fake agents in /tmp,
//! with demo keys made by `ssh-keygen` in `CARGO_TARGET_TMPDIR`. Never the
//! user's own agent: every child process runs with a cleared environment
//! and, where it needs one, the throwaway's own SSH_AUTH_SOCK; each
//! throwaway is stopped by its PID. Each test's /tmp folder is removed on
//! drop. Test names carry the case IDs of spec INT-06 (T-numbers) or the rule.

mod common;

use app_sshagent::messages::{Names, text};
use app_sshagent::{Agent, Error, Failure, Identity, Limits, SshKey};
use common::*;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------ keys

#[test]
fn t14_size_limits_before_parsing() {
    let big = vec![b'a'; 1_048_577];
    assert_eq!(SshKey::read(&big).unwrap_err(), Error::TooLarge);
    assert_eq!(SshKey::read(b"").unwrap_err(), Error::Empty);
    let names = Names {
        name: "id_big",
        ..Names::default()
    };
    assert_eq!(
        Error::TooLarge.message(&names),
        "id_big is over 1 MiB, so it can't be an SSH key."
    );
}

#[test]
fn t16_old_forms_dsa_and_text_are_refused() {
    let k = keys();
    assert_eq!(SshKey::read(&k.bytes("kp")).unwrap_err(), Error::OldFormat);
    assert_eq!(SshKey::read(&k.bytes("k8")).unwrap_err(), Error::OldFormat);
    let putty = b"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n";
    assert_eq!(SshKey::read(putty).unwrap_err(), Error::OldFormat);
    assert_eq!(SshKey::read(&dsa_key()).unwrap_err(), Error::Dsa);
    assert_eq!(
        SshKey::read(b"just some notes\n").unwrap_err(),
        Error::NotAKey
    );
    let names = Names {
        name: "id_rsa",
        file: "/tmp/id_rsa",
        ..Names::default()
    };
    assert_eq!(
        Error::OldFormat.message(&names),
        "id_rsa uses an older key format. Convert a copy with \"ssh-keygen -p -f /tmp/id_rsa\", then use the converted file."
    );
}

#[test]
fn t17_type_names_and_fingerprints() {
    let k = keys();
    for (file, label) in [
        ("k1", "ED25519"),
        ("k2", "ECDSA"),
        ("kr", "RSA 3072"),
        ("k384", "ECDSA P-384"),
        ("k521", "ECDSA P-521"),
    ] {
        let key = k.key(file);
        assert_eq!(key.type_label(), label);
        // INT-06.7: the fingerprint `ssh-keygen -l` prints.
        let out = tool("ssh-keygen", &k.0)
            .args(["-l", "-E", "sha256", "-f"])
            .arg(k.path(&format!("{file}.pub")))
            .output()
            .unwrap();
        let line = String::from_utf8(out.stdout).unwrap();
        assert_eq!(line.split(' ').nth(1), Some(key.fingerprint()), "{file}");
    }
    assert_eq!(
        SshKey::read(&sk_ed25519()).unwrap().type_label(),
        "ED25519-SK"
    );
    assert_eq!(SshKey::read(&sk_ecdsa()).unwrap().type_label(), "ECDSA-SK");
}

#[test]
fn t18_protected_key_shows_public_parts_without_passphrase() {
    let key = keys().key("k1e");
    assert!(key.is_encrypted());
    assert_eq!(key.type_label(), "ED25519");
    assert_eq!(key.fingerprint(), K1_FINGERPRINT);
    assert_eq!(key.comment(), None);
    assert_eq!(key.public_line(), K1_PUBLIC);
    let plain = SshKey::read(K1.as_bytes()).unwrap();
    assert_eq!(plain.public_line(), format!("{K1_PUBLIC} demo@app"));
    assert_eq!(plain.public_blob(), key.public_blob());
}

#[test]
fn t21_empty_and_wrong_passphrase() {
    let key = keys().key("k1e");
    let t0 = Instant::now();
    assert_eq!(key.unlock(&pass("")).unwrap_err(), Error::NoPassphrase);
    assert!(t0.elapsed() < Duration::from_millis(50), "no KDF ran");
    assert_eq!(
        key.unlock(&pass("wrong-pass")).unwrap_err(),
        Error::WrongPassphrase
    );
}

#[test]
fn t22_rounds_over_1000_refused_before_any_work() {
    let key = keys().key("k1big");
    let t0 = Instant::now();
    let err = key.unlock(&pass(PASS)).unwrap_err();
    assert!(
        t0.elapsed() < Duration::from_millis(50),
        "{:?}",
        t0.elapsed()
    );
    assert_eq!(err, Error::TooManyRounds(1001));
    let names = Names {
        file: "/tmp/k",
        ..Names::default()
    };
    assert!(
        err.message(&names)
            .contains("uses 1001 rounds; App allows at most 1,000")
    );
}

#[test]
fn int06_9_ciphers_ssh_keygen_offers() {
    let k = keys();
    let plain = k1_unlocked();
    for file in ["k1e", "k1gcm", "k1chacha", "k1cbc"] {
        let unlocked = k.key(file).unlock(&pass(PASS)).unwrap();
        assert_eq!(unlocked.fields(), plain.fields(), "{file}");
        assert_eq!(unlocked.comment(), "demo@app");
    }
    assert_eq!(
        k.key("k13des").unlock(&pass(PASS)).unwrap_err(),
        Error::Unsupported("3des-cbc".into())
    );
}

// ------------------------------------------------------- the real agent

#[test]
fn t20_protected_keys_load_and_list() {
    let a = Throwaway::start();
    let k = keys();
    for (file, comment) in [("k1e", "demo@app"), ("k2e", "ecdsa2@app")] {
        let key = k.key(file);
        let unlocked = key.unlock(&pass(PASS)).unwrap();
        a.agent
            .add(&unlocked, unlocked.comment(), &Limits::default())
            .unwrap();
        let want = Identity {
            blob: key.public_blob().to_vec(),
            comment: comment.into(),
        };
        assert!(a.agent.list().unwrap().contains(&want), "{file}");
    }
}

#[test]
fn int06_15_every_type_ssh_keygen_makes_is_taken() {
    let a = Throwaway::start();
    let k = keys();
    for file in ["k1", "k2", "k384", "k521", "kr"] {
        let key = k.key(file);
        let unlocked = key.unlock(&pass("")).unwrap();
        a.agent
            .add(&unlocked, "typed@app", &Limits::default())
            .unwrap();
        assert!(a.blobs().contains(&key.public_blob().to_vec()), "{file}");
    }
    assert_eq!(a.blobs().len(), 5);
}

#[test]
fn t31_lifetime_2s_key_gone_after_3s() {
    let _timed = timed();
    let a = Throwaway::start();
    let limits = Limits {
        lifetime: Some(2),
        ..Limits::default()
    };
    a.agent.add(&k1_unlocked(), "demo@app", &limits).unwrap();
    let blob = SshKey::read(K1.as_bytes()).unwrap().public_blob().to_vec();
    assert_eq!(a.blobs(), vec![blob]);
    thread::sleep(Duration::from_secs(3));
    assert!(a.blobs().is_empty(), "AT-H02: the agent kept the lifetime");
}

#[test]
fn t32_confirm_is_kept_and_refused_without_askpass() {
    // History case of option (a) (LD-173): the client still sends the limit;
    // a stock agent without an askpass helper refuses every signature.
    let a = Throwaway::start();
    let k = keys();
    let confirm = Limits {
        confirm: true,
        ..Limits::default()
    };
    a.agent.add(&k1_unlocked(), "demo@app", &confirm).unwrap();
    let k2 = k.key("k2").unlock(&pass("")).unwrap();
    a.agent.add(&k2, "ecdsa@app", &Limits::default()).unwrap();
    // Only public keys in the signing folder, so ssh-keygen must use the agent.
    fs::write(a.dir.join("data"), b"demo data").unwrap();
    fs::copy(k.path("k1.pub"), a.dir.join("k1.pub")).unwrap();
    fs::copy(k.path("k2.pub"), a.dir.join("k2.pub")).unwrap();
    let sign = |pub_file: &str| {
        run(a
            .tool("ssh-keygen")
            .args(["-Y", "sign", "-n", "file", "-f", pub_file, "data"]))
    };
    assert!(!sign("k1.pub"), "AT-H02: confirm reached the agent");
    assert!(sign("k2.pub"), "control: a key without confirm signs");
    // INT-06.16: adding K1 again without confirm takes the limit away.
    a.agent
        .add(&k1_unlocked(), "demo@app", &Limits::default())
        .unwrap();
    assert!(sign("k1.pub"), "control: K1 without confirm signs");
}

#[test]
fn t33_add_again_replaces_limits() {
    let _timed = timed();
    let a = Throwaway::start();
    let key = k1_unlocked();
    let limits = Limits {
        lifetime: Some(2),
        ..Limits::default()
    };
    a.agent.add(&key, "demo@app", &limits).unwrap();
    a.agent.add(&key, "demo@app", &Limits::default()).unwrap();
    thread::sleep(Duration::from_secs(3));
    assert_eq!(
        a.blobs().len(),
        1,
        "the second add took the time limit away"
    );
}

#[test]
fn t34_remove_absent_key_is_not_an_error() {
    let a = Throwaway::start();
    let blob = SshKey::read(K1.as_bytes()).unwrap().public_blob().to_vec();
    assert_eq!(a.agent.remove(&blob), Ok(false));
}

#[test]
fn at_h01_remove_leaves_agent_within_1s() {
    let _timed = timed();
    let a = Throwaway::start();
    let blob = SshKey::read(K1.as_bytes()).unwrap().public_blob().to_vec();
    a.agent
        .add(&k1_unlocked(), "demo@app", &Limits::default())
        .unwrap();
    let t0 = Instant::now();
    assert_eq!(a.agent.remove(&blob), Ok(true));
    assert!(a.blobs().is_empty());
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
}

#[test]
fn t35_remove_all_one_message_19_and_agent_empty() {
    let f = fake(vec![OK.to_vec()]);
    f.agent.remove_all().unwrap();
    assert_eq!(f.seen(), vec![vec![19]], "message 19 only");

    let a = Throwaway::start();
    a.agent
        .add(&k1_unlocked(), "demo@app", &Limits::default())
        .unwrap();
    assert!(run(a.tool("ssh-add").arg(keys().path("k2"))));
    assert_eq!(a.blobs().len(), 2);
    a.agent.remove_all().unwrap();
    assert!(a.blobs().is_empty());
    assert_eq!(
        text("MI06-20"),
        Some("Every key was removed from the SSH agent.")
    );
}

// ------------------------------------------------------- fake agents

#[test]
fn t25_no_agent_set() {
    let err = Agent::choose("", None).unwrap_err();
    assert_eq!(err, Error::NoAgent);
    assert!(
        err.message(&Names::default())
            .starts_with("No SSH agent was found.")
    );
}

#[test]
fn t26_not_a_socket_of_ours_nothing_written() {
    let dir = Dir::new("t26");
    let file = dir.join("file");
    fs::write(&file, b"x").unwrap();
    let not_ours = |p: &Path| Error::NotOurSocket {
        path: p.to_path_buf(),
    };
    assert_eq!(Agent::at(&file).list(), Err(not_ours(&file)));
    assert_eq!(fs::read(&file).unwrap(), b"x");

    let target = dir.join("real");
    let listener = UnixListener::bind(&target).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(Agent::at(&link).list(), Err(not_ours(&link)));
    assert!(no_connection(&listener), "nothing reached the socket");

    let long = PathBuf::from(format!("/tmp/{}", "x".repeat(99)));
    assert_eq!(long.as_os_str().len(), 104);
    assert_eq!(Agent::at(&long).list(), Err(not_ours(&long)));

    // LD-183 (1): a missing socket is MI06-03 too, and nothing is made there.
    for missing in [dir.join("missing"), dir.join("no-folder/s")] {
        let err = Agent::at(&missing).list().unwrap_err();
        assert_eq!(err, not_ours(&missing));
        assert_eq!(err.id(), "MI06-03");
        assert!(!missing.exists());
    }
}

#[test]
fn t27_silent_oversize_unknown_and_closed_replies() {
    let _timed = timed();
    // Silent: accepts and never answers.
    let dir = Dir::new("t27");
    let path = dir.join("s");
    let listener = UnixListener::bind(&path).unwrap();
    let hold = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(3));
        drop(stream);
    });
    let t0 = Instant::now();
    let err = Agent::at(&path).add(&k1_unlocked(), "demo@app", &Limits::default());
    let took = t0.elapsed();
    assert_eq!(
        err,
        Err(Error::Unreachable {
            path,
            why: Failure::Timeout
        })
    );
    assert!(
        took >= Duration::from_millis(1900) && took < Duration::from_millis(2600),
        "{took:?}"
    );
    hold.join().unwrap();

    // A 300 KiB reply, byte 99, and a connection closed without a reply.
    let big = [&(300u32 * 1024).to_be_bytes()[..], &[12; 64]].concat();
    for (reply, why) in [
        (big, Failure::TooLong),
        (vec![0, 0, 0, 1, 99], Failure::Protocol),
        (vec![], Failure::Closed),
        (vec![0, 0, 0, 0], Failure::Protocol),
    ] {
        let f = fake(vec![reply]);
        let err = f
            .agent
            .add(&k1_unlocked(), "demo@app", &Limits::default())
            .unwrap_err();
        assert_eq!(
            err,
            Error::Unreachable {
                path: f.agent.path().into(),
                why
            }
        );
        assert_eq!(err.id(), "MI06-02");
        f.seen();
    }
}

#[test]
fn t28_lifetime_bytes_after_the_comment() {
    let f = fake(vec![OK.to_vec(), OK.to_vec()]);
    let limits = Limits {
        lifetime: Some(120),
        ..Limits::default()
    };
    f.agent.add(&k1_unlocked(), "demo@app", &limits).unwrap();
    // T33's other half: an add without limits is message 17.
    f.agent
        .add(&k1_unlocked(), "demo@app", &Limits::default())
        .unwrap();
    let seen = f.seen();
    let comment = s(b"demo@app");
    assert_eq!(seen[0][0], 25);
    assert!(seen[0].ends_with(&[&comment[..], &[1, 0, 0, 0, 0x78]].concat()));
    assert_eq!(seen[1][0], 17);
    assert!(seen[1].ends_with(&comment));
    // The body is the key's type and fields, as INT-06.15's table.
    assert!(seen[1][1..].starts_with(k1_unlocked().fields().expose()));
}

#[test]
fn t29_confirm_after_lifetime() {
    let f = fake(vec![OK.to_vec()]);
    let limits = Limits {
        lifetime: Some(120),
        confirm: true,
        ..Limits::default()
    };
    f.agent.add(&k1_unlocked(), "demo@app", &limits).unwrap();
    let seen = f.seen();
    assert_eq!(seen[0][0], 25);
    assert!(seen[0].ends_with(&[&s(b"demo@app")[..], &[1, 0, 0, 0, 0x78, 2]].concat()));
}

#[test]
fn t30_security_key_provider_extension() {
    let f = fake(vec![OK.to_vec(), OK.to_vec(), vec![0, 0, 0, 1, 5]]);
    let agent = &f.agent;
    let key = SshKey::read(&sk_ed25519())
        .unwrap()
        .unlock(&pass(""))
        .unwrap();
    agent.add(&key, "sk@app", &Limits::default()).unwrap();
    let chosen = Limits {
        sk_provider: Some("/tmp/libsk.dylib".into()),
        ..Limits::default()
    };
    agent.add(&key, "sk@app", &chosen).unwrap();
    let refused = agent.add(
        &key,
        "sk@app",
        &Limits {
            lifetime: Some(60),
            ..Limits::default()
        },
    );
    assert_eq!(
        refused,
        Err(Error::AddRefused {
            lifetime: true,
            security_key: true
        })
    );
    let seen = f.seen();
    let ext =
        |provider: &[u8]| [&[255u8][..], &s(b"sk-provider@openssh.com"), &s(provider)].concat();
    assert_eq!(seen[0][0], 25);
    assert!(seen[0].ends_with(&ext(b"internal")));
    assert!(seen[1].ends_with(&ext(b"/tmp/libsk.dylib")));
    // The sk- body: type, public key, application, flags, handle, reserved.
    assert!(seen[0][1..].starts_with(&s(SK_ED)));
}

#[test]
fn t36_count_that_cannot_fit() {
    let f = fake(vec![vec![0, 0, 0, 9, 12, 0, 0x0f, 0x42, 0x40, 0, 0, 0, 0]]);
    assert_eq!(
        f.agent.list(),
        Err(Error::Unreachable {
            path: f.agent.path().into(),
            why: Failure::Protocol
        })
    );
    f.seen();
}

#[test]
fn t37_lifetime_0_refused_nothing_sent() {
    let dir = Dir::new("t37");
    let path = dir.join("s");
    let listener = UnixListener::bind(&path).unwrap();
    let agent = Agent::at(&path);
    for seconds in [0, 1_000_000_000] {
        let limits = Limits {
            lifetime: Some(seconds),
            ..Limits::default()
        };
        assert_eq!(
            agent.add(&k1_unlocked(), "demo@app", &limits),
            Err(Error::Lifetime)
        );
    }
    assert!(no_connection(&listener));
    assert_eq!(
        Error::Lifetime.message(&Names::default()),
        "The time limit must be at least 1 minute."
    );
}

#[test]
fn t68_one_request_at_a_time_one_message_per_connection() {
    let _timed = timed();
    let dir = Dir::new("t68");
    let path = dir.join("s");
    let listener = UnixListener::bind(&path).unwrap();
    let server = thread::spawn(move || {
        let mut log = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let msg = read_msg(&mut stream);
            // Answer slowly; meanwhile no second connection may arrive.
            listener.set_nonblocking(true).unwrap();
            let t0 = Instant::now();
            let mut early = false;
            while t0.elapsed() < Duration::from_secs(1) {
                early |= listener.accept().is_ok();
                thread::sleep(Duration::from_millis(10));
            }
            listener.set_nonblocking(false).unwrap();
            stream.write_all(&OK).unwrap();
            let mut more = Vec::new();
            stream.read_to_end(&mut more).unwrap();
            log.push((msg[0], early, more.len()));
        }
        log
    });
    let agent = Agent::at(&path);
    let adder = {
        let agent = agent.clone();
        let key = k1_unlocked();
        thread::spawn(move || agent.add(&key, "demo@app", &Limits::default()))
    };
    thread::sleep(Duration::from_millis(100));
    let blob = SshKey::read(K1.as_bytes()).unwrap().public_blob().to_vec();
    assert_eq!(agent.remove(&blob), Ok(true));
    assert_eq!(adder.join().unwrap(), Ok(()));
    let mut log = server.join().unwrap();
    log.sort();
    assert_eq!(log, vec![(17, false, 0), (18, false, 0)]);
}

/// F-109: the throwaway helper returns only once the agent answers. A
/// socket file nobody listens on yet (`ssh-agent` makes it at bind(),
/// before listen()) refuses the connect; the agent comes 300 ms later.
#[test]
fn f_109_the_throwaway_helper_waits_until_the_agent_answers() {
    let dir = Dir::new("f109");
    let path = dir.join("s");
    drop(UnixListener::bind(&path).unwrap());
    let later = path.clone();
    let server = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        fs::remove_file(&later).unwrap();
        let listener = UnixListener::bind(&later).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let msg = read_msg(&mut stream);
        // No keys (message 12, count 0).
        stream.write_all(&[0, 0, 0, 5, 12, 0, 0, 0, 0]).unwrap();
        let _ = stream.read_to_end(&mut Vec::new());
        msg[0]
    });
    let t0 = Instant::now();
    answers(&Agent::at(&path));
    assert!(
        t0.elapsed() >= Duration::from_millis(250),
        "returned before the agent listened: {:?}",
        t0.elapsed()
    );
    assert_eq!(server.join().unwrap(), 11, "one list request answered");
}
