//! Shared by the E9-S1 and E9-S2 tests: demo keys made by `ssh-keygen` in
//! `CARGO_TARGET_TMPDIR`, throwaway `ssh-agent` processes and fake agents
//! in /tmp. Never the user's own agent: every child process runs with a
//! cleared environment and, where it needs one, the throwaway's own
//! SSH_AUTH_SOCK; each throwaway is stopped by its PID; each folder is
//! removed on drop.
#![allow(dead_code, unused_imports)]

use app_crypto::base64::{Form, decode, encode};
use app_crypto::secret::SecretString;
use app_sshagent::messages::{Names, text};
use app_sshagent::{Agent, AgentKey, Error, Failure, Identity, Limits, SshKey};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// Demo key K1 of spec INT-06 (Ed25519, comment `demo@app`).
pub const K1: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAXBQ6tk+9cBEQnipP+gWQhhyC3TUJgLfuhlQjm1wPZhgAAAJCFFnN8hRZz
fAAAAAtzc2gtZWQyNTUxOQAAACAXBQ6tk+9cBEQnipP+gWQhhyC3TUJgLfuhlQjm1wPZhg
AAAEBFcbeDr4WGNkaX3X0F79RKibjugiw6qJhq2wgi7SoGGRcFDq2T71wERCeKk/6BZCGH
ILdNQmAt+6GVCObXA9mGAAAACGRlbW9AYXBwAQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";
pub const K1_FINGERPRINT: &str = "SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc";
pub const K1_PUBLIC: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcFDq2T71wERCeKk/6BZCGHILdNQmAt+6GVCObXA9mG";
pub const PASS: &str = "demo-ssh-pass";

/// Demo key K2s (P-256, comment `short@app`), made by `ssh-keygen`: the top
/// byte of its private scalar is zero, so OpenSSH stores the scalar in 31
/// bytes, as for 1 key in 256 (LD-209).
pub const K2S: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTJroutY9wcZUix/lhCLHB86AgBHnaA
vNsb+txHkP0upLnOumiXjGgv3AW75MBsAj25lYY6+LXXADVVaL7DI8CsAAAAoN6jeTbeo3
k2AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMmui61j3BxlSLH+
WEIscHzoCAEedoC82xv63EeQ/S6kuc66aJeMaC/cBbvkwGwCPbmVhjr4tdcANVVovsMjwK
wAAAAfBPS1Z0fXWWsotfZ05VcehQ/LotNv3l3dy9KNR0bC1AAAAAlzaG9ydEBhcHA=
-----END OPENSSH PRIVATE KEY-----
";
pub const K2S_PUBLIC: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMmui61j3BxlSLH+WEIscHzoCAEedoC82xv63EeQ/S6kuc66aJeMaC/cBbvkwGwCPbmVhjr4tdcANVVovsMjwKw=";
pub const K2S_FINGERPRINT: &str = "SHA256:vXGUUx/sN5T+6ungd/WFFzqfzKz2hdoUmRGTT8x4+u8";

// ---------------------------------------------------------------- helpers

/// One test's folder in /tmp (socket paths stay short), removed on drop.
pub struct Dir(pub PathBuf);

impl Dir {
    pub fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(format!("/tmp/e9s1-{}-{tag}{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Tests whose timing another test's long request would upset (a 2 s
/// silent agent, 1 s slow replies, a 2 s lifetime, the 1 s remove) run one
/// at a time: the product's one-request lock spans the whole process.
pub fn timed() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A tool from /usr/bin with a cleared environment (no SSH_AUTH_SOCK of
/// the user, no askpass, no display) and HOME in `dir`.
pub fn tool(name: &str, dir: &Path) -> Command {
    let mut cmd = Command::new(format!("/usr/bin/{name}"));
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .current_dir(dir)
        .stdin(Stdio::null());
    cmd
}

pub fn run(cmd: &mut Command) -> bool {
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

pub fn pass(text: &str) -> SecretString {
    SecretString::new(text.to_owned())
}

/// SSH `string`.
pub fn s(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

/// Demo keys, made once per test run in `CARGO_TARGET_TMPDIR`.
pub struct Keys(pub PathBuf);

impl Keys {
    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    pub fn bytes(&self, name: &str) -> Vec<u8> {
        fs::read(self.path(name)).unwrap()
    }
    pub fn key(&self, name: &str) -> SshKey {
        SshKey::read(&self.bytes(name)).unwrap()
    }
}

pub fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sshagent-keys");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let write_k1 = |name: &str| {
            fs::write(dir.join(name), K1).unwrap();
            fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        };
        let keygen = |args: &[&str]| assert!(run(tool("ssh-keygen", &dir).args(args)), "{args:?}");
        write_k1("k1");
        // K2s and K2se: K2s protected with ssh-keygen's defaults.
        for name in ["k2s", "k2se"] {
            fs::write(dir.join(name), K2S).unwrap();
            fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(dir.join("k2s.pub"), format!("{K2S_PUBLIC} short@app\n")).unwrap();
        keygen(&["-q", "-p", "-P", "", "-N", PASS, "-f", "k2se"]);
        fs::write(dir.join("k1.pub"), format!("{K1_PUBLIC} demo@app\n")).unwrap();
        // K1e: K1 protected with ssh-keygen's defaults (aes256-ctr, bcrypt).
        write_k1("k1e");
        keygen(&["-q", "-p", "-P", "", "-N", PASS, "-f", "k1e"]);
        for (name, cipher) in [
            ("k1gcm", "aes256-gcm@openssh.com"),
            ("k1chacha", "chacha20-poly1305@openssh.com"),
            ("k1cbc", "aes128-cbc"),
            ("k13des", "3des-cbc"),
        ] {
            write_k1(name);
            keygen(&["-q", "-p", "-P", "", "-N", PASS, "-Z", cipher, "-f", name]);
        }
        let new = |args: &[&str]| keygen(&[&["-q"], args].concat());
        new(&[
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
        new(&[
            "-t",
            "ecdsa",
            "-b",
            "256",
            "-N",
            PASS,
            "-C",
            "ecdsa2@app",
            "-f",
            "k2e",
        ]);
        new(&[
            "-t", "ecdsa", "-b", "384", "-N", "", "-C", "p384@app", "-f", "k384",
        ]);
        new(&[
            "-t", "ecdsa", "-b", "521", "-N", "", "-C", "p521@app", "-f", "k521",
        ]);
        new(&[
            "-t", "rsa", "-b", "3072", "-N", "", "-C", "rsa@app", "-f", "kr",
        ]);
        new(&[
            "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", PASS, "-f", "kp",
        ]);
        new(&[
            "-t", "ecdsa", "-b", "256", "-m", "PKCS8", "-N", "", "-f", "k8",
        ]);
        // K1big: K1e with its stored round count set to 1001. Same file
        // otherwise; `ssh-keygen -a 1001` would spend 8 s making it.
        let k1e = fs::read_to_string(dir.join("k1e")).unwrap();
        let body: String = k1e.lines().filter(|l| !l.starts_with("-----")).collect();
        let mut raw = decode(Form::Padded, body).unwrap();
        // magic(15) "aes256-ctr"(4+10) "bcrypt"(4+6) opts len(4) salt(4+16).
        assert_eq!(&raw[63..67], &24u32.to_be_bytes());
        raw[63..67].copy_from_slice(&1001u32.to_be_bytes());
        fs::write(dir.join("k1big"), pem(&raw)).unwrap();
        Keys(dir)
    })
}

pub fn pem(raw: &[u8]) -> String {
    let b64 = encode(Form::Padded, raw);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(70)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        lines.join("\n")
    )
}

/// An unprotected OpenSSH key file built by hand, for the types
/// `ssh-keygen` here cannot make (DSA, security keys).
pub fn hand_built(public: &[u8], fields: &[u8], comment: &str) -> Vec<u8> {
    let mut private = [
        &[0, 0, 0, 7, 0, 0, 0, 7][..],
        fields,
        &s(comment.as_bytes()),
    ]
    .concat();
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }
    let raw = [
        &b"openssh-key-v1\0"[..],
        &s(b"none"),
        &s(b"none"),
        &s(b""),
        &1u32.to_be_bytes(),
        &s(public),
        &s(&private),
    ]
    .concat();
    pem(&raw).into_bytes()
}

pub fn dsa_key() -> Vec<u8> {
    let public = [
        s(b"ssh-dss"),
        s(&[0x17]),
        s(&[0x0b]),
        s(&[0x02]),
        s(&[0x05]),
    ]
    .concat();
    hand_built(&public, &[public.clone(), s(&[0x03])].concat(), "dsa@app")
}

pub const SK_ED: &[u8] = b"sk-ssh-ed25519@openssh.com";
pub const SK_EC: &[u8] = b"sk-ecdsa-sha2-nistp256@openssh.com";

pub fn sk_ed25519() -> Vec<u8> {
    let k1 = SshKey::read(K1.as_bytes()).unwrap();
    let pk = &k1.public_blob()[19..51];
    let public = [s(SK_ED), s(pk), s(b"ssh:")].concat();
    let fields = [public.clone(), vec![1], s(b"demo-handle"), s(b"")].concat();
    hand_built(&public, &fields, "sk@app")
}

pub fn sk_ecdsa() -> Vec<u8> {
    let k2 = keys().key("k2");
    let point = &k2.public_blob()[39..104];
    let public = [s(SK_EC), s(b"nistp256"), s(point), s(b"ssh:")].concat();
    let fields = [public.clone(), vec![1], s(b"demo-handle"), s(b"")].concat();
    hand_built(&public, &fields, "sk-ec@app")
}

pub fn k1_unlocked() -> AgentKey {
    SshKey::read(K1.as_bytes())
        .unwrap()
        .unlock(&pass(""))
        .unwrap()
}

/// Waits until `agent` answers a list request (F-109): `ssh-agent` makes
/// its socket file at bind(), before listen(), so the file alone is not
/// enough under load.
pub fn answers(agent: &Agent) {
    let t0 = Instant::now();
    while agent.list().is_err() {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "agent did not start"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// A throwaway OpenSSH agent in its own /tmp folder, in the foreground
/// (`-D`), so the PID we hold is the agent's. Stopped by that PID on drop.
pub struct Throwaway {
    pub child: Child,
    pub dir: Dir,
    pub agent: Agent,
}

impl Throwaway {
    pub fn start() -> Self {
        let dir = Dir::new("a");
        let sock = dir.join("s");
        let child = tool("ssh-agent", &dir.0)
            .args(["-D", "-a"])
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let agent = Agent::at(&sock);
        answers(&agent);
        Self { child, dir, agent }
    }

    pub fn tool(&self, name: &str) -> Command {
        let mut cmd = tool(name, &self.dir.0);
        cmd.env("SSH_AUTH_SOCK", self.agent.path());
        cmd
    }

    pub fn blobs(&self) -> Vec<Vec<u8>> {
        self.agent
            .list()
            .unwrap()
            .into_iter()
            .map(|i| i.blob)
            .collect()
    }
}

impl Drop for Throwaway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Then `dir` drops and removes the folder.
    }
}

/// A hung agent at `path`: it accepts every connection, reads nothing and
/// never answers; it counts the connections. Stopped on drop.
pub struct Silent {
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
}

pub fn silent(path: &Path) -> Silent {
    let listener = UnixListener::bind(path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (seen, end) = (Arc::clone(&count), Arc::clone(&stop));
    let server = thread::spawn(move || {
        let mut held = Vec::new();
        while !end.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    seen.fetch_add(1, Ordering::SeqCst);
                    held.push(stream);
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    Silent {
        count,
        stop,
        server: Some(server),
    }
}

impl Silent {
    pub fn connections(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Drop for Silent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

pub fn read_msg(stream: &mut UnixStream) -> Vec<u8> {
    let mut len = [0; 4];
    stream.read_exact(&mut len).unwrap();
    let mut msg = vec![0; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut msg).unwrap();
    msg
}

/// A fake agent: answers each connection with the next scripted reply (raw
/// bytes, so it can be malformed) and returns the requests it read. It also
/// checks INT-06.12: after one reply the client closes and sends nothing more.
pub fn fake(replies: Vec<Vec<u8>>) -> Fake {
    let dir = Dir::new("f");
    let path = dir.join("s");
    let listener = UnixListener::bind(&path).unwrap();
    let server = thread::spawn(move || {
        let mut seen = Vec::new();
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            seen.push(read_msg(&mut stream));
            if reply.is_empty() {
                continue; // closes without a reply
            }
            let _ = stream.write_all(&reply);
            let mut more = Vec::new();
            let _ = stream.read_to_end(&mut more);
            assert!(more.is_empty(), "a second message on one connection");
        }
        seen
    });
    Fake {
        agent: Agent::at(path),
        server,
        _dir: dir,
    }
}

pub struct Fake {
    pub agent: Agent,
    pub server: thread::JoinHandle<Vec<Vec<u8>>>,
    pub _dir: Dir,
}

impl Fake {
    /// The requests the fake read; its folder goes when this returns.
    pub fn seen(self) -> Vec<Vec<u8>> {
        self.server.join().unwrap()
    }
}

pub const OK: [u8; 5] = [0, 0, 0, 1, 6];

pub fn no_connection(listener: &UnixListener) -> bool {
    listener.set_nonblocking(true).unwrap();
    matches!(listener.accept(), Err(e) if e.kind() == ErrorKind::WouldBlock)
}
