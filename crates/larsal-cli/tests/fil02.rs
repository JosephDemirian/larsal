//! E22-S5: `larsal encrypt` and `larsal decrypt` (FIL-02.18 to FIL-02.21, and
//! the FIL-02 and FIL-03 rows that name the command line), run on the built
//! `larsal` binary in a temp folder per case, with demo data only. Every test
//! name carries the row it proves. "pty" cases run `larsal` under `script(1)`,
//! which gives it a pseudo-terminal; signals go only to the `larsal` process
//! this test started, by its PID.
//!
//! The story's first check, a file made by the Mac app opens with `larsal
//! decrypt` and the other way round, is proven here at the format level
//! (lead's ruling 2): files made by larsal-files' own encrypt, the code the
//! app calls, open with `larsal decrypt`, and files made by `larsal encrypt`
//! open with larsal-files' decrypt, byte for byte, in both modes. The app's
//! own path, larsal-ffi's files bridge (E22-S4), is
//! `e22s5_check1_app_path_round_trip_after_e22s4`.

use larsal_crypto::secret::SecretString;
use larsal_files::{
    Identities, Lock, OutputFolder, Recipient, ScratchRoot, SourceFile, Unlock, Validation,
};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const APP: &str = env!("CARGO_BIN_EXE_larsal");

const DECRYPT_MSG: &str =
    "larsal: This file could not be decrypted. Check the passphrase or file key and try again.\n";
const EXISTS_MSG: &str = "larsal: A file already exists with this name. Choose a different name.\n";
const PASSPHRASE_MSG: &str = "larsal: Enter a passphrase within the allowed size.\n";
const CANCELLED_MSG: &str = "larsal: The file operation was cancelled.";

/// A demo passphrase above FEA-05's Excellent (about 124 bits), so encrypt
/// does not ask about its strength (FIL-01.7).
const STRONG: &str = "Demo-7Hq#v2Lr9!xWm4Tz@p8";
const WEAK_WARNING: &str = "This passphrase may be easy to guess. Anyone with the encrypted file can test guesses offline, with no limit on tries.";
const USE_ANYWAY: &str = "Use this passphrase anyway? [y/N] ";

// ---------------------------------------------------------------------------
// Harness.

/// A temp folder per case, with a private `tmp/` that `larsal` gets as its
/// TMPDIR, a `home/`, and a copy of the rich-v3 demo vault as `w.larsalvault`.
struct Dir(PathBuf);

impl Dir {
    fn new(case: &str) -> Dir {
        // LD-180: a runner started in the background passes SIGINT and SIGQUIT
        // on ignored, and `larsal` leaves ignored signals alone (LD-178).
        static RESET: std::sync::Once = std::sync::Once::new();
        RESET.call_once(larsal_platform::macos::reset_quit_signals_for_tests);
        let dir =
            std::env::temp_dir().join(format!("larsal-cli-fil02-{}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("home")).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.join("tmp"))
            .unwrap();
        let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
        std::fs::copy(data.join("rich-v3.larsalvault"), dir.join("w.larsalvault")).unwrap();
        Dir(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn put(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn command(&self, program: &str) -> Command {
        let mut c = Command::new(program);
        c.current_dir(&self.0)
            .env_clear()
            .env("HOME", self.path("home"))
            .env("CFFIXED_USER_HOME", self.path("home"))
            .env("TMPDIR", self.path("tmp"))
            .env("PATH", "/usr/bin:/bin");
        c
    }

    fn run(&self, args: &[&str], input: &[u8]) -> Out {
        self.run_env(args, input, &[])
    }

    fn run_env(&self, args: &[&str], input: &[u8], env: &[(&str, &str)]) -> Out {
        let mut c = self.command(APP);
        c.args(args).envs(env.iter().copied());
        finish(c, input)
    }

    /// `larsal` started by `/bin/sh -c`, for limits and redirections.
    fn sh(&self, script: &str, input: &[u8]) -> Out {
        let mut c = self.command("/bin/sh");
        c.args(["-c", script, APP]);
        finish(c, input)
    }

    /// Runs `script` under `/bin/sh -c` on a pseudo-terminal.
    fn pty(&self, script: &str) -> Pty {
        let mut child = self
            .command("/usr/bin/script")
            .args(["-q", "/dev/null", "/bin/sh", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let out = collect(child.stdout.take().unwrap());
        Pty {
            stdin: child.stdin.take(),
            child,
            out,
        }
    }

    /// Nothing of a decrypt is left in `larsal`'s TMPDIR.
    fn scratch_left(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.path("tmp"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Out {
    code: Option<i32>,
    signal: Option<i32>,
    out: String,
    err: String,
}

fn finish(mut c: Command, input: &[u8]) -> Out {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let bytes = input.to_vec();
    let writer = thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
    });
    let o = child.wait_with_output().unwrap();
    writer.join().unwrap();
    Out {
        code: o.status.code(),
        signal: o.status.signal(),
        out: String::from_utf8_lossy(&o.stdout).into_owned(),
        err: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn collect(mut r: impl Read + Send + 'static) -> Arc<Mutex<Vec<u8>>> {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let b = Arc::clone(&buf);
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = r.read(&mut chunk) {
            if n == 0 {
                break;
            }
            b.lock().unwrap().extend_from_slice(&chunk[..n]);
        }
    });
    buf
}

fn text(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&buf.lock().unwrap()).replace("\r\n", "\n")
}

struct Pty {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<Vec<u8>>>,
}

impl Pty {
    fn wait_for(&self, needle: &str) {
        self.wait_within(needle, Duration::from_secs(120));
    }

    fn wait_within(&self, needle: &str, limit: Duration) {
        let deadline = Instant::now() + limit;
        while !text(&self.out).contains(needle) {
            assert!(
                Instant::now() < deadline,
                "waited for {needle:?}, got {:?}",
                text(&self.out)
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Types `s` after a pause, so a prompt has turned echo off first.
    fn send(&mut self, s: &str) {
        thread::sleep(Duration::from_millis(400));
        let w = self.stdin.as_mut().unwrap();
        w.write_all(s.as_bytes()).unwrap();
        w.flush().unwrap();
    }

    fn finish(mut self) -> String {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(120);
        while self.child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("script did not end");
            }
            thread::sleep(Duration::from_millis(20));
        }
        thread::sleep(Duration::from_millis(50));
        text(&self.out)
    }

    /// The `larsal` process: the child of the `sh` that printed `PID:<n>`.
    fn app_pid(&self) -> String {
        self.wait_for("PID:");
        let t = text(&self.out);
        let sh = t.split("PID:").nth(1).unwrap().split_whitespace().next();
        let sh = sh.unwrap().to_owned();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let o = Command::new("/usr/bin/pgrep")
                .args(["-P", &sh])
                .output()
                .unwrap();
            let pid = String::from_utf8_lossy(&o.stdout).trim().to_owned();
            if !pid.is_empty() {
                return pid;
            }
            assert!(Instant::now() < deadline, "no child of {sh}");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Sends `signal` to `pid`, a process this test started.
fn kill(signal: &str, pid: &str) {
    let sent = Command::new("/bin/kill").args([signal, pid]).status();
    assert!(sent.unwrap().success());
}

/// The lflags words of `stty -a` show echo on.
fn echo_on(stty: &str) -> bool {
    let words: Vec<&str> = stty.split_whitespace().collect();
    words.contains(&"echo") && !words.contains(&"-echo")
}

/// `larsal ARGS` under sh, then its status and the terminal's settings.
fn sh_line(args: &str) -> String {
    format!("echo PID:$$; '{APP}' {args}; echo STATUS:$?; stty -a")
}

/// Demo bytes: a fixed pseudo-random stream, so a wrong byte anywhere shows.
fn demo(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

/// larsal-files' own encrypt (what the Mac app calls): `input` to `out` in
/// the folder of `out`.
fn lib_encrypt(input: &Path, out: &Path, lock: &Lock<'_>) {
    let folder = OutputFolder::open(out.parent().unwrap()).unwrap();
    let source = SourceFile::open(input).unwrap();
    larsal_files::encrypt_file(
        source,
        &folder,
        out.file_name().unwrap(),
        lock,
        &mut |_, _| true,
    )
    .unwrap();
}

/// larsal-files' own decrypt, whole, into memory. A low work factor is
/// accepted.
fn lib_decrypt(d: &Dir, file: &Path, unlock: &Unlock<'_>) -> Result<Vec<u8>, larsal_files::Error> {
    let root = d.path("lib-scratch");
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&root);
    let root = ScratchRoot::open(&root).unwrap();
    let keep_going = &mut |_: larsal_files::Phase, _: u64| true;
    let snapshot = root.capture_file(SourceFile::open(file)?, keep_going)?;
    let validated = match snapshot.unlock(unlock)?.validate(keep_going)? {
        Validation::Ready(v) => v,
        Validation::Weak(w) => w.accept(),
    };
    let mut out = Vec::new();
    validated.write_to(&mut out, keep_going)?;
    Ok(out)
}

/// A new identity: its private text and its public key text.
fn identity() -> (SecretString, String) {
    let (private, public) = larsal_files::generate_identity().unwrap();
    (private, public.to_text().unwrap())
}

fn assert_absent(p: &Path) {
    assert!(p.symlink_metadata().is_err(), "{} exists", p.display());
}

// ---------------------------------------------------------------------------
// Story check 1: the same format both ways (lead's ruling 2).

const SIZES: [usize; 6] = [0, 1, 65_535, 65_536, 65_537, 200_000];

#[test]
fn e22s5_check1_fil02_t24_fil03_t18_library_files_open_with_larsal_decrypt() {
    let d = Dir::new("c1a");
    let phrase = secret("demo file pass 1");
    d.put("pass.txt", b"demo file pass 1\n");
    let (private, public) = identity();
    let (other_private, other_public) = identity();
    let recipients = [
        Recipient::parse(&public).unwrap(),
        Recipient::parse(&other_public).unwrap(),
    ];
    d.put("key-1.txt", format!("{}\n", private.expose()).as_bytes());
    d.put("key-2.txt", other_private.expose().as_bytes());
    for (i, size) in SIZES.iter().enumerate() {
        let plain = demo(*size, i as u64 + 7);
        let input = d.put(&format!("in-{i}.bin"), &plain);
        let by_pass = d.path(&format!("p-{i}.age"));
        lib_encrypt(&input, &by_pass, &Lock::Passphrase(&phrase));
        let by_keys = d.path(&format!("k-{i}.age"));
        lib_encrypt(&input, &by_keys, &Lock::Recipients(&recipients));
        let runs = [
            (by_pass.clone(), "--passphrase-file", "pass.txt", "p"),
            (by_keys.clone(), "--identity-file", "key-1.txt", "k1"),
            (by_keys.clone(), "--identity-file", "key-2.txt", "k2"),
        ];
        for (file, flag, cred, tag) in runs {
            let out = format!("out-{i}-{tag}.bin");
            let o = d.run(
                &[
                    "decrypt",
                    file.to_str().unwrap(),
                    "--output",
                    &out,
                    flag,
                    cred,
                ],
                b"",
            );
            assert_eq!(o.code, Some(0), "{size} {tag}: {}", o.err);
            assert_eq!(std::fs::read(d.path(&out)).unwrap(), plain, "{size} {tag}");
            let mode = std::fs::metadata(d.path(&out))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
    assert!(d.scratch_left().is_empty(), "{:?}", d.scratch_left());
}

#[test]
fn e22s5_check1_fil03_t18_larsal_encrypt_files_open_in_the_library() {
    let d = Dir::new("c1b");
    d.put("pass.txt", format!("{STRONG} 2\r\n").as_bytes());
    let (private, public) = identity();
    let (other_private, other_public) = identity();
    for (i, size) in SIZES.iter().enumerate() {
        let plain = demo(*size, i as u64 + 11);
        let input = format!("in-{i}.bin");
        d.put(&input, &plain);
        let p_out = format!("p-{i}.age");
        let o = d.run(
            &[
                "encrypt",
                &input,
                "--output",
                &p_out,
                "--passphrase-file",
                "pass.txt",
            ],
            b"",
        );
        assert_eq!(o.code, Some(0), "{}", o.err);
        let k_out = format!("k-{i}.age");
        let o = d.run(
            &[
                "encrypt",
                &input,
                "--output",
                &k_out,
                "--recipient",
                &public,
                "--recipient",
                &other_public,
            ],
            b"",
        );
        assert_eq!(o.code, Some(0), "{}", o.err);
        let phrase = secret(&format!("{STRONG} 2"));
        let got = lib_decrypt(&d, &d.path(&p_out), &Unlock::Passphrase(&phrase)).unwrap();
        assert_eq!(got, plain, "passphrase {size}");
        for key in [&private, &other_private] {
            let ids = Identities::single(key).unwrap();
            let got = lib_decrypt(&d, &d.path(&k_out), &Unlock::Identities(&ids)).unwrap();
            assert_eq!(got, plain, "recipient {size}");
        }
        // The input is never changed.
        assert_eq!(std::fs::read(d.path(&input)).unwrap(), plain);
    }
}

/// One job of the Mac app's files bridge, polled to its end as the sheet does.
fn app_done(start: larsal_ffi::files::FileStart) {
    use larsal_ffi::files::{FileEnd, FileStart};
    let FileStart::Started { job } = start else {
        panic!("not started: {start:?}");
    };
    let until = Instant::now() + Duration::from_secs(120);
    loop {
        let p = job.progress();
        if p.finished {
            assert!(matches!(p.end, Some(FileEnd::Done { .. })), "{:?}", p.end);
            return;
        }
        assert!(Instant::now() < until, "the job never ended");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Story check 1 through the Mac app's own code, larsal-ffi's files bridge
/// (E22-S4; Verify's V-2 and its two steps): the app encrypts with a
/// passphrase and to the file key it makes and saves in the vault ("File
/// key"), and `larsal decrypt` opens both, the key by `--identity-entry`;
/// `larsal encrypt` makes a passphrase file and one for that key, and the
/// app's decrypt opens both. Byte for byte, each way.
#[test]
fn e22s5_check1_app_path_round_trip_after_e22s4() {
    use larsal_ffi::files::{FileCredential, FileSave};
    let d = Dir::new("c1app");
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    let vault = d.path("app.larsalvault");
    std::fs::copy(data.join("option-a-personal.larsalvault"), &vault).unwrap();
    let plain = demo(200_000, 47);
    let input = d.put("plain.bin", &plain).to_string_lossy().into_owned();
    d.put("pass.txt", STRONG.as_bytes());
    std::fs::create_dir(d.path("app")).unwrap();
    let app_out = d.path("app").to_string_lossy().into_owned();
    let s = larsal_ffi::session::Session::new();
    let v = s.open(vault.to_string_lossy().into_owned()).unwrap();
    s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
    // The app makes its files.
    let save = FileSave {
        vault: v,
        group: None,
        title: "Laptop files".into(),
    };
    let public = s.create_file_key(save).unwrap();
    let typed = || STRONG.to_owned();
    app_done(
        s.encrypt_file_passphrase(
            typed(),
            typed(),
            false,
            None,
            input.clone(),
            app_out.clone(),
            "app-pass.age".into(),
        )
        .unwrap(),
    );
    app_done(
        s.encrypt_file_recipients(
            vec![public.clone()],
            input,
            app_out.clone(),
            "app-key.age".into(),
        )
        .unwrap(),
    );
    // `larsal decrypt` opens them.
    let o = d.run(
        &[
            "decrypt",
            "app/app-pass.age",
            "--output",
            "cli-pass.bin",
            "--passphrase-file",
            "pass.txt",
        ],
        b"",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert_eq!(std::fs::read(d.path("cli-pass.bin")).unwrap(), plain);
    let o = d.run(
        &[
            "decrypt",
            "app/app-key.age",
            "--output",
            "cli-key.bin",
            "--identity-entry",
            "Laptop files",
            "--vault",
            "app.larsalvault",
        ],
        b"demo-pass-7\n",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert_eq!(std::fs::read(d.path("cli-key.bin")).unwrap(), plain);
    // `larsal encrypt` makes files the app opens.
    let o = d.run(
        &[
            "encrypt",
            "plain.bin",
            "--output",
            "cli-pass.age",
            "--passphrase-file",
            "pass.txt",
        ],
        b"",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    let o = d.run(
        &[
            "encrypt",
            "plain.bin",
            "--output",
            "cli-key.age",
            "--recipient",
            &public,
        ],
        b"",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    let key = s.file_key_choices(v).unwrap();
    let key = key.into_iter().find(|c| c.title == "Laptop files").unwrap();
    let cli_file = |name: &str| d.path(name).to_string_lossy().into_owned();
    app_done(
        s.decrypt_file(
            FileCredential::Passphrase {
                text: secret(STRONG),
            },
            cli_file("cli-pass.age"),
            app_out.clone(),
            "pass.bin".into(),
        )
        .unwrap(),
    );
    app_done(
        s.decrypt_file(
            FileCredential::Entry {
                vault: v,
                entry: key.entry,
            },
            cli_file("cli-key.age"),
            app_out,
            "key.bin".into(),
        )
        .unwrap(),
    );
    assert_eq!(std::fs::read(d.path("app/pass.bin")).unwrap(), plain);
    assert_eq!(std::fs::read(d.path("app/key.bin")).unwrap(), plain);
    assert!(d.scratch_left().is_empty(), "{:?}", d.scratch_left());
    // V-5, carried: a session that keeps its settings in memory leaves its
    // empty scratch folder in this test process's temp folder.
    let left = std::env::temp_dir().join(format!("larsal-file-scratch-{}", std::process::id()));
    let _ = std::fs::remove_dir(left);
}

// ---------------------------------------------------------------------------
// FIL-02.24: files another conforming tool made (the published test files).

/// Every published success file of the classical profile that is stored
/// uncompressed: `larsal decrypt` gives exactly the payload the file names.
#[test]
fn fil02_t24_published_files_from_another_tool_open_with_larsal_decrypt() {
    let d = Dir::new("t24");
    let kit = Path::new(env!("CARGO_MANIFEST_DIR")).join("../larsal-files/testdata/age-testkit");
    let mut ran = Vec::new();
    let mut names: Vec<PathBuf> = std::fs::read_dir(&kit)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    for path in names {
        let bytes = std::fs::read(&path).unwrap();
        let Some(split) = bytes.windows(2).position(|w| w == b"\n\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&bytes[..split]).into_owned();
        let field = |k: &str| {
            head.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}: ")).map(str::to_owned))
        };
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if field("expect").as_deref() != Some("success")
            || field("compressed").is_some()
            || name.contains("hybrid")
        {
            continue;
        }
        let file = d.put(&format!("{name}.in"), &bytes[split + 2..]);
        let out = format!("{name}.out");
        let o = if let Some(pass) = field("passphrase") {
            d.put("pass.txt", pass.as_bytes());
            // The published passphrase files use a low work factor: say yes.
            d.run(
                &[
                    "decrypt",
                    file.to_str().unwrap(),
                    "--output",
                    &out,
                    "--passphrase-file",
                    "pass.txt",
                ],
                b"y\n",
            )
        } else {
            d.put("key.txt", field("identity").unwrap().as_bytes());
            d.run(
                &[
                    "decrypt",
                    file.to_str().unwrap(),
                    "--output",
                    &out,
                    "--identity-file",
                    "key.txt",
                ],
                b"",
            )
        };
        assert_eq!(o.code, Some(0), "{name}: {}", o.err);
        let got = std::fs::read(d.path(&out)).unwrap();
        let hash = larsal_crypto::hash::sha256(&[&got]);
        let hex: String = hash.expose().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(Some(hex), field("payload"), "{name}");
        ran.push(name);
    }
    // Both modes, binary and armor, ran.
    for want in [
        "scrypt",
        "x25519",
        "armor_x25519",
        "armor_scrypt",
        "x25519_multiple_recipients",
    ] {
        assert!(ran.iter().any(|n| n == want), "{want} did not run: {ran:?}");
    }
}

// ---------------------------------------------------------------------------
// FIL-02.18: the grammar.

#[test]
fn fil02_t18_usage_errors_come_before_any_work() {
    let d = Dir::new("t18");
    d.put("in.bin", b"demo plain");
    d.put("pass.txt", b"demo-pass\n");
    let (_, public) = identity();
    let cases: &[(&[&str], &str)] = &[
        (
            &["encrypt", "in.bin", "--passphrase-file", "pass.txt"],
            "--output must name a new file",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "-",
                "--passphrase-file",
                "pass.txt",
            ],
            "--output must name a new file",
        ),
        (
            &["encrypt", "in.bin", "--output", "o"],
            "give exactly one way to the passphrase or key",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--passphrase",
                "--recipient",
                &public,
            ],
            "give exactly one way to the passphrase or key",
        ),
        (
            &[
                "decrypt",
                "in.bin",
                "--output",
                "o",
                "--passphrase-file",
                "pass.txt",
                "--identity-file",
                "pass.txt",
            ],
            "give exactly one way to the passphrase or key",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--generate",
                "--group",
                "",
                "--title",
                "T",
            ],
            "--vault is missing",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--generate",
                "--vault",
                "w.larsalvault",
                "--title",
                "T",
            ],
            "--group is missing",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--generate",
                "--vault",
                "w.larsalvault",
                "--group",
                "",
            ],
            "--title is missing",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--passphrase-entry",
                "E",
            ],
            "--vault is missing",
        ),
        (
            &[
                "decrypt",
                "in.bin",
                "--output",
                "o",
                "--identity-entry",
                "E",
            ],
            "--vault is missing",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--passphrase-file",
                "pass.txt",
                "--vault",
                "w.larsalvault",
            ],
            "--vault is only for a passphrase or key kept in a vault",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--passphrase-file",
                "pass.txt",
                "--no-password",
            ],
            "the unlock options are only for --vault",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--passphrase-file",
                "pass.txt",
                "--title",
                "T",
            ],
            "--group and --title are only for --generate",
        ),
        (
            &["encrypt", "--output", "o", "--passphrase-file", "pass.txt"],
            "INPUT is missing",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "more.bin",
                "--output",
                "o",
                "--passphrase-file",
                "pass.txt",
            ],
            "unexpected argument",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--identity-file",
                "pass.txt",
            ],
            "unknown option",
        ),
        (
            &["decrypt", "in.bin", "--output", "o", "--recipient", &public],
            "unknown option",
        ),
        (
            &["decrypt", "in.bin", "--output", "o", "--generate"],
            "unknown option",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--force",
                "--passphrase-file",
                "pass.txt",
            ],
            "unknown option",
        ),
        (&["encrypt", "in.bin", "--output"], "--output needs a value"),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o",
                "--passphrase-file",
                "pass.txt",
                "--key-file",
                "pass.txt",
            ],
            "the unlock options are only for --vault",
        ),
        (
            &[
                "encrypt",
                "in.bin",
                "--output",
                "",
                "--passphrase-file",
                "pass.txt",
            ],
            "--output must name a new file",
        ),
        (
            &[
                "encrypt",
                "-",
                "--output",
                "o",
                "--passphrase-file",
                "pass.txt",
            ],
            "encrypt reads a named file, not standard input",
        ),
    ];
    for (args, problem) in cases {
        let o = d.run(args, b"demo-pass-4\ndemo-pass-4\n");
        let cmd = args[0];
        assert_eq!(o.code, Some(2), "{args:?}: {}", o.err);
        assert_eq!(
            o.err,
            format!("larsal {cmd}: {problem}. Run larsal help {cmd} to see its options.\n"),
            "{args:?}"
        );
        assert_eq!(o.out, "", "{args:?}");
        assert_absent(&d.path("o"));
        assert!(d.scratch_left().is_empty());
    }
    // Help is not an error.
    for cmd in ["encrypt", "decrypt"] {
        let o = d.run(&[cmd, "-h"], b"");
        assert_eq!(o.code, Some(0));
        assert!(
            o.out
                .starts_with(&format!("Usage: larsal {cmd} [OPTIONS] INPUT\n"))
        );
        assert_eq!(o.out.matches("--quiet").count(), 1, "{}", o.out);
        assert_eq!(d.run(&["help", cmd], b"").out, o.out);
    }
}

/// FIL-02.18, FIL-02.19, lead's ruling 3: a passphrase typed as an argument is
/// a usage error, before any work, and it is never printed.
#[test]
fn fil02_t18_fil02_t19_a_passphrase_in_the_arguments_is_refused_and_never_printed() {
    let d = Dir::new("t18argv");
    d.put("in.bin", b"demo plain");
    let ct = d.path("in.age");
    lib_encrypt(
        &d.path("in.bin"),
        &ct,
        &Lock::Passphrase(&secret("demo-argv-secret-7")),
    );
    for cmd in ["encrypt", "decrypt"] {
        let input = if cmd == "encrypt" { "in.bin" } else { "in.age" };
        for extra in [
            &["--passphrase", "demo-argv-secret-7"][..],
            &["--passphrase=demo-argv-secret-7"],
            &["--passphrase", "--", "demo-argv-secret-7"],
            &["--passphrase", "--demo-argv-secret-7"],
            &["--passphrase", "-demo-argv-secret-7"],
        ] {
            let mut args = vec![cmd, input, "--output", "o"];
            args.extend_from_slice(extra);
            let o = d.run(&args, b"demo-argv-secret-7\ndemo-argv-secret-7\n");
            assert_eq!(o.code, Some(2), "{args:?}: {}", o.err);
            assert!(!o.err.contains("argv-secret"), "{args:?}: {}", o.err);
            assert!(!o.err.contains("Passphrase:"), "{args:?}: a prompt ran");
            assert_absent(&d.path("o"));
        }
    }
    // No option takes a secret as its value: every value option names a
    // file, a vault path, a key or a public recipient.
    for cmd in ["encrypt", "decrypt"] {
        let help = d.run(&["help", cmd], b"").out;
        let mut values = 0;
        for line in help.lines().filter(|l| l.trim_start().starts_with("-")) {
            let opt = line.split("  ").find(|p| !p.is_empty()).unwrap();
            let Some((_, value)) = opt.rsplit_once(" ").filter(|(_, v)| !v.starts_with("-")) else {
                continue;
            };
            values += 1;
            let names = [
                "FILE",
                "ENTRY",
                "VAULT",
                "GROUP",
                "TITLE",
                "KEY",
                "PATH",
                "SLOT[:SERIAL]",
            ];
            assert!(names.contains(&value), "{cmd}: {line}");
        }
        assert!(values >= 6, "{help}");
        assert!(help.contains("  --passphrase    "), "{help}");
    }
}

/// SC2-04, lead's ruling 1: no parse error of the tool repeats a word the
/// user typed, the top-level ones and the shell's included, so a secret given
/// by mistake is never printed.
#[test]
fn fil02_t18_no_parse_error_repeats_a_word_the_user_typed() {
    let d = Dir::new("t18words");
    d.put("in.bin", b"demo plain");
    const S: &str = "demo-parse-secret-5";
    let lines: &[&[&str]] = &[
        &[
            "--passphrase=S",
            "encrypt",
            "in.bin",
            "--output",
            "o",
            "--passphrase",
        ],
        &["--S", "encrypt"],
        &["-S"],
        &["S"],
        &["S", "--output", "o"],
        &["encrypt", "in.bin", "--output", "o", "--passphrase", "S"],
        &["encrypt", "in.bin", "--output", "o", "--S"],
        &["encrypt", "in.bin", "--output", "o", "-S"],
        &["encrypt", "in.bin", "--output", "o", "--help=S"],
        &["encrypt", "in.bin", "--output", "o", "--generate=S"],
        &[
            "decrypt",
            "in.bin",
            "--output",
            "o",
            "--passphrase",
            "--",
            "S",
        ],
        &[
            "encrypt",
            "in.bin",
            "--output",
            "o",
            "--passphrase-entry",
            "E",
            "--vault",
            "w.larsalvault",
            "--hw-key",
            "S",
        ],
        &["generate", "--S"],
        &["generate", "--length=8", "S"],
        &["ls", "w.larsalvault", "/", "S"],
        &["ls", "--hw-key", "S", "w.larsalvault"],
        &["show", "--S=x", "w.larsalvault", "E"],
        &["estimate", "--S"],
        &["help", "S"],
    ];
    for line in lines {
        let args: Vec<String> = line.iter().map(|w| w.replace('S', S)).collect();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = d.run(&args, b"demo-pass-4\n");
        assert!(
            !o.err.contains(S) && !o.out.contains(S),
            "{args:?}: {}{}",
            o.out,
            o.err
        );
        if line[0] != "help" {
            assert!(matches!(o.code, Some(1 | 2)), "{args:?}: {:?}", o.code);
        }
        assert_absent(&d.path("o"));
    }
    // The shell names only a command of its own table.
    let o = d.run(
        &["open", "w.larsalvault"],
        format!("demo-pass-4\n{S}\n{S} --output o\nencrypt\nquit\n").as_bytes(),
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(!o.err.contains(S) && !o.out.contains(S), "{}", o.err);
    assert_eq!(
        o.err
            .matches("There is no such command here. Type help to see the commands.")
            .count(),
        2,
        "{}",
        o.err
    );
    assert!(
        o.err.contains("There is no command encrypt here."),
        "{}",
        o.err
    );
}

/// FIL-02.17: two processes for one output name: at most one owns it.
#[test]
fn fil02_t17_two_processes_one_output_name_one_owner() {
    let d = Dir::new("t17");
    let plain = demo(300_000, 3);
    d.put("in.bin", &plain);
    d.put("pass.txt", b"demo-pass-17");
    lib_encrypt(
        &d.path("in.bin"),
        &d.path("in.age"),
        &Lock::Passphrase(&secret("demo-pass-17")),
    );
    let start = || {
        d.command(APP)
            .args([
                "decrypt",
                "in.age",
                "--output",
                "same.bin",
                "--passphrase-file",
                "pass.txt",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let (a, b) = (start(), start());
    let (a, b) = (a.wait_with_output().unwrap(), b.wait_with_output().unwrap());
    let mut codes = [a.status.code(), b.status.code()];
    codes.sort();
    assert_eq!(codes, [Some(0), Some(1)], "{a:?} {b:?}");
    let loser = if a.status.code() == Some(1) { &a } else { &b };
    // The loser may have started its work before the winner made the file:
    // the exclusive create still refuses it.
    assert!(
        String::from_utf8_lossy(&loser.stderr).ends_with(EXISTS_MSG),
        "{loser:?}"
    );
    assert_eq!(std::fs::read(d.path("same.bin")).unwrap(), plain);
    assert!(d.scratch_left().is_empty());
}

// ---------------------------------------------------------------------------
// FIL-02.19: where a passphrase may come from.

/// No environment variable gives a passphrase, whatever its name. SC2-03:
/// the source reads the environment only through the standard temp folder
/// (TMPDIR), and its words say exactly that.
#[test]
fn fil02_t19_no_secret_from_the_environment_only_tmpdir_is_read() {
    let d = Dir::new("t19env");
    d.put("in.bin", b"demo plain");
    let env = [
        ("LARSAL_PASSPHRASE", "demo-env-secret"),
        ("PASSPHRASE", "demo-env-secret"),
        ("AGE_PASSPHRASE", "demo-env-secret"),
        ("LARSAL_PASSWORD", "demo-env-secret"),
    ];
    let o = d.run_env(
        &["encrypt", "in.bin", "--output", "o", "--passphrase"],
        b"",
        &env,
    );
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "larsal: --passphrase needs a terminal to type on. Use --passphrase-file or --passphrase-entry.\n"
    );
    assert_absent(&d.path("o"));
    let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/files.rs"))
        .unwrap();
    let reads: Vec<&str> = src
        .match_indices("env::")
        .map(|(at, _)| {
            let rest = &src[at + 5..];
            &rest[..rest
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap()]
        })
        .collect();
    assert!(
        !reads.is_empty() && reads.iter().all(|r| *r == "temp_dir"),
        "files.rs reads the environment otherwise: {reads:?}"
    );
    for word in ["var_os", "getenv", "env!(", "option_env!("] {
        assert!(
            !src.contains(word),
            "files.rs reads the environment: {word}"
        );
    }
    assert!(src.contains("The environment these commands read is TMPDIR alone"));
}

/// The exact bytes of a passphrase file: one final LF and the CR before it
/// go, all else stays; empty, not UTF-8 and over the limit are refused before
/// any work.
#[test]
fn fil02_t19_passphrase_file_bytes_exactly() {
    let d = Dir::new("t19file");
    let plain = demo(70_000, 5);
    d.put("in.bin", &plain);
    // Each phrase holds STRONG, so encrypt does not ask about its strength.
    let s = STRONG;
    let cases: Vec<(String, String)> = vec![
        (format!("{s}\r\n"), s.to_owned()),
        (format!("{s}\n"), s.to_owned()),
        (s.to_owned(), s.to_owned()),
        (format!("{s}\n\n"), format!("{s}\n")),
        (format!("{s}\r"), format!("{s}\r")),
        (format!(" {s} \0 pass \t"), format!(" {s} \0 pass \t")),
        (format!("\u{e9}t\u{e9} {s}\n"), format!("\u{e9}t\u{e9} {s}")),
        (
            format!("e\u{301}t\u{e9} {s}\n"),
            format!("e\u{301}t\u{e9} {s}"),
        ),
    ];
    for (i, (file, phrase)) in cases.iter().enumerate() {
        d.put("pass.txt", file.as_bytes());
        let out = format!("o-{i}.age");
        let o = d.run(
            &[
                "encrypt",
                "in.bin",
                "--output",
                &out,
                "--passphrase-file",
                "pass.txt",
            ],
            b"",
        );
        assert_eq!(o.code, Some(0), "{file:?}: {}", o.err);
        assert!(!o.err.contains(WEAK_WARNING), "{file:?}: {}", o.err);
        let got = lib_decrypt(&d, &d.path(&out), &Unlock::Passphrase(&secret(phrase)));
        assert_eq!(got.unwrap(), plain, "{file:?}");
        // One byte off does not open it.
        let near = format!("{phrase}\n");
        let wrong = lib_decrypt(&d, &d.path(&out), &Unlock::Passphrase(&secret(&near)));
        assert_eq!(wrong.err(), Some(larsal_files::Error::Decrypt), "{file:?}");
    }
    let mut over = vec![b'a'; larsal_files::limits::MAX_PASSPHRASE + 1];
    let mut at_limit: Vec<u8> = STRONG
        .bytes()
        .cycle()
        .take(larsal_files::limits::MAX_PASSPHRASE)
        .collect();
    at_limit.extend_from_slice(b"\r\n");
    for (file, ok) in [
        (&b""[..], false),
        (b"\n", false),
        (b"\r\n", false),
        (b"\xff\xfe demo\n", false),
        (&over[..], false),
        (&at_limit[..], true),
    ] {
        d.put("pass.txt", file);
        let _ = std::fs::remove_file(d.path("o.age"));
        let o = d.run(
            &[
                "encrypt",
                "in.bin",
                "--output",
                "o.age",
                "--passphrase-file",
                "pass.txt",
            ],
            b"",
        );
        if ok {
            assert_eq!(o.code, Some(0), "{}", o.err);
        } else {
            assert_eq!(
                (o.code, o.err.as_str()),
                (Some(1), PASSPHRASE_MSG),
                "{:?}",
                &file[..file.len().min(8)]
            );
            assert_absent(&d.path("o.age"));
        }
    }
    over.push(b'\n');
    d.put("pass.txt", &over);
    let o = d.run(
        &[
            "decrypt",
            "o.age",
            "--output",
            "o.bin",
            "--passphrase-file",
            "pass.txt",
        ],
        b"",
    );
    assert_eq!((o.code, o.err.as_str()), (Some(1), PASSPHRASE_MSG));
    assert_absent(&d.path("o.bin"));
}

/// FIL-02.19 on a terminal: echo off, asked twice to encrypt, the prompts
/// also with `--quiet`, and a mismatch writes nothing.
#[test]
fn fil02_t19_terminal_prompt_twice_without_echo_pty() {
    let d = Dir::new("t19pty");
    let plain = demo(100_000, 9);
    d.put("in.bin", &plain);
    let mut p = d.pty(&format!(
        "'{APP}' encrypt -q in.bin --output o.age --passphrase; echo STATUS:$?"
    ));
    p.wait_for("Passphrase: ");
    p.send(&format!("{STRONG}\n"));
    p.wait_for("Repeat passphrase: ");
    p.send(&format!("{STRONG}\n"));
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(t.contains("STATUS:0"), "{t}");
    assert!(!t.contains(STRONG), "echoed: {t}");
    assert!(!t.contains(USE_ANYWAY), "{t}");
    let got = lib_decrypt(&d, &d.path("o.age"), &Unlock::Passphrase(&secret(STRONG)));
    assert_eq!(got.unwrap(), plain);
    // Decrypt asks once.
    let mut p = d.pty(&format!(
        "'{APP}' decrypt o.age --output o.bin --passphrase; echo STATUS:$?"
    ));
    p.wait_for("Passphrase: ");
    p.send(&format!("{STRONG}\n"));
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(t.contains("STATUS:0") && !t.contains("Repeat"), "{t}");
    assert_eq!(std::fs::read(d.path("o.bin")).unwrap(), plain);
    // A repeat that differs: nothing is written.
    let mut p = d.pty(&format!(
        "'{APP}' encrypt in.bin --output o2.age --passphrase; echo STATUS:$?"
    ));
    p.wait_for("Passphrase: ");
    p.send(&format!("{STRONG}\n"));
    p.wait_for("Repeat passphrase: ");
    p.send(&format!("{STRONG}z\n"));
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(
        t.contains("larsal: The passphrases do not match.\nSTATUS:1"),
        "{t}"
    );
    assert_absent(&d.path("o2.age"));
}

/// FIL-01.7, SC2-01, lead's ruling 3: a passphrase the user chose, typed or
/// from a file, below Excellent, is used only after a yes on a terminal, also
/// with `--quiet`; no, no answer or a quit signal writes nothing; with no
/// terminal it is refused before any work. A generated phrase and a vault
/// entry are not asked about (fil02_t18_generate_saves_first_then_encrypts,
/// fil02_t19_passphrase_and_key_from_vault_entries).
#[test]
fn fil02_t19_fil01_t07_a_weak_chosen_passphrase_needs_a_yes_pty() {
    let d = Dir::new("t19weak");
    let plain = demo(50_000, 41);
    d.put("in.bin", &plain);
    d.put("weak.txt", b"demo-weak-pass\n");
    // About 82 bits: Good, still below Excellent.
    d.put("good.txt", b"Demo-7Hq#v2Lr9!x\n");
    let refused = format!(
        "{WEAK_WARNING}\nlarsal: a passphrase that may be easy to guess needs a terminal to confirm it. Use a stronger passphrase.\n"
    );
    for file in ["weak.txt", "good.txt"] {
        let o = d.run(
            &[
                "encrypt",
                "in.bin",
                "--output",
                "f.age",
                "--passphrase-file",
                file,
            ],
            b"y\n",
        );
        assert_eq!(
            (o.code, o.err.as_str(), o.out.as_str()),
            (Some(1), refused.as_str(), ""),
            "{file}"
        );
        assert_absent(&d.path("f.age"));
    }
    let typed = |p: &mut Pty| {
        p.wait_for("Passphrase: ");
        p.send("demo-weak-pass\n");
        p.wait_for("Repeat passphrase: ");
        p.send("demo-weak-pass\n");
        p.wait_for(USE_ANYWAY);
    };
    // No, or no answer: a handled cancel, nothing written.
    for answer in ["n\n", "\n"] {
        let mut p = d.pty(&sh_line("encrypt -q in.bin --output t.age --passphrase"));
        typed(&mut p);
        p.send(answer);
        p.wait_for("lflags");
        let t = p.finish();
        assert!(t.contains(WEAK_WARNING), "{t}");
        assert!(t.contains(&format!("{CANCELLED_MSG}\nSTATUS:130")), "{t}");
        assert!(!t.contains("Encrypting file"), "{t}");
        assert_absent(&d.path("t.age"));
    }
    // A quit signal at the question ends the run at once, by that signal.
    for (signal, number) in QUIT {
        let mut p = d.pty(&sh_line("encrypt in.bin --output t.age --passphrase"));
        let pid = p.app_pid();
        typed(&mut p);
        thread::sleep(Duration::from_millis(300));
        kill(signal, &pid);
        p.wait_within("lflags", Duration::from_secs(10));
        let t = p.finish();
        assert!(
            t.contains(&format!("STATUS:{}", 128 + number)),
            "{signal}: {t}"
        );
        assert!(echo_on(t.split("STATUS:").nth(1).unwrap()), "{signal}: {t}");
        assert_absent(&d.path("t.age"));
    }
    // Yes: typed, and from a file on a terminal.
    let mut p = d.pty(&sh_line("encrypt in.bin --output t.age --passphrase"));
    typed(&mut p);
    p.send("y\n");
    p.wait_for("lflags");
    assert!(p.finish().contains("STATUS:0"));
    let mut p = d.pty(&sh_line(
        "encrypt in.bin --output f.age --passphrase-file weak.txt",
    ));
    p.wait_for(USE_ANYWAY);
    p.send("y\n");
    p.wait_for("lflags");
    assert!(p.finish().contains("STATUS:0"));
    for out in ["t.age", "f.age"] {
        let got = lib_decrypt(
            &d,
            &d.path(out),
            &Unlock::Passphrase(&secret("demo-weak-pass")),
        );
        assert_eq!(got.unwrap(), plain, "{out}");
    }
}

/// FIL-02.19, C1-04: every prompt prints also with `--quiet`, the vault
/// password's included.
#[test]
fn fil02_t19_every_prompt_ignores_quiet_pty() {
    let d = Dir::new("t19quiet");
    d.put("in.bin", b"demo plain for quiet");
    let o = d.run(
        &["add", "-q", "-p", "w.larsalvault", "File pass"],
        format!("demo-pass-4\n{STRONG}\n").as_bytes(),
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    let mut p = d.pty(&sh_line(
        "encrypt -q in.bin --output q.age --passphrase-entry 'File pass' --vault w.larsalvault",
    ));
    p.wait_for("Vault password for w.larsalvault: ");
    p.send("demo-pass-4\n");
    p.wait_for("lflags");
    let t = p.finish();
    assert!(t.contains("STATUS:0") && !t.contains("demo-pass-4"), "{t}");
    assert!(
        !t.contains("Encrypting file") && !t.contains("Done."),
        "{t}"
    );
}

/// FIL-02.19: a passphrase and a key from vault entries; the vault password
/// is the only line read.
#[test]
fn fil02_t19_passphrase_and_key_from_vault_entries() {
    let d = Dir::new("t19vault");
    let plain = demo(90_000, 13);
    d.put("in.bin", &plain);
    let (private, public) = identity();
    let o = d.run(
        &["add", "-q", "-p", "w.larsalvault", "File pass"],
        b"demo-pass-4\n demo entry pass \n",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    let line = format!("demo-pass-4\n{}\n", private.expose());
    let o = d.run(
        &["add", "-q", "-p", "w.larsalvault", "File key"],
        line.as_bytes(),
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    let o = d.run(
        &[
            "encrypt",
            "in.bin",
            "--output",
            "p.age",
            "--passphrase-entry",
            "File pass",
            "--vault",
            "w.larsalvault",
        ],
        b"demo-pass-4\n",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    // A weak entry is the user's own choice, kept in the vault: not asked.
    assert!(!o.err.contains(WEAK_WARNING), "{}", o.err);
    let got = lib_decrypt(
        &d,
        &d.path("p.age"),
        &Unlock::Passphrase(&secret(" demo entry pass ")),
    );
    assert_eq!(got.unwrap(), plain);
    let o = d.run(
        &[
            "decrypt",
            "p.age",
            "--output",
            "p.bin",
            "--passphrase-entry",
            "File pass",
            "--vault",
            "w.larsalvault",
        ],
        b"demo-pass-4\n",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert_eq!(std::fs::read(d.path("p.bin")).unwrap(), plain);
    let o = d.run(
        &[
            "encrypt",
            "in.bin",
            "--output",
            "k.age",
            "--recipient",
            &public,
        ],
        b"",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    let o = d.run(
        &[
            "decrypt",
            "k.age",
            "--output",
            "k.bin",
            "--identity-entry",
            "File key",
            "--vault",
            "w.larsalvault",
        ],
        b"demo-pass-4\n",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert_eq!(std::fs::read(d.path("k.bin")).unwrap(), plain);
    // A wrong vault password: the vault's own error, no output.
    let o = d.run(
        &[
            "decrypt",
            "k.age",
            "--output",
            "k2.bin",
            "--identity-entry",
            "File key",
            "--vault",
            "w.larsalvault",
        ],
        b"demo-pass-x\n",
    );
    assert_eq!(o.code, Some(1));
    assert_absent(&d.path("k2.bin"));
}

/// FIL-02.18: --generate saves the passphrase as a new protected entry first,
/// ten words of the built-in list, never printed; a later failure keeps it.
#[test]
fn fil02_t18_generate_saves_first_then_encrypts() {
    let d = Dir::new("t18gen");
    let plain = demo(1 << 20, 17);
    d.put("in.bin", &plain);
    let make = |title: &str, out: &str| {
        d.run(
            &[
                "encrypt",
                "in.bin",
                "--output",
                out,
                "--generate",
                "--vault",
                "w.larsalvault",
                "--group",
                "",
                "--title",
                title,
            ],
            b"demo-pass-4\n",
        )
    };
    let o = make("File passphrase", "g.age");
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(!o.err.contains(WEAK_WARNING), "{}", o.err);
    let shown = d.run(
        &[
            "show",
            "-q",
            "-a",
            "Password",
            "w.larsalvault",
            "/File passphrase",
        ],
        b"demo-pass-4\n",
    );
    let phrase = shown.out.strip_suffix('\n').unwrap().to_owned();
    let words: Vec<&str> = phrase.split(' ').collect();
    assert_eq!(words.len(), 10, "{phrase:?}");
    assert!(
        words
            .iter()
            .all(|w| !w.is_empty() && w.chars().all(|c| !c.is_uppercase()))
    );
    assert!(!o.out.contains(&phrase) && !o.err.contains(&phrase));
    let got = lib_decrypt(&d, &d.path("g.age"), &Unlock::Passphrase(&secret(&phrase)));
    assert_eq!(got.unwrap(), plain);
    // The entry is protected.
    let shown = d.run(
        &["show", "-q", "w.larsalvault", "/File passphrase"],
        b"demo-pass-4\n",
    );
    assert!(
        shown.out.contains("Password: PROTECTED") || !shown.out.contains(&phrase),
        "{}",
        shown.out
    );
    // A title in use: nothing saved, nothing written.
    let o = make("File passphrase", "g2.age");
    assert_eq!(o.code, Some(1));
    assert_absent(&d.path("g2.age"));
    // The file write fails after the save: the entry stays, no output stays.
    let o = d.sh(
        "trap '' XFSZ; ulimit -f 64; exec \"$0\" encrypt in.bin --output g3.age --generate --vault w.larsalvault --group '' --title 'Second'",
        b"demo-pass-4\n",
    );
    assert_eq!(o.code, Some(1), "{}", o.err);
    assert!(o.err.ends_with(
        "larsal: The file could not be read or saved. Check access to the files and try again.\n\
         larsal: The passphrase is saved in your vault. No encrypted file was completed.\n"
    ), "{}", o.err);
    assert_absent(&d.path("g3.age"));
    let shown = d.run(
        &["show", "-q", "-a", "Password", "w.larsalvault", "/Second"],
        b"demo-pass-4\n",
    );
    assert_eq!(shown.code, Some(0));
    assert_eq!(shown.out.split(' ').count(), 10);
}

/// FIL-01.16 through the command line: an encrypted key file asks for its own
/// passphrase on the terminal, and refuses without one.
#[test]
fn fil02_t19_an_encrypted_key_file_asks_for_its_own_passphrase_pty() {
    let d = Dir::new("t19key");
    let plain = demo(10_000, 19);
    d.put("in.bin", &plain);
    let (private, public) = identity();
    d.put(
        "key.txt",
        format!("# demo key\n{}\n", private.expose()).as_bytes(),
    );
    lib_encrypt(
        &d.path("key.txt"),
        &d.path("key.age"),
        &Lock::Passphrase(&secret("demo-key-pass")),
    );
    std::fs::remove_file(d.path("key.txt")).unwrap();
    let o = d.run(
        &[
            "encrypt",
            "in.bin",
            "--output",
            "k.age",
            "--recipient",
            &public,
        ],
        b"",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    let o = d.run(
        &[
            "decrypt",
            "k.age",
            "--output",
            "k.bin",
            "--identity-file",
            "key.age",
        ],
        b"demo-key-pass\n",
    );
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "larsal: the key file is encrypted, and its passphrase needs a terminal to type on.\n"
    );
    let mut p = d.pty(&format!(
        "'{APP}' decrypt k.age --output k.bin --identity-file key.age; echo STATUS:$?"
    ));
    p.wait_for("Passphrase of the key file: ");
    p.send("demo-key-pass\n");
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(
        t.contains("STATUS:0") && !t.contains("demo-key-pass"),
        "{t}"
    );
    assert_eq!(std::fs::read(d.path("k.bin")).unwrap(), plain);
    // C1-06 (X19): the same key file in armor is seen as encrypted too.
    let binary = std::fs::read(d.path("key.age")).unwrap();
    let text = larsal_crypto::base64::encode(larsal_crypto::base64::Form::Padded, &binary);
    let mut armor = String::from("-----BEGIN AGE ENCRYPTED FILE-----\n");
    for line in text.as_bytes().chunks(64) {
        armor.push_str(std::str::from_utf8(line).unwrap());
        armor.push('\n');
    }
    armor.push_str("-----END AGE ENCRYPTED FILE-----\n");
    d.put("key-armor.txt", armor.as_bytes());
    let o = d.run(
        &[
            "decrypt",
            "k.age",
            "--output",
            "k2.bin",
            "--identity-file",
            "key-armor.txt",
        ],
        b"demo-key-pass\n",
    );
    assert_eq!(
        (o.code, o.err.as_str()),
        (
            Some(1),
            "larsal: the key file is encrypted, and its passphrase needs a terminal to type on.\n"
        )
    );
    let mut p = d.pty(&format!(
        "'{APP}' decrypt k.age --output k2.bin --identity-file key-armor.txt; echo STATUS:$?"
    ));
    p.wait_for("Passphrase of the key file: ");
    p.send("demo-key-pass\n");
    p.wait_for("STATUS:");
    assert!(p.finish().contains("STATUS:0"));
    assert_eq!(std::fs::read(d.path("k2.bin")).unwrap(), plain);
}

// ---------------------------------------------------------------------------
// FIL-02.20: standard input.

#[test]
fn fil02_t20_standard_input_carries_data_or_a_secret_never_both() {
    let d = Dir::new("t20");
    let plain = demo(150_000, 23);
    d.put("in.bin", &plain);
    d.put("pass.txt", b"demo-pass-20\n");
    lib_encrypt(
        &d.path("in.bin"),
        &d.path("in.age"),
        &Lock::Passphrase(&secret("demo-pass-20")),
    );
    let ct = std::fs::read(d.path("in.age")).unwrap();
    let o = d.run(
        &[
            "decrypt",
            "-",
            "--output",
            "o.bin",
            "--passphrase-file",
            "pass.txt",
        ],
        &ct,
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert_eq!(std::fs::read(d.path("o.bin")).unwrap(), plain);
    let usage = |cmd: &str, problem: &str| {
        format!("larsal {cmd}: {problem}. Run larsal help {cmd} to see its options.\n")
    };
    let o = d.run(&["decrypt", "-", "--output", "o2.bin", "--passphrase"], &ct);
    assert_eq!(
        (o.code, o.err),
        (
            Some(2),
            usage(
                "decrypt",
                "the data and a password cannot both come from standard input"
            )
        )
    );
    let o = d.run(
        &[
            "decrypt",
            "-",
            "--output",
            "o2.bin",
            "--passphrase-entry",
            "E",
            "--vault",
            "w.larsalvault",
        ],
        &ct,
    );
    assert_eq!(
        (o.code, o.err),
        (
            Some(2),
            usage(
                "decrypt",
                "the data and a password cannot both come from standard input"
            )
        )
    );
    let o = d.run(
        &[
            "decrypt",
            "-",
            "--output",
            "o2.bin",
            "--passphrase-file",
            "/dev/stdin",
        ],
        &ct,
    );
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "larsal: the data and the passphrase or key cannot both come from standard input.\n"
    );
    assert_absent(&d.path("o2.bin"));
    // Damaged data on stdin: the one error, no output, no scratch.
    let mut bad = ct.clone();
    let at = bad.len() - 100;
    bad[at] ^= 1;
    let o = d.run(
        &[
            "decrypt",
            "-",
            "--output",
            "o3.bin",
            "--passphrase-file",
            "pass.txt",
        ],
        &bad,
    );
    // The phase lines come first; the one error closes stderr.
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with(DECRYPT_MSG), "{}", o.err);
    assert_eq!(o.err.matches("larsal:").count(), 1, "{}", o.err);
    assert_absent(&d.path("o3.bin"));
    assert!(d.scratch_left().is_empty());
    // A terminal as data is refused.
    let p = d.pty(&format!(
        "'{APP}' decrypt - --output o4.bin --passphrase-file pass.txt; echo STATUS:$?"
    ));
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(
        t.contains("standard input is a terminal, not an encrypted file") && t.contains("STATUS:2"),
        "{t}"
    );
}

// ---------------------------------------------------------------------------
// FIL-02.21: exit codes, own words, signals.

/// One error for every decrypt failure, no path or name in any message, no
/// existing file touched.
#[test]
fn fil02_t21_fil03_t08_fil03_t13_fil03_t14_own_words_and_exit_codes() {
    let d = Dir::new("t21words");
    let plain = demo(80_000, 29);
    d.put("secret-name-q7.bin", &plain);
    d.put("pass.txt", STRONG.as_bytes());
    d.put("wrong.txt", b"demo-pass-22");
    let o = d.run(
        &[
            "encrypt",
            "secret-name-q7.bin",
            "--output",
            "secret-out-q7.age",
            "--passphrase-file",
            "pass.txt",
        ],
        b"",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert_eq!(o.out, "Done. Saved secret-out-q7.age.\n");
    assert_eq!(
        o.err,
        "Encrypting file\nNo server is contacted. Anyone with this encrypted file can test passphrase guesses. Names, sizes and dates may still be visible.\n"
    );
    // Quiet drops progress and the success line only.
    let o = d.run(
        &[
            "encrypt",
            "-q",
            "secret-name-q7.bin",
            "--output",
            "q.age",
            "--passphrase-file",
            "pass.txt",
        ],
        b"",
    );
    assert_eq!(o.code, Some(0));
    assert_eq!(o.out, "");
    assert!(o.err.starts_with("No server is contacted."), "{}", o.err);
    // Wrong passphrase, cut file, damaged byte: the same words, exit 1.
    let ct = std::fs::read(d.path("secret-out-q7.age")).unwrap();
    d.put("cut.age", &ct[..ct.len() - 1]);
    let mut flipped = ct.clone();
    flipped[200] ^= 0x80;
    d.put("flip.age", &flipped);
    d.put("plain.txt", b"not an encrypted file\n");
    for (file, cred) in [
        ("secret-out-q7.age", "wrong.txt"),
        ("cut.age", "pass.txt"),
        ("flip.age", "pass.txt"),
        ("plain.txt", "pass.txt"),
    ] {
        let o = d.run(
            &[
                "decrypt",
                file,
                "--output",
                "secret-plain-q7.bin",
                "--passphrase-file",
                cred,
            ],
            b"",
        );
        assert_eq!(o.code, Some(1), "{file}");
        assert_eq!(o.out, "", "{file}");
        assert!(o.err.ends_with(DECRYPT_MSG), "{file}: {}", o.err);
        assert!(
            !o.err.contains("q7") && !o.err.contains(".age"),
            "{}",
            o.err
        );
        assert_absent(&d.path("secret-plain-q7.bin"));
    }
    // An existing output: left as it was.
    d.put("taken.bin", b"demo sentinel");
    for (cmd, input) in [
        ("encrypt", "secret-name-q7.bin"),
        ("decrypt", "secret-out-q7.age"),
    ] {
        let o = d.run(
            &[
                cmd,
                input,
                "--output",
                "taken.bin",
                "--passphrase-file",
                "pass.txt",
            ],
            b"",
        );
        assert_eq!((o.code, o.err.as_str()), (Some(1), EXISTS_MSG));
        assert_eq!(
            std::fs::read(d.path("taken.bin")).unwrap(),
            b"demo sentinel"
        );
    }
    std::os::unix::fs::symlink("taken.bin", d.path("link.bin")).unwrap();
    let o = d.run(
        &[
            "decrypt",
            "secret-out-q7.age",
            "--output",
            "link.bin",
            "--passphrase-file",
            "pass.txt",
        ],
        b"",
    );
    assert_eq!((o.code, o.err.as_str()), (Some(1), EXISTS_MSG));
    assert_eq!(
        std::fs::read(d.path("taken.bin")).unwrap(),
        b"demo sentinel"
    );
    // A folder or a missing input; a missing output folder.
    for (input, out, msg) in [
        (
            "home",
            "x.age",
            "Choose one local file. Folders and links are not supported here.",
        ),
        (
            "missing-q7.bin",
            "x.age",
            "Choose one local file. Folders and links are not supported here.",
        ),
        (
            "secret-name-q7.bin",
            "no-such-q7/x.age",
            "This location cannot be used. Choose another folder and a new file name.",
        ),
        (
            "secret-name-q7.bin",
            "home/",
            "This location cannot be used. Choose another folder and a new file name.",
        ),
        // C1-03: a folder, named any way, is no new file name.
        (
            "secret-name-q7.bin",
            "home",
            "This location cannot be used. Choose another folder and a new file name.",
        ),
        (
            "secret-name-q7.bin",
            "home/.",
            "This location cannot be used. Choose another folder and a new file name.",
        ),
        (
            "secret-name-q7.bin",
            "nd-q7/.",
            "This location cannot be used. Choose another folder and a new file name.",
        ),
        (
            "secret-name-q7.bin",
            "nd-q7/",
            "This location cannot be used. Choose another folder and a new file name.",
        ),
    ] {
        let o = d.run(
            &[
                "encrypt",
                input,
                "--output",
                out,
                "--passphrase-file",
                "pass.txt",
            ],
            b"",
        );
        assert_eq!(
            (o.code, o.err),
            (Some(1), format!("larsal: {msg}\n")),
            "{input} {out}"
        );
    }
    assert_absent(&d.path("nd-q7"));
    assert_eq!(std::fs::read_dir(d.path("home")).unwrap().count(), 0);
    let o = d.run(
        &[
            "encrypt",
            "secret-name-q7.bin",
            "--output",
            "r.age",
            "--recipient",
            "age1notakey",
        ],
        b"",
    );
    assert_eq!(
        (o.code, o.err.as_str()),
        (
            Some(1),
            "larsal: Add a valid native X25519 recipient key.\n"
        )
    );
    assert!(d.scratch_left().is_empty());
}

/// A failure is never turned into success: a closed stderr, a destination
/// that stops taking bytes.
#[test]
fn fil02_t21_fil03_t10_broken_stderr_and_a_failing_destination_fail() {
    let d = Dir::new("t21broken");
    let plain = demo(1 << 20, 31);
    d.put("in.bin", &plain);
    d.put("pass.txt", STRONG.as_bytes());
    lib_encrypt(
        &d.path("in.bin"),
        &d.path("in.age"),
        &Lock::Passphrase(&secret(STRONG)),
    );
    // C1-05: stderr, stdout or both lead to a pipe whose reader is gone, with
    // the right passphrase: a line that cannot be written fails the run
    // (exit 1, not a signal); the complete output stays.
    for (broken, out) in [("stderr", "e.bin"), ("stdout", "s.bin"), ("both", "b.bin")] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut c = d.command(APP);
        c.args([
            "decrypt",
            "in.age",
            "--output",
            out,
            "--passphrase-file",
            "pass.txt",
        ])
        .stdin(Stdio::null());
        match broken {
            "stderr" => c.stdout(Stdio::piped()).stderr(writer),
            "stdout" => c.stdout(writer).stderr(Stdio::piped()),
            _ => c.stdout(writer.try_clone().unwrap()).stderr(writer),
        };
        let o = c.output().unwrap();
        assert_eq!(
            (o.status.code(), o.status.signal()),
            (Some(1), None),
            "{broken}"
        );
        assert_eq!(std::fs::read(d.path(out)).unwrap(), plain, "{broken}");
        if broken == "stdout" {
            assert!(
                String::from_utf8_lossy(&o.stderr)
                    .ends_with("larsal: standard output or standard error could not be written.\n"),
                "{o:?}"
            );
        }
    }
    // The output stops at 32 KiB: the write fails, nothing stays.
    let o = d.sh(
        "trap '' XFSZ; ulimit -f 64; exec \"$0\" encrypt in.bin --output o.age --passphrase-file pass.txt",
        b"",
    );
    assert_eq!((o.code, o.signal), (Some(1), None), "{}", o.err);
    assert!(o.err.ends_with("larsal: The file could not be read or saved. Check access to the files and try again.\n"), "{}", o.err);
    assert_absent(&d.path("o.age"));
    let o = d.sh(
        "trap '' XFSZ; ulimit -f 64; exec \"$0\" decrypt in.age --output o.bin --passphrase-file pass.txt",
        b"",
    );
    assert_eq!(o.code, Some(1), "{}", o.err);
    assert_absent(&d.path("o.bin"));
    assert!(d.scratch_left().is_empty(), "{:?}", d.scratch_left());
}

/// FIL-03.2 through the command line: a low work factor asks; no is a
/// handled cancel, exit 130, and nothing is written.
#[test]
fn fil02_t21_fil03_t02_a_declined_low_work_factor_is_a_handled_cancel() {
    let d = Dir::new("t21weak");
    let kit =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../larsal-files/testdata/age-testkit/scrypt");
    let bytes = std::fs::read(kit).unwrap();
    let split = bytes.windows(2).position(|w| w == b"\n\n").unwrap();
    d.put("weak.age", &bytes[split + 2..]);
    d.put("pass.txt", b"password");
    for answer in [&b"n\n"[..], b"", b"no\n", b"\n"] {
        let o = d.run(
            &[
                "decrypt",
                "weak.age",
                "--output",
                "o.bin",
                "--passphrase-file",
                "pass.txt",
            ],
            answer,
        );
        assert_eq!(o.code, Some(130), "{answer:?}: {}", o.err);
        assert!(o.err.contains("This file uses a low passphrase work factor. Only save its contents if you trust the file.\nSave the readable file? [y/N] "), "{}", o.err);
        assert!(o.err.ends_with(&format!("{CANCELLED_MSG}\n")), "{}", o.err);
        assert_absent(&d.path("o.bin"));
    }
    let o = d.run(
        &[
            "decrypt",
            "weak.age",
            "--output",
            "o.bin",
            "--passphrase-file",
            "pass.txt",
        ],
        b"y\n",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(d.scratch_left().is_empty());
}

/// FIL-02.22, FIL-03.21: after each success the mode's limits are said on
/// stderr, also with `--quiet`, and nothing claims more.
#[test]
fn fil02_t22_fil03_t21_each_success_says_its_limits() {
    let d = Dir::new("t22");
    d.put("in.bin", b"demo plain for the notes");
    let (private, public) = identity();
    d.put("id.txt", format!("{}\n", private.expose()).as_bytes());
    for quiet in [false, true] {
        let tail: &[&str] = if quiet {
            &["-q", "--output"]
        } else {
            &["--output"]
        };
        let name = |s: &str| format!("{s}{}", u8::from(quiet));
        let (ct, out) = (name("r.age"), name("r.out"));
        let mut args = vec!["encrypt", "in.bin"];
        args.extend(tail);
        args.extend([ct.as_str(), "--recipient", public.as_str()]);
        let o = d.run(&args, b"");
        assert_eq!(o.code, Some(0), "{}", o.err);
        assert!(
            o.err.ends_with(
                "These public keys do not protect against a future quantum computer.\nThis does not prove who sent the file.\n"
            ),
            "{}",
            o.err
        );
        let mut args = vec!["decrypt", ct.as_str()];
        args.extend(tail);
        args.extend([out.as_str(), "--identity-file", "id.txt"]);
        let o = d.run(&args, b"");
        assert_eq!(o.code, Some(0), "{}", o.err);
        assert!(
            o.err
                .ends_with("The saved file is not encrypted. Keep it somewhere private.\n"),
            "{}",
            o.err
        );
        assert_eq!(o.out.is_empty(), quiet, "{}", o.out);
        for claim in ["anonym", "safe", "verified", "signed"] {
            assert!(!o.err.to_lowercase().contains(claim), "{}", o.err);
        }
    }
}

/// The recipient of `tests/data/weak-key-file.age`, a demo key file encrypted
/// to "demo passphrase" with a low work factor. Both were made by
/// larsal-files' independent writer of the format (testdata/make_derived.py,
/// its ID_A and log_n 4), not by Larsal code.
const WEAK_KEY_RECIPIENT: &str = "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72";

/// FIL-03.2, FIL-01.16, FIL-02.21: keys from an encrypted key file with a low
/// work factor are used only after a yes; no, or a quit signal at that
/// question, leaves no output.
#[test]
fn fil02_t21_fil03_t02_a_weak_key_file_asks_before_saving_pty() {
    let d = Dir::new("t21weakkey");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/weak-key-file.age");
    let key_bytes = std::fs::read(&key).unwrap();
    // The fixture really is a weak key file.
    let keys =
        Identities::read_key_file(&mut &key_bytes[..], Some(&secret("demo passphrase"))).unwrap();
    assert!(keys.from_weak_file());
    d.put("weak.key", &key_bytes);
    let plain = demo(70_000, 21);
    d.put("in.bin", &plain);
    let recipient = Recipient::parse(WEAK_KEY_RECIPIENT).unwrap();
    lib_encrypt(
        &d.path("in.bin"),
        &d.path("data.age"),
        &Lock::Recipients(&[recipient]),
    );
    let args = "decrypt data.age --output o.bin --identity-file weak.key";
    // No: a handled cancel.
    let mut p = d.pty(&sh_line(args));
    p.wait_for("Passphrase of the key file: ");
    p.send("demo passphrase\n");
    p.wait_for("Save the readable file? [y/N] ");
    p.send("n\n");
    p.wait_for("lflags");
    let t = p.finish();
    assert!(
        t.contains("This file uses a low passphrase work factor."),
        "{t}"
    );
    assert!(t.contains("STATUS:130"), "{t}");
    assert_absent(&d.path("o.bin"));
    // A quit signal at the question, then a yes: still nothing saved, and
    // the process ends by that signal.
    let mut p = d.pty(&sh_line(args));
    let pid = p.app_pid();
    p.wait_for("Passphrase of the key file: ");
    p.send("demo passphrase\n");
    p.wait_for("Save the readable file? [y/N] ");
    thread::sleep(Duration::from_millis(300));
    kill("-TERM", &pid);
    // C1-06 (X04c): it ends at once, by the signal, with no answer read.
    p.wait_within("STATUS:", Duration::from_secs(10));
    // The process is gone: the yes then has no reader.
    let _ = p.stdin.as_mut().unwrap().write_all(b"y\n");
    let t = p.finish();
    assert!(t.contains("STATUS:143"), "{t}");
    assert_absent(&d.path("o.bin"));
    // Yes: the exact bytes.
    let mut p = d.pty(&sh_line(args));
    p.wait_for("Passphrase of the key file: ");
    p.send("demo passphrase\n");
    p.wait_for("Save the readable file? [y/N] ");
    p.send("y\n");
    p.wait_for("lflags");
    let t = p.finish();
    assert!(t.contains("STATUS:0"), "{t}");
    assert_eq!(std::fs::read(d.path("o.bin")).unwrap(), plain);
    assert!(d.scratch_left().is_empty());
}

const QUIT: [(&str, i32); 4] = [("-INT", 2), ("-TERM", 15), ("-HUP", 1), ("-QUIT", 3)];

/// FIL-02.21: each quit signal at the passphrase prompt restores the echo,
/// ends `larsal` by that signal, and writes nothing.
#[test]
fn fil02_t21_each_quit_signal_at_the_prompt_restores_echo_pty() {
    let d = Dir::new("t21prompt");
    d.put("in.bin", b"demo plain");
    for (signal, number) in QUIT {
        let p = d.pty(&sh_line("encrypt in.bin --output o.age --passphrase"));
        let pid = p.app_pid();
        p.wait_for("Passphrase: ");
        thread::sleep(Duration::from_millis(400));
        kill(signal, &pid);
        p.wait_for("lflags");
        let t = p.finish();
        assert!(
            t.contains(&format!("STATUS:{}", 128 + number)),
            "{signal}: {t}"
        );
        assert!(echo_on(t.split("STATUS:").nth(1).unwrap()), "{signal}: {t}");
        assert_absent(&d.path("o.age"));
    }
}

/// FIL-02.21, FIL-03.7, FIL-03.11, lead's ruling 4: each quit signal while a
/// file is being written cancels it at the next chunk, removes the incomplete
/// output and the scratch folder, then ends `larsal` by that signal, with the
/// terminal's echo on.
#[test]
fn fil02_t21_fil03_t07_each_quit_signal_during_the_work_leaves_nothing_pty() {
    let d = Dir::new("t21work");
    // A large sparse input reads fast and gives the signal time to land.
    let big = std::fs::File::create(d.path("big.bin")).unwrap();
    big.set_len(1 << 30).unwrap();
    drop(big);
    // Ciphertext for the decrypt runs, made by the library.
    let mut zeros = std::io::repeat(0).take(512 << 20);
    let mut ct = std::fs::File::create(d.path("big.age")).unwrap();
    let phrase = secret(STRONG);
    larsal_files::encrypt_stream(
        &mut zeros,
        &mut ct,
        &Lock::Passphrase(&phrase),
        &mut |_, _| true,
    )
    .unwrap();
    drop(ct);
    for (cmd, input, phase) in [
        ("encrypt", "big.bin", "Encrypting file"),
        ("decrypt", "big.age", "Preparing encrypted copy"),
        ("decrypt", "big.age", "Saving readable file"),
    ] {
        for (signal, number) in QUIT {
            let mut p = d.pty(&sh_line(&format!(
                "{cmd} {input} --output out.bin --passphrase"
            )));
            let pid = p.app_pid();
            p.wait_for("Passphrase: ");
            p.send(&format!("{STRONG}\n"));
            if cmd == "encrypt" {
                p.wait_for("Repeat passphrase: ");
                p.send(&format!("{STRONG}\n"));
            }
            p.wait_for(phase);
            kill(signal, &pid);
            p.wait_for("lflags");
            let t = p.finish();
            assert!(
                t.contains(&format!("STATUS:{}", 128 + number)),
                "{cmd} {phase} {signal}: {t}"
            );
            assert!(t.contains(CANCELLED_MSG), "{cmd} {phase} {signal}: {t}");
            assert!(!t.contains("Done."), "{t}");
            assert!(echo_on(t.split("STATUS:").nth(1).unwrap()), "{signal}: {t}");
            assert_absent(&d.path("out.bin"));
            assert!(d.scratch_left().is_empty(), "{:?}", d.scratch_left());
            // V-4: nor larsal-files' hidden staging folder (F-340).
            let staging: Vec<_> = std::fs::read_dir(&d.0)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .filter(|n| n.to_string_lossy().starts_with(".larsal-staging-"))
                .collect();
            assert!(staging.is_empty(), "{cmd} {phase} {signal}: {staging:?}");
        }
    }
}

/// FIL-03.11, C1-01, lead's ruling 2: the ciphertext a crash left in a
/// capture is removed at the next start, and nothing else is touched: not a
/// live run's folder, not one of another mode, form or kind, not a folder
/// reached through a link. An empty folder of this tool's form goes too.
#[test]
fn fil02_t21_fil03_t11_a_crash_leftover_is_swept_at_the_next_start() {
    let d = Dir::new("t11sweep");
    let plain = demo(200_000, 43);
    d.put("in.bin", &plain);
    d.put("pass.txt", STRONG.as_bytes());
    lib_encrypt(
        &d.path("in.bin"),
        &d.path("in.age"),
        &Lock::Passphrase(&secret(STRONG)),
    );
    let ct = std::fs::read(d.path("in.age")).unwrap();
    // A decrypt from stdin that stops in its capture: part of the data, then
    // nothing. Its new scratch folder is returned with the running process.
    let stalled = || {
        let before = d.scratch_left();
        let mut child = d
            .command(APP)
            .args([
                "decrypt",
                "-",
                "--output",
                "late.bin",
                "--passphrase-file",
                "pass.txt",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut feed = child.stdin.take().unwrap();
        feed.write_all(&ct[..150_000]).unwrap();
        let said = collect(child.stderr.take().unwrap());
        let deadline = Instant::now() + Duration::from_secs(60);
        while !text(&said).contains("Preparing encrypted copy") {
            assert!(Instant::now() < deadline, "{}", text(&said));
            thread::sleep(Duration::from_millis(10));
        }
        let new: Vec<PathBuf> = d
            .scratch_left()
            .into_iter()
            .filter(|p| !before.contains(p))
            .collect();
        assert_eq!(new.len(), 1, "{new:?}");
        (child, feed, new[0].clone())
    };
    // A crash, by this test's own handle: the named ciphertext stays.
    let crash = |run: (Child, ChildStdin, PathBuf)| {
        let (mut child, feed, folder) = run;
        child.kill().unwrap();
        child.wait().unwrap();
        drop(feed);
        let op = std::fs::read_dir(&folder)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(std::fs::read_dir(op).unwrap().count(), 1, "the ciphertext");
        folder
    };
    let count = |p: &Path| std::fs::read_dir(p).unwrap().count();
    // A leftover with another mode: never this tool's to sweep.
    let open_mode = crash(stalled());
    std::fs::set_permissions(&open_mode, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A leftover reached through a link from the temp folder.
    let linked = crash(stalled());
    std::fs::rename(&linked, d.path("elsewhere")).unwrap();
    std::os::unix::fs::symlink(d.path("elsewhere"), &linked).unwrap();
    // A live run's folder is left alone by another run's start.
    let live = stalled();
    let o = d.run(
        &[
            "decrypt",
            "in.age",
            "--output",
            "a.bin",
            "--passphrase-file",
            "pass.txt",
        ],
        b"",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert_eq!(count(&live.2), 1);
    let left = crash(live);
    // Folders of another form, and an empty one of this form.
    let tmp = d.path("tmp");
    let folder = |name: &str, file: bool| {
        let p = tmp.join(name);
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        if file {
            std::fs::write(p.join("keep.txt"), b"demo keep").unwrap();
        }
        p
    };
    let with_file = folder(&format!("larsal-scratch-{}", "1".repeat(32)), true);
    let not_ours = folder("larsal-scratch-notours", false);
    let upper = folder(&format!("larsal-scratch-{}", "A".repeat(32)), false);
    let long = folder(&format!("larsal-scratch-{}", "4".repeat(33)), false);
    let empty = folder(&format!("larsal-scratch-{}", "3".repeat(32)), false);
    // A start that cannot remove an owned leftover says so, and goes on: the
    // temp folder takes no change for this one run (an encrypt needs no
    // scratch of its own).
    let note = "Note: Larsal could not remove the encrypted scratch an earlier run left behind.\n";
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o500)).unwrap();
    let o = d.run(
        &[
            "encrypt",
            "in.bin",
            "--output",
            "c.age",
            "--passphrase-file",
            "pass.txt",
        ],
        b"",
    );
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(o.err.starts_with(note), "{}", o.err);
    assert!(left.is_dir() && empty.is_dir());
    // The next start.
    let o = d.run(
        &[
            "decrypt",
            "in.age",
            "--output",
            "b.bin",
            "--passphrase-file",
            "pass.txt",
        ],
        b"",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(!o.err.contains(note), "{}", o.err);
    assert_eq!(std::fs::read(d.path("b.bin")).unwrap(), plain);
    assert_absent(&left);
    assert_absent(&empty);
    assert_eq!(count(&open_mode), 1);
    assert_eq!(
        count(
            &std::fs::read_dir(&open_mode)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path()
        ),
        1
    );
    assert!(linked.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(count(&d.path("elsewhere")), 1);
    assert_eq!(
        std::fs::read(with_file.join("keep.txt")).unwrap(),
        b"demo keep"
    );
    assert!(not_ours.is_dir() && upper.is_dir() && long.is_dir());
    assert_eq!(d.scratch_left().len(), 6, "{:?}", d.scratch_left());
    // C1R2-03 (Y24): larsal-files' own sweep fails inside a leftover (its
    // ciphertext carries the user-immutable flag, so it cannot be removed):
    // said once, and the run goes on; the next start removes it.
    let stuck = crash(stalled());
    let op = std::fs::read_dir(&stuck).unwrap().next().unwrap().unwrap();
    let ciphertext = std::fs::read_dir(op.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let flags = |f: &str| {
        let set = Command::new("/usr/bin/chflags")
            .arg(f)
            .arg(ciphertext.path())
            .status();
        assert!(set.unwrap().success());
    };
    let encrypt = |out: &str| {
        d.run(
            &[
                "encrypt",
                "in.bin",
                "--output",
                out,
                "--passphrase-file",
                "pass.txt",
            ],
            b"",
        )
    };
    flags("uchg");
    let o = encrypt("d.age");
    flags("nouchg");
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(o.err.starts_with(note), "{}", o.err);
    assert_eq!(o.err.matches(note).count(), 1, "{}", o.err);
    assert!(stuck.is_dir());
    let o = encrypt("e.age");
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(!o.err.contains(note), "{}", o.err);
    assert_absent(&stuck);
}

/// C1R2-01: an entry of the scratch form that is no folder of its own (a
/// FIFO, a link to a FIFO, a link to a folder) is never opened or followed:
/// encrypt and decrypt start and finish as usual, within 10 s, and the
/// entries and what a link leads to stay as they were.
#[test]
fn fil02_t21_fil03_t11_a_fifo_or_link_of_the_scratch_form_is_never_opened() {
    use std::os::unix::fs::FileTypeExt;
    let d = Dir::new("t11fifo");
    d.put("in.bin", &demo(70_000, 53));
    d.put("pass.txt", STRONG.as_bytes());
    lib_encrypt(
        &d.path("in.bin"),
        &d.path("in.age"),
        &Lock::Passphrase(&secret(STRONG)),
    );
    let tmp = d.path("tmp");
    let fifo = |p: &Path| {
        let made = Command::new("/usr/bin/mkfifo").arg(p).status();
        assert!(made.unwrap().success());
    };
    let name = |digit: &str| tmp.join(format!("larsal-scratch-{}", digit.repeat(32)));
    fifo(&name("e"));
    fifo(&d.path("far-fifo"));
    std::os::unix::fs::symlink(d.path("far-fifo"), name("d")).unwrap();
    let far = d.path("far-folder");
    std::fs::DirBuilder::new().mode(0o700).create(&far).unwrap();
    std::fs::write(far.join("keep.txt"), b"demo keep").unwrap();
    std::os::unix::fs::symlink(&far, name("c")).unwrap();
    for (cmd, input) in [("encrypt", "in.bin"), ("decrypt", "in.age")] {
        let out = format!("{cmd}.out");
        let mut child = d
            .command(APP)
            .args([
                cmd,
                input,
                "--output",
                &out,
                "--passphrase-file",
                "pass.txt",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                // Only this test's own child, by its handle.
                let _ = child.kill();
                let _ = child.wait();
                panic!("{cmd} still runs after 10 s");
            }
            thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(0), "{cmd}");
        assert!(d.path(&out).is_file(), "{cmd}");
    }
    let kind = |p: &Path| p.symlink_metadata().unwrap().file_type();
    assert!(kind(&name("e")).is_fifo());
    assert!(kind(&name("d")).is_symlink() && kind(&name("c")).is_symlink());
    assert_eq!(std::fs::read(far.join("keep.txt")).unwrap(), b"demo keep");
    assert_eq!(std::fs::read_dir(&far).unwrap().count(), 1);
}

// ---------------------------------------------------------------------------
// Ruling 5: 4 GiB through the command line.

/// A 4 GiB demo file through `larsal encrypt` and `larsal decrypt`, byte for
/// byte, with the time and the peak memory of each run. About 16 GiB of disk
/// while it runs; everything is deleted after.
#[test]
#[ignore = "4 GiB of demo data and about 16 GiB of disk: run by hand with --ignored --nocapture"]
fn e22s5_ruling5_four_gib_round_trip_through_the_command_line() {
    const GIB4: u64 = 4 << 30;
    const BLOCK: usize = 1 << 20;
    let d = Dir::new("4g");
    let block = |i: u64| demo(BLOCK, i.wrapping_mul(0x9e37_79b9) + 1);
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(d.path("big.bin")).unwrap());
        for i in 0..GIB4 / BLOCK as u64 {
            f.write_all(&block(i)).unwrap();
        }
        f.flush().unwrap();
    }
    d.put("pass.txt", STRONG.as_bytes());
    for (args, name) in [
        (["encrypt", "big.bin", "--output", "big.age"], "encrypt"),
        (["decrypt", "big.age", "--output", "big.out"], "decrypt"),
    ] {
        let started = Instant::now();
        let mut c = d.command("/usr/bin/time");
        c.args(["-l", APP])
            .args(args)
            .args(["-q", "--passphrase-file", "pass.txt"]);
        let o = finish(c, b"");
        let took = started.elapsed();
        assert_eq!(o.code, Some(0), "{name}: {}", o.err);
        let peak = o
            .err
            .lines()
            .find(|l| l.contains("maximum resident set size"))
            .unwrap()
            .trim()
            .to_owned();
        eprintln!("{name}: {:.1} s, {peak}", took.as_secs_f64());
    }
    let mut got = std::io::BufReader::new(std::fs::File::open(d.path("big.out")).unwrap());
    let mut buf = vec![0u8; BLOCK];
    for i in 0..GIB4 / BLOCK as u64 {
        got.read_exact(&mut buf).unwrap();
        assert!(buf == block(i), "block {i} differs");
    }
    assert_eq!(got.read(&mut buf).unwrap(), 0, "longer than 4 GiB");
    assert_eq!(std::fs::metadata(d.path("big.out")).unwrap().len(), GIB4);
    eprintln!("4 GiB: byte for byte equal");
}

// ---------------------------------------------------------------------------
// The shell has neither command (INT-10.45).

#[test]
fn int10_45_encrypt_and_decrypt_are_not_shell_commands() {
    let d = Dir::new("shell");
    let o = d.run(
        &["open", "w.larsalvault"],
        b"demo-pass-4\nencrypt a --output b --passphrase\ndecrypt a --output b --passphrase\nquit\n",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(
        o.err.contains("There is no command encrypt here."),
        "{}",
        o.err
    );
    assert!(
        o.err.contains("There is no command decrypt here."),
        "{}",
        o.err
    );
}
