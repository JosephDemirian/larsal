//! INT-10's test cases, run on the built `app` binary with copies of
//! `testdata/` vaults in a temp folder per case. Clip cases use the private
//! named pasteboard of the process under test, never the general one
//! (AGENTS.md rule 10). "pty" cases run `app` under `script(1)`, which gives
//! it a pseudo-terminal.

use app_core::time::Instant as CoreInstant;
use app_crypto::kdf::{self, Host, Verdict};
use app_crypto::secret::SecretString;
use app_format::keys::{Credentials, composite_key, final_keys, password_part};
use app_format::limits::Limits;
use app_format::{Opened, Saved};
use app_model::{Argon2Kind, Entry, Field, Group, Kdf, Time, Uuid, Vault};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const APP: &str = env!("CARGO_BIN_EXE_app");

// ---------------------------------------------------------------------------
// Harness.

/// A temp folder holding copies of the demo vaults and key files, and
/// `w.appvault`, a fresh copy of rich-v3 (INT-10 "Test cases").
struct Dir(PathBuf);

impl Dir {
    fn new(case: &str) -> Dir {
        // LD-180: a runner started in the background passes SIGINT and
        // SIGQUIT on ignored, and `app` leaves ignored signals alone
        // (LD-178); reset them once, before any `app` starts.
        static RESET: std::sync::Once = std::sync::Once::new();
        RESET.call_once(app_platform::macos::reset_quit_signals_for_tests);
        let dir = std::env::temp_dir().join(format!("app-cli-int10-{}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("home")).unwrap();
        let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
        for f in std::fs::read_dir(&data).unwrap() {
            let p = f.unwrap().path();
            let name = p.file_name().unwrap().to_str().unwrap().to_owned();
            let wanted = (name.ends_with(".appvault") && !name.starts_with("big-"))
                || name.ends_with(".appkey");
            if wanted {
                std::fs::copy(&p, dir.join(&name)).unwrap();
            }
        }
        std::fs::copy(dir.join("rich-v3.appvault"), dir.join("w.appvault")).unwrap();
        Dir(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(APP);
        c.args(args)
            .current_dir(&self.0)
            .env("HOME", self.path("home"))
            .env_remove("APP_TEST_PASTEBOARD")
            .env_remove("APP_TEST_SELF_TEST_FAIL");
        c
    }

    /// Runs `app` with `input` on a pipe as stdin.
    fn run(&self, args: &[&str], input: &str) -> Out {
        self.run_env(args, input, &[])
    }

    fn run_env(&self, args: &[&str], input: &str, env: &[(&str, &str)]) -> Out {
        let mut c = self.command(args);
        c.envs(env.iter().copied());
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let bytes = input.as_bytes().to_vec();
        let writer = thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
        let o = child.wait_with_output().unwrap();
        writer.join().unwrap();
        Out {
            code: o.status.code(),
            out: String::from_utf8_lossy(&o.stdout).into_owned(),
            err: String::from_utf8_lossy(&o.stderr).into_owned(),
            raw: o.stdout,
        }
    }

    /// Starts `app` with piped streams, read as they come.
    fn spawn(&self, args: &[&str], env: &[(&str, &str)]) -> Proc {
        let mut c = self.command(args);
        c.envs(env.iter().copied());
        start(c)
    }

    /// `app` started by `/bin/sh` with SIGINT ignored, as `nohup` or a
    /// background job starts it; `exec` keeps the process id.
    fn spawn_ignoring_sigint(&self, args: &[&str], env: &[(&str, &str)]) -> Proc {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "trap '' INT; exec \"$0\" \"$@\"", APP])
            .args(args)
            .current_dir(&self.0)
            .env("HOME", self.path("home"))
            .envs(env.iter().copied());
        start(c)
    }

    /// Runs `script` under `/bin/sh -c` on a pseudo-terminal.
    fn pty(&self, script: &str) -> Pty {
        let mut child = Command::new("/usr/bin/script")
            .args(["-q", "/dev/null", "/bin/sh", "-c", script])
            .current_dir(&self.0)
            .env("HOME", self.path("home"))
            .env_remove("APP_TEST_PASTEBOARD")
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
}

fn start(mut c: Command) -> Proc {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = collect(child.stdout.take().unwrap());
    let err = collect(child.stderr.take().unwrap());
    Proc {
        stdin: child.stdin.take(),
        child,
        out,
        err,
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Out {
    code: Option<i32>,
    out: String,
    err: String,
    raw: Vec<u8>,
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

fn wait_for(buf: &Arc<Mutex<Vec<u8>>>, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !text(buf).contains(needle) {
        assert!(
            Instant::now() < deadline,
            "waited for {needle:?}, got {:?}",
            text(buf)
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Waits for `child` to end, at most 120 s; then stops it by its PID.
fn wait_child(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("process did not end");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<Vec<u8>>>,
    err: Arc<Mutex<Vec<u8>>>,
}

impl Proc {
    fn send(&mut self, s: &str) {
        let w = self.stdin.as_mut().unwrap();
        w.write_all(s.as_bytes()).unwrap();
        w.flush().unwrap();
    }

    fn finish(mut self) -> (Option<i32>, String, String) {
        drop(self.stdin.take());
        let status = wait_child(&mut self.child);
        thread::sleep(Duration::from_millis(50));
        (status.code(), text(&self.out), text(&self.err))
    }
}

struct Pty {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<Vec<u8>>>,
}

impl Pty {
    fn wait_for(&self, needle: &str) {
        wait_for(&self.out, needle);
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
        wait_child(&mut self.child);
        thread::sleep(Duration::from_millis(50));
        text(&self.out)
    }

    /// The `app` process: the child of the `sh` that printed `PID:<n>`.
    fn app_pid(&self) -> String {
        self.wait_for("PID:");
        let t = text(&self.out);
        let sh = t
            .split("PID:")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
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
            thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Sends `signal` to `pid`, a process this test started.
fn kill(signal: &str, pid: &str) {
    assert!(
        Command::new("/bin/kill")
            .args([signal, pid])
            .status()
            .unwrap()
            .success()
    );
}

/// The lflags words of `stty -a` show echo on.
fn echo_on(stty: &str) -> bool {
    let words: Vec<&str> = stty.split_whitespace().collect();
    words.contains(&"echo") && !words.contains(&"-echo")
}

fn sh(app_args: &str) -> String {
    format!("echo PID:$$; '{APP}' {app_args}; echo STATUS:$?; stty -a")
}

fn lines(s: &str) -> Vec<&str> {
    s.lines().collect()
}

// ---------------------------------------------------------------------------
// App's test tool: vaults opened, changed and saved with the engine.

fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 4,
        argon2_record: None,
        aes_record: None,
    }
}

fn load(path: &Path, pw: &str) -> Vault {
    let bytes = std::fs::read(path).unwrap();
    let pw = SecretString::new(pw.into());
    let creds = Credentials {
        password: Some(&pw),
        ..Credentials::default()
    };
    match app_format::open(&bytes, &creds, &mut host(), &Limits::DEFAULT, None).unwrap() {
        Opened::Vault(o) => o.vault,
        Opened::Ask(_) => panic!("ask"),
    }
}

fn store(path: &Path, v: &Vault, pw: &str) {
    let pw = SecretString::new(pw.into());
    let creds = Credentials {
        password: Some(&pw),
        ..Credentials::default()
    };
    match app_format::save(v, &creds, None, &mut host(), &Limits::DEFAULT, None).unwrap() {
        Saved::File(f) => std::fs::write(path, &f.bytes).unwrap(),
        Saved::Ask(_) => panic!("ask"),
    }
}

fn now() -> Time {
    let s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Time::from_unix(i64::try_from(s).unwrap()).unwrap()
}

/// A new version 4 vault with a fast KDF and one entry titled `title`.
fn small_vault(title: &str) -> Vault {
    let mut v = app_core::settings::new_vault("Small", now(), 1).unwrap();
    v.encryption.kdf = Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: 1,
        memory_kib: 1024,
        lanes: 1,
    };
    let root = v.root.uuid;
    let mut e = app_core::edit::new_entry(&v, root, false).unwrap();
    e.set_field("Title".into(), field(title, false));
    app_core::edit::add_entry(&mut v, root, e, now()).unwrap();
    v
}

fn field(v: &str, protected: bool) -> Field {
    Field {
        value: SecretString::new(v.into()),
        protected,
    }
}

fn find<'v>(v: &'v Vault, title: &str) -> &'v Entry {
    v.root
        .all_entries()
        .find(|e| e.value("Title") == title)
        .unwrap()
}

fn find_mut<'v>(g: &'v mut Group, title: &str) -> Option<&'v mut Entry> {
    if let Some(i) = g.entries.iter().position(|e| e.value("Title") == title) {
        return g.entries.get_mut(i);
    }
    g.groups.iter_mut().find_map(|c| find_mut(c, title))
}

fn full_demo_history(path: &Path) -> usize {
    let v = load(path, "demo-pass-4");
    let id = Uuid([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a]);
    v.root
        .all_entries()
        .find(|e| e.uuid == id)
        .unwrap()
        .history
        .len()
}

/// Rewrites header bytes of a version 4 file with `edit`, then recomputes
/// the header hash and, with `pw`, the header HMAC (FMT-05).
fn patch_header(path: &Path, pw: Option<&str>, edit: impl FnOnce(&mut [u8])) {
    let mut bytes = std::fs::read(path).unwrap();
    let header = app_format::header::read_header(&bytes, &Limits::DEFAULT).unwrap();
    let len = header.len;
    edit(&mut bytes[..len]);
    let hash = app_crypto::hash::sha256(&[&bytes[..len]]);
    bytes[len..len + 32].copy_from_slice(hash.expose());
    if let Some(pw) = pw {
        let header = app_format::header::read_header(&bytes, &Limits::DEFAULT).unwrap();
        let p = password_part(&SecretString::new(pw.into()));
        let composite = composite_key(Some(&p), None, None);
        let mut h = host();
        let Verdict::Run(cleared) =
            kdf::assess(&header.kdf, &mut h, &Limits::DEFAULT.kdf, None).unwrap()
        else {
            panic!("ask")
        };
        let t = kdf::derive(&composite, &cleared).unwrap();
        let keys = final_keys(&header.master_seed, &t);
        let mac = app_format::integrity::header_hmac(&keys.hmac_key, &bytes[..len]);
        bytes[len + 32..len + 64].copy_from_slice(mac.expose());
    }
    std::fs::write(path, bytes).unwrap();
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------------------
// The private pasteboard of an `app` process (APP_TEST_PASTEBOARD).

mod pasteboard {
    use objc2::rc::{Retained, autoreleasepool};
    use objc2_app_kit::NSPasteboard;
    use objc2_foundation::NSString;

    pub const TEXT: &str = "public.utf8-plain-text";

    pub fn name(pid: u32) -> String {
        format!("com.app.clipboard.{pid}.0")
    }

    fn board(name: &str) -> Retained<NSPasteboard> {
        NSPasteboard::pasteboardWithName(&NSString::from_str(name))
    }

    pub fn items(name: &str) -> Vec<Vec<(String, Vec<u8>)>> {
        autoreleasepool(|_| {
            let Some(items) = board(name).pasteboardItems() else {
                return Vec::new();
            };
            items
                .to_vec()
                .iter()
                .map(|item| {
                    item.types()
                        .to_vec()
                        .iter()
                        .map(|kind| {
                            let data = item.dataForType(kind).map(|d| d.to_vec());
                            (kind.to_string(), data.unwrap_or_default())
                        })
                        .collect()
                })
                .collect()
        })
    }

    pub fn text(name: &str) -> Option<String> {
        let items = items(name);
        let [item] = items.as_slice() else {
            return None;
        };
        let (_, data) = item.iter().find(|(k, _)| k == TEXT)?;
        Some(String::from_utf8(data.clone()).unwrap())
    }

    pub fn write_other(name: &str, text: &str) {
        autoreleasepool(|_| {
            let pb = board(name);
            pb.clearContents();
            pb.setString_forType(&NSString::from_str(text), &NSString::from_str(TEXT));
        });
    }

    /// Empties the pasteboard after a case (its name stays known to the
    /// pasteboard server until logout; the binding has no release).
    pub fn release(name: &str) {
        autoreleasepool(|_| {
            board(name).clearContents();
        });
    }
}

const PB: &[(&str, &str)] = &[("APP_TEST_PASTEBOARD", "1")];

// ---------------------------------------------------------------------------
// INT-10.1 to INT-10.8: start-up, syntax, help, streams, quiet, exit codes.

#[test]
fn int10_1_a_self_test_failure_before_any_prompt() {
    let d = Dir::new("1a");
    let o = d.run_env(
        &["ls", "password-only.appvault"],
        "demo-pass-1\n",
        &[("APP_TEST_SELF_TEST_FAIL", "1")],
    );
    assert_eq!(o.code, Some(1));
    assert!(o.err.contains(
        "App cannot start: a self-check of its encryption code failed. SHA-256 gave a wrong answer."
    ));
    assert!(!o.err.contains("Vault password"));
    assert!(o.out.is_empty());
}

#[test]
fn int10_1_b_help_before_the_self_test() {
    let d = Dir::new("1b");
    let o = d.run_env(&["--help"], "", &[("APP_TEST_SELF_TEST_FAIL", "1")]);
    assert_eq!(o.code, Some(0));
    assert!(o.out.starts_with("App command line tool.\n"));
}

#[test]
fn int10_2_a_value_forms() {
    let d = Dir::new("2a");
    for args in [
        &["generate", "-L12"][..],
        &["generate", "--length=12"],
        &["generate", "-L", "12"],
    ] {
        let o = d.run(args, "");
        assert_eq!(o.code, Some(0));
        assert_eq!(o.out.trim_end_matches('\n').chars().count(), 12, "{args:?}");
    }
}

#[test]
fn int10_2_b_combined_flags() {
    let d = Dir::new("2b");
    let o = d.run(&["generate", "-ln", "-L", "40"], "");
    let pw = o.out.trim_end();
    assert_eq!(pw.chars().count(), 40);
    assert!(
        pw.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    );
}

#[test]
fn int10_2_c_double_dash_ends_options() {
    let d = Dir::new("2c");
    let o = d.run(
        &["ls", "password-only.appvault", "--", "-R"],
        "demo-pass-1\n",
    );
    assert_eq!(o.code, Some(1));
    assert!(o.err.contains("app: no group at -R."), "{}", o.err);
}

#[test]
fn int10_2_d_unknown_option() {
    let d = Dir::new("2d");
    let o = d.run(&["generate", "--bogus"], "");
    assert_eq!(o.code, Some(1));
    assert!(o.out.is_empty());
    assert_eq!(
        o.err,
        "app generate: unknown option --bogus. Run app help generate to see its options.\n"
    );
}

const C01_TO_C26: [&str; 26] = [
    "add",
    "analyze",
    "attachment-export",
    "attachment-import",
    "attachment-rm",
    "clip",
    "close",
    "db-create",
    "db-edit",
    "db-info",
    "passphrase",
    "edit",
    "estimate",
    "export",
    "generate",
    "help",
    "import",
    "ls",
    "merge",
    "mkdir",
    "mv",
    "open",
    "rm",
    "rmdir",
    "search",
    "show",
];

#[test]
fn int10_3_a_usage_lists_the_26_commands() {
    let d = Dir::new("3a");
    for args in [&[][..], &["--help"], &["--help-all"], &["-h"]] {
        let o = d.run(args, "");
        assert_eq!(o.code, Some(0));
        assert!(o.out.starts_with("App command line tool.\n"));
        for c in C01_TO_C26 {
            assert!(o.out.contains(&format!("\n  {c} ")), "{c} in {args:?}");
        }
        for hidden in ["diceware", "exit", "quit"] {
            assert!(!o.out.contains(&format!("\n  {hidden} ")), "{hidden}");
        }
    }
}

#[test]
fn int10_3_b_version_alone() {
    let d = Dir::new("3b");
    for args in [&["-v"][..], &["--version"]] {
        let o = d.run(args, "");
        assert_eq!(o.code, Some(0));
        assert_eq!(o.out, format!("{}\n", env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn int10_3_c_debug_info_without_paths() {
    let d = Dir::new("3c");
    let o = d.run(&["--debug-info"], "");
    assert_eq!(o.code, Some(0));
    for want in [
        "App command line tool 0.1.0",
        "Build type: debug",
        "Operating system: macOS ",
        "CPU architecture: ",
        "Kernel: Darwin ",
        "Features built in: none",
        "Crypto crates: aes 0.9.3",
    ] {
        assert!(o.out.contains(want), "{want}\n{}", o.out);
    }
    assert!(!o.out.contains('/'));
    assert!(!o.out.contains(d.0.to_str().unwrap()));
}

#[test]
fn int10_3_d_command_help_on_stdout_exit_0() {
    let d = Dir::new("3d");
    for args in [
        &["show", "--help"][..],
        &["ls", "password-only.appvault", "--help"],
    ] {
        let o = d.run(args, "demo-pass-1\n");
        assert_eq!(o.code, Some(0), "{args:?}");
        assert!(o.out.starts_with(&format!("Usage: app {} ", args[0])));
        assert!(o.err.is_empty(), "{}", o.err);
    }
}

#[test]
fn int10_4_a_passphrase_and_its_alias() {
    let d = Dir::new("4a");
    for c in ["diceware", "passphrase"] {
        let o = d.run(&[c, "-W", "3"], "");
        assert_eq!(o.code, Some(0));
        let words: Vec<&str> = o.out.split_whitespace().collect();
        assert_eq!(words.len(), 3, "{c}: {}", o.out);
        assert!(words.iter().all(|w| w.chars().all(|c| !c.is_uppercase())));
    }
}

#[test]
fn int10_4_b_unknown_command_and_top_level_option() {
    let d = Dir::new("4b");
    let o = d.run(&["bogus"], "");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: there is no command bogus. Run app help to see the commands.\n"
    );
    let o = d.run(&["--bogus"], "");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: unknown option --bogus. Run app help to see the commands.\n"
    );
    assert!(o.out.is_empty());
}

#[test]
fn int10_5_a_bad_seconds_before_the_prompt_pty() {
    let d = Dir::new("5a");
    let t = d
        .pty(&sh("clip password-only.appvault 'Demo login' abc"))
        .finish();
    assert!(
        t.contains("app: abc is not a number of seconds (0 or more)."),
        "{t}"
    );
    assert!(!t.contains("Vault password"));
    assert!(t.contains("STATUS:1"));
}

#[test]
fn int10_5_b_conflicts_before_the_prompt_pty() {
    let d = Dir::new("5b");
    let t = d
        .pty(&format!(
            "'{APP}' add -g -p w.appvault X; echo STATUS:$?; '{APP}' db-edit -p --unset-password w.appvault; echo STATUS:$?"
        ))
        .finish();
    assert!(
        t.contains("app: --generate and --password-prompt exclude each other."),
        "{t}"
    );
    assert!(t.contains("app: --set-password and --unset-password exclude each other."));
    assert!(!t.contains("Vault password"));
    assert_eq!(t.matches("STATUS:1").count(), 2);
}

#[test]
fn int10_6_a_prompts_on_stderr_data_on_stdout() {
    let d = Dir::new("6a");
    let o = d.run(
        &["add", "-p", "w.appvault", "New1"],
        "demo-pass-4\nentry-pw\n",
    );
    assert_eq!(o.code, Some(0));
    assert_eq!(o.out, "New entry New1 saved.\n");
    assert_eq!(o.err, "Vault password for w.appvault: Entry password: ");
}

#[test]
fn int10_7_a_quiet_never_hides_errors() {
    let d = Dir::new("7a");
    let o = d.run(&["ls", "-q", "password-only.appvault"], "wrong\n");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: Wrong password, key file or security key. Check them and try again.\n"
    );
}

#[test]
fn int10_7_b_quiet_add_prints_nothing() {
    let d = Dir::new("7b");
    let o = d.run(&["add", "-q", "w.appvault", "Q1"], "demo-pass-4\n");
    assert_eq!(o.code, Some(0));
    assert!(
        o.out.is_empty() && o.err.is_empty(),
        "{} / {}",
        o.out,
        o.err
    );
    let o = d.run(&["ls", "-q", "w.appvault"], "demo-pass-4\n");
    assert!(lines(&o.out).contains(&"Q1"));
}

/// `h.txt`: the upper-case SHA-1 of demo-entry-pass-1, `:3`, CR LF.
fn hash_file(d: &Dir) {
    let h = app_crypto::hash::sha1(&[b"demo-entry-pass-1"]);
    let hex: String = h.expose().iter().map(|b| format!("{b:02X}")).collect();
    std::fs::write(d.path("h.txt"), format!("{hex}:3\r\n")).unwrap();
}

#[test]
fn int10_7_c_quiet_analyze_prints_only_findings() {
    let d = Dir::new("7c");
    hash_file(&d);
    let o = d.run(
        &["analyze", "-q", "-H", "h.txt", "password-only.appvault"],
        "demo-pass-1\n",
    );
    assert_eq!(o.code, Some(0));
    assert_eq!(o.out, "Leaked password: Demo login (in the list 3 times)\n");
}

#[test]
fn int10_8_a_exit_codes_are_0_and_1() {
    let d = Dir::new("8a");
    let o = d.run(&["search", "rich-v3.appvault", "zzzz"], "demo-pass-4\n");
    assert_eq!(o.code, Some(1));
    assert!(o.err.contains("app: no entry matches zzzz."));
    let o = d.run(&["ls"], "");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app ls: VAULT is missing. Run app help ls to see its options.\n"
    );
}

// ---------------------------------------------------------------------------
// INT-10.9 to INT-10.16: state, terminal text, unlocking, secrets.

fn tree(dir: &Path) -> Vec<PathBuf> {
    let mut all = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            all.extend(tree(&p));
        }
        all.push(p);
    }
    all
}

#[test]
fn int10_9_a_no_settings_no_history_written() {
    let d = Dir::new("9a");
    let o = d.run(&["db-create", "-p", "n.appvault"], "pw-a\npw-a\n");
    assert_eq!(o.code, Some(0), "{}", o.err);
    let o = d.run(&["add", "w.appvault", "S1"], "demo-pass-4\n");
    assert_eq!(o.code, Some(0));
    assert!(
        tree(&d.path("home")).is_empty(),
        "{:?}",
        tree(&d.path("home"))
    );
}

#[test]
fn int10_10_a_controls_escaped_on_a_terminal_exact_in_a_pipe() {
    let d = Dir::new("10a");
    let mut v = small_vault("x");
    // Protected, so the file keeps every character (a plain XML text
    // cannot hold an ESC).
    v.root.entries[0].set_field("Password".into(), field("Demo\x1b[31mred", true));
    store(&d.path("v.appvault"), &v, "demo-pass-1");
    let mut p = d.pty(&format!(
        "'{APP}' show -a Password v.appvault x; echo STATUS:$?"
    ));
    p.wait_for("Vault password for v.appvault: ");
    p.send("demo-pass-1\n");
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(t.contains("Demo\\x1b[31mred"), "{t}");
    assert!(!t.contains('\x1b'));
    let o = d.run(
        &["show", "-a", "Password", "v.appvault", "x"],
        "demo-pass-1\n",
    );
    assert!(o.raw.windows(9).any(|w| w == b"Demo\x1b[31m"));
}

#[test]
fn int10_11_a_vault_argument_checks() {
    let d = Dir::new("11a");
    let o = d.run(&["ls", "none.appvault"], "x\n");
    assert_eq!(
        (o.code, o.err.as_str()),
        (Some(1), "app: none.appvault does not exist.\n")
    );
    let folder = d.0.to_str().unwrap().to_owned();
    let o = d.run(&["ls", &folder], "x\n");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        format!("app: {folder} is not a vault file but a folder or special file.\n")
    );
    std::fs::copy(d.path("password-only.appvault"), d.path("c.appvault")).unwrap();
    std::fs::set_permissions(d.path("c.appvault"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let o = d.run(&["ls", "c.appvault"], "x\n");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: c.appvault cannot be read: permission denied.\n"
    );
}

#[test]
fn int10_12_a_no_echo_at_the_prompt_pty() {
    let d = Dir::new("12a");
    let mut p = d.pty(&format!(
        "'{APP}' ls password-only.appvault; echo STATUS:$?"
    ));
    p.wait_for("Vault password for password-only.appvault: ");
    p.send("demo-pass-1\n");
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(!t.contains("demo-pass-1"), "{t}");
    assert!(
        t.contains("Vault password for password-only.appvault: \nDemo login\n"),
        "{t}"
    );
    assert!(t.contains("STATUS:0"));
}

#[test]
fn int10_12_b_signal_at_the_prompt_restores_echo_pty() {
    let d = Dir::new("12b");
    let p = d.pty(&sh("ls password-only.appvault"));
    let pid = p.app_pid();
    p.wait_for("Vault password");
    thread::sleep(Duration::from_millis(400));
    kill("-INT", &pid);
    p.wait_for("lflags");
    let t = p.finish();
    assert!(t.contains("STATUS:130"), "{t}");
    assert!(echo_on(t.split("STATUS:").nth(1).unwrap()), "{t}");
}

#[test]
fn int10_12_c_line_end_removed_nothing_else() {
    let d = Dir::new("12c");
    let o = d.run(&["ls", "password-only.appvault"], "demo-pass-1\r\n");
    assert_eq!(o.code, Some(0));
    assert_eq!(o.out, "Demo login\n");
    let o = d.run(&["ls", "password-only.appvault"], "demo-pass-1 \n");
    assert_eq!(o.code, Some(1));
    assert!(o.err.contains("Wrong password, key file or security key."));
}

#[test]
fn int10_12_d_end_of_input_is_the_empty_password() {
    let d = Dir::new("12d");
    let o = d.run(&["db-create", "-p", "e.appvault"], "\ny\n");
    assert_eq!(o.code, Some(0), "{}", o.err);
    let o = d.run(&["ls", "e.appvault"], "");
    assert_eq!(o.code, Some(0), "{}", o.err);
    let o = d.run(&["ls", "--no-password", "e.appvault"], "");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: nothing to unlock e.appvault with. --no-password needs --key-file or --hw-key.\n"
    );
}

fn merge_pair(d: &Dir) {
    std::fs::copy(d.path("rich-v3.appvault"), d.path("m1.appvault")).unwrap();
    std::fs::copy(d.path("rich-v3.appvault"), d.path("m2.appvault")).unwrap();
    let o = d.run(&["add", "-q", "m2.appvault", "/Merged in"], "demo-pass-4\n");
    assert_eq!(o.code, Some(0));
}

#[test]
fn int10_12_e_target_line_then_source_line() {
    let d = Dir::new("12e");
    merge_pair(&d);
    let o = d.run(
        &["merge", "m1.appvault", "m2.appvault", "-d"],
        "demo-pass-4\ndemo-pass-4\n",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert_eq!(
        o.err,
        "Vault password for m1.appvault: Vault password for m2.appvault: "
    );
    assert_eq!(o.out.matches("\tAdded: ").count(), 1, "{}", o.out);
}

#[test]
fn int10_13_a_key_files_and_the_early_kind_note() {
    let d = Dir::new("13a");
    let args = [
        "ls",
        "--no-password",
        "-k",
        "key-hex64.appkey",
        "keyfile-hex64.appvault",
    ];
    let o = d.run(&args, "");
    assert_eq!((o.code, o.out.as_str()), (Some(0), "Demo login\n"));
    assert!(
        o.err
            .contains("Note: key-hex64.appkey is an early kind of key file.")
    );
    let o = d.run(&[&args[..], &["-q"]].concat(), "");
    assert_eq!((o.out.as_str(), o.err.as_str()), ("Demo login\n", ""));
    let o = d.run(
        &[
            "ls",
            "--no-password",
            "-k",
            "key-xml-v2.appkey",
            "keyfile-xml-v2.appvault",
        ],
        "",
    );
    assert_eq!((o.out.as_str(), o.err.as_str()), ("Demo login\n", ""));
}

#[test]
fn int10_13_b_vault_as_its_own_key_file() {
    let d = Dir::new("13b");
    let o = d.run(
        &[
            "ls",
            "-k",
            "password-only.appvault",
            "password-only.appvault",
        ],
        "demo-pass-1\n",
    );
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: This is the vault file itself, so it cannot also be its key file. Leave the key file empty if the vault has none.\n"
    );
}

#[test]
fn int10_13_c_key_file_errors() {
    let d = Dir::new("13c");
    std::fs::write(d.path("empty.appkey"), b"").unwrap();
    for (key, want) in [
        (
            "none.appkey",
            "The key file \"none.appkey\" cannot be found. Choose it again.",
        ),
        (
            "/tmp",
            "\"tmp\" is a folder or a special file. Choose a normal file as the key file.",
        ),
        (
            "empty.appkey",
            "The key file \"empty.appkey\" is empty. Choose the right key file.",
        ),
    ] {
        let o = d.run(
            &["ls", "-k", key, "password-only.appvault"],
            "demo-pass-1\n",
        );
        assert_eq!(o.code, Some(1));
        assert!(
            o.err.contains(&format!("app: {want}\n")),
            "{key}: {}",
            o.err
        );
    }
}

#[test]
fn int10_13_d_password_and_key_file() {
    let d = Dir::new("13d");
    let o = d.run(
        &[
            "ls",
            "-k",
            "key-hex64.appkey",
            "password-and-keyfile.appvault",
        ],
        "demo-pass-2\n",
    );
    assert_eq!((o.code, o.out.as_str()), (Some(0), "Demo login\n"));
    assert!(o.err.contains("is an early kind of key file"));
}

/// The slot check and the alias. The unlock with the software key is the
/// unit test `hwkey::tests::f_107_hw_key_unlocks_and_saves` (F-107). This
/// binary asks real USB keys, so the valid slot runs (LD-232 (6)) only when
/// IOKit lists no supported key (read from properties, nothing opened):
/// then slot 2 is accepted, reaches the key layer and gives M06-17. With a
/// key plugged in they are skipped, so no slot of the owner's key is
/// touched (OD-01).
#[test]
fn int10_14_a_hardware_key_slot_values() {
    use app_hwkey::Bus;
    let d = Dir::new("14a");
    for args in [
        &["ls", "--hw-key", "3", "w.appvault"][..],
        &["ls", "-y", "3", "w.appvault"],
    ] {
        let o = d.run(args, "demo-pass-4\n");
        assert_eq!(o.code, Some(1));
        assert_eq!(
            o.err,
            "app ls: 3 is not a slot (1 or 2) with an optional serial. Run app help ls to see its options.\n"
        );
    }
    let devices = app_hwkey::usb::UsbBus::new().list().unwrap();
    if devices.iter().any(|d| [0x1050, 0x1D50].contains(&d.vendor)) {
        eprintln!("int10_14_a: a security key is plugged in; the valid slot runs wait (OD-01)");
        return;
    }
    for args in [
        &["ls", "-y", "2", "w.appvault"][..],
        &["ls", "--yubikey", "2", "w.appvault"],
        &["ls", "--hw-key", "2", "w.appvault"],
    ] {
        let o = d.run(args, "demo-pass-4\n");
        assert_eq!(o.code, Some(1), "{args:?}");
        assert!(
            o.err
                .contains("Your security key is not connected. Plug it in, then try again."),
            "{args:?}: {}",
            o.err
        );
    }
}

#[test]
fn int10_15_a_slow_unlock_needs_the_flag() {
    let d = Dir::new("15a");
    let big = d.path("big.appvault");
    store(&big, &small_vault("x"), "demo-pass-1");
    // M = 2 GiB in the KDF map: type 0x05, name "M", 8-byte value.
    patch_header(&big, None, |h| {
        let key = [0x05, 1, 0, 0, 0, b'M', 8, 0, 0, 0];
        let at = h.windows(key.len()).position(|w| w == key).unwrap() + key.len();
        h[at..at + 8].copy_from_slice(&(2u64 << 30).to_le_bytes());
    });
    let start = Instant::now();
    let o = d.run(&["ls", "big.appvault"], "x\n");
    assert_eq!(o.code, Some(1));
    assert!(
        o.err
            .contains("app: unlocking big.appvault needs about 2.0 GiB of memory and about "),
        "{}",
        o.err
    );
    assert!(o.err.contains(
        ". Nothing was done. Run the command again with --allow-slow-unlock to go ahead.\n"
    ));
    assert!(start.elapsed() < Duration::from_secs(5), "no 2 GiB KDF ran");
    let o = d.run(&["ls", "--allow-slow-unlock", "big.appvault"], "x\n");
    assert_eq!(o.code, Some(1));
    assert!(
        o.err
            .contains("app: Wrong password, key file or security key."),
        "{}",
        o.err
    );
}

#[test]
fn int10_15_b_not_a_vault_and_damaged() {
    let d = Dir::new("15b");
    std::fs::write(d.path("notvault.appvault"), b"hello").unwrap();
    let bytes = std::fs::read(d.path("password-only.appvault")).unwrap();
    std::fs::write(d.path("cut.appvault"), &bytes[..200]).unwrap();
    let o = d.run(&["ls", "notvault.appvault"], "x\n");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with(
        "app: \"notvault.appvault\" is not a vault file. Open the file that holds your vault.\n"
    ));
    let o = d.run(&["ls", "cut.appvault"], "x\n");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with(
        "app: \"cut.appvault\" is damaged and cannot be unlocked. If you have a backup copy, open that instead.\n"
    ));
}

#[test]
fn int10_15_c_key_change_notice() {
    let d = Dir::new("15c");
    let mut v = small_vault("Due");
    v.meta.master_key_change_rec = 1;
    v.meta.master_key_changed = Time::from_unix(1_600_000_000).unwrap();
    store(&d.path("t30.appvault"), &v, "demo-pass-1");
    let o = d.run(&["ls", "t30.appvault"], "demo-pass-1\n");
    assert_eq!((o.code, o.out.as_str()), (Some(0), "Due\n"));
    assert_eq!(
        o.err
            .matches("Note: a master key change is recommended")
            .count(),
        1,
        "{}",
        o.err
    );
    let o = d.run(&["ls", "-q", "t30.appvault"], "demo-pass-1\n");
    assert_eq!((o.out.as_str(), o.err.as_str()), ("Due\n", ""));
}

#[test]
fn int10_15_d_newer_version_note() {
    let d = Dir::new("15d");
    let p = d.path("v42.appvault");
    store(&p, &small_vault("Demo login"), "demo-pass-1");
    patch_header(&p, Some("demo-pass-1"), |h| {
        h[8..10].copy_from_slice(&2u16.to_le_bytes())
    });
    let o = d.run(&["ls", "v42.appvault"], "demo-pass-1\n");
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(o.err.contains(
        "Note: v42.appvault uses a newer vault format than App knows. Saving may lose settings that only the newer format holds."
    ));
    assert_eq!(o.out, "Demo login\n");
}

#[test]
fn int10_16_a_no_secret_in_arguments_or_environment() {
    let d = Dir::new("16a");
    let o = d.run(&["estimate", "demo-pass-1"], "");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: estimate does not take the password as an argument, because other programs can read arguments. Pipe it in, or type it at the prompt.\n"
    );
    // Code review, automated: no option that names a password takes a value,
    // and the only environment variables read are TZ and the debug-only
    // test switches.
    for c in C01_TO_C26 {
        let help = d.run(&["help", c], "").out;
        for line in help
            .lines()
            .filter(|l| l.starts_with("  -") && l.contains("password"))
        {
            let opt = line.split("  ").find(|p| !p.is_empty()).unwrap_or("");
            assert!(!opt.chars().any(|c| c.is_ascii_uppercase()), "{c}: {line}");
        }
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for f in std::fs::read_dir(src).unwrap() {
        let code = std::fs::read_to_string(f.unwrap().path()).unwrap();
        for (i, _) in code.match_indices("env::var") {
            let call = &code[i..code[i..].find(')').map_or(code.len(), |e| i + e)];
            assert!(
                [
                    "\"TZ\"",
                    "\"APP_TEST_PASTEBOARD\"",
                    "\"APP_TEST_SELF_TEST_FAIL\""
                ]
                .iter()
                .any(|n| call.contains(n)),
                "{call}"
            );
        }
    }
}

#[test]
fn int10_16_b_generated_password_never_printed() {
    let d = Dir::new("16b");
    let o = d.run(&["add", "-g", "w.appvault", "G1"], "demo-pass-4\n");
    assert_eq!(o.code, Some(0));
    let pw = d
        .run(
            &["show", "-a", "Password", "w.appvault", "G1"],
            "demo-pass-4\n",
        )
        .out;
    let pw = pw.trim_end();
    assert_eq!(pw.chars().count(), 32);
    assert!(!o.out.contains(pw) && !o.err.contains(pw));
}

// ---------------------------------------------------------------------------
// INT-10.17 to INT-10.20: paths and saving.

#[test]
fn int10_17_a_three_paths_one_entry() {
    let d = Dir::new("17a");
    for path in [
        "Server login",
        "Work/Servers/Server login",
        "/Work/Servers/Server login",
    ] {
        let o = d.run(
            &["show", "-a", "UserName", "rich-v3.appvault", path],
            "demo-pass-4\n",
        );
        assert_eq!(o.out, "admin\n", "{path}");
    }
}

#[test]
fn int10_17_b_partial_path_not_found() {
    let d = Dir::new("17b");
    let o = d.run(
        &["show", "rich-v3.appvault", "Servers/Server login"],
        "demo-pass-4\n",
    );
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with("app: no entry at Servers/Server login.\n"));
}

#[test]
fn int10_17_c_title_only_path_finds_a_deeper_entry() {
    let d = Dir::new("17c");
    let o = d.run(&["add", "w.appvault", "Server login"], "demo-pass-4\n");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with(
        "app: an entry is already found at Server login. To add one in the root group, start the path with /.\n"
    ));
    let o = d.run(&["add", "w.appvault", "/Server login"], "demo-pass-4\n");
    assert_eq!(o.code, Some(0));
    let v = load(&d.path("w.appvault"), "demo-pass-4");
    assert!(
        v.root
            .entries
            .iter()
            .any(|e| e.value("Title") == "Server login")
    );
}

#[test]
fn int10_17_d_slash_in_a_title_and_the_untitled_entry() {
    let d = Dir::new("17d");
    std::fs::copy(d.path("rich-v3.appvault"), d.path("s.appvault")).unwrap();
    let o = d.run(
        &[
            "edit",
            "-t",
            "Work/Servers/Server login",
            "s.appvault",
            "Full demo entry",
        ],
        "demo-pass-4\n",
    );
    assert_eq!(o.code, Some(0));
    let o = d.run(
        &[
            "show",
            "-a",
            "Uuid",
            "s.appvault",
            "Work/Servers/Server login",
        ],
        "demo-pass-4\n",
    );
    assert_eq!(o.out, "{00000000-0000-0000-0000-00000000000a}\n");
    let o = d.run(
        &["show", "-a", "Uuid", "rich-v3.appvault", "/"],
        "demo-pass-4\n",
    );
    assert_eq!(o.out, "{00000000-0000-0000-0000-00000000000f}\n");
}

#[test]
fn int10_18_a_group_paths() {
    let d = Dir::new("18a");
    let ls = |g: &str| d.run(&["ls", "rich-v3.appvault", g], "demo-pass-4\n").out;
    let servers = ls("Work/Servers");
    assert_eq!(servers, "Server login\nOld servers/\n");
    assert_eq!(ls("/Work/Servers/"), servers);
    assert_eq!(ls("Work/Servers/"), servers);
    let root = d.run(&["ls", "rich-v3.appvault"], "demo-pass-4\n").out;
    assert_eq!(ls("/"), root);
    assert_eq!(ls(""), root);
}

#[test]
fn int10_19_a_search_paths() {
    let d = Dir::new("19a");
    let o = d.run(&["search", "rich-v3.appvault", "server"], "demo-pass-4\n");
    assert_eq!(
        o.out,
        "/Work/Servers/Server login\n/Work/Servers/Old servers/Old server\n"
    );
}

#[test]
fn int10_20_a_save_keeps_the_mode() {
    let d = Dir::new("20a");
    let w = d.path("w.appvault");
    std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = d.run(&["add", "w.appvault", "S2"], "demo-pass-4\n");
    assert_eq!(o.code, Some(0));
    assert_eq!(mode(&w), 0o644);
    let bytes = std::fs::read(&w).unwrap();
    let h = app_format::header::read_header(&bytes, &Limits::DEFAULT).unwrap();
    assert!(
        matches!((h.major, h.minor), (3, 1) | (4, 0) | (4, 1)),
        "{}.{}",
        h.major,
        h.minor
    );
    let o = d.run(&["ls", "w.appvault"], "demo-pass-4\n");
    assert!(lines(&o.out).contains(&"S2"));
}

#[test]
fn int10_20_b_change_on_disk_is_not_overwritten() {
    let d = Dir::new("20b");
    let mut p = d.spawn(&["add", "-p", "w.appvault", "S3"], &[]);
    p.send("demo-pass-4\n");
    wait_for(&p.err, "Entry password: ");
    let other = std::fs::read(d.path("password-only.appvault")).unwrap();
    std::fs::write(d.path("w.appvault"), &other).unwrap();
    p.send("entry-pw\n");
    let (code, out, err) = p.finish();
    assert_eq!(code, Some(1));
    assert!(out.is_empty());
    assert!(err.ends_with(
        "app: w.appvault changed on disk while this command ran. Nothing was saved; run the command again.\n"
    ), "{err}");
    assert_eq!(std::fs::read(d.path("w.appvault")).unwrap(), other);
}

#[test]
fn int10_20_c_save_failure_leaves_the_file() {
    let d = Dir::new("20c");
    let sub = d.path("ro");
    std::fs::create_dir(&sub).unwrap();
    std::fs::copy(d.path("rich-v3.appvault"), sub.join("w.appvault")).unwrap();
    let before = std::fs::read(sub.join("w.appvault")).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)).unwrap();
    let o = d.run(&["add", "ro/w.appvault", "S4"], "demo-pass-4\n");
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(o.code, Some(1));
    assert!(
        o.err.ends_with(
            "app: could not save ro/w.appvault: permission denied. The file on disk is unchanged.\n"
        ),
        "{}",
        o.err
    );
    assert_eq!(std::fs::read(sub.join("w.appvault")).unwrap(), before);
}

// ---------------------------------------------------------------------------
// INT-10.21 to INT-10.27: add, edit, mkdir, mv, rm, rmdir, ls.

#[test]
fn int10_21_a_fields_of_a_new_entry() {
    let d = Dir::new("21a");
    let o = d.run(
        &[
            "add",
            "w.appvault",
            "New1",
            "-u",
            "u1",
            "--url",
            "https://example.com/n",
            "--notes",
            "a\\nb",
        ],
        "demo-pass-4\n",
    );
    assert_eq!(
        (o.code, o.out.as_str()),
        (Some(0), "New entry New1 saved.\n")
    );
    let o = d.run(
        &[
            "show",
            "-a",
            "UserName",
            "-a",
            "URL",
            "-a",
            "Notes",
            "w.appvault",
            "New1",
        ],
        "demo-pass-4\n",
    );
    assert_eq!(o.out, "u1\nhttps://example.com/n\na\nb\n");
}

#[test]
fn int10_21_b_no_default_user_name() {
    let d = Dir::new("21b");
    assert_eq!(
        load(&d.path("w.appvault"), "demo-pass-4")
            .meta
            .default_user_name,
        "demo-user"
    );
    d.run(&["add", "w.appvault", "E2"], "demo-pass-4\n");
    let o = d.run(
        &["show", "-a", "UserName", "w.appvault", "E2"],
        "demo-pass-4\n",
    );
    assert_eq!((o.code, o.out.as_str()), (Some(0), "\n"));
}

#[test]
fn int10_21_c_generated_password_and_a_bad_length() {
    let d = Dir::new("21c");
    let o = d.run(
        &["add", "-g", "-L", "12", "-n", "w.appvault", "Gen1"],
        "demo-pass-4\n",
    );
    assert_eq!(o.code, Some(0));
    let pw = d
        .run(
            &["show", "-a", "Password", "w.appvault", "Gen1"],
            "demo-pass-4\n",
        )
        .out;
    let pw = pw.trim_end();
    assert!(
        pw.len() == 12 && pw.chars().all(|c| c.is_ascii_digit()),
        "{pw}"
    );
    let o = d.run(
        &["add", "-g", "-L", "0", "w.appvault", "G0"],
        "demo-pass-4\n",
    );
    assert_eq!(o.code, Some(1));
    assert_eq!(o.err, "app: 0 is not a usable length.\n");
}

#[test]
fn int10_21_d_missing_group() {
    let d = Dir::new("21d");
    let o = d.run(&["add", "w.appvault", "Nogroup/X"], "demo-pass-4\n");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with("app: no group at Nogroup.\n"));
}

#[test]
fn int10_22_a_nothing_to_change_before_the_prompt_pty() {
    let d = Dir::new("22a");
    let t = d.pty(&sh("edit w.appvault 'Full demo entry'")).finish();
    assert!(t.contains(
        "app: nothing to change in Full demo entry. Give --title, --username, --url, --notes, --password-prompt or --generate."
    ), "{t}");
    assert!(!t.contains("Vault password"));
    assert!(t.contains("STATUS:1"));
}

#[test]
fn int10_22_b_empty_value_counts_as_not_given() {
    let d = Dir::new("22b");
    let w = d.path("w.appvault");
    let before = full_demo_history(&w);
    let o = d.run(
        &[
            "edit",
            "-t",
            "Renamed",
            "-u",
            "",
            "w.appvault",
            "Full demo entry",
        ],
        "demo-pass-4\n",
    );
    assert_eq!(
        (o.code, o.out.as_str()),
        (Some(0), "Changes to Renamed saved.\n")
    );
    let v = load(&w, "demo-pass-4");
    assert_eq!(find(&v, "Renamed").value("UserName"), "demo-user");
    assert_eq!(full_demo_history(&w), before + 1);
}

#[test]
fn int10_22_c_same_value_no_history_item() {
    let d = Dir::new("22c");
    let w = d.path("w.appvault");
    let before = full_demo_history(&w);
    let o = d.run(
        &["edit", "-u", "demo-user", "w.appvault", "Full demo entry"],
        "demo-pass-4\n",
    );
    assert_eq!(o.code, Some(0));
    assert_eq!(full_demo_history(&w), before);
}

#[test]
fn int10_23_a_mkdir() {
    let d = Dir::new("23a");
    let mk = |g: &str| d.run(&["mkdir", "w.appvault", g], "demo-pass-4\n");
    assert_eq!(mk("Work/New").out, "New group New saved.\n");
    let o = mk("Work/New");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with("app: a group Work/New is already there.\n"));
    let o = mk("Nope/New");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with("app: no group at Nope.\n"));
    assert_eq!(mk("/Top/").out, "New group Top saved.\n");
    let v = load(&d.path("w.appvault"), "demo-pass-4");
    assert!(v.root.groups.iter().any(|g| g.name == "Top"));
}

#[test]
fn int10_24_a_mv() {
    let d = Dir::new("24a");
    d.run(&["add", "-g", "w.appvault", "Gen1"], "demo-pass-4\n");
    let mv = |g: &str| d.run(&["mv", "w.appvault", "Gen1", g], "demo-pass-4\n");
    assert_eq!(mv("Work").out, "Gen1 moved to Work.\n");
    let v = load(&d.path("w.appvault"), "demo-pass-4");
    let work = v.root.groups.iter().find(|g| g.name == "Work").unwrap();
    let gen1 = work
        .entries
        .iter()
        .find(|e| e.value("Title") == "Gen1")
        .unwrap();
    assert_eq!(gen1.history.len(), 0);
    let o = mv("Work");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with("app: nothing to move: Gen1 is in Work.\n"));
    let o = mv("Nope");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with("app: no group at Nope.\n"));
}

#[test]
fn int10_25_a_rm_to_the_bin_then_for_good() {
    let d = Dir::new("25a");
    let w = d.path("w.appvault");
    d.run(
        &["add", "-g", "-L", "12", "-n", "w.appvault", "Gen1"],
        "demo-pass-4\n",
    );
    let records = load(&w, "demo-pass-4").deleted_objects.len();
    let rm = |e: &str| d.run(&["rm", "w.appvault", e], "demo-pass-4\n");
    assert_eq!(rm("Gen1").out, "Gen1 moved to the recycle bin.\n");
    assert_eq!(rm("Recycle Bin/Gen1").out, "Gen1 deleted for good.\n");
    assert_eq!(load(&w, "demo-pass-4").deleted_objects.len(), records + 1);
    let o = rm("Gen1");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with("app: no entry at Gen1.\n"));
}

#[test]
fn int10_25_b_rm_with_the_bin_off() {
    let d = Dir::new("25b");
    let p = d.path("p.appvault");
    let mut v = load(&d.path("password-only.appvault"), "demo-pass-1");
    v.meta.recycle_bin_enabled = false;
    store(&p, &v, "demo-pass-1");
    let o = d.run(&["rm", "p.appvault", "Demo login"], "demo-pass-1\n");
    assert_eq!(
        (o.code, o.out.as_str()),
        (Some(0), "Demo login deleted for good.\n")
    );
}

#[test]
fn int10_26_a_rmdir_and_the_root() {
    let d = Dir::new("26a");
    let o = d.run(&["rmdir", "w.appvault", "Personal"], "demo-pass-4\n");
    assert_eq!(o.out, "Group Personal moved to the recycle bin.\n");
    for g in ["/", ""] {
        let o = d.run(&["rmdir", "w.appvault", g], "demo-pass-4\n");
        assert_eq!(o.code, Some(1));
        assert_eq!(
            o.err,
            "app: the root group belongs to every vault and cannot be removed.\n"
        );
    }
}

#[test]
fn int10_26_b_group_holding_the_bin() {
    let d = Dir::new("26b");
    let w = d.path("w.appvault");
    let mut v = load(&w, "demo-pass-4");
    let bin = v.meta.recycle_bin.unwrap();
    let i = v.root.groups.iter().position(|g| g.uuid == bin).unwrap();
    let bin_group = v.root.groups.remove(i);
    v.root
        .groups
        .iter_mut()
        .find(|g| g.name == "Personal")
        .unwrap()
        .groups
        .push(bin_group);
    store(&w, &v, "demo-pass-4");
    let start = Instant::now();
    let o = d.run(&["rmdir", "w.appvault", "Personal"], "demo-pass-4\n");
    assert!(start.elapsed() < Duration::from_secs(10));
    assert_eq!(
        (o.code, o.out.as_str()),
        (Some(0), "Group Personal deleted for good.\n"),
        "{}",
        o.err
    );
    let v = load(&w, "demo-pass-4");
    assert!(
        v.root
            .subtree()
            .iter()
            .all(|g| g.name != "Personal" && g.uuid != bin)
    );
}

#[test]
fn int10_27_a_ls_plain_recursive_flat() {
    let d = Dir::new("27a");
    let o = d.run(&["ls", "rich-v3.appvault"], "demo-pass-4\n");
    let l = lines(&o.out);
    assert_eq!(l.len(), 9, "{}", o.out);
    assert_eq!(l[5], "");
    assert_eq!(&l[6..], ["Work/", "Personal/", "Recycle Bin/"]);
    let o = d.run(&["ls", "-R", "rich-v3.appvault"], "demo-pass-4\n");
    assert!(o.out.contains("Personal/\n  (empty group)\n"), "{}", o.out);
    assert!(o.out.contains("Work/\n  Servers/\n    Server login\n"));
    let o = d.run(&["ls", "-R", "-f", "rich-v3.appvault"], "demo-pass-4\n");
    assert!(lines(&o.out).contains(&"Work/Servers/Old servers/Old server"));
    assert!(lines(&o.out).contains(&"Personal/(empty group)"));
}

// ---------------------------------------------------------------------------
// INT-10.28 show.

#[test]
fn int10_28_a_seven_lines() {
    let d = Dir::new("28a");
    let o = d.run(
        &["show", "rich-v3.appvault", "Full demo entry"],
        "demo-pass-4\n",
    );
    assert_eq!(o.code, Some(0));
    let l = lines(&o.out);
    assert_eq!(l[0], "Title: Full demo entry");
    assert_eq!(l[1], "UserName: demo-user");
    assert_eq!(l[2], "Password: (hidden)");
    assert!(l[4].starts_with("Notes: "));
    assert_eq!(l.len(), 10, "notes over four lines: {}", o.out);
    assert_eq!(l[8], "Uuid: {00000000-0000-0000-0000-00000000000a}");
    assert_eq!(l[9], "Tags: demo,work");
}

#[test]
fn int10_28_b_all_fields_sorted() {
    let d = Dir::new("28b");
    let o = d.run(
        &["show", "--all", "rich-v3.appvault", "Full demo entry"],
        "demo-pass-4\n",
    );
    let tail: Vec<&str> = lines(&o.out)[10..].to_vec();
    assert_eq!(
        tail,
        [
            "Demo PIN: (hidden)",
            "Demo hint: not protected",
            "Empty custom field: ",
            "Spaces:   leading and trailing  ",
            "otp: (hidden)",
        ]
    );
}

#[test]
fn int10_28_c_show_protected() {
    let d = Dir::new("28c");
    let o = d.run(
        &["show", "-s", "rich-v3.appvault", "Full demo entry"],
        "demo-pass-4\n",
    );
    assert!(lines(&o.out).contains(&"Password: demo-entry-pass-2"));
}

#[test]
fn int10_28_d_named_fields() {
    let d = Dir::new("28d");
    let o = d.run(
        &[
            "show",
            "-a",
            "Password",
            "-a",
            "username",
            "-a",
            "demo pin",
            "-a",
            "uuid",
            "rich-v3.appvault",
            "Full demo entry",
        ],
        "demo-pass-4\n",
    );
    assert_eq!(o.code, Some(1));
    assert_eq!(o.out, "demo-entry-pass-2\ndemo-user\n0000\n");
    assert!(
        o.err
            .ends_with("app: Full demo entry has no field called uuid.\n")
    );
}

fn current_code(d: &Dir) -> String {
    let v = load(&d.path("rich-v3.appvault"), "demo-pass-4");
    let code = app_core::totp::code_for(find(&v, "Full demo entry"), now()).unwrap();
    code.expose().to_owned()
}

#[test]
fn int10_28_e_one_time_password() {
    let d = Dir::new("28e");
    let before = current_code(&d);
    let o = d.run(
        &["show", "-t", "rich-v3.appvault", "Full demo entry"],
        "demo-pass-4\n",
    );
    let after = current_code(&d);
    let code = o.out.trim_end();
    assert!(code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()));
    assert!(code == before || code == after, "{code} {before} {after}");
    let o = d.run(
        &["show", "-t", "rich-v3.appvault", "Server login"],
        "demo-pass-4\n",
    );
    assert_eq!(o.code, Some(1));
    assert!(o.out.is_empty());
    assert!(
        o.err
            .ends_with("app: Server login has no one-time password.\n")
    );
}

#[test]
fn int10_28_f_attachments() {
    let d = Dir::new("28f");
    let o = d.run(
        &[
            "show",
            "--show-attachments",
            "rich-v3.appvault",
            "Full demo entry",
        ],
        "demo-pass-4\n",
    );
    assert!(o.out.ends_with(
        "Tags: demo,work\n\nAttached files:\n  bytes.bin (256 B)\n  empty.bin (0 B)\n  notes.txt (20 B)\n"
    ), "{}", o.out);
}

#[test]
fn int10_28_g_ambiguous_field_name() {
    let d = Dir::new("28g");
    let p = d.path("pin.appvault");
    let mut v = load(&d.path("password-only.appvault"), "demo-pass-1");
    let e = find_mut(&mut v.root, "Demo login").unwrap();
    e.set_field("pin".into(), field("1", false));
    e.set_field("PIN".into(), field("2", false));
    store(&p, &v, "demo-pass-1");
    let o = d.run(
        &["show", "-a", "Pin", "pin.appvault", "Demo login"],
        "demo-pass-1\n",
    );
    assert_eq!(o.code, Some(1));
    assert!(
        o.err
            .ends_with("app: Pin could mean any of PIN, pin. Give the exact name.\n"),
        "{}",
        o.err
    );
}

/// LD-172: R10-1, an ENTRY with no title is refused before any prompt
/// (M10-26); R10-2, without `-s` a part that resolves from a protected
/// value prints as (hidden), while `-s` and `-a` resolve in full.
#[test]
fn ld172_no_title_and_masked_references() {
    let d = Dir::new("ld172");
    for path in ["Personal/", ""] {
        let o = d.run(&["add", "w.appvault", path], "demo-pass-4\n");
        assert_eq!(o.code, Some(1));
        assert_eq!(
            o.err,
            format!("app: {path} gives no title for the new entry.\n")
        );
    }
    let p = d.path("ref.appvault");
    let mut v = load(&d.path("password-only.appvault"), "demo-pass-1");
    let e = find_mut(&mut v.root, "Demo login").unwrap();
    e.set_field(
        "URL".into(),
        field("https://h.example/?p={PASSWORD}", false),
    );
    store(&p, &v, "demo-pass-1");
    let show = |extra: &[&str]| {
        let args = [&["show"][..], extra, &["ref.appvault", "Demo login"]].concat();
        d.run(&args, "demo-pass-1\n").out
    };
    assert!(show(&[]).contains("URL: https://h.example/?p=(hidden)\n"));
    assert!(show(&["-s"]).contains("URL: https://h.example/?p=demo-entry-pass-1\n"));
    assert_eq!(
        show(&["-a", "URL"]),
        "https://h.example/?p=demo-entry-pass-1\n"
    );
}

// ---------------------------------------------------------------------------
// INT-10.29 clip, on the private pasteboard of the process under test.

#[test]
fn int10_29_a_copied_with_markers_then_emptied() {
    let d = Dir::new("29a");
    let mut p = d.spawn(&["clip", "w.appvault", "Full demo entry", "2"], PB);
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-4\n");
    wait_for(&p.out, "copied.");
    let copied = Instant::now();
    let items = pasteboard::items(&name);
    let mut kinds: Vec<&str> = items[0].iter().map(|(k, _)| k.as_str()).collect();
    kinds.sort_unstable();
    assert_eq!(
        kinds,
        [
            "org.nspasteboard.ConcealedType",
            "org.nspasteboard.TransientType",
            pasteboard::TEXT
        ]
    );
    assert_eq!(
        pasteboard::text(&name).as_deref(),
        Some("demo-entry-pass-2")
    );
    let (code, out, _) = p.finish();
    let waited = copied.elapsed();
    assert!(
        waited > Duration::from_millis(1500) && waited < Duration::from_millis(2600),
        "{waited:?}"
    );
    assert_eq!(code, Some(0));
    assert!(pasteboard::items(&name).is_empty());
    assert_eq!(
        out,
        "Password of Full demo entry copied. The clipboard is emptied in 2 seconds.\nThe clipboard is empty again.\n"
    );
    pasteboard::release(&name);
}

/// M10-69 on a terminal: one line rewritten each second, on stderr.
#[test]
fn int10_29_a_countdown_on_a_terminal_pty() {
    let d = Dir::new("29a-pty");
    let mut p = d.pty(&format!(
        "APP_TEST_PASTEBOARD=1 '{APP}' clip w.appvault 'Full demo entry' 2; echo STATUS:$?"
    ));
    p.wait_for("Vault password for w.appvault: ");
    p.send("demo-pass-4\n");
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(
        t.contains("\r2 s left before the clipboard is emptied\x1b[K"),
        "{t:?}"
    );
    assert!(t.contains("\r1 s left before the clipboard is emptied\x1b[K"));
    assert!(
        t.contains("The clipboard is empty again.\nSTATUS:0"),
        "{t:?}"
    );
}

#[test]
fn int10_29_b_newer_content_is_left_alone() {
    let d = Dir::new("29b");
    let mut p = d.spawn(&["clip", "w.appvault", "Full demo entry", "2"], PB);
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-4\n");
    wait_for(&p.out, "copied.");
    thread::sleep(Duration::from_secs(1));
    pasteboard::write_other(&name, "other");
    let (code, out, _) = p.finish();
    assert_eq!(code, Some(0));
    assert_eq!(pasteboard::text(&name).as_deref(), Some("other"));
    assert!(out.ends_with("The clipboard holds something else now and was left as it is.\n"));
    pasteboard::release(&name);
}

#[test]
fn int10_29_c_zero_seconds_leaves_the_value() {
    let d = Dir::new("29c");
    let mut p = d.spawn(&["clip", "w.appvault", "Full demo entry", "0"], PB);
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-4\n");
    let (code, out, _) = p.finish();
    assert_eq!(code, Some(0));
    assert_eq!(
        out,
        "Password of Full demo entry copied. The clipboard is not emptied.\n"
    );
    assert_eq!(
        pasteboard::text(&name).as_deref(),
        Some("demo-entry-pass-2")
    );
    pasteboard::release(&name);
}

/// INT-10.29-h, APP-03.5: an empty value copies nothing; the pasteboard is
/// left as it was (LD-200 (8)).
#[test]
fn int10_29_h_empty_value_copies_nothing() {
    let d = Dir::new("29h");
    let mut p = d.spawn(
        &[
            "clip",
            "-a",
            "Empty custom field",
            "w.appvault",
            "Full demo entry",
            "2",
        ],
        PB,
    );
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-4\n");
    let (code, out, err) = p.finish();
    assert_eq!(code, Some(1));
    assert_eq!(out, "");
    assert!(err.contains("is empty. Nothing to copy."), "{err}");
    assert_eq!(pasteboard::text(&name), None);
    pasteboard::release(&name);
}

/// SC-07: a quit signal during the wait clears the pasteboard at once,
/// then the process ends by that signal.
#[test]
fn int10_29_d_quit_signal_clears_at_once() {
    use std::os::unix::process::ExitStatusExt;
    let d = Dir::new("29d");
    let mut p = d.spawn(&["clip", "w.appvault", "Full demo entry", "30"], PB);
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-4\n");
    wait_for(&p.out, "copied.");
    assert_eq!(
        pasteboard::text(&name).as_deref(),
        Some("demo-entry-pass-2")
    );
    thread::sleep(Duration::from_secs(1));
    kill("-INT", &p.child.id().to_string());
    let sent = Instant::now();
    let status = wait_child(&mut p.child);
    assert!(
        sent.elapsed() < Duration::from_secs(3),
        "{:?}",
        sent.elapsed()
    );
    assert_eq!(status.signal(), Some(2), "{status:?}");
    assert!(pasteboard::items(&name).is_empty());
    assert!(!text(&p.out).contains("The clipboard is empty again."));
    pasteboard::release(&name);
}

#[test]
fn int10_29_e_one_time_password_and_the_conflict() {
    let d = Dir::new("29e");
    let before = current_code(&d);
    let mut p = d.spawn(&["clip", "-t", "w.appvault", "Full demo entry", "0"], PB);
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-4\n");
    let (code, _, _) = p.finish();
    let after = current_code(&d);
    assert_eq!(code, Some(0));
    let copied = pasteboard::text(&name).unwrap();
    assert!(copied == before || copied == after, "{copied}");
    pasteboard::release(&name);
    let o = d.run_env(
        &["clip", "-a", "Title", "-t", "w.appvault", "Full demo entry"],
        "demo-pass-4\n",
        PB,
    );
    assert_eq!(o.code, Some(1));
    assert_eq!(o.err, "app: --attribute and --totp exclude each other.\n");
}

#[test]
fn int10_29_f_best_match() {
    let d = Dir::new("29f");
    let mut p = d.spawn(&["clip", "-b", "w.appvault", "Old serv", "0"], PB);
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-4\n");
    let (code, out, _) = p.finish();
    assert_eq!(code, Some(0));
    assert!(
        out.starts_with("Best match: /Work/Servers/Old servers/Old server.\n"),
        "{out}"
    );
    pasteboard::release(&name);
    let mut p = d.spawn(&["clip", "-b", "w.appvault", "e"], PB);
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-4\n");
    let (code, out, err) = p.finish();
    assert_eq!(code, Some(1));
    assert!(out.is_empty());
    assert!(
        err.contains("entries match e:\n/Full demo entry\n"),
        "{err}"
    );
    assert!(pasteboard::items(&name).is_empty());
    pasteboard::release(&name);
}

#[test]
fn int10_29_g_unknown_field_on_stderr() {
    let d = Dir::new("29g");
    let o = d.run_env(
        &["clip", "-a", "nothere", "w.appvault", "Full demo entry"],
        "demo-pass-4\n",
        PB,
    );
    assert_eq!(o.code, Some(1));
    assert!(o.out.is_empty());
    assert!(
        o.err
            .ends_with("app: Full demo entry has no field called nothere.\n")
    );
}

// ---------------------------------------------------------------------------
// INT-10.30 to INT-10.36: search, db-info, analyze, estimate, generate,
// passphrase, export.

#[test]
fn int10_30_a_bin_never_group_flags_ignored() {
    let d = Dir::new("30a");
    let o = d.run(&["search", "rich-v3.appvault", "deleted"], "demo-pass-4\n");
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with("app: no entry matches deleted.\n"));
    let o = d.run(&["search", "rich-v3.appvault", "server"], "demo-pass-4\n");
    assert_eq!(o.out.lines().filter(|l| l.starts_with("/Work/")).count(), 2);
}

#[test]
fn int10_30_b_expired_entries() {
    let d = Dir::new("30b");
    let o = d.run(
        &["search", "option-a-personal.appvault", "is:expired"],
        "demo-pass-7\n",
    );
    // The same list from the engine: live entries outside the bin past expiry.
    let v = load(&d.path("option-a-personal.appvault"), "demo-pass-7");
    let bin = v.meta.recycle_bin;
    let at = CoreInstant::from(now());
    let mut want = Vec::new();
    fn walk(g: &Group, path: &str, bin: Option<Uuid>, at: CoreInstant, out: &mut Vec<String>) {
        if Some(g.uuid) == bin {
            return;
        }
        for e in &g.entries {
            if app_core::expiry::is_expired(&e.times, at) {
                out.push(format!("{path}/{}", e.value("Title")));
            }
        }
        for c in &g.groups {
            walk(c, &format!("{path}/{}", c.name), bin, at, out);
        }
    }
    walk(&v.root, "", bin, at, &mut want);
    assert!(!want.is_empty());
    assert_eq!(lines(&o.out), want);
}

#[test]
fn int10_31_a_db_info() {
    let d = Dir::new("31a");
    let o = d.run_env(
        &["db-info", "rich-v4.appvault"],
        "demo-pass-5\n",
        &[("TZ", "Europe/Berlin")],
    );
    assert_eq!(o.code, Some(0));
    for want in [
        "Name: Rich demo\n",
        "Cipher: AES-256\n",
        "Key derivation: AES-KDF, ",
        "Recycle bin: on\n",
        "File: rich-v4.appvault\n",
        "Created on: 2024-01-01T01:00:00+01:00\n",
        "Changes not saved yet: no\n",
        "Groups: 5\n",
        "Entries: 8\n",
        "Past expiry: 1\n",
        "Different passwords: 5\n",
        "Repeated passwords: 0\n",
        "Most uses of one password: 1\n",
        "Under 8 characters: 0\n",
        "Rated below Good: 4\n",
        "Skipped in reports: 1\n",
        "Length on average: 15 characters\n",
        "Passkey entries: 0\n",
        "One-time code entries: 1\n",
    ] {
        assert!(o.out.contains(want), "{want}\n{}", o.out);
    }
    let saved = o
        .out
        .lines()
        .find(|l| l.starts_with("Most recent save: "))
        .unwrap();
    assert!(
        saved.ends_with("+01:00") || saved.ends_with("+02:00"),
        "{saved}"
    );
    assert!(!o.out.to_lowercase().contains("id:"));
}

#[test]
fn int10_32_a_offline_check() {
    let d = Dir::new("32a");
    hash_file(&d);
    let o = d.run(
        &["analyze", "-H", "h.txt", "password-only.appvault"],
        "demo-pass-1\n",
    );
    assert_eq!(o.code, Some(0));
    assert_eq!(
        o.out,
        "Checking every password against h.txt. This can need minutes for a big list.\nLeaked password: Demo login (in the list 3 times)\n"
    );
}

#[test]
fn int10_32_b_hash_file_option() {
    let d = Dir::new("32b");
    hash_file(&d);
    let o = d.run(&["analyze", "password-only.appvault"], "demo-pass-1\n");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: give the list of leaked hashes with --hash-file FILE.\n"
    );
    let o = d.run(
        &[
            "analyze",
            "--okon",
            "x",
            "-H",
            "h.txt",
            "password-only.appvault",
        ],
        "demo-pass-1\n",
    );
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app analyze: unknown option --okon. Run app help analyze to see its options.\n"
    );
    let o = d.run(
        &["analyze", "--hibp", "h.txt", "password-only.appvault"],
        "demo-pass-1\n",
    );
    assert_eq!(o.code, Some(0));
    assert!(o.out.contains("Leaked password: Demo login"));
}

fn estimate_line(pw: &str) -> String {
    let bits = app_core::health::bits_with(&app_core::health::zxcvbn_bits, pw, &[]);
    format!(
        "Characters {}\tBits {bits:.3}\tLog10 {:.3}\n",
        pw.chars().count(),
        bits * std::f64::consts::LOG10_2
    )
}

#[test]
fn int10_33_a_estimate_from_a_pipe_and_a_terminal() {
    let d = Dir::new("33a");
    let o = d.run(&["estimate"], "demo-pass-1\n");
    assert_eq!(o.code, Some(0));
    assert_eq!(o.out, estimate_line("demo-pass-1"));
    assert!(o.out.starts_with("Characters 11\t"));
    assert!(o.err.is_empty());
    let mut p = d.pty(&format!("'{APP}' estimate; echo STATUS:$?"));
    p.wait_for("Password to rate: ");
    p.send("demo-secret-9\n");
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(!t.contains("demo-secret-9"), "{t}");
    assert!(t.contains(estimate_line("demo-secret-9").trim_end()), "{t}");
    // -a: the parts add up to the estimate.
    let o = d.run(&["estimate", "-a"], "password1\n");
    let parts: Vec<&str> = o.out.lines().skip(1).collect();
    assert!(!parts.is_empty());
    assert!(
        parts.iter().all(|l| l.split('\t').count() == 3),
        "{}",
        o.out
    );
}

#[test]
fn int10_33_b_characters_not_bytes() {
    let d = Dir::new("33b");
    assert!(
        d.run(&["estimate"], "\u{e9}\n")
            .out
            .starts_with("Characters 1\t")
    );
    assert_eq!(
        d.run(&["estimate"], "\n").out,
        "Characters 0\tBits 0.000\tLog10 0.000\n"
    );
}

#[test]
fn int10_34_a_generate_defaults_and_limit() {
    let d = Dir::new("34a");
    let pool: std::collections::BTreeSet<char> = ('a'..='z')
        .chain('A'..='Z')
        .chain('0'..='9')
        .filter(|c| !"lBGIO01 68".contains(*c))
        .collect();
    assert_eq!(pool.len(), 53);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..300 {
        let o = d.run(&["generate"], "");
        let pw = o.out.trim_end();
        assert_eq!(pw.chars().count(), 32);
        assert!(pw.chars().all(|c| pool.contains(&c)), "{pw}");
        seen.extend(pw.chars());
    }
    assert_eq!(seen, pool);
    let o = d.run(&["generate", "-L", "10001"], "");
    assert_eq!(o.code, Some(1));
    assert_eq!(o.err, "app: 10001 is not a usable length.\n");
}

#[test]
fn int10_35_a_passphrase_errors() {
    let d = Dir::new("35a");
    for n in ["0", "1001"] {
        let o = d.run(&["passphrase", "-W", n], "");
        assert_eq!(o.code, Some(1));
        assert_eq!(o.err, format!("app: {n} is not a usable word count.\n"));
        assert!(o.out.is_empty());
    }
    let o = d.run(&["passphrase", "-w", "none.txt"], "");
    assert_eq!(o.code, Some(1));
    assert!(
        o.err
            .starts_with("app: cannot read the word list none.txt: ")
    );
}

#[test]
fn int10_36_a_export_formats_and_warning() {
    let d = Dir::new("36a");
    let o = d.run(&["export", "-q", "password-only.appvault"], "demo-pass-1\n");
    assert_eq!(o.code, Some(0));
    assert!(o.out.starts_with("<?xml"));
    assert!(o.out.contains("Demo login"));
    assert_eq!(
        o.err,
        "Warning: this export is not encrypted. Anyone who can read it can read every password in it.\n"
    );
    let o = d.run(
        &["export", "-f", "csv", "password-only.appvault"],
        "demo-pass-1\n",
    );
    assert!(o.out.starts_with("\"Group\",\"Title\""));
    assert!(
        o.err
            .contains("A spreadsheet may run values that start with =, +, - or @ as formulas.")
    );
    let o = d.run(
        &["export", "-f", "HTML", "password-only.appvault"],
        "demo-pass-1\n",
    );
    assert!(o.out.starts_with("<!DOCTYPE html>"));
    let o = d.run(
        &["export", "-f", "xmlx", "password-only.appvault"],
        "demo-pass-1\n",
    );
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: xmlx is not an export format. Use xml, csv or html.\n"
    );
}

// ---------------------------------------------------------------------------
// INT-10.37 to INT-10.40: import, db-create, db-edit, merge.

#[test]
fn int10_37_a_import() {
    let d = Dir::new("37a");
    let xml = d
        .run(&["export", "-q", "password-only.appvault"], "demo-pass-1\n")
        .raw;
    std::fs::write(d.path("x.xml"), xml).unwrap();
    let o = d.run(&["import", "-p", "x.xml", "i1.appvault"], "pw\npw\n");
    assert_eq!(
        (o.code, o.out.as_str()),
        (Some(0), "New vault i1.appvault made from x.xml.\n"),
        "{}",
        o.err
    );
    assert_eq!(mode(&d.path("i1.appvault")), 0o600);
    assert_eq!(
        d.run(&["ls", "-R", "i1.appvault"], "pw\n").out,
        "Demo login\n"
    );
    let o = d.run(&["import", "-p", "x.xml", "i1.appvault"], "pw\npw\n");
    assert_eq!(
        (o.code, o.err.as_str()),
        (Some(1), "app: File already exists.\n")
    );
    let o = d.run(&["import", "x.xml", "i2.appvault"], "");
    assert_eq!(
        (o.code, o.err.as_str()),
        (Some(1), "app: No key set, nothing created.\n")
    );
    assert!(!d.path("i2.appvault").exists());
}

#[test]
fn int10_38_a_db_create_defaults() {
    let d = Dir::new("38a");
    let o = d.run(&["db-create", "n1.appvault"], "");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: a vault needs a password, a key file or both. Give --set-password, --set-key-file or both.\n"
    );
    assert!(!d.path("n1.appvault").exists());
    let o = d.run(&["db-create", "-p", "n2.appvault"], "pw-a\npw-a\n");
    assert_eq!(
        (o.code, o.out.as_str()),
        (Some(0), "New vault n2.appvault saved.\n")
    );
    assert_eq!(mode(&d.path("n2.appvault")), 0o600);
    let v = load(&d.path("n2.appvault"), "pw-a");
    assert_eq!(v.root.name, "Root");
    assert_eq!(v.meta.name, "");
    assert!(matches!(
        v.encryption.kdf,
        Kdf::Argon2 {
            kind: Argon2Kind::Id,
            memory_kib: 65_536,
            ..
        }
    ));
}

#[test]
fn int10_38_b_new_password_questions() {
    let d = Dir::new("38b");
    let o = d.run(
        &["db-create", "-p", "-t", "100", "a.appvault"],
        "pw-a\npw-b\n",
    );
    assert_eq!(o.code, Some(1));
    assert!(
        o.err
            .ends_with("app: the two passwords are not the same. Nothing was changed.\n")
    );
    let o = d.run(&["db-create", "-p", "-t", "100", "b.appvault"], "\nn\n");
    assert_eq!(o.code, Some(1));
    assert!(
        o.err
            .ends_with("app: no password chosen. Nothing was changed.\n")
    );
    assert!(o.err.contains("Use an empty password? [y/N] "));
    assert!(!d.path("a.appvault").exists() && !d.path("b.appvault").exists());
    let o = d.run(&["db-create", "-p", "-t", "100", "c.appvault"], "\ny\n");
    assert_eq!(o.code, Some(0));
    assert_eq!(d.run(&["ls", "c.appvault"], "\n").code, Some(0));
}

#[test]
fn int10_38_c_decryption_time() {
    let d = Dir::new("38c");
    for (t, want) in [
        ("99", "app: the unlock time must be 100 to 5000 ms.\n"),
        ("abc", "app: abc is not a whole number of milliseconds.\n"),
    ] {
        let o = d.run(&["db-create", "-p", "-t", t, "n.appvault"], "pw\npw\n");
        assert_eq!((o.code, o.err.as_str()), (Some(1), want));
    }
    let o = d.run(&["db-create", "-p", "-t", "100", "n.appvault"], "pw\npw\n");
    assert_eq!(o.code, Some(0));
    assert!(
        o.out
            .starts_with("Key derivation tuned to about 100 ms on this Mac: ")
    );
    assert!(
        o.out
            .contains(" iterations.\nNew vault n.appvault saved.\n")
    );
}

#[test]
fn int10_38_d_key_file_made_or_kept() {
    let d = Dir::new("38d");
    let o = d.run(
        &[
            "db-create",
            "--set-key-file",
            "nk.appkey",
            "-t",
            "100",
            "n3.appvault",
        ],
        "",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
    let key = std::fs::read(d.path("nk.appkey")).unwrap();
    assert_eq!(key.len(), 278);
    assert!(String::from_utf8_lossy(&key).contains("<Version>2.0</Version>"));
    assert_eq!(mode(&d.path("nk.appkey")), 0o400);
    std::fs::copy(d.path("key-hashed.appkey"), d.path("old.appkey")).unwrap();
    let before = std::fs::read(d.path("old.appkey")).unwrap();
    let o = d.run(
        &[
            "db-create",
            "--set-key-file",
            "old.appkey",
            "-t",
            "100",
            "n4.appvault",
        ],
        "",
    );
    assert_eq!(o.code, Some(0));
    assert_eq!(std::fs::read(d.path("old.appkey")).unwrap(), before);
    let o = d.run(
        &["ls", "--no-password", "-k", "old.appkey", "n4.appvault"],
        "",
    );
    assert_eq!(o.code, Some(0), "{}", o.err);
}

#[test]
fn int10_38_e_target_exists() {
    let d = Dir::new("38e");
    std::fs::copy(d.path("password-only.appvault"), d.path("n2.appvault")).unwrap();
    let o = d.run(&["db-create", "-p", "n2.appvault"], "pw\npw\n");
    assert_eq!(
        (o.code, o.err.as_str()),
        (
            Some(1),
            "app: n2.appvault is taken: a file is already there.\n"
        )
    );
}

#[test]
fn int10_39_a_db_edit() {
    let d = Dir::new("39a");
    assert_eq!(
        d.run(
            &["db-create", "-p", "-t", "100", "n2.appvault"],
            "pw-a\npw-a\n"
        )
        .code,
        Some(0)
    );
    let o = d.run(&["db-edit", "n2.appvault"], "pw-a\n");
    assert_eq!(
        (o.code, o.out.as_str()),
        (Some(0), "Nothing changed; n2.appvault was not saved.\n")
    );
    let o = d.run(&["db-edit", "--unset-key-file", "n2.appvault"], "pw-a\n");
    assert!(
        o.err
            .ends_with("app: n2.appvault has no key file to remove.\n")
    );
    let o = d.run(&["db-edit", "--unset-password", "n2.appvault"], "pw-a\n");
    assert!(o.err.ends_with(
        "app: this would leave n2.appvault with no key part at all. Nothing was changed.\n"
    ));
    let o = d.run(
        &["db-edit", "--set-key-file", "nk2.appkey", "n2.appvault"],
        "pw-a\n",
    );
    assert_eq!(
        (o.code, o.out.as_str()),
        (Some(0), "New credentials of n2.appvault saved.\n")
    );
    assert_eq!(
        d.run(&["ls", "-k", "nk2.appkey", "n2.appvault"], "pw-a\n")
            .code,
        Some(0)
    );
    assert_eq!(d.run(&["ls", "n2.appvault"], "pw-a\n").code, Some(1));
}

#[test]
fn int10_40_a_merge() {
    let d = Dir::new("40a");
    merge_pair(&d);
    let m1 = std::fs::read(d.path("m1.appvault")).unwrap();
    let two = "demo-pass-4\ndemo-pass-4\n";
    let o = d.run(&["merge", "-q", "-d", "m1.appvault", "m2.appvault"], two);
    assert_eq!((o.code, o.out.as_str()), (Some(0), ""));
    let o = d.run(&["merge", "-d", "m1.appvault", "m2.appvault"], two);
    let l = lines(&o.out);
    assert_eq!(l.len(), 2, "{}", o.out);
    assert!(l[0].starts_with("\tAdded: '/Rich demo'/'Merged in' [{"));
    assert_eq!(l[1], "m1.appvault is unchanged.");
    assert_eq!(std::fs::read(d.path("m1.appvault")).unwrap(), m1);
    let o = d.run(
        &["merge", "-s", "m1.appvault", "m2.appvault"],
        "demo-pass-4\n",
    );
    assert!(
        o.out
            .ends_with("m1.appvault saved with the changes from m2.appvault.\n")
    );
    let o = d.run(
        &["merge", "-s", "m1.appvault", "m2.appvault"],
        "demo-pass-4\n",
    );
    assert_eq!(o.out, "m1.appvault is unchanged.\n");
}

#[test]
fn int10_40_b_same_credentials_fail() {
    let d = Dir::new("40b");
    merge_pair(&d);
    let o = d.run(
        &["merge", "-s", "m1.appvault", "password-only.appvault"],
        "demo-pass-4\n",
    );
    assert_eq!(o.code, Some(1));
    assert!(o.err.ends_with(
        "app: cannot open password-only.appvault with the credentials of m1.appvault: Wrong password, key file or security key. Check them and try again.\n"
    ), "{}", o.err);
}

// ---------------------------------------------------------------------------
// INT-10.41 to INT-10.44: attachments, help, close.

#[test]
fn int10_41_a_attachment_export() {
    let d = Dir::new("41a");
    let base = [
        "attachment-export",
        "w.appvault",
        "Full demo entry",
        "notes.txt",
    ];
    let o = d.run(&base, "demo-pass-4\n");
    assert_eq!(
        (o.code, o.err.as_str()),
        (
            Some(1),
            "app: say where the attachment goes: a file path or --stdout.\n"
        )
    );
    let o = d.run(&[&base[..], &["--stdout", "-q"]].concat(), "demo-pass-4\n");
    assert_eq!(o.raw, b"demo attachment one\n");
    let o = d.run(&[&base[..], &["out.bin"]].concat(), "demo-pass-4\n");
    assert_eq!(
        o.out,
        "Attachment notes.txt of Full demo entry written to out.bin.\n"
    );
    assert_eq!(mode(&d.path("out.bin")), 0o600);
    std::fs::write(d.path("out.bin"), b"keep").unwrap();
    let o = d.run(&[&base[..], &["out.bin"]].concat(), "demo-pass-4\n");
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.err,
        "app: out.bin exists and was left alone. Add --force to replace it.\n"
    );
    assert_eq!(std::fs::read(d.path("out.bin")).unwrap(), b"keep");
    let o = d.run(&[&base[..], &["out.bin", "-f"]].concat(), "demo-pass-4\n");
    assert_eq!(o.code, Some(0));
    assert_eq!(
        std::fs::read(d.path("out.bin")).unwrap(),
        b"demo attachment one\n"
    );
}

#[test]
fn int10_42_a_attachment_import() {
    let d = Dir::new("42a");
    std::fs::write(d.path("in.txt"), b"new text").unwrap();
    let w = d.path("w.appvault");
    let base = [
        "attachment-import",
        "w.appvault",
        "Full demo entry",
        "notes.txt",
    ];
    let o = d.run(&[&base[..], &["in.txt"]].concat(), "demo-pass-4\n");
    assert!(o.err.ends_with(
        "app: Full demo entry already has an attachment called notes.txt. Add --force to replace it.\n"
    ));
    let before = full_demo_history(&w);
    let o = d.run(&[&base[..], &["in.txt", "-f"]].concat(), "demo-pass-4\n");
    assert_eq!(o.out, "in.txt attached to Full demo entry as notes.txt.\n");
    assert_eq!(full_demo_history(&w), before + 1);
    let o = d.run(
        &[
            "attachment-export",
            "--stdout",
            "w.appvault",
            "Full demo entry",
            "notes.txt",
        ],
        "demo-pass-4\n",
    );
    assert_eq!(o.raw, b"new text");
    let o = d.run(&[&base[..], &["none.txt"]].concat(), "demo-pass-4\n");
    assert!(
        o.err
            .ends_with("already has an attachment called notes.txt. Add --force to replace it.\n")
    );
}

#[test]
fn int10_43_a_attachment_rm() {
    let d = Dir::new("43a");
    let o = d.run(
        &["attachment-rm", "w.appvault", "Full demo entry", "new.txt"],
        "demo-pass-4\n",
    );
    assert!(
        o.err
            .ends_with("app: Full demo entry has no attachment called new.txt.\n")
    );
    let o = d.run(
        &[
            "attachment-rm",
            "w.appvault",
            "Full demo entry",
            "notes.txt",
        ],
        "demo-pass-4\n",
    );
    assert_eq!(
        o.out,
        "Attachment notes.txt removed from Full demo entry.\n"
    );
    let v = load(&d.path("w.appvault"), "demo-pass-4");
    assert!(
        find(&v, "Full demo entry")
            .attachments
            .iter()
            .all(|a| a.name != "notes.txt")
    );
}

#[test]
fn int10_44_a_help_and_close() {
    let d = Dir::new("44a");
    let o = d.run(&["help", "ls"], "");
    assert_eq!(o.code, Some(0));
    assert!(o.out.starts_with("Usage: app ls [OPTIONS] VAULT [GROUP]\n"));
    let o = d.run(&["help", "nothing"], "");
    assert_eq!(o.code, Some(0));
    assert!(o.out.starts_with("App command line tool.\n"));
    let o = d.run(&["close"], "");
    assert_eq!((o.code, o.out.as_str(), o.err.as_str()), (Some(0), "", ""));
}

// ---------------------------------------------------------------------------
// INT-10.45 to INT-10.47: the shell.

#[test]
fn int10_45_a_shell_on_a_terminal_pty() {
    let d = Dir::new("45a");
    let mut p = d.pty(&format!("'{APP}' open rich-v3.appvault; echo STATUS:$?"));
    p.wait_for("Vault password for rich-v3.appvault: ");
    p.send("demo-pass-4\n");
    p.wait_for("app (Rich demo)> ");
    for line in ["ls", "show \"Full demo entry\"", "bogus", "export"] {
        p.send(&format!("{line}\n"));
    }
    p.send("close\n");
    p.wait_for("app> ");
    p.send("ls\n");
    p.send("quit\n");
    p.wait_for("STATUS:");
    let t = p.finish();
    assert!(t.contains("Recycle Bin/"), "{t}");
    assert!(t.contains("Uuid: {00000000-0000-0000-0000-00000000000a}"));
    assert!(t.contains("There is no command bogus here. Type help to see the commands."));
    assert!(t.contains("There is no command export here. Type help to see the commands."));
    assert!(t.contains("app ls: VAULT is missing. Run app help ls to see its options."));
    assert!(t.contains("STATUS:0"));
}

#[test]
fn int10_45_b_piped_shell() {
    let d = Dir::new("45b");
    let o = d.run(&["open", "rich-v3.appvault"], "demo-pass-4\nls\nquit\n");
    assert_eq!(o.code, Some(0));
    assert_eq!(
        o.out,
        d.run(&["ls", "rich-v3.appvault"], "demo-pass-4\n").out
    );
    assert!(!o.err.contains("app ("));
    assert_eq!(o.err, "Vault password for rich-v3.appvault: ");
}

#[test]
fn int10_45_c_shell_saves_at_once() {
    let d = Dir::new("45c");
    let mut p = d.spawn(&["open", "w.appvault"], &[]);
    p.send("demo-pass-4\nadd S5\n");
    wait_for(&p.out, "New entry S5 saved.");
    let v = load(&d.path("w.appvault"), "demo-pass-4");
    assert!(v.root.entries.iter().any(|e| e.value("Title") == "S5"));
    p.send("quit\n");
    assert_eq!(p.finish().0, Some(0));
}

#[test]
fn int10_46_a_shell_words() {
    let d = Dir::new("46a");
    let o = d.run(
        &["open", "rich-v3.appvault"],
        "demo-pass-4\nshow -a Uuid \"Full demo entry\"\nshow -a Uuid Full\\ demo\\ entry\nshow Full demo entry\n",
    );
    assert_eq!(o.code, Some(0));
    assert_eq!(
        o.out,
        "{00000000-0000-0000-0000-00000000000a}\n{00000000-0000-0000-0000-00000000000a}\n"
    );
    assert!(
        o.err.ends_with(
            "app show: unexpected argument demo. Run app help show to see its options.\n"
        )
    );
}

#[test]
fn int10_47_a_leaving_the_shell_pty() {
    let d = Dir::new("47a");
    let mut p = d.pty(&sh("open rich-v3.appvault"));
    let pid = p.app_pid();
    p.wait_for("Vault password");
    p.send("demo-pass-4\n");
    p.wait_for("app (Rich demo)> ");
    kill("-TERM", &pid);
    p.wait_for("lflags");
    let t = p.finish();
    assert!(t.contains("STATUS:143"), "{t}");
    assert!(echo_on(t.split("STATUS:").nth(1).unwrap()));
    let mut p = d.pty(&format!("'{APP}' open rich-v3.appvault; echo STATUS:$?"));
    p.wait_for("Vault password");
    p.send("demo-pass-4\n");
    p.wait_for("app (Rich demo)> ");
    // Closing script's input sends Ctrl-D to the terminal.
    let t = p.finish();
    assert!(t.contains("STATUS:0"), "{t}");
}

// ---------------------------------------------------------------------------
// Checker 1 findings, ruled in LD-178.

/// LD-178 (1): a SIGINT ignored at start stays ignored; the clip wait runs
/// to its end.
#[test]
fn ld178_1_ignored_sigint_does_not_cut_the_clip_wait() {
    let d = Dir::new("ld178-1");
    let mut p = d.spawn_ignoring_sigint(&["clip", "w.appvault", "Full demo entry", "3"], PB);
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-4\n");
    wait_for(&p.out, "copied.");
    let copied = Instant::now();
    thread::sleep(Duration::from_secs(1));
    kill("-INT", &p.child.id().to_string());
    let (code, out, _) = p.finish();
    assert!(
        copied.elapsed() > Duration::from_millis(2500),
        "{:?}",
        copied.elapsed()
    );
    assert_eq!(code, Some(0));
    assert!(out.ends_with("The clipboard is empty again.\n"), "{out}");
    pasteboard::release(&name);
}

/// LD-178 (2): INT-10.12-b with SIGHUP.
#[test]
fn int10_12_b_sighup_at_the_prompt_restores_echo_pty() {
    let d = Dir::new("12b-hup");
    let p = d.pty(&sh("ls password-only.appvault"));
    let pid = p.app_pid();
    p.wait_for("Vault password");
    thread::sleep(Duration::from_millis(400));
    kill("-HUP", &pid);
    p.wait_for("lflags");
    let t = p.finish();
    assert!(t.contains("STATUS:129"), "{t}");
    assert!(echo_on(t.split("STATUS:").nth(1).unwrap()), "{t}");
}

/// LD-178 (3): clap finds `-h` inside a cluster, and a value that looks like
/// `-h` stays a value.
#[test]
fn ld178_3_help_through_clap() {
    let d = Dir::new("ld178-3");
    let o = d.run(&["ls", "-qh", "w.appvault"], "");
    assert_eq!(o.code, Some(0));
    assert!(o.out.starts_with("Usage: app ls [OPTIONS] VAULT [GROUP]\n"));
    assert!(o.err.is_empty());
    let o = d.run(&["add", "-u", "-h", "w.appvault", "X"], "demo-pass-4\n");
    assert_eq!((o.code, o.out.as_str()), (Some(0), "New entry X saved.\n"));
    let o = d.run(
        &["show", "-a", "UserName", "w.appvault", "X"],
        "demo-pass-4\n",
    );
    assert_eq!(o.out, "-h\n");
    let o = d.run(&["open", "rich-v3.appvault"], "demo-pass-4\nls -h\nquit\n");
    assert!(
        o.out.starts_with("Usage: app ls [OPTIONS] VAULT [GROUP]\n"),
        "{}",
        o.out
    );
}

/// LD-178 (4): local times from macOS: `TZ` is followed, and a zone's rules
/// hold after 2037.
#[test]
fn ld178_4_local_time_from_macos() {
    let d = Dir::new("ld178-4");
    let mut v = small_vault("x");
    // 2040-07-01T00:00:00Z.
    v.root.times.creation = Time::from_unix(2_224_713_600).unwrap();
    store(&d.path("t.appvault"), &v, "demo-pass-1");
    for (tz, want) in [
        ("Europe/Berlin", "Created on: 2040-07-01T02:00:00+02:00\n"),
        (
            "America/New_York",
            "Created on: 2040-06-30T20:00:00-04:00\n",
        ),
        ("UTC", "Created on: 2040-07-01T00:00:00+00:00\n"),
    ] {
        let o = d.run_env(&["db-info", "t.appvault"], "demo-pass-1\n", &[("TZ", tz)]);
        assert!(o.out.contains(want), "{tz}: {}", o.out);
    }
}

/// LD-178 (5): a password after `--` is still a password argument (M10-92).
#[test]
fn ld178_5_estimate_after_double_dash() {
    let d = Dir::new("ld178-5");
    let o = d.run(&["estimate", "--", "-x"], "");
    assert_eq!(o.code, Some(1));
    assert!(
        o.err
            .starts_with("app: estimate does not take the password as an argument")
    );
    assert!(o.out.is_empty());
}

/// LD-178 (6): `attachment-export --stdout` writes the exact bytes, also to
/// a terminal (INT-10.41 over INT-10.10).
#[test]
fn ld178_6_stdout_export_is_exact_on_a_terminal_pty() {
    let d = Dir::new("ld178-6");
    let mut p = d.pty(&format!(
        "'{APP}' attachment-export --stdout w.appvault 'Full demo entry' bytes.bin; echo STATUS:$?"
    ));
    p.wait_for("Vault password");
    p.send("demo-pass-4\n");
    p.wait_for("STATUS:");
    let raw = p.out.lock().unwrap().clone();
    p.finish();
    // ESC and DEL reach the terminal as they are, not as `\x1b`, `\x7f`.
    assert!(raw.contains(&0x1b) && raw.contains(&0x7f));
    let t = String::from_utf8_lossy(&raw);
    assert!(!t.contains("\\x1b") && !t.contains("\\x7f"), "{t:?}");
}

// ---------------------------------------------------------------------------
// Verify findings, ruled in LD-185.

fn rated_below_good(d: &Dir, vault: &str, pw: &str) -> usize {
    let o = d.run(&["db-info", vault], &format!("{pw}\n"));
    let line = o
        .out
        .lines()
        .find(|l| l.starts_with("Rated below Good: "))
        .unwrap();
    line["Rated below Good: ".len()..].parse().unwrap()
}

/// LD-185 (C25): `is:weak` rates every password before it searches, so the
/// work bound is not spent on rating and no result is dropped.
#[test]
fn ld185_c25_is_weak_is_complete() {
    let d = Dir::new("ld185-c25");
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/big-10000.appvault");
    std::fs::copy(data, d.path("big.appvault")).unwrap();
    let o = d.run(
        &["search", "option-a-personal.appvault", "is:weak"],
        "demo-pass-7\n",
    );
    assert_eq!(o.code, Some(0));
    assert_eq!(lines(&o.out).len(), 6, "{}", o.out);
    let o = d.run(&["search", "big.appvault", "is:weak"], "demo-pass-6\n");
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(!o.err.contains("work limit"), "{}", o.err);
    assert_eq!(lines(&o.out).len(), 10_000);
    assert_eq!(rated_below_good(&d, "big.appvault", "demo-pass-6"), 10_000);
}

/// LD-185 (C19): a version 3 vault merged with itself (or a copy of
/// itself) changes nothing and is not saved.
#[test]
fn ld185_c19_version_3_merge_settles() {
    let d = Dir::new("ld185-c19");
    std::fs::copy(d.path("w.appvault"), d.path("w2.appvault")).unwrap();
    let before = std::fs::read(d.path("w.appvault")).unwrap();
    for source in ["w2.appvault", "w.appvault"] {
        let o = d.run(&["merge", "-s", "w.appvault", source], "demo-pass-4\n");
        assert_eq!(
            (o.code, o.out.as_str()),
            (Some(0), "w.appvault is unchanged.\n"),
            "{source}"
        );
    }
    assert_eq!(std::fs::read(d.path("w.appvault")).unwrap(), before);
}

/// F-066 (LD-207): with the vault flag that protects Titles on, the tool's
/// messages, lists and paths show the mask, never the Title; `show -s`
/// still prints it on request.
#[test]
fn f_066_protected_titles_masked_in_messages_lists_and_paths() {
    let d = Dir::new("f066");
    let mut v = small_vault("Demo login");
    v.meta.memory_protection.title = true;
    let root = v.root.uuid;
    let mut g = app_core::edit::new_group(&v).unwrap();
    "Moved".clone_into(&mut g.name);
    app_core::edit::add_group(&mut v, root, g, now()).unwrap();
    store(&d.path("t.appvault"), &v, "demo-pass-1");
    let mask = app_core::health::MASKED_TITLE;
    for args in [
        &["ls", "-R", "t.appvault"][..],
        &["search", "t.appvault", "Demo"],
        &["edit", "--notes", "n", "t.appvault", "Demo login"],
        &["add", "t.appvault", "Second"],
        &["mv", "t.appvault", "Demo login", "Moved"],
        &["rm", "t.appvault", "Moved/Demo login"],
    ] {
        let o = d.run(args, "demo-pass-1\n");
        let all = format!("{}{}", o.out, o.err);
        assert_eq!(o.code, Some(0), "{args:?}: {all}");
        assert!(all.contains(mask), "{args:?}: {all}");
        assert!(
            !all.contains("Demo login") && !all.contains("Second"),
            "{args:?}: {all}"
        );
    }
    let o = d.run(&["show", "-s", "t.appvault", "Second"], "demo-pass-1\n");
    assert!(o.out.contains("Title: Second"), "{}", o.out);
}

/// F-066 with INT-10.29: `clip -b` on a vault whose Title flag is on names
/// the best match with the mask and still copies its password.
#[test]
fn f_066_clip_best_match_with_protected_titles() {
    let d = Dir::new("f066b");
    let mut v = small_vault("Demo login");
    v.meta.memory_protection.title = true;
    v.root.entries[0].set_field("Password".into(), field("demo-secret-9", true));
    store(&d.path("t.appvault"), &v, "demo-pass-1");
    let mut p = d.spawn(&["clip", "-b", "t.appvault", "Demo", "0"], PB);
    let name = pasteboard::name(p.child.id());
    p.send("demo-pass-1\n");
    let (code, out, err) = p.finish();
    let mask = app_core::health::MASKED_TITLE;
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(out.starts_with(&format!("Best match: /{mask}.\n")), "{out}");
    assert!(!out.contains("Demo login") && !err.contains("Demo login"));
    assert_eq!(pasteboard::text(&name).as_deref(), Some("demo-secret-9"));
    pasteboard::release(&name);
}

/// INT-08.40 (T64): shares never run from `app`. A vault whose root group
/// exports and imports `team.appvault`: an edit saves, and no container is
/// written.
#[test]
fn t64_int08_40_an_app_save_exports_nothing() {
    use app_format::share_item::{KEY, Settings};
    let d = Dir::new("int08-40");
    let mut v = small_vault("Demo login");
    let mut share = Settings {
        import: true,
        export: true,
        path: "team.appvault".into(),
        password: SecretString::new("demo-share-1".into()),
        ..Settings::new()
    };
    v.root.custom_data.items.push(app_model::CustomDataItem {
        key: String::from_utf8(KEY.to_vec()).unwrap(),
        value: share.write().unwrap(),
        last_modified: None,
        unknown: Vec::new(),
    });
    store(&d.path("t.appvault"), &v, "demo-pass-1");
    let o = d.run(
        &["edit", "--notes", "n", "t.appvault", "Demo login"],
        "demo-pass-1\n",
    );
    assert_eq!(o.code, Some(0), "{}{}", o.out, o.err);
    let saved = load(&d.path("t.appvault"), "demo-pass-1");
    assert_eq!(find(&saved, "Demo login").value("Notes"), "n");
    assert!(!d.path("team.appvault").exists(), "the save exported");
}

/// MOD-08 row 08-63 (MOD-08.32, F-142, F-158): `app show` resolves Team
/// wiki's planted `{REF:P@U:ann@example.com}` inside Team's share scope,
/// so it prints no `gmail-secret-demo`; the same reference from Home,
/// outside every share group, still finds Gmail.
#[test]
fn mod08_63_app_show_of_a_planted_reference_prints_nothing_outside_the_share() {
    use app_format::share_item::{KEY, Settings};
    let d = Dir::new("mod08-63");
    let mut v = small_vault("Demo login");
    let entry = |n: u8, title: &str, user: &str, password: &str| {
        let mut e = Entry::new(Uuid([n; 16]), now());
        e.set_field("Title".into(), field(title, false));
        e.set_field("UserName".into(), field(user, false));
        e.set_field("Password".into(), field(password, true));
        e
    };
    let mut team = Group::new(Uuid([0x20; 16]), "Team".into(), now());
    team.entries.push(entry(0x0A, "Mail", "ann", "pw-1"));
    team.entries
        .push(entry(0x44, "Team wiki", "", "{REF:P@U:ann@example.com}"));
    let mut share = Settings {
        import: true,
        export: true,
        path: "team.appvault".into(),
        password: SecretString::new("demo-share-1".into()),
        keep_groups: true,
        ..Settings::new()
    };
    team.custom_data.items.push(app_model::CustomDataItem {
        key: String::from_utf8(KEY.to_vec()).unwrap(),
        value: share.write().unwrap(),
        last_modified: None,
        unknown: Vec::new(),
    });
    let mut home = Group::new(Uuid([0x30; 16]), "Home".into(), now());
    home.entries
        .push(entry(0x0F, "Gmail", "ann@example.com", "gmail-secret-demo"));
    home.entries
        .push(entry(0x31, "Outside", "", "{REF:P@U:ann@example.com}"));
    v.root.groups.push(team);
    v.root.groups.push(home);
    store(&d.path("s.appvault"), &v, "demo-pass-1");
    let show = |args: &[&str]| {
        let o = d.run(args, "demo-pass-1\n");
        assert_eq!(o.code, Some(0), "{}{}", o.out, o.err);
        o.out
    };
    let wiki = show(&["show", "-a", "Password", "s.appvault", "Team/Team wiki"]);
    assert_eq!(wiki.trim_end(), "");
    let all = show(&["show", "-s", "--all", "s.appvault", "Team/Team wiki"]);
    assert!(!all.contains("gmail-secret-demo"), "{all}");
    let outside = show(&["show", "-a", "Password", "s.appvault", "Home/Outside"]);
    assert_eq!(outside.trim_end(), "gmail-secret-demo");
}
