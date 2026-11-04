//! APP-09 cases that run the built Mac app, `App.app/Contents/MacOS/App`, as
//! check.sh builds it (Debug, `target/xcode`). Not part of `cargo test
//! --workspace`, which runs before the app is built: check.sh runs
//! `cargo test -p app-ffi --test app09` after `xcodebuild test`.
//!
//! Debug builds only: each test sets its own instance folder through the
//! debug-only test variable (a release build reads no environment variable,
//! LD-48), so every lock and socket here has the debug names of APP-09.29.
//! Every app a test starts is stopped when the test ends, and runs hidden
//! (`HIDDEN_VARIABLE`): no window, never the active app. Tests that start a
//! primary run one at a time.
#![cfg(debug_assertions)]

use app_ffi::instance::{
    HIDDEN_VARIABLE, LOCKED, NO_ANSWER, NOT_RUNNING, PASSED_ON, TEST_DIR_VARIABLE,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const APP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/xcode/Build/Products/Debug/App.app/Contents/MacOS/App"
);
const PROBE: &[u8] = b"{\"v\":1,\"cmd\":\"lock\"}\n"; // answered, and raises no window

static WINDOWS: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    WINDOWS.lock().unwrap_or_else(|e| e.into_inner())
}

struct Dir(PathBuf);

impl Dir {
    fn new(case: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("a09-{}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn lock(&self) -> PathBuf {
        self.0.join("com.app.desktop-debug.lock")
    }
    fn socket(&self) -> PathBuf {
        self.0.join("com.app.desktop-debug.sock")
    }
    /// A demo file (not a vault: nothing opens files before E5-S2).
    fn file(&self, name: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, b"demo").unwrap();
        path.to_str().unwrap().to_string()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn app(dir: &Dir) -> Command {
    assert!(
        std::path::Path::new(APP).exists(),
        "no {APP}: run scripts/build-core.sh and xcodebuild first (check.sh G2)"
    );
    let mut command = Command::new(APP);
    // No window, never active: these launches must not take the screen.
    command
        .env(TEST_DIR_VARIABLE, &dir.0)
        .env(HIDDEN_VARIABLE, "1")
        .stdin(Stdio::null());
    command
}

/// A launch that must end by itself: exit code, stdout, stderr.
fn run(dir: &Dir, args: &[&str]) -> (Option<i32>, String, String) {
    let mut child = app(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the launch {args:?} did not end");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
    (out.status.code(), text(out.stdout), text(out.stderr))
}

/// One request line on the channel; the answer, or `None` when the primary
/// closed without one.
fn ask(dir: &Dir, line: &[u8]) -> Option<String> {
    let mut stream = UnixStream::connect(dir.socket()).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let _ = stream.write_all(line); // a refused long line may break the pipe
    let mut answer = String::new();
    match stream.read_to_string(&mut answer) {
        Ok(_) if !answer.is_empty() => Some(answer),
        _ => None,
    }
}

/// A primary started by the test, stopped (and continued first) when dropped.
struct Primary(Child);

impl Primary {
    fn start(dir: &Dir) -> Self {
        let child = app(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self::answering(dir, child)
    }
    /// Waits until the primary answers on its channel (the window exists then).
    fn answering(dir: &Dir, child: Child) -> Self {
        let primary = Self(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        while ask(dir, PROBE).as_deref() != Some("{\"ok\":true}\n") {
            assert!(Instant::now() < deadline, "the primary did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        primary
    }
    fn signal(&self, name: &str) {
        let status = Command::new("/bin/kill")
            .args([format!("-{name}"), self.0.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }
    /// The exit code once it ends, waiting at most 10 seconds.
    fn exit_code(&mut self) -> Option<i32> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status.code();
            }
            assert!(Instant::now() < deadline, "the primary did not quit");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Primary {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            self.signal("CONT");
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn app09_2_a_unknown_flag_leaves_the_primary_alone() {
    let _one = one_at_a_time();
    let dir = Dir::new("2a");
    let _primary = Primary::start(&dir);
    let (code, out, err) = run(&dir, &["--bogus"]);
    assert_eq!(code, Some(1));
    assert_eq!(
        err,
        "Unknown flag: --bogus. Run App --help for the list of flags.\n"
    );
    assert!(out.is_empty());
    assert_eq!(ask(&dir, PROBE).as_deref(), Some("{\"ok\":true}\n"));
}

#[test]
fn app09_2_b_key_file_without_value() {
    let dir = Dir::new("2b");
    let (code, _, err) = run(&dir, &["--key-file"]);
    assert_eq!(code, Some(1));
    assert_eq!(
        err,
        "The flag --key-file needs a value. Run App --help for the list of flags.\n"
    );
    assert!(!dir.lock().exists(), "the instance check ran");
}

#[test]
fn app09_3_a_help_lists_the_flags_and_exits() {
    let dir = Dir::new("3a");
    let (code, out, err) = run(&dir, &["--help"]);
    assert_eq!((code, err.as_str()), (Some(0), ""));
    assert_eq!(out, app_ffi::cli::HELP);
    assert!(!dir.lock().exists(), "the instance check ran");
}

#[test]
fn app09_3_b_version_wins_over_help() {
    let dir = Dir::new("3b");
    for args in [&["--version"][..], &["-v", "--help"][..]] {
        let (code, out, _) = run(&dir, args);
        assert_eq!(code, Some(0));
        assert_eq!(out, format!("App {}\n", env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn app09_4_a_debug_info_names_no_path() {
    let dir = Dir::new("4a");
    let (code, out, _) = run(&dir, &["--debug-info"]);
    assert_eq!(code, Some(0));
    for line in [
        "App ",
        "Build type: debug",
        "Shell: SwiftUI (native)",
        "Web engine: none",
        "Operating system: macOS ",
        "CPU architecture: ",
        "Kernel: Darwin ",
        "Features built in: ",
        "Crypto crates: aes ",
    ] {
        assert!(out.contains(line), "{line}\n{out}");
    }
    assert!(!out.contains('/'), "{out}");
    assert!(!dir.lock().exists(), "the instance check ran");
}

#[test]
fn app09_8_a_after_kill_9_the_next_launch_is_primary() {
    let _one = one_at_a_time();
    let dir = Dir::new("8a");
    let mut first = Primary::start(&dir);
    first.signal("KILL");
    let _ = first.exit_code();
    assert!(dir.socket().exists(), "a leftover socket file");
    let _second = Primary::start(&dir);
    let (code, _, err) = run(&dir, &[]);
    assert_eq!((code, err), (Some(0), format!("{PASSED_ON}\n")));
}

#[test]
fn app09_8_b_folder_at_the_lock_path_refuses_to_start() {
    let dir = Dir::new("8b");
    std::fs::create_dir(dir.lock()).unwrap();
    let a = dir.file("a.appvault");
    let (code, _, err) = run(&dir, &[&a]);
    assert_eq!(code, Some(1));
    let want = format!(
        "App cannot start: the instance lock {} could not be created (Is a directory",
        dir.lock().display()
    );
    assert!(err.starts_with(&want), "{err}");
    assert!(!dir.socket().exists());
}

#[test]
fn app09_9_a_stopped_primary_gives_m09_05() {
    let _one = one_at_a_time();
    let dir = Dir::new("9a");
    let primary = Primary::start(&dir);
    primary.signal("STOP");
    let a = dir.file("a.appvault");
    let started = Instant::now();
    let (code, _, err) = run(&dir, &[&a]);
    assert_eq!((code, err), (Some(1), format!("{NO_ANSWER}\n")));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn app09_10_c_second_launch_activates_the_primary() {
    let _one = one_at_a_time();
    let dir = Dir::new("10c");
    let _primary = Primary::start(&dir);
    let (code, out, err) = run(&dir, &[]);
    assert_eq!(
        (code, out, err),
        (Some(0), String::new(), format!("{PASSED_ON}\n"))
    );
}

#[test]
fn app09_10_ab_open_is_passed_on_and_stdin_is_not_read() {
    let _one = one_at_a_time();
    let dir = Dir::new("10ab");
    let _primary = Primary::start(&dir);
    let b = dir.file("b.appvault");
    // 10-a: a file goes to the primary as an open request.
    let (code, out, err) = run(&dir, &[&b]);
    assert_eq!(
        (code, out, err),
        (Some(0), String::new(), format!("{PASSED_ON}\n"))
    );
    // 10-b: with F06 a secondary prints no M09-08 and passes no password on.
    let (code, out, err) = run(&dir, &["--password-stdin", &b]);
    assert_eq!(
        (code, out, err),
        (Some(0), String::new(), format!("{PASSED_ON}\n"))
    );
}

#[test]
fn app09_16_a_the_primary_reads_one_password_line_per_file() {
    let _one = one_at_a_time();
    let dir = Dir::new("16a");
    let a = dir.file("a.appvault");
    let mut child = app(&dir)
        .args(["--password-stdin", &a])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"demo-pass-a\n")
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let _primary = Primary::answering(&dir, child);
    // M09-08 before the line, then nothing: the password is never printed.
    let mut prompt = [0; 16];
    out.read_exact(&mut prompt).unwrap();
    assert_eq!(&prompt, b"Vault password: ");
}

#[test]
fn app09_12_a_lock_request_is_delivered() {
    let _one = one_at_a_time();
    let dir = Dir::new("10l");
    let _primary = Primary::start(&dir);
    let b = dir.file("b.appvault");
    let (code, _, err) = run(&dir, &["--lock", &b]);
    assert_eq!((code, err), (Some(0), format!("{LOCKED}\n")));
}

#[test]
fn app09_11_a_lock_without_an_instance() {
    let dir = Dir::new("11a");
    let (code, _, err) = run(&dir, &["--lock"]);
    assert_eq!((code, err), (Some(0), format!("{NOT_RUNNING}\n")));
    assert!(!dir.socket().exists(), "a window started");
}

#[test]
fn app09_11_b_lock_with_a_stopped_primary_gives_m09_05() {
    let _one = one_at_a_time();
    let dir = Dir::new("11b");
    let primary = Primary::start(&dir);
    primary.signal("STOP");
    let (code, _, err) = run(&dir, &["--lock"]);
    assert_eq!((code, err), (Some(1), format!("{NO_ANSWER}\n")));
}

#[test]
fn app09_13_abc_channel_limits() {
    let _one = one_at_a_time();
    let dir = Dir::new("13");
    let _primary = Primary::start(&dir);
    // 13-a: a 70,000-byte line is closed without an answer.
    let mut long = b"{\"v\":1,\"cmd\":\"activate\",\"x\":\"".to_vec();
    long.resize(69_999, b'a');
    long.push(b'\n');
    assert_eq!(ask(&dir, &long), None);
    // 13-b: a relative path is closed without an answer.
    assert_eq!(
        ask(
            &dir,
            b"{\"v\":1,\"cmd\":\"open\",\"paths\":[\"a.appvault\"]}\n"
        ),
        None
    );
    // 13-c: activate is answered.
    assert_eq!(
        ask(&dir, b"{\"v\":1,\"cmd\":\"activate\"}\n").as_deref(),
        Some("{\"ok\":true}\n")
    );
}

#[test]
fn app09_27_a_int_term_quit_end_with_exit_code_0() {
    let _one = one_at_a_time();
    for signal in ["INT", "TERM", "QUIT"] {
        let dir = Dir::new(&format!("27a-{signal}"));
        let mut primary = Primary::start(&dir);
        primary.signal(signal);
        assert_eq!(primary.exit_code(), Some(0), "SIG{signal}");
    }
}

#[test]
fn app09_27_b_hangup_is_ignored() {
    let _one = one_at_a_time();
    let dir = Dir::new("27b");
    let mut primary = Primary::start(&dir);
    primary.signal("HUP");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        primary.0.try_wait().unwrap().is_none(),
        "SIGHUP ended the app"
    );
    assert_eq!(ask(&dir, PROBE).as_deref(), Some("{\"ok\":true}\n"));
}

/// APP-09.20 a (APP-01.17): the start reopens the vaults open at the last
/// quit, locked, in the saved order, then the one shown last; the file
/// argument opens after them (APP-09.1 steps 11 and 12).
#[test]
fn app09_20_a_start_reopens_the_previous_vaults_then_the_file_argument() {
    let _one = one_at_a_time();
    let dir = Dir::new("20a");
    let demo = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/option-a-personal.appvault"
    );
    let vault = |name: &str| {
        let path = dir.0.join(name);
        std::fs::copy(demo, &path).unwrap();
        path.to_str().unwrap().to_string()
    };
    let (a, b, k) = (
        vault("a.appvault"),
        vault("b.appvault"),
        vault("k.appvault"),
    );
    let settings = dir.0.join("settings");
    std::fs::create_dir_all(&settings).unwrap();
    let state = settings.join("state_debug.json");
    let saved = app_model::json!({"state.open_at_quit": [a, b.clone()], "state.last_active": b});
    std::fs::write(&state, saved.to_string()).unwrap();
    let child = app(&dir)
        .arg(&k)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _primary = Primary::answering(&dir, child);
    let recent = || -> Vec<String> {
        let text = std::fs::read(&state).unwrap_or_default();
        let value = app_model::json::from_slice(&text).unwrap_or_default();
        value["state.recent"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| p.as_str()?.rsplit('/').next().map(str::to_string))
            .collect()
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while recent().len() < 3 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(recent(), ["k.appvault", "b.appvault", "a.appvault"]);
}
