//! INT-01's host program cases (story E7-S6): a test client starts the
//! built `larsal-bridge` as a browser would and talks to its standard input
//! and output. Larsal's side is Larsal's own bridge socket (larsal-browser, E7-S1)
//! in a fresh folder under /tmp, which the relay finds through
//! `LARSAL_TEST_INSTANCE_DIR` (INT-01.10: never the owner's Library). Every
//! process a test starts is stopped by its PID.

// Larsal's own name for the socket, so the relay and Larsal are tested together.
use larsal_browser::{BRIDGE_SOCKET, Bridge, Clock, Handler, Request, Route, Server};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::bridge::Secret;
use larsal_model::json::{self, Map, Value};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const INSTANCE_SOCKET: &str = "app.larsal.desktop-debug.sock";

struct Nothing;

impl Handler for Nothing {
    fn handle(&mut self, _: &Request<'_>) -> Result<Map, u8> {
        Ok(Map::new())
    }
}

static FOLDERS: AtomicU64 = AtomicU64::new(0);

/// A test instance folder under /tmp, with Larsal's bridge socket and Larsal's
/// instance socket when the test starts them.
struct Folder {
    dir: PathBuf,
    app: Option<Server>,
    instance: Option<UnixListener>,
}

impl Folder {
    fn new() -> Self {
        let n = FOLDERS.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(format!("/tmp/larsal-bridge-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            dir,
            app: None,
            instance: None,
        }
    }

    /// Larsal runs with S-BRW-01 on: its instance socket and its bridge socket.
    fn start_app(&mut self) {
        self.app_runs();
        let bridge = Arc::new(Mutex::new(Bridge::new("1.0", Box::new(Nothing))));
        let clock: Clock = Arc::new(Instant::now);
        self.app =
            Some(Server::start(&self.dir.join(BRIDGE_SOCKET), Route::Port, bridge, clock).unwrap());
    }

    /// Larsal runs with S-BRW-01 off: only its instance socket listens.
    fn app_runs(&mut self) {
        if self.instance.is_none() {
            self.instance = Some(UnixListener::bind(self.dir.join(INSTANCE_SOCKET)).unwrap());
        }
    }

    /// Larsal quits: both sockets close and go.
    fn quit_app(&mut self) {
        if let Some(app) = self.app.take() {
            app.stop();
        }
        self.instance = None;
        let _ = std::fs::remove_file(self.dir.join(INSTANCE_SOCKET));
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        self.quit_app();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A running `larsal-bridge` with its standard output read frame by frame.
struct Host {
    child: Child,
    stdin: Option<ChildStdin>,
    frames: Receiver<Vec<u8>>,
}

impl Host {
    fn start(dir: &Path, args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_larsal-bridge"))
            .args(args)
            .env("LARSAL_TEST_INSTANCE_DIR", dir)
            .env("TMPDIR", "/tmp/x-larsal-bridge-not-used")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let mut stdout = child.stdout.take().unwrap();
        let (tx, frames) = mpsc::channel();
        std::thread::spawn(move || {
            loop {
                let mut head = [0u8; 4];
                if stdout.read_exact(&mut head).is_err() {
                    return;
                }
                // The raw bytes, length included, so a test sees exactly
                // what the browser would.
                let len = u32::from_le_bytes(head) as usize;
                let mut body = vec![0u8; len.min(2 * 1_048_576)];
                if stdout.read_exact(&mut body).is_err() {
                    let _ = tx.send(head.to_vec());
                    return;
                }
                if tx.send(body).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            stdin,
            frames,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    fn send(&mut self, body: &[u8]) {
        self.write(&frame(body));
    }

    /// The next frame on standard output within 3 s.
    fn reply(&self) -> Option<Value> {
        let body = self.frames.recv_timeout(Duration::from_secs(3)).ok()?;
        Some(json::from_slice(&body).expect("stdout holds only JSON frames"))
    }

    /// Nothing more on standard output within `wait`.
    fn quiet(&self, wait: Duration) -> bool {
        self.frames.recv_timeout(wait).is_err()
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Waits up to `limit` for the process to end.
    fn exited_within(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    fn stderr(&mut self) -> String {
        let mut text = String::new();
        if let Some(mut err) = self.child.stderr.take() {
            err.read_to_string(&mut text).unwrap();
        }
        text
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // Stopped by its PID, never by name (AGENTS rule 11).
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut f = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    f.extend_from_slice(body);
    f
}

fn hello() -> Vec<u8> {
    let key = base64::encode(Form::Padded, &Secret::generate().unwrap().public());
    format!(r#"{{"type":"hello","versions":[1],"key":"{key}","browser":"Chrome"}}"#).into_bytes()
}

fn error(n: u32) -> Value {
    json::from_str(&format!(r#"{{"type":"error","error":{n}}}"#)).unwrap()
}

fn kind(v: &Value) -> Option<&str> {
    v.get("type").and_then(Value::as_str)
}

/// T01 INT-01.1: a framed hello on standard input gets Larsal's hello reply
/// as one frame on standard output, and nothing else is ever written there
/// or on standard error.
#[test]
fn t01_hello_through_the_relay_gets_apps_reply_and_stdout_holds_only_frames() {
    let mut folder = Folder::new();
    folder.start_app();
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&hello());
    let reply = host.reply().expect("a reply frame");
    assert_eq!(kind(&reply), Some("hello"));
    assert!(reply.get("sid").and_then(Value::as_str).is_some());
    host.close_stdin();
    assert!(host.exited_within(Duration::from_secs(2)).is_some());
    assert!(
        host.quiet(Duration::from_millis(200)),
        "more than one frame"
    );
    assert_eq!(host.stderr(), "");
}

/// INT-01.2 through the relay: a frame split over two writes, and two
/// frames in one write, give one reply each, in order. The length decides;
/// nothing looks for `}`.
#[test]
fn t02_t03_split_and_joined_frames_pass_unchanged_and_in_order() {
    let mut folder = Folder::new();
    folder.start_app();
    let mut host = Host::start(&folder.dir, &[]);
    let whole = frame(&hello());
    host.write(&whole[..2]);
    std::thread::sleep(Duration::from_millis(100));
    host.write(&whole[2..]);
    assert_eq!(kind(&host.reply().unwrap()), Some("hello"));
    let mut two = frame(&hello());
    two.extend(frame(br#"{"type":"nonsense"}"#));
    host.write(&two);
    assert_eq!(kind(&host.reply().unwrap()), Some("hello"));
    assert_eq!(host.reply().unwrap(), error(12));
}

/// T05 INT-01.3: a length of 1,048,577 is refused before any byte of the
/// body is read: with only the 4 length bytes sent and standard input kept
/// open, the relay writes the plain error 43 and exits. (A relay that read
/// or reserved the body first would wait here for bytes that never come.)
#[test]
fn t05_a_length_over_1_mib_gets_43_before_the_body_and_the_relay_exits() {
    let mut folder = Folder::new();
    folder.start_app();
    let mut host = Host::start(&folder.dir, &[]);
    host.write(&1_048_577u32.to_le_bytes());
    assert_eq!(host.reply(), Some(error(43)));
    let status = host.exited_within(Duration::from_secs(2)).expect("exited");
    assert!(status.success());
}

/// INT-01.3: exactly 1,048,576 bytes is still a frame: it is copied to Larsal,
/// which answers it (all blanks: the plain error 13 of an empty message).
#[test]
fn t05_a_frame_of_exactly_1_mib_is_relayed() {
    let mut folder = Folder::new();
    folder.start_app();
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&vec![b' '; 1_048_576]);
    assert_eq!(host.reply(), Some(error(13)));
}

/// T07 INT-01.5: no Larsal process: every frame gets 44, and the relay keeps
/// running.
#[test]
fn t07_no_app_every_frame_gets_44() {
    let folder = Folder::new();
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&hello());
    assert_eq!(host.reply(), Some(error(44)));
    host.send(&hello());
    assert_eq!(host.reply(), Some(error(44)));
    assert!(host.child.try_wait().unwrap().is_none(), "the relay quit");
}

/// T07 INT-01.5 after a real quit: Larsal's instance socket file may stay in
/// the folder; a file that takes no connection is no running Larsal: 44.
#[test]
fn t07_a_leftover_instance_socket_file_is_no_running_app() {
    let folder = Folder::new();
    drop(UnixListener::bind(folder.dir.join(INSTANCE_SOCKET)).unwrap());
    assert!(folder.dir.join(INSTANCE_SOCKET).exists());
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&hello());
    assert_eq!(host.reply(), Some(error(44)));
}

/// T08 INT-01.5: Larsal runs (its instance socket answers) but S-BRW-01 is
/// off (no bridge socket): 45.
#[test]
fn t08_app_running_with_integration_off_gets_45() {
    let mut folder = Folder::new();
    folder.app_runs();
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&hello());
    assert_eq!(host.reply(), Some(error(45)));
}

/// T09 INT-01.5: Larsal starts after the relay: the same process reaches it
/// at the next frame, so a browser port survives Larsal starting later.
#[test]
fn t09_app_started_later_is_reached_by_the_same_relay() {
    let mut folder = Folder::new();
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&hello());
    assert_eq!(host.reply(), Some(error(44)));
    folder.start_app();
    host.send(&hello());
    assert_eq!(kind(&host.reply().unwrap()), Some("hello"));
}

/// T10 INT-01.5: Larsal quits while a session is open: the relay goes back to
/// "not reachable", and the next frame gets 44.
#[test]
fn t10_app_quits_next_frame_gets_44() {
    let mut folder = Folder::new();
    folder.start_app();
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&hello());
    assert_eq!(kind(&host.reply().unwrap()), Some("hello"));
    folder.quit_app();
    std::thread::sleep(Duration::from_millis(200));
    host.send(&hello());
    assert_eq!(host.reply(), Some(error(44)));
    // And Larsal back again: reached once more by the same process.
    folder.start_app();
    host.send(&hello());
    assert_eq!(kind(&host.reply().unwrap()), Some("hello"));
}

/// INT-01.5: Larsal quits and starts again between two frames: the relay
/// sees the old link is gone and reaches the new Larsal at once, without a
/// 44 for a frame that Larsal could take.
#[test]
fn t09_app_restarted_between_frames_is_reached_at_the_next_frame() {
    let mut folder = Folder::new();
    folder.start_app();
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&hello());
    assert_eq!(kind(&host.reply().unwrap()), Some("hello"));
    folder.quit_app();
    folder.start_app();
    std::thread::sleep(Duration::from_millis(200));
    host.send(&hello());
    assert_eq!(kind(&host.reply().unwrap()), Some("hello"));
}

/// T11 INT-01.5: the browser closes the port (end of standard input): the
/// relay exits within 1 second, also while Larsal is connected.
#[test]
fn t11_end_of_stdin_exits_within_1_second() {
    let mut folder = Folder::new();
    folder.start_app();
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&hello());
    assert!(host.reply().is_some());
    host.close_stdin();
    let status = host.exited_within(Duration::from_secs(1)).expect("exited");
    assert!(status.success());
}

/// INT-01.5: SIGTERM (Firefox's stop), SIGINT and SIGHUP end the relay at
/// once.
#[test]
fn int01_5_quit_signals_end_the_relay_at_once() {
    let mut folder = Folder::new();
    folder.start_app();
    for signal in ["-TERM", "-INT", "-HUP"] {
        let mut host = Host::start(&folder.dir, &[]);
        host.send(&hello());
        assert!(host.reply().is_some());
        let pid = host.child.id().to_string();
        let killed = Command::new("/bin/kill")
            .args([signal, &pid])
            .status()
            .unwrap();
        assert!(killed.success());
        let status = host.exited_within(Duration::from_secs(1)).expect(signal);
        assert!(!status.success(), "{signal}");
    }
}

/// T66 INT-01.4: Chrome's caller origin, or Firefox's manifest path and
/// add-on id, change nothing: both get Larsal's hello reply, and standard
/// output holds only frames.
#[test]
fn t66_browser_arguments_are_ignored() {
    let mut folder = Folder::new();
    folder.start_app();
    for args in [
        &["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"][..],
        &[
            "/tmp/home/Library/Application Support/Mozilla/NativeMessagingHosts/app.larsal.browser.json",
            "browser@larsal.invalid",
        ][..],
    ] {
        let mut host = Host::start(&folder.dir, args);
        host.send(&hello());
        assert_eq!(kind(&host.reply().unwrap()), Some("hello"), "{args:?}");
        host.close_stdin();
        assert!(host.exited_within(Duration::from_secs(1)).is_some());
        assert!(host.quiet(Duration::from_millis(100)));
    }
}

/// INT-01.3: Larsal never sends a frame over 1 MiB; a socket that says it
/// would ends the link, and nothing of it reaches the browser (Chrome and
/// Firefox stop a host that writes more than 1 MB).
#[test]
fn int01_3_a_frame_over_1_mib_from_the_socket_never_reaches_the_browser() {
    let folder = Folder::new();
    let listener = UnixListener::bind(folder.dir.join(BRIDGE_SOCKET)).unwrap();
    let fake = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).unwrap();
        let mut body = vec![0u8; u32::from_le_bytes(head) as usize];
        s.read_exact(&mut body).unwrap();
        // The whole oversized frame, so a relay that took it could pass it on.
        // A relay that refuses it stops reading, so the write may stall.
        s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut reply = 1_048_577u32.to_le_bytes().to_vec();
        reply.extend(vec![b' '; 1_048_577]);
        let _ = s.write_all(&reply);
        std::thread::sleep(Duration::from_millis(500));
    });
    let mut host = Host::start(&folder.dir, &[]);
    host.send(&hello());
    assert!(
        host.quiet(Duration::from_secs(1)),
        "an oversized frame was relayed"
    );
    fake.join().unwrap();
}
