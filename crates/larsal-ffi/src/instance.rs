//! One Larsal per user and build kind (APP-09.7 to APP-09.14): an exclusive
//! lock on a file and one Unix socket, both in the per-user temp folder the
//! OS reports. The socket is the only listener Larsal has (AT-E08).

use larsal_model::json;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// M09-01.
pub const PASSED_ON: &str = "Larsal is already running. The request was passed to it.";
/// M09-02.
pub const LOCKED: &str = "All open vaults were locked.";
/// M09-03.
pub const NOT_LOCKED: &str = "The vaults could not be locked.";
/// M09-04.
pub const NOT_RUNNING: &str = "No copy of Larsal is running, so there is nothing to lock.";
/// M09-05.
pub const NO_ANSWER: &str = "The running copy of Larsal does not answer. Quit it and try again.";

/// Debug builds use their own names, so a debug and a release copy never
/// meet (APP-09.29).
const BASE: &str = if cfg!(debug_assertions) {
    "app.larsal.desktop-debug"
} else {
    "app.larsal.desktop"
};

/// Debug builds and unit-test code only: the folder tests start Larsal in. Release builds read no
/// environment variable (LD-48); this code is not in them.
#[cfg(any(debug_assertions, test))]
pub const TEST_DIR_VARIABLE: &str = "LARSAL_TEST_INSTANCE_DIR";

/// Debug builds only: set by tests and Mac QA snapshots so Larsal runs with no
/// window and never becomes the active app (owner, 2026-10-27: test launches
/// must not take the screen). Release builds ignore it.
#[cfg(debug_assertions)]
pub const HIDDEN_VARIABLE: &str = "LARSAL_TEST_HIDDEN";

/// True in a debug build started with [`HIDDEN_VARIABLE`]; always false in
/// a release build.
#[must_use]
pub fn hidden() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(HIDDEN_VARIABLE).is_some()
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// The instance folder: the per-user temp folder from the OS (APP-09.7).
pub fn dir() -> io::Result<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os(TEST_DIR_VARIABLE) {
        return Ok(dir.into());
    }
    larsal_platform::macos::user_temp_dir()
}

/// True in a debug build started by a test (the M09-06 alert is skipped:
/// nobody can close it).
#[must_use]
pub fn started_by_test() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(TEST_DIR_VARIABLE).is_some()
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// The lock file and socket paths in an instance folder.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `app.larsal.desktop.lock`.
    pub lock: PathBuf,
    /// `app.larsal.desktop.sock`.
    pub socket: PathBuf,
}

impl Paths {
    /// The two paths in `dir`.
    #[must_use]
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            lock: dir.join(format!("{BASE}.lock")),
            socket: dir.join(format!("{BASE}.sock")),
        }
    }
}

/// M09-06: the lock or socket at `path` could not be made, for `reason`.
#[derive(Debug)]
pub struct Refused {
    path: PathBuf,
    reason: io::Error,
}

impl Refused {
    /// The M09-06 text, naming the path and the system's reason.
    #[must_use]
    pub fn message(&self) -> String {
        format!(
            "Larsal cannot start: the instance lock {} could not be created ({}).",
            self.path.display(),
            self.reason
        )
    }
}

/// APP-09.8: takes the exclusive lock without waiting. `Some(file)`: this
/// process is the primary while `file` lives (the OS drops the lock when the
/// process ends, crash included). `None`: another process holds it.
pub fn take_lock(paths: &Paths) -> Result<Option<File>, Refused> {
    let refused = |reason| Refused {
        path: paths.lock.clone(),
        reason,
    };
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&paths.lock)
        .map_err(refused)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(refused(error)),
    }
}

/// APP-09.8, APP-09.14: the primary removes a leftover socket file and
/// listens on a new one, mode 0600. Call only while holding the lock.
pub fn listen(paths: &Paths) -> Result<UnixListener, Refused> {
    let refused = |reason| Refused {
        path: paths.socket.clone(),
        reason,
    };
    match std::fs::remove_file(&paths.socket) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(refused(e)),
        _ => {}
    }
    let listener = UnixListener::bind(&paths.socket).map_err(refused)?;
    // The folder is 0700, so nobody else could reach the socket before this.
    std::fs::set_permissions(&paths.socket, std::fs::Permissions::from_mode(0o600))
        .map_err(refused)?;
    Ok(listener)
}

/// One channel request (APP-09.13).
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// Come to the front.
    Activate,
    /// Open these absolute paths (1 to 64).
    Open(Vec<PathBuf>),
    /// Lock every open vault.
    Lock,
}

/// Longest request line, newline included.
pub const MAX_LINE: usize = 65_536;
/// Most paths in one `open` request.
pub const MAX_PATHS: usize = 64;
/// Longest path in bytes (the macOS path limit).
pub const MAX_PATH: usize = 1024;

/// A request on the wire: `{"v":1,"cmd":"open","paths":[...]}`, members in
/// that order, `paths` only for `open`.
struct Wire {
    v: u64,
    cmd: String,
    paths: Option<Vec<String>>,
}

impl Wire {
    /// A JSON object of `v` (a whole number), `cmd` (a text) and `paths`
    /// (texts; missing or `null` is none), with no other member and none
    /// given twice.
    fn read(line: &[u8]) -> Option<Self> {
        let json::Value::Object(map) = json::from_slice_unique(line).ok()? else {
            return None;
        };
        if map
            .keys()
            .any(|k| !matches!(k.as_str(), "v" | "cmd" | "paths"))
        {
            return None;
        }
        let paths = match map.get("paths") {
            None | Some(json::Value::Null) => None,
            Some(list) => Some(
                list.as_array()?
                    .iter()
                    .map(|p| p.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()?,
            ),
        };
        Some(Self {
            v: map.get("v")?.as_u64()?,
            cmd: map.get("cmd")?.as_str()?.to_owned(),
            paths,
        })
    }

    /// The request line, newline included.
    fn line(&self) -> Vec<u8> {
        let mut line = format!(
            "{{\"v\":{},\"cmd\":{}",
            self.v,
            json::Value::from(self.cmd.as_str())
        );
        if let Some(paths) = &self.paths {
            line.push_str(&format!(",\"paths\":{}", json::Value::from(paths.clone())));
        }
        line.push_str("}\n");
        line.into_bytes()
    }
}

/// Reads one request line of at most [`MAX_LINE`] bytes and checks it.
/// `None` for anything else: a longer line, no newline, bad JSON, another
/// `v`, an unknown field or command, a relative or too long path, or no or
/// too many paths.
pub fn read_request(stream: impl Read) -> Option<Request> {
    let mut line = Vec::new();
    BufReader::new(stream.take(MAX_LINE as u64))
        .read_until(b'\n', &mut line)
        .ok()?;
    let wire = Wire::read(line.strip_suffix(b"\n")?)?;
    match (wire.v, wire.cmd.as_str(), wire.paths) {
        (1, "activate", None) => Some(Request::Activate),
        (1, "lock", None) => Some(Request::Lock),
        (1, "open", Some(paths))
            if (1..=MAX_PATHS).contains(&paths.len())
                && paths
                    .iter()
                    .all(|p| (1..=MAX_PATH).contains(&p.len()) && Path::new(p).is_absolute()) =>
        {
            Some(Request::Open(
                paths.into_iter().map(PathBuf::from).collect(),
            ))
        }
        _ => None,
    }
}

/// APP-09.14: only a peer running as this user may talk to the primary.
#[must_use]
pub fn same_user(peer: u32, own: u32) -> bool {
    peer == own
}

/// How long one connection may take to send its request line, in all.
const REQUEST_TIME: Duration = Duration::from_secs(1);

/// Reads `stream` until one deadline: before each read the timeout is set to
/// the time left, so a peer that sends a byte now and then cannot hold the
/// channel past it.
struct Deadline<'a> {
    stream: &'a UnixStream,
    end: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        (&mut &*self.stream).read(buf)
    }
}

/// The primary's side (APP-09.12 to APP-09.14), on its own thread. Each
/// connection: peer check against `own` (this process's user id), one
/// request read within one second in all, `handle` decides the answer, then
/// close.
pub fn serve(
    listener: UnixListener,
    own: u32,
    handle: impl Fn(Request) -> bool + Send + 'static,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name("instance-channel".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let peer = larsal_platform::macos::peer_uid(&stream);
                if !peer.is_ok_and(|uid| same_user(uid, own)) {
                    continue; // dropping the stream closes it before anything is read
                }
                let request = read_request(Deadline {
                    stream: &stream,
                    end: Instant::now() + REQUEST_TIME,
                });
                let Some(request) = request else {
                    continue;
                };
                let _ = stream.set_write_timeout(Some(REQUEST_TIME));
                let answer: &[u8] = if handle(request) {
                    b"{\"ok\":true}\n"
                } else {
                    b"{\"ok\":false}\n"
                };
                let _ = stream.write_all(answer);
            }
        })?;
    Ok(())
}

/// What became of a secondary's request (APP-09.9, APP-09.10).
#[derive(Debug, PartialEq, Eq)]
pub enum Sent {
    /// The primary answered: `true` for `{"ok":true}`.
    Answered(bool),
    /// Connected, but the primary closed or broke the connection without an answer.
    NotDelivered,
    /// No connection after three tries, or no answer within one second:
    /// the running copy does not answer (M09-05).
    NoAnswer,
}

/// The secondary's side: up to 3 connection tries 150 ms apart, one request,
/// then at most one second for the answer. Paths past the 64th are not sent.
pub fn send(socket: &Path, request: &Request) -> Sent {
    let wire = match request {
        Request::Activate => Wire {
            v: 1,
            cmd: "activate".into(),
            paths: None,
        },
        Request::Lock => Wire {
            v: 1,
            cmd: "lock".into(),
            paths: None,
        },
        Request::Open(paths) => Wire {
            v: 1,
            cmd: "open".into(),
            // ponytail: one request holds 64 paths; more files on one command line are dropped.
            paths: Some(
                paths
                    .iter()
                    .filter_map(|p| p.to_str().map(String::from))
                    .take(MAX_PATHS)
                    .collect(),
            ),
        },
    };
    let line = wire.line();
    let Some(mut stream) = connect(socket) else {
        return Sent::NoAnswer;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    if let Err(e) = stream.write_all(&line) {
        return if timed_out(&e) {
            Sent::NoAnswer
        } else {
            Sent::NotDelivered
        };
    }
    let mut answer = Vec::new();
    match BufReader::new((&stream).take(64)).read_until(b'\n', &mut answer) {
        Ok(_) if answer == b"{\"ok\":true}\n" => Sent::Answered(true),
        Ok(_) if answer == b"{\"ok\":false}\n" => Sent::Answered(false),
        Err(e) if timed_out(&e) => Sent::NoAnswer,
        _ => Sent::NotDelivered,
    }
}

fn connect(socket: &Path) -> Option<UnixStream> {
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(150));
        }
        if let Ok(stream) = UnixStream::connect(socket) {
            return Some(stream);
        }
    }
    None
}

fn timed_out(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("a09u-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn app09_7_names_follow_the_build_kind() {
        let p = Paths::in_dir(Path::new("/d"));
        // F-166: a release build has no suffix.
        let kind = if cfg!(debug_assertions) { "-debug" } else { "" };
        assert_eq!(
            p.lock,
            Path::new(&format!("/d/app.larsal.desktop{kind}.lock"))
        );
        assert_eq!(
            p.socket,
            Path::new(&format!("/d/app.larsal.desktop{kind}.sock"))
        );
        let real = Paths::in_dir(&larsal_platform::macos::user_temp_dir().unwrap());
        assert!(real.socket.as_os_str().len() < 104);
    }

    #[test]
    fn app09_8_one_lock_holder_until_it_is_released() {
        let dir = test_dir("lock");
        let paths = Paths::in_dir(&dir);
        let first = take_lock(&paths).unwrap();
        assert!(first.is_some());
        assert_eq!(mode(&paths.lock), 0o600);
        assert!(take_lock(&paths).unwrap().is_none());
        drop(first);
        assert!(take_lock(&paths).unwrap().is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn app09_8_b_folder_at_the_lock_path_gives_m09_06() {
        let dir = test_dir("folder");
        let paths = Paths::in_dir(&dir);
        std::fs::create_dir(&paths.lock).unwrap();
        let text = take_lock(&paths).unwrap_err().message();
        assert!(
            text.starts_with("Larsal cannot start: the instance lock "),
            "{text}"
        );
        assert!(text.contains(paths.lock.to_str().unwrap()), "{text}");
        assert!(text.contains("(Is a directory"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn app09_14_socket_is_0600_and_replaces_a_leftover() {
        let dir = test_dir("sock");
        let paths = Paths::in_dir(&dir);
        std::fs::write(&paths.socket, b"leftover").unwrap();
        let _listener = listen(&paths).unwrap();
        use std::os::unix::fs::FileTypeExt;
        let meta = std::fs::symlink_metadata(&paths.socket).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(mode(&paths.socket), 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn app09_14_a_other_user_is_refused_before_reading() {
        let dir = test_dir("peer");
        let paths = Paths::in_dir(&dir);
        let called = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&called);
        // As if this process ran as the next user id: the peer (this test) is
        // then another user.
        let own = larsal_platform::macos::effective_uid().wrapping_add(1);
        serve(listen(&paths).unwrap(), own, move |_| {
            seen.store(true, Ordering::SeqCst);
            true
        })
        .unwrap();
        let mut stream = UnixStream::connect(&paths.socket).unwrap();
        // macOS answers EINVAL (InvalidInput) when the primary has already
        // closed the stream: then the read below ends at once anyway.
        if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(3))) {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
        }
        let _ = stream.write_all(b"{\"v\":1,\"cmd\":\"activate\"}\n");
        let mut answer = Vec::new();
        let _ = stream.read_to_end(&mut answer);
        assert!(answer.is_empty(), "answered another user");
        assert!(
            !called.load(Ordering::SeqCst),
            "handled another user's request"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn app09_13_a_slow_sender_is_cut_off_at_the_deadline() {
        let dir = test_dir("slow");
        let paths = Paths::in_dir(&dir);
        let own = larsal_platform::macos::effective_uid();
        serve(listen(&paths).unwrap(), own, |_| true).unwrap();
        let mut slow = UnixStream::connect(&paths.socket).unwrap();
        let started = Instant::now();
        // One byte every 100 ms: each read is quick, the line never ends.
        let dripping = std::thread::spawn(move || {
            while slow.write_all(b" ").is_ok() && started.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(100));
            }
            started.elapsed()
        });
        std::thread::sleep(Duration::from_millis(500));
        // The next request is answered once the slow one is cut off.
        assert_eq!(
            send(&paths.socket, &Request::Activate),
            Sent::Answered(true)
        );
        let cut = dripping.join().unwrap();
        assert!(cut < Duration::from_millis(1500), "cut off after {cut:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn read(line: &[u8]) -> Option<Request> {
        read_request(line)
    }

    #[test]
    fn app09_13_good_requests() {
        assert_eq!(
            read(b"{\"v\":1,\"cmd\":\"activate\"}\n"),
            Some(Request::Activate)
        );
        assert_eq!(read(b"{\"v\":1,\"cmd\":\"lock\"}\n"), Some(Request::Lock));
        assert_eq!(
            read(b"{\"v\":1,\"cmd\":\"open\",\"paths\":[\"/tmp/a.larsalvault\"]}\n"),
            Some(Request::Open(vec![PathBuf::from("/tmp/a.larsalvault")]))
        );
        let paths: Vec<String> = (0..64).map(|i| format!("/tmp/{i}")).collect();
        let line = format!(
            "{}\n",
            larsal_model::json!({"v": 1, "cmd": "open", "paths": paths})
        );
        assert!(matches!(read(line.as_bytes()), Some(Request::Open(p)) if p.len() == 64));
    }

    #[test]
    fn app09_13_a_line_over_the_limit_is_dropped() {
        let mut line = b"{\"v\":1,\"cmd\":\"activate\",\"x\":\"".to_vec();
        line.resize(69_999, b'a');
        line.push(b'\n');
        assert_eq!(line.len(), 70_000);
        assert_eq!(read(&line), None);
    }

    #[test]
    fn app09_13_b_bad_requests_are_dropped() {
        let long = format!("/{}", "a".repeat(MAX_PATH));
        let too_many: Vec<String> = (0..65).map(|i| format!("/tmp/{i}")).collect();
        for line in [
            "{\"v\":1,\"cmd\":\"open\",\"paths\":[\"a.larsalvault\"]}\n".to_string(),
            format!(
                "{}\n",
                larsal_model::json!({"v": 1, "cmd": "open", "paths": too_many})
            ),
            format!(
                "{}\n",
                larsal_model::json!({"v": 1, "cmd": "open", "paths": [long]})
            ),
            "{\"v\":1,\"cmd\":\"open\",\"paths\":[]}\n".into(),
            "{\"v\":1,\"cmd\":\"open\",\"paths\":[\"\"]}\n".into(),
            "{\"v\":1,\"cmd\":\"open\"}\n".into(),
            "{\"v\":2,\"cmd\":\"activate\"}\n".into(),
            "{\"v\":1.0,\"cmd\":\"activate\"}\n".into(),
            "{\"v\":\"1\",\"cmd\":\"activate\"}\n".into(),
            "{\"cmd\":\"activate\"}\n".into(),
            "{\"v\":1,\"cmd\":\"activate\",\"paths\":[\"/a\"]}\n".into(),
            "{\"v\":1,\"cmd\":\"activate\",\"extra\":1}\n".into(),
            "{\"v\":1,\"cmd\":\"unlock\"}\n".into(),
            "{\"v\":1,\"cmd\":\"activate\"}".into(),
            "not json\n".into(),
            // An array in place of the object: refused since Larsal's own
            // reader (E0-S7 R12); the old derived reader took it.
            "[1,\"activate\"]\n".into(),
            "{\"v\":1,\"v\":1,\"cmd\":\"lock\"}\n".into(),
        ] {
            assert_eq!(read(line.as_bytes()), None, "{line}");
        }
    }

    #[test]
    fn app09_13_send_and_serve_talk() {
        let dir = test_dir("talk");
        let paths = Paths::in_dir(&dir);
        let own = larsal_platform::macos::effective_uid();
        serve(listen(&paths).unwrap(), own, |r| r != Request::Lock).unwrap();
        assert_eq!(
            send(&paths.socket, &Request::Activate),
            Sent::Answered(true)
        );
        assert_eq!(send(&paths.socket, &Request::Lock), Sent::Answered(false));
        let open = Request::Open(vec![PathBuf::from("/tmp/a.larsalvault")]);
        assert_eq!(send(&paths.socket, &open), Sent::Answered(true));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(send(&paths.socket, &Request::Activate), Sent::NoAnswer);
    }
}
