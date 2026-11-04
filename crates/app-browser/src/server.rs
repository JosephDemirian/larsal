//! App's two listeners (INT-01.2, INT-01.3, INT-01.6, INT-01.13,
//! INT-01.44): a Unix socket for each route, framed messages, the peer
//! check and the connection limit. Where each socket lives and when it is
//! on (S-BRW-01, the Safari switch, the app-group folder) is E7-S6's.

use crate::channel::{Bridge, Route, Step};
use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The largest frame either way: JSON bytes after the 4-byte length (INT-01.3).
pub const MAX_FRAME: usize = 1_048_576;
/// Connections to one socket at once; one more is closed at once (INT-01.44).
pub const MAX_CONNECTIONS: usize = 16;
/// The longest socket path macOS takes (`sun_path`, 104 bytes with its NUL).
pub const MAX_SOCKET_PATH: usize = 103;
/// How often the accept loop wakes to stop and to end idle Safari sessions.
const TICK: Duration = Duration::from_millis(50);
/// A peer that does not read its replies for this long is closed, so it
/// never holds a reply or a notice for longer.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The time source of the channel: `Instant::now` in App, a clock the test
/// moves in tests (INT-01.14 without a 15-minute wait).
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Connection numbers, unique in the process across both listeners.
static CONNECTIONS: AtomicU64 = AtomicU64::new(1);

/// Reads the user id of a connection's peer for the check of INT-01.6:
/// `getpeereid` in App; a test gives one that names another user (T14).
type PeerUid = fn(&UnixStream) -> io::Result<u32>;

/// The peer program check of signed builds (INT-01.7): true when the
/// connecting process is one of App's own relays, signed by App's team.
/// [`crate::Listeners`] makes it from app-platform's code signature check;
/// tests give their own.
pub type Program = Arc<dyn Fn(&UnixStream) -> bool + Send + Sync>;

struct Shared {
    bridge: Arc<Mutex<Bridge>>,
    route: Route,
    clock: Clock,
    peer: PeerUid,
    program: Option<Program>,
    stop: AtomicBool,
    /// Each open connection, for replies, notices and the stop.
    open: Mutex<HashMap<u64, Arc<Conn>>>,
}

/// One open connection: writes take `write`, so frames never interleave;
/// a shutdown needs no lock.
struct Conn {
    stream: UnixStream,
    write: Mutex<()>,
}

impl Shared {
    fn bridge(&self) -> MutexGuard<'_, Bridge> {
        self.bridge.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open(&self) -> MutexGuard<'_, HashMap<u64, Arc<Conn>>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One listening socket of one [`Route`], serving a shared [`Bridge`].
///
/// Guarantees: the socket is mode 0600; only processes of this user are
/// served (peer user id, INT-01.6); at most [`MAX_CONNECTIONS`] at once;
/// a frame of length 0 or over [`MAX_FRAME`] closes its connection before
/// any of its body is read or reserved, and so does a stream that ends
/// inside a frame (INT-01.2, INT-01.3); the frame length decides, App never
/// looks for `}`. Bridge work runs on threads of its own, never the
/// caller's. Stopping (or dropping) closes every connection, ends the
/// route's sessions and removes the socket.
pub struct Server {
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
    socket: PathBuf,
    id: (u64, u64),
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Server({:?}, {})",
            self.shared.route,
            self.socket.display()
        )
    }
}

impl Server {
    /// Listens on `socket` for `route`. The folder must exist and belong to
    /// the user; a leftover file of the socket's name is removed only when
    /// it is a socket of the user (INT-01.6).
    ///
    /// # Errors
    /// `InvalidInput` for a path over [`MAX_SOCKET_PATH`] bytes;
    /// `PermissionDenied` when the folder is not the user's; `AlreadyExists`
    /// when anything else is in the way (left untouched, MI01-06); and the
    /// system's error when binding fails. Nothing is served then.
    pub fn start(
        socket: &Path,
        route: Route,
        bridge: Arc<Mutex<Bridge>>,
        clock: Clock,
    ) -> io::Result<Self> {
        Self::start_with(
            socket,
            route,
            bridge,
            clock,
            app_platform::macos::peer_uid,
            None,
        )
    }

    /// [`Server::start`] in a signed build: after the user id, each
    /// connection must also pass `program` (INT-01.7), or it is closed
    /// before anything is read.
    ///
    /// # Errors
    /// As [`Server::start`].
    pub fn start_checked(
        socket: &Path,
        route: Route,
        bridge: Arc<Mutex<Bridge>>,
        clock: Clock,
        program: Program,
    ) -> io::Result<Self> {
        let peer = app_platform::macos::peer_uid;
        Self::start_with(socket, route, bridge, clock, peer, Some(program))
    }

    /// [`Server::start`] with the peer check's user id read by `peer`.
    fn start_with(
        socket: &Path,
        route: Route,
        bridge: Arc<Mutex<Bridge>>,
        clock: Clock,
        peer: PeerUid,
        program: Option<Program>,
    ) -> io::Result<Self> {
        if socket.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "socket path too long",
            ));
        }
        let own = app_platform::macos::effective_uid();
        let folder = socket
            .parent()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "no folder"))?;
        let meta = std::fs::symlink_metadata(folder)?;
        if !meta.is_dir() || meta.uid() != own {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "the folder is not the user's",
            ));
        }
        if let Ok(old) = std::fs::symlink_metadata(socket) {
            if !old.file_type().is_socket() || old.uid() != own {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "something else is there",
                ));
            }
            std::fs::remove_file(socket)?;
        }
        let listener = UnixListener::bind(socket)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        let meta = std::fs::symlink_metadata(socket)?;
        let id = (meta.dev(), meta.ino());
        listener.set_nonblocking(true)?;
        let shared = Arc::new(Shared {
            bridge,
            route,
            clock,
            peer,
            program,
            stop: AtomicBool::new(false),
            open: Mutex::new(HashMap::new()),
        });
        let worker = Arc::clone(&shared);
        let accept = thread::Builder::new()
            .name("app-bridge-accept".into())
            .spawn(move || accept_loop(&worker, &listener))
            .inspect_err(|_| {
                let _ = std::fs::remove_file(socket);
            })?;
        Ok(Self {
            shared,
            accept: Some(accept),
            socket: socket.to_owned(),
            id,
        })
    }

    /// The socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Sends [`Bridge::notice`]'s notices to their connections on this
    /// socket (INT-01.46: the [`Route::Port`] route only).
    pub fn notify(&self, event: &str, to: impl Fn(Option<&[u8; 32]>) -> bool) {
        if self.shared.route != Route::Port {
            return;
        }
        let notices = self.shared.bridge().notice(event, to);
        for (conn, message) in notices {
            let target = self.shared.open().get(&conn).cloned();
            if let Some(target) = target {
                let _ = write_frame(&target, &message);
            }
        }
    }

    /// Stops serving (see the type's guarantees).
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        for conn in self.shared.open().values() {
            let _ = conn.stream.shutdown(std::net::Shutdown::Both);
        }
        self.shared.bridge().end(self.shared.route);
        if std::fs::symlink_metadata(&self.socket).is_ok_and(|m| (m.dev(), m.ino()) == self.id) {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.accept.is_some() {
            self.shutdown();
        }
    }
}

fn accept_loop(shared: &Arc<Shared>, listener: &UnixListener) {
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => admit(shared, stream),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => {
                let now = (shared.clock)();
                shared.bridge().expire(now);
                thread::sleep(TICK);
            }
        }
    }
}

/// INT-01.6, INT-01.7, INT-01.44: the user's processes only, in a signed
/// build only App's own relays, at most [`MAX_CONNECTIONS`]; any other is
/// closed at once.
fn admit(shared: &Arc<Shared>, stream: UnixStream) {
    // Accepted sockets inherit the listener's non-blocking mode on macOS.
    let same_user =
        (shared.peer)(&stream).is_ok_and(|uid| uid == app_platform::macos::effective_uid());
    if stream.set_nonblocking(false).is_err()
        || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
        || !same_user
        || shared.program.as_ref().is_some_and(|ours| !ours(&stream))
    {
        return;
    }
    let conn = CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    {
        let mut open = shared.open();
        if open.len() >= MAX_CONNECTIONS {
            return;
        }
        let Ok(writer) = stream.try_clone() else {
            return;
        };
        let write = Mutex::new(());
        open.insert(
            conn,
            Arc::new(Conn {
                stream: writer,
                write,
            }),
        );
    }
    let worker = Arc::clone(shared);
    let started = thread::Builder::new()
        .name("app-bridge-connection".into())
        .spawn(move || serve(&worker, conn, stream));
    if started.is_err() {
        shared.open().remove(&conn);
    }
}

fn serve(shared: &Shared, conn: u64, mut stream: UnixStream) {
    let writer = shared.open().get(&conn).cloned();
    if let Some(writer) = writer {
        while let Some(message) = read_frame(&mut stream) {
            if shared.stop.load(Ordering::SeqCst) {
                break;
            }
            let now = (shared.clock)();
            // The bridge's lock is let go before a request runs.
            let step = shared.bridge().begin(conn, shared.route, &message, now);
            let reply = match step {
                Step::Reply(reply) => Some(reply),
                Step::Close => None,
                // INT-01.44: on a bridge connection a request that waits
                // for the user holds up none of its session's others, so
                // it runs on a thread of its own; its reply comes when it
                // is done, matched by `req`. A Safari connection carries
                // one message.
                Step::Work(work) if shared.route == Route::Port => {
                    let out = Arc::clone(&writer);
                    // ponytail: a thread per request, at most 8 per
                    // session and 16 sessions; if none can start, the
                    // request is dropped without a reply.
                    let _ = thread::Builder::new()
                        .name("app-bridge-request".into())
                        .spawn(move || {
                            if let Some(reply) = work.finish() {
                                let _ = write_frame(&out, &reply);
                            }
                        });
                    continue;
                }
                Step::Work(work) => work.finish(),
            };
            if reply.is_none_or(|r| write_frame(&writer, &r).is_err()) {
                break;
            }
        }
    }
    shared.open().remove(&conn);
    shared.bridge().closed(conn);
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// One frame's JSON bytes (INT-01.2, INT-01.3), as each socket reads them
/// (public for the fuzz target, INT-01.48); `None` closes the connection:
/// a length of 0 or over [`MAX_FRAME`] (before reading or reserving
/// anything for the body), or a stream that ends early.
pub fn read_frame(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).ok()?;
    let len = usize::try_from(u32::from_le_bytes(head)).ok()?;
    if len == 0 || len > MAX_FRAME {
        return None;
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).ok()?;
    Some(body)
}

/// Writes one frame; App never sends one over [`MAX_FRAME`] (INT-01.3).
fn write_frame(conn: &Conn, message: &[u8]) -> io::Result<()> {
    let len = u32::try_from(message.len())
        .ok()
        .filter(|_| message.len() <= MAX_FRAME)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "frame too large"))?;
    let mut frame = len.to_le_bytes().to_vec();
    frame.extend_from_slice(message);
    let _turn = conn.write.lock().unwrap_or_else(PoisonError::into_inner);
    (&conn.stream).write_all(&frame)
}

/// T14 (INT-01.6): the peer check. The run with a real second user is
/// W-08's; here the reader names another user, and the real reader is
/// checked with this user.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{Handler, Request};
    use app_crypto::base64::{self, Form};
    use app_crypto::bridge::Secret;
    use app_model::json::{self, Map, Value};

    struct Nothing;

    impl Handler for Nothing {
        fn handle(&mut self, _: &Request<'_>) -> Result<Map, u8> {
            Ok(Map::new())
        }
    }

    /// A fresh owner-only folder under /tmp, removed when dropped
    /// (INT-01.10: never the owner's Library).
    struct Folder(PathBuf);

    impl Folder {
        fn new(name: &str) -> Self {
            let dir = PathBuf::from(format!("/tmp/app-browser-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(dir)
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn other_user(_: &UnixStream) -> io::Result<u32> {
        Ok(app_platform::macos::effective_uid().wrapping_add(1))
    }

    /// Starts a bridge-socket server in `dir` with the peer reader `peer`.
    fn serve(dir: &Path, peer: PeerUid) -> (Server, Arc<Mutex<Bridge>>, PathBuf) {
        let bridge = Arc::new(Mutex::new(Bridge::new("1.0", Box::new(Nothing))));
        let path = dir.join("p.sock");
        let clock: Clock = Arc::new(Instant::now);
        let server =
            Server::start_with(&path, Route::Port, bridge.clone(), clock, peer, None).unwrap();
        (server, bridge, path)
    }

    /// Connects and sends one hello frame; returns App's reply frame, or
    /// `None` when App closed the connection without one (EOF in 2 s).
    fn hello(path: &Path) -> Option<Vec<u8>> {
        let mut s = UnixStream::connect(path).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let key = base64::encode(Form::Padded, &Secret::generate().unwrap().public());
        let body = format!(r#"{{"type":"hello","versions":[1],"key":"{key}"}}"#);
        let mut frame = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
        frame.extend_from_slice(body.as_bytes());
        // App may already have closed it; the read below tells.
        let _ = s.write_all(&frame);
        let mut head = [0u8; 4];
        match s.read_exact(&mut head) {
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => None,
            Err(e) => panic!("neither a reply nor a close: {e}"),
            Ok(()) => {
                let mut reply = vec![0u8; usize::try_from(u32::from_le_bytes(head)).unwrap()];
                s.read_exact(&mut reply).unwrap();
                Some(reply)
            }
        }
    }

    /// T14 INT-01.6: a peer of another user is closed right after
    /// `accept`, with no reply, and its hello makes no session.
    #[test]
    fn t14_another_users_connection_is_closed_with_no_reply() {
        let dir = Folder::new("t14-other");
        let (server, bridge, path) = serve(&dir.0, other_user);
        assert_eq!(hello(&path), None);
        assert_eq!(bridge.lock().unwrap().sessions(), 0);
        server.stop();
    }

    /// INT-01.6: the real peer check (`getpeereid`) reads this user's id
    /// on both ends of a connection, and serves this user's hello.
    #[test]
    fn real_peer_check_serves_the_same_user() {
        let own = app_platform::macos::effective_uid();
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(app_platform::macos::peer_uid(&a).unwrap(), own);
        assert_eq!(app_platform::macos::peer_uid(&b).unwrap(), own);
        let dir = Folder::new("t14-same");
        let bridge = Arc::new(Mutex::new(Bridge::new("1.0", Box::new(Nothing))));
        let path = dir.0.join("p.sock");
        let server = Server::start(&path, Route::Port, bridge, Arc::new(Instant::now)).unwrap();
        let reply = json::from_slice(&hello(&path).expect("a reply")).unwrap();
        assert_eq!(reply.get("type").and_then(Value::as_str), Some("hello"));
        server.stop();
    }
}
