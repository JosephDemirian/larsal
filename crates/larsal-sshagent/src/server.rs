//! Larsal's own agent for keys that ask before each use (D-INT06-1 (b),
//! INT-06.32 to INT-06.36, R06-2 to R06-4; draft-ietf-sshm-ssh-agent).

use crate::agent::{
    EXTENSION, FAILURE, IDENTITIES_ANSWER, LOCK, REMOVE_ALL_IDENTITIES, REMOVE_IDENTITY,
    REQUEST_IDENTITIES, SIGN_REQUEST, SIGN_RESPONSE, SUCCESS, UNLOCK, own_socket, parse_identities,
    put_string, read_full, take_string, take_u32, write_full,
};
use crate::keyring::{Answer, Keyring};
use crate::messages::{fill, text};
use crate::{MAX_REPLY, MAX_SOCKET_PATH, TIMEOUT};
use larsal_crypto::secret::SecretBytes;
use std::collections::HashMap;
use std::io::{self, ErrorKind, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The question's time without an answer before it counts as Deny (INT-06.34).
pub const QUESTION_TIME: Duration = Duration::from_secs(60);
/// Clients served at once; one more is closed at once. One per `ssh` or
/// `git` in flight; more means something is wrong.
pub const MAX_CLIENTS: usize = 32;
/// How long a client may stay silent between messages before Larsal closes
/// it. Once a message started, all of it must arrive within [`TIMEOUT`].
pub const IDLE: Duration = Duration::from_secs(600);
/// Largest `known_hosts` Larsal reads to name a host (the first 4 MiB).
const MAX_KNOWN_HOSTS: u64 = 4 * 1_048_576;
/// How often the accept loop wakes to stop or drop keys whose lifetime ended.
const TICK: Duration = Duration::from_millis(50);
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// Asks the user before each signature (INT-06.34). The Mac app's dialog
/// implements it.
pub trait Asker: Send + Sync {
    /// Shows the question and blocks until the user answers: `true` is
    /// Allow Once. Called on a thread of its own, one question at a time.
    /// R06-6: the dialog comes up without any action in Larsal, so for its
    /// first second Return and Space do nothing; Escape and a click on Deny
    /// work at once.
    fn ask(&self, question: &Question) -> bool;
    /// The question ended without the user's answer (no answer within the
    /// question time, the key's vault locked, the key left Larsal's agent, or
    /// Larsal's agent stopped): close the dialog. Its later answer is ignored.
    fn cancel(&self, id: u64);
}

/// What the question shows (INT-06.34). Public data only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Unique per question and rising, across Larsal's agents too, for
    /// [`Asker::cancel`].
    pub id: u64,
    /// What the dialog calls the key: the entry title, or for a protected
    /// one the key's comment or fingerprint ([`crate::EntryKey::question_name`]).
    pub title: String,
    /// The key's comment.
    pub comment: String,
    /// The key's `SHA256:` fingerprint.
    pub fingerprint: String,
    /// The requesting program's name: a hint only, any process of the user
    /// can pick its name. `None` while Larsal cannot read it.
    pub program: Option<String>,
    /// The host of the connection's last checked session binding, named
    /// from a plain `known_hosts` line; `None` when unknown.
    pub host: Option<String>,
    /// A binding on this connection said it is forwarded (MI06-37).
    pub forwarded: bool,
}

impl Question {
    fn program(&self, start: bool) -> &str {
        match (&self.program, start) {
            (Some(p), _) => p,
            (None, true) => "A program",
            (None, false) => "a program",
        }
    }

    /// The dialog title, MI06-29.
    #[must_use]
    pub fn heading(&self) -> String {
        fill(
            text("MI06-29").unwrap_or_default(),
            &[
                ("‹program›", self.program(false)),
                ("‹entry title›", &self.title),
            ],
        )
    }

    /// The dialog text: MI06-30 with a known host, MI06-37 when it is
    /// forwarded, else MI06-31.
    #[must_use]
    pub fn text(&self) -> String {
        let id = match (&self.host, self.forwarded) {
            (Some(_), false) => "MI06-30",
            (Some(_), true) => "MI06-37",
            (None, _) => "MI06-31",
        };
        fill(
            text(id).unwrap_or_default(),
            &[
                ("‹program›", self.program(true)),
                ("‹host›", self.host.as_deref().unwrap_or_default()),
            ],
        )
    }
}

/// Where Larsal's agent lives and how long it asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The socket (INT-06.32).
    pub socket: PathBuf,
    /// The file that names hosts (INT-06.34).
    pub known_hosts: PathBuf,
    /// [`QUESTION_TIME`]; shorter in tests.
    pub question_time: Duration,
}

impl Options {
    /// The card's places for the user whose home folder is `home`:
    /// `~/Library/Application Support/Larsal/agent.sock` and
    /// `~/.ssh/known_hosts`.
    #[must_use]
    pub fn for_home(home: &Path) -> Self {
        Self {
            socket: home.join("Library/Application Support/Larsal/agent.sock"),
            known_hosts: home.join(".ssh/known_hosts"),
            question_time: QUESTION_TIME,
        }
    }
}

/// The line the settings row copies for `~/.ssh/config` (INT-06.36,
/// MI06-32): `IdentityAgent "<socket>"`, with `%` doubled (ssh_config
/// tokens) and `\` and `"` escaped by a backslash (its quoting).
#[must_use]
pub fn setup_line(socket: &Path) -> String {
    let path = socket
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("IdentityAgent \"{path}\"")
}

/// The first plain host name of a `known_hosts` line whose key is
/// `host_key` (INT-06.34): hashed names (`|1|…`), negations and patterns
/// with `*` or `?` cannot be named; `@cert-authority` and `@revoked` lines
/// are skipped.
#[must_use]
pub fn known_host_name(known_hosts: &str, host_key: &[u8]) -> Option<String> {
    let encoded = larsal_crypto::base64::encode(larsal_crypto::base64::Form::Padded, host_key);
    known_hosts.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with(['#', '@']) {
            return None;
        }
        let mut fields = line.split_whitespace();
        let (hosts, _kind, key) = (fields.next()?, fields.next()?, fields.next()?);
        if key != encoded {
            return None;
        }
        hosts
            .split(',')
            .find(|h| !h.is_empty() && !h.starts_with(['|', '!']) && !h.contains(['*', '?']))
            .map(str::to_owned)
    })
}

struct Shared {
    keyring: Arc<Keyring>,
    asker: Arc<dyn Asker>,
    known_hosts: PathBuf,
    question_time: Duration,
    stop: AtomicBool,
    clients: Mutex<HashMap<u64, UnixStream>>,
    /// Question tickets: (next to hand out, now asking).
    queue: Mutex<(u64, u64)>,
    turn: Condvar,
}

/// Question ids: unique and rising in the process, across Larsal's agents too,
/// because the [`Asker`] and the keyring outlive one agent (a turn-off and
/// a turn-on start a new one).
static QUESTION_IDS: AtomicU64 = AtomicU64::new(1);

impl Shared {
    fn queue(&self) -> MutexGuard<'_, (u64, u64)> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn clients(&self) -> MutexGuard<'_, HashMap<u64, UnixStream>> {
        self.clients.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Larsal's own agent: a Unix socket server for the keys of Larsal's
/// [`Keyring`] that ask before each use.
///
/// Guarantees: the socket is mode 0600 in a folder of mode 0700 and only
/// the current user's processes are served (peer user id); every signature
/// with an own key needs the [`Asker`]'s Allow Once, and none is made once
/// the key left Larsal's agent; Ed25519 and P-256 only; other keys and other
/// requests go to the system agent on one connection per client (R06-2);
/// messages over 256 KiB, slow clients and more than [`MAX_CLIENTS`] are
/// closed; no input panics. Stopping (or dropping) removes the socket.
pub struct OwnAgent {
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
    socket: PathBuf,
    id: (u64, u64),
}

impl std::fmt::Debug for OwnAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OwnAgent({})", self.socket.display())
    }
}

impl OwnAgent {
    /// Starts Larsal's agent (INT-06.32): makes the socket's folder (mode
    /// 0700; it must belong to the user), removes a stale file of the
    /// socket's name only when it is a socket of the user, binds the socket
    /// (mode 0600) and serves it on threads of its own. A path over 103
    /// bytes, a folder or file of another user, or anything else in the way
    /// is an error and nothing is served.
    pub fn start(
        options: Options,
        keyring: Arc<Keyring>,
        asker: Arc<dyn Asker>,
    ) -> io::Result<Self> {
        let socket = options.socket;
        let refuse = |what: &str| io::Error::new(ErrorKind::PermissionDenied, what.to_owned());
        if socket.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "socket path too long",
            ));
        }
        let own = larsal_platform::macos::effective_uid();
        let folder = socket.parent().ok_or_else(|| refuse("no folder"))?;
        std::fs::create_dir_all(folder)?;
        let meta = std::fs::symlink_metadata(folder)?;
        if !meta.is_dir() || meta.uid() != own {
            return Err(refuse("the folder is not the user's"));
        }
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700))?;
        if let Ok(old) = std::fs::symlink_metadata(&socket) {
            if !old.file_type().is_socket() || old.uid() != own {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "something else is there",
                ));
            }
            std::fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let meta = std::fs::symlink_metadata(&socket)?;
        let id = (meta.dev(), meta.ino());
        listener.set_nonblocking(true)?;
        own_socket(id, true);
        let shared = Arc::new(Shared {
            keyring,
            asker,
            known_hosts: options.known_hosts,
            question_time: options.question_time,
            stop: AtomicBool::new(false),
            clients: Mutex::new(HashMap::new()),
            queue: Mutex::new((0, 0)),
            turn: Condvar::new(),
        });
        let worker = Arc::clone(&shared);
        let accept = thread::Builder::new()
            .name("larsal-agent".into())
            .spawn(move || accept_loop(&worker, &listener))
            .inspect_err(|_| {
                let _ = std::fs::remove_file(&socket);
                own_socket(id, false);
            })?;
        Ok(Self {
            shared,
            accept: Some(accept),
            socket,
            id,
        })
    }

    /// The socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// [`setup_line`] for this socket.
    #[must_use]
    pub fn setup_line(&self) -> String {
        setup_line(&self.socket)
    }

    /// Stops serving: ends an open question as Deny, closes every client,
    /// removes the socket (only while it is still this one). The keys stay
    /// in the [`Keyring`]; [`Keyring::turn_off`] drops them.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.keyring.cancel_question();
        self.shared.turn.notify_all();
        for stream in self.shared.clients().values() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        if std::fs::symlink_metadata(&self.socket).is_ok_and(|m| (m.dev(), m.ino()) == self.id) {
            let _ = std::fs::remove_file(&self.socket);
        }
        own_socket(self.id, false);
    }
}

impl Drop for OwnAgent {
    fn drop(&mut self) {
        if self.accept.is_some() {
            self.shutdown();
        }
    }
}

fn accept_loop(shared: &Arc<Shared>, listener: &UnixListener) {
    let mut next = 0u64;
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                next = next.wrapping_add(1);
                admit(shared, stream, next);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => {
                shared.keyring.purge();
                thread::sleep(TICK);
            }
        }
    }
}

/// INT-06.32: only the user's processes, at most [`MAX_CLIENTS`]; others
/// are closed at once.
fn admit(shared: &Arc<Shared>, stream: UnixStream, id: u64) {
    // Accepted sockets inherit the listener's non-blocking mode on macOS.
    if stream.set_nonblocking(false).is_err()
        || !same_user(
            larsal_platform::macos::peer_uid(&stream),
            larsal_platform::macos::effective_uid(),
        )
    {
        return;
    }
    {
        let mut clients = shared.clients();
        if clients.len() >= MAX_CLIENTS {
            return;
        }
        let Ok(copy) = stream.try_clone() else {
            return;
        };
        clients.insert(id, copy);
    }
    let worker = Arc::clone(shared);
    let started = thread::Builder::new()
        .name("larsal-agent-client".into())
        .spawn(move || {
            serve(&worker, stream);
            worker.clients().remove(&id);
        });
    if started.is_err() {
        shared.clients().remove(&id);
    }
}

/// INT-06.32: the peer runs as this user; an unreadable peer is refused.
fn same_user(peer: io::Result<u32>, own: u32) -> bool {
    peer.is_ok_and(|uid| uid == own)
}

/// One client connection's state (R06-2).
#[derive(Default)]
struct Conn {
    /// The system agent, opened on first need, kept for the client's life.
    upstream: Option<UnixStream>,
    /// The host key and session ID of the last checked session binding.
    bound: Option<(Vec<u8>, Vec<u8>)>,
    /// Any binding said it is forwarded.
    forwarded: bool,
}

fn serve(shared: &Shared, mut stream: UnixStream) {
    let mut conn = Conn::default();
    while !shared.stop.load(Ordering::SeqCst) {
        let Some(msg) = read_message(&mut stream) else {
            return;
        };
        let reply = handle(shared, &mut conn, msg.expose());
        let Ok(len) = u32::try_from(reply.len()) else {
            return;
        };
        let deadline = Instant::now().checked_add(TIMEOUT);
        let sent = deadline.is_some_and(|d| {
            write_full(&mut stream, &len.to_be_bytes(), d).is_ok()
                && write_full(&mut stream, &reply, d).is_ok()
        });
        if !sent {
            return;
        }
    }
}

/// One message: the first byte within [`IDLE`], the rest within
/// [`TIMEOUT`]; empty or over [`MAX_REPLY`] ends the connection. Held in a
/// wiped buffer: an add forwarded through Larsal's socket carries a key.
fn read_message(stream: &mut UnixStream) -> Option<SecretBytes> {
    let mut len = [0u8; 4];
    stream.set_read_timeout(Some(IDLE)).ok()?;
    loop {
        match stream.read(len.get_mut(..1)?) {
            Ok(0) => return None,
            Ok(_) => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    let deadline = Instant::now().checked_add(TIMEOUT)?;
    read_full(stream, len.get_mut(1..)?, deadline).ok()?;
    let len = usize::try_from(u32::from_be_bytes(len)).ok()?;
    if len == 0 || len > MAX_REPLY {
        return None;
    }
    let mut msg = SecretBytes::zeroed(len);
    read_full(stream, msg.expose_mut(), deadline).ok()?;
    Some(msg)
}

fn handle(shared: &Shared, conn: &mut Conn, msg: &[u8]) -> Vec<u8> {
    let Some((&kind, body)) = msg.split_first() else {
        return vec![FAILURE];
    };
    match kind {
        REQUEST_IDENTITIES => list(shared, conn),
        SIGN_REQUEST => sign(shared, conn, msg, body),
        REMOVE_IDENTITY => {
            let mut rest = body;
            match take_string(&mut rest) {
                Some(blob) if shared.keyring.remove_own(blob) => vec![SUCCESS],
                _ => forward(shared, conn, msg),
            }
        }
        REMOVE_ALL_IDENTITIES => {
            shared.keyring.remove_all_own();
            forward_opt(shared, conn, msg).unwrap_or_else(|| vec![SUCCESS])
        }
        LOCK | UNLOCK => vec![FAILURE],
        EXTENSION => {
            let mut rest = body;
            if take_string(&mut rest) == Some(SESSION_BIND) {
                bind(shared, conn, msg, rest)
            } else {
                forward(shared, conn, msg)
            }
        }
        _ => forward(shared, conn, msg),
    }
}

/// 11: Larsal's keys, then the system agent's that Larsal does not hold, as many
/// as fit in one message.
fn list(shared: &Shared, conn: &mut Conn) -> Vec<u8> {
    let own = shared.keyring.own_list();
    let theirs = forward_opt(shared, conn, &[REQUEST_IDENTITIES])
        .and_then(|r| parse_identities(&r))
        .unwrap_or_default();
    let mut body = Vec::new();
    let mut count = 0u32;
    let entries = own.iter().map(|(b, c)| (b.as_slice(), c.as_bytes())).chain(
        theirs
            .iter()
            .filter(|i| !own.iter().any(|(b, _)| *b == i.blob))
            .map(|i| (i.blob.as_slice(), i.comment.as_bytes())),
    );
    for (blob, comment) in entries {
        let size = body
            .len()
            .saturating_add(blob.len())
            .saturating_add(comment.len())
            .saturating_add(13);
        if size > MAX_REPLY {
            break;
        }
        put_string(&mut body, blob);
        put_string(&mut body, comment);
        count = count.saturating_add(1);
    }
    let mut out = vec![IDENTITIES_ANSWER];
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// 13: a key Larsal holds is signed after Allow Once; others are forwarded.
fn sign(shared: &Shared, conn: &mut Conn, msg: &[u8], body: &[u8]) -> Vec<u8> {
    let mut rest = body;
    let (Some(blob), Some(data), Some(_flags)) = (
        take_string(&mut rest),
        take_string(&mut rest),
        take_u32(&mut rest),
    ) else {
        return vec![FAILURE];
    };
    let Some(own) = shared.keyring.own_key(blob) else {
        return forward(shared, conn, msg);
    };
    // LD-203 (2): a host is named only for a sign-in to the bound session.
    let host = conn
        .bound
        .as_ref()
        .filter(|(host_key, session)| sign_in_request(data, session, host_key, blob))
        .and_then(|(host_key, _)| {
            let mut text = String::new();
            std::fs::File::open(&shared.known_hosts)
                .ok()?
                .take(MAX_KNOWN_HOSTS)
                .read_to_string(&mut text)
                .ok()?;
            known_host_name(&text, host_key)
        });
    let question = Question {
        id: QUESTION_IDS.fetch_add(1, Ordering::Relaxed),
        title: own.title,
        comment: own.comment,
        fingerprint: own.fingerprint,
        program: None,
        host,
        forwarded: conn.forwarded,
    };
    if !ask(shared, &question, blob, &own.key) {
        return vec![FAILURE];
    }
    // The only strong reference outside Larsal's agent, for the signature only.
    let Some(key) = shared.keyring.take_for_signing(blob, &own.key) else {
        return vec![FAILURE];
    };
    let signed = key.sign(data);
    drop(key);
    match signed {
        Ok(signature) => {
            let mut out = vec![SIGN_RESPONSE];
            put_string(&mut out, &signature);
            out
        }
        Err(_) => vec![FAILURE],
    }
}

/// RFC 4252 section 7: `data` is a `publickey` sign-in request (or the
/// host-bound form `publickey-hostbound-v00@openssh.com`, whose server host
/// key must be `host_key`) for the key `key_blob`, carrying `session` as its
/// session ID, with nothing after it. As OpenSSH's agent checks it for keys
/// limited to hosts.
fn sign_in_request(data: &[u8], session: &[u8], host_key: &[u8], key_blob: &[u8]) -> bool {
    const USERAUTH_REQUEST: u8 = 50;
    let parse = || -> Option<bool> {
        let mut rest = data;
        let id = take_string(&mut rest)?;
        let (&kind, tail) = rest.split_first()?;
        rest = tail;
        let _user = take_string(&mut rest)?;
        let _service = take_string(&mut rest)?;
        let method = take_string(&mut rest)?;
        let (&with_signature, tail) = rest.split_first()?;
        rest = tail;
        let _algorithm = take_string(&mut rest)?;
        let key = take_string(&mut rest)?;
        let host_ok = match method {
            b"publickey" => true,
            b"publickey-hostbound-v00@openssh.com" => take_string(&mut rest)? == host_key,
            _ => false,
        };
        Some(
            id == session
                && kind == USERAUTH_REQUEST
                && with_signature == 1
                && key == key_blob
                && host_ok
                && rest.is_empty(),
        )
    };
    parse() == Some(true)
}

/// One question at a time, in arrival order (INT-06.34). `true` only for
/// the user's Allow Once within the question time while the key is held.
/// Holds no strong reference to the key while it waits or asks.
fn ask(
    shared: &Shared,
    question: &Question,
    blob: &[u8],
    key: &Weak<larsal_crypto::ssh::AgentKey>,
) -> bool {
    let ticket = {
        let mut q = shared.queue();
        let t = q.0;
        q.0 = t.wrapping_add(1);
        t
    };
    let mut q = shared.queue();
    while q.1 != ticket && !shared.stop.load(Ordering::SeqCst) {
        q = shared.turn.wait(q).unwrap_or_else(PoisonError::into_inner);
    }
    drop(q);
    let allowed = !shared.stop.load(Ordering::SeqCst) && put_question(shared, question, blob, key);
    let mut q = shared.queue();
    q.1 = q.1.wrapping_add(1);
    drop(q);
    shared.turn.notify_all();
    allowed
}

/// Shows the question only when Larsal's agent still holds `key`, checked
/// and registered in one step, so a lock always ends a question it shows.
fn put_question(
    shared: &Shared,
    question: &Question,
    blob: &[u8],
    key: &Weak<larsal_crypto::ssh::AgentKey>,
) -> bool {
    let (tx, rx) = mpsc::channel();
    if !shared
        .keyring
        .open_question(question.id, blob, key, tx.clone())
    {
        return false;
    }
    let asker = Arc::clone(&shared.asker);
    let shown = question.clone();
    let asked = thread::Builder::new()
        .name("larsal-agent-question".into())
        .spawn(move || {
            let yes = asker.ask(&shown);
            let _ = tx.send(Answer::User(yes));
        });
    let answer = match asked {
        Ok(_) => rx.recv_timeout(shared.question_time).ok(),
        Err(_) => None,
    };
    shared.keyring.close_question(question.id);
    match answer {
        Some(Answer::User(yes)) => yes,
        _ => {
            shared.asker.cancel(question.id);
            false
        }
    }
}

/// 27 `session-bind@openssh.com` (R06-2): an Ed25519 or P-256 host key
/// whose signature checks names the connection's host; a bad signature is
/// refused; a key Larsal cannot check leaves the host unknown. Then it goes to
/// the system agent on this connection; without one, a checked binding is
/// answered 6 and any other 5.
fn bind(shared: &Shared, conn: &mut Conn, msg: &[u8], body: &[u8]) -> Vec<u8> {
    let mut rest = body;
    let (Some(host_key), Some(session), Some(signature), Some(&forwarded)) = (
        take_string(&mut rest),
        take_string(&mut rest),
        take_string(&mut rest),
        rest.first(),
    ) else {
        return vec![FAILURE];
    };
    let checked = larsal_crypto::ssh::verify(host_key, session, signature);
    if checked == Some(false) {
        return vec![FAILURE];
    }
    conn.bound = checked.map(|_| (host_key.to_vec(), session.to_vec()));
    conn.forwarded |= forwarded != 0;
    let fallback = if checked.is_some() { SUCCESS } else { FAILURE };
    forward_opt(shared, conn, msg).unwrap_or_else(|| vec![fallback])
}

fn forward(shared: &Shared, conn: &mut Conn, msg: &[u8]) -> Vec<u8> {
    forward_opt(shared, conn, msg).unwrap_or_else(|| vec![FAILURE])
}

/// Passes `msg` to the system agent on this client's connection and
/// returns its reply; `None` when there is no system agent (also when it
/// is Larsal's own socket, R06-4) or it fails, which closes that connection.
fn forward_opt(shared: &Shared, conn: &mut Conn, msg: &[u8]) -> Option<Vec<u8>> {
    if conn.upstream.is_none() {
        conn.upstream = shared.keyring.system_agent().and_then(|a| a.connect()).ok();
    }
    let up = conn.upstream.as_mut()?;
    let reply = exchange(up, msg);
    if reply.is_none() {
        conn.upstream = None;
    }
    reply
}

fn exchange(up: &mut UnixStream, msg: &[u8]) -> Option<Vec<u8>> {
    let deadline = Instant::now().checked_add(TIMEOUT)?;
    let len = u32::try_from(msg.len()).ok()?;
    write_full(up, &len.to_be_bytes(), deadline).ok()?;
    write_full(up, msg, deadline).ok()?;
    let mut len = [0u8; 4];
    read_full(up, &mut len, deadline).ok()?;
    let len = usize::try_from(u32::from_be_bytes(len)).ok()?;
    if len == 0 || len > MAX_REPLY {
        return None;
    }
    let mut reply = vec![0; len];
    read_full(up, &mut reply, deadline).ok()?;
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryKey, Session, Settings, Source};
    use larsal_model::{Attachment, Entry, Group, Time, Uuid, Vault};
    use std::io::Write;
    use std::sync::mpsc::TryRecvError;

    /// Demo key K1 of spec INT-06 and a second Ed25519 demo key (`demo2@app`),
    /// both made by `ssh-keygen`.
    const K1: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAXBQ6tk+9cBEQnipP+gWQhhyC3TUJgLfuhlQjm1wPZhgAAAJCFFnN8hRZz
fAAAAAtzc2gtZWQyNTUxOQAAACAXBQ6tk+9cBEQnipP+gWQhhyC3TUJgLfuhlQjm1wPZhg
AAAEBFcbeDr4WGNkaX3X0F79RKibjugiw6qJhq2wgi7SoGGRcFDq2T71wERCeKk/6BZCGH
ILdNQmAt+6GVCObXA9mGAAAACGRlbW9AYXBwAQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";
    const K3: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDcaRZLjdHcFa/M29ofFvFwHt1Lt/7BfzfCxOB7JnA22wAAAJCbrZuTm62b
kwAAAAtzc2gtZWQyNTUxOQAAACDcaRZLjdHcFa/M29ofFvFwHt1Lt/7BfzfCxOB7JnA22w
AAAEA6VmJ6Phcz9/N9jqRz+S6mE68katEIixUD97Ki4ub20txpFkuN0dwVr8zb2h8W8XAe
3Uu3/sF/N8LE4HsmcDbbAAAACWRlbW8yQGFwcAECAwQ=
-----END OPENSSH PRIVATE KEY-----
";

    /// Loads `pem` for `session`; `asks` puts it in Larsal's own agent.
    fn load(keyring: &Keyring, pem: &str, session: u64, asks: bool) -> Vec<u8> {
        let settings = Settings {
            allow: true,
            confirm: asks,
            source: Source::Attachment,
            attachment_name: "k".into(),
            ..Settings::default()
        };
        let mut e = Entry::new(Uuid([1; 16]), Time(0));
        e.attachments.push(Attachment {
            name: "k".into(),
            data: Arc::new(SecretBytes::new(pem.as_bytes().to_vec())),
        });
        let v = Vault::new(Group::new(Uuid([2; 16]), "R".into(), Time(0)), Time(0));
        let root = Path::new("/");
        let key = EntryKey::read_with(&v, &e, settings, root, root, &|_| None).unwrap();
        let unlocked = key.unlock(&v, &e, root).unwrap();
        let session = Session {
            id: session,
            name: format!("V{session}"),
        };
        keyring.load(&session, &key, unlocked).unwrap();
        key.key().public_blob().to_vec()
    }

    /// Never answers; once cancelled it says Allow (to be ignored).
    #[derive(Default)]
    struct Quiet {
        asked: Mutex<Vec<u64>>,
        cancelled: Mutex<Vec<u64>>,
    }

    impl Asker for Quiet {
        fn ask(&self, q: &Question) -> bool {
            self.asked.lock().unwrap().push(q.id);
            let t0 = Instant::now();
            while !self.cancelled.lock().unwrap().contains(&q.id)
                && t0.elapsed() < Duration::from_secs(20)
            {
                thread::sleep(Duration::from_millis(5));
            }
            true
        }
        fn cancel(&self, id: u64) {
            self.cancelled.lock().unwrap().push(id);
        }
    }

    fn until(what: &str, done: impl Fn() -> bool) {
        let t0 = Instant::now();
        while !done() {
            assert!(t0.elapsed() < Duration::from_secs(10), "{what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn sign_on(socket: &Path, blob: &[u8]) -> thread::JoinHandle<Vec<u8>> {
        let socket = socket.to_path_buf();
        let mut body = vec![SIGN_REQUEST];
        put_string(&mut body, blob);
        put_string(&mut body, b"data");
        body.extend_from_slice(&[0; 4]);
        thread::spawn(move || {
            let mut c = UnixStream::connect(socket).unwrap();
            c.write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
                .unwrap();
            c.write_all(&body).unwrap();
            let mut len = [0; 4];
            c.read_exact(&mut len).unwrap();
            let mut reply = vec![0; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut reply).unwrap();
            reply
        })
    }

    /// A test's /tmp folder, removed on drop (also when the test fails).
    struct Tmp(PathBuf);

    impl Tmp {
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmp(tag: &str) -> Tmp {
        let dir = PathBuf::from(format!("/tmp/e9s2u-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Tmp(dir)
    }

    /// LD-203 (1): a request waiting behind another vault's question holds
    /// no strong reference, so the lock of its vault frees its key at once;
    /// when its turn comes, no question shows and it fails.
    #[test]
    fn ld203_1_lock_while_a_question_waits_frees_the_key_at_once() {
        let dir = tmp("wait");
        let keyring = Arc::new(Keyring::new());
        keyring.set_agent_settings(dir.join("none").to_str().unwrap(), None);
        let k1 = load(&keyring, K1, 1, true);
        let k3 = load(&keyring, K3, 2, true);
        let asker = Arc::new(Quiet::default());
        let options = Options {
            socket: dir.join("Larsal/agent.sock"),
            known_hosts: dir.join("kh"),
            question_time: Duration::from_secs(20),
        };
        let agent = OwnAgent::start(options, Arc::clone(&keyring), asker.clone()).unwrap();
        let first = sign_on(agent.socket(), &k3);
        until("the first question", || {
            asker.asked.lock().unwrap().len() == 1
        });
        let second = sign_on(agent.socket(), &k1);
        until("the second request waits", || agent.shared.queue().0 == 2);
        let weak = keyring.own_key(&k1).unwrap().key;
        keyring.lock(1);
        assert!(weak.upgrade().is_none(), "INT-06.31: freed at once");
        keyring.lock(2);
        assert_eq!(first.join().unwrap(), [FAILURE]);
        assert_eq!(second.join().unwrap(), [FAILURE]);
        assert_eq!(
            asker.asked.lock().unwrap().len(),
            1,
            "no question for a gone key"
        );
        agent.stop();
    }

    /// LD-203 (1): the question is registered only while the key is held,
    /// in one step; a lock just before it leaves nothing open, also when
    /// the same key was loaded again meanwhile.
    #[test]
    fn ld203_1_no_question_opens_for_a_key_gone_before_it_shows() {
        let keyring = Keyring::new();
        let k1 = load(&keyring, K1, 1, true);
        let weak = keyring.own_key(&k1).unwrap().key;
        keyring.lock(1);
        let (tx, rx) = mpsc::channel();
        assert!(!keyring.open_question(7, &k1, &weak, tx));
        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Disconnected)),
            "nothing registered"
        );
        load(&keyring, K1, 3, true);
        let (tx, rx) = mpsc::channel();
        assert!(
            !keyring.open_question(8, &k1, &weak, tx),
            "not the same key"
        );
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Disconnected)));
        assert!(keyring.take_for_signing(&k1, &weak).is_none());
    }

    /// LD-202 note: the lock frees Larsal's own keys at once, also while
    /// another operation waits on a silent system agent (2 s).
    #[test]
    fn ld202_lock_frees_own_keys_while_an_add_waits() {
        let dir = tmp("silent");
        let silent = std::os::unix::net::UnixListener::bind(dir.join("s")).unwrap();
        let keyring = Arc::new(Keyring::new());
        let k1 = load(&keyring, K1, 1, true);
        keyring.set_agent_settings(dir.join("s").to_str().unwrap(), None);
        let weak = keyring.own_key(&k1).unwrap().key;
        let adding = {
            let keyring = Arc::clone(&keyring);
            thread::spawn(move || {
                let settings = Settings {
                    allow: true,
                    source: Source::Attachment,
                    attachment_name: "k".into(),
                    ..Settings::default()
                };
                let mut e = Entry::new(Uuid([1; 16]), Time(0));
                e.attachments.push(Attachment {
                    name: "k".into(),
                    data: Arc::new(SecretBytes::new(K3.as_bytes().to_vec())),
                });
                let v = Vault::new(Group::new(Uuid([2; 16]), "R".into(), Time(0)), Time(0));
                let root = Path::new("/");
                let key = EntryKey::read_with(&v, &e, settings, root, root, &|_| None).unwrap();
                let unlocked = key.unlock(&v, &e, root).unwrap();
                let session = Session {
                    id: 1,
                    name: "V".into(),
                };
                keyring.load(&session, &key, unlocked)
            })
        };
        let (_held, _) = silent.accept().unwrap();
        let locking = {
            let keyring = Arc::clone(&keyring);
            thread::spawn(move || keyring.lock(1))
        };
        until("freed while the add waits", || weak.upgrade().is_none());
        assert!(
            !adding.is_finished(),
            "the add still waits on the silent agent"
        );
        assert!(adding.join().unwrap().is_err());
        let _ = locking.join().unwrap();
    }

    /// T52 (the part a test without a second user can reach): the peer
    /// check refuses another user id and a peer that cannot be read.
    #[test]
    fn t52_peer_of_another_user_is_refused() {
        assert!(same_user(Ok(501), 501));
        assert!(!same_user(Ok(502), 501));
        assert!(!same_user(Ok(0), 501));
        assert!(!same_user(Err(io::Error::other("no peer")), 501));
    }

    #[test]
    fn t72_setup_line_quotes_and_escapes() {
        assert_eq!(
            setup_line(Path::new(
                "/Users/a/Library/Application Support/Larsal/agent.sock"
            )),
            "IdentityAgent \"/Users/a/Library/Application Support/Larsal/agent.sock\""
        );
        assert_eq!(
            setup_line(Path::new("/tmp/50%\\x\"y")),
            "IdentityAgent \"/tmp/50%%\\\\x\\\"y\""
        );
    }

    #[test]
    fn int06_34_known_hosts_names_the_first_plain_host() {
        let key = b"\0\0\0\x0bssh-ed25519\0\0\0\x01k";
        let b64 = larsal_crypto::base64::encode(larsal_crypto::base64::Form::Padded, key);
        let text = format!(
            "# comment\n@revoked web00 ssh-ed25519 {b64}\n\
             |1|aGFzaA==|aGFzaA== ssh-ed25519 {b64}\n\
             other ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==\n\
             *.example,!bad,web01.example,10.0.0.1 ssh-ed25519 {b64} c\n"
        );
        assert_eq!(known_host_name(&text, key), Some("web01.example".into()));
        assert_eq!(known_host_name("|1|x|y ssh-ed25519 k\n", key), None);
        assert_eq!(known_host_name("", key), None);
    }

    #[test]
    fn mi06_29_to_37_question_texts() {
        let mut q = Question {
            id: 1,
            title: "Server root · web-01".into(),
            comment: "demo@app".into(),
            fingerprint: String::new(),
            program: Some("ssh".into()),
            host: Some("web01.example".into()),
            forwarded: false,
        };
        assert_eq!(q.heading(), "Allow ssh to use “Server root · web-01”?");
        assert_eq!(
            q.text(),
            "ssh wants to sign in to web01.example with this key."
        );
        q.forwarded = true;
        assert_eq!(
            q.text(),
            "ssh wants to sign in to web01.example through a forwarded connection."
        );
        q.host = None;
        q.program = None;
        assert_eq!(q.text(), "A program wants to sign with this key.");
        assert_eq!(
            q.heading(),
            "Allow a program to use “Server root · web-01”?"
        );
    }
}
