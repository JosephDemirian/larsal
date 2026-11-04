//! The channel (INT-01.20 to INT-01.28, INT-01.40 to INT-01.46): the hello,
//! the sessions found by `sid`, boxed requests and replies, the nonce sets,
//! the identification proof and notices. No I/O: [`crate::Server`] feeds it
//! one framed message at a time, with the time from its clock.

use app_crypto::base64::{self, Form};
use app_crypto::bridge::{self, KEY, NONCE, Secret};
use app_crypto::secret::{SecretBytes, ct_eq};
use app_model::json::{self, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The largest decrypted content of one box, either way (INT-01.24).
pub const MAX_CONTENT: usize = 655_360;
/// The deepest JSON nesting App reads (INT-01.25).
pub const MAX_DEPTH: usize = 32;
/// The most commas and opening brackets (`[`, `{`) outside strings, counted
/// together, in one message App reads (INT-01.25, LD-312): a bound on the
/// values the reader builds.
pub const MAX_VALUES: usize = 16_384;
/// The longest `url`, `top_url` or `form_url`, in bytes (INT-01.25).
pub const MAX_URL: usize = 8_192;
/// The longest `logins.search` `text` and `autotype.start` `search`, in
/// characters (INT-01.33, INT-01.36).
pub const MAX_TEXT: usize = 256;
/// Requests per session; then every box gets error 41 (INT-01.22).
pub const MAX_REQUESTS: u32 = 100_000;
/// A Safari session ends after this long without a request (INT-01.14).
pub const IDLE: Duration = Duration::from_secs(15 * 60);
/// Hellos App answers per second over all connections (INT-01.44).
pub const MAX_HELLOS: u32 = 20;
/// Safari sessions live at once; a Safari hello past it ends the Safari
/// session idle the longest (INT-01.44, LD-318 (3)).
pub const MAX_SAFARI: usize = 32;
/// Requests of one session in flight at once; one more gets error 42
/// (INT-01.44).
pub const MAX_IN_FLIGHT: usize = 8;
/// Requests of one session that wait for the user at once; one more gets
/// error 42 (INT-01.44).
pub const MAX_WAITING: usize = 4;

/// The highest `req` (2^53 - 1, INT-01.21).
const MAX_REQ: u64 = 9_007_199_254_740_991;
/// Protocol versions in a hello (INT-01.20).
const MAX_VERSIONS: usize = 16;
const PROOF: usize = 48;
/// The `browser` names App knows (INT-01.20); any other is `Browser`.
const BROWSERS: [&str; 9] = [
    "Safari", "Chrome", "Firefox", "Edge", "Brave", "Vivaldi", "Opera", "Chromium", "Arc",
];
/// The request types of INT-01.30; any other gets error 12.
const TYPES: [&str; 19] = [
    "status",
    "connect",
    "check",
    "unlock",
    "lock",
    "disconnect",
    "logins.find",
    "logins.get",
    "logins.search",
    "logins.recent",
    "logins.save",
    "logins.update",
    "code.get",
    "groups.list",
    "groups.create",
    "password.generate",
    "autotype.start",
    "passkey.create",
    "passkey.get",
];
/// The requests that carry `id_key` and `proof` (INT-01.28, INT-01.30).
const PROVING: [&str; 2] = ["connect", "check"];

/// The error numbers App sends itself (INT-01.40).
mod code {
    pub const NO_SESSION: u8 = 3;
    pub const NOT_OPENED: u8 = 4;
    pub const NOT_PROVEN: u8 = 8;
    pub const BAD_KEY: u8 = 10;
    pub const UNKNOWN: u8 = 12;
    pub const EMPTY: u8 = 13;
    pub const NO_VERSION: u8 = 40;
    pub const SEEN: u8 = 41;
    pub const BUSY: u8 = 42;
    pub const TOO_LARGE: u8 = 43;
}

/// The socket a message came in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// App's bridge socket, through `app-bridge` (the Chromium family and
    /// Firefox): a session belongs to the connection that said hello and
    /// ends when it closes (INT-01.21, INT-01.22).
    Port,
    /// The Safari socket: each message may come on a new connection, so a
    /// session is found by its `sid` alone and ends after [`IDLE`]
    /// without a request (INT-01.14).
    Safari,
}

/// One opened request, as the [`Handler`] sees it. No `Debug`: later
/// requests carry passwords (INT-01.47).
pub struct Request<'a> {
    /// Its `type`, one of INT-01.30's.
    pub kind: &'a str,
    /// The whole content object (`type`, `req` and the request fields).
    pub content: &'a Map,
    /// The hello's `browser` name, or `Browser` (INT-01.20).
    pub browser: &'a str,
    /// The identification key this session proved (INT-01.28), if any. For
    /// `connect` and `check` the proof of this very request has passed.
    pub identity: Option<&'a [u8; KEY]>,
    /// The session: whether it ended, and its requests that wait for the
    /// user (INT-01.44, INT-02.15).
    pub session: &'a Live,
    /// App's session public key A and the client's C (INT-01.20), for the
    /// pairing words (INT-02.5). Public keys, no secret.
    pub keys: (&'a [u8; KEY], &'a [u8; KEY]),
}

/// One session as its requests see it: whether it still lives, and how
/// many of its requests are in flight and wait for the user (INT-01.44).
#[derive(Debug, Default)]
pub struct Live {
    ended: AtomicBool,
    in_flight: AtomicUsize,
    waiting: AtomicUsize,
}

impl Live {
    /// The session ended (its connection closed, a new hello, the Safari
    /// idle time, S-BRW-01 off): a waiting dialog closes as Deny and the
    /// request is dropped without a reply (INT-01.45).
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }

    /// Ends the session: its waiting requests end without a reply.
    pub fn end(&self) {
        self.ended.store(true, Ordering::SeqCst);
    }

    /// One more request of this session waits for the user, until the
    /// guard drops; `None` when [`MAX_WAITING`] already wait (error 42).
    #[must_use]
    pub fn wait(&self) -> Option<Waiting<'_>> {
        take_one(&self.waiting, MAX_WAITING).then(|| Waiting(self))
    }
}

/// A request that waits for the user ([`Live::wait`]).
#[derive(Debug)]
pub struct Waiting<'a>(&'a Live);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Adds one to `count` unless it is at `max`.
fn take_one(count: &AtomicUsize, max: usize) -> bool {
    count
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < max).then(|| n.saturating_add(1))
        })
        .is_ok()
}

/// Answers opened requests: the vault side of INT-01.29 to INT-01.37
/// (stories E7-S2 to E7-S5). Called one request at a time.
pub trait Handler: Send {
    /// The reply fields for `request`, or an error number of INT-01.40.
    /// `type`, `req` and `error` are App's own: an `error` field is dropped,
    /// and `type` and `req` are set over any value the handler gives them.
    ///
    /// # Errors
    /// The error number the reply carries.
    fn handle(&mut self, request: &Request<'_>) -> Result<Map, u8>;
}

/// A [`Handler`] that answers many requests at once: one that waits for
/// the user (INT-02.15) never holds up another, of its session or any
/// other (INT-01.44). [`Bridge::shared`] takes it; it is called with no
/// lock of the bridge held.
pub trait SharedHandler: Send + Sync {
    /// As [`Handler::handle`].
    ///
    /// # Errors
    /// The error number the reply carries.
    fn handle(&self, request: &Request<'_>) -> Result<Map, u8>;
}

/// A [`Handler`] behind a lock: its requests run one at a time.
struct OneAtATime(Mutex<Box<dyn Handler>>);

impl SharedHandler for OneAtATime {
    fn handle(&self, request: &Request<'_>) -> Result<Map, u8> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handle(request)
    }
}

struct Session {
    route: Route,
    /// The connection that said hello (the [`Route::Port`] binding).
    conn: u64,
    /// App's session key pair (a, A) and the client's key C.
    secret: Secret,
    app: [u8; KEY],
    client: [u8; KEY],
    request_key: SecretBytes,
    /// Shared with the requests still in flight, which seal with it.
    reply_key: Arc<SecretBytes>,
    /// Every nonce of an opened request and of App's own notices (INT-01.23).
    nonces: HashSet<[u8; NONCE]>,
    requests: u32,
    identity: Option<[u8; KEY]>,
    browser: &'static str,
    last: Instant,
    live: Arc<Live>,
}

impl Drop for Session {
    /// INT-01.45: its waiting requests end without a reply.
    fn drop(&mut self) {
        self.live.end();
    }
}

/// What [`Bridge::begin`] gives for one message.
pub enum Step {
    /// The reply, ready to send.
    Reply(Vec<u8>),
    /// Close the connection (INT-01.44's hello limit, a failed random
    /// source).
    Close,
    /// An opened request for the handler: [`Work::finish`] runs it with no
    /// lock of the bridge held.
    Work(Box<Work>),
}

/// One opened request in flight (INT-01.44): what its handler needs and
/// what its reply is sealed with. No `Debug`: it holds the request.
pub struct Work {
    handler: Arc<dyn SharedHandler>,
    kind: &'static str,
    req: u64,
    request: Map,
    browser: &'static str,
    identity: Option<[u8; KEY]>,
    keys: ([u8; KEY], [u8; KEY]),
    live: Arc<Live>,
    sid: String,
    nonce: [u8; NONCE],
    reply_key: Arc<SecretBytes>,
}

impl Work {
    /// Runs the handler, then seals its reply with the request's nonce;
    /// `None` when the session ended meanwhile: nothing can be sent
    /// (INT-01.45).
    #[must_use]
    pub fn finish(self) -> Option<Vec<u8>> {
        let result = self.handler.handle(&Request {
            kind: self.kind,
            content: &self.request,
            browser: self.browser,
            identity: self.identity.as_ref(),
            session: &self.live,
            keys: (&self.keys.0, &self.keys.1),
        });
        if self.live.ended() {
            return None;
        }
        let mut reply = match result {
            Ok(mut fields) => {
                fields.remove("error");
                fields
            }
            Err(n) => error_map(n),
        };
        reply.insert("type".into(), self.kind.into());
        reply.insert("req".into(), self.req.into());
        Some(sealed(&self.reply_key, &self.sid, &self.nonce, &reply))
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        self.live.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// App's side of the channel for both routes.
///
/// Guarantees: replies are made only by the rules of INT-01.20 to
/// INT-01.28 and the [`Handler`]; a box that does not open, an unknown
/// `sid` and a seen nonce are answered before the handler or any vault is
/// asked (INT-01.41); no reply holds text but App's own members; session
/// keys, the X25519 results and opened contents live in wiping types and
/// are dropped when the session or the request ends (INT-01.47). No input
/// panics.
pub struct Bridge {
    app_version: String,
    handler: Arc<dyn SharedHandler>,
    sessions: HashMap<String, Session>,
    /// The start of the current second and the hellos in it (INT-01.44).
    hellos: Option<(Instant, u32)>,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge")
            .field("sessions", &self.sessions.len())
            .finish_non_exhaustive()
    }
}

impl Bridge {
    /// A bridge with no session. `app_version` goes in every hello reply's
    /// `app` member, for display only (INT-01.42).
    /// Its requests run one at a time, under the handler's lock.
    #[must_use]
    pub fn new(app_version: &str, handler: Box<dyn Handler>) -> Self {
        Self::shared(app_version, Arc::new(OneAtATime(Mutex::new(handler))))
    }

    /// [`Bridge::new`] with a handler that answers many requests at once.
    #[must_use]
    pub fn shared(app_version: &str, handler: Arc<dyn SharedHandler>) -> Self {
        Self {
            app_version: app_version.to_owned(),
            handler,
            sessions: HashMap::new(),
            hellos: None,
        }
    }

    /// Takes one message (a frame's JSON bytes) from connection `conn` on
    /// `route` at `now`, runs its request at once, and returns the reply's
    /// JSON bytes, or `None` when the connection must close (more than
    /// [`MAX_HELLOS`] hellos this second, or the random source failed).
    pub fn take(
        &mut self,
        conn: u64,
        route: Route,
        message: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        match self.begin(conn, route, message, now) {
            Step::Reply(reply) => Some(reply),
            Step::Close => None,
            Step::Work(work) => work.finish(),
        }
    }

    /// [`Bridge::take`] without running the request: an opened request
    /// comes back as [`Step::Work`], for [`Work::finish`] once the bridge's
    /// lock is let go, so a request that waits for the user holds up no
    /// other (INT-01.44).
    pub fn begin(&mut self, conn: u64, route: Route, message: &[u8], now: Instant) -> Step {
        self.expire(now);
        let Some(Value::Object(plain)) = read(message) else {
            let blank = message.iter().all(u8::is_ascii_whitespace);
            return Step::Reply(plain_error(if blank { code::EMPTY } else { code::UNKNOWN }));
        };
        match plain.get("type").and_then(Value::as_str) {
            Some("hello") => self
                .hello(conn, route, &plain, now)
                .map_or(Step::Close, Step::Reply),
            Some("box") => self.boxed(conn, route, &plain, now),
            _ => Step::Reply(plain_error(code::UNKNOWN)),
        }
    }

    /// Ends the [`Route::Port`] session of a connection that closed.
    pub fn closed(&mut self, conn: u64) {
        self.sessions
            .retain(|_, s| !(s.route == Route::Port && s.conn == conn));
    }

    /// Ends every Safari session without a request for [`IDLE`] (INT-01.14).
    pub fn expire(&mut self, now: Instant) {
        self.sessions
            .retain(|_, s| s.route == Route::Port || now.saturating_duration_since(s.last) < IDLE);
    }

    /// Ends every session of `route` (its switch turned off, or quit).
    pub fn end(&mut self, route: Route) {
        self.sessions.retain(|_, s| s.route != route);
    }

    /// Live sessions.
    #[must_use]
    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }

    /// The notice `{"type":"notice","event":…}` (INT-01.46) for each
    /// [`Route::Port`] session whose proven key `to` takes, as (connection,
    /// message bytes). Each is sealed with the session's reply key and a
    /// fresh random nonce outside its nonce set, which then joins the set
    /// (INT-01.23). A failed random source skips that session.
    pub fn notice(
        &mut self,
        event: &str,
        to: impl Fn(Option<&[u8; KEY]>) -> bool,
    ) -> Vec<(u64, Vec<u8>)> {
        let mut content = Map::new();
        content.insert("type".into(), "notice".into());
        content.insert("event".into(), event.into());
        let content = SecretBytes::new(json::to_string(&Value::Object(content)).into_bytes());
        let mut out = Vec::new();
        for (sid, s) in &mut self.sessions {
            if s.route != Route::Port || !to(s.identity.as_ref()) {
                continue;
            }
            let Some(nonce) = fresh_nonce(&s.nonces) else {
                continue;
            };
            if let Ok(sealed) = bridge::seal(&s.reply_key, &nonce, content.expose()) {
                s.nonces.insert(nonce);
                out.push((s.conn, box_message(sid, &nonce, &sealed)));
            }
        }
        out
    }

    /// INT-01.20.
    fn hello(&mut self, conn: u64, route: Route, plain: &Map, now: Instant) -> Option<Vec<u8>> {
        if !self.hello_allowed(now) {
            return None;
        }
        let speaks_one = plain
            .get("versions")
            .and_then(Value::as_array)
            .is_some_and(|v| {
                (1..=MAX_VERSIONS).contains(&v.len())
                    && v.iter().all(|x| x.as_i64().is_some())
                    && v.iter().any(|x| x.as_u64() == Some(1))
            });
        if !speaks_one {
            let mut reply = error_map(code::NO_VERSION);
            reply.insert("type".into(), "error".into());
            reply.insert("versions".into(), [1u32].into());
            return Some(write(reply));
        }
        let Some(client) = string(plain, "key").and_then(decode::<KEY>) else {
            return Some(plain_error(code::BAD_KEY));
        };
        let secret = Secret::generate().ok()?;
        let app = secret.public();
        let Some(z) = secret.agree(&client) else {
            return Some(plain_error(code::BAD_KEY));
        };
        let request_key = bridge::request_key(&z, &client, &app).ok()?;
        let reply_key = bridge::reply_key(&z, &client, &app).ok()?;
        drop(z);
        let sid = loop {
            let mut raw = [0u8; 16];
            app_crypto::random::fill(&mut raw).ok()?;
            let sid = base64::encode(Form::Url, &raw);
            if !self.sessions.contains_key(&sid) {
                break sid;
            }
        };
        let browser = string(plain, "browser")
            .and_then(|b| BROWSERS.into_iter().find(|k| *k == b))
            .unwrap_or("Browser");
        if route == Route::Port {
            // A hello replaces the connection's session: its keys are wiped.
            self.closed(conn);
        } else {
            self.make_room_for_safari();
        }
        self.sessions.insert(
            sid.clone(),
            Session {
                route,
                conn,
                secret,
                app,
                client,
                request_key,
                reply_key: Arc::new(reply_key),
                nonces: HashSet::new(),
                requests: 0,
                identity: None,
                browser,
                last: now,
                live: Arc::default(),
            },
        );
        let mut reply = Map::new();
        reply.insert("type".into(), "hello".into());
        reply.insert("version".into(), 1u32.into());
        reply.insert("key".into(), base64::encode(Form::Padded, &app).into());
        reply.insert("sid".into(), sid.into());
        reply.insert("app".into(), self.app_version.as_str().into());
        Some(write(reply))
    }

    /// INT-01.44, LD-318 (3): at most [`MAX_SAFARI`] Safari sessions; to
    /// make room for one more, the one idle the longest ends (its next box
    /// gets error 3, as any ended session's).
    fn make_room_for_safari(&mut self) {
        let safari = || self.sessions.values().filter(|s| s.route == Route::Safari);
        if safari().count() < MAX_SAFARI {
            return;
        }
        let oldest = self
            .sessions
            .iter()
            .filter(|(_, s)| s.route == Route::Safari)
            .min_by_key(|(_, s)| s.last)
            .map(|(sid, _)| sid.clone());
        if let Some(sid) = oldest {
            self.sessions.remove(&sid);
        }
    }

    /// INT-01.44: at most [`MAX_HELLOS`] in each second.
    fn hello_allowed(&mut self, now: Instant) -> bool {
        let (start, count) = match self.hellos {
            Some((start, count))
                if now.saturating_duration_since(start) < Duration::from_secs(1) =>
            {
                (start, count.saturating_add(1))
            }
            _ => (now, 1),
        };
        self.hellos = Some((start, count));
        count <= MAX_HELLOS
    }

    /// INT-01.21: the checks in the card's order, then the request.
    fn boxed(&mut self, conn: u64, route: Route, plain: &Map, now: Instant) -> Step {
        let Self {
            sessions, handler, ..
        } = self;
        let sid = string(plain, "sid").unwrap_or_default();
        let Some(session) = sessions
            .get_mut(sid)
            .filter(|s| s.route == route && (route == Route::Safari || s.conn == conn))
        else {
            return Step::Reply(plain_error(code::NO_SESSION));
        };
        let Some(nonce) = string(plain, "nonce").and_then(decode::<NONCE>) else {
            return Step::Reply(plain_error(code::NOT_OPENED));
        };
        if session.requests >= MAX_REQUESTS || session.nonces.contains(&nonce) {
            return Step::Reply(plain_error(code::SEEN));
        }
        // A box shorter than its tag does not open either (bridge::open).
        let Some(sealed_box) = string(plain, "box").and_then(decode_any) else {
            return Step::Reply(plain_error(code::NOT_OPENED));
        };
        let Ok(content) = bridge::open(&session.request_key, &nonce, &sealed_box) else {
            return Step::Reply(plain_error(code::NOT_OPENED));
        };
        session.nonces.insert(nonce);
        session.requests = session.requests.saturating_add(1);
        session.last = now;
        let opened = answer(session, &content, &nonce);
        drop(content);
        match opened {
            Ok((kind, req, request)) => Step::Work(Box::new(Work {
                handler: Arc::clone(handler),
                kind,
                req,
                request,
                browser: session.browser,
                identity: session.identity,
                keys: (session.app, session.client),
                live: Arc::clone(&session.live),
                sid: sid.to_owned(),
                nonce,
                reply_key: Arc::clone(&session.reply_key),
            })),
            Err(reply) => Step::Reply(sealed(&session.reply_key, sid, &nonce, &reply)),
        }
    }
}

/// The reply sealed with the reply key and the request's nonce. It is
/// never larger than INT-01.24 allows: its `type` and `req` stay, unless
/// the `type` alone is too long (an unknown one echoed).
fn sealed(reply_key: &SecretBytes, sid: &str, nonce: &[u8; NONCE], reply: &Map) -> Vec<u8> {
    let mut text = SecretBytes::new(json::to_string(&Value::Object(reply.clone())).into_bytes());
    if text.len() > MAX_CONTENT {
        let mut small = error_map(code::TOO_LARGE);
        for key in ["type", "req"] {
            if let Some(v) = reply.get(key) {
                small.insert(key.into(), v.clone());
            }
        }
        text = SecretBytes::new(json::to_string(&Value::Object(small.clone())).into_bytes());
        if text.len() > MAX_CONTENT {
            small.remove("type");
            text = SecretBytes::new(json::to_string(&Value::Object(small)).into_bytes());
        }
    }
    match bridge::seal(reply_key, nonce, text.expose()) {
        Ok(sealed) => box_message(sid, nonce, &sealed),
        Err(_) => plain_error(code::NOT_OPENED),
    }
}

/// One opened content as its `type`, `req` and request object, ready for
/// the handler, or the reply object when it ends here (INT-01.21,
/// INT-01.24, INT-01.25, INT-01.28, INT-01.30, INT-01.44).
fn answer(
    session: &mut Session,
    content: &SecretBytes,
    nonce: &[u8; NONCE],
) -> Result<(&'static str, u64, Map), Map> {
    if content.len() > MAX_CONTENT {
        return Err(error_map(code::TOO_LARGE));
    }
    // ponytail: app-model's reader keeps strings in plain `String`s; App
    // wipes them on free through app-ffi's zeroing allocator. The first
    // request that carries a password (`logins.save`, `logins.update`)
    // needs a reader that keeps values in SecretString.
    let Some(Value::Object(request)) = read(content.expose()) else {
        return Err(error_map(code::UNKNOWN));
    };
    let kind = request.get("type").and_then(Value::as_str);
    let req = request
        .get("req")
        .and_then(Value::as_u64)
        .filter(|r| (1..=MAX_REQ).contains(r));
    let result = match req {
        None => Err(code::UNKNOWN),
        Some(_) => check(session, &request, kind, nonce),
    };
    match (result, req) {
        (Ok(kind), Some(req)) => Ok((kind, req, request)),
        (result, req) => {
            let mut reply = error_map(result.err().unwrap_or(code::UNKNOWN));
            if let Some(kind) = kind {
                reply.insert("type".into(), kind.into());
            }
            if let Some(req) = req {
                reply.insert("req".into(), req.into());
            }
            Err(reply)
        }
    }
}

/// The checks before the handler: a known `type`, INT-01.25's lengths,
/// the proof of `connect` and `check`, and INT-01.44's requests in flight.
/// The known type, which then counts as in flight until its [`Work`] drops.
fn check(
    session: &mut Session,
    request: &Map,
    kind: Option<&str>,
    nonce: &[u8; NONCE],
) -> Result<&'static str, u8> {
    let kind = kind
        .and_then(|k| TYPES.into_iter().find(|t| *t == k))
        .ok_or(code::UNKNOWN)?;
    let long = |field: &str| string(request, field).is_some_and(|u| u.len() > MAX_URL);
    let text = match kind {
        "logins.search" => string(request, "text"),
        "autotype.start" => string(request, "search"),
        _ => None,
    };
    if ["url", "top_url", "form_url"].into_iter().any(long)
        || text.is_some_and(|t| t.chars().count() > MAX_TEXT)
    {
        return Err(code::TOO_LARGE);
    }
    if PROVING.contains(&kind) {
        prove(session, request, nonce)?;
    }
    if !take_one(&session.live.in_flight, MAX_IN_FLIGHT) {
        return Err(code::BUSY);
    }
    Ok(kind)
}

/// INT-01.28: error 10 for an `id_key` that is not 32 bytes, gives an
/// all-zero X25519 result with App's session key, or equals the client's
/// session key, before any proof work; error 8 for a `proof` that is not 48
/// bytes, does not open under the proof key with this request's nonce, or
/// holds anything but C. Then the session's identity is that key.
fn prove(session: &mut Session, request: &Map, nonce: &[u8; NONCE]) -> Result<(), u8> {
    let id = string(request, "id_key")
        .and_then(decode::<KEY>)
        .ok_or(code::BAD_KEY)?;
    if id == session.client {
        return Err(code::BAD_KEY);
    }
    let z_id = session.secret.agree(&id).ok_or(code::BAD_KEY)?;
    let proof = string(request, "proof")
        .and_then(decode::<PROOF>)
        .ok_or(code::NOT_PROVEN)?;
    let key = bridge::proof_key(&z_id, &session.client, &session.app, &id)
        .map_err(|_| code::NOT_PROVEN)?;
    let opened = bridge::open(&key, nonce, &proof).map_err(|_| code::NOT_PROVEN)?;
    if !ct_eq(opened.expose(), &session.client) {
        return Err(code::NOT_PROVEN);
    }
    session.identity = Some(id);
    Ok(())
}

/// Strict RFC 8259 JSON (INT-01.25): UTF-8, one value, at most
/// [`MAX_DEPTH`] levels and [`MAX_VALUES`] commas and opening brackets, no
/// repeated member name.
fn read(bytes: &[u8]) -> Option<Value> {
    if too_complex(bytes) {
        return None;
    }
    json::from_slice_unique(bytes).ok()
}

/// Whether the brackets outside strings nest deeper than [`MAX_DEPTH`], or
/// the commas and opening brackets outside strings number more than
/// [`MAX_VALUES`], so the reader never sees the message (LD-312). Exact for
/// valid JSON; anything else the reader refuses anyway.
fn too_complex(bytes: &[u8]) -> bool {
    let (mut depth, mut marks, mut in_string, mut escaped) = (0usize, 0usize, false, false);
    for &b in bytes {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth = depth.saturating_add(1);
                marks = marks.saturating_add(1);
                if depth > MAX_DEPTH || marks > MAX_VALUES {
                    return true;
                }
            }
            b',' => {
                marks = marks.saturating_add(1);
                if marks > MAX_VALUES {
                    return true;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

fn string<'a>(map: &'a Map, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

/// Strict base64 (INT-01.26): the standard alphabet with exactly the
/// padding the encoding writes and zero trailing bits, so the text is the
/// one encoding of its bytes.
fn decode_any(text: &str) -> Option<Vec<u8>> {
    let bytes = base64::decode(Form::Padded, text).ok()?;
    (base64::encode(Form::Padded, &bytes) == text).then_some(bytes)
}

fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode_any(text)?.try_into().ok()
}

/// A random nonce outside `seen` (INT-01.23); `None` if the source fails.
fn fresh_nonce(seen: &HashSet<[u8; NONCE]>) -> Option<[u8; NONCE]> {
    loop {
        let mut nonce = [0u8; NONCE];
        app_crypto::random::fill(&mut nonce).ok()?;
        if !seen.contains(&nonce) {
            return Some(nonce);
        }
    }
}

fn box_message(sid: &str, nonce: &[u8; NONCE], sealed: &[u8]) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("type".into(), "box".into());
    m.insert("sid".into(), sid.into());
    m.insert("nonce".into(), base64::encode(Form::Padded, nonce).into());
    m.insert("box".into(), base64::encode(Form::Padded, sealed).into());
    write(m)
}

fn error_map(n: u8) -> Map {
    let mut m = Map::new();
    m.insert("error".into(), u32::from(n).into());
    m
}

fn plain_error(n: u8) -> Vec<u8> {
    let mut m = error_map(n);
    m.insert("type".into(), "error".into());
    write(m)
}

fn write(map: Map) -> Vec<u8> {
    json::to_string(&Value::Object(map)).into_bytes()
}
