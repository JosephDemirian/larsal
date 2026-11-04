//! INT-01's channel cases (story E7-S1). A test client speaks the protocol
//! as the extension does, with app-crypto's channel functions, over App's
//! real sockets in a folder under /tmp (INT-01.10: never the owner's
//! Library). Each channel case runs on both routes: the bridge socket with
//! one connection per session, and the Safari socket with a new connection
//! for every message, where the session is found by its `sid` alone
//! (INT-01.14). Time comes from a clock the test moves.

use app_browser::{
    Bridge, Clock, Handler, IDLE, MAX_CONNECTIONS, MAX_CONTENT, MAX_DEPTH, MAX_FRAME, MAX_HELLOS,
    MAX_IN_FLIGHT, MAX_REQUESTS, MAX_TEXT, MAX_URL, MAX_VALUES, Request, Route, Server,
    SharedHandler,
};
use app_crypto::base64::{self, Form};
use app_crypto::bridge::{self, Secret};
use app_crypto::secret::SecretBytes;
use app_model::json::{self, Map, Value};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Seen = Arc<Mutex<Vec<(String, String, Option<[u8; 32]>)>>>;

/// The vault side's stand-in: notes every request it is given.
struct Demo(Seen);

impl Handler for Demo {
    fn handle(&mut self, r: &Request<'_>) -> Result<Map, u8> {
        self.0
            .lock()
            .unwrap()
            .push((r.kind.to_owned(), r.browser.to_owned(), r.identity.copied()));
        let mut reply = Map::new();
        match r.kind {
            "logins.find" => return Err(15),
            "logins.search" => {
                reply.insert("entries".into(), "x".repeat(MAX_CONTENT).into());
            }
            "lock" => {
                // App's own members, which the reply must not take from here.
                reply.insert("error".into(), 99u32.into());
                reply.insert("type".into(), "status".into());
                reply.insert("req".into(), 7u32.into());
                reply.insert("locked".into(), true.into());
            }
            _ => {
                reply.insert("vaults".into(), Value::Array(Vec::new()));
            }
        }
        Ok(reply)
    }
}

static FOLDERS: AtomicU64 = AtomicU64::new(0);

/// Both sockets over one bridge, in a fresh folder under /tmp.
struct Fixture {
    dir: PathBuf,
    bridge: Arc<Mutex<Bridge>>,
    seen: Seen,
    minutes: Arc<AtomicU64>,
    port: Option<Server>,
    safari: Option<Server>,
}

impl Fixture {
    fn new() -> Self {
        let n = FOLDERS.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(format!("/tmp/app-browser-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let seen = Seen::default();
        let bridge = Arc::new(Mutex::new(Bridge::new("1.0", Box::new(Demo(seen.clone())))));
        let minutes = Arc::new(AtomicU64::new(0));
        let clock = clock(&minutes);
        let port = Server::start(
            &dir.join("p.sock"),
            Route::Port,
            bridge.clone(),
            clock.clone(),
        )
        .unwrap();
        let safari =
            Server::start(&dir.join("s.sock"), Route::Safari, bridge.clone(), clock).unwrap();
        Self {
            dir,
            bridge,
            seen,
            minutes,
            port: Some(port),
            safari: Some(safari),
        }
    }

    fn wire(&self, route: Route) -> Wire {
        match route {
            Route::Port => Wire::Port(connect(&self.dir.join("p.sock"))),
            Route::Safari => Wire::Safari(self.dir.join("s.sock")),
        }
    }

    fn port(&self) -> &Server {
        self.port.as_ref().unwrap()
    }

    fn handled(&self, kind: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, ..)| k == kind)
            .count()
    }

    fn last_seen(&self) -> (String, String, Option<[u8; 32]>) {
        self.seen.lock().unwrap().last().cloned().unwrap()
    }

    fn advance(&self, minutes: u64) {
        self.minutes.fetch_add(minutes * 60, Ordering::SeqCst);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.port.take());
        drop(self.safari.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Real time plus what the test added (in seconds), so no test waits.
fn clock(added: &Arc<AtomicU64>) -> Clock {
    let added = added.clone();
    Arc::new(move || Instant::now() + Duration::from_secs(added.load(Ordering::SeqCst)))
}

fn connect(path: &std::path::Path) -> UnixStream {
    let s = UnixStream::connect(path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn send_frame(s: &mut UnixStream, body: &[u8]) {
    let mut frame = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    frame.extend_from_slice(body);
    s.write_all(&frame).unwrap();
}

fn read_frame(s: &mut UnixStream) -> Option<Vec<u8>> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head).ok()?;
    let mut body = vec![0u8; u32::from_le_bytes(head) as usize];
    s.read_exact(&mut body).ok()?;
    Some(body)
}

/// App closed the connection: the read ends (EOF) within 2 seconds, with no
/// reply. A read that only times out is not a close.
fn closed_by_app(s: &mut UnixStream) -> bool {
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut byte = [0u8; 1];
    matches!(s.read(&mut byte), Ok(0))
}

/// One way to App: a kept connection, or a new connection per message.
enum Wire {
    Port(UnixStream),
    Safari(PathBuf),
}

impl Wire {
    fn send(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        match self {
            Wire::Port(s) => {
                send_frame(s, body);
                read_frame(s)
            }
            Wire::Safari(path) => {
                let mut s = connect(path);
                send_frame(&mut s, body);
                read_frame(&mut s)
            }
        }
    }

    fn json(&mut self, body: &str) -> Value {
        parse(&self.send(body.as_bytes()).expect("a reply"))
    }
}

fn parse(bytes: &[u8]) -> Value {
    json::from_slice(bytes).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    base64::encode(Form::Padded, bytes)
}

fn plain_error(v: &Value) -> Option<u64> {
    (v.get("type").and_then(Value::as_str) == Some("error"))
        .then(|| v.get("error").and_then(Value::as_u64))
        .flatten()
}

fn hello(key: &[u8; 32], browser: &str) -> String {
    format!(
        r#"{{"type":"hello","versions":[1],"key":"{}","browser":"{browser}"}}"#,
        b64(key)
    )
}

/// The extension's side of one session (INT-11.7), with app-crypto's functions.
struct Client {
    secret: Secret,
    key: [u8; 32],
    app: [u8; 32],
    sid: String,
    request: SecretBytes,
    reply: SecretBytes,
    nonce: u64,
}

impl Client {
    fn hello(wire: &mut Wire) -> Self {
        Self::hello_as(wire, "Chrome")
    }

    fn hello_as(wire: &mut Wire, browser: &str) -> Self {
        let secret = Secret::generate().unwrap();
        let key = secret.public();
        let reply = wire.json(&hello(&key, browser));
        assert_eq!(
            reply.get("type").and_then(Value::as_str),
            Some("hello"),
            "{reply}"
        );
        let app: [u8; 32] =
            base64::decode(Form::Padded, reply.get("key").unwrap().as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let z = secret.agree(&app).unwrap();
        Self {
            request: bridge::request_key(&z, &key, &app).unwrap(),
            reply: bridge::reply_key(&z, &key, &app).unwrap(),
            sid: reply.get("sid").unwrap().as_str().unwrap().to_owned(),
            secret,
            key,
            app,
            nonce: 0,
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        self.nonce += 1;
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.nonce.to_be_bytes());
        n
    }

    /// A box message of `content` sealed with `key` and `nonce`.
    fn boxed_with(&self, key: &SecretBytes, nonce: &[u8; 12], content: &[u8]) -> String {
        let sealed = bridge::seal(key, nonce, content).unwrap();
        format!(
            r#"{{"type":"box","sid":"{}","nonce":"{}","box":"{}"}}"#,
            self.sid,
            b64(nonce),
            b64(&sealed)
        )
    }

    /// Sends `content` with a fresh nonce; returns the reply message.
    fn request(&mut self, wire: &mut Wire, content: &str) -> (Value, [u8; 12]) {
        let nonce = self.next_nonce();
        let message = self.boxed_with(&self.request, &nonce, content.as_bytes());
        (wire.json(&message), nonce)
    }

    /// Sends `content` and opens the boxed reply, which must use `nonce`.
    fn ask(&mut self, wire: &mut Wire, content: &str) -> Value {
        let (reply, nonce) = self.request(wire, content);
        self.open(&reply, &nonce)
    }

    fn open(&self, reply: &Value, nonce: &[u8; 12]) -> Value {
        assert_eq!(
            reply.get("type").and_then(Value::as_str),
            Some("box"),
            "{reply}"
        );
        assert_eq!(
            reply.get("sid").and_then(Value::as_str),
            Some(self.sid.as_str())
        );
        let got =
            base64::decode(Form::Padded, reply.get("nonce").unwrap().as_str().unwrap()).unwrap();
        assert_eq!(got, nonce, "INT-01.23: a reply uses its request's nonce");
        let sealed =
            base64::decode(Form::Padded, reply.get("box").unwrap().as_str().unwrap()).unwrap();
        parse(bridge::open(&self.reply, nonce, &sealed).unwrap().expose())
    }

    /// INT-01.28: C sealed under the proof key of `id` with `nonce`.
    fn proof(&self, id: &Secret, nonce: &[u8; 12]) -> Vec<u8> {
        let z_id = id.agree(&self.app).unwrap();
        let key = bridge::proof_key(&z_id, &self.key, &self.app, &id.public()).unwrap();
        bridge::seal(&key, nonce, &self.key).unwrap()
    }

    /// Proves a fresh identification key on this session (INT-01.28).
    fn prove(&mut self, wire: &mut Wire) -> Secret {
        let id = Secret::generate().unwrap();
        let nonce = self.next_nonce();
        let proof = self.proof(&id, &nonce);
        assert_eq!(error(&self.check(wire, &id.public(), &proof, nonce)), None);
        id
    }

    /// A `check` with `id_key` and `proof`, sealed with the nonce the proof used.
    fn check(&mut self, wire: &mut Wire, id_key: &[u8], proof: &[u8], nonce: [u8; 12]) -> Value {
        let content = format!(
            r#"{{"type":"check","req":5,"id_key":"{}","proof":"{}"}}"#,
            b64(id_key),
            b64(proof)
        );
        let message = self.boxed_with(&self.request, &nonce, content.as_bytes());
        let reply = wire.json(&message);
        self.open(&reply, &nonce)
    }
}

fn error(v: &Value) -> Option<u64> {
    v.get("error").and_then(Value::as_u64)
}

const STATUS: &str = r#"{"type":"status","req":1}"#;

/// INT-01.28: a failed proof gives the session no identity; its next
/// request reaches the handler without one.
fn assert_no_identity(f: &Fixture, client: &mut Client, wire: &mut Wire) {
    client.ask(wire, STATUS);
    assert_eq!(f.last_seen(), ("status".into(), "Chrome".into(), None));
}

// ---------------------------------------------------------------------------
// Channel cases, run on both routes (the Safari check of E7-S1).

/// T29 INT-01.20: version 1, a 32-byte key and a 16-byte `sid`, no `nonce`;
/// a status sealed with the request key from that reply is answered. A list
/// of 16 versions, the most the card allows, is answered too (F-199).
fn t29_hello_gives_version_1_a_key_and_a_sid_and_status_is_answered(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let key = Secret::generate().unwrap().public();
    let sixteen = wire.json(&format!(
        r#"{{"type":"hello","versions":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],"key":"{}","browser":"Chrome"}}"#,
        b64(&key)
    ));
    assert_eq!(
        sixteen.get("version").and_then(Value::as_u64),
        Some(1),
        "{sixteen}"
    );
    let reply = wire.json(&format!(
        r#"{{"type":"hello","versions":[1,2],"key":"{}","browser":"Chrome"}}"#,
        b64(&key)
    ));
    let obj = reply.as_object().unwrap();
    assert_eq!(reply.get("version").and_then(Value::as_u64), Some(1));
    assert!(!obj.contains_key("nonce"));
    let app = base64::decode(Form::Padded, reply.get("key").unwrap().as_str().unwrap()).unwrap();
    assert_eq!(app.len(), 32);
    let sid = base64::decode(Form::Url, reply.get("sid").unwrap().as_str().unwrap()).unwrap();
    assert_eq!(sid.len(), 16);
    let mut client = Client::hello(&mut wire);
    let answer = client.ask(&mut wire, STATUS);
    assert_eq!(answer.get("vaults"), Some(&Value::Array(Vec::new())));
}

/// T28 INT-01.20: no version in common.
fn t28_hello_without_version_1_gets_plain_error_40(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let key = b64(&Secret::generate().unwrap().public());
    for versions in [
        r#"[2,3]"#,
        "[]",
        r#"["1"]"#,
        "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]",
    ] {
        let reply = wire.json(&format!(
            r#"{{"type":"hello","versions":{versions},"key":"{key}"}}"#
        ));
        assert_eq!(
            json::to_string(&reply),
            r#"{"error":40,"type":"error","versions":[1]}"#
        );
    }
    assert_eq!(f.bridge.lock().unwrap().sessions(), 0);
}

/// T30 INT-01.20, AT-F03: a low-order client key (zero, order 8).
fn t30_low_order_client_key_gets_plain_error_10(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    for point in [
        [0u8; 32].to_vec(),
        base64::decode(Form::Padded, "4Ot6fDtBuK4WVuP68Z/EatoJjeucMrH9hmIFFl9JuAA=").unwrap(),
    ] {
        let reply = wire.json(&hello(&point.try_into().unwrap(), "Chrome"));
        assert_eq!(plain_error(&reply), Some(10));
    }
    assert_eq!(f.bridge.lock().unwrap().sessions(), 0);
}

/// T44 INT-01.26: keys decode strictly.
fn t44_key_that_is_not_strict_base64_gets_plain_error_10(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let good = b64(&Secret::generate().unwrap().public());
    // The character before `=` carries two unused bits; set the lowest.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut set_bits = good.clone().into_bytes();
    let last = good.len() - 2;
    let index = ALPHABET.iter().position(|c| *c == set_bits[last]).unwrap();
    set_bits[last] = ALPHABET[index | 1];
    let set_bits = String::from_utf8(set_bits).unwrap();
    assert_eq!(
        base64::decode(Form::Padded, &set_bits).unwrap(),
        base64::decode(Form::Padded, &good).unwrap()
    );
    for key in [
        good.replacen(&good[..1], "-", 1),
        good.trim_end_matches('=').to_owned(),
        format!("{good}="),
        set_bits,
        b64(&[7u8; 31]),
        b64(&[7u8; 33]),
    ] {
        let reply = wire.json(&format!(
            r#"{{"type":"hello","versions":[1],"key":"{key}"}}"#
        ));
        assert_eq!(plain_error(&reply), Some(10), "{key}");
    }
    assert_eq!(
        plain_error(&wire.json(r#"{"type":"hello","versions":[1]}"#)),
        Some(10)
    );
}

/// T32 INT-01.21: same `type` and `req`.
fn t32_boxed_status_gets_a_boxed_reply_with_its_type_and_req(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let answer = client.ask(&mut wire, r#"{"type":"status","req":9007199254740991}"#);
    assert_eq!(
        json::to_string(&answer),
        r#"{"req":9007199254740991,"type":"status","vaults":[]}"#
    );
}

/// T33 INT-01.21, AT-F03: one bit of the box flipped.
fn t33_flipped_bit_gets_plain_error_4_and_nothing_runs(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let client = Client::hello(&mut wire);
    let nonce = [9u8; 12];
    let mut sealed = bridge::seal(&client.request, &nonce, STATUS.as_bytes()).unwrap();
    sealed[3] ^= 0x10;
    let message = format!(
        r#"{{"type":"box","sid":"{}","nonce":"{}","box":"{}"}}"#,
        client.sid,
        b64(&nonce),
        b64(&sealed)
    );
    assert_eq!(plain_error(&wire.json(&message)), Some(4));
    assert_eq!(f.handled("status"), 0);
}

/// T35 INT-01.21: `req` as text, or missing, or out of range.
fn t35_request_without_a_usable_req_gets_boxed_error_12_without_req(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    for content in [
        r#"{"type":"status","req":"7"}"#,
        r#"{"type":"status"}"#,
        r#"{"type":"status","req":0}"#,
        r#"{"type":"status","req":9007199254740992}"#,
        r#"{"type":"status","req":1.5}"#,
    ] {
        let answer = client.ask(&mut wire, content);
        assert_eq!(
            json::to_string(&answer),
            r#"{"error":12,"type":"status"}"#,
            "{content}"
        );
    }
    assert_eq!(f.handled("status"), 0);
}

/// T39 INT-01.23, AT-F02: exactly the same frame again.
fn t39_replayed_box_gets_plain_error_41_and_runs_once(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let client = Client::hello(&mut wire);
    let message = client.boxed_with(&client.request, &[1; 12], STATUS.as_bytes());
    assert_eq!(
        wire.json(&message).get("type").and_then(Value::as_str),
        Some("box")
    );
    assert_eq!(plain_error(&wire.json(&message)), Some(41));
    assert_eq!(f.handled("status"), 1);
}

/// T40 INT-01.23: App's own reply sent back as a request.
fn t40_reply_sent_back_as_a_request_gets_plain_error_41(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let (reply, _) = client.request(&mut wire, STATUS);
    assert_eq!(plain_error(&wire.json(&json::to_string(&reply))), Some(41));
    assert_eq!(f.handled("status"), 1);
}

/// T41 INT-01.24: content of 655,361 bytes (valid JSON).
fn t41_content_over_640_kib_gets_boxed_error_43(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let pad = |n: usize| format!(r#"{{"type":"status","req":1,"pad":"{}"}}"#, "x".repeat(n));
    let base = pad(0).len();
    let over = pad(MAX_CONTENT + 1 - base);
    assert_eq!(over.len(), MAX_CONTENT + 1);
    assert_eq!(error(&client.ask(&mut wire, &over)), Some(43));
    assert_eq!(f.handled("status"), 0);
    let at = pad(MAX_CONTENT - base);
    assert_eq!(
        error(&client.ask(&mut wire, &at)),
        None,
        "exactly 640 KiB is read"
    );
    assert_eq!(f.handled("status"), 1);
}

/// INT-01.24: a reply is never over 640 KiB; it becomes error 43 with its
/// `type` and `req`.
fn reply_over_640_kib_becomes_boxed_error_43(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let answer = client.ask(&mut wire, r#"{"type":"logins.search","req":4,"text":"a"}"#);
    assert_eq!(
        json::to_string(&answer),
        r#"{"error":43,"req":4,"type":"logins.search"}"#
    );
}

/// INT-01.24, F-188: a reply that echoes an over-long unknown `type` (a
/// request of exactly 640 KiB) keeps only `req` in its error 43.
fn reply_echoing_a_long_type_stays_within_640_kib(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let base = r#"{"req":1,"type":""}"#.len();
    let content = format!(r#"{{"req":1,"type":"{}"}}"#, "t".repeat(MAX_CONTENT - base));
    assert_eq!(content.len(), MAX_CONTENT);
    let (reply, nonce) = client.request(&mut wire, &content);
    let sealed = base64::decode(Form::Padded, reply.get("box").unwrap().as_str().unwrap()).unwrap();
    assert!(sealed.len() - 16 <= MAX_CONTENT, "{}", sealed.len());
    assert_eq!(
        json::to_string(&client.open(&reply, &nonce)),
        r#"{"error":43,"req":1}"#
    );
    assert!(f.seen.lock().unwrap().is_empty());
}

/// T71 INT-01.33, T56 INT-01.36: a search text over 256 characters gets
/// boxed error 43 before the handler; 256 characters of two bytes each are
/// read. A `text` member of another type is unknown, so it is ignored
/// (INT-01.42).
fn t71_t56_search_text_over_256_characters_gets_boxed_error_43(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    client.prove(&mut wire);
    let over = "a".repeat(MAX_TEXT + 1);
    for (kind, field) in [("logins.search", "text"), ("autotype.start", "search")] {
        let content = |text: &str| format!(r#"{{"type":"{kind}","req":3,"{field}":"{text}"}}"#);
        assert_eq!(
            json::to_string(&client.ask(&mut wire, &content(&over))),
            format!(r#"{{"error":43,"req":3,"type":"{kind}"}}"#)
        );
        assert_eq!(f.handled(kind), 0, "{kind}");
        client.ask(&mut wire, &content(&"é".repeat(MAX_TEXT)));
        assert_eq!(f.handled(kind), 1, "{kind}: 256 characters are read");
    }
    let other = format!(r#"{{"type":"status","req":1,"text":"{over}"}}"#);
    assert_eq!(error(&client.ask(&mut wire, &other)), None);
}

/// The `Handler` docs: `type`, `req` and `error` are App's own; the
/// handler's values for them never reach the reply.
fn handler_never_sets_type_req_or_error(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    assert_eq!(
        json::to_string(&client.ask(&mut wire, r#"{"type":"lock","req":3}"#)),
        r#"{"locked":true,"req":3,"type":"lock"}"#
    );
}

/// T42 INT-01.25: a repeated member refuses the message.
fn t42_repeated_member_gets_error_12_and_nothing_runs(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let answer = client.ask(&mut wire, r#"{"type":"status","type":"lock","req":1}"#);
    assert_eq!(error(&answer), Some(12));
    assert!(f.seen.lock().unwrap().is_empty());
    let key = b64(&Secret::generate().unwrap().public());
    let twice = format!(r#"{{"type":"hello","versions":[1],"key":"{key}","key":"{key}"}}"#);
    assert_eq!(plain_error(&wire.json(&twice)), Some(12));
}

/// T43 INT-01.25: 33 levels refused, 32 read.
fn t43_content_nested_33_levels_gets_error_12(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let nest = |levels: usize| {
        format!(
            r#"{{"type":"status","req":1,"n":{}{}}}"#,
            "[".repeat(levels - 1),
            "]".repeat(levels - 1)
        )
    };
    assert_eq!(error(&client.ask(&mut wire, &nest(33))), Some(12));
    assert_eq!(f.handled("status"), 0);
    assert_eq!(error(&client.ask(&mut wire, &nest(32))), None);
    // Brackets inside strings are text, not nesting.
    let text = format!(r#"{{"type":"status","req":1,"t":"{}"}}"#, "[".repeat(100));
    assert_eq!(error(&client.ask(&mut wire, &text)), None);
    assert_eq!(f.handled("status"), 2);
}

/// INT-01.25: not one JSON object, or not UTF-8.
fn message_that_is_not_one_object_gets_error_12_or_13(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    assert_eq!(plain_error(&wire.json("   ")), Some(13));
    for bad in [
        &b"[1]"[..],
        b"{",
        b"{\"type\":\"box\"} {}",
        b"{\"type\":\"hello\xff\"}",
        b"null",
    ] {
        assert_eq!(plain_error(&parse(&wire.send(bad).unwrap())), Some(12));
    }
    assert_eq!(plain_error(&wire.json(r#"{"type":"connect"}"#)), Some(12));
    let mut client = Client::hello(&mut wire);
    let nonce = [3u8; 12];
    let message = client.boxed_with(&client.request, &nonce, b"[]");
    assert_eq!(
        json::to_string(&client.open(&wire.json(&message), &nonce)),
        r#"{"error":12}"#
    );
    // T50 INT-01.30, INT-01.37: a type App leaves out.
    let answer = client.ask(&mut wire, r#"{"type":"entries.delete","req":2}"#);
    assert_eq!(
        json::to_string(&answer),
        r#"{"error":12,"req":2,"type":"entries.delete"}"#
    );
    assert!(f.seen.lock().unwrap().is_empty());
}

/// T69, T75 INT-01.25, INT-01.27: URL fields at most 8,192 bytes.
fn t75_url_fields_over_8192_bytes_get_boxed_error_43(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let long = "u".repeat(MAX_URL + 1);
    let at = "u".repeat(MAX_URL);
    for field in ["url", "top_url", "form_url"] {
        let content = format!(r#"{{"type":"logins.find","req":3,"{field}":"{long}"}}"#);
        assert_eq!(error(&client.ask(&mut wire, &content)), Some(43), "{field}");
    }
    assert_eq!(f.handled("logins.find"), 0);
    let content = format!(
        r#"{{"type":"logins.find","req":3,"url":"{at}","top_url":"{at}","form_url":"{at}"}}"#
    );
    assert_eq!(
        error(&client.ask(&mut wire, &content)),
        Some(15),
        "searched"
    );
    assert_eq!(f.handled("logins.find"), 1);
}

/// T80 INT-01.49, INT-01.21: a box for the other direction does not open.
fn t80_request_sealed_with_the_reply_key_gets_plain_error_4(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let client = Client::hello(&mut wire);
    let message = client.boxed_with(&client.reply, &[5; 12], STATUS.as_bytes());
    assert_eq!(plain_error(&wire.json(&message)), Some(4));
    assert_eq!(f.handled("status"), 0);
}

/// T81 INT-01.23: the reply's nonce is the request's; it opens with the
/// reply key and not with the request key.
fn t81_reply_uses_the_request_nonce_and_opens_only_with_the_reply_key(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let (reply, nonce) = client.request(&mut wire, STATUS);
    let sealed = base64::decode(Form::Padded, reply.get("box").unwrap().as_str().unwrap()).unwrap();
    assert!(bridge::open(&client.request, &nonce, &sealed).is_err());
    assert_eq!(
        client
            .open(&reply, &nonce)
            .get("type")
            .and_then(Value::as_str),
        Some("status")
    );
}

/// T82 INT-01.26: nonces of 11 and 13 bytes, a box of 15 bytes.
fn t82_wrong_nonce_or_box_length_gets_plain_error_4(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let client = Client::hello(&mut wire);
    let good = bridge::seal(&client.request, &[6; 12], STATUS.as_bytes()).unwrap();
    let message = |nonce: &[u8], sealed: &[u8]| {
        format!(
            r#"{{"type":"box","sid":"{}","nonce":"{}","box":"{}"}}"#,
            client.sid,
            b64(nonce),
            b64(sealed)
        )
    };
    for m in [
        message(&[6; 11], &good),
        message(&[6; 13], &good),
        message(&[6; 12], &good[..15]),
    ] {
        assert_eq!(plain_error(&wire.json(&m)), Some(4));
    }
    let bad_text = format!(
        r#"{{"type":"box","sid":"{}","nonce":"{}","box":"not base64!"}}"#,
        client.sid,
        b64(&[6; 12])
    );
    assert_eq!(plain_error(&wire.json(&bad_text)), Some(4));
    assert_eq!(f.handled("status"), 0);
}

/// T83 INT-01.21: the sid first, then the nonce's encoding, then the set,
/// then the box.
fn t83_checks_run_in_the_cards_order(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let client = Client::hello(&mut wire);
    let unknown = r#"{"type":"box","sid":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"short","box":"x"}"#;
    assert_eq!(plain_error(&wire.json(unknown)), Some(3));
    let message = client.boxed_with(&client.request, &[8; 12], STATUS.as_bytes());
    assert!(plain_error(&wire.json(&message)).is_none());
    let seen_bad_box = format!(
        r#"{{"type":"box","sid":"{}","nonce":"{}","box":"%%%"}}"#,
        client.sid,
        b64(&[8; 12])
    );
    assert_eq!(plain_error(&wire.json(&seen_bad_box)), Some(41));
    let no_sid = format!(r#"{{"type":"box","nonce":"{}","box":"x"}}"#, b64(&[8; 12]));
    assert_eq!(plain_error(&wire.json(&no_sid)), Some(3));
}

/// T46 INT-01.28: the right proof; the handler sees the proven key.
fn t46_right_proof_proves_the_identification_key(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let id = Secret::generate().unwrap();
    let nonce = client.next_nonce();
    let proof = client.proof(&id, &nonce);
    assert_eq!(proof.len(), 48);
    let answer = client.check(&mut wire, &id.public(), &proof, nonce);
    assert_eq!(error(&answer), None, "{answer}");
    assert_eq!(f.last_seen().2, Some(id.public()));
    // The identity stays for the session's later requests.
    client.ask(&mut wire, STATUS);
    assert_eq!(
        f.last_seen(),
        ("status".into(), "Chrome".into(), Some(id.public()))
    );
}

/// T45 INT-01.28: a proof made for another session's client key.
fn t45_proof_for_another_sessions_key_gets_error_8(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let mut other_wire = f.wire(route);
    let other = Client::hello(&mut other_wire);
    let id = Secret::generate().unwrap();
    let nonce = client.next_nonce();
    let answer = client.check(&mut wire, &id.public(), &other.proof(&id, &nonce), nonce);
    assert_eq!(error(&answer), Some(8));
    assert_eq!(f.handled("check"), 0);
    assert_no_identity(f, &mut client, &mut wire);
}

/// T47 INT-01.28: the stored public key, copied out of a vault, with a
/// proof made with another secret key.
fn t47_copied_public_key_without_its_secret_gets_error_8(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let (stored, thief) = (Secret::generate().unwrap(), Secret::generate().unwrap());
    let nonce = client.next_nonce();
    let z = thief.agree(&client.app).unwrap();
    let key = bridge::proof_key(&z, &client.key, &client.app, &stored.public()).unwrap();
    let proof = bridge::seal(&key, &nonce, &client.key).unwrap();
    assert_eq!(
        error(&client.check(&mut wire, &stored.public(), &proof, nonce)),
        Some(8)
    );
    assert_eq!(f.handled("check"), 0);
    assert_no_identity(f, &mut client, &mut wire);
}

/// T72 INT-01.28: `id_key` of 32 zero bytes, or equal to the hello's key.
fn t72_zero_or_session_id_key_gets_error_10(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let nonce = client.next_nonce();
    assert_eq!(
        error(&client.check(&mut wire, &[0; 32], &[0; 48], nonce)),
        Some(10)
    );
    let nonce = client.next_nonce();
    let own = client.proof(&client.secret, &nonce);
    let key = client.key;
    assert_eq!(error(&client.check(&mut wire, &key, &own, nonce)), Some(10));
    let nonce = client.next_nonce();
    assert_eq!(
        error(&client.check(&mut wire, &[1; 31], &own, nonce)),
        Some(10)
    );
    assert_eq!(f.handled("check"), 0);
    assert_no_identity(f, &mut client, &mut wire);
}

/// T84 INT-01.28: a proof of 47 bytes, one sealed with another request's
/// nonce, one whose content is A instead of C.
fn t84_short_proof_other_nonce_or_wrong_content_gets_error_8(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let id = Secret::generate().unwrap();
    let nonce = client.next_nonce();
    let proof = client.proof(&id, &nonce);
    assert_eq!(
        error(&client.check(&mut wire, &id.public(), &proof[..47], nonce)),
        Some(8)
    );
    let (other, nonce) = (client.next_nonce(), client.next_nonce());
    assert_eq!(
        error(&client.check(&mut wire, &id.public(), &client.proof(&id, &other), nonce)),
        Some(8)
    );
    let nonce = client.next_nonce();
    let z_id = id.agree(&client.app).unwrap();
    let key = bridge::proof_key(&z_id, &client.key, &client.app, &id.public()).unwrap();
    let of_a = bridge::seal(&key, &nonce, &client.app).unwrap();
    assert_eq!(
        error(&client.check(&mut wire, &id.public(), &of_a, nonce)),
        Some(8)
    );
    assert_eq!(f.handled("check"), 0);
    assert_no_identity(f, &mut client, &mut wire);
}

/// T85 INT-01.20: `Arc` is named; an unknown browser is `Browser`.
fn t85_unknown_browser_is_named_browser(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello_as(&mut wire, "Arc");
    client.ask(&mut wire, STATUS);
    assert_eq!(f.last_seen().1, "Arc");
    let mut client = Client::hello_as(&mut wire, "NoSuchBrowser");
    client.ask(&mut wire, STATUS);
    assert_eq!(f.last_seen().1, "Browser");
}

/// T77 INT-01.42: unknown members are ignored; `app` is App's version.
fn t77_unknown_members_are_ignored(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let key = Secret::generate().unwrap();
    let reply = wire.json(&format!(
        r#"{{"type":"hello","versions":[1],"key":"{}","future":1,"nonce":"x"}}"#,
        b64(&key.public())
    ));
    assert_eq!(reply.get("app").and_then(Value::as_str), Some("1.0"));
    assert_eq!(reply.get("version").and_then(Value::as_u64), Some(1));
    let mut client = Client::hello(&mut wire);
    let answer = client.ask(&mut wire, r#"{"type":"status","req":1,"future":{"x":1}}"#);
    assert_eq!(
        json::to_string(&answer),
        r#"{"req":1,"type":"status","vaults":[]}"#
    );
}

/// T57 INT-01.40: an error reply holds only `type`, `req`, `error` (and
/// `versions` for 40): no text.
fn t57_errors_hold_only_type_req_and_error(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    for (message, expected) in [
        (
            r#"{"type":"box","sid":"x"}"#,
            r#"{"error":3,"type":"error"}"#,
        ),
        (r#"{"type":"what"}"#, r#"{"error":12,"type":"error"}"#),
    ] {
        assert_eq!(json::to_string(&wire.json(message)), expected);
    }
    let mut client = Client::hello(&mut wire);
    let answer = client.ask(
        &mut wire,
        r#"{"type":"logins.find","req":2,"url":"https://site-a.test/"}"#,
    );
    assert_eq!(
        json::to_string(&answer),
        r#"{"error":15,"req":2,"type":"logins.find"}"#
    );
}

/// INT-01.28, INT-01.30 (F-203): a boxed `connect` carries `id_key` and
/// `proof` as `check` does. With no key it gets error 10 and with a proof
/// made with another secret key error 8, and neither reaches the handler;
/// with its own proof the handler sees the key it proved.
fn connect_needs_its_proof(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let answer = client.ask(&mut wire, r#"{"type":"connect","req":2,"name":"x"}"#);
    assert_eq!(error(&answer), Some(10), "{answer}");
    let id = Secret::generate().unwrap();
    let other = Secret::generate().unwrap();
    let connect = |client: &mut Client, wire: &mut Wire, signer: &Secret| {
        let nonce = client.next_nonce();
        let content = format!(
            r#"{{"type":"connect","req":2,"id_key":"{}","proof":"{}"}}"#,
            b64(&id.public()),
            b64(&client.proof(signer, &nonce))
        );
        let message = client.boxed_with(&client.request, &nonce, content.as_bytes());
        let reply = wire.json(&message);
        client.open(&reply, &nonce)
    };
    assert_eq!(error(&connect(&mut client, &mut wire, &other)), Some(8));
    assert_eq!(f.handled("connect"), 0);
    assert_eq!(error(&connect(&mut client, &mut wire, &id)), None);
    assert_eq!(
        f.last_seen(),
        ("connect".into(), "Chrome".into(), Some(id.public()))
    );
}

/// INT-01.25 and its Limits table (F-204): a URL field's limit is 8,192
/// bytes, not characters. A `url` of 4,097 two-byte characters (8,194
/// bytes) gets boxed error 43 and does not reach the handler.
fn url_limit_counts_bytes_not_characters(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let long = "é".repeat(MAX_URL / 2 + 1);
    assert!(long.len() > MAX_URL && long.chars().count() <= MAX_URL);
    let content = format!(r#"{{"type":"logins.find","req":3,"url":"{long}"}}"#);
    assert_eq!(error(&client.ask(&mut wire, &content)), Some(43));
    assert_eq!(f.handled("logins.find"), 0);
}

/// INT-01.25 (F-204): the depth limit counts brackets outside strings
/// only, and an escaped quote does not end a string: brackets after `\"`
/// are still text, so this content is read and answered.
fn escaped_quote_then_brackets_inside_a_string_are_text(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let content = format!(
        r#"{{"type":"status","req":1,"t":"a\"{}"}}"#,
        "[".repeat(MAX_DEPTH + 8)
    );
    assert_eq!(error(&client.ask(&mut wire, &content)), None);
    assert_eq!(f.handled("status"), 1);
}

/// INT-01.25 (M1, M2): a closing bracket or brace ends its level, so 40
/// sibling objects and 40 sibling lists are two levels, not 80.
fn many_sibling_containers_are_not_nesting(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let objects = vec!["{}"; 40].join(",");
    let arrays = vec!["[]"; 40].join(",");
    let content = format!(r#"{{"type":"status","req":1,"o":[{objects}],"a":[{arrays}]}}"#);
    assert_eq!(error(&client.ask(&mut wire, &content)), None);
    assert_eq!(f.handled("status"), 1);
}

/// INT-01.20 (M3): every version in a hello is a whole number; a list with
/// a text, a fraction or a null gets plain error 40 and makes no session.
fn hello_versions_that_are_not_whole_numbers_get_plain_error_40(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let key = b64(&Secret::generate().unwrap().public());
    for versions in [r#"[1,"2"]"#, "[1,2.5]", "[1,null]"] {
        let reply = wire.json(&format!(
            r#"{{"type":"hello","versions":{versions},"key":"{key}","browser":"Chrome"}}"#
        ));
        assert_eq!(
            json::to_string(&reply),
            r#"{"error":40,"type":"error","versions":[1]}"#,
            "{versions}"
        );
    }
    assert_eq!(f.bridge.lock().unwrap().sessions(), 0);
}

/// `{"type":"status","req":1,"a":[…]}` with `items` in the list: the
/// status members add 4 commas and opening brackets to the items' own.
fn status_with_list(items: &[&str]) -> String {
    format!(r#"{{"type":"status","req":1,"a":[{}]}}"#, items.join(","))
}

/// T88 (a) INT-01.25, INT-01.48 (F-211): a plain frame of 1,048,575 bytes,
/// a flat list of 524,287 numbers, gets plain error 12 before the reader
/// builds it; so does a hello whose `versions` is such a list (without the
/// limit it would be read and get error 40). No session, nothing handled.
fn t88a_flat_list_frame_of_1_mib_gets_plain_error_12(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let list = format!("[{}]", vec!["0"; 524_287].join(","));
    assert_eq!(list.len(), 1_048_575);
    assert_eq!(
        plain_error(&parse(&wire.send(list.as_bytes()).unwrap())),
        Some(12)
    );
    let key = b64(&Secret::generate().unwrap().public());
    let versions = vec!["1"; MAX_VALUES].join(",");
    let hello = format!(r#"{{"type":"hello","versions":[{versions}],"key":"{key}"}}"#);
    assert_eq!(plain_error(&wire.json(&hello)), Some(12));
    assert_eq!(f.bridge.lock().unwrap().sessions(), 0);
    assert!(f.seen.lock().unwrap().is_empty());
}

/// T88 (b) INT-01.25, INT-01.48 (F-211): a box whose content is 600,000
/// bytes, a `status` with a flat list of numbers, gets boxed error 12 and
/// does not reach the handler.
fn t88b_boxed_flat_list_of_600_kb_gets_boxed_error_12(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let mut content = status_with_list(&vec!["0"; 299_980]);
    content.insert_str(content.len() - 2, &" ".repeat(600_000 - content.len()));
    assert_eq!(content.len(), 600_000);
    assert_eq!(
        json::to_string(&client.ask(&mut wire, &content)),
        r#"{"error":12}"#
    );
    assert!(f.seen.lock().unwrap().is_empty());
}

/// T88 (c) INT-01.25 (F-211): a box whose content is a list of 16,385 empty
/// lists gets boxed error 12. Opening brackets count as commas do: a
/// `status` with 600 chains 30 levels deep has only 601 commas but 18,002
/// opening brackets, so it is refused too (were brackets not counted, it
/// would be answered).
fn t88c_boxed_list_of_16385_empty_lists_gets_boxed_error_12(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    let lists = format!("[{}]", vec!["[]"; MAX_VALUES + 1].join(","));
    assert_eq!(
        json::to_string(&client.ask(&mut wire, &lists)),
        r#"{"error":12}"#
    );
    let chain = format!("{}{}", "[".repeat(MAX_DEPTH - 2), "]".repeat(MAX_DEPTH - 2));
    let chains = status_with_list(&vec![chain.as_str(); 600]);
    assert_eq!(
        json::to_string(&client.ask(&mut wire, &chains)),
        r#"{"error":12}"#
    );
    assert!(f.seen.lock().unwrap().is_empty());
}

/// T88 (d) INT-01.25 (F-211): a `status` with 16,384 commas and opening
/// brackets in all (8,191 items, 8,190 of them empty lists) is answered;
/// one bracket more (the number made an empty list) or one comma more (a
/// second number) gets boxed error 12.
fn t88d_16384_commas_and_brackets_are_answered_and_one_more_is_refused(f: &Fixture, route: Route) {
    let mut wire = f.wire(route);
    let mut client = Client::hello(&mut wire);
    // 4 for the status members, a comma between items, a bracket per list.
    let status = |lists: usize, numbers: usize, marks: usize| {
        assert_eq!(4 + lists + numbers - 1 + lists, marks);
        let mut items = vec!["[]"; lists];
        items.extend(vec!["0"; numbers]);
        status_with_list(&items)
    };
    let at_limit = status(8_190, 1, MAX_VALUES);
    assert_eq!(error(&client.ask(&mut wire, &at_limit)), None);
    assert_eq!(f.handled("status"), 1);
    for over in [
        status(8_191, 0, MAX_VALUES + 1),
        status(8_190, 2, MAX_VALUES + 1),
    ] {
        assert_eq!(
            json::to_string(&client.ask(&mut wire, &over)),
            r#"{"error":12}"#
        );
    }
    assert_eq!(f.handled("status"), 1);
}

macro_rules! on_both_routes {
    ($($case:ident),* $(,)?) => {
        /// The bridge socket: one connection per session.
        mod port {
            $(#[test] fn $case() { super::$case(&super::Fixture::new(), super::Route::Port); })*
        }
        /// The Safari socket: a new connection for every message.
        mod safari {
            $(#[test] fn $case() { super::$case(&super::Fixture::new(), super::Route::Safari); })*
        }
    };
}

on_both_routes!(
    t29_hello_gives_version_1_a_key_and_a_sid_and_status_is_answered,
    t28_hello_without_version_1_gets_plain_error_40,
    t30_low_order_client_key_gets_plain_error_10,
    t44_key_that_is_not_strict_base64_gets_plain_error_10,
    t32_boxed_status_gets_a_boxed_reply_with_its_type_and_req,
    t33_flipped_bit_gets_plain_error_4_and_nothing_runs,
    t35_request_without_a_usable_req_gets_boxed_error_12_without_req,
    t39_replayed_box_gets_plain_error_41_and_runs_once,
    t40_reply_sent_back_as_a_request_gets_plain_error_41,
    t41_content_over_640_kib_gets_boxed_error_43,
    reply_over_640_kib_becomes_boxed_error_43,
    reply_echoing_a_long_type_stays_within_640_kib,
    t71_t56_search_text_over_256_characters_gets_boxed_error_43,
    handler_never_sets_type_req_or_error,
    t42_repeated_member_gets_error_12_and_nothing_runs,
    t43_content_nested_33_levels_gets_error_12,
    message_that_is_not_one_object_gets_error_12_or_13,
    t75_url_fields_over_8192_bytes_get_boxed_error_43,
    t80_request_sealed_with_the_reply_key_gets_plain_error_4,
    t81_reply_uses_the_request_nonce_and_opens_only_with_the_reply_key,
    t82_wrong_nonce_or_box_length_gets_plain_error_4,
    t83_checks_run_in_the_cards_order,
    t46_right_proof_proves_the_identification_key,
    t45_proof_for_another_sessions_key_gets_error_8,
    t47_copied_public_key_without_its_secret_gets_error_8,
    t72_zero_or_session_id_key_gets_error_10,
    t84_short_proof_other_nonce_or_wrong_content_gets_error_8,
    t85_unknown_browser_is_named_browser,
    t77_unknown_members_are_ignored,
    t57_errors_hold_only_type_req_and_error,
    connect_needs_its_proof,
    url_limit_counts_bytes_not_characters,
    escaped_quote_then_brackets_inside_a_string_are_text,
    many_sibling_containers_are_not_nesting,
    hello_versions_that_are_not_whole_numbers_get_plain_error_40,
    t88a_flat_list_frame_of_1_mib_gets_plain_error_12,
    t88b_boxed_flat_list_of_600_kb_gets_boxed_error_12,
    t88c_boxed_list_of_16385_empty_lists_gets_boxed_error_12,
    t88d_16384_commas_and_brackets_are_answered_and_one_more_is_refused,
);

// ---------------------------------------------------------------------------
// The Safari route (INT-01.13, INT-01.14).

/// T26 INT-01.14: answered at T0+14 min on a new connection; at T0+30 min
/// (16 minutes after the last request) plain error 3.
#[test]
fn t26_safari_session_ends_after_15_minutes_without_a_request() {
    let f = Fixture::new();
    let mut wire = f.wire(Route::Safari);
    let mut client = Client::hello(&mut wire);
    f.advance(14);
    assert_eq!(error(&client.ask(&mut wire, STATUS)), None);
    f.advance(16);
    let (reply, _) = client.request(&mut wire, STATUS);
    assert_eq!(plain_error(&reply), Some(3));
    assert_eq!(f.handled("status"), 1);
    // A new hello starts a new session.
    let mut client = Client::hello(&mut wire);
    assert_eq!(error(&client.ask(&mut wire, STATUS)), None);
}

/// INT-01.14: each request starts the 15 minutes again; at exactly 15
/// minutes the session has ended.
#[test]
fn safari_idle_time_counts_from_the_last_request() {
    let f = Fixture::new();
    let mut wire = f.wire(Route::Safari);
    let mut client = Client::hello(&mut wire);
    for _ in 0..3 {
        f.minutes.fetch_add(IDLE.as_secs() - 1, Ordering::SeqCst);
        assert_eq!(error(&client.ask(&mut wire, STATUS)), None);
    }
    f.minutes.fetch_add(IDLE.as_secs(), Ordering::SeqCst);
    assert_eq!(plain_error(&client.request(&mut wire, STATUS).0), Some(3));
}

/// INT-01.14, INT-01.21 (T33 "nothing else happens"): a box that does not
/// open is not a request, so it does not start the 15 minutes again: 16
/// minutes after the hello, 6 after the failed box, the session has ended.
#[test]
fn failed_box_does_not_restart_safari_idle_time() {
    let f = Fixture::new();
    let mut wire = f.wire(Route::Safari);
    let mut client = Client::hello(&mut wire);
    f.advance(10);
    let nonce = client.next_nonce();
    let bad = client.boxed_with(&client.reply, &nonce, STATUS.as_bytes());
    assert_eq!(plain_error(&wire.json(&bad)), Some(4));
    f.advance(6);
    assert_eq!(plain_error(&client.request(&mut wire, STATUS).0), Some(3));
    assert_eq!(f.handled("status"), 0);
}

/// INT-01.14: an idle Safari session's keys go even when nothing comes in:
/// the listener's tick ends it.
#[test]
fn idle_safari_session_ends_without_any_traffic() {
    let f = Fixture::new();
    let mut wire = f.wire(Route::Safari);
    Client::hello(&mut wire);
    assert_eq!(f.bridge.lock().unwrap().sessions(), 1);
    f.advance(15);
    let deadline = Instant::now() + Duration::from_secs(5);
    while f.bridge.lock().unwrap().sessions() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(f.bridge.lock().unwrap().sessions(), 0);
}

/// INT-01.21: a session belongs to its route: a Safari `sid` on the bridge
/// socket and a bridge `sid` on the Safari socket get plain error 3.
#[test]
fn sid_of_the_other_route_gets_plain_error_3() {
    let f = Fixture::new();
    let (mut safari, mut port) = (f.wire(Route::Safari), f.wire(Route::Port));
    let mut s = Client::hello(&mut safari);
    let mut p = Client::hello(&mut port);
    assert_eq!(plain_error(&s.request(&mut port, STATUS).0), Some(3));
    assert_eq!(plain_error(&p.request(&mut safari, STATUS).0), Some(3));
    assert_eq!(error(&s.ask(&mut safari, STATUS)), None);
    assert_eq!(error(&p.ask(&mut port, STATUS)), None);
}

/// INT-01.14: Safari sessions end when the Safari switch turns off (the
/// listener stops); bridge sessions stay.
#[test]
fn safari_sessions_end_when_the_safari_socket_stops() {
    let mut f = Fixture::new();
    let (mut safari, mut port) = (f.wire(Route::Safari), f.wire(Route::Port));
    Client::hello(&mut safari);
    let mut p = Client::hello(&mut port);
    assert_eq!(f.bridge.lock().unwrap().sessions(), 2);
    f.safari.take().unwrap().stop();
    assert_eq!(f.bridge.lock().unwrap().sessions(), 1);
    assert!(!f.dir.join("s.sock").exists());
    assert_eq!(error(&p.ask(&mut port, STATUS)), None);
}

// ---------------------------------------------------------------------------
// The bridge socket (INT-01.2, INT-01.3, INT-01.6, INT-01.21, INT-01.44).

/// T34 INT-01.21: X's `sid` sent on connection Y.
#[test]
fn t34_sid_of_another_connection_gets_plain_error_3() {
    let f = Fixture::new();
    let (mut x, mut y) = (f.wire(Route::Port), f.wire(Route::Port));
    let mut cx = Client::hello(&mut x);
    Client::hello(&mut y);
    assert_eq!(plain_error(&cx.request(&mut y, STATUS).0), Some(3));
    assert_eq!(error(&cx.ask(&mut x, STATUS)), None);
}

/// INT-01.22: a bridge session ends when its connection closes.
#[test]
fn port_session_ends_when_its_connection_closes() {
    let f = Fixture::new();
    let mut x = f.wire(Route::Port);
    let mut client = Client::hello(&mut x);
    drop(x);
    let deadline = Instant::now() + Duration::from_secs(5);
    while f.bridge.lock().unwrap().sessions() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(f.bridge.lock().unwrap().sessions(), 0);
    let mut y = f.wire(Route::Port);
    assert_eq!(plain_error(&client.request(&mut y, STATUS).0), Some(3));
}

/// INT-01.22: a bridge session never ends by idle time: after 16 idle
/// minutes and the accept loops' ticks it is still there and answers (F-198).
#[test]
fn port_session_outlives_15_idle_minutes() {
    let f = Fixture::new();
    let mut x = f.wire(Route::Port);
    let mut client = Client::hello(&mut x);
    f.advance(16);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(f.bridge.lock().unwrap().sessions(), 1);
    assert_eq!(error(&client.ask(&mut x, STATUS)), None);
}

/// INT-01.20: a second hello on one connection replaces its session.
#[test]
fn second_hello_on_a_connection_replaces_its_session() {
    let f = Fixture::new();
    let mut x = f.wire(Route::Port);
    let mut old = Client::hello(&mut x);
    let mut new = Client::hello(&mut x);
    assert_eq!(f.bridge.lock().unwrap().sessions(), 1);
    assert_eq!(plain_error(&old.request(&mut x, STATUS).0), Some(3));
    assert_eq!(error(&new.ask(&mut x, STATUS)), None);
}

/// T02, T03 INT-01.2: a frame in two writes; two frames in one write.
#[test]
fn t02_t03_the_length_prefix_decides_where_a_frame_ends() {
    let f = Fixture::new();
    let mut s = connect(&f.dir.join("p.sock"));
    let key = Secret::generate().unwrap().public();
    let body = hello(&key, "Chrome").into_bytes();
    let mut frame = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    s.write_all(&frame[..2]).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    s.write_all(&frame[2..]).unwrap();
    assert_eq!(
        parse(&read_frame(&mut s).unwrap())
            .get("type")
            .and_then(Value::as_str),
        Some("hello")
    );
    let two = [frame.clone(), frame].concat();
    s.write_all(&two).unwrap();
    for _ in 0..2 {
        assert_eq!(
            parse(&read_frame(&mut s).unwrap())
                .get("type")
                .and_then(Value::as_str),
            Some("hello")
        );
    }
}

/// T04, T06 INT-01.2, INT-01.3: a stream that ends inside a frame, a length
/// of 0, of 1,048,577 and of `FF FF FF FF` close the connection; App keeps
/// serving new ones. A frame of exactly 1,048,576 bytes is read.
#[test]
fn t04_t06_bad_frames_close_the_connection_and_app_keeps_serving() {
    let f = Fixture::new();
    let path = f.dir.join("p.sock");
    let closed = |s: &mut UnixStream| closed_by_app(s);
    let mut s = connect(&path);
    s.write_all(&100u32.to_le_bytes()).unwrap();
    s.write_all(&[b' '; 50]).unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(closed(&mut s));
    for len in [0u32, u32::try_from(MAX_FRAME).unwrap() + 1, u32::MAX] {
        let mut s = connect(&path);
        s.write_all(&len.to_le_bytes()).unwrap();
        assert!(closed(&mut s), "{len}");
    }
    let key = b64(&Secret::generate().unwrap().public());
    let mut body = format!(r#"{{"type":"hello","versions":[1],"key":"{key}"}}"#).into_bytes();
    body.resize(MAX_FRAME, b' ');
    let mut s = connect(&path);
    send_frame(&mut s, &body);
    assert_eq!(
        parse(&read_frame(&mut s).unwrap())
            .get("type")
            .and_then(Value::as_str),
        Some("hello")
    );
}

/// T60 INT-01.44: a 17th connection is closed at once; the others work.
#[test]
fn t60_seventeenth_connection_is_closed_at_once() {
    let f = Fixture::new();
    let mut wires: Vec<Wire> = (0..MAX_CONNECTIONS).map(|_| f.wire(Route::Port)).collect();
    for w in &mut wires {
        Client::hello(w);
    }
    let mut extra = connect(&f.dir.join("p.sock"));
    let key = Secret::generate().unwrap().public();
    let body = hello(&key, "Chrome").into_bytes();
    let mut frame = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    let _ = extra.write_all(&frame);
    assert!(closed_by_app(&mut extra));
    wires.pop();
    std::thread::sleep(Duration::from_millis(100));
    Client::hello(&mut f.wire(Route::Port));
}

/// INT-01.6: the socket is mode 0600; a leftover file that is not the
/// user's socket stops the start and stays untouched; a leftover socket of
/// the user is replaced; stopping removes the socket.
#[test]
fn socket_is_owner_only_and_leftovers_follow_int_01_6() {
    let f = Fixture::new();
    let mode = std::fs::metadata(f.dir.join("p.sock"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let clock = clock(&f.minutes);
    let in_the_way = f.dir.join("file.sock");
    std::fs::write(&in_the_way, b"keep").unwrap();
    let err = Server::start(&in_the_way, Route::Port, f.bridge.clone(), clock.clone()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&in_the_way).unwrap(), b"keep");
    let left = f.dir.join("left.sock");
    drop(UnixListener::bind(&left).unwrap());
    let server = Server::start(&left, Route::Port, f.bridge.clone(), clock.clone()).unwrap();
    Client::hello(&mut Wire::Port(connect(&left)));
    server.stop();
    assert!(!left.exists());
    let long = f.dir.join("x".repeat(120));
    let err = Server::start(&long, Route::Port, f.bridge.clone(), clock).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

/// INT-01.6: a stopping server removes only its own socket: a newer
/// server's socket at the same path stays and keeps serving.
#[test]
fn stop_leaves_a_newer_socket_in_place() {
    let f = Fixture::new();
    let path = f.dir.join("again.sock");
    let clock = clock(&f.minutes);
    let old = Server::start(&path, Route::Port, f.bridge.clone(), clock.clone()).unwrap();
    let new = Server::start(&path, Route::Port, f.bridge.clone(), clock).unwrap();
    old.stop();
    assert!(path.exists());
    Client::hello(&mut Wire::Port(connect(&path)));
    new.stop();
    assert!(!path.exists());
}

/// T63, T73 INT-01.46, INT-01.23: a notice goes only to the bridge sessions
/// it names, sealed with the reply key and a nonce no request used; a
/// request that reuses a notice's nonce gets plain error 41.
#[test]
fn t63_t73_notices_and_their_nonces() {
    let f = Fixture::new();
    let (mut proven, mut other, mut safari) = (
        f.wire(Route::Port),
        f.wire(Route::Port),
        f.wire(Route::Safari),
    );
    let mut a = Client::hello(&mut proven);
    let id = Secret::generate().unwrap();
    let nonce = a.next_nonce();
    let proof = a.proof(&id, &nonce);
    assert_eq!(
        error(&a.check(&mut proven, &id.public(), &proof, nonce)),
        None
    );
    let mut b = Client::hello(&mut other);
    Client::hello(&mut safari);
    let wanted = id.public();
    f.port().notify("locked", |key| key == Some(&wanted));
    let Wire::Port(stream) = &mut proven else {
        unreachable!()
    };
    let notice = parse(&read_frame(stream).unwrap());
    let notice_nonce: [u8; 12] =
        base64::decode(Form::Padded, notice.get("nonce").unwrap().as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    assert_ne!(notice_nonce, nonce);
    let sealed =
        base64::decode(Form::Padded, notice.get("box").unwrap().as_str().unwrap()).unwrap();
    let content = bridge::open(&a.reply, &notice_nonce, &sealed).unwrap();
    assert_eq!(content.expose(), br#"{"event":"locked","type":"notice"}"#);
    // The other session got nothing: its next reply is the reply to its request.
    assert_eq!(error(&b.ask(&mut other, STATUS)), None);
    let reuse = a.boxed_with(&a.request, &notice_nonce, STATUS.as_bytes());
    assert_eq!(plain_error(&proven.json(&reuse)), Some(41));
}

// ---------------------------------------------------------------------------
// The bridge alone, with the time in the test's hand.

fn direct() -> (Bridge, Seen) {
    let seen = Seen::default();
    (Bridge::new("1.0", Box::new(Demo(seen.clone()))), seen)
}

/// A hello on `route` at `now`: the session's request key, reply key and `sid`.
fn direct_session(
    b: &mut Bridge,
    route: Route,
    now: Instant,
) -> (SecretBytes, SecretBytes, String) {
    let secret = Secret::generate().unwrap();
    let key = secret.public();
    let reply = parse(
        &b.take(1, route, hello(&key, "Chrome").as_bytes(), now)
            .unwrap(),
    );
    let app: [u8; 32] = base64::decode(Form::Padded, reply.get("key").unwrap().as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let z = secret.agree(&app).unwrap();
    (
        bridge::request_key(&z, &key, &app).unwrap(),
        bridge::reply_key(&z, &key, &app).unwrap(),
        reply.get("sid").unwrap().as_str().unwrap().to_owned(),
    )
}

/// A box of `status` sealed with `key` and the nonce numbered `n`.
fn status_box(key: &SecretBytes, sid: &str, n: u32) -> String {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&n.to_be_bytes());
    let sealed = bridge::seal(key, &nonce, STATUS.as_bytes()).unwrap();
    format!(
        r#"{{"type":"box","sid":"{sid}","nonce":"{}","box":"{}"}}"#,
        b64(&nonce),
        b64(&sealed)
    )
}

/// INT-01.14: the bridge ends an idle Safari session when a message comes,
/// not only on a listener's tick: with no listener, a good box at exactly
/// T0 + 15 minutes gets plain error 3 and the handler sees nothing.
#[test]
fn safari_session_ends_at_15_minutes_in_take_itself() {
    let (mut b, seen) = direct();
    let t0 = Instant::now();
    let (request, _, sid) = direct_session(&mut b, Route::Safari, t0);
    let message = status_box(&request, &sid, 0);
    let reply = parse(
        &b.take(1, Route::Safari, message.as_bytes(), t0 + IDLE)
            .unwrap(),
    );
    assert_eq!(plain_error(&reply), Some(3), "{reply}");
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(b.sessions(), 0);
}

/// INT-01.22, INT-01.21 (T33 "nothing else happens"): a box that does not
/// open is not a request, so it does not count toward the 100,000: after ten
/// boxes sealed with the reply key, 100,000 good boxes all reach the handler.
#[test]
fn failed_boxes_do_not_count_toward_100000() {
    let (mut b, seen) = direct();
    let now = Instant::now();
    let (request, reply, sid) = direct_session(&mut b, Route::Port, now);
    for n in 0..10 {
        let m = status_box(&reply, &sid, MAX_REQUESTS + n);
        let answer = parse(&b.take(1, Route::Port, m.as_bytes(), now).unwrap());
        assert_eq!(plain_error(&answer), Some(4), "{answer}");
    }
    for n in 0..MAX_REQUESTS {
        let m = status_box(&request, &sid, n);
        assert!(b.take(1, Route::Port, m.as_bytes(), now).is_some());
    }
    assert_eq!(seen.lock().unwrap().len(), MAX_REQUESTS as usize);
}

/// INT-01.46 (M4): notices go to bridge sessions only, never to a Safari
/// session, which has no connection to send them on.
#[test]
fn notices_never_go_to_safari_sessions() {
    let (mut b, _) = direct();
    let now = Instant::now();
    let hello_on = |b: &mut Bridge, conn: u64, route: Route| {
        let key = Secret::generate().unwrap().public();
        let reply = parse(
            &b.take(conn, route, hello(&key, "Chrome").as_bytes(), now)
                .unwrap(),
        );
        assert_eq!(reply.get("type").and_then(Value::as_str), Some("hello"));
    };
    hello_on(&mut b, 1, Route::Safari);
    assert!(b.notice("locked", |_| true).is_empty());
    hello_on(&mut b, 2, Route::Port);
    let sent: Vec<u64> = b
        .notice("locked", |_| true)
        .into_iter()
        .map(|(c, _)| c)
        .collect();
    assert_eq!(sent, [2]);
}

/// T68 INT-01.22: after 100,000 requests every box gets plain error 41;
/// after a new hello `status` is answered again.
#[test]
fn t68_after_100000_requests_a_session_needs_a_new_hello() {
    let (mut b, seen) = direct();
    let now = Instant::now();
    let take = |b: &mut Bridge, m: &str| parse(&b.take(1, Route::Port, m.as_bytes(), now).unwrap());
    let (key, _, sid) = direct_session(&mut b, Route::Port, now);
    for n in 0..MAX_REQUESTS {
        let m = status_box(&key, &sid, n);
        assert!(b.take(1, Route::Port, m.as_bytes(), now).is_some());
    }
    assert_eq!(seen.lock().unwrap().len(), MAX_REQUESTS as usize);
    assert_eq!(
        plain_error(&take(&mut b, &status_box(&key, &sid, MAX_REQUESTS))),
        Some(41)
    );
    assert_eq!(seen.lock().unwrap().len(), MAX_REQUESTS as usize);
    let (key, _, sid) = direct_session(&mut b, Route::Port, now);
    assert_eq!(
        take(&mut b, &status_box(&key, &sid, 0))
            .get("type")
            .and_then(Value::as_str),
        Some("box")
    );
}

/// INT-01.44: at most 20 hellos a second over all connections; the 21st
/// closes its connection; the next second takes hellos again.
#[test]
fn hellos_over_20_a_second_close_the_connection() {
    let (mut b, _) = direct();
    let now = Instant::now();
    let key = Secret::generate().unwrap().public();
    let message = hello(&key, "Chrome");
    for conn in 0..u64::from(MAX_HELLOS) {
        assert!(b.take(conn, Route::Port, message.as_bytes(), now).is_some());
    }
    assert!(
        b.take(
            99,
            Route::Safari,
            message.as_bytes(),
            now + Duration::from_millis(900)
        )
        .is_none()
    );
    assert!(
        b.take(
            99,
            Route::Port,
            message.as_bytes(),
            now + Duration::from_secs(1)
        )
        .is_some()
    );
}

/// INT-01.47: the bridge's `Debug` output holds no key and no content.
#[test]
fn debug_output_holds_no_secret() {
    let (mut b, _) = direct();
    let key = Secret::generate().unwrap().public();
    b.take(
        1,
        Route::Port,
        hello(&key, "Chrome").as_bytes(),
        Instant::now(),
    );
    assert_eq!(format!("{b:?}"), "Bridge { sessions: 1, .. }");
}

// --- INT-01.44 and INT-01.45 with a vault side that waits (E7-S2) ---

/// A vault side whose `logins.get` waits until released and whose
/// `code.get` waits until its session ends, as a dialog does.
#[derive(Default)]
struct Waits {
    release: std::sync::atomic::AtomicBool,
    ended: std::sync::atomic::AtomicUsize,
}

impl SharedHandler for Waits {
    fn handle(&self, r: &Request<'_>) -> Result<Map, u8> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match r.kind {
                "logins.get" if self.release.load(Ordering::SeqCst) => return Ok(Map::new()),
                "code.get" if r.session.ended() => {
                    self.ended.fetch_add(1, Ordering::SeqCst);
                    return Err(6);
                }
                "logins.get" | "code.get" => std::thread::sleep(Duration::from_millis(2)),
                _ => return Ok(Map::new()),
            }
        }
        Err(6)
    }
}

fn waiting_port(handler: Arc<Waits>) -> (PathBuf, Server) {
    let n = FOLDERS.fetch_add(1, Ordering::SeqCst);
    let dir = PathBuf::from(format!("/tmp/app-browser-{}-w{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bridge = Arc::new(Mutex::new(Bridge::shared("1.0", handler)));
    let path = dir.join("p.sock");
    let server = Server::start(&path, Route::Port, bridge, clock(&Arc::default())).unwrap();
    (path, server)
}

/// T59 INT-01.44: 8 requests of one session run at once; the 9th gets a
/// boxed 42 at once, and the 8 still get their replies.
#[test]
fn t59_int01_44_the_9th_request_in_flight_gets_42_while_8_wait() {
    let handler = Arc::new(Waits::default());
    let (path, server) = waiting_port(handler.clone());
    let mut wire = Wire::Port(connect(&path));
    let mut client = Client::hello(&mut wire);
    let Wire::Port(stream) = &mut wire else {
        unreachable!()
    };
    let mut nonces = Vec::new();
    for req in 1..=MAX_IN_FLIGHT + 1 {
        let nonce = client.next_nonce();
        let content = format!(r#"{{"type":"logins.get","req":{req}}}"#);
        send_frame(
            stream,
            client
                .boxed_with(&client.request, &nonce, content.as_bytes())
                .as_bytes(),
        );
        nonces.push(nonce);
    }
    let busy = parse(&read_frame(stream).unwrap());
    let opened = client.open(&busy, &nonces[MAX_IN_FLIGHT]);
    assert_eq!(
        json::to_string(&opened),
        r#"{"error":42,"req":9,"type":"logins.get"}"#
    );
    handler.release.store(true, Ordering::SeqCst);
    for _ in 0..MAX_IN_FLIGHT {
        let reply = parse(&read_frame(stream).unwrap());
        assert_eq!(reply.get("type").and_then(Value::as_str), Some("box"));
    }
    drop(server);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// T31 INT-01.20, INT-01.45: a second hello on the connection ends the
/// session; its request waiting for a dialog closes as Deny and gets no
/// reply; the new hello is answered. (The vault side's Connect dialog on
/// session end: int02 `t31_int01_45_…`.)
#[test]
fn t31_int01_45_a_new_hello_ends_the_waiting_request_without_a_reply() {
    let handler = Arc::new(Waits::default());
    let (path, server) = waiting_port(handler.clone());
    let mut wire = Wire::Port(connect(&path));
    let mut client = Client::hello(&mut wire);
    let Wire::Port(stream) = &mut wire else {
        unreachable!()
    };
    let nonce = client.next_nonce();
    let waiting = client.boxed_with(&client.request, &nonce, br#"{"type":"code.get","req":1}"#);
    send_frame(stream, waiting.as_bytes());
    std::thread::sleep(Duration::from_millis(50));
    let fresh = Secret::generate().unwrap();
    send_frame(stream, hello(&fresh.public(), "Chrome").as_bytes());
    let reply = parse(&read_frame(stream).unwrap());
    assert_eq!(reply.get("type").and_then(Value::as_str), Some("hello"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while handler.ended.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(handler.ended.load(Ordering::SeqCst), 1);
    // Nothing more comes on the connection for the old request.
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(read_frame(stream).is_none());
    drop(server);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
