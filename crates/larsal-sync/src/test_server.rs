//! Tests only (the `test-server` feature; larsal-sync's own tests and
//! larsal-ffi's turn it on, never a product build): servers on 127.0.0.1 for
//! the sync tests, and a clock that moves only when told.
//!
//! - [`larsal_server`]: Larsal's own server in process on 127.0.0.1:0 with its
//!   first-start certificate and its test clock (LD-327 (6)). It lets an
//!   account with no keys row upload unsigned, as E16's callers do
//!   (`TestSeams::allow_unsigned`); [`larsal_server_strict`] keeps a release
//!   server's rule (E17-S1). No seam writes a device row (E17-S2): a second
//!   device comes only through the approval ([`approve`], SYN-06.11) or the
//!   Recovery Kit.
//! - [`Memory`]: the device store of `account.rs` as a map, never a
//!   keychain (LD-317 (2)).
//! - [`Scripted`]: a TLS server on 127.0.0.1:0 with its own self-signed
//!   certificate that answers each request as the test says, for the
//!   replies Larsal's server never gives (endless 412, a rolled-back
//!   version, 429); it answers `GET /v1/account/keys` with 404 unless the
//!   script says otherwise, as an account of E16 without keys. As
//!   [`Scripted::proxy`] it passes every request on to an [`LarsalServer`]
//!   and keeps each request and reply as read: the test proxy of SYN-04 T13
//!   and SYN-03 T24. As [`Scripted::relay`] it may change a request's or a
//!   reply's body on the way: the relay in the middle of SYN-05 T03 and T04
//!   and SYN-06 T10 (E17-S2).
//! - [`approve`]: SYN-06.11 between two clients, both users choosing Codes
//!   match after comparing the codes (E17-S2).
//!
//! Every socket is on 127.0.0.1; nothing reaches another host.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::account::{AccountFail, Keep};
use crate::approval::{NSealed, Polled};
use crate::client::{Server, Signer};
use crate::sync::Clock;
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_proto::messages::DeviceId;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A clock that moves only when told or slept on; it keeps every wait.
#[derive(Debug, Default)]
pub struct TestClock {
    now: AtomicU64,
    pub waits: Mutex<Vec<u64>>,
}

impl TestClock {
    pub fn at(ms: u64) -> Arc<Self> {
        let c = Arc::new(Self::default());
        c.now.store(ms, Ordering::SeqCst);
        c
    }

    pub fn advance(&self, ms: u64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn waits(&self) -> Vec<u64> {
        self.waits.lock().unwrap().clone()
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn sleep_ms(&self, ms: u64) {
        self.waits.lock().unwrap().push(ms);
        self.advance(ms);
    }
}

/// A data folder, deleted on drop.
pub struct Scratch(pub PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A fresh folder name under the system's temp folder.
pub fn scratch(tag: &str) -> Scratch {
    let mut name = [0u8; 8];
    larsal_crypto::random::fill(&mut name).unwrap();
    let hex: String = name.iter().map(|b| format!("{b:02x}")).collect();
    Scratch(std::env::temp_dir().join(format!("larsal-sync-{tag}-{hex}")))
}

/// Larsal's server, serving on its own thread until the test process ends.
pub struct LarsalServer {
    pub port: u16,
    pub der: Vec<u8>,
    pub pin: [u8; 32],
    pub seams: larsal_server::TestSeams,
    pub _data: Scratch,
}

impl LarsalServer {
    pub fn address(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }
}

/// Starts larsal-server on 127.0.0.1:0 with a fresh data folder and its
/// first-start certificate; an account with no keys row may upload with no
/// signature (E16's tests, which make no account keys).
pub fn larsal_server() -> LarsalServer {
    let s = larsal_server_strict();
    s.seams.allow_unsigned(true);
    s
}

/// [`larsal_server`] with a release server's rule: every vault upload is
/// signed by the account's identity key (SYN-01.7, E17-S1).
pub fn larsal_server_strict() -> LarsalServer {
    let data = scratch("server");
    let root = data.0.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let config = larsal_server::http::Config::default();
            let server = larsal_server::Server::start(&root, 0, config)
                .await
                .unwrap();
            let cert = server.certificate();
            let started = (
                server.address().unwrap().port(),
                cert.der().to_vec(),
                server.test_seams(),
            );
            tx.send(started).unwrap();
            server.serve().await.unwrap();
        });
    });
    let (port, der, seams) = rx.recv_timeout(Duration::from_secs(30)).unwrap();
    let pin = sha256(&der);
    LarsalServer {
        port,
        der,
        pin,
        seams,
        _data: data,
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    crate::sync::hash(bytes)
}

/// `account.rs`'s device store as a map (LD-317 (2)): every value is a
/// `SecretBytes`, wiped on drop.
#[derive(Default)]
pub struct Memory(pub Mutex<std::collections::BTreeMap<String, SecretBytes>>);

impl Keep for Memory {
    fn put(&self, label: &str, secret: &SecretBytes) -> Result<(), AccountFail> {
        let copy = SecretBytes::new(secret.expose().to_vec());
        self.0.lock().unwrap().insert(label.to_owned(), copy);
        Ok(())
    }

    fn get(&self, label: &str) -> Option<SecretBytes> {
        let map = self.0.lock().unwrap();
        map.get(label)
            .map(|s| SecretBytes::new(s.expose().to_vec()))
    }
}

/// One request as the server read it.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The bytes as they came: head and body.
    pub raw: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// One reply a script gives.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} X\r\n", self.status).into_bytes();
        for (n, v) in &self.headers {
            out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
        }
        if self.status != 304 && self.status != 204 {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// Every request read, in order, with the raw reply sent.
pub type Seen = Arc<Mutex<Vec<(Request, Vec<u8>)>>>;

type Script = dyn Fn(&Request) -> Response + Send + Sync;

/// A scripted server on 127.0.0.1:0 with its own self-signed certificate.
pub struct Scripted {
    pub port: u16,
    pub pin: [u8; 32],
    /// Every request read, in order, with the raw reply sent.
    pub seen: Seen,
}

impl Scripted {
    pub fn address(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    /// The requests read so far.
    pub fn requests(&self) -> Vec<Request> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(r, _)| r.clone())
            .collect()
    }

    /// The requests read so far with this method, but for the account
    /// routes of E17: `PUT /v1/account/keys` (SYN-06.1) and
    /// `PUT …/keypart` (SYN-06.9). E16's counts are of the vault uploads,
    /// and since E17-S2 larsal-ffi's test Macs get account keys at sign-up
    /// and pass a vault's part through the server.
    pub fn count(&self, method: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| {
                r.method == method && r.path != "/v1/account/keys" && !r.path.ends_with("/keypart")
            })
            .count()
    }

    /// A server whose every reply is `script`'s, except `GET
    /// /v1/account/keys`, which is 404 (an account without keys, as E16's;
    /// E17-S2's fail-closed download asks for it).
    pub fn new(script: impl Fn(&Request) -> Response + Send + Sync + 'static) -> Self {
        let script: Arc<Script> = Arc::new(script);
        Self::serve(move |request: &Request| {
            if request.method == "GET" && request.path == "/v1/account/keys" {
                return Ok(Response::new(404, br#"{"error":"not_found"}"#).bytes());
            }
            let reply = script(request).bytes();
            Ok(reply)
        })
    }

    /// The test proxy: every request goes on to `to` unchanged, over its
    /// own TLS connection that trusts only `to`'s certificate; the client
    /// pins this proxy's certificate.
    pub fn proxy(to: &LarsalServer) -> Self {
        Self::proxy_with(to, |_| None)
    }

    /// [`Scripted::proxy`], except that a request `answer` answers gets
    /// that reply and does not reach `to` (a server that lies, E17-S1).
    pub fn proxy_with(
        to: &LarsalServer,
        answer: impl Fn(&Request) -> Option<Response> + Send + Sync + 'static,
    ) -> Self {
        let config = trusting(to);
        let port = to.port;
        Self::serve(move |request: &Request| {
            if let Some(reply) = answer(request) {
                return Ok(reply.bytes());
            }
            let (head, body) = forward(&config, port, &request.raw)?;
            let mut reply = head;
            reply.extend_from_slice(&body);
            Ok(reply)
        })
    }

    /// E17-S2: a relay in the middle. `request` may give a request a new
    /// body before it goes on to `to`; `reply` may give the reply a new body
    /// before the client reads it (status and other fields as `to` sent
    /// them). Each request and reply is kept as the client sent and read it.
    pub fn relay(
        to: &LarsalServer,
        request: impl Fn(&Request) -> Option<Vec<u8>> + Send + Sync + 'static,
        reply: impl Fn(&Request, &[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        let config = trusting(to);
        let port = to.port;
        Self::serve(move |q: &Request| {
            let raw = match request(q) {
                Some(body) => with_body(&q.raw[..q.raw.len() - q.body.len()], &body),
                None => q.raw.clone(),
            };
            let (head, body) = forward(&config, port, &raw)?;
            Ok(match reply(q, &body) {
                Some(body) => with_body(&head, &body),
                None => {
                    let mut out = head;
                    out.extend_from_slice(&body);
                    out
                }
            })
        })
    }

    fn serve(answer: impl Fn(&Request) -> io::Result<Vec<u8>> + Send + Sync + 'static) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Larsal test server");
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().clone();
        let pin = sha256(&der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![der], key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let answer = Arc::new(answer);
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let (config, log, answer) = (config.clone(), log.clone(), answer.clone());
                thread::spawn(move || {
                    let Ok(conn) = ServerConnection::new(config) else {
                        return;
                    };
                    let mut s = StreamOwned::new(conn, tcp);
                    // A closed connection or a refused handshake ends it.
                    while let Ok(request) = read_request(&mut s) {
                        let Ok(reply) = answer(&request) else {
                            return;
                        };
                        log.lock().unwrap().push((request, reply.clone()));
                        if s.write_all(&reply).and_then(|()| s.flush()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { port, pin, seen }
    }
}

/// A TLS client that trusts only `to`'s certificate.
fn trusting(to: &LarsalServer) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(to.der.clone())).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Sends `raw` to 127.0.0.1:`port` over a new TLS connection: the reply's
/// head and body.
fn forward(config: &Arc<ClientConfig>, port: u16, raw: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let conn = ClientConnection::new(config.clone(), name).map_err(io::Error::other)?;
    let tcp = TcpStream::connect(("127.0.0.1", port))?;
    let mut tls = StreamOwned::new(conn, tcp);
    tls.write_all(raw)?;
    tls.flush()?;
    let (head, _) = read_head(&mut tls)?;
    let text = String::from_utf8_lossy(&head).into_owned();
    let status: u16 = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let length = if status == 304 || status == 204 {
        0
    } else {
        content_length(&text)
    };
    let mut body = vec![0u8; length];
    tls.read_exact(&mut body)?;
    Ok((head, body))
}

/// `head` (a request's or a reply's, ending in an empty line) with its
/// `Content-Length` set for `body`, then `body`.
fn with_body(head: &[u8], body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(head).into_owned();
    let mut out = String::new();
    for line in text.trim_end_matches("\r\n").split("\r\n") {
        if !line.to_ascii_lowercase().starts_with("content-length:") {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

/// SYN-06.11 between `e` (holding the account's keys) and `n` (a client of
/// the same server with no device): N claims with the code E shows for
/// the device `key`, both poll until the codes are in, the codes are
/// compared (they must be equal), both users choose Codes match, E seals,
/// and N opens the seal. N's device is `n`'s from then on; N has not yet
/// read the account keys.
pub fn approve_to_seal<K1: Signer, K2: Signer>(
    e: &mut Server<K1>,
    n: &mut Server<K2>,
    key: K2,
    clock: &dyn Clock,
) -> Result<NSealed, AccountFail> {
    let approver = e.approval_start(clock)?;
    let typed = approver.code();
    let claimant = n.approval_claim(&typed, key, clock)?;
    drop(typed);
    // E answers the commitment; N reveals; E checks the reveal.
    let Polled::Waiting(approver) = approver.poll(e, clock)? else {
        panic!("E had a code before N revealed");
    };
    let Polled::Ready(n_compared) = claimant.poll(n, clock)? else {
        panic!("N saw no message (2)");
    };
    let Polled::Ready(e_compared) = approver.poll(e, clock)? else {
        panic!("E saw no reveal");
    };
    assert_eq!(
        e_compared.code(),
        n_compared.code(),
        "both screens show one code"
    );
    e_compared.codes_match().seal(e, clock)?;
    match n_compared.codes_match().poll(n, clock)? {
        Polled::Ready(sealed) => Ok(sealed),
        Polled::Waiting(_) => panic!("N saw no seal"),
    }
}

/// [`approve_to_seal`], then N's last step with `password` and `keep`
/// (SYN-06.11 step 6): N's device id.
pub fn approve<K1: Signer, K2: Signer>(
    e: &mut Server<K1>,
    n: &mut Server<K2>,
    key: K2,
    clock: &dyn Clock,
    password: &SecretString,
    keep: &dyn Keep,
) -> Result<DeviceId, AccountFail> {
    let sealed = approve_to_seal(e, n, key, clock)?;
    sealed.finish(n, password, keep)?;
    Ok(sealed.device_id())
}

fn read_head(s: &mut impl Read) -> io::Result<(Vec<u8>, ())> {
    let mut head = Vec::new();
    let mut byte = [0u8];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        head.push(byte[0]);
        if head.len() > 64 * 1024 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok((head, ()))
}

fn content_length(head: &str) -> usize {
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0)
}

fn read_request(s: &mut impl Read) -> io::Result<Request> {
    let (head, ()) = read_head(s)?;
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_owned();
    let path = first.next().unwrap_or("").to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let mut body = vec![0u8; content_length(&text)];
    s.read_exact(&mut body)?;
    let mut raw = head;
    raw.extend_from_slice(&body);
    Ok(Request {
        method,
        path,
        headers,
        body,
        raw,
    })
}
