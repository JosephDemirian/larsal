//! Tests only (the `test-server` feature; larsal-sync's own tests and
//! larsal-ffi's turn it on, never a product build): servers on 127.0.0.1 for
//! the sync tests, and a clock that moves only when told.
//!
//! - [`larsal_server`]: Larsal's own server in process on 127.0.0.1:0 with its
//!   first-start certificate, its test clock and SYN-04.11's second-device
//!   helper (LD-327 (6)).
//! - [`Scripted`]: a TLS server on 127.0.0.1:0 with its own self-signed
//!   certificate that answers each request as the test says, for the
//!   replies Larsal's server never gives (endless 412, a rolled-back
//!   version, 429). As [`Scripted::proxy`] it passes every request on to
//!   an [`LarsalServer`] and keeps each request and reply as read: the test
//!   proxy of SYN-04 T13 and SYN-03 T24.
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

use crate::sync::Clock;
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
/// first-start certificate.
pub fn larsal_server() -> LarsalServer {
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

    /// The requests read so far with this method.
    pub fn count(&self, method: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.method == method)
            .count()
    }

    /// A server whose every reply is `script`'s.
    pub fn new(script: impl Fn(&Request) -> Response + Send + Sync + 'static) -> Self {
        let script: Arc<Script> = Arc::new(script);
        Self::serve(move |request: &Request| {
            let reply = script(request).bytes();
            Ok(reply)
        })
    }

    /// The test proxy: every request goes on to `to` unchanged, over its
    /// own TLS connection that trusts only `to`'s certificate; the client
    /// pins this proxy's certificate.
    pub fn proxy(to: &LarsalServer) -> Self {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(to.der.clone())).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let port = to.port;
        Self::serve(move |request: &Request| {
            let name = ServerName::try_from("127.0.0.1").unwrap();
            let conn = ClientConnection::new(config.clone(), name).map_err(io::Error::other)?;
            let tcp = TcpStream::connect(("127.0.0.1", port))?;
            let mut tls = StreamOwned::new(conn, tcp);
            tls.write_all(&request.raw)?;
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
            let mut reply = head;
            let mut body = vec![0u8; length];
            tls.read_exact(&mut body)?;
            reply.extend_from_slice(&body);
            Ok(reply)
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
