//! The test client of app-server's integration tests: an in-process server
//! on 127.0.0.1:0 with a fresh data folder under the system's temp folder,
//! TLS clients that trust only its certificate, raw HTTP/1.1 requests, and
//! a device that signs in with a software P-256 key (app-crypto's
//! `P256TestKey`, tests only). Every client connects to 127.0.0.1 only;
//! nothing reaches another host.
#![allow(dead_code)]

use app_crypto::sign::P256TestKey;
use app_proto::messages::{
    AccountCreate, AccountCreated, AccountId, Challenge, ChallengeRequest, DeviceId, Session,
    SignIn,
};
use app_proto::signin;
use app_server::http::Config;
use app_server::{Server, TestSeams};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion, version};

/// A data folder, deleted on drop.
pub struct Scratch(pub PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// A server serving on this runtime.
pub struct Running {
    pub addr: SocketAddr,
    pub cert: CertificateDer<'static>,
    pub data: Scratch,
    /// The in-process server's seams; `None` for the binary.
    pub seams: Option<TestSeams>,
    /// `Authorization: Bearer <token>\r\n` of a signed-in device, or empty.
    pub auth: String,
    /// Every request [`exchange`] sent, with its reply, in order.
    pub sent: Arc<Mutex<Vec<Sent>>>,
}

/// A request's bytes and the reply they got.
pub type Sent = (Vec<u8>, Reply);

/// A fresh data folder's path; the server makes the folder.
pub fn scratch() -> Scratch {
    let mut name = [0u8; 8];
    app_crypto::random::fill(&mut name).unwrap();
    let hex: String = name.iter().map(|b| format!("{b:02x}")).collect();
    Scratch(std::env::temp_dir().join(format!("app-server-test-{hex}")))
}

/// Starts a server in this runtime with a fresh data folder; no device.
pub async fn start_bare(config: Config) -> Running {
    let data = scratch();
    let server = Server::start(&data.0, 0, config).await.unwrap();
    let addr = server.address().unwrap();
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    let cert = CertificateDer::from(server.certificate().der().to_vec());
    let seams = Some(server.test_seams());
    tokio::spawn(async move { server.serve().await.unwrap() });
    Running {
        addr,
        cert,
        data,
        seams,
        auth: String::new(),
        sent: Arc::default(),
    }
}

/// [`start_bare`], then one account whose device is signed in: its
/// `Authorization` line is in [`Running::auth`].
pub async fn start(config: Config) -> Running {
    let mut s = start_bare(config).await;
    let device = sign_up(&s).await;
    s.auth = bearer(&sign_in(&s, &device).await);
    s
}

/// A client that trusts only the server's own certificate, at one TLS
/// version.
pub fn client(
    cert: &CertificateDer<'static>,
    v: &'static SupportedProtocolVersion,
) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[v])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

pub async fn tls(s: &Running, v: &'static SupportedProtocolVersion) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
    client(&s.cert, v).connect(name, tcp).await.unwrap()
}

/// Everything the peer sends until it closes (a close without TLS's
/// close_notify counts as a close too); at most 60 s, since an upload's
/// full sync waits for the whole disk on a busy Mac.
pub async fn read_all<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut out = Vec::new();
    let read = async {
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(60), read)
        .await
        .expect("the server did not close the connection");
    out
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn parse(bytes: &[u8]) -> Self {
        let end = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap_or_else(|| panic!("no HTTP reply: {:?}", String::from_utf8_lossy(bytes)));
        let head = std::str::from_utf8(&bytes[..end]).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap();
        assert!(status.starts_with("HTTP/1.1 "), "{status}");
        let headers = lines
            .map(|l| {
                let (k, v) = l.split_once(':').unwrap();
                (k.to_ascii_lowercase(), v.trim().to_owned())
            })
            .collect();
        Self {
            status: status[9..12].parse().unwrap(),
            headers,
            body: bytes[end + 4..].to_vec(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// An App error reply: the body is the code only, never cached.
    pub fn assert_error(&self, status: u16, code: &str) {
        assert_eq!(self.status, status, "{self:?}");
        assert_eq!(self.body, format!(r#"{{"error":"{code}"}}"#).as_bytes());
        assert_eq!(self.header("content-type"), Some("application/json"));
        assert_eq!(self.header("cache-control"), Some("no-store"));
    }

    /// SYN-01.5, SYN-04.4: the one 401 reply, for every reason.
    pub fn assert_unauthorized(&self) {
        self.assert_error(401, "unauthorized");
        assert_eq!(self.header("www-authenticate"), Some("Bearer"));
    }

    /// A reply to a request head: no body (SYN-01.9).
    pub fn assert_head_reply(&self, status: u16) {
        assert_eq!(self.status, status, "{self:?}");
        assert!(self.body.is_empty(), "{self:?}");
        assert!(matches!(self.header("content-length"), None | Some("0")));
    }
}

pub async fn exchange(s: &Running, request: &[u8]) -> Reply {
    let mut stream = tls(s, &version::TLS13).await;
    stream.write_all(request).await.unwrap();
    // TLS may hold the last bytes of a large request until a flush.
    stream.flush().await.unwrap();
    let reply = Reply::parse(&read_all(&mut stream).await);
    let mut sent = s.sent.lock().unwrap();
    sent.push((request.to_vec(), reply.clone()));
    reply
}

/// A request with `extra` header lines (each ending in CRLF) and a body
/// of exactly its `Content-Length`.
pub fn request(method: &str, path: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

/// `Authorization: Bearer <token>\r\n` for a session.
pub fn bearer(session: &Session) -> String {
    let token = app_crypto::base64::encode(app_crypto::base64::Form::Url, session.token.expose());
    format!("Authorization: Bearer {token}\r\n")
}

/// A Mac of the test: its software device key and the ids the server gave.
pub struct Device {
    pub key: P256TestKey,
    pub id: DeviceId,
    pub account: AccountId,
}

/// `POST /v1/accounts` with a new key and the name "Mac": 201.
pub async fn sign_up(s: &Running) -> Device {
    let key = P256TestKey::new().unwrap();
    let record = AccountCreate {
        device_public_key: key.public().try_into().unwrap(),
        device_name: "Mac".to_owned(),
    };
    let r = exchange(s, &request("POST", "/v1/accounts", "", &record.to_json())).await;
    assert_eq!(r.status, 201, "{r:?}");
    let made = AccountCreated::read(&r.body).unwrap();
    Device {
        key,
        id: made.device_id,
        account: made.account_id,
    }
}

/// SYN-04.11's helper: another device of `account`, with a new key.
pub fn second_device(s: &Running, account: &AccountId) -> Device {
    let key = P256TestKey::new().unwrap();
    let public: [u8; 65] = key.public().try_into().unwrap();
    let seams = s.seams.as_ref().unwrap();
    let id = seams
        .add_device(account, &public, "Mac 2")
        .unwrap()
        .unwrap();
    Device {
        key,
        id,
        account: *account,
    }
}

/// `POST /v1/signin/challenge` for `device`: 200.
pub async fn challenge(s: &Running, device: &DeviceId) -> Challenge {
    let body = ChallengeRequest { device_id: *device }.to_json();
    let r = exchange(s, &request("POST", "/v1/signin/challenge", "", &body)).await;
    assert_eq!(r.status, 200, "{r:?}");
    Challenge::read(&r.body).unwrap()
}

/// The server's origin, as the client connected to it (SYN-04.4).
pub fn origin(s: &Running) -> String {
    signin::origin("127.0.0.1", s.addr.port())
}

/// The sign-in record of `device` for `nonce`, signed over `origin`.
pub fn signed(device: &Device, origin: &str, nonce: &[u8; 32]) -> SignIn {
    let message = signin::message(origin, nonce, &device.id).unwrap();
    SignIn {
        device_id: device.id,
        nonce: *nonce,
        signature: device.key.sign(&message),
    }
}

/// Sets the in-process server's clock (`TestSeams::set_clock`).
pub fn set_clock(s: &Running, seconds: u64) {
    s.seams.as_ref().unwrap().set_clock(seconds);
}

/// `POST /v1/signin` with `record`.
pub async fn post_sign_in(s: &Running, record: &SignIn) -> Reply {
    exchange(s, &request("POST", "/v1/signin", "", &record.to_json())).await
}

/// A challenge, then a sign-in signed over the server's origin: 200.
pub async fn sign_in(s: &Running, device: &Device) -> Session {
    let c = challenge(s, &device.id).await;
    let r = post_sign_in(s, &signed(device, &origin(s), &c.nonce)).await;
    assert_eq!(r.status, 200, "{r:?}");
    Session::read(&r.body).unwrap()
}
