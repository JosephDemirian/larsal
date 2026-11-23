//! The test client of larsal-server's integration tests: an in-process server
//! on 127.0.0.1:0 with a fresh data folder under the system's temp folder,
//! TLS clients that trust only its certificate, raw HTTP/1.1 requests, and
//! a device that signs in with a software P-256 key (larsal-crypto's
//! `P256TestKey`, tests only). A second device of an account joins as on a
//! release server, by approval (SYN-06.11, E17-S2): [`second_device`] runs
//! the code compare by raw HTTP with E and N both answering Codes match.
//! Every client connects to 127.0.0.1 only; nothing reaches another host.
#![allow(dead_code)]

use larsal_crypto::sign::P256TestKey;
use larsal_proto::approval::{
    self as approval, ApprovalClaim, ApprovalClaimed, ApprovalCreate, ApprovalSeal, ApprovalStart,
    ApprovalState, CompareCommit, CompareKeys,
};
use larsal_proto::messages::{
    AccountCreate, AccountCreated, AccountId, Challenge, ChallengeRequest, DeviceId, Session,
    SignIn,
};
use larsal_proto::signin;
use larsal_server::http::Config;
use larsal_server::{Server, TestSeams};
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
    larsal_crypto::random::fill(&mut name).unwrap();
    let hex: String = name.iter().map(|b| format!("{b:02x}")).collect();
    Scratch(std::env::temp_dir().join(format!("larsal-server-test-{hex}")))
}

/// Starts a server in this runtime with a fresh data folder; no device.
/// E16's tests upload with no `Upload-Signature`, so this server lets an
/// account with no keys row do that (`TestSeams::allow_unsigned`);
/// [`start_strict`] keeps a release server's rule (SYN-01.7, E17-S1).
pub async fn start_bare(config: Config) -> Running {
    let s = start_strict(config).await;
    s.seams.as_ref().unwrap().allow_unsigned(true);
    s
}

/// [`start_bare`] with a release server's rule: every vault upload is
/// signed by the account's identity key (SYN-01.7).
pub async fn start_strict(config: Config) -> Running {
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

    /// A Larsal error reply: the body is the code only, never cached.
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
    let token =
        larsal_crypto::base64::encode(larsal_crypto::base64::Form::Url, session.token.expose());
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

/// E17-S2: new account keys for `device`'s account, stored with
/// `PUT /v1/account/keys` while `device` is signed in (201); the session
/// is ended again, so the test's session rows stay as they were.
pub async fn keys_for(s: &Running, device: &Device) -> larsal_crypto::account::AccountKeys {
    let auth = bearer(&sign_in(s, device).await);
    let (keys, record) = account_keys(&device.account);
    let pre = format!("{auth}If-None-Match: *\r\n");
    let r = exchange(
        s,
        &request("PUT", "/v1/account/keys", &pre, &record.to_json()),
    )
    .await;
    assert_eq!(r.status, 201, "{r:?}");
    sign_out(s, &auth).await;
    keys
}

/// `POST /v1/signout` with the `Authorization` line `auth`: 204.
pub async fn sign_out(s: &Running, auth: &str) {
    let r = exchange(s, &request("POST", "/v1/signout", auth, b"")).await;
    assert_eq!(r.status, 204, "{r:?}");
}

/// The `Authorization` line of N's approval routes for `code`.
pub fn approval_line(code: &larsal_crypto::secret::SecretBytes) -> String {
    format!(
        "Authorization: {}\r\n",
        approval::authorization(code).expose()
    )
}

/// SYN-06.11 by raw HTTP, in place of SYN-04.11's helper (E17-S2's ruling
/// (7)): `approver` (E, of the account whose keys are `keys`) adds a new
/// device N with a new key named "Mac 2". E makes the request with the
/// code's SHA-256; N claims it and commits (SYN-05's message (1)); E sends
/// `K_R` and `n_R`; N reveals `K_C` and `n_C`; both compute one code and
/// answer Codes match; E seals `S_acct` to N's one-request X-Wing key and
/// signs N's device; N reads the seal and its device id, and opens the seal
/// with the info it builds itself, checked against the identity key it
/// compared. Every step's reply is checked; E's session is ended at the
/// end, and N has none, so the test's session rows stay as they were.
pub async fn second_device(
    s: &Running,
    approver: &Device,
    keys: &larsal_crypto::account::AccountKeys,
) -> Device {
    second_device_with(s, approver, keys, &|_| {}).await
}

/// [`second_device`], calling `after` with each step's name ("create",
/// "claim", "commit", "keys", "reveal", "seal", "taken") once its reply
/// is in, so a test can read the store between the steps.
pub async fn second_device_with(
    s: &Running,
    approver: &Device,
    keys: &larsal_crypto::account::AccountKeys,
    after: &dyn Fn(&'static str),
) -> Device {
    let e = bearer(&sign_in(s, approver).await);
    let account = approver.account;
    let post = async |path: String, auth: &str, body: Vec<u8>| {
        exchange(s, &request("POST", &path, auth, &body)).await
    };
    // Step 1.
    let code = larsal_crypto::random::bytes(approval::CODE_BYTES).unwrap();
    let create = ApprovalCreate {
        code_hash: approval::code_hash(&code).unwrap(),
    };
    let r = post("/v1/approvals".to_owned(), &e, create.to_json()).await;
    assert_eq!(r.status, 201, "{r:?}");
    let start = ApprovalStart::read(&r.body).unwrap();
    after("create");
    // Step 2.
    let n = approval_line(&code);
    let key = P256TestKey::new().unwrap();
    let device: [u8; 65] = key.public().try_into().unwrap();
    let claim = ApprovalClaim {
        device_public_key: device,
        device_name: "Mac 2".to_owned(),
    };
    let r = post("/v1/approvals/claim".to_owned(), &n, claim.to_json()).await;
    assert_eq!(r.status, 201, "{r:?}");
    let claimed = ApprovalClaimed::read(&r.body).unwrap();
    assert_eq!(
        (claimed.approval_id, claimed.account_id),
        (start.approval_id, account)
    );
    after("claim");
    let id = claimed.approval_id;
    let ctx = approval::ctx(&account, &id).unwrap();
    let (seed, xwing) = larsal_crypto::pq::xwing_keypair().unwrap();
    let keys_c = approval::keys_c(&device, &xwing).unwrap();
    let n_c: [u8; 32] = larsal_crypto::random::bytes(32)
        .unwrap()
        .expose()
        .try_into()
        .unwrap();
    let commit = approval::commitment(&ctx, &keys_c, &n_c).unwrap();
    let commit = CompareCommit {
        commit: commit.expose().try_into().unwrap(),
    };
    let r = post(format!("/v1/approvals/{id}/commit"), &n, commit.to_json()).await;
    assert_eq!(r.status, 204, "{r:?}");
    after("commit");
    // Step 3.
    let r = exchange(s, &request("GET", &format!("/v1/approvals/{id}"), &e, b"")).await;
    assert_eq!(r.status, 200, "{r:?}");
    let seen = ApprovalState::read(&r.body).unwrap();
    assert_eq!(seen.device_public_key, Some(device));
    assert_eq!(seen.commit, Some(commit.commit));
    let mine: [u8; 65] = approver.key.public().try_into().unwrap();
    let keys_r = approval::keys_r(keys.identity_public_key(), &mine).unwrap();
    let n_r: [u8; 32] = larsal_crypto::random::bytes(32)
        .unwrap()
        .expose()
        .try_into()
        .unwrap();
    let message = CompareKeys {
        keys: keys_r.clone(),
        nonce: n_r,
    };
    let r = post(format!("/v1/approvals/{id}/keys"), &e, message.to_json()).await;
    assert_eq!(r.status, 204, "{r:?}");
    after("keys");
    // Step 4.
    let r = exchange(s, &request("GET", &format!("/v1/approvals/{id}"), &n, b"")).await;
    assert_eq!(r.status, 200, "{r:?}");
    let seen = ApprovalState::read(&r.body).unwrap();
    assert_eq!(seen.keys_r, Some((keys_r.clone(), n_r)));
    let reveal = CompareKeys {
        keys: keys_c.clone(),
        nonce: n_c,
    };
    let r = post(format!("/v1/approvals/{id}/reveal"), &n, reveal.to_json()).await;
    assert_eq!(r.status, 204, "{r:?}");
    after("reveal");
    // E checks the reveal against the commitment; both codes agree.
    let r = exchange(s, &request("GET", &format!("/v1/approvals/{id}"), &e, b"")).await;
    let seen = ApprovalState::read(&r.body).unwrap();
    let (k, nonce) = seen.keys_c.unwrap();
    let again = approval::commitment(&ctx, &k, &nonce).unwrap();
    assert!(larsal_crypto::secret::ct_eq(again.expose(), &commit.commit));
    let on_e = approval::code(&ctx, &keys_r, &k, &n_r, &nonce).unwrap();
    let on_n = approval::code(&ctx, &keys_r, &keys_c, &n_r, &n_c).unwrap();
    assert_eq!(on_e, on_n, "Codes match");
    // Step 5.
    let info = approval::seal_info(&account, &id, &device).unwrap();
    let seal = larsal_crypto::wrap_record::make(
        &xwing,
        &info,
        keys.account_secret().expose(),
        *account.as_bytes(),
        keys.identity_private_key(),
    )
    .unwrap();
    let message = approval::device_message(&account, &device, &id).unwrap();
    let device_signature =
        larsal_crypto::pq::composite_sign(keys.identity_private_key(), &message).unwrap();
    let body = ApprovalSeal {
        seal,
        device_signature,
    };
    let r = post(format!("/v1/approvals/{id}/seal"), &e, body.to_json()).await;
    assert_eq!(r.status, 204, "{r:?}");
    after("seal");
    // Step 6.
    let r = exchange(s, &request("GET", &format!("/v1/approvals/{id}"), &n, b"")).await;
    assert_eq!(r.status, 200, "{r:?}");
    let (sealed, device_id) = ApprovalState::read(&r.body).unwrap().seal.unwrap();
    let record = larsal_proto::wrap::read(&sealed).unwrap();
    let opened =
        larsal_crypto::wrap_record::open(&record, keys.identity_public_key(), &info, &seed)
            .unwrap();
    assert!(larsal_crypto::secret::ct_eq(
        opened.expose(),
        keys.account_secret().expose()
    ));
    after("taken");
    sign_out(s, &e).await;
    Device {
        key,
        id: device_id,
        account,
    }
}

/// E17-S1: a new account's keys, drawn with larsal-crypto, and the record
/// of `PUT /v1/account/keys` for `account`: the public keys, the binding,
/// the recovery public key derived as SYN-06.5 says, and 158 demo bytes for
/// the blob, which the server never reads (P6).
pub fn account_keys(
    account: &AccountId,
) -> (
    larsal_crypto::account::AccountKeys,
    larsal_proto::account::AccountKeys,
) {
    let keys = larsal_crypto::account::AccountKeys::new().unwrap();
    let record = larsal_proto::account::AccountKeys {
        identity_public_key: keys.identity_public_key().to_vec(),
        kem_public_key: keys.kem_public_key().to_vec(),
        kem_signature: keys.kem_signature(account.as_bytes()).unwrap(),
        recovery_public_key: larsal_crypto::sign::ed25519_public(&recovery_seed(&keys, account))
            .unwrap(),
        blob: vec![0xb1; 158],
    };
    (keys, record)
}

/// SYN-06.5: the recovery key's seed of `keys` for `account`.
pub fn recovery_seed(
    keys: &larsal_crypto::account::AccountKeys,
    account: &AccountId,
) -> larsal_crypto::secret::SecretBytes {
    larsal_crypto::wrap::hkdf_sha256(
        account.as_bytes(),
        keys.account_secret(),
        b"sync-recovery-key-v1",
    )
    .unwrap()
}

/// `PUT /v1/account/keys` with `If-None-Match: *` and `record`.
pub async fn put_keys(s: &Running, record: &larsal_proto::account::AccountKeys) -> Reply {
    let pre = format!("{}If-None-Match: *\r\n", s.auth);
    exchange(
        s,
        &request("PUT", "/v1/account/keys", &pre, &record.to_json()),
    )
    .await
}

/// SYN-01.7: the `Upload-Signature` line (with its CRLF) of `body` as
/// version `version` of `vault`, signed by `keys`' identity key.
pub fn upload_header(
    keys: &larsal_crypto::account::AccountKeys,
    vault: &larsal_proto::messages::VaultId,
    version: u64,
    body: &[u8],
) -> String {
    let sha: [u8; 32] = larsal_crypto::hash::sha256(&[body])
        .expose()
        .try_into()
        .unwrap();
    let message = larsal_proto::account::upload_message(vault, version, &sha).unwrap();
    let signature =
        larsal_crypto::pq::composite_sign(keys.identity_private_key(), &message).unwrap();
    let text = larsal_crypto::base64::encode(larsal_crypto::base64::Form::Url, &signature);
    format!("Upload-Signature: {text}\r\n")
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
