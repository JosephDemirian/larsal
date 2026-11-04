//! E6-S7 checks against tiny servers on 127.0.0.1 only: never the internet.
//!
//! Fixtures: the certificates are made fresh by every run with rcgen (so no
//! file can expire): a test root "Larsal test root", leaves it signs for
//! 127.0.0.1 (good, from last year to next year: under Apple's 825-day limit),
//! for 127.0.0.1 but valid only in 2020 (expired), for
//! `other.example` (wrong host), a leaf signed through an intermediate it
//! signs (good chain), a leaf from a second root the client does not know
//! (unknown issuer), and a self-signed leaf for 127.0.0.1. All are ECDSA
//! P-256 with SHA-256, the leaves with the serverAuth key purpose.
//! The root reaches the client only in memory, as the only anchor of its own
//! trust evaluations (`Client::with_anchors`, `SecTrustSetAnchorCertificates`
//! in macos/trust.rs, LD-247 (2)): no keychain is touched. The certificates
//! hold no address to fetch from, so the trust evaluation has nothing to look
//! up online.

use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, date_time_ymd,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MIB: u64 = 1024 * 1024;

fn year() -> i32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    1970 + i32::try_from(secs / 31_556_952).unwrap()
}

fn params(name: &str, years: (i32, i32)) -> CertificateParams {
    let mut p = CertificateParams::new(vec![name.to_owned()]).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.not_before = date_time_ymd(years.0, 1, 1);
    p.not_after = date_time_ymd(years.1, 1, 1);
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p
}

/// A TLS server config that sends `chain` (its leaf first).
fn server(chain: Vec<CertificateDer<'static>>, key: &KeyPair) -> Arc<ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    Arc::new(config)
}

fn ca(name: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = date_time_ymd(year() - 1, 1, 1);
    p.not_after = date_time_ymd(year() + 2, 1, 1);
    p
}

struct Pki {
    root: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let p = ca("Larsal test root");
        let key = KeyPair::generate().unwrap();
        let root = p.self_signed(&key).unwrap().der().clone();
        Self {
            root,
            issuer: Issuer::new(p, key),
        }
    }

    /// A TLS server config with a leaf for `name` signed by the test root.
    fn leaf(&self, name: &str, years: (i32, i32)) -> Arc<ServerConfig> {
        let key = KeyPair::generate().unwrap();
        let cert = params(name, years).signed_by(&key, &self.issuer).unwrap();
        server(vec![cert.der().clone()], &key)
    }

    /// A TLS server config that sends a leaf for 127.0.0.1 and the
    /// intermediate that signed it; the test root signed the intermediate.
    fn chain(&self) -> Arc<ServerConfig> {
        let p = ca("Larsal test intermediate");
        let mid_key = KeyPair::generate().unwrap();
        let mid = p.signed_by(&mid_key, &self.issuer).unwrap().der().clone();
        let mid = (mid, Issuer::new(p, mid_key));
        let key = KeyPair::generate().unwrap();
        let leaf = params("127.0.0.1", now_years())
            .signed_by(&key, &mid.1)
            .unwrap();
        server(vec![leaf.der().clone(), mid.0], &key)
    }

    fn client(&self, timeouts: Timeouts) -> Client {
        Client::with_anchors(timeouts, vec![self.root.clone()]).unwrap()
    }
}

fn now_years() -> (i32, i32) {
    (year() - 1, year() + 1)
}

fn self_signed() -> Arc<ServerConfig> {
    let key = KeyPair::generate().unwrap();
    let cert = params("127.0.0.1", now_years()).self_signed(&key).unwrap();
    server(vec![cert.der().clone()], &key)
}

type Answer = dyn Fn(&str, &mut dyn Write) + Send;

/// A server on 127.0.0.1 (TLS when `tls` is set). For every request it sends
/// the request head to the test and lets `answer` write the reply. Its thread
/// ends with the test process.
fn serve(tls: Option<Arc<ServerConfig>>, answer: Box<Answer>) -> (u16, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            // A refused handshake or a closed connection ends that connection only.
            let _ = match &tls {
                Some(config) => ServerConnection::new(config.clone())
                    .map_err(io::Error::other)
                    .and_then(|c| exchange(StreamOwned::new(c, tcp), &*answer, &tx)),
                None => exchange(tcp, &*answer, &tx),
            };
        }
    });
    (port, rx)
}

fn exchange(
    mut s: impl Read + Write,
    answer: &Answer,
    tx: &mpsc::Sender<String>,
) -> io::Result<()> {
    loop {
        let mut head = Vec::new();
        let mut byte = [0u8];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read(&mut byte)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let _ = tx.send(head.clone());
        answer(&head, &mut s);
        s.flush()?;
    }
}

fn ok(body: &'static [u8]) -> Box<Answer> {
    Box::new(move |_, w| {
        let _ = write!(
            w,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = w.write_all(body);
    })
}

fn quick() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(5),
        read: Duration::from_secs(5),
        total: Duration::from_secs(10),
    }
}

fn nothing_received(rx: &Receiver<String>) -> bool {
    rx.recv_timeout(Duration::from_millis(200)).is_err()
}

#[test]
fn sn03_good_certificate_from_test_anchor_works() {
    let pki = Pki::new();
    let (port, rx) = serve(
        Some(pki.leaf("127.0.0.1", now_years())),
        ok(b"0018A45C4D1DEF81644B54AB7F969B88D65:1"),
    );
    let body = pki
        .client(quick())
        .get(
            &format!("https://127.0.0.1:{port}/range/5BAA6"),
            &[("Add-Padding", "true")],
            MIB,
        )
        .unwrap();
    assert_eq!(body, b"0018A45C4D1DEF81644B54AB7F969B88D65:1");
    let head = rx.recv().unwrap().to_ascii_lowercase();
    assert!(head.starts_with("get /range/5baa6 http/1.1\r\n"), "{head}");
    assert!(head.contains("\r\nuser-agent: larsal\r\n"), "{head}");
    assert!(head.contains("\r\nadd-padding: true\r\n"), "{head}");
    for banned in [
        "cookie:",
        "referer:",
        "accept-language:",
        "accept-encoding:",
        "authorization:",
    ] {
        assert!(!head.contains(banned), "{banned} in {head}");
    }
}

/// LD-247 (2): the server sends its leaf and an intermediate; Larsal's
/// verifier hands both to macOS, which builds the chain to the test anchor.
#[test]
fn ld247_good_chain_through_an_intermediate_works() {
    let pki = Pki::new();
    let (port, rx) = serve(Some(pki.chain()), ok(b"chain"));
    let body = pki
        .client(quick())
        .get(&format!("https://127.0.0.1:{port}/"), &[], MIB)
        .unwrap();
    assert_eq!(body, b"chain");
    assert!(rx.recv().unwrap().starts_with("GET / "));
}

#[test]
fn sn03_bad_certificates_refused() {
    let pki = Pki::new();
    let cases = [
        ("self-signed", self_signed(), "not issued by an authority"),
        (
            "unknown issuer",
            Pki::new().leaf("127.0.0.1", now_years()),
            "not issued by an authority",
        ),
        (
            "expired",
            pki.leaf("127.0.0.1", (2020, 2021)),
            "check this Mac's date and time",
        ),
        (
            "wrong host",
            pki.leaf("other.example", now_years()),
            "different site",
        ),
    ];
    for (case, tls, words) in cases {
        let (port, rx) = serve(Some(tls), ok(b"no"));
        let err = pki
            .client(quick())
            .get(&format!("https://127.0.0.1:{port}/"), &[], MIB)
            .unwrap_err();
        println!("{case}: {err}");
        assert!(matches!(err, NetError::Certificate(_)), "{case}: {err:?}");
        assert!(err.to_string().contains(words), "{case}: {err}");
        assert!(nothing_received(&rx), "{case}: a request was sent");
    }
    // The product client has no test anchor: the good leaf is refused too.
    let (port, rx) = serve(Some(pki.leaf("127.0.0.1", now_years())), ok(b"no"));
    let err = Client::new(quick())
        .unwrap()
        .get(&format!("https://127.0.0.1:{port}/"), &[], MIB)
        .unwrap_err();
    println!("no anchor: {err}");
    assert!(matches!(err, NetError::Certificate(_)), "{err:?}");
    assert!(nothing_received(&rx));
}

/// Hands out the good 127.0.0.1 leaf with a signing key that is not its own.
#[derive(Debug)]
struct WrongKey(Arc<CertifiedKey>);

impl ResolvesServerCert for WrongKey {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// LD-247 (2): a server that replays a good chain without its private key
/// signs the handshake with another key; rustls's handshake signature check
/// refuses it in TLS 1.3 and in TLS 1.2, before any request is sent.
#[test]
fn ld247_handshake_signed_with_another_key_refused() {
    let pki = Pki::new();
    let leaf = params("127.0.0.1", now_years())
        .signed_by(&KeyPair::generate().unwrap(), &pki.issuer)
        .unwrap();
    let other = KeyPair::generate().unwrap().serialize_der();
    let other = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(other));
    let signer = rustls::crypto::ring::sign::any_supported_type(&other).unwrap();
    let wrong = Arc::new(WrongKey(Arc::new(CertifiedKey::new(
        vec![leaf.der().clone()],
        signer,
    ))));
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(wrong.clone());
        let (port, rx) = serve(Some(Arc::new(config)), ok(b"no"));
        let err = pki
            .client(quick())
            .get(&format!("https://127.0.0.1:{port}/"), &[], MIB)
            .unwrap_err();
        let case = version.version;
        println!("{case:?}: {err}");
        assert!(matches!(err, NetError::Certificate(_)), "{case:?}: {err:?}");
        assert!(err.to_string().contains("key"), "{case:?}: {err}");
        assert!(nothing_received(&rx), "{case:?}: a request was sent");
    }
}

#[test]
fn sn03_http_only_for_icons() {
    let (port, rx) = serve(None, ok(b"icon"));
    let client = Client::new(quick()).unwrap();
    let url = format!("http://127.0.0.1:{port}/favicon.ico");
    assert!(matches!(client.get(&url, &[], MIB), Err(NetError::Url)));
    assert!(nothing_received(&rx), "plain http sent outside icons");
    assert_eq!(client.get_icon(&url, MIB).unwrap(), b"icon");
    assert!(
        rx.recv()
            .unwrap()
            .starts_with("GET /favicon.ico HTTP/1.1\r\n")
    );
    // LD-64: never a user name or password; no other scheme.
    for bad in [
        format!("http://demo:demo-pw@127.0.0.1:{port}/favicon.ico"),
        format!("ftp://127.0.0.1:{port}/favicon.ico"),
        "/favicon.ico".to_owned(),
        "not a url".to_owned(),
    ] {
        assert!(
            matches!(client.get_icon(&bad, MIB), Err(NetError::Url)),
            "{bad}"
        );
    }
    assert!(nothing_received(&rx));
}

#[test]
fn timeouts_fire() {
    let pki = Pki::new();
    // Connect: the server takes the TCP connection and never says a word, so
    // the TLS handshake waits.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    thread::spawn(move || {
        let held: Vec<_> = silent.incoming().take(1).collect();
        thread::sleep(Duration::from_secs(30));
        drop(held);
    });
    let short = |connect, read, total| Timeouts {
        connect: Duration::from_millis(connect),
        read: Duration::from_millis(read),
        total: Duration::from_millis(total),
    };
    let cases: [(&str, u16, Timeouts); 3] = [
        ("connect", port, short(300, 5_000, 10_000)),
        (
            "read",
            serve(
                Some(pki.leaf("127.0.0.1", now_years())),
                Box::new(|_, _| thread::sleep(Duration::from_secs(3))),
            )
            .0,
            short(5_000, 300, 10_000),
        ),
        (
            "total",
            serve(
                Some(pki.leaf("127.0.0.1", now_years())),
                Box::new(|_, w| {
                    let _ = w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n");
                    for _ in 0..30 {
                        let _ = w.write_all(b"x");
                        let _ = w.flush();
                        thread::sleep(Duration::from_millis(100));
                    }
                }),
            )
            .0,
            short(5_000, 1_000, 600),
        ),
    ];
    for (case, port, timeouts) in cases {
        let start = Instant::now();
        let err = pki
            .client(timeouts)
            .get(&format!("https://127.0.0.1:{port}/"), &[], MIB)
            .unwrap_err();
        let took = start.elapsed();
        println!("{case}: {err} after {took:?}");
        assert!(matches!(err, NetError::Timeout), "{case}: {err:?}");
        assert!(took < Duration::from_millis(1_500), "{case}: {took:?}");
    }
}

#[test]
fn size_limit_stops_big_body() {
    let pki = Pki::new();
    let answer: Box<Answer> = Box::new(|head, w| {
        let len = if head.starts_with("GET /big ") {
            MIB + 1
        } else {
            MIB
        };
        let _ = write!(w, "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n");
        let _ = w.write_all(&vec![b'0'; usize::try_from(len).unwrap()]);
    });
    let (port, _rx) = serve(Some(pki.leaf("127.0.0.1", now_years())), answer);
    let client = pki.client(quick());
    let at_limit = client.get(&format!("https://127.0.0.1:{port}/fits"), &[], MIB);
    assert_eq!(at_limit.unwrap().len(), 1024 * 1024);
    let over = client.get(&format!("https://127.0.0.1:{port}/big"), &[], MIB);
    assert!(matches!(over, Err(NetError::TooLarge)), "{over:?}");
}

#[test]
fn no_cookie_kept_or_sent() {
    let pki = Pki::new();
    let answer: Box<Answer> = Box::new(|_, w| {
        let _ = w.write_all(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: session=demo-cookie; Path=/\r\nContent-Length: 2\r\n\r\nok",
        );
    });
    let (port, rx) = serve(Some(pki.leaf("127.0.0.1", now_years())), answer);
    let client = pki.client(quick());
    for _ in 0..2 {
        client
            .get(&format!("https://127.0.0.1:{port}/"), &[], MIB)
            .unwrap();
        let head = rx.recv().unwrap().to_ascii_lowercase();
        assert!(!head.contains("cookie"), "{head}");
    }
}

#[test]
fn redirect_not_followed() {
    let pki = Pki::new();
    let (other, other_rx) = serve(None, ok(b"elsewhere"));
    let answer: Box<Answer> = Box::new(move |head, w| {
        let to = if head.starts_with("GET /away ") {
            format!("http://localhost:{other}/")
        } else {
            "/next".to_owned()
        };
        let _ = write!(
            w,
            "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n"
        );
    });
    let (port, rx) = serve(Some(pki.leaf("127.0.0.1", now_years())), answer);
    let client = pki.client(quick());
    for path in ["/", "/away"] {
        let err = client
            .get(&format!("https://127.0.0.1:{port}{path}"), &[], MIB)
            .unwrap_err();
        assert!(matches!(err, NetError::Redirect(302)), "{path}: {err:?}");
        assert!(rx.recv().unwrap().starts_with(&format!("GET {path} ")));
        assert!(nothing_received(&rx), "{path}: the redirect was followed");
    }
    assert!(nothing_received(&other_rx), "followed to another host");
}

/// Waits before handing the TCP connection on to the TLS step.
#[derive(Debug)]
struct Slow(Duration);

impl<In: Transport> Connector<In> for Slow {
    type Out = In;

    fn connect(
        &self,
        _: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<In>, ureq::Error> {
        thread::sleep(self.0);
        Ok(chained)
    }
}

#[test]
fn handshake_gets_only_what_is_left() {
    // The TCP connect takes 400 ms, then the server never answers the TLS
    // handshake: the connect and total limits still hold from the start.
    let pki = Pki::new();
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    thread::spawn(move || {
        let held: Vec<_> = silent.incoming().take(2).collect();
        thread::sleep(Duration::from_secs(30));
        drop(held);
    });
    let ms = Duration::from_millis;
    let cases = [
        (
            "connect",
            ms(500),
            Timeouts {
                connect: ms(500),
                read: ms(5_000),
                total: ms(10_000),
            },
        ),
        (
            "total",
            ms(600),
            Timeouts {
                connect: ms(5_000),
                read: ms(5_000),
                total: ms(600),
            },
        ),
    ];
    for (case, limit, timeouts) in cases {
        let tls = Tls::new(Check::System(vec![pki.root.clone()])).unwrap();
        let client = Client {
            agent: agent(
                timeouts,
                TcpConnector::default().chain(Slow(ms(400))).chain(tls),
            ),
        };
        let start = Instant::now();
        let err = client
            .get(&format!("https://127.0.0.1:{port}/"), &[], MIB)
            .unwrap_err();
        let took = start.elapsed();
        println!("{case}: {err} after {took:?}");
        assert!(matches!(err, NetError::Timeout), "{case}: {err:?}");
        assert!(took >= limit && took < limit + ms(50), "{case}: {took:?}");
    }
}

/// F-094 (SN-02): an icon follows a redirect on the same site or to
/// another one, at most `ICON_REDIRECTS` times, never from https to http;
/// `get` still follows none.
#[test]
fn f_094_icon_redirects_followed_within_the_rules() {
    let pki = Pki::new();
    let (plain, plain_rx) = serve(None, ok(b"plain"));
    let answer: Box<Answer> = Box::new(move |head, w| {
        let path = head.split(' ').nth(1).unwrap_or("/").to_owned();
        let to = match path.as_str() {
            "/favicon.ico" => Some("/real.ico".to_owned()),
            "/down" => Some(format!("http://127.0.0.1:{plain}/favicon.ico")),
            p if p.starts_with("/loop") => Some(format!("{p}x")),
            _ => None,
        };
        let _ = match to {
            Some(to) => write!(
                w,
                "HTTP/1.1 301 Moved\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n"
            ),
            None => write!(w, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nicon"),
        };
    });
    let (port, rx) = serve(Some(pki.leaf("127.0.0.1", now_years())), answer);
    let client = pki.client(quick());
    let base = format!("https://127.0.0.1:{port}");
    // A path on the same site is followed.
    let body = client
        .get_icon(&format!("{base}/favicon.ico"), MIB)
        .unwrap();
    assert_eq!(body, b"icon");
    assert!(rx.recv().unwrap().starts_with("GET /favicon.ico "));
    assert!(rx.recv().unwrap().starts_with("GET /real.ico "));
    // `get` follows none.
    let err = client.get(&format!("{base}/favicon.ico"), &[], MIB);
    assert!(matches!(err, Err(NetError::Redirect(301))), "{err:?}");
    assert!(rx.recv().unwrap().starts_with("GET /favicon.ico "));
    assert!(nothing_received(&rx));
    // Never from https to http.
    let err = client.get_icon(&format!("{base}/down"), MIB);
    assert!(matches!(err, Err(NetError::Redirect(301))), "{err:?}");
    assert!(rx.recv().unwrap().starts_with("GET /down "));
    assert!(nothing_received(&plain_rx), "followed from https to http");
    // At most ICON_REDIRECTS hops: the first request and 5 more, then stop.
    let err = client.get_icon(&format!("{base}/loop"), MIB);
    assert!(matches!(err, Err(NetError::Redirect(301))), "{err:?}");
    for _ in 0..=ICON_REDIRECTS {
        assert!(rx.recv().unwrap().starts_with("GET /loop"));
    }
    assert!(nothing_received(&rx), "more than ICON_REDIRECTS hops");
}

/// F-094 (APP-01.21): the total limit covers every redirect hop together.
/// Each hop waits 700 ms and redirects again; with a 1 s limit the second
/// hop gets only what is left, so the attempt ends near 1 s, not after
/// all six hops.
#[test]
fn f_094_icon_time_limit_covers_every_redirect() {
    let answer: Box<Answer> = Box::new(|head, w| {
        thread::sleep(Duration::from_millis(700));
        let path = head.split(' ').nth(1).unwrap_or("/");
        let _ = write!(
            w,
            "HTTP/1.1 301 Moved\r\nLocation: {path}x\r\nContent-Length: 0\r\n\r\n"
        );
    });
    let (port, _rx) = serve(None, answer);
    let client = Client::new(Timeouts {
        connect: Duration::from_secs(5),
        read: Duration::from_secs(5),
        total: Duration::from_secs(1),
    })
    .unwrap();
    let start = Instant::now();
    let err = client.get_icon(&format!("http://127.0.0.1:{port}/favicon.ico"), MIB);
    let took = start.elapsed();
    println!("{err:?} after {took:?}");
    assert!(matches!(err, Err(NetError::Timeout)), "{err:?}");
    assert!(took < Duration::from_millis(1_300), "{took:?}");
}

// E16-S6: the pinned path for Larsal's own sync server (SYN-01.2, P17,
// LD-317), the PUT and the request headers (SYN-01.5, SYN-01.6). The pinned
// server is Larsal's own, larsal-server, on 127.0.0.1:0 with its first-start
// certificate and a fresh data folder under the system temp folder
// (LD-317 (4)). The small servers above stand in only where larsal-server
// cannot: to show the request bytes, and to sign a handshake with a key
// that is not the certificate's.

/// An larsal-server data folder, deleted when the test ends.
struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running larsal-server: its port, the DER it presents and the fingerprint
/// it printed.
struct LarsalServer {
    port: u16,
    der: Vec<u8>,
    printed: String,
    _data: Scratch,
}

impl LarsalServer {
    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }
}

/// Starts larsal-server on 127.0.0.1:0 on its own thread (which ends with the
/// test process). With `tls`, the data folder gets that certificate and key
/// (DER, PKCS#8) as `tls/cert.der` and `tls/key.der` first, in the modes the
/// server asks for (SYN-02.1); without, the server makes its first-start
/// certificate.
fn larsal_server(tls: Option<(Vec<u8>, Vec<u8>)>) -> LarsalServer {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let mut name = [0u8; 8];
    larsal_crypto::random::fill(&mut name).unwrap();
    let hex: String = name.iter().map(|b| format!("{b:02x}")).collect();
    let data = Scratch(std::env::temp_dir().join(format!("larsal-platform-net-{hex}")));
    if let Some((cert, key)) = tls {
        let dir = data.0.join("tls");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&dir)
            .unwrap();
        for (file, bytes) in [("cert.der", cert), ("key.der", key)] {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join(file))
                .unwrap()
                .write_all(&bytes)
                .unwrap();
        }
    }
    let (tx, rx) = mpsc::channel();
    let root = data.0.clone();
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
                cert.fingerprint(),
            );
            tx.send(started).unwrap();
            server.serve().await.unwrap();
        });
    });
    let (port, der, printed) = rx.recv_timeout(Duration::from_secs(30)).unwrap();
    LarsalServer {
        port,
        der,
        printed,
        _data: data,
    }
}

fn sha256(der: &[u8]) -> [u8; 32] {
    fingerprint(&CertificateDer::from(der)).unwrap()
}

/// SYN-01.2's printed form: 64 uppercase hex digits in 8 groups of 8.
fn printed(pin: &[u8; 32]) -> String {
    let hex: Vec<String> = pin.iter().map(|b| format!("{b:02X}")).collect();
    hex.chunks(4)
        .map(|g| g.concat())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A self-signed leaf for 127.0.0.1 as a small server's config, with its DER.
fn self_signed_with_der() -> (Arc<ServerConfig>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let cert = params("127.0.0.1", now_years()).self_signed(&key).unwrap();
    let der = cert.der().to_vec();
    (server(vec![cert.der().clone()], &key), der)
}

/// SYN-01.14's health reply as larsal-server writes it (larsal-model `json.rs`
/// writes members in key order).
const HEALTH: &[u8] = br#"{"api":1,"service":"sync"}"#;

/// SYN-01.2, SYN-01.14, LD-317 (3): pinned to the fingerprint larsal-server
/// printed at its first start, the client reaches it, and macOS's trust
/// evaluation is never asked (macOS does not trust that self-signed
/// certificate; the pin alone decides).
#[test]
fn syn01_2_pinned_client_reaches_larsal_server() {
    let s = larsal_server(None);
    let pin = sha256(&s.der);
    assert_eq!(printed(&pin), s.printed);
    trust::probe::take();
    let answer = Client::pinned(quick(), pin)
        .unwrap()
        .send(Method::Get, &s.url("/v1/health"), &[], MIB)
        .unwrap();
    assert_eq!(trust::probe::take(), 0, "the pinned path asked macOS");
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, HEALTH);
    assert_eq!(answer.header("cache-control"), Some("no-store"));
}

/// SYN-01.2: the first handshake reads the server's certificate and closes
/// before any request: the small server sees no request byte, and
/// larsal-server's certificate reads as the fingerprint it printed.
#[test]
fn syn01_2_read_fingerprint_sends_no_request() {
    let (config, der) = self_signed_with_der();
    let (port, rx) = serve(Some(config), ok(b"never"));
    trust::probe::take();
    let seen = read_fingerprint(&format!("https://127.0.0.1:{port}/"), quick()).unwrap();
    assert_eq!(seen, sha256(&der));
    assert!(nothing_received(&rx), "a request was sent");
    let s = larsal_server(None);
    let seen = read_fingerprint(&s.url("/"), quick()).unwrap();
    assert_eq!(printed(&seen), s.printed);
    assert_eq!(trust::probe::take(), 0, "the fingerprint read asked macOS");
    // Only https, no user name or password (SN-03, LD-64).
    for bad in [
        format!("http://127.0.0.1:{}/", s.port),
        format!("https://demo:pw@127.0.0.1:{}/", s.port),
    ] {
        assert!(
            matches!(read_fingerprint(&bad, quick()), Err(NetError::Url)),
            "{bad}"
        );
    }
    // Nobody listening: a network error, not a fingerprint.
    let free = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("https://127.0.0.1:{}/", free.local_addr().unwrap().port());
    drop(free);
    assert!(matches!(
        read_fingerprint(&url, quick()),
        Err(NetError::Network(_))
    ));
}

/// SYN-01.2, SYN-01 T03 (AT-L03): pinned to one server's certificate, the
/// client refuses another larsal-server's first-start certificate and another
/// self-signed one, before any request.
#[test]
fn syn01_2_another_certificate_refused_before_any_request() {
    let pinned = larsal_server(None);
    let other = larsal_server(None);
    assert_ne!(pinned.der, other.der);
    let client = Client::pinned(quick(), sha256(&pinned.der)).unwrap();
    trust::probe::take();
    let err = client
        .send(Method::Get, &other.url("/v1/health"), &[], MIB)
        .unwrap_err();
    assert!(matches!(err, NetError::CertificateChanged), "{err:?}");
    println!("{err}");
    let (config, _) = self_signed_with_der();
    let (port, rx) = serve(Some(config), ok(b"never"));
    let url = format!("https://127.0.0.1:{port}/v1/health");
    let err = client.send(Method::Get, &url, &[], MIB).unwrap_err();
    assert!(matches!(err, NetError::CertificateChanged), "{err:?}");
    assert!(nothing_received(&rx), "a request was sent");
    assert_eq!(trust::probe::take(), 0, "the pinned path asked macOS");
    // The pinned server itself still answers.
    let ok = client.send(Method::Get, &pinned.url("/v1/health"), &[], MIB);
    assert_eq!(ok.unwrap().status, 200);
}

/// LD-317 (3), SYN-01.2 "a certificate that macOS trusts is refused too",
/// proven without trusting anything new: larsal-server presents a leaf for
/// 127.0.0.1 that the test's own root signed. A client with that root as
/// its anchor accepts it (macOS's evaluation says yes); the pinned client
/// refuses it, because it is not the pinned certificate, and never asks
/// macOS. Pinned to that very leaf, the client accepts it, still without
/// asking macOS.
#[test]
fn ld317_3_pin_refuses_a_certificate_the_anchor_trusts() {
    let pki = Pki::new();
    let key = KeyPair::generate().unwrap();
    let leaf = params("127.0.0.1", now_years())
        .signed_by(&key, &pki.issuer)
        .unwrap();
    let s = larsal_server(Some((leaf.der().to_vec(), key.serialize_der())));
    assert_eq!(s.der, leaf.der().to_vec());
    trust::probe::take();
    let anchored = pki.client(quick());
    let answer = anchored.send(Method::Get, &s.url("/v1/health"), &[], MIB);
    assert_eq!(answer.unwrap().body, HEALTH);
    assert_eq!(trust::probe::take(), 1, "the control did not ask macOS");
    let first_start = larsal_server(None);
    let pinned = Client::pinned(quick(), sha256(&first_start.der)).unwrap();
    let err = pinned
        .send(Method::Get, &s.url("/v1/health"), &[], MIB)
        .unwrap_err();
    assert!(matches!(err, NetError::CertificateChanged), "{err:?}");
    assert_eq!(trust::probe::take(), 0, "the pinned path asked macOS");
    let pinned = Client::pinned(quick(), sha256(&s.der)).unwrap();
    let answer = pinned.send(Method::Get, &s.url("/v1/health"), &[], MIB);
    assert_eq!(answer.unwrap().body, HEALTH);
    assert_eq!(trust::probe::take(), 0, "the pinned path asked macOS");
}

/// SYN-01.2: the pin is not enough without the key. A server that shows
/// the pinned certificate but signs the handshake with another key is
/// refused by rustls's handshake signature check, in TLS 1.3 and 1.2,
/// before any request.
#[test]
fn syn01_2_pinned_certificate_without_its_key_refused() {
    let leaf = params("127.0.0.1", now_years())
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap();
    let pin = sha256(leaf.der());
    let other = KeyPair::generate().unwrap().serialize_der();
    let other = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(other));
    let signer = rustls::crypto::ring::sign::any_supported_type(&other).unwrap();
    let wrong = Arc::new(WrongKey(Arc::new(CertifiedKey::new(
        vec![leaf.der().clone()],
        signer,
    ))));
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(wrong.clone());
        let (port, rx) = serve(Some(Arc::new(config)), ok(b"no"));
        let err = Client::pinned(quick(), pin)
            .unwrap()
            .send(Method::Get, &format!("https://127.0.0.1:{port}/"), &[], MIB)
            .unwrap_err();
        let case = version.version;
        assert!(matches!(err, NetError::Certificate(_)), "{case:?}: {err:?}");
        assert!(err.to_string().contains("key"), "{case:?}: {err}");
        assert!(nothing_received(&rx), "{case:?}: a request was sent");
    }
}

/// SYN-01.2 "the SHA-256 of the presented DER equals the pin" holds for the
/// leaf only (F-228). A man in the middle with no key of the pinned server
/// shows its own self-signed 127.0.0.1 leaf first and larsal-server's pinned
/// first-start certificate (public bytes) second, and signs the handshake
/// with its own key: refused as CertificateChanged, before any request.
#[test]
fn syn01_2_pinned_certificate_as_intermediate_refused() {
    let s = larsal_server(None);
    let key = KeyPair::generate().unwrap();
    let own = params("127.0.0.1", now_years()).self_signed(&key).unwrap();
    let chain = vec![own.der().clone(), CertificateDer::from(s.der.clone())];
    let (port, rx) = serve(Some(server(chain, &key)), ok(b"never"));
    let err = Client::pinned(quick(), sha256(&s.der))
        .unwrap()
        .send(
            Method::Get,
            &format!("https://127.0.0.1:{port}/v1/health"),
            &[],
            MIB,
        )
        .unwrap_err();
    assert!(matches!(err, NetError::CertificateChanged), "{err:?}");
    assert!(nothing_received(&rx), "a request was sent");
}

/// SYN-01.2: the pin is all 32 bytes of the SHA-256 (F-233). A pin one bit
/// off larsal-server's printed fingerprint, in its first or its last byte, is
/// refused as CertificateChanged.
#[test]
fn syn01_2_pin_one_bit_off_refused() {
    let s = larsal_server(None);
    for byte in [0, 31] {
        let mut pin = sha256(&s.der);
        pin[byte] ^= 1;
        let err = Client::pinned(quick(), pin)
            .unwrap()
            .send(Method::Get, &s.url("/v1/health"), &[], MIB)
            .unwrap_err();
        assert!(
            matches!(err, NetError::CertificateChanged),
            "{byte}: {err:?}"
        );
    }
}

/// One TLS connection on 127.0.0.1 that reads one request with its
/// `Content-Length` body, sends both to the test and answers 201 with an
/// ETag (SYN-01.6's reply to a new vault).
fn serve_put(config: Arc<ServerConfig>) -> (u16, Receiver<(String, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut s = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
        let mut head = Vec::new();
        let mut byte = [0u8];
        while !head.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let len = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .map_or(0, |v| v.parse::<usize>().unwrap());
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).unwrap();
        let reply = "HTTP/1.1 201 Created\r\nETag: \"1\"\r\nContent-Length: 2\r\n\r\n{}";
        s.write_all(reply.as_bytes()).unwrap();
        s.flush().unwrap();
        tx.send((head, body)).unwrap();
    });
    (port, rx)
}

/// SYN-01.5, SYN-01.6: a PUT carries the whole body with its
/// `Content-Length` (never chunked) and the caller's `If-None-Match` and
/// `Authorization` header fields, and the reply comes back with its status,
/// its ETag and its body.
#[test]
fn syn01_6_put_sends_body_with_length_and_headers() {
    let (config, der) = self_signed_with_der();
    let (port, rx) = serve_put(config);
    let vault: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    let token = "Bearer AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let url = format!("https://127.0.0.1:{port}/v1/vaults/0123456789abcdef0123456789abcdef");
    let answer = Client::pinned(quick(), sha256(&der))
        .unwrap()
        .send(
            Method::Put(&vault),
            &url,
            &[("If-None-Match", "*"), ("Authorization", token)],
            MIB,
        )
        .unwrap();
    assert_eq!(answer.status, 201);
    assert_eq!(answer.header("etag"), Some("\"1\""));
    assert_eq!(answer.body, b"{}");
    let (head, body) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let lower = head.to_ascii_lowercase();
    assert!(
        head.starts_with("PUT /v1/vaults/0123456789abcdef0123456789abcdef HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(lower.contains("\r\ncontent-length: 70000\r\n"), "{head}");
    assert!(!lower.contains("transfer-encoding"), "{head}");
    assert!(lower.contains("\r\nif-none-match: *\r\n"), "{head}");
    assert!(
        lower.contains(&format!(
            "\r\nauthorization: {}\r\n",
            token.to_ascii_lowercase()
        )),
        "{head}"
    );
    assert!(!lower.contains("cookie"), "{head}");
    assert_eq!(body, vault);
}

/// SYN-01.6: `send` returns every status with its headers, follows no
/// redirect, and holds the reply to the caller's limit (SYN-01.10).
#[test]
fn syn01_6_send_returns_every_status_and_keeps_the_limit() {
    let answer: Box<Answer> = Box::new(|head, w| {
        let reply = if head.starts_with("GET /stale ") {
            "HTTP/1.1 412 Precondition Failed\r\nETag: \"7\"\r\nContent-Length: 0\r\n\r\n"
        } else if head.starts_with("GET /same ") {
            "HTTP/1.1 304 Not Modified\r\nETag: \"3\"\r\n\r\n"
        } else if head.starts_with("GET /moved ") {
            "HTTP/1.1 301 Moved\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n"
        } else {
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789"
        };
        let _ = w.write_all(reply.as_bytes());
    });
    let (config, der) = self_signed_with_der();
    let (port, rx) = serve(Some(config), answer);
    let client = Client::pinned(quick(), sha256(&der)).unwrap();
    let url = |path: &str| format!("https://127.0.0.1:{port}{path}");
    let stale = client.send(Method::Get, &url("/stale"), &[("If-Match", "\"6\"")], MIB);
    let stale = stale.unwrap();
    assert_eq!((stale.status, stale.header("etag")), (412, Some("\"7\"")));
    assert!(rx.recv().unwrap().contains("\r\nif-match: \"6\"\r\n"));
    let same = client
        .send(
            Method::Get,
            &url("/same"),
            &[("If-None-Match", "\"3\"")],
            MIB,
        )
        .unwrap();
    assert_eq!((same.status, same.body.len()), (304, 0));
    let moved = client.send(Method::Get, &url("/moved"), &[], MIB).unwrap();
    assert_eq!(moved.status, 301);
    assert!(rx.recv().unwrap().starts_with("GET /same "));
    assert!(rx.recv().unwrap().starts_with("GET /moved "));
    assert!(nothing_received(&rx), "a redirect was followed");
    assert_eq!(
        client.send(Method::Get, &url("/"), &[], 10).unwrap().body,
        b"0123456789"
    );
    let err = client.send(Method::Get, &url("/"), &[], 9).unwrap_err();
    assert!(matches!(err, NetError::TooLarge), "{err:?}");
}

/// SYN-01.5 (request smuggling): a header value with a line break, as a
/// hostile server's ETag sent back in `If-Match` could hold, is refused
/// before anything is sent; so are `http` and a user name in the URL.
#[test]
fn syn01_5_header_with_line_break_refused_before_sending() {
    let (config, der) = self_signed_with_der();
    let (port, rx) = serve(Some(config), ok(b"no"));
    let client = Client::pinned(quick(), sha256(&der)).unwrap();
    let url = format!("https://127.0.0.1:{port}/v1/vaults/x");
    for value in [
        "\"1\"\r\nAuthorization: Bearer stolen",
        "\"1\"\nX: y",
        "\"1\"\0",
    ] {
        let err = client
            .send(Method::Put(b"v"), &url, &[("If-Match", value)], MIB)
            .unwrap_err();
        assert!(matches!(err, NetError::Network(_)), "{value:?}: {err:?}");
    }
    assert!(nothing_received(&rx), "a request was sent");
    for bad in [
        format!("http://127.0.0.1:{port}/"),
        format!("https://demo:pw@127.0.0.1:{port}/"),
    ] {
        let err = client.send(Method::Get, &bad, &[], MIB).unwrap_err();
        assert!(matches!(err, NetError::Url), "{bad}: {err:?}");
    }
}

/// SYN-01.2, LD-325 (5) (c), Verify's test: the pin is the whole check. A
/// self-signed leaf for another name (`other.example`) that expired in 2021
/// is accepted by the client pinned to it, and macOS's trust evaluation is
/// never asked (0 calls); a client that trusts what macOS trusts refuses
/// the same server.
#[test]
fn ld325_5c_pinned_leaf_with_another_name_and_old_dates_is_accepted() {
    let key = KeyPair::generate().unwrap();
    let leaf = params("other.example", (2020, 2021))
        .self_signed(&key)
        .unwrap();
    let der = leaf.der().to_vec();
    let (port, rx) = serve(Some(server(vec![leaf.der().clone()], &key)), ok(b"pinned"));
    let url = format!("https://127.0.0.1:{port}/v1/health");
    trust::probe::take();
    let answer = Client::pinned(quick(), sha256(&der))
        .unwrap()
        .send(Method::Get, &url, &[], MIB)
        .unwrap();
    assert_eq!(
        (answer.status, answer.body.as_slice()),
        (200, &b"pinned"[..])
    );
    assert_eq!(trust::probe::take(), 0, "the pinned path asked macOS");
    assert!(rx.recv().unwrap().starts_with("GET /v1/health "));
    let err = Client::new(quick())
        .unwrap()
        .get(&url, &[], MIB)
        .unwrap_err();
    assert!(matches!(err, NetError::Certificate(_)), "{err:?}");
    assert!(nothing_received(&rx), "a request was sent");
}

/// SYN-01.2, LD-325 (5) (c), Checker 1's K5: the fingerprint is the leaf's,
/// the certificate the server presents first, also when an intermediate
/// follows it.
#[test]
fn ld325_5c_read_fingerprint_gives_the_leaf() {
    let pki = Pki::new();
    let p = ca("Larsal test intermediate");
    let mid_key = KeyPair::generate().unwrap();
    let mid = p.signed_by(&mid_key, &pki.issuer).unwrap().der().clone();
    let key = KeyPair::generate().unwrap();
    let leaf = params("127.0.0.1", now_years())
        .signed_by(&key, &Issuer::new(p, mid_key))
        .unwrap();
    let chain = vec![leaf.der().clone(), mid.clone()];
    let (port, rx) = serve(Some(server(chain, &key)), ok(b"never"));
    let seen = read_fingerprint(&format!("https://127.0.0.1:{port}/"), quick()).unwrap();
    assert_eq!(seen, sha256(leaf.der()));
    assert_ne!(seen, sha256(&mid));
    assert!(nothing_received(&rx), "a request was sent");
}

/// SYN-04, LD-325 (5) (b): a POST carries its JSON body with its
/// `Content-Length`; an `Answer`'s `Debug` output shows the status and
/// sizes only, never a header value or the body (a session reply holds the
/// token).
#[test]
fn syn04_post_sends_body_and_answer_debug_hides_it() {
    let (config, der) = self_signed_with_der();
    let (port, rx) = serve_put(config);
    let record = br#"{"device_id":"0123456789abcdef0123456789abcdef"}"#;
    let url = format!("https://127.0.0.1:{port}/v1/signin/challenge");
    let answer = Client::pinned(quick(), sha256(&der))
        .unwrap()
        .send(
            Method::Post(record),
            &url,
            &[("Content-Type", "application/json")],
            MIB,
        )
        .unwrap();
    let (head, body) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(
        head.starts_with("POST /v1/signin/challenge HTTP/1.1\r\n"),
        "{head}"
    );
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains(&format!("\r\ncontent-length: {}\r\n", record.len())));
    assert!(!lower.contains("transfer-encoding"), "{head}");
    assert_eq!(body, record);
    let shown = format!("{answer:?}");
    assert_eq!(shown, "Answer { status: 201, headers: 2, body: 2 }");
    assert!(!shown.contains("{}") && !shown.contains("\"1\""), "{shown}");
}
