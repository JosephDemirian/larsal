//! The one HTTPS client for opt-in features (SN-01 to SN-05; story E6-S7,
//! LD-194): the breach range query (FEA-06), website icons (MOD-06.11,
//! APP-01.21), the update check (APP-01.19) and Larsal's own sync server
//! (SYN-01, E16-S6).
//!
//! Guarantees:
//! - Nothing here runs by itself: no global client, no thread, no start-up
//!   code. A caller makes a [`Client`] when the user asks for a network
//!   feature (SN-01); making one opens no connection, and only
//!   [`Client::get`], [`Client::get_icon`], [`Client::send`] and
//!   [`read_fingerprint`] connect.
//! - TLS is rustls on ring, TLS 1.2 and 1.3 only (rustls has no older
//!   version). Every server certificate goes through macOS's own trust
//!   evaluation (Security.framework, Larsal's [`Verifier`] over
//!   `macos/trust.rs`, LD-247 (2)) with the host name checked; nothing can
//!   switch the checks off (SN-03). The one other check is the pin of
//!   [`Client::pinned`], for Larsal's own demo server (SYN-01.2, P17): only the
//!   certificate whose SHA-256 equals the pin passes; macOS's trust
//!   evaluation is never asked, so a certificate macOS trusts is refused
//!   too; names and dates are not checked, but the handshake signatures
//!   are, so the server must hold that certificate's key.
//! - [`read_fingerprint`] reads a server's certificate in one handshake
//!   that refuses every certificate, so no request is ever sent on it
//!   (SYN-01.2: the user compares the fingerprint before Larsal pins it).
//! - [`Client::send`] sends GET, PUT or POST with the caller's headers (the
//!   sync routes' `If-Match`, `If-None-Match` and session token, SYN-01.5
//!   and SYN-01.6) and returns every status with the reply's headers. A
//!   PUT or POST body goes with its `Content-Length`, never chunked. An
//!   [`Answer`]'s `Debug` output shows its status and sizes only, never a
//!   header value or the body, which may hold a session token
//!   (LD-325 (5) (b)). A header value may
//!   be a secret (the session token): it goes only into the request this
//!   call writes, ureq logs nothing (`crates/log`), and the zeroing
//!   allocator wipes the copies when they are freed (LD-193). A header
//!   value with a line break is refused before anything is sent.
//! - `https` only. [`Client::get_icon`] also takes `http`, for an entry URL
//!   that uses it (SN-03). A URL with a user name or password is refused
//!   (LD-64).
//! - [`Client::get`] follows no redirect: a 3xx answer is
//!   [`NetError::Redirect`], so a request never moves to another host.
//!   [`Client::get_icon`] follows at most [`ICON_REDIRECTS`] (SN-02, F-094),
//!   each to `http` or `https` only, never from https to http, never with a
//!   user name or password.
//! - No cookies (ureq's cookie store is not built in), no `Referer`, no
//!   `Accept-Language`, no compression, no proxy; the `User-Agent` is the
//!   product name only, [`USER_AGENT`] (FEA-06.4).
//! - Connect, per-read and total time limits ([`Timeouts`]); a body longer
//!   than the caller's limit is [`NetError::TooLarge`]. For [`Client::get`]
//!   and [`Client::get_icon`], only status 200 is an answer.
//!
//! Rule 3: TLS is a transport, not Larsal's crypto. rustls, ring and macOS's
//! trust evaluation are reached only from this module; vault keys and
//! secrets never pass through them, only the request a caller builds. The
//! verifier writes no crypto: macOS decides trust, rustls checks the
//! handshake signatures.

use crate::macos::trust::{self, Refused};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
    StreamOwned,
};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use ureq::http::Uri;
use ureq::http::uri::Scheme;
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::time::{Duration as Budget, Instant as At};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout, TcpConnector,
    Transport, TransportAdapter,
};

/// The `User-Agent` of every request: the product name, no version, no
/// platform (FEA-06.4).
pub const USER_AGENT: &str = "Larsal";

/// The most redirects one icon address follows (SN-02: the reference's own
/// loop allows 5).
pub const ICON_REDIRECTS: usize = 5;

/// Time limits of a [`Client`].
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// TCP connect and TLS handshake together. It starts after the name
    /// lookup (ureq's own clock), so only `total` bounds a slow lookup.
    pub connect: Duration,
    /// Each wait for bytes from the server.
    pub read: Duration,
    /// The whole request, from lookup to the last byte of the body.
    pub total: Duration,
}

impl Default for Timeouts {
    /// FEA-06.8: 15 seconds to connect, 30 seconds per request.
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(15),
            read: Duration::from_secs(30),
            total: Duration::from_secs(30),
        }
    }
}

/// Why a request failed. The text is plain language, for the screen; it never
/// holds a response body (FEA-06.8).
#[derive(Debug)]
pub enum NetError {
    /// Not an address Larsal may ask: bad URL, a scheme other than https
    /// (http only for icons), or a user name or password in it.
    Url,
    /// The system trust evaluation refused the server's certificate.
    Certificate(String),
    /// The server's certificate is not the one pinned for it
    /// ([`Client::pinned`], SYN-01.2). The handshake stopped, so no request
    /// was sent.
    CertificateChanged,
    /// A time limit ran out.
    Timeout,
    /// The body is longer than the caller's limit.
    TooLarge,
    /// The server answered with a redirect Larsal does not follow: any for
    /// [`Client::get`]; for icons one past [`ICON_REDIRECTS`], to https from
    /// http only, or with no usable `Location`.
    Redirect(u16),
    /// Any status other than 200 and 3xx.
    Status(u16),
    /// No connection: name lookup, connect, TLS or transfer failed.
    Network(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url => f.write_str("the address is not allowed"),
            Self::Certificate(v) => write!(f, "the server's certificate was refused: {v}"),
            Self::CertificateChanged => {
                f.write_str("the server's certificate is not the one this Mac checked and saved")
            }
            Self::Timeout => f.write_str("the server took too long to answer"),
            Self::TooLarge => f.write_str("the answer is too large"),
            Self::Redirect(v) => write!(f, "the server sent a redirect (HTTP {v})"),
            Self::Status(v) => write!(f, "the server answered with HTTP {v}"),
            Self::Network(v) => write!(f, "the connection failed: {v}"),
        }
    }
}

impl std::error::Error for NetError {}

/// The HTTPS client. Make one per user action; it holds no state between
/// requests apart from open connections, which close when it is dropped.
pub struct Client {
    agent: ureq::Agent,
}

impl Client {
    /// A client that trusts what macOS trusts. Opens no connection.
    pub fn new(timeouts: Timeouts) -> Result<Self, NetError> {
        Self::build(timeouts, Check::System(Vec::new()))
    }

    /// Tests only: also trust `anchors`, in memory, for this client's trust
    /// evaluations (`SecTrustSetAnchorCertificates`); no keychain changes.
    #[cfg(test)]
    fn with_anchors(
        timeouts: Timeouts,
        anchors: Vec<CertificateDer<'static>>,
    ) -> Result<Self, NetError> {
        Self::build(timeouts, Check::System(anchors))
    }

    /// A client for Larsal's own server whose certificate the user compared
    /// and pinned (SYN-01.2, P17): it accepts only the certificate whose
    /// SHA-256 equals `pin`, compared in constant time (CRY-04.11). The pin
    /// is the whole check: macOS's trust evaluation is never asked, so a
    /// certificate macOS trusts is refused too, and names and dates are not
    /// checked; the handshake signatures are, so a server that only shows
    /// the pinned certificate without its key is refused. Any other
    /// certificate is [`NetError::CertificateChanged`]. Opens no connection.
    pub fn pinned(timeouts: Timeouts, pin: [u8; 32]) -> Result<Self, NetError> {
        Self::build(timeouts, Check::Pin(pin))
    }

    fn build(timeouts: Timeouts, check: Check) -> Result<Self, NetError> {
        let connector = TcpConnector::default().chain(Tls::new(check)?);
        Ok(Self {
            agent: agent(timeouts, connector),
        })
    }

    /// GET an `https` URL with extra `headers` and returns at most
    /// `max_bytes` of body: the breach range query and the update check.
    pub fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<Vec<u8>, NetError> {
        match self.fetch(url, headers, max_bytes, false, None)? {
            Reply::Body(body) => Ok(body),
            Reply::Moved(status, _) => Err(NetError::Redirect(status)),
        }
    }

    /// GET a website icon: `https`, or `http` when the entry URL uses it
    /// (SN-03). Follows at most [`ICON_REDIRECTS`] redirects (SN-02), never
    /// from https to http; each hop passes the same address checks. The
    /// total time limit covers every hop together (APP-01.21): each request
    /// gets only the time left.
    pub fn get_icon(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, NetError> {
        let total = self.agent.config().timeouts().global;
        let deadline = total.map(|t| Instant::now() + t);
        let mut url = url.to_owned();
        let mut hops = 0;
        loop {
            let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if left.is_some_and(|l| l.is_zero()) {
                return Err(NetError::Timeout);
            }
            match self.fetch(&url, &[], max_bytes, true, left)? {
                Reply::Body(body) => return Ok(body),
                Reply::Moved(status, location) => {
                    let next = (hops < ICON_REDIRECTS)
                        .then(|| follow(&url, location.as_deref()))
                        .flatten();
                    url = next.ok_or(NetError::Redirect(status))?;
                    hops += 1;
                }
            }
        }
    }

    /// Sends one request to an `https` URL with `headers` and returns the
    /// reply whatever its status, with at most `max_bytes` of body (the
    /// sync routes, SYN-01.4 to SYN-01.6). A PUT or POST body goes with its
    /// `Content-Length`, never chunked. Follows no redirect: a 3xx is an
    /// answer like any other. A header value with a line break, NUL or
    /// another control character other than tab is refused before anything
    /// is sent.
    pub fn send(
        &self,
        method: Method<'_>,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<Answer, NetError> {
        let uri = checked(url, false)?;
        let sent = match method {
            Method::Get => {
                let mut request = self.agent.get(uri);
                for (name, value) in headers {
                    request = request.header(*name, *value);
                }
                request.call()
            }
            Method::Put(body) => {
                let mut request = self.agent.put(uri);
                for (name, value) in headers {
                    request = request.header(*name, *value);
                }
                request.send(body)
            }
            Method::Post(body) => {
                let mut request = self.agent.post(uri);
                for (name, value) in headers {
                    request = request.header(*name, *value);
                }
                request.send(body)
            }
        };
        let mut response = sent.map_err(classify)?;
        let headers = response
            .headers()
            .iter()
            .filter_map(|(n, v)| Some((n.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        let body = response
            .body_mut()
            .with_config()
            // As in `fetch`: one byte more allows exactly max_bytes.
            .limit(max_bytes.saturating_add(1))
            .read_to_vec()
            .map_err(classify)?;
        Ok(Answer {
            status: response.status().as_u16(),
            headers,
            body,
        })
    }

    fn fetch(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
        http_ok: bool,
        left: Option<Duration>,
    ) -> Result<Reply, NetError> {
        let uri = checked(url, http_ok)?;
        let mut request = self.agent.get(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(left) = left {
            request = request.config().timeout_global(Some(left)).build();
        }
        let mut response = request.call().map_err(classify)?;
        match response.status().as_u16() {
            200 => response
                .body_mut()
                .with_config()
                // ureq refuses any read once its limit is used up, the
                // final empty read too: one byte more allows exactly max_bytes.
                .limit(max_bytes.saturating_add(1))
                .read_to_vec()
                .map(Reply::Body)
                .map_err(classify),
            s @ 300..=399 => Ok(Reply::Moved(
                s,
                response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned),
            )),
            s => Err(NetError::Status(s)),
        }
    }
}

/// Reads the certificate of the `https` server at `url` in one TLS
/// handshake and returns the SHA-256 of its DER bytes (SYN-01.2), for the
/// user to compare with the fingerprint the server printed. No request is
/// sent: this handshake refuses every certificate, so the connection closes
/// before a request byte could be written.
pub fn read_fingerprint(url: &str, timeouts: Timeouts) -> Result<[u8; 32], NetError> {
    let uri = checked(url, false)?;
    let seen = Arc::new(Mutex::new(None));
    let client = Client::build(timeouts, Check::Peek(seen.clone()))?;
    match client.agent.get(uri).call() {
        // Cannot happen: `Check::Peek` refuses every certificate.
        Ok(_) => Err(NetError::Network(
            "the server answered without a certificate check".into(),
        )),
        Err(e) => seen.lock().ok().and_then(|s| *s).ok_or_else(|| classify(e)),
    }
}

/// The request of [`Client::send`].
#[derive(Clone, Copy, Debug)]
pub enum Method<'a> {
    /// GET, with no body.
    Get,
    /// PUT with this body, sent with its `Content-Length` (SYN-01.6).
    Put(&'a [u8]),
    /// POST with this body (a JSON record, SYN-01.8), sent with its
    /// `Content-Length` (SYN-04).
    Post(&'a [u8]),
}

/// One reply of [`Client::send`], whatever its status.
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The reply's header fields whose values are text, in order; names in
    /// lower case.
    pub headers: Vec<(String, String)>,
    /// The body, at most the caller's limit.
    pub body: Vec<u8>,
}

/// The status and sizes only: a header value or the body may hold a
/// session token (LD-325 (5) (b)).
impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer")
            .field("status", &self.status)
            .field("headers", &self.headers.len())
            .field("body", &self.body.len())
            .finish()
    }
}

impl Answer {
    /// The first value of the header `name` (lower case), if any.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// One answer: a body, or a redirect with its `Location`.
enum Reply {
    Body(Vec<u8>),
    Moved(u16, Option<String>),
}

/// `url` as an address Larsal may ask: `https`, or `http` when `http_ok`
/// (icons, SN-03), with no user name or password (LD-64).
fn checked(url: &str, http_ok: bool) -> Result<Uri, NetError> {
    let uri: Uri = url.parse().map_err(|_| NetError::Url)?;
    let scheme_ok = match uri.scheme() {
        Some(s) if *s == Scheme::HTTPS => true,
        Some(s) if *s == Scheme::HTTP => http_ok,
        _ => false,
    };
    let userinfo = uri.authority().is_none_or(|a| a.as_str().contains('@'));
    if !scheme_ok || userinfo {
        return Err(NetError::Url);
    }
    Ok(uri)
}

/// The next address of an icon redirect: an absolute `http` or `https`
/// URL, or a path (`/…`, `//host/…`) on the current one; `None` for any
/// other form and for a move from https to http. The scheme and user name
/// checks of `fetch` run on it again.
fn follow(from: &str, location: Option<&str>) -> Option<String> {
    let location = location?.trim();
    let from: Uri = from.parse().ok()?;
    let scheme = from.scheme_str()?;
    let next = if let Some(rest) = location.strip_prefix("//") {
        format!("{scheme}://{rest}")
    } else if location.starts_with('/') {
        format!("{scheme}://{}{location}", from.authority()?)
    } else {
        location.to_owned()
    };
    let to: Uri = next.parse().ok()?;
    let downgrade = from.scheme() == Some(&Scheme::HTTPS) && to.scheme() != Some(&Scheme::HTTPS);
    (!downgrade).then_some(next)
}

fn agent(timeouts: Timeouts, connector: impl Connector) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        // No `.proxy(None)`: Larsal's ureq copy has no proxy support (E0-S7 step 4d).
        .user_agent(USER_AGENT)
        .timeout_connect(Some(timeouts.connect))
        .timeout_per_read(Some(timeouts.read))
        .timeout_global(Some(timeouts.total))
        .build();
    ureq::Agent::with_parts(config, connector, DefaultResolver::default())
}

fn classify(e: ureq::Error) -> NetError {
    match e {
        ureq::Error::Timeout(_) => NetError::Timeout,
        ureq::Error::BodyExceedsLimit(_) => NetError::TooLarge,
        ureq::Error::Io(e) => {
            let tls = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>());
            match tls {
                // Only `Check::Pin` refuses with this (SYN-01.2).
                Some(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                )) => NetError::CertificateChanged,
                Some(rustls::Error::InvalidCertificate(c)) => NetError::Certificate(reason(c)),
                _ if e.kind() == io::ErrorKind::TimedOut => NetError::Timeout,
                _ => NetError::Network(e.to_string()),
            }
        }
        e => NetError::Network(e.to_string()),
    }
}

/// Plain words for the common refusals; macOS's own text for the rest.
fn reason(c: &CertificateError) -> String {
    use CertificateError as C;
    match c {
        C::Expired | C::ExpiredContext { .. } => {
            "it has expired or is not valid yet (check this Mac's date and time)".into()
        }
        C::NotValidYet | C::NotValidYetContext { .. } => "it is not valid yet".into(),
        C::NotValidForName | C::NotValidForNameContext { .. } => {
            "it was issued for a different site".into()
        }
        C::UnknownIssuer => "it is not issued by an authority this Mac trusts".into(),
        C::BadSignature => "the server did not prove it holds the certificate's key".into(),
        C::Other(o) => o.to_string(),
        o => o.to_string(),
    }
}

/// Larsal's server certificate check (LD-247 (2)): [`Check`] decides the
/// certificate; the handshake signatures are rustls's own checks with the
/// provider's algorithms, for every check.
#[derive(Debug)]
struct Verifier {
    provider: Arc<CryptoProvider>,
    check: Check,
}

/// What decides a server's certificate.
#[derive(Debug)]
enum Check {
    /// macOS's trust evaluation (`macos/trust.rs`): the chain, the host
    /// name, the dates and revocation. Empty in the product (this Mac's
    /// trust settings); tests give their own root as the only anchor.
    System(Vec<CertificateDer<'static>>),
    /// Only the certificate whose SHA-256 is this pin (SYN-01.2): no chain,
    /// name or date check, and macOS is never asked.
    Pin([u8; 32]),
    /// Notes the certificate's SHA-256 and refuses it: the one handshake of
    /// [`read_fingerprint`].
    Peek(Arc<Mutex<Option<[u8; 32]>>>),
}

/// The refusal of [`Check::Pin`] and [`Check::Peek`]; macOS's answers never
/// map to it ([`refusal`]), so [`classify`] can tell it apart.
fn not_pinned() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

/// The SHA-256 of a certificate's DER bytes, from larsal-crypto (rule 3).
fn fingerprint(der: &CertificateDer<'_>) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(larsal_crypto::hash::sha256(&[der.as_ref()]).expose()).ok()
}

/// The rustls refusal for macOS's answer. Codes from `SecBase.h`.
fn refusal(refused: Refused) -> rustls::Error {
    use CertificateError as C;
    let error = match refused {
        Refused::BadEncoding => C::BadEncoding,
        Refused::Os { code, text } => match code {
            -67818 => C::Expired,                // errSecCertificateExpired
            -67819 => C::NotValidYet,            // errSecCertificateNotValidYet
            -67602 => C::NotValidForName,        // errSecHostNameMismatch
            -67843 | -25318 => C::UnknownIssuer, // errSecNotTrusted, errSecCreateChainFailed
            -67820 => C::Revoked,                // errSecCertificateRevoked
            -67609 => C::InvalidPurpose,         // errSecInvalidExtendedKeyUsage
            _ => C::Other(rustls::OtherError(Arc::new(io::Error::other(text)))),
        },
    };
    rustls::Error::InvalidCertificate(error)
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let anchors = match &self.check {
            Check::System(anchors) => anchors,
            Check::Pin(pin) => {
                let seen = larsal_crypto::hash::sha256(&[end_entity.as_ref()]);
                return if larsal_crypto::secret::ct_eq(seen.expose(), pin) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(not_pinned())
                };
            }
            Check::Peek(seen) => {
                if let Ok(mut slot) = seen.lock() {
                    *slot = fingerprint(end_entity);
                }
                return Err(not_pinned());
            }
        };
        let host = server_name.to_str();
        let host = host.strip_suffix('.').unwrap_or(&host);
        let chain: Vec<&[u8]> = std::iter::once(end_entity)
            .chain(intermediates)
            .map(AsRef::as_ref)
            .collect();
        let anchors: Vec<&[u8]> = anchors.iter().map(AsRef::as_ref).collect();
        trust::evaluate_server(&chain, host, ocsp_response, &anchors)
            .map(|()| ServerCertVerified::assertion())
            .map_err(refusal)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.provider.signature_verification_algorithms;
        verify_tls12_signature(message, cert, dss, algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.provider.signature_verification_algorithms;
        verify_tls13_signature(message, cert, dss, algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// rustls under ureq, with Larsal's own `ClientConfig` and [`Verifier`]
/// (ureq's built-in TLS takes neither).
#[derive(Debug)]
struct Tls(Arc<ClientConfig>);

impl Tls {
    fn new(check: Check) -> Result<Self, NetError> {
        let failed = |e: rustls::Error| NetError::Network(e.to_string());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Verifier {
            provider: provider.clone(),
            check,
        };
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(failed)?
            // Larsal's verifier is the system check, not a way around it.
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Self(Arc::new(config)))
    }
}

impl<In: Transport> Connector<In> for Tls {
    type Out = Either<In, TlsStream>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(tcp) = chained else {
            return Ok(None);
        };
        if !details.needs_tls() || tcp.is_tls() {
            return Ok(Some(Either::A(tcp)));
        }
        let host = details.uri.host().unwrap_or_default();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| ureq::Error::Tls("not a valid host name"))?;
        let conn = ClientConnection::new(self.0.clone(), name).map_err(io::Error::other)?;
        let mut sock = TransportAdapter::new(tcp.boxed(), details.current_time.clone());
        // ureq's connect budget (connect and total limits) runs from
        // `details.now`, before the TCP connect: the handshake gets what is left.
        let mut budget = details.timeout;
        let now = (details.current_time)();
        if let (Budget::Exact(limit), At::Exact(start), At::Exact(now)) =
            (budget.after, details.now, now)
        {
            budget.after =
                Budget::Exact(limit.saturating_sub(now.saturating_duration_since(start)));
        }
        sock.set_timeout(budget);
        let mut stream = StreamOwned::new(conn, sock);
        stream.conn.complete_io(&mut stream.sock)?;
        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );
        Ok(Some(Either::B(TlsStream { buffers, stream })))
    }
}

struct TlsStream {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter>,
}

impl std::fmt::Debug for TlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsStream")
    }
}

impl Transport for TlsStream {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.sock.set_timeout(timeout);
        let output = self.buffers.output().get(..amount).unwrap_or_default();
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.sock.set_timeout(timeout);
        let read = self.stream.read(self.buffers.input_append_buf())?;
        self.buffers.input_appended(read);
        Ok(read > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.sock.get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests;
