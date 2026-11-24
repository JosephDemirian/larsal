//! HTTPS on 127.0.0.1 (SYN-01.1, SYN-01.3, SYN-01.9 to SYN-01.11,
//! SYN-01.13, SYN-01.14): one TLS handshake per connection, then hyper's
//! HTTP/1.1 with Larsal's limits, then one route match.
//!
//! Before any route runs: hyper answers a head it cannot parse with 400, a
//! head over [`MAX_HEAD`] or with more than [`MAX_HEADERS`] fields with
//! 431; Larsal answers a request line over [`MAX_REQUEST_LINE`] with 414 and a
//! header field over [`MAX_HEADER_FIELD`] with 431, each with no body, and
//! closes the connection. A `Content-Length` over [`Config::max_body`] gets
//! 413 at once, before one body byte is read. Every reply of Larsal's has
//! `Cache-Control: no-store`, and every error reply the body
//! `{"error":"<code>"}` only.
//!
//! Timeouts (SYN-01.11): the handshake within [`Config::handshake`], each
//! request head within [`Config::head`] of the handshake or of the last
//! reply (hyper's `header_read_timeout`, which also ends an idle
//! connection), and no read or write that waits longer than [`Config::gap`].
//!
//! Then, in this order: the rate limit of SYN-01.12 (429 with
//! `Retry-After`), the body limit (413), and for the routes that need one
//! the session of SYN-01.5 (401, `auth.rs`); then the route. The vault
//! routes (SYN-01.6) are in `vaults.rs`, the account and sign-in routes
//! (SYN-04) in `accounts.rs`.
//!
//! Every request Larsal answers gets one log line (SYN-01.13): the method,
//! the route's name, the status, the reply's size and the time taken.
//! Never the path, a header, a token, a nonce, a signature, a code or a
//! body.

use crate::Error;
use crate::accounts;
use crate::auth::{self, Auth, Bucket, rate_limited, unauthorized};
use crate::blobs::Blobs;
use crate::vaults::{self, FileBody};
use http_body_util::{Either, Full};
use hyper::body::{Body as _, Bytes, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use larsal_proto::limits::{
    GAP_TIMEOUT, HANDSHAKE_TIMEOUT, HEAD_TIMEOUT, MAX_HEAD, MAX_HEADER_FIELD, MAX_HEADERS,
    MAX_REQUEST_LINE, MAX_VAULT, READS_PER_MINUTE, SIGNIN_PER_MINUTE, WRITES_PER_MINUTE,
};
use larsal_proto::messages::{ErrorCode, Health};
use larsal_proto::routes::{self, Match, Route};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::time::{Instant, Sleep};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

/// The server's limits and timeouts. [`Config::default`] holds SYN-01's
/// values; a test lowers them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The largest body any route takes: [`MAX_VAULT`] (SYN-01.10).
    pub max_body: u64,
    /// The TLS handshake: [`HANDSHAKE_TIMEOUT`].
    pub handshake: Duration,
    /// One request head: [`HEAD_TIMEOUT`].
    pub head: Duration,
    /// The longest wait of one read or write: [`GAP_TIMEOUT`].
    pub gap: Duration,
    /// Requests per IP address and minute (SYN-01.12).
    pub rate: RateLimits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_body: MAX_VAULT,
            handshake: HANDSHAKE_TIMEOUT,
            head: HEAD_TIMEOUT,
            gap: GAP_TIMEOUT,
            rate: RateLimits::default(),
        }
    }
}

/// Requests per IP address and minute (SYN-01.12). [`RateLimits::default`]
/// holds the card's values; a test lowers or raises them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// The sign-in routes: [`SIGNIN_PER_MINUTE`].
    pub signin: u32,
    /// POST, PUT and DELETE on every other route: [`WRITES_PER_MINUTE`].
    pub writes: u32,
    /// GET on every other route: [`READS_PER_MINUTE`].
    pub reads: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            signin: SIGNIN_PER_MINUTE,
            writes: WRITES_PER_MINUTE,
            reads: READS_PER_MINUTE,
        }
    }
}

/// Runs `f` on tokio's blocking pool, so the one writer lock never stops
/// the event loop (SYN-02.8).
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|_| Err(Error::new("a store task stopped")))
}

/// 500 `server_error`, with the reason in the server's log only.
pub(crate) fn failed(e: &Error) -> Response<Body> {
    crate::log(format_args!("a route failed: {e}"));
    error(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::ServerError)
}

/// A reply's body: Larsal's own small replies, or a vault file streamed from
/// its open handle.
pub(crate) type Body = Either<Full<Bytes>, FileBody>;

/// Accepts connections on `listener` until the process ends; each one runs
/// on its own task.
pub(crate) async fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    config: Arc<Config>,
    blobs: Arc<Blobs>,
    auth: Arc<Auth>,
) {
    let acceptor = TlsAcceptor::from(tls);
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let state = State {
                    config: config.clone(),
                    blobs: blobs.clone(),
                    auth: auth.clone(),
                    ip: peer.ip(),
                };
                tokio::spawn(connection(tcp, acceptor.clone(), state));
            }
            // ponytail: a full file table (EMFILE) waits a moment and tries
            // again; a connection cap comes with hosting (E19).
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

/// What one connection's requests share.
#[derive(Clone)]
struct State {
    config: Arc<Config>,
    blobs: Arc<Blobs>,
    auth: Arc<Auth>,
    /// The client's IP address, for the rate limits.
    ip: IpAddr,
}

async fn connection(tcp: tokio::net::TcpStream, acceptor: TlsAcceptor, state: State) {
    // A plain HTTP request, an old TLS version or a handshake that does not
    // end in time gets no HTTP reply: the connection closes (SYN-01.1).
    let handshake = state.config.handshake;
    let Ok(Ok(stream)) = tokio::time::timeout(handshake, acceptor.accept(tcp)).await else {
        return;
    };
    let io = TokioIo::new(Stall::new(stream, state.config.gap));
    let head = state.config.head;
    let service = service_fn(|req: Request<Incoming>| {
        let state = state.clone();
        async move {
            let started = std::time::Instant::now();
            let method = method_name(req.method());
            let (r, route) = answer(req, &state).await;
            log_request(method, route, &r, started.elapsed());
            Ok::<_, Infallible>(r)
        }
    });
    // An error here is the client's or a timeout's; the connection just ends.
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(head)
        .max_headers(MAX_HEADERS)
        .max_header_size(MAX_HEAD)
        .serve_connection(io, service)
        .await;
}

/// The method as the log writes it: a method of RFC 9110 or "other", so
/// no client text reaches the log.
fn method_name(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::PATCH => "PATCH",
        Method::TRACE => "TRACE",
        Method::CONNECT => "CONNECT",
        _ => "other",
    }
}

/// The request log line of SYN-01.13: only words of Larsal's own and numbers.
fn request_line(method: &str, route: &str, r: &Response<Body>, took: Duration) -> String {
    let size = r.body().size_hint().exact().unwrap_or(0);
    format!(
        "{method} {route} {} {size} bytes {} ms",
        r.status().as_u16(),
        took.as_millis()
    )
}

fn log_request(method: &str, route: &str, r: &Response<Body>, took: Duration) {
    crate::log(format_args!("{}", request_line(method, route, r, took)));
}

/// The reply to one request and the name its log line gives it.
async fn answer(req: Request<Incoming>, state: &State) -> (Response<Body>, &'static str) {
    if let Some(status) = head_over_limits(&req) {
        return (closing(reply(status, Vec::new())), "head");
    }
    let found = routes::find(req.method().as_str(), req.uri().path());
    let name = match found {
        Match::Route(route) => route.name(),
        Match::NotFound => "not_found",
        Match::MethodNotAllowed(_) => "method_not_allowed",
    };
    let (bucket, limit) = match found {
        Match::Route(route) if route.is_signin() => (Bucket::SignIn, state.config.rate.signin),
        _ if req.method() == Method::GET => (Bucket::Read, state.config.rate.reads),
        _ => (Bucket::Write, state.config.rate.writes),
    };
    let (head, mut body) = req.into_parts();
    let r = if let Some(wait) = state.auth.over_limit(state.ip, bucket, limit) {
        rate_limited(wait)
    } else if body.size_hint().lower() > state.config.max_body {
        error(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::TooLarge)
    } else {
        match found {
            Match::Route(route) => run(route, &head.headers, &mut body, state).await,
            Match::NotFound => error(StatusCode::NOT_FOUND, ErrorCode::NotFound),
            Match::MethodNotAllowed(allow) => {
                let mut r = error(StatusCode::METHOD_NOT_ALLOWED, ErrorCode::MethodNotAllowed);
                r.headers_mut()
                    .insert(header::ALLOW, HeaderValue::from_static(allow));
                r
            }
        }
    };
    // A reply that leaves the request body unread (429, 413, 411, 428, 412
    // before the upload, 401, a 400 from the length) ends the connection,
    // so the rest of the body is never read, nor taken for a next request
    // (syn01_10_t09, syn01_6_t10).
    let r = if body.is_end_stream() { r } else { closing(r) };
    (r, name)
}

/// One route; a session route first needs its caller (401 without one).
async fn run(
    route: Route,
    headers: &hyper::HeaderMap,
    body: &mut Incoming,
    state: &State,
) -> Response<Body> {
    let (blobs, auth) = (&state.blobs, &*state.auth);
    let caller = if route.needs_session() {
        match auth::caller(headers, blobs, auth).await {
            Ok(caller) => Some(caller),
            Err(refused) => return *refused,
        }
    } else {
        None
    };
    match (route, caller) {
        (Route::Health, _) => reply(StatusCode::OK, Health::this_server().to_json()),
        (Route::Accounts, _) => accounts::create(body, blobs, auth).await,
        (Route::Challenge, _) => accounts::challenge(body, blobs, auth).await,
        (Route::SignIn, _) => accounts::sign_in(body, blobs, auth).await,
        (Route::SignOut, Some(c)) => accounts::sign_out(c, blobs).await,
        (Route::DeviceDelete(device), Some(c)) => accounts::revoke(c, device, blobs).await,
        (Route::Vaults, Some(c)) => vaults::list(blobs, c.account).await,
        (Route::VaultGet(id), Some(c)) => vaults::get(headers, id, c.account, blobs).await,
        (Route::VaultPut(id), Some(c)) => vaults::put(headers, body, id, c.account, blobs).await,
        // A session route always has its caller here.
        (_, None) => unauthorized(),
    }
}

/// Larsal's own head checks, made on the parsed head (SYN-01.10): the request
/// line first, then each header field. hyper has already refused a head
/// over [`MAX_HEAD`], so these sums stay small.
fn head_over_limits(req: &Request<Incoming>) -> Option<StatusCode> {
    // The request line: method, space, target, space, version.
    let parts = [
        req.method().as_str().len(),
        1,
        req.uri().to_string().len(),
        1,
        8,
    ];
    let line = parts.iter().fold(0usize, |sum, n| sum.saturating_add(*n));
    if line > MAX_REQUEST_LINE {
        return Some(StatusCode::URI_TOO_LONG);
    }
    let field_over = req.headers().iter().any(|(name, value)| {
        name.as_str()
            .len()
            .saturating_add(2)
            .saturating_add(value.len())
            > MAX_HEADER_FIELD
    });
    field_over.then_some(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
}

/// A reply with `Cache-Control: no-store` (SYN-01.13); a body that is not
/// empty is JSON.
pub(crate) fn reply(status: StatusCode, body: Vec<u8>) -> Response<Body> {
    let json = !body.is_empty();
    let mut r = Response::new(Either::Left(Full::new(Bytes::from(body))));
    *r.status_mut() = status;
    let headers = r.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if json {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    r
}

/// An error reply: the body `{"error":"<code>"}` only (SYN-01.9).
pub(crate) fn error(status: StatusCode, code: ErrorCode) -> Response<Body> {
    reply(status, code.body())
}

/// The reply ends the connection: a client that sent a head over the limits
/// gets no second request on it.
fn closing(mut r: Response<Body>) -> Response<Body> {
    r.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    r
}

/// A connection that fails with `TimedOut` when a read or a write has waited
/// `gap` with no byte moving either way (SYN-01.11: no gap over 60 s between
/// two reads of a body or two writes of a reply).
// ponytail: one timer for both directions; hyper also keeps a read waiting
// while a route works, so a route that takes longer than `gap` before its
// reply starts ends the connection too.
struct Stall<S> {
    io: S,
    gap: Duration,
    timer: Pin<Box<Sleep>>,
    armed: bool,
}

impl<S> Stall<S> {
    fn new(io: S, gap: Duration) -> Self {
        Self {
            io,
            gap,
            timer: Box::pin(tokio::time::sleep(gap)),
            armed: false,
        }
    }

    /// Called when the inner stream waits: starts the clock at the first
    /// wait, and fails once `gap` has passed with no progress.
    fn waiting(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if !self.armed {
            let now = Instant::now();
            let deadline = now.checked_add(self.gap).unwrap_or(now);
            self.timer.as_mut().reset(deadline);
            self.armed = true;
        }
        match self.timer.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::ErrorKind::TimedOut.into()),
            Poll::Pending => Ok(()),
        }
    }

    fn track<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match poll {
            Poll::Pending => match self.waiting(cx) {
                Ok(()) => Poll::Pending,
                Err(e) => Poll::Ready(Err(e)),
            },
            ready => {
                self.armed = false;
                ready
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Stall<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.io).poll_read(cx, buf);
        this.track(cx, poll)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Stall<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.io).poll_write(cx, buf);
        this.track(cx, poll)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.io).poll_flush(cx);
        this.track(cx, poll)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.io).poll_shutdown(cx);
        this.track(cx, poll)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::tests::block_on;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// At most 5 s, so a broken timer fails the test instead of hanging it.
    async fn within<F: Future>(f: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), f)
            .await
            .unwrap()
    }

    #[test]
    fn syn01_11_defaults_are_the_cards_values() {
        let c = Config::default();
        assert_eq!(c.max_body, 1_140_850_688);
        let secs = [c.handshake, c.head, c.gap].map(|d| d.as_secs());
        assert_eq!(secs, [30, 30, 60]);
        let r = c.rate;
        assert_eq!((r.signin, r.writes, r.reads), (10, 60, 200));
    }

    /// SYN-01.13: the log line holds the method, the route's name, the
    /// status, the size and the time, and nothing a client chose; a method
    /// outside RFC 9110 is "other".
    #[test]
    fn syn01_13_request_line_holds_only_names_and_numbers() {
        let r = reply(StatusCode::CREATED, b"{\"a\":1}".to_vec());
        let line = request_line("POST", "accounts", &r, Duration::from_millis(12));
        assert_eq!(line, "POST accounts 201 7 bytes 12 ms");
        assert_eq!(method_name(&Method::GET), "GET");
        assert_eq!(method_name(&Method::DELETE), "DELETE");
        let odd = Method::from_bytes(b"TOKEN-abc").unwrap();
        assert_eq!(method_name(&odd), "other");
    }

    #[test]
    fn syn01_11_stalled_write_ends_after_gap() {
        block_on(async {
            // The peer never reads: after 64 bytes the write waits.
            let (ours, _peer) = tokio::io::duplex(64);
            let gap = Duration::from_millis(200);
            let mut io = Stall::new(ours, gap);
            let start = Instant::now();
            let err = within(io.write_all(&[0u8; 4096])).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert!(start.elapsed() >= gap);
        });
    }

    #[test]
    fn syn01_11_stalled_read_ends_after_gap() {
        block_on(async {
            let (ours, _peer) = tokio::io::duplex(64);
            let gap = Duration::from_millis(200);
            let mut io = Stall::new(ours, gap);
            let start = Instant::now();
            let err = within(io.read(&mut [0u8; 16])).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert!(start.elapsed() >= gap);
        });
    }

    #[test]
    fn syn01_11_bytes_within_the_gap_keep_the_connection() {
        block_on(async {
            let (ours, mut peer) = tokio::io::duplex(64);
            let gap = Duration::from_millis(300);
            let mut io = Stall::new(ours, gap);
            tokio::spawn(async move {
                for _ in 0..6 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    peer.write_all(b"x").await.unwrap();
                }
            });
            // Six bytes over 600 ms, never more than 100 ms apart: twice the
            // gap in all, and no timeout.
            let mut got = [0u8; 6];
            within(io.read_exact(&mut got)).await.unwrap();
            assert_eq!(&got, b"xxxxxx");
        });
    }
}
