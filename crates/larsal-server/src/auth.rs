//! Sessions, the server's clock and the rate limits (SYN-01.5, SYN-01.12,
//! SYN-04.3 to SYN-04.5).
//!
//! A session token is 32 bytes from larsal-crypto's random source; the store
//! keeps only its SHA-256 and looks the session up by it, so a copy of the
//! store signs nobody in (SV-03). Every expiry is checked on the server's
//! clock, never the client's. Over a rate limit a request gets 429 with
//! `Retry-After` and nothing else runs.
//!
//! Test seams (the `test-seams` feature, which only larsal-server's own tests
//! turn on): the clock can be set, so expiry is tested without waiting.

use crate::Error;
use crate::blobs::Blobs;
use crate::http::{Body, blocking, error, failed};
use crate::store::{self, Caller};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Response, StatusCode};
use larsal_proto::messages::ErrorCode;
use larsal_proto::routes;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// The window of every rate limit (SYN-01.12: per IP address and minute).
const WINDOW: u64 = 60;
/// Past this many windows, ended ones are dropped before a new one is made.
const PRUNE_AT: usize = 4096;

/// What a request counts against (SYN-01.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Bucket {
    /// The sign-in routes.
    SignIn,
    /// POST, PUT and DELETE on every other route.
    Write,
    /// GET on every other route.
    Read,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: u64,
    count: u32,
}

/// The server's sign-in state that is not in the store: its origin, its
/// clock and the rate limit windows.
pub(crate) struct Auth {
    /// The origin a sign-in signs (SYN-04.4): `https://127.0.0.1:<port>`.
    pub(crate) origin: String,
    windows: Mutex<HashMap<(IpAddr, Bucket), Window>>,
    /// Test seam: when not 0, the clock reads this second.
    #[cfg(any(test, feature = "test-seams"))]
    pub(crate) fixed: std::sync::atomic::AtomicU64,
}

impl Auth {
    pub(crate) fn new(origin: String) -> Self {
        Self {
            origin,
            windows: Mutex::new(HashMap::new()),
            #[cfg(any(test, feature = "test-seams"))]
            fixed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The server's clock, in whole seconds since 1970 (UTC).
    pub(crate) fn now(&self) -> u64 {
        #[cfg(any(test, feature = "test-seams"))]
        {
            let fixed = self.fixed.load(std::sync::atomic::Ordering::SeqCst);
            if fixed != 0 {
                return fixed;
            }
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// Counts one request of `ip` against `bucket`, whose limit is `limit`
    /// a minute. `Some(seconds)` when it is over the limit: the request
    /// gets 429 with that `Retry-After` and is not counted.
    // ponytail: one fixed window per IP address and bucket, ended ones
    // dropped past PRUNE_AT; a shared store comes with hosting (E19).
    pub(crate) fn over_limit(&self, ip: IpAddr, bucket: Bucket, limit: u32) -> Option<u64> {
        let now = self.now();
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() >= PRUNE_AT && !windows.contains_key(&(ip, bucket)) {
            windows.retain(|_, w| now < w.start.saturating_add(WINDOW));
        }
        let w = windows.entry((ip, bucket)).or_insert(Window {
            start: now,
            count: 0,
        });
        if now >= w.start.saturating_add(WINDOW) || now < w.start {
            *w = Window {
                start: now,
                count: 0,
            };
        }
        if w.count >= limit {
            let end = w.start.saturating_add(WINDOW);
            return Some(end.saturating_sub(now).max(1));
        }
        w.count = w.count.saturating_add(1);
        None
    }
}

/// 429 with `Retry-After` in seconds (SYN-01.12; RFC 6585 section 4).
pub(crate) fn rate_limited(seconds: u64) -> Response<Body> {
    let mut r = error(StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited);
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
    r
}

/// 401 with `WWW-Authenticate: Bearer` and one body for every reason
/// (SYN-01.5, SYN-04.4).
pub(crate) fn unauthorized() -> Response<Body> {
    let mut r = error(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized);
    r.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    r
}

/// The SHA-256 of a session token: the session's key in the store.
pub(crate) fn token_hash(token: &[u8]) -> Result<[u8; 32], Error> {
    <[u8; 32]>::try_from(larsal_crypto::hash::sha256(&[token]).expose())
        .map_err(|_| Error::new("a SHA-256 that is not 32 bytes"))
}

/// The caller of a session route (SYN-01.5): the live session named by the
/// one `Authorization: Bearer` line. A missing, malformed, unknown,
/// expired or revoked token gets [`unauthorized`], all alike (boxed, as a
/// reply is large); the token is hashed at once and never kept.
pub(crate) async fn caller(
    headers: &HeaderMap,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Result<Caller, Box<Response<Body>>> {
    let lines: Vec<&[u8]> = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let Some(token) = routes::bearer(&lines) else {
        return Err(Box::new(unauthorized()));
    };
    let hash = token_hash(token.expose()).map_err(|e| Box::new(failed(&e)))?;
    drop(token);
    let (b, now) = (blobs.clone(), auth.now());
    match blocking(move || b.store(|db| store::use_session(db, &hash, now))).await {
        Ok(Some(caller)) => Ok(caller),
        Ok(None) => Err(Box::new(unauthorized())),
        Err(e) => Err(Box::new(failed(&e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::Ordering;

    /// SYN-01.12, SYN-01 T19's window: the limit per IP address and bucket
    /// in one minute, the wait in `Retry-After`, then a new window.
    #[test]
    fn syn01_12_t19_window_limit_retry_after_and_reset() {
        let auth = Auth::new(String::new());
        let t0 = 1_800_000_000;
        auth.fixed.store(t0, Ordering::SeqCst);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        for _ in 0..3 {
            assert_eq!(auth.over_limit(ip, Bucket::SignIn, 3), None);
        }
        assert_eq!(auth.over_limit(ip, Bucket::SignIn, 3), Some(60));
        // Other buckets and other addresses have their own windows.
        assert_eq!(auth.over_limit(ip, Bucket::Write, 3), None);
        assert_eq!(auth.over_limit(other, Bucket::SignIn, 3), None);
        auth.fixed.store(t0 + 59, Ordering::SeqCst);
        assert_eq!(auth.over_limit(ip, Bucket::SignIn, 3), Some(1));
        auth.fixed.store(t0 + 60, Ordering::SeqCst);
        assert_eq!(auth.over_limit(ip, Bucket::SignIn, 3), None, "a new minute");
        // A limit of 0 refuses everything.
        assert_eq!(auth.over_limit(ip, Bucket::Read, 0), Some(60));
    }

    /// Ended windows are dropped once there are many, so the table stays
    /// bounded; a live one is kept with its count.
    #[test]
    fn syn01_12_ended_windows_are_pruned() {
        let auth = Auth::new(String::new());
        let t0 = 1_800_000_000;
        auth.fixed.store(t0, Ordering::SeqCst);
        for n in 0..PRUNE_AT {
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(u128::try_from(n).unwrap() + 1));
            assert_eq!(auth.over_limit(ip, Bucket::Read, 1), None);
        }
        auth.fixed.store(t0 + 30, Ordering::SeqCst);
        let live = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(auth.over_limit(live, Bucket::Read, 1), None);
        // F-251: that prune kept the windows of t0, which are still live:
        // the first is over its limit until t0 + 60.
        let first = IpAddr::V6(std::net::Ipv6Addr::from(1u128));
        assert_eq!(auth.over_limit(first, Bucket::Read, 1), Some(30));
        auth.fixed.store(t0 + 60, Ordering::SeqCst);
        let fresh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(auth.over_limit(fresh, Bucket::Read, 1), None);
        assert_eq!(auth.windows.lock().unwrap().len(), 2, "the ended ones went");
        assert_eq!(
            auth.over_limit(live, Bucket::Read, 1),
            Some(30),
            "count kept"
        );
    }

    #[test]
    fn syn01_5_token_hash_is_sha256() {
        // SHA-256 of 32 zero bytes.
        let want = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";
        let hex: String = token_hash(&[0; 32])
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, want);
    }
}
