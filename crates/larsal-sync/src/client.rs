//! The client side of Larsal's sync protocol (SYN-01, SYN-04): one pinned
//! server (SYN-01.2), sign-up and sign-in with this Mac's device key
//! (SYN-04.2, SYN-04.4), the session token (SYN-04.6) and the vault routes
//! (SYN-01.6).
//!
//! Guarantees:
//! - Every request goes through larsal-platform `net.rs` with the pinned
//!   certificate: only the certificate whose SHA-256 is the pin passes, and
//!   a changed one is [`Fail::CertChanged`] before any request byte is sent.
//! - The session token is moved out of the sign-in reply at once: the
//!   reply's body goes into a `SecretBytes` before it is read, and the
//!   `Authorization` value lives only in a `SecretString` (LD-325 (5) (b)).
//!   It is never written to disk, a log or the pasteboard (SYN-04.6), and
//!   [`Server`]'s `Debug` output never shows it.
//! - A 401 signs in again once and repeats the request; a second 401 is
//!   [`Fail::SignedOut`] (SYN-03.10, SYN-04.6).
//! - Every reply is read with its route's limit (SYN-01.10): JSON records
//!   1 MiB, a vault [`MAX_VAULT`]; a longer one is [`Fail::Protocol`].
//! - No text from the server is kept or shown (SYN-01.9): only statuses,
//!   the `ETag`, `Retry-After` and the records of SYN-01.8.

use larsal_crypto::base64::{self, Form};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_platform::net::{self, Answer, Method, NetError, Timeouts};
use larsal_proto::limits::{MAX_JSON, MAX_VAULT};
use larsal_proto::messages::{
    AccountCreate, AccountCreated, Challenge, ChallengeRequest, DeviceId, Health, Session, SignIn,
    VaultId, VaultVersion, read_vault_list,
};
use larsal_proto::{routes, signin};
use std::fmt;
use std::time::Duration;

/// The longest `Retry-After` Larsal waits, and the wait for one it cannot
/// read (SYN-03.10, LD-273 (9)).
pub const MAX_RETRY_AFTER: u64 = 300;

/// Why a call gave no reply the sync loop can use (SYN-03.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    /// Not an address Larsal takes: `https://<host>:<port>`, nothing more.
    Address,
    /// The server shows another certificate than the pinned one (SYN-01.2).
    CertChanged,
    /// No connection, a time limit, a TLS error other than a changed
    /// certificate, or a 5xx (SYN-03.10).
    Offline,
    /// A 401 after one new sign-in, or a sign-in refused (SYN-03.10).
    SignedOut,
    /// A 429 on a sign-in route: wait this many seconds (SYN-03.10).
    Limited(u64),
    /// A reply that breaks SYN-01: a record that does not read, a body
    /// over its limit (SYN-01.10), a missing `ETag`, or a status the route
    /// never gives.
    Protocol,
    /// The device key refused to sign, or this Mac has no device for the
    /// server yet (SYN-04.1).
    Key,
}

/// The sign-in key (SYN-04.1). The product key is larsal-platform's
/// `DeviceKey` (larsal-sync's `sync` feature); tests wrap it to change a
/// signature.
pub trait Signer {
    /// The public key, 65 SEC1 bytes.
    ///
    /// # Errors
    /// The key cannot give it.
    fn public_key(&self) -> Result<[u8; 65], Fail>;

    /// The P-256 signature of `message` (X9.62 DER).
    ///
    /// # Errors
    /// The key refused to sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Fail>;
}

#[cfg(feature = "sync")]
impl Signer for larsal_platform::device_key::DeviceKey {
    fn public_key(&self) -> Result<[u8; 65], Fail> {
        Self::public_key(self).map_err(|_| Fail::Key)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Fail> {
        Self::sign(self, message).map_err(|_| Fail::Key)
    }
}

/// One reply of a vault route.
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// The version the `ETag` names (SYN-01.6), if it is canonical.
    pub version: Option<u64>,
    /// The wait of a 429 in seconds (SYN-03.10).
    pub retry_after: u64,
    /// The body, at most the route's limit.
    pub body: Vec<u8>,
}

/// The status and sizes only.
impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("body", &self.body.len())
            .finish()
    }
}

/// `address` as `(base URL, origin)`: `https://`, a host of letters,
/// digits, dots and dashes (an IPv4 address included), an optional port
/// (443 when left out) and an optional `/`. The origin is SYN-04.4's, with
/// the port always written.
#[must_use]
pub fn parse_address(address: &str) -> Option<(String, String)> {
    let rest = address.strip_prefix("https://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => {
            let digits = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
            (host, digits.then(|| port.parse::<u16>().ok()).flatten()?)
        }
        None => (rest, 443),
    };
    let ok = |b: u8| b.is_ascii_alphanumeric() || b == b'.' || b == b'-';
    if host.is_empty() || host.len() > 253 || !host.bytes().all(ok) || port == 0 {
        return None;
    }
    let host = host.to_ascii_lowercase();
    Some((
        format!("https://{host}:{port}"),
        signin::origin(&host, port),
    ))
}

/// SYN-01.2: the SHA-256 of the certificate the server at `address` shows,
/// read in one handshake that sends no request.
///
/// # Errors
/// [`Fail::Address`], or [`Fail::Offline`] when no handshake happened.
pub fn fingerprint(address: &str) -> Result<[u8; 32], Fail> {
    let (base, _) = parse_address(address).ok_or(Fail::Address)?;
    net::read_fingerprint(&base, timeouts()).map_err(|_| Fail::Offline)
}

/// SYN-01.2's printed form: 64 uppercase hex digits in 8 groups of 8.
#[must_use]
pub fn printed(pin: &[u8; 32]) -> String {
    let hex: Vec<String> = pin.iter().map(|b| format!("{b:02X}")).collect();
    hex.chunks(4)
        .map(<[String]>::concat)
        .collect::<Vec<_>>()
        .join(" ")
}

/// [`printed`] read back, spaces ignored and either case taken.
#[must_use]
pub fn read_printed(text: &str) -> Option<[u8; 32]> {
    let hex: Vec<u8> = text.bytes().filter(|b| *b != b' ').collect();
    if hex.len() != 64 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut pin = [0u8; 32];
    for (byte, pair) in pin.iter_mut().zip(hex.chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(pin)
}

/// The time limits: a vault may be 1 GiB (SYN-01.10), so the total limit
/// is long; a stalled read still ends after 30 s.
fn timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(15),
        read: Duration::from_secs(30),
        total: Duration::from_secs(30 * 60),
    }
}

/// SYN-03.10: the wait of a 429. A whole number of seconds, at most
/// [`MAX_RETRY_AFTER`]; anything else (missing, a date, a fraction, a sign)
/// is [`MAX_RETRY_AFTER`], however many digits it has.
#[must_use]
pub fn retry_after(value: Option<&str>) -> u64 {
    value
        .map(|v| v.trim_matches(|c| c == ' ' || c == '\t'))
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(MAX_RETRY_AFTER, |s| s.min(MAX_RETRY_AFTER))
}

fn net_fail(e: &NetError) -> Fail {
    match e {
        NetError::CertificateChanged => Fail::CertChanged,
        NetError::TooLarge | NetError::Url => Fail::Protocol,
        _ => Fail::Offline,
    }
}

/// The sign-in routes' replies other than their success (SYN-03.10).
fn signin_fail(a: &Answer) -> Fail {
    match a.status {
        401 => Fail::SignedOut,
        429 => Fail::Limited(retry_after(a.header("retry-after"))),
        500..=599 => Fail::Offline,
        _ => Fail::Protocol,
    }
}

/// Larsal's own server, pinned, with this Mac's device and session.
pub struct Server<K: Signer> {
    net: net::Client,
    base: String,
    origin: String,
    device: Option<(DeviceId, K)>,
    /// `Bearer <token>` of the session (SYN-01.5), in memory only.
    bearer: Option<SecretString>,
}

/// The base URL only: never the token or a key.
impl<K: Signer> fmt::Debug for Server<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("base", &self.base)
            .field("signed_in", &self.bearer.is_some())
            .finish_non_exhaustive()
    }
}

impl<K: Signer> Server<K> {
    /// The server at `address`, pinned to `pin` (SYN-01.2). Opens no
    /// connection.
    ///
    /// # Errors
    /// [`Fail::Address`], or [`Fail::Offline`] when the TLS setup fails.
    pub fn new(address: &str, pin: [u8; 32]) -> Result<Self, Fail> {
        let (base, origin) = parse_address(address).ok_or(Fail::Address)?;
        Ok(Self {
            net: net::Client::pinned(timeouts(), pin).map_err(|_| Fail::Offline)?,
            base,
            origin,
            device: None,
            bearer: None,
        })
    }

    /// The canonical address, `https://<host>:<port>`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.base
    }

    /// This Mac's device on the server and its key (SYN-04.1).
    pub fn set_device(&mut self, id: DeviceId, key: K) {
        self.device = Some((id, key));
        self.bearer = None;
    }

    /// Tests only (`test-server`): sign the origin of the server behind the
    /// test proxy, `https://127.0.0.1:<port>` (SYN-04.4 binds a signature to
    /// the origin the client connected to).
    #[cfg(feature = "test-server")]
    pub fn sign_for_port(&mut self, port: u16) {
        self.origin = signin::origin("127.0.0.1", port);
    }

    /// Whether a session token is held (tests and the status).
    #[must_use]
    pub fn signed_in(&self) -> bool {
        self.bearer.is_some()
    }

    fn send(
        &self,
        method: Method<'_>,
        path: &str,
        headers: &[(&str, &str)],
        limit: u64,
    ) -> Result<Answer, Fail> {
        let url = format!("{}{path}", self.base);
        self.net
            .send(method, &url, headers, limit)
            .map_err(|e| net_fail(&e))
    }

    /// SYN-01.14: whether the server answers `GET /v1/health` as a Larsal
    /// sync server.
    ///
    /// # Errors
    /// [`Fail::CertChanged`] or [`Fail::Offline`].
    pub fn health(&self) -> Result<bool, Fail> {
        let a = self.send(Method::Get, routes::HEALTH, &[], MAX_JSON as u64)?;
        Ok(a.status == 200 && Health::read(&a.body).is_ok_and(|h| h.is_larsal_server()))
    }

    /// SYN-04.2: a new account whose first device is `key`, named "Mac"
    /// (never the computer's name). The key is this Mac's device from now
    /// on; the caller keeps the ids.
    ///
    /// # Errors
    /// As [`Fail`]; a 409 (the key is registered already) is
    /// [`Fail::Protocol`].
    pub fn sign_up(&mut self, key: K) -> Result<AccountCreated, Fail> {
        let body = AccountCreate {
            device_public_key: key.public_key()?,
            device_name: "Mac".to_owned(),
        }
        .to_json();
        let a = self.send(Method::Post(&body), routes::ACCOUNTS, &[], MAX_JSON as u64)?;
        if a.status != 201 {
            return Err(signin_fail(&a));
        }
        let made = AccountCreated::read(&a.body).map_err(|_| Fail::Protocol)?;
        self.set_device(made.device_id, key);
        Ok(made)
    }

    /// SYN-04.4: a challenge, signed with the device key, for a session.
    ///
    /// # Errors
    /// [`Fail::Key`] without a device; [`Fail::SignedOut`] when the server
    /// refuses the signature; else as [`Fail`].
    pub fn sign_in(&mut self) -> Result<(), Fail> {
        self.sign_in_with(|key, message| key.sign(message))
    }

    /// [`Server::sign_in`] with the signature `sign` makes.
    fn sign_in_with(
        &mut self,
        sign: impl FnOnce(&K, &[u8]) -> Result<Vec<u8>, Fail>,
    ) -> Result<(), Fail> {
        self.bearer = None;
        let (device, key) = self.device.as_ref().ok_or(Fail::Key)?;
        let device = *device;
        let request = ChallengeRequest { device_id: device }.to_json();
        let limit = MAX_JSON as u64;
        let a = self.send(Method::Post(&request), routes::CHALLENGE, &[], limit)?;
        if a.status != 200 {
            return Err(signin_fail(&a));
        }
        let challenge = Challenge::read(&a.body).map_err(|_| Fail::Protocol)?;
        let message =
            signin::message(&self.origin, &challenge.nonce, &device).map_err(|_| Fail::Protocol)?;
        let signed = SignIn {
            device_id: device,
            nonce: challenge.nonce,
            signature: sign(key, &message)?,
        }
        .to_json();
        let mut a = self.send(Method::Post(&signed), routes::SIGNIN, &[], limit)?;
        // LD-325 (5) (b): the reply holds the token; its bytes move into a
        // wiping buffer before anything reads them.
        let body = SecretBytes::new(std::mem::take(&mut a.body));
        if a.status != 200 {
            return Err(signin_fail(&a));
        }
        let session = Session::read(body.expose()).map_err(|_| Fail::Protocol)?;
        let token = base64::encode_secret(Form::Url, session.token.expose());
        let mut bearer = String::with_capacity(token.len().saturating_add(7));
        bearer.push_str("Bearer ");
        bearer.push_str(token.expose());
        self.bearer = Some(SecretString::new(bearer));
        Ok(())
    }

    /// A request that needs the session (SYN-01.5): signs in first when
    /// there is none, and once more on a 401 (SYN-04.6).
    fn call(
        &mut self,
        method: Method<'_>,
        path: &str,
        headers: &[(&str, &str)],
        limit: u64,
    ) -> Result<Reply, Fail> {
        let mut fresh = false;
        if self.bearer.is_none() {
            self.sign_in()?;
            fresh = true;
        }
        loop {
            let a = {
                let bearer = self.bearer.as_ref().ok_or(Fail::SignedOut)?;
                let mut all = vec![("authorization", bearer.expose())];
                all.extend_from_slice(headers);
                self.send(method, path, &all, limit)?
            };
            if a.status != 401 {
                return Ok(Reply {
                    status: a.status,
                    version: a.header("etag").and_then(routes::etag_version),
                    retry_after: retry_after(a.header("retry-after")),
                    body: a.body,
                });
            }
            self.bearer = None;
            if fresh {
                return Err(Fail::SignedOut);
            }
            self.sign_in()?;
            fresh = true;
        }
    }

    /// `GET /v1/vaults` (SYN-01.6).
    ///
    /// # Errors
    /// As [`Fail`]; a status other than 200, 429 and 5xx, or a list that
    /// does not read, is [`Fail::Protocol`].
    pub fn list(&mut self) -> Result<Vec<VaultVersion>, Fail> {
        let r = self.call(Method::Get, routes::VAULTS, &[], MAX_JSON as u64)?;
        match r.status {
            200 => read_vault_list(&r.body).map_err(|_| Fail::Protocol),
            429 => Err(Fail::Limited(r.retry_after)),
            500..=599 => Err(Fail::Offline),
            _ => Err(Fail::Protocol),
        }
    }

    /// `GET /v1/vaults/{vault}`, with `If-None-Match` of version `seen`
    /// when it is 1 or more (SYN-03.5 step 1).
    ///
    /// # Errors
    /// As [`Fail`]; every status is a [`Reply`].
    pub fn get(&mut self, vault: &VaultId, seen: u64) -> Result<Reply, Fail> {
        let tag = routes::etag(seen);
        let headers: &[(&str, &str)] = if seen >= 1 {
            &[("if-none-match", &tag)]
        } else {
            &[]
        };
        self.call(Method::Get, &vault_path(vault), headers, MAX_VAULT)
    }

    /// `PUT /v1/vaults/{vault}`: an update of version `base` with
    /// `If-Match`, or a new vault with `If-None-Match: *` when `base` is
    /// `None` (SYN-01.6, SYN-03.1 step 3).
    ///
    /// # Errors
    /// As [`Fail`]; every status is a [`Reply`].
    pub fn put(&mut self, vault: &VaultId, bytes: &[u8], base: Option<u64>) -> Result<Reply, Fail> {
        let tag = base.map(routes::etag);
        let header = match &tag {
            Some(tag) => ("if-match", tag.as_str()),
            None => ("if-none-match", "*"),
        };
        self.call(
            Method::Put(bytes),
            &vault_path(vault),
            &[header],
            MAX_JSON as u64,
        )
    }
}

fn vault_path(vault: &VaultId) -> String {
    format!("{}/{vault}", routes::VAULTS)
}

#[cfg(test)]
pub(crate) mod tests;
