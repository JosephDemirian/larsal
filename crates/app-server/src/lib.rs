//! App's sync server (E16; spec SYN-01, SYN-02): one binary that stores
//! locked vault files for App's clients and never opens them (P16).
//!
//! E16-S3 is the skeleton: [`data`] opens the data folder (SYN-02.1),
//! [`tls`] makes the demo certificate at the first start and gives its
//! fingerprint (SYN-01.2, P17), and [`http`] serves HTTPS on 127.0.0.1 with
//! the head and body limits, the timeouts and the health route (SYN-01.1,
//! SYN-01.3, SYN-01.9 to SYN-01.11, SYN-01.13, SYN-01.14). E16-S4 adds the
//! SQLite store (`store.rs`, SYN-02.2, SYN-02.3), the content-addressed
//! vault files with the compare-and-swap commit and the sweep at start
//! (`blobs.rs`, SYN-02.4 to SYN-02.8) and the vault routes (`vaults.rs`,
//! SYN-01.6). E16-S5 adds accounts, devices, the one-time challenge, the
//! signature check, sessions, revoke, 401 and 429 (`accounts.rs`,
//! `auth.rs`; SYN-04, SYN-01.5, SYN-01.12) and the request log line
//! (SYN-01.13). The sharing routes come with E18.
//!
//! Guarantees: the server listens on 127.0.0.1 only (architecture "Rules for
//! this part" 5); every request is untrusted, and no reply holds text from
//! a request. Its network and TLS code is the exception of P20 (LD-263 (18)):
//! tokio-rustls, rustls, ring, and rcgen for the TLS certificate and key
//! only. Every other hash comes from app-crypto.
#![forbid(unsafe_code)]
// Rust rule 4: requests come from the network. Test code is exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

mod accounts;
mod auth;
mod blobs;
pub mod data;
pub mod http;
mod store;
pub mod tls;
mod vaults;

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Why the server cannot start, in plain words. It never holds a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// One line of the server's log, on standard error (LD-321 (4): no
/// tracing crate). Callers give counts, statuses, route names, vault ids
/// and their own words only: never a header, a token, a nonce, a
/// signature, a code or request bytes (SYN-01.13).
// ponytail: plain stderr lines, no levels or filter; add them when a
// hosted server needs them (E19).
pub(crate) fn log(line: fmt::Arguments<'_>) {
    eprintln!("app-server: {line}");
}

/// A server ready to serve: its data folder is open, its certificate
/// loaded and its port bound on 127.0.0.1.
pub struct Server {
    listener: TcpListener,
    certificate: tls::Certificate,
    config: Arc<http::Config>,
    blobs: Arc<blobs::Blobs>,
    auth: Arc<auth::Auth>,
}

impl Server {
    /// Opens the data folder at `data` (made at the first start, SYN-02.1),
    /// locks it for this server, opens the store and sweeps what a crash
    /// left (SYN-02.2, SYN-02.6), loads or makes the demo certificate
    /// (SYN-01.2) and binds 127.0.0.1:`port` (0 asks the system for a free
    /// port). A sign-in signs the origin `https://127.0.0.1:<bound port>`
    /// (SYN-04.4).
    ///
    /// # Errors
    /// The folder is not safe or cannot be read or written, another server
    /// uses it, the store is from a newer server or fails, the certificate
    /// files are damaged, or the port cannot be bound.
    pub async fn start(
        data: &std::path::Path,
        port: u16,
        config: http::Config,
    ) -> Result<Self, Error> {
        let folder = data::open(data).await?;
        let blobs = Arc::new(blobs::Blobs::open(&folder)?);
        let certificate = tls::Certificate::load_or_make(&folder)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|e| Error::new(format!("cannot listen on 127.0.0.1:{port}: {e}")))?;
        let bound = listener
            .local_addr()
            .map_err(|e| Error::new(format!("cannot read the bound address: {e}")))?;
        let origin = app_proto::signin::origin(&bound.ip().to_string(), bound.port());
        Ok(Self {
            listener,
            certificate,
            config: Arc::new(config),
            blobs,
            auth: Arc::new(auth::Auth::new(origin)),
        })
    }

    /// The address the server listens on.
    ///
    /// # Errors
    /// The system cannot tell the bound address.
    pub fn address(&self) -> Result<SocketAddr, Error> {
        self.listener
            .local_addr()
            .map_err(|e| Error::new(format!("cannot read the bound address: {e}")))
    }

    /// The certificate the server presents.
    #[must_use]
    pub fn certificate(&self) -> &tls::Certificate {
        &self.certificate
    }

    /// Serves until the process ends.
    ///
    /// # Errors
    /// The certificate's key does not fit rustls.
    pub async fn serve(self) -> Result<(), Error> {
        let tls = self.certificate.server_config()?;
        http::serve(self.listener, tls, self.config, self.blobs, self.auth).await;
        Ok(())
    }

    /// The test seams of this server ([`TestSeams`]).
    #[cfg(any(test, feature = "test-seams"))]
    #[must_use]
    pub fn test_seams(&self) -> TestSeams {
        TestSeams {
            blobs: self.blobs.clone(),
            auth: self.auth.clone(),
        }
    }
}

/// Tests only: built with the `test-seams` feature, which only app-server's
/// own tests turn on (a dev-dependency on itself), so a release server has
/// none of this. The test clock, and SYN-04.11's helper that registers a
/// second device before E17-S2 brings the approval.
#[cfg(any(test, feature = "test-seams"))]
pub struct TestSeams {
    blobs: Arc<blobs::Blobs>,
    auth: Arc<auth::Auth>,
}

#[cfg(any(test, feature = "test-seams"))]
impl TestSeams {
    /// Sets the server's clock to `seconds` since 1970; 0 gives the system
    /// clock back. Every expiry and rate limit window reads this clock.
    pub fn set_clock(&self, seconds: u64) {
        self.auth
            .fixed
            .store(seconds, std::sync::atomic::Ordering::SeqCst);
    }

    /// SYN-04.11: registers `public_key` (65 SEC1 bytes) as another device
    /// of `account`. `Ok(None)` when the key is registered already.
    ///
    /// # Errors
    /// The account does not exist, or the store fails.
    pub fn add_device(
        &self,
        account: &app_proto::messages::AccountId,
        public_key: &[u8; 65],
        name: &str,
    ) -> Result<Option<app_proto::messages::DeviceId>, Error> {
        let mut id = [0u8; 16];
        app_crypto::random::fill(&mut id)
            .map_err(|e| Error::new(format!("cannot draw an id: {e}")))?;
        let device = app_proto::messages::DeviceId::from_bytes(id);
        let now = self.auth.now();
        let added = self
            .blobs
            .store(|db| store::add_device(db, account, &device, public_key, name, now))?;
        Ok(added.then_some(device))
    }
}

#[cfg(test)]
mod tests {
    /// P22, LD-303 (4): SQLite is built from libsqlite3-sys's bundled
    /// source, not taken from macOS: the library that runs is the version
    /// of the bundled header.
    #[test]
    fn p22_sqlite_is_built_from_its_bundled_source() {
        assert_eq!(
            rusqlite::version_number(),
            rusqlite::ffi::SQLITE_VERSION_NUMBER
        );
        assert_eq!(rusqlite::version(), "3.53.2");
    }
}
