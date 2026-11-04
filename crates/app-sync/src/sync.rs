//! The sync loop (SYN-03.5, SYN-03.6, SYN-03.10; P3), its timing (SYN-03.4)
//! and the rollback guard (SYN-03.7; P4).
//!
//! Guarantees:
//! - A run makes at most 3 tries. Before the 2nd and the 3rd it waits a
//!   random 1 to 3 s from app-crypto (after a 412) or the `Retry-After` of
//!   a 429, at most 300 s, on the caller's [`Clock`].
//! - A server version lower than the highest seen, or the highest seen
//!   with other bytes, is refused before it is opened: nothing is merged or
//!   uploaded (`MSG-SYNC-ROLLBACK`). An opened copy older by its newest
//!   change time is merged and warns (`MSG-SYNC-WENT-BACK`); a lower file
//!   version or weaker KDF settings warn by name, never by value
//!   (`MSG-SYNC-WEAKER`).
//! - The local vault is never left half merged: [`Local::merge`] merges and
//!   saves in one step, or changes nothing.
//! - Nothing runs by itself: [`Schedule`] only answers whether a run is
//!   due; the caller runs it.
//! - A 404 never makes the vault again (no `If-None-Match: *` outside
//!   [`first_upload`]).

use crate::client::{Fail, Reply, Server, Signer};
use crate::state::{Link, Measures};
use app_core::guard::kdf_lower;
use app_proto::messages::{VaultId, VaultVersion};

/// The tries of one run (SYN-03.6, LD-263 (2)).
pub const TRIES: u32 = 3;
/// The debounce after a save (SYN-03.4, LD-273 (1)).
pub const AFTER_SAVE_MS: u64 = 2_000;
/// The rhythm while unlocked (SYN-03.4).
pub const EVERY_MS: u64 = 60_000;

/// Milliseconds on some clock, and waits on it. The product uses
/// [`SystemClock`]; tests a clock that moves only when told.
pub trait Clock: Send + Sync {
    /// Now, in milliseconds.
    fn now_ms(&self) -> u64;
    /// Waits `ms` milliseconds.
    fn sleep_ms(&self, ms: u64);
}

/// The system's clock: Unix time, and the thread's sleep.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// When the runs of one vault start (SYN-03.4): after the unlock; 2 s
/// after a save, so a burst of saves gives one run; every 60 s while
/// unlocked; and on Sync now. Never while locked. A trigger while the
/// vault is busy (saving, unsaved changes, an open editor, a disk event)
/// or while a run is open waits, so one more run follows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schedule {
    unlocked: bool,
    /// A run is asked for (the unlock, Sync now, a tick that came).
    asked: bool,
    /// The time the debounced run after the last save is due.
    save_due: Option<u64>,
    /// The next 60-second tick.
    next_tick: u64,
    running: bool,
}

impl Schedule {
    /// The vault was unlocked at `now`: a run, and ticks from then on.
    pub fn unlocked(&mut self, now: u64) {
        *self = Self {
            unlocked: true,
            asked: true,
            next_tick: now.saturating_add(EVERY_MS),
            ..Self::default()
        };
    }

    /// The vault was locked or closed: nothing is due until the next
    /// unlock.
    pub fn locked(&mut self) {
        *self = Self::default();
    }

    /// The vault was saved at `now`: a run 2 s after the last save.
    pub fn saved(&mut self, now: u64) {
        if self.unlocked {
            self.save_due = Some(now.saturating_add(AFTER_SAVE_MS));
        }
    }

    /// Sync now: a run at the next look; nothing while locked.
    pub fn sync_now(&mut self) {
        if self.unlocked {
            self.asked = true;
        }
    }

    /// Whether a run starts at `now`. `busy` is the vault's state of
    /// SYN-03.4. A run that starts is open until [`Schedule::finished`].
    pub fn start(&mut self, now: u64, busy: bool) -> bool {
        if !self.unlocked {
            return false;
        }
        if now >= self.next_tick {
            self.asked = true;
            // The next tick after `now` on the 60-second grid of the unlock.
            let late = now.saturating_sub(self.next_tick) / EVERY_MS;
            self.next_tick = self
                .next_tick
                .saturating_add(late.saturating_add(1).saturating_mul(EVERY_MS));
        }
        let saved = self.save_due.is_some_and(|due| now >= due);
        if self.running || busy || !(self.asked || saved) {
            return false;
        }
        self.asked = false;
        if saved {
            self.save_due = None;
        }
        self.running = true;
        true
    }

    /// The run that [`Schedule::start`] began ended.
    pub fn finished(&mut self) {
        self.running = false;
    }

    /// Whether a run is open.
    #[must_use]
    pub fn running(&self) -> bool {
        self.running
    }
}

/// The open vault this run syncs: app-ffi's session.
pub trait Local {
    /// The local file's bytes and the open vault's measures, when nothing
    /// keeps the vault busy (SYN-03.4); `None` when something does.
    fn read(&self) -> Option<(Vec<u8>, Measures)>;

    /// SYN-03.5 step 3: opens `server` with this Mac's key, merges the open
    /// vault (the source) into it (the target) with a same-vault merge,
    /// puts the result in place of the open vault and saves it on this Mac,
    /// as one step under the vault's lock.
    fn merge(&self, server: &[u8]) -> Merge;
}

/// What [`Local::merge`] did.
#[derive(Debug)]
pub enum Merge {
    /// Merged and saved on this Mac.
    Done {
        /// The server copy's measures, as opened.
        copy: Measures,
        /// The saved result's measures.
        result: Measures,
        /// This Mac had something the server copy lacks: upload `saved`.
        changed: bool,
        /// The bytes saved on this Mac.
        saved: Vec<u8>,
    },
    /// The copy does not open with this Mac's key (SYN-03.8).
    WrongKey,
    /// The copy opens but has another root group id.
    OtherVault,
    /// The vault became busy (edited, saving, locked): nothing changed.
    Busy,
    /// The copy cannot be read, or the save failed: nothing changed, or
    /// the merged result waits for the next save.
    Failed,
}

/// A link's status (SYN-03.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The last run ended well, at this time (ms).
    Synced(u64),
    /// A run is open.
    Syncing,
    /// No connection; the next trigger tries again.
    Offline,
    /// The server copy opens with other credentials (SYN-03.8).
    NeedsPassword,
    /// The server copy uses a key this Mac retired (SYN-03.9, E16-S7b).
    ReplacedPassword,
    /// Signed out of the server (SYN-03.10).
    SignedOut,
    /// The run failed; the message says why.
    Error,
}

/// The messages of SYN-03 (App's own words; the server's text is never
/// shown, SYN-01.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `MSG-SYNC-CERT-CHANGED`.
    CertChanged,
    /// `MSG-SYNC-NOT-SERVER`.
    NotServer,
    /// `MSG-SYNC-OTHER-KEY`.
    OtherKey,
    /// `MSG-SYNC-OTHER-VAULT`.
    OtherVault,
    /// `MSG-SYNC-ROLLBACK`.
    Rollback,
    /// `MSG-SYNC-WENT-BACK`.
    WentBack,
    /// `MSG-SYNC-WEAKER`, with the settings' names.
    Weaker(Vec<&'static str>),
    /// `MSG-SYNC-BUSY`.
    Busy,
    /// `MSG-SYNC-SIGNED-OUT`.
    SignedOut,
    /// `MSG-SYNC-NO-WRITE`.
    NoWrite,
    /// `MSG-SYNC-GONE`.
    Gone,
    /// `MSG-SYNC-TOO-LARGE`.
    TooLarge,
    /// `MSG-SYNC-ERROR`.
    Error,
}

impl Message {
    /// The message's id in SYN-03's table.
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::CertChanged => "MSG-SYNC-CERT-CHANGED",
            Self::NotServer => "MSG-SYNC-NOT-SERVER",
            Self::OtherKey => "MSG-SYNC-OTHER-KEY",
            Self::OtherVault => "MSG-SYNC-OTHER-VAULT",
            Self::Rollback => "MSG-SYNC-ROLLBACK",
            Self::WentBack => "MSG-SYNC-WENT-BACK",
            Self::Weaker(_) => "MSG-SYNC-WEAKER",
            Self::Busy => "MSG-SYNC-BUSY",
            Self::SignedOut => "MSG-SYNC-SIGNED-OUT",
            Self::NoWrite => "MSG-SYNC-NO-WRITE",
            Self::Gone => "MSG-SYNC-GONE",
            Self::TooLarge => "MSG-SYNC-TOO-LARGE",
            Self::Error => "MSG-SYNC-ERROR",
        }
    }

    /// The words of SYN-03's table for vault `name` and server `address`.
    #[must_use]
    pub fn text(&self, name: &str, address: &str) -> String {
        match self {
            Self::CertChanged => format!(
                "The server \"{address}\" shows a different certificate. App stopped syncing with it."
            ),
            Self::NotServer => format!("\"{address}\" is not an App sync server."),
            Self::OtherKey => format!(
                "The server's copy of \"{name}\" opens with another password or key. Enter the password or key this copy opens with."
            ),
            Self::OtherVault => {
                "The server's copy is a different vault. Nothing was merged or uploaded.".into()
            }
            Self::Rollback => format!(
                "The server sent an older copy of \"{name}\" than this Mac has seen. Nothing was merged or uploaded."
            ),
            Self::WentBack => format!(
                "The server's copy of \"{name}\" went back in time. App merged it, so nothing newer was lost, and uploaded the result."
            ),
            Self::Weaker(settings) => format!(
                "The server's copy of \"{name}\" used {} weaker than this Mac has seen.",
                settings.join(" and ")
            ),
            Self::Busy => {
                "The server's copy kept changing. App will try again at the next sync.".into()
            }
            Self::SignedOut => format!("This Mac is signed out of \"{address}\"."),
            Self::NoWrite => {
                "You can't change this vault on the server. Your changes are kept on this Mac."
                    .into()
            }
            Self::Gone => {
                format!("The server no longer has \"{name}\". Your copy on this Mac is unchanged.")
            }
            Self::TooLarge => format!("\"{name}\" is too large for the server."),
            Self::Error => {
                format!("Sync with \"{address}\" failed. Your copy on this Mac is unchanged.")
            }
        }
    }
}

/// What a run ended with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The link's status; `None` when the run stopped before its merge
    /// because the vault became busy (the next save starts a new run).
    pub status: Option<Status>,
    /// The messages to show, in order: a warning of the guard, then the
    /// failure, if any.
    pub messages: Vec<Message>,
}

impl Report {
    fn of(status: Status, messages: Vec<Message>) -> Self {
        Self {
            status: Some(status),
            messages,
        }
    }

    fn error(message: Message) -> Self {
        Self::of(Status::Error, vec![message])
    }
}

/// How one try ended.
enum Try {
    Done(Report),
    /// 412: another Mac uploaded first.
    Conflict,
    /// 429: wait this many seconds.
    Limited(u64),
}

/// SYN-03.10's replies other than the ones a step expects.
fn other(r: &Reply) -> Try {
    match r.status {
        403 => Try::Done(Report::error(Message::NoWrite)),
        404 => Try::Done(Report::error(Message::Gone)),
        412 => Try::Conflict,
        413 => Try::Done(Report::error(Message::TooLarge)),
        429 => Try::Limited(r.retry_after),
        500..=599 => Try::Done(Report::of(Status::Offline, Vec::new())),
        _ => Try::Done(Report::error(Message::Error)),
    }
}

fn failed(f: Fail) -> Try {
    match f {
        Fail::Limited(seconds) => Try::Limited(seconds),
        Fail::Offline => Try::Done(Report::of(Status::Offline, Vec::new())),
        Fail::SignedOut => Try::Done(Report::of(Status::SignedOut, vec![Message::SignedOut])),
        Fail::CertChanged => Try::Done(Report::error(Message::CertChanged)),
        Fail::Address | Fail::Protocol | Fail::Key => Try::Done(Report::error(Message::Error)),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = app_crypto::hash::sha256(&[bytes]);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.expose());
    out
}

/// SYN-03.7: the guard's warnings for an opened `copy` against the values
/// kept for the last server version accepted or uploaded.
fn warnings(seen: &Measures, copy: &Measures) -> Vec<Message> {
    let mut out = Vec::new();
    if copy.newest < seen.newest {
        out.push(Message::WentBack);
    }
    let mut weaker = Vec::new();
    // The major version only, as APP-05.26 (FMT-16.20).
    if copy.version.major < seen.version.major {
        weaker.push("file format version");
    }
    if kdf_lower(&seen.kdf, &copy.kdf) {
        weaker.push("key derivation");
    }
    if !weaker.is_empty() {
        out.push(Message::Weaker(weaker));
    }
    out
}

/// The link after this Mac accepted or uploaded version `version` with
/// `measures`; the newest change time only moves up.
fn record(link: &mut Link, version: u64, server_sha: [u8; 32], measures: &Measures) {
    link.highest = link.highest.max(version);
    link.server_sha = server_sha;
    link.seen = Measures {
        newest: link.seen.newest.max(measures.newest),
        ..*measures
    };
}

/// SYN-03.5 step 4: the upload of `bytes` over version `base`.
fn upload<K: Signer>(
    server: &mut Server<K>,
    link: &mut Link,
    bytes: &[u8],
    base: u64,
    measures: &Measures,
    now: u64,
    mut messages: Vec<Message>,
) -> Try {
    let r = match server.put(&link.vault_id, bytes, Some(base)) {
        Ok(r) => r,
        Err(f) => return failed(f),
    };
    match (r.status, r.version) {
        (200 | 201, Some(v)) if v > base => {
            let sha = sha256(bytes);
            record(link, v, sha, measures);
            link.local_sha = sha;
            Try::Done(Report::of(Status::Synced(now), messages))
        }
        (200 | 201, _) => {
            messages.push(Message::Error);
            Try::Done(Report::of(Status::Error, messages))
        }
        _ => match other(&r) {
            // A guard warning of this try is kept with the failure.
            Try::Done(mut report) => {
                messages.append(&mut report.messages);
                report.messages = messages;
                Try::Done(report)
            }
            again => again,
        },
    }
}

/// One try of SYN-03.5.
fn one_try<K: Signer>(
    server: &mut Server<K>,
    link: &mut Link,
    local: &dyn Local,
    clock: &dyn Clock,
) -> Try {
    let r = match server.get(&link.vault_id, link.highest) {
        Ok(r) => r,
        Err(f) => return failed(f),
    };
    match r.status {
        304 => {
            let Some((bytes, measures)) = local.read() else {
                return Try::Done(Report {
                    status: None,
                    messages: Vec::new(),
                });
            };
            if sha256(&bytes) == link.local_sha {
                return Try::Done(Report::of(Status::Synced(clock.now_ms()), Vec::new()));
            }
            let base = link.highest;
            upload(
                server,
                link,
                &bytes,
                base,
                &measures,
                clock.now_ms(),
                Vec::new(),
            )
        }
        200 => {
            let Some(version) = r.version else {
                return Try::Done(Report::error(Message::Error));
            };
            let sha = sha256(&r.body);
            // SYN-03.7: before opening, only local state stops a rollback.
            if version < link.highest || (version == link.highest && sha != link.server_sha) {
                return Try::Done(Report::error(Message::Rollback));
            }
            match local.merge(&r.body) {
                Merge::Done {
                    copy,
                    result,
                    changed,
                    saved,
                } => {
                    let messages = warnings(&link.seen, &copy);
                    if changed {
                        // The copy is accepted; the local hash is recorded
                        // only once the server holds the same content.
                        record(link, version, sha, &copy);
                        upload(
                            server,
                            link,
                            &saved,
                            version,
                            &result,
                            clock.now_ms(),
                            messages,
                        )
                    } else {
                        record(link, version, sha, &copy);
                        link.local_sha = sha256(&saved);
                        Try::Done(Report::of(Status::Synced(clock.now_ms()), messages))
                    }
                }
                Merge::WrongKey => {
                    Try::Done(Report::of(Status::NeedsPassword, vec![Message::OtherKey]))
                }
                Merge::OtherVault => Try::Done(Report::error(Message::OtherVault)),
                Merge::Busy => Try::Done(Report {
                    status: None,
                    messages: Vec::new(),
                }),
                Merge::Failed => Try::Done(Report::error(Message::Error)),
            }
        }
        _ => other(&r),
    }
}

/// The wait before the 2nd or 3rd try after a 412: 1 to 3 s from
/// app-crypto's random source (SYN-03.6).
fn jitter_ms() -> u64 {
    1_000_u64.saturating_add(app_crypto::random::below(2_001).map_or(2_000, u64::from))
}

/// One run of SYN-03.5 for `link`: at most [`TRIES`] tries, the waits on
/// `clock`. `link` holds the new values when the run moved them.
pub fn run<K: Signer>(
    server: &mut Server<K>,
    link: &mut Link,
    local: &dyn Local,
    clock: &dyn Clock,
) -> Report {
    let mut tries: u32 = 0;
    loop {
        tries = tries.saturating_add(1);
        let wait = match one_try(server, link, local, clock) {
            Try::Done(report) => return report,
            Try::Conflict if tries >= TRIES => return Report::error(Message::Busy),
            // SYN-03.10 (LD-273 (9)): a 429 on the 3rd try is Offline.
            Try::Limited(_) if tries >= TRIES => return Report::of(Status::Offline, Vec::new()),
            Try::Conflict => jitter_ms(),
            Try::Limited(seconds) => seconds
                .min(crate::client::MAX_RETRY_AFTER)
                .saturating_mul(1_000),
        };
        clock.sleep_ms(wait);
    }
}

/// SYN-03.1 step 3: the first upload of a vault's saved `bytes` with
/// `If-None-Match: *`, under a new `vault_id` from app-crypto's random
/// source. On 201 the link's server values are the new version's.
///
/// # Errors
/// The report of the failure: nothing was linked.
pub fn first_upload<K: Signer>(
    server: &mut Server<K>,
    bytes: &[u8],
) -> Result<(VaultId, u64), Report> {
    let mut id = [0u8; 16];
    app_crypto::random::fill(&mut id).map_err(|_| Report::error(Message::Error))?;
    let vault_id = VaultId::from_bytes(id);
    let r = server
        .put(&vault_id, bytes, None)
        .map_err(|f| match failed(f) {
            Try::Done(report) => report,
            _ => Report::of(Status::Offline, Vec::new()),
        })?;
    match (r.status, r.version) {
        (201, Some(v)) => Ok((vault_id, v)),
        (201, None) => Err(Report::error(Message::Error)),
        _ => Err(match other(&r) {
            Try::Done(report) => report,
            _ => Report::of(Status::Offline, Vec::new()),
        }),
    }
}

/// SYN-03.7: a listed version of `link`'s vault lower than the highest
/// seen is refused; App downloads nothing.
#[must_use]
pub fn check_listed(link: &Link, listed: &[VaultVersion]) -> Option<Report> {
    listed
        .iter()
        .any(|v| v.id == link.vault_id && v.version < link.highest)
        .then(|| Report::error(Message::Rollback))
}

/// The SHA-256 the state keeps of `bytes`.
#[must_use]
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

#[cfg(test)]
mod tests;
