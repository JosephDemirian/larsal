//! The Reports screen (E5-S7): Health Check (FEA-05.11 to FEA-05.18), the
//! online breach check (FEA-06), Statistics (FEA-07), Passkeys (INT-04.52,
//! INT-04.53) and Browser (INT-02.32), over larsal-core.
//!
//! Guarantees (architecture, larsal-ffi Must; AGENTS.md rule 4):
//! - no record carries a password, a hash or a protected value: rows hold
//!   entry ids, titles, ratings, counts, hosts and reason texts only;
//! - Health Check and Statistics use the session's rating cache (LD-137):
//!   the screen fills it first in small steps ([`Session::rate`]) and shows
//!   [`Session::rating_progress`], so a lock between two steps cancels the
//!   work (FEA-05.18, FEA-07.17);
//! - the breach check sends nothing until [`Session::breach_start`], the
//!   user's press (FEA-06.1). Its requests go out in [`Session::breach_step`]
//!   calls, outside the session lock, at most 6 at a time; a lock or close
//!   drops the check with every hash and count, and answers that arrive
//!   after it are dropped (FEA-06.12). The HTTPS client is larsal-platform
//!   `net` (feature `net`); without it nothing can be sent (SN-05).

use crate::edit::{chain, custom_value, iso_utc, refused, site_access};
use crate::session::{LarsalError, Session};
use crate::views::{
    EntryRow, Offset, PASSKEY, count, find, has_totp_fields, live, now, parse_id, plain, plain_in,
    row, unix,
};
use larsal_core::breach::{Check, MAX_PARALLEL, RANGE_URL, exposure};
use larsal_core::edit::{change_entry, holds_reference};
use larsal_core::expiry::expire_now;
use larsal_core::health::{Detail, Level, Reason, health_check, score, skip_checked, toggle_skip};
use larsal_core::stats::{FileInfo, statistics};
use larsal_core::time::Instant;
use larsal_model::{Argon2Kind, Cipher, Entry, Kdf, Time, Uuid, Vault};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

/// How far the rating cache is filled: the progress of Health Check and
/// Statistics (LD-137 (4)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct RateProgress {
    /// Passwords rated.
    pub done: u32,
    /// Passwords to rate: live entries with a password.
    pub total: u32,
}

/// One Health Check row (FEA-05.17, frame `reports-reports-health-check`).
/// No secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HealthRow {
    /// The entry, for its logo, title, user name and change date.
    pub entry: EntryRow,
    /// The pill: `Expired`, `Reused`, else the health level's name.
    pub problem: String,
    /// The health score; may be negative.
    pub score: i64,
    /// The health level's name (FEA-05.4).
    pub level: String,
    /// The level's tooltip (FEA-05.17).
    pub level_tip: String,
    /// The reasons, in the order added (FEA-05.13, FEA-05.14).
    pub reasons: Vec<String>,
    /// The details, the reasons' tooltip.
    pub details: Vec<String>,
    /// The strength estimate E, rounded to whole bits.
    pub bits: u32,
    /// The strength level as 0 (Bad) to 4 (Excellent), for the meter.
    pub segments: u8,
    /// Skipped in reports (shown only with "Show Skipped Entries").
    pub excluded: bool,
    /// Past its expiry date.
    pub expired: bool,
}

/// The Health Check (FEA-05.11 to FEA-05.16). No secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HealthReport {
    /// Candidates, lowest score first, equal scores in tree order (D-05-5);
    /// expired ones listed, skipped ones only when asked.
    pub rows: Vec<HealthRow>,
    /// Live entries with a password ("of 21 passwords").
    pub passwords: u32,
    /// Evaluated passwords that score Good or better.
    pub healthy: u32,
    /// Different passwords among the listed `Reused` rows.
    pub reused_passwords: u32,
    /// Some evaluated entry is skipped in reports: "Show Skipped Entries"
    /// is offered (FEA-05.15).
    pub any_skipped: bool,
}

/// One bar of a Statistics chart.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Bar {
    /// Its label, for example `12–15`.
    pub label: String,
    /// Passwords in it.
    pub count: u32,
}

/// The Statistics tab (FEA-07; frame `reports-reports-statistics`). No
/// secret: numbers and the vault's name, description, path and times.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StatsReport {
    /// `stat.entries`.
    pub entries: u64,
    /// `stat.groups`, the root included.
    pub groups: u64,
    /// `stat.unique_pw`.
    pub unique_pw: u64,
    /// `stat.reused_pw`.
    pub reused_pw: u64,
    /// `stat.max_reuse`.
    pub max_reuse: u64,
    /// `stat.weak_pw`.
    pub weak_pw: u64,
    /// `stat.short_pw`.
    pub short_pw: u64,
    /// `stat.expired`.
    pub expired: u64,
    /// `stat.totp`.
    pub totp: u64,
    /// `stat.passkeys`.
    pub passkeys: u64,
    /// `stat.avg_len`, rounded, in UTF-16 units (FEA-07.12, FEA-07.18).
    pub avg_len: u64,
    /// `stat.excluded`.
    pub excluded: u64,
    /// `info.name`.
    pub name: String,
    /// `info.description`.
    pub description: String,
    /// `info.location`, the full path.
    pub location: String,
    /// `info.created`, unix seconds.
    pub created: i64,
    /// `info.last_saved`: the file's modification time, unix seconds.
    pub last_saved: Option<i64>,
    /// `info.unsaved`.
    pub unsaved: bool,
    /// The file's name.
    pub file_name: String,
    /// The file's size in bytes.
    pub size: Option<u64>,
    /// The format version read, for example `4.1`; empty when never read.
    pub version: String,
    /// The cipher and key derivation, for example `AES-256 · Argon2id,
    /// 64 MiB, 2 iterations`.
    pub encryption: String,
    /// Entries in the recycle bin.
    pub in_bin: u32,
    /// Attachments of the counted entries.
    pub attachments: u32,
    /// Their total size in bytes.
    pub attachment_bytes: u64,
    /// Password lengths in UTF-16 units: `Under 8` (only when some are),
    /// `8–11`, `12–15`, `16–19`, `20 and more`.
    pub lengths: Vec<Bar>,
    /// Passwords by their entry's last change: `This month` (under 31
    /// days), `1–6 months`, `Older` (183 days and more).
    pub ages: Vec<Bar>,
}

/// One Passkeys row (INT-04.52). No secret: the private key never leaves.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyRow {
    /// The entry.
    pub entry: EntryRow,
    /// The relying party.
    pub site: String,
    /// The passkey's user name (INT-04.4), else the entry's.
    pub user: String,
    /// The entry also has a password.
    pub has_password: bool,
    /// The entry also has one-time password settings.
    pub has_totp: bool,
}

/// One Browser row (INT-02.32). No secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserRow {
    /// The entry.
    pub entry: EntryRow,
    /// Hosts of the site access item's Allow list.
    pub allow: Vec<String>,
    /// Hosts of its Deny list.
    pub deny: Vec<String>,
    /// MI02-14 words of the options that are on, as resolved (INT-02.14).
    pub options: Vec<String>,
}

/// One connected browser (INT-02.1): an association of the vault.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConnectedBrowser {
    /// The association name.
    pub name: String,
    /// When it was connected, unix seconds, when stored as ISO 8601.
    pub since: Option<i64>,
    /// The stored text otherwise (D-INT02-2); empty with `since`.
    pub since_text: String,
}

/// The Browser report (INT-02.32). No secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserReport {
    /// Entries with site access hosts or an option on, in tree order (the
    /// screen sorts them by title).
    pub rows: Vec<BrowserRow>,
    /// The vault's associations, by name (MI02-15).
    pub browsers: Vec<ConnectedBrowser>,
}

/// The online breach check's progress (FEA-06.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct BreachProgress {
    /// Requests answered.
    pub done: u32,
    /// Requests in this check.
    pub total: u32,
    /// Every request answered, or the first failure stopped the check.
    pub finished: bool,
}

/// One finding (FEA-06.9). No secret: no hash, no password.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BreachRow {
    /// The entry.
    pub entry: EntryRow,
    /// Times the password was seen, more than 0.
    pub count: u64,
    /// The exposure text of the count (`MSG-BREACH-COUNT-*`).
    pub exposure: String,
}

/// The breach check's results so far (FEA-06.8 to FEA-06.10).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BreachReport {
    /// Findings: count highest first, equal counts in tree order.
    pub rows: Vec<BreachRow>,
    /// Entries whose password was checked (FEA-06.2).
    pub checked: u32,
    /// The highest count found; 0 without findings.
    pub largest: u64,
    /// When the check finished, unix seconds.
    pub checked_at: Option<i64>,
    /// `MSG-BREACH-FAILED` with its plain reason; never a response body.
    pub error: Option<String>,
    /// The progress.
    pub progress: BreachProgress,
}

/// A GET's status and body, or why it failed.
type Answer = Result<(u16, Vec<u8>), String>;

/// One GET of the breach check: the status and body, or a plain-language
/// reason. The app's is the HTTPS client of larsal-platform `net`; tests put a
/// fake or a local server here.
pub(crate) trait Fetch: Send + Sync {
    /// GET `url` with `headers`.
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Answer;
}

/// The product transport: one client per check, made on the user's press
/// (SN-01: making it opens no connection).
struct Net {
    #[cfg(feature = "net")]
    client: Result<larsal_platform::net::Client, String>,
}

impl Net {
    fn new() -> Self {
        #[cfg(test)]
        tests::NETS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self {
            #[cfg(feature = "net")]
            client: larsal_platform::net::Client::new(larsal_platform::net::Timeouts::default())
                .map_err(|e| e.to_string()),
        }
    }
}

impl Fetch for Net {
    #[cfg(feature = "net")]
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Answer {
        use larsal_platform::net::NetError;
        let client = self.client.as_ref().map_err(Clone::clone)?;
        let limit = u64::try_from(larsal_core::breach::MAX_BODY).unwrap_or(u64::MAX);
        match client.get(url, headers, limit) {
            Ok(body) => Ok((200, body)),
            // larsal-core words the status (FEA-06.8).
            Err(NetError::Status(code)) => Ok((code, Vec::new())),
            Err(NetError::TooLarge) => Err("the service's answer was too large".to_owned()),
            Err(e) => Err(e.to_string()),
        }
    }

    #[cfg(not(feature = "net"))]
    fn get(&self, _: &str, _: &[(&str, &str)]) -> Answer {
        Err("this build of Larsal has no network code".to_owned())
    }
}

/// A running or finished online breach check of one vault (FEA-06.12:
/// dropped on lock and close, which drops every hash and count).
pub(crate) struct Breach {
    check: Check,
    /// Tells this check from a later one: answers of another are dropped.
    run: u64,
    /// Prefixes sent and not yet answered.
    sent: HashSet<String>,
    done: u32,
    total: u32,
    error: Option<String>,
    checked_at: Option<i64>,
    fetch: Arc<dyn Fetch>,
}

impl Breach {
    fn finished(&self) -> bool {
        self.error.is_some() || self.done >= self.total
    }

    fn progress(&self) -> BreachProgress {
        BreachProgress {
            done: self.done,
            total: self.total,
            finished: self.finished(),
        }
    }
}

/// Now at full clock precision (MOD-09.2): an entry expired now in this
/// second already counts as expired.
fn instant_now() -> Instant {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Instant {
        secs: i64::try_from(since.as_secs())
            .ok()
            .and_then(Time::from_unix)
            .unwrap_or_default(),
        nanos: since.subsec_nanos(),
    }
}

static RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The short local date and time of the details (FEA-05.14), for example
/// `Oct 1, 2026, 02:00`.
fn short_time(t: Time, offset: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let Some(c) = t.0.checked_add(offset).and_then(|s| Time(s).to_civil()) else {
        return String::new();
    };
    let month = usize::try_from(c.month.saturating_sub(1)).unwrap_or(0);
    format!(
        "{} {}, {}, {:02}:{:02}",
        MONTHS.get(month).unwrap_or(&"Jan"),
        c.day,
        c.year,
        c.hour,
        c.minute
    )
}

/// The cipher and key derivation in the words of APP-07 (M07-07).
fn encryption_text(v: &Vault) -> String {
    let cipher = match v.encryption.cipher {
        Cipher::Aes256 => "AES-256",
        Cipher::Twofish256 => "Twofish-256",
        Cipher::ChaCha20 => "ChaCha20",
    };
    let kdf = match v.encryption.kdf {
        Kdf::AesKdf { rounds } => format!("AES-KDF, {} rounds", grouped(rounds)),
        Kdf::Argon2 {
            kind,
            iterations,
            memory_kib,
            ..
        } => {
            let name = if kind == Argon2Kind::Id {
                "Argon2id"
            } else {
                "Argon2d"
            };
            let memory = if memory_kib >= 1024 && memory_kib.is_multiple_of(1024) {
                format!("{} MiB", memory_kib / 1024)
            } else {
                format!("{memory_kib} KiB")
            };
            let word = if iterations == 1 {
                "iteration"
            } else {
                "iterations"
            };
            format!("{name}, {memory}, {} {word}", grouped(iterations))
        }
    };
    format!("{cipher} · {kdf}")
}

/// `1234567` as `1,234,567`.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The vault's associations (INT-02.1): the prefix as hex bytes of its
/// ASCII text (AGENTS.md rule 1), then the name.
const ASSOCIATION: &[u8] = &[
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x42, 0x52, 0x4F, 0x57, 0x53, 0x45, 0x52, 0x5F,
];

/// MI02-14's words for the four entry options, in the card's order.
const OPTIONS: [(&str, &str); 4] = [
    ("BrowserHideEntry", "hidden"),
    ("BrowserSkipAutoSubmit", "fill, no submit"),
    ("BrowserOnlyHttpAuth", "HTTP only"),
    ("BrowserNotHttpAuth", "not for HTTP"),
];

fn browsers(v: &Vault) -> Vec<ConnectedBrowser> {
    let mut out: Vec<ConnectedBrowser> = v
        .meta
        .custom_data
        .items
        .iter()
        .filter_map(|i| {
            let name = i.key.as_bytes().strip_prefix(ASSOCIATION)?;
            let name = std::str::from_utf8(name).ok()?.to_owned();
            let created = v.meta.custom_data.get(&format!("_CREATED_{name}"));
            let since = created.and_then(iso_utc);
            Some(ConnectedBrowser {
                since_text: if since.is_none() {
                    created.unwrap_or("").to_owned()
                } else {
                    String::new()
                },
                since,
                name,
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The options of `e` that are on (INT-02.14): the first group from its
/// group up that has the key decides, else the entry's own key.
fn options_on(v: &Vault, e: &Entry) -> Vec<String> {
    let mut holders = Vec::new();
    let groups = find(&v.root, e.uuid, &mut holders)
        .and_then(|_| holders.last())
        .map(|g| chain(v, g.uuid))
        .unwrap_or_default();
    OPTIONS
        .iter()
        .filter(|(key, _)| {
            groups
                .iter()
                .rev()
                .find_map(|g| g.custom_data.get(key).map(|x| x == "true"))
                .unwrap_or_else(|| custom_value(e, key.as_bytes()) == Some("true"))
        })
        .map(|(_, word)| (*word).to_owned())
        .collect()
}

/// The file's modification time, unix seconds.
fn modified(path: &Path) -> Option<i64> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_secs()).ok())
}

fn bars(items: &[(&str, usize)]) -> Vec<Bar> {
    items
        .iter()
        .map(|(label, n)| Bar {
            label: (*label).to_owned(),
            count: count(*n),
        })
        .collect()
}

/// The Option A rows that FEA-07 does not count: bin, attachments and the
/// two charts. Lengths in UTF-16 units, as FEA-07.18.
fn extra(v: &Vault, at: Time) -> (u32, u32, u64, Vec<Bar>, Vec<Bar>) {
    let in_bin = larsal_core::recycle::bin_id(v)
        .and_then(|id| v.root.find_group(id))
        .map_or(0, |b| count(b.all_entries().count()));
    let entries = live(v);
    let attachments = entries.iter().map(|e| e.attachments.len()).sum();
    let bytes = entries
        .iter()
        .flat_map(|e| &e.attachments)
        .map(|a| u64::try_from(a.data.expose().len()).unwrap_or(u64::MAX))
        .fold(0u64, u64::saturating_add);
    let with_pw: Vec<&&Entry> = entries
        .iter()
        .filter(|e| !e.value("Password").is_empty())
        .collect();
    let mut len = [0usize; 5];
    let mut age = [0usize; 3];
    for e in &with_pw {
        let units = e.value("Password").encode_utf16().count();
        let slot = match units {
            0..=7 => 0,
            8..=11 => 1,
            12..=15 => 2,
            16..=19 => 3,
            _ => 4,
        };
        if let Some(n) = len.get_mut(slot) {
            *n += 1;
        }
        let days = at.0.saturating_sub(e.times.last_modification.0) / 86_400;
        let slot = match days {
            ..31 => 0,
            31..183 => 1,
            _ => 2,
        };
        if let Some(n) = age.get_mut(slot) {
            *n += 1;
        }
    }
    let [short, a, b, c, d] = len;
    let mut lengths = Vec::new();
    if short > 0 {
        lengths.push(("Under 8", short));
    }
    lengths.extend([("8–11", a), ("12–15", b), ("16–19", c), ("20 and more", d)]);
    let [m, h, o] = age;
    (
        in_bin,
        count(attachments),
        bytes,
        bars(&lengths),
        bars(&[("This month", m), ("1–6 months", h), ("Older", o)]),
    )
}

fn ids(entries: &[String]) -> Result<Vec<Uuid>, LarsalError> {
    entries
        .iter()
        .map(|e| parse_id(e, LarsalError::UnknownEntry))
        .collect()
}

#[uniffi::export]
impl Session {
    /// How many live passwords of vault `vault` the rating cache holds
    /// (LD-137): the progress of Health Check and Statistics while the
    /// screen fills it with [`Session::rate`]. No secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn rating_progress(&self, vault: u64) -> Result<RateProgress, LarsalError> {
        self.with_open(vault, |v, _, rated| {
            let (done, total) = rated.progress(v);
            Ok(RateProgress {
                done: count(done),
                total: count(total),
            })
        })
    }

    /// The Health Check (FEA-05.11 to FEA-05.16) with the local offset
    /// `utc_offset` in seconds: expired entries listed, skipped ones only
    /// with `show_skipped` (FEA-05.15). Rates what the cache lacks first;
    /// call it off the main thread after [`Session::rate`] is done. No
    /// secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn health_report(
        &self,
        vault: u64,
        show_skipped: bool,
        utc_offset: i32,
    ) -> Result<HealthReport, LarsalError> {
        let offset = i64::from(utc_offset);
        self.with_open(vault, |v, _, rated| {
            let at = instant_now();
            let (report, bits) = rated.with_ratings(v, |r| {
                let report = health_check(r, v, at, &Offset(offset));
                let by_id: HashMap<Uuid, &Entry> =
                    live(v).into_iter().map(|e| (e.uuid, e)).collect();
                let bits: HashMap<Uuid, f64> = report
                    .rows(true, true)
                    .iter()
                    .filter_map(|row| Some((row.entry, r.stored(by_id.get(&row.entry)?))))
                    .collect();
                (report, bits)
            });
            let entries = live(v);
            let by_id: HashMap<Uuid, &Entry> = entries.iter().map(|e| (e.uuid, *e)).collect();
            let with_pw = entries.iter().filter(|e| !e.value("Password").is_empty());
            let passwords = with_pw.clone().count();
            let evaluated = with_pw
                .filter(|e| !holds_reference(e.value("Password")))
                .count();
            let all = report.rows(true, true).len();
            let when = |t: Time| short_time(t, offset);
            let mut reused: HashSet<String> = HashSet::new();
            let mut rows = Vec::new();
            for r in report.rows(show_skipped, true) {
                let Some(e) = by_id.get(&r.entry) else {
                    continue;
                };
                let is_reused = r.reasons.iter().any(|x| matches!(x, Reason::Reused(_)));
                let problem = if r.expired {
                    "Expired"
                } else if is_reused {
                    "Reused"
                } else {
                    r.level.name()
                };
                let details: Vec<String> = r.details.iter().map(|d| d.text(&when)).collect();
                if problem == "Reused" {
                    // Paths, not passwords, tell one reused password from
                    // another (FEA-05 security notes).
                    let uses: Vec<&str> = r
                        .details
                        .iter()
                        .zip(&details)
                        .filter(|(d, _)| matches!(d, Detail::UsedIn(_) | Detail::More))
                        .map(|(_, t)| t.as_str())
                        .collect();
                    reused.insert(uses.join("\n"));
                }
                let e_bits = bits.get(&r.entry).copied().unwrap_or(0.0);
                rows.push(HealthRow {
                    entry: row(v, e, at, rated, false),
                    problem: problem.to_owned(),
                    score: r.score,
                    level: r.level.name().to_owned(),
                    level_tip: r.level.tip().unwrap_or("").to_owned(),
                    reasons: r.reasons.iter().map(Reason::text).collect(),
                    details,
                    // `as` saturates; E is never negative.
                    bits: e_bits.round() as u32,
                    segments: Level::of(score(e_bits)).quality(),
                    excluded: r.excluded,
                    expired: r.expired,
                });
            }
            Ok(HealthReport {
                rows,
                passwords: count(passwords),
                healthy: count(evaluated.saturating_sub(all)),
                reused_passwords: count(reused.len()),
                any_skipped: report.excluded_toggle_visible(),
            })
        })
    }

    /// The Statistics tab (FEA-07, frame `reports-reports-statistics`) with
    /// the local offset `utc_offset`: larsal-core's one computation (FEA-07.21)
    /// plus the frame's file, format, encryption, bin, attachment and chart
    /// rows. Call it off the main thread. No secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn statistics_report(
        &self,
        vault: u64,
        utc_offset: i32,
    ) -> Result<StatsReport, LarsalError> {
        let offset = i64::from(utc_offset);
        self.with_edit(vault, |v, path, rated, edit| {
            let v: &Vault = v;
            let at = now();
            let location = path.to_string_lossy().into_owned();
            let saved = modified(path);
            let file = FileInfo {
                path: Some(&location),
                modified: saved.and_then(Time::from_unix),
                unsaved: edit.unsaved(),
            };
            let s = rated.with_ratings(v, |r| {
                statistics(r, v, &file, instant_now(), &Offset(offset))
            });
            let (in_bin, attachments, attachment_bytes, lengths, ages) = extra(v, at);
            Ok(StatsReport {
                entries: s.entries,
                groups: s.groups,
                unique_pw: s.unique_pw,
                reused_pw: s.reused_pw,
                max_reuse: s.max_reuse,
                weak_pw: s.weak_pw,
                short_pw: s.short_pw,
                expired: s.expired,
                totp: s.totp,
                passkeys: s.passkeys,
                avg_len: s.avg_len,
                excluded: s.excluded,
                name: s.name,
                description: s.description,
                location: s.location,
                created: unix(s.created),
                last_saved: s.last_saved.map(unix),
                unsaved: s.unsaved,
                file_name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                size: std::fs::metadata(path).ok().map(|m| m.len()),
                version: v
                    .read_version
                    .map(|r| format!("{}.{}", r.major, r.minor))
                    .unwrap_or_default(),
                encryption: encryption_text(v),
                in_bin,
                attachments,
                attachment_bytes,
                lengths,
                ages,
            })
        })
    }

    /// The Passkeys tab (INT-04.52): one row per live entry outside the bin
    /// with a private key field, in tree order (the screen sorts by
    /// title). No secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn passkeys_report(&self, vault: u64) -> Result<Vec<PasskeyRow>, LarsalError> {
        self.with_open(vault, |v, _, rated| {
            let at = instant_now();
            Ok(live(v)
                .into_iter()
                .filter(|e| e.fields().any(|(n, _)| n == "KPEX_PASSKEY_PRIVATE_KEY_PEM"))
                .map(|e| {
                    let user = plain(e, "KPEX_PASSKEY_USERNAME");
                    PasskeyRow {
                        entry: row(v, e, at, rated, false),
                        site: plain(e, "KPEX_PASSKEY_RELYING_PARTY"),
                        // LD-207: the vault's flag for UserName counts too.
                        user: if user.is_empty() {
                            plain_in(v, e, "UserName")
                        } else {
                            user
                        },
                        has_password: !e.value("Password").is_empty(),
                        has_totp: has_totp_fields(e),
                    }
                })
                .collect())
        })
    }

    /// Remove passkey from a report row (INT-04.46, entry menu path): every
    /// passkey field and the tag `Passkey` leave the entry, outside an edit
    /// session (no history item; times move to now).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `UnknownField` without a
    /// passkey.
    pub fn remove_entry_passkey(&self, vault: u64, entry: String) -> Result<(), LarsalError> {
        let id = parse_id(&entry, LarsalError::UnknownEntry)?;
        self.change(vault, |v, at| {
            let e = crate::views::entry_of(v, &entry)?;
            if !e.fields().any(|(n, _)| n.starts_with(PASSKEY)) {
                return Err(LarsalError::UnknownField);
            }
            let done = change_entry(v, id, at, |e| {
                let names: Vec<String> = e
                    .fields()
                    .map(|(n, _)| n)
                    .filter(|n| n.starts_with(PASSKEY))
                    .map(str::to_owned)
                    .collect();
                for n in names {
                    e.remove_field(&n);
                }
                larsal_core::tags::remove_from(e, "Passkey");
            })
            .map_err(|e| refused(&e))?;
            Ok(((), if done { vec![id] } else { Vec::new() }))
        })
    }

    /// The Browser tab (INT-02.32): live entries whose site access item
    /// lists a host or that have an entry option on (as resolved), and the
    /// vault's connected browsers. No secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn browser_report(&self, vault: u64) -> Result<BrowserReport, LarsalError> {
        self.with_open(vault, |v, _, rated| {
            let at = instant_now();
            let rows = live(v)
                .into_iter()
                .filter_map(|e| {
                    let (allow, deny) = site_access(e);
                    let options = options_on(v, e);
                    (!allow.is_empty() || !deny.is_empty() || !options.is_empty()).then(|| {
                        BrowserRow {
                            entry: row(v, e, at, rated, false),
                            allow,
                            deny,
                            options,
                        }
                    })
                })
                .collect();
            Ok(BrowserReport {
                rows,
                browsers: browsers(v),
            })
        })
    }

    /// `ACT-HC-EXPIRE` (FEA-05.18, FEA-06.11): the entries expire now
    /// (MOD-09.9), one change, no history item. How many changed.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry` (nothing changes then).
    pub fn expire_entries(&self, vault: u64, entries: Vec<String>) -> Result<u32, LarsalError> {
        let list = ids(&entries)?;
        self.change(vault, |v, at| {
            let n = expire_now(v, &list, at).map_err(|e| refused(&e))?;
            Ok((count(n), if n > 0 { list.clone() } else { Vec::new() }))
        })
    }

    /// Whether "Skip in Reports" shows checked for the entries: any of
    /// them is skipped (FEA-05.18).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`.
    pub fn skip_checked(&self, vault: u64, entries: Vec<String>) -> Result<bool, LarsalError> {
        let list = ids(&entries)?;
        self.with_vault(vault, |v| Ok(skip_checked(v, &list)))
    }

    /// `ACT-HC-EXCLUDE` "Skip in Reports" (FEA-05.18): every entry gets the
    /// opposite of [`Session::skip_checked`], each a change outside an edit
    /// session. How many changed.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry` (nothing changes then).
    pub fn toggle_skip_in_reports(
        &self,
        vault: u64,
        entries: Vec<String>,
    ) -> Result<u32, LarsalError> {
        let list = ids(&entries)?;
        self.change(vault, |v, at| {
            let n = toggle_skip(v, &list, at).map_err(|e| refused(&e))?;
            Ok((count(n), if n > 0 { list.clone() } else { Vec::new() }))
        })
    }

    /// `ACT-BREACH-RUN` (FEA-06.1): the user pressed "Check passwords
    /// online". Hashes the passwords to check (FEA-06.2, FEA-06.3) and
    /// makes the one HTTPS client; sends nothing yet. A check before it is
    /// dropped. With nothing to check it is finished at once (FEA-06.7).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn breach_start(&self, vault: u64) -> Result<BreachProgress, LarsalError> {
        self.breach_start_with(vault, Arc::new(Net::new()))
    }

    /// Sends the next requests of the check, at most 6 at a time, outside
    /// the session lock, and reads their answers (FEA-06.4 to FEA-06.8).
    /// Call it off the main thread until `finished`. An answer that comes
    /// after a lock, a close, Turn Off or a new start is dropped.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`; `Refused` when no check runs.
    pub fn breach_step(&self, vault: u64) -> Result<BreachProgress, LarsalError> {
        let next = self.with_breach(vault, |_, b| {
            let b = b.as_mut().ok_or_else(no_check)?;
            if b.finished() {
                return Ok(Err(b.progress()));
            }
            let mut batch = Vec::new();
            for r in b.check.requests() {
                if batch.len() >= MAX_PARALLEL {
                    break;
                }
                let Some(prefix) = r.url.strip_prefix(RANGE_URL).map(str::to_owned) else {
                    continue;
                };
                if b.sent.insert(prefix.clone()) {
                    batch.push((prefix, r));
                }
            }
            Ok(Ok((b.run, Arc::clone(&b.fetch), batch)))
        })?;
        let (run, fetch, batch) = match next {
            Ok(next) => next,
            Err(progress) => return Ok(progress),
        };
        let answers: Vec<(String, Answer)> = std::thread::scope(|s| {
            let running: Vec<_> = batch
                .iter()
                .map(|(prefix, r)| {
                    let fetch = Arc::clone(&fetch);
                    (prefix, s.spawn(move || fetch.get(&r.url, &r.headers)))
                })
                .collect();
            running
                .into_iter()
                .map(|(prefix, h)| {
                    let answer = h
                        .join()
                        .unwrap_or_else(|_| Err("the request stopped".to_owned()));
                    (prefix.clone(), answer)
                })
                .collect()
        });
        self.with_breach(vault, |_, b| {
            let Some(b) = b.as_mut().filter(|b| b.run == run) else {
                return Err(no_check());
            };
            for (prefix, answer) in answers {
                b.sent.remove(&prefix);
                if b.error.is_some() {
                    continue;
                }
                match answer {
                    Ok((status, body)) => match b.check.answer(&prefix, status, &body) {
                        Ok(()) => b.done = b.done.saturating_add(1),
                        Err(e) => b.error = Some(e.message()),
                    },
                    Err(reason) => {
                        b.error = Some(format!("The online check stopped early: {reason}"));
                    }
                }
            }
            if b.finished() && b.checked_at.is_none() {
                b.checked_at = Some(unix(now()));
            }
            Ok(b.progress())
        })
    }

    /// The breach check's findings so far (FEA-06.9): `None` before the
    /// user started one, and after Turn Off, a lock or a close (the page
    /// then shows the consent text, FEA-06.12). No secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn breach_report(&self, vault: u64) -> Result<Option<BreachReport>, LarsalError> {
        let rows_of = |v: &Vault, check: &Check| -> Vec<(Uuid, u64)> {
            check
                .findings(v)
                .into_iter()
                .map(|f| (f.entry, f.count))
                .collect()
        };
        let found = self.with_breach(vault, |v, b| {
            Ok(b.as_ref().map(|b| {
                (
                    rows_of(v, &b.check),
                    b.check.entries_checked(),
                    b.checked_at,
                    b.error.clone(),
                    b.progress(),
                )
            }))
        })?;
        let Some((found, checked, checked_at, error, progress)) = found else {
            return Ok(None);
        };
        self.with_open(vault, |v, _, rated| {
            let at = instant_now();
            let by_id: HashMap<Uuid, &Entry> = live(v).into_iter().map(|e| (e.uuid, e)).collect();
            let rows: Vec<BreachRow> = found
                .iter()
                .filter_map(|(id, n)| {
                    Some(BreachRow {
                        entry: row(v, by_id.get(id)?, at, rated, false),
                        count: *n,
                        exposure: exposure(*n).1.to_owned(),
                    })
                })
                .collect();
            Ok(Some(BreachReport {
                largest: rows.iter().map(|r| r.count).max().unwrap_or(0),
                rows,
                checked: count(checked),
                checked_at,
                error,
                progress,
            }))
        })
    }

    /// After entry `entry` was edited from the breach results and saved
    /// (FEA-06.11): it leaves its old password's findings when the password
    /// changed or it can no longer be checked; a changed password that can
    /// be checked gets one new request, sent by the next
    /// [`Session::breach_step`].
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`.
    pub fn breach_after_edit(
        &self,
        vault: u64,
        entry: String,
        password_changed: bool,
    ) -> Result<Option<BreachProgress>, LarsalError> {
        let id = parse_id(&entry, LarsalError::UnknownEntry)?;
        self.with_breach(vault, |v, b| {
            let Some(b) = b.as_mut() else {
                return Ok(None);
            };
            if b.check.after_edit(v, id, password_changed).is_some() {
                b.total = b.total.saturating_add(1);
                if b.error.is_none() {
                    b.checked_at = None;
                }
            }
            Ok(Some(b.progress()))
        })
    }

    /// Turn Off, and closing the reports (FEA-06.12): drops the check with
    /// every hash and count; answers still on their way are dropped.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn breach_stop(&self, vault: u64) -> Result<(), LarsalError> {
        match self.with_breach(vault, |_, b| {
            *b = None;
            Ok(())
        }) {
            Err(LarsalError::Locked) => Ok(()),
            other => other,
        }
    }
}

fn no_check() -> LarsalError {
    LarsalError::Refused("No breach check is running.".to_owned())
}

/// The notice to show instead of running `query` while the ratings are not
/// in yet: the limit notice when the query rates passwords (`is:weak`),
/// else `None`. The screen then runs the search again once the cache is
/// full (LD-137 (4), LD-139), so the screen thread never rates (LD-126
/// (8)).
#[uniffi::export]
pub fn search_waits_for_ratings(query: String) -> Option<String> {
    larsal_core::search::rates(&query).then(|| crate::views::LIMIT_NOTICE.to_owned())
}

impl Session {
    /// [`Session::breach_start`] with the transport `fetch` (tests: a fake).
    pub(crate) fn breach_start_with(
        &self,
        vault: u64,
        fetch: Arc<dyn Fetch>,
    ) -> Result<BreachProgress, LarsalError> {
        self.with_breach(vault, |v, b| {
            let check = Check::new(v);
            let total = count(check.requests().len());
            let mut next = Breach {
                check,
                run: RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                sent: HashSet::new(),
                done: 0,
                total,
                error: None,
                checked_at: None,
                fetch,
            };
            if next.finished() {
                next.checked_at = Some(unix(now()));
            }
            let progress = next.progress();
            *b = Some(next);
            Ok(progress)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::UnlockResult;
    use crate::test_dir::TempDir;
    use crate::views::ListView;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};

    /// Product clients made ([`Net::new`]): only the user's press makes one.
    pub(super) static NETS: AtomicUsize = AtomicUsize::new(0);

    /// A fresh copy of an Option A demo vault, unlocked in a test session,
    /// in `$TMPDIR/larsal-ffi-reports-<name>-<pid>`, removed when the folder
    /// drops (LD-211 (4)); keep it bound (`_folder`) for the whole test.
    fn demo(file: &str, password: &str, name: &str) -> (Arc<Session>, u64, TempDir) {
        let folder = TempDir::new(&format!("reports-{name}"));
        let path = folder.join(format!("{name}.larsalvault"));
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata")
                .join(file),
            &path,
        )
        .unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        assert_eq!(
            s.unlock(v, Some(password.into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        (s, v, folder)
    }

    fn personal(name: &str) -> (Arc<Session>, u64, TempDir) {
        demo("option-a-personal.larsalvault", "demo-pass-7", name)
    }

    fn rated(s: &Session, v: u64) {
        while !s.rate(v, 50, 3600).unwrap() {}
    }

    fn id_of(s: &Session, v: u64, title: &str) -> String {
        s.list(v, ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .find(|r| r.title == title)
            .unwrap()
            .id
    }

    /// A request the fake service saw: its URL and headers.
    type Seen = (String, Vec<(String, String)>);

    /// A Browser row: title, allowed, denied, options.
    type Site = (String, Vec<String>, Vec<String>, Vec<String>);

    /// The range service in a test: answers from a table (a padding line
    /// with count 0 first, FEA-06.5), records every request, and can hold
    /// its answers until the test opens the gate.
    struct Fake {
        answers: HashMap<String, (u16, Vec<u8>)>,
        seen: Mutex<Vec<Seen>>,
        gate: Option<(Mutex<bool>, Condvar)>,
    }

    impl Fake {
        fn new(counts: &[(&str, u64)]) -> Arc<Self> {
            Arc::new(Self::with(counts, None))
        }

        fn with(counts: &[(&str, u64)], gate: Option<(Mutex<bool>, Condvar)>) -> Self {
            let mut answers: HashMap<String, (u16, Vec<u8>)> = HashMap::new();
            for (pw, n) in counts {
                let h = larsal_core::breach::hash(pw);
                let (_, body) = answers
                    .entry(h.prefix.clone())
                    .or_insert((200, b"0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n".to_vec()));
                body.extend(format!("{}:{n}\r\n", h.suffix.expose()).bytes());
            }
            Self {
                answers,
                seen: Mutex::new(Vec::new()),
                gate,
            }
        }

        fn sent(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|(u, _)| u.clone())
                .collect()
        }

        fn open(&self) {
            if let Some((open, wake)) = &self.gate {
                *open.lock().unwrap() = true;
                wake.notify_all();
            }
        }
    }

    impl Fetch for Fake {
        fn get(&self, url: &str, headers: &[(&str, &str)]) -> Answer {
            self.seen.lock().unwrap().push((
                url.to_owned(),
                headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            ));
            if let Some((open, wake)) = &self.gate {
                let mut is_open = open.lock().unwrap();
                while !*is_open {
                    is_open = wake.wait(is_open).unwrap();
                }
            }
            let prefix = url.strip_prefix(RANGE_URL).unwrap_or("");
            Ok(self
                .answers
                .get(prefix)
                .cloned()
                .unwrap_or((200, b"0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n".to_vec())))
        }
    }

    fn run(s: &Session, v: u64) -> BreachProgress {
        loop {
            let p = s.breach_step(v).unwrap();
            if p.finished {
                return p;
            }
        }
    }

    /// The mockup's findings (frame `reports-reports-breach-check`).
    const LEAKED: [(&str, u64); 3] = [
        ("admin1234", 214_876),
        ("Summer2024!", 18_442),
        ("sunshine2019", 3_107),
    ];

    /// FEA-06.1, SN-01, E5-S7 check "the breach check sends nothing until
    /// the user starts it": opening every report sends nothing and makes no
    /// HTTPS client; a step without a start is refused.
    #[test]
    fn fea_06_01_nothing_is_sent_before_the_press() {
        let (s, v, _folder) = personal("press");
        let before = NETS.load(Ordering::SeqCst);
        rated(&s, v);
        s.rating_progress(v).unwrap();
        s.health_report(v, false, 3600).unwrap();
        s.health_report(v, true, 3600).unwrap();
        s.statistics_report(v, 3600).unwrap();
        s.passkeys_report(v).unwrap();
        s.browser_report(v).unwrap();
        assert_eq!(s.breach_report(v).unwrap(), None);
        assert!(matches!(s.breach_step(v), Err(LarsalError::Refused(_))));
        assert_eq!(
            s.breach_after_edit(v, id_of(&s, v, "Amazon"), true)
                .unwrap(),
            None
        );
        assert_eq!(NETS.load(Ordering::SeqCst), before);
    }

    /// FEA-07.17, LD-137, E5-S7 check "with progress": a cold cache counts
    /// up step by step until every live password is rated.
    #[test]
    fn ld_137_rating_progress_counts_up() {
        let (s, v, _folder) = personal("progress");
        let at = |s: &Session| {
            let p = s.rating_progress(v).unwrap();
            (p.done, p.total)
        };
        assert_eq!(at(&s), (0, 21), "cold after the unlock");
        assert!(!s.rate(v, 5, 3600).unwrap());
        assert_eq!(at(&s), (5, 21));
        rated(&s, v);
        assert_eq!(at(&s), (21, 21));
    }

    /// LD-137 (4), LD-126 (8): a `rate(max: 25)` step on a cold vault of 25
    /// random 100-character passwords (about 30 ms each) holds the session
    /// lock briefly, so a screen call made meanwhile does not wait for it.
    #[test]
    fn ld_137_a_list_does_not_wait_for_a_rating_step() {
        let (s, v, _folder) = personal("long-passwords");
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        s.with_edit(v, |vault, _, _, _| {
            for i in 1..=25 {
                let pw: String = (0..100)
                    .map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        char::from(b'!' + u8::try_from(seed % 94).unwrap())
                    })
                    .collect();
                let mut e = Entry::new(Uuid([i; 16]), now());
                let value = larsal_crypto::secret::SecretString::new(pw);
                let field = larsal_model::entry::Field {
                    value,
                    protected: true,
                };
                e.set_field("Password".into(), field);
                vault.root.entries.insert(0, e);
            }
            Ok(())
        })
        .unwrap();
        let rater = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || while !s.rate(v, 25, 3600).unwrap() {})
        };
        let mut waited = std::time::Duration::ZERO;
        while !rater.is_finished() {
            let t = std::time::Instant::now();
            s.list(v, ListView::All).unwrap();
            waited = waited.max(t.elapsed());
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        rater.join().unwrap();
        assert!(waited.as_millis() < 100, "a list waited {waited:?}");
    }

    /// LD-137 (4): a rating made outside the session lock is kept only if
    /// its entry did not change meanwhile, also within the same second.
    #[test]
    fn ld_137_a_rating_of_a_changed_password_is_dropped() {
        let (s, v, _folder) = personal("changed-meanwhile");
        s.with_edit(v, |vault, _, rated, _| {
            let mut todo = rated.todo(vault, 2, 0).unwrap();
            let (kept, changed) = (todo.remove(0), todo.remove(0));
            let e = vault
                .root
                .entries
                .iter_mut()
                .find(|e| e.uuid == changed.uuid)
                .unwrap();
            let value = larsal_crypto::secret::SecretString::new("changed".into());
            let field = larsal_model::entry::Field {
                value,
                protected: true,
            };
            e.set_field("Password".into(), field);
            rated.keep(vault, vec![(kept, 1.0), (changed, 1.0)]);
            assert_eq!(rated.progress(vault).0, 1);
            Ok(())
        })
        .unwrap();
    }

    /// LD-137 (4), LD-139: only a query that rates waits for the ratings,
    /// in every spelling the search reads (FEA-01.3, FEA-01.5).
    #[test]
    fn ld_139_which_searches_wait_for_ratings() {
        for q in [
            "is:weak",
            "IS:Weak",
            "i:weak",
            "is:\"weak\"",
            "-is:weak",
            "a is:weak",
        ] {
            assert_eq!(
                search_waits_for_ratings(q.into()).as_deref(),
                Some(crate::views::LIMIT_NOTICE),
                "{q}"
            );
        }
        for q in [
            "weak",
            "title:weak",
            "*is:weak",
            "is:expired",
            "is:weakness",
        ] {
            assert_eq!(search_waits_for_ratings(q.into()), None, "{q}");
        }
    }

    /// FEA-06.2 to FEA-06.4, FEA-06.6, FEA-06.9: one request per distinct
    /// prefix with exactly the two headers, at most 6 per step; findings by
    /// count, equal counts in tree order, with the card's exposure texts.
    #[test]
    fn fea_06_02_requests_and_findings() {
        let (s, v, _folder) = personal("findings");
        rated(&s, v);
        let fake = Fake::new(&LEAKED);
        let start = s.breach_start_with(v, fake.clone()).unwrap();
        assert!(!start.finished && start.done == 0);
        assert!(fake.sent().is_empty(), "the start sends nothing");
        let first = s.breach_step(v).unwrap();
        assert!(fake.sent().len() <= MAX_PARALLEL);
        assert_eq!(first.done as usize, fake.sent().len());
        let end = run(&s, v);
        assert_eq!((end.done, end.total), (start.total, start.total));
        let sent = fake.sent();
        let prefixes: HashSet<&str> = sent
            .iter()
            .map(|u| u.strip_prefix(RANGE_URL).unwrap())
            .collect();
        assert_eq!(prefixes.len(), sent.len(), "one request per prefix");
        assert_eq!(sent.len(), start.total as usize);
        assert!(prefixes.iter().all(|p| p.len() == 5));
        for (_, headers) in fake.seen.lock().unwrap().iter() {
            assert_eq!(
                headers,
                &[
                    ("User-Agent".to_owned(), "Larsal".to_owned()),
                    ("Add-Padding".to_owned(), "true".to_owned())
                ]
            );
        }
        let r = s.breach_report(v).unwrap().unwrap();
        let rows: Vec<(&str, u64, &str)> = r
            .rows
            .iter()
            .map(|r| (r.entry.title.as_str(), r.count, r.exposure.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("Router admin", 214_876, "Seen 100,001 to 1,000,000 times"),
                ("Amazon", 18_442, "Seen 10,001 to 100,000 times"),
                ("eBay", 18_442, "Seen 10,001 to 100,000 times"),
                ("Reddit", 3_107, "Seen 1,001 to 10,000 times"),
            ]
        );
        let health = s.health_report(v, false, 3600).unwrap();
        assert_eq!(r.checked, health.passwords, "every password is checked");
        assert_eq!((r.largest, r.error.as_deref()), (214_876, None));
        assert!(r.checked_at.is_some());
        // FEA-06.13: every suffix is wiped once its answer was read.
        s.with_breach(v, |_, b| {
            assert_eq!(b.as_ref().unwrap().check.suffixes_held(), 0);
            Ok(())
        })
        .unwrap();
    }

    /// FEA-06.8: the first failure stops the check, outstanding requests
    /// are never sent, and the reason names the status, never the body.
    #[test]
    fn fea_06_12_first_failure_stops_the_check() {
        let (s, v, _folder) = personal("failure");
        let mut fake = Fake::with(&[], None);
        for p in s
            .with_breach(v, |vault, _| Ok(Check::new(vault).requests()))
            .unwrap()
        {
            let prefix = p.url.strip_prefix(RANGE_URL).unwrap().to_owned();
            fake.answers
                .insert(prefix, (500, b"body text from the server".to_vec()));
        }
        let fake = Arc::new(fake);
        let start = s.breach_start_with(v, fake.clone()).unwrap();
        assert!(start.total as usize > MAX_PARALLEL);
        let end = s.breach_step(v).unwrap();
        assert!(end.finished && end.done == 0);
        let sent = fake.sent().len();
        assert!(sent <= MAX_PARALLEL && sent < start.total as usize);
        assert_eq!(s.breach_step(v).unwrap(), end);
        assert_eq!(fake.sent().len(), sent, "nothing more is sent");
        let r = s.breach_report(v).unwrap().unwrap();
        assert_eq!(
            r.error.as_deref(),
            Some("The online check stopped early: the service answered with status 500")
        );
        assert!(r.rows.is_empty());
    }

    /// FEA-06.7, FEA-06.10: with no password to check there is no request
    /// and the result is there at once.
    #[test]
    fn fea_06_11_nothing_to_check_sends_nothing() {
        let (s, v, _folder) = demo("option-a-family.larsalvault", "demo-pass-9", "family");
        let fake = Fake::new(&[]);
        let p = s.breach_start_with(v, fake.clone()).unwrap();
        assert_eq!(
            p,
            BreachProgress {
                done: 0,
                total: 0,
                finished: true
            }
        );
        assert_eq!(s.breach_step(v).unwrap(), p);
        assert!(fake.sent().is_empty());
        let r = s.breach_report(v).unwrap().unwrap();
        assert!(r.rows.is_empty() && r.checked == 0 && r.checked_at.is_some());
    }

    /// FEA-06.12, E5-S7 check "cancel on lock": a lock while requests run
    /// drops the check; the answer that comes later is dropped; after the
    /// unlock the page starts again from the consent text.
    #[test]
    fn fea_06_17_lock_drops_the_check_and_late_answers() {
        let (s, v, _folder) = personal("lock");
        let fake = Arc::new(Fake::with(
            &LEAKED,
            Some((Mutex::new(false), Condvar::new())),
        ));
        s.breach_start_with(v, fake.clone()).unwrap();
        let step = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.breach_step(v))
        };
        while fake.sent().is_empty() {
            std::thread::yield_now();
        }
        s.lock(v).unwrap();
        fake.open();
        assert!(matches!(step.join().unwrap(), Err(LarsalError::Locked)));
        assert!(matches!(s.breach_report(v), Err(LarsalError::Locked)));
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        assert_eq!(s.breach_report(v).unwrap(), None);
        // Turn Off drops a finished check the same way.
        s.breach_start_with(v, Fake::new(&LEAKED)).unwrap();
        run(&s, v);
        s.breach_stop(v).unwrap();
        assert_eq!(s.breach_report(v).unwrap(), None);
        // Turn Off while requests run, then a new start: the old answers
        // never land in the new check.
        let old = Arc::new(Fake::with(
            &LEAKED,
            Some((Mutex::new(false), Condvar::new())),
        ));
        s.breach_start_with(v, old.clone()).unwrap();
        let step = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.breach_step(v))
        };
        while old.sent().is_empty() {
            std::thread::yield_now();
        }
        s.breach_stop(v).unwrap();
        let new = Fake::new(&LEAKED);
        s.breach_start_with(v, new.clone()).unwrap();
        old.open();
        assert!(matches!(step.join().unwrap(), Err(LarsalError::Refused(_))));
        let p = s.breach_report(v).unwrap().unwrap().progress;
        assert_eq!((p.done, p.finished), (0, false));
        assert!(new.sent().is_empty());
    }

    /// FEA-06.11: after a password changed from the results, exactly one
    /// new request, for the new password's prefix; an empty password sends
    /// nothing and leaves the findings.
    #[test]
    fn fea_06_16_edit_from_the_results() {
        let (s, v, _folder) = personal("edit");
        let fake = Fake::new(&LEAKED);
        s.breach_start_with(v, fake.clone()).unwrap();
        let before = run(&s, v);
        let sent = fake.sent().len();
        let amazon = id_of(&s, v, "Amazon");
        s.begin_edit(v, amazon.clone()).unwrap();
        s.set_password(v, "4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap();
        s.commit_edit(v).unwrap();
        let p = s.breach_after_edit(v, amazon, true).unwrap().unwrap();
        assert_eq!((p.total, p.finished), (before.total + 1, false));
        assert!(run(&s, v).finished);
        let now_sent = fake.sent();
        assert_eq!(now_sent.len(), sent + 1);
        let new = larsal_core::breach::hash("4v8Nq2LmZ7rT1xKc9WbP").prefix;
        assert_eq!(now_sent.last().unwrap(), &format!("{RANGE_URL}{new}"));
        let titles = |s: &Session| -> Vec<String> {
            s.breach_report(v)
                .unwrap()
                .unwrap()
                .rows
                .into_iter()
                .map(|r| r.entry.title)
                .collect()
        };
        assert_eq!(titles(&s), ["Router admin", "eBay", "Reddit"]);
        let ebay = id_of(&s, v, "eBay");
        s.begin_edit(v, ebay.clone()).unwrap();
        s.set_password(v, String::new()).unwrap();
        s.commit_edit(v).unwrap();
        let p = s.breach_after_edit(v, ebay, true).unwrap().unwrap();
        assert!(p.finished && p.total == before.total + 1);
        assert_eq!(
            fake.sent().len(),
            sent + 1,
            "an empty password sends nothing"
        );
        assert_eq!(titles(&s), ["Router admin", "Reddit"]);
    }

    /// FEA-05.15, FEA-05.16, LD-163 (4): the report lists what the sidebar
    /// counts, lowest score first, with expired entries; reuse is told by
    /// path; "Skip in Reports" hides an entry unless asked (FEA-05.18).
    #[test]
    fn fea_05_15_health_report_matches_the_sidebar() {
        let (s, v, _folder) = personal("health");
        rated(&s, v);
        let side = s.sidebar(v).unwrap();
        // Central European summer time, as the mockup's times.
        let r = s.health_report(v, false, 7200).unwrap();
        assert_eq!(Some(count(r.rows.len())), side.attention);
        assert!(r.rows.windows(2).all(|w| w[0].score <= w[1].score));
        let with_pw = s
            .list(v, ListView::All)
            .unwrap()
            .rows
            .iter()
            .filter(|r| r.has_password)
            .count();
        assert_eq!(r.passwords as usize, with_pw);
        assert_eq!(r.healthy as usize, with_pw - r.rows.len());
        assert_eq!(r.reused_passwords, 1, "Amazon and eBay share one");
        let problem = |r: &HealthReport, t: &str| {
            r.rows
                .iter()
                .find(|x| x.entry.title == t)
                .map(|x| x.problem.clone())
        };
        assert_eq!(problem(&r, "Amazon").as_deref(), Some("Reused"));
        assert_eq!(problem(&r, "Zalando").as_deref(), Some("Expired"));
        assert_eq!(problem(&r, "Reddit").as_deref(), Some("Poor"));
        let zalando = r.rows.iter().find(|x| x.entry.title == "Zalando").unwrap();
        assert_eq!(
            zalando.reasons.last().map(String::as_str),
            Some("Past its expiry date")
        );
        assert_eq!(
            zalando.details.last().map(String::as_str),
            Some("Expiry date Oct 1, 2026, 00:00 has passed")
        );
        assert!(!r.any_skipped);
        let amazon = id_of(&s, v, "Amazon");
        assert!(!s.skip_checked(v, vec![amazon.clone()]).unwrap());
        assert_eq!(
            s.toggle_skip_in_reports(v, vec![amazon.clone()]).unwrap(),
            1
        );
        assert!(s.skip_checked(v, vec![amazon.clone()]).unwrap());
        let hidden = s.health_report(v, false, 3600).unwrap();
        assert!(hidden.any_skipped && problem(&hidden, "Amazon").is_none());
        let shown = s.health_report(v, true, 3600).unwrap();
        let row = shown
            .rows
            .iter()
            .find(|x| x.entry.title == "Amazon")
            .unwrap();
        assert!(row.excluded && row.bits > 0);
        s.toggle_skip_in_reports(v, vec![amazon]).unwrap();
        assert!(!s.health_report(v, false, 3600).unwrap().any_skipped);
    }

    /// FEA-05.18 `ACT-HC-EXPIRE`: the entry expires now and is listed as
    /// expired; an unknown id changes nothing.
    #[test]
    fn fea_05_26_expire_now_from_the_report() {
        let (s, v, _folder) = personal("expire");
        let slack = id_of(&s, v, "Slack");
        assert!(matches!(
            s.expire_entries(v, vec![slack.clone(), "00".repeat(16)]),
            Err(LarsalError::UnknownEntry)
        ));
        assert_eq!(s.expire_entries(v, vec![slack]).unwrap(), 1);
        rated(&s, v);
        let r = s.health_report(v, false, 3600).unwrap();
        let row = r.rows.iter().find(|x| x.entry.title == "Slack").unwrap();
        assert!(row.expired && row.problem == "Expired");
        assert_eq!(s.save_status(v).unwrap().changes, 1);
    }

    /// FEA-07 through the bridge on the Personal vault, and the frame's
    /// extra rows: they add up to what the vault holds.
    #[test]
    fn fea_07_statistics_and_the_frame_rows() {
        let (s, v, _folder) = personal("stats");
        let st = s.statistics_report(v, 3600).unwrap();
        let side = s.sidebar(v).unwrap();
        assert_eq!(st.entries, u64::from(side.all));
        assert_eq!(st.in_bin, side.bin.unwrap());
        assert_eq!(st.groups, side.groups.len() as u64 + 1, "the root counts");
        let with_pw = s.health_report(v, false, 3600).unwrap().passwords;
        assert_eq!(st.unique_pw + st.reused_pw, u64::from(with_pw));
        assert_eq!((st.unique_pw, st.reused_pw, st.max_reuse), (20, 1, 2));
        let sum = |b: &[Bar]| b.iter().map(|x| x.count).sum::<u32>();
        assert_eq!(sum(&st.lengths), with_pw);
        assert_eq!(sum(&st.ages), with_pw);
        let labels: Vec<&str> = st.lengths.iter().map(|b| b.label.as_str()).collect();
        assert_eq!(labels, ["8–11", "12–15", "16–19", "20 and more"]);
        assert_eq!(
            (st.version.as_str(), st.file_name.as_str()),
            ("4.1", "stats.larsalvault")
        );
        assert_eq!(st.encryption, "AES-256 · Argon2id, 1 MiB, 2 iterations");
        assert_eq!(
            (st.passkeys, st.totp),
            (u64::from(side.passkeys), u64::from(side.codes))
        );
        assert!(st.size.unwrap() > 0 && st.last_saved.is_some() && !st.unsaved);
        assert_eq!(st.attachments, 3);
        assert_eq!(st.attachment_bytes, 1229 + 464 + 98);
    }

    /// INT-04.52: one row per live entry with a private key field; Remove
    /// (INT-04.46, entry menu path) drops every passkey field and the tag,
    /// without a history item.
    #[test]
    fn int_04_52_passkeys_and_remove() {
        let (s, v, _folder) = personal("passkeys");
        let rows = s.passkeys_report(v).unwrap();
        let got: Vec<(&str, &str, &str, bool, bool)> = rows
            .iter()
            .map(|r| {
                (
                    r.entry.title.as_str(),
                    r.site.as_str(),
                    r.user.as_str(),
                    r.has_password,
                    r.has_totp,
                )
            })
            .collect();
        assert_eq!(got.len(), 4);
        assert!(got.contains(&("GitHub", "github.com", "alex-dev", true, true)));
        assert!(got.contains(&(
            "Mastodon",
            "mastodon.social",
            "@alex@mastodon.social",
            false,
            false
        )));
        let linear = id_of(&s, v, "Linear");
        // The tag the import gives a passkey entry (INT-04.46 removes it).
        let mut tags = s.entry(v, linear.clone()).unwrap().tags;
        tags.push("Passkey".into());
        s.begin_edit(v, linear.clone()).unwrap();
        s.set_tags(v, tags).unwrap();
        s.commit_edit(v).unwrap();
        let before = s.entry(v, linear.clone()).unwrap();
        assert!(before.tags.iter().any(|t| t == "Passkey"));
        let history = before.history;
        s.remove_entry_passkey(v, linear.clone()).unwrap();
        assert!(matches!(
            s.remove_entry_passkey(v, linear.clone()),
            Err(LarsalError::UnknownField)
        ));
        let after = s.entry(v, linear.clone()).unwrap();
        assert!(after.passkey.is_none() && !after.tags.iter().any(|t| t == "Passkey"));
        assert_eq!(after.history, history, "no history item");
        assert_eq!(s.passkeys_report(v).unwrap().len(), 3);
    }

    /// LD-207, rule 4: with the vault's flag for UserName on (MOD-12.16
    /// leaves the fields' own flags off) and no passkey user name, the row
    /// falls back to an empty user, never the protected user name.
    #[test]
    fn ld_207_passkey_row_masks_the_vault_flag_user_name() {
        let (s, v, _folder) = personal("passkey-flag");
        let linear = id_of(&s, v, "Linear");
        let uuid = parse_id(&linear, LarsalError::UnknownEntry).unwrap();
        let own = s
            .with_edit(v, |vault, _, _, _| {
                vault.meta.memory_protection.user_name = true;
                change_entry(vault, uuid, now(), |e| {
                    e.remove_field("KPEX_PASSKEY_USERNAME");
                })
                .unwrap();
                let e = find(&vault.root, uuid, &mut Vec::new()).unwrap();
                Ok(e.field("UserName")
                    .map(|f| (f.protected, f.value.expose().len())))
            })
            .unwrap();
        assert!(matches!(own, Some((false, n)) if n > 0), "own flag off");
        let row = s
            .passkeys_report(v)
            .unwrap()
            .into_iter()
            .find(|r| r.entry.id == linear)
            .unwrap();
        assert_eq!(row.user, "");
    }

    /// INT-02.32, INT-02.14: entries with site access hosts or an option on,
    /// the MI02-14 words, and the vault's connected browsers by name.
    #[test]
    fn int_02_32_browser_report() {
        let (s, v, _folder) = personal("browser");
        let r = s.browser_report(v).unwrap();
        let mut rows: Vec<Site> = r
            .rows
            .into_iter()
            .map(|r| (r.entry.title, r.allow, r.deny, r.options))
            .collect();
        rows.sort();
        let v_ = |l: &[&str]| l.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            rows,
            [
                (
                    "Amazon".to_owned(),
                    v_(&[]),
                    v_(&["www.amazon.com"]),
                    v_(&[])
                ),
                ("Figma".to_owned(), v_(&["www.figma.com"]), v_(&[]), v_(&[])),
                (
                    "GitHub".to_owned(),
                    v_(&["gist.github.com", "github.com"]),
                    v_(&[]),
                    v_(&["fill, no submit"])
                ),
                (
                    "Google".to_owned(),
                    v_(&["accounts.google.com"]),
                    v_(&[]),
                    v_(&[])
                ),
            ]
        );
        let names: Vec<(&str, Option<i64>)> = r
            .browsers
            .iter()
            .map(|b| (b.name.as_str(), b.since))
            .collect();
        assert_eq!(
            names,
            [
                ("Firefox on MacBook", Some(1_791_792_000)),
                ("Safari", Some(1_788_422_400))
            ]
        );
    }

    #[test]
    fn short_times_and_grouping() {
        let t = Time::from_unix(1_790_812_800).unwrap(); // 2026-10-01T00:00Z
        assert_eq!(short_time(t, 7200), "Oct 1, 2026, 02:00");
        assert_eq!(grouped(60_000), "60,000");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }
}
