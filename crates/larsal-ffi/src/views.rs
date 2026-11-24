//! What the main window shows (E5-S2, E5-S4): the sidebar, list rows, the
//! entry detail, Show, Copy and live one-time codes.
//!
//! Guarantees (architecture, larsal-ffi Must; AGENTS.md rule 4):
//! - no view record carries a protected value: a protected field shows as
//!   `protected` with an empty value, and the one-time password fields
//!   (`otp`, `TOTP Seed`, `TOTP Settings`, `TimeOtp-*`) never appear;
//! - the two values that cross are the one field the user asked for with
//!   Show ([`Session::show_field`]) and the current one-time code of the
//!   entry on screen ([`Session::totp`]), never its secret;
//! - Copy is a Rust call ([`Session::copy_field`], [`Session::copy_code`],
//!   [`Session::copy_fingerprint`]): the value is resolved (MOD-08) or
//!   computed, and written to the clipboard in Rust and never reaches Swift,
//!   which gets only the label and the countdown for the notice (APP-03);
//! - every id is checked against the one vault the call names: an id of
//!   another vault, a malformed id or an over-long text gives a typed error
//!   (AT-E03);
//! - search goes through larsal-core (FEA-01) and returns ids; rows are made
//!   from them here;
//! - strength ratings run in small steps ([`Session::rate`], LD-137) and are
//!   kept per vault as bits only; a rating, its level, reasons, the password
//!   length and the bits are not secret values (FEA-05 security notes).

use crate::session::{LarsalError, MAX_TEXT, Session};
use larsal_core::expiry::is_expired;
use larsal_core::health::{Level, Ratings, entry_bits, health_check, score, zxcvbn_bits};
use larsal_core::refs;
use larsal_core::search::{self, Options};
use larsal_core::time::{Instant, Zone};
use larsal_core::totp::{self, Problem};
use larsal_model::entry::STANDARD_FIELDS;
use larsal_model::{Entry, Group, Icon, Time, Uuid, Vault};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// The tag that marks a favorite (FEA-08.9). It shows as the star and in
/// Favorites, never in the tag list or the chips.
pub const FAVORITE: &str = "Favorite";
/// Passkey fields start with this name (MOD-01.8, INT-04).
pub(crate) const PASSKEY: &str = "KPEX_PASSKEY";
/// The most ids one [`Session::codes`] call takes.
const MAX_CODES: usize = 200;

/// The sidebar of an unlocked vault (mockup `.side`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Sidebar {
    /// All Entries (`*`, FEA-01.28).
    pub all: u32,
    /// Expired (`is:expired`).
    pub expired: u32,
    /// The groups below the root in tree order, without the recycle bin.
    pub groups: Vec<GroupRow>,
    /// The vault tag list (MOD-07.5) with counts, without [`FAVORITE`].
    pub tags: Vec<TagRow>,
    /// Entries in the recycle bin; `None` when the vault has no bin.
    pub bin: Option<u32>,
    /// Favorites: live entries with the tag [`FAVORITE`].
    pub favorites: u32,
    /// One-time codes: live entries with one-time password settings.
    pub codes: u32,
    /// Passkeys: live entries with a passkey (INT-04).
    pub passkeys: u32,
    /// Live entries whose health is below Good (FEA-05.15, excluded entries
    /// left out, expired ones counted); `None` until [`Session::rate`] is
    /// done.
    pub attention: Option<u32>,
    /// When the vault file was last written (its modification time, unix
    /// seconds).
    pub saved_at: Option<i64>,
    /// The root group's creation time, unix seconds.
    pub created: i64,
    /// The root group's id: All entries is the root group (APP-08.7).
    pub root: String,
}

/// One group of the sidebar tree.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GroupRow {
    /// 32 hex digits.
    pub id: String,
    /// The group name.
    pub name: String,
    /// 0 for a child of the root.
    pub depth: u32,
    /// Live entries in the group and its subgroups (FEA-01 `group:`).
    pub count: u32,
    /// The standard icon number (MOD-06.1); -1 for a custom icon.
    pub icon: i32,
    /// The custom icon's name, for a custom icon (Larsal names the ones it
    /// makes "<symbol> <colour>", LD-192 (1)); `None` otherwise.
    pub custom_icon: Option<String>,
    /// It has child groups (a twisty shows).
    pub has_children: bool,
    /// MOD-02.5: shown expanded at first.
    pub expanded: bool,
}

/// One tag of the sidebar.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TagRow {
    /// The tag text.
    pub name: String,
    /// Live entries outside the bin with this tag.
    pub count: u32,
}

/// Which entries the list shows.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ListView {
    /// All Entries (`*`).
    All,
    /// Expired (`is:expired`).
    Expired,
    /// Weak Passwords (`is:weak`).
    Weak,
    /// Favorites: live entries with the tag [`FAVORITE`].
    Favorites,
    /// One-time codes: live entries with one-time password settings.
    Codes,
    /// Passkeys: live entries with a passkey.
    Passkeys,
    /// The live entries of one group and its subgroups.
    Group {
        /// 32 hex digits.
        id: String,
    },
    /// One exact tag term (FEA-01.35, LD-66).
    Tag {
        /// The tag text.
        name: String,
    },
    /// The recycle bin and the groups inside it.
    Bin,
    /// A typed query (FEA-01).
    Search {
        /// The search box text.
        query: String,
    },
}

/// A search's hits: entry ids in tree order, for the rows the screen holds
/// already (FEA-01.22), and the search notice.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SearchHits {
    /// 32 hex digits each.
    pub ids: Vec<String>,
    /// FEA-01.31 or FEA-01.32: a notice for the search box, else `None`.
    pub notice: Option<String>,
}

/// The list's rows and the search notice.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EntryList {
    /// The rows, in tree order; the screen sorts them (FEA-01.22).
    pub rows: Vec<EntryRow>,
    /// FEA-01.31 or FEA-01.32: a notice for the search box, else `None`.
    pub notice: Option<String>,
}

/// One list row. No protected value (architecture, larsal-ffi Must).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EntryRow {
    /// 32 hex digits.
    pub id: String,
    /// The title; empty when the title is protected.
    pub title: String,
    /// The mockup's second line: the user name, else the URL's host, else
    /// the first unprotected custom field; empty when none.
    pub subtitle: String,
    /// The standard icon number (MOD-06.1); -1 for a custom icon.
    pub icon: i32,
    /// The custom icon's name, for a custom icon (as in [`GroupRow`]).
    pub custom_icon: Option<String>,
    /// Unix seconds.
    pub created: i64,
    /// Unix seconds.
    pub modified: i64,
    /// Expired now (MOD-09).
    pub expired: bool,
    /// The URL's host, for the logo; empty without a plain URL.
    pub host: String,
    /// It has the tag [`FAVORITE`].
    pub favorite: bool,
    /// It has one-time password settings: ask [`Session::codes`].
    pub has_totp: bool,
    /// It has a passkey.
    pub passkey: bool,
    /// Its layout.
    pub kind: EntryKind,
    /// Its password is not empty.
    pub has_password: bool,
    /// The strength and health of its password; `None` without a password,
    /// for an excluded entry, or until it is rated.
    pub rating: Option<Rating>,
    /// In the bin view: when it was moved there (`LocationChanged`).
    pub deleted: Option<i64>,
}

/// What an entry is, for the detail's layout. Larsal's own rule, from the
/// fields: a `Card number` field makes a card, an OpenSSH public key in an
/// attachment an SSH entry, a plain `Security` field starting with `WPA` or
/// `WEP` a Wi-Fi entry; anything else is a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EntryKind {
    /// A login.
    Login,
    /// A payment card.
    Card,
    /// A Wi-Fi network.
    WiFi,
    /// A server with an SSH key.
    Ssh,
}

/// The strength (FEA-05.4, FEA-05.9) and health (FEA-05.13 to FEA-05.15)
/// of one password. No secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Rating {
    /// The strength level's name (FEA-05.4).
    pub level: String,
    /// The list word: `Expired` or `Reused` when that makes the health
    /// below Good, else the level's name.
    pub word: String,
    /// The level as 0 (Bad) to 4 (Excellent), for the meter.
    pub segments: u8,
    /// Health below Good: the entry needs attention.
    pub attention: bool,
    /// Needs attention because it is past its expiry date.
    pub expired: bool,
    /// The notice's first words when it needs attention, for example
    /// `Reused password.`; empty otherwise.
    pub issue: String,
    /// The Health Check reasons (FEA-05.6, FEA-05.13, FEA-05.14).
    pub reasons: Vec<String>,
    /// The password's length in characters.
    pub chars: u32,
    /// E rounded to whole bits.
    pub bits: u32,
}

/// The passkey of an entry (INT-04).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyView {
    /// The relying party, for example `github.com`.
    pub site: String,
    /// The passkey's user name.
    pub user: String,
}

/// The OpenSSH public key of an entry's attachment. Public: a public key's
/// type and fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshKeyView {
    /// The key type, for example `ED25519`.
    pub kind: String,
    /// `SHA256:` and the unpadded base64 of the key's SHA-256.
    pub fingerprint: String,
}

/// What kind of field a [`FieldView`] is, for the detail's cards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FieldKind {
    /// `UserName`.
    UserName,
    /// `Password`.
    Password,
    /// `URL`.
    Url,
    /// `Notes`.
    Notes,
    /// Any other field.
    Custom,
}

/// One field of the detail view.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FieldView {
    /// The field's name, for Show and Copy.
    pub name: String,
    /// Its card.
    pub kind: FieldKind,
    /// The value; empty when `protected` (Show fetches it).
    pub value: String,
    /// Protected in memory (MOD-01): the screen shows dots.
    pub protected: bool,
}

/// One attachment of the detail view.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AttachmentView {
    /// The attachment name.
    pub name: String,
    /// Bytes.
    pub size: u64,
}

/// The detail view of one entry. No protected value.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EntryDetail {
    /// 32 hex digits.
    pub id: String,
    /// The title; empty when protected.
    pub title: String,
    /// The standard icon number; -1 for a custom icon.
    pub icon: i32,
    /// The group names from below the root down to the entry's group.
    pub path: Vec<String>,
    /// The entry is in the recycle bin.
    pub in_bin: bool,
    /// The non-empty fields: user name, password, URL, notes, then custom
    /// fields in stored order; the one-time password fields are left out.
    pub fields: Vec<FieldView>,
    /// It has one-time password settings (FEA-04): ask [`Session::totp`].
    pub has_totp: bool,
    /// Attachments, in stored order.
    pub attachments: Vec<AttachmentView>,
    /// Tags.
    pub tags: Vec<String>,
    /// Expiry time in unix seconds when expiry is on.
    pub expires: Option<i64>,
    /// Expired now.
    pub expired: bool,
    /// Unix seconds.
    pub created: i64,
    /// Unix seconds.
    pub modified: i64,
    /// Unix seconds.
    pub accessed: i64,
    /// Earlier versions kept.
    pub history: u32,
    /// Its layout.
    pub kind: EntryKind,
    /// The URL's host; empty without a plain URL.
    pub host: String,
    /// It has the tag [`FAVORITE`] (left out of `tags`).
    pub favorite: bool,
    /// The name of the group that holds it (the root group's name at the
    /// top).
    pub group: String,
    /// That group's standard icon number; -1 for the root group or a custom
    /// icon.
    pub group_icon: i32,
    /// The entry's custom icon name (as in [`GroupRow`]).
    pub custom_icon: Option<String>,
    /// The group's custom icon name.
    pub group_custom_icon: Option<String>,
    /// In the bin: when it was moved there (`LocationChanged`).
    pub deleted: Option<i64>,
    /// In the bin: the name of the group it came from, when that group
    /// still exists outside the bin (MOD-04.10).
    pub deleted_from: Option<String>,
    /// Its passkey.
    pub passkey: Option<PasskeyView>,
    /// The OpenSSH public key of an attachment.
    pub ssh: Option<SshKeyView>,
    /// The strength and health of its password, as in the list.
    pub rating: Option<Rating>,
    /// The id of the group that holds it, 32 hex digits (E11-S5: the share
    /// badge on the Group field's tile, INT-08.24).
    #[uniffi(default = "")]
    pub group_id: String,
}

/// The live one-time code (FEA-04.14, FEA-04.15). `Debug` hides the code
/// (Rust rule 3, F-062).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct TotpView {
    /// The code with its display space; empty in an error state.
    pub code: String,
    /// R, from `period` down to 1; 0 in an error state.
    pub seconds_left: u32,
    /// The time step in seconds.
    pub period: u32,
    /// FEA-04.10's state text when no code can be made.
    pub problem: Option<String>,
}

impl std::fmt::Debug for TotpView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpView")
            .field("code", &"<hidden>")
            .field("seconds_left", &self.seconds_left)
            .field("period", &self.period)
            .field("problem", &self.problem)
            .finish()
    }
}

/// What the copy notice needs (APP-03.21); never the value.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Copied {
    /// The field's label: `Username`, `Password`, `URL`, `Title`, `Notes`
    /// or the custom field's name.
    pub label: String,
    /// Seconds until Larsal clears the clipboard (`MSG-COPIED`, S-TIME-02); 0
    /// when nothing was copied or clearing is off (S-TIME-01).
    pub seconds: u32,
    /// The value is empty: nothing was copied and the clipboard is
    /// untouched (APP-03.5, `MSG-COPY-EMPTY`).
    pub empty: bool,
}

/// The notice's label for a field name (APP-03.21).
pub(crate) fn label(field: &str) -> String {
    match field {
        "UserName" => "Username",
        other => other,
    }
    .to_owned()
}

impl Session {
    /// The one copy path (APP-03.2): `value` goes to the clipboard with its
    /// markers and countdown; an empty value copies nothing (APP-03.5).
    pub(crate) fn copy_value(&self, label: String, value: &str) -> Result<Copied, LarsalError> {
        if value.is_empty() {
            return Ok(Copied {
                label,
                seconds: 0,
                empty: true,
            });
        }
        // S-TIME-01 and S-TIME-02, read at each copy (APP-01.3).
        let seconds = self.settings.clipboard_clear();
        let after = seconds.map(|s| Duration::from_secs(u64::from(s)));
        self.clipboard
            .copy(value, after)
            .map_err(|_| LarsalError::NotAvailable)?;
        Ok(Copied {
            label,
            seconds: seconds.unwrap_or(0),
            empty: false,
        })
    }
}

/// The fields a rating reads: the password and its LD-44 inputs.
const RATED: [&str; 4] = ["Password", "Title", "UserName", "URL"];

/// A copy of entry `e` with only the fields a rating reads, to rate
/// outside the session lock (LD-137 (4)). Its values stay secret strings.
fn rating_copy(e: &Entry) -> Entry {
    let mut c = Entry::new(e.uuid, e.times.last_modification);
    for n in RATED {
        if let Some(f) = e.field(n) {
            c.set_field(n.to_owned(), f.duplicate());
        }
    }
    c
}

/// Strength ratings by entry and the Health Check of one unlocked vault
/// (LD-137): bits, ids and reason texts only. Dropped on lock.
#[derive(Default)]
pub(crate) struct Rated {
    bits: HashMap<(Uuid, Time), f64>,
    /// Entries whose health is below Good, once every entry is rated.
    health: Option<HashMap<Uuid, Health>>,
}

struct Health {
    expired: bool,
    reused: bool,
    reasons: Vec<String>,
}

/// A fixed offset from UTC, from the screen layer (larsal-core makes no OS
/// call). ponytail: one offset for every date; a daylight-saving change
/// inside the 30-day expiry window can move a day count by one.
pub(crate) struct Offset(pub(crate) i64);

impl Zone for Offset {
    fn offset(&self, _: Time) -> i64 {
        self.0
    }
}

impl Rated {
    /// LD-139: entry `id` was edited, merged or reloaded: its ratings go
    /// and the Health Check runs again on the next [`Session::rate`]
    /// (reuse and expiry can change with any entry).
    pub(crate) fn forget(&mut self, id: Uuid) {
        self.bits.retain(|(e, _), _| *e != id);
        self.health = None;
    }

    /// Live passwords rated and live passwords in all (the reports'
    /// progress, LD-137 (4)).
    pub(crate) fn progress(&self, vault: &Vault) -> (usize, usize) {
        live(vault)
            .into_iter()
            .filter(|e| !e.value("Password").is_empty())
            .fold((0, 0), |(done, all), e| {
                let key = (e.uuid, e.times.last_modification);
                (done + usize::from(self.bits.contains_key(&key)), all + 1)
            })
    }

    /// Up to `max` passwords not rated yet, as [`rating_copy`]s to rate
    /// outside the session lock (LD-137 (4), LD-126 (8)). When none is
    /// left, runs the Health Check once and gives `None`: done.
    pub(crate) fn todo(
        &mut self,
        vault: &Vault,
        max: usize,
        utc_offset: i64,
    ) -> Option<Vec<Entry>> {
        if self.health.is_some() {
            return None;
        }
        let todo: Vec<Entry> = vault
            .root
            .all_entries()
            .filter(|e| {
                let key = (e.uuid, e.times.last_modification);
                !e.value("Password").is_empty() && !self.bits.contains_key(&key)
            })
            .take(max)
            .map(rating_copy)
            .collect();
        if !todo.is_empty() {
            return Some(todo);
        }
        let ratings = Ratings::with_cache(&zxcvbn_bits, std::mem::take(&mut self.bits));
        let report = health_check(&ratings, vault, Instant::from(now()), &Offset(utc_offset));
        let health = report
            .rows(false, true)
            .into_iter()
            .map(|r| {
                let reused = r
                    .reasons
                    .iter()
                    .any(|x| matches!(x, larsal_core::health::Reason::Reused(_)));
                let reasons = r
                    .reasons
                    .iter()
                    .map(larsal_core::health::Reason::text)
                    .collect();
                (
                    r.entry,
                    Health {
                        expired: r.expired,
                        reused,
                        reasons,
                    },
                )
            })
            .collect();
        self.bits = ratings.into_cache();
        self.health = Some(health);
        None
    }

    /// Keeps the ratings `done` of [`Rated::todo`]'s copies whose entry did
    /// not change while they were rated (an edit in the same second keeps
    /// the key, so the rated fields are compared too).
    pub(crate) fn keep(&mut self, vault: &Vault, done: Vec<(Entry, f64)>) {
        for (c, bits) in done {
            // Any entry, not the first with the id: a file may repeat an id.
            if vault.root.all_entries().any(|e| {
                e.uuid == c.uuid
                    && e.times.last_modification == c.times.last_modification
                    && RATED.iter().all(|n| e.value(n) == c.value(n))
            }) {
                self.bits.insert((c.uuid, c.times.last_modification), bits);
            }
        }
    }

    /// Runs `f` with this vault's ratings, every live password rated first
    /// (the ones `fill` has not reached yet are rated now), so a search's
    /// work bound is not spent on rating (LD-185). The cache stays filled.
    pub(crate) fn with_ratings<R>(
        &mut self,
        vault: &Vault,
        f: impl FnOnce(&Ratings<'_>) -> R,
    ) -> R {
        let ratings = Ratings::with_cache(&zxcvbn_bits, std::mem::take(&mut self.bits));
        ratings.fill(vault);
        let out = f(&ratings);
        self.bits = ratings.into_cache();
        out
    }

    /// Runs the query `query`, with every password rated first when it
    /// asks for `is:weak` (FEA-01.17, LD-185).
    fn search(&mut self, vault: &Vault, query: &str) -> (Vec<Uuid>, Option<String>) {
        if search::rates(query) {
            self.with_ratings(vault, |r| run(vault, query, Some(r)))
        } else {
            run(vault, query, None)
        }
    }

    /// The rating of `e`; rows leave out the notice texts (`issue`,
    /// `reasons`): only the detail shows them.
    fn rating(&self, e: &Entry, full: bool) -> Option<Rating> {
        let pw = e.value("Password");
        if pw.is_empty() || e.exclude_from_reports {
            return None;
        }
        let bits = *self.bits.get(&(e.uuid, e.times.last_modification))?;
        let level = Level::of(score(bits));
        let health = self.health.as_ref().and_then(|h| h.get(&e.uuid));
        let (word, mut issue) = match health {
            Some(h) if h.expired => ("Expired", "Expired password.".to_owned()),
            Some(h) if h.reused => ("Reused", "Reused password.".to_owned()),
            Some(_) => (level.name(), format!("{} password.", level.name())),
            None => (level.name(), String::new()),
        };
        if !full {
            issue.clear();
        }
        Some(Rating {
            level: level.name().to_owned(),
            word: word.to_owned(),
            segments: level.quality(),
            attention: health.is_some(),
            expired: health.is_some_and(|h| h.expired),
            issue,
            reasons: health
                .filter(|_| full)
                .map(|h| h.reasons.clone())
                .unwrap_or_default(),
            chars: count(pw.chars().count()),
            // `as` saturates; E is never negative.
            bits: bits.round() as u32,
        })
    }
}

pub(crate) fn is_favorite(e: &Entry) -> bool {
    e.tags().iter().any(|t| t.eq_ignore_ascii_case(FAVORITE))
}

pub(crate) fn passkey(v: &Vault, e: &Entry) -> Option<PasskeyView> {
    let site = plain(e, "KPEX_PASSKEY_RELYING_PARTY");
    if site.is_empty() {
        return None;
    }
    let user = plain(e, "KPEX_PASSKEY_USERNAME");
    Some(PasskeyView {
        site,
        user: if user.is_empty() {
            plain_in(v, e, "UserName")
        } else {
            user
        },
    })
}

/// The OpenSSH public key types Larsal names, with their labels. Any other
/// text is not a key: it is never echoed (an attachment can hold anything).
const SSH_KEY_TYPES: [(&str, &str); 8] = [
    ("ssh-ed25519", "ED25519"),
    ("ssh-rsa", "RSA"),
    ("ssh-dss", "DSA"),
    ("ecdsa-sha2-nistp256", "ECDSA"),
    ("ecdsa-sha2-nistp384", "ECDSA"),
    ("ecdsa-sha2-nistp521", "ECDSA"),
    ("sk-ssh-ed25519@openssh.com", "ED25519-SK"),
    ("sk-ecdsa-sha2-nistp256@openssh.com", "ECDSA-SK"),
];

/// The label of a known key type at the start of `data` (`<type> `).
pub(crate) fn ssh_type(data: &[u8]) -> Option<(&'static str, &'static str)> {
    SSH_KEY_TYPES.into_iter().find(|(name, _)| {
        data.strip_prefix(name.as_bytes())
            .is_some_and(|rest| rest.first() == Some(&b' '))
    })
}

/// The first attachment that holds an OpenSSH public key line: a known key
/// type, then base64 of a key blob that starts with the same type name,
/// length-prefixed (RFC 4253 section 6.6).
pub(crate) fn ssh_key(e: &Entry) -> Option<SshKeyView> {
    e.attachments.iter().find_map(|a| {
        let data = a.data.expose();
        let (name, label) = ssh_type(data)?;
        let text = std::str::from_utf8(data).ok()?;
        let blob = larsal_format::document::encode::base64_decode(text.split_whitespace().nth(1)?);
        let len = u32::try_from(name.len()).ok()?.to_be_bytes();
        if blob.get(..4) != Some(&len[..]) || blob.get(4..4 + name.len()) != Some(name.as_bytes()) {
            return None;
        }
        let hash = larsal_crypto::hash::sha256(&[&blob]);
        let encoded = larsal_format::document::encode::base64_encode(hash.expose());
        Some(SshKeyView {
            kind: label.to_owned(),
            fingerprint: format!("SHA256:{}", encoded.trim_end_matches('=')),
        })
    })
}

/// The fields that hold one-time password settings are there (rows; the
/// detail and [`Session::codes`] parse them, FEA-04.6).
pub(crate) fn has_totp_fields(e: &Entry) -> bool {
    let filled = |n: &str| e.field(n).is_some_and(|f| !f.value.is_empty());
    e.field(totp::SETTINGS).is_some() || filled(totp::OTP) || filled(totp::FORM_T[0])
}

fn has_passkey(e: &Entry) -> bool {
    e.field("KPEX_PASSKEY_RELYING_PARTY")
        .is_some_and(|f| !f.value.is_empty())
}

fn kind(e: &Entry) -> EntryKind {
    let wifi = e.field("Security").is_some_and(|f| {
        let v = f.value.expose().trim_start().to_ascii_uppercase();
        !f.protected && (v.starts_with("WPA") || v.starts_with("WEP"))
    });
    if e.field("Card number").is_some() {
        EntryKind::Card
    } else if ssh_key(e).is_some() {
        EntryKind::Ssh
    } else if wifi {
        EntryKind::WiFi
    } else {
        EntryKind::Login
    }
}

/// Live entries outside the bin under `g`, in tree order.
fn live_under<'a>(g: &'a Group, bin: Option<Uuid>, out: &mut Vec<&'a Entry>) {
    if Some(g.uuid) == bin {
        return;
    }
    out.extend(g.entries.iter());
    for c in &g.groups {
        live_under(c, bin, out);
    }
}

pub(crate) fn live(vault: &Vault) -> Vec<&Entry> {
    let mut out = Vec::new();
    live_under(&vault.root, larsal_core::recycle::bin_id(vault), &mut out);
    out
}

/// The one-time password fields: never in a view (FEA-04.1).
pub(crate) fn is_totp_field(name: &str) -> bool {
    name == totp::OTP
        || name == totp::SEED
        || name == totp::SETTINGS
        || totp::FORM_T.contains(&name)
        || name.starts_with("TimeOtp-")
}

pub(crate) fn now() -> Time {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Time::from_unix(secs).unwrap_or_default()
}

/// Seconds since year 1 to unix seconds.
pub(crate) fn unix(t: Time) -> i64 {
    t.0.saturating_sub(62_135_596_800)
}

/// Lowercase hex, the id form Swift sees.
pub(crate) fn hex(id: Uuid) -> String {
    format!("{id:?}")
}

/// An id from Swift: exactly 32 ASCII hex digits, else `bad` (a sign such as
/// `+` is not a digit).
pub(crate) fn parse_id(text: &str, bad: LarsalError) -> Result<Uuid, LarsalError> {
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad);
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = text.get(i * 2..i * 2 + 2).ok_or_else(|| bad.clone())?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| bad.clone())?;
    }
    Ok(Uuid(out))
}

/// The name of custom icon `icon` in `v`; `None` for a standard icon.
pub(crate) fn custom_icon_name(v: &Vault, icon: Icon) -> Option<String> {
    match icon {
        Icon::Custom(id) => v
            .meta
            .custom_icons
            .iter()
            .find(|i| i.uuid == id)
            .map(|i| i.name.clone()),
        Icon::Standard(_) => None,
    }
}

pub(crate) fn icon_number(icon: Icon) -> i32 {
    match icon {
        Icon::Standard(n) => n,
        Icon::Custom(_) => -1,
    }
}

/// Hidden from the screen until Show (MOD-01.7, LD-207): the field's own
/// protected flag, or the vault's flag for a standard field (as larsal-core
/// `refs` masks).
pub(crate) fn is_protected(v: &Vault, name: &str, f: &larsal_model::Field) -> bool {
    f.protected || v.meta.memory_protection.for_field(name)
}

/// A field's value when not protected by [`is_protected`]; empty otherwise.
pub(crate) fn plain_in(v: &Vault, e: &Entry, name: &str) -> String {
    match e.field(name) {
        Some(f) if !is_protected(v, name, f) => f.value.expose().to_owned(),
        _ => String::new(),
    }
}

/// A field's value when its own flag is off; empty otherwise. Only for
/// fields the vault flags never cover; standard fields use [`plain_in`].
pub(crate) fn plain(e: &Entry, name: &str) -> String {
    match e.field(name) {
        Some(f) if !f.protected => f.value.expose().to_owned(),
        _ => String::new(),
    }
}

/// The host of a URL as the mockup shows it, or the text itself.
pub(crate) fn host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest.get(..end).unwrap_or(rest);
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    if host.is_empty() { url } else { host }.to_owned()
}

pub(crate) fn row(v: &Vault, e: &Entry, at: Instant, rated: &Rated, in_bin: bool) -> EntryRow {
    let mut subtitle = plain_in(v, e, "UserName");
    if subtitle.is_empty() {
        let url = plain_in(v, e, "URL");
        if !url.is_empty() {
            subtitle = host(&url);
        }
    }
    if subtitle.is_empty() {
        subtitle = e
            .fields()
            .find(|(n, f)| {
                !f.protected
                    && !STANDARD_FIELDS.contains(n)
                    && !is_totp_field(n)
                    && !n.starts_with(PASSKEY)
                    && !f.value.is_empty()
            })
            .map(|(_, f)| f.value.expose().to_owned())
            .unwrap_or_default();
    }
    EntryRow {
        id: hex(e.uuid),
        title: plain_in(v, e, "Title"),
        subtitle,
        icon: icon_number(e.icon),
        custom_icon: custom_icon_name(v, e.icon),
        created: unix(e.times.creation),
        modified: unix(e.times.last_modification),
        expired: is_expired(&e.times, at),
        host: url_host(v, e),
        favorite: is_favorite(e),
        has_totp: has_totp_fields(e),
        passkey: has_passkey(e),
        kind: kind(e),
        has_password: !e.value("Password").is_empty(),
        rating: rated.rating(e, false),
        deleted: in_bin.then(|| unix(e.times.location_changed)),
    }
}

fn url_host(v: &Vault, e: &Entry) -> String {
    let url = plain_in(v, e, "URL");
    if url.is_empty() {
        String::new()
    } else {
        host(&url)
    }
}

/// The groups from the root down to the group holding `id`, or `None`.
pub(crate) fn find<'a>(g: &'a Group, id: Uuid, chain: &mut Vec<&'a Group>) -> Option<&'a Entry> {
    chain.push(g);
    if let Some(e) = g.entries.iter().find(|e| e.uuid == id) {
        return Some(e);
    }
    for child in &g.groups {
        if let Some(e) = find(child, id, chain) {
            return Some(e);
        }
    }
    chain.pop();
    None
}

pub(crate) fn entry_of<'a>(vault: &'a Vault, id: &str) -> Result<&'a Entry, LarsalError> {
    let id = parse_id(id, LarsalError::UnknownEntry)?;
    find(&vault.root, id, &mut Vec::new()).ok_or(LarsalError::UnknownEntry)
}

pub(crate) fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The search limit notice (FEA-01.31).
pub(crate) const LIMIT_NOTICE: &str = "A pattern in this search is not valid or is too large.";

/// Runs a query; ids and the notice. `ratings`: for `is:weak`; without,
/// it matches nothing.
fn run(vault: &Vault, query: &str, ratings: Option<&Ratings<'_>>) -> (Vec<Uuid>, Option<String>) {
    let mut o = Options::new(now());
    o.ratings = ratings;
    match search::search(vault, query, &o) {
        Ok(found) => (found.ids, found.invalid.then(|| LIMIT_NOTICE.to_owned())),
        Err(_) => (
            Vec::new(),
            Some("This search is too long. Shorten it and try again.".to_owned()),
        ),
    }
}

fn sidebar_of(vault: &Vault, path: &Path, rated: &Rated) -> Sidebar {
    let bin = larsal_core::recycle::bin_id(vault);
    let mut groups = Vec::new();
    let mut tags: HashMap<&str, u32> = HashMap::new();
    fn walk<'a>(
        vault: &Vault,
        g: &'a Group,
        depth: u32,
        bin: Option<Uuid>,
        out: &mut Vec<GroupRow>,
        tags: &mut HashMap<&'a str, u32>,
    ) {
        for e in &g.entries {
            for t in e.tags() {
                *tags.entry(t.as_str()).or_default() += 1;
            }
        }
        for child in g.groups.iter().filter(|c| Some(c.uuid) != bin) {
            let mut under = Vec::new();
            live_under(child, bin, &mut under);
            out.push(GroupRow {
                id: hex(child.uuid),
                name: child.name.clone(),
                depth,
                count: count(under.len()),
                icon: icon_number(child.icon),
                custom_icon: custom_icon_name(vault, child.icon),
                has_children: child.groups.iter().any(|c| Some(c.uuid) != bin),
                expanded: child.expanded,
            });
            walk(vault, child, depth.saturating_add(1), bin, out, tags);
        }
    }
    walk(vault, &vault.root, 0, bin, &mut groups, &mut tags);
    let bin_count = bin
        .and_then(|id| vault.root.find_group(id))
        .map(|b| count(b.all_entries().count()));
    let entries = live(vault);
    let saved_at = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_secs()).ok());
    Sidebar {
        all: count(run(vault, search::ALL, None).0.len()),
        expired: count(run(vault, search::EXPIRED, None).0.len()),
        groups,
        tags: larsal_core::tags::vault_tags(vault)
            .into_iter()
            .filter(|name| !name.eq_ignore_ascii_case(FAVORITE))
            .map(|name| TagRow {
                count: tags.get(name.as_str()).copied().unwrap_or(0),
                name,
            })
            .collect(),
        bin: bin_count,
        favorites: count(entries.iter().filter(|e| is_favorite(e)).count()),
        codes: count(
            entries
                .iter()
                .filter(|e| totp::settings(e).is_some())
                .count(),
        ),
        passkeys: count(
            entries
                .iter()
                .filter(|e| passkey(vault, e).is_some())
                .count(),
        ),
        attention: rated.health.as_ref().map(|h| count(h.len())),
        saved_at,
        created: unix(vault.root.times.creation),
        root: hex(vault.root.uuid),
    }
}

fn list_of(vault: &Vault, view: &ListView, rated: &mut Rated) -> Result<EntryList, LarsalError> {
    // Searches that need ratings run first, with the session's cache.
    let searched = match view {
        ListView::Weak => Some(rated.search(vault, search::WEAK)),
        ListView::Search { query } if query.len() <= MAX_TEXT => Some(rated.search(vault, query)),
        _ => None,
    };
    let rated: &Rated = rated;
    let at = Instant::from(now());
    let index: HashMap<Uuid, &Entry> = vault.root.all_entries().map(|e| (e.uuid, e)).collect();
    let rows_of = |ids: &[Uuid]| -> Vec<EntryRow> {
        ids.iter()
            .filter_map(|id| index.get(id))
            .map(|e| row(vault, e, at, rated, false))
            .collect()
    };
    let live_rows = |keep: &dyn Fn(&Entry) -> bool| -> Vec<EntryRow> {
        live(vault)
            .into_iter()
            .filter(|e| keep(e))
            .map(|e| row(vault, e, at, rated, false))
            .collect()
    };
    let (rows, notice) = match view {
        ListView::All => (rows_of(&run(vault, search::ALL, None).0), None),
        ListView::Expired => (rows_of(&run(vault, search::EXPIRED, None).0), None),
        ListView::Weak => {
            let (ids, notice) = searched.unwrap_or_default();
            (rows_of(&ids), notice)
        }
        ListView::Favorites => (live_rows(&is_favorite), None),
        ListView::Codes => (live_rows(&|e| totp::settings(e).is_some()), None),
        ListView::Passkeys => (live_rows(&|e| passkey(vault, e).is_some()), None),
        ListView::Group { id } => {
            let id = parse_id(id, LarsalError::UnknownGroup)?;
            let g = vault.root.find_group(id).ok_or(LarsalError::UnknownGroup)?;
            let mut under = Vec::new();
            live_under(g, larsal_core::recycle::bin_id(vault), &mut under);
            let rows = under
                .into_iter()
                .map(|e| row(vault, e, at, rated, false))
                .collect();
            (rows, None)
        }
        ListView::Tag { name } => {
            if name.len() > MAX_TEXT {
                return Err(LarsalError::TooLong);
            }
            let found = search::search_tags(vault, &[name.as_str()], &Options::new(now()));
            (rows_of(&found.ids), None)
        }
        ListView::Bin => {
            let bin = larsal_core::recycle::bin_id(vault).and_then(|id| vault.root.find_group(id));
            (
                bin.map_or_else(Vec::new, |b| {
                    b.all_entries()
                        .map(|e| row(vault, e, at, rated, true))
                        .collect()
                }),
                None,
            )
        }
        ListView::Search { query } => {
            if query.len() > MAX_TEXT {
                return Err(LarsalError::TooLong);
            }
            let (ids, notice) = searched.unwrap_or_default();
            (rows_of(&ids), notice)
        }
    };
    Ok(EntryList { rows, notice })
}

fn detail_of(vault: &Vault, id: &str, rated: &Rated) -> Result<EntryDetail, LarsalError> {
    let uuid = parse_id(id, LarsalError::UnknownEntry)?;
    let mut chain = Vec::new();
    let e = find(&vault.root, uuid, &mut chain).ok_or(LarsalError::UnknownEntry)?;
    let bin = larsal_core::recycle::bin_id(vault);
    let field = |name: &str, kind: FieldKind, f: &larsal_model::Field| FieldView {
        name: name.to_owned(),
        kind,
        value: if is_protected(vault, name, f) {
            String::new()
        } else {
            f.value.expose().to_owned()
        },
        protected: is_protected(vault, name, f),
    };
    let mut fields = Vec::new();
    for (name, kind) in [
        ("UserName", FieldKind::UserName),
        ("Password", FieldKind::Password),
        ("URL", FieldKind::Url),
        ("Notes", FieldKind::Notes),
    ] {
        if let Some(f) = e.field(name).filter(|f| !f.value.is_empty()) {
            fields.push(field(name, kind, f));
        }
    }
    // MOD-01.8: passkey fields are left out of the detail view.
    for (name, f) in e.fields() {
        if !STANDARD_FIELDS.contains(&name) && !is_totp_field(name) && !name.starts_with(PASSKEY) {
            fields.push(field(name, FieldKind::Custom, f));
        }
    }
    let in_bin = chain.iter().any(|g| Some(g.uuid) == bin);
    let parent = chain.last().copied().unwrap_or(&vault.root);
    let deleted_from = e
        .previous_parent
        .filter(|_| in_bin)
        .filter(|&p| !larsal_core::recycle::group_in_bin(vault, p))
        .and_then(|p| vault.root.find_group(p))
        .map(|g| g.name.clone());
    Ok(EntryDetail {
        id: hex(e.uuid),
        title: plain_in(vault, e, "Title"),
        icon: icon_number(e.icon),
        path: chain.iter().skip(1).map(|g| g.name.clone()).collect(),
        in_bin,
        fields,
        has_totp: totp::settings(e).is_some(),
        attachments: e
            .attachments
            .iter()
            .map(|a| AttachmentView {
                name: a.name.clone(),
                size: u64::try_from(a.data.len()).unwrap_or(u64::MAX),
            })
            .collect(),
        tags: e
            .tags()
            .iter()
            .filter(|t| !t.eq_ignore_ascii_case(FAVORITE))
            .cloned()
            .collect(),
        expires: e.times.expires.then(|| unix(e.times.expiry)),
        expired: is_expired(&e.times, Instant::from(now())),
        created: unix(e.times.creation),
        modified: unix(e.times.last_modification),
        accessed: unix(e.times.last_access),
        history: count(e.history.len()),
        kind: kind(e),
        host: url_host(vault, e),
        favorite: is_favorite(e),
        group: parent.name.clone(),
        group_icon: if parent.uuid == vault.root.uuid {
            -1
        } else {
            icon_number(parent.icon)
        },
        custom_icon: custom_icon_name(vault, e.icon),
        group_custom_icon: (parent.uuid != vault.root.uuid)
            .then(|| custom_icon_name(vault, parent.icon))
            .flatten(),
        deleted: in_bin.then(|| unix(e.times.location_changed)),
        deleted_from,
        passkey: passkey(vault, e),
        ssh: ssh_key(e),
        rating: rated.rating(e, true),
        group_id: hex(parent.uuid),
    })
}

pub(crate) fn totp_of(e: &Entry) -> Option<TotpView> {
    let settings = totp::settings(e)?;
    let at = now();
    let problem = settings.problem().map(|p| {
        match p {
            Problem::UnsupportedType => "Unsupported type",
            Problem::InvalidKey => "Invalid key",
            Problem::InvalidStep => "Invalid step",
            Problem::InvalidDigits => "Invalid digits",
        }
        .to_owned()
    });
    let code = settings
        .code(at)
        .map(|c| totp::display(c.expose()).expose().to_owned());
    Some(TotpView {
        seconds_left: if code.is_some() {
            settings.seconds_left(at).unwrap_or(0)
        } else {
            0
        },
        code: code.unwrap_or_default(),
        period: settings.period,
        problem,
    })
}

/// The full resolution of `text` in entry `e` (MOD-08.25) for Show and
/// Copy, in larsal-core's shared Copy context (`refs::copy_context`, which the
/// SSH passphrase uses too): `{S:…}` of a one-time password or passkey
/// field gives nothing (LD-170 (4)), so neither lets their raw value out.
pub(crate) fn resolved(
    v: &Vault,
    path: &Path,
    e: &Entry,
    text: &str,
) -> larsal_crypto::secret::SecretString {
    let dir = path.parent().unwrap_or(path).to_string_lossy();
    // LD-126: one work meter per resolution, so a field holding thousands
    // of references stops at the budget (its raw text is then shown).
    let meter = std::cell::Cell::new(refs::COPY_BUDGET);
    refs::resolve(text, e, &refs::copy_context(v, &dir, now(), &meter)).text
}

/// Show and Copy take any field but the one-time password fields and the
/// passkey fields: their secrets never leave Rust (the code comes from
/// [`Session::totp`]; passkeys stay hidden, MOD-01.8, F-057).
pub(crate) fn check_field(name: &str) -> Result<(), LarsalError> {
    if name.len() > MAX_TEXT {
        return Err(LarsalError::TooLong);
    }
    if is_totp_field(name) || name.starts_with(PASSKEY) {
        return Err(LarsalError::UnknownField);
    }
    Ok(())
}

#[uniffi::export]
impl Session {
    /// The sidebar of vault `vault`: counts, groups and tags. No secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn sidebar(&self, vault: u64) -> Result<Sidebar, LarsalError> {
        self.with_open(vault, |v, path, rated| Ok(sidebar_of(v, path, rated)))
    }

    /// The rows of one view; a search runs through larsal-core (FEA-01) and
    /// stays within its work bound (about 250 ms whatever the vault). No
    /// secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup`, `TooLong`.
    pub fn list(&self, vault: u64, view: ListView) -> Result<EntryList, LarsalError> {
        self.with_open(vault, |v, _, rated| list_of(v, &view, rated))
    }

    /// The detail view of entry `entry` (32 hex digits) of vault `vault`.
    /// Protected fields come with an empty value. No secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry` (also for an id of another
    /// vault).
    pub fn entry(&self, vault: u64, entry: String) -> Result<EntryDetail, LarsalError> {
        self.with_open(vault, |v, _, rated| detail_of(v, &entry, rated))
    }

    /// Runs a typed query (FEA-01) and returns the ids of the hits only:
    /// the screen maps them onto the All Entries rows it holds, so a search
    /// sends no row again (FEA-01.34). No secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong`.
    pub fn search(&self, vault: u64, query: String) -> Result<SearchHits, LarsalError> {
        if query.len() > MAX_TEXT {
            return Err(LarsalError::TooLong);
        }
        self.with_open(vault, |v, _, rated| {
            // With the session's ratings, so a typed `is:weak` matches as
            // the Weak view does (FEA-01.17, FEA-01.28, LD-185).
            let (ids, notice) = rated.search(v, &query);
            Ok(SearchHits {
                ids: ids.into_iter().map(hex).collect(),
                notice,
            })
        })
    }

    /// Rates up to `max` more passwords of vault `vault` (FEA-05.9, LD-137:
    /// call it off the screen thread, in small steps; the rating runs
    /// outside the session lock, so screen calls do not wait for it); once
    /// all are rated, runs the Health Check with the
    /// local offset `utc_offset` in seconds. True when done; rows, the
    /// detail and the sidebar then carry ratings. No secret.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn rate(&self, vault: u64, max: u32, utc_offset: i32) -> Result<bool, LarsalError> {
        let todo = self.with_open(vault, |v, _, rated| {
            Ok(rated.todo(v, max as usize, i64::from(utc_offset)))
        })?;
        let Some(todo) = todo else {
            return Ok(true);
        };
        // ponytail: two callers at once may rate the same passwords twice
        // (the list's fill and the reports); the second keep is the same.
        let done = todo
            .into_iter()
            .map(|c| {
                let bits = entry_bits(c.value("Password"), &c);
                (c, bits)
            })
            .collect();
        self.with_open(vault, |v, _, rated| {
            rated.keep(v, done);
            Ok(false)
        })
    }

    /// The current one-time code of each entry in `entries` (32 hex digits
    /// each), in order; `None` for an entry without settings. For the
    /// list's code column (FEA-04.24): ask once a second for the rows on
    /// screen. A crossing of LD-220: live one-time codes, never the secret
    /// they come from.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`, `TooLong` (over 200 ids).
    pub fn codes(
        &self,
        vault: u64,
        entries: Vec<String>,
    ) -> Result<Vec<Option<TotpView>>, LarsalError> {
        if entries.len() > MAX_CODES {
            return Err(LarsalError::TooLong);
        }
        self.with_vault(vault, |v| {
            let index: HashMap<Uuid, &Entry> = v.root.all_entries().map(|e| (e.uuid, e)).collect();
            entries
                .iter()
                .map(|id| {
                    let id = parse_id(id, LarsalError::UnknownEntry)?;
                    index
                        .get(&id)
                        .map(|e| totp_of(e))
                        .ok_or(LarsalError::UnknownEntry)
                })
                .collect()
        })
    }

    /// Show: the value of field `field` of entry `entry`, at the moment the
    /// user asked, resolved in full as the detail shows it (MOD-08.25); a
    /// placeholder for a one-time password or passkey field gives nothing
    /// (LD-170 (4)). A crossing of LD-220: the Show value; Swift drops it
    /// on Hide, on entry change and on lock.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`, `UnknownField`, `TooLong`.
    pub fn show_field(
        &self,
        vault: u64,
        entry: String,
        field: String,
    ) -> Result<String, LarsalError> {
        check_field(&field)?;
        self.with_open(vault, |v, path, _| {
            let e = entry_of(v, &entry)?;
            let f = e.field(&field).ok_or(LarsalError::UnknownField)?;
            Ok(resolved(v, path, e, f.value.expose()).expose().to_owned())
        })
    }

    /// Copy (APP-03): resolves field `field` of entry `entry` in full
    /// (MOD-08.26) and puts it on the clipboard in Rust, marked concealed
    /// and transient, cleared after 10 seconds while still Larsal's copy, and
    /// on every lock. The value never reaches Swift: the answer holds only
    /// the notice's label and seconds. An empty value copies nothing
    /// (APP-03.5). The one-time password and passkey fields are refused.
    ///
    /// # Errors
    /// `NotAvailable` when the clipboard could not be written
    /// (`MSG-COPY-FAILED`), or the errors of [`Session::show_field`].
    pub fn copy_field(
        &self,
        vault: u64,
        entry: String,
        field: String,
    ) -> Result<Copied, LarsalError> {
        check_field(&field)?;
        self.with_open(vault, |v, path, _| {
            let e = entry_of(v, &entry)?;
            let f = e.field(&field).ok_or(LarsalError::UnknownField)?;
            let value = resolved(v, path, e, f.value.expose());
            self.copy_value(label(&field), value.expose())
        })
    }

    /// Copy of the current one-time code of entry `entry` (APP-03.1
    /// `copy.totp`, FEA-04): computed now in Rust, without the display
    /// space, and copied under the same rules as [`Session::copy_field`].
    /// Neither the code nor its secret reaches Swift.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `UnknownField` when the
    /// entry has no valid one-time password settings (APP-03.4);
    /// `NotAvailable` when the clipboard could not be written.
    pub fn copy_code(&self, vault: u64, entry: String) -> Result<Copied, LarsalError> {
        self.with_vault(vault, |v| {
            let code =
                totp::code_for(entry_of(v, &entry)?, now()).ok_or(LarsalError::UnknownField)?;
            self.copy_value("One-time password".to_owned(), code.expose())
        })
    }

    /// Copy of the SSH key fingerprint of entry `entry`, the one the detail
    /// shows ([`SshKeyView`]), under the same rules as
    /// [`Session::copy_field`].
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `UnknownField` when the
    /// entry holds no OpenSSH public key; `NotAvailable` when the clipboard
    /// could not be written.
    pub fn copy_fingerprint(&self, vault: u64, entry: String) -> Result<Copied, LarsalError> {
        self.with_vault(vault, |v| {
            let key = ssh_key(entry_of(v, &entry)?).ok_or(LarsalError::UnknownField)?;
            self.copy_value("Fingerprint".to_owned(), &key.fingerprint)
        })
    }

    /// The current one-time code of entry `entry` with its seconds left,
    /// computed now; `None` when it has no one-time password. Ask once a
    /// second, only for the entry on screen. A crossing of LD-220: the live
    /// code, shown on screen (FEA-04.24); the secret never leaves Rust.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`.
    pub fn totp(&self, vault: u64, entry: String) -> Result<Option<TotpView>, LarsalError> {
        self.with_vault(vault, |v| Ok(totp_of(entry_of(v, &entry)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_hosts() {
        let id = Uuid([0xab; 16]);
        assert_eq!(parse_id(&hex(id), LarsalError::UnknownEntry), Ok(id));
        for bad in [
            "",
            "ab",
            &"zz".repeat(16),
            &"ab".repeat(17),
            &"é".repeat(16),
            &"+a".repeat(16),
        ] {
            assert_eq!(
                parse_id(bad, LarsalError::UnknownEntry),
                Err(LarsalError::UnknownEntry)
            );
        }
        assert_eq!(
            host("https://user@example.com:8443/login?x"),
            "example.com:8443"
        );
        assert_eq!(host("ssh://203.0.113.10"), "203.0.113.10");
        assert_eq!(host("example.com/path"), "example.com");
        assert_eq!(host("cmd://"), "cmd://");
    }
}
