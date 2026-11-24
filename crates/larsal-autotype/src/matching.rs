//! Candidates, window matching and the picker model (INT-05.19 to
//! INT-05.31, E8-S2). It types nothing and shows nothing: the screen layer
//! gets [`Row`]s and sends back the chosen row.
//!
//! - [`Picker::open`] matches the captured window title against every
//!   candidate of every unlocked vault (INT-05.19 to INT-05.24);
//!   [`Picker::single`] says when to type without the picker (INT-05.25
//!   step 7); [`Picker::rows`] is the list for a search text (INT-05.26,
//!   INT-05.27).
//! - [`Memory`] is "Preselect the previous choice for" (S-AT-08,
//!   INT-05.28, INT-05.31, D-INT05-12) on a clock the caller passes in.
//! - [`actions`] is INT-05.33's rule as LD-177 (R05-1) rules it: which of
//!   Type Login, Username Only and Password Only an entry offers.
//!
//! Guarantees:
//! - Bin entries, entries with Auto-Type off and entries of groups whose
//!   switch is Off are never rows (LD-57, SD-05); no row has an empty
//!   sequence (R05-1).
//! - Bounded on any vault and any title (AT-G03): a title over
//!   [`MAX_TITLE`] bytes is not matched (as an empty one, INT-05.24); an
//!   entry text or sequence over [`MAX_TEXT`] bytes never matches and makes
//!   no row; patterns go through `larsal_core::pattern` with search's bounds
//!   (LD-113, LD-116, LD-122, LD-123), each distinct pattern compiled and
//!   tested once per run (LD-120); one work meter per call ([`BUDGET`])
//!   pays for every resolution (LD-118's regex budget included), compile,
//!   scan, fold and row. When it runs out, the rest matches nothing and the
//!   result says `limited`, which always opens the picker. Wildcards and
//!   "occurs in" tests run in linear time.
//! - No secret in a [`Row`] (INT-05.45, LD-191 R02-2, LD-196 (1)): a title
//!   or user name that is protected, or whose resolution reads a protected
//!   value, a one-time password field or a passkey field, is empty with its
//!   `hidden` flag set. Resolved texts and their case-folded
//!   copies live in `SecretString`s. A pattern whose resolution reads a
//!   protected value matches nothing, so no secret reaches the pattern
//!   engine (LD-114).

use core::cell::Cell;
use larsal_core::edit::{DEFAULT_SEQUENCE, natural_cmp_folded};
use larsal_core::expiry::is_expired;
use larsal_core::pattern::{self, Compiled, MIN_CHARGED};
use larsal_core::recycle::bin_id;
use larsal_core::refs::{self, CHAR_UNITS, COMPILE_UNITS, Context, EntryIndex, REGEX_PER_UNIT};
use larsal_core::search;
use larsal_core::time::{Instant as At, Zone};
use larsal_core::totp;
use larsal_core::url::host_unicode;
use larsal_crypto::secret::SecretString;
use larsal_model::entry::cmp_utf16;
use larsal_model::{Entry, Group, Switch, Time, Uuid, Vault};
use regex_syntax::hir::{ClassUnicode, ClassUnicodeRange};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// The longest window title Larsal matches, in bytes (Larsal bound, the size of
/// INT-01.25's page URL); a longer one is treated as empty (INT-05.24).
pub const MAX_TITLE: usize = 8_192;
/// The longest entry text (window rule, title, URL) that may match and the
/// longest sequence a row may carry, in bytes (LD-113's text bound).
pub const MAX_TEXT: usize = 65_536;
/// The work meter of one [`Picker::open`] or [`Picker::rows`] call, in
/// LD-126 units (about a nanosecond each on the build Mac): search's run
/// budget.
pub const BUDGET: usize = search::RUN_BUDGET;
/// S-AT-08's largest value, in seconds (INT-05.31).
pub const REMEMBER_MAX: u32 = 60;
/// S-AT-08's default, in seconds (INT-05.31).
pub const REMEMBER_DEFAULT: u32 = 15;

/// Meter units of one resolution besides its own work.
const RESOLVE_UNITS: usize = 1_000;
/// Meter units of one candidate, one window rule looked at, or one row
/// made besides its bytes.
const STEP_UNITS: usize = 64;
/// Meter units per byte of a non-ASCII text to case-fold (each non-ASCII
/// character asks the case tables).
const FOLD_UNITS: usize = 300;

/// The Auto-Type settings this part reads (APP-01, General › Auto-Type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// S-AT-01 match by window title (on).
    pub by_title: bool,
    /// S-AT-02 match by URL in the title (on).
    pub by_url: bool,
    /// S-AT-03 always ask (on, D-INT05-14).
    pub always_ask: bool,
    /// S-AT-04 don't ask when starting from Larsal's window (off).
    pub dont_ask_from_window: bool,
    /// S-AT-05 skip expired entries (off).
    pub skip_expired: bool,
    /// S-AT-08 remember the choice, seconds, used up to 60 (15).
    pub remember_secs: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            by_title: true,
            by_url: true,
            always_ask: true,
            dont_ask_from_window: false,
            skip_expired: false,
            remember_secs: REMEMBER_DEFAULT,
        }
    }
}

impl Settings {
    /// Whether Type Login and the two field actions ask MI05-50 first
    /// (INT-05.33 step 2).
    #[must_use]
    pub fn asks_from_window(&self) -> bool {
        self.always_ask && !self.dont_ask_from_window
    }
}

/// One unlocked vault.
#[derive(Clone, Copy)]
pub struct Open<'a> {
    /// The caller's id for it, stable while it stays unlocked.
    pub id: u64,
    /// The vault.
    pub vault: &'a Vault,
    /// The vault file's folder for `{DB_DIR}`, no trailing slash.
    pub dir: &'a str,
}

/// What matching runs over.
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    /// Every unlocked vault.
    pub vaults: &'a [Open<'a>],
    /// The clock, for placeholders and expiry.
    pub now: Time,
    /// Local time zone rules, for date placeholders.
    pub zone: &'a dyn Zone,
    /// The settings.
    pub settings: &'a Settings,
}

/// One picker row: an entry and the sequence it types (INT-05.23,
/// INT-05.26). It holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The vault's [`Open::id`].
    pub vault: u64,
    /// The entry.
    pub entry: Uuid,
    /// The sequence to type, never empty.
    pub sequence: String,
    /// The title resolved for display, its first 1,024 characters; empty
    /// when hidden.
    pub title: String,
    /// The title is protected or reads a protected value (LD-191 R02-2).
    pub title_hidden: bool,
    /// The user name, as the title.
    pub username: String,
    /// As `title_hidden`.
    pub username_hidden: bool,
    /// Expired (drawn struck through, MOD-09.14).
    pub expired: bool,
}

/// The longest title or user name a row shows, in characters.
const SHOWN_CHARS: usize = 1_024;

/// The matching rows of one captured window (INT-05.20 to INT-05.24).
#[derive(Debug, Clone)]
pub struct Picker {
    matched: Vec<Row>,
    limited: bool,
    always_ask: bool,
}

impl Picker {
    /// Matches `title`, the captured window title, against every candidate
    /// of every vault in `scope` (INT-05.19 to INT-05.24).
    #[must_use]
    pub fn open(title: &str, scope: &Scope<'_>) -> Picker {
        let meter = Cell::new(BUDGET);
        let run = Run::new(title, &meter, scope.settings);
        let mut matched = Vec::new();
        if run.usable {
            for open in scope.vaults {
                let index = EntryIndex::new(open.vault);
                let (plain, shown) = contexts(open, scope, &index, &meter);
                for c in candidates(open.vault, scope.settings.skip_expired, scope.now) {
                    if !run.pay(STEP_UNITS) {
                        break;
                    }
                    let seqs = run.entry_rows(&c, &plain, &shown);
                    run.rows(&mut matched, open, &c, seqs, &plain, &shown, scope.now);
                }
            }
        }
        Picker {
            matched,
            limited: run.limited.get(),
            always_ask: scope.settings.always_ask,
        }
    }

    /// The matching rows in collection order (INT-05.23).
    #[must_use]
    pub fn matched(&self) -> &[Row] {
        &self.matched
    }

    /// The work meter ran out: some entries were not matched.
    #[must_use]
    pub fn limited(&self) -> bool {
        self.limited
    }

    /// The row to type without the picker (INT-05.25 step 7): S-AT-03 off,
    /// exactly one row, a title, no search text, and the meter not out.
    #[must_use]
    pub fn single(&self, search: &str) -> Option<&Row> {
        if self.always_ask || self.limited || !search::is_blank(search) {
            return None;
        }
        match self.matched.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }

    /// The picker's list for the search field's text (INT-05.27), sorted
    /// (INT-05.26), and whether a meter ran out or the search text was not
    /// valid (FEA-01.31). Blank text: the matching
    /// rows, else every candidate's rows. Other text: the entries FEA-01
    /// finds in every vault, kept when candidates; one with matching rows
    /// shows those, any other one its effective sequence and each other
    /// distinct sequence of its window rules.
    #[must_use]
    pub fn rows(&self, text: &str, scope: &Scope<'_>) -> (Vec<Row>, bool) {
        let blank = search::is_blank(text);
        let mut out = Vec::new();
        let mut limited = self.limited;
        if blank && !self.matched.is_empty() {
            out.clone_from(&self.matched);
        } else {
            let meter = Cell::new(BUDGET);
            let run = Run::new("", &meter, scope.settings);
            let mut mine: HashMap<(u64, Uuid), Vec<&Row>> = HashMap::new();
            for r in &self.matched {
                mine.entry((r.vault, r.entry)).or_default().push(r);
            }
            for open in scope.vaults {
                let index = EntryIndex::new(open.vault);
                let (plain, shown) = contexts(open, scope, &index, &meter);
                let cands = candidates(open.vault, scope.settings.skip_expired, scope.now);
                let picked: Vec<&Cand<'_>> = if blank {
                    cands.iter().collect()
                } else {
                    let by_id: HashMap<Uuid, &Cand<'_>> =
                        cands.iter().map(|c| (c.entry.uuid, c)).collect();
                    let o = search::Options {
                        zone: scope.zone,
                        ..search::Options::new(scope.now)
                    };
                    let found = search::search(open.vault, text, &o).map_or_else(
                        |_| Vec::new(),
                        |f| {
                            limited |= f.invalid;
                            f.ids
                        },
                    );
                    found
                        .iter()
                        .filter_map(|id| by_id.get(id).copied())
                        .collect()
                };
                for c in picked {
                    if let Some(rows) = mine.get(&(open.id, c.entry.uuid)) {
                        out.extend(rows.iter().map(|r| (*r).clone()));
                        continue;
                    }
                    let rules = c.entry.auto_type.associations.iter();
                    let seqs = core::iter::once(c.seq)
                        .chain(rules.map(|a| a.sequence.as_str()))
                        .take_while(|_| run.pay(STEP_UNITS));
                    let seqs = distinct(seqs);
                    run.rows(&mut out, open, c, seqs, &plain, &shown, scope.now);
                }
            }
            limited |= run.limited.get();
        }
        // LD-196: case is the last tie-break, after user name and sequence.
        out.sort_by(|a, b| {
            natural_cmp_folded(&a.title, &b.title)
                .then_with(|| natural_cmp_folded(&a.username, &b.username))
                .then_with(|| a.sequence.cmp(&b.sequence))
                .then_with(|| cmp_utf16(&a.title, &b.title))
                .then_with(|| cmp_utf16(&a.username, &b.username))
        });
        (out, limited)
    }
}

/// The remembered choice (S-AT-08, INT-05.31): ids and the sequence typed,
/// never a value.
#[derive(Debug, Clone, Default)]
pub struct Memory {
    choice: Option<Choice>,
}

#[derive(Debug, Clone)]
struct Choice {
    vault: u64,
    entry: Uuid,
    sequence: String,
    until: Instant,
}

impl Memory {
    /// The user typed `row` from the picker at `now`: remember it for
    /// `secs` seconds (used up to 60); 0 remembers nothing. Each choice
    /// starts the time again.
    pub fn remember(&mut self, row: &Row, secs: u32, now: Instant) {
        let secs = Duration::from_secs(secs.min(REMEMBER_MAX).into());
        self.choice = now
            .checked_add(secs)
            .filter(|_| !secs.is_zero())
            .map(|until| Choice {
                vault: row.vault,
                entry: row.entry,
                sequence: row.sequence.clone(),
                until,
            });
    }

    /// A vault locked: its remembered choice goes.
    pub fn forget_vault(&mut self, vault: u64) {
        if self.choice.as_ref().is_some_and(|c| c.vault == vault) {
            self.choice = None;
        }
    }

    /// When the remembered time ends (INT-05.32's last relock point).
    #[must_use]
    pub fn until(&self) -> Option<Instant> {
        self.choice.as_ref().map(|c| c.until)
    }

    /// The row to highlight (INT-05.28): while a choice is remembered, the
    /// row with its vault, entry and sequence, else the first row of its
    /// entry; otherwise the first row.
    #[must_use]
    pub fn highlight(&self, rows: &[Row], now: Instant) -> usize {
        let Some(c) = self.choice.as_ref().filter(|c| now < c.until) else {
            return 0;
        };
        let same = |r: &&Row| r.vault == c.vault && r.entry == c.entry;
        rows.iter()
            .position(|r| same(&r) && r.sequence == c.sequence)
            .or_else(|| rows.iter().position(|r| same(&r)))
            .unwrap_or(0)
    }
}

/// Which Auto-Type actions an entry or a row's entry offers (INT-05.33,
/// R05-1); no field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Actions {
    /// Type Login: a candidate whose effective sequence is not empty.
    pub type_login: bool,
    /// Auto-Type Username Only: a candidate whose user name is not empty.
    pub username_only: bool,
    /// Auto-Type Password Only: a candidate whose password is not empty.
    pub password_only: bool,
}

/// The actions of entry `id` in `open` (INT-05.33, R05-1); all off when it
/// is not a candidate (INT-05.19). A field counts as stored.
#[must_use]
pub fn actions(open: &Open<'_>, id: Uuid, settings: &Settings, now: Time) -> Actions {
    candidates(open.vault, settings.skip_expired, now)
        .iter()
        .find(|c| c.entry.uuid == id)
        .map_or_else(Actions::default, |c| Actions {
            type_login: !c.seq.is_empty(),
            username_only: !c.entry.value("UserName").is_empty(),
            password_only: !c.entry.value("Password").is_empty(),
        })
}

/// Type Login is enabled for entry `id`: [`actions`]' `type_login`.
#[must_use]
pub fn type_login_enabled(open: &Open<'_>, id: Uuid, settings: &Settings, now: Time) -> bool {
    actions(open, id, settings, now).type_login
}

/// Entry `id` is a candidate (INT-05.19 as R05-1 keeps it): its flag and
/// its group's switch on, not in the bin, not expired when S-AT-05 is on.
/// Its effective sequence may be empty: a picker row brings its own.
#[must_use]
pub fn is_candidate(open: &Open<'_>, id: Uuid, settings: &Settings, now: Time) -> bool {
    candidates(open.vault, settings.skip_expired, now)
        .iter()
        .any(|c| c.entry.uuid == id)
}

/// A candidate (INT-05.19) and its effective sequence (MOD-02.16).
struct Cand<'v> {
    entry: &'v Entry,
    seq: &'v str,
}

/// Every candidate of `vault` in tree order, with its effective sequence,
/// in one walk: the group switch of MOD-02.14 and the sequence of MOD-02.15
/// carried down the tree (what `larsal_core::edit::auto_type_on` and
/// `group_sequence` give, without walking up for each entry); the bin's
/// subtree left out (LD-57).
fn candidates(vault: &Vault, skip_expired: bool, now: Time) -> Vec<Cand<'_>> {
    let bin = bin_id(vault);
    let now = At::from(now);
    let mut out = Vec::new();
    let mut stack: Vec<(&Group, bool, &str)> = vec![(&vault.root, true, DEFAULT_SEQUENCE)];
    while let Some((g, up_on, up_seq)) = stack.pop() {
        if Some(g.uuid) == bin {
            continue;
        }
        let on = match g.auto_type {
            Switch::On => true,
            Switch::Off => false,
            Switch::Inherit => up_on,
        };
        let seq = match g.auto_type {
            Switch::Off => "",
            _ if !g.default_sequence.is_empty() => g.default_sequence.as_str(),
            _ => up_seq,
        };
        if on {
            let live = g
                .entries
                .iter()
                .filter(|e| e.auto_type.enabled && !(skip_expired && is_expired(&e.times, now)));
            out.extend(live.map(|e| Cand {
                entry: e,
                seq: effective(e, seq),
            }));
        }
        stack.extend(g.groups.iter().rev().map(|c| (c, on, seq)));
    }
    out
}

/// MOD-02.16 for an entry whose flag is on, from its group's sequence (as
/// `larsal_core::edit::entry_sequence`).
fn effective<'v>(e: &'v Entry, from_group: &'v str) -> &'v str {
    if from_group.is_empty() {
        return "";
    }
    if !e.auto_type.default_sequence.is_empty() {
        return &e.auto_type.default_sequence;
    }
    let no_user = e.value("UserName").is_empty();
    let no_pass = e.value("Password").is_empty();
    match (from_group == DEFAULT_SEQUENCE, no_user, no_pass) {
        (true, true, false) => "{PASSWORD}{ENTER}",
        (true, false, true) => "{USERNAME}{ENTER}",
        _ => from_group,
    }
}

/// The plain and the display resolution contexts of one vault, sharing the
/// call's meter and the vault's index; no one-time codes.
fn contexts<'c>(
    open: &Open<'c>,
    scope: &Scope<'c>,
    index: &'c EntryIndex<'c>,
    meter: &'c Cell<usize>,
) -> (Context<'c>, Context<'c>) {
    let plain = || Context {
        vault_dir: open.dir,
        zone: scope.zone,
        index: Some(index),
        meter: Some(meter),
        ..Context::new(Some(open.vault), scope.now)
    };
    let shown = Context {
        display: true,
        hidden: secret_field,
        ..plain()
    };
    (plain(), shown)
}

/// Fields whose values never show, protected or not (LD-170 (4), LD-196
/// (1)): the one-time password fields and the passkey fields. In display
/// resolution their `{S:…}` gives nothing, so a row that reads one is
/// hidden.
fn secret_field(name: &str) -> bool {
    [totp::OTP, totp::SEED, totp::SETTINGS].contains(&name)
        || name.starts_with("TimeOtp-")
        || name.starts_with("KPEX_PASSKEY")
}

/// Sequences in order, the first of each kept, empty ones dropped.
fn distinct<'s>(seqs: impl IntoIterator<Item = &'s str>) -> Vec<&'s str> {
    let mut seen = HashSet::new();
    seqs.into_iter()
        .filter(|s| !s.is_empty() && seen.insert(*s))
        .collect()
}

/// A text as stored, or as MOD-08 resolved it.
enum Val<'t> {
    Raw(&'t str),
    Resolved(SecretString),
}

impl Val<'_> {
    fn as_str(&self) -> &str {
        match self {
            Val::Raw(s) => s,
            Val::Resolved(s) => s.expose(),
        }
    }
}

/// One call's matching state: the title, its folded form, the meter and
/// the patterns already tested.
struct Run<'r> {
    title: &'r str,
    folded: SecretString,
    chars: usize,
    usable: bool,
    meter: &'r Cell<usize>,
    limited: Cell<bool>,
    patterns: core::cell::RefCell<Vec<(SecretString, bool)>>,
    settings: &'r Settings,
}

impl<'r> Run<'r> {
    fn new(title: &'r str, meter: &'r Cell<usize>, settings: &'r Settings) -> Self {
        let mut run = Run {
            title,
            folded: SecretString::new(String::new()),
            chars: 0,
            usable: false,
            meter,
            limited: Cell::new(false),
            patterns: core::cell::RefCell::new(Vec::new()),
            settings,
        };
        if !title.is_empty()
            && title.len() <= MAX_TITLE
            && let Some(f) = run.fold(title)
        {
            run.chars = f.expose().chars().count();
            run.folded = f;
            run.usable = true;
        }
        run
    }

    /// Pays `units` from the meter; when it holds less, empties it and
    /// marks the call limited.
    fn pay(&self, units: usize) -> bool {
        let left = self.meter.get();
        if units > left {
            self.meter.set(0);
            self.limited.set(true);
            return false;
        }
        self.meter.set(left.saturating_sub(units));
        true
    }

    /// `text` resolved in `e`'s context (MOD-08), paid from the meter;
    /// `None` when it is too long or a bound was hit.
    fn resolve<'t>(&self, text: &'t str, e: &Entry, ctx: &Context<'_>) -> Option<Val<'t>> {
        if text.len() > MAX_TEXT {
            return None;
        }
        if !text.contains('{') {
            return Some(Val::Raw(text));
        }
        if !self.pay(RESOLVE_UNITS) {
            return None;
        }
        let r = refs::resolve(text, e, ctx);
        if self.meter.get() == 0 {
            self.limited.set(true);
        }
        (!r.bounded && !r.depth_hit).then_some(Val::Resolved(r.text))
    }

    /// Whether resolving `raw` for display reads a protected or never shown
    /// value (or hits a bound, which counts as one): the resolution's
    /// masked flag, never a text compare a transform can fool (F-130).
    fn reads_protected(&self, raw: &str, e: &Entry, shown: &Context<'_>) -> bool {
        if !self.pay(RESOLVE_UNITS) {
            return true;
        }
        let d = refs::resolve(raw, e, shown);
        d.bounded || d.depth_hit || d.masked
    }

    /// `s` case-folded character by character, paid from the meter.
    fn fold(&self, s: &str) -> Option<SecretString> {
        let per_byte = if s.is_ascii() { CHAR_UNITS } else { FOLD_UNITS };
        if !self.pay(s.len().saturating_mul(per_byte)) {
            return None;
        }
        // Folding never makes a character longer: the canonical form is
        // the smallest code point of its class.
        let mut out = String::with_capacity(s.len());
        out.extend(s.chars().map(fold_char));
        Some(SecretString::new(out))
    }

    /// A scan of the title for a text of `len` bytes.
    fn pay_scan(&self, len: usize) -> bool {
        self.pay(
            self.folded
                .len()
                .saturating_add(len)
                .saturating_mul(CHAR_UNITS)
                .saturating_add(STEP_UNITS),
        )
    }

    /// Whether `s` has no more characters than the title.
    fn fits(&self, s: &str) -> bool {
        s.chars().nth(self.chars).is_none()
    }

    /// A non-empty text occurs in the title, case ignored (INT-05.21,
    /// INT-05.22).
    fn occurs(&self, needle: &str) -> bool {
        !needle.is_empty()
            && self.fits(needle)
            && self.fold(needle).is_some_and(|n| {
                self.pay_scan(n.len()) && self.folded.expose().contains(n.expose())
            })
    }

    /// INT-05.23 for one candidate: the sequences of its matching window
    /// rules, then of a title or URL match, then of its empty-window rules
    /// when any of these matched; repeats and empty ones dropped.
    fn entry_rows<'v>(
        &self,
        c: &Cand<'v>,
        plain: &Context<'_>,
        shown: &Context<'_>,
    ) -> Vec<&'v str> {
        let (e, eff) = (c.entry, c.seq);
        let or_eff = |s: &'v str| if s.is_empty() { eff } else { s };
        let rules = &e.auto_type.associations;
        let mut seqs: Vec<&'v str> = rules
            .iter()
            .take_while(|_| self.pay(STEP_UNITS))
            .filter(|a| !a.window.is_empty() && self.window_matches(&a.window, e, plain, shown))
            .map(|a| or_eff(&a.sequence))
            .collect();
        let by_title = || self.settings.by_title && self.title_matches(e, plain);
        let by_url = || self.settings.by_url && self.url_matches(e, plain);
        if !seqs.contains(&eff) && (by_title() || by_url()) {
            seqs.push(eff);
        }
        if seqs.is_empty() {
            return seqs;
        }
        let empty_window = rules.iter().filter(|a| a.window.is_empty());
        seqs.extend(empty_window.map(|a| or_eff(&a.sequence)));
        distinct(seqs)
    }

    /// INT-05.20: the window text resolved; a pattern from 4 characters
    /// between `//` and `//`, else a wildcard.
    fn window_matches(
        &self,
        window: &str,
        e: &Entry,
        plain: &Context<'_>,
        shown: &Context<'_>,
    ) -> bool {
        let Some(w) = self.resolve(window, e, plain) else {
            return false;
        };
        let text = w.as_str();
        if text.chars().nth(3).is_some() && text.starts_with("//") && text.ends_with("//") {
            // LD-114: no protected value goes into the pattern engine.
            if matches!(w, Val::Resolved(_)) && self.reads_protected(window, e, shown) {
                return false;
            }
            let body = text.get(2..text.len().saturating_sub(2)).unwrap_or("");
            return self.pattern(body);
        }
        self.wildcard(text)
    }

    /// A pattern, matched anywhere in the title, case ignored, through the
    /// bounded engine; invalid or too big matches nothing. Each distinct
    /// pattern is compiled and tested once per call.
    fn pattern(&self, body: &str) -> bool {
        if let Some((_, hit)) = self
            .patterns
            .borrow()
            .iter()
            .find(|(p, _)| p.expose() == body)
        {
            return *hit;
        }
        let hit = self.compile_and_test(body);
        self.patterns
            .borrow_mut()
            .push((SecretString::new(body.to_owned()), hit));
        hit
    }

    fn compile_and_test(&self, body: &str) -> bool {
        // ponytail: a flat worst-case charge per compile (LD-122) caps a
        // call near 75 distinct patterns; charge by pattern if vaults need
        // more.
        if !self.pay(COMPILE_UNITS) {
            return false;
        }
        let charged = self.title.len().max(MIN_CHARGED);
        let Compiled::Ok(re, size) = pattern::compile_sized(&format!("(?i){body}")) else {
            return false;
        };
        size <= pattern::cap_for(charged)
            && self.pay(size.saturating_mul(charged) / REGEX_PER_UNIT)
            && re.is_match(self.title)
    }

    /// A wildcard: `*` any run, every other character itself, the whole
    /// title, case ignored (Unicode simple case folding).
    fn wildcard(&self, rule: &str) -> bool {
        if rule.chars().filter(|&c| c != '*').nth(self.chars).is_some() {
            return false;
        }
        self.fold(rule)
            .is_some_and(|r| self.pay_scan(r.len()) && glob(r.expose(), self.folded.expose()))
    }

    /// INT-05.21: the resolved title occurs in the window title.
    fn title_matches(&self, e: &Entry, ctx: &Context<'_>) -> bool {
        self.resolve(e.value("Title"), e, ctx)
            .is_some_and(|t| self.occurs(t.as_str()))
    }

    /// INT-05.22: the resolved URL occurs in the window title, or its host
    /// (MOD-08.9) does, in ASCII or in its Unicode form (R05-5).
    fn url_matches(&self, e: &Entry, ctx: &Context<'_>) -> bool {
        let url = e.value("URL");
        if url.is_empty() || url.len() > MAX_TEXT {
            return false;
        }
        if self
            .resolve(url, e, ctx)
            .is_some_and(|u| self.occurs(u.as_str()))
        {
            return true;
        }
        let Some(host) = self.resolve("{URL:HOST}", e, ctx) else {
            return false;
        };
        let host = host.as_str();
        self.occurs(host) || host_unicode(host).is_some_and(|h| self.occurs(h.expose()))
    }

    /// Adds one row per sequence of `c`, paid from the meter; a sequence
    /// over [`MAX_TEXT`] makes no row.
    #[allow(clippy::too_many_arguments)]
    fn rows(
        &self,
        out: &mut Vec<Row>,
        open: &Open<'_>,
        c: &Cand<'_>,
        seqs: Vec<&str>,
        plain: &Context<'_>,
        shown: &Context<'_>,
        now: Time,
    ) {
        if seqs.is_empty() {
            return;
        }
        let (title, title_hidden) = self.shown(c.entry, "Title", open.vault, plain, shown);
        let (username, username_hidden) = self.shown(c.entry, "UserName", open.vault, plain, shown);
        let expired = is_expired(&c.entry.times, At::from(now));
        let shown_len = title.len().saturating_add(username.len());
        for s in seqs {
            let units = s.len().saturating_add(shown_len).saturating_mul(CHAR_UNITS);
            if s.len() > MAX_TEXT || !self.pay(units.saturating_add(STEP_UNITS)) {
                continue;
            }
            out.push(Row {
                vault: open.id,
                entry: c.entry.uuid,
                sequence: s.to_owned(),
                title: title.clone(),
                title_hidden,
                username: username.clone(),
                username_hidden,
                expired,
            });
        }
    }

    /// A title or user name for display (INT-05.26, LD-191 R02-2): hidden
    /// when protected or when its resolution reads a protected value; the
    /// stored text when a bound is hit; at most 1,024 characters.
    fn shown(
        &self,
        e: &Entry,
        name: &str,
        vault: &Vault,
        plain: &Context<'_>,
        shown: &Context<'_>,
    ) -> (String, bool) {
        let Some(f) = e.field(name) else {
            return (String::new(), false);
        };
        if f.protected || vault.meta.memory_protection.for_field(name) {
            return (String::new(), true);
        }
        let raw = f.value.expose();
        let cut = |s: &str| s.chars().take(SHOWN_CHARS).collect::<String>();
        if raw.len() > MAX_TEXT {
            return (cut(raw), false);
        }
        let Some(Val::Resolved(p)) = self.resolve(raw, e, plain) else {
            return (cut(raw), false);
        };
        if self.reads_protected(raw, e, shown) {
            return (String::new(), true);
        }
        (cut(p.expose()), false)
    }
}

/// Unicode simple case folding of one character: the smallest code point
/// of its class, from the case tables the pattern engine's `(?i)` uses.
fn fold_char(c: char) -> char {
    if c.is_ascii() {
        // The smallest of an ASCII letter's class (`k`, `K`, the Kelvin
        // sign; `s`, `S`, the long s) is its upper case.
        return c.to_ascii_uppercase();
    }
    let mut class = ClassUnicode::new([ClassUnicodeRange::new(c, c)]);
    if class.try_case_fold_simple().is_err() {
        return c;
    }
    class.ranges().first().map_or(c, ClassUnicodeRange::start)
}

/// A `*`-only wildcard over the whole text, in linear time: the part
/// before the first `*` starts the text, the part after the last ends it,
/// and the parts between are found leftmost, in order.
fn glob(rule: &str, text: &str) -> bool {
    let Some((head, last)) = rule.rsplit_once('*') else {
        return rule == text;
    };
    let mut parts = head.split('*');
    let Some(mut rest) = text.strip_prefix(parts.next().unwrap_or("")) else {
        return false;
    };
    for p in parts {
        let Some(at) = rest.find(p) else {
            return false;
        };
        rest = rest.get(at.saturating_add(p.len())..).unwrap_or("");
    }
    rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_cases() {
        for (rule, text, hit) in [
            ("ab", "ab", true),
            ("ab", "abc", false),
            ("*", "", true),
            ("**", "x", true),
            ("a*", "abc", true),
            ("*c", "abc", true),
            ("a*c", "ac", true),
            ("ab*ba", "aba", false),
            ("a*b*c", "axbxc", true),
            ("a*b*c", "axcxb", false),
            // INT-05.20, LD-196 (3): the last part must end the text.
            ("*c", "abcd", false),
            ("a*c", "acx", false),
            ("*Hub", "GitHub Desktop", false),
            ("*a*a*a*b", &"a".repeat(10_000), false),
        ] {
            assert_eq!(glob(rule, text), hit, "{rule} on {text:.20}");
        }
    }

    #[test]
    fn simple_case_folding() {
        let same = |a: char, b: char| fold_char(a) == fold_char(b);
        assert!(same('k', 'K') && same('k', '\u{212A}'), "Kelvin sign");
        assert!(same('s', '\u{17F}'), "long s");
        assert!(same('\u{3C2}', '\u{3A3}'), "final sigma");
        assert!(same('\u{1E9E}', '\u{DF}'), "capital sharp s");
        assert!(same('Ü', 'ü'));
        assert!(!same('\u{131}', 'i'), "dotless i has no simple folding");
        assert!(!same('\u{130}', 'i'), "dotted capital I neither");
        // Never longer in UTF-8, so a folded copy fits its reservation.
        for c in (0..=0x10FFFFu32).filter_map(char::from_u32) {
            assert!(fold_char(c).len_utf8() <= c.len_utf8(), "{c:?}");
        }
    }
}
