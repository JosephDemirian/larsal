//! Strength estimate and Health Check (FEA-05, story E4-S11): the estimate
//! in bits (E), its score and level, the meter and generator values, the
//! list indicator, the Health Check rows and the master password gate.
//!
//! Guarantees:
//! - E is the cheapest cover of the password by the matches of App's
//!   patched `zxcvbn` and single characters (D-05-1 (b), LD-140): a match
//!   costs log2 of its guesses, a repeat its base priced the same way plus
//!   log2 of its repeat count, a character outside a match log2(N), with N
//!   from the character classes used. The same input always gives the same
//!   E (LD-136). The estimator sees at most the first 256 characters (FEA-05.2;
//!   the crate itself reads only its first 100), so one estimate is bounded.
//! - Passwords are read in place from their secret types; this module makes
//!   no plain copy of one. The crate's own copies are the accepted residual
//!   F-048 (LD-133). The reuse count compares passwords by reference to the
//!   vault's own values, so the reuse map holds no copy to wipe.
//! - No result holds a secret: E, scores, levels, reasons, titles and
//!   paths only. A reason never quotes a password (FEA-05 security notes).

use crate::edit::{change_entry, holds_reference};
use crate::expiry::is_expired;
use crate::refs::{self, Context};
use crate::text::Text;
use crate::time::{Instant, Zone, local};
use crate::{Error, recycle, tree, url};
use app_crypto::secret::SecretString;
use app_model::{Entry, Time, Uuid, Vault};
use core::cell::RefCell;
use std::collections::HashMap;
use zxcvbn::matching::patterns::MatchPattern;

/// An estimator: E in bits for a password and its user inputs (FEA-05.1).
/// App's is [`zxcvbn_bits`]; tests pass a stub.
pub type Estimator<'a> = &'a dyn Fn(&str, &[&str]) -> f64;

/// Characters handed to the estimator (FEA-05.2, D-05-2: characters).
pub const ESTIMATOR_CHARS: usize = 256;

/// E of `password` (FEA-05.1 to FEA-05.3): 0 for an empty password without
/// calling `estimator`; else the estimate of the first 256 characters,
/// scaled by n / 256 for a password of n > 256 characters. Never negative.
#[must_use]
pub fn bits_with(estimator: Estimator<'_>, password: &str, inputs: &[&str]) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    let head = match password.char_indices().nth(ESTIMATOR_CHARS) {
        Some((at, _)) => password.get(..at).unwrap_or(password),
        None => password,
    };
    let e = estimator(head, inputs);
    let e = if e.is_finite() && e > 0.0 { e } else { 0.0 };
    let n = password.chars().count();
    if n > ESTIMATOR_CHARS {
        e * (n as f64) / (ESTIMATOR_CHARS as f64)
    } else {
        e
    }
}

/// App's estimator (D-05-1 (b), LD-140): the cheapest way to cover the
/// password, as the crate reads it (its first 100 characters), with the
/// matches App's patched crate finds and single characters. A match costs
/// log2 of its guesses, a repeat its base priced the same way plus log2 of
/// the repeat count (LD-139), and a character outside a match log2(N), N
/// from the classes of the text. No penalty per match. The same input
/// always gives the same E (LD-136).
#[must_use]
pub fn zxcvbn_bits(password: &str, inputs: &[&str]) -> f64 {
    let head = match password.char_indices().nth(CRATE_CHARS) {
        Some((at, _)) => password.get(..at).unwrap_or(password),
        None => password,
    };
    if head.is_empty() {
        return 0.0;
    }
    // The inputs as the crate takes them: lower-cased, ranked from 1 (a
    // later duplicate wins). Lower-cased in a wiping buffer; the map's own
    // copies are moved into secret strings afterwards, so they are wiped.
    let mut ranked: HashMap<String, usize> = HashMap::new();
    for (i, input) in inputs.iter().enumerate() {
        let mut low = Text::new();
        for c in input.chars() {
            for l in c.to_lowercase() {
                low.push(l);
            }
        }
        // `insert` on a present key keeps the old key and drops the new one
        // unwiped (F-052), so a duplicate only updates the rank.
        let key = String::from(low.as_str());
        let rank = i.saturating_add(1);
        match ranked.get_mut(key.as_str()) {
            Some(r) => {
                *r = rank;
                drop(SecretString::new(key));
            }
            None => {
                ranked.insert(key, rank);
            }
        }
    }
    let e = cover(head, &ranked, char_bits(head));
    for (key, _) in ranked.drain() {
        drop(SecretString::new(key));
    }
    e
}

/// The crate reads at most this many characters.
const CRATE_CHARS: usize = 100;

/// log2(N) for a character outside a match (D-05-1 (b)): N = 26 for a
/// lowercase letter, 26 for an uppercase one, 10 for a digit, 33 for any
/// other printable ASCII character (space included), 100 for any non-ASCII
/// character, over the classes `text` uses. A control character adds to no
/// class; N below 2 counts 0 (LD-135 (5)).
fn char_bits(text: &str) -> f64 {
    let mut classes = [false; 5];
    for c in text.chars() {
        let class = match c {
            'a'..='z' => 0,
            'A'..='Z' => 1,
            '0'..='9' => 2,
            ' '..='~' => 3,
            c if !c.is_ascii() => 4,
            _ => continue,
        };
        if let Some(seen) = classes.get_mut(class) {
            *seen = true;
        }
    }
    let n: u32 = [26, 26, 10, 33, 100]
        .iter()
        .zip(classes)
        .filter(|(_, seen)| *seen)
        .map(|(n, _)| n)
        .sum();
    if n < 2 { 0.0 } else { f64::from(n).log2() }
}

/// LD-140: the smallest sum over every cover of `text` (one dynamic program
/// over end positions; ties keep the first found, so it is deterministic).
fn cover(text: &str, ranked: &HashMap<String, usize>, per_char: f64) -> f64 {
    cover_path(text, ranked, per_char).0
}

/// One part of the cover [`zxcvbn_bits`] picks: characters `start..end`
/// (character indices), what covers them and the bits they cost.
#[derive(Debug, Clone, PartialEq)]
pub struct Part {
    /// `dictionary`, `spatial`, `repeat`, `sequence`, `regex`, `date`, or
    /// `bruteforce` for characters outside any match.
    pub kind: &'static str,
    /// First character.
    pub start: usize,
    /// One past the last character.
    pub end: usize,
    /// The part's cost in bits.
    pub bits: f64,
}

/// The cover [`zxcvbn_bits`] picks for `password` with no user inputs, in
/// password order, neighbouring single characters joined into one
/// `bruteforce` part; the bits add up to its E (the command line's
/// `estimate -a`, INT-10.33). Only the first 100 characters are covered.
#[must_use]
pub fn zxcvbn_parts(password: &str) -> Vec<Part> {
    let head = match password.char_indices().nth(CRATE_CHARS) {
        Some((at, _)) => password.get(..at).unwrap_or(password),
        None => password,
    };
    let mut parts = cover_path(head, &HashMap::new(), char_bits(head)).1;
    parts.dedup_by(|b, a| {
        let join = a.kind == "bruteforce" && b.kind == "bruteforce" && a.end == b.start;
        if join {
            a.end = b.end;
            a.bits += b.bits;
        }
        join
    });
    parts
}

fn kind(p: &MatchPattern) -> &'static str {
    match p {
        MatchPattern::Dictionary(_) => "dictionary",
        MatchPattern::Spatial(_) => "spatial",
        MatchPattern::Repeat(_) => "repeat",
        MatchPattern::Sequence(_) => "sequence",
        MatchPattern::Regex(_) => "regex",
        MatchPattern::Date(_) => "date",
        MatchPattern::BruteForce => "bruteforce",
    }
}

/// [`cover`] with the parts of the cheapest cover, in order.
fn cover_path(text: &str, ranked: &HashMap<String, usize>, per_char: f64) -> (f64, Vec<Part>) {
    let len = text.chars().count();
    // ends[k]: (start, cost, kind) of every way to cover characters start..k.
    let mut ends: Vec<Vec<(usize, f64, &'static str)>> = vec![Vec::new(); len.saturating_add(1)];
    let mut add = |end: usize, start: usize, cost: f64, k: &'static str| {
        if let Some(list) = ends.get_mut(end) {
            list.push((start, cost, k));
        }
    };
    for mut m in zxcvbn::matching::omnimatch(text, ranked) {
        if m.i > m.j || m.j >= len {
            continue;
        }
        let end = m.j.saturating_add(1);
        if let MatchPattern::Repeat(r) = &m.pattern {
            let base = cover(&r.base_token, ranked, per_char);
            let count = r.repeat_count.max(1) as f64;
            add(end, m.i, base + count.log2(), "repeat");
            // LD-139: characters right after it that spell the start of the
            // base are a copy cut short, one more repeat.
            let base_len = r.base_token.chars().count();
            let more = text
                .chars()
                .skip(end)
                .zip(r.base_token.chars())
                .take(base_len.saturating_sub(1))
                .take_while(|(a, b)| a == b)
                .count();
            for t in 1..=more {
                add(
                    end.saturating_add(t),
                    m.i,
                    base + (count + 1.0).log2(),
                    "repeat",
                );
            }
        } else {
            let guesses = zxcvbn::estimate_guesses(&mut m, text);
            add(end, m.i, guesses.max(1.0).log2(), kind(&m.pattern));
        }
    }
    let mut best = vec![0.0f64; len.saturating_add(1)];
    // from[k]: where the cheapest cover of 0..k starts its last part.
    let mut from: Vec<(usize, f64, &'static str)> =
        vec![(0, 0.0, "bruteforce"); len.saturating_add(1)];
    for k in 1..=len {
        let prev = best.get(k.saturating_sub(1)).copied().unwrap_or(0.0);
        let mut b = prev + per_char;
        let mut pick = (k.saturating_sub(1), per_char, "bruteforce");
        for &(start, cost, kd) in ends.get(k).map_or(&[][..], Vec::as_slice) {
            let via = best.get(start).copied().unwrap_or(0.0) + cost;
            if via < b {
                b = via;
                pick = (start, cost, kd);
            }
        }
        if let Some(slot) = best.get_mut(k) {
            *slot = b;
        }
        if let Some(slot) = from.get_mut(k) {
            *slot = pick;
        }
    }
    let mut parts = Vec::new();
    let mut k = len;
    while k > 0 {
        let Some(&(start, bits, kd)) = from.get(k) else {
            break;
        };
        parts.push(Part {
            kind: kd,
            start,
            end: k,
            bits,
        });
        if start >= k {
            break;
        }
        k = start;
    }
    parts.reverse();
    (best.get(len).copied().unwrap_or(0.0), parts)
}

/// LD-44: an entry's title, user name and URL host, the non-empty ones.
fn with_inputs<T>(entry: &Entry, f: impl FnOnce(&[&str]) -> T) -> T {
    let host = url::parse(entry.value("URL")).host;
    let inputs: Vec<&str> = [entry.value("Title"), entry.value("UserName"), host.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    f(&inputs)
}

/// E of `password` as a password of `entry` (LD-44 inputs), with App's
/// estimator. Fits `search::Strength` for `is:weak` (FEA-05.10).
#[must_use]
pub fn entry_bits(password: &str, entry: &Entry) -> f64 {
    entry_bits_with(&zxcvbn_bits, password, entry)
}

/// [`entry_bits`] with any estimator.
#[must_use]
pub fn entry_bits_with(estimator: Estimator<'_>, password: &str, entry: &Entry) -> f64 {
    with_inputs(entry, |inputs| bits_with(estimator, password, inputs))
}

/// Ratings by entry (LD-137 (1)): an entry's id and last-modification
/// time to E of its stored password with its LD-44 inputs. It holds no
/// secret. The list indicator, `is:weak`, statistics and the Health Check
/// share one; the session fills it off the screen thread (E5) and drops it
/// on lock. An entry changed in the same second as its cached rating keeps
/// that rating until the session calls [`Ratings::forget`].
pub struct Ratings<'a> {
    estimator: Estimator<'a>,
    cache: RefCell<HashMap<(Uuid, Time), f64>>,
}

impl<'a> Ratings<'a> {
    /// An empty cache rating with `estimator`.
    #[must_use]
    pub fn new(estimator: Estimator<'a>) -> Self {
        Self {
            estimator,
            cache: RefCell::new(HashMap::new()),
        }
    }

    fn key(e: &Entry) -> (Uuid, Time) {
        (e.uuid, e.times.last_modification)
    }

    /// The cached E of `e`'s stored password, if any.
    #[must_use]
    pub fn cached(&self, e: &Entry) -> Option<f64> {
        self.cache.borrow().get(&Self::key(e)).copied()
    }

    /// E of `e`'s stored password: from the cache, or estimated and kept.
    #[must_use]
    pub fn stored(&self, e: &Entry) -> f64 {
        if let Some(bits) = self.cached(e) {
            return bits;
        }
        let bits = entry_bits_with(self.estimator, e.value("Password"), e);
        self.cache.borrow_mut().insert(Self::key(e), bits);
        bits
    }

    /// E of `password` as `e`'s password: the stored rating when it is the
    /// stored text, else a fresh estimate that is not kept (a resolved
    /// password can change with other entries).
    #[must_use]
    pub fn of(&self, password: &str, e: &Entry) -> f64 {
        if password == e.value("Password") {
            self.stored(e)
        } else {
            entry_bits_with(self.estimator, password, e)
        }
    }

    /// Rates every live entry outside the recycle bin that has a password.
    pub fn fill(&self, vault: &Vault) {
        for item in live_items(vault) {
            if !item.e.value("Password").is_empty() {
                let _ = self.stored(item.e);
            }
        }
    }

    /// Ratings that `cache` already holds, as [`Ratings::into_cache`] gave
    /// them: the session keeps the cache between calls, off the screen
    /// thread (LD-137 (1)), while this type holds an estimator reference.
    #[must_use]
    pub fn with_cache(estimator: Estimator<'a>, cache: HashMap<(Uuid, Time), f64>) -> Self {
        Self {
            estimator,
            cache: RefCell::new(cache),
        }
    }

    /// The ratings held, by entry id and last-modification time. No
    /// secret: ids, times and bits only.
    #[must_use]
    pub fn into_cache(self) -> HashMap<(Uuid, Time), f64> {
        self.cache.into_inner()
    }

    /// Drops the ratings of entry `id` (after an edit in the same second).
    pub fn forget(&self, id: Uuid) {
        self.cache.borrow_mut().retain(|(e, _), _| *e != id);
    }

    /// Ratings held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.borrow().len()
    }

    /// Holds no rating.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.borrow().is_empty()
    }
}

/// The strength score: floor(E) (FEA-05.4).
#[must_use]
pub fn score(bits: f64) -> i64 {
    // `as` saturates and maps NaN to 0.
    bits.floor() as i64
}

/// The five levels (FEA-05.4), lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Score 0 or less.
    Bad,
    /// 1 to 39.
    Poor,
    /// 40 to 74.
    Weak,
    /// 75 to 99.
    Good,
    /// 100 or more.
    Excellent,
}

impl Level {
    /// The level of a strength or health score (FEA-05.4).
    #[must_use]
    pub fn of(score: i64) -> Self {
        match score {
            i64::MIN..=0 => Self::Bad,
            1..=39 => Self::Poor,
            40..=74 => Self::Weak,
            75..=99 => Self::Good,
            _ => Self::Excellent,
        }
    }

    /// The level's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Bad => "Bad",
            Self::Poor => "Poor",
            Self::Weak => "Weak",
            Self::Good => "Good",
            Self::Excellent => "Excellent",
        }
    }

    /// The mockup's design token (FEA-05.5).
    #[must_use]
    pub fn color(self) -> &'static str {
        match self {
            Self::Bad => "danger",
            Self::Poor => "poor",
            Self::Weak => "warn",
            Self::Good | Self::Excellent => "ok",
        }
    }

    /// `MSG-Q-LEVEL` / `MSG-GEN-QUALITY` "Rated <level>", Bad shown as Poor
    /// (FEA-05.7, FEA-05.8).
    #[must_use]
    pub fn rated(self) -> String {
        let shown = if self == Self::Bad { Self::Poor } else { self };
        format!("Rated {}", shown.name())
    }

    /// The report's level tooltip (FEA-05.17); none from Good up.
    #[must_use]
    pub fn tip(self) -> Option<&'static str> {
        match self {
            Self::Bad => Some("Bad. Replace this password now."),
            Self::Poor => Some("Poor. Replace this password soon."),
            Self::Weak => Some("Weak. A stronger password would be better."),
            Self::Good | Self::Excellent => None,
        }
    }

    /// 0 to 4 for Bad to Excellent: the quality the master password checks
    /// compare (FEA-05.20, MOD-12.10).
    #[must_use]
    pub fn quality(self) -> u8 {
        match self {
            Self::Bad => 0,
            Self::Poor => 1,
            Self::Weak => 2,
            Self::Good => 3,
            Self::Excellent => 4,
        }
    }
}

/// A reason line (FEA-05.6, FEA-05.13, FEA-05.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// `MSG-HC-VERY-WEAK`.
    VeryWeak,
    /// `MSG-HC-WEAK`.
    Weak,
    /// `MSG-HC-REUSED` with the reuse count.
    Reused(usize),
    /// `MSG-HC-EXPIRED`.
    Expired,
    /// `MSG-HC-EXPIRES-NOW` (d ≤ 2).
    ExpiresNow,
    /// `MSG-HC-EXPIRES-IN` with d (3 to 10).
    ExpiresIn(i64),
    /// `MSG-HC-EXPIRES-SOON` (11 to 30).
    ExpiresSoon,
}

impl Reason {
    /// The message id.
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::VeryWeak => "MSG-HC-VERY-WEAK",
            Self::Weak => "MSG-HC-WEAK",
            Self::Reused(_) => "MSG-HC-REUSED",
            Self::Expired => "MSG-HC-EXPIRED",
            Self::ExpiresNow => "MSG-HC-EXPIRES-NOW",
            Self::ExpiresIn(_) => "MSG-HC-EXPIRES-IN",
            Self::ExpiresSoon => "MSG-HC-EXPIRES-SOON",
        }
    }

    /// App's text.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::VeryWeak => "Very easy to guess".into(),
            Self::Weak => "Somewhat easy to guess".into(),
            Self::Reused(c) => format!("Same password on {c} entries"),
            Self::Expired => "Past its expiry date".into(),
            Self::ExpiresNow => "Expires in 2 days or less".into(),
            Self::ExpiresIn(d) => format!("{d} days until it expires"),
            Self::ExpiresSoon => "Expires within 30 days".into(),
        }
    }
}

/// A detail line, shown as a reason's tooltip.
#[derive(Debug, Clone, PartialEq)]
pub enum Detail {
    /// `MSG-HC-ENTROPY` with E.
    Bits(f64),
    /// `MSG-HC-USED-IN` with "group path/title".
    UsedIn(String),
    /// `…` after 20 uses.
    More,
    /// `MSG-HC-EXPIRY-WAS` with the expiry time.
    ExpiryWas(Time),
    /// `MSG-HC-EXPIRES-ON` with the expiry time.
    ExpiresOn(Time),
}

impl Detail {
    /// App's text; `when` formats a time in the system's short local
    /// format (FEA-05.14).
    #[must_use]
    pub fn text(&self, when: &dyn Fn(Time) -> String) -> String {
        match self {
            Self::Bits(e) => format!("Estimated strength: {e:.2} bits"),
            Self::UsedIn(path) => format!("• {path}"),
            Self::More => "…".into(),
            Self::ExpiryWas(t) => format!("Expiry date {} has passed", when(*t)),
            Self::ExpiresOn(t) => format!("Expiry date: {}", when(*t)),
        }
    }
}

/// The strength reasons and details of E (FEA-05.6): none from Good up.
#[must_use]
pub fn strength_reasons(bits: f64) -> (Vec<Reason>, Vec<Detail>) {
    match Level::of(score(bits)) {
        Level::Bad | Level::Poor => (vec![Reason::VeryWeak], vec![Detail::Bits(bits)]),
        Level::Weak => (vec![Reason::Weak], vec![Detail::Bits(bits)]),
        Level::Good | Level::Excellent => (Vec::new(), Vec::new()),
    }
}

/// The meter under a password field (FEA-05.7) or the generator's bar
/// (FEA-05.8).
#[derive(Debug, Clone, PartialEq)]
pub struct Meter {
    /// The bar value, 0 to `scale`.
    pub bar: i64,
    /// 100 for a field's meter, 200 for the generator.
    pub scale: i64,
    /// The color token; `None` for an empty field.
    pub color: Option<&'static str>,
    /// "Rated <level>"; `None` for an empty field.
    pub rated: Option<String>,
}

fn meter_of(bits: f64, scale: i64) -> Meter {
    let level = Level::of(score(bits));
    Meter {
        bar: score(bits).clamp(0, scale),
        scale,
        color: Some(level.color()),
        rated: Some(level.rated()),
    }
}

/// The meter for a typed text whose E is `bits` (FEA-05.7): empty text
/// gives bar 0 and no tooltip.
#[must_use]
pub fn meter(typed_is_empty: bool, bits: f64) -> Meter {
    if typed_is_empty {
        return Meter {
            bar: 0,
            scale: 100,
            color: None,
            rated: None,
        };
    }
    meter_of(bits, 100)
}

/// The entry editor's meter (FEA-05.7): the typed text is resolved for the
/// entry being edited (MOD-08), then rated with the entry's inputs.
#[must_use]
pub fn editor_meter(
    estimator: Estimator<'_>,
    typed: &str,
    entry: &Entry,
    ctx: &Context<'_>,
) -> Meter {
    let resolved = refs::resolve(typed, entry, ctx).text;
    meter(
        typed.is_empty(),
        entry_bits_with(estimator, resolved.expose(), entry),
    )
}

/// The generator display (FEA-05.8): `MSG-GEN-ENTROPY` "E bits of
/// strength" with 2 decimals, a bar of 200 and the rating. For the
/// passphrase tab pass FEA-03's entropy as `bits`.
#[must_use]
pub fn generator_display(bits: f64) -> (String, Meter) {
    (format!("{bits:.2} bits of strength"), meter_of(bits, 200))
}

/// The entry list's strength icon (FEA-05.9).
#[derive(Debug, Clone, PartialEq)]
pub struct Indicator {
    /// The strength score of the resolved password.
    pub score: i64,
    /// Its level.
    pub level: Level,
    /// The tooltip: the strength reasons and details.
    pub reasons: (Vec<Reason>, Vec<Detail>),
}

/// The list icon of `entry` (FEA-05.9): `None` (no icon, sort key 0) for an
/// empty password or an excluded entry; otherwise the resolved password's
/// strength, without reuse or expiry penalties.
#[must_use]
pub fn indicator(ratings: &Ratings<'_>, entry: &Entry, ctx: &Context<'_>) -> Option<Indicator> {
    let stored = entry.value("Password");
    if stored.is_empty() || entry.exclude_from_reports {
        return None;
    }
    let resolved = refs::resolve(stored, entry, ctx).text;
    let bits = ratings.of(resolved.expose(), entry);
    Some(Indicator {
        score: score(bits),
        level: Level::of(score(bits)),
        reasons: strength_reasons(bits),
    })
}

/// The list's sort key (FEA-05.9): the score, 0 without an icon.
#[must_use]
pub fn sort_key(icon: Option<&Indicator>) -> i64 {
    icon.map_or(0, |i| i.score)
}

// ---------------------------------------------------------------------------
// The Health Check (FEA-05.11 to FEA-05.18).

/// A live entry outside the recycle bin with its group path (FEA-05.12).
pub(crate) struct Item<'v> {
    pub(crate) e: &'v Entry,
    /// Group names from the root group down, joined with `/`.
    pub(crate) path: String,
    /// The Title as a report may name it: [`MASKED_TITLE`] when protected
    /// (LD-207).
    pub(crate) title: &'v str,
}

/// Live entries outside the recycle bin, in tree order (FEA-05 words).
pub(crate) fn live_items(vault: &Vault) -> Vec<Item<'_>> {
    let bin = recycle::bin_id(vault);
    let vault_flag = vault.meta.memory_protection.for_field("Title");
    let mut out = Vec::new();
    let mut stack = vec![(&vault.root, vault.root.name.clone())];
    while let Some((g, path)) = stack.pop() {
        if Some(g.uuid) == bin {
            continue;
        }
        for e in &g.entries {
            out.push(Item {
                e,
                path: path.clone(),
                title: shown_title(e, vault_flag),
            });
        }
        for c in g.groups.iter().rev() {
            stack.push((c, format!("{path}/{}", c.name)));
        }
    }
    out
}

/// FEA-05.12: reuse runs over the counted items (no field reference in the
/// password), compared by reference to the stored values. `count[i]` is the
/// reuse count of item `i` (1 for an item outside the count) and `uses[i]`
/// its run's "path/title" list in tree order.
pub(crate) struct Reuse {
    pub(crate) count: Vec<usize>,
    run: Vec<Option<usize>>,
    runs: Vec<Vec<usize>>,
}

impl Reuse {
    pub(crate) fn new(items: &[Item<'_>]) -> Self {
        let mut counted: Vec<usize> = (0..items.len())
            .filter(|&i| {
                items
                    .get(i)
                    .is_some_and(|it| !holds_reference(it.e.value("Password")))
            })
            .collect();
        let pw = |i: usize| items.get(i).map_or("", |it| it.e.value("Password"));
        // Stable: equal passwords keep tree order.
        counted.sort_by(|&a, &b| pw(a).cmp(pw(b)));
        let mut count = vec![1; items.len()];
        let mut run = vec![None; items.len()];
        let mut runs: Vec<Vec<usize>> = Vec::new();
        for i in counted {
            let joins = runs
                .last()
                .and_then(|r| r.first())
                .is_some_and(|&first| pw(first) == pw(i));
            if !joins {
                runs.push(Vec::new());
            }
            if let Some(r) = runs.last_mut() {
                r.push(i);
            }
            if let Some(slot) = run.get_mut(i) {
                *slot = Some(runs.len().saturating_sub(1));
            }
        }
        for r in &runs {
            for &i in r {
                if let Some(c) = count.get_mut(i) {
                    *c = r.len();
                }
            }
        }
        Self { count, run, runs }
    }

    fn uses(&self, i: usize) -> &[usize] {
        self.run
            .get(i)
            .copied()
            .flatten()
            .and_then(|r| self.runs.get(r))
            .map_or(&[], Vec::as_slice)
    }
}

/// An evaluated entry's health score, reasons and details (FEA-05.13,
/// FEA-05.14).
pub(crate) struct Health {
    pub(crate) score: i64,
    pub(crate) expired: bool,
    pub(crate) reasons: Vec<Reason>,
    pub(crate) details: Vec<Detail>,
}

/// The local calendar day of `t` (D-05-4).
fn local_day(zone: &dyn Zone, t: Time) -> Option<i64> {
    local(zone, t).map(|l| l.0.div_euclid(86_400))
}

pub(crate) fn evaluate(
    ratings: &Ratings<'_>,
    items: &[Item<'_>],
    reuse: &Reuse,
    i: usize,
    now: Instant,
    zone: &dyn Zone,
) -> Option<Health> {
    let item = items.get(i)?;
    let e = item.e;
    let bits = ratings.stored(e);
    let mut s = score(bits);
    let (mut reasons, mut details) = strength_reasons(bits);
    let c = reuse.count.get(i).copied().unwrap_or(1);
    if c >= 2 {
        let penalty = i64::try_from(c.saturating_sub(1))
            .unwrap_or(i64::MAX)
            .saturating_mul(15);
        s = s.saturating_sub(penalty);
        reasons.push(Reason::Reused(c));
        let uses = reuse.uses(i);
        for &u in uses.iter().take(20) {
            if let Some(other) = items.get(u) {
                details.push(Detail::UsedIn(format!("{}/{}", other.path, other.title)));
            }
        }
        if uses.len() > 20 {
            details.push(Detail::More);
        }
        s = s.min(74);
    }
    let t = &e.times;
    let expired = is_expired(t, now);
    if expired {
        s = 0;
        reasons.push(Reason::Expired);
        details.push(Detail::ExpiryWas(t.expiry));
    } else if t.expires
        && let (Some(end), Some(today)) = (local_day(zone, t.expiry), local_day(zone, now.secs))
        && let d = end.saturating_sub(today)
        && d <= 30
    {
        s = s
            .min(70)
            .saturating_sub(30_i64.saturating_sub(d).saturating_mul(2));
        details.push(Detail::ExpiresOn(t.expiry));
        reasons.push(match d {
            i64::MIN..=2 => Reason::ExpiresNow,
            3..=10 => Reason::ExpiresIn(d),
            _ => Reason::ExpiresSoon,
        });
    }
    Some(Health {
        score: s,
        expired,
        reasons,
        details,
    })
}

/// One Health Check row (FEA-05.17). Nothing in it is a secret.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// The entry.
    pub entry: Uuid,
    /// The entry's title.
    pub title: String,
    /// The group path, root group included.
    pub path: String,
    /// The health score; may be negative.
    pub score: i64,
    /// Its level.
    pub level: Level,
    /// Skipped in reports.
    pub excluded: bool,
    /// Past its expiry date.
    pub expired: bool,
    /// Reasons, in the order added: strength, reuse, expiry.
    pub reasons: Vec<Reason>,
    /// Details, the reasons' tooltip, in the same order.
    pub details: Vec<Detail>,
}

impl Row {
    /// The title column: the title, then ` (Excluded)`, then ` (Expired)`.
    #[must_use]
    pub fn title_text(&self) -> String {
        let mut t = self.title.clone();
        if self.excluded {
            t.push_str(" (Excluded)");
        }
        if self.expired {
            t.push_str(" (Expired)");
        }
        t
    }

    /// The title's tooltip: `MSG-HC-TIP-EXCLUDED` for an excluded entry.
    #[must_use]
    pub fn title_tip(&self) -> Option<&'static str> {
        self.excluded.then_some("Reports skip this entry")
    }
}

/// The mask for a protected Title in a composed text (LD-207): the dots
/// the screen draws for hidden values.
pub const MASKED_TITLE: &str = "••••••";

/// An entry's Title as a composed text may name it (LD-207, rule 4,
/// LD-105): the mask when the Title is protected by its own flag or by the
/// vault's flag for the Title (`vault_flag`, MOD-01.7, as `refs` masks);
/// the text keeps the entry's id or path, so Open and Show still reach it.
/// Reports, merge records and the command line use it (F-066).
#[must_use]
pub fn shown_title(e: &Entry, vault_flag: bool) -> &str {
    match e.field("Title") {
        Some(f) if f.protected || vault_flag => MASKED_TITLE,
        _ => e.value("Title"),
    }
}

/// `MSG-HC-ALL-HEALTHY` (FEA-05.18).
pub const ALL_HEALTHY: &str = "No password needs attention right now.";

/// A computed Health Check (FEA-05.15): every candidate, lowest score
/// first, equal scores in tree order (D-05-5).
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    candidates: Vec<Row>,
    any_excluded: bool,
}

impl Report {
    /// The rows shown with the two toggles (both start off, FEA-05.15).
    #[must_use]
    pub fn rows(&self, show_excluded: bool, show_expired: bool) -> Vec<&Row> {
        self.candidates
            .iter()
            .filter(|r| (show_excluded || !r.excluded) && (show_expired || !r.expired))
            .collect()
    }

    /// Whether `SET-HC-SHOW-EXCLUDED` is visible: some evaluated entry is
    /// excluded.
    #[must_use]
    pub fn excluded_toggle_visible(&self) -> bool {
        self.any_excluded
    }
}

/// The Health Check (FEA-05.11 to FEA-05.16): live entries outside the
/// recycle bin with a non-empty password and no field reference in it
/// (D-05-3), scored with reuse and expiry; candidates score 74 or less.
#[must_use]
pub fn health_check(ratings: &Ratings<'_>, vault: &Vault, now: Instant, zone: &dyn Zone) -> Report {
    let items = live_items(vault);
    let reuse = Reuse::new(&items);
    let mut candidates = Vec::new();
    let mut any_excluded = false;
    for (i, item) in items.iter().enumerate() {
        let pw = item.e.value("Password");
        if pw.is_empty() || holds_reference(pw) {
            continue;
        }
        any_excluded |= item.e.exclude_from_reports;
        let Some(h) = evaluate(ratings, &items, &reuse, i, now, zone) else {
            continue;
        };
        if h.score > 74 {
            continue;
        }
        candidates.push(Row {
            entry: item.e.uuid,
            title: item.title.to_owned(),
            path: item.path.clone(),
            score: h.score,
            level: Level::of(h.score),
            excluded: item.e.exclude_from_reports,
            expired: h.expired,
            reasons: h.reasons,
            details: h.details,
        });
    }
    candidates.sort_by_key(|r| r.score);
    Report {
        candidates,
        any_excluded,
    }
}

/// Whether `ACT-HC-EXCLUDE` "Skip in reports" shows checked for the
/// selected entries: any of them is excluded (FEA-05.18).
#[must_use]
pub fn skip_checked(vault: &Vault, ids: &[Uuid]) -> bool {
    ids.iter()
        .filter_map(|&id| tree::entry(vault, id))
        .any(|e| e.exclude_from_reports)
}

/// Chooses "Skip in reports" (FEA-05.18): every selected entry gets the
/// opposite of [`skip_checked`], each a change outside an edit session
/// (MOD-01.32: no history item). Returns how many changed.
///
/// # Errors
/// `NoSuchEntry` for any id; nothing changes then.
pub fn toggle_skip(vault: &mut Vault, ids: &[Uuid], now: Time) -> Result<usize, Error> {
    if ids.iter().any(|&id| tree::entry(vault, id).is_none()) {
        return Err(Error::NoSuchEntry);
    }
    let set = !skip_checked(vault, ids);
    let mut changed = 0usize;
    for &id in ids {
        if tree::entry(vault, id).is_some_and(|e| e.exclude_from_reports != set)
            && change_entry(vault, id, now, |e| e.exclude_from_reports = set)?
        {
            changed = changed.saturating_add(1);
        }
    }
    Ok(changed)
}

/// The master password gate (FEA-05.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterGate {
    /// `MSG-MK-TOO-WEAK`: below the minimum level; the key is not changed.
    TooWeak,
    /// `MSG-MK-WEAK`: below Good; ask, Cancel is the default.
    Warn,
    /// Good or better and not below the minimum.
    Fine,
}

/// FEA-05.20 for a non-empty new master password of strength `bits` and
/// the minimum level `SET-MK-MIN-LEVEL` (0 to 4; values outside clamped).
#[must_use]
pub fn master_gate(bits: f64, min_level: i64) -> MasterGate {
    let quality = i64::from(Level::of(score(bits)).quality());
    if quality < min_level.clamp(0, 4) {
        MasterGate::TooWeak
    } else if quality < i64::from(Level::Good.quality()) {
        MasterGate::Warn
    } else {
        MasterGate::Fine
    }
}
