//! Running a search (FEA-01.7 to FEA-01.24, FEA-01.33 to FEA-01.35).
//!
//! Guarantees:
//! - The query is parsed and every pattern compiled once per run, never
//!   once per entry (FEA-01.34); identical patterns compile once.
//! - Patterns go through the pattern engine with all its bounds (LD-110,
//!   LD-113, LD-116, LD-122, LD-123): linear-time matching, 256 KiB
//!   compiled, at most 100 levels of nesting, no Unicode category or script
//!   class, a compiled size no larger than `pattern::cap_for` the text it
//!   runs on (at least 512 bytes charged), one case-folding budget of
//!   200,000 code points for the whole query, and one regex budget
//!   (`pattern::SEARCH_BUDGET`, NFA size × text bytes) for every text where
//!   the lazy DFA gives up and the PikeVM must answer. A pattern past a bound
//!   counts as invalid there: it does not match and the run says so
//!   (FEA-01.31).
//! - One work meter per run ([`RUN_BUDGET`], LD-126) pays for every
//!   placeholder resolution (characters, entry visits, compiles, regex
//!   replaces), every byte the lazy DFA scans, every byte of DFA states it
//!   builds, the PikeVM, and the one-time password and tag checks.
//!   Resolutions may use the first two thirds: past that the rest of the
//!   run matches stored text without resolving. Every entry looked at and
//!   every step over its fields, tags and attachments is paid too, and when
//!   the meter is empty the run stops walking (LD-127). Either way the run
//!   raises the limit notice. References look entries up in one index per
//!   run.
//! - Bin entries are never results, whatever any flag says (LD-57).
//! - Values are matched in place. Title, user name, URL and password are
//!   resolved (MOD-08) only when they hold a `{`; the resolved text lives
//!   in a `SecretString` and is wiped when the entry is done. Only entry
//!   ids leave (FEA-01.33).

use super::parse::{Field, QueryError, Term, parse};
use crate::expiry::{expires_within, is_expired, search_days};
use crate::health::Ratings;
use crate::pattern::{self, Built, MAX_FOLDED, MAX_NEST, MIN_CHARGED, Matcher, SEARCH_BUDGET, pay};
use crate::refs::{self, Context, EntryIndex};
use crate::time::{Instant, Utc, Zone};
use app_crypto::secret::SecretString;
use app_model::entry::STANDARD_FIELDS;
use app_model::{Entry, Group, Switch, Time, Uuid, Vault};
use core::cell::Cell;
use std::rc::Rc;

/// The work meter of one run, in units of about a nanosecond on the build
/// Mac (LD-126): with the unmetered walk and compiles, a run stays under
/// 250 ms in release whatever the vault.
pub const RUN_BUDGET: usize = 150_000_000;
/// Resolutions stop once the meter holds less than this, so stored text
/// can still be matched with the rest.
const RESOLVE_FLOOR: usize = RUN_BUDGET / 3;
/// Meter units of one check besides its bytes; also what each entry the
/// run looks at costs.
const CHECK_UNITS: usize = 64;
/// Meter units of one step over an entry's fields, tags or attachments
/// (LD-127).
const WALK_UNITS: usize = 16;

/// LD-137 (2): what a strength estimate made during a run costs, by the
/// password's length L in characters (at most 100, the crate's own cut):
/// at least 1.6 times the worst release time measured on the build Mac for
/// LD-140's estimator, on l33t-heavy text (2.1 ms at 16 characters, 23 ms
/// at 20, 117 ms at 50, 490 ms at 100; a cached rating costs a stored-text
/// check instead).
fn estimate_units(password: &str) -> usize {
    const BASE: usize = 50_000;
    const PER_CHAR_SQUARED: usize = 96_000;
    let l = password.chars().take(100).count();
    BASE.saturating_add(PER_CHAR_SQUARED.saturating_mul(l.saturating_mul(l)))
}

/// What a run needs besides the vault and the query.
pub struct Options<'a> {
    /// The base group (FEA-01.23); `None` for the root.
    pub base: Option<Uuid>,
    /// `search.case_sensitive` (FEA-01.24).
    pub case_sensitive: bool,
    /// The clock (FEA-01.16, FEA-01.19).
    pub now: Instant,
    /// The local zone for `is:expired-N` and date placeholders.
    pub zone: &'a dyn Zone,
    /// FEA-05's shared ratings for `is:weak` (E4-S11, LD-137). `None`:
    /// `is:weak` matches nothing.
    pub ratings: Option<&'a Ratings<'a>>,
}

impl Options<'_> {
    /// Root base, case ignored, UTC, no strength estimate.
    #[must_use]
    pub fn new(now: Time) -> Self {
        Self {
            base: None,
            case_sensitive: false,
            now: Instant::from(now),
            zone: &Utc,
            ratings: None,
        }
    }
}

/// A run's result: entry ids in tree order (FEA-01.22), whether a
/// pattern was invalid or a bound was hit (FEA-01.31), and the work spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The matching entries, in tree order.
    pub ids: Vec<Uuid>,
    /// Show the invalid-pattern (limit) notice.
    pub invalid: bool,
    /// Meter units the run spent, at most [`RUN_BUDGET`].
    pub spent: usize,
}

/// Runs a text query (FEA-01).
///
/// # Errors
/// [`QueryError`] over 1,024 characters or 16 pattern terms (FEA-01.32,
/// LD-124): nothing runs.
pub fn search(vault: &Vault, query: &str, o: &Options<'_>) -> Result<Found, QueryError> {
    let terms = parse(query)?;
    let mut prep = Prep {
        case_sensitive: o.case_sensitive,
        fold_budget: MAX_FOLDED,
        cache: Vec::new(),
        invalid: false,
    };
    let tests: Vec<(bool, Test)> = terms.iter().map(|t| (t.exclude, prep.test(t))).collect();
    let invalid = prep.invalid;
    Ok(run(vault, &tests, o, invalid))
}

/// Runs exact tag terms from a sidebar click (FEA-01.35, LD-66): every
/// tag must equal one of the entry's tags code unit by code unit.
#[must_use]
pub fn search_tags(vault: &Vault, tags: &[&str], o: &Options<'_>) -> Found {
    let tests: Vec<(bool, Test)> = tags
        .iter()
        .map(|t| (false, Test::ExactTag((*t).to_owned())))
        .collect();
    run(vault, &tests, o, false)
}

/// A compiled pattern: `None` when invalid or too big.
type Rx = Option<Rc<Matcher>>;

enum Test {
    /// A text field with its substring (or exact) pattern and, where tags
    /// are looked at, the whole-text pattern (FEA-01.14).
    Text {
        field: Field,
        main: Rx,
        whole: Rx,
        /// FEA-01.15: the value holds `/`, so `group` looks at the path.
        slash: bool,
    },
    Expired(u32),
    Weak,
    Totp,
    Never,
    ExactTag(String),
}

struct Prep {
    case_sensitive: bool,
    fold_budget: u64,
    cache: Vec<(String, Rx)>,
    invalid: bool,
}

impl Prep {
    fn test(&mut self, t: &Term) -> Test {
        match &t.field {
            Field::Is => match search_days(&t.value) {
                Some(n) => Test::Expired(n),
                None if t.value.eq_ignore_ascii_case("weak") => Test::Weak,
                None => Test::Never,
            },
            Field::Has if t.value.eq_ignore_ascii_case("totp") => Test::Totp,
            Field::Has => Test::Never,
            field => {
                let needs_main = !matches!(field, Field::Tag);
                let needs_whole = matches!(field, Field::Tag | Field::Default);
                let main = if needs_main {
                    self.compiled(t, t.exact)
                } else {
                    None
                };
                let whole = if needs_whole {
                    self.compiled(t, true)
                } else {
                    None
                };
                Test::Text {
                    field: field.clone(),
                    main,
                    whole,
                    slash: t.value.contains('/'),
                }
            }
        }
    }

    /// The pattern of a term (FEA-01.7 to FEA-01.10): anchored to the whole
    /// text (with one optional final line feed) when `anchored`, case
    /// ignored unless the option is on or the term is exact.
    fn compiled(&mut self, t: &Term, anchored: bool) -> Rx {
        // The user's pattern alone must parse within 100 levels; App's
        // wrappers (the case flag, the anchor group) add up to 3 more.
        if t.regex && !pattern::parses_alone(&t.value) {
            self.invalid = true;
            return None;
        }
        let mut p = String::new();
        if !(self.case_sensitive || t.exact) {
            p.push_str("(?i)");
        }
        if anchored {
            p.push_str(r"\A(?:");
        }
        if t.regex {
            p.push_str(&t.value);
        } else {
            wildcards(&mut p, &t.value);
        }
        if anchored {
            p.push_str(r")\n?\z");
        }
        if let Some((_, rx)) = self.cache.iter().find(|(k, _)| *k == p) {
            return rx.clone();
        }
        let rx = match pattern::matcher(&p, MAX_NEST.saturating_add(3), &mut self.fold_budget) {
            Built::Ok(m) => Some(Rc::from(m)),
            Built::TooBig | Built::Invalid => {
                self.invalid = true;
                None
            }
        };
        self.cache.push((p, rx.clone()));
        rx
    }
}

/// FEA-01.7: `*` any run without a line feed, `?` one character but a
/// line feed, `|` alternatives; everything else literal.
fn wildcards(p: &mut String, value: &str) {
    p.push_str("(?:");
    let mut lit = String::new();
    for c in value.chars() {
        let special = match c {
            '*' => r"[^\n]*",
            '?' => r"[^\n]",
            '|' => "|",
            _ => {
                lit.push(c);
                continue;
            }
        };
        regex_syntax::escape_into(&lit, p);
        lit.clear();
        p.push_str(special);
    }
    regex_syntax::escape_into(&lit, p);
    p.push(')');
}

/// The walk: groups in pre-order from the root, the bin and everything in
/// it skipped (LD-57), entries of in-scope groups whose resolved search
/// flag is on (FEA-01.20, FEA-01.23).
fn run(vault: &Vault, tests: &[(bool, Test)], o: &Options<'_>, invalid: bool) -> Found {
    let meter = Cell::new(RUN_BUDGET);
    let res_meter = Cell::new(0);
    let index = EntryIndex::new(vault);
    let mut s = Scan {
        o,
        ctx: Context {
            otp: crate::totp::code_for,
            zone: o.zone,
            index: Some(&index),
            meter: Some(&res_meter),
            ..Context::new(Some(vault), o.now.secs)
        },
        tests,
        bin: crate::recycle::bin_id(vault),
        base: o.base.unwrap_or(vault.root.uuid),
        ids: Vec::new(),
        invalid: Cell::new(invalid),
        path: String::new(),
        meter: &meter,
        res_meter: &res_meter,
        slow: Cell::new(SEARCH_BUDGET),
    };
    s.group(&vault.root, true, false);
    Found {
        ids: s.ids,
        invalid: s.invalid.get(),
        spent: RUN_BUDGET.saturating_sub(meter.get()),
    }
}

struct Scan<'a> {
    o: &'a Options<'a>,
    ctx: Context<'a>,
    tests: &'a [(bool, Test)],
    bin: Option<Uuid>,
    base: Uuid,
    ids: Vec<Uuid>,
    invalid: Cell<bool>,
    path: String,
    /// The run's work meter (LD-126).
    meter: &'a Cell<usize>,
    /// What the resolution under way may spend; the context pays from it.
    res_meter: &'a Cell<usize>,
    /// What the PikeVM may still cost in this run (inside the meter).
    slow: Cell<usize>,
}

impl Scan<'_> {
    fn group(&mut self, g: &Group, parent_on: bool, parent_in_scope: bool) {
        if Some(g.uuid) == self.bin {
            return;
        }
        let on = match g.searching {
            Switch::On => true,
            Switch::Off => false,
            Switch::Inherit => parent_on,
        };
        let mark = self.path.len();
        self.path.push('/');
        self.path.push_str(&g.name);
        let in_scope = parent_in_scope || g.uuid == self.base;
        if in_scope && on {
            for e in &g.entries {
                // LD-127: an empty meter ends the walk.
                if !self.live() {
                    break;
                }
                if self.holds(e, g) {
                    self.ids.push(e.uuid);
                }
            }
        }
        for child in &g.groups {
            if !self.live() {
                break;
            }
            self.group(child, on, in_scope);
        }
        self.path.truncate(mark);
    }

    /// `false` (and the notice) once the meter is empty: the run walks no
    /// further (LD-127).
    fn live(&self) -> bool {
        let live = self.meter.get() > 0;
        if !live {
            self.invalid.set(true);
        }
        live
    }

    /// Pays one step of a walk over an entry's fields, tags or attachments
    /// (LD-127); `false` once the meter cannot.
    fn step(&self) -> bool {
        let paid = pay(self.meter, WALK_UNITS).is_some();
        if !paid {
            self.invalid.set(true);
        }
        paid
    }

    fn holds(&self, e: &Entry, g: &Group) -> bool {
        if !self.afford(0) {
            return false;
        }
        let mut view = View {
            e,
            resolved: [None, None, None, None],
        };
        self.tests
            .iter()
            .all(|(exclude, t)| self.matches(t, &mut view, g) != *exclude)
    }

    /// Pays a check of `bytes` from the meter; `false` (and the notice)
    /// when it cannot.
    fn afford(&self, bytes: usize) -> bool {
        let paid = pay(self.meter, bytes.saturating_add(CHECK_UNITS)).is_some();
        if !paid {
            self.invalid.set(true);
        }
        paid
    }

    fn matches(&self, t: &Test, v: &mut View<'_>, g: &Group) -> bool {
        match t {
            Test::Never => false,
            Test::Totp => {
                // The fields `totp::settings` looks up, by name: no walk.
                let bytes = [crate::totp::OTP, crate::totp::SEED, crate::totp::SETTINGS]
                    .into_iter()
                    .chain(crate::totp::FORM_T)
                    .filter_map(|n| v.e.field(n))
                    .map(|f| f.value.len())
                    .fold(0usize, usize::saturating_add);
                self.afford(bytes.saturating_mul(4)) && crate::totp::settings(v.e).is_some()
            }
            Test::Expired(n) => expires_within(&v.e.times, self.o.now, *n, self.o.zone),
            Test::Weak => self.weak(v),
            Test::ExactTag(tag) => {
                v.e.tags()
                    .iter()
                    .take_while(|t| self.afford(t.len()))
                    .any(|x| x == tag)
            }
            Test::Text {
                field,
                main,
                whole,
                slash,
            } => self.text(field, main.as_ref(), whole.as_ref(), *slash, v, g),
        }
    }

    /// FEA-01.17: in reports, a stored password, not expired, and a score
    /// below 75 for the resolved password.
    fn weak(&self, v: &mut View<'_>) -> bool {
        let Some(ratings) = self.o.ratings else {
            return false;
        };
        if v.e.exclude_from_reports
            || v.e.value("Password").is_empty()
            || is_expired(&v.e.times, self.o.now)
        {
            return false;
        }
        let e = v.e;
        let password = v.get(PASSWORD, self);
        let cached = if password == e.value("Password") {
            ratings.cached(e)
        } else {
            None
        };
        // LD-137 (2): a cached rating costs a stored-text check; an estimate
        // pays its modelled cost first, and an empty meter means no match
        // and the notice (LD-126 (7)).
        let bits = match cached {
            Some(bits) if self.afford(password.len()) => bits,
            Some(_) => return false,
            None if pay(self.meter, estimate_units(password)).is_some() => ratings.of(password, e),
            None => {
                self.invalid.set(true);
                return false;
            }
        };
        bits < 75.0
    }

    /// The resolved text of one of the four resolved fields (FEA-01.19),
    /// paid from the meter while it holds more than [`RESOLVE_FLOOR`];
    /// `None` (match the stored text, raise the notice) once it does not,
    /// or when the resolution hit a bound.
    fn resolve(&self, raw: &str, e: &Entry) -> Option<SecretString> {
        let left = self.meter.get();
        let share = left.saturating_sub(RESOLVE_FLOOR);
        if share == 0 {
            self.invalid.set(true);
            return None;
        }
        self.res_meter.set(share);
        let r = refs::resolve(raw, e, &self.ctx);
        let used = share.saturating_sub(self.res_meter.get());
        self.meter.set(left.saturating_sub(used));
        if r.bounded {
            self.invalid.set(true);
            return None;
        }
        Some(r.text)
    }

    fn text(
        &self,
        field: &Field,
        main: Option<&Rc<Matcher>>,
        whole: Option<&Rc<Matcher>>,
        slash: bool,
        v: &mut View<'_>,
        g: &Group,
    ) -> bool {
        let e = v.e;
        match field {
            Field::Default => {
                for i in [TITLE, USER, URL] {
                    if self.hit(main, v.get(i, self)) {
                        return true;
                    }
                }
                e.tags()
                    .iter()
                    .take_while(|_| self.step())
                    .any(|t| self.hit(whole, t))
                    || self.hit(main, e.value("Notes"))
            }
            Field::Title => self.hit(main, v.get(TITLE, self)),
            Field::UserName => self.hit(main, v.get(USER, self)),
            Field::Url => self.hit(main, v.get(URL, self)),
            Field::Password => self.hit(main, v.get(PASSWORD, self)),
            Field::Notes => self.hit(main, e.value("Notes")),
            Field::Tag => e
                .tags()
                .iter()
                .take_while(|_| self.step())
                .any(|t| self.hit(whole, t)),
            Field::Attribute => e
                .fields()
                .take_while(|_| self.step())
                .filter(|(n, _)| !STANDARD_FIELDS.contains(n) && !passkey_field(n))
                .any(|(n, f)| self.hit(main, n) || self.hit(main, f.value.expose())),
            Field::Attachment => e
                .attachments
                .iter()
                .take_while(|_| self.step())
                .any(|a| self.hit(main, &a.name)),
            Field::Named(name) => e
                .field(name)
                .is_some_and(|f| self.hit(main, f.value.expose())),
            Field::Group if slash => self.hit(main, &self.path),
            Field::Group => self.hit(main, &g.name),
            Field::Uuid => {
                let mut hex = String::with_capacity(32);
                for b in e.uuid.0 {
                    for nibble in [b >> 4, b & 15] {
                        hex.push(char::from(*HEX.get(usize::from(nibble)).unwrap_or(&b'0')));
                    }
                }
                self.hit(main, &hex)
            }
            Field::Is | Field::Has => false,
        }
    }

    /// One pattern on one text: LD-116's size cap for the text, then the
    /// lazy DFA, or the PikeVM, all paid from the run's meter.
    fn hit(&self, rx: Option<&Rc<Matcher>>, text: &str) -> bool {
        let Some(m) = rx else {
            return false;
        };
        if m.size() > pattern::cap_for(text.len().max(MIN_CHARGED)) {
            self.invalid.set(true);
            return false;
        }
        let mut slow = self.slow.get();
        let found = m.is_match(text, self.meter, &mut slow);
        self.slow.set(slow);
        found.unwrap_or_else(|| {
            self.invalid.set(true);
            false
        })
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";
const TITLE: usize = 0;
const USER: usize = 1;
const URL: usize = 2;
const PASSWORD: usize = 3;
const RESOLVED: [&str; 4] = ["Title", "UserName", "URL", "Password"];

/// The prefix of passkey fields (INT-04), which `attribute` skips.
pub(crate) const PASSKEY: &str = "KPEX_PASSKEY";
/// The foreign passkey user name field (INT-04), as bytes (name rule).
const FOREIGN_PASSKEY_USER: [u8; 21] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x41, 0x53, 0x53, 0x4B, 0x45, 0x59, 0x5F, 0x55, 0x53, 0x45,
    0x52, 0x4E, 0x41, 0x4D, 0x45,
];

pub(crate) fn passkey_field(name: &str) -> bool {
    name.starts_with(PASSKEY) || name.as_bytes() == FOREIGN_PASSKEY_USER
}

/// An entry's four resolved fields, resolved on first use and wiped when
/// the entry is done (FEA-01.19, FEA-01.33).
struct View<'e> {
    e: &'e Entry,
    resolved: [Option<SecretString>; 4],
}

impl View<'_> {
    fn get(&mut self, i: usize, s: &Scan<'_>) -> &str {
        let e = self.e;
        let raw = e.value(RESOLVED.get(i).copied().unwrap_or("Title"));
        if !raw.contains('{') {
            return raw;
        }
        let Some(slot) = self.resolved.get_mut(i) else {
            return raw;
        };
        if slot.is_none() {
            *slot = s.resolve(raw, e);
        }
        slot.as_ref().map_or(raw, SecretString::expose)
    }
}
