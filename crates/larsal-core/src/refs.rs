//! Field references and placeholders (MOD-08): finding spans, escaping,
//! classification, every placeholder, field references, conversions and
//! regex replace, the depth budget and Larsal's work bounds, display masking,
//! the browser save guard and the reference marker.
//!
//! Guarantees: resolution never changes the vault and never fails; it ends
//! on every input: the depth budget of MOD-08.18 (with the current budget
//! everywhere, never a fresh one, D-08-2) bounds the nesting, and each
//! top-level call stops after 10,000 span steps, 1,048,576 characters in
//! any one result, or 16,777,216 characters of total work, returning the
//! raw input (MOD-08.20, D-08-3, LD-111). Regex replace runs on the
//! linear-time engine of `pattern` (LD-110). Every intermediate and final
//! text lives in a wiping buffer; the result is a `SecretString` (SR-07,
//! AT-C02). A caller that resolves many fields (search) can share one work
//! meter across all of them and look entries up in one index (LD-126).

use crate::edit::holds_reference;
use crate::history::otp_field;
use crate::pattern::Compiled;
use crate::text::{Bytes, Text};
use crate::time::{Utc, Zone, local};
use crate::url;
use core::cell::Cell;
use larsal_crypto::secret::SecretString;
use larsal_format::share_item;
use larsal_model::entry::STANDARD_FIELDS;
use larsal_model::{Entry, Field, Group, Time, Uuid, Vault};
use regex_automata::util::captures::Captures;
use std::collections::hash_map::Entry as Slot;
use std::collections::{HashMap, HashSet};

/// The depth budget of a top-level call (MOD-08.18).
pub const DEPTH: i32 = 10;
/// Span steps per top-level call (MOD-08.20, D-08-3).
pub const MAX_SPANS: usize = 10_000;
/// Characters in any one result of a top-level call (MOD-08.20, D-08-3).
pub const MAX_OUTPUT: usize = 1_048_576;
/// Characters scanned and copied at every level of a top-level call. The
/// two card bounds alone still allow about 10^10 character copies through
/// conversions that drop their text; this keeps every call short.
pub const MAX_WORK: usize = 16 * 1_048_576;
/// Distinct patterns compiled per resolution (LD-120).
pub const MAX_COMPILES: usize = 8;
/// The longest text a regex replace works on (LD-113).
pub const MAX_REPLACE_TEXT: usize = 65_536;
/// The display mask (MOD-08.23).
pub const MASK: &str = "******";
/// Meter units per character scanned or copied (LD-126); a unit is about a
/// nanosecond on the build Mac.
pub const CHAR_UNITS: usize = 2;
/// Meter units per group or entry a reference search visits.
pub const VISIT_UNITS: usize = 20;
/// Meter units per pattern compile (LD-122: the worst compile took 1.6 ms).
pub const COMPILE_UNITS: usize = 2_000_000;
/// Regex budget units (compiled size × text bytes) per meter unit: the
/// replace engine runs at about 0.07 to 0.2 ns per unit (LD-116, LD-123).
pub const REGEX_PER_UNIT: usize = 4;

/// The live entries of a vault in the order MOD-08.15 searches them, with
/// an id lookup and each entry's share scope (MOD-08.32), built once by a
/// caller that resolves many fields (LD-126 (3), F-156); without it every
/// reference walks the tree.
pub struct EntryIndex<'v> {
    order: Vec<&'v Entry>,
    groups: usize,
    by_id: HashMap<Uuid, &'v Entry>,
    /// Ids that more than one live entry holds.
    repeated: HashSet<Uuid>,
    /// Each live entry's place in `order`, by address (ids can repeat).
    at: HashMap<*const Entry, usize>,
    /// The group (place in `tree`) of each entry of `order`.
    group_of: Vec<usize>,
    /// Every group in pre-order.
    tree: Vec<Node>,
}

/// A group of [`EntryIndex::tree`]; places are pre-order positions.
struct Node {
    /// The place in `order` of the group's first entry.
    first: usize,
    /// The place just past the group's subtree.
    end: usize,
    /// The nearest share group at or above it (MOD-08.32).
    share: Option<usize>,
    /// A share group whose item reads with Keep group structure on.
    keep: bool,
    /// The nearest group at or above it that is the recycle bin.
    bin: Option<usize>,
}

impl<'v> EntryIndex<'v> {
    /// Indexes every live entry of `vault` (history items never).
    #[must_use]
    pub fn new(vault: &'v Vault) -> Self {
        let key = core::str::from_utf8(share_item::KEY).unwrap_or_default();
        let bin_id = crate::recycle::bin_id(vault);
        let mut index = Self {
            order: Vec::new(),
            groups: 0,
            by_id: HashMap::new(),
            repeated: HashSet::new(),
            at: HashMap::new(),
            group_of: Vec::new(),
            tree: Vec::new(),
        };
        let mut parents = Vec::new();
        let mut stack = vec![(&vault.root, None::<usize>)];
        while let Some((g, parent)) = stack.pop() {
            let place = index.tree.len();
            let above = parent.and_then(|p| index.tree.get(p));
            let shared = g.custom_data.get(key).is_some();
            index.tree.push(Node {
                first: index.order.len(),
                end: place.saturating_add(1),
                share: if shared {
                    Some(place)
                } else {
                    above.and_then(|n| n.share)
                },
                keep: shared
                    && matches!(share_item::of(g), Some(share_item::Item::Settings(s)) if s.keep_groups),
                bin: if Some(g.uuid) == bin_id {
                    Some(place)
                } else {
                    above.and_then(|n| n.bin)
                },
            });
            parents.push(parent);
            for e in &g.entries {
                match index.by_id.entry(e.uuid) {
                    Slot::Occupied(_) => {
                        index.repeated.insert(e.uuid);
                    }
                    Slot::Vacant(slot) => {
                        slot.insert(e);
                    }
                }
                index.at.insert(core::ptr::from_ref(e), index.order.len());
                index.order.push(e);
                index.group_of.push(place);
            }
            stack.extend(g.groups.iter().rev().map(|c| (c, Some(place))));
        }
        // Children come after their parent, so this sees each subtree's end
        // before its parent needs it.
        for (place, parent) in parents.iter().enumerate().rev() {
            let end = index.tree.get(place).map_or(place, |n| n.end);
            if let Some(n) = parent.and_then(|p| index.tree.get_mut(p)) {
                n.end = n.end.max(end);
            }
        }
        index.groups = index.tree.len();
        index
    }

    /// The share group (its place) of the live entry `e`, if it has one.
    fn share_of(&self, e: &Entry) -> Option<usize> {
        let at = self.at.get(&core::ptr::from_ref(e))?;
        let g = self.group_of.get(*at)?;
        self.tree.get(*g)?.share
    }
}

/// The one-time code of an entry for `{TOTP}` (MOD-08.12, FEA-04); `None`
/// when it has none or its settings are invalid (D-08-7).
pub type Otp = fn(&Entry, Time) -> Option<SecretString>;

fn no_otp(_: &Entry, _: Time) -> Option<SecretString> {
    None
}

/// What a resolution needs besides the text and its entry (MOD-08 inputs).
pub struct Context<'a> {
    /// The vault the entry lives in, if any.
    pub vault: Option<&'a Vault>,
    /// The vault file's folder for `{DB_DIR}`, no trailing slash; empty for
    /// a vault never saved (D-08-8).
    pub vault_dir: &'a str,
    /// The clock (MOD-08.10).
    pub now: Time,
    /// Local time zone rules (MOD-08.10).
    pub zone: &'a dyn Zone,
    /// One-time codes (MOD-08.12).
    pub otp: Otp,
    /// Resolve for display: every value from a protected field shows as
    /// `******` (MOD-08.23, D-08-4). Only the list's URL column, the URL in
    /// the preview and the command question use this.
    pub display: bool,
    /// The live entries of `vault`, indexed once (LD-126 (3)); `None` walks
    /// the tree for every reference.
    pub index: Option<&'a EntryIndex<'a>>,
    /// Field names whose `{S:…}` resolves to nothing (LD-170 (4)): the
    /// window's Show and Copy pass the one-time password and passkey field
    /// names, so a placeholder never lets their raw value out.
    pub hidden: fn(&str) -> bool,
    /// Work units this and later resolutions may still spend (LD-126 (1)):
    /// every character, visit, compile and regex replace is paid from it;
    /// when it runs out the resolution gives its raw input (`bounded`).
    /// `None`: only MOD-08's own bounds.
    pub meter: Option<&'a Cell<usize>>,
}

impl<'a> Context<'a> {
    /// A context with no saved file, UTC, no one-time codes and no
    /// masking.
    #[must_use]
    pub fn new(vault: Option<&'a Vault>, now: Time) -> Self {
        Self {
            vault,
            vault_dir: "",
            now,
            zone: &Utc,
            otp: no_otp,
            display: false,
            index: None,
            meter: None,
            hidden: no_hidden,
        }
    }
}

fn no_hidden(_: &str) -> bool {
    false
}

/// Work units one Show or Copy resolution may spend (LD-126), as one
/// Auto-Type run.
pub const COPY_BUDGET: usize = 100_000_000;

/// The context Show and Copy resolve in (MOD-08.25), shared by every
/// caller that must resolve "as Copy does" (the SSH agent's passphrase,
/// D-INT06-5): references resolve in `vault`, `{DB_DIR}` is `vault_dir`,
/// `{TOTP}` gives the current code, and `{S:…}` of a one-time password or
/// passkey field gives nothing (LD-170 (4)), so neither lets its raw value
/// out. Every step is paid from `meter` (LD-126): give each resolution its
/// own, started at [`COPY_BUDGET`].
#[must_use]
pub fn copy_context<'a>(
    vault: &'a Vault,
    vault_dir: &'a str,
    now: Time,
    meter: &'a Cell<usize>,
) -> Context<'a> {
    Context {
        vault_dir,
        otp: crate::totp::code_for,
        hidden: copy_hidden,
        meter: Some(meter),
        ..Context::new(Some(vault), now)
    }
}

/// LD-170 (4): the one-time password and passkey fields.
fn copy_hidden(name: &str) -> bool {
    otp_field(name) || name.starts_with(crate::search::run::PASSKEY)
}

/// A resolution's result.
#[derive(Debug)]
pub struct Resolved {
    /// The resolved text.
    pub text: SecretString,
    /// Some step ran out of depth budget: the caller logs one warning with
    /// the entry id and no value (MOD-08.18, Rust rule 9).
    pub depth_hit: bool,
    /// A work bound was passed and `text` is the raw input (MOD-08.20).
    pub bounded: bool,
    /// Some field step or the one-time-code step put in the display mask
    /// for a protected value (MOD-08.23, D-08-4), a display `{S:…}` left out
    /// a field that never shows (LD-170 (4)), or a reference search read
    /// either kind of value (F-130). F-129: a caller asks this, never the
    /// text, whether a protected value was read, since a transform can turn
    /// the mask and the value into the same text.
    pub masked: bool,
}

/// Resolves `text` in the context of `entry` (MOD-08). References resolve
/// only when `entry` is a live entry of `ctx.vault` (MOD-08.29): a history
/// item or an entry not yet added keeps them as written.
#[must_use]
pub fn resolve(text: &str, entry: &Entry, ctx: &Context<'_>) -> Resolved {
    let live = match ctx.index {
        Some(index) => index.by_id.get(&entry.uuid).copied(),
        None => ctx.vault.and_then(|v| crate::tree::entry(v, entry.uuid)),
    };
    let in_vault = live.is_some_and(|live| core::ptr::eq(live, entry));
    let mut run = Run {
        ctx,
        spans: 0,
        work: 0,
        depth_hit: false,
        regex_budget: crate::pattern::RESOLUTION_BUDGET,
        patterns: Vec::new(),
        mask_copied: false,
    };
    let at = Ent { e: entry, in_vault };
    match run.string_step(text, at, DEPTH) {
        Ok(t) => Resolved {
            text: t.into_secret(),
            depth_hit: run.depth_hit,
            bounded: false,
            masked: run.mask_copied,
        },
        Err(Bound) => Resolved {
            text: raw(text),
            depth_hit: run.depth_hit,
            bounded: true,
            masked: run.mask_copied,
        },
    }
}

fn raw(text: &str) -> SecretString {
    let mut s = String::with_capacity(text.len());
    s.push_str(text);
    SecretString::new(s)
}

/// A work bound was passed.
struct Bound;

type Step = Result<Text, Bound>;

#[derive(Clone, Copy)]
struct Ent<'e> {
    e: &'e Entry,
    in_vault: bool,
}

struct Run<'c, 'a> {
    ctx: &'c Context<'a>,
    spans: usize,
    work: usize,
    depth_hit: bool,
    /// What is left of the regex budget (LD-118).
    regex_budget: usize,
    /// The patterns compiled in this resolution, at most
    /// [`MAX_COMPILES`] (LD-120).
    patterns: Vec<(String, Compiled)>,
    /// The mask stood in for a protected value ([`Resolved::masked`]).
    mask_copied: bool,
}

impl Run<'_, '_> {
    /// The pattern compiled once per resolution (LD-120): `None` once
    /// [`MAX_COMPILES`] different patterns were compiled, valid or not.
    fn compiled(&mut self, pattern: &str) -> Option<&Compiled> {
        let at = match self.patterns.iter().position(|(p, _)| p == pattern) {
            Some(at) => at,
            None if self.patterns.len() < MAX_COMPILES => {
                self.spend(COMPILE_UNITS).ok()?;
                let c = crate::pattern::compile_sized(pattern);
                self.patterns.push((pattern.to_owned(), c));
                self.patterns.len().saturating_sub(1)
            }
            None => return None,
        };
        self.patterns.get(at).map(|(_, c)| c)
    }

    fn charge(&mut self, n: usize) -> Result<(), Bound> {
        self.work = self.work.saturating_add(n);
        if self.work > MAX_WORK {
            return Err(Bound);
        }
        self.spend(n.saturating_mul(CHAR_UNITS))
    }

    /// Pays `units` from the caller's meter, if there is one (LD-126).
    fn spend(&self, units: usize) -> Result<(), Bound> {
        let Some(meter) = self.ctx.meter else {
            return Ok(());
        };
        let left = meter.get();
        if units > left {
            meter.set(0);
            return Err(Bound);
        }
        meter.set(left.saturating_sub(units));
        Ok(())
    }

    fn append(&mut self, out: &mut Text, s: &str) -> Result<(), Bound> {
        self.charge(s.len())?;
        out.push_str(s);
        if out.chars() > MAX_OUTPUT {
            return Err(Bound);
        }
        Ok(())
    }

    fn copy(&mut self, s: &str) -> Step {
        let mut out = Text::new();
        self.append(&mut out, s)?;
        Ok(out)
    }

    /// The display mask in place of a protected value, noted (F-129).
    fn mask(&mut self) -> Step {
        self.mask_copied = true;
        self.copy(MASK)
    }

    /// A string step (MOD-08.18): every span of `text` resolved.
    fn string_step(&mut self, text: &str, x: Ent<'_>, budget: i32) -> Step {
        let b = budget.saturating_sub(1);
        if b < 0 {
            self.depth_hit = true;
            return self.copy(text);
        }
        self.charge(text.len())?;
        if let Some(mid) = escaped(text) {
            let mut out = Text::new();
            self.append(&mut out, "{")?;
            self.append(&mut out, mid)?;
            self.append(&mut out, "}")?;
            return Ok(out);
        }
        let mut out = Text::new();
        let mut at = 0usize;
        for (s, e) in spans(text) {
            self.append(&mut out, text.get(at..s).unwrap_or(""))?;
            let r = self.span_step(text.get(s..e).unwrap_or(""), x, b)?;
            self.append(&mut out, r.as_str())?;
            at = e;
        }
        self.append(&mut out, text.get(at..).unwrap_or(""))?;
        Ok(out)
    }

    /// A span step (MOD-08.18): one span, or a whole text (a reference's
    /// search text) that is classified as one span when it starts with `{`
    /// and ends with `}`.
    fn span_step(&mut self, span: &str, x: Ent<'_>, budget: i32) -> Step {
        self.spans = self.spans.saturating_add(1);
        if self.spans > MAX_SPANS {
            return Err(Bound);
        }
        let b = budget.saturating_sub(1);
        if b < 0 {
            self.depth_hit = true;
            return self.copy(span);
        }
        if !(span.len() >= 2 && span.starts_with('{') && span.ends_with('}')) {
            return self.string_step(span, x, b);
        }
        let inner = span.get(1..span.len().saturating_sub(1)).unwrap_or("");
        if let Some(name) = inner.strip_prefix("S:") {
            return match x.e.field(name) {
                Some(_) if (self.ctx.hidden)(name) => {
                    self.mask_copied |= self.ctx.display;
                    Ok(Text::new())
                }
                Some(f) if self.masked(name, f) => self.mask(),
                Some(f) => self.string_step(f.value.expose(), x, b),
                None => Ok(Text::new()),
            };
        }
        if inner.starts_with("REF:") {
            return self.reference_step(span, x, b.saturating_add(1));
        }
        if starts_ci(inner, "T-CONV:") {
            return self.conversion(inner, x, b);
        }
        if starts_ci(inner, "T-REPLACE-RX:") {
            return self.replace(inner, x, b);
        }
        match fixed(span) {
            Some(p) => self.fixed(p, x, b),
            None => {
                let r = self.string_step(inner, x, b)?;
                let mut out = Text::new();
                self.append(&mut out, "{")?;
                self.append(&mut out, r.as_str())?;
                self.append(&mut out, "}")?;
                Ok(out)
            }
        }
    }

    /// Whether a field's value shows masked: display mode and a protected
    /// field (its own flag, or the vault's flag for a standard field).
    fn masked(&self, name: &str, f: &Field) -> bool {
        self.ctx.display
            && (f.protected
                || (STANDARD_FIELDS.contains(&name)
                    && self
                        .ctx
                        .vault
                        .is_some_and(|v| v.meta.memory_protection.for_field(name))))
    }

    /// F-130: whether a reference search over `search` reads, on `e`, a
    /// value display mode never shows (protected, or a field `hidden`
    /// names).
    fn search_reads_withheld(&self, search: Code, e: &Entry) -> bool {
        let withheld =
            |n: &str, f: &Field| self.masked(n, f) || (self.ctx.display && (self.ctx.hidden)(n));
        match search {
            Code::Field(name) => e.field(name).is_some_and(|f| withheld(name, f)),
            Code::Any => e.fields().any(|(n, f)| withheld(n, f)),
            Code::Id => false,
        }
    }

    fn field_step(&mut self, name: &str, x: Ent<'_>, b: i32) -> Step {
        match x.e.field(name) {
            Some(f) if self.masked(name, f) => self.mask(),
            Some(f) => self.string_step(f.value.expose(), x, b),
            None => Ok(Text::new()),
        }
    }

    fn fixed(&mut self, p: Fixed, x: Ent<'_>, b: i32) -> Step {
        match p {
            Fixed::Field(name) => self.field_step(name, x, b),
            Fixed::Uuid => self.copy(&hex_lower(x.e.uuid)),
            Fixed::Otp => match (self.ctx.otp)(x.e, self.ctx.now) {
                // D-08-4: a protected one-time password shows masked.
                Some(_)
                    if self.ctx.display
                        && x.e.fields().any(|(n, f)| f.protected && otp_field(n)) =>
                {
                    self.mask()
                }
                Some(code) => self.copy(code.expose()),
                None => Ok(Text::new()),
            },
            Fixed::Url(part) => {
                let resolved = self.field_step("URL", x, b)?;
                if resolved.is_empty() {
                    return Ok(Text::new());
                }
                let parts = url::parse(resolved.as_str());
                let port;
                let text = match part {
                    UrlPart::WithoutScheme => parts.without_scheme.as_str(),
                    UrlPart::Scheme => parts.scheme.as_str(),
                    UrlPart::Host => parts.host.as_str(),
                    UrlPart::Port => {
                        port = parts.port.to_string();
                        port.as_str()
                    }
                    UrlPart::Path => parts.path.as_str(),
                    UrlPart::Query => parts.query.as_str(),
                    UrlPart::Fragment => parts.fragment.as_str(),
                    UrlPart::UserInfo => parts.userinfo.as_str(),
                    UrlPart::UserName => parts.username.as_str(),
                    UrlPart::Password => parts.password.as_str(),
                };
                self.copy(text)
            }
            Fixed::Date(utc, part) => {
                let zone: &dyn Zone = if utc { &Utc } else { self.ctx.zone };
                let text = date_text(zone, self.ctx.now, part);
                self.string_step(&text, x, b)
            }
            Fixed::DbDir => {
                if x.in_vault {
                    self.copy(self.ctx.vault_dir)
                } else {
                    Ok(Text::new())
                }
            }
        }
    }

    /// A reference step (MOD-08.13 to MOD-08.17).
    fn reference_step(&mut self, span: &str, x: Ent<'_>, budget: i32) -> Step {
        let b = budget.saturating_sub(1);
        if b < 0 {
            self.depth_hit = true;
            return self.copy(span);
        }
        let Some((want, search, text)) = parse_reference(span) else {
            return self.copy(span);
        };
        if !x.in_vault {
            return self.copy(span);
        }
        let Some(vault) = self.ctx.vault else {
            return self.copy(span);
        };
        let wanted = self.span_step(text, x, b)?;
        // MOD-08.32: inside a share group the search keeps to what that
        // share sends. The index knows each entry's share group (F-156);
        // without it, finding the scope is a walk, paid like a search.
        let (scope, looked) = match self.ctx.index {
            Some(_) => (None, 0),
            None => scope(vault, x.e),
        };
        self.charge(looked)?;
        self.spend(looked.saturating_mul(VISIT_UNITS))?;
        // F-130: the answer tells whether the text equals what the search
        // read, so a withheld value read on the way counts as shown masked.
        let mut read = false;
        let mut visit = |e: &Entry| read |= self.search_reads_withheld(search, e);
        let w = wanted.as_str();
        let (found, visited) = match (self.ctx.index, scope) {
            (Some(index), _) => match index.share_of(x.e) {
                Some(share) => find_scoped(index, share, search, w, &mut visit),
                None => find_indexed(index, search, w, &mut visit),
            },
            (None, Some(groups)) => find_in(&groups, search, w, &mut visit),
            (None, None) => find_in(&vault.root.subtree(), search, w, &mut visit),
        };
        self.mask_copied |= read;
        self.charge(visited)?;
        self.spend(visited.saturating_mul(VISIT_UNITS))?;
        let Some(found) = found else {
            return Ok(Text::new());
        };
        let at = Ent {
            e: found,
            in_vault: true,
        };
        match want {
            Code::Field(name) => self.field_step(name, at, b),
            Code::Id => {
                let id = hex_lower(found.uuid);
                self.string_step(&id, at, b)
            }
            Code::Any => Ok(Text::new()),
        }
    }

    /// `{T-CONV:...}` (MOD-08.21); `inner` is the span without its braces.
    fn conversion(&mut self, inner: &str, x: Ent<'_>, b: i32) -> Step {
        let Some(parts) = body_parts(inner, "T-CONV:".len(), 4) else {
            return Ok(Text::new());
        };
        let (Some(text), Some(kind)) = (parts.get(1), parts.get(2)) else {
            return Ok(Text::new());
        };
        let text = self.string_step(text, x, b)?;
        let t = text.as_str();
        let mut out = Text::new();
        let is = |name: &str| kind.eq_ignore_ascii_case(name);
        let first = kind.chars().next().map(|c| c.to_ascii_lowercase());
        if is("base64") {
            base64(&mut out, t.as_bytes());
        } else if is("hex") {
            for byte in t.bytes() {
                push_hex(&mut out, byte, false);
            }
        } else if is("uri") {
            for byte in t.bytes() {
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                    out.push(char::from(byte));
                } else {
                    out.push('%');
                    push_hex(&mut out, byte, true);
                }
            }
        } else if is("uri-dec") {
            uri_decode(&mut out, t);
        } else if first == Some('u') {
            for u in t.chars().flat_map(char::to_uppercase) {
                out.push(u);
            }
        } else if first == Some('l') {
            for l in t.chars().flat_map(char::to_lowercase) {
                out.push(l);
            }
        } else {
            return Ok(Text::new());
        }
        self.charge(out.len())?;
        self.string_step(out.as_str(), x, b)
    }

    /// `{T-REPLACE-RX:...}` (MOD-08.22): text and replacement resolved
    /// first, the pattern used as written (LD-114); an invalid or too large
    /// pattern, look-around or a backreference gives the empty string
    /// (LD-110, LD-113); a text over 65,536 characters, or one met after the
    /// resolution's regex budget is spent, comes back as it is, unreplaced
    /// (LD-113, LD-118).
    fn replace(&mut self, inner: &str, x: Ent<'_>, b: i32) -> Step {
        let Some(parts) = body_parts(inner, "T-REPLACE-RX:".len(), 5) else {
            return Ok(Text::new());
        };
        let (Some(text), Some(pattern), Some(with)) = (parts.get(1), parts.get(2), parts.get(3))
        else {
            return Ok(Text::new());
        };
        let text = self.string_step(text, x, b)?;
        if text.chars() > MAX_REPLACE_TEXT {
            return Ok(text);
        }
        let with = self.string_step(with, x, b)?;
        let t = text.as_str();
        // LD-120: at most 8 distinct patterns are compiled per resolution;
        // the same pattern text is compiled once (it is never resolved, so it
        // holds no secret). LD-118: one budget per resolution; each replace
        // costs its compiled size × its text length (at least 512, LD-123);
        // once too
        // little is left, or past the compile cap, the text stays unchanged.
        let len = t.len().max(crate::pattern::MIN_CHARGED);
        // The engine shares its program between clones.
        let (re, size) = match self.compiled(pattern) {
            None => return Ok(text),
            Some(Compiled::Ok(re, size)) => (re.clone(), *size),
            Some(Compiled::TooBig | Compiled::Invalid) => return Ok(Text::new()),
        };
        if size > crate::pattern::cap_for(len) {
            return Ok(Text::new());
        }
        let cost = size.saturating_mul(len);
        if cost > self.regex_budget {
            return Ok(text);
        }
        self.regex_budget = self.regex_budget.saturating_sub(cost);
        self.spend(cost / REGEX_PER_UNIT)?;
        let mut out = Text::new();
        let mut at = 0usize;
        for caps in re.captures_iter(t) {
            let Some(m) = caps.get_group(0) else { continue };
            self.append(&mut out, t.get(at..m.start).unwrap_or(""))?;
            self.charge(with.len().saturating_add(m.len()))?;
            expand(&mut out, with.as_str(), t, &caps);
            if out.chars() > MAX_OUTPUT {
                return Err(Bound);
            }
            at = m.end.max(at);
        }
        self.append(&mut out, t.get(at..).unwrap_or(""))?;
        self.string_step(out.as_str(), x, b)
    }
}

// ---------------------------------------------------------------------------
// Spans, escape and classification (MOD-08.1 to MOD-08.5).

/// The whole text's escape (MOD-08.2): `\{...\}` gives the inside.
fn escaped(text: &str) -> Option<&str> {
    text.strip_prefix("\\{")?.strip_suffix("\\}")
}

/// The spans of `text`, left to right, not overlapping (MOD-08.1), as
/// byte ranges. One pass with a stack: a `{` starts a valid span when its
/// matching `}` closes a non-empty run of items, each a character that is
/// not a brace or a nested valid span.
fn spans(text: &str) -> Vec<(usize, usize)> {
    struct Open {
        at: usize,
        items: usize,
        bad: bool,
    }
    let mut stack: Vec<Open> = Vec::new();
    let mut valid: Vec<(usize, usize)> = Vec::new();
    for (i, c) in text.char_indices() {
        match c {
            '{' => stack.push(Open {
                at: i,
                items: 0,
                bad: false,
            }),
            '}' => {
                let Some(o) = stack.pop() else { continue };
                let ok = o.items > 0 && !o.bad;
                if ok {
                    valid.push((o.at, i.saturating_add(1)));
                }
                if let Some(parent) = stack.last_mut() {
                    parent.items = parent.items.saturating_add(1);
                    parent.bad |= !ok;
                }
            }
            _ => {
                if let Some(top) = stack.last_mut() {
                    top.items = top.items.saturating_add(1);
                }
            }
        }
    }
    valid.sort_unstable();
    let mut out = Vec::new();
    let mut end = 0usize;
    for (s, e) in valid {
        if s >= end {
            out.push((s, e));
            end = e;
        }
    }
    out
}

fn starts_ci(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|h| h.eq_ignore_ascii_case(prefix))
}

#[derive(Clone, Copy)]
enum UrlPart {
    WithoutScheme,
    Scheme,
    Host,
    Port,
    Path,
    Query,
    Fragment,
    UserInfo,
    UserName,
    Password,
}

#[derive(Clone, Copy)]
enum DatePart {
    Simple,
    Year,
    Month,
    Day,
    Hour,
    Minute,
    Second,
}

#[derive(Clone, Copy)]
enum Fixed {
    Field(&'static str),
    Uuid,
    Otp,
    Url(UrlPart),
    Date(bool, DatePart),
    DbDir,
}

/// The table of MOD-08.4, matched on the whole span upper-cased.
fn fixed(span: &str) -> Option<Fixed> {
    use DatePart as D;
    use UrlPart as U;
    const TABLE: [(&str, Fixed); 35] = [
        ("{TITLE}", Fixed::Field("Title")),
        ("{USERNAME}", Fixed::Field("UserName")),
        ("{PASSWORD}", Fixed::Field("Password")),
        ("{NOTES}", Fixed::Field("Notes")),
        ("{URL}", Fixed::Field("URL")),
        ("{UUID}", Fixed::Uuid),
        ("{TOTP}", Fixed::Otp),
        ("{TIMEOTP}", Fixed::Otp),
        ("{URL:RMVSCM}", Fixed::Url(U::WithoutScheme)),
        ("{URL:WITHOUTSCHEME}", Fixed::Url(U::WithoutScheme)),
        ("{URL:SCM}", Fixed::Url(U::Scheme)),
        ("{URL:SCHEME}", Fixed::Url(U::Scheme)),
        ("{URL:HOST}", Fixed::Url(U::Host)),
        ("{URL:PORT}", Fixed::Url(U::Port)),
        ("{URL:PATH}", Fixed::Url(U::Path)),
        ("{URL:QUERY}", Fixed::Url(U::Query)),
        ("{URL:FRAGMENT}", Fixed::Url(U::Fragment)),
        ("{URL:USERINFO}", Fixed::Url(U::UserInfo)),
        ("{URL:USERNAME}", Fixed::Url(U::UserName)),
        ("{URL:PASSWORD}", Fixed::Url(U::Password)),
        ("{DT_SIMPLE}", Fixed::Date(false, D::Simple)),
        ("{DT_YEAR}", Fixed::Date(false, D::Year)),
        ("{DT_MONTH}", Fixed::Date(false, D::Month)),
        ("{DT_DAY}", Fixed::Date(false, D::Day)),
        ("{DT_HOUR}", Fixed::Date(false, D::Hour)),
        ("{DT_MINUTE}", Fixed::Date(false, D::Minute)),
        ("{DT_SECOND}", Fixed::Date(false, D::Second)),
        ("{DT_UTC_SIMPLE}", Fixed::Date(true, D::Simple)),
        ("{DT_UTC_YEAR}", Fixed::Date(true, D::Year)),
        ("{DT_UTC_MONTH}", Fixed::Date(true, D::Month)),
        ("{DT_UTC_DAY}", Fixed::Date(true, D::Day)),
        ("{DT_UTC_HOUR}", Fixed::Date(true, D::Hour)),
        ("{DT_UTC_MINUTE}", Fixed::Date(true, D::Minute)),
        ("{DT_UTC_SECOND}", Fixed::Date(true, D::Second)),
        ("{DB_DIR}", Fixed::DbDir),
    ];
    // Upper case never makes fewer characters, and no name has more than
    // 19, so a longer span (more than 76 bytes) matches nothing.
    if span.len() > 76 {
        return None;
    }
    TABLE
        .iter()
        .find(|(name, _)| span.chars().flat_map(char::to_uppercase).eq(name.chars()))
        .map(|(_, f)| *f)
}

/// The date text of a `DT_` placeholder (MOD-08.10): SIMPLE is
/// `yyyyMMddHHmmss`, YEAR 4 digits, the others 2 digits; empty when the
/// clock is outside year 1 to 9999.
fn date_text(zone: &dyn Zone, now: Time, part: DatePart) -> String {
    let Some(c) = local(zone, now).and_then(Time::to_civil) else {
        return String::new();
    };
    match part {
        DatePart::Simple => format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        ),
        DatePart::Year => format!("{:04}", c.year),
        DatePart::Month => format!("{:02}", c.month),
        DatePart::Day => format!("{:02}", c.day),
        DatePart::Hour => format!("{:02}", c.hour),
        DatePart::Minute => format!("{:02}", c.minute),
        DatePart::Second => format!("{:02}", c.second),
    }
}

// ---------------------------------------------------------------------------
// Field references (MOD-08.13 to MOD-08.17, MOD-08.30).

#[derive(Clone, Copy)]
enum Code {
    Field(&'static str),
    Id,
    Any,
}

fn code(c: char) -> Option<Code> {
    Some(match c.to_ascii_uppercase() {
        'T' => Code::Field("Title"),
        'U' => Code::Field("UserName"),
        'P' => Code::Field("Password"),
        'A' => Code::Field("URL"),
        'N' => Code::Field("Notes"),
        'I' => Code::Id,
        'O' => Code::Any,
        _ => return None,
    })
}

/// `{REF:` W `@` S `:` text `}` read from the span's start (MOD-08.13):
/// W in `TUPANI`, S in `TUPANIO`, any case; the text one or more items,
/// each a character that is not a brace or a `{...}` group with no `}`
/// inside.
fn parse_reference(span: &str) -> Option<(Code, Code, &str)> {
    let body = span.strip_prefix("{REF:")?.strip_suffix('}')?;
    let mut chars = body.chars();
    let want = code(chars.next()?).filter(|c| !matches!(c, Code::Any))?;
    if chars.next()? != '@' {
        return None;
    }
    let search = code(chars.next()?)?;
    if chars.next()? != ':' {
        return None;
    }
    let text = chars.as_str();
    let mut items = 0usize;
    let mut rest = text.chars();
    while let Some(c) = rest.next() {
        match c {
            '{' => {
                if !rest.by_ref().any(|d| d == '}') {
                    return None;
                }
            }
            '}' => return None,
            _ => {}
        }
        items = items.saturating_add(1);
    }
    (items > 0).then_some((want, search, text))
}

/// The id a search text names (MOD-08.15): its hex digits, paired from the
/// right (an odd count makes the leftmost digit a byte of its own); exactly
/// 16 bytes.
fn id_from_text(text: &str) -> Option<Uuid> {
    // At most 32 digits make 16 bytes: a fixed buffer, no allocation.
    let mut digits = [0u8; 32];
    let mut count = 0usize;
    for d in text.chars().filter_map(|c| c.to_digit(16)) {
        *digits.get_mut(count)? = u8::try_from(d).ok()?;
        count = count.saturating_add(1);
    }
    // 31 or 32 digits make 16 bytes (a 33rd never fits the buffer).
    if count < 31 {
        return None;
    }
    let mut id = [0u8; 16];
    let mut rev = digits.get(..count)?.iter().rev();
    for slot in id.iter_mut().rev() {
        let lo = rev.next().copied().unwrap_or(0);
        let hi = rev.next().copied().unwrap_or(0);
        *slot = hi.saturating_mul(16).saturating_add(lo);
    }
    Some(Uuid(id))
}

/// MOD-08.32: the groups whose entries a reference of the live entry
/// `referrer` searches, in search order; `None` when the entry has no share
/// group (the nearest group at or above it with a share item, readable or
/// not), so the whole vault. Keep group structure on: the share group's
/// subtree in pre-order, the recycle bin's subtree left out; off, or an
/// item that cannot be read: the share group alone. Also returns how many
/// groups and entries finding them visited, for the work bound.
fn scope<'v>(vault: &'v Vault, referrer: &Entry) -> (Option<Vec<&'v Group>>, usize) {
    let key = core::str::from_utf8(share_item::KEY).unwrap_or_default();
    let mut visited = 0usize;
    let mut stack = vec![(&vault.root, None::<&Group>)];
    while let Some((g, above)) = stack.pop() {
        visited = visited.saturating_add(1).saturating_add(g.entries.len());
        let item = g.custom_data.get(key);
        let here = if item.is_some() { Some(g) } else { above };
        if !g.entries.iter().any(|e| core::ptr::eq(e, referrer)) {
            stack.extend(g.groups.iter().map(|c| (c, here)));
            continue;
        }
        let Some(share) = here else {
            return (None, visited);
        };
        let keep =
            matches!(share_item::of(share), Some(share_item::Item::Settings(s)) if s.keep_groups);
        if !keep {
            return (Some(vec![share]), visited);
        }
        let bin = crate::recycle::bin_id(vault);
        let mut groups = Vec::new();
        let mut walk = vec![share];
        while let Some(g) = walk.pop() {
            visited = visited.saturating_add(1);
            if Some(g.uuid) == bin {
                continue;
            }
            groups.push(g);
            walk.extend(g.groups.iter().rev());
        }
        return (Some(groups), visited);
    }
    (None, visited)
}

/// MOD-08.27 (LD-284 (2)): whether a reference of the live entry
/// `referrer` of `vault` can find the entry `target` (MOD-08.32).
#[must_use]
pub fn in_scope(vault: &Vault, referrer: &Entry, target: Uuid) -> bool {
    match scope(vault, referrer).0 {
        None => true,
        Some(groups) => groups
            .iter()
            .any(|g| g.entries.iter().any(|e| e.uuid == target)),
    }
}

/// The first live entry that matches (MOD-08.15) among the entries of
/// `groups`, taken in order (from the root: every group in pre-order),
/// each group's entries in stored order, the recycle bin and the referring
/// entry included, history items never. Also returns how many groups and
/// entries the search visited, for the work bound. `visit` sees every
/// entry whose values the search compares.
fn find_in<'v>(
    groups: &[&'v Group],
    search: Code,
    text: &str,
    visit: &mut dyn FnMut(&Entry),
) -> (Option<&'v Entry>, usize) {
    let id = matches!(search, Code::Id)
        .then(|| id_from_text(text))
        .flatten();
    let mut visited = 0usize;
    for &g in groups {
        for e in &g.entries {
            visited = visited.saturating_add(1);
            visit(e);
            let hit = match search {
                Code::Field(name) => e.value(name) == text,
                Code::Any => e.fields().any(|(_, f)| f.value.expose() == text),
                Code::Id => id == Some(e.uuid),
            };
            if hit {
                return (Some(e), visited);
            }
        }
        visited = visited.saturating_add(1);
    }
    (None, visited)
}

/// [`find_in`] over the whole vault's index: the same first match, an id in one lookup
/// (ids are unique in a vault, and the index keeps the first).
fn find_indexed<'v>(
    index: &EntryIndex<'v>,
    search: Code,
    text: &str,
    visit: &mut dyn FnMut(&Entry),
) -> (Option<&'v Entry>, usize) {
    if matches!(search, Code::Id) {
        let found = id_from_text(text).and_then(|id| index.by_id.get(&id).copied());
        return (found, 1);
    }
    for (i, e) in index.order.iter().enumerate() {
        visit(e);
        let hit = match search {
            Code::Field(name) => e.value(name) == text,
            Code::Any => e.fields().any(|(_, f)| f.value.expose() == text),
            Code::Id => false,
        };
        if hit {
            return (Some(e), i.saturating_add(1));
        }
    }
    (None, index.order.len().saturating_add(index.groups))
}

/// [`find_in`] over the scope of the share group at place `share` of the
/// index (MOD-08.32), the same first match: with Keep group structure on
/// the entries of its subtree in pre-order, less the recycle bin's; off, its
/// own entries only. An id is one lookup unless more entries hold it.
fn find_scoped<'v>(
    index: &EntryIndex<'v>,
    share: usize,
    search: Code,
    text: &str,
    visit: &mut dyn FnMut(&Entry),
) -> (Option<&'v Entry>, usize) {
    let Some(top) = index.tree.get(share) else {
        return (None, 1);
    };
    let end = if top.keep {
        top.end
    } else {
        share.saturating_add(1)
    };
    let inside = |place: usize| {
        let Some(&g) = index.group_of.get(place) else {
            return false;
        };
        // Keep off: the share group's own entries, also when it is the bin.
        if !top.keep {
            return g == share;
        }
        // A bin at or below the share group, on the way down to g, keeps g out.
        (share..end).contains(&g)
            && index
                .tree
                .get(g)
                .and_then(|n| n.bin)
                .is_none_or(|bin| bin < share)
    };
    if matches!(search, Code::Id) {
        let id = id_from_text(text);
        let first = id.and_then(|id| index.by_id.get(&id)).copied();
        let hit = first.filter(|e| {
            index
                .at
                .get(&core::ptr::from_ref(*e))
                .is_some_and(|&at| inside(at))
        });
        if hit.is_some() || id.is_none_or(|id| !index.repeated.contains(&id)) {
            return (hit, 1);
        }
    }
    let first = top.first;
    let last = index.tree.get(end).map_or(index.order.len(), |n| n.first);
    let id = matches!(search, Code::Id)
        .then(|| id_from_text(text))
        .flatten();
    for place in first..last {
        if !inside(place) {
            continue;
        }
        let Some(&e) = index.order.get(place) else {
            continue;
        };
        visit(e);
        let hit = match search {
            Code::Field(name) => e.value(name) == text,
            Code::Any => e.fields().any(|(_, f)| f.value.expose() == text),
            Code::Id => id == Some(e.uuid),
        };
        if hit {
            return (Some(e), place.saturating_sub(first).saturating_add(1));
        }
    }
    let groups = end.saturating_sub(share);
    (None, last.saturating_sub(first).saturating_add(groups))
}

/// The reference Larsal writes (MOD-08.30): `{REF:` code `@I:` 32 uppercase
/// hex digits `}`; code `U` or `P` (MOD-10.5).
#[must_use]
pub fn reference(code: char, id: Uuid) -> String {
    let hex: String = id.0.iter().map(|b| format!("{b:02X}")).collect();
    format!("{{REF:{code}@I:{hex}}}")
}

fn hex_lower(id: Uuid) -> String {
    id.0.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Conversions and regex replace (MOD-08.21, MOD-08.22).

/// The parts of a conversion or regex body (MOD-08.21): `inner` after its
/// `skip` prefix, split on its first character, empty parts kept; `None`
/// with fewer than `need` parts or a line feed anywhere in the span. The
/// card's body also holds the span's final `}`; it only lengthens the last
/// part, which a body with enough parts never uses (and a `}` cannot be the
/// separator inside a valid span).
fn body_parts(inner: &str, skip: usize, need: usize) -> Option<Vec<&str>> {
    if inner.contains('\n') {
        return None;
    }
    let body = inner.get(skip..)?;
    let sep = body.chars().next()?;
    let parts: Vec<&str> = body.split(sep).collect();
    (parts.len() >= need).then_some(parts)
}

fn push_hex(out: &mut Text, byte: u8, upper: bool) {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    for nibble in [byte >> 4, byte & 15] {
        out.push(char::from(
            digits.get(usize::from(nibble)).copied().unwrap_or(b'0'),
        ));
    }
}

/// Standard Base64 with `=` padding, written into `out`.
fn base64(out: &mut Text, data: &[u8]) {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sym = |i: u32| {
        char::from(
            ABC.get(usize::try_from(i & 63).unwrap_or(0))
                .copied()
                .unwrap_or(b'A'),
        )
    };
    for chunk in data.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = b(0) << 16 | b(1) << 8 | b(2);
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        out.push(if chunk.len() > 1 { sym(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { sym(n) } else { '=' });
    }
}

/// `uri-dec` (MOD-08.21, D-08-10): `%` and two hex digits become a byte;
/// a `%` without two hex digits after it stays as written; `+` stays; then
/// UTF-8 with U+FFFD for bad bytes.
fn uri_decode(out: &mut Text, s: &str) {
    let b = s.as_bytes();
    let mut bytes = Bytes::new();
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        let hex = |at: usize| b.get(at).and_then(|&x| char::from(x).to_digit(16));
        if c == b'%'
            && let (Some(h), Some(l)) = (hex(i.saturating_add(1)), hex(i.saturating_add(2)))
        {
            let v = u8::try_from(h.saturating_mul(16).saturating_add(l)).unwrap_or(0);
            bytes.extend(&[v]);
            i = i.saturating_add(3);
        } else {
            bytes.extend(&[c]);
            i = i.saturating_add(1);
        }
    }
    bytes.utf8_lossy_into(out);
}

/// The replacement of one match (MOD-08.22): `$n` and `\n` insert capture
/// group n (1 or more); two digits are read when that group exists, else
/// one; a group that does not exist is written as `\` and its digit.
fn expand(out: &mut Text, with: &str, text: &str, caps: &Captures) {
    let count = caps.group_len().saturating_sub(1);
    let exists = |n: usize| (1..=count).contains(&n);
    let group = |n: usize| {
        caps.get_group(n)
            .and_then(|m| text.get(m.start..m.end))
            .unwrap_or("")
    };
    let mut rest = with;
    while let Some(c) = rest.chars().next() {
        rest = rest.get(c.len_utf8()..).unwrap_or("");
        let mut d = rest.chars();
        let (Some(d1), true) = (d.next().and_then(|x| x.to_digit(10)), c == '$' || c == '\\')
        else {
            out.push(c);
            continue;
        };
        let d1 = usize::try_from(d1).unwrap_or(0);
        let two = d
            .next()
            .and_then(|x| x.to_digit(10))
            .and_then(|d2| usize::try_from(d2).ok())
            .map(|d2| d1.saturating_mul(10).saturating_add(d2))
            .filter(|&n| exists(n));
        match two {
            Some(n) => {
                out.push_str(group(n));
                rest = rest.get(2..).unwrap_or("");
            }
            None if exists(d1) => {
                out.push_str(group(d1));
                rest = rest.get(1..).unwrap_or("");
            }
            None => {
                out.push('\\');
                out.push_str(rest.get(..1).unwrap_or(""));
                rest = rest.get(1..).unwrap_or("");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Markers and the browser save guard (MOD-08.24, MOD-08.28).

/// Whether an entry is drawn as a reference holder (MOD-08.24): any of its
/// standard fields holds a reference.
#[must_use]
pub fn holds_any_reference(e: &Entry) -> bool {
    STANDARD_FIELDS.iter().any(|n| holds_reference(e.value(n)))
}

/// The browser save guard (MOD-08.28, D-08-5): a login or password is
/// refused when resolving it in a blank entry of the target vault changes
/// it, or the result holds a reference.
#[must_use]
pub fn browser_refuses(vault: &Vault, value: &str, now: Time) -> bool {
    let blank = Entry::new(Uuid::ZERO, now);
    let r = resolve(value, &blank, &Context::new(Some(vault), now));
    r.text.expose() != value || holds_reference(r.text.expose())
}

#[cfg(test)]
mod copy_tests {
    use super::*;
    use larsal_model::Group;

    /// LD-170 (4) and LD-126 through the shared constructor.
    #[test]
    fn copy_context_hides_otp_and_passkey_fields_and_meters() {
        let mut e = Entry::new(Uuid([1; 16]), Time(0));
        for (name, value) in [
            ("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
            ("KPEX_PASSKEY_PRIVATE_KEY", "pk"),
            ("Note", "n"),
        ] {
            e.set_field(
                name.into(),
                Field {
                    value: SecretString::new(value.into()),
                    protected: true,
                },
            );
        }
        let mut root = Group::new(Uuid([2; 16]), "Root".into(), Time(0));
        root.entries.push(e);
        let v = Vault::new(root, Time(0));
        let e = v.root.entries.first().unwrap();
        let meter = Cell::new(COPY_BUDGET);
        let ctx = copy_context(&v, "/tmp/v", Time(0), &meter);
        let r = |t: &str| resolve(t, e, &ctx).text;
        assert_eq!(r("{S:otp}").expose(), "");
        assert_eq!(r("{S:KPEX_PASSKEY_PRIVATE_KEY}").expose(), "");
        assert_eq!(r("{S:Note}|{DB_DIR}").expose(), "n|/tmp/v");
        assert!(meter.get() < COPY_BUDGET, "the work is metered");
        let open = Context::new(Some(&v), Time(0));
        assert_eq!(
            resolve("{S:otp}", e, &open).text.expose(),
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
            "without it the raw value shows"
        );
    }
}

#[cfg(test)]
mod f_130_tests {
    use super::*;
    use crate::auto_open::resolve_field;
    use larsal_model::Group;

    fn entry(n: u8, fields: &[(&str, &str, bool)]) -> Entry {
        let mut e = Entry::new(Uuid([n; 16]), Time(0));
        for &(name, value, protected) in fields {
            e.set_field(
                name.into(),
                Field {
                    value: SecretString::new(value.into()),
                    protected,
                },
            );
        }
        e
    }

    /// F-130 (LD-242 (1)): a reference search that reads a protected (or
    /// never shown) value marks the display resolution masked, so the URL
    /// `?t={REF:T@P:demo-s}` and a key file path built that way are refused
    /// (MSG-08-4) whether the guess is right or wrong; the row's probe.
    #[test]
    fn f_130_reference_search_over_protected_field_is_masked() {
        let target = entry(
            1,
            &[("Title", "Target", false), ("Password", "demo-s", true)],
        );
        let otp = entry(
            3,
            &[("Title", "Seed", false), ("otp", "otpauth://demo", false)],
        );
        let probe = entry(
            2,
            &[
                ("Title", "Probe", false),
                ("URL", "https://example.com/?t={REF:T@P:demo-s}", false),
                ("UserName", "{REF:T@P:wrong}.larsalkey", false),
                ("Notes", "{REF:T@O:otpauth://demo}", false),
                ("Pin", "{REF:T@T:Target}", false),
            ],
        );
        let mut root = Group::new(Uuid([9; 16]), "Root".into(), Time(0));
        root.entries = vec![otp, target, probe];
        let mut v = Vault::new(root, Time(0));
        // Only the explicit flags protect: every entry's empty Password
        // would count otherwise.
        v.meta.memory_protection.password = false;
        let e = v.root.entries.get(2).unwrap();
        let field = |name| resolve_field(&v, "", e, name, Time(0));
        let (full, _, secret) = field("URL");
        assert_eq!(full.expose(), "https://example.com/?t=Target");
        assert!(secret, "a right guess is refused");
        assert!(field("UserName").2, "a wrong guess is refused too");
        assert!(
            field("Notes").2,
            "the search over every field reads the seed"
        );
        let (full, shown, secret) = field("Pin");
        assert_eq!((full.expose(), shown.expose()), ("Target", "Target"));
        assert!(!secret, "a search over plain titles stays plain");
        let mut show = Context::new(Some(&v), Time(0));
        show.display = true;
        let id = |n: u8| reference('T', Uuid([n; 16]));
        assert!(
            !resolve(&id(1), e, &show).masked,
            "an id search reads no value"
        );
        show.display = false;
        let plain = resolve("{REF:T@P:demo-s}", e, &show);
        assert!(!plain.masked && plain.text.expose() == "Target");
    }
}
