//! The vault side of the bridge (INT-02, E7-S2): [`VaultSide`] answers
//! the requests of INT-01.30 that read vaults, over any [`Vaults`] (App's
//! session in app-ffi; a demo set in the tests).
//!
//! - Which vaults a request uses (INT-02.10) and which entries a page may
//!   see (INT-02.13, INT-02.14, INT-02.17, INT-02.19).
//! - `logins.find`, `logins.search` and `logins.recent` give summaries
//!   only, never a secret, and never open a dialog (INT-02.20, R02-1,
//!   R02-2); `logins.get` and `code.get` give secrets only for entries in
//!   state allowed, or after the user's Allow in the site access prompt
//!   (INT-02.18, INT-02.21, INT-02.23).
//! - One work meter and one entry index per request bound every
//!   resolution (LD-126 (1), (3), LD-326 (1)).
//! - Nothing waits while holding a vault: a prompt waits in [`Prompts`]
//!   and reads the vault again when its turn comes (INT-02.15).

use crate::channel::{Request, SharedHandler};
use crate::matching::{Page, Site, order, url_host};
use crate::prompts::{
    Access, Answer, CONNECT_TIME, Connect, Outcome, PROMPT_TIME, Prompts, Question, Row,
};
use crate::psl::registrable_domain;
use crate::site::{self, Lists, State};
use app_core::expiry::is_expired;
use app_core::refs::{self, COPY_BUDGET, Context, EntryIndex};
use app_core::time::Instant;
use app_crypto::base64::{self, Form};
use app_model::json::{Map, Value};
use app_model::{Entry, Group, Time, Uuid, Vault};
use std::cell::Cell;
use std::sync::{Arc, Mutex, PoisonError};

/// The error numbers of INT-01.40 this side sends.
mod code {
    pub const LOCKED: u8 = 1;
    pub const DENIED: u8 = 6;
    pub const NOT_PROVEN: u8 = 8;
    pub const UNKNOWN: u8 = 12;
    pub const NOT_A_PAGE: u8 = 14;
    pub const NONE: u8 = 15;
    pub const BAD_ID: u8 = 18;
    pub const BUSY: u8 = 42;
    pub const TOO_LARGE: u8 = 43;
}

/// Summaries `logins.find` gives at most, the best first (INT-02.20).
pub const MAX_FOUND: usize = 200;
/// Summaries `logins.search` gives at most (INT-02.22).
pub const MAX_SEARCH: usize = 50;
/// Summaries `logins.recent` gives at most (INT-02.9).
pub const MAX_RECENT: usize = 5;
/// Entry references one `logins.get` may name (INT-02.21).
pub const MAX_IDS: usize = 20;
/// One notification per browser and host in this many seconds (INT-02.31).
const NOTICE_GAP: i64 = 600;
/// Browser and host pairs remembered for [`NOTICE_GAP`].
const MAX_NOTICES: usize = 1_000;
/// The prefix of the extra fields for the browser (INT-02.21).
const KPH: &str = "KPH: ";
/// The prefix of the passkey fields (INT-04).
const PASSKEY: &str = "KPEX_PASSKEY";
const HIDE: &str = "BrowserHideEntry";
const SKIP: &str = "BrowserSkipAutoSubmit";
const ONLY_HTTP: &str = "BrowserOnlyHttpAuth";
const NOT_HTTP: &str = "BrowserNotHttpAuth";
const OMIT_WWW: &str = "BrowserOmitWww";
const RESTRICT: &str = "BrowserRestrictKey";

/// The S-BRW settings a request reads (APP-01); [`Options::default`] is
/// the card's defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Options {
    /// S-BRW-09 "Show a notification" (on).
    pub notify: bool,
    /// S-BRW-11 match scheme (on).
    pub match_scheme: bool,
    /// S-BRW-12 best matches only (off).
    pub best_only: bool,
    /// S-BRW-13 allow expired entries (off).
    pub allow_expired: bool,
    /// S-BRW-14 search every open vault (off).
    pub search_all: bool,
    /// S-BRW-15 never ask before giving access (off).
    pub never_ask: bool,
    /// S-BRW-17 HTTP sign-in without asking (off).
    pub skip_http_ask: bool,
    /// S-BRW-18 extra fields (on).
    pub extra_fields: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            notify: true,
            match_scheme: true,
            best_only: false,
            allow_expired: false,
            search_all: false,
            never_ask: false,
            skip_http_ask: false,
            extra_fields: true,
        }
    }
}

/// One open vault as the bridge sees it, in open order (APP-09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVault {
    /// The session's id of the vault.
    pub id: u64,
    /// Its file name without the extension (INT-01.30 `status`).
    pub name: String,
    /// The shown vault.
    pub shown: bool,
    /// Unlocked and not behind MOD-13's forced prompt (MOD-13.8).
    pub unlocked: bool,
}

/// What a [`Vaults::with`] call changed (APP-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Changed {
    /// Nothing.
    Nothing,
    /// A view-state change: written with the next save, no changed mark
    /// (INT-02.9).
    View,
    /// A data change: the vault is changed (INT-02.6, INT-02.16).
    Data,
}

/// App's open vaults, as the bridge reaches them.
pub trait Vaults: Send + Sync {
    /// The open vaults in open order.
    fn list(&self) -> Vec<OpenVault>;
    /// Runs `f` on vault `id` and its file's folder (`{DB_DIR}`) while it
    /// is unlocked; false when it is not. `f` says what it changed.
    fn with(&self, id: u64, f: &mut dyn FnMut(&mut Vault, &str) -> Changed) -> bool;
    /// The S-BRW settings now.
    fn options(&self) -> Options;
    /// The clock.
    fn now(&self) -> Time;
    /// The Mac's name (INT-02.4).
    fn computer(&self) -> String;
    /// Posts notification `text` (INT-02.31).
    fn notify(&self, text: &str);
}

/// A vault a request may use (INT-02.10): its id, its vault id and the
/// names under which it holds the session's key.
struct Use {
    id: u64,
    vid: String,
    names: Vec<String>,
}

/// The entry options as INT-02.14 resolves them.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
struct Flags {
    skip_submit: bool,
    only_http: bool,
    not_http: bool,
    omit_www: bool,
}

/// The group options a group passes down (MOD-02.17): the nearest group
/// that has a key decides.
#[derive(Clone, Default)]
struct Up {
    hide: Option<bool>,
    skip: Option<bool>,
    only: Option<bool>,
    not: Option<bool>,
    www: Option<bool>,
    restrict: Option<String>,
}

/// INT-02.13 steps 1 to 3 (and INT-02.12): every entry of `v` the bridge
/// may see under `names`, in tree order, with its group and options.
fn visible<'v>(v: &'v Vault, names: &[String]) -> Vec<(&'v Entry, &'v Group, Flags)> {
    let left_out = [app_core::recycle::bin_id(v), v.meta.entry_templates_group];
    let mut out = Vec::new();
    let mut stack = vec![(&v.root, Up::default())];
    while let Some((g, above)) = stack.pop() {
        if left_out.contains(&Some(g.uuid)) {
            continue;
        }
        let flag =
            |key: &str, above: Option<bool>| g.custom_data.get(key).map(|x| x == "true").or(above);
        let up = Up {
            hide: flag(HIDE, above.hide),
            skip: flag(SKIP, above.skip),
            only: flag(ONLY_HTTP, above.only),
            not: flag(NOT_HTTP, above.not),
            www: flag(OMIT_WWW, above.www),
            restrict: g
                .custom_data
                .get(RESTRICT)
                .map(str::to_owned)
                .or(above.restrict),
        };
        let reaches = up
            .restrict
            .as_deref()
            .is_none_or(|r| r.is_empty() || names.iter().any(|n| n == r));
        if reaches {
            for e in &g.entries {
                let own = |key: &str| e.custom_data.get(key) == Some("true");
                if up.hide.unwrap_or_else(|| own(HIDE)) {
                    continue;
                }
                let flags = Flags {
                    skip_submit: up.skip.unwrap_or_else(|| own(SKIP)),
                    only_http: up.only.unwrap_or_else(|| own(ONLY_HTTP)),
                    not_http: up.not.unwrap_or_else(|| own(NOT_HTTP)),
                    omit_www: up.www.unwrap_or(false),
                };
                out.push((e, g, flags));
            }
        }
        for c in g.groups.iter().rev() {
            stack.push((c, up.clone()));
        }
    }
    out
}

/// The page of one request (INT-03.1) with P, F and INT-02.19's line.
struct Target {
    page: Page,
    /// P, the page host in ASCII form; empty for a file page.
    p: String,
    /// F, the form host when present and different from P.
    f: Option<String>,
    http_auth: bool,
    /// MI02-05 or MI02-06 when the frame or the form is of another site.
    line: Option<String>,
}

fn text<'a>(r: &'a Map, key: &str) -> Option<&'a str> {
    r.get(key).and_then(Value::as_str)
}

impl Target {
    /// Reads `url`, `top_url`, `form_url` (when `form`) and `http_auth`.
    fn read(r: &Map, o: &Options, form: bool) -> Result<Self, u8> {
        let url = text(r, "url").ok_or(code::NOT_A_PAGE)?;
        let form_url = if form { text(r, "form_url") } else { None };
        let page = Page::read(url, form_url, o.match_scheme)?;
        let p = page.host().unwrap_or_default();
        let f = page.form_host().filter(|f| *f != p);
        let line = match page.host() {
            Some(p) => other_site(&p, text(r, "top_url"), f.as_deref())?,
            None => None,
        };
        Ok(Self {
            page,
            p,
            f,
            http_auth: r.get("http_auth").and_then(Value::as_bool) == Some(true),
            line,
        })
    }

    /// P and F, the hosts a Remember adds (INT-02.18).
    fn hosts(&self) -> Vec<String> {
        core::iter::once(self.p.clone())
            .chain(self.f.clone())
            .collect()
    }
}

/// INT-02.19: the line when the registrable domain of the top page or of
/// F differs from P's (a host without one stands for itself). A `top_url`
/// App cannot read: error 14.
fn other_site(p: &str, top_url: Option<&str>, f: Option<&str>) -> Result<Option<String>, u8> {
    let site = |h: &str| registrable_domain(h).unwrap_or_else(|| h.to_owned());
    if let Some(top) = top_url {
        let top = url_host(top).ok_or(code::NOT_A_PAGE)?;
        if site(&top) != site(p) {
            return Ok(Some(format!(
                "This sign-in form is inside a frame from {p} on {top}."
            )));
        }
    }
    Ok(f.filter(|f| site(f) != site(p))
        .map(|f| format!("This form sends what you type to {f}.")))
}

/// INT-02.13 steps 4 to 7 for one visible entry: its rank and its state
/// from its lists, `None` when it is not kept.
fn fit(t: &Target, e: &Entry, flags: Flags, ctx: &Context<'_>, o: &Options) -> Option<(u8, State)> {
    let lists = Lists::of(e);
    let site = Site {
        omit_www: flags.omit_www,
        allow: &lists.allow,
        deny: &lists.deny,
    };
    let rank = t.page.rank(e, ctx, &site)?;
    if (t.http_auth && flags.not_http) || (!t.http_auth && flags.only_http) {
        return None;
    }
    if !o.allow_expired && is_expired(&e.times, Instant::from(ctx.now)) {
        return None;
    }
    let state = State::of(&lists, &t.p, t.f.as_deref());
    (state != State::Denied).then_some((rank, state))
}

/// INT-02.17 to INT-02.19, INT-02.22: the state after the settings.
fn access(state: State, t: &Target, outside: bool, o: &Options) -> State {
    if state == State::Denied {
        State::Denied
    } else if t.line.is_some() || outside {
        State::Ask
    } else if t.http_auth {
        if o.skip_http_ask {
            State::Allowed
        } else {
            State::Ask
        }
    } else if o.never_ask {
        State::Allowed
    } else {
        state
    }
}

/// A title or user name for a summary (R02-2): resolved for display;
/// `None` when its field is protected or its resolution read a protected
/// value.
fn shown(e: &Entry, name: &str, ctx: &Context<'_>) -> Option<String> {
    let Some(f) = e.field(name) else {
        return Some(String::new());
    };
    if f.protected {
        return None;
    }
    let raw = f.value.expose();
    if !raw.contains('{') {
        return Some(raw.to_owned());
    }
    let r = refs::resolve(raw, e, ctx);
    (!r.masked).then(|| r.text.expose().to_owned())
}

/// A field resolved in full (MOD-08), for `logins.get` and the prompt rows.
fn resolved(e: &Entry, name: &str, ctx: &Context<'_>) -> String {
    let raw = e.value(name);
    if raw.contains('{') {
        refs::resolve(raw, e, ctx).text.expose().to_owned()
    } else {
        raw.to_owned()
    }
}

/// The live entry `id` of `v`.
fn live(v: &Vault, id: Uuid) -> Option<&Entry> {
    v.root.all_entries().find(|e| e.uuid == id)
}

fn has_code(e: &Entry) -> bool {
    app_core::totp::settings(e).is_some_and(|s| s.problem().is_none())
}

/// INT-02.20: an entry summary, never with a secret.
fn summary(vid: &str, e: &Entry, g: &Group, flags: Flags, ctx: &Context<'_>, access: State) -> Map {
    let mut m = Map::new();
    m.insert("vault".into(), vid.into());
    m.insert("id".into(), site::entry_id(e.uuid).into());
    let mut hidden = false;
    for (key, field) in [("title", "Title"), ("username", "UserName")] {
        let value = shown(e, field, ctx);
        hidden |= value.is_none();
        m.insert(key.into(), value.unwrap_or_default().into());
    }
    if hidden {
        m.insert("hidden_value".into(), true.into());
    }
    m.insert("group".into(), g.name.as_str().into());
    m.insert("code".into(), has_code(e).into());
    let passkey = e.fields().any(|(n, _)| n.starts_with(PASSKEY));
    m.insert("passkey".into(), passkey.into());
    m.insert("skip_submit".into(), flags.skip_submit.into());
    if is_expired(&e.times, Instant::from(ctx.now)) {
        m.insert("expired".into(), true.into());
    }
    let access = if access == State::Allowed {
        "allowed"
    } else {
        "ask"
    };
    m.insert("access".into(), access.into());
    m
}

/// A display context: protected values show as the mask and say so
/// (MOD-08.23), and `{TOTP}` gives nothing: a summary never carries a
/// code (R02-2).
fn display<'a>(
    v: &'a Vault,
    dir: &'a str,
    now: Time,
    meter: &'a Cell<usize>,
    index: &'a EntryIndex<'a>,
) -> Context<'a> {
    Context {
        display: true,
        index: Some(index),
        otp: no_code,
        ..refs::copy_context(v, dir, now, meter)
    }
}

fn no_code(_: &Entry, _: Time) -> Option<app_crypto::secret::SecretString> {
    None
}

/// The context `logins.get` and matching resolve in (MOD-08.25).
fn full<'a>(
    v: &'a Vault,
    dir: &'a str,
    now: Time,
    meter: &'a Cell<usize>,
    index: &'a EntryIndex<'a>,
) -> Context<'a> {
    Context {
        index: Some(index),
        ..refs::copy_context(v, dir, now, meter)
    }
}

/// One entry a `logins.get` or `code.get` names, with its state.
#[derive(Debug, Clone)]
struct Pick {
    /// Index into the request's [`Use`] list.
    at: usize,
    id: Uuid,
    state: State,
    /// Found through search or recent, not by the page (INT-02.22).
    outside: bool,
    flags: Flags,
}

/// INT-02.21: `ids`, 1 to 20 `{"vault","id"}` pairs, first ones first,
/// without repeats.
fn read_ids(r: &Map) -> Result<Vec<(String, Uuid)>, u8> {
    let list = r
        .get("ids")
        .and_then(Value::as_array)
        .filter(|l| !l.is_empty())
        .ok_or(code::BAD_ID)?;
    if list.len() > MAX_IDS {
        return Err(code::TOO_LARGE);
    }
    let mut out: Vec<(String, Uuid)> = Vec::with_capacity(list.len());
    for item in list {
        let item = item.as_object().ok_or(code::BAD_ID)?;
        let vault = text(item, "vault").ok_or(code::BAD_ID)?;
        let id = text(item, "id")
            .and_then(site::read_entry_id)
            .ok_or(code::BAD_ID)?;
        if !out.iter().any(|(v, i)| v == vault && *i == id) {
            out.push((vault.to_owned(), id));
        }
    }
    Ok(out)
}

/// The vault side (see the module docs).
pub struct VaultSide {
    vaults: Arc<dyn Vaults>,
    prompts: Arc<Prompts>,
    /// Browser, host and time of the last notifications (INT-02.31).
    notices: Mutex<Vec<(String, String, Time)>>,
}

impl std::fmt::Debug for VaultSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSide").finish_non_exhaustive()
    }
}

impl VaultSide {
    /// The vault side over `vaults`, its dialogs in `prompts`.
    #[must_use]
    pub fn new(vaults: Arc<dyn Vaults>, prompts: Arc<Prompts>) -> Self {
        Self {
            vaults,
            prompts,
            notices: Mutex::default(),
        }
    }

    fn unlocked(&self, id: u64) -> bool {
        self.vaults.list().iter().any(|v| v.id == id && v.unlocked)
    }

    /// INT-02.10: the usable vaults, in open order. Error 8 without a
    /// proven key or when no unlocked one stores it; error 1 when none the
    /// request may use is unlocked.
    fn usable(&self, r: &Request<'_>, o: &Options) -> Result<Vec<Use>, u8> {
        let key = r.identity.ok_or(code::NOT_PROVEN)?;
        let may: Vec<OpenVault> = self
            .vaults
            .list()
            .into_iter()
            .filter(|v| (o.search_all || v.shown) && v.unlocked)
            .collect();
        if may.is_empty() {
            return Err(code::LOCKED);
        }
        let mut out = Vec::new();
        for ov in may {
            self.vaults.with(ov.id, &mut |v, _| {
                let names = site::names(v, key);
                if !names.is_empty() {
                    out.push(Use {
                        id: ov.id,
                        vid: site::vault_id(v),
                        names,
                    });
                }
                Changed::Nothing
            });
        }
        if out.is_empty() {
            Err(code::NOT_PROVEN)
        } else {
            Ok(out)
        }
    }

    /// INT-01.30 `status`.
    fn status(&self, r: &Request<'_>) -> Map {
        let mut list = Vec::new();
        for ov in self.vaults.list() {
            let mut m = Map::new();
            m.insert("name".into(), ov.name.as_str().into());
            let state = if ov.unlocked { "unlocked" } else { "locked" };
            m.insert("state".into(), state.into());
            m.insert("shown".into(), ov.shown.into());
            if let (true, Some(key)) = (ov.unlocked, r.identity) {
                self.vaults.with(ov.id, &mut |v, _| {
                    if let Some(name) = site::names(v, key).into_iter().next() {
                        m.insert("id".into(), site::vault_id(v).into());
                        m.insert("connection".into(), name.into());
                    }
                    Changed::Nothing
                });
            }
            list.push(Value::Object(m));
        }
        let mut reply = Map::new();
        reply.insert("vaults".into(), Value::Array(list));
        reply
    }

    /// The name and vault id under which the shown vault `id` already
    /// stores `key` (INT-02.3).
    fn known(&self, id: u64, key: &[u8; 32]) -> Option<Map> {
        let mut out = None;
        self.vaults.with(id, &mut |v, _| {
            out = site::names(v, key).into_iter().next().map(|name| {
                let mut m = Map::new();
                m.insert("name".into(), name.into());
                m.insert("vault".into(), site::vault_id(v).into());
                m
            });
            Changed::Nothing
        });
        out
    }

    /// INT-02.3 to INT-02.6: `connect`.
    fn connect(&self, r: &Request<'_>) -> Result<Map, u8> {
        let key = r.identity.ok_or(code::NOT_PROVEN)?;
        let shown = self
            .vaults
            .list()
            .into_iter()
            .find(|v| v.shown && v.unlocked)
            .ok_or(code::LOCKED)?;
        if let Some(reply) = self.known(shown.id, key) {
            return Ok(reply);
        }
        let _wait = r.session.wait().ok_or(code::BUSY)?;
        let words = format!(
            "Check that the extension shows: {}",
            site::pairing_words(r.keys.0, r.keys.1, key)
        );
        let suggested = text(r.content, "name");
        let computer = self.vaults.computer();
        let mut make = || {
            let mut q = None;
            self.vaults.with(shown.id, &mut |v, _| {
                if site::names(v, key).is_empty() {
                    let taken = app_core::settings::associations(v);
                    let taken = |n: &str| taken.iter().any(|a| a.name == n);
                    let title = if v.meta.name.is_empty() {
                        shown.name.as_str()
                    } else {
                        v.meta.name.as_str()
                    };
                    q = Some(Question::Connect(Connect {
                        vault: shown.id,
                        text: format!(
                            "An App extension asks to connect to “{title}”. Name it so you know it later. Only allow it if you just installed the extension."
                        ),
                        name: default_name(suggested, r.browser, &computer, &taken),
                        words: words.clone(),
                    }));
                }
                Changed::Nothing
            });
            q
        };
        let outcome = self.prompts.ask(
            CONNECT_TIME,
            &|| r.session.ended(),
            &|| !self.unlocked(shown.id),
            &mut make,
        );
        match outcome {
            Outcome::Answered(Answer::Connect(name)) => {
                let name = site::valid_name(&name).ok_or(code::DENIED)?;
                let now = self.vaults.now();
                let value = base64::encode(Form::Padded, key);
                let mut made = false;
                self.vaults.with(shown.id, &mut |v, _| {
                    made =
                        app_core::settings::add_association(v, name, &value, &site::iso(now), now);
                    if made {
                        Changed::Data
                    } else {
                        Changed::Nothing
                    }
                });
                if made {
                    self.known(shown.id, key).ok_or(code::DENIED)
                } else {
                    Err(code::DENIED)
                }
            }
            // Connected meanwhile (INT-02.3), else locked.
            Outcome::NotNeeded => self.known(shown.id, key).ok_or(code::DENIED),
            Outcome::Busy => Err(code::BUSY),
            _ => Err(code::DENIED),
        }
    }

    /// INT-02.7: `check`.
    fn check(&self, r: &Request<'_>) -> Result<Map, u8> {
        let key = r.identity.ok_or(code::NOT_PROVEN)?;
        let mut list = Vec::new();
        for ov in self.vaults.list().into_iter().filter(|v| v.unlocked) {
            self.vaults.with(ov.id, &mut |v, _| {
                if let Some(name) = site::names(v, key).into_iter().next() {
                    let mut m = Map::new();
                    m.insert("id".into(), site::vault_id(v).into());
                    m.insert("name".into(), ov.name.as_str().into());
                    m.insert("connection".into(), name.into());
                    list.push(Value::Object(m));
                }
                Changed::Nothing
            });
        }
        if list.is_empty() {
            return Err(code::NOT_PROVEN);
        }
        let mut reply = Map::new();
        reply.insert("vaults".into(), Value::Array(list));
        Ok(reply)
    }

    /// INT-01.30 `disconnect`.
    fn disconnect(&self, r: &Request<'_>, o: &Options) -> Result<Map, u8> {
        self.usable(r, o)?;
        let key = r.identity.ok_or(code::NOT_PROVEN)?;
        let now = self.vaults.now();
        let mut unchanged = Vec::new();
        for ov in self.vaults.list() {
            if !ov.unlocked {
                unchanged.push(Value::from(ov.name));
                continue;
            }
            self.vaults.with(ov.id, &mut |v, _| {
                let names = site::names(v, key);
                let names: Vec<&str> = names.iter().map(String::as_str).collect();
                if app_core::settings::remove_associations(v, &names, now) > 0 {
                    Changed::Data
                } else {
                    Changed::Nothing
                }
            });
        }
        let mut reply = Map::new();
        reply.insert("unchanged".into(), Value::Array(unchanged));
        Ok(reply)
    }

    /// INT-02.11, the part without the unlock panel: the vault id at once
    /// when the shown vault is unlocked; error 1 otherwise.
    fn unlock(&self, r: &Request<'_>) -> Result<Map, u8> {
        let shown = self
            .vaults
            .list()
            .into_iter()
            .find(|v| v.shown && v.unlocked)
            .ok_or(code::LOCKED)?;
        let mut reply = Map::new();
        if let Some(key) = r.identity {
            self.vaults.with(shown.id, &mut |v, _| {
                if !site::names(v, key).is_empty() {
                    reply.insert("vault".into(), site::vault_id(v).into());
                }
                Changed::Nothing
            });
        }
        Ok(reply)
    }

    /// INT-02.13 to INT-02.20: `logins.find`.
    fn find(&self, r: &Request<'_>, o: &Options) -> Result<Map, u8> {
        let uses = self.usable(r, o)?;
        let t = Target::read(r.content, o, true)?;
        let now = self.vaults.now();
        let meter = Cell::new(COPY_BUDGET);
        let mut found: Vec<(u8, Map)> = Vec::new();
        for u in &uses {
            self.vaults.with(u.id, &mut |v, dir| {
                let index = EntryIndex::new(v);
                let ctx = full(v, dir, now, &meter, &index);
                let mut kept = Vec::new();
                for (e, g, flags) in visible(v, &u.names) {
                    if let Some((rank, state)) = fit(&t, e, flags, &ctx, o) {
                        kept.push((rank, (e, g, flags, access(state, &t, false, o))));
                    }
                }
                // Summaries only for what can be given: the order across
                // vaults keeps each vault's best.
                order(&mut kept, o.best_only);
                kept.truncate(MAX_FOUND);
                let shown = display(v, dir, now, &meter, &index);
                for (rank, (e, g, flags, state)) in kept {
                    found.push((rank, summary(&u.vid, e, g, flags, &shown, state)));
                }
                Changed::Nothing
            });
        }
        order(&mut found, o.best_only);
        found.truncate(MAX_FOUND);
        if found.is_empty() {
            return Err(code::NONE);
        }
        Ok(entries(found.into_iter().map(|f| f.1)))
    }

    /// The entries `ids` names that this page may see or that search and
    /// recent could give, with their states, in the order asked; `page`:
    /// only those INT-02.13 keeps for the page (`code.get`).
    fn picks(
        &self,
        uses: &[Use],
        ids: &[(String, Uuid)],
        t: &Target,
        o: &Options,
        page: bool,
    ) -> Vec<Pick> {
        let now = self.vaults.now();
        let meter = Cell::new(COPY_BUDGET);
        let mut out: Vec<(usize, Pick)> = Vec::new();
        for (at, u) in uses.iter().enumerate() {
            if !ids.iter().any(|(vid, _)| *vid == u.vid) {
                continue;
            }
            self.vaults.with(u.id, &mut |v, dir| {
                let index = EntryIndex::new(v);
                let ctx = full(v, dir, now, &meter, &index);
                for (e, _, flags) in visible(v, &u.names) {
                    let Some(asked) = ids
                        .iter()
                        .position(|(vid, id)| *vid == u.vid && *id == e.uuid)
                    else {
                        continue;
                    };
                    let (state, outside) = match fit(t, e, flags, &ctx, o) {
                        Some((_, state)) => (access(state, t, false, o), false),
                        None if page => continue,
                        None if !o.allow_expired && is_expired(&e.times, Instant::from(now)) => {
                            continue;
                        }
                        None => (
                            access(State::of(&Lists::of(e), &t.p, t.f.as_deref()), t, true, o),
                            true,
                        ),
                    };
                    if state != State::Denied {
                        out.push((
                            asked,
                            Pick {
                                at,
                                id: e.uuid,
                                state,
                                outside,
                                flags,
                            },
                        ));
                    }
                }
                Changed::Nothing
            });
        }
        out.sort_by_key(|p| p.0);
        out.into_iter().map(|p| p.1).collect()
    }

    /// The prompt rows of `asked` (INT-02.18): title and user name,
    /// resolved for display, plain text.
    fn rows(&self, uses: &[Use], asked: &[Pick]) -> Vec<Row> {
        let now = self.vaults.now();
        let meter = Cell::new(COPY_BUDGET);
        let mut rows: Vec<(usize, Row)> = Vec::new();
        for (at, u) in uses.iter().enumerate() {
            self.vaults.with(u.id, &mut |v, dir| {
                let index = EntryIndex::new(v);
                let ctx = display(v, dir, now, &meter, &index);
                for (i, p) in asked.iter().enumerate().filter(|(_, p)| p.at == at) {
                    if let Some(e) = live(v, p.id) {
                        let row = Row {
                            title: resolved(e, "Title", &ctx),
                            username: resolved(e, "UserName", &ctx),
                        };
                        rows.push((i, row));
                    }
                }
                Changed::Nothing
            });
        }
        rows.sort_by_key(|r| r.0);
        rows.into_iter().map(|r| r.1).collect()
    }

    /// INT-02.18: adds `hosts` to Allow (`allow`) or Deny of each entry.
    fn remember(&self, uses: &[Use], picks: &[(&Pick, Vec<String>, bool)]) {
        let now = self.vaults.now();
        for (at, u) in uses.iter().enumerate() {
            let mine: Vec<_> = picks.iter().filter(|p| p.0.at == at).collect();
            if mine.is_empty() {
                continue;
            }
            self.vaults.with(u.id, &mut |v, _| {
                let mut changed = Changed::Nothing;
                for (p, hosts, allow) in &mine {
                    let done = app_core::edit::change_entry(v, p.id, now, |e| {
                        let mut lists = Lists::of(e);
                        lists.add(hosts, *allow);
                        lists.write(e, now);
                    });
                    if done.is_ok_and(|d| d) {
                        changed = Changed::Data;
                    }
                }
                changed
            });
        }
    }

    /// The picks given after INT-02.18's prompt for those in state ask,
    /// and whether a dialog showed. Error 6 when the user denied, the time
    /// ran out or the vault locked; 42 when the line is full.
    fn decide(
        &self,
        r: &Request<'_>,
        uses: &[Use],
        ids: &[(String, Uuid)],
        t: &Target,
        o: &Options,
        page: bool,
    ) -> Result<(Vec<Pick>, bool), u8> {
        let picks = self.picks(uses, ids, t, o, page);
        if picks.is_empty() {
            return Err(if page { code::BAD_ID } else { code::NONE });
        }
        if picks.iter().all(|p| p.state == State::Allowed) {
            return Ok((picks, false));
        }
        let _wait = r.session.wait().ok_or(code::BUSY)?;
        let mut asked: Vec<Pick> = Vec::new();
        let mut ready: Vec<Pick> = Vec::new();
        let remember = (!t.http_auth && t.line.is_none()).then(|| format!("Remember for {}", t.p));
        let mut make = || {
            // Checked again at its turn: an earlier answer may have
            // remembered (INT-02 edge cases).
            let now: Vec<Pick> = self.picks(uses, ids, t, o, page);
            (asked, ready) = now.into_iter().partition(|p| p.state == State::Ask);
            let rows = self.rows(uses, &asked);
            let vault = asked.first().and_then(|p| uses.get(p.at)).map(|u| u.id)?;
            (rows.len() == asked.len()).then(|| {
                Question::Access(Access {
                    vault,
                    title: format!("{} asks for a sign-in on {}", r.browser, t.p),
                    text: format!("Choose the entries {} may use on this site.", r.browser),
                    rows,
                    remember: remember.clone(),
                    line: t.line.clone(),
                })
            })
        };
        let vaults: Vec<u64> = uses.iter().map(|u| u.id).collect();
        let outcome = self.prompts.ask(
            PROMPT_TIME,
            &|| r.session.ended(),
            &|| vaults.iter().any(|id| !self.unlocked(*id)),
            &mut make,
        );
        let hosts = |p: &Pick| {
            if p.outside {
                vec![t.p.clone()]
            } else {
                t.hosts()
            }
        };
        let may_remember = remember.is_some();
        match outcome {
            Outcome::NotNeeded if !ready.is_empty() => Ok((ready, false)),
            Outcome::Answered(Answer::Allow { checked, remember }) => {
                if remember && may_remember {
                    let marks: Vec<_> = asked
                        .iter()
                        .zip(checked.iter().chain(core::iter::repeat(&false)))
                        .map(|(p, c)| (p, hosts(p), *c))
                        .collect();
                    self.remember(uses, &marks);
                }
                let mut given = ready;
                given.extend(
                    asked
                        .into_iter()
                        .zip(checked.into_iter().chain(core::iter::repeat(false)))
                        .filter(|(_, c)| *c)
                        .map(|(p, _)| p),
                );
                if given.is_empty() {
                    return Err(code::DENIED);
                }
                Ok((given, true))
            }
            Outcome::Answered(Answer::Deny { remember: true }) if may_remember => {
                let marks: Vec<_> = asked.iter().map(|p| (p, hosts(p), false)).collect();
                self.remember(uses, &marks);
                Err(code::DENIED)
            }
            Outcome::Busy => Err(code::BUSY),
            _ => Err(code::DENIED),
        }
    }

    /// INT-02.31: MI02-13, at most once per browser and host in 10 minutes.
    fn notice(&self, browser: &str, host: &str) {
        let now = self.vaults.now();
        let mut seen = self.notices.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|n| now.0.saturating_sub(n.2.0) < NOTICE_GAP);
        if seen.iter().any(|n| n.0 == browser && n.1 == host) {
            return;
        }
        if seen.len() >= MAX_NOTICES {
            seen.remove(0);
        }
        seen.push((browser.to_owned(), host.to_owned(), now));
        drop(seen);
        self.vaults
            .notify(&format!("{browser} filled a sign-in on {host}."));
    }

    /// Runs `give` on each given entry in its vault and records its use
    /// (INT-02.9); the replies in the order of `given`.
    fn give(
        &self,
        uses: &[Use],
        given: &[Pick],
        give: &dyn Fn(&str, &Entry, &Pick, &Context<'_>) -> Option<Map>,
    ) -> Vec<Map> {
        let now = self.vaults.now();
        let meter = Cell::new(COPY_BUDGET);
        let mut out: Vec<(usize, Map)> = Vec::new();
        for (at, u) in uses.iter().enumerate() {
            if !given.iter().any(|p| p.at == at) {
                continue;
            }
            self.vaults.with(u.id, &mut |v, dir| {
                let mut used = Vec::new();
                {
                    let index = EntryIndex::new(v);
                    let ctx = full(v, dir, now, &meter, &index);
                    for (i, p) in given.iter().enumerate().filter(|(_, p)| p.at == at) {
                        if let Some(m) = live(v, p.id).and_then(|e| give(&u.vid, e, p, &ctx)) {
                            out.push((i, m));
                            used.push(p.id);
                        }
                    }
                }
                for id in &used {
                    site::record_use(v, *id, &u.names, now);
                }
                if used.is_empty() {
                    Changed::Nothing
                } else {
                    Changed::View
                }
            });
        }
        out.sort_by_key(|m| m.0);
        out.into_iter().map(|m| m.1).collect()
    }

    /// INT-02.21: `logins.get`.
    fn get(&self, r: &Request<'_>, o: &Options) -> Result<Map, u8> {
        let uses = self.usable(r, o)?;
        let ids = read_ids(r.content)?;
        let t = Target::read(r.content, o, true)?;
        let (given, asked) = self.decide(r, &uses, &ids, &t, o, false)?;
        let extra = o.extra_fields;
        let list = self.give(&uses, &given, &|vid, e, p, ctx| {
            let mut m = Map::new();
            m.insert("vault".into(), vid.into());
            m.insert("id".into(), site::entry_id(e.uuid).into());
            for (key, field) in [
                ("title", "Title"),
                ("username", "UserName"),
                ("password", "Password"),
            ] {
                m.insert(key.into(), resolved(e, field, ctx).into());
            }
            if let Some(code) = app_core::totp::code_for(e, ctx.now) {
                m.insert("code".into(), code.expose().into());
            }
            m.insert("skip_submit".into(), p.flags.skip_submit.into());
            if is_expired(&e.times, Instant::from(ctx.now)) {
                m.insert("expired".into(), true.into());
            }
            if extra {
                let mut fields: Vec<(&str, String)> = e
                    .fields()
                    .filter_map(|(n, _)| Some((n.strip_prefix(KPH)?, resolved(e, n, ctx))))
                    .collect();
                fields.sort_by(|a, b| a.0.cmp(b.0));
                let fields: Vec<Value> = fields
                    .into_iter()
                    .map(|(n, value)| {
                        let mut f = Map::new();
                        f.insert("name".into(), n.into());
                        f.insert("value".into(), value.into());
                        Value::Object(f)
                    })
                    .collect();
                m.insert("fields".into(), Value::Array(fields));
            }
            Some(m)
        });
        if list.is_empty() {
            return Err(code::DENIED);
        }
        if !asked && o.notify {
            self.notice(r.browser, &t.p);
        }
        Ok(entries(list.into_iter()))
    }

    /// INT-02.23: `code.get`.
    fn code(&self, r: &Request<'_>, o: &Options) -> Result<Map, u8> {
        let uses = self.usable(r, o)?;
        let vault = text(r.content, "vault").ok_or(code::BAD_ID)?;
        let id = text(r.content, "id")
            .and_then(site::read_entry_id)
            .ok_or(code::BAD_ID)?;
        let ids = [(vault.to_owned(), id)];
        let t = Target::read(r.content, o, false)?;
        // No valid one-time settings: error 15, before any prompt.
        let kept = self.picks(&uses, &ids, &t, o, true);
        let first = kept.first().ok_or(code::BAD_ID)?;
        let mut valid = false;
        if let Some(u) = uses.get(first.at) {
            self.vaults.with(u.id, &mut |v, _| {
                valid = live(v, id).is_some_and(has_code);
                Changed::Nothing
            });
        }
        if !valid {
            return Err(code::NONE);
        }
        let (given, asked) = self.decide(r, &uses, &ids, &t, o, true)?;
        let list = self.give(&uses, &given, &|_, e, _, ctx| {
            let s = app_core::totp::settings(e)?;
            let mut m = Map::new();
            m.insert("code".into(), s.code(ctx.now)?.expose().into());
            m.insert("period".into(), s.period.into());
            m.insert("remaining".into(), s.seconds_left(ctx.now)?.into());
            Some(m)
        });
        let reply = list.into_iter().next().ok_or(code::NONE)?;
        if !asked && o.notify {
            self.notice(r.browser, &t.p);
        }
        Ok(reply)
    }

    /// INT-02.22 (R02-1): `logins.search`, one plain term without letter
    /// case in the title, the user name and the main URL's host.
    fn search(&self, r: &Request<'_>, o: &Options) -> Result<Map, u8> {
        let uses = self.usable(r, o)?;
        let term = text(r.content, "text")
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        let t = Target::read(r.content, o, true).ok();
        let now = self.vaults.now();
        let meter = Cell::new(COPY_BUDGET);
        let mut found: Vec<Map> = Vec::new();
        for u in &uses {
            if term.is_empty() || found.len() >= MAX_SEARCH {
                break;
            }
            self.vaults.with(u.id, &mut |v, dir| {
                let index = EntryIndex::new(v);
                let ctx = full(v, dir, now, &meter, &index);
                let shown = display(v, dir, now, &meter, &index);
                for (e, g, flags) in visible(v, &u.names) {
                    if found.len() >= MAX_SEARCH {
                        break;
                    }
                    if (!o.allow_expired && is_expired(&e.times, Instant::from(now)))
                        || !matches(e, &term)
                    {
                        continue;
                    }
                    let state = t
                        .as_ref()
                        .and_then(|t| {
                            fit(t, e, flags, &ctx, o).map(|(_, s)| access(s, t, false, o))
                        })
                        .unwrap_or(State::Ask);
                    found.push(summary(&u.vid, e, g, flags, &shown, state));
                }
                Changed::Nothing
            });
        }
        Ok(entries(found.into_iter()))
    }

    /// INT-02.9: `logins.recent`.
    fn recent(&self, r: &Request<'_>, o: &Options) -> Result<Map, u8> {
        let uses = self.usable(r, o)?;
        let now = self.vaults.now();
        let meter = Cell::new(COPY_BUDGET);
        let mut found: Vec<(String, Map)> = Vec::new();
        for u in &uses {
            self.vaults.with(u.id, &mut |v, dir| {
                let index = EntryIndex::new(v);
                let shown = display(v, dir, now, &meter, &index);
                for (e, g, flags) in visible(v, &u.names) {
                    if !o.allow_expired && is_expired(&e.times, Instant::from(now)) {
                        continue;
                    }
                    if let Some(at) = site::last_use(e, &u.names) {
                        found.push((at, summary(&u.vid, e, g, flags, &shown, State::Ask)));
                    }
                }
                Changed::Nothing
            });
        }
        found.sort_by(|a, b| b.0.cmp(&a.0));
        found.truncate(MAX_RECENT);
        Ok(entries(found.into_iter().map(|f| f.1)))
    }
}

/// R02-1: `term` (lower case, not empty) is part of the title, the user
/// name or the main URL's host. Protected fields and values holding a
/// placeholder are never searched.
fn matches(e: &Entry, term: &str) -> bool {
    let plain = |name: &str| {
        e.field(name)
            .filter(|f| !f.protected && !f.value.expose().contains('{'))
            .map(|f| f.value.expose())
    };
    let host = plain("URL").and_then(|u| url_host(u).or_else(|| url_host(&format!("https://{u}"))));
    ["Title", "UserName"]
        .into_iter()
        .filter_map(plain)
        .any(|t| t.to_lowercase().contains(term))
        || host.is_some_and(|h| h.contains(term))
}

/// INT-02.4: the request's name when valid and free, else "‹browser› on
/// ‹computer›", else "‹browser› 2", "‹browser› 3" … the first free one.
fn default_name(
    suggested: Option<&str>,
    browser: &str,
    computer: &str,
    taken: &dyn Fn(&str) -> bool,
) -> String {
    let free = |n: &str| site::valid_name(n).filter(|n| !taken(n)).map(str::to_owned);
    suggested
        .and_then(free)
        .or_else(|| free(&format!("{browser} on {computer}")))
        .or_else(|| (2..=1_000u32).find_map(|i| free(&format!("{browser} {i}"))))
        .unwrap_or_default()
}

fn entries(list: impl Iterator<Item = Map>) -> Map {
    let mut reply = Map::new();
    reply.insert(
        "entries".into(),
        Value::Array(list.map(Value::Object).collect()),
    );
    reply
}

impl SharedHandler for VaultSide {
    fn handle(&self, r: &Request<'_>) -> Result<Map, u8> {
        let o = self.vaults.options();
        match r.kind {
            "status" => Ok(self.status(r)),
            "connect" => self.connect(r),
            "check" => self.check(r),
            "unlock" => self.unlock(r),
            "disconnect" => self.disconnect(r, &o),
            "logins.find" => self.find(r, &o),
            "logins.get" => self.get(r, &o),
            "code.get" => self.code(r, &o),
            "logins.search" => self.search(r, &o),
            "logins.recent" => self.recent(r, &o),
            // Later stories (E7-S4, E7-S5, INT-01.34 to INT-01.36): the
            // association check first, then "unknown".
            _ => {
                self.usable(r, &o)?;
                Err(code::UNKNOWN)
            }
        }
    }
}
