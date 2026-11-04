//! URL matching (INT-03, E7-S3): which entries fit a page and in which
//! order they are offered. No I/O and no network: the Public Suffix List is
//! compiled in (`psl`, INT-03.19).
//!
//! - [`Page::read`] reads the page URL and the form URL (INT-03.1).
//! - [`Page::rank`] says whether an entry fits the page and its rank
//!   (INT-03.2 to INT-03.14). The caller walks the vault (INT-02.13) and
//!   gives each entry's group option and site access lists.
//! - [`order`] puts the ranked entries in offer order (INT-03.15, INT-03.16).
//! - [`note`] is the editor's note under a website row (INT-03.18).
//!
//! Guarantees (INT-03 "What must never happen"):
//! - An entry never fits a page outside its registrable domain: a name
//!   host fits only itself and the hosts below it by whole labels, inside
//!   one registrable domain; a public suffix fits nothing; IP addresses and
//!   one-label hosts fit only themselves; a pattern's fixed tail must hold a
//!   registrable domain, is matched anchored, label by label, and fits only
//!   pages in that registrable domain.
//! - Paths never decide whether a plain entry URL fits; ports and (with
//!   S-BRW-11 on) schemes always do.
//! - Hosts are compared in one ASCII form (INT-03.4); no Unicode mapping
//!   beyond MOD-08.9's lower case and Punycode, so a lookalike never fits.
//! - Bounded on any vault (INT-03.17): at most 64 URLs per entry, 2,048
//!   characters per URL, 16 `*` per pattern, 10 labels in a host pattern
//!   holding `*`; patterns are matched with linear substring search, never
//!   a regular expression or backtracking.
//!   Placeholder resolution is paid from the caller's `Context` meter.
//! - A resolved URL can hold a protected value, so it stays in its
//!   `SecretString`; the only copies made from it are its host and the
//!   percent-encoded path, which is a `SecretString` too.

use crate::MAX_URL;
use crate::psl::domain_of;
use app_core::edit::holds_reference;
use app_core::refs::{self, Context};
use app_crypto::secret::SecretString;
use app_model::Entry;
use core::cmp::Ordering;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The longest entry URL, after resolving, that may fit (INT-03.17).
pub const MAX_ENTRY_URL: usize = 2_048;
/// URLs looked at per entry, in INT-03.2's order (INT-03.17).
pub const MAX_URLS: usize = 64;
/// The most `*` in one pattern (INT-03.17).
pub const MAX_STARS: usize = 16;
/// The most labels in a host pattern that holds `*` (INT-03.11 step 1,
/// INT-03.17, F-245).
pub const MAX_PATTERN_LABELS: usize = 10;
/// The error a page App cannot match gets (INT-03.1, INT-01.40).
pub const NOT_A_PAGE: u8 = 14;

/// The main URL field.
const MAIN: &str = "URL";
/// The prefix of additional URL fields (MOD-01.8).
const EXTRA: &str = "KP2A_URL";
/// The passkey relying party field (INT-04.8).
const PASSKEY_RP: &str = "KPEX_PASSKEY_RELYING_PARTY";

/// A host in App's one form (INT-03.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Host {
    /// A name: ASCII, lower case, Punycode labels, no final dot.
    Name(String),
    /// Four decimal numbers.
    V4(Ipv4Addr),
    /// Compared as its 16 bytes.
    V6(Ipv6Addr),
}

impl Host {
    /// The host as text: the name, the four numbers, or `[…]` (INT-02.16,
    /// INT-02.18: P in ASCII form).
    pub(crate) fn text(&self) -> String {
        match self {
            Self::Name(n) => n.clone(),
            Self::V4(a) => a.to_string(),
            Self::V6(a) => format!("[{a}]"),
        }
    }
}

/// `host` in App's form (INT-03.4), `None` when it is not a valid host:
/// one final `.` removed; `[…]` must be IPv6; when the last label is all
/// digits, four decimal numbers 0 to 255 without leading zeros; otherwise
/// labels of letters, digits, `-` and `_` (non-ASCII letters encoded as
/// MOD-08.9 does), no empty label, the DNS limits after encoding.
pub(crate) fn host_form(host: &str) -> Option<Host> {
    if let Some(inner) = host.strip_prefix('[') {
        return inner.strip_suffix(']')?.parse().ok().map(Host::V6);
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    let last = name.rsplit('.').next().unwrap_or("");
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        // std reads only the four-number form and refuses leading zeros.
        return name.parse().ok().map(Host::V4);
    }
    name_form(name).map(Host::Name)
}

/// A name's form (INT-03.4) without the IP address rules.
fn name_form(name: &str) -> Option<String> {
    let ok = |c: char| {
        if c.is_ascii() {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
        } else {
            // No Unicode mapping (D-INT03-5): white space and controls are
            // refused, not trimmed.
            !c.is_whitespace() && !c.is_control()
        }
    };
    if name.is_empty() || name.split('.').any(str::is_empty) || !name.chars().all(ok) {
        return None;
    }
    if name.is_ascii() {
        // LD-112's limits; lower case is all MOD-08.9 does to ASCII.
        return (name.len() <= 253 && name.split('.').all(|l| l.len() <= 63))
            .then(|| name.to_ascii_lowercase());
    }
    // MOD-08.9's encoding and LD-112's limits (LD-58: one host form in App).
    app_core::url::site_host(name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// The raw parts of `scheme://authority/path?query#fragment`, the
/// fragment and the user info dropped.
struct Raw<'a> {
    scheme: &'a str,
    /// Host and port, as written.
    hostport: &'a str,
    host: &'a str,
    port: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
}

/// `url` without its fragment (INT-03.1: ignored everywhere).
fn no_fragment(url: &str) -> &str {
    url.split('#').next().unwrap_or(url)
}

fn split(url: &str) -> Option<Raw<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    parts(scheme, rest)
}

/// An entry URL's parts (INT-03.3): a value without `://` is read as if
/// `https://` stood in front, unless it names another scheme (`None`).
fn split_entry(v: &str) -> Option<Raw<'_>> {
    if v.contains("://") {
        split(v)
    } else if other_scheme(v) {
        None
    } else {
        parts("https", v)
    }
}

fn parts<'a>(scheme: &'a str, rest: &'a str) -> Option<Raw<'a>> {
    // The authority ends where WHATWG's does for http and https.
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at_checked(end)?;
    let tail = tail.split_once('#').map_or(tail, |(t, _)| t);
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = if hostport.starts_with('[') {
        let close = hostport.find(']')?.checked_add(1)?;
        let (h, after) = hostport.split_at_checked(close)?;
        if after.is_empty() {
            (h, None)
        } else {
            (h, Some(after.strip_prefix(':')?))
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    Some(Raw {
        scheme,
        hostport,
        host,
        port,
        path,
        query,
    })
}

/// A valid scheme: a letter, then letters, digits, `+`, `-` or `.`.
fn valid_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// `http` or `https`, in any letter case.
fn web_scheme(s: &str) -> Option<Scheme> {
    if s.eq_ignore_ascii_case("http") {
        Some(Scheme::Http)
    } else if s.eq_ignore_ascii_case("https") {
        Some(Scheme::Https)
    } else {
        None
    }
}

/// A written port: `None` when absent or empty, else decimal digits.
fn port_of(port: Option<&str>) -> Option<Option<u16>> {
    match port {
        None | Some("") => Some(None),
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok().map(Some),
        Some(_) => None,
    }
}

/// An http or https page or form URL.
struct Web {
    scheme: Scheme,
    host: Host,
    /// The effective port (INT-03.1).
    port: u16,
    /// The path, `/` when empty, `%` escapes in upper case.
    path: String,
    query: Option<String>,
}

fn read_web(url: &str) -> Option<Web> {
    let raw = split(url)?;
    let scheme = web_scheme(raw.scheme)?;
    let host = host_form(raw.host)?;
    Some(Web {
        scheme,
        host,
        port: port_of(raw.port)?.unwrap_or(scheme.port()),
        path: encode_path(raw.path).expose().to_owned(),
        query: raw.query.map(str::to_owned),
    })
}

/// The path as WHATWG's path percent-encode set writes it (INT-03.11 step
/// 4): controls, space, `"`, `#`, `<`, `>`, `?`, `` ` ``, `{`, `}` and every
/// byte past `~` become `%` escapes; the hex digits of every escape are in
/// upper case, so escapes compare without letter case; `*` stays. An empty
/// path is `/`.
fn encode_path(path: &str) -> SecretString {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(path.len().saturating_mul(3).saturating_add(1));
    if path.is_empty() {
        out.push('/');
    }
    let b = path.as_bytes();
    let hex_at = |i: usize| b.get(i).is_some_and(u8::is_ascii_hexdigit);
    // The hex digits still to come of the escape being copied.
    let mut digits = 0u8;
    for (i, &c) in b.iter().enumerate() {
        if c == b'%' && hex_at(i.saturating_add(1)) && hex_at(i.saturating_add(2)) {
            out.push('%');
            digits = 2;
        } else if c <= b' ' || c >= 0x7f || b"\"#<>?`{}".contains(&c) {
            out.push('%');
            out.push(char::from(*HEX.get(usize::from(c >> 4)).unwrap_or(&b'0')));
            out.push(char::from(*HEX.get(usize::from(c & 15)).unwrap_or(&b'0')));
        } else if digits > 0 {
            out.push(char::from(c.to_ascii_uppercase()));
            digits = digits.saturating_sub(1);
        } else {
            out.push(char::from(c));
        }
    }
    SecretString::new(out)
}

/// Characters that make an entry URL never fit (INT-03.3): white space
/// inside, controls, and `<`, `>`, `^`, `` ` ``, `{`, `|`, `}`.
fn forbidden(c: char) -> bool {
    c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '^' | '`' | '{' | '|' | '}')
}

/// A value without `://` that names another scheme (INT-03.3): letters,
/// digits, `+`, `-` or `.` up to a `:` that no digit follows.
fn other_scheme(v: &str) -> bool {
    v.split_once(':').is_some_and(|(s, after)| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            && !after.starts_with(|c: char| c.is_ascii_digit())
    })
}

/// The page, read once per request (INT-03.1), with its registrable
/// domain computed once (INT-03.17).
pub struct Page {
    /// `url` without its fragment and user info: what a quoted exact URL
    /// (INT-03.11) or a file page's entry URL (INT-03.13) must equal.
    text: String,
    /// `None` for a file page.
    web: Option<Web>,
    /// The form URL, when it is an http or https URL App can read.
    form: Option<Web>,
    /// S-BRW-11 match scheme.
    match_scheme: bool,
    /// The registrable domain of the page host (INT-03.10).
    domain: Option<String>,
}

/// What a caller knows of one entry besides its fields.
pub struct Site<'a> {
    /// `BrowserOmitWww` as the entry's group resolves it (MOD-02.17,
    /// INT-03.9).
    pub omit_www: bool,
    /// The site access item's `Allow` hosts (INT-02.16, INT-03.12).
    pub allow: &'a [String],
    /// The site access item's `Deny` hosts (INT-02.17).
    pub deny: &'a [String],
}

impl Site<'_> {
    /// No group option and no site access item.
    pub const NONE: Site<'static> = Site {
        omit_www: false,
        allow: &[],
        deny: &[],
    };
}

/// Which kind of URL field a value came from (INT-03.2).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Main,
    /// An additional URL or the passkey relying party field (INT-04.8).
    Extra,
}

/// A plain (no `*`) http or https entry URL, as fitted (INT-03.9). It
/// borrows the resolved value, so it makes no copy of it.
struct Plain<'a> {
    scheme: Scheme,
    host: Host,
    /// The written port.
    port: Option<u16>,
    path: &'a str,
    query: Option<&'a str>,
}

impl Page {
    /// Reads the page URL `url` and the form URL `form_url` (INT-03.1)
    /// with S-BRW-11 `match_scheme`. Only `http`, `https` (with a valid
    /// host) and `file` pages take part.
    ///
    /// # Errors
    /// [`NOT_A_PAGE`] (14) for any other scheme, a URL without a valid
    /// host or longer than INT-01.25's limit, or text App cannot read. A
    /// form URL App cannot read is left out (it only ranks).
    pub fn read(url: &str, form_url: Option<&str>, match_scheme: bool) -> Result<Page, u8> {
        if url.len() > MAX_URL {
            return Err(NOT_A_PAGE);
        }
        let raw = split(url).ok_or(NOT_A_PAGE)?;
        let form = form_url.filter(|f| f.len() <= MAX_URL).and_then(read_web);
        let mut page = Page {
            text: String::new(),
            web: None,
            form,
            match_scheme,
            domain: None,
        };
        if raw.scheme.eq_ignore_ascii_case("file") {
            page.text = no_fragment(url).to_owned();
            return Ok(page);
        }
        let web = read_web(url).ok_or(NOT_A_PAGE)?;
        page.text = format!(
            "{}://{}{}{}{}",
            raw.scheme,
            raw.hostport,
            raw.path,
            if raw.query.is_some() { "?" } else { "" },
            raw.query.unwrap_or("")
        );
        if let Host::Name(n) = &web.host {
            page.domain = domain_of(n).map(str::to_owned);
        }
        page.web = Some(web);
        Ok(page)
    }

    /// The page host P in ASCII form (INT-02.17); `None` for a file page.
    #[must_use]
    pub fn host(&self) -> Option<String> {
        self.web.as_ref().map(|w| w.host.text())
    }

    /// The form host F in ASCII form, when the form URL could be read
    /// (INT-02.17).
    #[must_use]
    pub fn form_host(&self) -> Option<String> {
        self.form.as_ref().map(|w| w.host.text())
    }

    /// Whether `entry` fits this page and, when it does, its rank from 0 to
    /// 100 (INT-03.14): the highest rate of its URLs that fit (INT-03.2 to
    /// INT-03.13). URLs resolve in `ctx` (MOD-08): the main URL only when it
    /// holds a reference, the others always. `site` gives the entry's group
    /// option and site access lists. `None`: it does not fit, also when the
    /// page host is in `site.deny` (INT-03.12).
    #[must_use]
    pub fn rank(&self, entry: &Entry, ctx: &Context<'_>, site: &Site<'_>) -> Option<u8> {
        if let Some(web) = &self.web
            && site
                .deny
                .iter()
                .any(|d| host_form(d).as_ref() == Some(&web.host))
        {
            return None;
        }
        let mut best = self.allowed(site);
        for (kind, raw) in urls(entry) {
            let resolve = kind == Kind::Extra || holds_reference(raw);
            let rate = if resolve && raw.contains('{') {
                self.rate(kind, refs::resolve(raw, entry, ctx).text.expose(), site)
            } else {
                self.rate(kind, raw, site)
            };
            best = best.max(rate);
        }
        best
    }

    /// INT-03.12: an allowed host fits a page with that very host, on the
    /// default port of its scheme, `https` (S-BRW-11 on) or `http` too
    /// (off); rate 80.
    fn allowed(&self, site: &Site<'_>) -> Option<u8> {
        let web = self.web.as_ref()?;
        (web.port == web.scheme.port()
            && (web.scheme == Scheme::Https || !self.match_scheme)
            && site
                .allow
                .iter()
                .any(|a| host_form(a).as_ref() == Some(&web.host)))
        .then_some(80)
    }

    /// The rate of one entry URL, `None` when it does not fit.
    fn rate(&self, kind: Kind, value: &str, site: &Site<'_>) -> Option<u8> {
        if value.chars().nth(MAX_ENTRY_URL).is_some() {
            return None;
        }
        let v = value.trim_matches([' ', '\t']);
        // INT-03.3, for every value: file URLs and quoted exact URLs too.
        if v.chars().any(forbidden) {
            return None;
        }
        // INT-03.3: a main URL holding * never fits, on a file page too.
        if kind == Kind::Main && v.contains('*') {
            return None;
        }
        let Some(web) = &self.web else {
            // INT-03.13: a file page fits only its exact URL.
            return (no_fragment(v) == self.text).then_some(100);
        };
        if kind == Kind::Extra
            && let Some(inner) = v.strip_prefix('"').and_then(|r| r.strip_suffix('"'))
        {
            // INT-03.11: a quoted exact URL.
            return (!inner.is_empty() && !inner.contains('*') && no_fragment(inner) == self.text)
                .then_some(100);
        }
        if v.contains('*') {
            // In the main URL `*` has no meaning, so it never fits.
            return match kind {
                Kind::Extra => self.rate_pattern(web, v),
                Kind::Main => None,
            };
        }
        let e = plain(v, site.omit_www)?;
        self.fits(web, &e).then(|| self.rate_plain(web, &e))
    }

    /// INT-03.5 to INT-03.7.
    fn fits(&self, p: &Web, e: &Plain<'_>) -> bool {
        (e.scheme == p.scheme || !self.match_scheme)
            && e.port.unwrap_or(p.scheme.port()) == p.port
            && match (&e.host, &p.host) {
                (Host::Name(h), Host::Name(ph)) if h.contains('.') => {
                    (ph == h || below(ph, h))
                        && self
                            .domain
                            .as_deref()
                            .is_some_and(|d| domain_of(h) == Some(d))
                }
                (h, ph) => h == ph,
            }
    }

    /// INT-03.14's table for a plain URL that fits.
    fn rate_plain(&self, p: &Web, e: &Plain<'_>) -> u8 {
        if e.scheme != p.scheme {
            return 0;
        }
        let port = e.port.unwrap_or(e.scheme.port());
        let encoded = encode_path(e.path);
        let path = encoded.expose();
        let pages = || core::iter::once(p).chain(self.form.as_ref());
        let origin = |u: &Web| u.scheme == e.scheme && u.host == e.host && u.port == port;
        let query = |u: &Web| u.query.as_deref() == e.query;
        let host_below = |u: &Web| match (&u.host, &e.host) {
            (Host::Name(uh), Host::Name(eh)) => below(uh, eh),
            _ => false,
        };
        if pages().any(|u| origin(u) && u.path == path && query(u)) {
            100
        } else if pages().any(|u| origin(u) && u.path == path) {
            90
        } else if pages().any(|u| origin(u) && parent_folder(path, &u.path)) {
            85
        } else if p.host == e.host {
            80
        } else if self.form.as_ref().is_some_and(|f| f.host == e.host) {
            70
        } else if host_below(p) {
            60
        } else if self.form.as_ref().is_some_and(host_below) {
            50
        } else {
            0
        }
    }

    /// INT-03.11 patterns: rate 40 when it fits (0 when its scheme differs,
    /// S-BRW-11 off), `None` when it does not fit or is refused. A name
    /// pattern fits only a page in its tail's registrable domain (INT-03.7):
    /// the tail rule alone lets `*.srcf.net` reach `a.user.srcf.net`, below
    /// the private suffix `user.srcf.net` (F-230).
    fn rate_pattern(&self, p: &Web, v: &str) -> Option<u8> {
        let pattern = Pattern::read(v)?;
        ((pattern.scheme == p.scheme || !self.match_scheme)
            && pattern.port.unwrap_or(p.scheme.port()) == p.port
            && pattern.host.fits(&p.host)
            && match &pattern.host {
                PatternHost::Name(_, d) => self.domain.as_deref() == Some(d.as_str()),
                _ => true,
            }
            && pattern.path_fits(&p.path))
        .then_some(if pattern.scheme == p.scheme { 40 } else { 0 })
    }
}

/// The host of an http or https URL in ASCII form (INT-03.4), `None` when
/// App cannot read it (INT-02.19's `top_url`).
#[must_use]
pub(crate) fn url_host(url: &str) -> Option<String> {
    (url.len() <= MAX_URL)
        .then(|| read_web(url))
        .flatten()
        .map(|w| w.host.text())
}

/// `host` is below `parent` by whole labels.
fn below(host: &str, parent: &str) -> bool {
    host.strip_suffix(parent)
        .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.'))
}

/// INT-03.14's parent folder: the page path is longer and starts with the
/// entry path, which ends with `/` or is followed by `/`.
fn parent_folder(entry: &str, page: &str) -> bool {
    page.len() > entry.len()
        && page
            .strip_prefix(entry)
            .is_some_and(|rest| entry.ends_with('/') || rest.starts_with('/'))
}

/// A plain entry URL (INT-03.3) as fitted (INT-03.9).
fn plain(v: &str, omit_www: bool) -> Option<Plain<'_>> {
    let raw = split_entry(v)?;
    let scheme = web_scheme(raw.scheme)?;
    let mut host = host_form(raw.host)?;
    if omit_www
        && let Host::Name(n) = &host
        && let Some(rest) = n.strip_prefix("www.")
        && domain_of(rest).is_some()
    {
        host = Host::Name(rest.to_owned());
    }
    Some(Plain {
        scheme,
        host,
        port: port_of(raw.port)?,
        path: raw.path,
        query: raw.query,
    })
}

/// One host label of a name pattern.
enum Label {
    /// `*` alone: one or more whole labels.
    Any,
    /// A label with `*` among other characters: one label, each `*` any
    /// run of characters (lower case ASCII).
    Glob(String),
    /// A fixed label in host form.
    Fixed(String),
}

impl Label {
    fn fits(&self, label: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Glob(g) => glob(g, label),
            Self::Fixed(f) => f == label,
        }
    }
}

enum PatternHost {
    /// A host without `*`: compared whole.
    Fixed(Host),
    /// Name labels, left to right, and the fixed tail's registrable domain.
    Name(Vec<Label>, String),
    /// IPv4 parts, left to right (`Label::Any` or `Label::Fixed`).
    V4(Vec<Label>),
}

impl PatternHost {
    fn fits(&self, host: &Host) -> bool {
        match (self, host) {
            (Self::Fixed(h), host) => h == host,
            (Self::Name(labels, _), Host::Name(n)) => {
                let page: Vec<&str> = n.split('.').collect();
                labels_fit(labels, &page)
            }
            (Self::V4(parts), Host::V4(a)) => {
                let octets = a.octets().map(|o| o.to_string());
                let page: Vec<&str> = octets.iter().map(String::as_str).collect();
                labels_fit(parts, &page)
            }
            _ => false,
        }
    }
}

/// An additional URL holding `*` (INT-03.11).
struct Pattern<'a> {
    scheme: Scheme,
    port: Option<u16>,
    host: PatternHost,
    /// As written, encoded only in [`Pattern::path_fits`] (F-252); `None`
    /// fits every path.
    path: Option<&'a str>,
}

impl<'a> Pattern<'a> {
    /// The pattern of `v` (trimmed, no forbidden character), `None` when it
    /// never fits (step 1, MI03-01) or has no valid host or scheme.
    fn read(v: &'a str) -> Option<Pattern<'a>> {
        let stars = v.matches('*').count();
        if stars > MAX_STARS || v.chars().all(|c| c == '*') || v.contains("**") || v.contains("*.*")
        {
            return None;
        }
        let raw = split_entry(v)?;
        if raw.scheme.contains('*') || raw.port.is_some_and(|p| p.contains('*')) {
            return None;
        }
        let scheme = web_scheme(raw.scheme)?;
        let port = port_of(raw.port)?;
        let host = if raw.host.contains('*') {
            if raw.host.starts_with('[') {
                return None;
            }
            pattern_host(raw.host)?
        } else {
            let fixed = host_form(raw.host)?;
            // A public suffix fits nothing (INT-03.7), in a pattern too.
            if let Host::Name(n) = &fixed
                && n.contains('.')
                && domain_of(n).is_none()
            {
                return None;
            }
            PatternHost::Fixed(fixed)
        };
        let path = (!matches!(raw.path, "" | "/")).then_some(raw.path);
        Some(Pattern {
            scheme,
            port,
            host,
            path,
        })
    }

    /// Step 4: the whole page path, `*` any run, `/` included. Called after
    /// scheme, port and host fit, so other patterns encode nothing (F-252).
    fn path_fits(&self, page: &str) -> bool {
        self.path
            .is_none_or(|p| glob(encode_path(p).expose(), page))
    }
}

/// Step 1 and step 3's host of a pattern holding `*`.
fn pattern_host(host: &str) -> Option<PatternHost> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let labels: Vec<&str> = host.split('.').collect();
    // More labels never fit (INT-03.11 step 1, F-245): each run between
    // two `*` is tried at every place of the page host.
    if labels.len() > MAX_PATTERN_LABELS {
        return None;
    }
    let part = |l: &&str| *l == "*" || l.parse::<u8>().is_ok_and(|n| n.to_string() == *l);
    if (2..=4).contains(&labels.len())
        && labels.iter().all(part)
        && labels.first().is_some_and(|l| *l != "*")
    {
        let parts = labels
            .iter()
            .map(|l| {
                if *l == "*" {
                    Label::Any
                } else {
                    Label::Fixed((*l).to_owned())
                }
            })
            .collect();
        return Some(PatternHost::V4(parts));
    }
    // The fixed tail: the labels right of the last label holding `*`; it
    // must be a name whose registrable domain exists (and so ends it).
    let last = labels.iter().rposition(|l| l.contains('*'))?;
    let tail = labels.get(last.checked_add(1)?..)?.join(".");
    let domain = match host_form(&tail)? {
        Host::Name(t) => domain_of(&t)?.to_owned(),
        _ => return None,
    };
    let mut out = Vec::with_capacity(labels.len());
    for l in labels {
        out.push(if l == "*" {
            Label::Any
        } else if l.contains('*') {
            let glob_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '*');
            if !l.chars().all(glob_char) {
                return None;
            }
            Label::Glob(l.to_ascii_lowercase())
        } else {
            Label::Fixed(name_form(l)?)
        });
    }
    Some(PatternHost::Name(out, domain))
}

/// The labels `page` fit `pattern` whole, where each [`Label::Any`]
/// stands for one or more labels: the parts between them are placed
/// leftmost, which is exact for this kind of pattern.
fn labels_fit(pattern: &[Label], page: &[&str]) -> bool {
    let run_fits = |run: &[Label], at: &[&str]| {
        run.len() == at.len() && run.iter().zip(at).all(|(l, p)| l.fits(p))
    };
    let mut runs = pattern.split(|l| matches!(l, Label::Any));
    let first = runs.next().unwrap_or_default();
    let Some(mut rest) = page.get(first.len()..) else {
        return false;
    };
    if !run_fits(first, page.get(..first.len()).unwrap_or_default()) {
        return false;
    }
    let runs: Vec<&[Label]> = runs.collect();
    let Some((last, middle)) = runs.split_last() else {
        return rest.is_empty();
    };
    for run in middle {
        // One label at least for the `*` before it.
        let found = (1..=rest.len().saturating_sub(run.len())).find(|&at| {
            rest.get(at..at.saturating_add(run.len()))
                .is_some_and(|w| run_fits(run, w))
        });
        let Some(at) = found else {
            return false;
        };
        rest = rest.get(at.saturating_add(run.len())..).unwrap_or_default();
    }
    rest.len() > last.len()
        && rest
            .get(rest.len().saturating_sub(last.len())..)
            .is_some_and(|w| run_fits(last, w))
}

/// `text` fits `pattern` whole, where `*` stands for any run of characters.
/// Each part between `*`s is found leftmost with the standard library's
/// linear substring search, so the work is linear in the two lengths.
fn glob(pattern: &str, text: &str) -> bool {
    // No `Vec` per call: a `*` label run calls this once per label (F-252).
    let Some((head, last)) = pattern.rsplit_once('*') else {
        return pattern == text;
    };
    let mut parts = head.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    for part in parts {
        let Some(at) = rest.find(part) else {
            return false;
        };
        rest = rest.get(at.saturating_add(part.len())..).unwrap_or("");
    }
    rest.ends_with(last)
}

/// The order of additional URL field names (INT-03.2): `KP2A_URL`, then
/// `KP2A_URL_` and a number by that number, then the others by name.
#[must_use]
pub fn extra_url_order(a: &str, b: &str) -> Ordering {
    let key = |n: &str| match n.strip_prefix(EXTRA) {
        Some("") => (0, 0),
        Some(rest) => match rest
            .strip_prefix('_')
            .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|d| d.parse::<u64>().ok())
        {
            Some(number) => (1, number),
            None => (2, 0),
        },
        None => (3, 0),
    };
    key(a).cmp(&key(b)).then_with(|| a.cmp(b))
}

/// An entry's URLs in INT-03.2's order, empty values skipped, at most
/// [`MAX_URLS`] (INT-03.17): the main URL, the additional URLs, the
/// passkey relying party field. Values as stored.
fn urls(entry: &Entry) -> impl Iterator<Item = (Kind, &str)> {
    let mut extra: Vec<(&str, &str)> = entry
        .fields()
        .filter(|(name, _)| name.starts_with(EXTRA))
        .map(|(name, f)| (name, f.value.expose()))
        .collect();
    extra.sort_by(|a, b| extra_url_order(a.0, b.0));
    core::iter::once((Kind::Main, entry.value(MAIN)))
        .chain(extra.into_iter().map(|(_, v)| (Kind::Extra, v)))
        .chain(core::iter::once((Kind::Extra, entry.value(PASSKEY_RP))))
        .filter(|(_, v)| !v.is_empty())
        .take(MAX_URLS)
}

/// Puts ranked entries in offer order (INT-03.15, INT-03.16): higher rank
/// first; equal ranks keep the order given, which is the vault, group tree
/// and stored order of INT-02.13's walk. With S-BRW-12 `best_only`, only
/// the entries of the highest rank stay.
pub fn order<T>(found: &mut Vec<(u8, T)>, best_only: bool) {
    // A stable sort keeps the walk's order among equal ranks.
    found.sort_by_key(|f| core::cmp::Reverse(f.0));
    if best_only && let Some(top) = found.first().map(|f| f.0) {
        found.retain(|f| f.0 == top);
    }
}

/// The editor's note under a website row (INT-03.18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// MI03-01: a refused pattern.
    RefusedPattern,
    /// MI03-02: no valid host.
    NoHost,
    /// MI03-03: another scheme.
    OtherScheme,
}

impl Note {
    /// The message id (INT-03 "Messages").
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::RefusedPattern => "MI03-01",
            Self::NoHost => "MI03-02",
            Self::OtherScheme => "MI03-03",
        }
    }
}

/// The note under an additional URL row (INT-03.18), `None` when the value
/// can fit a web page, is empty, or holds a placeholder (it is resolved
/// when matched). Notes never stop a save.
#[must_use]
pub fn note(value: &str) -> Option<Note> {
    let v = value.trim_matches([' ', '\t']);
    if v.is_empty() || v.contains('{') {
        return None;
    }
    if let Some(inner) = v.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        if inner.is_empty() || inner.contains('*') {
            return Some(Note::RefusedPattern);
        }
        // LD-323 (5): a quoted URL fits only an http or https page whose
        // text it is (INT-03.11), so one that no page reads back to never
        // fits.
        let fits = !v.chars().any(forbidden)
            && Page::read(inner, None, false)
                .is_ok_and(|p| p.web.is_some() && p.text == no_fragment(inner));
        return (!fits).then_some(Note::NoHost);
    }
    let scheme = match v.split_once("://") {
        Some((s, _)) if s.contains('*') => return Some(Note::RefusedPattern),
        Some((s, _)) => s,
        None if other_scheme(v) => return Some(Note::OtherScheme),
        None => "https",
    };
    if web_scheme(scheme).is_none() {
        return Some(if valid_scheme(scheme) {
            Note::OtherScheme
        } else {
            Note::NoHost
        });
    }
    if v.chars().any(forbidden) {
        return Some(Note::NoHost);
    }
    let fits = if v.contains('*') {
        if Pattern::read(v).is_none() {
            return Some(Note::RefusedPattern);
        }
        true
    } else {
        plain(v, false).is_some()
    };
    (!fits).then_some(Note::NoHost)
}
