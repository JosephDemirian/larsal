//! URLs: the parts the `{URL:...}` placeholders give (MOD-08.9), and the
//! decisions of opening an entry URL (MOD-08.31).
//!
//! The parser is our own, small and tolerant, checked against the MOD-08.9
//! table (lead decision D-08-9: "a small parser of our own for the parts
//! only"). Hosts are always given in ASCII: non-ASCII labels are lower-cased
//! and Punycode-encoded (RFC 3492; LD-58).
//!
//! Guarantees: a URL can hold a password, so every part is built in a
//! wiping buffer (`Text`); nothing here panics or loops on any input.

use crate::text::{Bytes, Text};
use app_crypto::secret::{SecretBytes, SecretString};

/// The parts of a URL (MOD-08.9). Empty strings for absent parts.
pub(crate) struct Parts {
    pub(crate) scheme: Text,
    pub(crate) host: Text,
    /// `-1` when absent or empty (D-08-6).
    pub(crate) port: i64,
    pub(crate) path: Text,
    pub(crate) query: Text,
    pub(crate) fragment: Text,
    pub(crate) userinfo: Text,
    pub(crate) username: Text,
    pub(crate) password: Text,
    /// The URL without its scheme; empty for an invalid URL.
    pub(crate) without_scheme: Text,
}

impl Parts {
    fn empty() -> Self {
        Self {
            scheme: Text::new(),
            host: Text::new(),
            port: -1,
            path: Text::new(),
            query: Text::new(),
            fragment: Text::new(),
            userinfo: Text::new(),
            username: Text::new(),
            password: Text::new(),
            without_scheme: Text::new(),
        }
    }
}

/// The scheme: a letter, then letters, digits, `+`, `-` or `.`, then `:`.
fn split_scheme(url: &str) -> Option<(&str, &str)> {
    let colon = url.find(':')?;
    let (s, rest) = (url.get(..colon)?, url.get(colon.checked_add(1)?..)?);
    let mut chars = s.chars();
    (chars.next()?.is_ascii_alphabetic()
        && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)))
    .then_some((s, rest))
}

fn hex(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Percent-decoding into `out`, keeping `%3A` when `keep_colon` (user info,
/// MOD-08.9); bad escapes stay as written; bad UTF-8 becomes U+FFFD.
fn decode_into(out: &mut Text, s: &str, keep_colon: bool) {
    let b = s.as_bytes();
    let mut bytes = Bytes::new();
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        let pair = (b.get(i.saturating_add(1)), b.get(i.saturating_add(2)));
        if let (b'%', (Some(&h), Some(&l))) = (c, pair)
            && let (Some(h), Some(l)) = (hex(h), hex(l))
        {
            let v = h.saturating_mul(16).saturating_add(l);
            if keep_colon && v == b':' {
                bytes.extend(b"%3A");
            } else {
                bytes.extend(&[v]);
            }
            i = i.saturating_add(3);
            continue;
        }
        bytes.extend(&[c]);
        i = i.saturating_add(1);
    }
    bytes.utf8_lossy_into(out);
}

/// One host label in ASCII: lower case, Punycode with `xn--` when it is not
/// ASCII. `None` when it cannot be encoded.
fn label_ascii(out: &mut Text, label: &str) -> Option<()> {
    if label.is_ascii() {
        lower_into(out, label);
        return Some(());
    }
    // ponytail: lower case stands in for the full IDNA mapping and
    // normalization (UTS 46); exotic labels may differ from a browser's.
    out.push_str("xn--");
    punycode(out, || label.chars().flat_map(char::to_lowercase))
}

/// ASCII lower case of `s`, appended to `out` with no plain copy.
fn lower_into(out: &mut Text, s: &str) {
    for c in s.chars() {
        out.push(c.to_ascii_lowercase());
    }
}

/// RFC 3492 parameters.
const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;

/// RFC 3492 bias adaptation.
fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / 700 } else { delta / 2 };
    delta = delta.saturating_add(delta.checked_div(points).unwrap_or(0));
    let mut k = 0u32;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k = k.saturating_add(BASE);
    }
    k.saturating_add(
        BASE.saturating_mul(delta)
            .checked_div(delta.saturating_add(38))
            .unwrap_or(0),
    )
}

/// RFC 3492 Punycode encoding of the code points `input()` gives into
/// `out` (the iterator is made again for each pass, so nothing is copied).
fn punycode<I: Iterator<Item = char>>(out: &mut Text, input: impl Fn() -> I) -> Option<()> {
    /// RFC 3492 digits: 0 to 25 are `a` to `z`, 26 to 35 are `0` to `9`.
    fn digit(d: u32) -> char {
        let b = u8::try_from(d).unwrap_or(0);
        char::from(if b < 26 {
            b'a'.saturating_add(b)
        } else {
            b'0'.saturating_add(b.saturating_sub(26))
        })
    }
    let mut b = 0u32;
    for c in input().filter(char::is_ascii) {
        out.push(c);
        b = b.checked_add(1)?;
    }
    let mut h = b;
    if b > 0 {
        out.push('-');
    }
    let (mut n, mut delta, mut bias) = (128u32, 0u32, 72u32);
    let total = u32::try_from(input().count()).ok()?;
    while h < total {
        let m = input().map(u32::from).filter(|&c| c >= n).min()?;
        delta = delta.checked_add(m.checked_sub(n)?.checked_mul(h.checked_add(1)?)?)?;
        n = m;
        for c in input().map(u32::from) {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias.saturating_add(TMAX) {
                        TMAX
                    } else {
                        k.checked_sub(bias)?
                    };
                    if q < t {
                        break;
                    }
                    let span = BASE.checked_sub(t)?;
                    out.push(digit(t.checked_add(q.checked_sub(t)?.checked_rem(span)?)?));
                    q = q.checked_sub(t)?.checked_div(span)?;
                    k = k.checked_add(BASE)?;
                }
                out.push(digit(q));
                bias = adapt(delta, h.checked_add(1)?, h == b);
                delta = 0;
                h = h.checked_add(1)?;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(())
}

/// The Unicode form of a host in ASCII (MOD-08.9's form): every `xn--`
/// label decoded (RFC 3492), for Auto-Type's host test (INT-05.22, R05-5).
/// `None` when no label has the prefix or one does not decode. Built in
/// wiping buffers only (LD-196 (4)).
#[must_use]
pub fn host_unicode(host: &str) -> Option<SecretString> {
    let mut out = Text::new();
    let mut changed = false;
    for (n, label) in host.split('.').enumerate() {
        if n > 0 {
            out.push('.');
        }
        let code = label
            .get(..4)
            .filter(|p| p.eq_ignore_ascii_case("xn--"))
            .and_then(|_| label.get(4..));
        match code {
            Some(code) => {
                punycode_decode(&mut out, code)?;
                changed = true;
            }
            None => out.push_str(label),
        }
    }
    changed.then(|| out.into_secret())
}

/// RFC 3492 decoding of a label's part after `xn--` into `out`. A label
/// has at most 63 octets (LD-112), so at most 63 code points: they are
/// kept, 4 bytes each, in one wiping buffer of that size.
fn punycode_decode(out: &mut Text, code: &str) -> Option<()> {
    const MAX: usize = MAX_LABEL;
    if code.len() > MAX {
        return None;
    }
    let (basic, digits) = match code.rfind('-') {
        Some(at) => (code.get(..at)?, code.get(at.saturating_add(1)..)?),
        None => ("", code),
    };
    if !basic.is_ascii() {
        return None;
    }
    let mut points = SecretBytes::zeroed(MAX.saturating_mul(4));
    let mut len = 0usize;
    // Puts `c` at position `at`, moving the later ones up.
    let mut put = |at: usize, c: u32| -> Option<()> {
        if at > len || len >= MAX {
            return None;
        }
        let buf = points.expose_mut();
        buf.get_mut(at.checked_mul(4)?..len.checked_add(1)?.checked_mul(4)?)?
            .rotate_right(4);
        buf.get_mut(at.checked_mul(4)?..at.checked_mul(4)?.checked_add(4)?)?
            .copy_from_slice(&c.to_le_bytes());
        len = len.checked_add(1)?;
        Some(())
    };
    for (i, b) in basic.bytes().enumerate() {
        put(i, u32::from(b))?;
    }
    let (mut n, mut i, mut bias) = (128u32, 0u32, 72u32);
    let mut count = u32::try_from(basic.len()).ok()?;
    let mut digits = digits.bytes().peekable();
    while digits.peek().is_some() {
        let old = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let d = match digits.next()? {
                b @ b'a'..=b'z' => b.wrapping_sub(b'a'),
                b @ b'A'..=b'Z' => b.wrapping_sub(b'A'),
                b @ b'0'..=b'9' => b.wrapping_sub(b'0').wrapping_add(26),
                _ => return None,
            };
            let d = u32::from(d);
            i = i.checked_add(d.checked_mul(w)?)?;
            let t = k.saturating_sub(bias).clamp(TMIN, TMAX);
            if d < t {
                break;
            }
            w = w.checked_mul(BASE.saturating_sub(t))?;
            k = k.checked_add(BASE)?;
        }
        count = count.checked_add(1)?;
        bias = adapt(i.saturating_sub(old), count, old == 0);
        n = n.checked_add(i.checked_div(count)?)?;
        i = i.checked_rem(count)?;
        if n < 0x80 || char::from_u32(n).is_none() {
            return None;
        }
        put(usize::try_from(i).ok()?, n)?;
        i = i.checked_add(1)?;
    }
    let buf = points.expose();
    for at in 0..len {
        let b = buf.get(at.checked_mul(4)?..at.checked_mul(4)?.checked_add(4)?)?;
        let c = u32::from_le_bytes(b.try_into().ok()?);
        out.push(char::from_u32(c)?);
    }
    Some(())
}

/// Characters a host may not hold (spaces, delimiters, controls).
fn bad_host_char(c: char) -> bool {
    c.is_control() || " #%/:<>?@[\\]^|".contains(c)
}

/// The host in ASCII, `None` when it is not a valid host.
/// The DNS limits (LD-112): a label of at most 63 octets and a host of at
/// most 253, both after encoding.
const MAX_LABEL: usize = 63;
const MAX_HOST: usize = 253;

/// The host in ASCII, `None` when it is not a valid host (an empty label
/// included, LD-119). Each label's
/// length is checked before it is encoded: encoding never makes a label
/// shorter than its character count, so a longer label is invalid at once
/// and Punycode only ever sees at most 63 characters; the whole host is
/// checked after encoding (LD-112).
fn host_ascii(out: &mut Text, host: &str) -> Option<()> {
    if host.is_empty() || host.split('.').any(|l| l.chars().nth(MAX_LABEL).is_some()) {
        return None;
    }
    // LD-119: no empty label (`a..b`, `.a`); one final dot (`example.com.`,
    // the fully qualified form) is kept.
    let labels = host.strip_suffix('.').unwrap_or(host);
    if labels.split('.').any(str::is_empty) {
        return None;
    }
    if host.chars().any(bad_host_char) {
        return None;
    }
    let start = out.len();
    for (i, label) in host.split('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        let before = out.len();
        label_ascii(out, label)?;
        if out.len().saturating_sub(before) > MAX_LABEL {
            return None;
        }
    }
    (out.len().saturating_sub(start) <= MAX_HOST).then_some(())
}

/// A site typed on the editor's Browser page (INT-02.29): a host, or a
/// URL whose host is taken; the host in ASCII form (INT-03.4: one final
/// dot dropped, lower case, Punycode labels, DNS limits). `None` when the
/// text gives no valid host (MI02-10).
#[must_use]
pub fn site_host(typed: &str) -> Option<String> {
    let typed = typed.trim();
    if typed.is_empty() {
        return None;
    }
    let url = if typed.contains("://") {
        typed.to_owned()
    } else {
        format!("https://{typed}")
    };
    let parts = parse(&url);
    let host = parts.host.as_str();
    let host = host.strip_suffix('.').unwrap_or(host);
    let mut out = Text::new();
    host_ascii(&mut out, host)?;
    let ascii = out.as_str();
    (!ascii.is_empty()).then(|| ascii.to_owned())
}

/// Parses a resolved URL into its parts (MOD-08.9): scheme and host lower
/// case, IPv6 hosts without brackets, path, query, fragment, user name and
/// password percent-decoded, user info decoded but `%3A` kept; text with no
/// scheme is all path; an absent or empty port is `-1`; an invalid URL
/// gives an empty `without_scheme` and empty parts wherever none parsed.
pub(crate) fn parse(url: &str) -> Parts {
    let mut p = Parts::empty();
    if url.is_empty() {
        return p;
    }
    let (scheme, rest) = split_scheme(url).unwrap_or(("", url));
    lower_into(&mut p.scheme, scheme);
    let mut valid = true;
    let (authority, tail) = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            (
                Some(after.get(..end).unwrap_or("")),
                after.get(end..).unwrap_or(""),
            )
        }
        None => (None, rest),
    };
    let (before_frag, fragment) = match tail.find('#') {
        Some(i) => (tail.get(..i).unwrap_or(""), tail.get(i.saturating_add(1)..)),
        None => (tail, None),
    };
    let (path, query) = match before_frag.find('?') {
        Some(i) => (
            before_frag.get(..i).unwrap_or(""),
            before_frag.get(i.saturating_add(1)..),
        ),
        None => (before_frag, None),
    };
    decode_into(&mut p.path, path, false);
    decode_into(&mut p.query, query.unwrap_or(""), false);
    decode_into(&mut p.fragment, fragment.unwrap_or(""), false);
    let mut port_text = None;
    let mut userinfo_raw = None;
    if let Some(auth) = authority {
        let hostport = match auth.rfind('@') {
            Some(i) => {
                let info = auth.get(..i).unwrap_or("");
                userinfo_raw = Some(info);
                decode_into(&mut p.userinfo, info, true);
                let (user, pass) = info.split_once(':').unwrap_or((info, ""));
                decode_into(&mut p.username, user, false);
                decode_into(&mut p.password, pass, false);
                auth.get(i.saturating_add(1)..).unwrap_or("")
            }
            None => auth,
        };
        let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
            match v6.split_once(']') {
                // LD-119: only a valid IPv6 address between brackets.
                // LD-121: anything else after the brackets (`[::1]x`) makes
                // the URL invalid, and the host empty.
                Some((h, after)) if h.parse::<std::net::Ipv6Addr>().is_ok() => {
                    match after.strip_prefix(':') {
                        Some(port) => {
                            lower_into(&mut p.host, h);
                            (None, Some(port))
                        }
                        None if after.is_empty() => {
                            lower_into(&mut p.host, h);
                            (None, None)
                        }
                        None => {
                            valid = false;
                            (None, None)
                        }
                    }
                }
                _ => {
                    valid = false;
                    (None, None)
                }
            }
        } else {
            match hostport.rsplit_once(':') {
                Some((h, port)) => (Some(h), Some(port)),
                None => (Some(hostport), None),
            }
        };
        if let Some(h) = host {
            let mut ascii = Text::new();
            if host_ascii(&mut ascii, h).is_some() {
                p.host = ascii;
            } else {
                valid = false;
            }
        }
        match port {
            Some("") | None => {}
            Some(digits) => match digits.parse::<u16>() {
                Ok(n) if digits.bytes().all(|b| b.is_ascii_digit()) => {
                    p.port = i64::from(n);
                    port_text = Some(digits);
                }
                _ => valid = false,
            },
        }
    }
    if valid {
        let w = &mut p.without_scheme;
        if authority.is_some() {
            w.push_str("//");
            if let Some(info) = userinfo_raw {
                w.push_str(info);
                w.push('@');
            }
            if p.host.as_str().contains(':') {
                w.push('[');
                w.push_str(p.host.as_str());
                w.push(']');
            } else {
                w.push_str(p.host.as_str());
            }
            if let Some(port) = port_text {
                w.push(':');
                w.push_str(port);
            }
        }
        w.push_str(p.path.as_str());
        if query.is_some() {
            w.push('?');
            w.push_str(p.query.as_str());
        }
        if fragment.is_some() {
            w.push('#');
            w.push_str(p.fragment.as_str());
        }
    }
    p
}

// ---------------------------------------------------------------------------
// Opening an entry URL (MOD-08.31).

/// The vault link prefix, stored encoded (name rule).
pub const VAULT_LINK: &[u8] = &[0x6b, 0x64, 0x62, 0x78, 0x3a, 0x2f, 0x2f];

/// What opening a resolved URL does (MOD-08.31). The texts come from a
/// resolution and may hold secrets, so they stay in `SecretString`.
#[derive(Debug, PartialEq, Eq)]
pub enum Open {
    /// Nothing: an empty URL, or `cmd://` with nothing after it.
    Nothing,
    /// A command URL: ask (unless a remembered Yes matches), then run.
    Command(SecretString),
    /// Another vault, opened with the auto-open logic.
    VaultLink(SecretString),
    /// A URL for the system opener (`http`, `https`, `mailto`).
    Url(SecretString),
    /// Any other scheme: `MSG-08-4`, nothing opens (LD-59).
    Refused,
}

/// The kind of a resolved URL (MOD-08.31), by how it starts (exact case):
/// `cmd://`, the vault link prefix, else a URL read as typed input (no
/// scheme gets `http://`) that opens only for `http`, `https` and `mailto`.
#[must_use]
pub fn open_kind(resolved: &str) -> Open {
    let secret = |s: &str| Text::from(s).into_secret();
    if let Some(cmd) = resolved.strip_prefix("cmd://") {
        return if cmd.is_empty() {
            Open::Nothing
        } else {
            Open::Command(secret(cmd))
        };
    }
    if let Some(path) = resolved.as_bytes().strip_prefix(VAULT_LINK) {
        let mut t = Text::new();
        let mut b = Bytes::new();
        b.extend(path);
        b.utf8_lossy_into(&mut t);
        return Open::VaultLink(t.into_secret());
    }
    let url = resolved.trim();
    if url.is_empty() {
        return Open::Nothing;
    }
    match split_scheme(url) {
        Some((s, _))
            if ["http", "https", "mailto"]
                .iter()
                .any(|x| x.eq_ignore_ascii_case(s)) =>
        {
            Open::Url(secret(url))
        }
        Some(_) => Open::Refused,
        None => {
            let mut t = Text::from("http://");
            t.push_str(url);
            Open::Url(t.into_secret())
        }
    }
}

/// The words of a command (MOD-08.31): split at spaces; double quotes group
/// words; three double quotes in a row are one literal quote. The first
/// word is the program. Run directly, never through a shell.
#[must_use]
pub fn command_words(cmd: &str) -> Vec<SecretString> {
    let mut words = Vec::new();
    let mut word = Text::new();
    let (mut quoted, mut started) = (false, false);
    let mut rest = cmd;
    while let Some(c) = rest.chars().next() {
        if let Some(after) = rest.strip_prefix("\"\"\"") {
            word.push('"');
            started = true;
            rest = after;
            continue;
        }
        rest = rest.get(c.len_utf8()..).unwrap_or("");
        match c {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            ' ' if !quoted => {
                if started {
                    words.push(core::mem::replace(&mut word, Text::new()).into_secret());
                    started = false;
                }
            }
            _ => {
                word.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(word.into_secret());
    }
    words
}

/// The command question's text (MOD-08.31, `MSG-08-2`): the URL resolved
/// for display without `cmd://`, cut after 400 characters with ` […]`.
#[must_use]
pub fn question_text(display: &str) -> String {
    let text = display.strip_prefix("cmd://").unwrap_or(display);
    match text.char_indices().nth(400) {
        Some((i, _)) => format!("{} […]", text.get(..i).unwrap_or(text)),
        None => text.to_owned(),
    }
}

/// The key of a remembered Yes (MOD-08.31, LD-70): the vault file, the
/// entry id and a SHA-256 of the exact command, so a changed command asks
/// again. F-071: "Remember my choice" is offered only when the URL is not
/// protected (its own flag or the vault's, LD-207) and resolving it changes
/// nothing, so the stored text is the exact command: it holds no secret
/// for this unsalted hash in the settings file, and a field that a sync
/// changes cannot reuse the Yes. Every other command asks every time
/// (app-ffi `auto_open::remember_key`).
#[must_use]
pub fn remember_key(vault_file: &str, entry: app_model::Uuid, command: &str) -> String {
    let digest = app_crypto::hash::sha256(&[command.as_bytes()]);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!("{vault_file}\n{}\n{}", hex(&entry.0), hex(digest.expose()))
}

/// The path of a vault link (MOD-08.31): a `file://` URL becomes a local
/// path; a relative path is taken from the current vault's folder.
#[must_use]
pub fn vault_link_path(link: &str, vault_dir: &str) -> String {
    let path = match link.strip_prefix("file://") {
        Some(p) => {
            let mut t = Text::new();
            decode_into(&mut t, p, false);
            t.as_str().to_owned()
        }
        None => link.to_owned(),
    };
    if path.starts_with('/') || vault_dir.is_empty() {
        path
    } else {
        format!("{}/{path}", vault_dir.trim_end_matches('/'))
    }
}
