//! One-time passwords (FEA-04, story E4-S10): the four storage forms and
//! which one wins, parsing, Base32 secrets, codes (RFC 6238 over RFC 4226),
//! display, and the field changes of the setup screen.
//!
//! Guarantees:
//! - The settings are derived from the entry's fields on every call and
//!   never stored (FEA-04.2).
//! - The secret text, the decoded key bytes, every code and every form U
//!   text live only in wiping buffers (`Text`, `SecretBytes`,
//!   `SecretString`); no plain copy is made (SR-07, AT-C01, AT-C02).
//! - Parsing is linear in the text and allocates at most a few times its
//!   size; digits and periods are bounded before any code is built
//!   (FEA-04.3, D-04-8), so hostile text cannot crash or hang.
//! - A code is never made from an empty or undecodable secret (D-04-1) or
//!   from a counter-based link (D-04-3).
//! - The time is an argument: time 0 is counter 0, not "now".
//!
//! The QR symbol (FEA-04.23, D-04-9) belongs to the QR screen (E5): its
//! content is [`Settings::uri`] with the unresolved title and user name,
//! and [`Settings::is_custom`] says when the screen shows its note. No QR
//! crate is added here.

use crate::text::Text;
use app_crypto::mac;
use app_crypto::secret::{SecretBytes, SecretString};
use app_model::{Entry, Field, Time};

/// The field of forms U and K.
pub const OTP: &str = "otp";
/// The secret field of form L.
pub const SEED: &str = "TOTP Seed";
/// The settings field of form L.
pub const SETTINGS: &str = "TOTP Settings";
/// The four form T fields App reads (never written; Save and Remove drop
/// every `TimeOtp-` field, LD-125).
pub const FORM_T: [&str; 4] = [
    "TimeOtp-Secret-Base32",
    "TimeOtp-Algorithm",
    "TimeOtp-Length",
    "TimeOtp-Period",
];
/// The longest code (FEA-04.3 clamp, D-04-8).
pub const MAX_DIGITS: u32 = 10;
/// The longest time step in seconds (FEA-04.3 clamp, D-04-8).
pub const MAX_PERIOD: u32 = 86_400;
/// The Steam alphabet (FEA-04.13).
const STEAM: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
/// The label and issuer when the title is empty (D-04-2).
const PRODUCT: &str = "App";

/// The hash of the HMAC (FEA-04.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC-SHA-1, the default.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// How V becomes characters (FEA-04.12, FEA-04.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoder {
    /// Decimal digits.
    Decimal,
    /// The 26 Steam letters and digits.
    Steam,
}

/// Where the settings came from (FEA-04 words).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// The `otpauth://` link.
    U,
    /// The key-query text `key=…&size=…&step=…`.
    K,
    /// The legacy pair `TOTP Seed` plus `TOTP Settings`.
    L,
    /// The four `TimeOtp-*` fields.
    T,
}

/// Why settings cannot make a code (FEA-04.10 and D-04-3), in check order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// A form U link whose type is neither `totp` nor empty
    /// (`MSG-OTP-UNSUPPORTED`, D-04-3).
    UnsupportedType,
    /// The secret cannot be decoded or is empty (`MSG-OTP-INVALID-KEY`,
    /// D-04-1).
    InvalidKey,
    /// The period is 0 (`MSG-OTP-INVALID-STEP`; form T only).
    InvalidStep,
    /// The digits are 0 (`MSG-OTP-INVALID-DIGITS`; form T only).
    InvalidDigits,
}

/// The one-time password settings of an entry (FEA-04 "Settings").
///
/// No `Clone` and no `Debug` of the secret: the secret text is wiped when
/// the value drops.
pub struct Settings {
    secret: Text,
    /// Code length, 0 to 10 (0 only from form T: invalid).
    pub digits: u32,
    /// Time step in seconds, 0 to 86400 (0 only from form T: invalid).
    pub period: u32,
    /// The HMAC hash.
    pub algorithm: Algorithm,
    /// Decimal or Steam.
    pub encoder: Encoder,
    /// The storage form.
    pub form: Form,
    unsupported: bool,
    /// The secret held a control-character escape (LD-128).
    control: bool,
}

impl core::fmt::Debug for Settings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Settings")
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("algorithm", &self.algorithm)
            .field("encoder", &self.encoder)
            .field("form", &self.form)
            .field("problem", &self.problem())
            .finish_non_exhaustive()
    }
}

impl Settings {
    /// The defaults of FEA-04.8 with `secret`.
    fn defaults(secret: Text, form: Form) -> Self {
        Self {
            secret,
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
            encoder: Encoder::Decimal,
            form,
            unsupported: false,
            control: false,
        }
    }

    fn clamp(&mut self) {
        self.digits = self.digits.clamp(1, MAX_DIGITS);
        self.period = self.period.clamp(1, MAX_PERIOD);
    }

    /// The first problem of FEA-04.10 (after D-04-3), or `None` when the
    /// settings make codes.
    #[must_use]
    pub fn problem(&self) -> Option<Problem> {
        if self.unsupported {
            Some(Problem::UnsupportedType)
        } else if self.key().is_none() {
            Some(Problem::InvalidKey)
        } else if self.period == 0 {
            Some(Problem::InvalidStep)
        } else if self.digits == 0 {
            Some(Problem::InvalidDigits)
        } else {
            None
        }
    }

    /// The key bytes of FEA-04.9, or `None` when the secret cannot be
    /// decoded, gives no bytes (D-04-1) or held a control-character escape
    /// (LD-128).
    #[must_use]
    pub fn key(&self) -> Option<SecretBytes> {
        if self.control {
            return None;
        }
        let cleaned = clean(self.secret.as_str())?;
        decode(cleaned.as_str()).filter(|k| !k.is_empty())
    }

    /// True when the secret text is not empty (FEA-08.10: a parse that
    /// gives no secret sets nothing).
    pub(crate) fn has_secret(&self) -> bool {
        !self.secret.is_empty()
    }

    /// Settings are custom when digits are not 6, the period is not 30 or
    /// the hash is not SHA-1; Steam is custom (FEA-04.21).
    #[must_use]
    pub fn is_custom(&self) -> bool {
        self.digits != 6
            || self.period != 30
            || self.algorithm != Algorithm::Sha1
            || self.encoder == Encoder::Steam
    }

    /// The code at `now` without the display space (FEA-04.11 to
    /// FEA-04.13), or `None` when [`Settings::problem`] is not `None` or
    /// `now` is before 1970.
    #[must_use]
    pub fn code(&self, now: Time) -> Option<SecretString> {
        if self.problem().is_some() {
            return None;
        }
        let key = self.key()?;
        let counter = unix(now)?.checked_div(u64::from(self.period))?;
        let msg = counter.to_be_bytes();
        let h = match self.algorithm {
            Algorithm::Sha1 => mac::hmac_sha1(key.expose(), &[&msg]),
            Algorithm::Sha256 => mac::hmac_sha256(key.expose(), &[&msg]),
            Algorithm::Sha512 => mac::hmac_sha512(key.expose(), &[&msg]),
        }
        .ok()?;
        let h = h.expose();
        let offset = usize::from(h.last()? & 0x0f);
        let four: [u8; 4] = h.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
        let v = u64::from(u32::from_be_bytes(four) & 0x7fff_ffff);
        Some(encode(v, self.digits, self.encoder).into_secret())
    }

    /// Seconds the code at `now` stays valid, `period` down to 1
    /// (FEA-04.14, D-04-10); `None` when the period is 0 or `now` is before
    /// 1970.
    #[must_use]
    pub fn seconds_left(&self, now: Time) -> Option<u32> {
        let p = u64::from(self.period);
        let r = p.checked_sub(unix(now)?.checked_rem(p)?)?;
        u32::try_from(r).ok()
    }

    /// The form U text of FEA-04.17 for these settings, with `title` and
    /// `user` as given: resolved for Save and CSV export, unresolved for
    /// the QR screen (FEA-04.23). The secret is cleaned and padded
    /// (FEA-04.9 step 1); a secret that cannot be cleaned is written as
    /// its kept characters.
    #[must_use]
    pub fn uri(&self, title: &str, user: &str) -> SecretString {
        let secret = clean(self.secret.as_str()).unwrap_or_else(|| kept(self.secret.as_str()));
        uri_text(
            secret.as_str(),
            self.digits,
            self.period,
            self.algorithm,
            self.encoder,
            title,
            user,
        )
        .into_secret()
    }
}

/// The settings of `entry` by the precedence of FEA-04.1, or `None` when it
/// has no one-time password.
#[must_use]
pub fn settings(entry: &Entry) -> Option<Settings> {
    if let Some(f) = entry.field(SETTINGS) {
        return from_text(f.value.expose(), entry.value(SEED));
    }
    if let Some(f) = entry.field(OTP) {
        return from_text(f.value.expose(), "");
    }
    let [secret, algorithm, length, period] = FORM_T;
    let f = entry.field(secret)?;
    if f.value.is_empty() {
        return None;
    }
    // FEA-04.7 with D-04-8: 0 stays invalid, large values are clamped.
    let mut s = Settings::defaults(Text::from(f.value.expose()), Form::T);
    let value = |n| entry.value(n);
    if !value(algorithm).is_empty() {
        s.algorithm = algorithm_named(value(algorithm));
    }
    if !value(length).is_empty() {
        s.digits = number(value(length)).min(MAX_DIGITS);
    }
    if !value(period).is_empty() {
        s.period = number(value(period)).min(MAX_PERIOD);
    }
    Some(s)
}

/// The code of `entry` at `now`, or `None` with no settings or invalid
/// ones (D-04-4). Fits `refs::Context::otp` for `{TOTP}` and `{TIMEOTP}`
/// (FEA-04.25, D-04-11).
#[must_use]
pub fn code_for(entry: &Entry, now: Time) -> Option<SecretString> {
    settings(entry)?.code(now)
}

/// Settings text (FEA-04.3): forms U, K, then L with `fallback` as the
/// secret; `None` when nothing applies.
#[must_use]
pub fn from_text(text: &str, fallback: &str) -> Option<Settings> {
    if text.is_empty() && fallback.is_empty() {
        return None;
    }
    let mut s = form_u(text)
        .or_else(|| form_k(text))
        .or_else(|| form_l(text, fallback))?;
    s.clamp();
    Some(s)
}

fn form_u(text: &str) -> Option<Settings> {
    let (scheme, rest) = text.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return None;
    }
    // D-04-3: the type is the authority part after `//`.
    let kind = rest
        .strip_prefix("//")
        .map_or("", |r| r.split(['/', '?', '#']).next().unwrap_or(""));
    let query = text
        .split_once('?')
        .map_or("", |(_, q)| q.split('#').next().unwrap_or(""));
    let mut s = Settings::defaults(item(query, "secret").unwrap_or_else(Text::new), Form::U);
    s.control = raw_item(query, "secret").is_some_and(control_escape);
    s.unsupported = !(kind.is_empty() || kind.eq_ignore_ascii_case("totp"));
    if let Some(v) = item(query, "digits") {
        s.digits = number(v.as_str());
    }
    if let Some(v) = item(query, "period") {
        s.period = number(v.as_str());
    }
    if let Some(v) = item(query, "encoder") {
        s.encoder = encoder_named(v.as_str());
    }
    if let Some(v) = item(query, "algorithm") {
        s.algorithm = algorithm_named(v.as_str());
    }
    Some(s)
}

fn form_k(text: &str) -> Option<Settings> {
    let mut s = Settings::defaults(item(text, "key")?, Form::K);
    s.control = raw_item(text, "key").is_some_and(control_escape);
    if let Some(v) = item(text, "size") {
        s.digits = number(v.as_str());
    }
    if let Some(v) = item(text, "step") {
        s.period = number(v.as_str());
    }
    if let Some(v) = item(text, "otpHashMode") {
        s.algorithm = algorithm_named(v.as_str());
    }
    Some(s)
}

fn form_l(text: &str, fallback: &str) -> Option<Settings> {
    if fallback.is_empty() {
        return None;
    }
    let mut s = Settings::defaults(Text::from(fallback), Form::L);
    let mut parts = text.split(';');
    if let (Some(p), Some(d)) = (parts.next(), parts.next()) {
        if d == "S" {
            s.encoder = Encoder::Steam;
            s.digits = 5;
        } else {
            s.period = number(p);
            s.digits = number(d);
        }
    }
    Some(s)
}

/// The decoded value of the first item named exactly `name` in a query
/// (`&`-separated `name=value` pairs).
fn item(query: &str, name: &str) -> Option<Text> {
    raw_item(query, name).map(percent_decode)
}

/// The undecoded value of the first item named exactly `name`.
fn raw_item<'q>(query: &'q str, name: &str) -> Option<&'q str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
}

/// LD-128: the value holds an escape of a control character, `%00` to
/// `%1F` or `%7F`, which makes a secret invalid.
fn control_escape(raw: &str) -> bool {
    let b = raw.as_bytes();
    b.windows(3).any(|w| match w {
        [b'%', hi, lo] => {
            let digit = |h: &u8| char::from(*h).to_digit(16);
            matches!(
                (digit(hi), digit(lo)),
                (Some(0 | 1), Some(_)) | (Some(7), Some(15))
            )
        }
        _ => false,
    })
}

/// FEA-04.5: `%XX` becomes its byte except `%25` and `%2B`; `+` stays;
/// the bytes are read as UTF-8, a bad sequence as U+FFFD.
fn percent_decode(v: &str) -> Text {
    let mut bytes = crate::text::Bytes::new();
    let b = v.as_bytes();
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        let hex = |j: usize| b.get(j).and_then(|h| char::from(*h).to_digit(16));
        let pair = (c == b'%')
            .then(|| hex(i.saturating_add(1)).zip(hex(i.saturating_add(2))))
            .flatten();
        match pair {
            Some((hi, lo)) if !matches!((hi, lo), (2, 5) | (2, 11)) => {
                // Both digits are below 16, so the byte fits.
                bytes
                    .extend(&[u8::try_from(hi.saturating_mul(16).saturating_add(lo)).unwrap_or(0)]);
                i = i.saturating_add(3);
            }
            _ => {
                bytes.extend(&[c]);
                i = i.saturating_add(1);
            }
        }
    }
    let mut out = Text::new();
    bytes.utf8_lossy_into(&mut out);
    out
}

/// FEA-04.4: a decimal unsigned 32-bit value, spaces around and one
/// leading `+` allowed; anything else is 0.
fn number(text: &str) -> u32 {
    let t = text.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r'));
    let t = t.strip_prefix('+').unwrap_or(t);
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    t.parse().unwrap_or(0)
}

/// FEA-04.6, hash names compared without case.
fn algorithm_named(name: &str) -> Algorithm {
    if name.eq_ignore_ascii_case("SHA512") || name.eq_ignore_ascii_case("HMAC-SHA-512") {
        Algorithm::Sha512
    } else if name.eq_ignore_ascii_case("SHA256") || name.eq_ignore_ascii_case("HMAC-SHA-256") {
        Algorithm::Sha256
    } else {
        Algorithm::Sha1
    }
}

/// FEA-04.6: exactly `steam` is Steam.
fn encoder_named(name: &str) -> Encoder {
    if name == "steam" {
        Encoder::Steam
    } else {
        Encoder::Decimal
    }
}

/// The characters cleaning keeps (FEA-04.9 step 1, without the padding).
fn kept(secret: &str) -> Text {
    let mut out = Text::new();
    for c in secret.chars() {
        match c {
            '0' => out.push('O'),
            '1' => out.push('L'),
            '8' => out.push('B'),
            'A'..='Z' | 'a'..='z' | '2'..='7' => out.push(c),
            _ => {}
        }
    }
    out
}

/// FEA-04.9 step 1: the kept characters padded with `=` to a multiple of
/// 8, or `None` for a length of 1, 3 or 6 modulo 8.
fn clean(secret: &str) -> Option<Text> {
    let mut out = kept(secret);
    let pad = match out.len() % 8 {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => return None,
    };
    for _ in 0..pad {
        out.push('=');
    }
    Some(out)
}

/// FEA-04.9 step 2: RFC 4648 Base32 of a cleaned text, letters in any
/// case, the bits left over in the last group ignored.
fn decode(cleaned: &str) -> Option<SecretBytes> {
    let symbols = cleaned.trim_end_matches('=');
    let n = symbols.len().checked_mul(5)? / 8;
    let mut key = SecretBytes::zeroed(n);
    let (mut acc, mut bits, mut at) = (0u32, 0u32, 0usize);
    for c in symbols.bytes() {
        let v = match c {
            b'A'..=b'Z' => c.wrapping_sub(b'A'),
            b'a'..=b'z' => c.wrapping_sub(b'a'),
            b'2'..=b'7' => c.wrapping_sub(b'2').wrapping_add(26),
            _ => return None,
        };
        acc = ((acc << 5) | u32::from(v)) & 0x1fff;
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            *key.expose_mut().get_mut(at)? = u8::try_from((acc >> bits) & 0xff).ok()?;
            at = at.wrapping_add(1);
        }
    }
    Some(key)
}

/// Unix seconds of `t`, or `None` before 1970.
fn unix(t: Time) -> Option<u64> {
    u64::try_from(t.0.checked_sub(Time::from_unix(0)?.0)?).ok()
}

/// V as `digits` characters (FEA-04.12, FEA-04.13), in 64 bits.
fn encode(v: u64, digits: u32, encoder: Encoder) -> Text {
    let mut out = Text::new();
    match encoder {
        Encoder::Decimal => {
            let code = 10u64
                .checked_pow(digits)
                .and_then(|m| v.checked_rem(m))
                .unwrap_or(v);
            let mut buf = [b'0'; 20];
            let mut rest = code;
            for slot in buf.iter_mut().rev() {
                *slot = b'0'.wrapping_add(u8::try_from(rest % 10).unwrap_or(0));
                rest /= 10;
            }
            let start = buf
                .len()
                .saturating_sub(usize::try_from(digits).unwrap_or(0));
            out.push_str(core::str::from_utf8(buf.get(start..).unwrap_or(&[])).unwrap_or(""));
            buf.fill(0);
        }
        Encoder::Steam => {
            let mut rest = v;
            for _ in 0..digits {
                let i = usize::try_from(rest % 26).unwrap_or(0);
                out.push(char::from(*STEAM.get(i).unwrap_or(&b'2')));
                rest /= 26;
            }
        }
    }
    out
}

/// A code with its display space after the first floor(length / 2)
/// characters (FEA-04.15). Only the screen uses this.
#[must_use]
pub fn display(code: &str) -> SecretString {
    let half = crate::text::char_count(code) / 2;
    let mut out = Text::new();
    for (i, c) in code.chars().enumerate() {
        if i == half && half > 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out.into_secret()
}

/// FEA-04.17 percent-encoding: every UTF-8 byte except `A`–`Z`, `a`–`z`,
/// `0`–`9`, `-`, `.`, `_`, `~` becomes `%` and two uppercase hex digits.
pub(crate) fn percent_encode(out: &mut Text, text: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(*HEX.get(usize::from(b >> 4)).unwrap_or(&b'0')));
            out.push(char::from(*HEX.get(usize::from(b & 0x0f)).unwrap_or(&b'0')));
        }
    }
}

fn decimal(out: &mut Text, n: u32) {
    let mut buf = [0u8; 10];
    let mut at = buf.len();
    let mut rest = n;
    loop {
        at = at.saturating_sub(1);
        if let Some(slot) = buf.get_mut(at) {
            *slot = b'0'.wrapping_add(u8::try_from(rest % 10).unwrap_or(0));
        }
        rest /= 10;
        if rest == 0 || at == 0 {
            break;
        }
    }
    out.push_str(core::str::from_utf8(buf.get(at..).unwrap_or(&[])).unwrap_or(""));
}

fn hash_name(a: Algorithm) -> Option<&'static str> {
    match a {
        Algorithm::Sha1 => None,
        Algorithm::Sha256 => Some("SHA256"),
        Algorithm::Sha512 => Some("SHA512"),
    }
}

/// FEA-04.17 with a secret already cleaned and padded.
fn uri_text(
    secret: &str,
    digits: u32,
    period: u32,
    algorithm: Algorithm,
    encoder: Encoder,
    title: &str,
    user: &str,
) -> Text {
    let label = if title.is_empty() { PRODUCT } else { title };
    let user = if user.is_empty() { "none" } else { user };
    let mut out = Text::from("otpauth://totp/");
    percent_encode(&mut out, label);
    out.push(':');
    percent_encode(&mut out, user);
    out.push_str("?secret=");
    percent_encode(&mut out, secret);
    out.push_str("&period=");
    decimal(&mut out, period);
    out.push_str("&digits=");
    decimal(&mut out, digits);
    out.push_str("&issuer=");
    percent_encode(&mut out, label);
    if encoder == Encoder::Steam {
        out.push_str("&encoder=steam");
    }
    if let Some(name) = hash_name(algorithm) {
        out.push_str("&algorithm=");
        out.push_str(name);
    }
    out
}

/// The setup screen's choice (FEA-04.22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// 6 digits, 30 seconds, SHA-1.
    Standard,
    /// 5 Steam characters, 30 seconds, SHA-1.
    Steam,
    /// The three Custom controls.
    Custom,
}

/// The setup screen's controls (FEA-04.22): pre-filled by [`prefill`],
/// changed by the user, saved by [`write`].
pub struct Setup {
    /// The secret key text as shown and typed.
    pub secret: SecretString,
    /// Standard, Steam or Custom.
    pub choice: Choice,
    /// Custom: the hash.
    pub algorithm: Algorithm,
    /// Custom: the time step, 1 to 86400 (always pre-filled).
    pub period: u32,
    /// Custom: the code size. The screen offers 6 to 10; a pre-filled
    /// value outside stays until the user changes it (D-04-12).
    pub digits: u32,
    /// Show `MSG-OTP-SETUP-INVALID` at the top: the current settings are
    /// in an error state.
    pub invalid: bool,
}

/// The setup screen's controls for an entry (FEA-04.22): the current
/// secret with every `=` removed, the time step always, Steam for a Steam
/// encoder, else Custom with digits and hash when the settings are custom,
/// else Standard. With no settings: empty, Standard, SHA-1, 30, 6.
#[must_use]
pub fn prefill(entry: &Entry) -> Setup {
    let Some(s) = settings(entry) else {
        return Setup {
            secret: SecretString::new(String::new()),
            choice: Choice::Standard,
            algorithm: Algorithm::Sha1,
            period: 30,
            digits: 6,
            invalid: false,
        };
    };
    let mut secret = Text::new();
    for c in s.secret.as_str().chars().filter(|c| *c != '=') {
        secret.push(c);
    }
    let custom = s.encoder == Encoder::Decimal && s.is_custom();
    Setup {
        secret: secret.into_secret(),
        choice: match s.encoder {
            Encoder::Steam => Choice::Steam,
            Encoder::Decimal if custom => Choice::Custom,
            Encoder::Decimal => Choice::Standard,
        },
        algorithm: if custom { s.algorithm } else { Algorithm::Sha1 },
        period: s.period,
        digits: if custom { s.digits } else { 6 },
        invalid: s.problem().is_some(),
    }
}

/// A setup secret that passed the Save check (FEA-04.22): only `A`–`Z`
/// and `2`–`7`, no padding, a decodable length. Wiped on drop.
pub struct SetupSecret(Text);

/// The setup secret check failed: show `MSG-OTP-BAD-SECRET` and keep the
/// screen open (FEA-04.22, D-04-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadSecret;

/// The Save check of FEA-04.22: uppercase, every space and `=` removed,
/// the ends trimmed; then only `A`–`Z` and `2`–`7` may remain and the
/// length may not be 1, 3 or 6 modulo 8 (D-04-5). `Ok(None)` for an empty
/// result: the caller removes the one-time password after
/// `MSG-OTP-CONFIRM-REMOVE`, or closes when the entry has none.
///
/// # Errors
/// [`BadSecret`] for any other character or an undecodable length.
pub fn setup_secret(typed: &str) -> Result<Option<SetupSecret>, BadSecret> {
    let mut out = Text::new();
    for c in typed.trim().chars().filter(|c| *c != ' ' && *c != '=') {
        let c = c.to_ascii_uppercase();
        if !matches!(c, 'A'..='Z' | '2'..='7') {
            return Err(BadSecret);
        }
        out.push(c);
    }
    match out.len() % 8 {
        _ if out.is_empty() => Ok(None),
        1 | 3 | 6 => Err(BadSecret),
        _ => Ok(Some(SetupSecret(out))),
    }
}

/// Removes the one-time password (FEA-04.20, LD-125): `otp`,
/// `TOTP Seed`, `TOTP Settings` and every field whose name starts with
/// `TimeOtp-`. Run it inside one `edit::edit_entry` so the change gets one
/// history item (MOD-03).
pub fn remove(entry: &mut Entry) {
    let names: Vec<String> = entry
        .fields()
        .map(|(n, _)| n)
        .filter(|n| [OTP, SEED, SETTINGS].contains(n) || n.starts_with("TimeOtp-"))
        .map(str::to_owned)
        .collect();
    for name in names {
        entry.remove_field(&name);
    }
}

/// Saves the setup screen (FEA-04.16): picks the form from the existing
/// settings and the choice, removes the old fields (every `TimeOtp-` field too, LD-125)
/// and writes the new ones. `title` and `user` are the entry's title and
/// user name with placeholders resolved (MOD-08). Run it inside one
/// `edit::edit_entry` (MOD-03).
pub fn write(entry: &mut Entry, secret: &SetupSecret, setup: &Setup, title: &str, user: &str) {
    let (digits, period, algorithm, encoder) = match setup.choice {
        Choice::Standard => (6, 30, Algorithm::Sha1, Encoder::Decimal),
        Choice::Steam => (5, 30, Algorithm::Sha1, Encoder::Steam),
        Choice::Custom => (
            setup.digits.clamp(1, MAX_DIGITS),
            setup.period.clamp(1, MAX_PERIOD),
            setup.algorithm,
            Encoder::Decimal,
        ),
    };
    let form = match (settings(entry).map(|s| s.form), setup.choice) {
        (Some(Form::K), Choice::Standard | Choice::Custom) => Form::K,
        (Some(Form::L), Choice::Standard | Choice::Steam) => Form::L,
        _ => Form::U, // D-04-6: Steam leaves form K for form U.
    };
    remove(entry);
    let look = Look {
        digits,
        period,
        algorithm,
        encoder,
    };
    for (name, field) in form_fields(form, secret.0.as_str(), &look, title, user) {
        entry.set_field(name.to_owned(), field);
    }
}

/// Code length, step, hash and encoder of one form's text.
#[derive(Clone, Copy)]
struct Look {
    digits: u32,
    period: u32,
    algorithm: Algorithm,
    encoder: Encoder,
}

/// The fields FEA-04.16 writes for `form` (FEA-04.17 to FEA-04.19), with
/// `secret` as given: form L stores it as is, forms K and U cleaned.
fn form_fields(
    form: Form,
    secret: &str,
    look: &Look,
    title: &str,
    user: &str,
) -> Vec<(&'static str, Field)> {
    let Look {
        digits,
        period,
        algorithm,
        encoder,
    } = *look;
    let cleaned = clean(secret).unwrap_or_else(|| kept(secret));
    let protected = |t: Text| Field {
        value: t.into_secret(),
        protected: true,
    };
    match form {
        Form::L => {
            let mut t = Text::new();
            decimal(&mut t, period);
            t.push(';');
            match encoder {
                Encoder::Steam => t.push('S'),
                Encoder::Decimal => decimal(&mut t, digits),
            }
            vec![
                (SEED, protected(Text::from(secret))),
                (
                    SETTINGS,
                    Field {
                        value: t.into_secret(),
                        protected: false,
                    },
                ),
            ]
        }
        Form::K => {
            let mut t = Text::from("key=");
            t.push_str(cleaned.as_str());
            t.push_str("&size=");
            decimal(&mut t, digits);
            t.push_str("&step=");
            decimal(&mut t, period);
            if let Some(name) = hash_name(algorithm) {
                t.push_str("&otpHashMode=");
                t.push_str(name);
            }
            vec![(OTP, protected(t))]
        }
        Form::U | Form::T => {
            let t = uri_text(
                cleaned.as_str(),
                digits,
                period,
                algorithm,
                encoder,
                title,
                user,
            );
            vec![(OTP, protected(t))]
        }
    }
}

/// FEA-08.10 storing (imports): the fields FEA-04.16 writes for the form
/// `s` was read in, the secret as read; `title` and `user` are the entry's
/// with placeholders resolved. Form T is written as form U.
pub(crate) fn stored_fields(s: &Settings, title: &str, user: &str) -> Vec<(&'static str, Field)> {
    let look = Look {
        digits: s.digits,
        period: s.period,
        algorithm: s.algorithm,
        encoder: s.encoder,
    };
    form_fields(s.form, s.secret.as_str(), &look, title, user)
}
