//! The vault data of INT-02 that every request reads: an entry's site
//! access item (INT-02.16) and its access state (INT-02.17), association
//! names (INT-02.2), the pairing words (INT-02.5), the vault id
//! (INT-01.31) and last use (INT-02.9). Keys that hold a banned word are
//! hex bytes of their ASCII text (AGENTS.md rule 1).

use crate::matching::host_form;
use larsal_crypto::base64::{self, Form};
use larsal_model::json::{self, Map, Value};
use larsal_model::{CustomData, CustomDataItem, Entry, Time, Uuid, Vault};

/// The site access item's key (INT-02.16).
pub(crate) const SITE_ACCESS: &[u8] = &[
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x58, 0x43, 0x2D, 0x42, 0x72, 0x6F, 0x77, 0x73, 0x65,
    0x72, 0x20, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x73,
];
/// The most of a site access item or a `BrowserLastUse` item Larsal reads.
const MAX_ITEM: usize = 1_048_576;
/// Hosts per site access list (INT-02.16).
pub const MAX_SITES: usize = 1_000;
/// Names in an entry's `BrowserLastUse` item (INT-02.9).
pub const MAX_USES: usize = 16;
/// The longest association name, in characters (INT-02.2).
pub const MAX_NAME: usize = 64;
const LAST_USE: &str = "BrowserLastUse";
const LAST_USED: &str = "_LAST_USED_";

fn item<'a>(data: &'a CustomData, key: &[u8]) -> Option<&'a str> {
    data.items
        .iter()
        .find(|i| i.key.as_bytes() == key)
        .map(|i| i.value.as_str())
}

/// Sets or adds item `key` (new keys at the end, FMT-14.15), with `now` as
/// its time.
fn set_item(data: &mut CustomData, key: &str, value: String, now: Time) {
    match data.items.iter_mut().find(|i| i.key == key) {
        Some(i) => {
            i.value = value;
            i.last_modified = Some(now);
        }
        None => data.items.push(CustomDataItem {
            key: key.to_owned(),
            value,
            last_modified: Some(now),
            unknown: Vec::new(),
        }),
    }
}

/// A host in the ASCII form hosts are compared in (INT-02.16, INT-03.4);
/// `None` when it cannot be encoded.
pub(crate) fn ascii(host: &str) -> Option<String> {
    host_form(host).map(|h| h.text())
}

/// An entry's site access lists (INT-02.16).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Lists {
    /// Allowed hosts, ASCII form, sorted, no repeats, none also denied.
    pub allow: Vec<String>,
    /// Denied hosts, ASCII form, sorted, no repeats.
    pub deny: Vec<String>,
    /// `Realm`, kept but unused.
    realm: String,
}

impl Lists {
    /// Reads the item of `e`: up to 1 MiB, a JSON object, string elements
    /// of `Allow` and `Deny` that can be encoded; a host in both counts as
    /// denied. Anything else counts as absent.
    #[must_use]
    pub fn of(e: &Entry) -> Self {
        let Some(Value::Object(map)) = item(&e.custom_data, SITE_ACCESS)
            .filter(|t| t.len() <= MAX_ITEM)
            .and_then(|t| json::from_str(t).ok())
        else {
            return Self::default();
        };
        let list = |name: &str| -> Vec<String> {
            let mut out: Vec<String> = map
                .get(name)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|h| h.as_str().and_then(ascii))
                        .collect()
                })
                .unwrap_or_default();
            out.sort();
            out.dedup();
            out
        };
        let deny = list("Deny");
        let mut allow = list("Allow");
        allow.retain(|h| deny.binary_search(h).is_err());
        let realm = map
            .get("Realm")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Self { allow, deny, realm }
    }

    /// Adds `hosts` to Allow (`allow`) or Deny, removing them from the
    /// other list (INT-02.16).
    pub fn add(&mut self, hosts: &[String], allow: bool) {
        let (to, from) = if allow {
            (&mut self.allow, &mut self.deny)
        } else {
            (&mut self.deny, &mut self.allow)
        };
        for h in hosts.iter().filter_map(|h| ascii(h)) {
            from.retain(|x| *x != h);
            if !to.contains(&h) {
                to.push(h);
            }
        }
    }

    /// Writes the item into `e` (INT-02.16): compact, `Allow`, `Deny`,
    /// `Realm` in that order, each list sorted, without repeats, at most
    /// [`MAX_SITES`] hosts: past that the first in list order go, so the
    /// hosts just added stay.
    pub fn write(&self, e: &mut Entry, now: Time) {
        let clip = |l: &[String]| -> Value {
            let mut l = l.to_vec();
            l.drain(..l.len().saturating_sub(MAX_SITES));
            l.sort();
            Value::from(l)
        };
        // A JSON object keeps its members in key order; the card's order is
        // written by hand.
        let text = format!(
            "{{\"Allow\":{},\"Deny\":{},\"Realm\":{}}}",
            json::to_string(&clip(&self.allow)),
            json::to_string(&clip(&self.deny)),
            json::to_string(&Value::from(self.realm.as_str()))
        );
        let key = String::from_utf8_lossy(SITE_ACCESS);
        set_item(&mut e.custom_data, &key, text, now);
    }
}

/// An entry's access state for a page (INT-02.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Given without a question.
    Allowed,
    /// Given after the user's Allow.
    Ask,
    /// Never offered or given.
    Denied,
}

impl State {
    /// INT-02.17 for page host `p` and form host `f` (when present and
    /// different): denied when either is in Deny; allowed when `p` is in
    /// Allow and so is `f`, if any; ask otherwise.
    #[must_use]
    pub fn of(lists: &Lists, p: &str, f: Option<&str>) -> Self {
        let deny = |h: &str| lists.deny.iter().any(|d| d == h);
        let allow = |h: &str| lists.allow.iter().any(|a| a == h);
        if deny(p) || f.is_some_and(deny) {
            Self::Denied
        } else if allow(p) && f.is_none_or(allow) {
            Self::Allowed
        } else {
            Self::Ask
        }
    }
}

/// INT-02.2: the name trimmed of spaces at both ends, when it has 1 to 64
/// characters and no control character or line break.
#[must_use]
pub fn valid_name(name: &str) -> Option<&str> {
    let n = name.trim_matches(' ');
    let bad = |c: char| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}');
    (!n.is_empty() && n.chars().count() <= MAX_NAME && !n.chars().any(bad)).then_some(n)
}

/// The association names under which `v` stores the identification key
/// `id` (INT-02.1), in stored order.
#[must_use]
pub fn names(v: &Vault, id: &[u8; 32]) -> Vec<String> {
    let key = base64::encode(Form::Padded, id);
    larsal_core::settings::associations(v)
        .into_iter()
        .filter(|a| a.value == key)
        .map(|a| a.name)
        .collect()
}

/// INT-01.31: base64url, no padding, of the first 16 bytes of SHA-256 over
/// `browser-bridge vault id v1` and the root group id.
#[must_use]
pub fn vault_id(v: &Vault) -> String {
    let d = larsal_crypto::hash::sha256(&[b"browser-bridge vault id v1", &v.root.uuid.0]);
    base64::encode(Form::Url, d.expose().get(..16).unwrap_or_default())
}

/// INT-02.5: the four pairing words of Larsal's session key `app`, the
/// client's `client` and the identification key `id`, lower case, spaces
/// between.
#[must_use]
pub fn pairing_words(app: &[u8; 32], client: &[u8; 32], id: &[u8; 32]) -> String {
    let d = larsal_crypto::hash::sha256(&[b"browser-bridge pairing v1", app, client, id]);
    let mut first = [0u8; 8];
    first.copy_from_slice(d.expose().get(..8).unwrap_or(&[0; 8]));
    let mut n = u64::from_be_bytes(first);
    let list = larsal_core::generator::wordlist::builtin();
    let mut words = Vec::with_capacity(4);
    for _ in 0..4 {
        let at = usize::try_from(n % 7_776).unwrap_or(0);
        words.push(list.get(at).unwrap_or_default().to_lowercase());
        n /= 7_776;
    }
    words.join(" ")
}

/// ISO 8601 UTC, for example `2026-10-28T09:12:00Z` (INT-02.1, INT-02.9).
#[must_use]
pub fn iso(t: Time) -> String {
    t.to_civil().map_or_else(String::new, |c| {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    })
}

/// An entry id on the wire: 32 lower-case hex digits (INT-01.30).
#[must_use]
pub fn entry_id(id: Uuid) -> String {
    id.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// [`entry_id`] read back; `None` for anything but 32 lower-case hex
/// digits.
#[must_use]
pub fn read_entry_id(text: &str) -> Option<Uuid> {
    let b = text.as_bytes();
    if b.len() != 32 || !b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let pair = text.get(i.saturating_mul(2)..i.saturating_mul(2).saturating_add(2))?;
        *o = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(Uuid(out))
}

/// INT-02.9: `_LAST_USED_` + each name in the vault's custom data, and
/// name → time in the entry's `BrowserLastUse` item (compact JSON, names
/// sorted, at most [`MAX_USES`]: the oldest time goes first). A view-state
/// change: no history item, no modification time moves.
pub fn record_use(v: &mut Vault, entry: Uuid, names: &[String], now: Time) {
    let at = iso(now);
    for n in names {
        set_item(
            &mut v.meta.custom_data,
            &format!("{LAST_USED}{n}"),
            at.clone(),
            now,
        );
    }
    let Some(e) = entry_mut(&mut v.root, entry) else {
        return;
    };
    let mut uses: Map = item(&e.custom_data, LAST_USE.as_bytes())
        .filter(|t| t.len() <= MAX_ITEM)
        .and_then(|t| match json::from_str(t) {
            Ok(Value::Object(m)) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    uses.retain(|_, t| t.as_str().is_some());
    for n in names {
        uses.insert(n.clone(), at.as_str().into());
    }
    while uses.len() > MAX_USES {
        // ISO texts of one form sort as their times.
        let oldest = uses
            .iter()
            .min_by(|a, b| a.1.as_str().cmp(&b.1.as_str()))
            .map(|(n, _)| n.clone());
        match oldest {
            Some(n) => {
                uses.remove(&n);
            }
            None => break,
        }
    }
    // The map's members come out sorted by name.
    set_item(
        &mut e.custom_data,
        LAST_USE,
        json::to_string(&Value::Object(uses)),
        now,
    );
}

/// The newest `BrowserLastUse` time of `e` under any of `names`, as its ISO
/// text (INT-02.9, for `logins.recent`).
#[must_use]
pub fn last_use(e: &Entry, names: &[String]) -> Option<String> {
    let text = item(&e.custom_data, LAST_USE.as_bytes()).filter(|t| t.len() <= MAX_ITEM)?;
    let Ok(Value::Object(m)) = json::from_str(text) else {
        return None;
    };
    names
        .iter()
        .filter_map(|n| m.get(n).and_then(Value::as_str))
        .max()
        .map(str::to_owned)
}

/// The live entry `id` below `g`, to change in place.
pub(crate) fn entry_mut(g: &mut larsal_model::Group, id: Uuid) -> Option<&mut Entry> {
    if let Some(at) = g.entries.iter().position(|e| e.uuid == id) {
        return g.entries.get_mut(at);
    }
    g.groups.iter_mut().find_map(|c| entry_mut(c, id))
}
