//! Search (FEA-01, story E4-S8): the query language (`parse`), running it
//! over a vault (`run`) and the saved searches stored in the vault
//! (FEA-01.29).
//!
//! The screen parts (when a search runs, live results, ending a search,
//! the idle timer, the result header) belong to E5-S4; the core gives them
//! [`is_blank`], the built-in queries and the ids.

pub mod parse;
pub mod run;

pub use parse::{MAX_PATTERN_TERMS, MAX_QUERY, QueryError};
pub use run::{Found, Options, RUN_BUDGET, search, search_tags};

use larsal_model::entry::cmp_utf16;
use larsal_model::{CustomDataItem, Time, Vault, json};

/// All Entries (FEA-01.28).
pub const ALL: &str = "*";
/// Expired (FEA-01.28).
pub const EXPIRED: &str = "is:expired";
/// Weak Passwords (FEA-01.28).
pub const WEAK: &str = "is:weak";
/// One-time password entries (FEA-01.28).
pub const TOTP: &str = "has:totp";

/// The query after unlock for MOD-09's day offset (FEA-01.28): always run
/// from the root group.
#[must_use]
pub fn unlock_expired(days: u32) -> String {
    format!("is:expired-{days}")
}

/// True when `query` holds an `is:weak` term (FEA-01.17): the caller fills
/// its strength ratings before the search (`Ratings::fill`), so the run's
/// work bound is not spent on rating (LD-185). A query the parser refuses
/// gives false.
#[must_use]
pub fn rates(query: &str) -> bool {
    parse::parse(query).is_ok_and(|terms| {
        terms.iter().any(|t| {
            t.field == parse::Field::Is && !t.regex && t.value.eq_ignore_ascii_case("weak")
        })
    })
}

/// Text that is empty or white space only ends the search (FEA-01.25).
#[must_use]
pub fn is_blank(text: &str) -> bool {
    text.trim().is_empty()
}

/// The search box text shown for exact tag terms (FEA-01.35): `tag:"T"`
/// per tag, each `"` written `\"`; display only, and what Save stores.
#[must_use]
pub fn tag_display(tags: &[&str]) -> String {
    let mut out = String::new();
    for t in tags {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str("tag:\"");
        out.push_str(&t.replace('"', "\\\""));
        out.push('"');
    }
    out
}

/// The vault custom data key of saved searches (FMT-14), as bytes (name
/// rule).
const SAVED_KEY: [u8; 16] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x53, 0x61, 0x76, 0x65, 0x64, 0x53, 0x65, 0x61, 0x72, 0x63, 0x68,
];

fn saved_key() -> &'static str {
    core::str::from_utf8(&SAVED_KEY).unwrap_or("")
}

/// The saved searches (FEA-01.29): name and query, by name in UTF-16 code
/// unit order. An item that is not a JSON object gives none; members
/// whose value is not text are left out.
#[must_use]
pub fn saved(vault: &Vault) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = read_saved(vault)
        .into_iter()
        .filter_map(|(k, v)| v.as_str().map(|q| (k, q.to_owned())))
        .collect();
    out.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
    out
}

fn read_saved(vault: &Vault) -> json::Map {
    vault
        .meta
        .custom_data
        .get(saved_key())
        .and_then(|text| json::from_str(text).ok())
        .and_then(|v| match v {
            json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default()
}

fn write_saved(vault: &mut Vault, map: json::Map, now: Time) {
    let text = json::to_string_pretty(&json::Value::Object(map));
    let items = &mut vault.meta.custom_data.items;
    match items.iter_mut().find(|i| i.key == saved_key()) {
        Some(item) => {
            item.value = text;
            item.last_modified = Some(now);
        }
        None => items.push(CustomDataItem {
            key: saved_key().to_owned(),
            value: text,
            last_modified: Some(now),
            unknown: Vec::new(),
        }),
    }
}

/// Saves `query` under `name`, replacing a query of that name (FEA-01.29).
/// An empty name saves nothing: `false`. An item that was not a JSON
/// object is replaced by one holding only the new search.
pub fn save(vault: &mut Vault, name: &str, query: &str, now: Time) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut map = read_saved(vault);
    map.insert(name.to_owned(), json::Value::String(query.to_owned()));
    write_saved(vault, map, now);
    true
}

/// Removes the saved search `name`, without a confirm step (FEA-01.29);
/// `false` when there is none.
pub fn remove(vault: &mut Vault, name: &str, now: Time) -> bool {
    let mut map = read_saved(vault);
    if map.remove(name).is_none() {
        return false;
    }
    write_saved(vault, map, now);
    true
}
