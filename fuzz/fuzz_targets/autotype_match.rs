//! Fuzz target `autotype_match` (E8-S2, INT-05.19 to INT-05.27, AT-G03):
//! window matching and the picker model on an arbitrary window title and
//! entry texts. Must never panic or hang; no row has an empty sequence;
//! and two oracles from the bounded pattern engine: a wildcard rule
//! matches exactly when `(?i)\A…\z` with `(?s:.*)` for each `*` does, and
//! an entry title matches exactly when `(?i)` of its escaped text does.
//!
//! Input: the window title, then up to four parts separated by byte 0x1E:
//! a window rule, an entry title, a URL, a sequence. Demo data only.
#![no_main]

use app_autotype::matching::{MAX_TEXT, MAX_TITLE};
use app_autotype::{Open, Picker, Scope, Settings};
use app_core::pattern;
use app_core::time::Utc;
use app_crypto::secret::SecretString;
use app_model::autotype::Association;
use app_model::{Entry, Field, Group, Time, Uuid, Vault};
use libfuzzer_sys::fuzz_target;

const SEPARATOR: u8 = 0x1E;
const A: Uuid = Uuid([0xA; 16]);
const B: Uuid = Uuid([0xB; 16]);

fn set(e: &mut Entry, name: &str, value: &str) {
    e.set_field(
        name.to_owned(),
        Field {
            value: SecretString::new(value.to_owned()),
            protected: false,
        },
    );
}

fn rule(window: &str, sequence: &str) -> Association {
    Association {
        window: window.to_owned(),
        sequence: sequence.to_owned(),
        unknown: Vec::new(),
    }
}

/// `text` as a literal for the pattern engine: its meta characters escaped.
fn literal(out: &mut String, text: &str) {
    for c in text.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
}

fn engine(pattern: &str, title: &str) -> Option<bool> {
    pattern::compile(pattern).map(|re| re.is_match(title))
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&b| b == SEPARATOR);
    let mut next = || String::from_utf8_lossy(parts.next().unwrap_or(&[])).into_owned();
    let (title, window, entry_title, url, sequence) = (next(), next(), next(), next(), next());

    // A: only the window rule. B: only the entry title. C: everything.
    let mut a = Entry::new(A, Time(0));
    a.auto_type.associations = vec![rule(&window, "a")];
    let mut b = Entry::new(B, Time(0));
    set(&mut b, "Title", &entry_title);
    let mut c = Entry::new(Uuid([0xC; 16]), Time(0));
    set(&mut c, "Title", &entry_title);
    set(&mut c, "URL", &url);
    set(&mut c, "UserName", "demo-user");
    set(&mut c, "Site", "Portal");
    c.auto_type.default_sequence = sequence.clone();
    c.auto_type.associations = vec![rule(&window, &sequence), rule("", "{S:Site}")];
    let mut root = Group::new(Uuid([0xF; 16]), "R".into(), Time(0));
    root.entries = vec![a, b, c];
    let v = Vault::new(root, Time(0));
    let vaults = [Open {
        id: 1,
        vault: &v,
        dir: "",
    }];
    let settings = Settings::default();
    let scope = Scope {
        vaults: &vaults,
        now: Time(63_928_466_236),
        zone: &Utc,
        settings: &settings,
    };

    let p = Picker::open(&title, &scope);
    assert!(p.matched().iter().all(|r| !r.sequence.is_empty()));
    assert!(p.single("").is_none(), "always ask is on");
    for text in ["", entry_title.as_str()] {
        let (rows, _) = p.rows(text, &scope);
        assert!(rows.iter().all(|r| !r.sequence.is_empty()));
    }

    let matched = |id: Uuid| p.matched().iter().any(|r| r.entry == id);
    let usable = !title.is_empty() && title.len() <= MAX_TITLE && !p.limited();
    if !usable {
        return;
    }
    // Oracle 1: a plain wildcard rule against the engine.
    let is_pattern =
        window.chars().count() >= 4 && window.starts_with("//") && window.ends_with("//");
    if !window.is_empty() && !window.contains('{') && !is_pattern && window.len() <= MAX_TEXT {
        let mut re = String::from(r"(?i)\A");
        for (i, part) in window.split('*').enumerate() {
            if i > 0 {
                re.push_str("(?s:.*)");
            }
            literal(&mut re, part);
        }
        re.push_str(r"\z");
        if let Some(hit) = engine(&re, &title) {
            assert_eq!(matched(A), hit, "wildcard {window:?} on {title:?}");
        }
    }
    // Oracle 2: the entry title occurs in the window title, case ignored.
    if !entry_title.is_empty() && !entry_title.contains('{') && entry_title.len() <= MAX_TEXT {
        let mut re = String::from("(?i)");
        literal(&mut re, &entry_title);
        if let Some(hit) = engine(&re, &title) {
            assert_eq!(matched(B), hit, "title {entry_title:?} in {title:?}");
        }
    }
});
