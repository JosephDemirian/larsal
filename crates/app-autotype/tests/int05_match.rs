//! INT-05 test cases on the matching and picker-model level (E8-S2): T42
//! to T59, T62 to T65 and T70 to T73 (the Rust halves), T87's defaults,
//! R05-1, R05-5, LD-114, LD-184 (4), LD-186 (2), LD-191 R02-2, and hostile
//! titles and patterns (AT-G03). The panels, the shortcut and the screens
//! are the Swift part. Demo data only: the card's vaults V and W.

use app_autotype::matching::{MAX_TITLE, REMEMBER_DEFAULT};
use app_autotype::{
    Action, Actions, Error, Layout, Memory, Mods, Open, Options, Picker, Row, Scope, Settings,
    actions, check, is_candidate, plan, type_login_enabled,
};
use app_core::edit::{auto_type_on, entry_sequence};
use app_core::refs::{Context, reference};
use app_core::time::Utc;
use app_crypto::secret::SecretString;
use app_model::autotype::Association;
use app_model::times::Civil;
use app_model::{Entry, Field, Group, Switch, Time, Uuid, Vault};
use std::time::{Duration, Instant};

const V: u64 = 1;
const W: u64 = 2;

fn id(n: u8) -> Uuid {
    Uuid([n; 16])
}

const NAMES: [(u8, &str); 12] = [
    (1, "E1"),
    (2, "E2"),
    (3, "E3"),
    (4, "E4"),
    (5, "E5"),
    (6, "E6"),
    (7, "E7"),
    (8, "E8"),
    (9, "E9"),
    (10, "E10"),
    (11, "E11"),
    (0x77, "GW"),
];

fn day(year: i64, month: u32, d: u32) -> Time {
    Time::from_civil(Civil {
        year,
        month,
        day: d,
        hour: 10,
        minute: 0,
        second: 0,
    })
    .unwrap()
}

fn now() -> Time {
    day(2026, 10, 28)
}

fn set(e: &mut Entry, name: &str, value: &str, protected: bool) {
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(value.into()),
            protected,
        },
    );
}

fn entry(n: u8, fields: &[(&str, &str)], rules: &[(&str, &str)]) -> Entry {
    let mut e = Entry::new(id(n), Time(0));
    for (k, v) in fields {
        set(&mut e, k, v, false);
    }
    e.auto_type.associations = rules
        .iter()
        .map(|(w, s)| Association {
            window: (*w).into(),
            sequence: (*s).into(),
            unknown: Vec::new(),
        })
        .collect();
    e
}

fn group(n: u8, name: &str, switch: Switch, seq: &str) -> Group {
    let mut g = Group::new(Uuid([0xA0 | n; 16]), name.into(), Time(0));
    g.auto_type = switch;
    g.default_sequence = seq.into();
    g
}

const BANK_SEQ: &str = "{USERNAME}{ENTER}{DELAY 200}{PASSWORD}{ENTER}";
const E1_SEQ: &str = "{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}";
const DEFAULT: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

/// The card's demo vault V; `edit` may change any entry before it goes in.
fn vault_v(edit: impl Fn(&mut Entry)) -> Vault {
    let mut e1 = entry(
        1,
        &[
            ("Title", "GitHub"),
            ("UserName", "alex-dev"),
            ("Password", "demo-gh-pass-1"),
            ("URL", "https://github.com/login"),
            (
                "otp",
                "otpauth://totp/GitHub:alex-dev?secret=JBSWY3DPEHPK3PXP&period=30&digits=6",
            ),
        ],
        &[
            ("*GitHub*", ""),
            ("Sign in to GitHub · GitHub — Safari", DEFAULT),
        ],
    );
    e1.auto_type.default_sequence = E1_SEQ.into();
    let e2 = entry(
        2,
        &[
            ("Title", "GitHub (work bot)"),
            ("UserName", "morgan-labs-ci"),
            ("Password", "demo-gh-pass-2"),
            ("URL", "https://github.com"),
        ],
        &[("*GitHub*", "")],
    );
    let e3 = entry(
        3,
        &[
            ("Title", "Demo Mail"),
            ("UserName", "demo@mail.example"),
            ("Password", "demo-pass-1"),
            ("URL", "https://mail.example.com"),
        ],
        &[],
    );
    let e4 = entry(4, &[("Title", "Pin only"), ("Password", "4321")], &[]);
    let mut e11 = entry(
        11,
        &[
            ("Title", "GitHub"),
            ("UserName", "old-user"),
            ("Password", "demo-old-gh"),
        ],
        &[],
    );
    e11.auto_type.enabled = false;
    let e5 = entry(
        5,
        &[
            ("Title", "Bank login"),
            ("UserName", "demo-bank"),
            ("Password", "demo-bank-pass"),
        ],
        &[
            ("//BANK1//", "b1{ENTER}"),
            ("//^BANK2$//", "b2"),
            (r"//^BANK3-([ab]\d){2}$//", "b3"),
            ("//(?<=x)BANK//", "bad"),
        ],
    );
    let mut e6 = entry(
        6,
        &[("Title", "Fields"), ("Site", "Portal"), ("Field 2", "two")],
        &[
            ("", "{S:Pin}"),
            ("//^{S:Site}$//", "{S:Site}"),
            ("*Notes app*", ""),
        ],
    );
    set(&mut e6, "Pin", "1234", true);
    let e7 = entry(7, &[("Title", "Hidden")], &[("*GitHub*", "")]);
    let mut e8 = entry(8, &[("Title", "Old Portal"), ("Password", "demo-old")], &[]);
    e8.times.expires = true;
    e8.times.expiry = day(2020, 1, 1);
    let e9 = entry(9, &[("Title", "Binned")], &[("*GitHub*", "")]);
    let e10 = entry(10, &[("Title", "Quiet")], &[]);

    let mut all = [e1, e2, e3, e4, e11, e5, e6, e7, e8, e9, e10];
    all.iter_mut().for_each(&edit);
    let [e1, e2, e3, e4, e11, e5, e6, e7, e8, e9, e10] = all;

    let mut web = group(1, "Web", Switch::Inherit, "");
    web.entries = vec![e1, e2, e3, e4, e11];
    let mut bank = group(2, "Bank", Switch::Inherit, BANK_SEQ);
    bank.entries = vec![e5, e6];
    let mut off = group(3, "Off", Switch::Off, "");
    off.entries = vec![e7];
    let mut quiet = group(4, "Quiet", Switch::On, "");
    quiet.entries = vec![e10];
    let mut off2 = group(5, "Off2", Switch::Off, "");
    off2.groups = vec![quiet];
    let mut s = group(6, "S", Switch::On, "");
    s.entries = vec![e9];
    let mut bin = group(7, "Recycle Bin", Switch::Inherit, "");
    bin.groups = vec![s];
    let bin_id = bin.uuid;
    let mut root = group(0xF, "R", Switch::Inherit, "");
    root.entries = vec![e8];
    root.groups = vec![web, bank, off, off2, bin];
    let mut v = Vault::new(root, Time(0));
    v.meta.recycle_bin = Some(bin_id);
    v
}

fn vault_w() -> Vault {
    let gw = entry(
        0x77,
        &[
            ("Title", "GitHub W"),
            ("UserName", "second-user"),
            ("Password", "demo-second-pass"),
        ],
        &[("*GitHub*", "")],
    );
    let mut root = group(0xE, "R", Switch::Inherit, "");
    root.entries = vec![gw];
    Vault::new(root, Time(0))
}

fn open_v(v: &Vault) -> Open<'_> {
    Open {
        id: V,
        vault: v,
        dir: "",
    }
}

fn scope<'a>(vaults: &'a [Open<'a>], s: &'a Settings) -> Scope<'a> {
    Scope {
        vaults,
        now: now(),
        zone: &Utc,
        settings: s,
    }
}

fn name(r: &Row) -> &'static str {
    NAMES
        .iter()
        .find(|(n, _)| id(*n) == r.entry)
        .map(|(_, s)| *s)
        .unwrap()
}

/// Rows as "E5 b2".
fn labels(rows: &[Row]) -> Vec<String> {
    rows.iter()
        .map(|r| format!("{} {}", name(r), r.sequence))
        .collect()
}

/// The matching rows of V for `title` with `s`.
fn collect_with(v: &Vault, title: &str, s: &Settings) -> Vec<String> {
    let vaults = [open_v(v)];
    labels(Picker::open(title, &scope(&vaults, s)).matched())
}

fn collect(title: &str) -> Vec<String> {
    collect_with(&vault_v(|_| {}), title, &Settings::default())
}

fn entries(rows: &[String]) -> Vec<&str> {
    let mut out: Vec<&str> = rows.iter().map(|r| r.split(' ').next().unwrap()).collect();
    out.dedup();
    out
}

fn ask_off() -> Settings {
    Settings {
        always_ask: false,
        ..Settings::default()
    }
}

#[test]
fn candidates_walk_agrees_with_app_core() {
    // The one-walk inheritance equals MOD-02.14 to MOD-02.16 in app-core.
    let v = vault_v(|_| {});
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let (rows, _) = Picker::open("", &scope(&vaults, &s)).rows("", &scope(&vaults, &s));
    for g in v.root.subtree() {
        for e in &g.entries {
            let in_bin = app_core::recycle::entry_in_bin(&v, e.uuid);
            let candidate =
                !in_bin && e.auto_type.enabled && auto_type_on(&v, g.uuid) == Some(true);
            let eff = entry_sequence(&v, e.uuid);
            let has_eff_row = rows.iter().any(|r| r.entry == e.uuid && r.sequence == eff);
            assert_eq!(has_eff_row, candidate && !eff.is_empty(), "{:?}", e.uuid);
            assert_eq!(
                type_login_enabled(&vaults[0], e.uuid, &s, now()),
                candidate && !eff.is_empty()
            );
        }
    }
}

#[test]
fn t42_candidates() {
    let rows = collect("GitHub");
    assert_eq!(rows, [format!("E1 {E1_SEQ}"), format!("E2 {DEFAULT}")]);
    // None for E11 (flag off), E7 (group Off), E9 (bin).
}

#[test]
fn t43_pattern_types_directly() {
    let v = vault_v(|_| {});
    let vaults = [open_v(&v)];
    let s = ask_off();
    for title in ["lorem BANK1 ipsum", "lorem bank1 ipsum"] {
        let p = Picker::open(title, &scope(&vaults, &s));
        let row = p.single("").unwrap();
        assert_eq!((name(row), row.sequence.as_str()), ("E5", "b1{ENTER}"));
        let layout = Layout::new([('b', 0x0B)]);
        let o = Options {
            layout: &layout,
            shortcut: None,
            start_delay_ms: 500,
            key_pause_ms: 25,
        };
        let e5 = v.root.groups[1].entries.first().unwrap();
        let plan = plan(&row.sequence, e5, &Context::new(Some(&v), now()), &o).unwrap();
        match plan.actions() {
            [
                Action::Text { text: b, .. },
                Action::Text { text: one, .. },
                Action::Key { code, mods },
            ] => {
                assert_eq!((b.expose(), one.expose()), ("b", "1"));
                assert_eq!((*code, *mods), (0x24, Mods::NONE));
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn t44_anchored_pattern() {
    assert_eq!(collect("BANK2"), ["E5 b2"]);
    assert!(collect("xBANK2").is_empty());
}

#[test]
fn t45_case_ignored_inside_the_pattern() {
    assert_eq!(collect("BANK3-A1B2"), ["E5 b3"]);
}

#[test]
fn t46_lookbehind_matches_nothing() {
    assert!(collect("xBANK").is_empty());
}

#[test]
fn t47_resolved_pattern_and_empty_window_rule() {
    assert_eq!(collect("Portal"), ["E6 {S:Site}", "E6 {S:Pin}"]);
    assert!(collect("Portal 2").is_empty());
}

#[test]
fn t48_wildcard_whole_title_and_entry_sequence() {
    assert_eq!(
        collect("My notes APP"),
        [format!("E6 {BANK_SEQ}"), "E6 {S:Pin}".into()]
    );
    assert!(collect("Notes").is_empty());
}

#[test]
fn t49_only_star_is_special() {
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = vec![entry(
        1,
        &[("Title", "X entry")],
        &[("a?c", "q"), ("a.c", "d"), ("a+b", "p")],
    )];
    let v = Vault::new(root, Time(0));
    let s = Settings::default();
    let hits: Vec<(&str, Vec<String>)> = ["a?c", "abc", "a.c", "a+b", "aab"]
        .into_iter()
        .map(|t| (t, collect_with(&v, t, &s)))
        .collect();
    assert_eq!(
        hits,
        [
            ("a?c", vec!["E1 q".to_owned()]),
            ("abc", vec![]),
            ("a.c", vec!["E1 d".to_owned()]),
            ("a+b", vec!["E1 p".to_owned()]),
            ("aab", vec![]),
        ]
    );
}

#[test]
fn t50_empty_pattern_matches_every_title() {
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = vec![entry(1, &[("Title", "X")], &[("////", "z")])];
    let v = Vault::new(root, Time(0));
    assert_eq!(
        collect_with(&v, "anything at all", &Settings::default()),
        ["E1 z"]
    );
}

#[test]
fn t51_title_match_setting() {
    let v = vault_v(|_| {});
    assert_eq!(
        collect_with(&v, "Demo Mail – Inbox", &Settings::default()),
        [format!("E3 {DEFAULT}")]
    );
    let off = Settings {
        by_title: false,
        ..Settings::default()
    };
    assert!(collect_with(&v, "Demo Mail – Inbox", &off).is_empty());
}

#[test]
fn t52_url_and_host_in_the_title() {
    for title in [
        "Inbox – mail.example.com",
        "https://mail.example.com - Inbox",
    ] {
        assert_eq!(collect(title), [format!("E3 {DEFAULT}")], "{title}");
    }
    let off = Settings {
        by_url: false,
        ..Settings::default()
    };
    assert!(collect_with(&vault_v(|_| {}), "Inbox – mail.example.com", &off).is_empty());
}

#[test]
fn t53_sequence_order_and_repeats() {
    assert_eq!(
        collect("Sign in to GitHub · GitHub — Safari"),
        [
            format!("E1 {E1_SEQ}"),
            format!("E1 {DEFAULT}"),
            format!("E2 {DEFAULT}")
        ]
    );
}

#[test]
fn t54_empty_window_rule_alone_does_not_match() {
    assert!(collect("Unrelated").is_empty());
}

#[test]
fn t55_empty_effective_sequence() {
    let v = vault_v(|_| {});
    assert!(collect_with(&v, "Quiet", &Settings::default()).is_empty());
    let s = Settings::default();
    assert!(!type_login_enabled(&open_v(&v), id(10), &s, now()));
    assert!(type_login_enabled(&open_v(&v), id(3), &s, now()));
    // R05-1: a window rule with its own sequence still gives a row.
    let v = vault_v(|e| {
        if e.uuid == id(10) {
            e.auto_type.associations.push(Association {
                window: "*Quiet*".into(),
                sequence: "{PASSWORD}".into(),
                unknown: Vec::new(),
            });
        }
    });
    assert_eq!(collect_with(&v, "Quiet", &s), ["E10 {PASSWORD}"]);
    assert!(!type_login_enabled(&open_v(&v), id(10), &s, now()));
    // Its row can be typed: E10 stays a candidate; E7 (group Off) is not.
    assert!(is_candidate(&open_v(&v), id(10), &s, now()));
    assert!(!is_candidate(&open_v(&v), id(7), &s, now()));
}

#[test]
fn t56_expired_entries() {
    let v = vault_v(|_| {});
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let p = Picker::open("Old Portal", &scope(&vaults, &s));
    assert_eq!(labels(p.matched()), ["E8 {PASSWORD}{ENTER}"]);
    assert!(p.matched()[0].expired);
    let skip = Settings {
        skip_expired: true,
        ..Settings::default()
    };
    assert!(collect_with(&v, "Old Portal", &skip).is_empty());
}

#[test]
fn t57_empty_title_lists_every_candidate() {
    let v = vault_v(|_| {});
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let p = Picker::open("", &scope(&vaults, &s));
    assert!(p.matched().is_empty());
    assert_eq!(p.single(""), None);
    let (rows, limited) = p.rows("", &scope(&vaults, &s));
    assert!(!limited);
    let labelled = labels(&rows);
    let mut seen = entries(&labelled);
    seen.sort_unstable();
    seen.dedup();
    // Every candidate with a sequence; E10's is empty (R05-1).
    assert_eq!(seen, ["E1", "E2", "E3", "E4", "E5", "E6", "E8"]);
    // E5: its sequence and each distinct one of its window rules.
    let e5: Vec<&str> = rows
        .iter()
        .filter(|r| r.entry == id(5))
        .map(|r| r.sequence.as_str())
        .collect();
    assert_eq!(e5.len(), 5);
    assert!(e5.contains(&BANK_SEQ) && e5.contains(&"bad"));
}

#[test]
fn t58_t59_always_ask_off() {
    let v = vault_v(|_| {});
    let vaults = [open_v(&v)];
    let s = ask_off();
    let p = Picker::open("Inbox – mail.example.com", &scope(&vaults, &s));
    let row = p.single("").unwrap();
    assert_eq!((name(row), row.sequence.as_str()), ("E3", DEFAULT));
    // T59: several rows open the picker.
    assert_eq!(Picker::open("GitHub", &scope(&vaults, &s)).single(""), None);
    // S-AT-03 on (the default) always opens it.
    let on = Settings::default();
    let p = Picker::open("Inbox – mail.example.com", &scope(&vaults, &on));
    assert_eq!(p.single(""), None);
}

#[test]
fn t62_rows_from_every_unlocked_vault() {
    let (v, w) = (vault_v(|_| {}), vault_w());
    let vaults = [
        open_v(&v),
        Open {
            id: W,
            vault: &w,
            dir: "",
        },
    ];
    let s = Settings::default();
    let p = Picker::open("GitHub", &scope(&vaults, &s));
    let found: Vec<(u64, &str)> = p.matched().iter().map(|r| (r.vault, name(r))).collect();
    assert_eq!(found, [(V, "E1"), (V, "E2"), (W, "GW")]);
}

#[test]
fn t63_t65_picker_rows_sorted_and_highlighted() {
    let v = vault_v(|_| {});
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let sc = scope(&vaults, &s);
    let p = Picker::open("Sign in to GitHub · GitHub — Safari", &sc);
    let (rows, _) = p.rows("", &sc);
    let shown: Vec<(&str, &str)> = rows
        .iter()
        .map(|r| (r.title.as_str(), r.username.as_str()))
        .collect();
    assert_eq!(
        shown,
        [
            ("GitHub", "alex-dev"),
            ("GitHub", "alex-dev"),
            ("GitHub (work bot)", "morgan-labs-ci")
        ]
    );
    assert_eq!(Memory::default().highlight(&rows, Instant::now()), 0);
    // T65: sorted by title, `GitHub` before `GitHub (work bot)`.
    let (rows, _) = Picker::open("GitHub", &sc).rows("", &sc);
    assert_eq!(name(&rows[0]), "E1");
    assert_eq!(name(&rows[1]), "E2");
}

#[test]
fn t64_search_text_searches_every_entry() {
    let v = vault_v(|_| {});
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let sc = scope(&vaults, &s);
    let p = Picker::open("GitHub", &sc);
    let (rows, _) = p.rows("mail", &sc);
    assert_eq!(labels(&rows), [format!("E3 {DEFAULT}")]);
    // A found entry with matching rows shows those; bin and Off entries
    // never show.
    let (rows, _) = p.rows("GitHub", &sc);
    assert_eq!(entries(&labels(&rows)), ["E1", "E2"]);
    // SI-12: a search text always opens the picker.
    let p = Picker::open("Inbox – mail.example.com", &scope(&vaults, &ask_off()));
    assert!(p.single("mail").is_none());
    assert!(p.single("").is_some());
}

#[test]
fn t70_t73_preselect_the_previous_choice() {
    let v = vault_v(|_| {});
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let sc = scope(&vaults, &s);
    let (rows, _) = Picker::open("GitHub", &sc).rows("", &sc);
    let e2 = rows.iter().find(|r| r.entry == id(2)).unwrap();
    let t0 = Instant::now();
    let after = |secs| t0 + Duration::from_secs(secs);

    // T70: remembered for 15 s.
    let mut m = Memory::default();
    m.remember(e2, s.remember_secs, t0);
    assert_eq!(m.highlight(&rows, after(10)), 1);
    assert_eq!(m.highlight(&rows, after(16)), 0);
    assert_eq!(m.until(), Some(after(15)));
    // The same entry with another sequence: its first row.
    let other = Row {
        sequence: "x".into(),
        ..e2.clone()
    };
    let mut m2 = Memory::default();
    m2.remember(&other, 15, t0);
    assert_eq!(m2.highlight(&rows, after(1)), 1);

    // T71: S-AT-08 = 0 remembers nothing.
    let mut m = Memory::default();
    m.remember(e2, 0, t0);
    assert_eq!(m.highlight(&rows, after(1)), 0);
    assert_eq!(m.until(), None);
    // Used up to 60 s.
    m.remember(e2, 600, t0);
    assert_eq!(m.until(), Some(after(60)));

    // T72: typing a single match remembers nothing (the caller only
    // remembers picker choices), so a later picker starts at the top.
    let one = Picker::open("Inbox – mail.example.com", &scope(&vaults, &ask_off()));
    assert!(one.single("").is_some());
    assert_eq!(Memory::default().highlight(&rows, after(5)), 0);

    // T73: a lock drops it.
    let mut m = Memory::default();
    m.remember(e2, 15, t0);
    m.forget_vault(W);
    assert_eq!(m.highlight(&rows, after(1)), 1);
    m.forget_vault(V);
    assert_eq!(m.highlight(&rows, after(1)), 0);
}

#[test]
fn t87_settings_defaults() {
    let s = Settings::default();
    assert!(s.by_title && s.by_url && s.always_ask);
    assert!(!s.skip_expired && !s.dont_ask_from_window);
    assert_eq!(s.remember_secs, REMEMBER_DEFAULT);
    assert_eq!(REMEMBER_DEFAULT, 15);
    // T79, T81: Type Login asks unless S-AT-03 is off or S-AT-04 on.
    assert!(s.asks_from_window());
    assert!(!ask_off().asks_from_window());
    let no_window = Settings {
        dont_ask_from_window: true,
        ..Settings::default()
    };
    assert!(!no_window.asks_from_window());
}

#[test]
fn r05_5_host_in_both_forms() {
    let mk = |url: &str| {
        let mut root = group(1, "R", Switch::Inherit, "");
        root.entries = vec![entry(
            1,
            &[("Title", "Shop"), ("UserName", "u"), ("URL", url)],
            &[],
        )];
        Vault::new(root, Time(0))
    };
    let off = Settings {
        by_title: false,
        ..Settings::default()
    };
    for (url, title) in [
        ("https://bücher.example/", "Shop – bücher.example"),
        ("https://bücher.example/", "Shop – BÜCHER.EXAMPLE"),
        ("https://bücher.example/", "Shop – xn--bcher-kva.example"),
        ("https://xn--bcher-kva.example/", "Shop – bücher.example"),
    ] {
        assert_eq!(
            collect_with(&mk(url), title, &off).len(),
            1,
            "{url} {title}"
        );
    }
    assert!(
        collect_with(
            &mk("https://bücher.example/"),
            "Shop – bucher.example",
            &off
        )
        .is_empty()
    );
    // A URL without a scheme has no host: only the URL itself counts.
    assert!(collect_with(&mk("mail.example.com/x"), "mail.example.com", &off).is_empty());
}

#[test]
fn ld114_no_protected_value_in_a_pattern() {
    let v = vault_v(|e| {
        if e.uuid == id(3) {
            e.auto_type.associations.push(Association {
                window: "//{PASSWORD}//".into(),
                sequence: "p".into(),
                unknown: Vec::new(),
            });
            e.auto_type.associations.push(Association {
                window: "*{PASSWORD}*".into(),
                sequence: "w".into(),
                unknown: Vec::new(),
            });
        }
    });
    let off = Settings {
        by_title: false,
        by_url: false,
        ..Settings::default()
    };
    // The wildcard may use the password (it never reaches the engine);
    // the pattern built from it matches nothing.
    assert_eq!(collect_with(&v, "x demo-pass-1 y", &off), ["E3 w"]);
}

#[test]
fn r02_2_rows_hold_no_secret() {
    let v = vault_v(|e| match e.uuid {
        u if u == id(3) => {
            set(e, "Title", "Mail {S:Pin}", false);
            set(e, "UserName", "{PASSWORD}", false);
            set(e, "Pin", "9876", true);
        }
        u if u == id(4) => {
            set(e, "Title", "Pin only", true);
            set(e, "UserName", "{S:Site}", false);
            set(e, "Site", "Portal", false);
        }
        _ => {}
    });
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let sc = scope(&vaults, &s);
    let (rows, _) = Picker::open("", &sc).rows("", &sc);
    let e3 = rows.iter().find(|r| r.entry == id(3)).unwrap();
    assert_eq!((e3.title.as_str(), e3.title_hidden), ("", true));
    assert_eq!((e3.username.as_str(), e3.username_hidden), ("", true));
    let e4 = rows.iter().find(|r| r.entry == id(4)).unwrap();
    assert_eq!((e4.title.as_str(), e4.title_hidden), ("", true));
    assert_eq!(
        (e4.username.as_str(), e4.username_hidden),
        ("Portal", false)
    );
    let all = format!("{rows:?}");
    for secret in ["9876", "demo-pass-1", "4321", "demo-gh-pass", "1234"] {
        assert!(!all.contains(secret), "{secret}");
    }
}

#[test]
fn ld184_4_editor_check_with_the_vaults_own_entry() {
    let v = vault_v(|_| {});
    let seq = reference('U', id(3));
    let layout = Layout::default();
    let o = Options {
        layout: &layout,
        shortcut: None,
        start_delay_ms: 500,
        key_pause_ms: 25,
    };
    let ctx = Context::new(Some(&v), now());
    let own = &v.root.groups[0].entries[0];
    assert_eq!(check(&seq, own, &ctx, &o), Ok(()));
    // A copy (the editor's draft) is not the vault's entry: MOD-08.29
    // keeps the reference as written, so the check would refuse it.
    let draft = own.duplicate(false);
    assert_eq!(check(&seq, &draft, &ctx, &o).unwrap_err().id(), "MI05-19");
}

#[test]
fn ld186_2_zero_waits_and_pauses_count() {
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = vec![entry(1, &[], &[])];
    let v = Vault::new(root, Time(0));
    let layout = Layout::default();
    let o = Options {
        layout: &layout,
        shortcut: None,
        start_delay_ms: 500,
        key_pause_ms: 25,
    };
    let ctx = Context::new(Some(&v), now());
    let e = &v.root.entries[0];
    for token in ["{DELAY 0}", "{DELAY=0}", "{DELAY= 5}"] {
        let p = plan(&token.repeat(10_000), e, &ctx, &o).unwrap();
        assert_eq!(p.keys(), 10_000, "{token}");
        assert_eq!(
            plan(&token.repeat(10_001), e, &ctx, &o).unwrap_err(),
            Error::TooManyKeys,
            "{token}"
        );
    }
    let mixed = format!("{}{}", "{TAB 100}".repeat(99), "{DELAY 0}".repeat(101));
    assert_eq!(plan(&mixed, e, &ctx, &o).unwrap_err(), Error::TooManyKeys);
}

// --- Hostile titles and patterns (AT-G03) ---

/// Runs `f`, prints how long it took (`--nocapture`), and fails past
/// `limit_ms` of this thread's CPU time (F-090, F-092: work, not the wait
/// for a core on a busy Mac).
fn timed<T>(what: &str, limit_ms: u64, f: impl FnOnce() -> T) -> T {
    let start = app_platform::macos::thread_cpu_time();
    let out = f();
    let took = app_platform::macos::thread_cpu_time() - start;
    eprintln!("{what}: {took:?}");
    assert!(
        took < Duration::from_millis(limit_ms),
        "{what} took {took:?}"
    );
    out
}

#[test]
fn hostile_catastrophic_looking_patterns() {
    let rules = [
        "//(a+)+$b//",
        "//(a|aa)*b//",
        "//(.*a){12}b//",
        "//((a*)*)*b//",
        "//(x+x+)+y//",
        "//^(a?){25}a{25}b$//",
        "//(a{1,100}){1,100}b//",
        "//[\\x{0}-\\x{10FFFF}]{1,500}b//",
    ];
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = rules
        .iter()
        .enumerate()
        .map(|(n, r)| entry(n as u8 + 1, &[("Title", "T")], &[(r, "s")]))
        .collect();
    let v = Vault::new(root, Time(0));
    let vaults = [open_v(&v)];
    let s = Settings::default();
    for title in ["a".repeat(MAX_TITLE), "a".repeat(30)] {
        let what = format!("8 hostile patterns, {}-byte title", title.len());
        let p = timed(&what, 1_000, || Picker::open(&title, &scope(&vaults, &s)));
        assert!(p.matched().is_empty(), "no pattern ends in b");
        assert!(!p.limited());
    }
}

#[test]
fn hostile_huge_title_and_texts() {
    let mib = "GitHub ".repeat(150_000);
    let v = vault_v(|e| {
        if e.uuid == id(3) {
            set(e, "Title", &mib, false);
            set(e, "URL", &format!("https://x/{{S:Site}}{mib}"), false);
            e.auto_type.associations.push(Association {
                window: format!("*{mib}"),
                sequence: "w".into(),
                unknown: Vec::new(),
            });
            e.auto_type.associations.push(Association {
                window: format!("//{mib}//"),
                sequence: "p".into(),
                unknown: Vec::new(),
            });
        }
    });
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let sc = scope(&vaults, &s);
    // A 1 MB title is not matched (as an empty title): the picker lists
    // every candidate.
    let p = timed("1 MB title", 1_000, || Picker::open(&mib, &sc));
    assert!(p.matched().is_empty());
    let (rows, limited) = timed("every candidate, a 1 MB entry title", 1_000, || {
        p.rows("", &sc)
    });
    assert!(!limited);
    let e3 = rows.iter().find(|r| r.entry == id(3)).unwrap();
    assert_eq!(
        e3.title.chars().count(),
        1_024,
        "titles are cut for display"
    );
    // A 1 MB entry title, URL and window texts against a normal title.
    let p = timed("1 MB entry title, URL and window texts", 1_000, || {
        Picker::open("GitHub", &sc)
    });
    assert_eq!(entries(&labels(p.matched())), ["E1", "E2"]);
    assert!(!p.limited());
}

#[test]
fn hostile_many_distinct_patterns_run_out_of_meter() {
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = (0..2_000u32)
        .map(|n| {
            let b = n.to_le_bytes();
            let mut e = Entry::new(
                Uuid([b[0], b[1], 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]),
                Time(0),
            );
            // Valid and distinct: each is compiled once and charged.
            e.auto_type.associations.push(Association {
                window: format!("//z{n}(a|b)+q//"),
                sequence: "s".into(),
                unknown: Vec::new(),
            });
            e
        })
        .collect();
    let v = Vault::new(root, Time(0));
    let vaults = [open_v(&v)];
    let s = ask_off();
    let p = timed("2,000 distinct patterns", 1_000, || {
        Picker::open("a title with z1 in it", &scope(&vaults, &s))
    });
    assert!(p.limited(), "the meter stops the run");
    assert!(
        p.single("").is_none(),
        "a limited run always opens the picker"
    );
}

#[test]
fn hostile_ten_thousand_entries_stay_fast() {
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = (0..10_000u32)
        .map(|n| {
            let b = n.to_le_bytes();
            let mut e = entry(0, &[], &[(&format!("*Site {n} —*"), "")]);
            e.uuid = Uuid([b[0], b[1], 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]);
            set(&mut e, "Title", &format!("Entry {n}"), false);
            set(&mut e, "UserName", "user", false);
            set(
                &mut e,
                "URL",
                &format!("https://site{n}.example.com/login"),
                false,
            );
            e
        })
        .collect();
    let v = Vault::new(root, Time(0));
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let sc = scope(&vaults, &s);
    let p = timed("10,000 entries, one match", 1_000, || {
        Picker::open("Site 4242 — Sign in · site4242.example.com", &sc)
    });
    assert_eq!(p.matched().len(), 1);
    assert!(!p.limited());
    let (rows, limited) = timed("its rows", 1_000, || p.rows("", &sc));
    assert_eq!((rows.len(), limited), (1, false));
    let (rows, limited) = timed("10,000 entries, every candidate", 1_000, || {
        Picker::open("", &sc).rows("", &sc)
    });
    assert_eq!((rows.len(), limited), (10_000, false));
}

#[test]
fn ld196_2_limited_run_never_types_directly() {
    // A cheap single match first, then titles that resolve to more than
    // MOD-08's 1,048,576-character bound and window texts that grow: every
    // entry costs real work until the meter stops the run.
    let big = "x".repeat(60_000);
    let mut root = group(1, "R", Switch::Inherit, "");
    let victim = entry(1, &[("Title", "Victim"), ("UserName", "v")], &[]);
    root.entries = core::iter::once(victim)
        .chain((0..5_000u32).map(|n| {
            let b = n.to_le_bytes();
            let mut e = entry(0, &[("Big", &big)], &[("*{S:Big}{S:Big}*", "")]);
            e.uuid = Uuid([b[0], b[1], 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]);
            set(&mut e, "Title", &"{S:Big}".repeat(100), false);
            set(&mut e, "URL", &"{S:Big}".repeat(100), false);
            e
        }))
        .collect();
    let v = Vault::new(root, Time(0));
    let vaults = [open_v(&v)];
    let s = ask_off();
    let p = timed("5,000 entries of growing texts", 1_000, || {
        Picker::open("Victim here", &scope(&vaults, &s))
    });
    assert_eq!(labels(p.matched()), ["E1 {USERNAME}{ENTER}"]);
    assert!(p.limited());
    assert_eq!(p.single(""), None, "a limited run always opens the picker");
}

#[test]
fn ld196_3_wildcard_last_part_ends_the_title() {
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = vec![entry(1, &[("Title", "X")], &[("*Hub", "h")])];
    let v = Vault::new(root, Time(0));
    let s = Settings::default();
    assert!(collect_with(&v, "GitHub Desktop", &s).is_empty());
    assert_eq!(collect_with(&v, "GitHub", &s), ["E1 h"]);
}

#[test]
fn ld196_1_no_one_time_password_or_passkey_in_rows() {
    let pass = "demo-ck-secret-77";
    let mut target = entry(50, &[("Title", "T"), ("UserName", "tu")], &[]);
    set(&mut target, "Password", "ref-target-pass", true);
    let r: String = target.uuid.0.iter().map(|b| format!("{b:02X}")).collect();
    let titled = |n: u8, title: &str| {
        let mut e = entry(n, &[("Title", title)], &[("*Match*", "")]);
        set(&mut e, "Password", pass, true);
        e
    };
    let mut otp = titled(60, "{S:otp}");
    set(
        &mut otp,
        "otp",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
        false,
    );
    set(&mut otp, "UserName", "plain-user", false);
    let mut seed = titled(63, "Seed {S:TOTP Seed}");
    set(&mut seed, "TOTP Seed", "GEZDGNBVGY3TQOJQ", false);
    set(&mut seed, "UserName", "{S:TimeOtp-Secret-Base32}", false);
    set(
        &mut seed,
        "TimeOtp-Secret-Base32",
        "MFRGGZDFMZTWQ2LK",
        false,
    );
    let mut passkey = titled(64, "Key {S:KPEX_PASSKEY_PRIVATE_KEY}");
    set(
        &mut passkey,
        "KPEX_PASSKEY_PRIVATE_KEY",
        "demo-passkey-pem",
        false,
    );
    let mut pin = titled(61, "Pin {S:Pin}");
    set(&mut pin, "UserName", "{PASSWORD}", false);
    set(&mut pin, "Pin", "9876", true);
    let mut prot_user = titled(62, "PU");
    set(&mut prot_user, "UserName", "secret-user-1", true);
    let mut fine = titled(56, "Fine {USERNAME}");
    set(&mut fine, "UserName", "ok-user", false);
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = vec![
        target,
        titled(51, "{PASSWORD}"),
        titled(52, &format!("{{REF:P@I:{r}}}")),
        titled(53, "{T-CONV:/{PASSWORD}/upper/}"),
        titled(54, "{T-REPLACE-RX:/{PASSWORD}/demo/x/}"),
        titled(55, "{PASSWORD}{PASSWORD}{PASSWORD}"),
        fine,
        otp,
        seed,
        passkey,
        pin,
        prot_user,
    ];
    let v = Vault::new(root, Time(0));
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let sc = scope(&vaults, &s);
    let p = Picker::open("Match", &sc);
    let (listed, _) = p.rows("", &sc);
    let (all, _) = Picker::open("zzz", &sc).rows("", &sc);
    for row in p.matched().iter().chain(&listed).chain(&all) {
        let dbg = format!("{row:?}");
        for bad in [
            pass,
            "DEMO-CK-SECRET-77",
            "ref-target-pass",
            "9876",
            "secret-user-1",
            "JBSWY3DPEHPK3PXP",
            "GEZDGNBVGY3TQOJQ",
            "MFRGGZDFMZTWQ2LK",
            "demo-passkey-pem",
        ] {
            assert!(!dbg.contains(bad), "{bad} in {dbg}");
        }
    }
    let by = |n: u8| p.matched().iter().find(|r| r.entry == id(n)).unwrap();
    for n in [51, 52, 53, 54, 55, 60, 61, 63, 64] {
        assert!(by(n).title_hidden && by(n).title.is_empty(), "{n}");
    }
    assert_eq!(
        (by(60).username.as_str(), by(60).username_hidden),
        ("plain-user", false)
    );
    for n in [61, 62, 63] {
        assert!(by(n).username_hidden && by(n).username.is_empty(), "{n}");
    }
    assert_eq!(
        (by(56).title.as_str(), by(56).title_hidden),
        ("Fine ok-user", false)
    );
}

#[test]
fn ld196_sort_ignores_case_before_user_name() {
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = vec![
        entry(2, &[("Title", "GitHub"), ("UserName", "b")], &[]),
        entry(1, &[("Title", "github"), ("UserName", "a")], &[]),
        entry(3, &[("Title", "GitHub"), ("UserName", "a")], &[]),
    ];
    let v = Vault::new(root, Time(0));
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let sc = scope(&vaults, &s);
    let (rows, _) = Picker::open("GitHub", &sc).rows("", &sc);
    // Case only breaks the last tie: E3 (`GitHub`, `a`) before E1
    // (`github`, `a`), both before E2 (`GitHub`, `b`).
    assert_eq!(entries(&labels(&rows)), ["E3", "E1", "E2"]);
}

#[test]
fn ld196_actions_of_an_entry() {
    let v = vault_v(|_| {});
    let o = open_v(&v);
    let s = Settings::default();
    let of = |n: u8| actions(&o, id(n), &s, now());
    let all = Actions {
        type_login: true,
        username_only: true,
        password_only: true,
    };
    assert_eq!(of(3), all);
    // E4: no user name; E10: empty sequence and no fields (R05-1).
    assert_eq!(
        of(4),
        Actions {
            username_only: false,
            ..all
        }
    );
    assert_eq!(of(10), Actions::default());
    // Not candidates: flag off, group Off, bin.
    for n in [11, 7, 9] {
        assert_eq!(of(n), Actions::default(), "E{n}");
    }
}

/// F-130 (LD-242 (1)): a row's title is hidden when its display resolution
/// reads a protected value, by the resolution's masked flag, not a text
/// compare: a transform that gives the same text for the value and the mask,
/// and a reference search over a protected password, both stay hidden; a
/// search over plain titles shows.
#[test]
fn f_130_reads_protected_uses_the_masked_flag() {
    let titled = |n: u8, title: &str| entry(n, &[("Title", title)], &[("*Match*", "")]);
    let mut target = titled(1, "Target");
    set(&mut target, "Password", "demo-s", true);
    let mut rx = titled(2, "{T-REPLACE-RX:/{PASSWORD}/^.{6}$/six/}");
    set(&mut rx, "Password", "demo-s", true);
    let mut root = group(1, "R", Switch::Inherit, "");
    root.entries = vec![
        target,
        rx,
        titled(3, "{REF:T@P:demo-s}"),
        titled(4, "{REF:T@T:Target}"),
        titled(5, "{REF:T@P:wrong}"),
    ];
    let v = Vault::new(root, Time(0));
    let vaults = [open_v(&v)];
    let s = Settings::default();
    let sc = scope(&vaults, &s);
    let p = Picker::open("Match", &sc);
    let by = |n: u8| p.matched().iter().find(|r| r.entry == id(n)).unwrap();
    // 5: a wrong guess is hidden too, so a right and a wrong guess look alike
    for n in [2, 3, 5] {
        assert!(by(n).title_hidden && by(n).title.is_empty(), "{n}");
    }
    assert_eq!(
        (by(4).title.as_str(), by(4).title_hidden),
        ("Target", false)
    );
}
