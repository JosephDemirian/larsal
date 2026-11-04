//! Story E4-S11, card FEA-05: strength estimate and Health Check. One test
//! per case (`fea05_NN_…`), 05-01 to 05-31, plus the edge cases and the
//! `zxcvbn` crate checks of the story (guess cap, 100-character reading,
//! no panic on long keyboard walks).
//!
//! Where a case gives "E = …", a stub estimator returns that value, as the
//! card says. "Now" is 2026-10-25 12:00, UTC unless stated. The screens
//! (E5-S5 to E5-S8) own drawing; their values are tested here.

mod common;

use app_core::expiry::expire_now;
use app_core::health::{
    self, ALL_HEALTHY, Detail, Level, MasterGate, Ratings, Reason, Report, Row, bits_with,
    entry_bits, entry_bits_with, generator_display, health_check, indicator, meter, score,
    sort_key, strength_reasons, zxcvbn_bits,
};
use app_core::recycle;
use app_core::refs::{self, Context};
use app_core::search::{Options, search};
use app_core::settings::{self, Changes, KeyChange, PasswordPart, Refusal};
use app_core::time::{Instant, Utc, Zone};
use app_crypto::secret::SecretString;
use app_model::{Entry, Field, Group, Time, Uuid, Vault};
use common::{Fixed, at};
use std::cell::RefCell;

fn uid(b: u8) -> Uuid {
    Uuid([b; 16])
}

fn now() -> Instant {
    Instant::from(at(2026, 10, 25, 12, 0, 0))
}

fn set(e: &mut Entry, name: &str, value: &str) {
    e.set_field(
        name.to_owned(),
        Field {
            value: SecretString::new(value.to_owned()),
            protected: name == "Password",
        },
    );
}

fn ent(b: u8, title: &str, pw: &str) -> Entry {
    let mut e = Entry::new(uid(b), at(2026, 1, 1, 0, 0, 0));
    set(&mut e, "Title", title);
    set(&mut e, "Password", pw);
    e
}

fn grp(b: u8, name: &str) -> Group {
    Group::new(uid(b), name.into(), at(2026, 1, 1, 0, 0, 0))
}

fn vault(root: Group) -> Vault {
    let mut v = Vault::new(root, at(2026, 1, 1, 0, 0, 0));
    v.meta.recycle_bin_enabled = false;
    v
}

/// A stub estimator from a table; unknown passwords rate 0.
fn table(rows: &'static [(&'static str, f64)]) -> impl Fn(&str, &[&str]) -> f64 {
    move |pw: &str, _: &[&str]| rows.iter().find(|(p, _)| *p == pw).map_or(0.0, |r| r.1)
}

fn check(est: &dyn Fn(&str, &[&str]) -> f64, v: &Vault) -> Report {
    health_check(&Ratings::new(est), v, now(), &Utc)
}

fn titles(rows: &[&Row]) -> Vec<String> {
    rows.iter().map(|r| r.title.clone()).collect()
}

fn reason_texts(r: &Row) -> Vec<String> {
    r.reasons.iter().map(Reason::text).collect()
}

fn ymd(t: Time) -> String {
    let c = t.to_civil().unwrap();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        c.year, c.month, c.day, c.hour, c.minute
    )
}

fn detail_texts(r: &Row) -> Vec<String> {
    r.details.iter().map(|d| d.text(&ymd)).collect()
}

#[test]
fn fea05_01_levels() {
    let want = [
        (-25, Level::Bad),
        (0, Level::Bad),
        (1, Level::Poor),
        (39, Level::Poor),
        (40, Level::Weak),
        (74, Level::Weak),
        (75, Level::Good),
        (99, Level::Good),
        (100, Level::Excellent),
        (250, Level::Excellent),
    ];
    for (s, l) in want {
        assert_eq!(Level::of(s), l, "{s}");
    }
}

#[test]
fn fea05_02_floor() {
    for (e, s, l) in [
        (39.99, 39, Level::Poor),
        (74.5, 74, Level::Weak),
        (100.0, 100, Level::Excellent),
    ] {
        assert_eq!((score(e), Level::of(score(e))), (s, l), "{e}");
    }
}

/// A stub that records each call: the password and the user inputs.
struct Recorder {
    calls: RefCell<Vec<(String, Vec<String>)>>,
    value: f64,
}

impl Recorder {
    fn new(value: f64) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            value,
        }
    }
    fn est(&self) -> impl Fn(&str, &[&str]) -> f64 + '_ {
        move |pw: &str, inputs: &[&str]| {
            self.calls.borrow_mut().push((
                pw.to_owned(),
                inputs.iter().map(|s| (*s).to_owned()).collect(),
            ));
            self.value
        }
    }
}

#[test]
fn fea05_03_empty() {
    let r = Recorder::new(50.0);
    let e = bits_with(&r.est(), "", &[]);
    assert_eq!((e, score(e), Level::of(score(e))), (0.0, 0, Level::Bad));
    assert!(r.calls.borrow().is_empty(), "the estimator is not called");
    assert_eq!(zxcvbn_bits("", &[]), 0.0);
}

#[test]
fn fea05_04_long_text() {
    let pw: String = "kT7#pQ2vZ9mW4xR8".chars().cycle().take(300).collect();
    let r = Recorder::new(109.118);
    let e = bits_with(&r.est(), &pw, &[]);
    // LD-135 (2): 109.118 × 300 / 256 = 127.8727; ±0.001.
    assert!((e - 127.872).abs() < 0.001, "{e}");
    assert_eq!(score(e), 127);
    let calls = r.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0.chars().count(), 256);
    assert!(pw.starts_with(&calls[0].0));
    // Counted in characters (D-05-2): 300 two-byte characters scale too.
    let wide: String = "é".repeat(300);
    let r = Recorder::new(10.0);
    let e = bits_with(&r.est(), &wide, &[]);
    assert_eq!(r.calls.borrow()[0].0.chars().count(), 256);
    assert!((e - 10.0 * 300.0 / 256.0).abs() < 1e-9);
}

#[test]
fn fea05_05_user_inputs() {
    // LD-135 (1), LD-44: the title, user name and URL host go in as user
    // inputs (ratings only get stricter).
    let mut e = ent(0x10, "alice", "alice2024");
    set(&mut e, "UserName", "alice");
    let r = Recorder::new(5.0);
    let _ = entry_bits_with(&r.est(), "alice2024", &e);
    assert_eq!(
        r.calls.borrow().as_slice(),
        [(
            "alice2024".to_owned(),
            vec!["alice".to_owned(), "alice".to_owned()]
        )]
    );
    set(&mut e, "URL", "https://login.example.com/path");
    let r = Recorder::new(5.0);
    let _ = entry_bits_with(&r.est(), "alice2024", &e);
    assert_eq!(
        r.calls.borrow()[0].1,
        ["alice", "alice", "login.example.com"]
    );
    // With the real estimator the inputs only lower the rating.
    assert!(entry_bits("alice2024", &e) < zxcvbn_bits("alice2024", &[]));
}

#[test]
fn fea05_06_reasons() {
    let text = |e: f64| {
        let (r, d) = strength_reasons(e);
        (
            r.iter().map(Reason::text).collect::<Vec<_>>(),
            d.iter().map(|d| d.text(&ymd)).collect::<Vec<_>>(),
        )
    };
    assert_eq!(
        text(12.5),
        (
            vec!["Very easy to guess".into()],
            vec!["Estimated strength: 12.50 bits".into()]
        )
    );
    assert_eq!(
        text(58.492),
        (
            vec!["Somewhat easy to guess".into()],
            vec!["Estimated strength: 58.49 bits".into()]
        )
    );
    assert_eq!(text(85.0), (vec![], vec![]));
    assert_eq!(strength_reasons(12.5).0[0].id(), "MSG-HC-VERY-WEAK");
}

#[test]
fn fea05_07_meter() {
    let m = meter(true, 0.0);
    assert_eq!((m.bar, m.color, m.rated), (0, None, None));
    for (e, bar, color, rated) in [
        (1.0, 1, "poor", "Rated Poor"),
        (58.492, 58, "warn", "Rated Weak"),
        (150.0, 100, "ok", "Rated Excellent"),
        (0.0, 0, "danger", "Rated Poor"),
    ] {
        let m = meter(false, e);
        assert_eq!(
            (m.bar, m.scale, m.color, m.rated.as_deref()),
            (bar, 100, Some(color), Some(rated)),
            "{e}"
        );
    }
}

#[test]
fn fea05_08_meter_resolves_references() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x10, "X", "kT7#pQ2vZ9mW4xR8"));
    root.entries.push(ent(0x11, "Y", "old"));
    let v = vault(root);
    let ctx = Context::new(Some(&v), now().secs);
    let y = &v.root.entries[1];
    let r = Recorder::new(80.0);
    let typed = refs::reference('P', uid(0x10));
    let by_ref = health::editor_meter(&r.est(), &typed, y, &ctx);
    let direct = health::editor_meter(&r.est(), "kT7#pQ2vZ9mW4xR8", y, &ctx);
    assert_eq!(by_ref, direct);
    let calls = r.calls.borrow();
    assert_eq!(
        calls[0].0, "kT7#pQ2vZ9mW4xR8",
        "rated by the password it points to"
    );
    // The same E as typing it, with App's estimator.
    let real = |t: &str| health::editor_meter(&zxcvbn_bits, t, y, &ctx);
    assert_eq!(real(&typed), real("kT7#pQ2vZ9mW4xR8"));
}

#[test]
fn fea05_09_generator() {
    let (text, m) = generator_display(113.306);
    assert_eq!(text, "113.31 bits of strength");
    assert_eq!(
        (m.bar, m.scale, m.rated.as_deref()),
        (113, 200, Some("Rated Excellent"))
    );
    // Passphrase tab: FEA-03's entropy, no estimator involved.
    let (text, m) = generator_display(77.55);
    assert_eq!(text, "77.55 bits of strength");
    assert_eq!(m.rated.as_deref(), Some("Rated Good"));
    assert_eq!(generator_display(250.0).1.bar, 200);
}

#[test]
fn fea05_10_list_indicator() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0a, "A", "password"));
    root.entries.push(ent(0x0b, "B", ""));
    let mut c = ent(0x0c, "C", "password");
    c.exclude_from_reports = true;
    root.entries.push(c);
    root.entries
        .push(ent(0x0d, "D", &refs::reference('P', uid(0x0a))));
    let v = vault(root);
    let ctx = Context::new(Some(&v), now().secs);
    let est = table(&[("password", 1.0)]);
    let icons: Vec<_> = v
        .root
        .entries
        .iter()
        .map(|e| indicator(&Ratings::new(&est), e, &ctx))
        .collect();
    let a = icons[0].as_ref().unwrap();
    assert_eq!((a.level, sort_key(Some(a))), (Level::Poor, 1));
    assert_eq!(a.reasons, (vec![Reason::VeryWeak], vec![Detail::Bits(1.0)]));
    assert_eq!((icons[1].is_none(), sort_key(icons[1].as_ref())), (true, 0));
    assert_eq!((icons[2].is_none(), sort_key(icons[2].as_ref())), (true, 0));
    assert_eq!(
        icons[3].as_ref().unwrap().level,
        Level::Poor,
        "rated as `password`"
    );
}

#[test]
fn fea05_11_weak_predicate() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0a, "A", "password"));
    let mut b = ent(0x0b, "B", "password");
    b.exclude_from_reports = true;
    root.entries.push(b);
    let mut c = ent(0x0c, "C", "password");
    c.times.expires = true;
    c.times.expiry = at(2026, 10, 1, 0, 0, 0);
    root.entries.push(c);
    root.entries.push(ent(0x0d, "D", ""));
    root.entries.push(ent(0x0e, "E", "4v8Nq2LmZ7rT1xKc9WbP"));
    let v = vault(root);
    let ratings = Ratings::new(&zxcvbn_bits);
    let o = Options {
        ratings: Some(&ratings),
        ..Options::new(now().secs)
    };
    assert_eq!(search(&v, "is:weak", &o).unwrap().ids, [uid(0x0a)]);
}

/// Root > Work, Root > Recycle Bin (the bin) > Old.
#[test]
fn fea05_12_skipped_entries() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0a, "A", ""));
    let mut work = grp(0x02, "Work");
    let mut b = ent(0x0b, "B", "x");
    b.history.push(ent(0x0b, "B", "y"));
    work.entries.push(b);
    let mut bin = grp(0x03, "Recycle Bin");
    bin.entries.push(ent(0x0c, "C", "x"));
    let mut old = grp(0x04, "Old");
    old.entries.push(ent(0x0d, "D", "x"));
    bin.groups.push(old);
    root.groups.extend([work, bin]);
    let mut v = vault(root);
    v.meta.recycle_bin = Some(uid(0x03));
    let r = Recorder::new(2.0);
    let report = check(&r.est(), &v);
    assert_eq!(r.calls.borrow().len(), 1, "only B is evaluated");
    let rows = report.rows(true, true);
    assert_eq!(titles(&rows), ["B"]);
    assert_eq!(rows[0].reasons, [Reason::VeryWeak], "reuse count 1");
    assert_eq!(rows[0].path, "Root/Work");
}

#[test]
fn fea05_13_reuse() {
    let mut root = grp(0x01, "Root");
    let mut bank = ent(0x0c, "Bank", "Tr0ub4dor&3");
    bank.exclude_from_reports = true;
    root.entries.push(bank);
    let mut work = grp(0x02, "Work");
    work.entries.push(ent(0x0a, "GitHub", "Tr0ub4dor&3"));
    let mut mail = grp(0x03, "Mail");
    mail.entries.push(ent(0x0b, "Proton", "Tr0ub4dor&3"));
    root.groups.extend([work, mail]);
    let v = vault(root);
    let report = check(&table(&[("Tr0ub4dor&3", 46.711)]), &v);
    let rows = report.rows(false, false);
    assert_eq!(titles(&rows), ["GitHub", "Proton"]);
    for r in &rows {
        assert_eq!((r.score, r.level), (16, Level::Poor));
        assert_eq!(
            reason_texts(r),
            ["Somewhat easy to guess", "Same password on 3 entries"]
        );
        assert_eq!(
            detail_texts(r),
            [
                "Estimated strength: 46.71 bits",
                "• Root/Bank",
                "• Root/Work/GitHub",
                "• Root/Mail/Proton"
            ]
        );
    }
    assert!(report.excluded_toggle_visible());
    assert_eq!(
        titles(&report.rows(true, false)),
        ["Bank", "GitHub", "Proton"]
    );
}

#[test]
fn fea05_14_reuse_cap() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0a, "A", "4v8Nq2LmZ7rT1xKc9WbP"));
    root.entries.push(ent(0x0b, "B", "4v8Nq2LmZ7rT1xKc9WbP"));
    let report = check(&table(&[("4v8Nq2LmZ7rT1xKc9WbP", 113.306)]), &vault(root));
    let rows = report.rows(false, false);
    assert_eq!(rows.len(), 2);
    assert_eq!((rows[0].score, rows[0].level), (74, Level::Weak));
    assert_eq!(reason_texts(rows[0]), ["Same password on 2 entries"]);
}

#[test]
fn fea05_15_case_sensitive_reuse() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0a, "A", "Secret-1"));
    root.entries.push(ent(0x0b, "B", "secret-1"));
    let report = check(&table(&[]), &vault(root));
    for r in report.rows(true, true) {
        assert!(
            !r.reasons.iter().any(|x| matches!(x, Reason::Reused(_))),
            "count 1"
        );
    }
}

#[test]
fn fea05_16_more_than_20_uses() {
    let mut root = grp(0x01, "Root");
    for i in 1..=22u8 {
        root.entries.push(ent(i, &format!("E{i:02}"), "same"));
    }
    let report = check(&table(&[("same", 10.0)]), &vault(root));
    let e01 = report
        .rows(true, true)
        .into_iter()
        .find(|r| r.title == "E01")
        .unwrap();
    assert!(reason_texts(e01).contains(&"Same password on 22 entries".to_owned()));
    let mut want = vec!["Estimated strength: 10.00 bits".to_owned()];
    want.extend((1..=20).map(|i| format!("• Root/E{i:02}")));
    want.push("…".into());
    assert_eq!(detail_texts(e01), want);
}

fn expiring(b: u8, title: &str, pw: &str, expiry: Time) -> Entry {
    let mut e = ent(b, title, pw);
    e.times.expires = true;
    e.times.expiry = expiry;
    e
}

#[test]
fn fea05_17_expired() {
    let mut root = grp(0x01, "Root");
    root.entries
        .push(expiring(0x0a, "X", "strong", at(2026, 10, 20, 12, 0, 0)));
    let report = check(&table(&[("strong", 113.306)]), &vault(root));
    assert!(
        report.rows(false, false).is_empty(),
        "hidden while show-expired is off"
    );
    let rows = report.rows(false, true);
    assert_eq!((rows[0].score, rows[0].level), (0, Level::Bad));
    assert_eq!(reason_texts(rows[0]), ["Past its expiry date"]);
    assert_eq!(
        detail_texts(rows[0]),
        ["Expiry date 2026-10-20 12:00 has passed"]
    );
    assert_eq!(rows[0].title_text(), "X (Expired)");
}

#[test]
fn fea05_18_expiring() {
    let mut root = grp(0x01, "Root");
    let days = [(26, 10), (1, 11), (14, 11), (24, 11), (25, 11)];
    for (i, (day, month)) in days.iter().enumerate() {
        let b = 0x10 + u8::try_from(i).unwrap();
        root.entries.push(expiring(
            b,
            &format!("D{i}"),
            &format!("pw{i}"),
            at(2026, *month, *day, 12, 0, 0),
        ));
    }
    let est = table(&[
        ("pw0", 113.306),
        ("pw1", 113.306),
        ("pw2", 113.306),
        ("pw3", 113.306),
        ("pw4", 113.306),
    ]);
    let report = check(&est, &vault(root));
    let rows = report.rows(false, false);
    let got: Vec<(String, i64, String)> = rows
        .iter()
        .map(|r| (r.title.clone(), r.score, reason_texts(r).join("|")))
        .collect();
    assert_eq!(
        got,
        [
            ("D0".into(), 12, "Expires in 2 days or less".into()),
            ("D1".into(), 24, "7 days until it expires".into()),
            ("D2".into(), 50, "Expires within 30 days".into()),
            ("D3".into(), 70, "Expires within 30 days".into()),
        ],
        "d = 31: 113, not listed"
    );
    assert_eq!(detail_texts(rows[0]), ["Expiry date: 2026-10-26 12:00"]);
}

#[test]
fn fea05_19_expiring_and_weak() {
    let mut root = grp(0x01, "Root");
    root.entries
        .push(expiring(0x0a, "A", "weak", at(2026, 10, 30, 12, 0, 0)));
    root.entries.push(ent(0x0b, "B", "weak"));
    let report = check(&table(&[("weak", 20.0)]), &vault(root));
    let a = report
        .rows(false, false)
        .into_iter()
        .find(|r| r.title == "A")
        .unwrap();
    assert_eq!((a.score, a.level), (-45, Level::Bad));
    assert_eq!(
        reason_texts(a),
        [
            "Very easy to guess",
            "Same password on 2 entries",
            "5 days until it expires"
        ]
    );
}

#[test]
fn fea05_20_expiry_later_today() {
    let mut root = grp(0x01, "Root");
    root.entries
        .push(expiring(0x0a, "A", "p", at(2026, 10, 25, 23, 0, 0)));
    let report = check(&table(&[("p", 90.0)]), &vault(root));
    let a = report.rows(false, false)[0];
    assert_eq!((a.score, a.level, a.expired), (10, Level::Poor, false));
    assert_eq!(reason_texts(a), ["Expires in 2 days or less"]);
}

#[test]
fn fea05_21_time_zone() {
    // UTC+2, now 2026-10-25 23:30 local; expiry 2026-10-26 23:30 UTC
    // (2026-10-27 01:30 local): d = 2 by local dates (D-05-4).
    let mut root = grp(0x01, "Root");
    root.entries
        .push(expiring(0x0a, "A", "p", at(2026, 10, 26, 23, 30, 0)));
    let now = Instant::from(at(2026, 10, 25, 21, 30, 0));
    let zone: &dyn Zone = &Fixed(7200);
    let report = health_check(
        &Ratings::new(&table(&[("p", 90.0)])),
        &vault(root),
        now,
        zone,
    );
    let a = report.rows(false, false)[0];
    assert_eq!(a.score, 14);
    assert_eq!(reason_texts(a), ["Expires in 2 days or less"]);
}

#[test]
fn fea05_22_order() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0a, "A", "a"));
    root.entries.push(ent(0x0b, "B", "b"));
    // C: E 20, expiring in 15 days: 20 − 30 = −10.
    root.entries
        .push(expiring(0x0c, "C", "c", at(2026, 11, 9, 12, 0, 0)));
    root.entries.push(ent(0x0d, "D", "d"));
    let report = check(
        &table(&[("a", 30.0), ("b", 30.0), ("c", 20.0), ("d", 74.0)]),
        &vault(root),
    );
    let rows = report.rows(false, false);
    let got: Vec<(String, i64)> = rows.iter().map(|r| (r.title.clone(), r.score)).collect();
    assert_eq!(
        got,
        [
            ("C".into(), -10),
            ("A".into(), 30),
            ("B".into(), 30),
            ("D".into(), 74)
        ]
    );
}

#[test]
fn fea05_23_row_content() {
    let mut root = grp(0x01, "Root");
    let mut work = grp(0x02, "Work");
    let mut g = expiring(0x0a, "Gamma", "g", at(2026, 10, 1, 0, 0, 0));
    g.exclude_from_reports = true;
    work.entries.push(g);
    root.groups.push(work);
    let report = check(&table(&[("g", 10.0)]), &vault(root));
    assert!(report.rows(false, true).is_empty() && report.rows(true, false).is_empty());
    let r = report.rows(true, true)[0];
    assert_eq!(r.title_text(), "Gamma (Excluded) (Expired)");
    assert_eq!(
        (r.path.as_str(), r.score, r.level),
        ("Root/Work", 0, Level::Bad)
    );
    assert_eq!(r.title_tip(), Some("Reports skip this entry"));
    assert_eq!(r.level.tip(), Some("Bad. Replace this password now."));
    assert_eq!(Level::Poor.tip(), Some("Poor. Replace this password soon."));
    assert_eq!(
        Level::Weak.tip(),
        Some("Weak. A stronger password would be better.")
    );
}

#[test]
fn fea05_24_healthy() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0a, "A", "good"));
    root.entries.push(ent(0x0b, "B", "great"));
    let report = check(&table(&[("good", 75.0), ("great", 140.0)]), &vault(root));
    assert!(report.rows(true, true).is_empty());
    assert_eq!(ALL_HEALTHY, "No password needs attention right now.");
    // No evaluated entries at all: the same message.
    assert!(
        check(&table(&[]), &vault(grp(0x01, "Root")))
            .rows(true, true)
            .is_empty()
    );
}

#[test]
fn fea05_25_exclude_action() {
    let mut root = grp(0x01, "Root");
    let mut a = ent(0x0a, "A", "p");
    a.exclude_from_reports = true;
    root.entries.push(a);
    root.entries.push(ent(0x0b, "B", "q"));
    let mut v = vault(root);
    let ids = [uid(0x0a), uid(0x0b)];
    assert!(health::skip_checked(&v, &ids));
    assert_eq!(health::toggle_skip(&mut v, &ids, now().secs), Ok(1));
    assert!(v.root.entries.iter().all(|e| !e.exclude_from_reports));
    assert!(!health::skip_checked(&v, &ids));
    assert_eq!(health::toggle_skip(&mut v, &ids, now().secs), Ok(2));
    assert!(
        v.root
            .entries
            .iter()
            .all(|e| e.exclude_from_reports && e.history.is_empty())
    );
    assert!(
        !check(&table(&[]), &v)
            .rows(false, false)
            .iter()
            .any(|_| true)
    );
    assert_eq!(
        health::toggle_skip(&mut v, &[uid(0x0a), uid(0x99)], now().secs),
        Err(app_core::Error::NoSuchEntry)
    );
    assert!(v.root.entries[0].exclude_from_reports, "nothing changed");
}

#[test]
fn fea05_26_expire_and_delete_actions() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0a, "X", "p"));
    let mut v = vault(root);
    v.meta.recycle_bin_enabled = true;
    let est = table(&[("p", 30.0)]);
    assert_eq!(titles(&check(&est, &v).rows(false, false)), ["X"]);
    let t = at(2026, 10, 25, 11, 0, 0);
    expire_now(&mut v, &[uid(0x0a)], t).unwrap();
    let after = check(&est, &v);
    assert!(
        after.rows(false, false).is_empty(),
        "now under the show-expired rule"
    );
    assert_eq!(titles(&after.rows(false, true)), ["X"]);
    recycle::delete_entries(&mut v, &[uid(0x0a)], t, |_, _| {
        recycle::References::Overwrite
    })
    .unwrap();
    assert!(recycle::entry_in_bin(&v, uid(0x0a)));
    assert!(
        check(&est, &v).rows(true, true).is_empty(),
        "left the report"
    );
}

/// FEA-05.19's sample: password, reference E, level, may differ.
const SAMPLE: [(&str, f64, Level, bool); 19] = [
    ("", 0.0, Level::Bad, false),
    ("password", 1.0, Level::Poor, false),
    ("P@ssw0rd", 3.0, Level::Poor, false),
    ("abc123", 3.7, Level::Poor, false),
    ("letmein", 4.0, Level::Poor, false),
    ("qwertyuiop", 4.459, Level::Poor, false),
    ("hunter2", 11.379, Level::Poor, false),
    ("Summer2024!", 19.087, Level::Poor, false),
    ("demo-pass-1", 38.32, Level::Poor, true),
    ("Zm4#Lp9", 43.091, Level::Weak, false),
    ("Tr0ub4dor&3", 46.711, Level::Weak, false),
    ("correcthorsebatterystaple", 47.983, Level::Weak, false),
    ("x9!Lq#4vTz", 58.492, Level::Weak, false),
    ("Vp5#nQ2wLk8", 67.548, Level::Weak, false),
    ("Zm4#Lp9qW2xR", 73.97, Level::Weak, true),
    ("Zm4#Lp9qW2xR7v", 85.091, Level::Good, false),
    ("kT7#pQ2vZ9mW4xR8", 100.263, Level::Excellent, true),
    ("4v8Nq2LmZ7rT1xKc9WbP", 113.306, Level::Excellent, false),
    ("kT7#pQ2vZ9mW4xR8nB3yL6cF", 148.733, Level::Excellent, false),
];

#[test]
fn fea05_27_parity_sample() {
    let long: String = "kT7#pQ2vZ9mW4xR8".chars().cycle().take(300).collect();
    let mut rows: Vec<(String, f64, Level, bool)> = SAMPLE
        .iter()
        .map(|(p, e, l, m)| ((*p).to_owned(), *e, *l, *m))
        .collect();
    rows.push((long, 127.872, Level::Excellent, false));
    for (pw, reference, want, may_differ) in rows {
        let e = bits_with(&zxcvbn_bits, &pw, &[]);
        let got = Level::of(score(e));
        let short: String = pw.chars().take(24).collect();
        println!("PARITY {short:<26} ref {reference:>8.3}  App {e:>8.3}  {got:?}");
        if !may_differ {
            assert_eq!(got, want, "{short}: E {e}");
        }
    }
}

fn key_change(pw: &str, min: u8) -> Changes {
    let level = Level::of(score(zxcvbn_bits(pw, &[])));
    Changes {
        key: Some(KeyChange {
            password: PasswordPart::New {
                typed: SecretString::new(pw.to_owned()),
                repeat: SecretString::new(pw.to_owned()),
                quality: level.quality(),
            },
            had_password: true,
            key_file: false,
            hardware: false,
            min_quality: min,
        }),
        ..Changes::default()
    }
}

fn apply(v: &mut Vault, c: &Changes) -> Result<settings::Applied, Refusal> {
    let mut host = app_crypto::kdf::Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: None,
    };
    let ceilings = app_crypto::kdf::Ceilings {
        refuse_iterations: 1_000_000_000,
        ask_memory_kib: 1_048_576,
        ask_lanes: 128,
        ask_ms: 10_000,
    };
    settings::apply(v, c, &mut host, &ceilings, now().secs)
}

#[test]
fn fea05_28_master_password_minimum() {
    let e = zxcvbn_bits("Zm4#Lp9", &[]);
    assert_eq!(Level::of(score(e)), Level::Weak);
    assert_eq!(health::master_gate(e, 3), MasterGate::TooWeak);
    let mut v = vault(grp(0x01, "Root"));
    let before = v.meta.master_key_changed;
    assert_eq!(
        apply(&mut v, &key_change("Zm4#Lp9", 3)),
        Err(Refusal::BelowMinimum)
    );
    assert_eq!(v.meta.master_key_changed, before, "key unchanged");
    // Values outside 0 to 4 are clamped.
    assert_eq!(health::master_gate(500.0, 9), MasterGate::Fine);
    assert_eq!(health::master_gate(1.0, -3), MasterGate::Warn);
}

#[test]
fn fea05_29_master_password_warning() {
    let e = zxcvbn_bits("password", &[]);
    assert_eq!(health::master_gate(e, 0), MasterGate::Warn);
    let mut v = vault(grp(0x01, "Root"));
    let before = v.meta.master_key_changed;
    let c = key_change("password", 0);
    assert_eq!(
        apply(&mut v, &c),
        Err(Refusal::Confirm(settings::Confirm::WeakPassword))
    );
    assert_eq!(v.meta.master_key_changed, before, "Cancel: nothing changed");
    let use_it = Changes {
        confirmed: vec![settings::Confirm::WeakPassword],
        ..c
    };
    assert!(apply(&mut v, &use_it).unwrap().key_changed);
    let strong = zxcvbn_bits("4v8Nq2LmZ7rT1xKc9WbP", &[]);
    assert_eq!(health::master_gate(strong, 0), MasterGate::Fine);
    assert!(
        apply(&mut v, &key_change("4v8Nq2LmZ7rT1xKc9WbP", 0)).is_ok(),
        "no warning"
    );
}

#[test]
fn fea05_30_reference_skipped() {
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0a, "X", "abc"));
    root.entries
        .push(ent(0x0b, "Y", &refs::reference('P', uid(0x0a))));
    let r = Recorder::new(3.0);
    let report = check(&r.est(), &vault(root));
    let rows = report.rows(true, true);
    assert_eq!(titles(&rows), ["X"]);
    assert_eq!(rows[0].reasons, [Reason::VeryWeak], "reuse count 1");
    assert_eq!(r.calls.borrow().len(), 1, "Y not evaluated");
}

#[test]
fn fea05_31_colors() {
    let got: Vec<&str> = [
        Level::Bad,
        Level::Poor,
        Level::Weak,
        Level::Good,
        Level::Excellent,
    ]
    .iter()
    .map(|l| l.color())
    .collect();
    assert_eq!(got, ["danger", "poor", "warn", "ok", "ok"]);
}

#[test]
fn fea05_edge_cases() {
    // Only spaces: not empty, estimated normally.
    assert!(zxcvbn_bits("     ", &[]) > 0.0);
    // Expiry flag off with a time set: ignored.
    let mut root = grp(0x01, "Root");
    let mut e = ent(0x0a, "A", "p");
    e.times.expiry = at(2026, 10, 26, 0, 0, 0);
    root.entries.push(e);
    let report = check(&table(&[("p", 90.0)]), &vault(root));
    assert!(report.rows(true, true).is_empty());
    // A reused excluded entry counts (05-13); a history item never does
    // (05-12); the recycle bin never does (05-12).
    // E is never negative or NaN, whatever an estimator returns.
    assert_eq!(bits_with(&|_, _| -5.0, "x", &[]), 0.0);
    assert_eq!(bits_with(&|_, _| f64::NAN, "x", &[]), 0.0);
}

#[test]
fn fea05_brute_force_classes() {
    // D-05-1 (b): a character outside any match costs log2(N), N summed
    // from the classes the text uses: 26, 26, 10, 33 (space included), 100.
    // These texts hold no match at all, so E = 10 × log2(N).
    let cases: [(&str, f64); 6] = [
        ("qzxjvkqzxj", 26.0),
        ("QZXJVKQZXJ", 26.0),
        ("qzXJvkQZxj", 52.0),
        ("zq8j6V#w g", 95.0),
        ("ßøæþðłŋħĸŧ", 100.0),
        ("zqøj6V#wæg", 195.0),
    ];
    let empty = std::collections::HashMap::new();
    for (pw, n) in cases {
        assert!(
            zxcvbn::matching::omnimatch(pw, &empty).is_empty(),
            "{pw}: no match"
        );
        let want = 10.0 * f64::log2(n);
        assert!((zxcvbn_bits(pw, &[]) - want).abs() < 1e-9, "{pw}");
    }
}

#[test]
fn fea05_reuse_and_expiry_bounds() {
    // Exactly 21 uses: 20 path details, then `…`.
    let mut root = grp(0x01, "Root");
    for i in 1..=21u8 {
        root.entries.push(ent(i, &format!("E{i:02}"), "same"));
    }
    let report = check(&table(&[("same", 10.0)]), &vault(root));
    let e01 = report
        .rows(true, true)
        .into_iter()
        .find(|r| r.title == "E01")
        .unwrap();
    assert_eq!(detail_texts(e01).last().unwrap(), "…");
    assert_eq!(detail_texts(e01).len(), 22);
    // d = 2, 3, 10 and 11 at the reason bounds.
    let mut root = grp(0x01, "Root");
    for (b, day) in [(0x0a, 27), (0x0b, 28), (0x0c, 4), (0x0d, 5)] {
        let month = if day > 25 { 10 } else { 11 };
        root.entries.push(expiring(
            b,
            &format!("d{b}"),
            &format!("p{b}"),
            at(2026, month, day, 12, 0, 0),
        ));
    }
    let est = |_: &str, _: &[&str]| 90.0;
    let report = check(&est, &vault(root));
    let got: Vec<String> = report
        .rows(false, false)
        .iter()
        .map(|r| reason_texts(r).join(""))
        .collect();
    assert_eq!(
        got,
        [
            "Expires in 2 days or less",
            "3 days until it expires",
            "10 days until it expires",
            "Expires within 30 days"
        ]
    );
}

// ---- The `zxcvbn` crate (story rule 2): guess cap and long input ----

#[test]
fn fea05_crate_guesses_never_saturate() {
    // LD-136 (1): guesses are f64 in App's copy. Upstream they saturated at
    // the 64-bit maximum from about 19 random characters on.
    let pw = "kT7#pQ2vZ9mW4xR8nB3yL6cF";
    assert!(zxcvbn::zxcvbn(pw, &[]).guesses() > u64::MAX as f64 * 1e4);
    assert!(zxcvbn_bits(pw, &[]) > 100.0);
}

#[test]
fn fea05_crate_reads_only_100_characters() {
    // A 256-character input: the crate cuts it to its first 100
    // characters; its match sequence ends at index 99.
    let pw: String = "kT7#pQ2vZ9mW4xR8".chars().cycle().take(256).collect();
    let z = zxcvbn::zxcvbn(&pw, &[]);
    assert_eq!(z.sequence().last().unwrap().j, 99);
    let head: String = pw.chars().take(100).collect();
    assert_eq!(zxcvbn_bits(&pw, &[]), zxcvbn_bits(&head, &[]));
}

#[test]
fn fea05_crate_long_keyboard_walks_do_not_panic() {
    // Upstream these panicked with overflow checks on (an integer power
    // and sum); App's copy counts guesses in f64 (LD-136), so they rate low
    // with overflow checks on for every crate.
    let walk = |pair: &str, n: usize| pair.chars().cycle().take(n).collect::<String>();
    for pw in [
        walk("12", 30),
        walk("qw", 33),
        walk("Qw", 100),
        walk("aS", 100),
    ] {
        let e = zxcvbn_bits(&pw, &[]);
        assert!(e.is_finite() && e < 75.0, "{pw}: {e}");
    }
    let input: String = "abcdefghijklmnopqrstuvwxyz"
        .chars()
        .cycle()
        .take(100)
        .collect();
    let mixed: String = input
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    assert!(zxcvbn_bits(&mixed, &[&input]).is_finite());
}

#[test]
fn fea05_estimate_is_fast() {
    // One estimate is bounded (the crate reads 100 characters): the worst
    // of these takes milliseconds.
    let inputs = [
        "QwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQw".to_owned(),
        "a".repeat(5_000),
        "1a2b3c4d5e6f7g8h9i0j".repeat(50),
    ];
    for pw in &inputs {
        let t = std::time::Instant::now();
        let _ = bits_with(&zxcvbn_bits, pw, &[]);
        let ms = t.elapsed().as_millis();
        println!("TIMING estimate of {} chars: {ms} ms", pw.chars().count());
        assert!(ms < 2_000, "{ms} ms");
    }
}

// ---- LD-136: App's patched copy of the crate ----

/// Passwords of 10 to 40 characters mixing words, keyboard runs, years,
/// l33t and random characters: where upstream's ties showed.
fn mixed_passwords(n: usize) -> Vec<String> {
    let parts = [
        "qwerty", "welcome", "admin", "p@ss", "dragon", "1987", "2024", "asdf", "letmein",
        "monkey", "Tr0ub", "zxcv", "!!", "#", "iloveyou", "summer", "12345", "abc", "s3cr3t", "LS",
    ];
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move |m: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % m
    };
    (0..n)
        .map(|_| {
            let want = 10 + next(31) as usize;
            let mut p = String::new();
            while p.chars().count() < want {
                if next(3) == 0 {
                    p.push(char::from(
                        b"abcdefghijkLMNOPQ0123456789!@#$%"[next(32) as usize],
                    ));
                } else {
                    p.push_str(parts[next(parts.len() as u64) as usize]);
                }
            }
            p.chars().take(want).collect()
        })
        .collect()
}

#[test]
fn fea05_ld136_same_input_same_e() {
    // 2,000 passwords of 10 to 40 characters, 30 estimates each: the same
    // E every time (upstream picked among tied sequences in hash order).
    let calls = if cfg!(debug_assertions) { 5 } else { 30 };
    let t = std::time::Instant::now();
    for pw in mixed_passwords(2_000) {
        let first = zxcvbn_bits(&pw, &[]).to_bits();
        for _ in 1..calls {
            assert_eq!(zxcvbn_bits(&pw, &[]).to_bits(), first, "{pw}");
        }
    }
    println!(
        "TIMING 2,000 passwords x {calls}: {} ms",
        t.elapsed().as_millis()
    );
}

#[test]
fn fea05_ld136_flip_repro_is_stable() {
    let pw = "TqwertyiwelcomeadminhLS";
    let first = Level::of(score(zxcvbn_bits(pw, &[])));
    for _ in 0..100 {
        assert_eq!(Level::of(score(zxcvbn_bits(pw, &[]))), first);
    }
}

#[test]
fn fea05_ld136_repeated_block() {
    // An 18-digit block repeated to 100 characters rates about the block
    // plus log2 of the repeats, not as 100 new characters (upstream: 331.7).
    let block = "787789328792174218";
    let one = zxcvbn_bits(block, &[]);
    let long: String = block.chars().cycle().take(100).collect();
    let e = zxcvbn_bits(&long, &[]);
    println!("REPEAT block {one:.3} bits; repeated to 100: {e:.3} bits");
    assert!(e <= one + 3.0, "{one} -> {e}");
}

#[test]
fn fea05_ld136_long_row_near_the_reference() {
    // FEA-05.19's 300-character row: the reference gives 127.872.
    let pw: String = "kT7#pQ2vZ9mW4xR8".chars().cycle().take(300).collect();
    let e = bits_with(&zxcvbn_bits, &pw, &[]);
    assert!((e - 127.872).abs() < 3.0, "{e}");
}

// ---- LD-137: the rating cache and the `is:weak` budget ----

#[test]
fn fea05_ld137_rating_cache() {
    let r = Recorder::new(30.0);
    let est = r.est();
    let ratings = Ratings::new(&est);
    let mut e = ent(0x0a, "A", "p");
    assert_eq!(ratings.cached(&e), None);
    assert_eq!((ratings.stored(&e), ratings.stored(&e)), (30.0, 30.0));
    assert_eq!(r.calls.borrow().len(), 1, "estimated once");
    assert_eq!(ratings.cached(&e), Some(30.0));
    // A new modification time is a new key.
    e.times.last_modification = at(2026, 2, 1, 0, 0, 0);
    assert_eq!(ratings.cached(&e), None);
    let _ = ratings.stored(&e);
    assert_eq!(r.calls.borrow().len(), 2);
    // Any other text (a resolved password) is rated fresh and not kept.
    let _ = ratings.of("resolved text", &e);
    assert_eq!((r.calls.borrow().len(), ratings.len()), (3, 2));
    ratings.forget(e.uuid);
    assert!(ratings.is_empty());
    // The Health Check, statistics and the list share one cache.
    let mut root = grp(0x01, "Root");
    root.entries.push(ent(0x0b, "B", "q"));
    let v = vault(root);
    ratings.fill(&v);
    let calls = r.calls.borrow().len();
    let _ = health_check(&ratings, &v, now(), &Utc);
    let _ = app_core::stats::statistics(&ratings, &v, &Default::default(), now(), &Utc);
    let ctx = Context::new(Some(&v), now().secs);
    let _ = indicator(&ratings, &v.root.entries[0], &ctx);
    assert_eq!(r.calls.borrow().len(), calls, "no new estimate");
}

/// `n` entries with 100-character passwords; every fourth (from 1) starts
/// with `w`.
fn hundred_chars(n: u32) -> Vault {
    let mut root = grp(0x01, "Root");
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for i in 0..n {
        let mut id = [7u8; 16];
        id[..4].copy_from_slice(&i.to_be_bytes());
        let mut e = Entry::new(Uuid(id), at(2026, 1, 1, 0, 0, 0));
        let pw: String = (0..100)
            .map(|k| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if k == 0 && i % 4 == 1 {
                    'w'
                } else {
                    char::from(
                        b"ABCDEFGHJKLMNPQRSTUVXYZabcdefghjkmnpqrstuvxyz0123456789#%&*"
                            [(x % 59) as usize],
                    )
                }
            })
            .collect();
        set(&mut e, "Password", &pw);
        root.entries.push(e);
    }
    vault(root)
}

#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn fea05_ld137_cold_cache_stays_in_budget() {
    let v = hundred_chars(10_000);
    let ratings = Ratings::new(&zxcvbn_bits);
    let o = Options {
        ratings: Some(&ratings),
        ..Options::new(now().secs)
    };
    let t = std::time::Instant::now();
    let f = search(&v, "is:weak", &o).unwrap();
    let ms = t.elapsed().as_millis();
    println!(
        "TIMING cold is:weak, 10,000 x 100 characters: {ms} ms, notice {}",
        f.invalid
    );
    assert!(ms < 250, "{ms} ms");
    assert!(f.invalid, "the limit notice");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn fea05_ld137_warm_cache_full_result() {
    let v = hundred_chars(10_000);
    let stub = |pw: &str, _: &[&str]| if pw.starts_with('w') { 10.0 } else { 120.0 };
    let ratings = Ratings::new(&stub);
    ratings.fill(&v);
    let o = Options {
        ratings: Some(&ratings),
        ..Options::new(now().secs)
    };
    let mut best = u128::MAX;
    for _ in 0..3 {
        let t = std::time::Instant::now();
        let f = search(&v, "is:weak", &o).unwrap();
        best = best.min(t.elapsed().as_millis());
        assert!(!f.invalid, "the full result");
        assert_eq!(f.ids.len(), 2_500);
    }
    println!("TIMING warm is:weak, 10,000 x 100 characters: best {best} ms");
    assert!(best < 50, "{best} ms");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn fea05_ld137_cold_cache_worst_text() {
    // l33t-heavy text, the crate's slowest found (LD-137 (2)), at 16 to 50
    // characters: some are estimated within the meter, and the run still
    // ends in time.
    let l33t: String = "4@8([{<369!|170$5+7%2".chars().cycle().take(50).collect();
    let mut root = grp(0x01, "Root");
    for i in 0..10_000u32 {
        let mut id = [9u8; 16];
        id[..4].copy_from_slice(&i.to_be_bytes());
        let mut e = Entry::new(Uuid(id), at(2026, 1, 1, 0, 0, 0));
        let len = 16 + (i % 35) as usize;
        set(
            &mut e,
            "Password",
            &l33t
                .chars()
                .skip(i as usize % 7)
                .take(len)
                .collect::<String>(),
        );
        root.entries.push(e);
    }
    let v = vault(root);
    let ratings = Ratings::new(&zxcvbn_bits);
    let o = Options {
        ratings: Some(&ratings),
        ..Options::new(now().secs)
    };
    let t = std::time::Instant::now();
    let f = search(&v, "is:weak", &o).unwrap();
    let ms = t.elapsed().as_millis();
    println!(
        "TIMING cold is:weak, l33t-heavy 16 to 50 characters: {ms} ms, {} rated",
        ratings.len()
    );
    assert!(ms < 250 && f.invalid && !ratings.is_empty(), "{ms} ms");
}

// ---- LD-140: one price for choosing and reporting the sequence ----

#[test]
fn fea05_ld140_word_phrases() {
    let rate = |pw: &str| {
        let e = zxcvbn_bits(pw, &[]);
        println!("PHRASE {pw:<36} {e:>7.3}  {:?}", Level::of(score(e)));
        Level::of(score(e))
    };
    // Common words joined by spaces or dashes rate below Good, as in the
    // reference (70.9 bits, Weak).
    assert!(rate("correct horse battery staple") < Level::Good);
    assert!(rate("correct-horse-battery-staple") < Level::Good);
    // A random 16-character password with all four classes keeps the
    // card's level (FEA-05.19: Excellent).
    assert_eq!(rate("kT7#pQ2vZ9mW4xR8"), Level::Excellent);
    for pw in [
        "purple monkey dishwasher river",
        "my-dog-likes-long-walks",
        "the quick brown fox jumps",
        "sunshine-coffee-garden-window",
        "blue sky green grass red rose",
        "happy birthday to you my friend",
        "summer-holiday-beach-house",
        "i love my family very much",
        "red-apple-banana-orange-lemon",
        "open the door please",
    ] {
        let _ = rate(pw);
    }
}

/// INT-10.33 `estimate -a`: the parts cover the password in order, without
/// gaps, and their bits add up to E.
#[test]
fn int10_33_parts_add_up_to_the_estimate() {
    use app_core::health::{zxcvbn_bits, zxcvbn_parts};
    for pw in [
        "demo-secret-9",
        "password",
        "Tr0ub4dor&3",
        "abcabcabcab",
        "qwertyuiop2024",
        "x",
        "9#Kq!zR2",
    ] {
        let parts = zxcvbn_parts(pw);
        let mut at = 0;
        for p in &parts {
            assert_eq!(p.start, at, "{pw}: {parts:?}");
            assert!(p.end > p.start);
            at = p.end;
        }
        assert_eq!(at, pw.chars().count(), "{pw}");
        let sum: f64 = parts.iter().map(|p| p.bits).sum();
        assert!((sum - zxcvbn_bits(pw, &[])).abs() < 1e-9, "{pw}");
    }
    assert!(
        zxcvbn_parts("password")
            .iter()
            .any(|p| p.kind == "dictionary")
    );
    assert!(zxcvbn_parts("").is_empty());
}

/// LD-207 (rule 4, LD-105, MOD-01.7): a protected Title never reaches a
/// report's text, whether its own flag or the vault's flag for the Title
/// protects it. The row and every "• path/title" detail that names that
/// entry use the mask; the row keeps the entry's id.
#[test]
fn ld_207_protected_title_is_masked_in_the_report() {
    let tree = |own_flag: bool| {
        let mut root = grp(0x01, "Root");
        let mut secret = ent(0x10, "Secret Bank", "Tr0ub4dor&3");
        secret.set_field(
            "Title".to_owned(),
            Field {
                value: SecretString::new("Secret Bank".to_owned()),
                protected: own_flag,
            },
        );
        root.entries.push(secret);
        root.entries.push(ent(0x11, "Mail", "Tr0ub4dor&3"));
        vault(root)
    };
    let est = table(&[("Tr0ub4dor&3", 46.711)]);
    let mask = health::MASKED_TITLE;
    // The entry's own flag: only that entry is masked.
    let r = check(&est, &tree(true));
    let rows = r.rows(false, false);
    assert_eq!(titles(&rows), [mask, "Mail"]);
    assert_eq!(rows[0].entry, uid(0x10), "the row keeps the id");
    let text = |row: &Row| -> Vec<String> {
        row.details
            .iter()
            .map(|d| d.text(&|_| String::new()))
            .collect()
    };
    assert!(text(rows[1]).contains(&format!("• Root/{mask}")));
    let all = format!("{:?}", r.rows(true, true));
    assert!(!all.contains("Secret Bank"), "{all}");
    // The vault's flag for the Title: every Title is masked.
    let mut v = tree(false);
    v.meta.memory_protection.title = true;
    let r = check(&est, &v);
    let rows = r.rows(false, false);
    assert_eq!(titles(&rows), [mask, mask]);
    assert!(text(rows[1]).contains(&format!("• Root/{mask}")));
    let all = format!("{:?}", r.rows(true, true));
    assert!(
        !all.contains("Secret Bank") && !all.contains("Mail"),
        "{all}"
    );
}
