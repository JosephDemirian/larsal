//! E4-S7: the rules of MOD-09 (expiry), on the card's vault R9. Each test
//! names its rule and checks the invariants where it changes the vault.

mod common;

use app_core::clone::{Options, clone_entry};
use app_core::edit::{add_entry, add_group, new_entry, new_group};
use app_core::expiry::{
    Controls, NoticeSettings, PRESETS, Preset, Shown, expire_now, expired_entries, expires_within,
    is_expired, notice, search_days, shown, sort_key,
};
use app_core::time::{Instant, Utc};
use app_model::{Entry, Group, Time, Times, Uuid, Vault};
use common::*;

/// 2026-10-24T22:50:59Z, the time R9 was built.
fn r9_now() -> Time {
    at(2026, 10, 24, 22, 50, 59)
}

fn x(n: u8, title: &str, expires: bool, expiry: i64) -> Entry {
    let mut e = entry(n, title);
    (e.times.expires, e.times.expiry) = (expires, Time(r9_now().0 + expiry));
    e
}

const DAY: i64 = 86_400;

/// Vault R9 (MOD-09 test cases).
fn r9() -> Vault {
    let mut root = Group::new(id(1), "Root".into(), T0);
    let mut hist = x(0x19, "X9hist", false, 0);
    let mut item = x(0x19, "X9hist", true, -10 * DAY);
    item.uuid = id(0x19);
    hist.history.push(item);
    root.entries = vec![
        x(0x11, "X1past", true, -DAY),
        x(0x12, "X2flagoff", false, -DAY),
        x(0x13, "X3in2days", true, 2 * DAY),
        x(0x14, "X4in5days", true, 5 * DAY),
        x(0x17, "X7in40s", true, 40),
        hist,
    ];
    let mut expired_group = Group::new(id(2), "ExpiredGroup".into(), T0);
    (expired_group.times.expires, expired_group.times.expiry) = (true, Time(r9_now().0 - 3 * DAY));
    expired_group
        .entries
        .push(x(0x16, "X6inExpiredGroup", false, 0));
    let mut bin = Group::new(id(3), "Recycle Bin".into(), T0);
    bin.entries.push(x(0x15, "X5binned", true, -DAY));
    root.groups = vec![expired_group, bin];
    let mut v = Vault::new(root, T0);
    v.meta.recycle_bin = Some(id(3));
    v
}

fn now(t: Time) -> Instant {
    Instant::from(t)
}

fn titles_of(v: &Vault, ids: &[Uuid]) -> Vec<String> {
    ids.iter()
        .map(|&i| find(v, i).value("Title").to_owned())
        .collect()
}

#[test]
fn mod_09_1_defaults() {
    let mut v = sample();
    let t = at(2026, 10, 25, 8, 0, 0);
    let e = new_entry(&v, id(1), false).unwrap();
    let eid = add_entry(&mut v, id(1), e, t).unwrap();
    let g = new_group(&v).unwrap();
    let gid = add_group(&mut v, id(1), g, t).unwrap();
    for times in [&find(&v, eid).times, &group(&v, gid).times] {
        assert_eq!((times.expires, times.expiry), (false, t));
    }
    ok(&v);
}

#[test]
fn mod_09_2_expired() {
    let v = r9();
    let found = expired_entries(&v, now(at(2026, 10, 24, 22, 51, 0)), 0, &Utc);
    assert_eq!(titles_of(&v, &found), ["X1past"]);
    let later = expired_entries(&v, now(at(2026, 10, 24, 22, 54, 16)), 0, &Utc);
    assert_eq!(titles_of(&v, &later), ["X1past", "X7in40s"]);
    // The strict boundary, at full precision.
    let t = Times {
        expires: true,
        expiry: at(2026, 10, 25, 12, 0, 0),
        ..Times::all(T0)
    };
    let before = Instant {
        secs: at(2026, 10, 25, 11, 59, 59),
        nanos: 999_000_000,
    };
    assert!(!is_expired(&t, before));
    assert!(!is_expired(&t, now(at(2026, 10, 25, 12, 0, 0))));
    let after = Instant {
        secs: at(2026, 10, 25, 12, 0, 0),
        nanos: 1_000_000,
    };
    assert!(is_expired(&t, after));
}

#[test]
fn mod_09_3_within_days() {
    let v = r9();
    let n = now(at(2026, 10, 24, 22, 51, 0));
    assert_eq!(
        titles_of(&v, &expired_entries(&v, n, 3, &Utc)),
        ["X1past", "X3in2days", "X7in40s"]
    );
    assert_eq!(
        titles_of(&v, &expired_entries(&v, n, 7, &Utc)),
        ["X1past", "X3in2days", "X4in5days", "X7in40s"]
    );
    // Across a daylight-saving change (09-06): the window ends at local
    // 2026-10-27 22:00 CET = 21:00:00Z.
    let n = now(at(2026, 10, 24, 20, 0, 0));
    let t = |h: u32, m: u32, s: u32| Times {
        expires: true,
        expiry: at(2026, 10, 27, h, m, s),
        ..Times::all(T0)
    };
    assert!(expires_within(&t(20, 30, 0), n, 3, &Berlin));
    assert!(!expires_within(&t(21, 0, 0), n, 3, &Berlin));
    assert!(!expires_within(&t(21, 0, 1), n, 3, &Berlin));
}

#[test]
fn mod_09_4_groups_do_not_spread() {
    let v = r9();
    let n = now(at(2026, 10, 24, 22, 51, 0));
    assert!(!is_expired(&find(&v, id(0x16)).times, n));
    assert!(is_expired(&group(&v, id(2)).times, n));
    assert!(!expired_entries(&v, n, 90, &Utc).contains(&id(0x16)));
}

#[test]
fn mod_09_5_history_never_counts() {
    let v = r9();
    let found = expired_entries(&v, now(at(2026, 10, 24, 22, 51, 0)), 7, &Utc);
    assert!(!found.contains(&id(0x19)));
}

#[test]
fn mod_09_6_recycle_bin() {
    let v = r9();
    let n = now(at(2026, 10, 24, 22, 51, 0));
    assert!(!expired_entries(&v, n, 7, &Utc).contains(&id(0x15)));
    assert!(
        is_expired(&find(&v, id(0x15)).times, n),
        "still drawn as expired"
    );
}

#[test]
fn mod_09_7_notice_after_unlock() {
    let v = r9();
    let n = now(at(2026, 10, 24, 22, 51, 0));
    let shown = notice(&v, NoticeSettings::default(), true, n, &Utc).unwrap();
    assert_eq!(
        (shown.search.as_str(), shown.message, shown.days),
        ("is:expired-3", "MSG-09-2", 3)
    );
    assert_eq!(
        titles_of(&v, &shown.entries),
        ["X1past", "X3in2days", "X7in40s"]
    );
    let zero = NoticeSettings { on: true, days: 0 };
    let shown = notice(&v, zero, true, n, &Utc).unwrap();
    assert_eq!(
        (shown.search.as_str(), shown.message),
        ("is:expired-0", "MSG-09-1")
    );
    assert_eq!(titles_of(&v, &shown.entries), ["X1past"]);
    assert_eq!(
        notice(&v, NoticeSettings::default(), false, n, &Utc),
        None,
        "not after a relock"
    );
    let off = NoticeSettings { on: false, days: 3 };
    assert_eq!(notice(&v, off, true, n, &Utc), None);
    assert_eq!(
        notice(&sample(), NoticeSettings::default(), true, n, &Utc),
        None,
        "nothing found"
    );
    assert_eq!(
        NoticeSettings::default(),
        NoticeSettings { on: true, days: 3 }
    );
}

#[test]
fn mod_09_8_search_word() {
    let cases = [
        ("expired", Some(0)),
        ("EXPIRED", Some(0)),
        ("expired-3", Some(3)),
        ("expired--3", Some(3)),
        ("expired--1", Some(1)),
        ("expired-+3", Some(3)),
        ("expired-3x", Some(0)),
        ("expired-abc", Some(0)),
        ("expiredX", Some(0)),
        ("expiredfoo-3", Some(3)),
        ("expired-0", Some(0)),
        ("expired-2147483647", Some(2_147_483_647)),
        ("expired-2147483648", Some(0)),
        ("expire", None),
        ("tag", None),
    ];
    for (word, want) in cases {
        assert_eq!(search_days(word), want, "{word}");
    }
    // A window past what App computes holds every in-range entry.
    let v = r9();
    let n = now(at(2026, 10, 24, 22, 51, 0));
    assert_eq!(
        titles_of(&v, &expired_entries(&v, n, 2_147_483_647, &Utc)),
        ["X1past", "X3in2days", "X4in5days", "X7in40s"]
    );
}

#[test]
fn mod_09_9_expire_now() {
    let mut v = sample();
    let t = at(2026, 10, 25, 9, 0, 0);
    v.root.entries[1].times.expires = true;
    v.root.entries[1].times.expiry = at(2030, 1, 1, 0, 0, 0);
    assert_eq!(expire_now(&mut v, &[id(0x10), id(0x11)], t), Ok(2));
    for n in [0x10, 0x11] {
        let e = find(&v, id(n));
        let tt = &e.times;
        assert_eq!(
            (tt.expires, tt.expiry, tt.last_modification, tt.last_access),
            (true, t, t, t)
        );
        assert!(e.history.is_empty());
    }
    // In the recycle bin too.
    v.meta.recycle_bin = Some(id(4));
    v.root.groups[1].entries.push(entry(0x15, "binned"));
    assert_eq!(expire_now(&mut v, &[id(0x15)], t), Ok(1));
    ok(&v);
}

#[test]
fn mod_09_10_entry_editor() {
    let mut t = Times {
        expires: false,
        expiry: at(2020, 1, 1, 0, 0, 0),
        ..Times::all(T0)
    };
    let mut c = Controls::load(&t);
    let tick = at(2026, 10, 25, 9, 15, 0);
    c.tick_entry(tick);
    c.untick();
    c.save(&mut t);
    assert_eq!(
        (t.expires, t.expiry),
        (false, tick),
        "the moment of ticking"
    );
    // Through an edit session, that is a change with a history item.
    let mut v = sample();
    app_core::edit::edit_entry(&mut v, id(0x10), tick, |e| {
        let mut c = Controls::load(&e.times);
        c.tick_entry(tick);
        c.untick();
        c.save(&mut e.times);
    })
    .unwrap();
    assert_eq!(find(&v, id(0x10)).history.len(), 1);
    ok(&v);
}

#[test]
fn mod_09_11_presets() {
    assert_eq!(PRESETS.len(), 12);
    let local_now = at(2026, 10, 24, 20, 0, 0); // 22:00 CEST
    let mut c = Controls::load(&Times::all(T0));
    assert!(c.preset(Preset::Hours(12), local_now, &Berlin));
    assert_eq!((c.expires, c.time), (true, at(2026, 10, 25, 8, 0, 0)));
    assert!(c.preset(Preset::Hours(24), local_now, &Berlin));
    assert_eq!(c.time, at(2026, 10, 25, 20, 0, 0));
    assert!(c.preset(Preset::Weeks(1), local_now, &Berlin));
    assert_eq!(c.time, at(2026, 10, 31, 21, 0, 0));
    let p = |preset: Preset, t: Time| preset.apply(t, &Berlin).unwrap();
    assert_eq!(
        p(Preset::Months(1), at(2026, 1, 31, 9, 0, 0)),
        at(2026, 2, 28, 9, 0, 0)
    );
    assert_eq!(
        p(Preset::Months(3), at(2026, 1, 15, 9, 0, 0)),
        at(2026, 4, 15, 8, 0, 0)
    );
    assert_eq!(
        p(Preset::Years(1), at(2028, 2, 29, 11, 0, 0)),
        at(2029, 2, 28, 11, 0, 0)
    );
    assert_eq!(
        p(Preset::Months(1), at(2028, 1, 31, 9, 0, 0)),
        at(2028, 2, 29, 9, 0, 0),
        "leap year"
    );
    // Past what App computes: nothing changes.
    let before = c;
    assert!(!c.preset(Preset::Years(3), at(9999, 6, 1, 0, 0, 0), &Utc));
    assert_eq!(c, before);
}

#[test]
fn mod_09_12_group_editor() {
    let created = at(2026, 10, 25, 8, 0, 0);
    let mut t = Times::all(created);
    let mut c = Controls::load(&t);
    c.tick_group();
    c.save(&mut t);
    assert_eq!((t.expires, t.expiry), (true, created));
    assert!(is_expired(
        &t,
        Instant {
            secs: created,
            nanos: 1
        }
    ));
}

#[test]
fn mod_09_13_whole_seconds() {
    // A preset at local 22:00:00.700 is stored at 22:00:00 local: stored
    // times have whole seconds, so the sub-second part never enters.
    let local_now = Instant {
        secs: at(2026, 10, 24, 20, 0, 0),
        nanos: 700_000_000,
    };
    assert_eq!(
        Preset::Weeks(1).apply(local_now.secs, &Berlin),
        Some(at(2026, 10, 31, 21, 0, 0))
    );
}

#[test]
fn mod_09_14_look() {
    let v = r9();
    let n = now(at(2026, 10, 24, 22, 51, 0));
    assert!(is_expired(&find(&v, id(0x11)).times, n));
    assert!(!is_expired(&find(&v, id(0x13)).times, n));
    assert!(
        is_expired(&group(&v, id(2)).times, n),
        "groups get the line and badge too"
    );
}

#[test]
fn mod_09_15_text_and_sort() {
    let v = r9();
    let x3 = &find(&v, id(0x13)).times;
    let local = r9_now().0 + 2 * DAY + 3600;
    assert_eq!(
        shown(x3, &Berlin),
        Shown::Local(Time(local).to_civil().unwrap())
    );
    assert_eq!(shown(&find(&v, id(0x12)).times, &Utc), Shown::Never);
    assert!(
        matches!(shown(&group(&v, id(2)).times, &Berlin), Shown::Local(_)),
        "group in local time (D-09-2)"
    );
    assert_eq!(
        sort_key(&find(&v, id(0x12)).times),
        at(9999, 1, 1, 0, 0, 0).0,
        "never as 9999-01-01"
    );
    assert!(sort_key(&find(&v, id(0x12)).times) > sort_key(x3));
}

#[test]
fn mod_09_16_other_features() {
    // Clone keeps the expiry (MOD-10.2); the other readers are other cards.
    let mut v = r9();
    let c = clone_entry(
        &mut v,
        id(0x11),
        Options::default(),
        &app_core::clone::Limits::DEFAULT,
        NOW,
    )
    .unwrap();
    let (a, b) = (&find(&v, id(0x11)).times, &find(&v, c).times);
    assert_eq!((a.expires, a.expiry), (b.expires, b.expiry));
    ok(&v);
}

#[test]
fn mod_09_17_computed_each_time() {
    let v = r9();
    let e = &find(&v, id(0x17)).times;
    assert!(!is_expired(e, now(at(2026, 10, 24, 22, 51, 0))));
    assert!(
        is_expired(e, now(at(2026, 10, 24, 22, 53, 0))),
        "nothing stored, just asked again"
    );
}

#[test]
fn mod_09_18_times_outside_the_range() {
    let below = Times {
        expires: true,
        expiry: Time(-1),
        ..Times::all(T0)
    };
    let above = Times {
        expires: true,
        expiry: Time(315_537_897_600),
        ..Times::all(T0)
    };
    let never = Times::all(T0);
    let a = Times {
        expires: true,
        expiry: at(2026, 1, 1, 0, 0, 0),
        ..Times::all(T0)
    };
    let n = now(at(2026, 10, 24, 22, 51, 0));
    assert!(is_expired(&below, n) && expires_within(&below, n, 3, &Berlin));
    assert!(!is_expired(&above, n) && !expires_within(&above, n, 90, &Berlin));
    assert!(!expires_within(&above, n, 2_147_483_647, &Utc));
    assert_eq!(shown(&below, &Berlin), Shown::Invalid);
    assert_eq!(shown(&above, &Utc), Shown::Invalid);
    let mut keys = [
        sort_key(&a),
        sort_key(&above),
        sort_key(&never),
        sort_key(&below),
    ];
    keys.sort();
    assert_eq!(
        keys,
        [
            sort_key(&below),
            sort_key(&a),
            sort_key(&never),
            sort_key(&above)
        ]
    );
    // The editor keeps the raw value unless the user picks a date.
    let mut t = above.clone();
    Controls::load(&t).save(&mut t);
    assert_eq!(t.expiry, Time(315_537_897_600));
}

/// X08: the notice window is at most 90 days.
#[test]
fn mod_09_7_notice_days_capped() {
    let v = r9();
    let n = now(at(2026, 10, 24, 22, 51, 0));
    let wide = NoticeSettings {
        on: true,
        days: 200,
    };
    let shown = notice(&v, wide, true, n, &Utc).unwrap();
    assert_eq!((shown.search.as_str(), shown.days), ("is:expired-90", 90));
}
