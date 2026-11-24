//! Story E4-S11, card FEA-07: statistics. One test per case (`fea07_tNN_…`),
//! T01 to T26, on the card's demo vaults V3, V4, V6, V7 and FEA-01's S1.
//! Clock 2026-10-25T12:00:00Z, UTC unless a case says otherwise.
//!
//! The tab itself (progress note, cancel on lock, tile order: T22, T25) is
//! E5-S7's and the database-info command E12-S1's; both call
//! `stats::statistics`, the one computation (FEA-07.21, T23).

mod common;

use common::{Berlin, at};
use larsal_core::health::{Ratings, zxcvbn_bits};
use larsal_core::stats::{FileInfo, Stats, statistics};
use larsal_core::time::{Instant, Utc, local};
use larsal_crypto::secret::SecretString;
use larsal_model::{Entry, Field, Group, Uuid, Vault};

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
    let mut e = Entry::new(uid(b), at(2026, 1, 10, 10, 0, 0));
    set(&mut e, "Title", title);
    set(&mut e, "Password", pw);
    e
}

fn grp(b: u8, name: &str) -> Group {
    Group::new(uid(b), name.into(), at(2026, 1, 10, 10, 0, 0))
}

fn saved() -> FileInfo<'static> {
    FileInfo {
        path: Some("/tmp/spec/v3.larsalvault"),
        modified: Some(at(2026, 10, 20, 8, 0, 0)),
        unsaved: false,
    }
}

fn stats(v: &Vault) -> Stats {
    statistics(&Ratings::new(&zxcvbn_bits), v, &saved(), now(), &Utc)
}

/// Demo vault V3 of the card.
fn v3() -> Vault {
    let mut root = grp(0x01, "Root");
    for (b, t) in [(0x10, "Same 1"), (0x11, "Same 2"), (0x12, "Same 3")] {
        root.entries.push(ent(b, t, "samepass1"));
    }
    let mut weak = ent(0x13, "Excluded weak", "abc");
    weak.exclude_from_reports = true;
    root.entries.push(weak);
    let mut empty = ent(0x14, "Excluded empty", "");
    empty.exclude_from_reports = true;
    root.entries.push(empty);
    root.entries.push(ent(0x15, "Emoji", "🔑🔑🔑🔑"));
    root.entries
        .push(ent(0x16, "Long reused 1", "correct horse battery staple"));
    root.entries
        .push(ent(0x17, "Long reused 2", "correct horse battery staple"));
    let mut expired = ent(0x18, "Expired long", "Vb7#Qx2!Lm9$Rt4&Kp6@Wz3^Hy");
    expired.times.expires = true;
    expired.times.expiry = at(2026, 1, 1, 0, 0, 0);
    root.entries.push(expired);
    root.entries.push(ent(
        0x19,
        "Ref pw",
        "{REF:P@I:31313131313131313131313131313131}",
    ));
    let mut hist = ent(0x1a, "With history", "Zq8!fT3#nB6^wR9*");
    hist.history.push(ent(0x1a, "With history", "histpass"));
    root.entries.push(hist);
    let mut totp = ent(0x1b, "Totp", "");
    set(
        &mut totp,
        "otp",
        "otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP",
    );
    root.entries.push(totp);
    let mut passkey = ent(0x1c, "Passkey", "");
    set(
        &mut passkey,
        "KPEX_PASSKEY_CREDENTIAL_ID",
        "ZGVtby1jcmVkZW50aWFs",
    );
    root.entries.push(passkey);
    let mut sub = grp(0x02, "Sub");
    sub.entries.push(ent(0x1d, "Empty pw", ""));
    let mut bin = grp(0x03, "Recycle Bin");
    bin.entries.push(ent(0x1e, "Trashed", "samepass1"));
    root.groups.extend([sub, bin]);
    let mut v = Vault::new(root, at(2026, 1, 10, 10, 0, 0));
    v.meta.name = "V3".into();
    v.meta.recycle_bin = Some(uid(0x03));
    v
}

/// The root plus `pw` entries, one per password.
fn flat(passwords: &[&str]) -> Vault {
    let mut root = grp(0x01, "Root");
    for (i, p) in passwords.iter().enumerate() {
        root.entries
            .push(ent(0x40 + u8::try_from(i).unwrap(), &format!("E{i}"), p));
    }
    Vault::new(root, at(2026, 1, 10, 10, 0, 0))
}

#[test]
fn fea07_t01_groups_and_entries() {
    let s = stats(&v3());
    assert_eq!((s.groups, s.entries), (2, 14));
}

#[test]
fn fea07_t02_expired() {
    assert_eq!(stats(&v3()).expired, 1);
}

#[test]
fn fea07_t03_unique_and_reused() {
    let s = stats(&v3());
    assert_eq!((s.unique_pw, s.reused_pw), (7, 3));
}

#[test]
fn fea07_t04_max_reuse() {
    assert_eq!(stats(&v3()).max_reuse, 3);
}

#[test]
fn fea07_t05_short() {
    assert_eq!(
        stats(&v3()).short_pw,
        1,
        "the emoji password is 8 UTF-16 units"
    );
}

#[test]
fn fea07_t06_weak() {
    assert_eq!(stats(&v3()).weak_pw, 5);
}

#[test]
fn fea07_t07_excluded() {
    assert_eq!(stats(&v3()).excluded, 1);
}

#[test]
fn fea07_t08_average() {
    let s = stats(&v3());
    assert_eq!((s.avg_len, s.avg_text()), (18, "18 characters".into()));
}

#[test]
fn fea07_t09_passkeys_and_totp() {
    let s = stats(&v3());
    assert_eq!((s.passkeys, s.totp), (1, 1));
}

#[test]
fn fea07_t10_warnings() {
    assert_eq!(
        stats(&v3()).warnings(),
        [
            "stat.expired",
            "stat.reused_pw",
            "stat.short_pw",
            "stat.weak_pw",
            "stat.excluded"
        ]
    );
}

#[test]
fn fea07_t11_v6() {
    let mut v = flat(&[
        "Zq8!fT3#nB6^wR9*",
        "Zq8!fT3#nB6^wR9*",
        "Hk4@pX7!mQ2#vT9%",
        "Wd5$rN8^jL3&cF6*",
    ]);
    v.root.entries[2].times.expires = true;
    v.root.entries[2].times.expiry = at(2026, 11, 4, 12, 0, 0);
    v.root.entries[3].exclude_from_reports = true;
    let s = stats(&v);
    assert_eq!(
        (
            s.unique_pw,
            s.reused_pw,
            s.max_reuse,
            s.short_pw,
            s.weak_pw,
            s.excluded
        ),
        (3, 1, 2, 0, 3, 1)
    );
    assert_eq!(s.avg_text(), "16 characters");
}

#[test]
fn fea07_t12_v7() {
    let s = stats(&flat(&["abcdefghi", "abcdefghij"]));
    assert_eq!((s.avg_text(), s.weak_pw), ("10 characters".into(), 2));
    assert!(!s.warnings().contains(&"stat.avg_len"));
}

#[test]
fn fea07_t13_root_only() {
    let s = stats(&flat(&[]));
    assert_eq!((s.groups, s.entries, s.max_reuse, s.avg_len), (1, 0, 0, 0));
    assert_eq!(s.avg_text(), "0 characters");
    assert!(
        s.warnings().is_empty(),
        "the reference warns on the average here"
    );
    let one = stats(&flat(&["x"]));
    assert_eq!(one.avg_text(), "1 character");
}

#[test]
fn fea07_t14_ten_plus_one() {
    let mut pws: Vec<String> = (0..10).map(|i| format!("Distinct-{i}-pass")).collect();
    pws.push("Distinct-0-pass".into());
    let refs: Vec<&str> = pws.iter().map(String::as_str).collect();
    let s = stats(&flat(&refs));
    assert_eq!((s.unique_pw, s.reused_pw), (10, 1));
    assert!(!s.warnings().contains(&"stat.reused_pw"));
}

#[test]
fn fea07_t15_nine_plus_one() {
    let mut pws: Vec<String> = (0..9).map(|i| format!("Distinct-{i}-pass")).collect();
    pws.push("Distinct-0-pass".into());
    let refs: Vec<&str> = pws.iter().map(String::as_str).collect();
    let s = stats(&flat(&refs));
    assert_eq!((s.unique_pw, s.reused_pw), (9, 1));
    assert!(s.warnings().contains(&"stat.reused_pw"));
}

#[test]
fn fea07_t16_four_share() {
    let s = stats(&flat(&["samepass1"; 4]));
    assert_eq!(s.max_reuse, 4);
    assert!(s.warnings().contains(&"stat.max_reuse"));
}

/// FEA-01's demo vault S1, with the parts this card reads.
fn s1() -> Vault {
    let mut root = grp(0x01, "Vault");
    root.entries.push(ent(0x11, "GitHub", "Tr0ub4dor&3"));
    root.entries.push(ent(0x12, "Gmail", "hunter2"));
    for (e, user, url) in [
        (0, "alex@example.com", "https://github.com/login"),
        (1, "alex.personal", "https://mail.google.com"),
    ] {
        set(&mut root.entries[e], "UserName", user);
        set(&mut root.entries[e], "URL", url);
    }
    let mut banking = grp(0x02, "Banking");
    banking.entries.push(ent(0x13, "Big Bank", "hunter2"));
    let mut cards = grp(0x03, "Cards");
    let mut visa = ent(0x14, "Visa Card", "4111-1111");
    visa.times.expires = true;
    visa.times.expiry = at(2026, 1, 1, 0, 0, 0);
    cards.entries.push(visa);
    banking.groups.push(cards);
    let mut archive = grp(0x04, "Archive");
    archive.searching = larsal_model::Switch::Off;
    archive.entries.push(ent(0x15, "Old GitHub", "oldpass"));
    let mut bin = grp(0x05, "Recycle Bin");
    bin.entries.push(ent(0x16, "Deleted GitHub", ""));
    let mut dev = grp(0x06, "Dev & Ops");
    let mut build = ent(0x17, "Build server", "s3rver!");
    set(
        &mut build,
        "otp",
        "otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP",
    );
    dev.entries.push(build);
    root.groups.extend([banking, archive, bin, dev]);
    let mut v = Vault::new(root, at(2026, 1, 1, 0, 0, 0));
    v.meta.recycle_bin = Some(uid(0x05));
    v
}

#[test]
fn fea07_t17_s1() {
    let s = stats(&s1());
    assert_eq!(
        (
            s.groups,
            s.entries,
            s.expired,
            s.unique_pw,
            s.reused_pw,
            s.max_reuse
        ),
        (5, 6, 1, 5, 1, 2)
    );
    assert_eq!(
        (s.short_pw, s.weak_pw, s.excluded, s.passkeys, s.totp),
        (4, 6, 0, 0, 1)
    );
    assert_eq!(s.avg_text(), "8 characters");
}

#[test]
fn fea07_t18_case_matters() {
    let s = stats(&flat(&["Abc", "abc"]));
    assert_eq!((s.unique_pw, s.reused_pw), (2, 0));
}

#[test]
fn fea07_t19_information_rows() {
    let mut v = v3();
    v.meta.description = "demo".into();
    let s = stats(&v);
    assert_eq!(
        (
            s.name.as_str(),
            s.description.as_str(),
            s.location.as_str(),
            s.unsaved
        ),
        ("V3", "demo", "/tmp/spec/v3.larsalvault", false)
    );
    assert_eq!(
        s.created,
        at(2026, 1, 10, 10, 0, 0),
        "the root group's creation"
    );
    assert_eq!(s.last_saved, Some(at(2026, 10, 20, 8, 0, 0)));
    // FEA-07.20: both shown in local time (Europe/Berlin): 11:00 and 10:00.
    assert_eq!(local(&Berlin, s.created), Some(at(2026, 1, 10, 11, 0, 0)));
    assert_eq!(
        local(&Berlin, s.last_saved.unwrap()),
        Some(at(2026, 10, 20, 10, 0, 0))
    );
}

#[test]
fn fea07_t20_never_saved() {
    let file = FileInfo {
        path: None,
        modified: None,
        unsaved: true,
    };
    let s = statistics(&Ratings::new(&zxcvbn_bits), &flat(&[]), &file, now(), &Utc);
    assert_eq!(
        (s.location.as_str(), s.last_saved, s.unsaved),
        ("", None, true)
    );
    assert_eq!(s.warnings(), ["info.unsaved"]);
}

#[test]
fn fea07_t21_not_live() {
    let mut v = v3();
    let s = stats(&v);
    set(&mut v.root.entries[0], "Password", "changed elsewhere");
    assert_eq!(
        s.unique_pw, 7,
        "the computed numbers stay until computed again"
    );
    assert_eq!(stats(&v).unique_pw, 8);
}

#[test]
fn fea07_t22_large_vault() {
    // The progress note and the cancel on lock are E5-S7's; the core
    // computation for 10,000 entries finishes and is timed here.
    let mut root = grp(0x01, "Root");
    for i in 0..10_000u32 {
        let mut e = Entry::new(
            Uuid([
                (i % 251) as u8,
                (i / 251) as u8,
                7,
                7,
                7,
                7,
                7,
                7,
                7,
                7,
                7,
                7,
                7,
                7,
                7,
                1,
            ]),
            at(2026, 1, 1, 0, 0, 0),
        );
        set(&mut e, "Password", &format!("pw-{i}-x{}", i % 97));
        root.entries.push(e);
    }
    let v = Vault::new(root, at(2026, 1, 1, 0, 0, 0));
    let t = std::time::Instant::now();
    let s = stats(&v);
    println!(
        "TIMING statistics of 10,000 entries: {} ms",
        t.elapsed().as_millis()
    );
    assert_eq!((s.entries, s.unique_pw), (10_000, 10_000));
}

#[test]
fn fea07_t23_one_computation() {
    // The tab and the command line both call `statistics`: the same
    // inputs give the same record.
    assert_eq!(stats(&v3()), stats(&v3()));
}

#[test]
fn fea07_t24_root_named_as_bin() {
    // LD-135 (4), LD-76: a bin reference naming the root means no bin, so
    // nothing is left out.
    let mut v = v3();
    v.meta.recycle_bin = Some(uid(0x01));
    let s = stats(&v);
    assert_eq!((s.groups, s.entries), (3, 15));
}

#[test]
fn fea07_t26_no_password_crosses() {
    let text = format!("{:?}", stats(&v3()));
    for pw in [
        "samepass1",
        "abc\"",
        "🔑",
        "correct horse",
        "Vb7#",
        "{REF:",
        "Zq8!",
        "histpass",
    ] {
        assert!(!text.contains(pw), "{pw}");
    }
}

#[test]
fn fea07_edge_cases() {
    // No recycle bin: nothing left out.
    let mut v = v3();
    v.meta.recycle_bin = None;
    assert_eq!(stats(&v).entries, 15);
    // An expired entry with a password of 25 units or more is never weak.
    let mut v = flat(&["Vb7#Qx2!Lm9$Rt4&Kp6@Wz3^Hy"]);
    v.root.entries[0].times.expires = true;
    v.root.entries[0].times.expiry = at(2026, 1, 1, 0, 0, 0);
    let s = stats(&v);
    assert_eq!((s.expired, s.weak_pw), (1, 0));
    // FEA-07.10's bounds: under 25 units and a score under 75.
    let est = |pw: &str, _: &[&str]| if pw.starts_with('s') { 75.0 } else { 1.0 };
    let v = flat(&[&"w".repeat(24), &"w".repeat(25), "strong"]);
    let s = statistics(&Ratings::new(&est), &v, &saved(), now(), &Utc);
    assert_eq!(s.weak_pw, 1, "24 units weak; 25 units and score 75 not");
    // Expiry on but still ahead: not expired.
    let mut v = flat(&["x"]);
    v.root.entries[0].times.expires = true;
    v.root.entries[0].times.expiry = at(2027, 1, 1, 0, 0, 0);
    assert_eq!(stats(&v).expired, 0);
    // A reference password is its own 42-unit password.
    let s = stats(&flat(&[
        "samepass1",
        "{REF:P@I:40404040404040404040404040404040}",
    ]));
    assert_eq!((s.unique_pw, s.reused_pw), (2, 0));
}
