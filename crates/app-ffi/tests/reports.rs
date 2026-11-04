//! E5-S7 check "numbers match app-core tests": the Statistics and Health
//! Check numbers that reach the screen equal app-core's own computation and
//! the card's cases (FEA-07 T01 to T09 on the card's vault V3, FEA-05.12 to
//! FEA-05.15 on the same vault). The vault is made here, saved with a fast
//! KDF and opened in a test session; nothing leaves this Mac.

use app_core::health::{Ratings, health_check, zxcvbn_bits};
use app_core::stats::{FileInfo, statistics};
use app_core::time::{Instant, Utc};
use app_crypto::kdf::Host;
use app_crypto::secret::SecretString;
use app_ffi::session::{Session, UnlockResult};
use app_format::keys::Credentials;
use app_format::limits::Limits;
use app_format::{Saved, save};
use app_model::{Argon2Kind, Encryption, Entry, Field, Group, Kdf, Time, Uuid, Vault};
use std::path::PathBuf;
use std::sync::Arc;

fn uid(b: u8) -> Uuid {
    Uuid([b; 16])
}

fn made() -> Time {
    Time::from_unix(1_768_039_200).unwrap() // 2026-01-10T10:00Z
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
    let mut e = Entry::new(uid(b), made());
    set(&mut e, "Title", title);
    set(&mut e, "Password", pw);
    e
}

/// The card's demo vault V3 (FEA-07 test cases).
fn v3() -> Vault {
    let mut root = Group::new(uid(0x01), "Root".into(), made());
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
    expired.times.expiry = Time::from_unix(1_767_225_600).unwrap(); // 2026-01-01
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
    let mut sub = Group::new(uid(0x02), "Sub".into(), made());
    sub.entries.push(ent(0x1d, "Empty pw", ""));
    let mut bin = Group::new(uid(0x03), "Recycle Bin".into(), made());
    bin.entries.push(ent(0x1e, "Trashed", "samepass1"));
    root.groups.extend([sub, bin]);
    let mut v = Vault::new(root, made());
    v.meta.name = "V3".into();
    v.meta.recycle_bin = Some(uid(0x03));
    v.meta.recycle_bin_enabled = true;
    // A fast KDF: a demo vault for a test.
    v.encryption = Encryption {
        kdf: Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 2,
            memory_kib: 1024,
            lanes: 1,
        },
        ..Encryption::default()
    };
    v
}

/// V3 saved with the demo password `demo` and unlocked in a test session.
fn opened(name: &str) -> (Arc<Session>, u64, Vault) {
    opened_with(name, v3())
}

/// `vault` saved with the demo password `demo` and unlocked in a test
/// session.
fn opened_with(name: &str, vault: Vault) -> (Arc<Session>, u64, Vault) {
    let secret = SecretString::new("demo".to_owned());
    let credentials = Credentials {
        password: Some(&secret),
        key_file: None,
        hardware_key: None,
    };
    let mut host = Host {
        physical_memory: 8 << 30,
        logical_processors: 4,
        argon2_record: None,
        aes_record: None,
    };
    let Ok(Saved::File(saved)) = save(
        &vault,
        &credentials,
        None,
        &mut host,
        &Limits::DEFAULT,
        None,
    ) else {
        panic!("save V3");
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("reports-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.appvault"));
    std::fs::write(&path, &saved.bytes).unwrap();
    let session = Session::new();
    let id = session.open(path.to_string_lossy().into_owned()).unwrap();
    assert_eq!(
        session.unlock(id, Some("demo".into()), None).unwrap(),
        UnlockResult::Unlocked
    );
    (session, id, vault)
}

fn core_now() -> Instant {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Instant::from(Time::from_unix(i64::try_from(secs).unwrap()).unwrap())
}

/// LD-137 (4), E5-S7 Verify advisory: the background fill rates with the
/// entry's title, user name and host as inputs (FEA-05.9), as app-core does:
/// a password made of its own user name or title rates far lower than alone.
#[test]
fn ld_137_the_fill_rates_with_title_user_and_host() {
    let mut vault = v3();
    let mut router = ent(0x30, "Router admin", "routeradmin");
    set(&mut router, "UserName", "routeradmin");
    vault.root.entries.push(router);
    let mut site = ent(0x31, "Kestrelmoor", "kestrelmoor.example");
    set(&mut site, "URL", "https://kestrelmoor.example/login");
    vault.root.entries.push(site);
    let (s, v, vault) = opened_with("v3-inputs", vault);
    while !s.rate(v, 25, 0).unwrap() {}
    let core = health_check(&Ratings::new(&zxcvbn_bits), &vault, core_now(), &Utc);
    let tab = s.health_report(v, true, 0).unwrap();
    for title in ["Router admin", "Kestrelmoor"] {
        let got = tab.rows.iter().find(|r| r.entry.title == title);
        let want = core.rows(true, true).into_iter().find(|r| r.title == title);
        assert_eq!(
            got.map(|r| r.score),
            want.map(|r| r.score),
            "{title}: the fill's score equals app-core's"
        );
    }
}

/// FEA-07 T01 to T09 and FEA-07.21: the tab shows app-core's numbers.
#[test]
fn fea_07_t01_to_t09_match_app_core() {
    let (s, v, vault) = opened("v3-stats");
    let tab = s.statistics_report(v, 0).unwrap();
    let core = statistics(
        &Ratings::new(&zxcvbn_bits),
        &vault,
        &FileInfo::default(),
        core_now(),
        &Utc,
    );
    let numbers = |a: [u64; 12]| a;
    let card = numbers([14, 2, 7, 3, 3, 5, 1, 1, 1, 1, 18, 1]);
    let from_core = numbers([
        core.entries,
        core.groups,
        core.unique_pw,
        core.reused_pw,
        core.max_reuse,
        core.weak_pw,
        core.short_pw,
        core.expired,
        core.totp,
        core.passkeys,
        core.avg_len,
        core.excluded,
    ]);
    let from_tab = numbers([
        tab.entries,
        tab.groups,
        tab.unique_pw,
        tab.reused_pw,
        tab.max_reuse,
        tab.weak_pw,
        tab.short_pw,
        tab.expired,
        tab.totp,
        tab.passkeys,
        tab.avg_len,
        tab.excluded,
    ]);
    assert_eq!(from_core, card, "app-core against the card");
    assert_eq!(from_tab, from_core, "the tab against app-core");
    assert_eq!((tab.name.as_str(), tab.in_bin), ("V3", 1));
    assert_eq!(tab.created, 1_768_039_200, "the root group's creation");
    assert!(tab.location.ends_with("v3-stats.appvault") && !tab.unsaved);
}

/// FEA-05.12 to FEA-05.16 on V3: the report's rows are app-core's
/// candidates in the same order, the excluded one only when asked.
#[test]
fn fea_05_rows_match_app_core() {
    let (s, v, vault) = opened("v3-health");
    let core = health_check(&Ratings::new(&zxcvbn_bits), &vault, core_now(), &Utc);
    // Once through the product's background fill (LD-137), so its ratings
    // (title, user name and host as inputs) are the ones compared (E5-S7
    // Verify advisory).
    while !s.rate(v, 25, 0).unwrap() {}
    for skipped in [false, true] {
        let tab = s.health_report(v, skipped, 0).unwrap();
        let got: Vec<(String, i64)> = tab
            .rows
            .iter()
            .map(|r| (r.entry.title.clone(), r.score))
            .collect();
        let want: Vec<(String, i64)> = core
            .rows(skipped, true)
            .iter()
            .map(|r| (r.title.clone(), r.score))
            .collect();
        assert_eq!(got, want);
        assert!(tab.any_skipped);
    }
    let tab = s.health_report(v, false, 0).unwrap();
    // Same 1 to 3 share one password; the long pair another.
    let same = tab.rows.iter().find(|r| r.entry.title == "Same 1").unwrap();
    assert_eq!(same.problem, "Reused");
    assert!(
        same.reasons
            .contains(&"Same password on 3 entries".to_owned())
    );
    assert!(same.details.contains(&"• Root/Same 2".to_owned()));
    assert!(tab.reused_passwords >= 1);
    // Ten passwords in the counted entries, the reference one not
    // evaluated (D-05-3).
    assert_eq!(tab.passwords, 10);
    assert_eq!(
        tab.healthy as usize,
        9 - core.rows(true, true).len(),
        "evaluated minus every candidate"
    );
}
