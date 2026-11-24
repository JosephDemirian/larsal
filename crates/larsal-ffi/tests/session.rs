//! E5-S2: the session and its views, on the demo vaults of testdata/
//! (passwords in testdata/README.md). Each test names its card row or check.

use larsal_crypto::secret::SecretString;
use larsal_ffi::session::{LarsalError, Session, UnlockResult};
use larsal_ffi::views::{EntryDetail, EntryList, FieldKind, ListView, Sidebar};
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, open};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

fn testdata(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// A session with `name` open and unlocked with `password`.
fn unlocked(name: &str, password: &str) -> (Arc<Session>, u64) {
    let session = Session::new();
    let id = session.open(testdata(name)).unwrap();
    let result = session.unlock(id, Some(password.into()), None).unwrap();
    assert_eq!(result, UnlockResult::Unlocked, "{name}");
    (session, id)
}

fn failed_id(result: UnlockResult) -> String {
    match result {
        UnlockResult::Failed { message } => message.id,
        other => panic!("expected a message, got {other:?}"),
    }
}

/// Every view the main window can ask for.
fn every_view(session: &Session, id: u64) -> (Sidebar, Vec<EntryList>, Vec<EntryDetail>) {
    let sidebar = session.sidebar(id).unwrap();
    let mut views = vec![
        ListView::All,
        ListView::Expired,
        ListView::Weak,
        ListView::Bin,
        ListView::Search {
            query: "demo".into(),
        },
    ];
    views.extend(
        sidebar
            .groups
            .iter()
            .map(|g| ListView::Group { id: g.id.clone() }),
    );
    views.extend(sidebar.tags.iter().map(|t| ListView::Tag {
        name: t.name.clone(),
    }));
    let lists: Vec<EntryList> = views
        .into_iter()
        .map(|v| session.list(id, v).unwrap())
        .collect();
    let mut details = Vec::new();
    for list in &lists {
        for row in &list.rows {
            details.push(session.entry(id, row.id.clone()).unwrap());
        }
    }
    (sidebar, lists, details)
}

/// The vault's protected values, read with larsal-format directly.
fn protected_values(name: &str, password: &str) -> Vec<String> {
    let file = std::fs::read(testdata(name)).unwrap();
    let pw = SecretString::new(password.into());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let mut host = larsal_crypto::kdf::Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: None,
    };
    let Ok(Opened::Vault(v)) = open(&file, &creds, &mut host, &Limits::DEFAULT, None) else {
        panic!("{name} opens")
    };
    let mut out = Vec::new();
    for e in v.vault.root.all_entries() {
        for item in std::iter::once(e).chain(e.history.iter()) {
            for (_, f) in item.fields() {
                if f.protected && !f.value.is_empty() {
                    out.push(f.value.expose().to_owned());
                }
            }
        }
    }
    out
}

/// AGENTS.md rule 4, architecture larsal-ffi Must: no view string of rich-v4
/// holds a protected value (passwords, `Demo PIN`, the `otp` secret).
#[test]
fn e5_s2_views_carry_no_protected_value() {
    let secrets = protected_values("rich-v4.larsalvault", "demo-pass-5");
    assert!(
        secrets.len() >= 5,
        "rich-v4 has protected values: {}",
        secrets.len()
    );
    let (session, id) = unlocked("rich-v4.larsalvault", "demo-pass-5");
    let (sidebar, lists, details) = every_view(&session, id);
    assert!(details.len() >= 5, "views list entries");
    // Every text a view carries, but ids: fixed demo ids such as
    // 00000000000000000000000000000002 would match a PIN like 0000.
    let mut texts: Vec<String> = Vec::new();
    for g in &sidebar.groups {
        texts.push(g.name.clone());
    }
    texts.extend(sidebar.tags.iter().map(|t| t.name.clone()));
    for list in &lists {
        texts.extend(list.notice.clone());
        for r in &list.rows {
            texts.extend([r.title.clone(), r.subtitle.clone()]);
        }
    }
    for d in &details {
        texts.push(d.title.clone());
        texts.extend(d.path.iter().cloned());
        texts.extend(d.tags.iter().cloned());
        texts.extend(d.attachments.iter().map(|a| a.name.clone()));
        for f in &d.fields {
            texts.extend([f.name.clone(), f.value.clone()]);
        }
    }
    for v in session.vaults() {
        texts.extend([v.name, v.path]);
    }
    assert!(texts.len() > 30);
    for s in &secrets {
        assert!(
            texts.iter().all(|t| !t.contains(s.as_str())),
            "a view holds a protected value"
        );
    }
    // The password field is there, hidden.
    let full = details
        .iter()
        .find(|d| d.title == "Full demo entry")
        .unwrap();
    let pw = full
        .fields
        .iter()
        .find(|f| f.kind == FieldKind::Password)
        .unwrap();
    assert!(pw.protected && pw.value.is_empty());
    assert!(
        full.fields.iter().all(|f| f.name != "otp"),
        "otp is never a field"
    );
    assert!(full.has_totp);
    assert_eq!(full.attachments.len(), 3);
    assert!(full.expired, "expires 2025-06-30");
}

/// Show returns the one value; Copy keeps it in Rust and answers only the
/// notice's label and seconds (E6-S1; more in tests/clipboard.rs).
#[test]
fn e5_s2_show_and_copy() {
    let (session, id) = unlocked("rich-v4.larsalvault", "demo-pass-5");
    let rows = session.list(id, ListView::All).unwrap().rows;
    let full = rows.iter().find(|r| r.title == "Full demo entry").unwrap();
    let shown = session
        .show_field(id, full.id.clone(), "Password".into())
        .unwrap();
    assert!(protected_values("rich-v4.larsalvault", "demo-pass-5").contains(&shown));
    let copied = session
        .copy_field(id, full.id.clone(), "Password".into())
        .unwrap();
    assert_eq!((copied.label.as_str(), copied.seconds), ("Password", 10));
    assert_eq!(
        session.show_field(id, full.id.clone(), "No such field".into()),
        Err(LarsalError::UnknownField)
    );
    session.lock(id).unwrap();
    assert!(session.clipboard().peek().is_empty(), "cleared on lock");
}

/// AT-E03: hostile arguments give typed errors, never a panic or a secret.
#[test]
fn at_e03_hostile_arguments() {
    let (session, rich) = unlocked("rich-v4.larsalvault", "demo-pass-5");
    let big = session.open(testdata("big-10000.larsalvault")).unwrap();
    assert_eq!(
        session.unlock(big, Some("demo-pass-6".into()), None),
        Ok(UnlockResult::Unlocked)
    );
    let big_row = session.list(big, ListView::All).unwrap().rows[0].id.clone();
    // An id of another vault.
    assert_eq!(
        session.entry(rich, big_row.clone()),
        Err(LarsalError::UnknownEntry)
    );
    assert_eq!(
        session.show_field(rich, big_row.clone(), "Password".into()),
        Err(LarsalError::UnknownEntry)
    );
    assert_eq!(
        session.copy_code(rich, big_row.clone()),
        Err(LarsalError::UnknownEntry)
    );
    assert_eq!(
        session.copy_fingerprint(rich, big_row.clone()),
        Err(LarsalError::UnknownEntry)
    );
    // The one-time password fields: neither Show nor Copy gives their secret.
    let full = session.list(rich, ListView::All).unwrap().rows;
    let full = full.iter().find(|r| r.title == "Full demo entry").unwrap();
    // The passkey fields too (MOD-01.8, F-057).
    for field in [
        "otp",
        "TOTP Seed",
        "TOTP Settings",
        "TimeOtp-Secret-Base32",
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
        "KPEX_PASSKEY_USER_HANDLE",
    ] {
        assert_eq!(
            session.show_field(rich, full.id.clone(), field.into()),
            Err(LarsalError::UnknownField),
            "{field}"
        );
        assert_eq!(
            session.copy_field(rich, full.id.clone(), field.into()),
            Err(LarsalError::UnknownField),
            "{field}"
        );
    }
    // Unknown and malformed ids; a sign is not a hex digit.
    let signed = format!("+{}", full.id.get(1..).unwrap());
    assert_eq!(session.entry(rich, signed), Err(LarsalError::UnknownEntry));
    assert_eq!(session.sidebar(999), Err(LarsalError::UnknownVault));
    for bad in [
        "",
        "x",
        &"0".repeat(32),
        &"é".repeat(16),
        &"a".repeat(1 << 20),
    ] {
        assert_eq!(
            session.entry(rich, bad.into()),
            Err(LarsalError::UnknownEntry)
        );
        assert_eq!(
            session.totp(rich, bad.into()),
            Err(LarsalError::UnknownEntry)
        );
        assert_eq!(
            session.copy_code(rich, bad.into()),
            Err(LarsalError::UnknownEntry)
        );
        assert_eq!(
            session.copy_fingerprint(rich, bad.into()),
            Err(LarsalError::UnknownEntry)
        );
    }
    assert_eq!(
        session.list(rich, ListView::Group { id: "zz".into() }),
        Err(LarsalError::UnknownGroup)
    );
    // Huge strings.
    let huge = "a".repeat(10 << 20);
    assert_eq!(
        session.show_field(rich, big_row.clone(), huge.clone()),
        Err(LarsalError::TooLong)
    );
    assert_eq!(
        session.list(
            rich,
            ListView::Search {
                query: huge.clone()
            }
        ),
        Err(LarsalError::TooLong)
    );
    assert_eq!(
        session.unlock(rich, Some(huge.clone()), None),
        Err(LarsalError::TooLong)
    );
    assert_eq!(session.open(huge.clone()), Err(LarsalError::TooLong));
    // After lock.
    session.lock(rich).unwrap();
    assert_eq!(session.sidebar(rich), Err(LarsalError::Locked));
    assert_eq!(
        session.entry(rich, big_row.clone()),
        Err(LarsalError::Locked)
    );
    // Two threads at once.
    let threads: Vec<_> = (0..2)
        .map(|n| {
            let session = session.clone();
            let row = big_row.clone();
            std::thread::spawn(move || {
                for _ in 0..50 {
                    let _ = session.list(
                        big,
                        ListView::Search {
                            query: "Entry 00".into(),
                        },
                    );
                    let _ = session.entry(big, row.clone());
                    if n == 1 {
                        let _ = session.switch_to(big);
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    // Closed: every call answers UnknownVault; error texts hold no secret.
    session.close(big).unwrap();
    let error = session.entry(big, big_row).unwrap_err();
    assert_eq!(error, LarsalError::UnknownVault);
    assert!(!error.to_string().contains("demo-pw"));
}

/// APP-06 messages through the session: M06-05, M06-06, M06-11, M06-30, and
/// a key file vault unlocked by its key file alone.
#[test]
fn app06_unlock_messages() {
    let session = Session::new();
    let id = session.open(testdata("rich-v4.larsalvault")).unwrap();
    let none = session.unlock(id, None, None).unwrap();
    let UnlockResult::Failed { message } = none else {
        panic!("M06-05")
    };
    assert_eq!(message.id, "M06-05");
    assert!(message.blank_password);
    assert_eq!(
        failed_id(session.unlock(id, Some("wrong".into()), None).unwrap()),
        "M06-06"
    );
    assert_eq!(
        failed_id(
            session
                .unlock(id, None, Some("missing.larsalkey".into()))
                .unwrap()
        ),
        "M06-11"
    );
    assert_eq!(
        failed_id(
            session
                .unlock(id, None, Some("rich-v4.larsalvault".into()))
                .unwrap()
        ),
        "M06-30"
    );
    let keyed = session.open(testdata("keyfile-hex64.larsalvault")).unwrap();
    assert_eq!(
        session.unlock(keyed, None, Some("key-hex64.larsalkey".into())),
        Ok(UnlockResult::Unlocked)
    );
    // T35: the same message for a wrong key file as for a wrong password.
    let both = session
        .open(testdata("password-and-keyfile.larsalvault"))
        .unwrap();
    assert_eq!(
        failed_id(
            session
                .unlock(
                    both,
                    Some("demo-pass-2".into()),
                    Some("key-binary32.larsalkey".into())
                )
                .unwrap()
        ),
        "M06-06"
    );
}

/// APP-09.15: the same file twice is one vault; a missing path is M09-07;
/// close and switch.
#[test]
fn app09_15_open_switch_close() {
    let session = Session::new();
    let a = session.open(testdata("rich-v4.larsalvault")).unwrap();
    let b = session.open(testdata("rich-v3.larsalvault")).unwrap();
    assert_eq!(
        session.open(testdata("../testdata/rich-v4.larsalvault")),
        Ok(a)
    );
    let shown: Vec<bool> = session.vaults().iter().map(|v| v.shown).collect();
    assert_eq!(shown, [true, false]);
    session.switch_to(b).unwrap();
    let v = session.vaults();
    assert_eq!(
        (v[1].name.as_str(), v[1].shown, v[1].locked),
        ("rich-v3", true, true)
    );
    assert!(v[1].path.ends_with("testdata/rich-v3.larsalvault"));
    let missing = testdata("none.larsalvault");
    assert_eq!(
        session.open(missing.clone()),
        Err(LarsalError::CannotOpen(missing))
    );
    assert!(matches!(
        session.open(testdata("")),
        Err(LarsalError::CannotOpen(_))
    ));
    session.close(b).unwrap();
    assert_eq!(session.vaults().len(), 1);
    assert!(session.vaults()[0].shown);
    assert_eq!(session.switch_to(b), Err(LarsalError::UnknownVault));
}

/// APP-06.3: a file that is not a vault shows M06-01 before Unlock.
#[test]
fn app06_3_header_look() {
    let session = Session::new();
    let text = session.open(testdata("README.md")).unwrap();
    assert_eq!(session.check_header(text).unwrap().unwrap().id, "M06-01");
    let vault = session.open(testdata("rich-v4.larsalvault")).unwrap();
    assert_eq!(session.check_header(vault), Ok(None));
}

/// APP-06.16: a lock that arrives while the KDF runs wins.
#[test]
fn app06_16_lock_during_unlock_drops_the_result() {
    let session = Session::new();
    let id = session.open(testdata("default-time.larsalvault")).unwrap();
    // Calibrate first, so the second attempt is only the KDF.
    let _ = session.unlock(id, Some("wrong".into()), None);
    // F-090: under heavy load the KDF can end before this thread sees the
    // flag, or before the lock lands; such a round proves nothing and runs
    // again, and no wait is without a deadline.
    for round in 1..=20 {
        let worker = {
            let session = session.clone();
            std::thread::spawn(move || session.unlock(id, Some("demo-pass-3".into()), None))
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while !session.vaults()[0].unlocking && !worker.is_finished() {
            assert!(std::time::Instant::now() < deadline, "the unlock never ran");
            std::thread::yield_now();
        }
        session.lock(id).unwrap();
        let result = worker.join().unwrap();
        assert!(session.vaults()[0].locked);
        if result == Ok(UnlockResult::Ignored) {
            return;
        }
        assert_eq!(result, Ok(UnlockResult::Unlocked), "round {round}");
    }
    panic!("the lock never landed during the unlock in 20 rounds");
}

/// LD-277 (2), APP-06.16: the unlock form reads the lock count at the
/// click; a lock between the click and the unlock's start stops it, so
/// the vault stays locked and the password is dropped.
#[test]
fn ld277_2_a_lock_after_the_click_stops_the_unlock() {
    let session = Session::new();
    let id = session.open(testdata("default-time.larsalvault")).unwrap();
    let clicked = session.lock_epoch(id).unwrap();
    session.lock(id).unwrap();
    let late = session.unlock_with_key(id, Some("demo-pass-3".into()), None, None, clicked);
    assert_eq!(late, Ok(UnlockResult::Ignored));
    assert!(session.vaults()[0].locked);
    let clicked = session.lock_epoch(id).unwrap();
    let now = session.unlock_with_key(id, Some("demo-pass-3".into()), None, None, clicked);
    assert_eq!(now, Ok(UnlockResult::Unlocked));
    assert_eq!(session.lock_epoch(id), Ok(clicked));
    assert_eq!(session.lock_epoch(99), Err(LarsalError::UnknownVault));
}

/// FEA-01 through the session: views, tags, the bin and the notice.
#[test]
fn fea01_views_through_the_session() {
    let (session, id) = unlocked("rich-v4.larsalvault", "demo-pass-5");
    let sidebar = session.sidebar(id).unwrap();
    let names: Vec<&str> = sidebar.groups.iter().map(|g| g.name.as_str()).collect();
    assert!(
        names.contains(&"Work") && names.contains(&"Old servers"),
        "{names:?}"
    );
    assert!(
        sidebar.bin.is_some_and(|n| n >= 2),
        "deleted entry and group entry"
    );
    let demo_tag = sidebar.tags.iter().find(|t| t.name == "demo").unwrap();
    let tagged = session
        .list(
            id,
            ListView::Tag {
                name: "demo".into(),
            },
        )
        .unwrap()
        .rows;
    assert_eq!(u32::try_from(tagged.len()).unwrap(), demo_tag.count);
    let found = session
        .list(
            id,
            ListView::Search {
                query: "*t:[".into(),
            },
        )
        .unwrap();
    assert!(
        found.rows.is_empty() && found.notice.is_some(),
        "FEA-01.31 notice"
    );
    let long = session
        .list(
            id,
            ListView::Search {
                query: "x".repeat(1025),
            },
        )
        .unwrap();
    assert!(long.notice.is_some(), "FEA-01.32");
    assert_eq!(
        session.list(id, ListView::All).unwrap().rows.len(),
        sidebar.all as usize
    );
}

/// FEA-04.14, FEA-04.15: the live code of the entry on screen.
#[test]
fn fea04_live_code() {
    let (session, id) = unlocked("rich-v4.larsalvault", "demo-pass-5");
    let rows = session
        .list(
            id,
            ListView::Tag {
                name: "demo".into(),
            },
        )
        .unwrap()
        .rows;
    let full = rows.iter().find(|r| r.title == "Full demo entry").unwrap();
    let code = session.totp(id, full.id.clone()).unwrap().unwrap();
    assert_eq!(code.problem, None);
    assert!((1..=code.period).contains(&code.seconds_left));
    let (left, right) = code.code.split_once(' ').unwrap();
    assert!(left.len() + right.len() >= 6 && left.len() == (left.len() + right.len()) / 2);
    // An entry without settings has no code.
    let plain = rows.iter().find(|r| r.id != full.id);
    if let Some(r) = plain {
        assert_eq!(session.totp(id, r.id.clone()), Ok(None));
    }
}

/// FEA-01.34 and the architecture's target: a search of up to 5 terms over
/// 10,000 entries, rows included, in under 50 ms (debug builds optimize the
/// engine crates, Cargo.toml).
#[test]
fn fea01_34_search_speed_on_big_10000() {
    let (session, id) = unlocked("big-10000.larsalvault", "demo-pass-6");
    let queries = [
        "Entry 0999",
        "user01 -Entry",
        "t:Entry u:user0 9 99 999",
        "*t:^Entry 1",
        "zzz",
    ];
    let mut worst = 0u128;
    // The best of three runs per query: the work itself, not a moment when
    // other test binaries hold every core.
    for q in queries {
        let mut best = u128::MAX;
        let mut rows = 0;
        for _ in 0..3 {
            let start = Instant::now();
            let list = session
                .list(id, ListView::Search { query: q.into() })
                .unwrap();
            best = best.min(start.elapsed().as_millis());
            rows = list.rows.len();
        }
        worst = worst.max(best);
        eprintln!("search {q:?}: {rows} rows in {best} ms");
    }
    let start = Instant::now();
    let all = session.list(id, ListView::All).unwrap();
    eprintln!(
        "all {} rows in {} ms",
        all.rows.len(),
        start.elapsed().as_millis()
    );
    assert_eq!(all.rows.len(), 10_000);
    assert!(worst < 50, "worst search {worst} ms");
}

/// LD-185 (Verify C25): the Weak view and a typed `is:weak` rate every
/// password first with the session's cache, so they are complete.
#[test]
fn ld185_weak_view_and_typed_search_are_complete() {
    let (s, id) = unlocked("option-a-personal.larsalvault", "demo-pass-7");
    assert_eq!(s.list(id, ListView::Weak).unwrap().rows.len(), 6);
    assert_eq!(s.search(id, "is:weak".into()).unwrap().ids.len(), 6);
    let (s, id) = unlocked("big-10000.larsalvault", "demo-pass-6");
    let weak = s.list(id, ListView::Weak).unwrap();
    assert_eq!(weak.rows.len(), 10_000);
    assert!(weak.notice.is_none());
    let typed = s.search(id, "is:weak".into()).unwrap();
    assert_eq!(typed.ids.len(), 10_000);
    assert!(typed.notice.is_none());
}
