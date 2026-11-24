//! The loop, the guard and the timing against scripted servers on
//! 127.0.0.1, with a stand-in for the open vault and a test clock (no
//! test sleeps). The full runs with real vaults, two Macs and Larsal's server
//! are larsal-ffi's (`sync.rs` tests).
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#![allow(clippy::arithmetic_side_effects)]

use super::*;
use crate::client::tests::{client, signin};
use crate::test_server::{Request, Response, Scripted, TestClock};
use larsal_model::{Argon2Kind, FileVersion, Kdf, Time, Uuid};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn m(newest: i64, major: u16, memory_kib: u64) -> Measures {
    Measures {
        newest: Time(newest),
        version: FileVersion { major, minor: 1 },
        kdf: Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 2,
            memory_kib,
            lanes: 2,
        },
    }
}

/// A link that has seen version 5 (`b"v5"`), with the local file
/// `b"local"` uploaded.
fn link() -> Link {
    Link {
        server: String::new(),
        vault_id: VaultId::from_bytes([3; 16]),
        file: "/tmp/demo.larsalvault".into(),
        root: Uuid([1; 16]),
        highest: 5,
        server_sha: hash(b"v5"),
        local_sha: hash(b"local"),
        seen: m(1_000, 4, 65_536),
    }
}

type MergeFn = dyn Fn(&[u8]) -> Merge + Send + Sync;

/// The open vault: its file is `file`; a merge answers `merge`.
struct Fake {
    file: Option<Vec<u8>>,
    merge: Box<MergeFn>,
    merges: AtomicUsize,
}

impl Fake {
    fn new(file: &[u8], merge: impl Fn(&[u8]) -> Merge + Send + Sync + 'static) -> Self {
        Self {
            file: Some(file.to_vec()),
            merge: Box::new(merge),
            merges: AtomicUsize::new(0),
        }
    }

    /// A merge that keeps a local change: the copy's measures are
    /// `copy`, the result is saved as `b"merged"`.
    fn changed(copy: Measures) -> Self {
        Self::new(b"local", move |_| Merge::Done {
            copy,
            result: m(2_000, 4, 65_536),
            changed: true,
            saved: b"merged".to_vec(),
        })
    }

    fn merges(&self) -> usize {
        self.merges.load(Ordering::SeqCst)
    }
}

impl Local for Fake {
    fn read(&self) -> Option<(Vec<u8>, Measures)> {
        self.file.clone().map(|f| (f, m(1_500, 4, 65_536)))
    }

    fn merge(&self, server: &[u8]) -> Merge {
        self.merges.fetch_add(1, Ordering::SeqCst);
        (self.merge)(server)
    }
}

fn vault(version: u64, body: &[u8]) -> Response {
    Response::new(200, body).with("ETag", &format!("\"{version}\""))
}

/// A server: the sign-in routes, then `script`.
fn server(script: impl Fn(&Request) -> Response + Send + Sync + 'static) -> Scripted {
    Scripted::new(move |r| signin(r).unwrap_or_else(|| script(r)))
}

fn vault_requests(s: &Scripted) -> Vec<Request> {
    s.requests()
        .into_iter()
        .filter(|r| r.path.starts_with("/v1/vaults/"))
        .collect()
}

/// E16-S7a check 5, SYN-03.6, SYN-03 T08: a server that answers every PUT
/// with 412 gets exactly 3 PUTs, with waits of 1 to 3 s before the 2nd and
/// the 3rd; then `MSG-SYNC-BUSY` with the status Error.
#[test]
fn syn03_6_t08_endless_412_gives_3_tries_then_busy() {
    let s = server(|r| match r.method.as_str() {
        "GET" => vault(6, b"v6"),
        _ => Response::new(412, br#"{"error":"precondition_failed"}"#),
    });
    let clock = TestClock::at(0);
    let local = Fake::changed(m(1_200, 4, 65_536));
    let mut l = link();
    let report = run(&mut client(&s), &mut l, &local, &*clock);
    assert_eq!(report, Report::error(Message::Busy));
    assert_eq!(Message::Busy.id(), "MSG-SYNC-BUSY");
    let puts: Vec<Request> = vault_requests(&s)
        .into_iter()
        .filter(|r| r.method == "PUT")
        .collect();
    assert_eq!(puts.len(), 3);
    for p in &puts {
        assert_eq!(p.header("if-match"), Some("\"6\""));
        assert_eq!(p.body, b"merged");
    }
    let waits = clock.waits();
    assert_eq!(waits.len(), 2, "{waits:?}");
    assert!(
        waits.iter().all(|w| (1_000..=3_000).contains(w)),
        "{waits:?}"
    );
    assert_eq!(local.merges(), 3);
}

/// SYN-03.6: the waits are random, not one fixed value (larsal-crypto's
/// source): 40 draws give more than one value, all from 1 to 3 s.
#[test]
fn syn03_6_the_wait_is_random_from_1_to_3_s() {
    let draws: std::collections::BTreeSet<u64> = (0..40).map(|_| jitter_ms()).collect();
    assert!(draws.len() > 1);
    assert!(draws.iter().all(|w| (1_000..=3_000).contains(w)));
}

/// E16-S7a check 4, SYN-03.7, SYN-03 T10: this Mac has seen version 5. A
/// list with version 4, and version 5 served with other bytes, are both
/// refused with `MSG-SYNC-ROLLBACK`: nothing merged, nothing uploaded.
#[test]
fn syn03_7_t10_a_rolled_back_server_is_refused_with_a_warning() {
    let l = link();
    let listed = [VaultVersion {
        id: l.vault_id,
        version: 4,
        size: 2,
    }];
    assert_eq!(
        check_listed(&l, &listed),
        Some(Report::error(Message::Rollback))
    );
    let other = [VaultVersion {
        id: VaultId::from_bytes([4; 16]),
        version: 1,
        size: 2,
    }];
    assert_eq!(check_listed(&l, &other), None);
    assert_eq!(
        check_listed(
            &l,
            &[VaultVersion {
                version: 5,
                ..listed[0]
            }]
        ),
        None
    );

    for (version, body) in [(5, &b"v5 other"[..]), (4, &b"v4"[..])] {
        let s = server(move |_| vault(version, body));
        let local = Fake::changed(m(1_200, 4, 65_536));
        let mut l = link();
        let before = l.clone();
        let report = run(&mut client(&s), &mut l, &local, &*TestClock::at(0));
        assert_eq!(report, Report::error(Message::Rollback), "{version}");
        assert!(
            Message::Rollback
                .text("Personal", "")
                .contains("older copy")
        );
        assert_eq!(local.merges(), 0, "nothing merged");
        assert_eq!(s.count("PUT"), 0, "nothing uploaded");
        assert_eq!(l, before, "the state does not move");
    }
}

/// SYN-03.7, SYN-03 T11: version 6 holding an older file (its newest
/// change time is earlier than the stored one) is merged, the result
/// uploaded, and `MSG-SYNC-WENT-BACK` shown.
#[test]
fn syn03_7_t11_an_old_file_under_a_new_number_is_merged_and_warns() {
    let s = server(|r| match r.method.as_str() {
        "GET" => vault(6, b"v2 bytes"),
        _ => vault(7, br#"{"id":"x"}"#),
    });
    let local = Fake::changed(m(500, 4, 65_536));
    let mut l = link();
    let report = run(&mut client(&s), &mut l, &local, &*TestClock::at(9));
    assert_eq!(
        report,
        Report::of(Status::Synced(9), vec![Message::WentBack])
    );
    assert_eq!(s.count("PUT"), 1);
    assert_eq!(
        (l.highest, l.server_sha, l.local_sha),
        (7, hash(b"merged"), hash(b"merged"))
    );
    assert_eq!(l.seen.newest, Time(2_000), "the result's");
}

/// SYN-03.7, LD-269 (4), SYN-03 T12: weaker KDF settings and a lower file
/// version only warn, by name and never by value; the copy is merged.
#[test]
fn syn03_7_t12_weaker_settings_warn_by_name_only() {
    let s = server(|r| match r.method.as_str() {
        "GET" => vault(6, b"v6"),
        _ => vault(7, b"{}"),
    });
    let local = Fake::changed(m(1_200, 3, 16_384));
    let mut l = link();
    let report = run(&mut client(&s), &mut l, &local, &*TestClock::at(0));
    let weaker = Message::Weaker(vec!["file format version", "key derivation"]);
    assert_eq!(report.messages, std::slice::from_ref(&weaker));
    assert_eq!(report.status, Some(Status::Synced(0)));
    let text = weaker.text("Personal", "");
    assert!(!text.chars().any(|c| c.is_ascii_digit()), "{text}");
    assert_eq!(s.count("PUT"), 1);
}

/// SYN-03.5 step 2, SYN-03 T06: 304 with the local file as uploaded: one
/// GET, no PUT, Synced.
#[test]
fn syn03_5_t06_304_with_no_local_change_sends_no_put() {
    let s = server(|_| Response::new(304, b"").with("ETag", "\"5\""));
    let local = Fake::new(b"local", |_| unreachable!());
    let mut l = link();
    let report = run(&mut client(&s), &mut l, &local, &*TestClock::at(4));
    assert_eq!(report, Report::of(Status::Synced(4), Vec::new()));
    let sent = vault_requests(&s);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "GET");
    assert_eq!(sent[0].header("if-none-match"), Some("\"5\""));
}

/// SYN-03.5 step 2: 304 with a changed local file uploads it with
/// `If-Match` of the highest version; the new version is recorded.
#[test]
fn syn03_5_304_with_a_local_change_uploads_the_file() {
    let s = server(|r| match r.method.as_str() {
        "GET" => Response::new(304, b"").with("ETag", "\"5\""),
        _ => vault(6, b"{}"),
    });
    let local = Fake::new(b"local 2", |_| unreachable!());
    let mut l = link();
    let report = run(&mut client(&s), &mut l, &local, &*TestClock::at(0));
    assert_eq!(report.status, Some(Status::Synced(0)));
    let put = vault_requests(&s).pop().unwrap();
    assert_eq!(
        (put.method.as_str(), put.header("if-match")),
        ("PUT", Some("\"5\""))
    );
    assert_eq!(put.body, b"local 2");
    assert_eq!((l.highest, l.local_sha), (6, hash(b"local 2")));
    assert_eq!(l.seen, m(1_500, 4, 65_536), "the uploaded vault's");
}

/// SYN-03.5 step 3, SYN-03 T07: a merge with nothing new on this Mac
/// uploads nothing; the state takes the server's version and the new
/// local file.
#[test]
fn syn03_5_t07_an_empty_merge_uploads_nothing() {
    let s = server(|_| vault(6, b"v6"));
    let local = Fake::new(b"local", |_| Merge::Done {
        copy: m(1_800, 4, 65_536),
        result: m(1_800, 4, 65_536),
        changed: false,
        saved: b"saved v6".to_vec(),
    });
    let mut l = link();
    let report = run(&mut client(&s), &mut l, &local, &*TestClock::at(0));
    assert_eq!(report, Report::of(Status::Synced(0), Vec::new()));
    assert_eq!(s.count("PUT"), 0);
    assert_eq!(
        (l.highest, l.server_sha, l.local_sha),
        (6, hash(b"v6"), hash(b"saved v6"))
    );
}

/// SYN-03.10, SYN-03 T20: a 404 for a linked vault is `MSG-SYNC-GONE`; Larsal
/// never makes it again (no PUT, no `If-None-Match: *`).
#[test]
fn syn03_10_t20_404_is_gone_and_makes_nothing() {
    let s = server(|_| Response::new(404, br#"{"error":"not_found"}"#));
    let local = Fake::changed(m(1_200, 4, 65_536));
    let mut l = link();
    let report = run(&mut client(&s), &mut l, &local, &*TestClock::at(0));
    assert_eq!(report, Report::error(Message::Gone));
    assert_eq!(s.count("PUT"), 0);
    assert!(
        s.requests()
            .iter()
            .all(|r| r.header("if-none-match") != Some("*"))
    );
    assert_eq!(l, link());
}

/// SYN-01.9, SYN-01 T15: a 403 with text of its own is `MSG-SYNC-NO-WRITE`;
/// the server's text is never kept or shown.
#[test]
fn syn01_9_t15_403_shows_app_words_never_the_servers() {
    let s = server(|r| match r.method.as_str() {
        "GET" => vault(6, b"v6"),
        _ => Response::new(
            403,
            br#"{"error":"forbidden","message":"<b>Click here</b>"}"#,
        ),
    });
    let local = Fake::changed(m(1_200, 4, 65_536));
    let mut l = link();
    let report = run(&mut client(&s), &mut l, &local, &*TestClock::at(0));
    assert_eq!(report, Report::error(Message::NoWrite));
    let shown: String = report
        .messages
        .iter()
        .map(|m| m.text("Personal", "https://127.0.0.1:1"))
        .collect();
    assert!(!shown.contains("Click") && !format!("{report:?}").contains("Click"));
    assert!(shown.contains("kept on this Mac"));
}

/// SYN-03.10: the other replies, each with its own status and message.
#[test]
fn syn03_10_each_reply_has_its_status() {
    for (status, report) in [
        (413, Report::error(Message::TooLarge)),
        (400, Report::error(Message::Error)),
        (411, Report::error(Message::Error)),
        (428, Report::error(Message::Error)),
        (409, Report::error(Message::Error)),
        (500, Report::of(Status::Offline, Vec::new())),
        (503, Report::of(Status::Offline, Vec::new())),
    ] {
        let s = server(move |r| match r.method.as_str() {
            "GET" => vault(6, b"v6"),
            _ => Response::new(status, br#"{"error":"x"}"#),
        });
        let local = Fake::changed(m(1_200, 4, 65_536));
        let got = run(&mut client(&s), &mut link(), &local, &*TestClock::at(0));
        assert_eq!(got, report, "{status}");
    }
    // A 200 without a canonical ETag is a protocol error, merged nothing.
    let s = server(|_| Response::new(200, b"v6").with("ETag", "W/\"6\""));
    let local = Fake::changed(m(1_200, 4, 65_536));
    let got = run(&mut client(&s), &mut link(), &local, &*TestClock::at(0));
    assert_eq!((got, local.merges()), (Report::error(Message::Error), 0));
    // Sign-in refused: Signed out.
    let s = Scripted::new(|_| Response::new(401, br#"{"error":"unauthorized"}"#));
    let got = run(&mut client(&s), &mut link(), &local, &*TestClock::at(0));
    assert_eq!(got, Report::of(Status::SignedOut, vec![Message::SignedOut]));
    // Another certificate: stopped before any request.
    let mut pinned = Server::new(&s.address(), [1; 32]).unwrap();
    pinned.set_device(
        larsal_proto::messages::DeviceId::from_bytes([9; 16]),
        larsal_platform::device_key::DeviceKey::test_seam().unwrap(),
    );
    let before = s.requests().len();
    let got = run(&mut pinned, &mut link(), &local, &*TestClock::at(0));
    assert_eq!(got, Report::error(Message::CertChanged));
    assert_eq!(s.requests().len(), before);
}

/// SYN-03.8, SYN-03.4: a copy that does not open with this Mac's key is
/// Needs password and uploads nothing; another vault is refused; a vault
/// that became busy stops the run before its merge with no status.
#[test]
fn syn03_8_wrong_key_other_vault_and_busy_upload_nothing() {
    for (merge, report) in [
        (
            Merge::WrongKey,
            Report::of(Status::NeedsPassword, vec![Message::OtherKey]),
        ),
        (Merge::OtherVault, Report::error(Message::OtherVault)),
        (Merge::Failed, Report::error(Message::Error)),
        (
            Merge::Busy,
            Report {
                status: None,
                messages: Vec::new(),
            },
        ),
    ] {
        let s = server(|_| vault(6, b"v6"));
        let merge = Mutex::new(Some(merge));
        let local = Fake::new(b"local", move |_| merge.lock().unwrap().take().unwrap());
        let mut l = link();
        let got = run(&mut client(&s), &mut l, &local, &*TestClock::at(0));
        assert_eq!(got, report);
        assert_eq!(s.count("PUT"), 0);
        assert_eq!(l, link(), "the state does not move");
    }
}

/// SYN-03.10, SYN-03 T21: the server stopped: Offline, no message, the
/// vault untouched.
#[test]
fn syn03_10_t21_offline_changes_nothing() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut c = Server::new(&format!("https://127.0.0.1:{port}"), [0; 32]).unwrap();
    c.set_device(
        larsal_proto::messages::DeviceId::from_bytes([9; 16]),
        larsal_platform::device_key::DeviceKey::test_seam().unwrap(),
    );
    let local = Fake::changed(m(1_200, 4, 65_536));
    let mut l = link();
    let got = run(&mut c, &mut l, &local, &*TestClock::at(0));
    assert_eq!(got, Report::of(Status::Offline, Vec::new()));
    assert_eq!((local.merges(), l), (0, link()));
}

/// A server whose answer to the n-th GET is `get(n)` (from 0), every PUT
/// 412; it notes the clock at each GET.
fn counted(
    clock: &Arc<TestClock>,
    get: impl Fn(usize) -> Response + Send + Sync + 'static,
) -> (Scripted, Arc<Mutex<Vec<u64>>>) {
    let times = Arc::new(Mutex::new(Vec::new()));
    let (c, t) = (clock.clone(), times.clone());
    let s = server(move |r| {
        if r.method == "GET" {
            let mut t = t.lock().unwrap();
            t.push(c.now_ms());
            return get(t.len() - 1);
        }
        Response::new(412, br#"{"error":"precondition_failed"}"#)
    });
    (s, times)
}

/// SYN-03.10, SYN-03.6, SYN-03 T29: after a 429 with `Retry-After: 3600`
/// Larsal waits 300 s, not 3600; the 429 is the 1st of the 3 tries (3 GETs,
/// 2 PUTs, a 1 to 3 s wait before the 3rd, then `MSG-SYNC-BUSY`). A server
/// that answers three GETs with 429 gets 3 GETs at 0, 300 and 600 s and
/// the run ends Offline with no message.
#[test]
fn syn03_10_t29_a_long_retry_after_waits_300_s_and_counts_as_a_try() {
    let clock = TestClock::at(0);
    let (s, times) = counted(&clock, |n| {
        if n == 0 {
            Response::new(429, br#"{"error":"rate_limited"}"#).with("Retry-After", "3600")
        } else {
            Response::new(304, b"").with("ETag", "\"5\"")
        }
    });
    let local = Fake::new(b"local 2", |_| unreachable!());
    let report = run(&mut client(&s), &mut link(), &local, &*clock);
    assert_eq!(report, Report::error(Message::Busy));
    assert_eq!((s.count("GET"), s.count("PUT")), (3, 2));
    let t = times.lock().unwrap().clone();
    assert_eq!(&t[..2], [0, 300_000]);
    assert!((1_000..=3_000).contains(&(t[2] - t[1])), "{t:?}");

    let clock = TestClock::at(0);
    // A 4th GET would find the server free: a run that tried again ends
    // Synced, not Offline.
    let (s, times) = counted(&clock, |n| {
        if n < 3 {
            Response::new(429, br#"{"error":"rate_limited"}"#).with("Retry-After", "3600")
        } else {
            Response::new(304, b"").with("ETag", "\"5\"")
        }
    });
    let report = run(&mut client(&s), &mut link(), &local, &*clock);
    assert_eq!(report, Report::of(Status::Offline, Vec::new()));
    assert_eq!(*times.lock().unwrap(), [0, 300_000, 600_000]);
}

/// SYN-03.10, SYN-03 T30: a `Retry-After` that is missing, a date, a
/// fraction or too long counts as 300 s; the run then ends Synced.
#[test]
fn syn03_10_t30_a_retry_after_that_is_no_number_counts_as_300_s() {
    for value in [
        None,
        Some("Fri, 31 Dec 2099 23:59:59 GMT"),
        Some("1.5"),
        Some("99999999999999999999999"),
    ] {
        let clock = TestClock::at(0);
        let (s, times) = counted(&clock, move |n| match (n, value) {
            (0, Some(v)) => Response::new(429, b"{}").with("Retry-After", v),
            (0, None) => Response::new(429, b"{}"),
            _ => Response::new(304, b"").with("ETag", "\"5\""),
        });
        let local = Fake::new(b"local", |_| unreachable!());
        let report = run(&mut client(&s), &mut link(), &local, &*clock);
        assert_eq!(
            report,
            Report::of(Status::Synced(300_000), Vec::new()),
            "{value:?}"
        );
        assert_eq!(*times.lock().unwrap(), [0, 300_000], "{value:?}");
    }
}

/// E16-S7a check 6, SYN-03.4, SYN-03 T09 (the schedule): with a test clock,
/// runs at the unlock, once 2 s after the second of two saves 1 s apart,
/// once at 60 s; none while locked, and Sync now does nothing while
/// locked.
#[test]
fn syn03_4_t09_runs_on_unlock_after_a_save_every_60_s_and_never_locked() {
    let mut s = Schedule::default();
    let mut runs = Vec::new();
    let mut look = |s: &mut Schedule, now: u64| {
        if s.start(now, false) {
            runs.push(now);
            s.finished();
        }
    };
    assert!(!s.start(0, false), "locked: nothing");
    s.unlocked(0);
    for now in (0..=73_000).step_by(500) {
        if now == 10_000 || now == 11_000 {
            s.saved(now);
        }
        if now == 71_000 {
            s.locked();
        }
        look(&mut s, now);
    }
    s.sync_now();
    for now in (73_500..=200_000).step_by(500) {
        look(&mut s, now);
    }
    assert_eq!(runs, [0, 13_000, 60_000]);
}

/// SYN-03.4: a trigger while the vault is busy or a run is open waits, and
/// one more run follows; Sync now starts a run while unlocked.
#[test]
fn syn03_4_a_trigger_during_a_run_or_while_busy_waits() {
    let mut s = Schedule::default();
    s.unlocked(0);
    assert!(s.start(0, false));
    assert!(s.running());
    s.sync_now();
    s.saved(100);
    assert!(!s.start(5_000, false), "one run at a time");
    s.finished();
    assert!(s.start(5_000, false), "one more after it");
    s.finished();
    s.saved(6_000);
    assert!(!s.start(8_000, true), "busy: waits");
    assert!(!s.start(9_000, true));
    assert!(s.start(9_500, false), "then runs");
    s.finished();
    assert!(!s.start(9_600, false));
    s.sync_now();
    assert!(s.start(9_700, false));
    s.finished();
    // Ticks stay on the 60 s grid of the unlock, never piling up.
    assert!(s.start(130_000, false));
    s.finished();
    assert!(!s.start(150_000, false));
    assert!(s.start(180_000, false));
}

/// SYN-01.13, Rust rule 9, SYN-01 T20 (the client half): larsal-sync writes
/// no log line, so no token, nonce, signature or body can reach a log.
#[test]
fn syn01_13_t20_the_client_logs_nothing() {
    for (name, src) in [
        ("lib.rs", include_str!("../lib.rs")),
        ("client.rs", include_str!("../client.rs")),
        ("state.rs", include_str!("../state.rs")),
        ("sync.rs", include_str!("../sync.rs")),
        ("test_server.rs", include_str!("../test_server.rs")),
    ] {
        for word in [
            "log::",
            "println!",
            "eprintln!",
            "print!(",
            "eprint!(",
            "dbg!",
            "NSLog",
            "os_log",
            "tracing",
        ] {
            assert!(!src.contains(word), "{name} has {word}");
        }
    }
}
