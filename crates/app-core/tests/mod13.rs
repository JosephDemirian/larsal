//! Story E4-S14, card MOD-13: master key change reminders. One test per
//! rule (`mod13_NN_…`) with the card's cases.
//!
//! The window flows (MOD-13.7 to MOD-13.10: when the check runs, the
//! blocking prompt, no lock-out on a failed save, the notice) are E5's;
//! here is the status they show. The force-once read and write rules of
//! MOD-13.13 are also covered by app-format's `document_read.rs` and
//! `write_meta.rs`; MOD-13.15 (a missing time becomes the open time) by
//! app-format's reader tests.

mod common;

use app_core::merge::{Kind, Options, merge};
use app_core::settings::{self, Changes, KeyChange, PasswordPart, Refusal, Reminder, reminder};
use app_crypto::kdf::{Ceilings, Host, SpeedRecord};
use app_crypto::secret::SecretString;
use app_format::keys::Credentials;
use app_format::limits::Limits;
use app_format::{Opened, Saved};
use app_model::{Group, Kdf, Time, Uuid, Vault};
use common::at;

fn uid(b: u8) -> Uuid {
    Uuid([b; 16])
}

fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1_000,
        }),
    }
}

fn ceilings() -> Ceilings {
    Ceilings {
        refuse_iterations: 1_000_000_000,
        ask_memory_kib: 1_048_576,
        ask_lanes: 128,
        ask_ms: 10_000,
    }
}

fn demo(changed: Time, rec: i32, force: i32) -> Vault {
    let mut v = Vault::new(Group::new(uid(0x01), "Root".into(), changed), changed);
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    v.meta.master_key_change_rec = rec;
    v.meta.master_key_change_force = force;
    v
}

fn save_open(v: &Vault) -> Vault {
    let pw = SecretString::new("demo".into());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let mut h = host();
    let Saved::File(f) = app_format::save(v, &creds, None, &mut h, &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    let Opened::Vault(o) =
        app_format::open(&f.bytes, &creds, &mut h, &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    o.vault
}

#[test]
fn mod13_01_stored_values_and_defaults() {
    // T01: a new vault; force-once absent (false).
    let v = settings::new_vault("Passwords", at(2026, 10, 25, 10, 0, 0), 4).unwrap();
    assert_eq!(v.meta.master_key_changed, at(2026, 10, 25, 10, 0, 0));
    assert_eq!(
        (v.meta.master_key_change_rec, v.meta.master_key_change_force),
        (-1, -1)
    );
    assert!(!v.meta.master_key_change_force_once);
}

#[test]
fn mod13_03_values_kept() {
    // T04: open and save without touching keeps the three values.
    let v = demo(at(2012, 4, 5, 17, 9, 34), 101, -1);
    let read = save_open(&v);
    assert_eq!(read.meta.master_key_changed, at(2012, 4, 5, 17, 9, 34));
    assert_eq!(
        (
            read.meta.master_key_change_rec,
            read.meta.master_key_change_force
        ),
        (101, -1)
    );
}

#[test]
fn mod13_04_counting_days() {
    // T05: the boundary to the second.
    let m = demo(at(2026, 7, 27, 12, 0, 0), 90, -1).meta;
    assert_eq!(reminder(&m, at(2026, 10, 25, 11, 59, 59)), Reminder::None);
    assert_eq!(
        reminder(&m, at(2026, 10, 25, 12, 0, 0)),
        Reminder::Recommended {
            days: 90,
            every: 90
        }
    );
    // T06: 24-hour periods, not calendar days.
    let m = demo(at(2026, 10, 24, 23, 59, 59), 1, -1).meta;
    assert_eq!(reminder(&m, at(2026, 10, 25, 0, 0, 1)), Reminder::None);
    // T07: the reference's sample vault.
    let m = demo(at(2012, 4, 5, 17, 9, 34), 101, -1).meta;
    assert_eq!(
        reminder(&m, at(2026, 10, 25, 9, 0, 0)),
        Reminder::Recommended {
            days: 5_315,
            every: 101
        }
    );
    // T29 / MOD-13.15: a future time is not due.
    let m = demo(at(2027, 1, 1, 0, 0, 0), 1, 1).meta;
    assert_eq!(reminder(&m, at(2026, 10, 25, 0, 0, 0)), Reminder::None);
}

#[test]
fn mod13_05_active_values() {
    // T08: 0 and negatives are off, and written back as read.
    let v = demo(at(2000, 1, 1, 0, 0, 0), 0, -5);
    assert_eq!(reminder(&v.meta, at(2026, 10, 25, 0, 0, 0)), Reminder::None);
    let read = save_open(&v);
    assert_eq!(
        (
            read.meta.master_key_change_rec,
            read.meta.master_key_change_force
        ),
        (0, -5)
    );
    // A huge interval is active but never due in practice.
    let big = demo(at(2026, 1, 1, 0, 0, 0), -1, i32::MAX).meta;
    assert_eq!(reminder(&big, at(2026, 10, 25, 0, 0, 0)), Reminder::None);
}

#[test]
fn mod13_06_status() {
    // T09: forced wins.
    let now = at(2026, 10, 25, 0, 0, 0);
    let m = demo(Time(now.0 - 45 * 86_400), 10, 30).meta;
    assert_eq!(
        reminder(&m, now),
        Reminder::Forced {
            days: 45,
            every: Some(30)
        }
    );
    // T10: force-once.
    let mut m = demo(now, -1, -1).meta;
    m.master_key_change_force_once = true;
    assert_eq!(
        reminder(&m, now),
        Reminder::Forced {
            days: 0,
            every: None
        }
    );
}

#[test]
fn mod13_11_what_counts_as_a_key_change() {
    // T18: a KDF change only: the time and force-once stay.
    let mut v = demo(at(2026, 1, 1, 0, 0, 0), -1, -1);
    v.meta.master_key_change_force_once = true;
    let c = Changes {
        encryption: Some(settings::EncryptionEdit {
            cipher: app_model::Cipher::Aes256,
            kdf: Kdf::AesKdf { rounds: 200_000 },
            unlock_time_ms: None,
        }),
        ..Changes::default()
    };
    settings::apply(
        &mut v,
        &c,
        &mut host(),
        &ceilings(),
        at(2026, 6, 1, 0, 0, 0),
    )
    .unwrap();
    assert_eq!(v.meta.master_key_changed, at(2026, 1, 1, 0, 0, 0));
    assert!(save_open(&v).meta.master_key_change_force_once);
    // T19: a key change at T5 clears it.
    settings::key_changed(&mut v.meta, at(2026, 6, 1, 0, 0, 0));
    assert_eq!(v.meta.master_key_changed, at(2026, 6, 1, 0, 0, 0));
    assert!(!save_open(&v).meta.master_key_change_force_once);
}

#[test]
fn mod13_12_settings_controls() {
    let t5 = at(2026, 6, 1, 0, 0, 0);
    let run = |v: &mut Vault, c: Changes| settings::apply(v, &c, &mut host(), &ceilings(), t5);
    // T20: on with 90, then off.
    let mut v = demo(at(2026, 1, 1, 0, 0, 0), -1, -1);
    run(
        &mut v,
        Changes {
            key_change_rec: Some(90),
            ..Changes::default()
        },
    )
    .unwrap();
    assert_eq!(
        (v.meta.master_key_change_rec, v.meta.settings_changed),
        (90, t5)
    );
    run(
        &mut v,
        Changes {
            key_change_rec: Some(-1),
            ..Changes::default()
        },
    )
    .unwrap();
    assert_eq!(v.meta.master_key_change_rec, -1);
    // T21: an untouched out-of-range value stays.
    let mut v = demo(at(2026, 1, 1, 0, 0, 0), -1, 0);
    run(
        &mut v,
        Changes {
            name: Some("renamed".into()),
            ..Changes::default()
        },
    )
    .unwrap();
    assert_eq!(save_open(&v).meta.master_key_change_force, 0);
    // T22: the range 1 to 3,650.
    for bad in [0, 3_651] {
        assert_eq!(
            run(
                &mut v,
                Changes {
                    key_change_rec: Some(bad),
                    ..Changes::default()
                }
            ),
            Err(Refusal::OutOfRange("keychange.recommend"))
        );
    }
    for good in [1, 3_650] {
        assert!(
            run(
                &mut v,
                Changes {
                    key_change_force: Some(good),
                    ..Changes::default()
                }
            )
            .is_ok()
        );
    }
    // The force-once switch.
    run(
        &mut v,
        Changes {
            force_once: Some(true),
            ..Changes::default()
        },
    )
    .unwrap();
    assert!(v.meta.master_key_change_force_once);
}

#[test]
fn mod13_13_force_once_in_the_file() {
    // T25: written when true, read back; false is not written.
    let mut v = demo(at(2026, 1, 1, 0, 0, 0), -1, -1);
    v.meta.master_key_change_force_once = true;
    assert!(save_open(&v).meta.master_key_change_force_once);
    v.meta.master_key_change_force_once = false;
    assert!(!save_open(&v).meta.master_key_change_force_once);
}

#[test]
fn mod13_14_merge() {
    let pair = || {
        let a = demo(at(2026, 1, 1, 0, 0, 0), -1, -1);
        let b = demo(at(2026, 1, 1, 0, 0, 0), -1, -1);
        (a, b)
    };
    let t2 = at(2026, 3, 1, 0, 0, 0);
    // T26: the newer key comes with its time and flag when confirmed.
    let (mut a, mut b) = pair();
    a.meta.master_key_change_force_once = true;
    b.meta.master_key_changed = t2;
    let yes = Options {
        take_key: true,
        ..Options::new(Kind::Window)
    };
    assert!(merge(&mut a, &b, &yes, t2).unwrap().key_taken);
    assert_eq!(
        (
            a.meta.master_key_changed,
            a.meta.master_key_change_force_once
        ),
        (t2, false)
    );
    // T26b: not confirmed, or the command line: all three stay.
    for o in [Options::new(Kind::Window), Options::new(Kind::CommandLine)] {
        let (mut a, mut b) = pair();
        a.meta.master_key_change_force_once = true;
        b.meta.master_key_changed = t2;
        let m = merge(&mut a, &b, &o, t2).unwrap();
        assert!(!m.key_taken && a.meta.master_key_change_force_once);
        assert_eq!(m.changes.len(), 1);
    }
    // T27: a tie keeps the flag from either side.
    let (mut a, mut b) = pair();
    b.meta.master_key_change_force_once = true;
    merge(&mut a, &b, &Options::new(Kind::Window), t2).unwrap();
    assert!(a.meta.master_key_change_force_once);
    // The day values travel with the settings group.
    let (mut a, mut b) = pair();
    b.meta.master_key_change_rec = 30;
    b.meta.settings_changed = t2;
    merge(&mut a, &b, &Options::new(Kind::Window), t2).unwrap();
    assert_eq!(a.meta.master_key_change_rec, 30);
}

#[test]
fn mod13_16_command_line_notice() {
    // T30: one line, forced, with the days and the interval.
    let now = at(2026, 10, 25, 0, 0, 0);
    let m = demo(at(2020, 1, 1, 0, 0, 0), 1, 1).meta;
    let r = reminder(&m, now);
    let line = settings::cli_notice(&r).unwrap();
    assert!(line.starts_with("Note: this vault requires a master key change"));
    assert!(line.contains("2489 days") && line.contains("every 1 days"));
    assert_eq!(settings::cli_notice(&Reminder::None), None);
    let rec = settings::cli_notice(&Reminder::Recommended {
        days: 5_315,
        every: 101,
    })
    .unwrap();
    assert!(rec.contains("5315") && rec.contains("101"));
}

#[test]
fn mod13_17_messages_hold_no_vault_text() {
    // T31: numbers only, never the vault's name.
    let mut m = demo(at(2012, 4, 5, 17, 9, 34), 101, -1).meta;
    m.name = "Secret Vault".into();
    let line = settings::cli_notice(&reminder(&m, at(2026, 10, 25, 9, 0, 0))).unwrap();
    assert!(!line.contains("Secret Vault"));
    // The key change page's checks run before any change (MOD-12.10).
    let mut v = demo(at(2026, 1, 1, 0, 0, 0), -1, -1);
    let c = Changes {
        key: Some(KeyChange {
            password: PasswordPart::New {
                typed: SecretString::new("a".into()),
                repeat: SecretString::new("b".into()),
                quality: 4,
            },
            had_password: true,
            key_file: false,
            hardware: false,
            min_quality: 0,
        }),
        ..Changes::default()
    };
    assert_eq!(
        settings::apply(
            &mut v,
            &c,
            &mut host(),
            &ceilings(),
            at(2026, 6, 1, 0, 0, 0)
        ),
        Err(Refusal::PasswordMismatch)
    );
    assert_eq!(v.meta.master_key_changed, at(2026, 1, 1, 0, 0, 0));
}
