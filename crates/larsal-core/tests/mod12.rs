//! Story E4-S14, card MOD-12: vault settings and field protection. One
//! test per rule (`mod12_NN_…`) with the card's cases.
//!
//! The screen itself (pages, controls, dialogs; MOD-12.1, T01, T05's
//! notice, T41) is E5's. MOD-12.21 (a failed save keeps the change in
//! memory) is APP-05's storage path, tested in `app05.rs`.

mod common;

use common::at;
use larsal_core::settings::{
    self, Applied, Changes, Confirm, EncryptionEdit, KeyChange, PasswordPart, Protection, Refusal,
    apply,
};
use larsal_core::{icons, recycle};
use larsal_crypto::kdf::{Ceilings, Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved};
use larsal_model::{
    Argon2Kind, Cipher, Compression, CustomDataItem, CustomIcon, Entry, Field, FileVersion, Group,
    Icon, Kdf, Time, Uuid, Vault,
};
use std::cell::Cell;
use std::time::Duration;

fn t0() -> Time {
    at(2026, 1, 1, 0, 0, 0)
}
fn t5() -> Time {
    at(2026, 6, 1, 0, 0, 0)
}
fn t6() -> Time {
    at(2026, 7, 1, 0, 0, 0)
}

fn uid(b: u8) -> Uuid {
    Uuid([b; 16])
}

fn host() -> Host {
    let record = SpeedRecord {
        count: 1_000_000,
        memory_kib: 65_536,
        lanes: 1,
        ms: 100,
    };
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: Some(record),
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1_000,
        }),
    }
}

/// LD-22's ceilings.
fn ceilings() -> Ceilings {
    Ceilings {
        refuse_iterations: 1_000_000_000,
        ask_memory_kib: 1_048_576,
        ask_lanes: 128,
        ask_ms: 10_000,
    }
}

fn run(v: &mut Vault, c: &Changes, now: Time) -> Result<Applied, Refusal> {
    apply(v, c, &mut host(), &ceilings(), now)
}

fn field(v: &str, protected: bool) -> Field {
    Field {
        value: SecretString::new(v.to_owned()),
        protected,
    }
}

fn entry(b: u8) -> Entry {
    let mut e = Entry::new(uid(b), t0());
    e.set_field("Title".into(), field("T", false));
    e.set_field("UserName".into(), field("U", false));
    e.set_field("Password".into(), field("P", false));
    e.set_field("URL".into(), field("http://x", false));
    e.set_field("Notes".into(), field("N", false));
    e
}

fn demo() -> Vault {
    let mut root = Group::new(uid(0x01), "Root".into(), t0());
    root.entries.push(entry(0x0a));
    let mut v = Vault::new(root, t0());
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    v
}

fn new_password(typed: &str, repeat: &str, quality: u8) -> KeyChange {
    KeyChange {
        password: PasswordPart::New {
            typed: SecretString::new(typed.into()),
            repeat: SecretString::new(repeat.into()),
            quality,
        },
        had_password: true,
        key_file: false,
        hardware: false,
        min_quality: 0,
    }
}

/// Saves with a fast KDF and opens again (larsal-format).
fn save_open(v: &Vault) -> Vault {
    let pw = SecretString::new("demo".into());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let mut h = host();
    let Saved::File(f) =
        larsal_format::save(v, &creds, None, &mut h, &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask expected")
    };
    let Opened::Vault(o) =
        larsal_format::open(&f.bytes, &creds, &mut h, &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask expected")
    };
    o.vault
}

#[test]
fn mod12_02_apply_is_all_or_nothing() {
    // T02: a refusing credentials page applies nothing.
    let mut v = demo();
    v.meta.name = "Old".into();
    let c = Changes {
        name: Some("New".into()),
        key: Some(new_password("abc", "abd", 4)),
        ..Changes::default()
    };
    assert_eq!(run(&mut v, &c, t5()), Err(Refusal::PasswordMismatch));
    assert_eq!(v.meta.name, "Old");
}

#[test]
fn mod12_03_name_description_default_user_name() {
    // T03.
    let mut v = demo();
    v.meta.name = "Demo".into();
    let r = run(
        &mut v,
        &Changes {
            name: Some("Demo".into()),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert!(!r.changed && v.meta.name_changed == t0());
    run(
        &mut v,
        &Changes {
            name: Some("Demo2".into()),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert_eq!((v.meta.name.as_str(), v.meta.name_changed), ("Demo2", t5()));
    // T04: the default user name fills new entries made in the window.
    run(
        &mut v,
        &Changes {
            default_user_name: Some("demo".into()),
            description: Some("d".into()),
            ..Changes::default()
        },
        t6(),
    )
    .unwrap();
    assert_eq!(
        (v.meta.default_user_name_changed, v.meta.description_changed),
        (t6(), t6())
    );
    let e = larsal_core::edit::new_entry(&v, uid(0x01), false).unwrap();
    assert_eq!(e.value("UserName"), "demo");
}

#[test]
fn mod12_04_public_display_settings() {
    let mut v = demo();
    let c = Changes {
        public_name: Some(Some("Shown name".into())),
        public_color: Some(Some("#1A2B3C".into())),
        public_icon: Some(Some(5)),
        ..Changes::default()
    };
    assert!(run(&mut v, &c, t5()).unwrap().settings_changed);
    let item = |suffix: &[u8]| {
        let mut name = [
            0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x5F,
        ]
        .to_vec();
        name.extend_from_slice(suffix);
        v.public_custom_data
            .iter()
            .find(|i| i.name == name)
            .map(|i| (i.kind, i.value.clone()))
    };
    assert_eq!(
        item(b"COLOR"),
        Some((0x18, b"#1a2b3c".to_vec())),
        "lowercase (FMT-03.23)"
    );
    assert_eq!(item(b"ICON"), Some((0x0C, 5i32.to_le_bytes().to_vec())));
    assert_eq!(item(b"NAME"), Some((0x18, b"Shown name".to_vec())));
    // T05: cleared, the item is gone.
    run(
        &mut v,
        &Changes {
            public_color: Some(None),
            ..Changes::default()
        },
        t6(),
    )
    .unwrap();
    assert!(
        v.public_custom_data
            .iter()
            .all(|i| !i.name.ends_with(b"COLOR"))
    );
    assert_eq!(
        run(
            &mut v,
            &Changes {
                public_color: Some(Some("red".into())),
                ..Changes::default()
            },
            t6()
        ),
        Err(Refusal::OutOfRange("vault.public_color"))
    );
}

#[test]
fn mod12_05_history_limits() {
    // T07: untouched controls keep odd stored values.
    for size in [3_500_000, 100] {
        let mut v = demo();
        v.meta.history_max_size = size;
        let r = run(
            &mut v,
            &Changes {
                name: Some("x".into()),
                ..Changes::default()
            },
            t5(),
        )
        .unwrap();
        assert_eq!(v.meta.history_max_size, size);
        assert!(!r.settings_changed && v.meta.settings_changed == t0());
    }
    // T09: a lower item limit cuts every history at once.
    let mut v = demo();
    for d in 1..=12 {
        let mut h = entry(0x0a);
        h.times.last_modification = at(2025, 1, d, 0, 0, 0);
        v.root.entries[0].history.push(h);
    }
    let r = run(
        &mut v,
        &Changes {
            history_items: Some(5),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert!(r.pruned && r.settings_changed);
    let kept: Vec<Time> = v.root.entries[0]
        .history
        .iter()
        .map(|h| h.times.last_modification)
        .collect();
    assert_eq!(
        kept,
        (8..=12)
            .map(|d| at(2025, 1, d, 0, 0, 0))
            .collect::<Vec<_>>()
    );
    // T09b: the Larsal range; an untouched stored 200,000 stays.
    assert!(
        run(
            &mut v,
            &Changes {
                history_items: Some(100_000),
                ..Changes::default()
            },
            t5()
        )
        .is_ok()
    );
    assert_eq!(
        run(
            &mut v,
            &Changes {
                history_items: Some(100_001),
                ..Changes::default()
            },
            t5()
        ),
        Err(Refusal::OutOfRange("vault.history_items"))
    );
    assert_eq!(
        run(
            &mut v,
            &Changes {
                history_mib: Some(2_048),
                ..Changes::default()
            },
            t5()
        ),
        Err(Refusal::OutOfRange("vault.history_size"))
    );
    let mut big = demo();
    big.meta.history_max_items = 200_000;
    run(
        &mut big,
        &Changes {
            name: Some("y".into()),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert_eq!(big.meta.history_max_items, 200_000);
    // T10: off is −1 and removes nothing; size in MiB.
    let before = v.root.entries[0].history.len();
    run(
        &mut v,
        &Changes {
            history_items: Some(-1),
            history_mib: Some(3),
            ..Changes::default()
        },
        t6(),
    )
    .unwrap();
    assert_eq!(
        (v.meta.history_max_items, v.meta.history_max_size),
        (-1, 3 * 1_048_576)
    );
    assert_eq!(v.root.entries[0].history.len(), before);
}

#[test]
fn mod12_06_recycle_bin() {
    // T11: off, keep: the bin becomes `<name> (old)` with icon 48.
    let bin_vault = || {
        let mut v = demo();
        let mut bin = Group::new(uid(0x5a), "Recycle Bin".into(), t0());
        bin.icon = Icon::Standard(43);
        bin.entries.push(entry(0x0b));
        let mut g = Group::new(uid(0x02), "G".into(), t0());
        g.entries.push(entry(0x0c));
        bin.groups.push(g);
        v.root.groups.push(bin);
        v.meta.recycle_bin = Some(uid(0x5a));
        v
    };
    let mut v = bin_vault();
    run(
        &mut v,
        &Changes {
            recycle_bin: Some(false),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    let old = v.root.find_group(uid(0x5a)).unwrap();
    assert_eq!(
        (old.name.as_str(), old.icon),
        ("Recycle Bin (old)", Icon::Standard(48))
    );
    assert_eq!(
        (v.meta.recycle_bin, v.meta.recycle_bin_enabled),
        (None, false)
    );
    assert!(v.deleted_objects.is_empty());
    // T12: off, delete: the bin and its contents go, with deleted objects.
    let mut v = bin_vault();
    let c = Changes {
        recycle_bin: Some(false),
        delete_old_bin: true,
        ..Changes::default()
    };
    run(&mut v, &c, t5()).unwrap();
    assert!(v.root.find_group(uid(0x5a)).is_none());
    let ids: Vec<Uuid> = v.deleted_objects.iter().map(|d| d.uuid).collect();
    assert_eq!(ids, [uid(0x0b), uid(0x0c), uid(0x02), uid(0x5a)]);
    // On again: only the flag.
    run(
        &mut v,
        &Changes {
            recycle_bin: Some(true),
            ..Changes::default()
        },
        t6(),
    )
    .unwrap();
    assert!(v.meta.recycle_bin_enabled && recycle::bin_id(&v).is_none());
}

#[test]
fn mod12_07_compression() {
    // T13: off is written as none by the next save.
    let mut v = demo();
    run(
        &mut v,
        &Changes {
            compression: Some(Compression::None),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert_eq!(save_open(&v).encryption.compression, Compression::None);
}

#[test]
fn mod12_08_autosave_delay() {
    // T14: untouched adds no item.
    let mut v = demo();
    run(
        &mut v,
        &Changes {
            name: Some("n".into()),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert_eq!(settings::autosave_minutes(&v), 0);
    assert!(v.meta.custom_data.items.is_empty());
    // Set, then T15: off removes it (and the stamp with it).
    run(
        &mut v,
        &Changes {
            autosave_minutes: Some(5),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert_eq!(settings::autosave_minutes(&v), 5);
    assert!(v.meta.custom_data.get("_LAST_MODIFIED").is_some());
    run(
        &mut v,
        &Changes {
            autosave_minutes: Some(0),
            ..Changes::default()
        },
        t6(),
    )
    .unwrap();
    assert!(v.meta.custom_data.items.is_empty());
    assert_eq!(
        run(
            &mut v,
            &Changes {
                autosave_minutes: Some(420_000_001),
                ..Changes::default()
            },
            t6()
        ),
        Err(Refusal::OutOfRange("vault.autosave_delay"))
    );
}

#[test]
fn mod12_09_settings_time() {
    // T16.
    let mut v = demo();
    run(
        &mut v,
        &Changes {
            name: Some("only name".into()),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert_eq!(v.meta.settings_changed, t0());
    run(
        &mut v,
        &Changes {
            history_items: Some(3),
            ..Changes::default()
        },
        t6(),
    )
    .unwrap();
    assert_eq!(v.meta.settings_changed, t6());
    // The key and force-once are not in the settings group.
    let mut w = demo();
    run(
        &mut w,
        &Changes {
            force_once: Some(true),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert_eq!(w.meta.settings_changed, t0());
}

#[test]
fn mod12_10_changing_the_key() {
    let mut v = demo();
    // T17: no password needs the confirm; with a key file it applies.
    let no_pw = || KeyChange {
        password: PasswordPart::Removed,
        had_password: true,
        key_file: true,
        hardware: false,
        min_quality: 0,
    };
    let c = Changes {
        key: Some(no_pw()),
        ..Changes::default()
    };
    assert_eq!(
        run(&mut v, &c, t5()),
        Err(Refusal::Confirm(Confirm::NoPassword))
    );
    let c = Changes {
        key: Some(no_pw()),
        confirmed: vec![Confirm::NoPassword],
        ..Changes::default()
    };
    assert!(run(&mut v, &c, t5()).unwrap().key_changed);
    // T18: below the minimum quality.
    let mut k = new_password("password1", "password1", 2);
    k.min_quality = 3;
    assert_eq!(
        run(
            &mut v,
            &Changes {
                key: Some(k),
                ..Changes::default()
            },
            t5()
        ),
        Err(Refusal::BelowMinimum)
    );
    // T19: a weak password warns.
    let c = Changes {
        key: Some(new_password("password1", "password1", 2)),
        ..Changes::default()
    };
    assert_eq!(
        run(&mut v, &c, t5()),
        Err(Refusal::Confirm(Confirm::WeakPassword))
    );
    // T20: no key part at all.
    let c = Changes {
        key: Some(KeyChange {
            key_file: false,
            ..no_pw()
        }),
        confirmed: vec![Confirm::NoPassword],
        ..Changes::default()
    };
    assert_eq!(run(&mut v, &c, t5()), Err(Refusal::NoKeyPart));
    // T21 and T22: the effect, also for the same password again.
    let mut w = demo();
    w.meta.master_key_change_force_once = true;
    let c = Changes {
        key: Some(new_password("demo2", "demo2", 4)),
        ..Changes::default()
    };
    let r = run(&mut w, &c, t5()).unwrap();
    assert!(r.key_changed && r.changed);
    assert_eq!(
        (
            w.meta.master_key_changed,
            w.meta.master_key_change_force_once
        ),
        (t5(), false)
    );
    run(
        &mut w,
        &Changes {
            key: Some(new_password("demo2", "demo2", 4)),
            ..Changes::default()
        },
        t6(),
    )
    .unwrap();
    assert_eq!(w.meta.master_key_changed, t6());
    assert_eq!(
        w.meta.settings_changed,
        t0(),
        "the key is not a settings value"
    );
}

thread_local! {
    static CLOCK: Cell<u64> = const { Cell::new(0) };
}

/// A test clock: every reading is 60 ms later (CRY-02.28 measures with
/// it; the thread CPU clock is larsal-platform's, later).
fn test_clock() -> Duration {
    CLOCK.with(|c| {
        c.set(c.get() + 60);
        Duration::from_millis(c.get())
    })
}

#[test]
fn f_075_tune_keeps_the_record_for_the_save() {
    // F-075: the save right after a tune estimates from the tune's own run
    // (no second measurement), so the tuned cost never lands in the ask
    // band.
    for kdf in [
        Kdf::AesKdf { rounds: 1 },
        Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 1,
            memory_kib: 64,
            lanes: 1,
        },
    ] {
        let mut h = host();
        (h.aes_record, h.argon2_record) = (None, None);
        let tuned = settings::tune(&kdf, 1_000, &mut h, test_clock).unwrap();
        let record = match tuned {
            Kdf::AesKdf { .. } => h.aes_record,
            Kdf::Argon2 { .. } => h.argon2_record,
        };
        assert!(record.is_some(), "{tuned:?}");
    }
}

#[test]
fn mod12_11_simple_mode() {
    // T24: the benchmark sets the iterations; memory and lanes stay; the
    // unlock time item holds the chosen time.
    let kdf = Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: 7,
        memory_kib: 64,
        lanes: 1,
    };
    let tuned = settings::tune(&kdf, 1_000, &mut host(), test_clock).unwrap();
    let Kdf::Argon2 {
        iterations,
        memory_kib,
        lanes,
        kind,
    } = tuned
    else {
        panic!("still Argon2")
    };
    assert_eq!((kind, memory_kib, lanes), (Argon2Kind::Id, 64, 1));
    assert!(
        iterations >= 1 && iterations != 7,
        "set by the benchmark: {iterations}"
    );
    let aes = settings::tune(&Kdf::AesKdf { rounds: 1 }, 1_000, &mut host(), test_clock).unwrap();
    assert!(matches!(aes, Kdf::AesKdf { rounds } if rounds >= 100_000));
    assert_eq!(
        settings::tune(&kdf, 99, &mut host(), test_clock),
        Err(Refusal::KdfUnchanged)
    );
    let mut v = demo();
    let c = Changes {
        encryption: Some(EncryptionEdit {
            cipher: Cipher::Aes256,
            kdf: Kdf::AesKdf { rounds: 200_000 },
            unlock_time_ms: Some(2_000),
        }),
        ..Changes::default()
    };
    run(&mut v, &c, t5()).unwrap();
    assert_eq!(settings::unlock_time_ms(&v), Some(2_000));
}

#[test]
fn mod12_12_advanced_mode() {
    let enc = |kdf: Kdf| Changes {
        encryption: Some(EncryptionEdit {
            cipher: Cipher::Aes256,
            kdf,
            unlock_time_ms: None,
        }),
        ..Changes::default()
    };
    let argon = |iterations: u64, memory_kib: u64| Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations,
        memory_kib,
        lanes: 2,
    };
    let mut v = demo();
    // T25.
    assert_eq!(
        run(&mut v, &enc(argon(20_000, 65_536)), t5()),
        Err(Refusal::Confirm(Confirm::SlowArgon2))
    );
    assert_eq!(
        run(&mut v, &enc(Kdf::AesKdf { rounds: 50_000 }), t5()),
        Err(Refusal::Confirm(Confirm::WeakAesKdf))
    );
    let mut ok = enc(Kdf::AesKdf { rounds: 50_000 });
    ok.confirmed = vec![Confirm::WeakAesKdf];
    run(&mut v, &ok, t5()).unwrap();
    assert_eq!(v.encryption.kdf, Kdf::AesKdf { rounds: 50_000 });
    // T26: the safe minimum.
    assert_eq!(
        run(&mut v, &enc(argon(3, 8_192)), t5()),
        Err(Refusal::Confirm(Confirm::BelowSafeMinimum))
    );
    assert_eq!(
        run(&mut v, &enc(argon(1, 65_536)), t5()),
        Err(Refusal::Confirm(Confirm::BelowSafeMinimum))
    );
    // T27: the cost check asks before anything runs; the report approves.
    let report = match run(&mut v, &enc(argon(2, 2_097_152)), t5()) {
        Err(Refusal::Cost(r)) => r,
        other => panic!("{other:?}"),
    };
    assert!(report.over_memory());
    let mut approved = enc(argon(2, 2_097_152));
    approved.cost_approval = Some(report);
    run(&mut v, &approved, t5()).unwrap();
    // T28: advanced mode removes the unlock time item.
    v.meta.custom_data.items.push(CustomDataItem {
        key: String::from_utf8(
            [
                0x4B, 0x50, 0x58, 0x43, 0x5F, 0x44, 0x45, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4F,
                0x4E, 0x5F, 0x54, 0x49, 0x4D, 0x45, 0x5F, 0x50, 0x52, 0x45, 0x46, 0x45, 0x52, 0x45,
                0x4E, 0x43, 0x45,
            ]
            .to_vec(),
        )
        .unwrap(),
        value: larsal_crypto::secret::SecretString::new("1000".into()),
        last_modified: None,
        unknown: Vec::new(),
    });
    assert_eq!(settings::unlock_time_ms(&v), Some(1_000));
    let mut adv = enc(argon(4, 65_536));
    adv.cost_approval = None;
    run(&mut v, &adv, t6()).unwrap();
    assert_eq!(settings::unlock_time_ms(&v), None);
}

#[test]
fn mod12_13_no_format_choice() {
    // T29: a vault read from a version 3.1 file is saved as version 4.
    let mut v = demo();
    v.read_version = Some(FileVersion { major: 3, minor: 1 });
    assert_eq!(save_open(&v).read_version.map(|r| r.major), Some(4));
}

#[test]
fn mod12_14_when_encryption_changes_take_effect() {
    // T31: nothing touched, nothing runs.
    let mut v = demo();
    let r = run(&mut v, &Changes::default(), t5()).unwrap();
    assert_eq!(r, Applied::default());
    // T30: a touched page derives now; the next save writes the cipher.
    let c = Changes {
        encryption: Some(EncryptionEdit {
            cipher: Cipher::ChaCha20,
            kdf: Kdf::AesKdf { rounds: 1 },
            unlock_time_ms: None,
        }),
        confirmed: vec![Confirm::WeakAesKdf],
        ..Changes::default()
    };
    let r = run(&mut v, &c, t5()).unwrap();
    assert!(r.derive_now && r.settings_changed);
    assert_eq!(save_open(&v).encryption.cipher, Cipher::ChaCha20);
}

#[test]
fn mod12_15_flags_take_effect_on_save() {
    // T32: Title and Notes flags on, password flag off: what the reader
    // sees after a save (own flags from the attribute).
    let mut v = demo();
    let mp = &mut v.meta.memory_protection;
    (mp.title, mp.notes, mp.password) = (true, true, false);
    let read = save_open(&v);
    let e = &read.root.entries[0];
    let flag = |n: &str| e.field(n).unwrap().protected;
    assert!(flag("Title") && flag("Notes"));
    assert!(!flag("UserName") && !flag("URL"));
    // T33: an own flag wins over an off vault flag.
    let mut w = demo();
    w.root.entries[0].set_field("Notes".into(), field("N", true));
    assert!(
        save_open(&w).root.entries[0]
            .field("Notes")
            .unwrap()
            .protected
    );
}

#[test]
fn mod12_16_field_protection_page() {
    // T34: the password switch cannot be off; URL on.
    let mut v = demo();
    v.meta.memory_protection.password = false;
    let p = Protection {
        title: false,
        user_name: false,
        url: true,
        notes: false,
    };
    run(
        &mut v,
        &Changes {
            protection: Some(p),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert!(v.meta.memory_protection.password && v.meta.memory_protection.url);
    // T35: turning notes off clears own flags, times unchanged.
    let mut w = demo();
    w.meta.memory_protection.notes = true;
    w.root.entries[0].set_field("Notes".into(), field("N", true));
    let mut h = entry(0x0a);
    h.set_field("Notes".into(), field("old", true));
    w.root.entries[0].history.push(h);
    let off = Protection {
        title: false,
        user_name: false,
        url: false,
        notes: false,
    };
    run(
        &mut w,
        &Changes {
            protection: Some(off),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    let e = &w.root.entries[0];
    assert!(
        !e.field("Notes").unwrap().protected && !e.history[0].field("Notes").unwrap().protected
    );
    assert_eq!(e.times.last_modification, t0());
}

#[test]
fn mod12_17_passwords_always_protected() {
    // T36: every password field gets its own flag; ProtectPassword stays.
    let mut v = demo();
    v.meta.memory_protection.password = false;
    let mut h = entry(0x0a);
    h.set_field("Password".into(), field("old", false));
    v.root.entries[0].history.push(h);
    settings::protect_all_passwords(&mut v);
    let e = &v.root.entries[0];
    assert!(
        e.field("Password").unwrap().protected && e.history[0].field("Password").unwrap().protected
    );
    assert!(!v.meta.memory_protection.password);
    let read = save_open(&v);
    assert!(read.root.entries[0].field("Password").unwrap().protected);
    // Also on merge (a new entry arriving).
    let mut a = demo();
    a.root.entries.clear();
    let b = demo();
    larsal_core::merge::merge(
        &mut a,
        &b,
        &larsal_core::merge::Options::new(larsal_core::merge::Kind::CommandLine),
        t5(),
    )
    .unwrap();
    assert!(a.root.entries[0].field("Password").unwrap().protected);
}

fn browser(name: &str) -> String {
    format!(
        "{}{name}",
        text(&[
            0x4B, 0x50, 0x58, 0x43, 0x5F, 0x42, 0x52, 0x4F, 0x57, 0x53, 0x45, 0x52, 0x5F
        ])
    )
}

/// Bytes of a name the name rule keeps as hex, as text.
fn text(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}

fn cd(key: &str, value: &str) -> CustomDataItem {
    CustomDataItem {
        key: key.into(),
        value: larsal_crypto::secret::SecretString::new(value.into()),
        last_modified: None,
        unknown: Vec::new(),
    }
}

#[test]
fn mod12_18_association_public_view_excludes_private_metadata() {
    let prefix = browser("");
    let private = "demo-private-share-value";
    let mut v = demo();
    v.meta.custom_data.items = vec![
        cd(&text(larsal_format::share_item::KEY), private),
        cd("_CREATED_private", private),
        cd("_LAST_USED_private", private),
        cd(&format!("x{}", browser("private")), private),
        cd(&prefix.to_ascii_lowercase(), private),
        cd(prefix.strip_suffix('_').unwrap(), private),
        cd(&browser("démo🗝️"), "public-key-1"),
        cd("_CREATED_démo🗝️", "created"),
        cd(&prefix, "public-key-2"),
    ];
    assert_eq!(
        settings::associations(&v),
        vec![
            settings::Association {
                name: "démo🗝️".into(),
                value: "public-key-1".into(),
                created: Some("created".into()),
            },
            settings::Association {
                name: "".into(),
                value: "public-key-2".into(),
                created: None,
            },
        ]
    );
    assert_eq!(
        v.meta
            .custom_data
            .get(&text(larsal_format::share_item::KEY)),
        Some(private)
    );
}

#[test]
fn mod12_18_browser_integration_actions() {
    let assoc = || {
        let mut v = demo();
        v.meta.custom_data.items = vec![
            cd(&browser("demo"), "pk1"),
            cd("_CREATED_demo", "c1"),
            cd(&browser("work"), "pk2"),
            cd("_CREATED_work", "c2"),
        ];
        v
    };
    let mut v = assoc();
    let list = settings::associations(&v);
    assert_eq!(list.len(), 2);
    assert_eq!(
        (list[0].name.as_str(), list[0].created.as_deref()),
        ("demo", Some("c1"))
    );
    // Rename both items; edit the row's own value.
    assert!(settings::rename_association(&mut v, "demo", "home", t5()));
    assert!(v.meta.custom_data.get("_CREATED_home").is_some());
    assert!(settings::set_association_value(&mut v, "home", "pk9", t5()));
    assert_eq!(v.meta.custom_data.get(&browser("home")), Some("pk9"));
    // T37: remove one.
    let mut v = assoc();
    assert_eq!(settings::remove_associations(&mut v, &["demo"], t5()), 1);
    assert!(
        v.meta.custom_data.get(&browser("demo")).is_none()
            && v.meta.custom_data.get("_CREATED_demo").is_none()
    );
    assert_eq!(v.meta.custom_data.get(&browser("work")), Some("pk2"));
    // T38: disconnect all, created items too (D-12-7).
    let mut v = assoc();
    assert_eq!(settings::disconnect_all(&mut v, t5()), 2);
    assert!(v.meta.custom_data.items.is_empty());
    // T39: forget site access is an entry edit.
    let mut v = demo();
    let site: String = text(&[
        0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x58, 0x43, 0x2D, 0x42, 0x72, 0x6F, 0x77, 0x73,
        0x65, 0x72, 0x20, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x73,
    ]);
    v.root.entries[0].custom_data.items.push(cd(&site, "{}"));
    v.root.entries[0].history.push(entry(0x0a));
    v.root.entries.push(entry(0x0b));
    assert_eq!(settings::forget_site_access(&mut v, t5()), 1);
    let e1 = &v.root.entries[0];
    assert!(e1.custom_data.get(&site).is_none());
    assert_eq!((e1.times.last_modification, e1.history.len()), (t5(), 2));
    assert!(
        e1.history[1].custom_data.get(&site).is_some(),
        "history keeps it"
    );
    // T40: a new random root id, no deleted object.
    let old = v.root.uuid;
    let new = settings::new_root_id(&mut v).unwrap();
    assert!(new != old && v.root.uuid == new && v.deleted_objects.is_empty());
}

#[test]
fn mod12_19_maintenance() {
    // T42 and T43 through MOD-06's icon removal (icons.rs).
    let icon = |b: u8| CustomIcon {
        uuid: uid(b),
        name: String::new(),
        last_modified: None,
        data: vec![1],
        unknown: Vec::new(),
    };
    let mut v = demo();
    v.meta.custom_icons = vec![icon(0x32), icon(0x33), icon(0x34)];
    let mut h = entry(0x0a);
    h.icon = Icon::Custom(uid(0x33));
    v.root.entries[0].history.push(h);
    let mut g = Group::new(uid(0x02), "G".into(), t0());
    g.icon = Icon::Custom(uid(0x34));
    v.root.groups.push(g);
    assert_eq!(icons::purge(&mut v, t5()), 2);
    let left: Vec<Uuid> = v.meta.custom_icons.iter().map(|i| i.uuid).collect();
    assert_eq!(left, [uid(0x34)]);
    assert_eq!(v.root.entries[0].history[0].icon, Icon::Standard(0));
    assert_eq!(v.deleted_objects.len(), 2);
    // Delete an icon in use: the group gets icon 48.
    assert_eq!(icons::remove(&mut v, &[uid(0x34)], true, t6()), 1);
    assert_eq!(
        v.root.find_group(uid(0x02)).unwrap().icon,
        Icon::Standard(48)
    );
}

#[test]
fn mod12_20_values_with_no_control_are_kept() {
    // T44.
    let mut v = demo();
    v.meta.color = "#1a2b3c".into();
    v.meta.maintenance_history_days = 30;
    v.meta.entry_templates_group = Some(uid(0x01));
    run(
        &mut v,
        &Changes {
            name: Some("x".into()),
            history_items: Some(4),
            ..Changes::default()
        },
        t5(),
    )
    .unwrap();
    assert_eq!(
        (v.meta.color.as_str(), v.meta.maintenance_history_days),
        ("#1a2b3c", 30)
    );
    assert_eq!(v.meta.entry_templates_group, Some(uid(0x01)));
    let read = save_open(&v);
    assert_eq!(
        (read.meta.color.as_str(), read.meta.maintenance_history_days),
        ("#1a2b3c", 30)
    );
}

#[test]
fn mod12_22_new_vault_defaults() {
    // T46.
    let v = settings::new_vault("Passwords", t5(), 8).unwrap();
    assert_eq!(
        (v.meta.name.as_str(), v.root.name.as_str()),
        ("Passwords", "Root")
    );
    assert_eq!(v.encryption.cipher, Cipher::Aes256);
    assert_eq!(
        v.encryption.kdf,
        Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 2,
            memory_kib: 65_536,
            lanes: 4
        }
    );
    assert!(matches!(
        settings::new_vault("x", t5(), 2).unwrap().encryption.kdf,
        Kdf::Argon2 { lanes: 2, .. }
    ));
    assert_eq!(v.encryption.compression, Compression::Gzip);
    assert!(v.meta.recycle_bin_enabled && recycle::bin_id(&v).is_none());
    assert_eq!(
        (v.meta.history_max_items, v.meta.history_max_size),
        (10, 6_291_456)
    );
    let mp = &v.meta.memory_protection;
    assert!(mp.password && !mp.title && !mp.user_name && !mp.url && !mp.notes);
    assert_eq!(
        (v.meta.master_key_change_rec, v.meta.master_key_change_force),
        (-1, -1)
    );
    assert_eq!(v.meta.maintenance_history_days, 365);
    assert_eq!(
        (
            v.meta.master_key_changed,
            v.meta.settings_changed,
            v.meta.name_changed
        ),
        (t5(), t5(), t5())
    );
    assert!(v.meta.custom_data.items.is_empty() && v.read_version.is_none());
}

// ---- Checker fix pass: tests for the surviving mutants ----

fn changes() -> Changes {
    Changes::default()
}

#[test]
fn mod12_ranges_at_their_edges() {
    // ST02, ST26: 0 MiB is out of range; -1 (off) stays -1.
    let mut v = demo();
    let c = Changes {
        history_mib: Some(0),
        ..changes()
    };
    assert_eq!(
        run(&mut v, &c, t5()),
        Err(Refusal::OutOfRange("vault.history_size"))
    );
    let c = Changes {
        history_mib: Some(-1),
        ..changes()
    };
    run(&mut v, &c, t5()).unwrap();
    assert_eq!(v.meta.history_max_size, -1);
    // ST03: the largest autosave delay is taken, one more is not.
    let c = Changes {
        autosave_minutes: Some(settings::MAX_AUTOSAVE),
        ..changes()
    };
    run(&mut v, &c, t5()).unwrap();
    assert_eq!(settings::autosave_minutes(&v), settings::MAX_AUTOSAVE);
    let c = Changes {
        autosave_minutes: Some(settings::MAX_AUTOSAVE + 1),
        ..changes()
    };
    assert_eq!(
        run(&mut v, &c, t5()),
        Err(Refusal::OutOfRange("vault.autosave_delay"))
    );
}

fn kdf_change(kdf: Kdf, confirmed: Vec<Confirm>) -> Result<Applied, Refusal> {
    let mut v = demo();
    let c = Changes {
        encryption: Some(EncryptionEdit {
            cipher: v.encryption.cipher,
            kdf,
            unlock_time_ms: None,
        }),
        confirmed,
        ..changes()
    };
    run(&mut v, &c, t5())
}

fn argon(iterations: u64, memory_kib: u64) -> Kdf {
    Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations,
        memory_kib,
        lanes: 1,
    }
}

#[test]
fn mod12_kdf_warnings_and_refusal() {
    // ST08: 10,000 iterations need no slow warning; 10,001 do.
    let slow = Err(Refusal::Confirm(Confirm::SlowArgon2));
    assert_ne!(kdf_change(argon(10_000, 19_456), vec![]).map(|_| ()), slow);
    assert_eq!(kdf_change(argon(10_001, 19_456), vec![]).map(|_| ()), slow);
    // ST13: more memory than the machine has: the KDF stays.
    let mut v = demo();
    let before = v.encryption.kdf;
    let c = Changes {
        encryption: Some(EncryptionEdit {
            cipher: v.encryption.cipher,
            kdf: argon(2, 32 << 20),
            unlock_time_ms: None,
        }),
        ..changes()
    };
    assert_eq!(run(&mut v, &c, t5()), Err(Refusal::KdfUnchanged));
    assert_eq!(v.encryption.kdf, before);
}

#[test]
fn mod12_key_checks_at_their_edges() {
    // ST17: Good needs no weak warning; one below does.
    let mut v = demo();
    let c = |q: u8| Changes {
        key: Some(new_password("abc", "abc", q)),
        ..changes()
    };
    assert!(run(&mut v, &c(settings::GOOD), t5()).is_ok());
    assert_eq!(
        run(&mut v, &c(settings::GOOD - 1), t5()),
        Err(Refusal::Confirm(Confirm::WeakPassword))
    );
    // ST19: an untouched password field on a key without one: confirm.
    let k = |had_password: bool| KeyChange {
        password: PasswordPart::Untouched,
        had_password,
        key_file: true,
        hardware: false,
        min_quality: 0,
    };
    let c = Changes {
        key: Some(k(false)),
        ..changes()
    };
    assert_eq!(
        run(&mut v, &c, t5()),
        Err(Refusal::Confirm(Confirm::NoPassword))
    );
    let c = Changes {
        key: Some(k(true)),
        ..changes()
    };
    assert!(run(&mut v, &c, t5()).is_ok());
}

#[test]
fn mod12_settings_time_moves_for_each_settings_value() {
    // ST22, ST23, ST27, ST28.
    let base = demo();
    let mut cases = vec![
        Changes {
            key_change_force: Some(30),
            ..changes()
        },
        Changes {
            protection: Some(Protection {
                title: true,
                user_name: false,
                url: false,
                notes: false,
            }),
            ..changes()
        },
        Changes {
            recycle_bin: Some(!base.meta.recycle_bin_enabled),
            ..changes()
        },
    ];
    cases.push(Changes {
        compression: Some(match base.encryption.compression {
            Compression::None => Compression::Gzip,
            Compression::Gzip => Compression::None,
        }),
        ..changes()
    });
    for (i, c) in cases.iter().enumerate() {
        let mut v = demo();
        let out = run(&mut v, c, t6()).unwrap();
        assert!(out.settings_changed && out.changed, "case {i}");
        assert_eq!(v.meta.settings_changed, t6(), "case {i}");
    }
}

#[test]
fn mod12_force_once_and_same_values() {
    // ST34: setting the force-once flag is a change.
    let mut v = demo();
    let c = Changes {
        force_once: Some(true),
        ..changes()
    };
    let out = run(&mut v, &c, t5()).unwrap();
    assert!(out.changed && v.meta.master_key_change_force_once);
    // ST41: the same autosave value again changes nothing.
    let c = Changes {
        autosave_minutes: Some(5),
        ..changes()
    };
    assert!(run(&mut v, &c, t5()).unwrap().changed);
    let data = v.meta.custom_data.clone();
    assert!(!run(&mut v, &c, t6()).unwrap().changed);
    assert_eq!(v.meta.custom_data, data);
}

#[test]
fn mod12_unlock_time_shown_at_least_100() {
    // ST45: a stored 50 ms shows as 100.
    let mut v = demo();
    let c = Changes {
        encryption: Some(EncryptionEdit {
            cipher: v.encryption.cipher,
            kdf: v.encryption.kdf,
            unlock_time_ms: Some(50),
        }),
        ..changes()
    };
    run(&mut v, &c, t5()).unwrap();
    assert_eq!(settings::unlock_time_ms(&v), Some(100));
}

#[test]
fn mod12_rename_onto_an_existing_association() {
    // ST47: refused; both rows stay as they were.
    let mut v = demo();
    v.meta.custom_data.items = vec![cd(&browser("demo"), "pk1"), cd(&browser("work"), "pk2")];
    let before = v.meta.custom_data.clone();
    assert!(!settings::rename_association(&mut v, "demo", "work", t5()));
    assert_eq!(v.meta.custom_data, before);
}

/// APP-07.9 (T15): Argon2d with 8 MiB and 20,000 iterations asks the safe
/// minimum first, then the slow warning, then the cost question; the
/// warnings come in the card's order, one at a time.
#[test]
fn app07_9_safe_minimum_asks_before_the_slow_warning() {
    let mut v = demo();
    let kdf = Kdf::Argon2 {
        kind: Argon2Kind::D,
        iterations: 20_000,
        memory_kib: 8_192,
        lanes: 1,
    };
    let c = |confirmed: Vec<Confirm>| Changes {
        encryption: Some(EncryptionEdit {
            cipher: Cipher::Aes256,
            kdf,
            unlock_time_ms: None,
        }),
        confirmed,
        ..changes()
    };
    assert_eq!(
        run(&mut v, &c(vec![]), t5()),
        Err(Refusal::Confirm(Confirm::BelowSafeMinimum))
    );
    assert_eq!(
        run(&mut v, &c(vec![Confirm::BelowSafeMinimum]), t5()),
        Err(Refusal::Confirm(Confirm::SlowArgon2))
    );
    // T15's third question: 20,000 passes over 8 MiB pass the 10-second
    // estimate of CRY-02.14 on a real Mac, so the cost question comes
    // last; its report approves.
    let report = match run(
        &mut v,
        &c(vec![Confirm::BelowSafeMinimum, Confirm::SlowArgon2]),
        t5(),
    ) {
        Err(Refusal::Cost(r)) => r,
        other => panic!("{other:?}"),
    };
    assert!(report.over_time());
    let mut approved = c(vec![Confirm::BelowSafeMinimum, Confirm::SlowArgon2]);
    approved.cost_approval = Some(report);
    run(&mut v, &approved, t5()).unwrap();
    assert_eq!(v.encryption.kdf, kdf);
}
