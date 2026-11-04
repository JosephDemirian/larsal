//! E5-S8: the new vault wizard over the Rust session (APP-07, MOD-12.22).
//! Small Argon2 costs (1 MiB, 100 ms) keep the runs short; demo passwords
//! only. Each test names its card rule.

use larsal_crypto::kdf::{Host, KdfParams};
use larsal_crypto::secret::SecretString;
use larsal_ffi::larsal_settings::{LarsalSetting, LarsalSettingValue};
use larsal_ffi::session::{Session, UnlockResult};
use larsal_ffi::wizard::{
    Answer, CipherChoice, EncryptionChoice, KdfChoice, KeyFileOutcome, Outcome, Wizard,
};
use larsal_format::header::{Compression, read_header};
use larsal_format::keyfile::read_key_file;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, open};
use larsal_model::{Argon2Kind, Cipher, Kdf};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("new-vault")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Small and quick: Argon2id 1 MiB, 1 lane, 100 ms.
fn small() -> EncryptionChoice {
    EncryptionChoice {
        cipher: CipherChoice::Aes256,
        kdf: KdfChoice::Argon2id,
        memory_mib: 1,
        lanes: 1,
        unlock_ms: 100,
    }
}

fn wizard() -> (Arc<Session>, Arc<Wizard>) {
    let s = Session::new();
    let w = Wizard::new(Arc::clone(&s));
    assert!(w.measure(small()).unwrap());
    (s, w)
}

fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: None,
    }
}

/// Opens `path` with our reader; the vault or the error.
fn reopen(
    path: &Path,
    password: Option<&str>,
    key: Option<&PathBuf>,
) -> Result<larsal_model::Vault, larsal_format::Error> {
    let bytes = std::fs::read(path).unwrap();
    let p = password.map(|p| SecretString::new(p.to_owned()));
    let k = key.map(|k| read_key_file(std::fs::File::open(k).unwrap(), &Limits::DEFAULT).unwrap());
    let creds = Credentials {
        password: p.as_ref(),
        key_file: k.as_ref(),
        hardware_key: None,
    };
    match open(&bytes, &creds, &mut host(), &Limits::DEFAULT, None)? {
        Opened::Vault(v) => Ok(v.vault),
        Opened::Ask(_) => panic!("asked"),
    }
}

/// The small settings fall below the safe minimum: answered once.
const SMALL_OK: [Answer; 1] = [Answer::SafeMinimum];

#[test]
fn app07_17_t35_a_new_vault_reopens_with_our_tools_with_the_same_settings() {
    let d = dir("t35");
    let path = d.join("new.larsalvault");
    let (s, w) = wizard();
    assert_eq!(
        w.set_password("4v8Nq2LmZ7rT1xKc9WbP".into())
            .unwrap()
            .map(|r| r.level),
        Some("Excellent".into())
    );
    assert_eq!(
        w.set_repeat("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap(),
        Some(true)
    );
    let mut choice = small();
    choice.cipher = CipherChoice::ChaCha20;
    let out = w
        .create(
            "Demo vault".into(),
            "Made by the wizard test".into(),
            path.to_string_lossy().into(),
            choice,
            false,
            SMALL_OK.to_vec(),
        )
        .unwrap();
    let Outcome::Created { vault } = out else {
        panic!("{out:?}")
    };
    // SD-09: owner only.
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The header: version 4.0, the cipher chosen, Argon2id 1 MiB, gzip.
    let bytes = std::fs::read(&path).unwrap();
    let h = read_header(&bytes, &Limits::DEFAULT).unwrap();
    assert_eq!((h.major, h.minor), (4, 0));
    assert_eq!(h.compression, Compression::Gzip);
    assert!(matches!(
        h.kdf,
        KdfParams::Argon2 {
            memory_kib: 1024,
            lanes: 1,
            ..
        }
    ));
    // Our reader opens it with the password: the same settings (MOD-12.22).
    let v = reopen(&path, Some("4v8Nq2LmZ7rT1xKc9WbP"), None).unwrap();
    assert_eq!(v.meta.name, "Demo vault");
    assert_eq!(v.meta.description, "Made by the wizard test");
    assert_eq!(v.root.name, "Root");
    assert!(v.root.entries.is_empty() && v.root.groups.is_empty());
    assert_eq!(v.encryption.cipher, Cipher::ChaCha20);
    assert!(matches!(
        v.encryption.kdf,
        Kdf::Argon2 {
            kind: Argon2Kind::Id,
            memory_kib: 1024,
            lanes: 1,
            ..
        }
    ));
    assert!(v.meta.recycle_bin_enabled && v.meta.recycle_bin.is_none());
    assert_eq!(
        (v.meta.history_max_items, v.meta.history_max_size),
        (10, 6_291_456)
    );
    let mp = &v.meta.memory_protection;
    assert!(mp.password && !mp.title && !mp.user_name && !mp.url && !mp.notes);
    assert_eq!(v.meta.maintenance_history_days, 365);
    assert_eq!(
        (v.meta.master_key_change_rec, v.meta.master_key_change_force),
        (-1, -1)
    );
    // APP-07.10: the unlock time item holds the time.
    assert!(v.meta.custom_data.items.iter().any(|i| i.value == "100"));
    // A wrong password does not open it.
    assert!(reopen(&path, Some("demo-new-2"), None).is_err());
    // APP-07.18: open, unlocked and shown in the session; it opens again
    // in Larsal after a lock with the same password.
    let info = s.vaults().into_iter().find(|i| i.id == vault).unwrap();
    assert!(info.shown && !info.locked);
    s.lock(vault).unwrap();
    assert_eq!(
        s.unlock(vault, Some("4v8Nq2LmZ7rT1xKc9WbP".into()), None)
            .unwrap(),
        UnlockResult::Unlocked
    );
    // The typed passwords are wiped after the write.
    assert_eq!(w.password(), "");
}

#[test]
fn app07_13_t22_t36_a_new_key_file_and_a_vault_that_needs_both() {
    let d = dir("t22");
    let key = d.join("k.larsalkey");
    let (_s, w) = wizard();
    let KeyFileOutcome::Chosen { file } = w.new_key_file(key.to_string_lossy().into()).unwrap()
    else {
        panic!()
    };
    assert_eq!(file.name, "k.larsalkey");
    // FMT-18.20 to FMT-18.22: the XML 2.0 layout, owner read-only.
    let meta = std::fs::metadata(&key).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o400);
    let text = std::fs::read_to_string(&key).unwrap();
    assert!(text.contains("<Version>2.0</Version>") && text.contains("Hash=\""));
    let k = read_key_file(std::fs::File::open(&key).unwrap(), &Limits::DEFAULT).unwrap();
    assert_eq!(k.kind(), larsal_format::keyfile::KeyFileKind::Xml2);
    // T36: a vault with the password and the key file needs both.
    w.set_password("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap();
    w.set_repeat("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap();
    let path = d.join("both.larsalvault");
    let out = w
        .create(
            "Both".into(),
            String::new(),
            path.to_string_lossy().into(),
            small(),
            false,
            SMALL_OK.to_vec(),
        )
        .unwrap();
    assert!(matches!(out, Outcome::Created { .. }), "{out:?}");
    assert!(reopen(&path, Some("4v8Nq2LmZ7rT1xKc9WbP"), Some(&key)).is_ok());
    assert!(reopen(&path, Some("4v8Nq2LmZ7rT1xKc9WbP"), None).is_err());
    // T03: the key file stays after the wizard is gone.
    drop(w);
    assert!(key.exists());
}

#[test]
fn app07_13_t23_never_over_an_existing_file() {
    let d = dir("t23");
    let photo = d.join("photo.jpg");
    std::fs::write(&photo, b"demo photo bytes").unwrap();
    let (_s, w) = wizard();
    let out = w.new_key_file(photo.to_string_lossy().into()).unwrap();
    let KeyFileOutcome::Then {
        outcome: Outcome::Refused { id, text },
    } = out
    else {
        panic!("{out:?}")
    };
    assert_eq!(id, "M07-26");
    assert!(text.contains("\"photo.jpg\" already exists"));
    assert_eq!(std::fs::read(&photo).unwrap(), b"demo photo bytes");
}

#[test]
fn app07_14_t25_t26_t27_chosen_key_files() {
    let d = dir("t25");
    let (_s, w) = wizard();
    let testdata = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    // T25: an early kind works with M07-28.
    let out = w
        .choose_key_file(
            testdata
                .join("key-xml-v1.larsalkey")
                .to_string_lossy()
                .into(),
            vec![],
        )
        .unwrap();
    let KeyFileOutcome::Chosen { file } = out else {
        panic!("{out:?}")
    };
    assert!(file.note.unwrap().contains("early kind"));
    // T26: an empty file gives the M06-07 text as M07-27.
    let empty = d.join("empty.larsalkey");
    std::fs::write(&empty, b"").unwrap();
    let out = w
        .choose_key_file(empty.to_string_lossy().into(), vec![])
        .unwrap();
    let KeyFileOutcome::Then {
        outcome: Outcome::Refused { id, text },
    } = out
    else {
        panic!("{out:?}")
    };
    assert_eq!(id, "M07-27");
    assert!(text.contains("is empty"), "{text}");
    // T27: a vault-like name asks M06-31; the yes takes it.
    let like = d.join("x.larsalvault");
    std::fs::write(&like, b"demo bytes that are not a vault").unwrap();
    let out = w
        .choose_key_file(like.to_string_lossy().into(), vec![])
        .unwrap();
    let KeyFileOutcome::Then {
        outcome: Outcome::Ask { question },
    } = out
    else {
        panic!("{out:?}")
    };
    assert_eq!(
        (question.id.as_str(), question.answer),
        ("M06-31", Answer::VaultLikeKeyFile)
    );
    let out = w
        .choose_key_file(
            like.to_string_lossy().into(),
            vec![Answer::VaultLikeKeyFile],
        )
        .unwrap();
    assert!(matches!(out, KeyFileOutcome::Chosen { .. }));
}

#[test]
fn app07_16_the_checks_in_the_cards_order() {
    let d = dir("t28");
    let (_s, w) = wizard();
    let path = d.join("v.larsalvault").to_string_lossy().into_owned();
    let create = |answers: Vec<Answer>| {
        w.create(
            "V".into(),
            String::new(),
            path.clone(),
            small(),
            true,
            answers,
        )
        .unwrap()
    };
    // T28: only the repeat typed: M07-20 and nothing else.
    w.set_repeat("abc".into()).unwrap();
    assert!(matches!(create(vec![]), Outcome::Refused { id, .. } if id == "M07-20"));
    // T32: both empty and nothing else: M07-21, then M07-24.
    w.set_repeat(String::new()).unwrap();
    let Outcome::Ask { question } = create(vec![]) else {
        panic!()
    };
    assert_eq!(
        (question.id.as_str(), question.confirm.as_str()),
        ("M07-21", "Use No Password")
    );
    assert!(
        matches!(create(vec![Answer::NoPassword]), Outcome::Refused { id, .. } if id == "M07-24")
    );
    // T30: a weak password: M07-23, then "Use this password" goes on.
    w.set_password("password".into()).unwrap();
    w.set_repeat("password".into()).unwrap();
    let Outcome::Ask { question } = create(vec![]) else {
        panic!()
    };
    assert_eq!(
        (
            question.id.as_str(),
            question.message.as_str(),
            question.confirm.as_str()
        ),
        (
            "M07-23",
            "This password is easy to guess, so your vault is less safe. Use it anyway?",
            "Use this password"
        )
    );
    assert!(
        !std::path::Path::new(&path).exists(),
        "nothing written before the yes"
    );
    // APP-07.16 step 8: with every check passed and no path yet, the save
    // panel comes next; nothing is written.
    let out = w
        .create(
            "V".into(),
            String::new(),
            String::new(),
            small(),
            true,
            vec![Answer::WeakPassword],
        )
        .unwrap();
    assert_eq!(out, Outcome::Done);
    assert!(!std::path::Path::new(&path).exists());
    assert!(matches!(
        create(vec![Answer::WeakPassword]),
        Outcome::Created { .. }
    ));
}

/// APP-07.16 check 3, T31 (S-CFG-02, FEA-05.7): with the minimum at 3 a
/// weak password is refused with M07-22, no "Use this password" question;
/// a stronger one still goes on.
#[test]
fn app07_16_t31_a_password_below_the_set_minimum_is_refused() {
    let d = dir("t31");
    let path = d.join("v.larsalvault").to_string_lossy().into_owned();
    let (s, w) = wizard();
    s.save_settings(vec![LarsalSetting {
        key: "security.min_master_quality".into(),
        value: LarsalSettingValue::Number { value: 3 },
    }])
    .unwrap();
    let create = |answers: Vec<Answer>| {
        w.create(
            "V".into(),
            String::new(),
            path.clone(),
            small(),
            true,
            answers,
        )
        .unwrap()
    };
    w.set_password("password1".into()).unwrap();
    w.set_repeat("password1".into()).unwrap();
    for answers in [vec![], vec![Answer::WeakPassword]] {
        assert!(
            matches!(create(answers), Outcome::Refused { id, .. } if id == "M07-22"),
            "below the minimum"
        );
    }
    assert!(!Path::new(&path).exists(), "nothing written");
    w.set_password("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap();
    w.set_repeat("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap();
    assert!(matches!(create(vec![]), Outcome::Created { .. }));
}

/// The level of a demo password (FEA-05.4: 0 Bad to 4 Excellent), as the
/// meter shows it, typed into both fields.
fn typed(w: &Wizard, password: &str) -> u8 {
    let level = w.set_password(password.into()).unwrap().unwrap().segments;
    w.set_repeat(password.into()).unwrap();
    level
}

/// S-CFG-02's edges (FEA-05.7, APP-07.16 check 3): a password exactly at
/// the minimum passes with no question, one level below is refused with
/// M07-22, and a minimum of 4 refuses Good (3), also with the yes.
#[test]
fn app07_16_s_cfg_02_a_password_at_the_minimum_passes_and_4_refuses_good() {
    let d = dir("s-cfg-02");
    let (s, w) = wizard();
    let minimum = |n: i64| {
        s.save_settings(vec![LarsalSetting {
            key: "security.min_master_quality".into(),
            value: LarsalSettingValue::Number { value: n },
        }])
        .unwrap();
    };
    let create = |name: &str, answers: Vec<Answer>| {
        let path = d.join(name).to_string_lossy().into_owned();
        w.create("V".into(), String::new(), path, small(), true, answers)
            .unwrap()
    };
    let refused = |out: Outcome| matches!(out, Outcome::Refused { id, .. } if id == "M07-22");
    minimum(3);
    assert_eq!(typed(&w, "Tr0ub4dor&3"), 2);
    assert!(refused(create("below.larsalvault", vec![])));
    assert_eq!(typed(&w, "kT7#pQ2vZ9mW4x"), 3);
    assert!(matches!(
        create("at.larsalvault", vec![]),
        Outcome::Created { .. }
    ));
    minimum(4);
    assert_eq!(typed(&w, "kT7#pQ2vZ9mW4x"), 3);
    assert!(refused(create("good.larsalvault", vec![])));
    assert!(refused(create(
        "good.larsalvault",
        vec![Answer::WeakPassword]
    )));
    assert!(!d.join("good.larsalvault").exists() && !d.join("below.larsalvault").exists());
    assert_eq!(typed(&w, "4v8Nq2LmZ7rT1xKc9WbP"), 4);
    assert!(matches!(
        create("excellent.larsalvault", vec![]),
        Outcome::Created { .. }
    ));
}

#[test]
fn app07_16_t29_no_password_with_a_key_file_opens_with_the_key_file_alone() {
    let d = dir("t29");
    let key = d.join("only.larsalkey");
    let path = d.join("v.larsalvault");
    let (_s, w) = wizard();
    assert!(matches!(
        w.new_key_file(key.to_string_lossy().into()).unwrap(),
        KeyFileOutcome::Chosen { .. }
    ));
    let out = w
        .create(
            "V".into(),
            String::new(),
            path.to_string_lossy().into(),
            small(),
            true,
            vec![Answer::NoPassword],
        )
        .unwrap();
    assert!(matches!(out, Outcome::Created { .. }), "{out:?}");
    // No password part: the key file alone opens it; the empty password does not.
    assert!(reopen(&path, None, Some(&key)).is_ok());
    assert!(reopen(&path, Some(""), Some(&key)).is_err());
}

#[test]
fn app07_17_t34_never_over_its_own_key_file_and_t37_no_partial_file() {
    let d = dir("t34");
    let key = d.join("k.larsalkey");
    let (_s, w) = wizard();
    w.new_key_file(key.to_string_lossy().into()).unwrap();
    w.set_password("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap();
    w.set_repeat("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap();
    let before = std::fs::read(&key).unwrap();
    let out = w
        .create(
            "V".into(),
            String::new(),
            key.to_string_lossy().into(),
            small(),
            true,
            vec![],
        )
        .unwrap();
    assert!(matches!(out, Outcome::Refused { id, .. } if id == "M07-29"));
    assert_eq!(std::fs::read(&key).unwrap(), before);
    // T37: a folder Larsal may not write: M07-30 with the reason, no file, and
    // the values kept for another place.
    let locked = d.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    let target = locked.join("v.larsalvault");
    let out = w
        .create(
            "V".into(),
            String::new(),
            target.to_string_lossy().into(),
            small(),
            true,
            vec![],
        )
        .unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    let Outcome::Refused { id, text } = out else {
        panic!("{out:?}")
    };
    assert_eq!(id, "M07-30");
    assert_eq!(
        text,
        "The vault could not be created: Larsal is not allowed to write there."
    );
    assert_eq!(std::fs::read_dir(&locked).unwrap().count(), 0);
    assert_eq!(w.password(), "4v8Nq2LmZ7rT1xKc9WbP");
    let ok = d.join("v.larsalvault");
    let out = w
        .create(
            "V".into(),
            String::new(),
            ok.to_string_lossy().into(),
            small(),
            true,
            vec![],
        )
        .unwrap();
    assert!(matches!(out, Outcome::Created { .. }));
}

#[test]
fn app07_9_step_two_checks_and_m07_35() {
    let (_s, w) = wizard();
    // Simple mode: none.
    assert_eq!(w.check_encryption(small(), true, vec![]), Outcome::Done);
    // Advanced: 1 MiB is below the safe minimum (M07-33), with the time.
    let Outcome::Ask { question } = w.check_encryption(small(), false, vec![]) else {
        panic!()
    };
    assert_eq!(question.id, "M07-33");
    assert!(
        question.message.contains("about 0.1 seconds"),
        "{}",
        question.message
    );
    assert_eq!(
        w.check_encryption(small(), false, SMALL_OK.to_vec()),
        Outcome::Done
    );
    // T16: more memory than this Mac has: M07-35, before anything else.
    let mut big = small();
    big.memory_mib = 1 << 30;
    assert!(
        w.memory_note(big.memory_mib)
            .unwrap()
            .starts_with("This Mac has ")
    );
    assert!(
        matches!(w.check_encryption(big, false, vec![]), Outcome::Refused { id, .. } if id == "M07-35")
    );
    // Not measured yet for another memory: M07-08, Continue waits.
    let mut other = small();
    other.memory_mib = 2;
    assert!(
        matches!(w.check_encryption(other, false, vec![]), Outcome::Refused { id, .. } if id == "M07-08")
    );
}

// APP-07.8's cancel: wizard.rs unit test
// `app07_8_a_cancel_during_the_run_drops_its_result` (deterministic).
#[test]
fn app07_6_the_defaults() {
    let w = Wizard::new(Session::new());
    // The defaults (APP-07.6): AES-256, Argon2id, 64 MiB, min(4, cores), 1 s.
    let d = w.defaults();
    assert_eq!(
        (d.cipher, d.kdf, d.memory_mib, d.unlock_ms),
        (CipherChoice::Aes256, KdfChoice::Argon2id, 64, 1_000)
    );
    assert!((1..=4).contains(&d.lanes));
}

#[test]
fn app07_11_meter_match_show_and_generate() {
    let (_s, w) = wizard();
    // FEA-05.7: nothing for an empty field.
    assert_eq!(w.set_password(String::new()).unwrap(), None);
    w.set_password("demo-new-1".into()).unwrap();
    // T19.
    assert_eq!(w.set_repeat("demo-new".into()).unwrap(), Some(false));
    assert_eq!(w.set_repeat("demo-new-1".into()).unwrap(), Some(true));
    assert_eq!(w.set_repeat(String::new()).unwrap(), None);
    assert_eq!(w.password(), "demo-new-1");
    // T20: the dice fills both fields.
    let value = w.generate().unwrap();
    assert!(!value.is_empty());
    assert_eq!((w.password(), w.repeat()), (value.clone(), value));
}
