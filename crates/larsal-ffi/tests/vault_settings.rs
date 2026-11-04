//! E5-S8: the vault settings over the Rust session (MOD-12), on copies of
//! the Option A demo vaults (passwords in testdata/README.md). Each test
//! names its card rule.

use larsal_crypto::cipher::Cipher;
use larsal_crypto::kdf::{Argon2Type, KdfParams};
use larsal_ffi::larsal_settings::{LarsalSetting, LarsalSettingValue};
use larsal_ffi::session::{Session, UnlockResult};
use larsal_ffi::vault_settings::{SettingsChange, VaultSettings};
use larsal_ffi::wizard::{
    Answer, CipherChoice, EncryptionChoice, KdfChoice, KeyFileOutcome, Outcome,
};
use larsal_format::header::read_header;
use larsal_format::limits::Limits;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A fresh copy of a demo vault, unlocked in a test session.
fn open(
    source: &str,
    password: &str,
    name: &str,
) -> (Arc<Session>, u64, PathBuf, Arc<VaultSettings>) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("vault-settings")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("Vault.larsalvault");
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(source),
        &path,
    )
    .unwrap();
    let s = Session::new();
    let id = s.open(path.to_string_lossy().into_owned()).unwrap();
    assert_eq!(
        s.unlock(id, Some(password.into()), None).unwrap(),
        UnlockResult::Unlocked
    );
    let settings = VaultSettings::new(Arc::clone(&s), id);
    (s, id, path, settings)
}

fn family(name: &str) -> (Arc<Session>, u64, PathBuf, Arc<VaultSettings>) {
    open("option-a-family.larsalvault", "demo-pass-9", name)
}

fn saved(s: &Session, id: u64) {
    let status = s.save(id).unwrap();
    assert_eq!((status.changes, status.failure), (0, None));
}

fn unlocks(path: &Path, password: &str, key: Option<&PathBuf>) -> bool {
    let s = Session::new();
    let id = s.open(path.to_string_lossy().into_owned()).unwrap();
    let key = key.map(|k| k.to_string_lossy().into_owned());
    s.unlock(id, Some(password.into()), key).unwrap() == UnlockResult::Unlocked
}

#[test]
fn mod12_14_a_changed_cipher_and_kdf_are_in_the_saved_header() {
    let (s, id, path, vs) = family("encryption");
    // The stored 1 MiB is below Larsal's safe minimum: a cipher change asks too.
    let Outcome::Ask { question } = vs.set_cipher(CipherChoice::ChaCha20, vec![]).unwrap() else {
        panic!()
    };
    assert_eq!(question.id, "M07-33");
    assert_eq!(
        vs.set_cipher(CipherChoice::ChaCha20, vec![Answer::SafeMinimum])
            .unwrap(),
        Outcome::Done
    );
    let choice = EncryptionChoice {
        cipher: CipherChoice::ChaCha20,
        kdf: KdfChoice::Argon2d,
        memory_mib: 2,
        lanes: 1,
        unlock_ms: 100,
    };
    assert!(vs.measure(choice).unwrap());
    // 2 MiB is below Larsal's safe minimum: asked (MOD-12.12, D-12-6).
    let Outcome::Ask { question } = vs.set_kdf(choice, vec![]).unwrap() else {
        panic!()
    };
    assert_eq!(question.id, "M07-33");
    assert_eq!(
        vs.set_kdf(choice, vec![Answer::SafeMinimum]).unwrap(),
        Outcome::Done
    );
    assert_eq!(s.save_status(id).unwrap().changes, 2);
    saved(&s, id);
    // The next save wrote the new settings into the header (re-encrypted).
    let h = read_header(&std::fs::read(&path).unwrap(), &Limits::DEFAULT).unwrap();
    assert_eq!(h.cipher, Cipher::ChaCha20);
    assert!(matches!(
        h.kdf,
        KdfParams::Argon2 {
            kind: Argon2Type::D,
            memory_kib: 2048,
            lanes: 1,
            ..
        }
    ));
    // MOD-12.11: the unlock time item keeps the time; the view shows it.
    let view = vs.view().unwrap();
    assert_eq!(view.encryption, choice);
    assert!(unlocks(&path, "demo-pass-9", None));
}

#[test]
fn mod12_10_a_credential_change_needs_the_new_credentials_to_open() {
    let (s, id, path, vs) = family("credentials");
    // The match first (APP-07.16 order on this page too).
    vs.set_password("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap();
    vs.set_repeat("4v8Nq2LmZ7rT1xKc9Wb".into()).unwrap();
    assert!(
        matches!(vs.change_password(vec![]).unwrap(), Outcome::Refused { id, .. } if id == "M07-20")
    );
    assert_eq!(
        vs.set_repeat("4v8Nq2LmZ7rT1xKc9WbP".into()).unwrap(),
        Some(true)
    );
    let before = vs.view().unwrap().password_changed;
    assert_eq!(vs.change_password(vec![]).unwrap(), Outcome::Done);
    // T21: MasterKeyChanged moved; the typed passwords are wiped.
    assert!(vs.view().unwrap().password_changed >= before);
    assert_eq!(vs.password(), "");
    saved(&s, id);
    assert!(!unlocks(&path, "demo-pass-9", None));
    assert!(unlocks(&path, "4v8Nq2LmZ7rT1xKc9WbP", None));
    // A new key file joins the key: then the vault needs both.
    let key = path.with_file_name("family.larsalkey");
    let out = vs
        .new_key_file(key.to_string_lossy().into(), vec![])
        .unwrap();
    assert_eq!(
        out,
        KeyFileOutcome::Then {
            outcome: Outcome::Done
        }
    );
    assert_eq!(
        vs.view().unwrap().key_file.as_deref(),
        Some("family.larsalkey")
    );
    saved(&s, id);
    assert!(!unlocks(&path, "4v8Nq2LmZ7rT1xKc9WbP", None));
    assert!(unlocks(&path, "4v8Nq2LmZ7rT1xKc9WbP", Some(&key)));
    // T20: removing the password with no key file left is refused; with
    // the key file kept, M07-21 asks first.
    vs.set_password(String::new()).unwrap();
    vs.set_repeat(String::new()).unwrap();
    let Outcome::Ask { question } = vs.change_password(vec![]).unwrap() else {
        panic!()
    };
    assert_eq!(question.id, "M07-21");
    assert_eq!(
        vs.change_password(vec![Answer::NoPassword]).unwrap(),
        Outcome::Done
    );
    assert!(matches!(
        vs.remove_key_file(vec![Answer::NoPassword]).unwrap(),
        Outcome::Refused { id, .. } if id == "M07-24"
    ));
    saved(&s, id);
    let s2 = Session::new();
    let v2 = s2.open(path.to_string_lossy().into_owned()).unwrap();
    assert_eq!(
        s2.unlock(v2, None, Some(key.to_string_lossy().into()))
            .unwrap(),
        UnlockResult::Unlocked
    );
}

/// MOD-12.10 step 3, T18 (S-CFG-02, FEA-05.7): with the minimum at 3 a
/// weak new password is refused with M07-22 and the key stays as it was.
#[test]
fn mod12_10_t18_a_password_below_the_set_minimum_is_refused() {
    let (s, id, path, vs) = family("minimum");
    s.save_settings(vec![LarsalSetting {
        key: "security.min_master_quality".into(),
        value: LarsalSettingValue::Number { value: 3 },
    }])
    .unwrap();
    vs.set_password("password1".into()).unwrap();
    vs.set_repeat("password1".into()).unwrap();
    for answers in [vec![], vec![Answer::WeakPassword]] {
        assert!(
            matches!(vs.change_password(answers).unwrap(), Outcome::Refused { id, .. } if id == "M07-22")
        );
    }
    saved(&s, id);
    assert!(unlocks(&path, "demo-pass-9", None));
    assert!(!unlocks(&path, "password1", None));
}

/// S-CFG-02's edges in Change… (MOD-12.10 step 3, FEA-05.7): a new
/// password exactly at the minimum is taken with no question; a minimum of
/// 4 refuses Good (3), also with the yes, and the key stays as it was.
#[test]
fn mod12_10_s_cfg_02_a_password_at_the_minimum_passes_and_4_refuses_good() {
    let (s, id, path, vs) = family("minimum-edges");
    let minimum = |n: i64| {
        s.save_settings(vec![LarsalSetting {
            key: "security.min_master_quality".into(),
            value: LarsalSettingValue::Number { value: n },
        }])
        .unwrap();
    };
    let typed = |password: &str| {
        let level = vs.set_password(password.into()).unwrap().unwrap().segments;
        vs.set_repeat(password.into()).unwrap();
        level
    };
    minimum(4);
    assert_eq!(typed("kT7#pQ2vZ9mW4x"), 3);
    for answers in [vec![], vec![Answer::WeakPassword]] {
        assert!(
            matches!(vs.change_password(answers).unwrap(), Outcome::Refused { id, .. } if id == "M07-22")
        );
    }
    saved(&s, id);
    assert!(unlocks(&path, "demo-pass-9", None));
    minimum(3);
    assert_eq!(typed("kT7#pQ2vZ9mW4x"), 3);
    assert_eq!(vs.change_password(vec![]).unwrap(), Outcome::Done);
    saved(&s, id);
    assert!(unlocks(&path, "kT7#pQ2vZ9mW4x", None));
}

#[test]
fn fmt18_24_the_vault_itself_is_never_its_key_file() {
    let (_s, _id, path, vs) = family("own-key");
    let out = vs
        .choose_key_file(
            path.to_string_lossy().into(),
            vec![Answer::VaultLikeKeyFile],
        )
        .unwrap();
    assert!(
        matches!(out, KeyFileOutcome::Then { outcome: Outcome::Refused { id, .. } } if id == "M06-30")
    );
}

#[test]
fn mod12_3_to_mod12_6_general_bin_and_history() {
    let (s, id, path, vs) = open("option-a-personal.larsalvault", "demo-pass-7", "general");
    let view = vs.view().unwrap();
    assert_eq!(
        (view.version.as_str(), view.history_items, view.history_mib),
        ("4.1", 10, 6)
    );
    assert!(view.path.ends_with("/Vault.larsalvault"));
    assert!(view.recycle_bin && view.bin_items == 2);
    // T31: nothing touched, nothing changed.
    assert_eq!(vs.apply(SettingsChange::default()).unwrap(), Outcome::Done);
    assert_eq!(s.save_status(id).unwrap().changes, 0);
    // MOD-12.3, MOD-12.4: name, default user name, description, colour.
    let change = SettingsChange {
        name: Some("Personal".into()),
        default_user_name: Some("alex.morgan@posteo.de".into()),
        description: Some("Everything that is mine, not work.".into()),
        colour: Some("#5A6B7D".into()),
        ..SettingsChange::default()
    };
    assert_eq!(vs.apply(change).unwrap(), Outcome::Done);
    let view = vs.view().unwrap();
    assert_eq!(view.default_user_name, "alex.morgan@posteo.de");
    assert_eq!(view.colour, Some(0x5a6b7d));
    // MOD-12.5: out of range refused, nothing applied.
    let bad = SettingsChange {
        history_items: Some(100_001),
        ..SettingsChange::default()
    };
    assert!(
        matches!(vs.apply(bad).unwrap(), Outcome::Refused { id, .. } if id == "vault.history_items")
    );
    // T09: a lower limit cuts the histories at once.
    let (_, before) = (view.history_bytes, view.history_versions);
    let fewer = SettingsChange {
        history_items: Some(0),
        ..SettingsChange::default()
    };
    assert_eq!(vs.apply(fewer).unwrap(), Outcome::Done);
    let view = vs.view().unwrap();
    assert!(before > 0 && view.history_versions == 0 && view.history_bytes == 0);
    // MOD-12.6, MOD-04.12: the bin off and kept as a normal group.
    let off = SettingsChange {
        recycle_bin: Some(false),
        ..SettingsChange::default()
    };
    assert_eq!(vs.apply(off).unwrap(), Outcome::Done);
    assert!(!vs.view().unwrap().recycle_bin);
    saved(&s, id);
    assert!(unlocks(&path, "demo-pass-7", None));
}

#[test]
fn mod12_18_browser_keys_and_site_permissions() {
    let (s, id, _path, vs) = open("option-a-personal.larsalvault", "demo-pass-7", "browser");
    let view = vs.view().unwrap();
    let names: Vec<&str> = view.browsers.iter().map(|b| b.name.as_str()).collect();
    assert!(
        names.contains(&"Firefox on MacBook") && names.contains(&"Safari"),
        "{names:?}"
    );
    assert_eq!(view.site_access, 4);
    // INT-02.8: Disconnect of one row removes that association only.
    assert!(vs.disconnect("Safari".into()).unwrap());
    let left: Vec<String> = vs
        .view()
        .unwrap()
        .browsers
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(left, vec!["Firefox on MacBook".to_owned()]);
    assert!(!vs.disconnect("Safari".into()).unwrap());
    // `vault.act.forget_site_access`: four entries changed.
    assert_eq!(vs.forget_site_access().unwrap(), 4);
    assert_eq!(vs.view().unwrap().site_access, 0);
    // MOD-03.13 for every entry: Delete all history….
    assert!(vs.delete_all_history().unwrap() > 0);
    assert_eq!(vs.view().unwrap().history_versions, 0);
    assert_eq!(s.save_status(id).unwrap().changes, 3);
}
