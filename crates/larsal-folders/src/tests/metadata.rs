//! FIL-04-T01 to T04, T16 and FIL-06-T01, T18: the metadata files, the order of the
//! checks, and the words.

use super::common::*;
use super::fx;
use crate::error::{Error, Refused};
use crate::limits::{MAX_JSON_MEMBERS, MAX_JSON_SCALAR, MAX_METADATA, MAX_PASSWORD};
use crate::seam;
use crate::{Phase, Stores, Vault};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::secret::SecretString;
use std::fs;
use std::path::Path;

fn try_open(path: &Path, stores: &Stores, password: &str) -> (Result<Vault, Error>, u32) {
    let before = seam::kdf_calls();
    let got = Vault::unlock(path, &secret(password), stores, &mut |_, _| true);
    (got, seam::kdf_calls() - before)
}

fn folder_with(key: &str, config: &str) -> (std::path::PathBuf, Stores) {
    let top = fresh("meta");
    let path = top.join("folder");
    make_folder_with(&path, key, config);
    (path, Stores::open(&top.join("stores")).unwrap())
}

fn good_key() -> String {
    key_file(PASSWORD, &KeySettings::default())
}

fn good_config() -> String {
    jws(&ENC, &MAC, HEADER, CLAIMS)
}

/// FIL-04.1, FIL-04.3: a new folder's exact wire profile, and it opens again. That the
/// peer tool opens it is NOT proven here (FIL-04-T14, the peer run).
#[test]
fn fil04_t01_create_and_reopen_has_the_exact_wire_profile() {
    let top = fresh("create");
    let path = top.join("folder");
    let stores = Stores::open(&top.join("stores")).unwrap();
    let vault = Vault::create(&path, &secret(PASSWORD), &stores, &mut |_, _| true).unwrap();
    assert!(!vault.weak_kdf());
    let root = vault.root_dir().unwrap();
    let node = vault
        .create_file(&root, "hello.txt", &mut &b"hello"[..], 5, &mut |_, _| true)
        .unwrap();
    let mut got = Vec::new();
    vault.read_to(&node, &mut got, &mut |_, _| true).unwrap();
    assert_eq!(got, b"hello");
    vault.lock();

    let config = fs::read_to_string(path.join("vault.cryptomator")).unwrap();
    let mut parts = config.split('.');
    let head = base64::decode(Form::Url, parts.next().unwrap()).unwrap();
    let claims = base64::decode(Form::Url, parts.next().unwrap()).unwrap();
    let head = larsal_model::json::from_slice_unique(&head).unwrap();
    let claims = larsal_model::json::from_slice_unique(&claims).unwrap();
    assert_eq!(head.get("alg").unwrap().as_str(), Some("HS256"));
    assert_eq!(head.get("typ").unwrap().as_str(), Some("JWT"));
    assert_eq!(
        head.get("kid").unwrap().as_str(),
        Some("masterkeyfile:masterkey.cryptomator")
    );
    assert_eq!(claims.get("format").unwrap().as_u64(), Some(8));
    assert_eq!(claims.get("cipherCombo").unwrap().as_str(), Some("SIV_GCM"));
    assert_eq!(
        claims.get("shorteningThreshold").unwrap().as_u64(),
        Some(220)
    );
    assert!(claims.get("jti").unwrap().as_str().unwrap().len() == 36);

    let key = larsal_model::json::from_slice_unique(
        &fs::read(path.join("masterkey.cryptomator")).unwrap(),
    )
    .unwrap();
    assert_eq!(key.get("version").unwrap().as_u64(), Some(999));
    assert_eq!(key.get("scryptCostParam").unwrap().as_u64(), Some(1 << 18));
    assert_eq!(key.get("scryptBlockSize").unwrap().as_u64(), Some(8));
    let member =
        |n: &str| base64::decode(Form::Padded, key.get(n).unwrap().as_str().unwrap()).unwrap();
    assert_eq!(member("scryptSalt").len(), 32);
    assert_eq!(member("primaryMasterKey").len(), 40);
    assert_eq!(member("hmacMasterKey").len(), 40);
    assert_eq!(member("versionMac").len(), 32);

    // Nothing but the format's own objects: no wrapper, no marker, no container.
    let tree = raw_tree(&path);
    assert!(
        tree.keys().all(|p| p == "vault.cryptomator"
            || p == "masterkey.cryptomator"
            || p.starts_with("d/")),
        "{tree:?}"
    );
    let backups: Vec<_> = tree.keys().filter(|p| p.ends_with("/dirid.c9r")).collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::metadata(path.join(backups[0])).unwrap().len(), 68 + 28);

    let again = Vault::unlock(&path, &secret(PASSWORD), &stores, &mut |_, _| true).unwrap();
    assert!(!again.weak_kdf());
    let root = again.root_dir().unwrap();
    let row = again.lookup(&root, "hello.txt").unwrap().unwrap();
    let mut got = Vec::new();
    again
        .read_to(&row.node, &mut got, &mut |_, _| true)
        .unwrap();
    assert_eq!(got, b"hello");
    assert!(Vault::create(&path, &secret(PASSWORD), &stores, &mut |_, _| true).is_err());
    assert_eq!(
        Vault::unlock(&path, &secret("not the password"), &stores, &mut |_, _| {
            true
        })
        .err(),
        Some(Error::Open)
    );
}

/// FIL-06.13, C1-F3: the stores-apart check holds alone, where nothing else refuses: an
/// empty chosen place that is itself the stores, and a folder opened with its stores
/// inside it. Refused before any key work, and nothing is made.
#[test]
fn fil06_t13_stores_apart_refuses_on_its_own() {
    let top = fresh("apart");
    let place = top.join("place");
    let stores = Stores::open(&place).unwrap();
    assert!(
        fs::read_dir(&place).unwrap().next().is_none(),
        "a place not already used"
    );
    let before = seam::kdf_calls();
    assert_eq!(
        Vault::create(&place, &secret(PASSWORD), &stores, &mut |_, _| true).err(),
        Some(Error::Input)
    );
    assert!(
        fs::read_dir(&place).unwrap().next().is_none(),
        "nothing made"
    );
    let path = top.join("folder");
    make_folder(&path, PASSWORD);
    let inside = Stores::open(&path.join("stores")).unwrap();
    let (got, _) = try_open(&path, &inside, PASSWORD);
    assert_eq!(got.err(), Some(Error::Input));
    assert_eq!(seam::kdf_calls(), before, "no key work");
    assert!(
        !path.join("stores").join("recovery").exists(),
        "nothing made"
    );
}

/// FIL-06.13: a create the stores-apart check refuses removes the empty folder it made
/// itself, and nothing else: a folder that was there before stays.
#[test]
fn fil06_t13_a_create_refused_as_not_apart_removes_only_what_it_made() {
    let top = fresh("apart-made");
    let stores_path = top.join("stores");
    let stores = Stores::open(&stores_path).unwrap();
    let before = raw_tree(&stores_path);
    let made = stores_path.join("new");
    assert_eq!(
        Vault::create(&made, &secret(PASSWORD), &stores, &mut |_, _| true).err(),
        Some(Error::Input)
    );
    assert!(!made.exists(), "the folder it made is gone");
    assert_eq!(raw_tree(&stores_path), before, "nothing else changed");
    let was_there = stores_path.join("was-there");
    fs::create_dir(&was_there).unwrap();
    assert_eq!(
        Vault::create(&was_there, &secret(PASSWORD), &stores, &mut |_, _| true).err(),
        Some(Error::Input)
    );
    assert!(was_there.is_dir(), "a folder it did not make stays");
}

#[test]
fn fil04_t01_create_refuses_a_used_place_and_an_empty_password() {
    let top = fresh("create-no");
    let stores = Stores::open(&top.join("stores")).unwrap();
    let used = top.join("used");
    fs::create_dir(&used).unwrap();
    fs::write(used.join("sentinel"), b"stays").unwrap();
    assert_eq!(
        Vault::create(&used, &secret(PASSWORD), &stores, &mut |_, _| true).err(),
        Some(Error::Input)
    );
    assert_eq!(fs::read(used.join("sentinel")).unwrap(), b"stays");
    let free = top.join("free");
    assert_eq!(
        Vault::create(&free, &secret(""), &stores, &mut |_, _| true).err(),
        Some(Error::Input)
    );
    assert!(!free.exists());
    // Cancel before the key work: the folder this call made is gone again.
    let before = seam::kdf_calls();
    assert_eq!(
        Vault::create(&free, &secret(PASSWORD), &stores, &mut |_, _| false).err(),
        Some(Error::Cancelled)
    );
    assert_eq!(seam::kdf_calls(), before);
    assert!(!free.exists());
    // Stores inside the folder would sync: refused.
    let inside = top.join("inside");
    fs::create_dir(&inside).unwrap();
    let in_stores = Stores::open(&inside.join("stores")).unwrap();
    assert_eq!(
        Vault::create(&inside, &secret(PASSWORD), &in_stores, &mut |_, _| true).err(),
        Some(Error::Input)
    );
}

/// FIL-04.1: HS384 and HS512 read, each only under its own name.
#[test]
fn fil04_t02_read_takes_each_hmac_under_its_own_name() {
    for alg in ["HS256", "HS384", "HS512"] {
        let head = HEADER.replace("HS256", alg);
        let (path, stores) = folder_with(&good_key(), &jws(&ENC, &MAC, &head, CLAIMS));
        let (opened, kdf) = try_open(&path, &stores, PASSWORD);
        assert!(opened.is_ok(), "{alg}");
        assert_eq!(kdf, 1);
    }
    // A signature made by one algorithm under the name of another.
    let sig_512 = jws(&ENC, &MAC, &HEADER.replace("HS256", "HS512"), CLAIMS);
    let sig = sig_512.rsplit('.').next().unwrap();
    let good = good_config();
    let mut parts: Vec<&str> = good.split('.').collect();
    parts[2] = sig;
    let (path, stores) = folder_with(&good_key(), &parts.join("."));
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Open)
    );
}

/// FIL-04.2: each hostile header is the generic error, with no key derivation.
#[test]
fn fil04_t02_hostile_headers_stop_before_any_key_work() {
    let control = folder_with(&good_key(), &good_config());
    assert!(try_open(&control.0, &control.1, PASSWORD).0.is_ok());
    let hostile = [
        (
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWT","alg":"none"}"#,
            "none",
        ),
        (
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWT","alg":"RS256"}"#,
            "other alg",
        ),
        (
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWT"}"#,
            "no alg",
        ),
        (
            r#"{"kid":"masterkeyfile:../masterkey.cryptomator","typ":"JWT","alg":"HS256"}"#,
            "traversal",
        ),
        (
            r#"{"kid":"masterkeyfile:/etc/masterkey.cryptomator","typ":"JWT","alg":"HS256"}"#,
            "absolute",
        ),
        (
            r#"{"kid":"https://example.invalid/key","typ":"JWT","alg":"HS256"}"#,
            "url",
        ),
        (
            r#"{"kid":"file:///masterkey.cryptomator","typ":"JWT","alg":"HS256"}"#,
            "file uri",
        ),
        (
            r#"{"kid":"plugin:key","typ":"JWT","alg":"HS256"}"#,
            "plugin",
        ),
        (r#"{"typ":"JWT","alg":"HS256"}"#, "no kid"),
        (
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWT","alg":"HS256","crit":["x"]}"#,
            "crit",
        ),
        (
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWT","alg":"HS256","jku":"https://example.invalid"}"#,
            "jku",
        ),
        (
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWS","alg":"HS256"}"#,
            "typ",
        ),
        (
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","alg":"HS256","alg":"HS256"}"#,
            "duplicate",
        ),
    ];
    for (head, what) in hostile {
        let (path, stores) = folder_with(&good_key(), &jws(&ENC, &MAC, head, CLAIMS));
        let (got, kdf) = try_open(&path, &stores, PASSWORD);
        assert_eq!(got.err(), Some(Error::Open), "{what}");
        assert_eq!(kdf, 0, "{what}");
    }
    for bad in [
        "",
        "a.b",
        "a.b.c.d",
        "!!!.b.c",
        "e30.e30.e30=",
        "e30=.e30.e30",
    ] {
        let (path, stores) = folder_with(&good_key(), bad);
        let (got, kdf) = try_open(&path, &stores, PASSWORD);
        assert_eq!(got.err(), Some(Error::Open), "{bad}");
        assert_eq!(kdf, 0, "{bad}");
    }
}

/// FIL-04.2: a server's key is refused by name, with no network and no key derivation.
#[test]
fn fil04_t02_a_remote_key_is_refused_by_name_with_no_work() {
    let head =
        r#"{"kid":"hub+https://hub.example.invalid/api/vaults/x","typ":"JWT","alg":"HS256"}"#;
    let (path, stores) = folder_with(&good_key(), &jws(&ENC, &MAC, head, CLAIMS));
    let (got, kdf) = try_open(&path, &stores, PASSWORD);
    assert_eq!(got.err(), Some(Error::Profile(Refused::RemoteKey)));
    assert_eq!(kdf, 0);
}

/// FIL-04.2: changed signed bytes, or a wrong signature, fail after the keys are known,
/// the same way a wrong password does, and no session exists.
#[test]
fn fil04_t02_changed_signed_bytes_give_no_session() {
    let good = good_config();
    let mut parts: Vec<String> = good.split('.').map(str::to_owned).collect();
    parts[1] = base64::encode(Form::Url, CLAIMS.replace("220", "221").as_bytes());
    let (path, stores) = folder_with(&good_key(), &parts.join("."));
    let (got, kdf) = try_open(&path, &stores, PASSWORD);
    assert_eq!(got.err(), Some(Error::Open));
    assert_eq!(kdf, 1);
    let mut sig = good.clone();
    let flip = if sig.ends_with('A') { 'B' } else { 'A' };
    sig.pop();
    sig.push(flip);
    let (path, stores) = folder_with(&good_key(), &sig);
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Open)
    );
    // Signed by other keys: the same.
    let (path, stores) = folder_with(&good_key(), &jws(&[1; 32], &[2; 32], HEADER, CLAIMS));
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Open)
    );
    // No duplicates in the signed claims either.
    let twice = r#"{"format":8,"format":8,"shorteningThreshold":220,"cipherCombo":"SIV_GCM"}"#;
    let (path, stores) = folder_with(&good_key(), &jws(&ENC, &MAC, HEADER, twice));
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Open)
    );
    for threshold in [
        "0",
        "31",
        "256",
        "99999999999999999999",
        "\"220\"",
        "-1",
        "22.0",
    ] {
        let claims = CLAIMS.replace("220", threshold);
        let (path, stores) = folder_with(&good_key(), &jws(&ENC, &MAC, HEADER, &claims));
        assert_eq!(
            try_open(&path, &stores, PASSWORD).0.err(),
            Some(Error::Open),
            "{threshold}"
        );
    }
}

fn with_settings(s: &KeySettings) -> (std::path::PathBuf, Stores) {
    folder_with(&key_file(PASSWORD, s), &good_config())
}

/// FIL-04.3, LD-376: RFC-valid controls open; r = 1, N = 2^16 fits every ceiling and is
/// invalid, with no key derivation.
#[test]
fn fil04_t03_rfc_validity_apart_from_the_ceilings() {
    for (log_n, r) in [(15u8, 1u32), (1, 1), (4, 8), (10, 32)] {
        let (path, stores) = with_settings(&KeySettings {
            log_n,
            r,
            ..KeySettings::default()
        });
        let (got, kdf) = try_open(&path, &stores, PASSWORD);
        let vault = got.unwrap_or_else(|e| panic!("{log_n} {r}: {e}"));
        assert_eq!(kdf, 1);
        assert!(
            vault.weak_kdf(),
            "a low cost is known, after authentication"
        );
    }
    let member = |n: u64, r: u64| {
        let good = good_key();
        good.replace(
            "\"scryptCostParam\":16",
            &format!("\"scryptCostParam\":{n}"),
        )
        .replace("\"scryptBlockSize\":8", &format!("\"scryptBlockSize\":{r}"))
    };
    for (n, r, what) in [
        (1u64 << 16, 1u64, "r1 N2^16"),
        (1 << 17, 1, "r1 N2^17"),
        (1 << 21, 8, "over N*r"),
        ((1 << 23) + 1, 1, "not a power of two"),
        (3, 8, "not a power of two"),
        (1, 8, "N below 2"),
        (0, 8, "N zero"),
        (16, 0, "r zero"),
        (16, 33, "r over 32"),
        (1 << 63, 8, "overflow"),
        (1 << 18, 33, "r over 32, large N"),
    ] {
        let (path, stores) = folder_with(&member(n, r), &good_config());
        let (got, kdf) = try_open(&path, &stores, PASSWORD);
        assert_eq!(got.err(), Some(Error::Open), "{what}");
        assert_eq!(kdf, 0, "{what}");
    }
    // Past u64 is a parse failure, not a wrap.
    let huge = good_key().replace(
        "\"scryptCostParam\":16",
        "\"scryptCostParam\":18446744073709551616",
    );
    let (path, stores) = folder_with(&huge, &good_config());
    let (got, kdf) = try_open(&path, &stores, PASSWORD);
    assert_eq!((got.err(), kdf), (Some(Error::Open), 0));
}

/// FIL-04.3: salt and wrap lengths, before any key work; a changed wrap or version MAC
/// after it, with no session and no fallback.
#[test]
fn fil04_t03_corrupt_key_material_gives_no_session() {
    for (len, ok) in [(7usize, false), (8, true), (64, true), (65, false)] {
        let (path, stores) = with_settings(&KeySettings {
            salt: vec![9; len],
            ..KeySettings::default()
        });
        let (got, kdf) = try_open(&path, &stores, PASSWORD);
        assert_eq!(got.is_ok(), ok, "salt {len}");
        assert_eq!(kdf, u32::from(ok), "salt {len}");
    }
    let good = larsal_model::json::from_str(&good_key()).unwrap();
    let text = |n: &str| good.get(n).unwrap().as_str().unwrap().to_owned();
    for member in ["primaryMasterKey", "hmacMasterKey"] {
        let wrapped = base64::decode(Form::Padded, text(member)).unwrap();
        // A length no wrap has: no work.
        let short = base64::encode(Form::Padded, &wrapped[..39]);
        let (path, stores) =
            folder_with(&good_key().replace(&text(member), &short), &good_config());
        let (got, kdf) = try_open(&path, &stores, PASSWORD);
        assert_eq!((got.err(), kdf), (Some(Error::Open), 0), "{member} short");
        // A changed wrap: found by its own integrity check.
        let mut changed = wrapped.clone();
        changed[20] ^= 1;
        let changed = base64::encode(Form::Padded, &changed);
        let (path, stores) =
            folder_with(&good_key().replace(&text(member), &changed), &good_config());
        let (got, kdf) = try_open(&path, &stores, PASSWORD);
        assert_eq!((got.err(), kdf), (Some(Error::Open), 1), "{member} changed");
    }
    let mut mac_bytes = base64::decode(Form::Padded, text("versionMac")).unwrap();
    mac_bytes[0] ^= 1;
    let bad = base64::encode(Form::Padded, &mac_bytes);
    let (path, stores) = folder_with(
        &good_key().replace(&text("versionMac"), &bad),
        &good_config(),
    );
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Open)
    );
    // A base64 text with stray low bits is not the one text of those bytes.
    let salt = text("scryptSalt");
    let last = salt.trim_end_matches('=').chars().last().unwrap();
    let stray = if last == 'A' { 'B' } else { 'A' };
    let at = salt.trim_end_matches('=').len() - 1;
    let mut odd = salt.clone();
    odd.replace_range(at..=at, &stray.to_string());
    let (path, stores) = folder_with(&good_key().replace(&salt, &odd), &good_config());
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Open)
    );
}

/// FIL-04.4: composed and decomposed forms are one password; spaces, NUL and other forms
/// are not, and no other form is ever tried (one key derivation, no retry).
#[test]
fn fil04_t04_password_is_nfc_utf8_and_nothing_else() {
    let (path, stores) = folder_with(
        &key_file("caf\u{e9} \u{2713}", &KeySettings::default()),
        &good_config(),
    );
    assert!(try_open(&path, &stores, "caf\u{e9} \u{2713}").0.is_ok());
    assert!(try_open(&path, &stores, "cafe\u{301} \u{2713}").0.is_ok());
    for wrong in [
        "caf\u{e9} \u{2713} ",
        " caf\u{e9} \u{2713}",
        "CAF\u{c9} \u{2713}",
        "caf\u{e9}\0 \u{2713}",
        "caf\u{e9}\u{a0}\u{2713}",
    ] {
        let (got, kdf) = try_open(&path, &stores, wrong);
        assert_eq!(got.err(), Some(Error::Open), "{wrong:?}");
        assert_eq!(kdf, 1, "no other form is tried: {wrong:?}");
    }
    // A trailing NUL reaches the KDF as it is. It still opens: HMAC pads a short key with
    // zeros (RFC 2104), so in scrypt's PBKDF2 step (RFC 7914) the two are one key. That is
    // the primitive, for every tool of this format, and is disclosed (proposed-findings).
    assert!(try_open(&path, &stores, "caf\u{e9} \u{2713}\0").0.is_ok());
    let (path, stores) = folder_with(&key_file(" a\0b ", &KeySettings::default()), &good_config());
    assert!(try_open(&path, &stores, " a\0b ").0.is_ok());
    assert_eq!(try_open(&path, &stores, "a\0b").0.err(), Some(Error::Open));
    // Newer Unicode than the table passes through unchanged, and opens the same way.
    let newer = "demo \u{10FFFD} \u{E0001}";
    let (path, stores) = folder_with(&key_file(newer, &KeySettings::default()), &good_config());
    assert!(try_open(&path, &stores, newer).0.is_ok());
}

/// FIL-04.16, FIL-04.1: other profiles are refused by name, never as a success. A format
/// or cipher is believed only after the signature holds.
#[test]
fn fil04_t16_other_profiles_are_refused_by_name_after_authentication() {
    let claims = CLAIMS.replace("SIV_GCM", "SIV_CTRMAC");
    let (path, stores) = folder_with(&good_key(), &jws(&ENC, &MAC, HEADER, &claims));
    let (got, kdf) = try_open(&path, &stores, PASSWORD);
    assert_eq!(got.err(), Some(Error::Profile(Refused::SivCtrMac)));
    assert_eq!(kdf, 1, "a cipher name is believed only after the proof");
    let wrong = jws(&[1; 32], &[2; 32], HEADER, &claims);
    let (path, stores) = folder_with(&good_key(), &wrong);
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Open),
        "unsigned: no name"
    );
    let claims = CLAIMS.replace("SIV_GCM", "OTHER");
    let (path, stores) = folder_with(&good_key(), &jws(&ENC, &MAC, HEADER, &claims));
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Profile(Refused::OtherCipher))
    );
    let claims = CLAIMS.replace("\"format\":8", "\"format\":9");
    let (path, stores) = folder_with(&good_key(), &jws(&ENC, &MAC, HEADER, &claims));
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Profile(Refused::OtherFormat))
    );
    // An older folder: a key file, no configuration, proven by its own MAC.
    let old = KeySettings {
        version: 7,
        ..KeySettings::default()
    };
    let (path, stores) = folder_with(&key_file(PASSWORD, &old), &good_config());
    fs::remove_file(path.join("vault.cryptomator")).unwrap();
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Profile(Refused::PreFormat8))
    );
    assert_eq!(try_open(&path, &stores, "wrong").0.err(), Some(Error::Open));
    let (path, stores) = folder_with(&good_key(), &good_config());
    fs::remove_file(path.join("vault.cryptomator")).unwrap();
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Open)
    );
    // A version other than 999 beside a configuration.
    let (path, stores) = folder_with(&key_file(PASSWORD, &old), &good_config());
    assert_eq!(
        try_open(&path, &stores, PASSWORD).0.err(),
        Some(Error::Open)
    );
    // The other format's own file: no key work.
    let (path, stores) = folder_with(&good_key(), &good_config());
    fs::write(path.join("vault.uvf"), b"{}").unwrap();
    let (got, kdf) = try_open(&path, &stores, PASSWORD);
    assert_eq!((got.err(), kdf), (Some(Error::Profile(Refused::Uvf)), 0));
    // Each of these says the one profile sentence.
    for r in [
        Refused::SivCtrMac,
        Refused::OtherCipher,
        Refused::OtherFormat,
        Refused::PreFormat8,
        Refused::Uvf,
        Refused::RemoteKey,
    ] {
        assert_eq!(
            Error::Profile(r).to_string(),
            "This folder uses a format Larsal does not support yet."
        );
    }
}

/// FIL-06.1: every bound and the first thing past it, before any key work.
#[test]
fn fil06_t01_limits_stop_before_any_key_work() {
    // At the size limit, padded with white space: still read; one past: refused.
    let key = good_key();
    let at = format!("{key}{}", " ".repeat(MAX_METADATA - key.len()));
    let (path, stores) = folder_with(&at, &good_config());
    assert!(try_open(&path, &stores, PASSWORD).0.is_ok());
    let past = format!("{at} ");
    let (path, stores) = folder_with(&past, &good_config());
    assert_eq!(
        try_open(&path, &stores, PASSWORD),
        (Err(Error::Open), 0).into_compare()
    );
    let long_config = format!("{}{}", good_config(), "A".repeat(MAX_METADATA));
    let (path, stores) = folder_with(&key, &long_config);
    assert_eq!(
        try_open(&path, &stores, PASSWORD),
        (Err(Error::Open), 0).into_compare()
    );

    // Depth.
    let nest = |n: usize| format!("{}1{}", "[".repeat(n), "]".repeat(n));
    let with_member = |extra: &str| key.replacen('{', &format!("{{\"extra\":{extra},"), 1);
    let (path, stores) = folder_with(&with_member(&nest(15)), &good_config());
    assert!(
        try_open(&path, &stores, PASSWORD).0.is_ok(),
        "depth 16 with the object"
    );
    let (path, stores) = folder_with(&with_member(&nest(16)), &good_config());
    assert_eq!(
        try_open(&path, &stores, PASSWORD),
        (Err(Error::Open), 0).into_compare()
    );

    // Members: the key file has 7 of its own.
    let extra = |n: usize| {
        let members: String = (0..n).map(|i| format!("\"x{i}\":1,")).collect();
        key.replacen('{', &format!("{{{members}"), 1)
    };
    let (path, stores) = folder_with(&extra(MAX_JSON_MEMBERS - 7), &good_config());
    assert!(try_open(&path, &stores, PASSWORD).0.is_ok());
    let (path, stores) = folder_with(&extra(MAX_JSON_MEMBERS - 6), &good_config());
    assert_eq!(
        try_open(&path, &stores, PASSWORD),
        (Err(Error::Open), 0).into_compare()
    );

    // A string.
    let s = |n: usize| with_member(&format!("\"{}\"", "s".repeat(n)));
    let (path, stores) = folder_with(&s(MAX_JSON_SCALAR), &good_config());
    assert!(try_open(&path, &stores, PASSWORD).0.is_ok());
    let (path, stores) = folder_with(&s(MAX_JSON_SCALAR + 1), &good_config());
    assert_eq!(
        try_open(&path, &stores, PASSWORD),
        (Err(Error::Open), 0).into_compare()
    );

    // A duplicate member of the key file.
    let twice = key.replacen('{', "{\"version\":999,", 1);
    let (path, stores) = folder_with(&twice, &good_config());
    assert_eq!(
        try_open(&path, &stores, PASSWORD),
        (Err(Error::Open), 0).into_compare()
    );
    // Each required member missing.
    for member in [
        "version",
        "scryptSalt",
        "scryptCostParam",
        "scryptBlockSize",
        "primaryMasterKey",
        "hmacMasterKey",
        "versionMac",
    ] {
        let gone = key.replacen(&format!("\"{member}\""), "\"other\"", 1);
        let (path, stores) = folder_with(&gone, &good_config());
        assert_eq!(
            try_open(&path, &stores, PASSWORD),
            (Err(Error::Open), 0).into_compare(),
            "{member}"
        );
    }

    // A password at the bound, one past it, and past it only after normalization.
    let (path, stores) = folder_with(&good_key(), &good_config());
    let (got, kdf) = try_open(&path, &stores, &"a".repeat(MAX_PASSWORD));
    assert_eq!((got.err(), kdf), (Some(Error::Open), 1));
    let (got, kdf) = try_open(&path, &stores, &"a".repeat(MAX_PASSWORD + 1));
    assert_eq!((got.err(), kdf), (Some(Error::Open), 0));
    // U+0958 grows from 3 bytes to 6 in NFC.
    let grows = "\u{958}".repeat(MAX_PASSWORD / 3);
    let (got, kdf) = try_open(&path, &stores, &grows);
    assert_eq!((got.err(), kdf), (Some(Error::Open), 0));
}

trait IntoCompare {
    fn into_compare(self) -> CompareOpen;
}
impl IntoCompare for (Result<Vault, Error>, u32) {
    fn into_compare(self) -> CompareOpen {
        CompareOpen(self.0.err(), self.1)
    }
}
#[derive(Debug, PartialEq, Eq)]
struct CompareOpen(Option<Error>, u32);
impl PartialEq<CompareOpen> for (Result<Vault, Error>, u32) {
    fn eq(&self, other: &CompareOpen) -> bool {
        self.0.as_ref().err() == other.0.as_ref() && self.1 == other.1
    }
}

/// FIL-06.1, FIL-06.8: control before and after the key work; a cancel leaves no session.
#[test]
fn fil06_t01_control_is_asked_around_the_key_work() {
    let (path, stores) = folder_with(&good_key(), &good_config());
    let before = seam::kdf_calls();
    let got = Vault::unlock(&path, &secret(PASSWORD), &stores, &mut |p, _| {
        assert_eq!(p, Phase::Kdf);
        false
    });
    assert_eq!(got.err(), Some(Error::Cancelled));
    assert_eq!(seam::kdf_calls(), before, "cancelled before");
    let mut calls = 0;
    let got = Vault::unlock(&path, &secret(PASSWORD), &stores, &mut |_, _| {
        calls += 1;
        calls < 2
    });
    assert_eq!(got.err(), Some(Error::Cancelled));
    assert_eq!(seam::kdf_calls(), before + 1, "cancelled after");
}

/// FIL-06.18: the exact words of the inventory, each alone.
#[test]
fn fil06_t18_every_message_is_the_exact_text_and_holds_nothing_else() {
    let table = [
        (
            Error::Open,
            "This encrypted folder or file could not be opened. Check the password and try again.",
        ),
        (
            Error::Profile(Refused::Uvf),
            "This folder uses a format Larsal does not support yet.",
        ),
        (
            Error::Input,
            "Choose local files or a folder. Links and special files cannot be added.",
        ),
        (
            Error::Name,
            "Choose a name that can be used safely on this disk.",
        ),
        (
            Error::Exists,
            "An item already has this name. Keep both or choose a different name.",
        ),
        (Error::Busy, "A folder operation is already running."),
        (
            Error::Changed,
            "This item changed in storage. Larsal kept your version for review.",
        ),
        (
            Error::Conflict,
            "Both versions are kept. Choose how to keep them.",
        ),
        (
            Error::DeleteConflict,
            "Another version changed this item. Deletion is pending; the edited version is kept.",
        ),
        (
            Error::Recovery,
            "There is not enough room to keep recovery copies safely. Review recovery copies before changing this folder.",
        ),
        (
            Error::Space,
            "There is not enough free space. Free some space or choose another disk.",
        ),
        (
            Error::Io,
            "The files could not be read or saved. Check access and try again.",
        ),
        (
            Error::Uncertain,
            "Larsal could not confirm that this change was saved safely. Keep the source and review the recovery copies.",
        ),
        (
            Error::Locked,
            "This encrypted folder is locked. Unlock it to see its files.",
        ),
        // Proposed, E23-S3, until the card has them.
        (
            Error::Budget,
            "This folder has reached the safe limit for new encrypted data on this Mac. Your files can still be read.",
        ),
        (Error::Cancelled, "Cancelled. Nothing was changed."),
        (
            Error::Inside,
            "A folder cannot be moved into itself or into a folder inside it.",
        ),
    ];
    for (error, text) in table {
        assert_eq!(error.to_string(), text);
        assert!(!format!("{error:?}").contains(PASSWORD));
    }
}

/// FIL-06.18: a secret never reaches a session's text forms.
#[test]
fn fil06_t18_debug_forms_show_no_secret() {
    let fx = fx("debug");
    let root = fx.root();
    let node = fx.write(&root, "DEMOSECRETNAME.txt", b"DEMOSECRETBODY");
    let row = fx.find(&root, "DEMOSECRETNAME.txt");
    for text in [
        format!("{:?}", fx.vault),
        format!("{node:?}"),
        format!("{row:?}"),
    ] {
        assert!(!text.contains("DEMOSECRET"), "{text}");
        assert!(
            !text.contains(&hex(&ENC)) && !text.contains(&hex(&MAC)),
            "{text}"
        );
    }
    let _ = SecretString::new(String::new());
}
