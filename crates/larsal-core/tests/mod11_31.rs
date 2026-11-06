//! Story E15-S2, MOD-11.31 (LD-267 (2), LD-269 (2), (3)): the retired-key
//! record and a copy under a key this Mac retired, on demo vault files
//! saved and opened here (password `demo`, then `demo2`).

mod common;

use common::at;
use larsal_core::merge::{Kind, Options, merge};
use larsal_core::retired::{Record, is_retired, password_alone, replaced_by_merge};
use larsal_crypto::cipher::Cipher;
use larsal_crypto::kdf::{Host, KdfParams, SpeedRecord, Verdict};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_format::header::AES256_ID;
use larsal_format::keys::{
    Credentials, SlotMode, SoftwareKey, cipher_key_v3, composite_key, final_keys, hardware_part,
    password_part,
};
use larsal_format::limits::Limits;
use larsal_format::payload::{Open, open_payload};
use larsal_format::{Opened, OpenedVault, Saved, SavedFile};
use larsal_model::{CustomDataItem, DeletedObject, Entry, Field, Group, Kdf, Time, Uuid, Vault};

fn uid(b: u8) -> Uuid {
    Uuid([b; 16])
}

fn t0() -> Time {
    at(2026, 1, 1, 0, 0, 0)
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

fn entry(b: u8, title: &str, pw: &str, m: Time) -> Entry {
    let mut e = Entry::new(uid(b), m);
    for (name, value) in [("Title", title), ("Password", pw)] {
        e.set_field(
            name.into(),
            Field {
                value: SecretString::new(value.into()),
                protected: name == "Password",
            },
        );
    }
    e
}

/// A: root(01) → G1(02) → Mail(0A), Bank(0B), name `Demo`.
fn demo_vault() -> Vault {
    let mut g = Group::new(uid(0x02), "G1".into(), t0());
    g.entries = vec![
        entry(0x0a, "Mail", "m", t0()),
        entry(0x0b, "Bank", "b", t0()),
    ];
    let mut root = Group::new(uid(0x01), "Root".into(), t0());
    root.groups.push(g);
    let mut v = Vault::new(root, t0());
    v.meta.recycle_bin_enabled = false;
    v.meta.name = "Demo".into();
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    v
}

fn save(v: &Vault, pw: &str) -> SavedFile {
    let p = SecretString::new(pw.into());
    let c = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    let Saved::File(f) =
        larsal_format::save(v, &c, None, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    *f
}

fn open(bytes: &[u8], pw: &str) -> Result<OpenedVault, larsal_format::Error> {
    let p = SecretString::new(pw.into());
    let c = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    match larsal_format::open(bytes, &c, &mut host(), &Limits::DEFAULT, None)? {
        Opened::Vault(o) => Ok(*o),
        Opened::Ask(_) => panic!("no ask"),
    }
}

fn retired(records: &[Record], pw: &str) -> bool {
    let p = SecretString::new(pw.into());
    let c = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    is_retired(records, &c, &mut host(), &Limits::DEFAULT).unwrap()
}

fn seed(k: &KdfParams) -> &[u8] {
    match k {
        KdfParams::AesKdf { seed, .. } => seed,
        KdfParams::Argon2 { salt, .. } => salt,
    }
}

fn has_entry(v: &Vault, b: u8) -> bool {
    v.root.all_entries().any(|e| e.uuid == uid(b))
}

/// T62 (MOD-11.31, LD-267 (2), LD-269 (2), (3)): this Mac changed A's key
/// from `demo` to `demo2` and kept a record of `demo`. B is a copy under
/// `demo`, saved again (a fresh seed), with a new entry, a newer Bank, a
/// deletion of Mail, a new name, custom data and a key time in 2099.
#[test]
fn mod11_31_t62_a_copy_under_a_retired_key_gets_the_content_merge_only() {
    let first = save(&demo_vault(), "demo");
    let opened = open(&first.bytes, "demo").unwrap();
    let record = Record::new(&opened.key).unwrap();
    // The credential change (MOD-12.10 step 8), then the save under demo2.
    let mut a = opened.vault.duplicate();
    let changed = at(2026, 2, 1, 0, 0, 0);
    larsal_core::settings::key_changed(&mut a.meta, changed);
    let mine = save(&a, "demo2");
    let mine = open(&mine.bytes, "demo2").unwrap();
    // A record of another key, as after a second credential change.
    let other = Record::new(&mine.key).unwrap();
    let a = mine.vault;
    // B, a copy of the first file, edited and saved again under demo.
    let mut b = open(&first.bytes, "demo").unwrap().vault;
    let t3 = at(2026, 4, 1, 0, 0, 0);
    b.root.groups[0].entries.retain(|e| e.uuid != uid(0x0a));
    b.root.groups[0].entries[0] = entry(0x0b, "Bank", "evil", t3);
    b.root.groups[0].entries.push(entry(0x0e, "N", "n", t3));
    b.deleted_objects.push(DeletedObject {
        uuid: uid(0x0a),
        deleted_at: t3,
        unknown: Vec::new(),
    });
    b.meta.name = "Evil".into();
    b.meta.name_changed = t3;
    b.meta.master_key_changed = at(2099, 1, 1, 0, 0, 0);
    b.meta.custom_data.items.push(CustomDataItem {
        key: "X".into(),
        value: larsal_crypto::secret::SecretString::new("1".into()),
        last_modified: Some(t3),
        unknown: Vec::new(),
    });
    let copy = save(&b, "demo");
    let copy = open(&copy.bytes, "demo").unwrap();
    assert_ne!(
        seed(copy.key.kdf()),
        seed(&record.kdf),
        "a fresh seed (FMT-04.17)"
    );
    // The credentials given for B match the record; demo2 and others do not.
    assert!(retired(std::slice::from_ref(&record), "demo"));
    assert!(!retired(std::slice::from_ref(&record), "demo2"));
    assert!(!retired(std::slice::from_ref(&record), "Demo"));
    assert!(!retired(&[], "demo"));
    // Any record matches, not only the first (LD-267 (2)).
    assert!(!retired(std::slice::from_ref(&other), "demo"));
    assert!(retired(&[other, record], "demo"));
    // Skip: nothing merged. Merge anyway: the content merge into this
    // Mac's vault, also for the change-on-disk flow.
    let o = Options {
        retired: true,
        ..Options::new(Kind::ChangeOnDisk)
    };
    let mut result = a.duplicate();
    let m = merge(&mut result, &copy.vault, &o, at(2026, 9, 9, 9, 9, 9)).unwrap();
    assert!(has_entry(&result, 0x0e), "N added");
    let bank = result
        .root
        .all_entries()
        .find(|e| e.uuid == uid(0x0b))
        .unwrap();
    assert_eq!(bank.value("Password"), "evil", "newer content");
    assert!(has_entry(&result, 0x0a), "Mail stays: no deletions");
    assert_eq!(result.deleted_objects, a.deleted_objects);
    assert_eq!(result.meta.name, "Demo");
    assert_eq!(result.meta.master_key_changed, changed);
    assert!(result.meta.custom_data.get("X").is_none(), "no custom data");
    assert!(!m.key_taken && !replaced_by_merge(&o, &m, true));
    // Saved with this Mac's own key, the result opens with demo2 only.
    let out = save(&result, "demo2");
    assert!(open(&out.bytes, "demo2").is_ok());
    assert_eq!(
        open(&out.bytes, "demo").unwrap_err(),
        larsal_format::Error::WrongKey
    );
}

/// LD-269 (2): the record holds no key or password bytes and equals
/// neither `K_enc` nor `K_mac`; each record has its own salt; its `Debug`
/// output shows nothing.
#[test]
fn mod11_31_the_record_holds_no_key_or_password_bytes() {
    let file = save(&demo_vault(), "demo");
    let opened = open(&file.bytes, "demo").unwrap();
    let r = Record::new(&opened.key).unwrap();
    let again = Record::new(&opened.key).unwrap();
    assert_ne!(r.salt, again.salt, "a fresh salt each time");
    assert_ne!(r.digest, again.digest);
    assert!(retired(&[again], "demo") && retired(std::slice::from_ref(&r), "demo"));
    assert_eq!(r.kdf, opened.header.kdf);
    assert!(r.v4);
    // The key flow of the file, worked out here (FMT-04).
    let password = SecretString::new("demo".into());
    let p = password_part(&password);
    let c = composite_key(Some(&p), None, None);
    let mut h = host();
    let Verdict::Run(cleared) =
        larsal_crypto::kdf::assess(&opened.header.kdf, &mut h, &Limits::DEFAULT.kdf, None).unwrap()
    else {
        panic!("no ask")
    };
    let t = larsal_crypto::kdf::derive(&c, &cleared).unwrap();
    let k = final_keys(&opened.header.master_seed, &t);
    let secrets: [&[u8]; 6] = [
        b"demo",
        p.expose(),
        c.expose(),
        t.expose(),
        k.cipher_key.expose(),
        k.hmac_key.expose(),
    ];
    assert_ne!(&r.digest[..], k.cipher_key.expose(), "not K_enc");
    assert_ne!(
        &r.digest[..],
        k.hmac_key.expose().get(..32).unwrap(),
        "not K_mac"
    );
    assert_ne!(
        &r.salt[..],
        &opened.header.master_seed[..],
        "not the seed S"
    );
    let mut held = r.salt.to_vec();
    held.extend(r.digest);
    held.extend(seed(&r.kdf));
    for s in secrets {
        let window = s.len().min(4);
        for part in s.windows(window) {
            assert!(
                !held.windows(window).any(|w| w == part),
                "a key or password byte run is in the record"
            );
        }
    }
    assert_eq!(format!("{r:?}"), "Record([hidden])");
}

/// T55 (d), last part (LD-264, LD-267 (2), AT-A09): this Mac retired
/// `demo2`; the server copy under `demo2` has a key time in 2099. It is
/// found by its record before any merge, and Merge anyway keeps this Mac's
/// key and key time: the result opens with `demo` only.
#[test]
fn at_a09_t55_d_a_retired_key_never_comes_back() {
    let mut old = demo_vault();
    old.meta.master_key_changed = at(2026, 3, 1, 0, 0, 0);
    let under_demo2 = save(&old, "demo2");
    let record = Record::new(&open(&under_demo2.bytes, "demo2").unwrap().key).unwrap();
    let a = open(&save(&demo_vault(), "demo").bytes, "demo")
        .unwrap()
        .vault;
    let mut b = open(&under_demo2.bytes, "demo2").unwrap().vault;
    b.meta.master_key_changed = at(2099, 1, 1, 0, 0, 0);
    let b = open(&save(&b, "demo2").bytes, "demo2").unwrap().vault;
    assert!(retired(std::slice::from_ref(&record), "demo2"));
    for kind in [Kind::ServerSync, Kind::ConflictCopy] {
        let o = Options {
            retired: true,
            ..Options::new(kind)
        };
        let mut result = a.duplicate();
        let m = merge(&mut result, &b, &o, at(2026, 9, 9, 9, 9, 9)).unwrap();
        assert!(!m.key_taken, "{kind:?}");
        assert_eq!(result.meta.master_key_changed, a.meta.master_key_changed);
        let out = save(&result, "demo");
        assert!(open(&out.bytes, "demo").is_ok());
        assert!(open(&out.bytes, "demo2").is_err());
    }
}

/// MOD-11.31 (LD-269 (2), LD-283 (1)): a record of a vault keyed by a
/// password plus a hardware key matches both parts, and not the password
/// alone. The record keeps the file's v4 key flow for the hardware part.
#[test]
fn mod11_31_a_record_with_a_hardware_key_part_matches_both_parts_only() {
    let p = SecretString::new("demo".into());
    let slot = SoftwareKey {
        secret: SecretBytes::new(vec![9; 20]),
        mode: SlotMode::Fixed,
    };
    let both = Credentials {
        password: Some(&p),
        hardware_key: Some(&slot),
        ..Default::default()
    };
    let password_only = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    let Saved::File(f) = larsal_format::save(
        &demo_vault(),
        &both,
        None,
        &mut host(),
        &Limits::DEFAULT,
        None,
    )
    .unwrap() else {
        panic!("no ask")
    };
    let Opened::Vault(o) =
        larsal_format::open(&f.bytes, &both, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    let record = Record::new(&o.key).unwrap();
    let records = [record];
    assert!(is_retired(&records, &both, &mut host(), &Limits::DEFAULT).unwrap());
    assert!(!is_retired(&records, &password_only, &mut host(), &Limits::DEFAULT).unwrap());
    // LD-288 (2): the credential change's record of a version 4 key of a
    // password plus a hardware key holds the password-alone digest too.
    let alone = password_alone(&o.key, &both, &mut host(), &Limits::DEFAULT).unwrap();
    let records = [Record::with(&o.key, alone.as_ref()).unwrap()];
    assert!(records[0].alone.is_some(), "version 4: the second digest");
    assert!(is_retired(&records, &both, &mut host(), &Limits::DEFAULT).unwrap());
    assert!(is_retired(&records, &password_only, &mut host(), &Limits::DEFAULT).unwrap());
}

/// A version 3.1 demo file (FMT-17) of a vault with no entries, keyed by
/// `p` plus `key`: AES-256-CBC, no compression, AES-KDF with one round.
/// The hardware part goes into the final key, never into `T` (FMT-04.15).
fn v3_file(p: &SecretString, key: &SoftwareKey) -> Vec<u8> {
    // The document: the XML of a version 4 save. No entries, so no
    // protected values for the field stream.
    let mut empty = demo_vault();
    empty.root.groups.clear();
    let x = SecretString::new("x".into());
    let c = Credentials {
        password: Some(&x),
        ..Default::default()
    };
    let Saved::File(f) =
        larsal_format::save(&empty, &c, None, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    let Open::Opened(payload) =
        open_payload(&f.bytes, &c, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    let xml = payload.xml.bytes();
    let (seed, transform_seed, iv, start) = ([0x31; 32], [0x35; 32], [0x37; 16], [0x39; 32]);
    // The header: signature, minor 1, major 3, fields 2 to 10, then 0.
    let mut file = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 0, 3, 0];
    let fields: [(u8, &[u8]); 10] = [
        (2, &AES256_ID),
        (3, &0u32.to_le_bytes()),
        (4, &seed),
        (5, &transform_seed),
        (6, &1u64.to_le_bytes()),
        (7, &iv),
        (8, &[0x38; 32]),
        (9, &start),
        (10, &2u32.to_le_bytes()),
        (0, &[0x0D, 0x0A, 0x0D, 0x0A]),
    ];
    for (id, data) in fields {
        file.push(id);
        file.extend(u16::try_from(data.len()).unwrap().to_le_bytes());
        file.extend_from_slice(data);
    }
    // T from the password part alone, K = SHA-256(S || R || T).
    let kdf = KdfParams::AesKdf {
        rounds: 1,
        seed: transform_seed.to_vec(),
    };
    let Verdict::Run(cleared) =
        larsal_crypto::kdf::assess(&kdf, &mut host(), &Limits::DEFAULT.kdf, None).unwrap()
    else {
        panic!("no ask")
    };
    let pp = password_part(p);
    let t = larsal_crypto::kdf::derive(&composite_key(Some(&pp), None, None), &cleared).unwrap();
    let r = hardware_part(key, &seed).unwrap();
    let k = cipher_key_v3(&seed, Some(&r), &t);
    // The start bytes, one hashed block, the end block (FMT-07.7).
    let mut plain = start.to_vec();
    plain.extend(0u32.to_le_bytes());
    plain.extend_from_slice(larsal_crypto::hash::sha256(&[xml]).expose());
    plain.extend(u32::try_from(xml.len()).unwrap().to_le_bytes());
    plain.extend_from_slice(xml);
    plain.extend(1u32.to_le_bytes());
    plain.extend([0; 36]);
    file.extend(larsal_crypto::cipher::encrypt(Cipher::Aes256Cbc, &k, &iv, &plain).unwrap());
    file
}

/// MOD-11.31 (LD-269 (2), LD-287 (4)): a record of a version 3 file keyed
/// by a password plus a hardware key matches those credentials. Version 3
/// keeps the hardware part out of `T` (FMT-04.15), so the record keeps the
/// file's version 3 key flow (`v4` false).
#[test]
fn mod11_31_a_record_of_a_version_3_file_with_a_hardware_key_matches() {
    let p = SecretString::new("demo".into());
    let slot = SoftwareKey {
        secret: SecretBytes::new(vec![9; 20]),
        mode: SlotMode::Fixed,
    };
    let both = Credentials {
        password: Some(&p),
        hardware_key: Some(&slot),
        ..Default::default()
    };
    let file = v3_file(&p, &slot);
    let Opened::Vault(o) =
        larsal_format::open(&file, &both, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    assert_eq!(o.vault.read_version.map(|v| v.major), Some(3));
    let records = [Record::new(&o.key).unwrap()];
    assert!(is_retired(&records, &both, &mut host(), &Limits::DEFAULT).unwrap());
    let other = SecretString::new("demo2".into());
    let wrong = Credentials {
        password: Some(&other),
        hardware_key: Some(&slot),
        ..Default::default()
    };
    assert!(!is_retired(&records, &wrong, &mut host(), &Limits::DEFAULT).unwrap());
    assert!(!records[0].v4, "version 3: no hardware part in T");
}

/// T74, the E15-S4 part (LD-288 (2), LD-291 (1); FMT-04.15): the
/// credential change's record of that version 3 file has one digest (its
/// `T` already is the password-alone key, so no second KDF run), and
/// `demo` alone matches it too: the safe side.
#[test]
fn mod11_31_t74_a_version_3_record_also_matches_the_password_alone() {
    let p = SecretString::new("demo".into());
    let slot = SoftwareKey {
        secret: SecretBytes::new(vec![9; 20]),
        mode: SlotMode::Fixed,
    };
    let both = Credentials {
        password: Some(&p),
        hardware_key: Some(&slot),
        ..Default::default()
    };
    let file = v3_file(&p, &slot);
    let Opened::Vault(o) =
        larsal_format::open(&file, &both, &mut host(), &Limits::DEFAULT, None).unwrap()
    else {
        panic!("no ask")
    };
    let alone = password_alone(&o.key, &both, &mut host(), &Limits::DEFAULT).unwrap();
    assert!(
        alone.is_none(),
        "version 3, password and hardware key: one digest"
    );
    let records = [Record::with(&o.key, alone.as_ref()).unwrap()];
    assert!(records[0].alone.is_none());
    let password_only = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    assert!(is_retired(&records, &both, &mut host(), &Limits::DEFAULT).unwrap());
    assert!(is_retired(&records, &password_only, &mut host(), &Limits::DEFAULT).unwrap());
}

fn with<'a>(
    p: Option<&'a SecretString>,
    f: Option<&'a larsal_format::keyfile::KeyFileKey>,
) -> Credentials<'a> {
    Credentials {
        password: p,
        key_file: f,
        ..Default::default()
    }
}

fn key_file(byte: u8) -> larsal_format::keyfile::KeyFileKey {
    larsal_format::keyfile::read_key_file(std::io::Cursor::new([byte; 32]), &Limits::DEFAULT)
        .unwrap()
}

/// T75 (MOD-11.31, LD-288 (2), LD-291 (1)): this Mac changed A's key from
/// `demo` plus key file K to `demo2`. The record of `demo` plus K has two
/// digests with one salt and matches `demo` alone and `demo` plus K, never
/// K alone, `demo` plus K2 or `demo-x` plus K; a record of K alone has one
/// digest. Neither digest equals `K_enc` or `K_mac` of any file, and no
/// record holds key or password bytes. B, a copy under `demo` alone with a
/// deletion of Mail and a key time in 2099, is found before any merge; its
/// content merge keeps Mail, A's key time and A's key.
#[test]
fn mod11_31_t75_a_retired_key_with_a_password_plus_a_key_file() {
    let (demo, demo_x) = (
        SecretString::new("demo".into()),
        SecretString::new("demo-x".into()),
    );
    let (k, k2) = (key_file(5), key_file(6));
    let both = with(Some(&demo), Some(&k));
    let save_with = |v: &Vault, c: &Credentials<'_>| {
        let Saved::File(f) =
            larsal_format::save(v, c, None, &mut host(), &Limits::DEFAULT, None).unwrap()
        else {
            panic!("no ask")
        };
        f
    };
    let open_with = |bytes: &[u8], c: &Credentials<'_>| {
        let Opened::Vault(o) =
            larsal_format::open(bytes, c, &mut host(), &Limits::DEFAULT, None).unwrap()
        else {
            panic!("no ask")
        };
        o
    };
    let first = save_with(&demo_vault(), &both);
    let opened = open_with(&first.bytes, &both);
    // The credential change: the record of the key it replaces.
    let alone = password_alone(&opened.key, &both, &mut host(), &Limits::DEFAULT)
        .unwrap()
        .expect("a password plus a key file: the second digest");
    let record = Record::with(&opened.key, Some(&alone)).unwrap();
    let second = record.alone.expect("two digests");
    assert_ne!(second, record.digest);
    let only_k = with(None, Some(&k));
    let k_alone = save_with(&demo_vault(), &only_k);
    let k_opened = open_with(&k_alone.bytes, &only_k);
    assert!(
        password_alone(&k_opened.key, &only_k, &mut host(), &Limits::DEFAULT)
            .unwrap()
            .is_none(),
        "no password: no second KDF run"
    );
    let k_record = Record::with(&k_opened.key, None).unwrap();
    assert!(k_record.alone.is_none(), "one part, one digest");
    let matches = |r: &Record, c: &Credentials<'_>| {
        is_retired(std::slice::from_ref(r), c, &mut host(), &Limits::DEFAULT).unwrap()
    };
    assert!(matches(&record, &with(Some(&demo), None)), "demo alone");
    assert!(matches(&record, &both), "demo plus K");
    assert!(!matches(&record, &only_k), "K alone");
    assert!(
        !matches(&record, &with(Some(&demo), Some(&k2))),
        "demo plus K2"
    );
    assert!(
        !matches(&record, &with(Some(&demo_x), Some(&k))),
        "demo-x plus K"
    );
    assert!(matches(&k_record, &only_k) && !matches(&k_record, &both));
    // No digest equals K_enc or K_mac of the files, or holds key bytes.
    for (file, c, r) in [(&first, &both, &record), (&k_alone, &only_k, &k_record)] {
        let o = open_with(&file.bytes, c);
        let mut h = host();
        let Verdict::Run(cleared) =
            larsal_crypto::kdf::assess(&o.header.kdf, &mut h, &Limits::DEFAULT.kdf, None).unwrap()
        else {
            panic!("no ask")
        };
        let pp = c.password.map(password_part);
        let comp = composite_key(pp.as_ref(), c.key_file.map(|f| f.key()), None);
        let t = larsal_crypto::kdf::derive(&comp, &cleared).unwrap();
        let keys = final_keys(&o.header.master_seed, &t);
        for d in std::iter::once(r.digest).chain(r.alone) {
            assert_ne!(&d[..], keys.cipher_key.expose(), "not K_enc");
            assert_ne!(&d[..], &keys.hmac_key.expose()[..32], "not K_mac");
            assert_ne!(&d[..], t.expose(), "not T");
            assert_ne!(&d[..], comp.expose());
        }
    }
    let mut held = record.salt.to_vec();
    held.extend(record.digest);
    held.extend(second);
    for s in [&b"demo"[..], k.key().expose()] {
        for part in s.windows(4) {
            assert!(
                !held.windows(4).any(|w| w == part),
                "a key or password byte run"
            );
        }
    }
    // A under demo2; B, a copy under demo alone, saved again (fresh seed).
    let mut a = opened.vault.duplicate();
    let changed = at(2026, 2, 1, 0, 0, 0);
    larsal_core::settings::key_changed(&mut a.meta, changed);
    let a = open(&save(&a, "demo2").bytes, "demo2").unwrap().vault;
    let mut b = opened.vault.duplicate();
    b.root.groups[0].entries.retain(|e| e.uuid != uid(0x0a));
    b.deleted_objects.push(DeletedObject {
        uuid: uid(0x0a),
        deleted_at: at(2026, 4, 1, 0, 0, 0),
        unknown: Vec::new(),
    });
    b.meta.master_key_changed = at(2099, 1, 1, 0, 0, 0);
    let b = open(&save(&b, "demo").bytes, "demo").unwrap().vault;
    assert!(
        retired(std::slice::from_ref(&record), "demo"),
        "found before any merge"
    );
    let o = Options {
        retired: true,
        ..Options::new(Kind::ChangeOnDisk)
    };
    let mut result = a.duplicate();
    let m = merge(&mut result, &b, &o, at(2026, 9, 9, 9, 9, 9)).unwrap();
    assert!(has_entry(&result, 0x0a), "Mail stays");
    assert!(!m.key_taken && result.meta.master_key_changed == changed);
    assert_eq!(result.deleted_objects, a.deleted_objects);
    assert!(open(&save(&result, "demo2").bytes, "demo2").is_ok());
}

/// LD-291 (3), MOD-11.30, FMT-15.11 step 2 (L15-3), F-173, LD-313 (1): A
/// deleted Mail for good at T1; a copy under a key this Mac retired still
/// holds Mail, edited at T2, and Merge anyway brings it back and drops A's
/// own item for it, so no bring-back state (FMT-15.5) is left. B, a cloud
/// conflict copy, deleted Mail at T3: the first conflict-copy merge erases
/// Mail by B's item, and a second merge of the same B records nothing
/// (MOD-11.30). Before the fix, A's stale item at T1 kept Mail in the first
/// merge (step 2 keeps the earliest time) and the second erased it.
#[test]
fn f173_mod11_30_a_brought_back_entry_and_a_conflict_copy_merge_twice_the_same() {
    let (t1, t2, t3) = (
        at(2026, 2, 1, 0, 0, 0),
        at(2026, 3, 1, 0, 0, 0),
        at(2026, 4, 1, 0, 0, 0),
    );
    let gone = |v: &mut Vault, t: Time| {
        v.root.groups[0].entries.retain(|e| e.uuid != uid(0x0a));
        v.deleted_objects.push(DeletedObject {
            uuid: uid(0x0a),
            deleted_at: t,
            unknown: Vec::new(),
        });
    };
    let mut a = demo_vault();
    gone(&mut a, t1);
    let mut old = demo_vault();
    old.root.groups[0].entries[0] = entry(0x0a, "Mail", "m2", t2);
    let anyway = Options {
        retired: true,
        ..Options::new(Kind::ConflictCopy)
    };
    merge(&mut a, &old, &anyway, t3).unwrap();
    assert!(
        has_entry(&a, 0x0a) && a.deleted_objects.is_empty(),
        "Mail back and this Mac's item dropped"
    );
    let mut b = demo_vault();
    gone(&mut b, t3);
    let copy = Options::new(Kind::ConflictCopy);
    let first = merge(&mut a, &b, &copy, t3).unwrap();
    let second = merge(&mut a, &b, &copy, t3).unwrap();
    assert!(
        second.changes.is_empty(),
        "first merge: Mail kept {}, {:?}; second merge: Mail kept {}, {:?}",
        !first
            .changes
            .iter()
            .any(|c| c.kind == larsal_core::merge::ChangeKind::Deleted),
        first.changes.iter().map(|c| c.kind).collect::<Vec<_>>(),
        has_entry(&a, 0x0a),
        second.changes.iter().map(|c| c.kind).collect::<Vec<_>>()
    );
}

/// T76, MOD-11.31, MOD-11.30 (F-173, LD-313 (1)): Merge anyway drops this
/// Mac's own deleted-objects item for each entry or group it brings back.
/// A deleted Mail(0A) at T1 and a group G2(03) at T1; B, same root id,
/// under a key this Mac retired, holds Mail Mod=T2 and G2; C, a conflict
/// copy of A under A's key, holds [id(0A) T3]. A's item for an object B
/// does not bring back (0C) stays.
#[test]
fn mod11_31_t76_merge_anyway_drops_this_macs_item_for_what_it_brings_back() {
    let (t1, t2, t3) = (
        at(2026, 2, 1, 0, 0, 0),
        at(2026, 3, 1, 0, 0, 0),
        at(2026, 4, 1, 0, 0, 0),
    );
    let item = |b: u8, t: Time| DeletedObject {
        uuid: uid(b),
        deleted_at: t,
        unknown: Vec::new(),
    };
    let mut a = demo_vault();
    a.root.groups[0].entries.retain(|e| e.uuid != uid(0x0a));
    a.deleted_objects = vec![item(0x0a, t1), item(0x03, t1), item(0x0c, t1)];
    let mut b = demo_vault();
    b.root.groups[0].entries[0] = entry(0x0a, "Mail", "m2", t2);
    b.root.groups.push(Group::new(uid(0x03), "G2".into(), t2));
    let anyway = Options {
        retired: true,
        ..Options::new(Kind::ConflictCopy)
    };
    let m = merge(&mut a, &b, &anyway, t3).unwrap();
    assert!(!m.key_taken);
    assert!(has_entry(&a, 0x0a), "Mail is back");
    assert!(a.root.find_group(uid(0x03)).is_some(), "G2 is back");
    assert_eq!(
        a.deleted_objects,
        vec![item(0x0c, t1)],
        "no item for 0A or 03"
    );
    let mut c = a.duplicate();
    c.root.groups[0].entries.retain(|e| e.uuid != uid(0x0a));
    c.deleted_objects = vec![item(0x0c, t1), item(0x0a, t3)];
    let copy = Options::new(Kind::ConflictCopy);
    let first = merge(&mut a, &c, &copy, t3).unwrap();
    assert!(!has_entry(&a, 0x0a), "Mail erased");
    assert!(a.deleted_objects.contains(&item(0x0a, t3)));
    assert!(
        first
            .changes
            .iter()
            .any(|x| x.kind == larsal_core::merge::ChangeKind::Deleted && x.id == Some(uid(0x0a))),
        "change Deleted: {:?}",
        first.changes.iter().map(|x| x.kind).collect::<Vec<_>>()
    );
    let second = merge(&mut a, &c, &copy, t3).unwrap();
    assert!(
        second.changes.is_empty(),
        "second merge: no change recorded"
    );
}

/// T77, MOD-11.31, MOD-11.30 (F-216, LD-315): A deleted the bin itself for good
/// at T1 (MOD-04.8: items for Old(0D) and the bin(0E)); B, under a key this
/// Mac retired, still holds the bin with Old. Merge anyway makes the bin
/// again with B's bin id (MOD-11.16) and drops A's item for it. C, a
/// conflict copy of A, then deletes the bin at T4: the first merge of C
/// erases the bin and Old, and a second merge of the same C records nothing.
#[test]
fn mod11_31_t77_merge_anyway_drops_this_macs_item_for_the_bin_it_makes() {
    let (t1, t3, t4) = (
        at(2026, 2, 1, 0, 0, 0),
        at(2026, 4, 1, 0, 0, 0),
        at(2026, 5, 1, 0, 0, 0),
    );
    let item = |b: u8, t: Time| DeletedObject {
        uuid: uid(b),
        deleted_at: t,
        unknown: Vec::new(),
    };
    let bin = uid(0x0e);
    let mut b = demo_vault();
    b.meta.recycle_bin_enabled = true;
    let mut g = Group::new(bin, "Recycle Bin".into(), t0());
    g.entries.push(entry(0x0d, "Old", "o", t0()));
    b.root.groups.push(g);
    b.meta.recycle_bin = Some(bin);
    let mut a = demo_vault();
    a.meta.recycle_bin_enabled = true;
    a.deleted_objects = vec![item(0x0d, t1), item(0x0e, t1)];
    let anyway = Options {
        retired: true,
        ..Options::new(Kind::ConflictCopy)
    };
    merge(&mut a, &b, &anyway, t3).unwrap();
    assert!(a.root.find_group(bin).is_some() && has_entry(&a, 0x0d));
    assert!(a.deleted_objects.is_empty(), "{:?}", a.deleted_objects);
    let mut c = a.duplicate();
    c.root.groups.retain(|g| g.uuid != bin);
    c.meta.recycle_bin = None;
    c.deleted_objects = vec![item(0x0d, t4), item(0x0e, t4)];
    let copy = Options::new(Kind::ConflictCopy);
    merge(&mut a, &c, &copy, t4).unwrap();
    assert!(a.root.find_group(bin).is_none() && !has_entry(&a, 0x0d));
    let second = merge(&mut a, &c, &copy, t4).unwrap();
    assert!(second.changes.is_empty(), "second merge: no change");
}
