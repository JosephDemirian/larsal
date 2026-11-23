//! E17-S1's account checks (SYN-06, CRY-05.8, CRY-05.10) against Larsal's
//! server in process with a release server's rule
//! (`larsal_server_strict`: every vault upload signed), through the test
//! proxy where a test reads or changes what passes, with device stores that
//! are maps (`Memory`, never a keychain, LD-317 (2)) and the test-seam
//! device key. The server's clock is fixed and moved a minute on before the
//! sign-in routes are used again (SYN-01.12 allows 10 a minute from one
//! address); no test sleeps or reads the wall clock for a result.
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#![allow(clippy::arithmetic_side_effects)]

use super::*;
use crate::state::{self, Link, Measures, State};
use crate::sync::{Local, Merge, Report, Status, Unproven, first_upload, run};
use crate::test_server::{
    LarsalServer, Memory, Request, Response, Scripted, TestClock, larsal_server_strict, scratch,
};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::kdf;
use larsal_model::{Argon2Kind, FileVersion, Kdf, Time, Uuid};
use larsal_platform::device_key::DeviceKey;
use larsal_proto::messages::DeviceId;
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// SYN-06 T01's account password.
const PASSWORD: &str = "demo-account-pw";
/// The demo vault of testdata (master password `demo-pass-1`, its one entry
/// "Demo login", `demo-user`, `demo-entry-pass-1`) and a second demo vault:
/// the bytes a Mac uploads. The server never opens them; the merge is the
/// stand-in below (the real merge is larsal-ffi's).
const VAULT: &[u8] = include_bytes!("../../../../testdata/password-only.larsalvault");
const VAULT2: &[u8] = include_bytes!("../../../../testdata/option-a-personal.larsalvault");

/// proof/independent_kv.log: RFC 9106 Argon2id on Python's hashlib.blake2b
/// (checked first on RFC 9106's vector), HKDF per RFC 5869 on Python's
/// hmac, Ed25519 per RFC 8032 section 5.1.5, for password `demo`, salt 32
/// bytes of 0x01, `S_acct` 32 bytes of 0x02, `account_id` 16 bytes of 0x03.
const KV_A: &str = "b5b571b61cc87d213b9abc2c69c31d2bd5867ad5a273d1e7658e5988c152457b";
const KV_K_WRAP: &str = "8b6010029fcc980d13724ef292cb837349560f329001e61caba7a12e549fbed6";
const KV_SEED_R: &str = "160a056f4f962c212cfe7392b362a9e82bddab5efde17ef98c6ea22eda981ee7";
const KV_RECOVERY: &str = "df793ccd48531a2f05c2851e139a35f8f33078fe44db8fa3ab89b7b6fd1adf00";

fn password() -> SecretString {
    SecretString::new(PASSWORD.to_owned())
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    crate::sync::hash(bytes)
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// A value in LD-426's forms: raw, upper hex, lower hex, padded base64 and
/// URL base64 (SYN-03 T24's method, larsal-ffi's T29).
fn encoded(value: &[u8]) -> Vec<Vec<u8>> {
    let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        value.to_vec(),
        hex.to_uppercase().into_bytes(),
        hex.into_bytes(),
        base64::encode(Form::Padded, value).into_bytes(),
        base64::encode(Form::Url, value).into_bytes(),
    ]
}

/// Every file under `dir`, with its bytes.
fn files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else {
                let bytes = std::fs::read(&p).unwrap();
                out.push((p, bytes));
            }
        }
    }
    out
}

fn measures() -> Measures {
    Measures {
        newest: Time(1_000),
        version: FileVersion { major: 4, minor: 1 },
        kdf: Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 2,
            memory_kib: 65_536,
            lanes: 2,
        },
    }
}

/// The open vault of a Mac: its file; a merge takes the server copy as it
/// is and saves it.
struct OpenVault {
    file: Mutex<Vec<u8>>,
    merges: AtomicUsize,
}

impl OpenVault {
    fn new(file: &[u8]) -> Self {
        Self {
            file: Mutex::new(file.to_vec()),
            merges: AtomicUsize::new(0),
        }
    }

    fn file(&self) -> Vec<u8> {
        self.file.lock().unwrap().clone()
    }

    fn merges(&self) -> usize {
        self.merges.load(Ordering::SeqCst)
    }
}

impl Local for OpenVault {
    fn read(&self) -> Option<Result<(Vec<u8>, Measures), Unproven>> {
        Some(Ok((self.file(), measures())))
    }

    fn merge(&self, server: &[u8], _version: u64) -> Merge {
        self.merges.fetch_add(1, Ordering::SeqCst);
        *self.file.lock().unwrap() = server.to_vec();
        Merge::Done {
            copy: measures(),
            result: measures(),
            changed: false,
            saved: server.to_vec(),
        }
    }
}

/// The open vault of a stopped account: never read, never merged.
struct Untouched;

impl Local for Untouched {
    fn read(&self) -> Option<Result<(Vec<u8>, Measures), Unproven>> {
        panic!("a stopped account read the vault")
    }

    fn merge(&self, _server: &[u8], _version: u64) -> Merge {
        panic!("a stopped account merged a download")
    }
}

/// A link of `c`'s server vault `vault`, at version `highest` with `bytes`
/// on both sides; version 0 for a vault this Mac links from the server.
fn link(c: &Server<DeviceKey>, vault: VaultId, highest: u64, bytes: &[u8]) -> Link {
    let sha = if highest == 0 { [0; 32] } else { sha(bytes) };
    Link {
        server: c.address().to_owned(),
        vault_id: vault,
        file: "demo.larsalvault".into(),
        root: Uuid([1; 16]),
        highest,
        server_sha: sha,
        local_sha: sha,
        seen: measures(),
    }
}

fn keys_changed() -> Report {
    Report {
        status: Some(Status::Error),
        messages: vec![Message::KeysChanged],
    }
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A client of the proxy `p` that signs for the server behind it
/// (SYN-04.4 binds a signature to the origin of `port`).
fn client_of(p: &Scripted, port: u16) -> Server<DeviceKey> {
    let mut c = Server::new(&p.address(), p.pin).unwrap();
    c.sign_for_port(port);
    c
}

/// One Mac of an account: its client and its device store.
struct Mac {
    c: Server<DeviceKey>,
    keep: Memory,
}

impl Mac {
    fn keys(&self) -> &AccountKeys {
        &self.c.account.as_ref().unwrap().1
    }
}

/// A strict server, the test proxy before it, and Mac A of a new account
/// (SYN-04.2) signed up with [`PASSWORD`] (SYN-06.1 to SYN-06.7).
struct Run {
    app: LarsalServer,
    proxy: Scripted,
    a: Mac,
    made: AccountCreated,
    kit: Kit,
    t0: u64,
    minute: Cell<u64>,
}

impl Run {
    /// One minute on, on the server's clock: a new window of SYN-01.12's
    /// sign-in limit. Sessions (15 minutes idle) and challenges (5
    /// minutes) are used within it.
    fn later(&self) {
        let m = self.minute.get() + 1;
        self.minute.set(m);
        self.app.seams.set_clock(self.t0 + 61 * m);
    }

    fn label(&self) -> String {
        format!("{} account {}", self.kit.address(), self.made.account_id)
    }
}

fn account_with(proxy_of: impl FnOnce(&LarsalServer) -> Scripted) -> Run {
    let app = larsal_server_strict();
    let t0 = now_seconds();
    app.seams.set_clock(t0);
    let proxy = proxy_of(&app);
    let mut c = client_of(&proxy, app.port);
    let made = c.sign_up(DeviceKey::test_seam().unwrap()).unwrap();
    let keep = Memory::default();
    let kit = c
        .sign_up_account(&made.account_id, &password(), &keep)
        .unwrap();
    Run {
        app,
        proxy,
        a: Mac { c, keep },
        made,
        kit,
        t0,
        minute: Cell::new(0),
    }
}

fn account() -> Run {
    account_with(Scripted::proxy)
}

/// Mac N: an empty demo app state (a new client, an empty device store)
/// restored with the kit and the password (SYN-06.12).
fn recovered(r: &Run) -> Mac {
    r.later();
    let mut c = Server::new(r.kit.address(), r.kit.pin()).unwrap();
    c.sign_for_port(r.app.port);
    c.recover(&r.kit, DeviceKey::test_seam().unwrap()).unwrap();
    let keep = Memory::default();
    c.restore(&r.kit, &password(), &keep).unwrap();
    Mac { c, keep }
}

/// SYN-06.1 to SYN-06.6, SYN-06 T01 and T19's sign-up half, CRY-05 T14
/// with the server: the keys PUT carries CRY-05.8's names with
/// `If-None-Match: *`; the server's keys hold a 1,984-byte identity key, a
/// 1,216-byte receiving key, a 3,373-byte binding over `sync-kem-key-v1`
/// that verifies, a 32-byte recovery key and a 158-byte blob of version 1,
/// which opens with `S_acct` and the password to 96 bytes whose seeds give
/// those public keys; nothing the server keeps equals `S_acct`, a seed, a
/// private key or the password, or their SHA-256.
#[test]
fn syn06_1_to_6_t01_t19_cry05_t14_sign_up_stores_four_public_values_and_a_blob() {
    let mut r = account();
    let account = r.made.account_id;
    assert_eq!(r.a.c.account_id(), Some(account));
    let puts: Vec<Request> = r
        .proxy
        .requests()
        .into_iter()
        .filter(|q| q.path == "/v1/account/keys")
        .collect();
    assert_eq!(puts.len(), 1, "one PUT, no GET after a 201");
    let put = &puts[0];
    assert_eq!(put.method, "PUT");
    assert_eq!(put.header("if-none-match"), Some("*"));
    assert_eq!(put.header("content-type"), Some("application/json"));
    let text = String::from_utf8(put.body.clone()).unwrap();
    for name in [
        "\"identity_public_key\"",
        "\"kem_public_key\"",
        "\"kem_signature\"",
        "\"recovery_public_key\"",
        "\"blob\"",
    ] {
        assert!(text.contains(name), "{name}");
    }
    assert_eq!(text.matches("\":").count(), 5, "five fields, no other");
    let sent = KeysRecord::read(&put.body).unwrap();

    let record = r.a.c.get_keys().unwrap();
    assert_eq!(record, sent, "stored as sent");
    assert_eq!(record.identity_public_key.len(), 1984);
    assert_eq!(record.kem_public_key.len(), 1216);
    assert_eq!(record.kem_signature.len(), 3373);
    assert_eq!(record.blob.len(), 158);
    assert_eq!(record.blob[..2], [0, 1], "version 1");
    check_kem_binding(
        &record.identity_public_key,
        account.as_bytes(),
        &record.kem_public_key,
        &record.kem_signature,
    )
    .unwrap();
    let keys = r.a.keys();
    assert_eq!(record.identity_public_key, keys.identity_public_key());
    assert_eq!(record.kem_public_key, keys.kem_public_key());
    assert_eq!(r.kit.secret.expose(), keys.account_secret().expose());

    let plaintext = open_blob(&record.blob, &account, &r.kit.secret, &password()).unwrap();
    assert_eq!(plaintext.len(), 96);
    let opened =
        AccountKeys::from_blob(SecretBytes::new(r.kit.secret.expose().to_vec()), &plaintext)
            .unwrap();
    assert_eq!(opened.identity_public_key(), record.identity_public_key);
    assert_eq!(opened.kem_public_key(), record.kem_public_key);
    let seed = recovery_seed(&account, &r.kit.secret).unwrap();
    assert_eq!(
        record.recovery_public_key,
        sign::ed25519_public(&seed).unwrap()
    );

    let secrets: Vec<(&str, Vec<u8>)> = vec![
        ("S_acct", keys.account_secret().expose().to_vec()),
        (
            "the identity private key",
            keys.identity_private_key().expose().to_vec(),
        ),
        (
            "the ML-DSA seed",
            keys.identity_private_key().expose()[..32].to_vec(),
        ),
        (
            "the Ed25519 seed",
            keys.identity_private_key().expose()[32..].to_vec(),
        ),
        ("the receiving seed", keys.kem_seed().expose().to_vec()),
        ("the recovery seed", seed.expose().to_vec()),
        ("the password", PASSWORD.as_bytes().to_vec()),
    ];
    let stored = files(&r.app._data.0);
    assert!(stored.len() >= 3, "{}", stored.len());
    for (path, bytes) in &stored {
        for (what, secret) in &secrets {
            assert!(!has(bytes, secret), "{what} in {}", path.display());
            assert!(
                !has(bytes, &sha(secret)),
                "{what}'s SHA-256 in {}",
                path.display()
            );
        }
    }
}

/// SYN-06.2, SYN-06 T16: a password of 7 characters (14 bytes) is refused
/// before anything is drawn, kept or sent; one of 8 is taken exactly as
/// typed: trimmed, cut or normalized forms do not open the blob.
#[test]
fn syn06_2_t16_seven_characters_refused_eight_taken_as_typed() {
    let app = larsal_server_strict();
    let proxy = Scripted::proxy(&app);
    let mut c = client_of(&proxy, app.port);
    let made = c.sign_up(DeviceKey::test_seam().unwrap()).unwrap();
    let keep = Memory::default();
    let seven = SecretString::new("ééééééé".to_owned());
    assert_eq!(seven.expose().len(), 14);
    assert_eq!(
        c.sign_up_account(&made.account_id, &seven, &keep)
            .unwrap_err(),
        AccountFail::ShortPassword
    );
    assert!(keep.0.lock().unwrap().is_empty(), "nothing drawn or kept");
    assert_eq!(c.account_id(), None);
    let keys_calls = |p: &Scripted| {
        p.requests()
            .iter()
            .filter(|q| q.path == "/v1/account/keys")
            .count()
    };
    assert_eq!(keys_calls(&proxy), 0, "nothing sent");

    let typed = " éééééé ";
    assert_eq!(typed.chars().count(), 8);
    let eight = SecretString::new(typed.to_owned());
    let kit = c.sign_up_account(&made.account_id, &eight, &keep).unwrap();
    assert_eq!(keys_calls(&proxy), 1);
    let record = c.get_keys().unwrap();
    let open = |pw: &str| {
        open_blob(
            &record.blob,
            &made.account_id,
            &kit.secret,
            &SecretString::new(pw.to_owned()),
        )
    };
    assert!(open(typed).is_ok());
    // Trimmed at either end, cut, or with each é decomposed (NFD).
    let decomposed = " e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301} ";
    for other in ["éééééé", " éééééé", "éééééé ", " ééééé ", decomposed] {
        assert_eq!(
            open(other).unwrap_err(),
            AccountFail::RestoreFailed,
            "{other:?}"
        );
    }
}

/// SYN-06.3, SYN-06 T03: `K_wrap` of password `demo`, salt 32 x 0x01,
/// `S_acct` 32 x 0x02 and `account_id` 16 x 0x03 equals the independent
/// computation, and the blob of those inputs is sealed under exactly that
/// key with SYN-06.4's associated data.
#[test]
fn syn06_3_t03_k_wrap_known_value() {
    let account = AccountId::from_bytes([3; 16]);
    let secret = SecretBytes::new(vec![2; 32]);
    let demo = SecretString::new("demo".to_owned());
    let a =
        kdf::import_argon2id(&SecretBytes::new(b"demo".to_vec()), &[1; 32], 3, 64, 4, 32).unwrap();
    assert_eq!(a.expose(), unhex(KV_A));
    let k = wrap::account_key(&demo, &[1; 32], &secret, account.as_bytes()).unwrap();
    assert_eq!(k.expose(), unhex(KV_K_WRAP));

    let plaintext = SecretBytes::new((0u8..96).collect());
    let keys = AccountKeys::from_blob(SecretBytes::new(vec![2; 32]), &plaintext).unwrap();
    let blob = make_blob_with(&keys, &account, &demo, &[1; 32]).unwrap();
    assert_eq!(blob.len(), BLOB_LEN);
    assert_eq!(blob[..2], [0, 1]);
    assert_eq!(blob[2..34], [1; 32]);
    let aad = sign::field_list(&[
        &b"sync-account-blob-v1"[..],
        &[3u8; 16][..],
        &[0u8, 1][..],
        &[1u8; 32][..],
    ])
    .unwrap();
    let known = SecretBytes::new(unhex(KV_K_WRAP));
    let opened = wrap::open(&known, &aad, &blob[34..]).unwrap();
    assert_eq!(opened.expose(), plaintext.expose());
    let read = open_blob(&blob, &account, &secret, &demo).unwrap();
    assert_eq!(read.expose(), plaintext.expose());
}

/// SYN-06.5, SYN-06 T17: the recovery seed and public key of T03's
/// `S_acct` and `account_id` equal the independent HKDF and Ed25519; after
/// a sign-up the server's stored recovery key is the one of the account's
/// `S_acct`.
#[test]
fn syn06_5_t17_recovery_key_known_value_and_the_stored_copy() {
    let seed = recovery_seed(
        &AccountId::from_bytes([3; 16]),
        &SecretBytes::new(vec![2; 32]),
    )
    .unwrap();
    assert_eq!(seed.expose(), unhex(KV_SEED_R));
    assert_eq!(
        sign::ed25519_public(&seed).unwrap().to_vec(),
        unhex(KV_RECOVERY)
    );

    let mut r = account();
    let record = r.a.c.get_keys().unwrap();
    let mine = recovery_seed(&r.made.account_id, &r.kit.secret).unwrap();
    assert_eq!(
        record.recovery_public_key,
        sign::ed25519_public(&mine).unwrap()
    );
}

/// SYN-06.4, SYN-06 T04: a blob of version 2 (and any blob of another
/// version or length) is refused before any Argon2id run, version 2 as
/// `MSG-ACCOUNT-NEEDS-UPDATE`; one changed byte at either end of the salt,
/// the nonce, the ciphertext and the tag fails with
/// `MSG-ACCOUNT-RESTORE-FAILED`, the same words each time.
#[test]
fn syn06_4_t04_version_2_refused_before_argon2id_and_each_changed_byte_fails() {
    let account = AccountId::from_bytes([3; 16]);
    let keys = AccountKeys::new().unwrap();
    let pw = password();
    let blob = make_blob(&keys, &account, &pw).unwrap();
    let secret = keys.account_secret();
    let before = probe::runs();
    let mut v2 = blob.clone();
    v2[1] = 2;
    assert_eq!(
        open_blob(&v2, &account, secret, &pw).unwrap_err(),
        AccountFail::NeedsUpdate
    );
    assert_eq!(
        AccountFail::NeedsUpdate.message().id(),
        "MSG-ACCOUNT-NEEDS-UPDATE"
    );
    let longer = [v2.clone(), vec![0; 10]].concat();
    for other in [&v2[..2], &longer[..], &[0u8, 0][..], &[1u8, 1][..]] {
        assert_eq!(
            open_blob(other, &account, secret, &pw).unwrap_err(),
            AccountFail::NeedsUpdate
        );
    }
    let one_more = [blob.clone(), vec![0]].concat();
    for other in [&blob[..157], &one_more[..], &blob[..1], &[][..]] {
        assert_eq!(
            open_blob(other, &account, secret, &pw).unwrap_err(),
            AccountFail::RestoreFailed,
            "{}",
            other.len()
        );
    }
    assert_eq!(probe::runs(), before, "no Argon2id run");

    let words = AccountFail::RestoreFailed.message();
    assert_eq!(words.id(), "MSG-ACCOUNT-RESTORE-FAILED");
    for (part, at) in [
        ("salt", 2),
        ("salt", 33),
        ("nonce", 34),
        ("nonce", 45),
        ("ciphertext", 46),
        ("ciphertext", 141),
        ("tag", 142),
        ("tag", 157),
    ] {
        let mut changed = blob.clone();
        changed[at] ^= 1;
        let e = open_blob(&changed, &account, secret, &pw).unwrap_err();
        assert_eq!(e, AccountFail::RestoreFailed, "{part} byte {at}");
        assert_eq!(e.message().text("", ""), words.text("", ""));
    }
    assert_eq!(probe::runs(), before + 8);
    assert!(open_blob(&blob, &account, secret, &pw).is_ok(), "unchanged");
}

/// SYN-06.6, SYN-06 T05, CRY-05.8: a server that sends other keys than
/// this Mac's pin after sign-up: another account's keys, an identity key
/// whose Ed25519 half alone differs (its last 32 bytes), a receiving key
/// with its last byte changed and bound by this account's own identity
/// key, this account's keys with a changed binding. Each is
/// `MSG-ACCOUNT-KEYS-CHANGED` and stops the account: no download, no
/// upload signed, no wrap made or opened, not one request more; a later
/// GET of the right keys does not start it again. A record with an
/// Ed25519-only binding or an X25519 receiving key (SYN-06 T19) does not
/// read: refused.
#[test]
#[allow(clippy::too_many_lines)]
fn syn06_6_t05_swapped_keys_stop_the_account() {
    let lie: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
    let served = lie.clone();
    let mut r = account_with(move |app| {
        Scripted::proxy_with(app, move |q| {
            let body = served.lock().unwrap().clone()?;
            (q.method == "GET" && q.path == "/v1/account/keys")
                .then(|| Response::new(200, &body).with("Content-Type", "application/json"))
        })
    });
    let account = r.made.account_id;
    let vault = VaultId::from_bytes([0x51; 16]);
    assert_eq!(first_upload(&mut r.a.c, &vault, VAULT), Ok(1));
    let part = SecretBytes::new(vec![0x46; 32]);
    r.a.c.put_keypart(&vault, &part).unwrap();
    r.a.c.check_keys().unwrap();
    assert!(!r.a.c.stopped(), "the real keys pass");

    let real = r.a.c.get_keys().unwrap();
    let (private, identity, kem) = {
        let k = r.a.keys();
        (
            SecretBytes::new(k.identity_private_key().expose().to_vec()),
            k.identity_public_key().to_vec(),
            k.kem_public_key().to_vec(),
        )
    };
    let bind = |key: &SecretBytes, kem: &[u8]| {
        let signed = sign::field_list(&[&b"sync-kem-key-v1"[..], account.as_bytes(), kem]).unwrap();
        pq::composite_sign(key, &signed).unwrap()
    };
    let other = AccountKeys::new().unwrap();
    let theirs = KeysRecord {
        identity_public_key: other.identity_public_key().to_vec(),
        kem_public_key: other.kem_public_key().to_vec(),
        kem_signature: other.kem_signature(account.as_bytes()).unwrap(),
        ..real.clone()
    };
    let mut half = SecretBytes::new(private.expose().to_vec());
    half.expose_mut()[32..].copy_from_slice(&[0x5a; 32]);
    let near = pq::identity_public(&half).unwrap();
    assert_eq!(near[..1952], identity[..1952], "the same ML-DSA key");
    assert_ne!(near[1952..], identity[1952..]);
    let ed25519_half = KeysRecord {
        identity_public_key: near,
        kem_signature: bind(&half, &kem),
        ..real.clone()
    };
    let mut kem_changed = kem.clone();
    *kem_changed.last_mut().unwrap() ^= 1;
    let receiving = KeysRecord {
        kem_signature: bind(&private, &kem_changed),
        kem_public_key: kem_changed,
        ..real.clone()
    };
    let mut binding = real.clone();
    *binding.kem_signature.last_mut().unwrap() ^= 1;

    let clock = TestClock::at(0);
    for (what, record) in [
        ("another account's keys", theirs),
        ("another Ed25519 half", ed25519_half),
        ("another receiving key", receiving),
        ("a changed binding", binding),
    ] {
        *lie.lock().unwrap() = Some(record.to_json());
        // This Mac after a restart: its device and its kept keys.
        r.later();
        let (id, key) = r.a.c.device.take().unwrap();
        r.a.c = client_of(&r.proxy, r.app.port);
        r.a.c.set_device(id, key);
        r.a.c.load_account(&account, &r.a.keep).unwrap();
        assert!(!r.a.c.stopped());
        assert_eq!(r.a.c.check_keys(), Err(AccountFail::KeysChanged), "{what}");
        assert!(r.a.c.stopped(), "{what}");
        assert_eq!(
            AccountFail::KeysChanged.message().id(),
            "MSG-ACCOUNT-KEYS-CHANGED"
        );
        let seen = r.proxy.requests().len();
        let mut l = link(&r.a.c, vault, 1, VAULT);
        let before = l.clone();
        assert_eq!(run(&mut r.a.c, &mut l, &Untouched, &*clock), keys_changed());
        assert_eq!(l, before, "{what}");
        assert_eq!(
            first_upload(&mut r.a.c, &VaultId::from_bytes([0x52; 16]), VAULT),
            Err(keys_changed())
        );
        assert_eq!(r.a.c.put(&vault, VAULT2, Some(1)).unwrap_err(), Fail::Key);
        assert_eq!(
            r.a.c.get_keypart(&vault, &r.a.keep).unwrap_err(),
            AccountFail::KeysChanged
        );
        assert_eq!(
            r.a.c.put_keypart(&vault, &part).unwrap_err(),
            AccountFail::KeysChanged
        );
        assert_eq!(
            r.proxy.requests().len(),
            seen,
            "{what}: not one request more"
        );
        *lie.lock().unwrap() = None;
        assert_eq!(r.a.c.check_keys(), Ok(()));
        assert!(r.a.c.stopped(), "{what}: stopped until the user acts");
        assert_eq!(run(&mut r.a.c, &mut l, &Untouched, &*clock), keys_changed());
    }

    // T19: records that do not read are refused, the account untouched.
    let mut ed25519_only = real.clone();
    ed25519_only.kem_signature.truncate(64);
    let mut x25519 = real.clone();
    x25519.kem_public_key.truncate(32);
    for (what, record) in [
        ("an Ed25519-only binding", ed25519_only),
        ("an X25519 key", x25519),
    ] {
        *lie.lock().unwrap() = Some(record.to_json());
        r.later();
        let (id, key) = r.a.c.device.take().unwrap();
        r.a.c = client_of(&r.proxy, r.app.port);
        r.a.c.set_device(id, key);
        r.a.c.load_account(&account, &r.a.keep).unwrap();
        assert_eq!(
            r.a.c.check_keys(),
            Err(AccountFail::Net(Fail::Protocol)),
            "{what}"
        );
        assert!(!r.a.c.stopped(), "{what}");
    }
    // Control: the real keys, after a restart.
    *lie.lock().unwrap() = None;
    r.later();
    let (id, key) = r.a.c.device.take().unwrap();
    r.a.c = client_of(&r.proxy, r.app.port);
    r.a.c.set_device(id, key);
    r.a.c.load_account(&account, &r.a.keep).unwrap();
    r.a.c.check_keys().unwrap();
    assert_eq!(
        r.a.c.get_keypart(&vault, &r.a.keep).unwrap().expose(),
        part.expose()
    );
}

/// SYN-06.8, SYN-06 T18's this-Mac half, LD-273 (2): the device store holds
/// one item, `S_acct` ‖ the identity private key ‖ the receiving seed, as
/// `SecretBytes`; after a restart the client signs uploads and opens wraps
/// with no password; a saved state file holds none of the secrets.
#[test]
fn syn06_8_t18_after_a_restart_this_mac_signs_and_opens_with_no_password() {
    let mut r = account();
    let account = r.made.account_id;
    let (expected, secrets) = {
        let k = r.a.keys();
        let expected = [
            k.account_secret().expose(),
            k.identity_private_key().expose(),
            k.kem_seed().expose(),
        ]
        .concat();
        let secrets = vec![
            k.account_secret().expose().to_vec(),
            k.identity_private_key().expose().to_vec(),
            k.identity_private_key().expose()[..32].to_vec(),
            k.identity_private_key().expose()[32..].to_vec(),
            k.kem_seed().expose().to_vec(),
            recovery_seed(&account, k.account_secret())
                .unwrap()
                .expose()
                .to_vec(),
            PASSWORD.as_bytes().to_vec(),
        ];
        (expected, secrets)
    };
    {
        let kept = r.a.keep.0.lock().unwrap();
        assert_eq!(kept.len(), 1);
        let (label, item) = kept.iter().next().unwrap();
        assert_eq!(*label, r.label());
        assert_eq!(*label, format!("{} account {account}", r.a.c.address()));
        assert_eq!(item.expose(), expected);
        assert_eq!(format!("{item:?}"), "[hidden]");
    }

    // A restart: a new client, this Mac's device, the kept keys, no password.
    r.later();
    let (id, key) = r.a.c.device.take().unwrap();
    let mut c = client_of(&r.proxy, r.app.port);
    c.set_device(id, key);
    let mut other = client_of(&r.proxy, r.app.port);
    assert_eq!(
        other.load_account(&AccountId::from_bytes([7; 16]), &r.a.keep),
        Err(AccountFail::NoKeys),
        "another account's item is not there"
    );
    assert_eq!(c.account_id(), None);
    c.load_account(&account, &r.a.keep).unwrap();
    c.check_keys().unwrap();
    let vault = VaultId::from_bytes([0x51; 16]);
    assert_eq!(
        first_upload(&mut c, &vault, VAULT),
        Ok(1),
        "signed: the strict server took it"
    );
    let part = SecretBytes::new(vec![0x46; 32]);
    c.put_keypart(&vault, &part).unwrap();
    assert_eq!(
        c.get_keypart(&vault, &r.a.keep).unwrap().expose(),
        part.expose()
    );

    let state = State {
        servers: vec![state::Server {
            address: c.address().to_owned(),
            pin: r.proxy.pin,
            account: Some(state::Account {
                account,
                device: r.made.device_id,
                label: "0123456789abcdef0123456789abcdef".to_owned(),
                public_key: [4; 65],
            }),
        }],
        links: vec![link(&c, vault, 1, VAULT)],
        parts: vec![state::Part {
            file: "demo.larsalvault".into(),
            root: Uuid([1; 16]),
            label: state::part_label(c.address(), vault),
        }],
        retired: std::collections::BTreeMap::new(),
    };
    let folder = scratch("state");
    let path = folder.0.join("sync-state.json");
    state.save(&path).unwrap();
    let saved = std::fs::read(&path).unwrap();
    assert_eq!(State::load(&path).unwrap(), state);
    for secret in &secrets {
        for form in encoded(secret) {
            assert!(!has(&saved, &form), "a secret in the state file");
        }
    }
}

/// SYN-06.7 and its edge cases: the kit's text (format 1, the address,
/// the fingerprint, the account id as 32 hex digits, `S_acct` in base32,
/// upper case, no padding, groups of 4) and how a typed kit is read: either
/// case, hyphens, spaces and tabs ignored, CR LF line ends; anything else
/// refused with no detail; `{:?}` prints `[hidden]`.
#[test]
fn syn06_7_the_kit_text_and_how_it_is_read() {
    let kit = Kit {
        address: "https://127.0.0.1:8443".to_owned(),
        pin: [0xab; 32],
        account: AccountId::from_bytes([0x3c; 16]),
        secret: SecretBytes::new((0u8..32).collect()),
    };
    assert_eq!(format!("{kit:?}"), "[hidden]");
    let text = kit.text();
    assert_eq!(format!("{text:?}"), "[hidden]");
    let lines: Vec<&str> = text.expose().lines().collect();
    assert_eq!(
        lines,
        [
            "Larsal Recovery Kit".to_owned(),
            "Format: 1".to_owned(),
            "Server: https://127.0.0.1:8443".to_owned(),
            format!("Fingerprint: {}", printed(&[0xab; 32])),
            "Account: 3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c".to_owned(),
            // RFC 4648 section 6 of the bytes 0 to 31, checked with
            // Python's base64.b32encode.
            "Secret: AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4IB-CEQT-CQKR-MFYY-DENB-WHA5-DYPQ".to_owned(),
        ]
    );
    assert!(text.expose().ends_with('\n'));

    let read = |t: &str| Kit::read(&SecretString::new(t.to_owned()));
    let same = |t: &str| {
        let k = read(t).unwrap();
        assert_eq!(k.address(), kit.address());
        assert_eq!(k.pin(), kit.pin());
        assert_eq!(k.account_id(), kit.account_id());
        assert_eq!(k.secret.expose(), kit.secret.expose(), "{t:?}");
    };
    let t = text.expose();
    same(t);
    same(&t.to_lowercase());
    same(&t.to_uppercase().replace("HTTPS://", "https://"));
    same(&t.replace('-', ""));
    same(&t.replace('-', " "));
    same(&t.replace('-', "\t"));
    same(&t.replace('\n', "\r\n"));
    same(&t.replace("Larsal Recovery Kit\n", ""));
    same(&format!("Printed for the demo\n{t}"));
    same(&t.replace("Secret: ", "secret :  "));

    let secret_line = lines[5];
    let with_secret = |s: &str| t.replace(secret_line, &format!("Secret: {s}"));
    // One changed character gives another secret or is refused.
    let changed = read(&with_secret(&secret_line[8..].replacen('A', "B", 1))).unwrap();
    assert_ne!(changed.secret.expose(), kit.secret.expose());
    let ok = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ";
    let refused = [
        with_secret(&ok[..51]),
        with_secret(&format!("{ok}A")),
        with_secret(&ok.replace('Q', "R")),
        with_secret(&format!("{}1", &ok[..51])),
        with_secret(&format!("{}0", &ok[..51])),
        with_secret(&format!("{}8", &ok[..51])),
        with_secret(&format!("{}=", &ok[..51])),
        with_secret(&format!("{ok}====")),
        t.replace("Format: 1", "Format: 2"),
        t.replace("Format: 1\n", ""),
        t.replace("Account: 3c", "Account: 3g"),
        t.replace("Account: 3c", "Account: 3"),
        t.replace("Fingerprint: AB", "Fingerprint: A"),
        t.replace("Server: https://", "Server: http://"),
        format!("{t}Account: 3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c\n"),
        format!("{t}{secret_line}\n"),
        t.replace(&format!("{secret_line}\n"), ""),
        String::new(),
    ];
    for bad in &refused {
        assert_eq!(
            read(bad).unwrap_err(),
            AccountFail::RestoreFailed,
            "{bad:?}"
        );
    }
}

/// E17-S1's check, SYN-06.12, SYN-06 T13: the Recovery Kit (as the user
/// types it, lower case, no hyphens) and the password restore the account
/// into an empty demo app state (a new client folder, an empty device
/// store): N is registered with a session, the account keys unwrap and are
/// kept, the vault list shows the account's vault, N syncs it (the
/// signature verifies with the pinned key) and gets the key-file part from
/// the server; N's signed change reaches A.
#[test]
fn syn06_12_t13_e17s1_the_kit_and_the_password_restore_into_an_empty_demo_app_state() {
    let mut r = account();
    let account = r.made.account_id;
    let vault = VaultId::from_bytes([0x51; 16]);
    assert_eq!(first_upload(&mut r.a.c, &vault, VAULT), Ok(1));
    let mut f = SecretBytes::zeroed(32);
    random::fill(f.expose_mut()).unwrap();
    r.a.c.put_keypart(&vault, &f).unwrap();

    let folder = scratch("mac-n");
    let state_path = folder.0.join("sync-state.json");
    assert_eq!(State::load(&state_path).unwrap(), State::default(), "empty");
    let keep = Memory::default();
    let typed = r.kit.text().expose().to_lowercase().replace('-', "");
    let kit = Kit::read(&SecretString::new(typed)).unwrap();
    r.later();
    let mut n = Server::new(kit.address(), kit.pin()).unwrap();
    n.sign_for_port(r.app.port);
    let made = n.recover(&kit, DeviceKey::test_seam().unwrap()).unwrap();
    assert_eq!(made.account_id, account);
    assert_ne!(made.device_id, r.made.device_id);
    assert!(n.signed_in(), "a session");
    assert_eq!(n.account_id(), None, "no keys before the password");
    n.restore(&kit, &password(), &keep).unwrap();
    assert_eq!(n.account_id(), Some(account));
    let label = format!("{} account {account}", kit.address());
    assert_eq!(label, r.label());
    assert_eq!(
        keep.get(&label).unwrap().expose(),
        r.a.keep.get(&label).unwrap().expose(),
        "N keeps the account's keys"
    );
    n.check_keys().unwrap();
    let listed: Vec<(VaultId, u64)> = n
        .list()
        .unwrap()
        .iter()
        .map(|v| (v.id, v.version))
        .collect();
    assert_eq!(listed, [(vault, 1)]);

    let open = OpenVault::new(b"");
    let mut l = link(&n, vault, 0, b"");
    let report = run(&mut n, &mut l, &open, &*TestClock::at(7));
    assert_eq!(report.status, Some(Status::Synced(7)), "{report:?}");
    assert_eq!(
        (open.merges(), open.file(), l.highest),
        (1, VAULT.to_vec(), 1)
    );
    assert_eq!(n.get_keypart(&vault, &keep).unwrap().expose(), f.expose());

    // N's change, signed with the restored key, reaches A.
    *open.file.lock().unwrap() = VAULT2.to_vec();
    let report = run(&mut n, &mut l, &open, &*TestClock::at(8));
    assert_eq!(report.status, Some(Status::Synced(8)), "{report:?}");
    assert_eq!(l.highest, 2);
    let at_a = OpenVault::new(VAULT);
    let mut la = link(&r.a.c, vault, 1, VAULT);
    let report = run(&mut r.a.c, &mut la, &at_a, &*TestClock::at(9));
    assert_eq!(report.status, Some(Status::Synced(9)), "{report:?}");
    assert_eq!((at_a.file(), la.highest), (VAULT2.to_vec(), 2));

    // N's state: its server, account and link, and no secret.
    let state = State {
        servers: vec![state::Server {
            address: n.address().to_owned(),
            pin: kit.pin(),
            account: Some(state::Account {
                account,
                device: made.device_id,
                label: "00112233445566778899aabbccddeeff".to_owned(),
                public_key: [4; 65],
            }),
        }],
        links: vec![l],
        parts: Vec::new(),
        retired: std::collections::BTreeMap::new(),
    };
    state.save(&state_path).unwrap();
    assert_eq!(State::load(&state_path).unwrap(), state);
    let saved = std::fs::read(&state_path).unwrap();
    assert!(!has(&saved, kit.secret.expose()));
    assert!(!has(&saved, f.expose()));
}

/// SYN-06.12, SYN-06 T14: one changed kit character (the recovery sign-in
/// is refused), a kit of an unknown account, a wrong password and a wrong
/// kit at the unwrap all give `MSG-ACCOUNT-RESTORE-FAILED` with the same
/// words; nothing is kept; the password is used as typed; the right
/// password then restores. A kit of another server is not sent anywhere.
#[test]
fn syn06_12_t14_a_wrong_kit_or_password_gives_one_message() {
    let r = account();
    let text = r.kit.text();
    let t = text.expose();
    let secret_line = t.lines().find(|l| l.starts_with("Secret: ")).unwrap();
    let first = secret_line.as_bytes()[8];
    let swapped = if first == b'A' { "B" } else { "A" };
    let changed = t.replace(
        secret_line,
        &format!("Secret: {swapped}{}", &secret_line[9..]),
    );
    let wrong_kit = Kit::read(&SecretString::new(changed)).unwrap();
    let account_line = t.lines().find(|l| l.starts_with("Account: ")).unwrap();
    let last = account_line.as_bytes()[account_line.len() - 1];
    let digit = if last == b'0' { "1" } else { "0" };
    let unknown = t.replace(
        account_line,
        &format!("{}{digit}", &account_line[..account_line.len() - 1]),
    );
    let unknown_kit = Kit::read(&SecretString::new(unknown)).unwrap();
    let kit = Kit::read(&text).unwrap();
    let words = |e: AccountFail| {
        (
            e.message().id(),
            e.message().text("Personal", kit.address()),
        )
    };

    let mut failures = Vec::new();
    for k in [&wrong_kit, &unknown_kit] {
        r.later();
        let mut n = Server::new(kit.address(), kit.pin()).unwrap();
        n.sign_for_port(r.app.port);
        let e = n.recover(k, DeviceKey::test_seam().unwrap()).unwrap_err();
        assert!(!n.signed_in());
        failures.push(e);
    }
    r.later();
    let mut n = Server::new(kit.address(), kit.pin()).unwrap();
    n.sign_for_port(r.app.port);
    n.recover(&kit, DeviceKey::test_seam().unwrap()).unwrap();
    let keep = Memory::default();
    for pw in ["demo-account-pv", "demo-account-pw ", "Demo-account-pw"] {
        let e = n
            .restore(&kit, &SecretString::new(pw.to_owned()), &keep)
            .unwrap_err();
        failures.push(e);
    }
    failures.push(n.restore(&wrong_kit, &password(), &keep).unwrap_err());
    let one = words(AccountFail::RestoreFailed);
    assert_eq!(one.0, "MSG-ACCOUNT-RESTORE-FAILED");
    assert_eq!(
        one.1,
        "The Recovery Kit or the account password is not right."
    );
    for e in &failures {
        assert_eq!(*e, AccountFail::RestoreFailed);
        assert_eq!(words(*e), one);
    }
    assert!(keep.0.lock().unwrap().is_empty(), "nothing kept");
    assert_eq!(n.account_id(), None);

    n.restore(&kit, &password(), &keep).unwrap();
    assert_eq!(n.account_id(), Some(r.made.account_id));

    let elsewhere = Kit {
        address: "https://127.0.0.1:1".to_owned(),
        pin: kit.pin(),
        account: kit.account_id(),
        secret: SecretBytes::new(kit.secret.expose().to_vec()),
    };
    let seen = r.proxy.requests().len();
    assert_eq!(
        n.recover(&elsewhere, DeviceKey::test_seam().unwrap())
            .unwrap_err(),
        AccountFail::OtherServer
    );
    assert_eq!(
        n.restore(&elsewhere, &password(), &keep).unwrap_err(),
        AccountFail::OtherServer
    );
    assert_eq!(r.proxy.requests().len(), seen, "nothing sent");
}

/// SYN-06.9, SYN-06 T07, LD-266 (2), CRY-05.4: Mac A wraps the key-file
/// part F to the account's own receiving key with info (`sync-wrap-info-v1`,
/// `keypart`, account, vault), signed by the identity key; Mac B, restored
/// by kit with an empty device store (no copy of A's items: the test
/// helper's copy is gone), gets F from the server's wrap. A wrap signed by
/// another key, with info naming another vault, of the classical suite,
/// naming another signer or with a changed byte is refused.
#[test]
#[allow(clippy::too_many_lines)]
fn syn06_9_t07_the_part_reaches_the_second_mac_through_the_server() {
    let swap: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
    let served = swap.clone();
    let mut r = account_with(move |app| {
        Scripted::proxy_with(app, move |q| {
            let body = served.lock().unwrap().clone()?;
            (q.method == "GET" && q.path.ends_with("/keypart"))
                .then(|| Response::new(200, &body).with("Content-Type", "application/json"))
        })
    });
    let me = r.made.account_id;
    let vault = VaultId::from_bytes([0x51; 16]);
    assert_eq!(first_upload(&mut r.a.c, &vault, VAULT), Ok(1));
    let mut f = SecretBytes::zeroed(32);
    random::fill(f.expose_mut()).unwrap();
    // A keeps F under the part label, as larsal-ffi does (SYN-03.1 step 2).
    let part_label = state::part_label(r.a.c.address(), vault);
    r.a.keep.put(&part_label, &f).unwrap();
    r.a.c.put_keypart(&vault, &f).unwrap();

    let puts: Vec<Request> = r
        .proxy
        .requests()
        .into_iter()
        .filter(|q| q.method == "PUT" && q.path.ends_with("/keypart"))
        .collect();
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0].path, format!("/v1/vaults/{vault}/keypart"));
    let sent = wire::read(&puts[0].body).unwrap();
    let info = keypart_info(&me, &vault).unwrap();
    assert_eq!(sent.suite, [25722, 1, 3]);
    assert_eq!(sent.info, info);
    assert_eq!(sent.signer, *me.as_bytes());
    for form in encoded(f.expose()) {
        assert!(!has(&puts[0].raw, &form), "F in the PUT");
    }

    let mut b = recovered(&r);
    assert!(
        b.keep.get(&part_label).is_none(),
        "B's store holds no part before B asks the server"
    );
    assert_eq!(b.keep.0.lock().unwrap().len(), 1, "only the account's item");
    let got = b.c.get_keypart(&vault, &b.keep).unwrap();
    assert_eq!(got.expose(), f.expose());
    assert_eq!(
        b.keep.get(&part_label).unwrap().expose(),
        f.expose(),
        "B puts F into its device store"
    );
    let gets = |p: &Scripted| {
        p.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(q, reply)| {
                q.method == "GET"
                    && q.path.ends_with("/keypart")
                    && reply.starts_with(b"HTTP/1.1 200")
            })
            .count()
    };
    assert_eq!(gets(&r.proxy), 1, "F came in the server's reply");

    let (kem, private) = {
        let k = r.a.keys();
        (
            k.kem_public_key().to_vec(),
            SecretBytes::new(k.identity_private_key().expose().to_vec()),
        )
    };
    let make = |info: &[u8], signer: [u8; 16], key: &SecretBytes| {
        wrap_record::make(&kem, info, f.expose(), signer, key).unwrap()
    };
    let other = AccountKeys::new().unwrap();
    let other_vault = VaultId::from_bytes([0x52; 16]);
    let mut classical = make(&info, *me.as_bytes(), &private);
    classical.suite = [0x0020, 0x0001, 0x0003];
    let mut changed = make(&info, *me.as_bytes(), &private);
    changed.ct[0] ^= 1;
    let mut changed_info = make(&info, *me.as_bytes(), &private);
    *changed_info.info.last_mut().unwrap() ^= 1;
    for (what, record) in [
        (
            "signed by another key",
            make(&info, *me.as_bytes(), other.identity_private_key()),
        ),
        (
            "info naming another vault",
            make(
                &keypart_info(&me, &other_vault).unwrap(),
                *me.as_bytes(),
                &private,
            ),
        ),
        ("the classical suite", classical),
        ("another signer id", make(&info, [0x0b; 16], &private)),
        ("a changed ciphertext", changed),
        ("a changed info byte", changed_info),
    ] {
        *swap.lock().unwrap() = Some(wire::to_json(&record));
        let empty = Memory::default();
        assert_eq!(
            b.c.get_keypart(&vault, &empty).unwrap_err(),
            AccountFail::BadWrap,
            "{what}"
        );
        assert!(empty.0.lock().unwrap().is_empty(), "{what}: nothing kept");
    }
    // Control: a wrap made the same way by the account opens.
    *swap.lock().unwrap() = Some(wire::to_json(&make(&info, *me.as_bytes(), &private)));
    assert_eq!(
        b.c.get_keypart(&vault, &b.keep).unwrap().expose(),
        f.expose()
    );
    *swap.lock().unwrap() = None;
    assert_eq!(
        b.c.get_keypart(&vault, &b.keep).unwrap().expose(),
        f.expose()
    );
    assert_eq!(
        b.c.get_keypart(&other_vault, &b.keep).unwrap_err(),
        AccountFail::NoPart
    );
}

/// CRY-05.10, CRY-05 T18's measure on a personal upload, SYN-01.10: every
/// vault PUT carries one `Upload-Signature` of 4,498 base64url characters
/// that verifies with the identity key over (`sync-upload-v1`, the vault,
/// the new version, the body's SHA-256), and its head is under 32 KiB.
#[test]
fn cry05_10_t18_the_upload_head_stays_inside_syn01_10() {
    let mut r = account();
    let vault = VaultId::from_bytes([0x51; 16]);
    assert_eq!(first_upload(&mut r.a.c, &vault, VAULT), Ok(1));
    let open = OpenVault::new(VAULT2);
    let mut l = link(&r.a.c, vault, 1, VAULT);
    let report = run(&mut r.a.c, &mut l, &open, &*TestClock::at(3));
    assert_eq!(report.status, Some(Status::Synced(3)), "{report:?}");
    let identity = r.a.keys().identity_public_key().to_vec();
    let puts: Vec<Request> = r
        .proxy
        .requests()
        .into_iter()
        .filter(|q| q.method == "PUT" && q.path == format!("/v1/vaults/{vault}"))
        .collect();
    assert_eq!(puts.len(), 2);
    for (version, q) in (1u64..).zip(&puts) {
        let lines: Vec<&str> = q
            .headers
            .iter()
            .filter(|(n, _)| n == "upload-signature")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), 4498);
        let head = q.raw.len() - q.body.len();
        assert!(head < 32 * 1024, "{head}");
        let signature = base64::decode(Form::Url, lines[0]).unwrap();
        let message = upload_message(&vault, version, &sha(&q.body)).unwrap();
        pq::composite_verify(&identity, &message, &signature).unwrap();
        println!(
            "CRY-05 T18: PUT of version {version}: Upload-Signature {} characters, request head {head} bytes (limit 32768)",
            lines[0].len()
        );
    }
}

/// SYN-06.3, SYN-06 T02: given every file of the server (its store, with
/// every row, its write-ahead log, its blobs, its certificate and key) and
/// the right account password, but not `S_acct`, the blob opens with no
/// 32-byte window of those bytes taken as `S_acct` (with `A` of the right
/// password) or as `K_wrap`, nor with `A` alone or a zero `S_acct`; the
/// real `S_acct` opens it (the control).
#[test]
fn syn06_3_t02_every_row_and_file_and_the_password_without_s_acct_open_nothing() {
    let mut r = account();
    let account = r.made.account_id;
    let vault = VaultId::from_bytes([0x51; 16]);
    assert_eq!(first_upload(&mut r.a.c, &vault, VAULT), Ok(1));
    r.a.c
        .put_keypart(&vault, &SecretBytes::new(vec![0x46; 32]))
        .unwrap();
    let record = r.a.c.get_keys().unwrap();
    let salt: [u8; 32] = record.blob[2..34].try_into().unwrap();
    let aad = blob_aad(&account, 1, &salt).unwrap();
    let sealed = &record.blob[34..];
    let a = kdf::import_argon2id(
        &SecretBytes::new(PASSWORD.as_bytes().to_vec()),
        &salt,
        3,
        64,
        4,
        32,
    )
    .unwrap();
    let key_of = |s: &[u8]| {
        let ikm = SecretBytes::new([s, a.expose()].concat());
        wrap::hkdf_sha256(account.as_bytes(), &ikm, b"sync-account-key-v1").unwrap()
    };
    assert!(
        wrap::open(&key_of(r.kit.secret.expose()), &aad, sealed).is_ok(),
        "the control"
    );

    let stored = files(&r.app._data.0);
    let mut windows = 0usize;
    let mut bytes = 0usize;
    for (path, data) in &stored {
        bytes += data.len();
        for w in data.windows(32) {
            windows += 1;
            assert!(
                wrap::open(&key_of(w), &aad, sealed).is_err(),
                "{}",
                path.display()
            );
            assert!(
                wrap::open(&SecretBytes::new(w.to_vec()), &aad, sealed).is_err(),
                "{}",
                path.display()
            );
        }
    }
    assert!(wrap::open(&a, &aad, sealed).is_err(), "A alone");
    let a_only = wrap::hkdf_sha256(account.as_bytes(), &a, b"sync-account-key-v1").unwrap();
    assert!(
        wrap::open(&a_only, &aad, sealed).is_err(),
        "HKDF of A alone"
    );
    assert!(
        wrap::open(&key_of(&[0; 32]), &aad, sealed).is_err(),
        "a zero S_acct"
    );
    assert!(stored.iter().any(|(p, _)| p.ends_with("store.sqlite")));
    println!(
        "SYN-06 T02: {} files, {bytes} bytes, {windows} windows of 32 bytes, each tried as S_acct with A and as K_wrap: none opened the blob",
        stored.len()
    );
}

/// SYN-02 T14, CRY-05 T29, LD-340, LD-426: after a full demo run (sign-up,
/// sync with signed uploads, a key-file part wrap, a restore by kit on a
/// second Mac that syncs and gets the part), no secret is in any stored or
/// sent byte: `S_acct`, the kit's text and its base32, `A`, `K_wrap`, the
/// blob's plaintext, the identity private key and its two seeds, the
/// receiving seed, the recovery seed, the account password, the part F,
/// the demo master password and the entry's title, user name and password,
/// each raw, as upper and lower hex, padded and URL base64, and the same
/// of its SHA-256, in every request and reply through the proxy, every file
/// of the server's data folder and both Macs' state files.
#[test]
#[allow(clippy::too_many_lines)]
fn syn02_t14_cry05_t29_no_secret_in_any_stored_byte_after_a_full_run() {
    let mut r = account();
    let account = r.made.account_id;
    let vault = VaultId::from_bytes([0x51; 16]);
    assert_eq!(first_upload(&mut r.a.c, &vault, VAULT), Ok(1));
    let open_a = OpenVault::new(VAULT2);
    let mut la = link(&r.a.c, vault, 1, VAULT);
    assert_eq!(
        run(&mut r.a.c, &mut la, &open_a, &*TestClock::at(5)).status,
        Some(Status::Synced(5))
    );
    assert_eq!(la.highest, 2);
    let mut f = SecretBytes::zeroed(32);
    random::fill(f.expose_mut()).unwrap();
    r.a.c.put_keypart(&vault, &f).unwrap();

    let mut n = recovered(&r);
    let open_n = OpenVault::new(b"");
    let mut ln = link(&n.c, vault, 0, b"");
    assert_eq!(
        run(&mut n.c, &mut ln, &open_n, &*TestClock::at(6)).status,
        Some(Status::Synced(6))
    );
    assert_eq!(open_n.file(), VAULT2);
    assert_eq!(
        n.c.get_keypart(&vault, &n.keep).unwrap().expose(),
        f.expose()
    );

    let folder = scratch("states");
    let mut state_files = Vec::new();
    for (name, c, l) in [("a", &r.a.c, la), ("n", &n.c, ln)] {
        let s = State {
            servers: vec![state::Server {
                address: c.address().to_owned(),
                pin: r.kit.pin(),
                account: Some(state::Account {
                    account,
                    device: DeviceId::from_bytes([0x44; 16]),
                    label: "00112233445566778899aabbccddeeff".to_owned(),
                    public_key: [4; 65],
                }),
            }],
            links: vec![l],
            parts: vec![state::Part {
                file: "demo.larsalvault".into(),
                root: Uuid([1; 16]),
                label: state::part_label(c.address(), vault),
            }],
            retired: std::collections::BTreeMap::new(),
        };
        let path = folder.0.join(format!("mac-{name}.json"));
        s.save(&path).unwrap();
        state_files.push(path);
    }

    let record = r.a.c.get_keys().unwrap();
    let keys = r.a.keys();
    let salt: [u8; 32] = record.blob[2..34].try_into().unwrap();
    let a_value = kdf::import_argon2id(
        &SecretBytes::new(PASSWORD.as_bytes().to_vec()),
        &salt,
        3,
        64,
        4,
        32,
    )
    .unwrap();
    let k_wrap = wrap::account_key(
        &password(),
        &salt,
        keys.account_secret(),
        account.as_bytes(),
    )
    .unwrap();
    let kit_text = r.kit.text();
    let secret_line = kit_text
        .expose()
        .lines()
        .find(|l| l.starts_with("Secret: "))
        .unwrap()[8..]
        .to_owned();
    let identity = keys.identity_private_key().expose();
    let needles: Vec<(&str, Vec<u8>)> = vec![
        ("S_acct", keys.account_secret().expose().to_vec()),
        ("the kit's text", kit_text.expose().as_bytes().to_vec()),
        ("the kit's secret", secret_line.as_bytes().to_vec()),
        (
            "the kit's secret without hyphens",
            secret_line.replace('-', "").into_bytes(),
        ),
        ("A", a_value.expose().to_vec()),
        ("K_wrap", k_wrap.expose().to_vec()),
        (
            "the blob's plaintext",
            keys.blob_plaintext().expose().to_vec(),
        ),
        ("the identity private key", identity.to_vec()),
        ("its ML-DSA seed", identity[..32].to_vec()),
        ("its Ed25519 seed", identity[32..].to_vec()),
        ("the receiving seed", keys.kem_seed().expose().to_vec()),
        (
            "the recovery seed",
            recovery_seed(&account, keys.account_secret())
                .unwrap()
                .expose()
                .to_vec(),
        ),
        ("the account password", PASSWORD.as_bytes().to_vec()),
        ("the key-file part F", f.expose().to_vec()),
        ("the master password", b"demo-pass-1".to_vec()),
        ("the entry title", b"Demo login".to_vec()),
        ("the entry user name", b"demo-user".to_vec()),
        ("the entry password", b"demo-entry-pass-1".to_vec()),
    ];
    let mut forms: Vec<(String, Vec<u8>)> = Vec::new();
    for (what, value) in &needles {
        for form in encoded(value) {
            forms.push(((*what).to_owned(), form));
        }
        for form in encoded(&sha(value)) {
            forms.push((format!("{what}'s SHA-256"), form));
        }
    }

    let mut hay: Vec<(String, Vec<u8>)> = Vec::new();
    let exchanges = {
        let seen = r.proxy.seen.lock().unwrap();
        for (q, reply) in seen.iter() {
            hay.push((format!("request {} {}", q.method, q.path), q.raw.clone()));
            hay.push((format!("reply to {} {}", q.method, q.path), reply.clone()));
        }
        seen.len()
    };
    let stored = files(&r.app._data.0);
    let server_files = stored.len();
    for (p, b) in stored {
        hay.push((p.display().to_string(), b));
    }
    for p in &state_files {
        hay.push((p.display().to_string(), std::fs::read(p).unwrap()));
    }
    assert!(
        hay.iter().any(|(_, b)| has(b, VAULT2)),
        "the search sees the vault bytes it should"
    );
    let bytes: usize = hay.iter().map(|(_, b)| b.len()).sum();
    let mut found = Vec::new();
    for (place, b) in &hay {
        for (what, form) in &forms {
            if has(b, form) {
                found.push(format!("{what} in {place}"));
            }
        }
    }
    println!(
        "SYN-02 T14, CRY-05 T29: {} needles, {} forms (5 encodings of each and of its SHA-256), {} places ({exchanges} proxied exchanges as request and reply, {server_files} server files, {} state files), {bytes} bytes searched, {} found",
        needles.len(),
        forms.len(),
        hay.len(),
        state_files.len(),
        found.len()
    );
    assert!(found.is_empty(), "{found:?}");
}
