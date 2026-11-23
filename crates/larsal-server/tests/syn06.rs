//! SYN-06 checks of E17-S1 on the server's side: the account keys routes
//! (SYN-06.6), the upload signature (SYN-01.7, SYN-01 T12), the key-file
//! part routes (SYN-06.9), the recovery sign-in (SYN-06.12) and no email
//! anywhere (SYN-06.13, T15), against a release server's rule: every server
//! here is strict (`start_strict`), so no upload passes unsigned. E17-S2
//! adds the approval routes (SYN-06.11 with SYN-05's code compare): every
//! route's statuses, one claim and one commitment, the order, the 15
//! minutes, the seal's checks and the device row only after E's seal. The
//! keys are larsal-crypto's; the blob is demo bytes the server never reads.
//! Every client connects to 127.0.0.1 only; expiry runs on the test clock.

mod common;

use common::{
    Device, Reply, Running, account_keys, approval_line, bearer, block_on, challenge, exchange,
    origin, put_keys, recovery_seed, request, second_device_with, set_clock, sign_in, sign_up,
    signed, start_strict, upload_header,
};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::sign::P256TestKey;
use larsal_crypto::{pq, sign, wrap_record};
use larsal_proto::account::{
    AccountKeys, Recovered, RecoveryChallengeRequest, RecoverySignIn, keypart_info, upload_message,
};
use larsal_proto::approval::{
    self as approval, ApprovalClaim, ApprovalCreate, ApprovalSeal, ApprovalStart, ApprovalState,
    CompareCommit, CompareKeys,
};
use larsal_proto::messages::{AccountId, Challenge, Id, Session, VaultId};
use larsal_proto::{signin, wrap};
use larsal_server::http::{Config, RateLimits};

/// A second on the test clock: 2027-01-15.
const T0: u64 = 1_800_000_000;
const X: VaultId = VaultId::from_bytes([0x58; 16]);
const Y: VaultId = VaultId::from_bytes([0x59; 16]);

/// A strict server with one account signed in on it; the rate limits are
/// raised, since these runs use the sign-in routes many times a minute.
async fn strict() -> (Running, Device) {
    let rate = RateLimits {
        signin: 1000,
        writes: 1000,
        reads: 1000,
    };
    let mut s = start_strict(Config {
        rate,
        ..Config::default()
    })
    .await;
    let d = sign_up(&s).await;
    s.auth = bearer(&sign_in(&s, &d).await);
    (s, d)
}

fn sha(body: &[u8]) -> [u8; 32] {
    larsal_crypto::hash::sha256(&[body])
        .expose()
        .try_into()
        .unwrap()
}

fn path(vault: &VaultId) -> String {
    format!("/v1/vaults/{vault}")
}

/// `method path` with this session and the header lines `pre`.
async fn call(s: &Running, method: &str, path: &str, pre: &str, body: &[u8]) -> Reply {
    let head = format!("{}{pre}", s.auth);
    exchange(s, &request(method, path, &head, body)).await
}

/// `PUT /v1/vaults/{vault}` with the precondition `pre` and the header
/// lines `extra` (each with its CRLF).
async fn put(s: &Running, vault: &VaultId, pre: &str, extra: &str, body: &[u8]) -> Reply {
    let head = format!("{}{pre}{extra}", s.auth);
    exchange(s, &request("PUT", &path(vault), &head, body)).await
}

/// Versions 1 to `n` of `vault`, each signed by `keys`.
async fn versions(
    s: &Running,
    keys: &larsal_crypto::account::AccountKeys,
    vault: &VaultId,
    n: u64,
) {
    for v in 1..=n {
        let body = format!("demo vault bytes {v}");
        let pre = if v == 1 {
            "If-None-Match: *\r\n".to_owned()
        } else {
            format!("If-Match: \"{}\"\r\n", v - 1)
        };
        let sig = upload_header(keys, vault, v, body.as_bytes());
        let r = put(s, vault, &pre, &sig, body.as_bytes()).await;
        assert_eq!(r.status, if v == 1 { 201 } else { 200 }, "{r:?}");
    }
}

/// SYN-01.7, SYN-01 T12, CRY-05.10: vault X at version 4 of an account with
/// identity key K. A PUT with `If-Match: "4"` signed over version 4 (the
/// If-Match version, not the new one) gets 403; with no signature 400; one
/// that does not read (a character short, or two lines) 400; one signed by
/// another key, over other bytes or for another vault 403; and none of them
/// stores anything. The PUT signed over (X, 5, the body's SHA-256) gets 200,
/// and the GET returns `Upload-Signer` (the account id) and version 5's
/// signature, 4,498 base64url characters that verify with K.
#[test]
fn syn01_7_t12_upload_signature_put_and_get() {
    block_on(async {
        let (s, d) = strict().await;
        let (k, record) = account_keys(&d.account);
        assert_eq!(put_keys(&s, &record).await.status, 201);
        versions(&s, &k, &X, 4).await;
        let body = b"demo vault bytes 5";
        let at4 = "If-Match: \"4\"\r\n";
        put(&s, &X, at4, &upload_header(&k, &X, 4, body), body)
            .await
            .assert_error(403, "forbidden");
        put(&s, &X, at4, "", body)
            .await
            .assert_error(400, "bad_request");
        let short = format!("Upload-Signature: {}\r\n", "A".repeat(4497));
        put(&s, &X, at4, &short, body)
            .await
            .assert_error(400, "bad_request");
        let twice = upload_header(&k, &X, 5, body).repeat(2);
        put(&s, &X, at4, &twice, body)
            .await
            .assert_error(400, "bad_request");
        let (other, _) = account_keys(&d.account);
        put(&s, &X, at4, &upload_header(&other, &X, 5, body), body)
            .await
            .assert_error(403, "forbidden");
        put(&s, &X, at4, &upload_header(&k, &X, 5, b"other bytes"), body)
            .await
            .assert_error(403, "forbidden");
        put(&s, &X, at4, &upload_header(&k, &Y, 5, body), body)
            .await
            .assert_error(403, "forbidden");
        let good = upload_header(&k, &X, 5, body);
        let r = put(&s, &X, at4, &good, body).await;
        assert_eq!(r.status, 200, "{r:?}");
        assert_eq!(r.header("etag"), Some("\"5\""), "nothing was stored before");
        let g = exchange(&s, &request("GET", &path(&X), &s.auth, b"")).await;
        assert_eq!(g.status, 200);
        assert_eq!(g.body, body);
        assert_eq!(
            g.header("upload-signer"),
            Some(d.account.to_string().as_str())
        );
        let text = g.header("upload-signature").unwrap();
        assert_eq!(text.len(), 4498);
        assert_eq!(format!("Upload-Signature: {text}\r\n"), good);
        let signature = base64::decode(Form::Url, text).unwrap();
        let message = upload_message(&X, 5, &sha(body)).unwrap();
        assert!(pq::composite_verify(k.identity_public_key(), &message, &signature).is_ok());
    });
}

/// SYN-01.7, ruling (7): an account with no keys row has no identity key,
/// so it cannot upload: a signed PUT gets 403 (the signature does not
/// verify with the account's key, SYN-01.6), an unsigned one 400; nothing
/// is stored.
#[test]
fn syn01_7_an_account_with_no_keys_row_cannot_upload() {
    block_on(async {
        let (s, d) = strict().await;
        let (k, _) = account_keys(&d.account);
        let body = b"demo vault bytes 1";
        let create = "If-None-Match: *\r\n";
        put(&s, &X, create, &upload_header(&k, &X, 1, body), body)
            .await
            .assert_error(403, "forbidden");
        put(&s, &X, create, "", body)
            .await
            .assert_error(400, "bad_request");
        let list = exchange(&s, &request("GET", "/v1/vaults", &s.auth, b"")).await;
        assert_eq!(list.body, br#"{"vaults":[]}"#);
    });
}

/// CRY-05.10, CRY-05 T18 on a personal upload: the `Upload-Signature`
/// field is 4,498 characters and the whole request head stays far under
/// SYN-01.10's limits (one field 8 KiB, the head 32 KiB).
#[test]
fn cry05_t18_the_upload_head_stays_inside_syn01_10() {
    block_on(async {
        let (s, d) = strict().await;
        let (k, record) = account_keys(&d.account);
        assert_eq!(put_keys(&s, &record).await.status, 201);
        versions(&s, &k, &X, 1).await;
        let sent = s.sent.lock().unwrap();
        let (request, reply) = sent.last().unwrap();
        assert_eq!(reply.status, 201);
        let end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = std::str::from_utf8(&request[..end]).unwrap();
        let field = head
            .split("\r\n")
            .find(|l| l.starts_with("Upload-Signature: "))
            .unwrap();
        assert_eq!(field.len() - "Upload-Signature: ".len(), 4498);
        assert!(field.len() < larsal_proto::limits::MAX_HEADER_FIELD);
        assert!(end + 4 < larsal_proto::limits::MAX_HEAD, "{}", end + 4);
        println!(
            "CRY-05 T18: Upload-Signature field {} bytes (limit {}), head {} bytes (limit {})",
            field.len(),
            larsal_proto::limits::MAX_HEADER_FIELD,
            end + 4,
            larsal_proto::limits::MAX_HEAD
        );
    });
}

/// SYN-06.6, CRY-05 T14 with the server: `PUT /v1/account/keys` needs
/// `If-None-Match: *` (428 without, 412 with `If-Match`, 400 with both),
/// takes only CRY-05.8's record with every size right (400 otherwise),
/// stores it once (201, then 412 with the row unchanged) and returns it on
/// GET (200); an account with no keys gets 404, and no session 401.
#[test]
fn syn06_6_cry05_t14_keys_are_stored_once_and_returned() {
    block_on(async {
        let (mut s, d) = strict().await;
        let (_, record) = account_keys(&d.account);
        let keys = "/v1/account/keys";
        call(&s, "GET", keys, "", b"")
            .await
            .assert_error(404, "not_found");
        let body = record.to_json();
        call(&s, "PUT", keys, "", &body)
            .await
            .assert_error(428, "precondition_required");
        call(&s, "PUT", keys, "If-Match: \"1\"\r\n", &body)
            .await
            .assert_error(412, "precondition_failed");
        let both = "If-Match: \"1\"\r\nIf-None-Match: *\r\n";
        call(&s, "PUT", keys, both, &body)
            .await
            .assert_error(400, "bad_request");
        let create = "If-None-Match: *\r\n";
        let mut short = record.clone();
        short.kem_signature.pop();
        call(&s, "PUT", keys, create, &short.to_json())
            .await
            .assert_error(400, "bad_request");
        let mut x25519 = record.clone();
        x25519.kem_public_key.truncate(32);
        call(&s, "PUT", keys, create, &x25519.to_json())
            .await
            .assert_error(400, "bad_request");
        call(&s, "PUT", keys, create, b"{}")
            .await
            .assert_error(400, "bad_request");
        let r = call(&s, "PUT", keys, create, &body).await;
        assert_eq!(r.status, 201, "{r:?}");
        assert!(r.body.is_empty());
        let (_, second) = account_keys(&d.account);
        call(&s, "PUT", keys, create, &second.to_json())
            .await
            .assert_error(412, "precondition_failed");
        let g = call(&s, "GET", keys, "", b"").await;
        assert_eq!(g.status, 200);
        assert_eq!(AccountKeys::read(&g.body).unwrap(), record, "unchanged");
        assert_eq!(g.header("cache-control"), Some("no-store"));
        s.auth.clear();
        call(&s, "GET", keys, "", b"").await.assert_unauthorized();
        call(&s, "PUT", keys, create, &body)
            .await
            .assert_unauthorized();
    });
}

/// SYN-06.9, CRY-05.7: `PUT /v1/vaults/{vault}/keypart` keeps a wrap
/// record of the suite `[25722, 1, 3]` for this account's vault (204), in
/// place of the one before it, and `GET` returns it (200). A record of
/// another suite, one that does not read and one over 16 KiB get 400
/// before anything is stored; another account's vault and a vault with no
/// part get 404; no session 401.
#[test]
fn syn06_9_keypart_put_and_get() {
    block_on(async {
        let (mut s, d) = strict().await;
        let (k, record) = account_keys(&d.account);
        assert_eq!(put_keys(&s, &record).await.status, 201);
        versions(&s, &k, &X, 1).await;
        let part_path = format!("{}/keypart", path(&X));
        let wrap_of = |part: &[u8]| {
            let info = keypart_info(&d.account, &X).unwrap();
            let signer = *d.account.as_bytes();
            wrap_record::make(
                k.kem_public_key(),
                &info,
                part,
                signer,
                k.identity_private_key(),
            )
            .unwrap()
        };
        let get = async |s: &Running, p: &str| call(s, "GET", p, "", b"").await;
        get(&s, &part_path).await.assert_error(404, "not_found");
        let first = wrap_of(b"demo key-file part one");
        let send = async |s: &Running, p: &str, body: Vec<u8>| call(s, "PUT", p, "", &body).await;
        let r = send(&s, &part_path, wrap::to_json(&first)).await;
        assert_eq!(r.status, 204, "{r:?}");
        let g = get(&s, &part_path).await;
        assert_eq!(g.status, 200);
        assert_eq!(wrap::read(&g.body).unwrap(), first);
        let second = wrap_of(b"demo key-file part two");
        assert_eq!(
            send(&s, &part_path, wrap::to_json(&second)).await.status,
            204
        );
        assert_eq!(wrap::read(&get(&s, &part_path).await.body).unwrap(), second);
        // CRY-05.7: a record of any suite but CRY-05.3's (here [32, 1, 3],
        // which no card names) is refused before it is stored; the classical
        // suite [32, 1, 2] is c1_keypart_refuses_the_classical_suite's.
        let mut other_suite = second.clone();
        other_suite.suite = [0x0020, 0x0001, 0x0003];
        send(&s, &part_path, wrap::to_json(&other_suite))
            .await
            .assert_error(400, "bad_request");
        send(&s, &part_path, b"{}".to_vec())
            .await
            .assert_error(400, "bad_request");
        let mut big = wrap::to_json(&second);
        let end = big.pop().unwrap();
        big.resize(16 * 1024 + 1, b' ');
        big.push(end);
        send(&s, &part_path, big)
            .await
            .assert_error(400, "bad_request");
        assert_eq!(wrap::read(&get(&s, &part_path).await.body).unwrap(), second);
        // No such vault for this account.
        let y_path = format!("{}/keypart", path(&Y));
        send(&s, &y_path, wrap::to_json(&second))
            .await
            .assert_error(404, "not_found");
        // Another account sees no part and stores none on X.
        let other = sign_up(&s).await;
        let theirs = bearer(&sign_in(&s, &other).await);
        let mine = std::mem::replace(&mut s.auth, theirs);
        get(&s, &part_path).await.assert_error(404, "not_found");
        send(&s, &part_path, wrap::to_json(&first))
            .await
            .assert_error(404, "not_found");
        s.auth = mine;
        assert_eq!(wrap::read(&get(&s, &part_path).await.body).unwrap(), second);
        s.auth.clear();
        get(&s, &part_path).await.assert_unauthorized();
    });
}

/// E17-S1's Checker 1 test, adopted by E17-S2 (ruling (13)(e)): SYN-06.9,
/// CRY-05.7: a keypart record in CRY-04.5's classical form (suite
/// [32,1,2], a 32-byte enc, a 64-byte Ed25519 signature) and a hybrid
/// record labelled [32,1,2] (the suite CRY-04.6 names) get 400 and nothing
/// is stored.
#[test]
fn c1_keypart_refuses_the_classical_suite() {
    block_on(async {
        let (s, d) = strict().await;
        let (k, record) = account_keys(&d.account);
        assert_eq!(put_keys(&s, &record).await.status, 201);
        let v1 = b"c1 demo bytes 1";
        let r = call(
            &s,
            "PUT",
            &path(&X),
            &format!("If-None-Match: *\r\n{}", upload_header(&k, &X, 1, v1)),
            v1,
        )
        .await;
        assert_eq!(r.status, 201, "{r:?}");
        let part = format!("{}/keypart", path(&X));
        let info = keypart_info(&d.account, &X).unwrap();
        // The classical form's sizes: a 32-byte X25519 enc, a 48-byte ct.
        let (enc, ct) = ([0x20u8; 32], [0x21u8; 48]);
        let seed = larsal_crypto::secret::SecretBytes::new(vec![0x5a; 32]);
        let classical = format!(
            r#"{{"suite":[32,1,2],"enc":"{}","ct":"{}","info":"{}","signer":"{}","signature":"{}"}}"#,
            base64::encode(Form::Url, &enc),
            base64::encode(Form::Url, &ct),
            base64::encode(Form::Url, &info),
            d.account,
            base64::encode(Form::Url, &sign::ed25519_sign(&seed, b"c1").unwrap())
        );
        let mut relabelled = wrap_record::make(
            k.kem_public_key(),
            &info,
            &[0x45; 32],
            *d.account.as_bytes(),
            k.identity_private_key(),
        )
        .unwrap();
        relabelled.suite = [32, 1, 2];
        for (what, body) in [
            ("classical", classical.into_bytes()),
            ("hybrid labelled [32,1,2]", wrap::to_json(&relabelled)),
        ] {
            let r = call(&s, "PUT", &part, "", &body).await;
            assert_eq!(r.status, 400, "{what}: {r:?}");
            call(&s, "GET", &part, "", b"")
                .await
                .assert_error(404, "not_found");
        }
    });
}

/// The record of `POST /v1/recovery/signin` for `nonce`, signed by the
/// recovery seed `seed` over `origin`, for the new device `key`.
fn recovery(
    seed: &larsal_crypto::secret::SecretBytes,
    origin: &str,
    account: &AccountId,
    nonce: &[u8; 32],
    key: &[u8; 65],
) -> RecoverySignIn {
    let message = signin::recovery_message(origin, nonce, account, key).unwrap();
    RecoverySignIn {
        account_id: *account,
        nonce: *nonce,
        device_public_key: *key,
        device_name: "Mac".to_owned(),
        signature: sign::ed25519_sign(seed, &message).unwrap(),
    }
}

async fn recovery_challenge(s: &Running, account: &AccountId) -> Reply {
    let body = RecoveryChallengeRequest {
        account_id: *account,
    }
    .to_json();
    exchange(s, &request("POST", "/v1/recovery/challenge", "", &body)).await
}

async fn recovery_sign_in(s: &Running, record: &RecoverySignIn) -> Reply {
    exchange(
        s,
        &request("POST", "/v1/recovery/signin", "", &record.to_json()),
    )
    .await
}

fn new_key() -> (P256TestKey, [u8; 65]) {
    let key = P256TestKey::new().unwrap();
    let public = key.public().try_into().unwrap();
    (key, public)
}

/// SYN-06.12, SYN-04.3, SYN-04.4, ruling (8): `POST /v1/recovery/challenge`
/// gives the same reply for an unknown account (200, a nonce valid 300 s).
/// `POST /v1/recovery/signin` checked with the stored recovery key
/// registers the new device and gives its session with its id (200); the
/// session works and the device then signs in with its own key. The nonce
/// is used once, by a failed try too; a changed byte of the signature,
/// another origin, another account's id, an unknown account, an account
/// with no keys and an expired nonce all get the one 401; a device's nonce
/// passes no recovery sign-in and a recovery nonce no device sign-in (LD-327
/// (7)); a key registered already gets 409, one that is not a P-256 point
/// 400.
#[test]
fn syn06_12_recovery_challenge_and_sign_in() {
    block_on(async {
        let (s, d) = strict().await;
        let (k, record) = account_keys(&d.account);
        assert_eq!(put_keys(&s, &record).await.status, 201);
        // The rest uses no session of the system clock.
        set_clock(&s, T0);
        let seed = recovery_seed(&k, &d.account);
        let o = origin(&s);

        // Same reply for an unknown account.
        let unknown = AccountId::from_bytes([0x77; 16]);
        for account in [d.account, unknown] {
            let r = recovery_challenge(&s, &account).await;
            assert_eq!(r.status, 200, "{r:?}");
            let c = Challenge::read(&r.body).unwrap();
            assert_eq!(c.expires, T0 + 300);
            assert_eq!(
                r.body.len(),
                Challenge {
                    nonce: [0; 32],
                    expires: T0 + 300
                }
                .to_json()
                .len()
            );
        }
        exchange(&s, &request("POST", "/v1/recovery/challenge", "", b"{}"))
            .await
            .assert_error(400, "bad_request");

        // Each failure: one 401, and the nonce is gone.
        let (_, key) = new_key();
        let nonce = |r: Reply| Challenge::read(&r.body).unwrap().nonce;
        let n = nonce(recovery_challenge(&s, &d.account).await);
        let mut bad = recovery(&seed, &o, &d.account, &n, &key);
        bad.signature[10] ^= 1;
        recovery_sign_in(&s, &bad).await.assert_unauthorized();
        recovery_sign_in(&s, &recovery(&seed, &o, &d.account, &n, &key))
            .await
            .assert_unauthorized();
        let n = nonce(recovery_challenge(&s, &d.account).await);
        let elsewhere = signin::origin("127.0.0.1", s.addr.port().wrapping_add(1));
        recovery_sign_in(&s, &recovery(&seed, &elsewhere, &d.account, &n, &key))
            .await
            .assert_unauthorized();
        let n = nonce(recovery_challenge(&s, &unknown).await);
        recovery_sign_in(&s, &recovery(&seed, &o, &unknown, &n, &key))
            .await
            .assert_unauthorized();
        let n = nonce(recovery_challenge(&s, &unknown).await);
        recovery_sign_in(&s, &recovery(&seed, &o, &d.account, &n, &key))
            .await
            .assert_unauthorized();
        let n = nonce(recovery_challenge(&s, &d.account).await);
        set_clock(&s, T0 + 300);
        recovery_sign_in(&s, &recovery(&seed, &o, &d.account, &n, &key))
            .await
            .assert_unauthorized();
        set_clock(&s, T0);
        // An account with keys row empty: no recovery key.
        let keyless = sign_up(&s).await;
        let n = nonce(recovery_challenge(&s, &keyless.account).await);
        recovery_sign_in(&s, &recovery(&seed, &o, &keyless.account, &n, &key))
            .await
            .assert_unauthorized();
        // LD-327 (7): the kinds stay apart.
        let device_nonce = challenge(&s, &d.id).await.nonce;
        recovery_sign_in(&s, &recovery(&seed, &o, &d.account, &device_nonce, &key))
            .await
            .assert_unauthorized();
        let n = nonce(recovery_challenge(&s, &d.account).await);
        let r = common::post_sign_in(&s, &signed(&d, &o, &n)).await;
        r.assert_unauthorized();
        // 400: not a P-256 point; a body that does not read.
        let n = nonce(recovery_challenge(&s, &d.account).await);
        let mut not_a_point = [0u8; 65];
        not_a_point[0] = 4;
        recovery_sign_in(&s, &recovery(&seed, &o, &d.account, &n, &not_a_point))
            .await
            .assert_error(400, "bad_request");
        exchange(&s, &request("POST", "/v1/recovery/signin", "", b"{}"))
            .await
            .assert_error(400, "bad_request");
        // 409: the key of a registered device.
        let taken: [u8; 65] = d.key.public().try_into().unwrap();
        let n = nonce(recovery_challenge(&s, &d.account).await);
        recovery_sign_in(&s, &recovery(&seed, &o, &d.account, &n, &taken))
            .await
            .assert_error(409, "conflict");

        // The good one.
        let (device_key, key) = new_key();
        let n = nonce(recovery_challenge(&s, &d.account).await);
        let good = recovery(&seed, &o, &d.account, &n, &key);
        let r = recovery_sign_in(&s, &good).await;
        assert_eq!(r.status, 200, "{r:?}");
        let made = Recovered::read(&r.body).unwrap();
        assert_eq!(made.session.idle_seconds, 15 * 60);
        assert_eq!(made.session.expires, T0 + 8 * 60 * 60);
        let auth = bearer(&made.session);
        let list = exchange(&s, &request("GET", "/v1/vaults", &auth, b"")).await;
        assert_eq!(list.status, 200, "the session works");
        recovery_sign_in(&s, &good).await.assert_unauthorized();
        let new = Device {
            key: device_key,
            id: made.device_id,
            account: d.account,
        };
        let session: Session = sign_in(&s, &new).await;
        assert_eq!(session.token.len(), 32);
    });
}

/// SYN-06.13, SYN-06 T15: no route, record or row of the server has an
/// email field: a full run (sign-up, keys, a signed upload, a key-file
/// part, a recovery sign-in) sends and gets no byte string `mail`, and no
/// file of the data folder (the store's schema is in it) holds one, in any
/// case.
#[test]
fn syn06_13_t15_no_email_in_any_route_record_or_row() {
    block_on(async {
        let (s, d) = strict().await;
        let (k, record) = account_keys(&d.account);
        assert_eq!(put_keys(&s, &record).await.status, 201);
        versions(&s, &k, &X, 2).await;
        let info = keypart_info(&d.account, &X).unwrap();
        let w = wrap_record::make(
            k.kem_public_key(),
            &info,
            b"demo part",
            *d.account.as_bytes(),
            k.identity_private_key(),
        )
        .unwrap();
        let part_path = format!("{}/keypart", path(&X));
        let r = exchange(&s, &request("PUT", &part_path, &s.auth, &wrap::to_json(&w))).await;
        assert_eq!(r.status, 204);
        let n = Challenge::read(&recovery_challenge(&s, &d.account).await.body)
            .unwrap()
            .nonce;
        let (_, key) = new_key();
        let seed = recovery_seed(&k, &d.account);
        let r = recovery_sign_in(&s, &recovery(&seed, &origin(&s), &d.account, &n, &key)).await;
        assert_eq!(r.status, 200);
        let mail = |hay: &[u8]| hay.windows(4).any(|w| w.eq_ignore_ascii_case(b"mail"));
        let sent = s.sent.lock().unwrap();
        assert!(sent.len() >= 8);
        for (request, reply) in sent.iter() {
            assert!(
                !mail(request),
                "{}",
                String::from_utf8_lossy(&request[..40])
            );
            assert!(!mail(&reply.body));
            assert!(
                reply
                    .headers
                    .iter()
                    .all(|(n, v)| !mail(n.as_bytes()) && !mail(v.as_bytes()))
            );
        }
        let mut dirs = vec![s.data.0.clone()];
        let (mut files, mut schema_seen) = (0, false);
        while let Some(dir) = dirs.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    dirs.push(p);
                } else {
                    files += 1;
                    let bytes = std::fs::read(&p).unwrap();
                    assert!(!mail(&bytes), "{}", p.display());
                    schema_seen |= bytes.windows(8).any(|w| w == b"keyparts");
                }
            }
        }
        assert!(files >= 3, "{files}");
        assert!(schema_seen, "the store's schema is in the searched bytes");
    });
}

/// SYN-01.12, SYN-01.4's 429 of the recovery routes: they are sign-in
/// routes, so with 3 sign-in requests a minute the 4th recovery challenge
/// gets 429 with `Retry-After`, `POST /v1/recovery/signin` counts in the
/// same bucket, and a new minute lets a challenge through again.
#[test]
fn syn01_12_the_recovery_routes_count_in_the_sign_in_bucket() {
    block_on(async {
        let rate = RateLimits {
            signin: 3,
            writes: 100,
            reads: 100,
        };
        let s = start_strict(Config {
            rate,
            ..Config::default()
        })
        .await;
        set_clock(&s, T0);
        let account = AccountId::from_bytes([0x77; 16]);
        for _ in 0..3 {
            assert_eq!(recovery_challenge(&s, &account).await.status, 200);
        }
        let r = recovery_challenge(&s, &account).await;
        r.assert_error(429, "rate_limited");
        assert_eq!(r.header("retry-after"), Some("60"));
        exchange(&s, &request("POST", "/v1/recovery/signin", "", b""))
            .await
            .assert_error(429, "rate_limited");
        set_clock(&s, T0 + 60);
        let r = recovery_challenge(&s, &account).await;
        assert_eq!(r.status, 200, "a new minute: {r:?}");
    });
}

/// Rows of `table` in the server's store, read beside the server.
fn rows(s: &Running, table: &str) -> i64 {
    rusqlite::Connection::open(s.data.0.join("store.sqlite"))
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

/// One approval request driven by raw HTTP for the edge cases: E is `d`
/// (signed in as `s.auth`, its account's keys `keys`), N a new key.
struct Approval {
    code: larsal_crypto::secret::SecretBytes,
    n: String,
    id: Id,
    key: P256TestKey,
    device: [u8; 65],
    seed: larsal_crypto::secret::SecretBytes,
    xwing: Vec<u8>,
    ctx: Vec<u8>,
    keys_c: Vec<u8>,
    n_c: [u8; 32],
    keys_r: Vec<u8>,
    n_r: [u8; 32],
}

fn nonce() -> [u8; 32] {
    larsal_crypto::random::bytes(32)
        .unwrap()
        .expose()
        .try_into()
        .unwrap()
}

impl Approval {
    /// Step 1 (201).
    async fn create(s: &Running, d: &Device, keys: &larsal_crypto::account::AccountKeys) -> Self {
        let code = larsal_crypto::random::bytes(approval::CODE_BYTES).unwrap();
        let body = ApprovalCreate {
            code_hash: approval::code_hash(&code).unwrap(),
        };
        let r = call(s, "POST", "/v1/approvals", "", &body.to_json()).await;
        assert_eq!(r.status, 201, "{r:?}");
        let start = ApprovalStart::read(&r.body).unwrap();
        let key = P256TestKey::new().unwrap();
        let device: [u8; 65] = key.public().try_into().unwrap();
        let (seed, xwing) = pq::xwing_keypair().unwrap();
        let keys_c = approval::keys_c(&device, &xwing).unwrap();
        let mine: [u8; 65] = d.key.public().try_into().unwrap();
        Self {
            n: approval_line(&code),
            code,
            id: start.approval_id,
            key,
            device,
            seed,
            xwing,
            ctx: approval::ctx(&d.account, &start.approval_id).unwrap(),
            keys_c,
            n_c: nonce(),
            keys_r: approval::keys_r(keys.identity_public_key(), &mine).unwrap(),
            n_r: nonce(),
        }
    }

    fn path(&self, tail: &str) -> String {
        format!("/v1/approvals/{}{tail}", self.id)
    }

    async fn as_n(&self, s: &Running, method: &str, tail: &str, body: &[u8]) -> Reply {
        exchange(s, &request(method, &self.path(tail), &self.n, body)).await
    }

    async fn claim(&self, s: &Running) -> Reply {
        let body = ApprovalClaim {
            device_public_key: self.device,
            device_name: "New Mac".to_owned(),
        };
        exchange(
            s,
            &request("POST", "/v1/approvals/claim", &self.n, &body.to_json()),
        )
        .await
    }

    fn commitment(&self) -> [u8; 32] {
        approval::commitment(&self.ctx, &self.keys_c, &self.n_c)
            .unwrap()
            .expose()
            .try_into()
            .unwrap()
    }

    async fn commit(&self, s: &Running) -> Reply {
        let body = CompareCommit {
            commit: self.commitment(),
        };
        self.as_n(s, "POST", "/commit", &body.to_json()).await
    }

    async fn keys(&self, s: &Running) -> Reply {
        let body = CompareKeys {
            keys: self.keys_r.clone(),
            nonce: self.n_r,
        };
        call(s, "POST", &self.path("/keys"), "", &body.to_json()).await
    }

    async fn reveal(&self, s: &Running) -> Reply {
        let body = CompareKeys {
            keys: self.keys_c.clone(),
            nonce: self.n_c,
        };
        self.as_n(s, "POST", "/reveal", &body.to_json()).await
    }

    /// E's seal of `S_acct` and its device signature, made with `keys`.
    fn seal_body(&self, d: &Device, keys: &larsal_crypto::account::AccountKeys) -> ApprovalSeal {
        let info = approval::seal_info(&d.account, &self.id, &self.device).unwrap();
        let seal = wrap_record::make(
            &self.xwing,
            &info,
            keys.account_secret().expose(),
            *d.account.as_bytes(),
            keys.identity_private_key(),
        )
        .unwrap();
        let message = approval::device_message(&d.account, &self.device, &self.id).unwrap();
        ApprovalSeal {
            seal,
            device_signature: pq::composite_sign(keys.identity_private_key(), &message).unwrap(),
        }
    }

    async fn seal(&self, s: &Running, body: &ApprovalSeal) -> Reply {
        call(s, "POST", &self.path("/seal"), "", &body.to_json()).await
    }

    /// Steps 2 to 4 (the claim, the commitment, `K_R` and the reveal).
    async fn to_reveal(&self, s: &Running) {
        assert_eq!(self.claim(s).await.status, 201);
        assert_eq!(self.commit(s).await.status, 204);
        assert_eq!(self.keys(s).await.status, 204);
        assert_eq!(self.reveal(s).await.status, 204);
    }
}

/// A strict server with one signed-in account E that has its keys.
async fn with_keys() -> (Running, Device, larsal_crypto::account::AccountKeys) {
    let (s, d) = strict().await;
    let (keys, record) = account_keys(&d.account);
    assert_eq!(put_keys(&s, &record).await.status, 201);
    (s, d, keys)
}

/// SYN-06 T09 (server half), T19's approval half, SYN-05 T09 (rows), and
/// ruling (6): through SYN-06.11 by raw HTTP, no device row exists before
/// E's seal (the store is read after every step); the seal is a
/// `[25722, 1, 3]` record with a 3,373-byte composite signature that N
/// opens with the info it builds itself; N's read takes it and the row
/// goes (no nonce, commitment or key list left); N signs in with its new
/// device key. Ruling (10)'s proxy view: `POST /v1/approvals` carries only
/// the code's SHA-256, and the code, in any form, is only in the
/// `Authorization` line of N's routes.
#[test]
fn syn06_11_t09_t19_n_is_registered_only_after_e_seals() {
    block_on(async {
        let (s, d, keys) = with_keys().await;
        let devices = rows(&s, "devices");
        let seen = std::cell::RefCell::new(Vec::new());
        let n = second_device_with(&s, &d, &keys, &|step| {
            let want = if matches!(step, "seal" | "taken") {
                devices + 1
            } else {
                devices
            };
            assert_eq!(rows(&s, "devices"), want, "after {step}");
            let left = if step == "taken" { 0 } else { 1 };
            assert_eq!(rows(&s, "approvals"), left, "after {step}");
            seen.borrow_mut().push(step);
        })
        .await;
        assert_eq!(
            *seen.borrow(),
            [
                "create", "claim", "commit", "keys", "reveal", "seal", "taken"
            ]
        );
        let session = sign_in(&s, &n).await;
        assert_eq!(session.idle_seconds, 900);
        // The seal N took: CRY-05.4's record, a composite signature.
        let sent = s.sent.lock().unwrap().clone();
        let taken = sent
            .iter()
            .filter(|(q, r)| q.starts_with(b"GET /v1/approvals/") && r.status == 200)
            .filter_map(|(_, r)| ApprovalState::read(&r.body).unwrap().seal)
            .next_back()
            .unwrap();
        let record = wrap::read(&taken.0).unwrap();
        assert_eq!(record.suite, [25722, 1, 3]);
        assert_eq!(record.signature.len(), 3373);
        assert_eq!(taken.1, n.id);
        // The proxy view: the create body is the code's SHA-256 only, and
        // no form of the code is anywhere but N's Authorization line.
        let claim = sent
            .iter()
            .find(|(q, _)| q.starts_with(b"POST /v1/approvals/claim "))
            .unwrap();
        let claim = String::from_utf8_lossy(&claim.0).into_owned();
        let typed = claim
            .split("\r\n")
            .find_map(|l| l.strip_prefix("Authorization: Approval "))
            .unwrap()
            .to_owned();
        let code = approval::read_code(&typed).unwrap();
        let hex: String = code.expose().iter().map(|b| format!("{b:02x}")).collect();
        let forms = [
            code.expose().to_vec(),
            typed.clone().into_bytes(),
            typed.to_ascii_lowercase().into_bytes(),
            hex.clone().into_bytes(),
            hex.to_ascii_uppercase().into_bytes(),
            base64::encode(Form::Url, code.expose()).into_bytes(),
            base64::encode(Form::Padded, code.expose()).into_bytes(),
        ];
        let holds = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        for (q, r) in &sent {
            let text = String::from_utf8_lossy(q);
            let rest: Vec<&str> = text
                .split("\r\n")
                .filter(|l| !l.starts_with("Authorization: Approval "))
                .collect();
            let rest = rest.join("\r\n");
            for form in &forms {
                assert!(
                    !holds(rest.as_bytes(), form),
                    "{}",
                    text.lines().next().unwrap()
                );
                assert!(!holds(&r.body, form), "{}", text.lines().next().unwrap());
            }
        }
        let create = sent
            .iter()
            .find(|(q, _)| q.starts_with(b"POST /v1/approvals HTTP"))
            .unwrap();
        let body_at = create.0.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let sent_hash = ApprovalCreate::read(&create.0[body_at..])
            .unwrap()
            .code_hash;
        assert_eq!(sent_hash, approval::code_hash(&code).unwrap());
        for (q, _) in &sent {
            let text = String::from_utf8_lossy(q);
            for line in text.split("\r\n") {
                if let Some(code) = line.strip_prefix("Authorization: Approval ") {
                    assert_eq!(code.len(), 26);
                    assert!(
                        text.starts_with("POST /v1/approvals/claim ")
                            || text.contains("/commit ")
                            || text.contains("/reveal ")
                            || text.starts_with("GET /v1/approvals/"),
                        "{}",
                        text.lines().next().unwrap()
                    );
                }
            }
        }
    });
}

/// SYN-05 T05, SYN-06 T11 (the claim and the commitment twice): a second
/// claim gets 409 and ends the request (the commitment then gets 401); a
/// second commitment gets 409 and ends it too (N's read then gets 401);
/// a second request with a code hash already in use gets 409.
#[test]
fn syn05_t05_syn06_11_t11_one_claim_and_one_commitment() {
    block_on(async {
        let (s, d, keys) = with_keys().await;
        let a = Approval::create(&s, &d, &keys).await;
        assert_eq!(a.claim(&s).await.status, 201);
        let r = a.claim(&s).await;
        r.assert_error(409, "conflict");
        assert_eq!(rows(&s, "approvals"), 0, "the request ended");
        assert_eq!(a.commit(&s).await.status, 401);

        let b = Approval::create(&s, &d, &keys).await;
        assert_eq!(b.claim(&s).await.status, 201);
        assert_eq!(b.commit(&s).await.status, 204);
        let mut other = Approval::create(&s, &d, &keys).await;
        other.n = b.n.clone();
        other.id = b.id;
        other.n_c = nonce();
        other.commit(&s).await.assert_error(409, "conflict");
        assert_eq!(b.as_n(&s, "GET", "", b"").await.status, 401);
        assert_eq!(rows(&s, "approvals"), 1, "the third request only");

        let same = ApprovalCreate {
            code_hash: approval::code_hash(&other.code).unwrap(),
        };
        call(&s, "POST", "/v1/approvals", "", &same.to_json())
            .await
            .assert_error(409, "conflict");
    });
}

/// SYN-05 T06 and SYN-05.2: a message out of its order gets 409 and ends
/// the request: the commitment before the claim, `K_R` before the
/// commitment, the reveal before `K_R`, the seal before the reveal.
#[test]
fn syn05_t06_a_message_out_of_order_ends_the_request() {
    block_on(async {
        let (s, d, keys) = with_keys().await;
        let a = Approval::create(&s, &d, &keys).await;
        a.commit(&s).await.assert_error(409, "conflict");
        assert_eq!(rows(&s, "approvals"), 0);
        let a = Approval::create(&s, &d, &keys).await;
        assert_eq!(a.claim(&s).await.status, 201);
        a.keys(&s).await.assert_error(409, "conflict");
        assert_eq!(rows(&s, "approvals"), 0);
        let a = Approval::create(&s, &d, &keys).await;
        assert_eq!(a.claim(&s).await.status, 201);
        assert_eq!(a.commit(&s).await.status, 204);
        a.reveal(&s).await.assert_error(409, "conflict");
        assert_eq!(rows(&s, "approvals"), 0);
        let a = Approval::create(&s, &d, &keys).await;
        assert_eq!(a.claim(&s).await.status, 201);
        assert_eq!(a.commit(&s).await.status, 204);
        assert_eq!(a.keys(&s).await.status, 204);
        let devices = rows(&s, "devices");
        a.seal(&s, &a.seal_body(&d, &keys))
            .await
            .assert_error(409, "conflict");
        assert_eq!((rows(&s, "approvals"), rows(&s, "devices")), (0, devices));
    });
}

/// SYN-06 T11 (expired) and ruling (9): each route of a request made at T0
/// gets 401 at T0 + 15 min 1 s (the claim, the commitment, `K_R`, the
/// reveal, and N's `GET` and `DELETE` by the code) or 404 (the seal, as
/// SYN-06's edge case says, and E's `GET` and `DELETE` by its session),
/// the row goes and no device is registered; at T0 + 14 min 59 s the same
/// route passes.
#[test]
fn syn06_11_t11_a_request_older_than_15_minutes_is_refused() {
    block_on(async {
        let (mut s, d, keys) = with_keys().await;
        let devices = rows(&s, "devices");
        for stage in 0..9 {
            for (at, live) in [(T0 + 899, true), (T0 + 901, false)] {
                // A session live at each clock time, so only the request's
                // own 15 minutes decide.
                set_clock(&s, T0);
                s.auth = bearer(&sign_in(&s, &d).await);
                let a = Approval::create(&s, &d, &keys).await;
                if stage > 0 {
                    assert_eq!(a.claim(&s).await.status, 201);
                }
                if stage > 1 {
                    assert_eq!(a.commit(&s).await.status, 204);
                }
                if stage > 2 {
                    assert_eq!(a.keys(&s).await.status, 204);
                }
                if stage > 3 {
                    assert_eq!(a.reveal(&s).await.status, 204);
                }
                set_clock(&s, at);
                s.auth = bearer(&sign_in(&s, &d).await);
                let r = match stage {
                    0 => a.claim(&s).await,
                    1 => a.commit(&s).await,
                    2 => a.keys(&s).await,
                    3 => a.reveal(&s).await,
                    4 => a.seal(&s, &a.seal_body(&d, &keys)).await,
                    5 => a.as_n(&s, "GET", "", b"").await,
                    6 => a.as_n(&s, "DELETE", "", b"").await,
                    7 => call(&s, "GET", &a.path(""), "", b"").await,
                    _ => call(&s, "DELETE", &a.path(""), "", b"").await,
                };
                if live {
                    assert!(matches!(r.status, 200 | 201 | 204), "stage {stage}: {r:?}");
                    call(&s, "DELETE", &a.path(""), "", b"").await;
                } else {
                    let want = if matches!(stage, 4 | 7 | 8) { 404 } else { 401 };
                    assert_eq!(r.status, want, "stage {stage}: {r:?}");
                    assert_eq!(rows(&s, "approvals"), 0, "stage {stage}: the row went");
                }
                assert_eq!(rows(&s, "devices"), devices, "stage {stage}");
            }
        }
    });
}

/// SYN-06 T12 (the server's own check): a seal whose device signature is
/// by another identity key, or over another device, gets 403, ends the
/// request and registers nothing; an account with no keys row gets 403
/// too. SYN-06 T19 (server half): a seal record of another suite
/// ([32, 1, 2]) gets 400 and the request stays for the right one.
#[test]
fn syn06_11_t12_t19_the_server_registers_only_a_device_the_identity_key_signed() {
    block_on(async {
        let (s, d, keys) = with_keys().await;
        let devices = rows(&s, "devices");
        let a = Approval::create(&s, &d, &keys).await;
        a.to_reveal(&s).await;
        let (other, _) = account_keys(&d.account);
        let mut forged = a.seal_body(&d, &keys);
        let message = approval::device_message(&d.account, &a.device, &a.id).unwrap();
        forged.device_signature =
            pq::composite_sign(other.identity_private_key(), &message).unwrap();
        a.seal(&s, &forged).await.assert_error(403, "forbidden");
        assert_eq!((rows(&s, "approvals"), rows(&s, "devices")), (0, devices));

        let a = Approval::create(&s, &d, &keys).await;
        a.to_reveal(&s).await;
        let mut wrong = a.seal_body(&d, &keys);
        let message = approval::device_message(&d.account, &[4; 65], &a.id).unwrap();
        wrong.device_signature = pq::composite_sign(keys.identity_private_key(), &message).unwrap();
        a.seal(&s, &wrong).await.assert_error(403, "forbidden");
        assert_eq!((rows(&s, "approvals"), rows(&s, "devices")), (0, devices));

        let a = Approval::create(&s, &d, &keys).await;
        a.to_reveal(&s).await;
        let mut classical = a.seal_body(&d, &keys);
        classical.seal.suite = [32, 1, 2];
        a.seal(&s, &classical)
            .await
            .assert_error(400, "bad_request");
        assert_eq!(rows(&s, "approvals"), 1, "a 400 leaves the request");
        let r = a.seal(&s, &a.seal_body(&d, &keys)).await;
        assert_eq!(r.status, 204, "{r:?}");
        assert_eq!(rows(&s, "devices"), devices + 1);
        // N takes the seal, opens it with its own info and signs in.
        let r = a.as_n(&s, "GET", "", b"").await;
        assert_eq!(r.status, 200, "{r:?}");
        let (sealed, id) = ApprovalState::read(&r.body).unwrap().seal.unwrap();
        let record = wrap::read(&sealed).unwrap();
        assert_eq!(record.suite, [25722, 1, 3]);
        let info = approval::seal_info(&d.account, &a.id, &a.device).unwrap();
        let opened =
            wrap_record::open(&record, keys.identity_public_key(), &info, &a.seed).unwrap();
        assert_eq!(opened.expose(), keys.account_secret().expose());
        assert_eq!(rows(&s, "approvals"), 0, "taken");
        let n = Device {
            key: a.key,
            id,
            account: d.account,
        };
        assert_eq!(sign_in(&s, &n).await.idle_seconds, 900);

        // An account with no keys row: 403, nothing registered.
        let (t, e) = strict().await;
        let none = rows(&t, "devices");
        let b = Approval::create(&t, &e, &keys).await;
        b.to_reveal(&t).await;
        b.seal(&t, &b.seal_body(&e, &keys))
            .await
            .assert_error(403, "forbidden");
        assert_eq!((rows(&t, "approvals"), rows(&t, "devices")), (0, none));
    });
}

/// SYN-05 T08 and SYN-05.6 on the server: Codes differ on N after E's seal
/// (N's `DELETE` by code) ends the request and removes the device the seal
/// registered; on E (`DELETE` by session) before the seal, the row goes.
/// Then the code and the id name nothing: 401 and 404.
#[test]
fn syn05_t08_codes_differ_ends_the_request_and_registers_nothing() {
    block_on(async {
        let (s, d, keys) = with_keys().await;
        let devices = rows(&s, "devices");
        let a = Approval::create(&s, &d, &keys).await;
        a.to_reveal(&s).await;
        assert_eq!(a.seal(&s, &a.seal_body(&d, &keys)).await.status, 204);
        assert_eq!(rows(&s, "devices"), devices + 1);
        assert_eq!(a.as_n(&s, "DELETE", "", b"").await.status, 204);
        assert_eq!((rows(&s, "approvals"), rows(&s, "devices")), (0, devices));
        assert_eq!(a.as_n(&s, "GET", "", b"").await.status, 401);

        let b = Approval::create(&s, &d, &keys).await;
        assert_eq!(b.claim(&s).await.status, 201);
        assert_eq!(b.commit(&s).await.status, 204);
        let r = call(&s, "DELETE", &b.path(""), "", b"").await;
        assert_eq!(r.status, 204, "{r:?}");
        assert_eq!(rows(&s, "approvals"), 0);
        call(&s, "GET", &b.path(""), "", b"")
            .await
            .assert_error(404, "not_found");
        assert_eq!(b.as_n(&s, "DELETE", "", b"").await.status, 401);
    });
}

/// Every status of the approval routes not reached above: 400 for records
/// that do not read (and a device key that is not a P-256 point), 401
/// without a session or code (and with `WWW-Authenticate: Approval` for
/// the code routes), 404 for a code of another request and for another
/// account's request.
#[test]
fn syn06_11_every_approval_route_status() {
    block_on(async {
        let (mut s, d, keys) = with_keys().await;
        let a = Approval::create(&s, &d, &keys).await;
        let b = Approval::create(&s, &d, &keys).await;
        // 400.
        call(&s, "POST", "/v1/approvals", "", b"{}")
            .await
            .assert_error(400, "bad_request");
        let not_a_point = ApprovalClaim {
            device_public_key: [4; 65],
            device_name: "New Mac".to_owned(),
        };
        exchange(
            &s,
            &request("POST", "/v1/approvals/claim", &a.n, &not_a_point.to_json()),
        )
        .await
        .assert_error(400, "bad_request");
        assert_eq!(a.claim(&s).await.status, 201);
        a.as_n(&s, "POST", "/commit", b"{}")
            .await
            .assert_error(400, "bad_request");
        assert_eq!(a.commit(&s).await.status, 204);
        let short = CompareKeys {
            keys: vec![1; 10],
            nonce: [2; 32],
        };
        call(&s, "POST", &a.path("/keys"), "", &short.to_json())
            .await
            .assert_error(400, "bad_request");
        assert_eq!(a.keys(&s).await.status, 204);
        a.as_n(&s, "POST", "/reveal", &short.to_json())
            .await
            .assert_error(400, "bad_request");
        // 404: the code is another request's.
        let mut cross = Approval::create(&s, &d, &keys).await;
        cross.id = a.id;
        cross.n = b.n.clone();
        cross.reveal(&s).await.assert_error(404, "not_found");
        cross
            .as_n(&s, "GET", "", b"")
            .await
            .assert_error(404, "not_found");
        cross.commit(&s).await.assert_error(404, "not_found");
        cross
            .as_n(&s, "DELETE", "", b"")
            .await
            .assert_error(404, "not_found");
        assert_eq!(a.reveal(&s).await.status, 204);
        call(&s, "POST", &a.path("/seal"), "", b"{}")
            .await
            .assert_error(400, "bad_request");
        // 404: another account's request.
        let other = sign_up(&s).await;
        let theirs = bearer(&sign_in(&s, &other).await);
        let mine = std::mem::replace(&mut s.auth, theirs);
        let keys_body = CompareKeys {
            keys: a.keys_r.clone(),
            nonce: a.n_r,
        }
        .to_json();
        let seal_body = a.seal_body(&d, &keys).to_json();
        for (method, tail, body) in [
            ("GET", "", Vec::new()),
            ("POST", "/keys", keys_body),
            ("POST", "/seal", seal_body),
            ("DELETE", "", Vec::new()),
        ] {
            call(&s, method, &a.path(tail), "", &body)
                .await
                .assert_error(404, "not_found");
        }
        s.auth = mine;
        assert_eq!(call(&s, "GET", &a.path(""), "", b"").await.status, 200);
        // 401: no session, no code, a malformed code.
        let keep = std::mem::take(&mut s.auth);
        for (method, path) in [
            ("POST", "/v1/approvals".to_owned()),
            ("POST", a.path("/keys")),
            ("POST", a.path("/seal")),
            ("GET", a.path("")),
            ("DELETE", a.path("")),
        ] {
            call(&s, method, &path, "", b"{}")
                .await
                .assert_unauthorized();
        }
        for line in [
            "",
            "Authorization: Approval AAAA\r\n",
            "Authorization: Approval aaaqeayeaudaocajbifqydiob4\r\n",
        ] {
            let r = exchange(&s, &request("POST", "/v1/approvals/claim", line, b"{}")).await;
            r.assert_error(401, "unauthorized");
            assert_eq!(r.header("www-authenticate"), Some("Approval"));
            let r = exchange(&s, &request("POST", &a.path("/commit"), line, b"{}")).await;
            assert_eq!(r.status, 401);
        }
        s.auth = keep;
    });
}

/// SYN-01.12 (ruling (4)): the claim counts in the sign-in bucket (10 a
/// minute per address in the card; here a limit of 3): after 3 claims, the
/// fourth gets 429 with `Retry-After`, whatever its code, and so does a
/// sign-in challenge; in the next minute a challenge and 2 claims fill it.
#[test]
fn syn01_12_the_claim_counts_in_the_sign_in_bucket() {
    block_on(async {
        let rate = RateLimits {
            signin: 3,
            writes: 1000,
            reads: 1000,
        };
        let s = start_strict(Config {
            rate,
            ..Config::default()
        })
        .await;
        set_clock(&s, T0);
        let code = larsal_crypto::random::bytes(approval::CODE_BYTES).unwrap();
        let line = approval_line(&code);
        for _ in 0..3 {
            let r = exchange(&s, &request("POST", "/v1/approvals/claim", &line, b"{}")).await;
            assert_eq!(r.status, 400, "{r:?}");
        }
        let r = exchange(&s, &request("POST", "/v1/approvals/claim", &line, b"{}")).await;
        r.assert_error(429, "rate_limited");
        assert!(r.header("retry-after").is_some());
        // The same bucket: the claims leave no sign-in challenge this minute,
        // and a new minute takes a challenge and a claim again.
        let ask = larsal_proto::messages::ChallengeRequest {
            device_id: larsal_proto::messages::DeviceId::from_bytes([9; 16]),
        }
        .to_json();
        exchange(&s, &request("POST", "/v1/signin/challenge", "", &ask))
            .await
            .assert_error(429, "rate_limited");
        set_clock(&s, T0 + 60);
        let r = exchange(&s, &request("POST", "/v1/signin/challenge", "", &ask)).await;
        assert_eq!(r.status, 200, "{r:?}");
        for _ in 0..2 {
            let r = exchange(&s, &request("POST", "/v1/approvals/claim", &line, b"{}")).await;
            assert_eq!(r.status, 400, "{r:?}");
        }
        exchange(&s, &request("POST", "/v1/approvals/claim", &line, b"{}"))
            .await
            .assert_error(429, "rate_limited");
    });
}
