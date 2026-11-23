//! SYN-06 checks of E17-S1 on the server's side: the account keys routes
//! (SYN-06.6), the upload signature (SYN-01.7, SYN-01 T12), the key-file
//! part routes (SYN-06.9), the recovery sign-in (SYN-06.12) and no email
//! anywhere (SYN-06.13, T15), against a release server's rule: every server
//! here is strict (`start_strict`), so no upload passes unsigned. The keys
//! are larsal-crypto's; the blob is demo bytes the server never reads. Every
//! client connects to 127.0.0.1 only; expiry runs on the test clock.

mod common;

use common::{
    Device, Reply, Running, account_keys, bearer, block_on, challenge, exchange, origin, put_keys,
    recovery_seed, request, set_clock, sign_in, sign_up, signed, start_strict, upload_header,
};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::sign::P256TestKey;
use larsal_crypto::{pq, sign, wrap_record};
use larsal_proto::account::{
    AccountKeys, Recovered, RecoveryChallengeRequest, RecoverySignIn, keypart_info, upload_message,
};
use larsal_proto::messages::{AccountId, Challenge, Session, VaultId};
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
        // CRY-05.7: a classical suite's record is refused before it is stored.
        let mut classical = second.clone();
        classical.suite = [0x0020, 0x0001, 0x0003];
        send(&s, &part_path, wrap::to_json(&classical))
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
