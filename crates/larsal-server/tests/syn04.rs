//! SYN-04 checks of E16-S5 (accounts, the one-time challenge, the signature
//! check, sessions, revoke), SYN-01.5's bad tokens, SYN-01.6's other
//! account, SYN-01.8's records, SYN-01.12's rate limits and SYN-01.13's
//! quiet log, against a server on 127.0.0.1:0 with a fresh data folder.
//! The client is the test client of `common`, with a software P-256 key
//! from larsal-crypto. Expiry runs on the server's test clock, never by
//! waiting. Every client connects to 127.0.0.1 only.

mod common;

use common::{
    Device, Reply, Running, Scratch, bearer, block_on, challenge, exchange, origin, post_sign_in,
    read_all, request, scratch, second_device, set_clock, sign_in, sign_up, signed, start,
    start_bare, tls,
};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::sign::P256TestKey;
use larsal_proto::limits::MAX_SIGNATURE;
use larsal_proto::messages::{AccountCreate, AccountCreated, ChallengeRequest, DeviceId, SignIn};
use larsal_proto::signin;
use larsal_server::http::{Config, RateLimits};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::version;

/// A second on the test clock: 2027-01-15.
const T0: u64 = 1_800_000_000;

/// SYN-01.12's limits with `signin` sign-in requests a minute.
fn signin_limit(signin: u32) -> Config {
    Config {
        rate: RateLimits {
            signin,
            ..RateLimits::default()
        },
        ..Config::default()
    }
}

/// Reads the server's store with a second connection (reads only).
fn store(s: &Running) -> rusqlite::Connection {
    rusqlite::Connection::open(s.data.0.join("store.sqlite")).unwrap()
}

fn count(s: &Running, table: &str) -> i64 {
    store(s)
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

/// `GET /v1/vaults` with the `Authorization` line `auth`.
async fn vaults(s: &Running, auth: &str) -> Reply {
    exchange(s, &request("GET", "/v1/vaults", auth, b"")).await
}

/// `DELETE /v1/devices/{device}` with `auth`.
async fn revoke(s: &Running, auth: &str, device: &DeviceId) -> Reply {
    let path = format!("/v1/devices/{device}");
    exchange(s, &request("DELETE", &path, auth, b"")).await
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    larsal_crypto::hash::sha256(&[bytes]).expose().to_vec()
}

/// Every file under `dir`, read whole.
fn every_file(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut all = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(p) = todo.pop() {
        for entry in std::fs::read_dir(&p).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                todo.push(path);
            } else {
                all.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    all
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// T02: 201 with two ids; the same key again 409 with no row made; a name
/// outside 1 to 64 scalar values or with a Cc character 400 with no row
/// made; 64 ASCII letters and 64 "ä" (128 bytes) 201.
#[test]
fn syn04_2_t02_new_account_duplicate_key_and_device_names() {
    block_on(async {
        let s = start_bare(signin_limit(100)).await;
        let key = P256TestKey::new().unwrap();
        let record = |key: &P256TestKey, name: &str| {
            AccountCreate {
                device_public_key: key.public().try_into().unwrap(),
                device_name: name.to_owned(),
            }
            .to_json()
        };
        let post = |body: Vec<u8>| {
            let s = &s;
            async move { exchange(s, &request("POST", "/v1/accounts", "", &body)).await }
        };
        let r = post(record(&key, "Mac")).await;
        assert_eq!(r.status, 201, "{r:?}");
        assert_eq!(r.header("cache-control"), Some("no-store"));
        let made = AccountCreated::read(&r.body).unwrap();
        let want = format!(
            r#"{{"account_id":"{}","device_id":"{}"}}"#,
            made.account_id, made.device_id
        );
        assert_eq!(r.body, want.as_bytes());
        assert_ne!(made.account_id, made.device_id);
        assert_eq!((count(&s, "accounts"), count(&s, "devices")), (1, 1));

        post(record(&key, "Mac 2"))
            .await
            .assert_error(409, "conflict");
        assert_eq!((count(&s, "accounts"), count(&s, "devices")), (1, 1));

        for name in [
            String::new(),
            "a".repeat(65),
            "Ma\u{7}c".to_owned(),
            "Mac\n".to_owned(),
            "ä".repeat(65),
        ] {
            let r = post(record(&P256TestKey::new().unwrap(), &name)).await;
            r.assert_error(400, "bad_request");
            assert_eq!(
                (count(&s, "accounts"), count(&s, "devices")),
                (1, 1),
                "{name:?}"
            );
        }
        for name in ["a".repeat(64), "ä".repeat(64)] {
            let r = post(record(&P256TestKey::new().unwrap(), &name)).await;
            assert_eq!(r.status, 201, "{name:?}");
        }
        assert_eq!((count(&s, "accounts"), count(&s, "devices")), (3, 3));
        // A key that is not a P-256 point could never sign in (CRY-04.4).
        let mut bad = record(&P256TestKey::new().unwrap(), "Mac");
        let text = String::from_utf8(bad.clone()).unwrap();
        let k = base64::encode(Form::Url, &[4; 65]);
        let start = text.find(r#""device_public_key":""#).unwrap() + 21;
        bad.splice(start..start + k.len(), k.bytes());
        post(bad).await.assert_error(400, "bad_request");
        assert_eq!(count(&s, "accounts"), 3);
    });
}

/// T03: a challenge for a device that exists and for one that does not
/// get replies of the same fields and sizes, and both are stored, so the
/// work is the same too. Their sign-ins (d1 with a wrong signature, d9
/// with any) get the same 401, and both nonces are gone.
#[test]
fn syn04_3_t03_challenge_for_unknown_device_looks_the_same() {
    block_on(async {
        let s = start_bare(Config::default()).await;
        set_clock(&s, T0);
        let d1 = sign_up(&s).await;
        let d9 = DeviceId::from_bytes([9; 16]);
        let ask = |id: DeviceId| {
            let body = ChallengeRequest { device_id: id }.to_json();
            request("POST", "/v1/signin/challenge", "", &body)
        };
        let known = exchange(&s, &ask(d1.id)).await;
        let unknown = exchange(&s, &ask(d9)).await;
        let names = |r: &Reply| -> Vec<String> { r.headers.iter().map(|h| h.0.clone()).collect() };
        assert_eq!((known.status, unknown.status), (200, 200));
        assert_eq!(names(&known), names(&unknown));
        assert_eq!(
            known.header("content-length"),
            unknown.header("content-length")
        );
        assert_eq!(known.body.len(), unknown.body.len());
        let (a, b) = (
            larsal_proto::messages::Challenge::read(&known.body).unwrap(),
            larsal_proto::messages::Challenge::read(&unknown.body).unwrap(),
        );
        assert_eq!((a.expires, b.expires), (T0 + 300, T0 + 300));
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(count(&s, "challenges"), 2, "stored for d9 too");

        let mut wrong = signed(&d1, &origin(&s), &a.nonce);
        wrong.signature = signed(&d1, &origin(&s), &b.nonce).signature;
        let other = sign_up(&s).await;
        let mut d9_in = signed(&other, &origin(&s), &b.nonce);
        d9_in.device_id = d9;
        let r1 = post_sign_in(&s, &wrong).await;
        let r9 = post_sign_in(&s, &d9_in).await;
        r1.assert_unauthorized();
        r9.assert_unauthorized();
        assert_eq!((names(&r1), &r1.body), (names(&r9), &r9.body));
        assert_eq!(count(&s, "challenges"), 0, "both nonces used");
    });
}

/// T04, SV-03: a valid sign-in gets 200 with a 43-character token of 32
/// bytes; the `sessions` row holds only its SHA-256, and no file of the
/// data folder holds the token. Each sign-in draws a new token.
#[test]
fn syn04_4_t04_valid_sign_in_stores_only_the_tokens_sha256() {
    block_on(async {
        let s = start_bare(Config::default()).await;
        set_clock(&s, T0);
        let d1 = sign_up(&s).await;
        let c = challenge(&s, &d1.id).await;
        let r = post_sign_in(&s, &signed(&d1, &origin(&s), &c.nonce)).await;
        assert_eq!(r.status, 200, "{r:?}");
        assert_eq!(r.header("cache-control"), Some("no-store"));
        let session = larsal_proto::messages::Session::read(&r.body).unwrap();
        let token = session.token.expose().to_vec();
        let text = base64::encode(Form::Url, &token);
        assert_eq!((token.len(), text.len()), (32, 43));
        let want = format!(
            r#"{{"expires":{},"idle_seconds":900,"token":"{text}"}}"#,
            T0 + 8 * 3600
        );
        assert_eq!(r.body, want.as_bytes());

        let rows: Vec<(Vec<u8>, Vec<u8>, i64, i64)> = store(&s)
            .prepare("SELECT hash, device, created, last_used FROM sessions")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let t0 = i64::try_from(T0).unwrap();
        assert_eq!(rows, [(sha256(&token), d1.id.as_bytes().to_vec(), t0, t0)]);
        for (path, bytes) in every_file(&s.data.0) {
            assert!(!holds(&bytes, &token), "{path:?}");
            assert!(!holds(&bytes, text.as_bytes()), "{path:?}");
        }
        let auth = bearer(&session);
        assert_eq!(vaults(&s, &auth).await.status, 200);

        let again = sign_in(&s, &d1).await;
        assert_ne!(again.token.expose(), token.as_slice(), "a new token");
        assert_eq!(count(&s, "sessions"), 2);
        assert_eq!(count(&s, "challenges"), 0, "each nonce used once");
    });
}

/// T05, AT-L07: a reused nonce, another device's nonce, another origin,
/// another device id with this signature, one changed byte of the
/// signature or of the message, and a nonce 300 or 301 s old: 401 each
/// time, with the same reply; every nonce named is gone.
#[test]
fn syn04_4_t05_each_failure_gets_the_same_401() {
    block_on(async {
        let s = start_bare(signin_limit(100)).await;
        set_clock(&s, T0);
        let d1 = sign_up(&s).await;
        let d2 = second_device(&s, &d1.account);
        let o = origin(&s);
        let port = s.addr.port();
        let mut refused = Vec::new();

        // A reused nonce: the first sign-in passes, the same record fails.
        let c = challenge(&s, &d1.id).await;
        let record = signed(&d1, &o, &c.nonce);
        assert_eq!(post_sign_in(&s, &record).await.status, 200);
        refused.push(post_sign_in(&s, &record).await);

        // d2's nonce, signed by d1 for d1; then the nonce is gone for d2 too.
        let c = challenge(&s, &d2.id).await;
        refused.push(post_sign_in(&s, &signed(&d1, &o, &c.nonce)).await);
        refused.push(post_sign_in(&s, &signed(&d2, &o, &c.nonce)).await);
        // d2's nonce, signed by d1's key over d2's id and sent as d1: the
        // message the server builds with the nonce's own device would
        // verify, so only the binding check stops a session for d2.
        let c = challenge(&s, &d2.id).await;
        let message = signin::message(&o, &c.nonce, &d2.id).unwrap();
        let record = SignIn {
            device_id: d1.id,
            nonce: c.nonce,
            signature: d1.key.sign(&message),
        };
        refused.push(post_sign_in(&s, &record).await);

        // Another origin: another host, another port, plain http.
        for other in [
            signin::origin("localhost", port),
            signin::origin("127.0.0.1", port.wrapping_add(1)),
            format!("http://127.0.0.1:{port}"),
        ] {
            let c = challenge(&s, &d1.id).await;
            refused.push(post_sign_in(&s, &signed(&d1, &other, &c.nonce)).await);
        }

        // d2's id with d1's signature: over d1's id, and over d2's id.
        for over in [d1.id, d2.id] {
            let c = challenge(&s, &d2.id).await;
            let message = signin::message(&o, &c.nonce, &over).unwrap();
            let record = SignIn {
                device_id: d2.id,
                nonce: c.nonce,
                signature: d1.key.sign(&message),
            };
            refused.push(post_sign_in(&s, &record).await);
        }

        // One changed byte of the signature: the first, a middle, the last
        // (a DER signature is 70 to 72 bytes long).
        for at in [0, 35, usize::MAX] {
            let c = challenge(&s, &d1.id).await;
            let mut record = signed(&d1, &o, &c.nonce);
            let i = at.min(record.signature.len() - 1);
            record.signature[i] ^= 1;
            refused.push(post_sign_in(&s, &record).await);
        }

        // One changed byte of the message: in the label, the last byte.
        for at in [4, usize::MAX] {
            let c = challenge(&s, &d1.id).await;
            let mut message = signin::message(&o, &c.nonce, &d1.id).unwrap();
            let i = at.min(message.len() - 1);
            message[i] ^= 1;
            let record = SignIn {
                device_id: d1.id,
                nonce: c.nonce,
                signature: d1.key.sign(&message),
            };
            refused.push(post_sign_in(&s, &record).await);
        }

        // A nonce that is 300 s old (its end) and one 301 s old.
        for age in [300, 301] {
            set_clock(&s, T0);
            let c = challenge(&s, &d1.id).await;
            set_clock(&s, T0 + age);
            refused.push(post_sign_in(&s, &signed(&d1, &o, &c.nonce)).await);
        }

        assert_eq!(refused.len(), 16);
        for r in &refused {
            r.assert_unauthorized();
            assert_eq!(r.headers.len(), refused[0].headers.len(), "{r:?}");
        }
        assert_eq!(count(&s, "challenges"), 0, "every nonce named is gone");
        assert_eq!(count(&s, "sessions"), 1, "only the first sign-in");
    });
}

/// T06: a wrong signature, then the right one on the same nonce: both
/// 401, since the first attempt deleted the nonce. Before them, a body
/// that fails SYN-01.8 (a signature one byte longer than 72) gets 400 and
/// leaves the nonce, since no signature was checked (LD-327 (3)).
#[test]
fn syn04_4_t06_nonce_is_used_once_even_by_a_failed_sign_in() {
    block_on(async {
        let s = start_bare(Config::default()).await;
        let d1 = sign_up(&s).await;
        let o = origin(&s);
        let c = challenge(&s, &d1.id).await;
        let right = signed(&d1, &o, &c.nonce);
        let mut long = right.clone();
        long.signature.resize(MAX_SIGNATURE + 1, 0);
        post_sign_in(&s, &long)
            .await
            .assert_error(400, "bad_request");
        assert_eq!(count(&s, "challenges"), 1, "a 400 leaves the nonce");
        let mut wrong = right.clone();
        let last = wrong.signature.len() - 1;
        wrong.signature[last] ^= 1;
        post_sign_in(&s, &wrong).await.assert_unauthorized();
        post_sign_in(&s, &right).await.assert_unauthorized();
        assert_eq!(count(&s, "challenges"), 0);
        assert_eq!(count(&s, "sessions"), 0);
    });
}

/// T07: on the test clock, a session used at 0 and at 14 min works; after
/// 16 min idle it gets 401 and its row is gone. At 899 s idle it works, at
/// 900 s not. Used every 10 min it works until 8 h and gets 401 from 8 h on.
#[test]
fn syn04_5_t07_idle_and_absolute_expiry_on_the_test_clock() {
    block_on(async {
        let s = start_bare(Config::default()).await;
        set_clock(&s, T0);
        let d1 = sign_up(&s).await;
        let auth = bearer(&sign_in(&s, &d1).await);
        assert_eq!(vaults(&s, &auth).await.status, 200);
        set_clock(&s, T0 + 14 * 60);
        assert_eq!(vaults(&s, &auth).await.status, 200, "at 14 min");
        set_clock(&s, T0 + 30 * 60);
        vaults(&s, &auth).await.assert_unauthorized();
        assert_eq!(count(&s, "sessions"), 0, "the row is deleted");

        let t1 = T0 + 3600;
        set_clock(&s, t1);
        let auth = bearer(&sign_in(&s, &d1).await);
        set_clock(&s, t1 + 899);
        assert_eq!(vaults(&s, &auth).await.status, 200, "899 s idle");
        set_clock(&s, t1 + 899 + 900);
        vaults(&s, &auth).await.assert_unauthorized();

        let t2 = T0 + 7200;
        set_clock(&s, t2);
        let auth = bearer(&sign_in(&s, &d1).await);
        for minute in (10..=490).step_by(10) {
            set_clock(&s, t2 + minute * 60);
            let r = vaults(&s, &auth).await;
            if minute < 480 {
                assert_eq!(r.status, 200, "at {minute} min");
            } else {
                r.assert_unauthorized();
            }
        }
        assert_eq!(count(&s, "sessions"), 0);
    });
}

/// T09: sign out gets 204 and deletes this session's row only; the token
/// then gets 401. A second session of the same device and another
/// account's session stay.
#[test]
fn syn04_7_t09_sign_out_ends_the_session() {
    block_on(async {
        let s = start_bare(Config::default()).await;
        let d1 = sign_up(&s).await;
        let this = bearer(&sign_in(&s, &d1).await);
        let same_device = bearer(&sign_in(&s, &d1).await);
        let other = bearer(&sign_in(&s, &sign_up(&s).await).await);
        let r = exchange(&s, &request("POST", "/v1/signout", &this, b"")).await;
        assert_eq!(r.status, 204, "{r:?}");
        assert!(r.body.is_empty());
        assert_eq!(r.header("cache-control"), Some("no-store"));
        vaults(&s, &this).await.assert_unauthorized();
        exchange(&s, &request("POST", "/v1/signout", &this, b""))
            .await
            .assert_unauthorized();
        assert_eq!(
            vaults(&s, &same_device).await.status,
            200,
            "this device's other session stays"
        );
        assert_eq!(vaults(&s, &other).await.status, 200, "other sessions stay");
        assert_eq!(count(&s, "sessions"), 2);
    });
}

/// T10: d1 revokes d2: 204; d2's next call and its next sign-in get 401,
/// and its open challenge is gone. d1 revoking itself while d2 is gone:
/// 409 (the last device). Another account's device and an unknown id:
/// 404. A Mac may revoke itself: 204, then 401.
#[test]
fn syn04_8_t10_revoke_ends_the_device_and_keeps_the_last() {
    block_on(async {
        let s = start_bare(signin_limit(100)).await;
        let d1 = sign_up(&s).await;
        let a1 = bearer(&sign_in(&s, &d1).await);
        let d2 = second_device(&s, &d1.account);
        let a2 = bearer(&sign_in(&s, &d2).await);
        let open = challenge(&s, &d2.id).await;
        let other = sign_up(&s).await;

        revoke(&s, "", &d2.id).await.assert_unauthorized();
        revoke(&s, &a1, &other.id)
            .await
            .assert_error(404, "not_found");
        revoke(&s, &a1, &DeviceId::from_bytes([9; 16]))
            .await
            .assert_error(404, "not_found");
        assert_eq!(count(&s, "devices"), 3);

        let r = revoke(&s, &a1, &d2.id).await;
        assert_eq!(r.status, 204, "{r:?}");
        let gone = store(&s)
            .query_row(
                "SELECT (SELECT count(*) FROM devices WHERE id = ?1) + \
                 (SELECT count(*) FROM sessions WHERE device = ?1) + \
                 (SELECT count(*) FROM challenges WHERE device = ?1)",
                [d2.id.as_bytes()],
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(gone, 0, "d2's row, sessions and challenges");
        vaults(&s, &a2).await.assert_unauthorized();
        post_sign_in(&s, &signed(&d2, &origin(&s), &open.nonce))
            .await
            .assert_unauthorized();
        let c = challenge(&s, &d2.id).await;
        post_sign_in(&s, &signed(&d2, &origin(&s), &c.nonce))
            .await
            .assert_unauthorized();

        revoke(&s, &a1, &d1.id).await.assert_error(409, "conflict");
        assert_eq!(vaults(&s, &a1).await.status, 200, "d1 is unchanged");

        let d3 = second_device(&s, &d1.account);
        let a3 = bearer(&sign_in(&s, &d3).await);
        assert_eq!(revoke(&s, &a3, &d3.id).await.status, 204, "itself");
        vaults(&s, &a3).await.assert_unauthorized();
        assert_eq!(vaults(&s, &a1).await.status, 200);
    });
}

/// T15: 20 more challenges for d1 do not push out its first one, which
/// still signs in at 299 s.
#[test]
fn syn04_3_t15_challenge_lifetime_no_push_out() {
    block_on(async {
        let s = start_bare(signin_limit(100)).await;
        set_clock(&s, T0);
        let d1 = sign_up(&s).await;
        let c1 = challenge(&s, &d1.id).await;
        for _ in 0..20 {
            challenge(&s, &d1.id).await;
        }
        set_clock(&s, T0 + 299);
        let r = post_sign_in(&s, &signed(&d1, &origin(&s), &c1.nonce)).await;
        assert_eq!(r.status, 200, "{r:?}");
    });
}

/// SYN-01 T05, SV-03: with a valid session beside them, no header, a
/// 42-character token, a random 32-byte token, an expired token, a revoked
/// device's token, the session's own SHA-256 (a stolen store), two
/// `Authorization` lines and another scheme each get the same 401.
#[test]
fn syn01_5_t05_bad_tokens_get_one_401() {
    block_on(async {
        let s = start_bare(signin_limit(100)).await;
        set_clock(&s, T0);
        let d1 = sign_up(&s).await;
        let old = sign_in(&s, &d1).await;
        set_clock(&s, T0 + 901);
        let live = sign_in(&s, &d1).await;
        let auth = bearer(&live);
        let d2 = second_device(&s, &d1.account);
        let revoked = bearer(&sign_in(&s, &d2).await);
        assert_eq!(revoke(&s, &auth, &d2.id).await.status, 204);

        let mut random = [0u8; 32];
        larsal_crypto::random::fill(&mut random).unwrap();
        let line = |token: &[u8]| {
            format!(
                "Authorization: Bearer {}\r\n",
                base64::encode(Form::Url, token)
            )
        };
        let text = base64::encode(Form::Url, live.token.expose());
        let bad = [
            String::new(),
            format!("Authorization: Bearer {}\r\n", &text[..42]),
            line(&random),
            bearer(&old),
            revoked,
            line(&sha256(live.token.expose())),
            format!("{auth}{auth}"),
            format!("Authorization: Basic {text}\r\n"),
            format!("Authorization: Bearer {text}=\r\n"),
        ];
        let mut bodies = Vec::new();
        for b in &bad {
            let r = vaults(&s, b).await;
            r.assert_unauthorized();
            bodies.push(r.body);
        }
        assert!(bodies.windows(2).all(|w| w[0] == w[1]));
        // The scheme is case-insensitive (RFC 9110 section 11.1).
        let lower = auth.replace("Bearer", "bearer");
        assert_eq!(vaults(&s, &lower).await.status, 200);
        assert_eq!(vaults(&s, &auth).await.status, 200);
        // Every session route needs it.
        for (method, path) in [
            ("GET", "/v1/vaults/0123456789abcdef0123456789abcdef"),
            ("PUT", "/v1/vaults/0123456789abcdef0123456789abcdef"),
            ("POST", "/v1/signout"),
            ("DELETE", "/v1/devices/0123456789abcdef0123456789abcdef"),
        ] {
            let extra = if method == "PUT" {
                "If-None-Match: *\r\n"
            } else {
                ""
            };
            let r = exchange(&s, &request(method, path, extra, b"x")).await;
            r.assert_unauthorized();
        }
        assert_eq!(count(&s, "vaults"), 0);
    });
}

/// SYN-01 T11: account B's session gets 404 for A's vault, 412 for a PUT
/// with its current version or a create on its id, and B's list does not
/// hold it; the vault is unchanged.
#[test]
fn syn01_6_t11_another_account_sees_no_vault() {
    block_on(async {
        let s = start(Config::default()).await;
        let id = "0123456789abcdef0123456789abcdef";
        let path = format!("/v1/vaults/{id}");
        let create = format!("{}If-None-Match: *\r\n", s.auth);
        let r = exchange(&s, &request("PUT", &path, &create, b"vault of A")).await;
        assert_eq!(r.status, 201, "{r:?}");
        let b = bearer(&sign_in(&s, &sign_up(&s).await).await);

        exchange(&s, &request("GET", &path, &b, b""))
            .await
            .assert_error(404, "not_found");
        for pre in ["If-Match: \"1\"\r\n", "If-None-Match: *\r\n"] {
            let r = exchange(&s, &request("PUT", &path, &format!("{b}{pre}"), b"of B")).await;
            r.assert_error(412, "precondition_failed");
        }
        let r = vaults(&s, &b).await;
        assert_eq!(r.body, br#"{"vaults":[]}"#);
        let r = vaults(&s, &s.auth).await;
        assert!(holds(&r.body, id.as_bytes()), "{r:?}");
        let r = exchange(&s, &request("GET", &path, &s.auth, b"")).await;
        assert_eq!(r.header("etag"), Some("\"1\""));
        assert_eq!((r.status, r.body), (200, b"vault of A".to_vec()));
    });
}

/// SYN-01 T13 on the challenge: a valid body, an extra field, an extra
/// field nesting the body to 8 levels and a body of exactly 1 MiB get 200;
/// a duplicate `device_id`, 31 hex digits, an upper-case digit, an array,
/// 9 levels and 1 MiB + 1 byte (refused from its length) get 400.
#[test]
fn syn01_8_t13_challenge_records() {
    block_on(async {
        let s = start_bare(signin_limit(100)).await;
        let id = "0123456789abcdef0123456789abcdef";
        let nest = |levels: usize| {
            let inner = levels - 2;
            format!(
                r#"{{"device_id":"{id}","x":{}{{}}{}}}"#,
                r#"{"a":"#.repeat(inner),
                "}".repeat(inner)
            )
        };
        let ask = |body: &[u8]| request("POST", "/v1/signin/challenge", "", body);
        let valid = format!(r#"{{"device_id":"{id}"}}"#);
        let mut full = valid.clone().into_bytes();
        full.resize(1024 * 1024, b' ');
        for body in [
            valid.clone().into_bytes(),
            format!(r#"{{"device_id":"{id}","x":1}}"#).into_bytes(),
            nest(8).into_bytes(),
            full,
        ] {
            let r = exchange(&s, &ask(&body)).await;
            assert_eq!(r.status, 200, "{r:?}");
        }
        for body in [
            format!(r#"{{"device_id":"{id}","device_id":"{id}"}}"#),
            format!(r#"{{"device_id":"{}"}}"#, &id[1..]),
            format!(r#"{{"device_id":"{}"}}"#, id.replace('a', "A")),
            format!("[{valid}]"),
            nest(9),
        ] {
            let r = exchange(&s, &ask(body.as_bytes())).await;
            r.assert_error(400, "bad_request");
        }
        let head = format!(
            "POST /v1/signin/challenge HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Content-Length: {}\r\n\r\n",
            1024 * 1024 + 1
        );
        exchange(&s, head.as_bytes())
            .await
            .assert_error(400, "bad_request");
    });
}

/// SYN-01.10, F-250: a chunked body has no `Content-Length`, so only the
/// count of the bytes read can stop it. One chunk of 1 MiB + 1 spaces and
/// no last chunk to `POST /v1/signin/challenge` (no session needed) gets
/// 400 as soon as the bytes pass the limit, within 5 s; a server that read
/// on with no bound would wait for more.
#[test]
fn syn01_10_t13_chunked_body_over_1_mib_gets_400_at_once() {
    block_on(async {
        let s = start_bare(Config::default()).await;
        let size = 1024 * 1024 + 1;
        let mut ask = format!(
            "POST /v1/signin/challenge HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Transfer-Encoding: chunked\r\n\r\n{size:x}\r\n"
        )
        .into_bytes();
        ask.resize(ask.len() + size, b' ');
        let mut stream = tls(&s, &version::TLS13).await;
        stream.write_all(&ask).await.unwrap();
        stream.flush().await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), read_all(&mut stream))
            .await
            .expect("no reply in 5 s: the body was read with no bound");
        Reply::parse(&reply).assert_error(400, "bad_request");
    });
}

/// SYN-01 T19, SYN-01.12: with 3 sign-in requests a minute, the 4th
/// challenge gets 429 with `Retry-After` and nothing runs (a sign-up then
/// makes no row); after the wait a challenge works again. Reads and writes
/// have their own limits, counted before the session check.
#[test]
fn syn01_12_t19_rate_limit_429_with_retry_after() {
    block_on(async {
        let limits = Config {
            rate: RateLimits {
                signin: 3,
                writes: 2,
                reads: 2,
            },
            ..Config::default()
        };
        let s = start_bare(limits).await;
        set_clock(&s, T0);
        let nobody = DeviceId::from_bytes([9; 16]);
        for _ in 0..3 {
            challenge(&s, &nobody).await;
        }
        let ask = ChallengeRequest { device_id: nobody }.to_json();
        let ask = request("POST", "/v1/signin/challenge", "", &ask);
        let r = exchange(&s, &ask).await;
        r.assert_error(429, "rate_limited");
        assert_eq!(r.header("retry-after"), Some("60"));
        // F-248: `POST /v1/signin` counts in the same bucket.
        exchange(&s, &request("POST", "/v1/signin", "", b""))
            .await
            .assert_error(429, "rate_limited");
        let key = P256TestKey::new().unwrap();
        let account = AccountCreate {
            device_public_key: key.public().try_into().unwrap(),
            device_name: "Mac".to_owned(),
        };
        let r = exchange(&s, &request("POST", "/v1/accounts", "", &account.to_json())).await;
        r.assert_error(429, "rate_limited");
        assert_eq!(count(&s, "accounts"), 0, "nothing ran");
        set_clock(&s, T0 + 59);
        let r = exchange(&s, &ask).await;
        assert_eq!(r.header("retry-after"), Some("1"));
        set_clock(&s, T0 + 60);
        assert_eq!(exchange(&s, &ask).await.status, 200, "a new minute");

        let health = request("GET", "/v1/health", "", b"");
        for _ in 0..2 {
            assert_eq!(exchange(&s, &health).await.status, 200);
        }
        exchange(&s, &health)
            .await
            .assert_error(429, "rate_limited");
        let signout = request("POST", "/v1/signout", "", b"");
        for _ in 0..2 {
            exchange(&s, &signout).await.assert_unauthorized();
        }
        exchange(&s, &signout)
            .await
            .assert_error(429, "rate_limited");
    });
}

/// The JSON keys of a record: every `"<name>":`.
fn keys(body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();
    for (end, _) in text.match_indices("\":") {
        if let Some(start) = text[..end].rfind('"') {
            out.push(text[start + 1..end].to_owned());
        }
    }
    out
}

/// The header names of a request.
fn header_names(request: &[u8]) -> Vec<String> {
    let end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&request[..end]).unwrap();
    head.split("\r\n")
        .skip(1)
        .map(|l| l.split_once(':').unwrap().0.to_ascii_lowercase())
        .collect()
}

/// T13, SYN-04.10, P5: every request of a sign-up, a sign-in, an upload of
/// the demo vault `password-only.larsalvault`, its download, the list and a
/// sign-out is read whole; none holds its password `demo-pass-1` or a
/// value made from it (its UTF-8 and UTF-16 bytes, hex, base64, SHA-256,
/// the SHA-256 of its SHA-256), and each names only the protocol's fields.
#[test]
fn syn04_10_t13_no_request_holds_the_password_or_a_value_made_from_it() {
    block_on(async {
        let vault =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/password-only.larsalvault");
        let vault = std::fs::read(vault).unwrap();
        let s = start(Config::default()).await;
        let path = "/v1/vaults/0123456789abcdef0123456789abcdef";
        let create = format!("{}If-None-Match: *\r\n", s.auth);
        assert_eq!(
            exchange(&s, &request("PUT", path, &create, &vault))
                .await
                .status,
            201
        );
        let r = exchange(&s, &request("GET", path, &s.auth, b"")).await;
        assert!(r.body == vault);
        assert_eq!(vaults(&s, &s.auth).await.status, 200);
        let r = exchange(&s, &request("POST", "/v1/signout", &s.auth, b"")).await;
        assert_eq!(r.status, 204);

        let password = "demo-pass-1";
        let utf16 = |be: bool| -> Vec<u8> {
            password
                .encode_utf16()
                .flat_map(|u| if be { u.to_be_bytes() } else { u.to_le_bytes() })
                .collect()
        };
        let mut made: Vec<Vec<u8>> = vec![password.as_bytes().to_vec(), utf16(false), utf16(true)];
        let hash = sha256(password.as_bytes());
        for value in [password.as_bytes().to_vec(), hash.clone(), sha256(&hash)] {
            made.push(hex(&value).into_bytes());
            made.push(hex(&value).to_uppercase().into_bytes());
            made.push(base64::encode(Form::Padded, &value).into_bytes());
            made.push(base64::encode(Form::Url, &value).into_bytes());
            made.push(value);
        }
        // Base64 without its padding, as a URL form would carry it.
        made.push(
            base64::encode(Form::Padded, password.as_bytes())
                .trim_end_matches('=')
                .into(),
        );

        let sent = s.sent.lock().unwrap();
        assert_eq!(
            sent.len(),
            7,
            "sign-up, challenge, sign-in, PUT, GET, list, sign-out"
        );
        let fields = [
            "device_public_key",
            "device_name",
            "device_id",
            "nonce",
            "signature",
        ];
        let headers = [
            "host",
            "connection",
            "content-length",
            "authorization",
            "if-none-match",
        ];
        for (request, _) in sent.iter() {
            for value in &made {
                assert!(
                    !holds(request, value),
                    "{:?}",
                    String::from_utf8_lossy(value)
                );
            }
            for name in header_names(request) {
                assert!(headers.contains(&name.as_str()), "{name}");
            }
            if request.ends_with(b"}") {
                for key in keys(request) {
                    assert!(fields.contains(&key.as_str()), "{key}");
                }
            }
        }
    });
}

/// Stops the server process it holds (by its own PID) when dropped.
struct Stop(std::process::Child);

impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// True when `line` is SYN-01.13's request line: `larsal-server: `, a method,
/// a route name of `a` to `z` and `_`, a status, a size in bytes and the
/// time in ms; nothing else.
fn is_request_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("larsal-server: ") else {
        return false;
    };
    let digits = |w: &str| !w.is_empty() && w.bytes().all(|c| c.is_ascii_digit());
    match rest.split(' ').collect::<Vec<_>>()[..] {
        [method, route, status, size, "bytes", ms, "ms"] => {
            ["GET", "POST", "PUT", "DELETE", "other"].contains(&method)
                && !route.is_empty()
                && route.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
                && status.len() == 3
                && digits(status)
                && digits(size)
                && digits(ms)
        }
        _ => false,
    }
}

/// LD-321 (4), SYN-01 T20: the server binary, run through a sign-up, a
/// sign-in, an upload, a download, the list, a bad token, an unknown path,
/// a revoke and a sign-out, writes one request line per request on its
/// standard error and nothing else; no line holds the `Authorization`
/// header, a token, a nonce, a signature, a device key or a body. Every
/// reply has `Cache-Control: no-store`.
#[test]
fn ld321_4_t20_log_line_never_holds_a_secret_and_every_reply_no_store() {
    use std::io::{BufRead, Read};
    let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let data: Scratch = scratch();
    let mut server = Stop(
        Command::new(env!("CARGO_BIN_EXE_larsal-server"))
            .arg("--data")
            .arg(&data.0)
            .arg("--port")
            .arg(port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut out = std::io::BufReader::new(server.0.stdout.take().unwrap());
    let mut first = String::new();
    out.read_line(&mut first).unwrap();
    assert!(first.starts_with("Larsal sync server (demo)"), "{first}");
    let mut err = server.0.stderr.take().unwrap();
    let der = std::fs::read(data.0.join("tls").join("cert.der")).unwrap();
    let mut s = Running {
        addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        cert: CertificateDer::from(der),
        data,
        seams: None,
        auth: String::new(),
        sent: std::sync::Arc::default(),
    };
    let vault = b"encrypted vault bytes of a demo file".to_vec();
    block_on(async {
        assert_eq!(
            exchange(&s, &request("GET", "/v1/health", "", b""))
                .await
                .status,
            200
        );
        let d1: Device = sign_up(&s).await;
        s.auth = bearer(&sign_in(&s, &d1).await);
        let path = "/v1/vaults/0123456789abcdef0123456789abcdef";
        let create = format!("{}If-None-Match: *\r\n", s.auth);
        assert_eq!(
            exchange(&s, &request("PUT", path, &create, &vault))
                .await
                .status,
            201
        );
        assert_eq!(
            exchange(&s, &request("GET", path, &s.auth, b""))
                .await
                .status,
            200
        );
        assert_eq!(vaults(&s, &s.auth).await.status, 200);
        let random = format!("Authorization: Bearer {}\r\n", "A".repeat(43));
        vaults(&s, &random).await.assert_unauthorized();
        let r = exchange(&s, &request("GET", "/v1/secret-path-words", "", b"")).await;
        assert_eq!(r.status, 404);
        let r = revoke(&s, &s.auth, &DeviceId::from_bytes([9; 16])).await;
        assert_eq!(r.status, 404);
        let r = exchange(&s, &request("POST", "/v1/signout", &s.auth, b"")).await;
        assert_eq!(r.status, 204);
    });
    drop(server);
    let mut log = String::new();
    err.read_to_string(&mut log).unwrap();

    let sent = s.sent.lock().unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), sent.len(), "{log}");
    for line in &lines {
        assert!(is_request_line(line), "{line}");
    }
    assert!(
        lines[3].starts_with("larsal-server: POST signin 200 "),
        "{log}"
    );
    // Each secret the run moved, in the forms it moved in.
    let mut secrets: Vec<Vec<u8>> = vec![b"Authorization".to_vec(), b"Bearer".to_vec()];
    for (request, reply) in sent.iter() {
        assert_eq!(reply.header("cache-control"), Some("no-store"), "{reply:?}");
        let end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let (head, body) = (&request[..end], &request[end + 4..]);
        for line in String::from_utf8_lossy(head).split("\r\n") {
            if let Some(token) = line.strip_prefix("Authorization: Bearer ") {
                secrets.push(token.as_bytes().to_vec());
            }
        }
        // An error body holds only its code, which may name a route too.
        let reply_body: &[u8] = if reply.body.starts_with(b"{\"error\":") {
            b""
        } else {
            &reply.body
        };
        for bytes in [body, reply_body] {
            if !bytes.is_empty() {
                secrets.push(bytes.to_vec());
            }
            // Every JSON string value of 8 characters or more.
            let text = String::from_utf8_lossy(bytes);
            for value in text.split('"').skip(1).step_by(2) {
                if value.len() >= 8 && !value.contains(':') {
                    secrets.push(value.as_bytes().to_vec());
                }
            }
        }
    }
    assert!(secrets.len() > 15, "{}", secrets.len());
    for secret in &secrets {
        assert!(
            !holds(log.as_bytes(), secret),
            "{:?}",
            String::from_utf8_lossy(secret)
        );
    }
    assert!(!log.contains("secret-path-words"));
}
