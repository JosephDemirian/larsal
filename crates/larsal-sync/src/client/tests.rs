//! Client checks against Larsal's server in process on 127.0.0.1:0 with its
//! first-start certificate, pinned (LD-327 (6)), and scripted servers on
//! 127.0.0.1. The device key is the test-seam key (LD-317 (2)): no test
//! touches a keychain.
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#![allow(clippy::arithmetic_side_effects)]

use super::*;
use crate::test_server::{Request, Response, Scripted, larsal_server};
use larsal_crypto::secret::SecretBytes;
use larsal_platform::device_key::DeviceKey;
use larsal_proto::messages::{VaultId, VaultVersion};

/// A key that signs, then changes the signature's last byte.
struct Changed(DeviceKey);

impl Signer for Changed {
    fn public_key(&self) -> Result<[u8; 65], Fail> {
        Signer::public_key(&self.0)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Fail> {
        let mut s = Signer::sign(&self.0, message)?;
        *s.last_mut().unwrap() ^= 1;
        Ok(s)
    }
}

/// The sign-in routes of a scripted server: any device passes.
pub(crate) fn signin(r: &Request) -> Option<Response> {
    match (r.method.as_str(), r.path.as_str()) {
        ("POST", "/v1/signin/challenge") => Some(Response::new(
            200,
            &Challenge {
                nonce: [1; 32],
                expires: 4_000_000_000,
            }
            .to_json(),
        )),
        ("POST", "/v1/signin") => Some(Response::new(
            200,
            &Session {
                token: SecretBytes::new(vec![2; 32]),
                idle_seconds: 900,
                expires: 4_000_000_000,
            }
            .to_json(),
        )),
        _ => None,
    }
}

/// A client of a scripted server with a test-seam device.
pub(crate) fn client(s: &Scripted) -> Server<DeviceKey> {
    let mut c = Server::new(&s.address(), s.pin).unwrap();
    c.set_device(
        DeviceId::from_bytes([9; 16]),
        DeviceKey::test_seam().unwrap(),
    );
    c
}

/// E16-S7a check 1, SYN-04.4, SYN-04 T04: a client signs up and signs in
/// through `device_key.rs` (the test-seam key) against Larsal's server, and
/// a changed signature gets 401: signed out, no session.
#[test]
fn syn04_4_signs_in_through_device_key_and_a_changed_signature_gets_401() {
    let app = larsal_server();
    let mut a = Server::new(&app.address(), app.pin).unwrap();
    let made = a.sign_up(DeviceKey::test_seam().unwrap()).unwrap();
    a.sign_in().unwrap();
    assert!(a.signed_in());
    assert!(a.list().unwrap().is_empty());

    // The same device, with every signature changed in one bit.
    let key = DeviceKey::test_seam().unwrap();
    let account = made.account_id;
    let second = app
        .seams
        .add_device(&account, &key.public_key().unwrap(), "Mac")
        .unwrap()
        .unwrap();
    let mut b = Server::new(&app.address(), app.pin).unwrap();
    b.set_device(second, Changed(key));
    assert_eq!(b.sign_in(), Err(Fail::SignedOut));
    assert!(!b.signed_in());
    assert_eq!(b.list().unwrap_err(), Fail::SignedOut);
}

/// SYN-03.10, SYN-04.6, SYN-03 T19: an expired session signs in again once
/// and the call goes on; a device the server does not know is signed out.
#[test]
fn syn03_10_t19_401_signs_in_once_then_signed_out() {
    let app = larsal_server();
    let proxy = Scripted::proxy(&app);
    let mut a = Server::new(&proxy.address(), proxy.pin).unwrap();
    a.sign_for_port(app.port);
    a.sign_up(DeviceKey::test_seam().unwrap()).unwrap();
    a.list().unwrap();
    let signins = |p: &Scripted| {
        p.requests()
            .iter()
            .filter(|r| r.path == "/v1/signin")
            .count()
    };
    assert_eq!(signins(&proxy), 1);
    // 16 minutes later on the server's clock: idle expiry (SYN-04.5).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    app.seams.set_clock(now + 16 * 60);
    a.list().unwrap();
    assert_eq!(signins(&proxy), 2, "one more sign-in, then the call");
    let lists: Vec<u16> = proxy
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(r, _)| r.path == "/v1/vaults")
        .map(|(_, reply)| String::from_utf8_lossy(reply)[9..12].parse().unwrap())
        .collect();
    assert_eq!(lists, [200, 401, 200]);

    let mut unknown = Server::new(&app.address(), app.pin).unwrap();
    unknown.set_device(
        DeviceId::from_bytes([3; 16]),
        DeviceKey::test_seam().unwrap(),
    );
    assert_eq!(unknown.list().unwrap_err(), Fail::SignedOut);
}

/// SYN-04.6: a server that answers 401 again after the new sign-in is
/// Signed out: one more sign-in only, never a loop.
#[test]
fn syn04_6_a_401_after_the_new_sign_in_is_signed_out() {
    let lists = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let seen = std::sync::Arc::clone(&lists);
    let s = Scripted::new(move |r| {
        signin(r).unwrap_or_else(|| {
            // A client that kept signing in would get its list at last.
            match seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                1..=4 => Response::new(401, b"{}"),
                _ => Response::new(200, br#"{"vaults":[]}"#),
            }
        })
    });
    let mut c = client(&s);
    c.list().unwrap();
    assert_eq!(c.list().unwrap_err(), Fail::SignedOut);
    assert!(!c.signed_in());
    assert_eq!(s.count("GET"), 3);
    let signins = s
        .requests()
        .iter()
        .filter(|r| r.path == "/v1/signin")
        .count();
    assert_eq!(signins, 2);
}

/// SYN-01.2: pinned to another certificate, no request reaches the
/// server: the certificate changed.
#[test]
fn syn01_2_another_certificate_stops_every_request() {
    let s = Scripted::new(|_| Response::new(200, b"{}"));
    let mut c = Server::<DeviceKey>::new(&s.address(), [0; 32]).unwrap();
    assert_eq!(c.health(), Err(Fail::CertChanged));
    assert_eq!(c.list().unwrap_err(), Fail::Key, "no device: nothing sent");
    c.set_device(
        DeviceId::from_bytes([9; 16]),
        DeviceKey::test_seam().unwrap(),
    );
    assert_eq!(c.list().unwrap_err(), Fail::CertChanged);
    assert!(s.requests().is_empty());
    assert_eq!(fingerprint(&s.address()), Ok(s.pin));
    assert!(
        s.requests().is_empty(),
        "the fingerprint read sends nothing"
    );
}

/// SYN-01.14, SYN-01 T21: Larsal's server answers health as a sync server; a
/// server that answers 404 does not.
#[test]
fn syn01_14_t21_health_names_only_an_larsal_server() {
    let app = larsal_server();
    let a = Server::<DeviceKey>::new(&app.address(), app.pin).unwrap();
    assert_eq!(a.health(), Ok(true));
    let s = Scripted::new(|_| Response::new(404, br#"{"error":"not_found"}"#));
    let b = Server::<DeviceKey>::new(&s.address(), s.pin).unwrap();
    assert_eq!(b.health(), Ok(false));
}

/// SYN-01.10, SYN-01 T17: a vault list of exactly 1 MiB is read in full;
/// a list or a challenge reply of 1 MiB + 1 byte is a protocol error.
#[test]
fn syn01_10_t17_client_reply_limits() {
    let item = |n: u32| {
        let mut id = [0u8; 16];
        id[12..].copy_from_slice(&n.to_be_bytes());
        VaultVersion {
            id: VaultId::from_bytes(id),
            version: u64::from(n) + 1,
            size: 1000,
        }
        .to_json()
    };
    let list = move |len: usize| {
        let mut body = br#"{"vaults":["#.to_vec();
        let mut n = 0;
        while body.len() + item(n).len() + 3 < len {
            if n > 0 {
                body.push(b',');
            }
            body.extend_from_slice(&item(n));
            n += 1;
        }
        body.extend_from_slice(b"]}");
        body.resize(len, b' ');
        (body, n)
    };
    let (exact, n) = list(MAX_JSON);
    let s =
        Scripted::new(move |r| signin(r).unwrap_or_else(|| Response::new(200, &list(MAX_JSON).0)));
    assert_eq!(exact.len(), MAX_JSON);
    let listed = client(&s).list().unwrap();
    assert_eq!(listed.len(), n as usize);
    assert!(n > 10_000);

    let s = Scripted::new(move |r| {
        signin(r).unwrap_or_else(|| Response::new(200, &list(MAX_JSON + 1).0))
    });
    assert_eq!(client(&s).list().unwrap_err(), Fail::Protocol);

    let s = Scripted::new(|r| {
        if r.path == "/v1/signin/challenge" {
            let mut body = Challenge {
                nonce: [1; 32],
                expires: 4_000_000_000,
            }
            .to_json();
            body.resize(MAX_JSON + 1, b' ');
            return Response::new(200, &body);
        }
        signin(r).unwrap()
    });
    assert_eq!(client(&s).sign_in(), Err(Fail::Protocol));
}

/// SYN-03.10 (LD-273 (9)), SYN-03 T29 and T30: a `Retry-After` is whole
/// seconds, at most 300; anything else counts as 300.
#[test]
fn syn03_10_retry_after_is_whole_seconds_at_most_300() {
    for (value, wait) in [
        (None, 300),
        (Some("3600"), 300),
        (Some("Fri, 31 Dec 2099 23:59:59 GMT"), 300),
        (Some("1.5"), 300),
        (Some("99999999999999999999999"), 300),
        (Some("-1"), 300),
        (Some(""), 300),
        (Some("12"), 12),
        (Some(" 7 "), 7),
        (Some("0"), 0),
    ] {
        assert_eq!(retry_after(value), wait, "{value:?}");
    }
}

/// SYN-01.2, SYN-04.4: the address is `https://host:port` (port 443 when
/// left out), the origin always writes the port; the printed fingerprint
/// is 8 groups of 8 uppercase hex digits and reads back.
#[test]
fn syn01_2_address_origin_and_printed_fingerprint() {
    assert_eq!(
        parse_address("https://LocalHost:8443/"),
        Some((
            "https://localhost:8443".into(),
            "https://localhost:8443".into()
        ))
    );
    assert_eq!(
        parse_address("https://sync.example").map(|a| a.1),
        Some("https://sync.example:443".into())
    );
    for bad in [
        "http://127.0.0.1:1",
        "https://",
        "https://a@b:1",
        "https://a:0",
        "https://a:99999",
        "https://a:1/v1",
        "https://a:",
        "https://[::1]:1",
    ] {
        assert_eq!(parse_address(bad), None, "{bad}");
    }
    let pin: [u8; 32] = std::array::from_fn(|i| u8::try_from(i * 7).unwrap());
    let text = printed(&pin);
    assert_eq!(text.len(), 64 + 7);
    assert_eq!(text.split(' ').count(), 8);
    assert!(!text.chars().any(|c| c.is_ascii_lowercase()));
    assert_eq!(read_printed(&text), Some(pin));
    assert_eq!(
        read_printed(&text.to_lowercase().replace(' ', "")),
        Some(pin)
    );
    assert_eq!(read_printed(&text[1..]), None);
}

/// SYN-04.6, SYN-04 T08 (the client's memory half): the token lives only
/// in the client; its `Debug` output, and the one of a reply, never shows
/// it.
#[test]
fn syn04_6_t08_debug_output_never_shows_the_token() {
    let s = Scripted::new(|r| signin(r).unwrap_or_else(|| Response::new(200, br#"{"vaults":[]}"#)));
    let mut c = client(&s);
    c.list().unwrap();
    let token = larsal_crypto::base64::encode(Form::Url, &[2; 32]);
    let sent = s.requests();
    let auth = sent.last().unwrap().header("authorization").unwrap();
    assert_eq!(auth, format!("Bearer {token}"));
    let shown = format!("{c:?}");
    assert!(!shown.contains(&token), "{shown}");
    assert!(shown.contains("signed_in: true"));
}

/// F-285 / SYN-01.8: inspect the real requests for all three JSON POSTs.
#[test]
fn f285_all_three_posts_send_json_content_type() {
    let app = larsal_server();
    let proxy = Scripted::proxy(&app);
    let mut c = Server::new(&proxy.address(), proxy.pin).unwrap();
    c.sign_for_port(app.port);
    c.sign_up(DeviceKey::test_seam().unwrap()).unwrap();
    c.sign_in().unwrap();
    let posts: Vec<Request> = proxy
        .requests()
        .into_iter()
        .filter(|r| r.method == "POST")
        .collect();
    assert_eq!(
        posts.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        ["/v1/accounts", "/v1/signin/challenge", "/v1/signin"]
    );
    for r in posts {
        assert_eq!(
            r.header("content-type"),
            Some("application/json"),
            "{}",
            r.path
        );
    }
}

/// LD-325 (5) (b): the sign-in reply holds the token, so its bytes move into the
/// wiping buffer, and the token is read only from there; a copy would leave them in
/// the reply. This reads the source text: it holds the move, not the wipe.
#[test]
fn ld325_5b_the_signin_reply_moves_into_the_wiping_buffer() {
    let src = include_str!("../client.rs");
    let moved = "let body = SecretBytes::new(std::mem::take(&mut a.body));";
    assert_eq!(src.matches(moved).count(), 1);
    assert_eq!(src.matches("Session::read(body.expose())").count(), 1);
    assert!(!src.contains("a.body.clone()"));
}
