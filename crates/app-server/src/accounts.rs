//! The account and sign-in routes (SYN-04.2 to SYN-04.5, SYN-04.7, and
//! SYN-04.8's revoke): `POST /v1/accounts`, `POST /v1/signin/challenge`,
//! `POST /v1/signin`, `POST /v1/signout` and `DELETE /v1/devices/{id}`.
//!
//! No password reaches the server in any form: a Mac signs a one-time nonce
//! with its device key and the server checks the signature with the public
//! key it stored (P5). A failed sign-in gets 401 with one body for every
//! reason, and its nonce is gone all the same. Ids, nonces and tokens come
//! from app-crypto's random source; the store keeps the SHA-256 of a token,
//! never the token.

use crate::Error;
use crate::auth::{Auth, token_hash, unauthorized};
use crate::blobs::Blobs;
use crate::http::{Body, blocking, error, failed, reply};
use crate::store::{self, Caller, Revoke};
use app_crypto::{random, sign};
use app_proto::limits::{CHALLENGE_SECONDS, MAX_JSON, SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS};
use app_proto::messages::{
    AccountCreate, AccountCreated, AccountId, Challenge, ChallengeRequest, DeviceId, ErrorCode,
    Session, SignIn,
};
use app_proto::signin;
use http_body_util::BodyExt;
use hyper::body::{Body as _, Incoming};
use hyper::{Response, StatusCode};
use std::sync::Arc;

/// The body of a JSON route, at most [`MAX_JSON`] bytes; `None` when it is
/// longer (refused from its `Content-Length` before one byte is read, or as
/// soon as the bytes pass the limit) or cut off: 400 (SYN-01.8, SYN-01.10).
async fn read_json(body: &mut Incoming) -> Option<Vec<u8>> {
    let limit = u64::try_from(MAX_JSON).unwrap_or(u64::MAX);
    if body.size_hint().lower() > limit {
        return None;
    }
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(data) = frame.ok()?.into_data() else {
            continue;
        };
        if out.len().saturating_add(data.len()) > MAX_JSON {
            return None;
        }
        out.extend_from_slice(&data);
    }
    Some(out)
}

/// The key an unknown or revoked device's sign-in is checked against, for
/// the time only: its result is never used. The P-256 generator, 65 SEC1
/// bytes (SEC 2 v2 section 2.4.2), a point on the curve, so the check does
/// all the work of a real one. Its private key is 1, so anyone can sign for
/// it: its result must never open a session.
const DECOY: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];

fn bad_request() -> Response<Body> {
    error(StatusCode::BAD_REQUEST, ErrorCode::BadRequest)
}

/// 16 bytes from app-crypto's random source (SYN-02.3, P20).
fn new_id() -> Result<AccountId, Error> {
    let mut id = [0u8; 16];
    random::fill(&mut id).map_err(|e| Error::new(format!("cannot draw an id: {e}")))?;
    Ok(AccountId::from_bytes(id))
}

/// `POST /v1/accounts` (SYN-04.2): an account and its first device; 201
/// with both ids, 409 for a key that is registered already, 400 for a body
/// that is not an `AccountCreate` or a key that is not a P-256 point
/// (CRY-04.4), which could never sign in.
pub(crate) async fn create(body: &mut Incoming, blobs: &Arc<Blobs>, auth: &Auth) -> Response<Body> {
    let Some(record) = read_json(body)
        .await
        .and_then(|b| AccountCreate::read(&b).ok())
        .filter(|r| sign::p256_public_ok(&r.device_public_key))
    else {
        return bad_request();
    };
    let (b, now) = (blobs.clone(), auth.now());
    let made = blocking(move || {
        let made = AccountCreated {
            account_id: new_id()?,
            device_id: new_id()?,
        };
        let key = record.device_public_key;
        let name = record.device_name;
        let fresh = b.store(|db| {
            store::create_account(db, &made.account_id, &made.device_id, &key, &name, now)
        })?;
        Ok(fresh.then_some(made))
    })
    .await;
    match made {
        Ok(Some(made)) => reply(StatusCode::CREATED, made.to_json()),
        Ok(None) => error(StatusCode::CONFLICT, ErrorCode::Conflict),
        Err(e) => failed(&e),
    }
}

/// `POST /v1/signin/challenge` (SYN-04.3): 32 random bytes, valid
/// [`CHALLENGE_SECONDS`], bound to the device id and stored. An unknown or
/// revoked device id gets the same reply after the same work; its sign-in
/// then fails.
pub(crate) async fn challenge(
    body: &mut Incoming,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(record) = read_json(body)
        .await
        .and_then(|b| ChallengeRequest::read(&b).ok())
    else {
        return bad_request();
    };
    let mut nonce = [0u8; 32];
    if let Err(e) = random::fill(&mut nonce) {
        return failed(&Error::new(format!("cannot draw a nonce: {e}")));
    }
    let (b, now) = (blobs.clone(), auth.now());
    let expires = now.saturating_add(CHALLENGE_SECONDS);
    let stored = blocking(move || {
        b.store(|db| store::challenge(db, &nonce, &record.device_id, expires, now))
    })
    .await;
    match stored {
        Ok(()) => reply(StatusCode::OK, Challenge { nonce, expires }.to_json()),
        Err(e) => failed(&e),
    }
}

/// `POST /v1/signin` (SYN-04.4, SYN-04.5): the nonce is deleted first,
/// whatever comes next; then, in order, it must have been bound to this
/// device and not expired, the device must exist, and the signature must
/// verify with its stored key over the message built with this server's
/// own origin. Then a session: 32 random bytes, stored as their SHA-256.
/// Any failure: 401, one body for every reason. An unknown or revoked
/// device is checked against [`DECOY`], so its failure costs the same time
/// as a wrong signature (SYN-04.3: ids cannot be probed).
pub(crate) async fn sign_in(
    body: &mut Incoming,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(record) = read_json(body).await.and_then(|b| SignIn::read(&b).ok()) else {
        return bad_request();
    };
    let (b, now, origin) = (blobs.clone(), auth.now(), auth.origin.clone());
    let token = blocking(move || {
        b.store(|db| {
            let Some((bound, expires)) = store::take_challenge(db, &record.nonce)? else {
                return Ok(None);
            };
            if bound != record.device_id || now >= expires {
                return Ok(None);
            }
            let Some(key) = store::device_key(db, &record.device_id)? else {
                let decoy =
                    signin::verify(&DECOY, &origin, &record.nonce, &bound, &record.signature);
                std::hint::black_box(decoy);
                return Ok(None);
            };
            if !signin::verify(&key, &origin, &record.nonce, &bound, &record.signature) {
                return Ok(None);
            }
            let token =
                random::bytes(32).map_err(|e| Error::new(format!("cannot draw a token: {e}")))?;
            store::open_session(db, &token_hash(token.expose())?, &bound, now)?;
            Ok(Some(token))
        })
    })
    .await;
    match token {
        Ok(Some(token)) => {
            let session = Session {
                token,
                idle_seconds: SESSION_IDLE_SECONDS,
                expires: now.saturating_add(SESSION_MAX_SECONDS),
            };
            reply(StatusCode::OK, session.to_json())
        }
        Ok(None) => unauthorized(),
        Err(e) => failed(&e),
    }
}

/// `POST /v1/signout` (SYN-04.7): this session's row goes; 204.
pub(crate) async fn sign_out(caller: Caller, blobs: &Arc<Blobs>) -> Response<Body> {
    let b = blobs.clone();
    match blocking(move || b.store(|db| store::end_session(db, &caller.session))).await {
        Ok(()) => reply(StatusCode::NO_CONTENT, Vec::new()),
        Err(e) => failed(&e),
    }
}

/// `DELETE /v1/devices/{device_id}` (SYN-04.8): revokes a device of this
/// account, this Mac included, with its sessions and open challenges; 204.
/// The account's last device gets 409; another account's id or an unknown
/// one gets 404.
pub(crate) async fn revoke(caller: Caller, device: DeviceId, blobs: &Arc<Blobs>) -> Response<Body> {
    let b = blobs.clone();
    match blocking(move || b.store(|db| store::revoke(db, &caller.account, &device))).await {
        Ok(Revoke::Done) => reply(StatusCode::NO_CONTENT, Vec::new()),
        Ok(Revoke::NotFound) => error(StatusCode::NOT_FOUND, ErrorCode::NotFound),
        Ok(Revoke::Last) => error(StatusCode::CONFLICT, ErrorCode::Conflict),
        Err(e) => failed(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SYN-04.3: the decoy is a P-256 point, so an unknown device's check
    /// runs the whole verify, not a quick refusal of the key.
    #[test]
    fn syn04_3_decoy_is_a_p256_point() {
        assert!(sign::p256_public_ok(&DECOY));
    }
}
