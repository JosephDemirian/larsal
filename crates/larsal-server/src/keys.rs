//! The account keys, key-file part and recovery routes (E17-S1; SYN-06.6,
//! SYN-06.9, SYN-06.12, CRY-05.8): `PUT` and `GET /v1/account/keys`, `PUT`
//! and `GET /v1/vaults/{vault_id}/keypart`, `POST /v1/recovery/challenge`
//! and `POST /v1/recovery/signin`.
//!
//! Guarantees: the server only stores and returns: it never opens the blob
//! or a wrap, and holds no key that opens either (P6, P7, LD-340). The keys
//! are stored once (a second `PUT` gets 412: no key change in this build).
//! A key-file part record of any suite other than CRY-05.3's
//! `[25722, 1, 3]` is refused (400) before it is stored (CRY-05.7), so no
//! classical record reaches a reader through this server. A recovery
//! challenge gets the same reply for an unknown account, and a failed
//! recovery sign-in 401 with one body for every reason after the same work
//! (an unknown account is checked against [`DECOY`]); its nonce is gone all
//! the same and passes no device sign-in (LD-327 (7)).

use crate::Error;
use crate::accounts::{bad_request, new_id, read_json};
use crate::auth::{Auth, token_hash, unauthorized};
use crate::blobs::Blobs;
use crate::http::{Body, blocking, error, failed, reply};
use crate::store;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Response, StatusCode};
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::wrap_record::SUITE;
use larsal_crypto::{random, sign};
use larsal_proto::account::{AccountKeys, Recovered, RecoveryChallengeRequest, RecoverySignIn};
use larsal_proto::limits::{CHALLENGE_SECONDS, SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS};
use larsal_proto::messages::{AccountId, Challenge, DeviceId, ErrorCode, Session, VaultId};
use larsal_proto::routes::{self, Precondition, PreconditionError};
use larsal_proto::{signin, wrap};
use std::sync::Arc;

/// The key an unknown account's recovery sign-in is checked against, for
/// the time only: its result is never used. The Ed25519 base point B
/// (RFC 8032 section 5.1), whose encoding is a valid point, so the check
/// does all the work of a real one. Its private scalar is 1, so anyone can
/// sign for it: its result must never register a device.
const DECOY: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

fn lines<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Vec<&'a [u8]> {
    headers
        .get_all(name)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect()
}

/// `PUT /v1/account/keys` (SYN-06.6): with `If-None-Match: *` only (428
/// without a precondition, 412 with `If-Match`, 400 for both or a field that
/// does not read), a body that is CRY-05.8's record with every size right
/// (400 otherwise), stored once: 201, then 412.
pub(crate) async fn put(
    headers: &HeaderMap,
    body: &mut Incoming,
    account: AccountId,
    blobs: &Arc<Blobs>,
) -> Response<Body> {
    match routes::put_precondition(
        &lines(headers, &header::IF_MATCH),
        &lines(headers, &header::IF_NONE_MATCH),
    ) {
        Ok(Precondition::Create) => {}
        Ok(Precondition::Update(_)) => {
            return error(
                StatusCode::PRECONDITION_FAILED,
                ErrorCode::PreconditionFailed,
            );
        }
        Err(PreconditionError::Required) => {
            return error(
                StatusCode::PRECONDITION_REQUIRED,
                ErrorCode::PreconditionRequired,
            );
        }
        Err(PreconditionError::Bad) => return bad_request(),
    }
    let Some(keys) = read_json(body)
        .await
        .and_then(|b| AccountKeys::read(&b).ok())
    else {
        return bad_request();
    };
    let b = blobs.clone();
    match blocking(move || b.store(|db| store::put_account_keys(db, &account, &keys))).await {
        Ok(true) => reply(StatusCode::CREATED, Vec::new()),
        Ok(false) => error(
            StatusCode::PRECONDITION_FAILED,
            ErrorCode::PreconditionFailed,
        ),
        Err(e) => failed(&e),
    }
}

/// `GET /v1/account/keys` (SYN-06.6): 200 with the record; 404 before the
/// keys are stored.
pub(crate) async fn get(account: AccountId, blobs: &Arc<Blobs>) -> Response<Body> {
    let b = blobs.clone();
    match blocking(move || b.store(|db| store::account_keys(db, &account))).await {
        Ok(Some(keys)) => reply(StatusCode::OK, keys.to_json()),
        Ok(None) => error(StatusCode::NOT_FOUND, ErrorCode::NotFound),
        Err(e) => failed(&e),
    }
}

/// `PUT /v1/vaults/{vault_id}/keypart` (SYN-06.9): a wrap record (16 KiB at
/// most, CRY-05.14) of the suite `[25722, 1, 3]` only, kept in place of any
/// before it: 204; 400 for a body that is not such a record, before
/// anything is stored; 404 when the vault is not this account's.
pub(crate) async fn put_part(
    body: &mut Incoming,
    vault: VaultId,
    account: AccountId,
    blobs: &Arc<Blobs>,
) -> Response<Body> {
    let Some(record) = read_json(body)
        .await
        .and_then(|b| wrap::read(&b).ok())
        .filter(|r| r.suite == SUITE)
    else {
        return bad_request();
    };
    let stored = wrap::to_json(&record);
    let b = blobs.clone();
    match blocking(move || b.store(|db| store::put_keypart(db, &account, &vault, &stored))).await {
        Ok(true) => reply(StatusCode::NO_CONTENT, Vec::new()),
        Ok(false) => error(StatusCode::NOT_FOUND, ErrorCode::NotFound),
        Err(e) => failed(&e),
    }
}

/// `GET /v1/vaults/{vault_id}/keypart` (SYN-06.9): 200 with the record; 404
/// when the vault is not this account's or has none.
pub(crate) async fn get_part(
    vault: VaultId,
    account: AccountId,
    blobs: &Arc<Blobs>,
) -> Response<Body> {
    let b = blobs.clone();
    match blocking(move || b.store(|db| store::keypart(db, &account, &vault))).await {
        Ok(Some(record)) => reply(StatusCode::OK, record),
        Ok(None) => error(StatusCode::NOT_FOUND, ErrorCode::NotFound),
        Err(e) => failed(&e),
    }
}

/// `POST /v1/recovery/challenge` (SYN-06.12): 32 random bytes, valid
/// [`CHALLENGE_SECONDS`] (SYN-04.3's expiry), bound to the account id and
/// stored as a recovery challenge, for any account id: an unknown one gets
/// the same reply after the same work.
pub(crate) async fn recovery_challenge(
    body: &mut Incoming,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(record) = read_json(body)
        .await
        .and_then(|b| RecoveryChallengeRequest::read(&b).ok())
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
        b.store(|db| store::recovery_challenge(db, &nonce, &record.account_id, expires, now))
    })
    .await;
    match stored {
        Ok(()) => reply(StatusCode::OK, Challenge { nonce, expires }.to_json()),
        Err(e) => failed(&e),
    }
}

/// What a recovery sign-in came to.
enum Recovery {
    /// A new device and its session's token.
    Done(DeviceId, SecretBytes),
    /// 401: one reply for every reason.
    Refused,
    /// 409: the device key is registered already (SYN-04.2).
    Taken,
}

/// `POST /v1/recovery/signin` (SYN-06.12), checked as SYN-04.4 checks a
/// device: the nonce is deleted first, whatever comes next; then, in order,
/// it must be a recovery nonce bound to this account and not expired, the
/// account must have a recovery key, and the Ed25519 signature must verify
/// with it over the message built with this server's own origin. Then the
/// device is registered with its first session (409 for a key that is
/// registered already, 400 for a key that is not a P-256 point) and the
/// reply is the session with the device's id. Any failed check: 401.
pub(crate) async fn recovery_sign_in(
    body: &mut Incoming,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(record) = read_json(body)
        .await
        .and_then(|b| RecoverySignIn::read(&b).ok())
        .filter(|r| sign::p256_public_ok(&r.device_public_key))
    else {
        return bad_request();
    };
    let (b, now, origin) = (blobs.clone(), auth.now(), auth.origin.clone());
    let done = blocking(move || {
        b.store(|db| {
            let Some((bound, expires)) = store::take_recovery(db, &record.nonce)? else {
                return Ok(Recovery::Refused);
            };
            if bound != record.account_id || now >= expires {
                return Ok(Recovery::Refused);
            }
            let check = |key: &[u8; 32]| {
                signin::recovery_verify(
                    key,
                    &origin,
                    &record.nonce,
                    &bound,
                    &record.device_public_key,
                    &record.signature,
                )
            };
            let Some(keys) = store::account_keys(db, &bound)? else {
                std::hint::black_box(check(&DECOY));
                return Ok(Recovery::Refused);
            };
            if !check(&keys.recovery_public_key) {
                return Ok(Recovery::Refused);
            }
            let device = new_id()?;
            let token =
                random::bytes(32).map_err(|e| Error::new(format!("cannot draw a token: {e}")))?;
            let hash = token_hash(token.expose())?;
            let key = record.device_public_key;
            let name = record.device_name.as_str();
            if !store::recover_device(db, &bound, &device, &key, name, &hash, now)? {
                return Ok(Recovery::Taken);
            }
            Ok(Recovery::Done(device, token))
        })
    })
    .await;
    match done {
        Ok(Recovery::Done(device_id, token)) => {
            let session = Session {
                token,
                idle_seconds: SESSION_IDLE_SECONDS,
                expires: now.saturating_add(SESSION_MAX_SECONDS),
            };
            reply(StatusCode::OK, Recovered { device_id, session }.to_json())
        }
        Ok(Recovery::Refused) => unauthorized(),
        Ok(Recovery::Taken) => error(StatusCode::CONFLICT, ErrorCode::Conflict),
        Err(e) => failed(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SYN-06.12: the decoy is an Ed25519 point (B, RFC 8032 section 5.1),
    /// so an unknown account's check runs the whole verify; a signature by
    /// some seed never verifies with it.
    #[test]
    fn syn06_12_decoy_is_an_ed25519_point() {
        let mut one = vec![0u8; 32];
        one[0] = 1;
        let signed = sign::ed25519_sign(&SecretBytes::new(one), b"m").unwrap();
        assert!(sign::ed25519_verify(&DECOY, b"m", &signed).is_err());
        assert_eq!(DECOY[0], 0x58);
        assert!(DECOY[1..].iter().all(|b| *b == 0x66));
    }
}
