//! The approval routes (E17-S2; SYN-06.11 with SYN-05 and CRY-05.8): a new
//! Mac N joins the account of a Mac E that approves it.
//!
//! - `POST /v1/approvals` (E's session): `{"code_hash"}`; 201
//!   `{"approval_id","expires"}`. The server keeps only the SHA-256 of the
//!   code, so it first sees the code at the claim.
//! - `POST /v1/approvals/claim` (`Authorization: Approval <code>`):
//!   `{"device_public_key","device_name"}`; 201
//!   `{"approval_id","account_id","expires"}`.
//! - `POST /v1/approvals/{approval_id}/commit` (the code): `{"commit"}`,
//!   SYN-05's message (1); 204.
//! - `POST …/keys` (E's session): `{"keys","nonce"}`, message (2); 204.
//! - `POST …/reveal` (the code): `{"keys","nonce"}`, message (3); 204.
//! - `POST …/seal` (E's session): the sealed `S_acct` and the device
//!   signature; the server checks the signature with the account's
//!   identity key and registers N's device (204), or answers 403.
//! - `GET` and `DELETE /v1/approvals/{approval_id}` (E's session or the
//!   code): what is stored so far; the request's end.
//!
//! Guarantees: each stage is accepted once and only after the one before
//! (SYN-05.2): a second claim, commitment, message (2) or (3) or seal, or
//! one out of order, gets 409 and ends the request. A request lives 15
//! minutes from its creation on the server's clock: after that the code
//! routes (the claim, the commitment, the reveal, and `GET` or `DELETE`
//! with the code) and `…/keys` get 401, the seal and `GET` or `DELETE`
//! with E's session 404 (SYN-06's edge case), and the request ends. When a
//! request ends, whichever way, its row goes with its nonces, commitment
//! and key lists, and a device its seal registered goes too unless N has
//! read the seal ("the first side's match has no effect", SYN-05). No
//! device is registered before the seal, which E sends only after its
//! user's Codes match. The code is hashed at once and never kept, logged
//! or put in a reply; a code that names no live request gets 401 with one
//! body for every reason.

use crate::Error;
use crate::accounts::{bad_request, new_id, read_json};
use crate::auth::{self, Auth, unauthorized};
use crate::blobs::Blobs;
use crate::http::{Body, blocking, error, failed, reply};
use crate::store::{self, Approval, Caller, Sealed, Stage};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Response, StatusCode};
use larsal_crypto::wrap_record::SUITE;
use larsal_crypto::{pq, sign};
use larsal_proto::approval::{
    self as wire, ApprovalClaim, ApprovalClaimed, ApprovalCreate, ApprovalSeal, ApprovalStart,
    CompareCommit, CompareKeys, KEYS_C, KEYS_R,
};
use larsal_proto::limits::APPROVAL_SECONDS;
use larsal_proto::messages::{ErrorCode, Id};
use larsal_proto::wrap;
use rusqlite::Connection;
use std::sync::Arc;

/// What a route came to.
enum Done {
    /// The reply.
    Reply(StatusCode, Vec<u8>),
    /// 401: no live request has this code.
    Refused,
    /// 404.
    NotFound,
    /// 409: a second or out-of-order message; the request has ended.
    Conflict,
    /// 403: the device signature does not verify; the request has ended.
    Forbidden,
}

fn answer(done: Result<Done, Error>) -> Response<Body> {
    match done {
        Ok(Done::Reply(status, body)) => reply(status, body),
        Ok(Done::Refused) => unauthorized_approval(),
        Ok(Done::NotFound) => error(StatusCode::NOT_FOUND, ErrorCode::NotFound),
        Ok(Done::Conflict) => error(StatusCode::CONFLICT, ErrorCode::Conflict),
        Ok(Done::Forbidden) => error(StatusCode::FORBIDDEN, ErrorCode::Forbidden),
        Err(e) => failed(&e),
    }
}

/// 401 for the code routes: `WWW-Authenticate: Approval`, one body.
fn unauthorized_approval() -> Response<Body> {
    let mut r = unauthorized();
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(wire::SCHEME),
    );
    r
}

/// The SHA-256 of the approval code of `headers`' one `Authorization: Approval`
/// line; the code itself is wiped here.
fn code_hash(headers: &HeaderMap) -> Option<[u8; 32]> {
    let lines: Vec<&[u8]> = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let code = wire::approval(&lines)?;
    wire::code_hash(&code).ok()
}

/// The live request of the code with SHA-256 `hash`; one past its 15
/// minutes ends here and is `None`, as an unknown code is (401).
fn by_code(db: &mut Connection, hash: &[u8; 32], now: u64) -> Result<Option<Approval>, Error> {
    let Some(row) = store::approval_by_code(db, hash)? else {
        return Ok(None);
    };
    if now >= row.state.expires {
        store::end_approval(db, &row.id)?;
        return Ok(None);
    }
    Ok(Some(row))
}

/// As [`by_code`] for the code route of request `id`: 401 for no live
/// request, 404 when the code is another request's.
fn code_route(
    db: &mut Connection,
    hash: &[u8; 32],
    id: &Id,
    now: u64,
) -> Result<Result<Approval, Done>, Error> {
    Ok(match by_code(db, hash, now)? {
        None => Err(Done::Refused),
        Some(row) if row.id != *id => Err(Done::NotFound),
        Some(row) => Ok(row),
    })
}

/// E's request `id`: 404 when it is not this account's; one past its 15
/// minutes ends here with `expired` (401 for keys, 404 for the seal and
/// the reads).
fn session_route(
    db: &mut Connection,
    caller: &Caller,
    id: &Id,
    now: u64,
    expired: Done,
) -> Result<Result<Approval, Done>, Error> {
    let Some(row) = store::approval_of(db, id, &caller.account)? else {
        return Ok(Err(Done::NotFound));
    };
    if now >= row.state.expires {
        store::end_approval(db, id)?;
        return Ok(Err(expired));
    }
    Ok(Ok(row))
}

/// A message at the wrong stage: the request ends (SYN-05.2).
fn conflict(db: &mut Connection, id: &Id) -> Result<Done, Error> {
    store::end_approval(db, id)?;
    Ok(Done::Conflict)
}

/// `POST /v1/approvals` (step 1): E's new request, valid
/// [`APPROVAL_SECONDS`] from now; the requests past their 15 minutes end
/// first.
pub(crate) async fn create(
    body: &mut Incoming,
    caller: Caller,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(record) = read_json(body)
        .await
        .and_then(|b| ApprovalCreate::read(&b).ok())
    else {
        return bad_request();
    };
    let (b, now) = (blobs.clone(), auth.now());
    let expires = now.saturating_add(APPROVAL_SECONDS);
    answer(
        blocking(move || {
            let id = new_id()?;
            b.store(|db| {
                let made = store::create_approval(
                    db,
                    &id,
                    &caller.account,
                    &record.code_hash,
                    expires,
                    now,
                )?;
                Ok(if made {
                    let start = ApprovalStart {
                        approval_id: id,
                        expires,
                    };
                    Done::Reply(StatusCode::CREATED, start.to_json())
                } else {
                    Done::Conflict
                })
            })
        })
        .await,
    )
}

/// `POST /v1/approvals/claim` (step 2): N's device key (a P-256 point) and
/// name for the request of the code; 201 with the request and its account,
/// 401 for a code that names no live request, 409 (the request ends) when
/// it was claimed already.
pub(crate) async fn claim(
    headers: &HeaderMap,
    body: &mut Incoming,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(hash) = code_hash(headers) else {
        return unauthorized_approval();
    };
    let Some(record) = read_json(body)
        .await
        .and_then(|b| ApprovalClaim::read(&b).ok())
        .filter(|r| sign::p256_public_ok(&r.device_public_key))
    else {
        return bad_request();
    };
    let (b, now) = (blobs.clone(), auth.now());
    answer(
        blocking(move || {
            b.store(|db| {
                let Some(row) = by_code(db, &hash, now)? else {
                    return Ok(Done::Refused);
                };
                if row.stage != Stage::Open
                    || !store::claim_approval(
                        db,
                        &row.id,
                        &record.device_public_key,
                        &record.device_name,
                    )?
                {
                    return conflict(db, &row.id);
                }
                let claimed = ApprovalClaimed {
                    approval_id: row.id,
                    account_id: row.account,
                    expires: row.state.expires,
                };
                Ok(Done::Reply(StatusCode::CREATED, claimed.to_json()))
            })
        })
        .await,
    )
}

/// `POST /v1/approvals/{approval_id}/commit`: SYN-05's message (1), once,
/// after the claim.
pub(crate) async fn commit(
    headers: &HeaderMap,
    body: &mut Incoming,
    id: Id,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(hash) = code_hash(headers) else {
        return unauthorized_approval();
    };
    let Some(record) = read_json(body)
        .await
        .and_then(|b| CompareCommit::read(&b).ok())
    else {
        return bad_request();
    };
    let (b, now) = (blobs.clone(), auth.now());
    answer(
        blocking(move || {
            b.store(|db| {
                let row = match code_route(db, &hash, &id, now)? {
                    Ok(row) => row,
                    Err(done) => return Ok(done),
                };
                if row.stage != Stage::Claimed || !store::commit_approval(db, &id, &record.commit)?
                {
                    return conflict(db, &id);
                }
                Ok(Done::Reply(StatusCode::NO_CONTENT, Vec::new()))
            })
        })
        .await,
    )
}

/// `POST …/keys`: SYN-05's message (2), `K_R` (2,057 bytes) and `n_R`,
/// once, after the commitment.
pub(crate) async fn keys(
    body: &mut Incoming,
    id: Id,
    caller: Caller,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(record) = read_json(body)
        .await
        .and_then(|b| CompareKeys::read(&b, KEYS_R).ok())
    else {
        return bad_request();
    };
    let (b, now) = (blobs.clone(), auth.now());
    answer(
        blocking(move || {
            b.store(|db| {
                let row = match session_route(db, &caller, &id, now, Done::Refused)? {
                    Ok(row) => row,
                    Err(done) => return Ok(done),
                };
                if row.stage != Stage::Committed
                    || !store::keys_approval(db, &id, &record.keys, &record.nonce)?
                {
                    return conflict(db, &id);
                }
                Ok(Done::Reply(StatusCode::NO_CONTENT, Vec::new()))
            })
        })
        .await,
    )
}

/// `POST …/reveal`: SYN-05's message (3), `K_C` (1,289 bytes) and `n_C`,
/// once, after message (2).
pub(crate) async fn reveal(
    headers: &HeaderMap,
    body: &mut Incoming,
    id: Id,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(hash) = code_hash(headers) else {
        return unauthorized_approval();
    };
    let Some(record) = read_json(body)
        .await
        .and_then(|b| CompareKeys::read(&b, KEYS_C).ok())
    else {
        return bad_request();
    };
    let (b, now) = (blobs.clone(), auth.now());
    answer(
        blocking(move || {
            b.store(|db| {
                let row = match code_route(db, &hash, &id, now)? {
                    Ok(row) => row,
                    Err(done) => return Ok(done),
                };
                if row.stage != Stage::Keyed
                    || !store::reveal_approval(db, &id, &record.keys, &record.nonce)?
                {
                    return conflict(db, &id);
                }
                Ok(Done::Reply(StatusCode::NO_CONTENT, Vec::new()))
            })
        })
        .await,
    )
}

/// `POST …/seal` (step 5), once, after message (3): a CRY-05.4 record of
/// the suite `[25722, 1, 3]` only (400 otherwise) and the identity key's
/// composite signature over (`sync-device-v1`, `account_id`, N's device
/// key, `approval_id`), checked with the account's stored identity key:
/// 403 when it does not verify or the account has no keys, 409 when N's
/// key is registered already (both end the request). Then N's device is
/// registered and the seal kept for N: 204. Past the 15 minutes: 404, and
/// nothing is registered (SYN-06's edge case).
pub(crate) async fn seal(
    body: &mut Incoming,
    id: Id,
    caller: Caller,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let Some(record) = read_json(body)
        .await
        .and_then(|b| ApprovalSeal::read(&b).ok())
        .filter(|r| r.seal.suite == SUITE)
    else {
        return bad_request();
    };
    let (b, now) = (blobs.clone(), auth.now());
    answer(
        blocking(move || {
            let device = new_id()?;
            b.store(|db| {
                let row = match session_route(db, &caller, &id, now, Done::NotFound)? {
                    Ok(row) => row,
                    Err(done) => return Ok(done),
                };
                let (Stage::Revealed, Some(key), Some(name)) = (
                    row.stage,
                    row.state.device_public_key,
                    row.state.device_name,
                ) else {
                    return conflict(db, &id);
                };
                let Some(keys) = store::account_keys(db, &caller.account)? else {
                    store::end_approval(db, &id)?;
                    return Ok(Done::Forbidden);
                };
                let message = wire::device_message(&caller.account, &key, &id)
                    .map_err(|_| Error::new("cannot build the device message"))?;
                if pq::composite_verify(
                    &keys.identity_public_key,
                    &message,
                    &record.device_signature,
                )
                .is_err()
                {
                    store::end_approval(db, &id)?;
                    return Ok(Done::Forbidden);
                }
                let sealed = wrap::to_json(&record.seal);
                match store::seal_approval(
                    db,
                    &id,
                    &caller.account,
                    &device,
                    &key,
                    &name,
                    &sealed,
                    now,
                )? {
                    Sealed::Done => Ok(Done::Reply(StatusCode::NO_CONTENT, Vec::new())),
                    Sealed::Taken | Sealed::Stale => conflict(db, &id),
                }
            })
        })
        .await,
    )
}

/// `GET /v1/approvals/{approval_id}` with E's session or the code: what is
/// stored so far (`ApprovalState`). N's read of a sealed request takes the
/// seal: the request is done and its row goes (SYN-06.11 step 6).
pub(crate) async fn get(
    headers: &HeaderMap,
    id: Id,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let now = auth.now();
    if let Some(hash) = code_hash(headers) {
        let b = blobs.clone();
        return answer(
            blocking(move || {
                b.store(|db| {
                    let row = match code_route(db, &hash, &id, now)? {
                        Ok(row) => row,
                        Err(done) => return Ok(done),
                    };
                    if row.stage == Stage::Sealed {
                        store::hand_over(db, &id)?;
                    }
                    Ok(Done::Reply(StatusCode::OK, row.state.to_json()))
                })
            })
            .await,
        );
    }
    let caller = match auth::caller(headers, blobs, auth).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let b = blobs.clone();
    answer(
        blocking(move || {
            b.store(|db| {
                Ok(
                    match session_route(db, &caller, &id, now, Done::NotFound)? {
                        Ok(row) => Done::Reply(StatusCode::OK, row.state.to_json()),
                        Err(done) => done,
                    },
                )
            })
        })
        .await,
    )
}

/// `DELETE /v1/approvals/{approval_id}` with E's session or the code: the
/// request ends (Codes differ, a failed check, 15 minutes), its row and any
/// device its seal registered with it; 204.
pub(crate) async fn delete(
    headers: &HeaderMap,
    id: Id,
    blobs: &Arc<Blobs>,
    auth: &Auth,
) -> Response<Body> {
    let now = auth.now();
    let ended = Done::Reply(StatusCode::NO_CONTENT, Vec::new());
    if let Some(hash) = code_hash(headers) {
        let b = blobs.clone();
        return answer(
            blocking(move || {
                b.store(|db| {
                    if let Err(done) = code_route(db, &hash, &id, now)? {
                        return Ok(done);
                    }
                    store::end_approval(db, &id)?;
                    Ok(ended)
                })
            })
            .await,
        );
    }
    let caller = match auth::caller(headers, blobs, auth).await {
        Ok(caller) => caller,
        Err(refused) => return *refused,
    };
    let b = blobs.clone();
    answer(
        blocking(move || {
            b.store(|db| {
                if let Err(done) = session_route(db, &caller, &id, now, Done::NotFound)? {
                    return Ok(done);
                }
                store::end_approval(db, &id)?;
                Ok(ended)
            })
        })
        .await,
    )
}
