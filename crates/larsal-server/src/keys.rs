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
//! (a keyless or unknown account is checked against the decoy the server
//! drew at start, `Auth::decoy`, whose private key nobody holds, and the
//! result is never used); its nonce is gone all the same and passes no
//! device sign-in (LD-327 (7)).

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
use rusqlite::Connection;
use std::sync::Arc;

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
    let (b, now, origin, decoy) = (blobs.clone(), auth.now(), auth.origin.clone(), auth.decoy);
    let done = blocking(move || b.store(|db| recover(db, &record, now, &origin, &decoy))).await;
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

/// The checks of [`recovery_sign_in`] on the store, in its order; a keyless
/// or unknown account is checked against `decoy` for the time only, and
/// that result is never used.
fn recover(
    db: &mut Connection,
    record: &RecoverySignIn,
    now: u64,
    origin: &str,
    decoy: &[u8; 32],
) -> Result<Recovery, Error> {
    let Some((bound, expires)) = store::take_recovery(db, &record.nonce)? else {
        return Ok(Recovery::Refused);
    };
    if bound != record.account_id || now >= expires {
        return Ok(Recovery::Refused);
    }
    let check = |key: &[u8; 32]| {
        signin::recovery_verify(
            key,
            origin,
            &record.nonce,
            &bound,
            &record.device_public_key,
            &record.signature,
        )
    };
    let Some(keys) = store::account_keys(db, &bound)? else {
        std::hint::black_box(check(decoy));
        return Ok(Recovery::Refused);
    };
    if !check(&keys.recovery_public_key) {
        return Ok(Recovery::Refused);
    }
    let device = new_id()?;
    let token = random::bytes(32).map_err(|e| Error::new(format!("cannot draw a token: {e}")))?;
    let hash = token_hash(token.expose())?;
    let key = record.device_public_key;
    let name = record.device_name.as_str();
    if !store::recover_device(db, &bound, &device, &key, name, &hash, now)? {
        return Ok(Recovery::Taken);
    }
    Ok(Recovery::Done(device, token))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::data::tests::Scratch;

    /// RFC 8032 section 5.1's base point B, whose private scalar is 1: the
    /// decoy of E17-S1, kept here to show the drawn one is not it.
    const B: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// Checker 2's scalar-1 signature over its demo message
    /// (e17s1 c2/scripts/decoy.py, RFC 8032 arithmetic, no Larsal code).
    const C2_MESSAGE: &[u8] = b"sync-recovery-signin-v1 demo message for the decoy proof";
    const C2_SIGNATURE: &str = "8f5b037474d0c5a271d7ed32fd9ca87d31b366f2f5bc993b740b2fdd74c236cb\
                                85f977ff4867f6a816b0eb7f2d90ba5946822e330dcddd83ec0354a7b096d900";

    /// The fixed inputs of the scalar-1 recovery signatures below, which
    /// proof/decoy-scalar-one.py made over SYN-06.12's message.
    const ORIGIN: &str = "https://127.0.0.1:1";
    const NONCE: [u8; 32] = [0x37; 32];
    /// The P-256 generator, 65 SEC1 bytes (SEC 2 v2 section 2.4.2): a point.
    const DEVICE: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                          4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    /// For account [1; 16] (keyless) and [9; 16] (unknown).
    const KEYLESS_SIGNATURE: &str = "84adc36018c28326e3b2b7addf77689b5e602bc7837703af5b41681f5a228cc6\
                                     05757e43d30d987367810e6b8aa04655affe790560a84bf85159aa86474f8600";
    const UNKNOWN_SIGNATURE: &str = "bd2e783079a6a277f08c54225e29149ed9c5ab0bd74b776beb5ebef11beea656\
                                     0803df0f96b1c5203a4cdf7721d1cac6e353540c07ceddd18d3505a7f2d3c10d";

    /// E17-S1's finding C2-F2 (ruling (13)(b)): the decoy is drawn at each
    /// start, is a point (a seed's public key, so the check runs the whole
    /// verify), is never B, and a signature by scalar 1, which verifies
    /// with B, does not verify with it.
    #[test]
    fn syn06_12_c2_f2_the_decoy_is_drawn_at_start_and_nobody_holds_its_key() {
        let (one, two) = (
            Auth::new(String::new()).unwrap(),
            Auth::new(String::new()).unwrap(),
        );
        assert_ne!(one.decoy, two.decoy, "drawn at each start");
        assert_ne!(one.decoy, B);
        let signature = hex(C2_SIGNATURE);
        assert!(
            sign::ed25519_verify(&B, C2_MESSAGE, &signature).is_ok(),
            "control: the vector is a scalar-1 signature"
        );
        assert!(sign::ed25519_verify(&one.decoy, C2_MESSAGE, &signature).is_err());
        let seed = SecretBytes::new(vec![5; 32]);
        let signed = sign::ed25519_sign(&seed, b"m").unwrap();
        let public = sign::ed25519_public(&seed).unwrap();
        assert!(sign::ed25519_verify(&public, b"m", &signed).is_ok());
        assert!(sign::ed25519_verify(&one.decoy, b"m", &signed).is_err());
    }

    /// Checker 2's test (mutant S06, ruling (13)(b)): a recovery sign-in
    /// with a signature by scalar 1 for a keyless account and for an
    /// unknown one is refused (401) and writes no device, even with B as
    /// the decoy, where that signature verifies: the decoy's result is
    /// never used.
    #[test]
    fn syn06_12_c2_a_scalar_one_signature_for_a_keyless_or_unknown_account_registers_nothing() {
        let scratch = Scratch::new();
        let mut db = store::open(&scratch.0.join("store.sqlite")).unwrap();
        let keyless = AccountId::from_bytes([1; 16]);
        let first = DeviceId::from_bytes([101; 16]);
        assert!(store::create_account(&mut db, &keyless, &first, &[1; 65], "Mac", 1).unwrap());
        let unknown = AccountId::from_bytes([9; 16]);
        let t0 = 1_800_000_000;
        let device: [u8; 65] = hex(DEVICE).try_into().unwrap();
        assert!(sign::p256_public_ok(&device));
        let devices = |db: &Connection| -> i64 {
            db.query_row("SELECT count(*) FROM devices", [], |r| r.get(0))
                .unwrap()
        };
        let before = devices(&db);
        for (account, signature) in [(keyless, KEYLESS_SIGNATURE), (unknown, UNKNOWN_SIGNATURE)] {
            let signature = hex(signature);
            let message = signin::recovery_message(ORIGIN, &NONCE, &account, &device).unwrap();
            assert!(
                sign::ed25519_verify(&B, &message, &signature).is_ok(),
                "control: a scalar-1 signature over this sign-in"
            );
            let record = RecoverySignIn {
                account_id: account,
                nonce: NONCE,
                device_public_key: device,
                device_name: "Mac".to_owned(),
                signature: signature.try_into().unwrap(),
            };
            for decoy in [B, Auth::new(String::new()).unwrap().decoy] {
                store::recovery_challenge(&db, &NONCE, &account, t0 + 300, t0).unwrap();
                let done = recover(&mut db, &record, t0 + 1, ORIGIN, &decoy).unwrap();
                assert!(matches!(done, Recovery::Refused), "401");
                assert_eq!(devices(&db), before, "no device row");
            }
        }
    }
}
