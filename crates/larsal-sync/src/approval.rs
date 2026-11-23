//! A new Mac by approval on this Mac (E17-S2; SYN-05, SYN-06.11 with
//! SYN-06.14): E, the Mac that holds the account's keys, approves N, the
//! new Mac, after both users compared one 6-digit code.
//!
//! - [`Committer`] and [`Responder`] are SYN-05's two roles with no network:
//!   C (N) sends its commitment first and its keys and nonce only after it
//!   has R's message (2); R (E) answers only a commitment it holds, draws
//!   `n_R` only then, and checks the reveal against the commitment, whole,
//!   in constant time (CRY-04.11). Both give a [`Compared`]: the code.
//! - E: [`Server::approval_start`] draws the approval code (16 bytes) and
//!   sends only its SHA-256; [`Approver::poll`] answers N's commitment with
//!   `K_R` and `n_R` and checks N's reveal; [`ECompared`] shows the code.
//!   Only [`ECompared::codes_match`] gives an [`EMatched`], the one value
//!   that can seal `S_acct` and sign N's device ([`EMatched::seal`]).
//! - N: [`Server::approval_claim`] claims with the typed code, makes the
//!   one-request X-Wing key pair and sends the commitment;
//!   [`Claimant::poll`] reveals once E's keys are in; only
//!   [`NCompared::codes_match`] gives an [`NMatched`], the one value that
//!   reads the seal: [`NMatched::poll`] checks that its signer is the
//!   identity key both Macs compared and opens it with the info N builds
//!   itself; [`NSealed::finish`] signs in, unwraps the blob with the
//!   password and checks that its identity seed gives the compared key
//!   before anything is pinned or kept.
//! - Codes differ, a failed check, a second message or 15 minutes on this
//!   Mac's own [`Clock`]: `DELETE /v1/approvals/{approval_id}`, and the
//!   request's values (the code, the nonces, the commitment, the
//!   one-request private key) are dropped, which wipes them.
//!
//! Secrets (rule 4): the approval code, the nonces until revealed, the
//! commitment, the one-request seed and `S_acct` live only in
//! `SecretBytes` and `SecretString`, wiped on drop; every type here prints
//! `[hidden]` or names no secret; no error holds one. Crypto only through
//! larsal-crypto.

use crate::account::{AccountFail, JSON, Keep, status_fail};
use crate::client::{Fail, Server, Signer, signin_fail};
use crate::sync::Clock;
use larsal_crypto::secret::{SecretBytes, SecretString, ct_eq};
use larsal_crypto::{pq, random, wrap_record};
use larsal_platform::net::Method;
use larsal_proto::approval::{
    self as wire, ApprovalClaim, ApprovalClaimed, ApprovalCreate, ApprovalSeal, ApprovalStart,
    ApprovalState, CODE_BYTES, CompareCommit, CompareKeys, DEVICE_KEY, KEYS_C, KEYS_R,
};
use larsal_proto::limits::{APPROVAL_SECONDS, MAX_JSON};
use larsal_proto::messages::{AccountId, DeviceId, Id};
use larsal_proto::{routes, wrap as record};
use std::fmt;

/// A request's life on this Mac's own clock (SYN-06.11: 15 minutes).
pub const LIFE_MS: u64 = APPROVAL_SECONDS.saturating_mul(1000);
/// SYN-05's nonces.
const NONCE: usize = 32;
/// The name N's claim gives the new device: never the computer's name.
const NAME: &str = "Mac";

/// What a poll gives: the same step while the other Mac has not answered,
/// or the next step.
#[derive(Debug)]
pub enum Polled<W, R> {
    /// The other Mac has not answered yet: poll again.
    Waiting(W),
    /// The next step.
    Ready(R),
}

fn code_failed<E>(_: E) -> AccountFail {
    AccountFail::CodeFailed
}

fn store<E>(_: E) -> AccountFail {
    AccountFail::Store
}

fn nonce_of(bytes: &SecretBytes) -> Result<[u8; NONCE], AccountFail> {
    <[u8; NONCE]>::try_from(bytes.expose()).map_err(code_failed)
}

/// SYN-05's role C (N's side): message (1), the commitment, first; `K_C`
/// and `n_C` leave only in message (3).
pub struct Committer {
    ctx: Vec<u8>,
    keys: Vec<u8>,
    nonce: SecretBytes,
    commit: SecretBytes,
}

/// Names no value.
impl fmt::Debug for Committer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[hidden]")
    }
}

impl Committer {
    /// Draws `n_C` from larsal-crypto's random source and makes the
    /// commitment over (`sync-compare-commit-v1`, `ctx`, `K_C` = `keys`,
    /// `n_C`) (SYN-05.1).
    ///
    /// # Errors
    /// [`AccountFail::Store`] when the random source fails.
    pub fn new(ctx: Vec<u8>, keys: Vec<u8>) -> Result<Self, AccountFail> {
        let nonce = random::bytes(NONCE).map_err(store)?;
        let commit = wire::commitment(&ctx, &keys, nonce.expose()).map_err(code_failed)?;
        Ok(Self {
            ctx,
            keys,
            nonce,
            commit,
        })
    }

    /// Message (1).
    ///
    /// # Errors
    /// Never in practice.
    pub fn commit(&self) -> Result<[u8; 32], AccountFail> {
        <[u8; 32]>::try_from(self.commit.expose()).map_err(code_failed)
    }

    /// Message (2), `K_R` and `n_R`, in; message (3), `K_C` and `n_C`, out,
    /// with the code (SYN-05.4: the fields in R's order, then C's).
    ///
    /// # Errors
    /// [`AccountFail::CodeFailed`] for a `K_R` of another length.
    pub fn reveal(
        self,
        keys_r: &[u8],
        nonce_r: &[u8; NONCE],
    ) -> Result<(CompareKeys, Compared), AccountFail> {
        if keys_r.len() != KEYS_R {
            return Err(AccountFail::CodeFailed);
        }
        let code = wire::code(&self.ctx, keys_r, &self.keys, nonce_r, self.nonce.expose())
            .map_err(code_failed)?;
        let message = CompareKeys {
            nonce: nonce_of(&self.nonce)?,
            keys: self.keys,
        };
        Ok((
            message,
            Compared {
                code,
                other: keys_r.to_vec(),
            },
        ))
    }
}

/// SYN-05's role R (E's side): message (2) answers a commitment already
/// held, with `n_R` drawn only then; message (3) is checked against the
/// commitment.
pub struct Responder {
    ctx: Vec<u8>,
    keys: Vec<u8>,
    nonce: SecretBytes,
    commit: SecretBytes,
}

/// Names no value.
impl fmt::Debug for Responder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[hidden]")
    }
}

impl Responder {
    /// SYN-05.2: with the commitment `commit` held, draws `n_R` and makes
    /// message (2) with `K_R` = `keys`.
    ///
    /// # Errors
    /// [`AccountFail::Store`] when the random source fails.
    pub fn answer(
        ctx: Vec<u8>,
        keys: Vec<u8>,
        commit: &[u8; 32],
    ) -> Result<(Self, CompareKeys), AccountFail> {
        let nonce = random::bytes(NONCE).map_err(store)?;
        #[cfg(test)]
        probe::drew_nonce_r();
        let message = CompareKeys {
            keys: keys.clone(),
            nonce: nonce_of(&nonce)?,
        };
        let commit = SecretBytes::new(commit.to_vec());
        Ok((
            Self {
                ctx,
                keys,
                nonce,
                commit,
            },
            message,
        ))
    }

    /// SYN-05.3: message (3) in; the commitment is made again from it and
    /// compared with the one held, all 32 bytes, in constant time. Only a
    /// match gives the code.
    ///
    /// # Errors
    /// [`AccountFail::CodeFailed`]: no code is shown.
    pub fn check(self, keys_c: &[u8], nonce_c: &[u8; NONCE]) -> Result<Compared, AccountFail> {
        let again = wire::commitment(&self.ctx, keys_c, nonce_c).map_err(code_failed)?;
        if !ct_eq(again.expose(), self.commit.expose()) {
            return Err(AccountFail::CodeFailed);
        }
        let code = wire::code(&self.ctx, &self.keys, keys_c, self.nonce.expose(), nonce_c)
            .map_err(code_failed)?;
        Ok(Compared {
            code,
            other: keys_c.to_vec(),
        })
    }
}

/// Both messages in: the code to compare and the other side's key list.
pub struct Compared {
    code: u32,
    other: Vec<u8>,
}

/// The code is shown on the screen; the key list is public.
impl fmt::Debug for Compared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Compared")
            .field("code", &wire::shown(self.code))
            .finish_non_exhaustive()
    }
}

impl Compared {
    /// SYN-05.4's code as shown: 6 digits in two groups of 3 (`042 917`).
    #[must_use]
    pub fn code(&self) -> String {
        wire::shown(self.code)
    }

    /// The other side's key list (`K_C` for R, `K_R` for C).
    #[must_use]
    pub fn other_keys(&self) -> &[u8] {
        &self.other
    }
}

fn path(id: &Id, tail: &str) -> String {
    format!("{}/{id}{tail}", routes::APPROVALS)
}

fn expired(started: u64, clock: &dyn Clock) -> bool {
    clock.now_ms().saturating_sub(started) >= LIFE_MS
}

/// Ends E's request: `DELETE` with E's session. The server ends it either
/// way (or did already), so the answer does not matter.
fn end_by_session<K: Signer>(server: &mut Server<K>, id: &Id) -> AccountFail {
    let _ = server.call(Method::Delete, &path(id, ""), &[], MAX_JSON as u64);
    AccountFail::CodeFailed
}

/// Ends N's request: `DELETE` with the approval code.
fn end_by_code<K: Signer>(server: &Server<K>, id: &Id, code: &SecretBytes) -> AccountFail {
    let auth = wire::authorization(code);
    let _ = server.send(
        Method::Delete,
        &path(id, ""),
        &[("authorization", auth.expose())],
        MAX_JSON as u64,
    );
    AccountFail::CodeFailed
}

/// `GET /v1/approvals/{id}` with E's session.
fn state_by_session<K: Signer>(
    server: &mut Server<K>,
    id: &Id,
) -> Result<ApprovalState, AccountFail> {
    let r = server
        .call(Method::Get, &path(id, ""), &[], MAX_JSON as u64)
        .map_err(AccountFail::Net)?;
    match r.status {
        200 => ApprovalState::read(&r.body).map_err(|_| AccountFail::Net(Fail::Protocol)),
        401 | 404 => Err(AccountFail::CodeFailed),
        s => Err(status_fail(s, r.retry_after)),
    }
}

/// `GET /v1/approvals/{id}` with the approval code.
fn state_by_code<K: Signer>(
    server: &Server<K>,
    id: &Id,
    code: &SecretBytes,
) -> Result<ApprovalState, AccountFail> {
    let auth = wire::authorization(code);
    let a = server
        .send(
            Method::Get,
            &path(id, ""),
            &[("authorization", auth.expose())],
            MAX_JSON as u64,
        )
        .map_err(AccountFail::Net)?;
    match a.status {
        200 => ApprovalState::read(&a.body).map_err(|_| AccountFail::Net(Fail::Protocol)),
        401 | 404 => Err(AccountFail::CodeFailed),
        _ => Err(AccountFail::Net(signin_fail(&a))),
    }
}

/// A POST of N's with the approval code: 204 or the request is over.
fn post_by_code<K: Signer>(
    server: &Server<K>,
    id: &Id,
    tail: &str,
    code: &SecretBytes,
    body: &[u8],
) -> Result<(), AccountFail> {
    let auth = wire::authorization(code);
    let a = server
        .send(
            Method::Post(body),
            &path(id, tail),
            &[JSON, ("authorization", auth.expose())],
            MAX_JSON as u64,
        )
        .map_err(AccountFail::Net)?;
    match a.status {
        204 => Ok(()),
        429 => Err(AccountFail::Net(signin_fail(&a))),
        _ => Err(end_by_code(server, id, code)),
    }
}

/// E's request (SYN-06.11 steps 1 and 3): the code to show, and the polls
/// that answer N's commitment and check N's reveal.
pub struct Approver {
    id: Id,
    account: AccountId,
    code: SecretBytes,
    started: u64,
    keys: Vec<u8>,
    answered: Option<Answered>,
}

/// E's message (2), sent: what the later polls check against.
struct Answered {
    device: [u8; DEVICE_KEY],
    name: String,
    commit: SecretBytes,
    sent: CompareKeys,
    responder: Responder,
}

/// The request's id only.
impl fmt::Debug for Approver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Approver")
            .field("id", &self.id)
            .field("answered", &self.answered.is_some())
            .finish_non_exhaustive()
    }
}

impl<K: Signer> Server<K> {
    /// SYN-06.11 step 1 on E: draws the approval code (16 bytes from
    /// larsal-crypto's random source) and sends only its SHA-256 with
    /// `POST /v1/approvals`. The request lives 15 minutes from now on
    /// `clock`.
    ///
    /// # Errors
    /// [`AccountFail::KeysChanged`] for a stopped account and
    /// [`AccountFail::NoKeys`] without keys, before anything is drawn;
    /// [`AccountFail::Store`]; else [`AccountFail::Net`].
    pub fn approval_start(&mut self, clock: &dyn Clock) -> Result<Approver, AccountFail> {
        let (account, keys) = self.usable()?;
        let account = *account;
        let identity = keys.identity_public_key().to_vec();
        let (_, key) = self.device.as_ref().ok_or(AccountFail::Net(Fail::Key))?;
        let device = key.public_key().map_err(AccountFail::Net)?;
        let keys_r = wire::keys_r(&identity, &device).map_err(code_failed)?;
        let code = random::bytes(CODE_BYTES).map_err(store)?;
        let body = ApprovalCreate {
            code_hash: wire::code_hash(&code).map_err(code_failed)?,
        }
        .to_json();
        let r = self
            .call(
                Method::Post(&body),
                routes::APPROVALS,
                &[JSON],
                MAX_JSON as u64,
            )
            .map_err(AccountFail::Net)?;
        if r.status != 201 {
            return Err(status_fail(r.status, r.retry_after));
        }
        let start = ApprovalStart::read(&r.body).map_err(|_| AccountFail::Net(Fail::Protocol))?;
        Ok(Approver {
            id: start.approval_id,
            account,
            code,
            started: clock.now_ms(),
            keys: keys_r,
            answered: None,
        })
    }

    /// SYN-06.11 step 2 on N: claims the request with the code the user
    /// typed (`Authorization: Approval`, read case-blind, spaces and `-`
    /// ignored) for the device `key`, makes the one-request X-Wing key
    /// pair, and sends the commitment (SYN-05.1) with
    /// `POST /v1/approvals/{approval_id}/commit`. The request lives 15
    /// minutes from now on `clock`.
    ///
    /// # Errors
    /// [`AccountFail::CodeFailed`] for a code that does not read, is not
    /// known, has expired or was claimed; [`AccountFail::Store`]; else
    /// [`AccountFail::Net`] (a 429: SYN-01.12's sign-in limit).
    pub fn approval_claim(
        &mut self,
        typed: &SecretString,
        key: K,
        clock: &dyn Clock,
    ) -> Result<Claimant<K>, AccountFail> {
        let code = wire::read_code(typed.expose()).ok_or(AccountFail::CodeFailed)?;
        let started = clock.now_ms();
        let device = key.public_key().map_err(AccountFail::Net)?;
        let body = ApprovalClaim {
            device_public_key: device,
            device_name: NAME.to_owned(),
        }
        .to_json();
        let a = {
            let auth = wire::authorization(&code);
            self.send(
                Method::Post(&body),
                routes::APPROVAL_CLAIM,
                &[JSON, ("authorization", auth.expose())],
                MAX_JSON as u64,
            )
            .map_err(AccountFail::Net)?
        };
        match a.status {
            201 => {}
            400 | 401 | 404 | 409 => return Err(AccountFail::CodeFailed),
            _ => return Err(AccountFail::Net(signin_fail(&a))),
        }
        let claimed =
            ApprovalClaimed::read(&a.body).map_err(|_| AccountFail::Net(Fail::Protocol))?;
        let id = claimed.approval_id;
        let made = (|| {
            let (seed, xwing) = pq::xwing_keypair().map_err(store)?;
            let ctx = wire::ctx(&claimed.account_id, &id).map_err(code_failed)?;
            let keys_c = wire::keys_c(&device, &xwing).map_err(code_failed)?;
            Ok::<_, AccountFail>((seed, Committer::new(ctx, keys_c)?))
        })();
        let (seed, committer) = match made {
            Ok(made) => made,
            Err(e) => {
                end_by_code(self, &id, &code);
                return Err(e);
            }
        };
        let body = CompareCommit {
            commit: committer.commit()?,
        }
        .to_json();
        post_by_code(self, &id, "/commit", &code, &body)?;
        Ok(Claimant {
            code,
            id,
            account: claimed.account_id,
            started,
            key,
            device,
            seed,
            committer,
        })
    }
}

impl Approver {
    /// The approval code as E shows it (`MSG-ACCOUNT-ADD-MAC`): base32 in
    /// groups of 4, in a `SecretString`.
    #[must_use]
    pub fn code(&self) -> SecretString {
        wire::code_shown(&self.code)
    }

    /// The request's id.
    #[must_use]
    pub fn id(&self) -> Id {
        self.id
    }

    /// One look at the request (`GET /v1/approvals/{approval_id}`). Once
    /// the server holds N's commitment, E draws `n_R` and sends message (2)
    /// with `POST …/keys` (SYN-05.2); once N's reveal is in, E checks that
    /// its device key is the claim's and that it matches the commitment
    /// (SYN-05.3), and gives the code. The claim, the commitment and E's
    /// own message (2) must stay as first seen.
    ///
    /// # Errors
    /// [`AccountFail::CodeFailed`] when the request ended or a check
    /// failed (E sends `DELETE` first); else [`AccountFail::Net`].
    pub fn poll<K: Signer>(
        mut self,
        server: &mut Server<K>,
        clock: &dyn Clock,
    ) -> Result<Polled<Self, ECompared>, AccountFail> {
        if expired(self.started, clock) {
            return Err(end_by_session(server, &self.id));
        }
        let state = state_by_session(server, &self.id)?;
        let Some(answered) = self.answered.take() else {
            let Some(commit) = state.commit else {
                return Ok(Polled::Waiting(self));
            };
            let (Some(device), Some(name)) = (state.device_public_key, state.device_name) else {
                return Err(end_by_session(server, &self.id));
            };
            let ctx = wire::ctx(&self.account, &self.id).map_err(code_failed)?;
            let (responder, sent) = Responder::answer(ctx, self.keys.clone(), &commit)?;
            let body = sent.to_json();
            let r = server
                .call(
                    Method::Post(&body),
                    &path(&self.id, "/keys"),
                    &[JSON],
                    MAX_JSON as u64,
                )
                .map_err(AccountFail::Net)?;
            if r.status != 204 {
                return Err(end_by_session(server, &self.id));
            }
            self.answered = Some(Answered {
                device,
                name,
                commit: SecretBytes::new(commit.to_vec()),
                sent,
                responder,
            });
            return Ok(Polled::Waiting(self));
        };
        let unchanged = state
            .device_public_key
            .is_some_and(|k| ct_eq(&k, &answered.device))
            && state
                .commit
                .is_some_and(|c| ct_eq(&c, answered.commit.expose()))
            && state.keys_r.as_ref().is_some_and(|(k, n)| {
                ct_eq(k, &answered.sent.keys) && ct_eq(n, &answered.sent.nonce)
            });
        if !unchanged {
            return Err(end_by_session(server, &self.id));
        }
        let Some((keys_c, nonce_c)) = state.keys_c else {
            self.answered = Some(answered);
            return Ok(Polled::Waiting(self));
        };
        let Some((device, xwing)) = wire::split_keys_c(&keys_c) else {
            return Err(end_by_session(server, &self.id));
        };
        if keys_c.len() != KEYS_C || !ct_eq(&device, &answered.device) {
            return Err(end_by_session(server, &self.id));
        }
        let Ok(compared) = answered.responder.check(&keys_c, &nonce_c) else {
            return Err(end_by_session(server, &self.id));
        };
        Ok(Polled::Ready(ECompared {
            id: self.id,
            account: self.account,
            started: self.started,
            device,
            name: answered.name,
            xwing,
            compared,
        }))
    }

    /// The user closed E's sheet: `DELETE`, and the request's values are
    /// wiped.
    pub fn cancel<K: Signer>(self, server: &mut Server<K>) {
        end_by_session(server, &self.id);
    }
}

/// E's side with both messages in: the code to show (`MSG-CODE-COMPARE`)
/// and N's keys, which E uses only after its user's Codes match.
pub struct ECompared {
    id: Id,
    account: AccountId,
    started: u64,
    device: [u8; DEVICE_KEY],
    name: String,
    xwing: Vec<u8>,
    compared: Compared,
}

/// The request and the code only.
impl fmt::Debug for ECompared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECompared")
            .field("id", &self.id)
            .field("code", &self.compared.code())
            .finish_non_exhaustive()
    }
}

impl ECompared {
    /// SYN-05.4's code as E shows it.
    #[must_use]
    pub fn code(&self) -> String {
        self.compared.code()
    }

    /// The name N's claim gave the new device.
    #[must_use]
    pub fn device_name(&self) -> &str {
        &self.name
    }

    /// E's user chose Codes match: the only way to [`EMatched::seal`].
    #[must_use]
    pub fn codes_match(self) -> EMatched {
        EMatched(self)
    }

    /// E's user chose Codes differ: `DELETE`; nothing is sealed or signed.
    pub fn codes_differ<K: Signer>(self, server: &mut Server<K>) {
        end_by_session(server, &self.id);
    }
}

/// E after its user's Codes match (SYN-05.5): the one value that seals.
#[derive(Debug)]
pub struct EMatched(ECompared);

impl EMatched {
    /// SYN-06.11 step 5: seals `S_acct` to N's one-request X-Wing key as
    /// CRY-05.4's record with info (`sync-wrap-info-v1`, `account-secret`,
    /// `account_id`, `approval_id`, N's device public key), signed by the
    /// identity key; signs N's device, the composite signature over
    /// (`sync-device-v1`, `account_id`, N's device public key,
    /// `approval_id`); sends both with `POST …/seal`. The server registers
    /// N's device only now. E first looks at the request: one N ended
    /// (Codes differ on N) gets no seal made at all.
    ///
    /// # Errors
    /// [`AccountFail::CodeFailed`] after 15 minutes, for an ended request,
    /// or when the server refuses (403, 404, 409); E sends `DELETE` on any
    /// refusal. [`AccountFail::KeysChanged`] when E's account stopped since
    /// the codes (or is another), [`AccountFail::Store`] when the seal
    /// cannot be made: E sends `DELETE` then too, and no seal is sent
    /// (ruling (5)). Else [`AccountFail::Net`].
    pub fn seal<K: Signer>(
        self,
        server: &mut Server<K>,
        clock: &dyn Clock,
    ) -> Result<(), AccountFail> {
        let e = self.0;
        if expired(e.started, clock) {
            return Err(end_by_session(server, &e.id));
        }
        let state = state_by_session(server, &e.id)?;
        if state.keys_c.is_none() || state.seal.is_some() {
            return Err(end_by_session(server, &e.id));
        }
        let body = match seal_body(&e, server) {
            Ok(body) => body,
            Err(fail) => {
                end_by_session(server, &e.id);
                return Err(fail);
            }
        };
        let r = server
            .call(
                Method::Post(&body),
                &path(&e.id, "/seal"),
                &[JSON],
                MAX_JSON as u64,
            )
            .map_err(AccountFail::Net)?;
        match r.status {
            204 => Ok(()),
            403 | 404 | 409 => Err(end_by_session(server, &e.id)),
            s => {
                let fail = status_fail(s, r.retry_after);
                end_by_session(server, &e.id);
                Err(fail)
            }
        }
    }
}

/// The body of E's `POST …/seal` (SYN-06.11 step 5): none while E's account
/// is stopped (SYN-06.6) or is not the request's.
fn seal_body<K: Signer>(e: &ECompared, server: &Server<K>) -> Result<Vec<u8>, AccountFail> {
    let (account, keys) = server.usable()?;
    if *account != e.account {
        return Err(AccountFail::KeysChanged);
    }
    let info = wire::seal_info(account, &e.id, &e.device).map_err(code_failed)?;
    let seal = wrap_record::make(
        &e.xwing,
        &info,
        keys.account_secret().expose(),
        *account.as_bytes(),
        keys.identity_private_key(),
    )
    .map_err(store)?;
    #[cfg(test)]
    probe::sealed();
    let message = wire::device_message(account, &e.device, &e.id).map_err(code_failed)?;
    let device_signature =
        pq::composite_sign(keys.identity_private_key(), &message).map_err(store)?;
    #[cfg(test)]
    probe::signed();
    Ok(ApprovalSeal {
        seal,
        device_signature,
    }
    .to_json())
}

/// N's claimed request: the code, the commitment sent, the one-request
/// key pair and the device key to register.
pub struct Claimant<K: Signer> {
    code: SecretBytes,
    id: Id,
    account: AccountId,
    started: u64,
    key: K,
    device: [u8; DEVICE_KEY],
    seed: SecretBytes,
    committer: Committer,
}

/// The request's id only.
impl<K: Signer> fmt::Debug for Claimant<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Claimant")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<K: Signer> Claimant<K> {
    /// The account N joins.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        self.account
    }

    /// One look at the request with the approval code. Once E's message
    /// (2) is in, N reveals `K_C` and `n_C` with `POST …/reveal` and gives
    /// the code (SYN-05.4). The claim and the commitment must be N's own.
    ///
    /// # Errors
    /// [`AccountFail::CodeFailed`] when the request ended or a check
    /// failed (N sends `DELETE` first); else [`AccountFail::Net`].
    pub fn poll(
        self,
        server: &mut Server<K>,
        clock: &dyn Clock,
    ) -> Result<Polled<Self, NCompared<K>>, AccountFail> {
        if expired(self.started, clock) {
            return Err(end_by_code(server, &self.id, &self.code));
        }
        let state = state_by_code(server, &self.id, &self.code)?;
        let commit = self.committer.commit()?;
        let ours = state
            .device_public_key
            .is_some_and(|k| ct_eq(&k, &self.device))
            && state.commit.is_some_and(|c| ct_eq(&c, &commit));
        if !ours {
            return Err(end_by_code(server, &self.id, &self.code));
        }
        let Some((keys_r, nonce_r)) = state.keys_r else {
            return Ok(Polled::Waiting(self));
        };
        let Some((identity, _)) = wire::split_keys_r(&keys_r) else {
            return Err(end_by_code(server, &self.id, &self.code));
        };
        let Self {
            code,
            id,
            account,
            started,
            key,
            device,
            seed,
            committer,
        } = self;
        let (reveal, compared) = match committer.reveal(&keys_r, &nonce_r) {
            Ok(done) => done,
            Err(e) => {
                end_by_code(server, &id, &code);
                return Err(e);
            }
        };
        post_by_code(server, &id, "/reveal", &code, &reveal.to_json())?;
        Ok(Polled::Ready(NCompared {
            code,
            id,
            account,
            started,
            key,
            device,
            seed,
            identity,
            keys_r,
            nonce_r,
            compared,
        }))
    }

    /// The user closed N's sheet: `DELETE`, and the request's values are
    /// wiped.
    pub fn cancel(self, server: &mut Server<K>) {
        end_by_code(server, &self.id, &self.code);
    }

    /// Tests only (`test-server`; tests/approval_wipe.rs, the wipe probe of
    /// E17-S2's ruling (11)): copies of N's request secrets, each in a
    /// `SecretBytes`: the approval code, `n_C` and the one-request X-Wing
    /// seed.
    #[cfg(feature = "test-server")]
    #[must_use]
    pub fn test_secrets(&self) -> [SecretBytes; 3] {
        [
            SecretBytes::new(self.code.expose().to_vec()),
            SecretBytes::new(self.committer.nonce.expose().to_vec()),
            SecretBytes::new(self.seed.expose().to_vec()),
        ]
    }
}

/// N's side with both messages in: the code to show (`MSG-CODE-COMPARE`)
/// and E's keys, which N uses only after its user's Codes match.
pub struct NCompared<K: Signer> {
    code: SecretBytes,
    id: Id,
    account: AccountId,
    started: u64,
    key: K,
    device: [u8; DEVICE_KEY],
    seed: SecretBytes,
    identity: Vec<u8>,
    keys_r: Vec<u8>,
    nonce_r: [u8; NONCE],
    compared: Compared,
}

/// The request and the code only.
impl<K: Signer> fmt::Debug for NCompared<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NCompared")
            .field("id", &self.id)
            .field("code", &self.compared.code())
            .finish_non_exhaustive()
    }
}

impl<K: Signer> NCompared<K> {
    /// SYN-05.4's code as N shows it.
    #[must_use]
    pub fn code(&self) -> String {
        self.compared.code()
    }

    /// N's user chose Codes match: the only way to the seal.
    #[must_use]
    pub fn codes_match(self) -> NMatched<K> {
        NMatched(self)
    }

    /// N's user chose Codes differ: `DELETE`; nothing is read or pinned.
    pub fn codes_differ(self, server: &mut Server<K>) {
        end_by_code(server, &self.id, &self.code);
    }
}

/// N after its user's Codes match (SYN-05.5): the one value that reads
/// the seal.
#[derive(Debug)]
pub struct NMatched<K: Signer>(NCompared<K>);

impl<K: Signer> NMatched<K> {
    /// SYN-06.11 step 6's first half: one look at the request. Once E's
    /// seal is in, N checks that the record's signer is this account and
    /// its signature verifies with the identity key of the compared `K_R`,
    /// opens it with the info N builds itself (never the record's) and its
    /// one-request seed, and takes the device the seal registered as this
    /// client's.
    ///
    /// # Errors
    /// [`AccountFail::CodeFailed`] when the request ended, E's message (2)
    /// changed, or the seal is refused (nothing of it is kept); else
    /// [`AccountFail::Net`].
    pub fn poll(
        self,
        server: &mut Server<K>,
        clock: &dyn Clock,
    ) -> Result<Polled<Self, NSealed>, AccountFail> {
        let n = &self.0;
        if expired(n.started, clock) {
            return Err(end_by_code(server, &n.id, &n.code));
        }
        let state = state_by_code(server, &n.id, &n.code)?;
        let unchanged = state
            .keys_r
            .as_ref()
            .is_some_and(|(k, r)| ct_eq(k, &n.keys_r) && ct_eq(r, &n.nonce_r));
        if !unchanged {
            return Err(end_by_code(server, &n.id, &n.code));
        }
        let Some((sealed, device_id)) = state.seal else {
            return Ok(Polled::Waiting(self));
        };
        let secret = open_seal(&sealed, n)?;
        let n = self.0;
        server.set_device(device_id, n.key);
        Ok(Polled::Ready(NSealed {
            account: n.account,
            device: device_id,
            identity: n.identity,
            secret,
        }))
    }
}

/// Opens E's seal: the signer and the signature (with the compared
/// identity key), then the info N builds, then the one-request seed.
fn open_seal<K: Signer>(sealed: &[u8], n: &NCompared<K>) -> Result<SecretBytes, AccountFail> {
    let seal = record::read(sealed).map_err(code_failed)?;
    if !ct_eq(&seal.signer, n.account.as_bytes()) {
        return Err(AccountFail::CodeFailed);
    }
    let info = wire::seal_info(&n.account, &n.id, &n.device).map_err(code_failed)?;
    let secret = wrap_record::open(&seal, &n.identity, &info, &n.seed).map_err(code_failed)?;
    if secret.len() != 32 {
        return Err(AccountFail::CodeFailed);
    }
    Ok(secret)
}

/// N with E's seal opened: `S_acct` and the identity key both Macs
/// compared, until [`NSealed::finish`] keeps them.
pub struct NSealed {
    account: AccountId,
    device: DeviceId,
    identity: Vec<u8>,
    secret: SecretBytes,
}

/// The ids only.
impl fmt::Debug for NSealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NSealed")
            .field("account", &self.account)
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl NSealed {
    /// The account N joined.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        self.account
    }

    /// N's device, as the seal registered it.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device
    }

    /// SYN-06.11 step 6's second half: signs in with N's device key and
    /// reads the account keys, unwraps the blob with `S_acct` and
    /// `password`, checks that the unwrapped identity seed gives the
    /// identity key both Macs compared and that the record is these keys
    /// with a binding that verifies; only then pins them and keeps the
    /// secrets in `keep` (SYN-06.8). It may be called again after a wrong
    /// password: N stays registered.
    ///
    /// # Errors
    /// [`AccountFail::RestoreFailed`] for a wrong password;
    /// [`AccountFail::NeedsUpdate`]; [`AccountFail::KeysChanged`];
    /// [`AccountFail::Store`]; else [`AccountFail::Net`].
    pub fn finish<K: Signer>(
        &self,
        server: &mut Server<K>,
        password: &SecretString,
        keep: &dyn Keep,
    ) -> Result<(), AccountFail> {
        let keys = server.get_keys()?;
        server.adopt(
            &self.account,
            &self.secret,
            &keys,
            password,
            Some(&self.identity),
            keep,
        )
    }
}

/// Test-only counts on this thread (SYN-05 T04, T08; SYN-06 T09): `n_R`
/// draws, seals made, device signatures made, account keys pinned.
#[cfg(test)]
pub(crate) mod probe {
    use std::cell::Cell;

    thread_local! {
        static COUNTS: Cell<[usize; 4]> = const { Cell::new([0; 4]) };
    }

    fn add(at: usize) {
        COUNTS.with(|c| {
            let mut v = c.get();
            if let Some(n) = v.get_mut(at) {
                *n = n.wrapping_add(1);
            }
            c.set(v);
        });
    }

    pub(crate) fn drew_nonce_r() {
        add(0);
    }

    pub(crate) fn sealed() {
        add(1);
    }

    pub(crate) fn signed() {
        add(2);
    }

    pub(crate) fn pinned() {
        add(3);
    }

    /// (`n_R` draws, seals, device signatures, pins) so far on this thread.
    pub(crate) fn counts() -> [usize; 4] {
        COUNTS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests;
