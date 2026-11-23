//! The account of SYN-06 on this Mac (E17-S1; CRY-05.8, CRY-05.10,
//! SYN-06.14): sign-up of the account keys (SYN-06.1 to SYN-06.7), their
//! pin (SYN-06.6), what this Mac keeps (SYN-06.8, LD-273 (2)), the key-file
//! part through the server (SYN-06.9), the upload signature's check
//! (SYN-03.11; the signing is [`Server::put`]'s) and a new Mac by Recovery
//! Kit (SYN-06.12).
//!
//! - Sign-up draws `S_acct`, the composite identity key and the X-Wing
//!   receiving seed (larsal-crypto `account.rs`), signs the binding, makes
//!   the blob (a fresh 32-byte salt, `K_wrap` of [`wrap::account_key`],
//!   AES-256-GCM with SYN-06.4's associated data, version 1) and the
//!   recovery key (SYN-06.5), keeps the secrets in the device store first,
//!   then sends `PUT /v1/account/keys` with `If-None-Match: *`.
//! - The blob is `version (2) ‖ salt (32) ‖ nonce (12) ‖ ciphertext (96) ‖
//!   tag (16)`, 158 bytes; a reader refuses another version before any
//!   Argon2id run.
//! - The Recovery Kit (SYN-06.7) is a wiping value; Larsal writes it
//!   nowhere. Its secret is base32 (RFC 4648 section 6) in upper case,
//!   without padding, 52 characters in 13 groups of 4; it is read
//!   case-blind, with hyphens and spaces ignored, and only in its one
//!   canonical form (the last character's 4 unused bits are zero).
//! - The pins are the public keys of the keys this Mac holds: after every
//!   GET of the keys the binding is checked with the record's identity key
//!   and both public keys are compared whole, in constant time, with this
//!   Mac's ([`pins_match`]). A failure stops the account: no upload is
//!   signed and no wrap opened until the user acts (`MSG-ACCOUNT-KEYS-
//!   CHANGED`).
//! - A wrong kit or a wrong password gives one [`AccountFail::RestoreFailed`],
//!   whose words never say which was wrong (`MSG-ACCOUNT-RESTORE-FAILED`).
//! - E17-S2: the stop of `MSG-ACCOUNT-KEYS-CHANGED` is kept in the device
//!   store, so [`Server::load_account`] after a restart stops the account
//!   again; only the user's restore (SYN-06.12) or approval (SYN-06.11,
//!   `approval.rs`) clears it. A 412 at sign-up gives a kit only when the
//!   server's blob opens with this `S_acct` and the password just typed
//!   (`MSG-ACCOUNT-OTHER-PASSWORD` otherwise).
//!
//! Secrets (CRY-05.17, rule 4): `S_acct`, the private keys, the recovery
//! seed, `A`, `K_wrap`, the blob's plaintext and the kit's text live only in
//! `SecretBytes` and `SecretString`, wiped on drop; [`Kit`]'s `Debug` prints
//! `[hidden]`; no error holds one. Crypto only through larsal-crypto.

use crate::client::{Fail, Server, Signer, parse_address, printed, read_printed, signin_fail};
use crate::sync::Message;
use larsal_crypto::account::{AccountKeys, BLOB_PLAINTEXT, check_kem_binding, pins_match};
use larsal_crypto::secret::{SecretBytes, SecretString, ct_eq};
use larsal_crypto::{pq, random, sign, wrap, wrap_record};
use larsal_platform::net::Method;
use larsal_proto::account::{
    AccountKeys as KeysRecord, Recovered, RecoveryChallengeRequest, RecoverySignIn, keypart_info,
    upload_message,
};
use larsal_proto::limits::MAX_JSON;
use larsal_proto::messages::{AccountCreated, AccountId, Challenge, VaultId};
use larsal_proto::{base32, routes, signin, wrap as wire};
use std::fmt;

/// SYN-06.2: the shortest account password, in characters.
pub const MIN_PASSWORD: usize = 8;
/// SYN-06.4: the one blob version this build writes and reads.
pub const BLOB_VERSION: u16 = 1;
/// SYN-06.4: version (2) ‖ salt (32) ‖ nonce (12) ‖ ciphertext (96) ‖ tag (16).
pub const BLOB_LEN: usize = 158;
/// The label of the blob's associated data (CRY-04.2, SYN-06.4).
const BLOB_LABEL: &[u8] = b"sync-account-blob-v1";
/// The info of the recovery key's HKDF (SYN-06.5).
const RECOVERY_INFO: &[u8] = b"sync-recovery-key-v1";
/// `S_acct`'s bytes.
const SECRET: usize = 32;
/// The device store item of one account: `S_acct` ‖ the blob's plaintext.
const KEPT: usize = SECRET + BLOB_PLAINTEXT;
/// `S_acct` in the kit: 52 characters, 12 hyphens.
const SECRET_TEXT: usize = 64;

/// Why an account call did not end well. It holds no secret and no server
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountFail {
    /// A call failed as [`Fail`] says.
    Net(Fail),
    /// SYN-06.2: fewer than [`MIN_PASSWORD`] characters; nothing was made.
    ShortPassword,
    /// `MSG-ACCOUNT-RESTORE-FAILED`: the Recovery Kit or the account
    /// password is not right, never which.
    RestoreFailed,
    /// `MSG-ACCOUNT-KEYS-CHANGED`: the server sent other account keys than
    /// this Mac's pin; the account is stopped (SYN-06.6).
    KeysChanged,
    /// The blob has a version this build does not read (SYN-06.4's edge
    /// case): refused before any Argon2id run.
    NeedsUpdate,
    /// The account has no keys on the server, or this Mac holds none.
    NoKeys,
    /// The server has no key-file part for the vault.
    NoPart,
    /// A key-file part wrap that does not open: another signer, another
    /// vault's info, another suite, a changed byte (SYN-06.9, CRY-05.4).
    BadWrap,
    /// The kit names another server than this client's (SYN-06.12's edge
    /// case: add that server first).
    OtherServer,
    /// The device store refused, or larsal-crypto's random source failed.
    Store,
    /// `MSG-CODE-FAILED` (SYN-05.3, SYN-06.11): the approval ended, by a
    /// failed check, a code the server does not know, a second message,
    /// Codes differ on the other Mac or its 15 minutes; nothing was sealed,
    /// signed, registered or pinned.
    CodeFailed,
    /// `MSG-ACCOUNT-OTHER-PASSWORD` (E17-S2, E17-S1's F4): sign-up met keys
    /// that are this Mac's, but the server's blob does not open with the
    /// password just typed; no kit is given.
    OtherPassword,
}

impl AccountFail {
    /// The message of SYN-06's or SYN-03's table to show for this failure.
    #[must_use]
    pub fn message(self) -> Message {
        match self {
            Self::RestoreFailed => Message::RestoreFailed,
            Self::KeysChanged => Message::KeysChanged,
            Self::NeedsUpdate => Message::NeedsUpdate,
            Self::CodeFailed => Message::CodeFailed,
            Self::OtherPassword => Message::OtherPassword,
            Self::Net(Fail::CertChanged) => Message::CertChanged,
            Self::Net(Fail::SignedOut) => Message::SignedOut,
            _ => Message::Error,
        }
    }
}

/// SYN-06.8: the device store this Mac keeps an account's secrets in
/// (E16-S6's store: the login keychain until W-02, then this device only).
/// The product store is [`Keychain`]; tests use a map
/// (`test_server::Memory`) and never a keychain (LD-317 (2)).
pub trait Keep {
    /// Keeps `secret` under `label`, in place of any there.
    ///
    /// # Errors
    /// The store refused.
    fn put(&self, label: &str, secret: &SecretBytes) -> Result<(), AccountFail>;

    /// The secret under `label`, if there is one.
    fn get(&self, label: &str) -> Option<SecretBytes>;
}

/// The product store: larsal-platform `device_key.rs`'s items (E16-S6).
#[cfg(feature = "sync")]
#[derive(Debug, Default)]
pub struct Keychain;

#[cfg(feature = "sync")]
impl Keep for Keychain {
    fn put(&self, label: &str, secret: &SecretBytes) -> Result<(), AccountFail> {
        larsal_platform::device_key::part_put(label, secret).map_err(|_| AccountFail::Store)
    }

    fn get(&self, label: &str) -> Option<SecretBytes> {
        larsal_platform::device_key::part_get(label).ok()
    }
}

/// SYN-06.7: the Recovery Kit: the kit format `1`, the server address and
/// its certificate fingerprint, the account id and `S_acct`. A wiping value:
/// `S_acct` is only in `SecretBytes`, [`Kit::text`] only in a
/// `SecretString`, and `Debug` prints `[hidden]`.
pub struct Kit {
    address: String,
    pin: [u8; 32],
    account: AccountId,
    secret: SecretBytes,
}

impl fmt::Debug for Kit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[hidden]")
    }
}

impl Kit {
    /// The server's address, `https://<host>:<port>`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The server certificate's SHA-256 (SYN-01.2): N pins the server by it.
    #[must_use]
    pub fn pin(&self) -> [u8; 32] {
        self.pin
    }

    /// The account's id.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        self.account
    }

    /// The kit's text, built in one buffer of its final size, so it never
    /// moves and leaves no unwiped copy:
    ///
    /// ```text
    /// Larsal Recovery Kit
    /// Format: 1
    /// Server: https://127.0.0.1:8443
    /// Fingerprint: <64 hex digits in 8 groups of 8>
    /// Account: <32 hex digits>
    /// Secret: <52 base32 characters in 13 groups of 4>
    /// ```
    #[must_use]
    pub fn text(&self) -> SecretString {
        let head = format!(
            "Larsal Recovery Kit\nFormat: 1\nServer: {}\nFingerprint: {}\nAccount: {}\nSecret: ",
            self.address,
            printed(&self.pin),
            self.account
        );
        let mut text = String::with_capacity(head.len().saturating_add(SECRET_TEXT + 1));
        text.push_str(&head);
        base32::push(&mut text, self.secret.expose(), true);
        text.push('\n');
        SecretString::new(text)
    }

    /// Reads a kit's text as a user types it: labels and base32 in either
    /// case, hyphens and spaces in the secret ignored, lines without a
    /// known label (the title) skipped. Each of the five lines must be
    /// there once.
    ///
    /// # Errors
    /// [`AccountFail::RestoreFailed`] for anything else, with no detail.
    pub fn read(text: &SecretString) -> Result<Self, AccountFail> {
        let mut fields: [Option<&str>; 5] = [None; 5];
        for line in text.expose().lines() {
            let Some((label, value)) = line.split_once(':') else {
                continue;
            };
            let at = ["format", "server", "fingerprint", "account", "secret"]
                .iter()
                .position(|l| label.trim().eq_ignore_ascii_case(l));
            if let Some(slot) = at.and_then(|i| fields.get_mut(i)) {
                if slot.is_some() {
                    return Err(AccountFail::RestoreFailed);
                }
                *slot = Some(value.trim());
            }
        }
        let [
            Some(format),
            Some(server),
            Some(fingerprint),
            Some(account),
            Some(secret),
        ] = fields
        else {
            return Err(AccountFail::RestoreFailed);
        };
        let fail = AccountFail::RestoreFailed;
        if format != "1" {
            return Err(fail);
        }
        let (address, _) = parse_address(server).ok_or(fail)?;
        Ok(Self {
            address,
            pin: read_printed(fingerprint).ok_or(fail)?,
            account: AccountId::parse(&account.to_ascii_lowercase()).ok_or(fail)?,
            secret: base32::read(secret, SECRET).ok_or(fail)?,
        })
    }
}

/// SYN-06.4's associated data: the field list (`sync-account-blob-v1`,
/// `account_id`, the version as a u16 big endian, the salt).
fn blob_aad(account: &AccountId, version: u16, salt: &[u8; 32]) -> Result<Vec<u8>, AccountFail> {
    sign::field_list(&[BLOB_LABEL, account.as_bytes(), &version.to_be_bytes(), salt])
        .map_err(|_| AccountFail::Store)
}

/// SYN-06.4: the blob of `keys` for `account` under `password`, with a
/// fresh 32-byte salt from larsal-crypto's random source.
pub(crate) fn make_blob(
    keys: &AccountKeys,
    account: &AccountId,
    password: &SecretString,
) -> Result<Vec<u8>, AccountFail> {
    let mut salt = [0u8; 32];
    random::fill(&mut salt).map_err(|_| AccountFail::Store)?;
    make_blob_with(keys, account, password, &salt)
}

/// [`make_blob`] with the salt `salt` (SYN-06 T03's known value).
fn make_blob_with(
    keys: &AccountKeys,
    account: &AccountId,
    password: &SecretString,
    salt: &[u8; 32],
) -> Result<Vec<u8>, AccountFail> {
    let key = wrap::account_key(password, salt, keys.account_secret(), account.as_bytes())
        .map_err(|_| AccountFail::Store)?;
    let aad = blob_aad(account, BLOB_VERSION, salt)?;
    let sealed =
        wrap::seal(&key, &aad, keys.blob_plaintext().expose()).map_err(|_| AccountFail::Store)?;
    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(&BLOB_VERSION.to_be_bytes());
    blob.extend_from_slice(salt);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// SYN-06.4: the blob's plaintext under `secret` (`S_acct`) and
/// `password`. The version is read first: another one is
/// [`AccountFail::NeedsUpdate`] before any Argon2id run; any other failure
/// (a length, a changed byte, the wrong secret or password) is
/// [`AccountFail::RestoreFailed`].
pub(crate) fn open_blob(
    blob: &[u8],
    account: &AccountId,
    secret: &SecretBytes,
    password: &SecretString,
) -> Result<SecretBytes, AccountFail> {
    let fail = AccountFail::RestoreFailed;
    let (version, rest) = blob.split_first_chunk::<2>().ok_or(fail)?;
    if u16::from_be_bytes(*version) != BLOB_VERSION {
        return Err(AccountFail::NeedsUpdate);
    }
    if blob.len() != BLOB_LEN {
        return Err(fail);
    }
    let (salt, sealed) = rest.split_first_chunk::<32>().ok_or(fail)?;
    #[cfg(test)]
    probe::argon2id();
    let key = wrap::account_key(password, salt, secret, account.as_bytes()).map_err(|_| fail)?;
    let plaintext =
        wrap::open(&key, &blob_aad(account, BLOB_VERSION, salt)?, sealed).map_err(|_| fail)?;
    if plaintext.len() != BLOB_PLAINTEXT {
        return Err(fail);
    }
    Ok(plaintext)
}

/// SYN-06.5: the recovery key's seed: HKDF-SHA256 with salt `account`,
/// input key material `S_acct` and info `sync-recovery-key-v1`.
pub(crate) fn recovery_seed(
    account: &AccountId,
    secret: &SecretBytes,
) -> Result<SecretBytes, AccountFail> {
    wrap::hkdf_sha256(account.as_bytes(), secret, RECOVERY_INFO).map_err(|_| AccountFail::Store)
}

/// The device store item of `keys`: `S_acct` ‖ the blob's plaintext.
pub(crate) fn kept(keys: &AccountKeys) -> SecretBytes {
    let mut out = SecretBytes::zeroed(KEPT);
    let (secret, rest) = out.expose_mut().split_at_mut(SECRET);
    secret.copy_from_slice(keys.account_secret().expose());
    rest.copy_from_slice(keys.blob_plaintext().expose());
    out
}

/// The keys of a device store item.
fn from_kept(item: &SecretBytes) -> Result<AccountKeys, AccountFail> {
    let (secret, rest) = item
        .expose()
        .split_at_checked(SECRET)
        .filter(|(_, rest)| rest.len() == BLOB_PLAINTEXT)
        .ok_or(AccountFail::NoKeys)?;
    AccountKeys::from_blob(
        SecretBytes::new(secret.to_vec()),
        &SecretBytes::new(rest.to_vec()),
    )
    .map_err(|_| AccountFail::NoKeys)
}

/// A JSON route's status other than its success (SYN-03.10).
pub(crate) fn status_fail(status: u16, retry_after: u64) -> AccountFail {
    AccountFail::Net(match status {
        401 => Fail::SignedOut,
        429 => Fail::Limited(retry_after),
        500..=599 => Fail::Offline,
        _ => Fail::Protocol,
    })
}

/// The type of a JSON body (F-285).
pub(crate) const JSON: (&str, &str) = ("content-type", "application/json");

/// The device store item that marks a stopped account: `[1]` stopped,
/// `[0]` cleared by the user's restore or approval.
const STOPPED: [u8; 1] = [1];

impl<K: Signer> Server<K> {
    /// The device store label of `account`'s secrets on this server.
    pub(crate) fn label(&self, account: &AccountId) -> String {
        format!("{} account {account}", self.base)
    }

    /// The device store label of the stop of `account` on this server
    /// (SYN-06.6, E17-S2): kept apart from the secrets.
    pub(crate) fn stop_label(&self, account: &AccountId) -> String {
        format!("{} account {account} stopped", self.base)
    }

    /// SYN-06.6: stops the account until the user acts, here and in the
    /// device store, so a restart keeps the stop.
    fn stop(&mut self, keep: &dyn Keep) {
        self.stopped = true;
        if let Some(account) = self.account_id() {
            // The stop holds in memory even when the store refuses.
            let _ = keep.put(
                &self.stop_label(&account),
                &SecretBytes::new(STOPPED.to_vec()),
            );
        }
    }

    /// Whether `kit` names this client's server: its address and its
    /// pinned certificate (compared in constant time, CRY-04.11).
    fn names_this_server(&self, kit: &Kit) -> bool {
        kit.address == self.base && ct_eq(&kit.pin, &self.pin)
    }

    /// The account whose keys this Mac holds, if any.
    #[must_use]
    pub fn account_id(&self) -> Option<AccountId> {
        self.account.as_ref().map(|(id, _)| *id)
    }

    /// Whether the account is stopped by `MSG-ACCOUNT-KEYS-CHANGED`.
    #[must_use]
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// SYN-06.1 to SYN-06.7, CRY-05.8: the account keys of `account`, just
    /// made by [`Server::sign_up`]. The password needs [`MIN_PASSWORD`]
    /// characters and is used exactly as typed. The secrets go into `keep`
    /// before the PUT, so a lost reply loses nothing; a second call reuses
    /// them. A 412 means the server has keys already: they must be these
    /// (a PUT whose reply was lost), else the account is stopped; and the
    /// server's blob must open with this `S_acct` and `password`, else no
    /// kit is given (E17-S1's F4: a second call with another password).
    ///
    /// # Errors
    /// [`AccountFail::ShortPassword`] before anything is drawn;
    /// [`AccountFail::Store`]; [`AccountFail::KeysChanged`];
    /// [`AccountFail::OtherPassword`]; else [`AccountFail::Net`].
    pub fn sign_up_account(
        &mut self,
        account: &AccountId,
        password: &SecretString,
        keep: &dyn Keep,
    ) -> Result<Kit, AccountFail> {
        if password.expose().chars().count() < MIN_PASSWORD {
            return Err(AccountFail::ShortPassword);
        }
        let label = self.label(account);
        let keys = match keep.get(&label) {
            Some(item) => from_kept(&item)?,
            None => {
                let keys = AccountKeys::new().map_err(|_| AccountFail::Store)?;
                keep.put(&label, &kept(&keys))?;
                keys
            }
        };
        let seed = recovery_seed(account, keys.account_secret())?;
        let record = KeysRecord {
            identity_public_key: keys.identity_public_key().to_vec(),
            kem_public_key: keys.kem_public_key().to_vec(),
            kem_signature: keys
                .kem_signature(account.as_bytes())
                .map_err(|_| AccountFail::Store)?,
            recovery_public_key: sign::ed25519_public(&seed).map_err(|_| AccountFail::Store)?,
            blob: make_blob(&keys, account, password)?,
        };
        drop(seed);
        let body = record.to_json();
        let r = self
            .call(
                Method::Put(&body),
                routes::ACCOUNT_KEYS,
                &[JSON, ("if-none-match", "*")],
                MAX_JSON as u64,
            )
            .map_err(AccountFail::Net)?;
        let kit = Kit {
            address: self.base.clone(),
            pin: self.pin,
            account: *account,
            secret: SecretBytes::new(keys.account_secret().expose().to_vec()),
        };
        match r.status {
            201 => {}
            412 => {
                self.account = Some((*account, keys));
                let record = self.checked_keys(keep)?;
                let (_, keys) = self.usable()?;
                return match open_blob(&record.blob, account, keys.account_secret(), password) {
                    Ok(_) => Ok(kit),
                    Err(AccountFail::RestoreFailed) => Err(AccountFail::OtherPassword),
                    Err(e) => Err(e),
                };
            }
            s => return Err(status_fail(s, r.retry_after)),
        }
        self.account = Some((*account, keys));
        self.stopped = false;
        Ok(kit)
    }

    /// SYN-06.8, T18's this-Mac half: after a restart, the keys of
    /// `account` from `keep`, with no password. A stop kept in `keep`
    /// (SYN-06.6) holds again: loading never clears it.
    ///
    /// # Errors
    /// [`AccountFail::NoKeys`] when the store has none for this server.
    pub fn load_account(
        &mut self,
        account: &AccountId,
        keep: &dyn Keep,
    ) -> Result<(), AccountFail> {
        let item = keep.get(&self.label(account)).ok_or(AccountFail::NoKeys)?;
        self.account = Some((*account, from_kept(&item)?));
        if keep
            .get(&self.stop_label(account))
            .is_some_and(|mark| mark.expose() == STOPPED)
        {
            self.stopped = true;
        }
        Ok(())
    }

    /// E17-S2 (E17-S1's C1-F2, C2-F1): whether the server holds account keys
    /// for this Mac's account, asked by a Mac that holds none: a 200 means a
    /// download must wait for them (`MSG-ACCOUNT-RESTORE-NEEDED`), a 404 is
    /// an account without keys, whose versions the version and hash guard
    /// checks alone.
    ///
    /// # Errors
    /// [`AccountFail::Net`].
    pub(crate) fn keys_on_server(&mut self) -> Result<bool, AccountFail> {
        match self.get_keys() {
            Ok(_) => Ok(true),
            Err(AccountFail::NoKeys) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `GET /v1/account/keys` (SYN-06.6).
    pub(crate) fn get_keys(&mut self) -> Result<KeysRecord, AccountFail> {
        let r = self
            .call(Method::Get, routes::ACCOUNT_KEYS, &[], MAX_JSON as u64)
            .map_err(AccountFail::Net)?;
        match r.status {
            200 => KeysRecord::read(&r.body).map_err(|_| AccountFail::Net(Fail::Protocol)),
            404 => Err(AccountFail::NoKeys),
            s => Err(status_fail(s, r.retry_after)),
        }
    }

    /// SYN-06.6, CRY-05.8: reads the account's keys from the server and
    /// checks them: the binding verifies with the record's identity key,
    /// and both public keys equal this Mac's pin, whole, in constant time.
    /// A failure stops the account until the user acts: no upload signed,
    /// no wrap opened (T05); the stop is kept in `keep` too, so a restart
    /// keeps it (E17-S2).
    ///
    /// # Errors
    /// [`AccountFail::KeysChanged`]; [`AccountFail::NoKeys`] without keys
    /// held or on the server; else [`AccountFail::Net`].
    pub fn check_keys(&mut self, keep: &dyn Keep) -> Result<(), AccountFail> {
        self.checked_keys(keep).map(drop)
    }

    /// [`Server::check_keys`], giving the record that passed.
    fn checked_keys(&mut self, keep: &dyn Keep) -> Result<KeysRecord, AccountFail> {
        let account = self.account_id().ok_or(AccountFail::NoKeys)?;
        let record = self.get_keys()?;
        let (_, keys) = self.account.as_ref().ok_or(AccountFail::NoKeys)?;
        let bound = check_kem_binding(
            &record.identity_public_key,
            account.as_bytes(),
            &record.kem_public_key,
            &record.kem_signature,
        )
        .is_ok();
        let pinned = pins_match(
            keys.identity_public_key(),
            keys.kem_public_key(),
            &record.identity_public_key,
            &record.kem_public_key,
        );
        if bound && pinned {
            Ok(record)
        } else {
            self.stop(keep);
            Err(AccountFail::KeysChanged)
        }
    }

    /// SYN-03.11: whether `reply`, version `version` of `vault` with bytes
    /// of SHA-256 `sha`, carries `Upload-Signer` (this account, for a
    /// personal vault) and an `Upload-Signature` that verifies with the
    /// pinned identity key over SYN-01.7's field list. Always true while
    /// this Mac holds no account keys (an account of E16, before E17-S1:
    /// the version and hash guard applies alone); never true for a stopped
    /// account.
    #[must_use]
    pub fn signed_by_account(
        &self,
        vault: &VaultId,
        version: u64,
        sha: &[u8; 32],
        reply: &crate::client::Reply,
    ) -> bool {
        let Some((account, keys)) = &self.account else {
            return !self.stopped;
        };
        let (Some(signer), Some(signature)) = (reply.signer, reply.signature.as_ref()) else {
            return false;
        };
        !self.stopped
            && signer == *account
            && upload_message(vault, version, sha).is_ok_and(|m| {
                pq::composite_verify(keys.identity_public_key(), &m, signature).is_ok()
            })
    }

    /// The account and keys of a call that signs or opens: none while the
    /// account is stopped (SYN-06.6).
    pub(crate) fn usable(&self) -> Result<(&AccountId, &AccountKeys), AccountFail> {
        if self.stopped {
            return Err(AccountFail::KeysChanged);
        }
        let (account, keys) = self.account.as_ref().ok_or(AccountFail::NoKeys)?;
        Ok((account, keys))
    }

    /// SYN-06.9, CRY-05.4: wraps the key-file part `part` of `vault` to the
    /// account's own receiving key, with info (`sync-wrap-info-v1`,
    /// `keypart`, the account id, the vault id), signed by the identity key,
    /// and sends it with `PUT /v1/vaults/{vault}/keypart`.
    ///
    /// # Errors
    /// [`AccountFail::KeysChanged`] for a stopped account and
    /// [`AccountFail::NoKeys`] without keys, before anything is made or
    /// sent; [`AccountFail::Store`] when the wrap fails; else
    /// [`AccountFail::Net`] (a 404: no such vault of this account).
    pub fn put_keypart(&mut self, vault: &VaultId, part: &SecretBytes) -> Result<(), AccountFail> {
        let (account, keys) = self.usable()?;
        let info = keypart_info(account, vault).map_err(|_| AccountFail::Store)?;
        let record = wrap_record::make(
            keys.kem_public_key(),
            &info,
            part.expose(),
            *account.as_bytes(),
            keys.identity_private_key(),
        )
        .map_err(|_| AccountFail::Store)?;
        let body = wire::to_json(&record);
        let path = format!("{}/{vault}{}", routes::VAULTS, routes::KEYPART);
        let r = self
            .call(Method::Put(&body), &path, &[JSON], MAX_JSON as u64)
            .map_err(AccountFail::Net)?;
        match r.status {
            204 => Ok(()),
            s => Err(status_fail(s, r.retry_after)),
        }
    }

    /// SYN-06.9, CRY-05.4: the key-file part of `vault` from the server's
    /// wrap: the signer must be this account (its pinned identity key), and
    /// the wrap opens with the info built here, never the record's, and
    /// this Mac's receiving seed. The part goes into `keep` under
    /// `state::part_label` (SYN-03.1 step 2's label) and is returned.
    ///
    /// # Errors
    /// [`AccountFail::KeysChanged`] for a stopped account and
    /// [`AccountFail::NoKeys`] without keys, before any request;
    /// [`AccountFail::NoPart`] for a 404; [`AccountFail::BadWrap`] for a
    /// record that does not read or open, and nothing is kept;
    /// [`AccountFail::Store`]; else [`AccountFail::Net`].
    pub fn get_keypart(
        &mut self,
        vault: &VaultId,
        keep: &dyn Keep,
    ) -> Result<SecretBytes, AccountFail> {
        self.usable()?;
        let path = format!("{}/{vault}{}", routes::VAULTS, routes::KEYPART);
        let r = self
            .call(Method::Get, &path, &[], MAX_JSON as u64)
            .map_err(AccountFail::Net)?;
        match r.status {
            200 => {}
            404 => return Err(AccountFail::NoPart),
            s => return Err(status_fail(s, r.retry_after)),
        }
        let (account, keys) = self.usable()?;
        let record = wire::read(&r.body).map_err(|_| AccountFail::BadWrap)?;
        if record.signer != *account.as_bytes() {
            return Err(AccountFail::BadWrap);
        }
        let info = keypart_info(account, vault).map_err(|_| AccountFail::BadWrap)?;
        let part = wrap_record::open(&record, keys.identity_public_key(), &info, keys.kem_seed())
            .map_err(|_| AccountFail::BadWrap)?;
        keep.put(&crate::state::part_label(&self.base, *vault), &part)?;
        Ok(part)
    }

    /// SYN-06.12's first half, a new Mac by Recovery Kit: with the kit's
    /// recovery key (SYN-06.5), `POST /v1/recovery/challenge` then
    /// `POST /v1/recovery/signin` for the device `key`, named "Mac". The
    /// server registers the device; its id and session are this client's
    /// from then on. [`Server::restore`] follows with the password.
    ///
    /// # Errors
    /// [`AccountFail::OtherServer`] when the kit names another server or
    /// certificate; [`AccountFail::RestoreFailed`] when the server refuses
    /// the signature (a wrong kit; the same failure as a wrong password);
    /// else [`AccountFail::Net`] (a 409: the key is registered already).
    pub fn recover(&mut self, kit: &Kit, key: K) -> Result<AccountCreated, AccountFail> {
        if !self.names_this_server(kit) {
            return Err(AccountFail::OtherServer);
        }
        let account = kit.account;
        let seed = recovery_seed(&account, &kit.secret)?;
        let device_public_key = key.public_key().map_err(AccountFail::Net)?;
        let ask = RecoveryChallengeRequest {
            account_id: account,
        }
        .to_json();
        let limit = MAX_JSON as u64;
        let a = self
            .send(
                Method::Post(&ask),
                routes::RECOVERY_CHALLENGE,
                &[JSON],
                limit,
            )
            .map_err(AccountFail::Net)?;
        if a.status != 200 {
            return Err(AccountFail::Net(signin_fail(&a)));
        }
        let challenge = Challenge::read(&a.body).map_err(|_| AccountFail::Net(Fail::Protocol))?;
        let message =
            signin::recovery_message(&self.origin, &challenge.nonce, &account, &device_public_key)
                .map_err(|_| AccountFail::Net(Fail::Protocol))?;
        let signed = RecoverySignIn {
            account_id: account,
            nonce: challenge.nonce,
            device_public_key,
            device_name: "Mac".to_owned(),
            signature: sign::ed25519_sign(&seed, &message).map_err(|_| AccountFail::Store)?,
        }
        .to_json();
        drop(seed);
        let mut a = self
            .send(
                Method::Post(&signed),
                routes::RECOVERY_SIGNIN,
                &[JSON],
                limit,
            )
            .map_err(AccountFail::Net)?;
        // LD-325 (5) (b): the reply holds the token.
        let body = SecretBytes::new(std::mem::take(&mut a.body));
        match a.status {
            200 => {}
            401 => return Err(AccountFail::RestoreFailed),
            _ => return Err(AccountFail::Net(signin_fail(&a))),
        }
        let made = Recovered::read(body.expose()).map_err(|_| AccountFail::Net(Fail::Protocol))?;
        self.set_device(made.device_id, key);
        self.hold(&made.session);
        Ok(AccountCreated {
            account_id: account,
            device_id: made.device_id,
        })
    }

    /// SYN-06.12's second half, after [`Server::recover`]: reads the
    /// account's keys, unwraps the blob with the kit's `S_acct` and
    /// `password`, checks that the unwrapped keys are the record's and its
    /// binding verifies, pins them and keeps the secrets in `keep`
    /// (SYN-06.8). It may be called again after a wrong password.
    ///
    /// # Errors
    /// [`AccountFail::RestoreFailed`] for a wrong kit or password, with no
    /// detail; [`AccountFail::NeedsUpdate`] for a blob of another version,
    /// before any Argon2id run; [`AccountFail::KeysChanged`] when the blob's
    /// keys are not the record's; [`AccountFail::NoKeys`];
    /// [`AccountFail::Store`]; else [`AccountFail::Net`].
    pub fn restore(
        &mut self,
        kit: &Kit,
        password: &SecretString,
        keep: &dyn Keep,
    ) -> Result<(), AccountFail> {
        if !self.names_this_server(kit) {
            return Err(AccountFail::OtherServer);
        }
        let account = kit.account;
        let record = self.get_keys()?;
        self.adopt(&account, &kit.secret, &record, password, None, keep)
    }

    /// The tail of SYN-06.12 and of SYN-06.11 step 6: unwraps `record`'s
    /// blob with `secret` (`S_acct`) and `password`; with `compared`
    /// (SYN-06.11), checks that the unwrapped identity seed gives the
    /// identity public key both Macs compared, whole, in constant time;
    /// checks that the unwrapped keys are the record's and its binding
    /// verifies; only then keeps the secrets in `keep`, pins the keys and
    /// clears a kept stop (the user's action, SYN-06.6).
    ///
    /// # Errors
    /// [`AccountFail::RestoreFailed`], [`AccountFail::NeedsUpdate`],
    /// [`AccountFail::KeysChanged`], [`AccountFail::Store`]; nothing is kept
    /// or pinned.
    pub(crate) fn adopt(
        &mut self,
        account: &AccountId,
        secret: &SecretBytes,
        record: &KeysRecord,
        password: &SecretString,
        compared: Option<&[u8]>,
        keep: &dyn Keep,
    ) -> Result<(), AccountFail> {
        let account = *account;
        let plaintext = open_blob(&record.blob, &account, secret, password)?;
        let secret = SecretBytes::new(secret.expose().to_vec());
        let keys =
            AccountKeys::from_blob(secret, &plaintext).map_err(|_| AccountFail::RestoreFailed)?;
        drop(plaintext);
        if let Some(identity) = compared
            && !ct_eq(keys.identity_public_key(), identity)
        {
            return Err(AccountFail::KeysChanged);
        }
        let bound = check_kem_binding(
            &record.identity_public_key,
            account.as_bytes(),
            &record.kem_public_key,
            &record.kem_signature,
        )
        .is_ok();
        let pinned = pins_match(
            keys.identity_public_key(),
            keys.kem_public_key(),
            &record.identity_public_key,
            &record.kem_public_key,
        );
        if !(bound && pinned) {
            return Err(AccountFail::KeysChanged);
        }
        keep.put(&self.label(&account), &kept(&keys))?;
        let stop = self.stop_label(&account);
        if keep.get(&stop).is_some() {
            keep.put(&stop, &SecretBytes::new(vec![0]))?;
        }
        #[cfg(test)]
        crate::approval::probe::pinned();
        self.account = Some((account, keys));
        self.stopped = false;
        Ok(())
    }
}

/// Test-only: how many times [`open_blob`] reached its Argon2id run on this
/// thread (SYN-06 T04: a version-2 blob is refused before it).
#[cfg(test)]
pub(crate) mod probe {
    use std::cell::Cell;

    thread_local! {
        static RUNS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn argon2id() {
        RUNS.with(|c| c.set(c.get().wrapping_add(1)));
    }

    pub(crate) fn runs() -> usize {
        RUNS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests;
