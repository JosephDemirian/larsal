//! A new Mac by approval on the wire (E17-S2; SYN-05, SYN-06.11 with
//! CRY-05.8): the approval code and its header, the field lists both Macs
//! build (`ctx`, `K_C`, `K_R`, the commitment, the code, the seal's info,
//! the device signature's message) and the records of the approval routes.
//!
//! - The approval code is 16 bytes from larsal-crypto's random source,
//!   shown as base32 in groups of 4 ([`crate::base32`]) and sent only as
//!   `Authorization: Approval <26 characters>` ([`approval`]); the server
//!   gets its SHA-256 in `POST /v1/approvals` and stores only that.
//! - `ctx` = (`sync-approval-v1`, `account_id`, `approval_id`); `K_C` = (N's
//!   device public key, N's one-request X-Wing public key); `K_R` = (the
//!   identity public key, E's device public key): CRY-04.2 field lists.
//! - The commitment is SHA-256 of (`sync-compare-commit-v1`, ctx, `K_C`,
//!   `n_C`); the code is the first 8 bytes of SHA-256 of
//!   (`sync-compare-code-v1`, ctx, `K_R`, `K_C`, `n_R`, `n_C`) as a u64 big
//!   endian, modulo 1,000,000 (SYN-05.1, SYN-05.4).
//!
//! Guarantees: every reader takes untrusted bytes and never panics; a key
//! list or nonce of another length is refused; a field list that holds a
//! nonce before its reveal is built straight into a [`SecretBytes`].

use crate::Error;
use crate::base32;
use crate::limits::{MAX_JSON, MAX_WRAP};
use crate::messages::{
    AccountId, DeviceId, Id, array, b64, byte_string, device_name_ok, id, number, read_record,
    text, write,
};
use crate::wrap as wire;
use larsal_crypto::pq::{IDENTITY_PUBLIC, PUBLIC_KEY, SIGNATURE};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::wrap_record::WrapRecord;
use larsal_crypto::{hash, sign};
use larsal_model::json::Value;
use std::fmt;

/// The approval code's bytes (SYN-06.11 step 1).
pub const CODE_BYTES: usize = 16;
/// The approval code in base32 without separators.
pub const CODE_CHARS: usize = base32::chars(CODE_BYTES);
/// A device public key: 65 SEC1 bytes (CRY-04.4).
pub const DEVICE_KEY: usize = 65;
/// `K_C`: the field list (N's device key, N's one-request X-Wing key).
pub const KEYS_C: usize = 4 + DEVICE_KEY + 4 + PUBLIC_KEY;
/// `K_R`: the field list (the identity public key, E's device key).
pub const KEYS_R: usize = 4 + IDENTITY_PUBLIC + 4 + DEVICE_KEY;
/// The `Authorization` scheme of the approval routes (SYN-01.4).
pub const SCHEME: &str = "Approval";

const CTX_LABEL: &[u8] = b"sync-approval-v1";
const COMMIT_LABEL: &[u8] = b"sync-compare-commit-v1";
const CODE_LABEL: &[u8] = b"sync-compare-code-v1";
const WRAP_INFO_LABEL: &[u8] = b"sync-wrap-info-v1";
const DEVICE_LABEL: &[u8] = b"sync-device-v1";

fn list(parts: &[&[u8]]) -> Result<Vec<u8>, Error> {
    sign::field_list(parts).map_err(|_| Error::TooLarge)
}

fn sha(parts: &[&[u8]]) -> Result<[u8; 32], Error> {
    <[u8; 32]>::try_from(hash::sha256(parts).expose()).map_err(|_| Error::TooLarge)
}

/// SYN-06.11's `ctx`: (`sync-approval-v1`, `account_id`, `approval_id`).
///
/// # Errors
/// Never in practice (the fields are short).
pub fn ctx(account: &AccountId, approval: &Id) -> Result<Vec<u8>, Error> {
    list(&[CTX_LABEL, account.as_bytes(), approval.as_bytes()])
}

/// `K_C`: (N's device public key, N's one-request X-Wing public key).
///
/// # Errors
/// [`Error::Invalid`] for a key of another length.
pub fn keys_c(device: &[u8; DEVICE_KEY], xwing: &[u8]) -> Result<Vec<u8>, Error> {
    if xwing.len() != PUBLIC_KEY {
        return Err(Error::Invalid("keys"));
    }
    list(&[device, xwing])
}

/// `K_R`: (the identity public key, E's device public key).
///
/// # Errors
/// [`Error::Invalid`] for a key of another length.
pub fn keys_r(identity: &[u8], device: &[u8; DEVICE_KEY]) -> Result<Vec<u8>, Error> {
    if identity.len() != IDENTITY_PUBLIC {
        return Err(Error::Invalid("keys"));
    }
    list(&[identity, device])
}

/// The two fields of a key list whose fields are `a` and `b` bytes long,
/// or `None` when `bytes` is not exactly that field list.
fn split(bytes: &[u8], a: usize, b: usize) -> Option<(&[u8], &[u8])> {
    let first = bytes.get(4..a.checked_add(4)?)?;
    let start = a.checked_add(8)?;
    let second = bytes.get(start..start.checked_add(b)?)?;
    (list(&[first, second]).ok()?.as_slice() == bytes).then_some((first, second))
}

/// `K_C` read back: (N's device key, N's one-request key).
#[must_use]
pub fn split_keys_c(bytes: &[u8]) -> Option<([u8; DEVICE_KEY], Vec<u8>)> {
    let (device, xwing) = split(bytes, DEVICE_KEY, PUBLIC_KEY)?;
    Some((device.try_into().ok()?, xwing.to_vec()))
}

/// `K_R` read back: (the identity public key, E's device key).
#[must_use]
pub fn split_keys_r(bytes: &[u8]) -> Option<(Vec<u8>, [u8; DEVICE_KEY])> {
    let (identity, device) = split(bytes, IDENTITY_PUBLIC, DEVICE_KEY)?;
    Some((identity.to_vec(), device.try_into().ok()?))
}

/// SYN-05.1: SHA-256 of (`sync-compare-commit-v1`, ctx, `K_C`, `n_C`). The
/// field list, which holds `n_C` before its reveal, lives in a
/// [`SecretBytes`].
///
/// # Errors
/// Never in practice.
pub fn commitment(ctx: &[u8], keys_c: &[u8], nonce_c: &[u8]) -> Result<SecretBytes, Error> {
    let fields = SecretBytes::new(list(&[COMMIT_LABEL, ctx, keys_c, nonce_c])?);
    Ok(hash::sha256(&[fields.expose()]))
}

/// SYN-05.4: the first 8 bytes of SHA-256 of (`sync-compare-code-v1`, ctx,
/// `K_R`, `K_C`, `n_R`, `n_C`) as a u64 big endian, modulo 1,000,000. The
/// order of the fields is fixed by role, so both sides get one value.
///
/// # Errors
/// Never in practice.
pub fn code(
    ctx: &[u8],
    keys_r: &[u8],
    keys_c: &[u8],
    nonce_r: &[u8],
    nonce_c: &[u8],
) -> Result<u32, Error> {
    let fields = SecretBytes::new(list(&[CODE_LABEL, ctx, keys_r, keys_c, nonce_r, nonce_c])?);
    let h = hash::sha256(&[fields.expose()]);
    let first = h.expose().first_chunk::<8>().ok_or(Error::TooLarge)?;
    u32::try_from(u64::from_be_bytes(*first) % 1_000_000).map_err(|_| Error::TooLarge)
}

/// SYN-05.4's written form: 6 digits with leading zeros in two groups of 3
/// (`042 917`).
#[must_use]
pub fn shown(code: u32) -> String {
    let digits = format!("{:06}", code % 1_000_000);
    let (a, b) = digits.split_at(3);
    format!("{a} {b}")
}

/// The seal's info (SYN-06.11 step 5): (`sync-wrap-info-v1`,
/// `account-secret`, `account_id`, `approval_id`, N's device public key).
///
/// # Errors
/// Never in practice.
pub fn seal_info(
    account: &AccountId,
    approval: &Id,
    device: &[u8; DEVICE_KEY],
) -> Result<Vec<u8>, Error> {
    list(&[
        WRAP_INFO_LABEL,
        b"account-secret",
        account.as_bytes(),
        approval.as_bytes(),
        device,
    ])
}

/// The message of E's device signature (SYN-06.11 step 5):
/// (`sync-device-v1`, `account_id`, N's device public key, `approval_id`).
///
/// # Errors
/// Never in practice.
pub fn device_message(
    account: &AccountId,
    device: &[u8; DEVICE_KEY],
    approval: &Id,
) -> Result<Vec<u8>, Error> {
    list(&[
        DEVICE_LABEL,
        account.as_bytes(),
        device,
        approval.as_bytes(),
    ])
}

/// The SHA-256 of an approval code: what `POST /v1/approvals` sends and the
/// server stores (SYN-02.3).
///
/// # Errors
/// Never in practice.
pub fn code_hash(code: &SecretBytes) -> Result<[u8; 32], Error> {
    sha(&[code.expose()])
}

/// The approval code as the user types it: base32 in groups of 4.
#[must_use]
pub fn code_shown(code: &SecretBytes) -> SecretString {
    base32::encode(code.expose(), true)
}

/// The approval code as typed: read case-blind, spaces and `-` ignored.
#[must_use]
pub fn read_code(text: &str) -> Option<SecretBytes> {
    base32::read(text, CODE_BYTES)
}

/// The `Authorization` value of the approval routes: `Approval ` and the 26
/// characters, in a [`SecretString`].
#[must_use]
pub fn authorization(code: &SecretBytes) -> SecretString {
    let mut out = String::with_capacity(SCHEME.len().saturating_add(1 + CODE_CHARS));
    out.push_str(SCHEME);
    out.push(' ');
    base32::push(&mut out, code.expose(), false);
    SecretString::new(out)
}

/// The approval code of the `Authorization` field lines (SYN-01.4):
/// exactly one line, the scheme `Approval` in any case, one or more spaces,
/// then 26 upper-case base32 characters in their canonical form. Anything
/// else, a second line included, is `None`: 401. Untrusted bytes; never
/// panics.
#[must_use]
pub fn approval(lines: &[&[u8]]) -> Option<SecretBytes> {
    let [line] = lines else {
        return None;
    };
    let line = line.trim_ascii();
    let (scheme, rest) = line.split_at_checked(SCHEME.len())?;
    if !scheme.eq_ignore_ascii_case(SCHEME.as_bytes()) || rest.first() != Some(&b' ') {
        return None;
    }
    let start = rest.iter().position(|c| *c != b' ').unwrap_or(rest.len());
    let token = rest.get(start..)?;
    let ok = |c: &u8| c.is_ascii_uppercase() || (b'2'..=b'7').contains(c);
    if token.len() != CODE_CHARS || !token.iter().all(ok) {
        return None;
    }
    base32::read(std::str::from_utf8(token).ok()?, CODE_BYTES)
}

/// `POST /v1/approvals` (SYN-06.11 step 1): `{"code_hash"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalCreate {
    /// The SHA-256 of the approval code.
    pub code_hash: [u8; 32],
}

impl ApprovalCreate {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            code_hash: array(&map, "code_hash")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&larsal_model::json!({"code_hash": b64(&self.code_hash)}))
    }
}

/// The reply to `POST /v1/approvals`: `{"approval_id","expires"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalStart {
    /// The request's id.
    pub approval_id: Id,
    /// The first second, on the server's clock, at which it is no longer
    /// valid: 15 minutes after it was made.
    pub expires: u64,
}

impl ApprovalStart {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            approval_id: id(&map, "approval_id")?,
            expires: number(&map, "expires")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&larsal_model::json!({
            "approval_id": self.approval_id.to_string(),
            "expires": self.expires
        }))
    }
}

/// `POST /v1/approvals/claim` (step 2): `{"device_public_key","device_name"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalClaim {
    /// N's device public key: 65 SEC1 bytes.
    pub device_public_key: [u8; DEVICE_KEY],
    /// N's device name ([`device_name_ok`]).
    pub device_name: String,
}

impl ApprovalClaim {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        let name = text(&map, "device_name")?;
        if !device_name_ok(name) {
            return Err(Error::Invalid("device_name"));
        }
        Ok(Self {
            device_public_key: array(&map, "device_public_key")?,
            device_name: name.to_owned(),
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&larsal_model::json!({
            "device_public_key": b64(&self.device_public_key),
            "device_name": self.device_name.as_str()
        }))
    }
}

/// The reply to the claim: `{"approval_id","account_id","expires"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalClaimed {
    /// The request's id.
    pub approval_id: Id,
    /// The account N joins.
    pub account_id: AccountId,
    /// As [`ApprovalStart::expires`].
    pub expires: u64,
}

impl ApprovalClaimed {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            approval_id: id(&map, "approval_id")?,
            account_id: id(&map, "account_id")?,
            expires: number(&map, "expires")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&larsal_model::json!({
            "approval_id": self.approval_id.to_string(),
            "account_id": self.account_id.to_string(),
            "expires": self.expires
        }))
    }
}

/// `POST /v1/approvals/{approval_id}/commit`, SYN-05's message (1):
/// `{"commit"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompareCommit {
    /// SYN-05.1's commitment, 32 bytes.
    pub commit: [u8; 32],
}

impl CompareCommit {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            commit: array(&map, "commit")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&larsal_model::json!({"commit": b64(&self.commit)}))
    }
}

/// SYN-05's messages (2) and (3): `{"keys","nonce"}`, a key list and a
/// 32-byte nonce. `POST …/keys` carries `K_R` ([`KEYS_R`] bytes) and
/// `POST …/reveal` `K_C` ([`KEYS_C`] bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareKeys {
    /// The key list.
    pub keys: Vec<u8>,
    /// The sender's nonce.
    pub nonce: [u8; 32],
}

/// `POST …/reveal`'s record: the same fields as [`CompareKeys`].
pub type CompareReveal = CompareKeys;

impl CompareKeys {
    /// Reads the record, whose key list must be `len` bytes.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8], len: usize) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            keys: byte_string(&map, "keys", len..=len)?,
            nonce: array(&map, "nonce")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&larsal_model::json!({"keys": b64(&self.keys), "nonce": b64(&self.nonce)}))
    }
}

/// `POST …/seal` (step 5): CRY-05.4's wrap record of `S_acct` with one more
/// field, `device_signature` (3,373 bytes): the identity key's composite
/// signature over [`device_message`]. At most [`MAX_WRAP`] bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalSeal {
    /// The sealed `S_acct`.
    pub seal: WrapRecord,
    /// The device signature.
    pub device_signature: Vec<u8>,
}

impl ApprovalSeal {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`wire::read`], or a missing or invalid `device_signature`.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let seal = wire::read(bytes)?;
        let map = read_record(bytes, MAX_WRAP)?;
        Ok(Self {
            seal,
            device_signature: byte_string(&map, "device_signature", SIGNATURE..=SIGNATURE)?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        let mut map = read_record(&wire::to_json(&self.seal), MAX_WRAP).unwrap_or_default();
        map.insert(
            "device_signature".to_owned(),
            Value::from(b64(&self.device_signature)),
        );
        write(&Value::Object(map))
    }
}

/// `GET /v1/approvals/{approval_id}` (SYN-06.11 steps 3, 4 and 6):
/// `{"device_public_key","device_name","commit","keys_r","nonce_r","keys_c",
/// "nonce_c","seal","device_id","expires"}`, each `""` until it is sent
/// (SHR-03.6's form). `seal` is the wrap record's bytes in base64url;
/// `device_id` names the device the seal registered.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ApprovalState {
    /// The claim's device public key.
    pub device_public_key: Option<[u8; DEVICE_KEY]>,
    /// The claim's device name.
    pub device_name: Option<String>,
    /// Message (1).
    pub commit: Option<[u8; 32]>,
    /// Message (2): `K_R` and `n_R`.
    pub keys_r: Option<(Vec<u8>, [u8; 32])>,
    /// Message (3): `K_C` and `n_C`.
    pub keys_c: Option<(Vec<u8>, [u8; 32])>,
    /// The seal record's bytes and the device it registered.
    pub seal: Option<(Vec<u8>, DeviceId)>,
    /// As [`ApprovalStart::expires`].
    pub expires: u64,
}

/// Sizes and presence only.
impl fmt::Debug for ApprovalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalState")
            .field("claimed", &self.device_public_key.is_some())
            .field("commit", &self.commit.is_some())
            .field("keys_r", &self.keys_r.is_some())
            .field("keys_c", &self.keys_c.is_some())
            .field("sealed", &self.seal.is_some())
            .field("expires", &self.expires)
            .finish()
    }
}

/// A byte string of exactly `len` bytes, or `""` for none.
fn maybe(
    map: &larsal_model::json::Map,
    field: &'static str,
    len: usize,
) -> Result<Option<Vec<u8>>, Error> {
    if text(map, field)?.is_empty() {
        return Ok(None);
    }
    byte_string(map, field, len..=len).map(Some)
}

fn nonce(map: &larsal_model::json::Map, field: &'static str) -> Result<Option<[u8; 32]>, Error> {
    maybe(map, field, 32)?
        .map(|n| <[u8; 32]>::try_from(n).map_err(|_| Error::Invalid(field)))
        .transpose()
}

/// A key list and its nonce (SYN-05's message (2) or (3)).
type KeysAndNonce = (Vec<u8>, [u8; 32]);

/// A key list and its nonce: both there, or both `""`.
fn pair(
    map: &larsal_model::json::Map,
    keys: &'static str,
    nonce_field: &'static str,
    len: usize,
) -> Result<Option<KeysAndNonce>, Error> {
    match (maybe(map, keys, len)?, nonce(map, nonce_field)?) {
        (Some(k), Some(n)) => Ok(Some((k, n))),
        (None, None) => Ok(None),
        _ => Err(Error::Invalid(keys)),
    }
}

impl ApprovalState {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        let device_public_key = maybe(&map, "device_public_key", DEVICE_KEY)?
            .map(|k| {
                <[u8; DEVICE_KEY]>::try_from(k).map_err(|_| Error::Invalid("device_public_key"))
            })
            .transpose()?;
        let name = text(&map, "device_name")?;
        let device_name = match name {
            "" => None,
            n if device_name_ok(n) => Some(n.to_owned()),
            _ => return Err(Error::Invalid("device_name")),
        };
        let seal = match (text(&map, "seal")?, text(&map, "device_id")?) {
            ("", "") => None,
            (_, device) => Some((
                byte_string(&map, "seal", 1..=MAX_WRAP)?,
                Id::parse(device).ok_or(Error::Invalid("device_id"))?,
            )),
        };
        Ok(Self {
            device_public_key,
            device_name,
            commit: nonce(&map, "commit")?,
            keys_r: pair(&map, "keys_r", "nonce_r", KEYS_R)?,
            keys_c: pair(&map, "keys_c", "nonce_c", KEYS_C)?,
            seal,
            expires: number(&map, "expires")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        let or = |b: Option<&[u8]>| b.map(b64).unwrap_or_default();
        let (seal, device) = self
            .seal
            .as_ref()
            .map_or((String::new(), String::new()), |(s, d)| {
                (b64(s), d.to_string())
            });
        write(&larsal_model::json!({
            "device_public_key": or(self.device_public_key.as_ref().map(|k| &k[..])),
            "device_name": self.device_name.clone().unwrap_or_default(),
            "commit": or(self.commit.as_ref().map(|c| &c[..])),
            "keys_r": or(self.keys_r.as_ref().map(|(k, _)| k.as_slice())),
            "nonce_r": or(self.keys_r.as_ref().map(|(_, n)| &n[..])),
            "keys_c": or(self.keys_c.as_ref().map(|(k, _)| k.as_slice())),
            "nonce_c": or(self.keys_c.as_ref().map(|(_, n)| &n[..])),
            "seal": seal,
            "device_id": device,
            "expires": self.expires
        }))
    }
}

#[cfg(test)]
mod tests;
