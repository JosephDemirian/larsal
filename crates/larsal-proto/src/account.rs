//! The account records of SYN-06 (E17-S1; CRY-05.8, CRY-05.10, SYN-06.14):
//! the account keys record of `PUT` and `GET /v1/account/keys` (SYN-06.6),
//! the recovery sign-in records (SYN-06.12), the upload signature's message
//! and headers (SYN-01.7, CRY-05.10) and the key-file part's wrap info
//! (SYN-06.9).
//!
//! Guarantees: every reader takes untrusted bytes and never panics; each
//! byte string has CRY-05.8's size, checked before it is decoded; the
//! `Debug` output of a recovery sign-in hides its nonce and signature
//! (SYN-01.13). Nothing here is secret: the blob is ciphertext, every key a
//! public key.

use crate::Error;
use crate::limits::MAX_JSON;
use crate::messages::{
    AccountId, DeviceId, Session, VaultId, array, b64, byte_string, device_name_ok, id,
    read_record, text, write,
};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::pq::{IDENTITY_PUBLIC, PUBLIC_KEY, SIGNATURE};
use larsal_crypto::sign;
use std::fmt;

/// The largest account blob a record carries (SYN-06: at most 4 KiB).
pub const MAX_BLOB: usize = 4096;
/// The header of an upload's signature (SYN-01.7; no `X-`, RFC 6648).
pub const UPLOAD_SIGNATURE: &str = "upload-signature";
/// The header naming an upload's signer, 32 lowercase hex (SYN-01.7).
pub const UPLOAD_SIGNER: &str = "upload-signer";
/// `Upload-Signature`'s length: 3,373 bytes in base64url without padding
/// (CRY-05.10).
pub const UPLOAD_SIGNATURE_LEN: usize = 4498;
/// The label of an upload signature's field list (CRY-04.2, SYN-01.7).
const UPLOAD_LABEL: &[u8] = b"sync-upload-v1";
/// The label of a wrap's info (CRY-04.2, SYN-06.9).
const WRAP_INFO_LABEL: &[u8] = b"sync-wrap-info-v1";

/// `PUT` and `GET /v1/account/keys` (SYN-06.6 with CRY-05.8):
/// `{"identity_public_key","kem_public_key","kem_signature",
/// "recovery_public_key","blob"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountKeys {
    /// The composite identity public key, 1,984 bytes (CRY-05.5).
    pub identity_public_key: Vec<u8>,
    /// The X-Wing receiving public key, 1,216 bytes (CRY-05.2).
    pub kem_public_key: Vec<u8>,
    /// The binding: the composite signature over (`sync-kem-key-v1`,
    /// `account_id`, the receiving public key), 3,373 bytes.
    pub kem_signature: Vec<u8>,
    /// The Ed25519 recovery public key (SYN-06.5, CRY-05.13).
    pub recovery_public_key: [u8; 32],
    /// The account blob (SYN-06.4), 1 to [`MAX_BLOB`] bytes; the server
    /// never reads it.
    pub blob: Vec<u8>,
}

impl AccountKeys {
    /// Reads the record; every byte string must have its size.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            identity_public_key: byte_string(
                &map,
                "identity_public_key",
                IDENTITY_PUBLIC..=IDENTITY_PUBLIC,
            )?,
            kem_public_key: byte_string(&map, "kem_public_key", PUBLIC_KEY..=PUBLIC_KEY)?,
            kem_signature: byte_string(&map, "kem_signature", SIGNATURE..=SIGNATURE)?,
            recovery_public_key: array(&map, "recovery_public_key")?,
            blob: byte_string(&map, "blob", 1..=MAX_BLOB)?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&larsal_model::json!({
            "identity_public_key": b64(&self.identity_public_key),
            "kem_public_key": b64(&self.kem_public_key),
            "kem_signature": b64(&self.kem_signature),
            "recovery_public_key": b64(&self.recovery_public_key),
            "blob": b64(&self.blob)
        }))
    }
}

/// `POST /v1/recovery/challenge` (SYN-06.12): `{"account_id":…}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryChallengeRequest {
    /// The account to restore.
    pub account_id: AccountId,
}

impl RecoveryChallengeRequest {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid `account_id`.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            account_id: id(&map, "account_id")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&larsal_model::json!({"account_id": self.account_id.to_string()}))
    }
}

/// `POST /v1/recovery/signin` (SYN-06.12):
/// `{"account_id","nonce","device_public_key","device_name","signature"}`.
///
/// Guarantees: the `Debug` output hides the nonce and the signature.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoverySignIn {
    /// The account to restore.
    pub account_id: AccountId,
    /// The nonce of its recovery challenge.
    pub nonce: [u8; 32],
    /// The new device's P-256 public key, 65 SEC1 bytes (CRY-04.4).
    pub device_public_key: [u8; 65],
    /// The device's name ([`device_name_ok`]).
    pub device_name: String,
    /// The recovery key's Ed25519 signature of
    /// [`crate::signin::recovery_message`].
    pub signature: [u8; 64],
}

impl RecoverySignIn {
    /// Reads the record; a name [`device_name_ok`] refuses is
    /// [`Error::Invalid`].
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
            account_id: id(&map, "account_id")?,
            nonce: array(&map, "nonce")?,
            device_public_key: array(&map, "device_public_key")?,
            device_name: name.to_owned(),
            signature: array(&map, "signature")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&larsal_model::json!({
            "account_id": self.account_id.to_string(),
            "nonce": b64(&self.nonce),
            "device_public_key": b64(&self.device_public_key),
            "device_name": self.device_name.as_str(),
            "signature": b64(&self.signature)
        }))
    }
}

impl fmt::Debug for RecoverySignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoverySignIn")
            .field("account_id", &self.account_id)
            .field("nonce", &format_args!("[hidden]"))
            .field("device_name", &self.device_name)
            .field("signature", &format_args!("[hidden]"))
            .finish_non_exhaustive()
    }
}

/// The reply to a passed recovery sign-in: SYN-04.5's session record with
/// the new device's `device_id`, a field SYN-01.8 lets a record add, so the
/// Mac can sign in with its device key from then on.
#[derive(Debug)]
pub struct Recovered {
    /// The device the server registered.
    pub device_id: DeviceId,
    /// Its session.
    pub session: Session,
}

impl Recovered {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`Session::read`], or a missing or invalid `device_id`.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            device_id: id(&map, "device_id")?,
            session: Session::read(bytes)?,
        })
    }

    /// The record's bytes; they hold the token, as the reply must.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        let token = base64::encode_secret(Form::Url, self.session.token.expose());
        write(&larsal_model::json!({
            "token": token.expose(),
            "idle_seconds": self.session.idle_seconds,
            "expires": self.session.expires,
            "device_id": self.device_id.to_string()
        }))
    }
}

/// The bytes an upload signature covers (SYN-01.7): the field list
/// (`sync-upload-v1`, the 16 bytes of `vault`, `version` as a u64 big
/// endian, the SHA-256 of the body).
///
/// # Errors
/// None in practice: the fields are small ([`Error::TooLarge`] otherwise).
pub fn upload_message(vault: &VaultId, version: u64, sha256: &[u8; 32]) -> Result<Vec<u8>, Error> {
    sign::field_list(&[
        UPLOAD_LABEL,
        vault.as_bytes(),
        &version.to_be_bytes(),
        sha256,
    ])
    .map_err(|_| Error::TooLarge)
}

/// The signature in `Upload-Signature`'s field lines (SYN-01.7,
/// CRY-05.10): exactly one line of exactly [`UPLOAD_SIGNATURE_LEN`]
/// base64url characters that decode to 3,373 bytes with the unused low
/// bits zero; `None` for anything else, no line included. Untrusted bytes;
/// never panics.
#[must_use]
pub fn upload_signature(lines: &[&[u8]]) -> Option<Vec<u8>> {
    let [line] = lines else {
        return None;
    };
    let url = |c: &u8| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_';
    if line.len() != UPLOAD_SIGNATURE_LEN || !line.iter().all(url) {
        return None;
    }
    base64::decode(Form::Url, line)
        .ok()
        .filter(|s| s.len() == SIGNATURE)
}

/// The info of a key-file part's wrap (SYN-06.9): the field list
/// (`sync-wrap-info-v1`, `keypart`, the 16 bytes of `account`, the 16 bytes
/// of `vault`). The reader builds it itself, never from the record.
///
/// # Errors
/// None in practice ([`Error::TooLarge`] otherwise).
pub fn keypart_info(account: &AccountId, vault: &VaultId) -> Result<Vec<u8>, Error> {
    sign::field_list(&[
        WRAP_INFO_LABEL,
        b"keypart",
        account.as_bytes(),
        vault.as_bytes(),
    ])
    .map_err(|_| Error::TooLarge)
}

#[cfg(test)]
mod tests;
