//! The two public metadata files: the signed configuration and the key file (FIL-04.1
//! to FIL-04.3). Bounded, strict, and read in the order the rules ask: nothing in a
//! configuration's claims is believed until its signature holds.

use crate::error::{Error, Refused};
use crate::limits::{
    CREATE_THRESHOLD, MAX_JSON_DEPTH, MAX_JSON_MEMBERS, MAX_JSON_SCALAR, MAX_METADATA, MAX_R,
    MAX_THRESHOLD, MIN_THRESHOLD, SALT_RANGE,
};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::{kdf, keywrap, mac};
use larsal_model::json::{self, Value};

pub(crate) const CONFIG_FILE: &str = "vault.cryptomator";
pub(crate) const KEY_FILE: &str = "masterkey.cryptomator";
pub(crate) const UVF_FILE: &str = "vault.uvf";
const KID: &str = "masterkeyfile:masterkey.cryptomator";
const REMOTE_KID: &str = "hub+";
/// The key file's version for format 8 and later: the format says it no longer means.
const KEY_FILE_VERSION: u64 = 999;
const FIRST_CONFIG_FORMAT: u64 = 8;

fn within_limits(value: &Value, depth: usize) -> bool {
    let Some(next) = depth.checked_add(1) else {
        return false;
    };
    match value {
        Value::String(s) => s.len() <= MAX_JSON_SCALAR,
        Value::Number(n) => n.to_string().len() <= MAX_JSON_SCALAR,
        Value::Array(items) => {
            depth <= MAX_JSON_DEPTH
                && items.len() <= MAX_JSON_MEMBERS
                && items.iter().all(|v| within_limits(v, next))
        }
        Value::Object(members) => {
            depth <= MAX_JSON_DEPTH
                && members.len() <= MAX_JSON_MEMBERS
                && members
                    .iter()
                    .all(|(k, v)| k.len() <= MAX_JSON_SCALAR && within_limits(v, next))
        }
        Value::Null | Value::Bool(_) => true,
    }
}

fn object(bytes: &[u8]) -> Result<Value, Error> {
    let value = json::from_slice_unique(bytes).map_err(|_| Error::Open)?;
    if value.as_object().is_some() && within_limits(&value, 1) {
        Ok(value)
    } else {
        Err(Error::Open)
    }
}

/// Which HMAC signs a configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alg {
    Hs256,
    Hs384,
    Hs512,
}

/// A configuration whose header has been read. Nothing else is believed yet.
#[derive(Debug)]
pub(crate) struct Config {
    alg: Alg,
    signing_input: Vec<u8>,
    claims: Vec<u8>,
    signature: Vec<u8>,
}

/// One base64url part of a token, with one text for one byte string.
fn token_part(text: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes = base64::decode(Form::Url, text).map_err(|_| Error::Open)?;
    if base64::encode(Form::Url, &bytes).as_bytes() == text {
        Ok(bytes)
    } else {
        Err(Error::Open)
    }
}

/// Reads a configuration up to what may be known before any key: its size, its three
/// parts and its header. `kid` allows only the local key file (FIL-04.2); a server's
/// key is refused by name, with no network call and no key derivation.
///
/// # Errors
/// [`Error::Open`] for anything hostile; [`Error::Profile`] for a remote key.
pub(crate) fn parse_config(bytes: &[u8]) -> Result<Config, Error> {
    if bytes.len() > MAX_METADATA {
        return Err(Error::Open);
    }
    let mut parts = bytes.split(|b| *b == b'.');
    let (Some(head), Some(claims), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Open);
    };
    let header = object(&token_part(head)?)?;
    let members = header.as_object().ok_or(Error::Open)?;
    if !members
        .keys()
        .all(|k| matches!(k.as_str(), "kid" | "typ" | "alg"))
    {
        return Err(Error::Open);
    }
    if members
        .get("typ")
        .is_some_and(|t| t.as_str() != Some("JWT"))
    {
        return Err(Error::Open);
    }
    let alg = match members.get("alg").and_then(Value::as_str) {
        Some("HS256") => Alg::Hs256,
        Some("HS384") => Alg::Hs384,
        Some("HS512") => Alg::Hs512,
        _ => return Err(Error::Open),
    };
    match members.get("kid").and_then(Value::as_str) {
        Some(KID) => {}
        Some(kid) if kid.starts_with(REMOTE_KID) => return Err(Error::Profile(Refused::RemoteKey)),
        _ => return Err(Error::Open),
    }
    let signing_len = head
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(claims.len()))
        .ok_or(Error::Open)?;
    Ok(Config {
        alg,
        signing_input: bytes.get(..signing_len).ok_or(Error::Open)?.to_vec(),
        claims: token_part(claims)?,
        signature: token_part(signature)?,
    })
}

impl Config {
    /// True when the original signing input is signed with the whole raw key under the
    /// algorithm the header named, and only that one.
    pub(crate) fn signed_by(&self, raw_key: &SecretBytes) -> bool {
        let (key, input, sig) = (
            raw_key.expose(),
            &[&self.signing_input[..]],
            &self.signature[..],
        );
        match self.alg {
            Alg::Hs256 => mac::verify_hmac_sha256(key, input, sig),
            Alg::Hs384 => mac::verify_hmac_sha384(key, input, sig),
            Alg::Hs512 => mac::verify_hmac_sha512(key, input, sig),
        }
    }

    /// The shortening threshold of a configuration whose signature has been proven,
    /// or which format it is, by name. Call only after [`Config::signed_by`].
    ///
    /// # Errors
    /// [`Error::Profile`] for an authenticated other format or cipher; [`Error::Open`]
    /// for anything malformed.
    pub(crate) fn authenticated_threshold(&self) -> Result<usize, Error> {
        let claims = object(&self.claims)?;
        match claims.get("format").and_then(Value::as_u64) {
            Some(8) => {}
            Some(_) => return Err(Error::Profile(Refused::OtherFormat)),
            None => return Err(Error::Open),
        }
        match claims.get("cipherCombo").and_then(Value::as_str) {
            Some("SIV_GCM") => {}
            Some("SIV_CTRMAC") => return Err(Error::Profile(Refused::SivCtrMac)),
            Some(_) => return Err(Error::Profile(Refused::OtherCipher)),
            None => return Err(Error::Open),
        }
        let threshold = claims
            .get("shorteningThreshold")
            .and_then(Value::as_u64)
            .filter(|t| (MIN_THRESHOLD..=MAX_THRESHOLD).contains(t))
            .ok_or(Error::Open)?;
        usize::try_from(threshold).map_err(|_| Error::Open)
    }
}

/// The key file's settings and wrapped keys. Nothing in it is secret.
#[derive(Debug)]
pub(crate) struct KeyFile {
    pub(crate) version: u32,
    pub(crate) log_n: u8,
    pub(crate) r: u32,
    pub(crate) salt: Vec<u8>,
    pub(crate) wrapped_enc: Vec<u8>,
    pub(crate) wrapped_mac: Vec<u8>,
    pub(crate) version_mac: Vec<u8>,
}

fn key_file_bytes(file: &Value, member: &str) -> Result<Vec<u8>, Error> {
    let text = file
        .get(member)
        .and_then(Value::as_str)
        .ok_or(Error::Open)?;
    let bytes = base64::decode(Form::Padded, text).map_err(|_| Error::Open)?;
    // One text for one byte string: `Padded` alone ignores the low bits of the last
    // character.
    if base64::encode(Form::Padded, &bytes) == text {
        Ok(bytes)
    } else {
        Err(Error::Open)
    }
}

/// Reads a key file, and proves every bound before any key derivation or allocation it
/// would pay for (FIL-04.3, FIL-06.1), RFC 7914's validity apart from the ceilings.
///
/// # Errors
/// [`Error::Open`] for anything hostile, with no work done.
pub(crate) fn parse_key_file(bytes: &[u8]) -> Result<KeyFile, Error> {
    if bytes.len() > MAX_METADATA {
        return Err(Error::Open);
    }
    let file = object(bytes)?;
    let version = file
        .get("version")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(Error::Open)?;
    let n = file
        .get("scryptCostParam")
        .and_then(Value::as_u64)
        .ok_or(Error::Open)?;
    let r = file
        .get("scryptBlockSize")
        .and_then(Value::as_u64)
        .ok_or(Error::Open)?;
    if !n.is_power_of_two() || n < 2 || !(1..=MAX_R).contains(&r) {
        return Err(Error::Open);
    }
    let log_n = u8::try_from(n.trailing_zeros()).map_err(|_| Error::Open)?;
    let r = u32::try_from(r).map_err(|_| Error::Open)?;
    kdf::scrypt_settings(log_n, r, 1).map_err(|_| Error::Open)?;
    let salt = key_file_bytes(&file, "scryptSalt")?;
    let wrapped_enc = key_file_bytes(&file, "primaryMasterKey")?;
    let wrapped_mac = key_file_bytes(&file, "hmacMasterKey")?;
    let version_mac = key_file_bytes(&file, "versionMac")?;
    if !SALT_RANGE.contains(&salt.len())
        || wrapped_enc.len() != keywrap::WRAPPED
        || wrapped_mac.len() != keywrap::WRAPPED
        || version_mac.len() != 32
    {
        return Err(Error::Open);
    }
    Ok(KeyFile {
        version,
        log_n,
        r,
        salt,
        wrapped_enc,
        wrapped_mac,
        version_mac,
    })
}

impl KeyFile {
    /// True when the version MAC holds under the unwrapped MAC key.
    pub(crate) fn version_proven(&self, mac_key: &SecretBytes) -> bool {
        mac::verify_hmac_sha256(
            mac_key.expose(),
            &[&self.version.to_be_bytes()],
            &self.version_mac,
        )
    }

    /// With a configuration present, a key file says version 999.
    pub(crate) fn fits_a_config(&self) -> bool {
        u64::from(self.version) == KEY_FILE_VERSION
    }

    /// A key file older than the first format with a configuration.
    pub(crate) fn predates_config(&self) -> bool {
        u64::from(self.version) < FIRST_CONFIG_FORMAT
    }
}

/// The key file of a new folder.
#[must_use]
pub(crate) fn write_key_file(
    n: u64,
    r: u32,
    salt: &[u8],
    wrapped_enc: &[u8],
    wrapped_mac: &[u8],
    version_mac: &[u8],
) -> String {
    format!(
        "{{\n  \"version\": {KEY_FILE_VERSION},\n  \"scryptSalt\": \"{}\",\n  \"scryptCostParam\": {n},\n  \"scryptBlockSize\": {r},\n  \"primaryMasterKey\": \"{}\",\n  \"hmacMasterKey\": \"{}\",\n  \"versionMac\": \"{}\"\n}}",
        base64::encode(Form::Padded, salt),
        base64::encode(Form::Padded, wrapped_enc),
        base64::encode(Form::Padded, wrapped_mac),
        base64::encode(Form::Padded, version_mac),
    )
}

/// The signed configuration of a new folder: HS256 over the whole raw key.
///
/// # Errors
/// [`Error::Io`] when the MAC cannot be made.
pub(crate) fn write_config(raw_key: &SecretBytes, jti: &str) -> Result<String, Error> {
    let head = format!("{{\"kid\":\"{KID}\",\"typ\":\"JWT\",\"alg\":\"HS256\"}}");
    let claims = format!(
        "{{\"format\":8,\"shorteningThreshold\":{CREATE_THRESHOLD},\"jti\":\"{jti}\",\"cipherCombo\":\"SIV_GCM\"}}"
    );
    let input = format!(
        "{}.{}",
        base64::encode(Form::Url, head.as_bytes()),
        base64::encode(Form::Url, claims.as_bytes())
    );
    let tag = mac::hmac_sha256(raw_key.expose(), &[input.as_bytes()]).map_err(|_| Error::Io)?;
    Ok(format!(
        "{input}.{}",
        base64::encode(Form::Url, tag.expose())
    ))
}

/// A UUID's 16 bytes in their usual text.
pub(crate) fn uuid_text(bytes: &[u8; 16]) -> String {
    let hex = crate::names::hex(bytes);
    let cut = |r: std::ops::Range<usize>| hex.get(r).unwrap_or_default();
    format!(
        "{}-{}-{}-{}-{}",
        cut(0..8),
        cut(8..12),
        cut(12..16),
        cut(16..20),
        cut(20..32)
    )
}
