//! Records (SYN-01.8): one JSON object in UTF-8, read and written with
//! app-model's `json.rs`. E16-S3 has the health record (SYN-01.14) and the
//! error body (SYN-01.9); E16-S4 the vault id and the vault records of
//! SYN-01.6; E16-S5 the account, challenge, sign-in and session records of
//! SYN-04; later stories add theirs on [`read_record`].

use crate::Error;
use crate::limits::{
    MAX_DEVICE_NAME, MAX_JSON, MAX_RECORD_DEPTH, MAX_RECORD_NUMBER, MAX_SIGNATURE,
};
use app_crypto::base64::{self, Form};
use app_crypto::secret::SecretBytes;
use app_model::json::{self, Map, Value};
use std::fmt;
use std::ops::RangeInclusive;

/// Reads one record of at most `limit` bytes: one JSON object, no repeated
/// key, arrays and objects at most [`MAX_RECORD_DEPTH`] levels deep (the top
/// object is level 1). The length is checked before any byte is parsed.
/// Fields a reader does not know stay in the map and are ignored, so a later
/// `/v1` server may add one (SYN-01.8).
///
/// # Errors
/// [`Error::TooLarge`], [`Error::NotJson`], [`Error::NotObject`] or
/// [`Error::TooDeep`].
pub fn read_record(bytes: &[u8], limit: usize) -> Result<Map, Error> {
    if bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    let value = json::from_slice_unique(bytes).map_err(|_| Error::NotJson)?;
    if depth(&value) > MAX_RECORD_DEPTH {
        return Err(Error::TooDeep);
    }
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(Error::NotObject),
    }
}

// ponytail: recursive, bounded by json.rs's MAX_DEPTH (127) on at most
// MAX_JSON bytes.
fn depth(value: &Value) -> usize {
    let inner = match value {
        Value::Array(items) => items.iter().map(depth).max(),
        Value::Object(map) => map.values().map(depth).max(),
        _ => return 0,
    };
    inner.unwrap_or(0).saturating_add(1)
}

pub(crate) fn text<'a>(map: &'a Map, field: &'static str) -> Result<&'a str, Error> {
    map.get(field)
        .ok_or(Error::Missing(field))?
        .as_str()
        .ok_or(Error::Invalid(field))
}

/// A whole number from 0 to 2^53 − 1 (SYN-01.8).
pub(crate) fn number(map: &Map, field: &'static str) -> Result<u64, Error> {
    map.get(field)
        .ok_or(Error::Missing(field))?
        .as_u64()
        .filter(|n| *n <= MAX_RECORD_NUMBER)
        .ok_or(Error::Invalid(field))
}

/// A byte string field (SYN-01.8): base64url without padding, every unused
/// low bit zero, of a length in `len`. Text longer than the longest
/// allowed encoding is refused before it is decoded.
pub(crate) fn byte_string(
    map: &Map,
    field: &'static str,
    len: RangeInclusive<usize>,
) -> Result<Vec<u8>, Error> {
    let text = text(map, field)?;
    // The unpadded encoding of n bytes is ceil(4n / 3) characters.
    let longest = len.end().saturating_mul(4).saturating_add(2) / 3;
    if text.len() > longest || text.contains('=') {
        return Err(Error::Invalid(field));
    }
    let out = base64::decode(Form::Url, text).map_err(|_| Error::Invalid(field))?;
    if len.contains(&out.len()) {
        Ok(out)
    } else {
        Err(Error::Invalid(field))
    }
}

/// A byte string field of exactly `N` bytes.
pub(crate) fn array<const N: usize>(map: &Map, field: &'static str) -> Result<[u8; N], Error> {
    <[u8; N]>::try_from(byte_string(map, field, N..=N)?).map_err(|_| Error::Invalid(field))
}

/// An id field: 32 lowercase hex digits (SYN-01.8).
pub(crate) fn id(map: &Map, field: &'static str) -> Result<Id, Error> {
    Id::parse(text(map, field)?).ok_or(Error::Invalid(field))
}

/// Bytes as base64url without padding (SYN-01.8).
pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::encode(Form::Url, bytes)
}

pub(crate) fn write(value: &Value) -> Vec<u8> {
    json::to_string(value).into_bytes()
}

/// The health record, `{"service":"sync","api":1}` (SYN-01.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    service: String,
    api: u64,
}

impl Health {
    /// The record this server sends.
    #[must_use]
    pub fn this_server() -> Self {
        Self {
            service: "sync".to_owned(),
            api: 1,
        }
    }

    /// Reads a health reply of at most [`MAX_JSON`] bytes.
    ///
    /// # Errors
    /// As [`read_record`], or [`Error::Missing`] and [`Error::Invalid`] for
    /// `service` (a string) and `api` (a number).
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            service: text(&map, "service")?.to_owned(),
            api: number(&map, "api")?,
        })
    }

    /// True when the reply names App's sync service, API version 1: only
    /// then is the address an App server (SYN-01.3).
    #[must_use]
    pub fn is_app_server(&self) -> bool {
        *self == Self::this_server()
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        json::to_string(&app_model::json!({"service": self.service.as_str(), "api": self.api}))
            .into_bytes()
    }
}

/// An id (SYN-01.8): 16 bytes from a random source, written as 32
/// lowercase hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id([u8; 16]);

/// A vault's id (SYN-01.6): drawn by the client at the first upload. It is
/// not the vault's root group id, so the server learns nothing from inside
/// the file.
pub type VaultId = Id;
/// An account's id (SYN-04.2), drawn by the server.
pub type AccountId = Id;
/// A device's id (SYN-04.2), drawn by the server.
pub type DeviceId = Id;

impl Id {
    /// Reads exactly 32 lowercase hex digits; anything else (another
    /// length, an upper-case digit, a sign) is `None` (SYN-01.8).
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let hex = |c: u8| matches!(c, b'0'..=b'9' | b'a'..=b'f');
        if text.len() != 32 || !text.bytes().all(hex) {
            return None;
        }
        u128::from_str_radix(text, 16)
            .ok()
            .map(|n| Self(n.to_be_bytes()))
    }

    /// The id of these 16 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The id's 16 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The 32 lowercase hex digits of the id.
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", u128::from_be_bytes(self.0))
    }
}

/// One vault as a reply names it (SYN-01.6): `{"id":…,"version":…,"size":…}`
/// and nothing else, no names, no times, no item counts. The body of a
/// PUT's reply, and one item of the vault list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultVersion {
    /// The vault's id.
    pub id: VaultId,
    /// Its current version, from 1.
    pub version: u64,
    /// The bytes of that version.
    pub size: u64,
}

impl VaultVersion {
    fn value(&self) -> Value {
        app_model::json!({"id": self.id.to_string(), "version": self.version, "size": self.size})
    }

    fn of(map: &Map) -> Result<Self, Error> {
        Ok(Self {
            id: id(map, "id")?,
            version: number(map, "version")?,
            size: number(map, "size")?,
        })
    }

    /// Reads a PUT's reply (the client, SYN-01.6).
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        Self::of(&read_record(bytes, MAX_JSON)?)
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        json::to_string(&self.value()).into_bytes()
    }
}

/// The vault list, `{"vaults":[…]}`, in the order given; the server gives
/// them sorted by id (SYN-01.6).
#[must_use]
pub fn vault_list(vaults: &[VaultVersion]) -> Vec<u8> {
    let items: Vec<Value> = vaults.iter().map(VaultVersion::value).collect();
    json::to_string(&app_model::json!({"vaults": items})).into_bytes()
}

/// Reads the vault list (the client, SYN-01.6, SYN-01.10): at most
/// [`MAX_JSON`] bytes, checked first, so 1 MiB holds more than 11,000 items
/// and no item count is checked apart from the bytes.
///
/// # Errors
/// As [`read_record`], or `vaults` missing, not an array, or an item that
/// is not a valid vault record.
pub fn read_vault_list(bytes: &[u8]) -> Result<Vec<VaultVersion>, Error> {
    let map = read_record(bytes, MAX_JSON)?;
    map.get("vaults")
        .ok_or(Error::Missing("vaults"))?
        .as_array()
        .ok_or(Error::Invalid("vaults"))?
        .iter()
        .map(|item| VaultVersion::of(item.as_object().ok_or(Error::Invalid("vaults"))?))
        .collect()
}

/// True when `name` is a device name App takes (SYN-04.2, SYN-02.3): 1 to
/// 64 Unicode scalar values, none in the Unicode category Cc (U+0000 to
/// U+001F and U+007F to U+009F, which is what `char::is_control` tests).
#[must_use]
pub fn device_name_ok(name: &str) -> bool {
    let count = name.chars().count();
    (1..=MAX_DEVICE_NAME).contains(&count) && !name.chars().any(char::is_control)
}

/// `POST /v1/accounts` (SYN-04.2): `{"device_public_key":…,"device_name":…}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCreate {
    /// The first device's P-256 public key: 65 SEC1 bytes (CRY-04.4).
    pub device_public_key: [u8; 65],
    /// The device's name ([`device_name_ok`]).
    pub device_name: String,
}

impl AccountCreate {
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
            device_public_key: array(&map, "device_public_key")?,
            device_name: name.to_owned(),
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&app_model::json!({
            "device_public_key": b64(&self.device_public_key),
            "device_name": self.device_name.as_str()
        }))
    }
}

/// The reply to `POST /v1/accounts` (SYN-04.2):
/// `{"account_id":…,"device_id":…}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountCreated {
    /// The new account.
    pub account_id: AccountId,
    /// Its first device.
    pub device_id: DeviceId,
}

impl AccountCreated {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid id.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            account_id: id(&map, "account_id")?,
            device_id: id(&map, "device_id")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&app_model::json!({
            "account_id": self.account_id.to_string(),
            "device_id": self.device_id.to_string()
        }))
    }
}

/// `POST /v1/signin/challenge` (SYN-04.3): `{"device_id":…}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeRequest {
    /// The device that will sign in.
    pub device_id: DeviceId,
}

impl ChallengeRequest {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid `device_id`.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            device_id: id(&map, "device_id")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&app_model::json!({"device_id": self.device_id.to_string()}))
    }
}

/// The reply to a challenge request (SYN-04.3): `{"nonce":…,"expires":…}`.
///
/// Guarantees: the `Debug` output hides the nonce (SYN-01.13).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Challenge {
    /// 32 random bytes, used once.
    pub nonce: [u8; 32],
    /// The first second, on the server's clock, at which it is no longer
    /// valid.
    pub expires: u64,
}

impl Challenge {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            nonce: array(&map, "nonce")?,
            expires: number(&map, "expires")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&app_model::json!({"nonce": b64(&self.nonce), "expires": self.expires}))
    }
}

/// `POST /v1/signin` (SYN-04.4): `{"device_id":…,"nonce":…,"signature":…}`.
///
/// Guarantees: the `Debug` output hides the nonce and the signature
/// (SYN-01.13): with its nonce, a signature signs the device in.
#[derive(Clone, PartialEq, Eq)]
pub struct SignIn {
    /// The device signing in.
    pub device_id: DeviceId,
    /// The nonce of its challenge.
    pub nonce: [u8; 32],
    /// The device key's DER signature of the sign-in message
    /// (`crate::signin::message`), 1 to 72 bytes.
    pub signature: Vec<u8>,
}

impl SignIn {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        Ok(Self {
            device_id: id(&map, "device_id")?,
            nonce: array(&map, "nonce")?,
            signature: byte_string(&map, "signature", 1..=MAX_SIGNATURE)?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        write(&app_model::json!({
            "device_id": self.device_id.to_string(),
            "nonce": b64(&self.nonce),
            "signature": b64(&self.signature)
        }))
    }
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Challenge")
            .field("nonce", &format_args!("[hidden]"))
            .field("expires", &self.expires)
            .finish()
    }
}

impl fmt::Debug for SignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignIn")
            .field("device_id", &self.device_id)
            .field("nonce", &format_args!("[hidden]"))
            .field("signature", &format_args!("[hidden]"))
            .finish()
    }
}

/// The reply to a passed sign-in (SYN-04.5):
/// `{"token":…,"idle_seconds":900,"expires":…}`.
///
/// Guarantees: the token is held in a [`SecretBytes`] (wiped on drop, no
/// `Debug` output). The record's bytes hold it too, as they must, since
/// they are the reply.
#[derive(Debug)]
pub struct Session {
    /// The 32-byte session token (SYN-01.5).
    pub token: SecretBytes,
    /// Seconds of no use after which the session ends.
    pub idle_seconds: u64,
    /// The second, on the server's clock, at which the session ends even
    /// when it is used.
    pub expires: u64,
}

impl Session {
    /// Reads the record.
    ///
    /// # Errors
    /// As [`read_record`], or a missing or invalid field.
    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let map = read_record(bytes, MAX_JSON)?;
        // 32 bytes are 43 characters; the length is checked first.
        let text = text(&map, "token")?;
        let token = (text.len() == 43)
            .then(|| base64::decode_secret(Form::Url, text).ok())
            .flatten()
            .filter(|t| t.len() == 32)
            .ok_or(Error::Invalid("token"))?;
        Ok(Self {
            token,
            idle_seconds: number(&map, "idle_seconds")?,
            expires: number(&map, "expires")?,
        })
    }

    /// The record's bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        let token = base64::encode_secret(Form::Url, self.token.expose());
        write(&app_model::json!({
            "token": token.expose(),
            "idle_seconds": self.idle_seconds,
            "expires": self.expires
        }))
    }
}

/// The code of an error body, `{"error":"<code>"}` (SYN-01.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// 400.
    BadRequest,
    /// 401.
    Unauthorized,
    /// 403.
    Forbidden,
    /// 404.
    NotFound,
    /// 405.
    MethodNotAllowed,
    /// 409.
    Conflict,
    /// 411.
    LengthRequired,
    /// 412.
    PreconditionFailed,
    /// 413.
    TooLarge,
    /// 428.
    PreconditionRequired,
    /// 429.
    RateLimited,
    /// 5xx.
    ServerError,
}

impl ErrorCode {
    /// Every code, in the card's order.
    pub const ALL: [ErrorCode; 12] = [
        ErrorCode::BadRequest,
        ErrorCode::Unauthorized,
        ErrorCode::Forbidden,
        ErrorCode::NotFound,
        ErrorCode::MethodNotAllowed,
        ErrorCode::Conflict,
        ErrorCode::LengthRequired,
        ErrorCode::PreconditionFailed,
        ErrorCode::TooLarge,
        ErrorCode::PreconditionRequired,
        ErrorCode::RateLimited,
        ErrorCode::ServerError,
    ];

    /// The code as the body writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::NotFound => "not_found",
            ErrorCode::MethodNotAllowed => "method_not_allowed",
            ErrorCode::Conflict => "conflict",
            ErrorCode::LengthRequired => "length_required",
            ErrorCode::PreconditionFailed => "precondition_failed",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::PreconditionRequired => "precondition_required",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::ServerError => "server_error",
        }
    }

    /// The error body: `{"error":"<code>"}` and nothing else, so it never
    /// holds a token, a key, a request body or a path.
    #[must_use]
    pub fn body(self) -> Vec<u8> {
        json::to_string(&app_model::json!({"error": self.as_str()})).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested(levels: usize) -> String {
        // The top object is level 1; each "a" adds one.
        let mut s = String::from("{\"device_id\":\"x\"");
        for _ in 1..levels {
            s.push_str(",\"a\":{\"b\":1");
        }
        for _ in 1..levels {
            s.push('}');
        }
        s.push('}');
        s
    }

    #[test]
    fn syn01_8_records_refused_and_taken() {
        let ok = |b: &[u8]| read_record(b, MAX_JSON).map(|m| m.len());
        assert_eq!(ok(br#"{"device_id":"x"}"#), Ok(1));
        // An extra field is kept in the map and ignored by the readers.
        assert_eq!(ok(br#"{"device_id":"x","x":1}"#), Ok(2));
        assert!(ok(nested(8).as_bytes()).is_ok());
        assert_eq!(ok(nested(9).as_bytes()), Err(Error::TooDeep));
        assert_eq!(
            ok(br#"{"device_id":"x","device_id":"y"}"#),
            Err(Error::NotJson)
        );
        assert_eq!(ok(br#"[{"device_id":"x"}]"#), Err(Error::NotObject));
        assert_eq!(ok(b"\"x\""), Err(Error::NotObject));
        assert_eq!(ok(b"{} {}"), Err(Error::NotJson));
        assert_eq!(ok(b"{\"a\":\"\xff\"}"), Err(Error::NotJson));
        // Arrays count as levels too.
        assert_eq!(ok(br#"{"a":[[[[[[[[1]]]]]]]]}"#), Err(Error::TooDeep));
        assert!(ok(br#"{"a":[[[[[[[1]]]]]]]}"#).is_ok());
        // An empty object or array is one level too.
        assert!(ok(br#"{"a":{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}}"#).is_ok());
        assert!(ok(br#"{"a":[[[[[[[]]]]]]]}"#).is_ok());
        assert_eq!(ok(br#"{"a":[[[[[[[[]]]]]]]]}"#), Err(Error::TooDeep));
        // The deepest item or field counts, wherever it stands.
        assert_eq!(ok(br#"{"a":[1,[[[[[[[1]]]]]]]]}"#), Err(Error::TooDeep));
        assert_eq!(ok(br#"{"a":1,"b":[[[[[[[[1]]]]]]]]}"#), Err(Error::TooDeep));
    }

    #[test]
    fn syn01_10_record_over_limit_refused_before_parse() {
        // One byte over: refused even though it is not JSON at all, so
        // nothing was parsed.
        let mut big = vec![b' '; MAX_JSON];
        big[0] = b'{';
        big[MAX_JSON - 1] = b'}';
        assert!(read_record(&big, MAX_JSON).is_ok());
        big.push(b' ');
        assert_eq!(read_record(&big, MAX_JSON), Err(Error::TooLarge));
        assert_eq!(read_record(b"not json", 7), Err(Error::TooLarge));
    }

    #[test]
    fn syn01_14_health_round_trip_and_check() {
        let h = Health::this_server();
        assert_eq!(h.to_json(), br#"{"api":1,"service":"sync"}"#);
        assert_eq!(Health::read(&h.to_json()), Ok(h.clone()));
        assert!(h.is_app_server());
        let read = |b: &[u8]| Health::read(b);
        assert_eq!(read(br#"{"service":"sync","api":1,"later":true}"#), Ok(h));
        assert!(
            !read(br#"{"service":"sync","api":2}"#)
                .unwrap()
                .is_app_server()
        );
        assert!(
            !read(br#"{"service":"other","api":1}"#)
                .unwrap()
                .is_app_server()
        );
        assert_eq!(read(br#"{"api":1}"#), Err(Error::Missing("service")));
        assert_eq!(
            read(br#"{"service":1,"api":1}"#),
            Err(Error::Invalid("service"))
        );
        for api in ["1.0", "-1", "1e0", "9007199254740992", "\"1\""] {
            let body = format!(r#"{{"service":"sync","api":{api}}}"#);
            assert_eq!(read(body.as_bytes()), Err(Error::Invalid("api")), "{api}");
        }
        let top = r#"{"service":"sync","api":9007199254740991}"#;
        assert!(read(top.as_bytes()).is_ok());
    }

    #[test]
    fn syn01_6_vault_id_is_32_lowercase_hex_digits() {
        let text = "0123456789abcdef0011223344556677";
        let id = VaultId::parse(text).unwrap();
        assert_eq!(id.as_bytes()[0], 0x01);
        assert_eq!(id.as_bytes()[15], 0x77);
        assert_eq!(id.to_string(), text);
        assert_eq!(VaultId::from_bytes(*id.as_bytes()), id);
        assert_eq!(VaultId::from_bytes([0; 16]).to_string(), "0".repeat(32));
        for bad in [
            "0123456789ABCDEF0011223344556677",
            "0123456789abcdef001122334455667",
            "0123456789abcdef00112233445566778",
            "+123456789abcdef0011223344556677",
            "0123456789abcdef001122334455667g",
            "0123456789abcdef00112233445566 7",
            "",
        ] {
            assert_eq!(VaultId::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn syn01_6_vault_records_hold_id_version_and_size_only() {
        let id = VaultId::parse("0123456789abcdef0011223344556677").unwrap();
        let v = VaultVersion {
            id,
            version: 3,
            size: 1_140_850_688,
        };
        assert_eq!(
            v.to_json(),
            br#"{"id":"0123456789abcdef0011223344556677","size":1140850688,"version":3}"#
        );
        let other = VaultVersion {
            id: VaultId::from_bytes([0xff; 16]),
            version: 1,
            size: 0,
        };
        let list = vault_list(&[v, other]);
        let want = format!(
            r#"{{"vaults":[{},{}]}}"#,
            String::from_utf8(v.to_json()).unwrap(),
            String::from_utf8(other.to_json()).unwrap()
        );
        assert_eq!(list, want.as_bytes());
        assert_eq!(vault_list(&[]), br#"{"vaults":[]}"#);
        // The reply is a record the client's reader takes.
        assert!(read_record(&list, MAX_JSON).is_ok());
    }

    #[test]
    fn syn01_9_error_bodies_hold_only_the_code() {
        let codes: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            codes,
            [
                "bad_request",
                "unauthorized",
                "forbidden",
                "not_found",
                "method_not_allowed",
                "conflict",
                "length_required",
                "precondition_failed",
                "too_large",
                "precondition_required",
                "rate_limited",
                "server_error"
            ]
        );
        for code in ErrorCode::ALL {
            let want = format!(r#"{{"error":"{}"}}"#, code.as_str());
            assert_eq!(code.body(), want.as_bytes());
        }
    }

    const KEY: [u8; 65] = [4; 65];

    fn account(name: &str) -> Vec<u8> {
        format!(
            r#"{{"device_public_key":"{}","device_name":"{name}"}}"#,
            b64(&KEY)
        )
        .into_bytes()
    }

    /// SYN-04 T02: a device name of 1 to 64 Unicode scalar values, none in
    /// the category Cc; scalar values count, not bytes.
    #[test]
    fn syn04_2_t02_device_names() {
        let read = |name: &str| AccountCreate::read(&account(name));
        let ok = read("Mac").unwrap();
        assert_eq!(
            (ok.device_public_key, ok.device_name.as_str()),
            (KEY, "Mac")
        );
        let refused = Err(Error::Invalid("device_name"));
        assert_eq!(read(""), refused);
        assert_eq!(read(&"a".repeat(65)), refused);
        assert_eq!(read("Ma\\u0007c"), refused);
        assert_eq!(read("Ma\\nc"), refused);
        assert_eq!(read("Ma\\u0085c"), refused, "U+0085 is Cc too");
        assert_eq!(
            read(&"\u{e4}".repeat(65)),
            refused,
            "65 scalar values, 130 bytes"
        );
        assert!(read(&"a".repeat(64)).is_ok());
        assert!(
            read(&"\u{e4}".repeat(64)).is_ok(),
            "64 scalar values, 128 bytes"
        );
        assert!(
            read("Mac \u{1f600}").is_ok(),
            "an emoji is one scalar value, category So"
        );
        assert!(device_name_ok("Mac\u{a0}"), "U+00A0 is Zs, not Cc");
        assert!(!device_name_ok("Mac\u{7f}"));
        // The record writes back to the same record.
        assert_eq!(AccountCreate::read(&ok.to_json()), Ok(ok));
    }

    /// SYN-01.8 for byte strings: base64url without padding, the exact
    /// length, no unused low bit set, nothing outside the alphabet.
    #[test]
    fn syn01_8_byte_strings_refused_and_taken() {
        let key = |text: &str| {
            let body = format!(r#"{{"device_public_key":"{text}","device_name":"Mac"}}"#);
            AccountCreate::read(body.as_bytes()).map(|r| r.device_public_key)
        };
        let good = b64(&KEY);
        assert_eq!(good.len(), 87);
        assert_eq!(key(&good), Ok(KEY));
        let refused = Err(Error::Invalid("device_public_key"));
        assert_eq!(key(&format!("{good}=")), refused, "padding");
        assert_eq!(key(&b64(&[4; 64])), refused, "64 bytes");
        assert_eq!(key(&b64(&[4; 66])), refused, "66 bytes");
        assert_eq!(key(&format!("{good}A")), refused);
        // The last character carries 2 unused bits: they must be zero.
        let mut bits = good.clone().into_bytes();
        let last = bits.len() - 1;
        assert_eq!(bits[last], b'Q');
        bits[last] = b'R';
        assert_eq!(key(std::str::from_utf8(&bits).unwrap()), refused);
        // The standard alphabet's + and / are not base64url.
        let plus = b64(&[0xfb; 65]).replace('-', "+");
        assert!(plus.contains('+'));
        assert_eq!(key(&plus), refused);
        assert_eq!(key(&b64(&[0xfb; 65])), Ok([0xfb; 65]));
        // Text far over the longest encoding is refused before it is decoded.
        assert_eq!(key(&"A".repeat(100_000)), refused);
        let body = br#"{"device_public_key":1,"device_name":"Mac"}"#;
        assert_eq!(
            AccountCreate::read(body),
            Err(Error::Invalid("device_public_key"))
        );
        assert_eq!(
            AccountCreate::read(br#"{"device_name":"Mac"}"#),
            Err(Error::Missing("device_public_key"))
        );
    }

    /// SYN-01 T13 on the challenge request: an extra field is ignored; a
    /// duplicate key, an id of 31 digits or with an upper-case digit, an
    /// array, 9 levels and a body over 1 MiB are refused.
    #[test]
    fn syn01_8_t13_challenge_request_records() {
        let id = "0123456789abcdef0123456789abcdef";
        let read = |b: &[u8]| ChallengeRequest::read(b).map(|r| r.device_id.to_string());
        assert_eq!(
            read(format!(r#"{{"device_id":"{id}"}}"#).as_bytes()),
            Ok(id.to_owned())
        );
        assert!(read(format!(r#"{{"device_id":"{id}","x":1}}"#).as_bytes()).is_ok());
        // The top object is level 1; each `{"a":` below "x" adds one.
        let deep = format!(
            r#"{{"device_id":"{id}","x":{}1{}}}"#,
            r#"{"a":"#.repeat(7),
            "}".repeat(7)
        );
        assert!(read(deep.as_bytes()).is_ok(), "8 levels");
        let too_deep = format!(
            r#"{{"device_id":"{id}","x":{}1{}}}"#,
            r#"{"a":"#.repeat(8),
            "}".repeat(8)
        );
        assert_eq!(read(too_deep.as_bytes()), Err(Error::TooDeep));
        let twice = format!(r#"{{"device_id":"{id}","device_id":"{id}"}}"#);
        assert_eq!(read(twice.as_bytes()), Err(Error::NotJson));
        let short = format!(r#"{{"device_id":"{}"}}"#, &id[1..]);
        assert_eq!(read(short.as_bytes()), Err(Error::Invalid("device_id")));
        let upper = format!(r#"{{"device_id":"{}"}}"#, id.to_uppercase());
        assert_eq!(read(upper.as_bytes()), Err(Error::Invalid("device_id")));
        assert_eq!(
            read(format!(r#"[{{"device_id":"{id}"}}]"#).as_bytes()),
            Err(Error::NotObject)
        );
        let mut big = format!(r#"{{"device_id":"{id}"}}"#).into_bytes();
        big.resize(MAX_JSON + 1, b' ');
        assert_eq!(read(&big), Err(Error::TooLarge));
        big.truncate(MAX_JSON);
        assert!(read(&big).is_ok(), "exactly 1 MiB");
    }

    /// The other SYN-04 records write back to the same record, and refuse
    /// a nonce, signature or token of the wrong length.
    #[test]
    fn syn04_records_round_trip_and_lengths() {
        let created = AccountCreated {
            account_id: Id::from_bytes([1; 16]),
            device_id: Id::from_bytes([2; 16]),
        };
        assert_eq!(AccountCreated::read(&created.to_json()), Ok(created));
        let challenge = Challenge {
            nonce: [9; 32],
            expires: 1_800_000_300,
        };
        assert_eq!(Challenge::read(&challenge.to_json()), Ok(challenge));
        let sign_in = SignIn {
            device_id: Id::from_bytes([2; 16]),
            nonce: [9; 32],
            signature: vec![0x30; 72],
        };
        assert_eq!(SignIn::read(&sign_in.to_json()), Ok(sign_in.clone()));
        let with = |sig: &[u8], nonce: &[u8]| {
            let body = format!(
                r#"{{"device_id":"{}","nonce":"{}","signature":"{}"}}"#,
                "02".repeat(16),
                b64(nonce),
                b64(sig)
            );
            SignIn::read(body.as_bytes()).map(|_| ())
        };
        assert_eq!(
            with(&[0x30; 73], &[9; 32]),
            Err(Error::Invalid("signature"))
        );
        assert_eq!(with(&[], &[9; 32]), Err(Error::Invalid("signature")));
        assert_eq!(with(&[0x30; 8], &[9; 31]), Err(Error::Invalid("nonce")));
        assert!(with(&[0x30; 8], &[9; 32]).is_ok());

        let session = Session {
            token: SecretBytes::new(vec![0xab; 32]),
            idle_seconds: 900,
            expires: 1_800_028_800,
        };
        let bytes = session.to_json();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            text.contains(&format!(r#""token":"{}""#, b64(&[0xab; 32]))),
            "{text}"
        );
        let back = Session::read(&bytes).unwrap();
        assert_eq!(back.token.expose(), &[0xab; 32]);
        assert_eq!((back.idle_seconds, back.expires), (900, 1_800_028_800));
        assert_eq!(
            format!("{back:?}").matches("[hidden]").count(),
            1,
            "{back:?}"
        );
        let token = |t: &str| {
            let body = format!(r#"{{"token":"{t}","idle_seconds":900,"expires":1}}"#);
            Session::read(body.as_bytes()).map(|_| ())
        };
        assert_eq!(token(&b64(&[1; 31])), Err(Error::Invalid("token")));
        assert_eq!(
            token(&format!("{}=", b64(&[1; 32]))),
            Err(Error::Invalid("token"))
        );
        assert!(token(&b64(&[1; 32])).is_ok());
    }

    /// SYN-01.13, F-247: the `Debug` text of a challenge and of a sign-in
    /// record holds no nonce and no signature, so a log line, an assert or
    /// a panic message never writes the pair that signs a device in.
    #[test]
    fn syn01_13_challenge_and_sign_in_debug_hide_nonce_and_signature() {
        let challenge = Challenge {
            nonce: [0xab; 32],
            expires: 1_800_000_300,
        };
        let sign_in = SignIn {
            device_id: Id::from_bytes([1; 16]),
            nonce: [0xab; 32],
            signature: vec![0xcd; 70],
        };
        for (text, kept) in [
            (format!("{challenge:?}"), "1800000300"),
            (format!("{sign_in:?}"), "[1, 1, 1"),
        ] {
            assert!(!text.contains("171") && !text.contains("205"), "{text}");
            assert!(text.contains("[hidden]") && text.contains(kept), "{text}");
        }
        assert_eq!(format!("{sign_in:?}").matches("[hidden]").count(), 2);
    }

    /// SYN-01.6, SYN-01.10 (the client's reads): a PUT reply and the vault
    /// list round-trip; a list of exactly 1 MiB of the largest items reads in
    /// full, one byte more is refused before it is parsed; an item that is
    /// not a vault record is refused.
    #[test]
    fn syn01_6_client_reads_vault_records() {
        let one = VaultVersion {
            id: Id::from_bytes([0xab; 16]),
            version: 9_007_199_254_740_991,
            size: 9_007_199_254_740_990,
        };
        assert_eq!(VaultVersion::read(&one.to_json()), Ok(one));
        let item = String::from_utf8(one.to_json()).unwrap();
        assert!(item.len() <= 93, "{}", item.len());
        let head = r#"{"vaults":["#;
        let n = (MAX_JSON - head.len() - 2) / (item.len() + 1);
        let mut list = String::from(head);
        list.push_str(&vec![item.as_str(); n].join(","));
        list.push_str("]}");
        list.push_str(&" ".repeat(MAX_JSON - list.len()));
        assert_eq!(list.len(), MAX_JSON);
        assert_eq!(read_vault_list(list.as_bytes()).unwrap().len(), n);
        list.push(' ');
        assert_eq!(read_vault_list(list.as_bytes()), Err(Error::TooLarge));
        assert_eq!(
            read_vault_list(&vault_list(&[one, one])).unwrap(),
            [one, one]
        );
        for bad in [r#"{"vaults":[1]}"#, r#"{"vaults":{}}"#, r#"{"vault":[]}"#] {
            assert!(read_vault_list(bad.as_bytes()).is_err(), "{bad}");
        }
        let short = r#"{"id":"ab","version":1,"size":2}"#;
        assert_eq!(
            VaultVersion::read(short.as_bytes()),
            Err(Error::Invalid("id"))
        );
    }
}
