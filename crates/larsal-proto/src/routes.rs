//! Paths, methods, preconditions and the session header (SYN-01.3 to
//! SYN-01.6). E16-S3 serves the health route, E16-S4 the vault routes,
//! E16-S5 the account, sign-in, sign-out and revoke routes (SYN-04), E17-S1
//! the account keys, key-file part and recovery routes (SYN-06.6, SYN-06.9,
//! SYN-06.12), E17-S2 the approval routes (SYN-06.11, SYN-05); each later
//! story adds its routes to [`find`].
//!
//! The ETag rules of SYN-01.6 (RFC 9110 sections 8.8.3, 13.1.1, 13.1.2): an
//! ETag is always strong, `"` + the version in decimal + `"`, and is
//! compared with the strong compare only, so `W/"3"` never matches. A PUT
//! needs exactly one precondition: [`put_precondition`]. A GET answers 304
//! when its `If-None-Match` names the current version: [`not_modified`].

use crate::messages::{DeviceId, Id, VaultId};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::secret::SecretBytes;

/// The health route's path (SYN-01.14).
pub const HEALTH: &str = "/v1/health";
/// The vault list's path (SYN-01.6).
pub const VAULTS: &str = "/v1/vaults";
/// A new account (SYN-04.2).
pub const ACCOUNTS: &str = "/v1/accounts";
/// A sign-in challenge (SYN-04.3).
pub const CHALLENGE: &str = "/v1/signin/challenge";
/// A sign-in (SYN-04.4).
pub const SIGNIN: &str = "/v1/signin";
/// A sign-out (SYN-04.7).
pub const SIGNOUT: &str = "/v1/signout";
/// The account's keys (SYN-06.6).
pub const ACCOUNT_KEYS: &str = "/v1/account/keys";
/// A recovery sign-in challenge (SYN-06.12).
pub const RECOVERY_CHALLENGE: &str = "/v1/recovery/challenge";
/// A recovery sign-in (SYN-06.12).
pub const RECOVERY_SIGNIN: &str = "/v1/recovery/signin";
/// The last segment of a vault's key-file part path (SYN-06.9).
pub const KEYPART: &str = "/keypart";
/// A new approval request (SYN-06.11 step 1); its routes are under it.
pub const APPROVALS: &str = "/v1/approvals";
/// The claim of an approval code (SYN-06.11 step 2).
pub const APPROVAL_CLAIM: &str = "/v1/approvals/claim";

/// A route the server serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `GET /v1/health`, no session: 200 with the health record.
    Health,
    /// `GET /v1/vaults`: the vault list.
    Vaults,
    /// `GET /v1/vaults/{vault_id}`: the vault's bytes.
    VaultGet(VaultId),
    /// `PUT /v1/vaults/{vault_id}`: a new version of the vault.
    VaultPut(VaultId),
    /// `POST /v1/accounts`, no session: a new account and its first device.
    Accounts,
    /// `POST /v1/signin/challenge`, no session: a one-time nonce.
    Challenge,
    /// `POST /v1/signin`, no session: a signed nonce for a session.
    SignIn,
    /// `POST /v1/signout`: ends this session.
    SignOut,
    /// `DELETE /v1/devices/{device_id}`: revokes a device of this account.
    DeviceDelete(DeviceId),
    /// `PUT /v1/account/keys`: the account's keys, once.
    KeysPut,
    /// `GET /v1/account/keys`: the account's keys.
    KeysGet,
    /// `PUT /v1/vaults/{vault_id}/keypart`: the vault's key-file part wrap.
    KeyPartPut(VaultId),
    /// `GET /v1/vaults/{vault_id}/keypart`: the vault's key-file part wrap.
    KeyPartGet(VaultId),
    /// `POST /v1/recovery/challenge`, no session: a one-time nonce.
    RecoveryChallenge,
    /// `POST /v1/recovery/signin`, no session: a new device by the
    /// recovery key.
    RecoverySignIn,
    /// `POST /v1/approvals`: a new approval request (SYN-06.11 step 1).
    Approvals,
    /// `POST /v1/approvals/claim`, approval code: N claims the request.
    ApprovalClaim,
    /// `GET /v1/approvals/{approval_id}`, a session or the approval code.
    ApprovalGet(Id),
    /// `POST /v1/approvals/{approval_id}/commit`, approval code: SYN-05's
    /// message (1).
    ApprovalCommit(Id),
    /// `POST /v1/approvals/{approval_id}/keys`: SYN-05's message (2).
    ApprovalKeys(Id),
    /// `POST /v1/approvals/{approval_id}/reveal`, approval code: SYN-05's
    /// message (3).
    ApprovalReveal(Id),
    /// `POST /v1/approvals/{approval_id}/seal`: the sealed `S_acct` and the
    /// device signature (SYN-06.11 step 5).
    ApprovalSeal(Id),
    /// `DELETE /v1/approvals/{approval_id}`, a session or the approval
    /// code: the request ends.
    ApprovalDelete(Id),
}

impl Route {
    /// The route's name in the request log (SYN-01.13): never the path,
    /// so no id from a request reaches the log.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Route::Health => "health",
            Route::Vaults => "vaults",
            Route::VaultGet(_) => "vault_get",
            Route::VaultPut(_) => "vault_put",
            Route::Accounts => "accounts",
            Route::Challenge => "challenge",
            Route::SignIn => "signin",
            Route::SignOut => "signout",
            Route::DeviceDelete(_) => "device_delete",
            Route::KeysPut => "keys_put",
            Route::KeysGet => "keys_get",
            Route::KeyPartPut(_) => "keypart_put",
            Route::KeyPartGet(_) => "keypart_get",
            Route::RecoveryChallenge => "recovery_challenge",
            Route::RecoverySignIn => "recovery_signin",
            Route::Approvals => "approvals",
            Route::ApprovalClaim => "approval_claim",
            Route::ApprovalGet(_) => "approval_get",
            Route::ApprovalCommit(_) => "approval_commit",
            Route::ApprovalKeys(_) => "approval_keys",
            Route::ApprovalReveal(_) => "approval_reveal",
            Route::ApprovalSeal(_) => "approval_seal",
            Route::ApprovalDelete(_) => "approval_delete",
        }
    }

    /// True when the route needs `Authorization: Bearer` (SYN-01.4). The
    /// approval routes that take the approval code (`Authorization:
    /// Approval`), alone or in place of a session, check it themselves.
    #[must_use]
    pub fn needs_session(&self) -> bool {
        !matches!(
            self,
            Route::Health
                | Route::Accounts
                | Route::Challenge
                | Route::SignIn
                | Route::RecoveryChallenge
                | Route::RecoverySignIn
                | Route::ApprovalClaim
                | Route::ApprovalGet(_)
                | Route::ApprovalCommit(_)
                | Route::ApprovalReveal(_)
                | Route::ApprovalDelete(_)
        )
    }

    /// True for the sign-in routes, which have their own rate limit
    /// (SYN-01.12).
    #[must_use]
    pub fn is_signin(&self) -> bool {
        matches!(
            self,
            Route::Accounts
                | Route::Challenge
                | Route::SignIn
                | Route::RecoveryChallenge
                | Route::RecoverySignIn
                | Route::ApprovalClaim
        )
    }
}

/// What a method and a path name (SYN-01.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// A route.
    Route(Route),
    /// No route has this path: 404.
    NotFound,
    /// The path is known, the method is not: 405 with this `Allow` value.
    MethodNotAllowed(&'static str),
}

/// The route for `method` and `path` (the path without its query). Methods
/// are compared exactly, as RFC 9110 section 9.1 says (case-sensitive). A
/// vault path whose id is not 32 lowercase hex digits names no route: 404.
#[must_use]
pub fn find(method: &str, path: &str) -> Match {
    match path {
        HEALTH if method == "GET" => Match::Route(Route::Health),
        HEALTH => Match::MethodNotAllowed("GET"),
        VAULTS if method == "GET" => Match::Route(Route::Vaults),
        VAULTS => Match::MethodNotAllowed("GET"),
        ACCOUNTS => post(method, Route::Accounts),
        CHALLENGE => post(method, Route::Challenge),
        SIGNIN => post(method, Route::SignIn),
        SIGNOUT => post(method, Route::SignOut),
        RECOVERY_CHALLENGE => post(method, Route::RecoveryChallenge),
        RECOVERY_SIGNIN => post(method, Route::RecoverySignIn),
        APPROVALS => post(method, Route::Approvals),
        APPROVAL_CLAIM => post(method, Route::ApprovalClaim),
        ACCOUNT_KEYS => match method {
            "GET" => Match::Route(Route::KeysGet),
            "PUT" => Match::Route(Route::KeysPut),
            _ => Match::MethodNotAllowed("GET, PUT"),
        },
        _ => {
            if let Some(rest) = path.strip_prefix("/v1/approvals/") {
                return approval(method, rest);
            }
            if let Some(id) = path.strip_prefix("/v1/devices/") {
                return match VaultId::parse(id) {
                    Some(id) if method == "DELETE" => Match::Route(Route::DeviceDelete(id)),
                    Some(_) => Match::MethodNotAllowed("DELETE"),
                    None => Match::NotFound,
                };
            }
            let vault = path.strip_prefix("/v1/vaults/");
            if let Some(id) = vault.and_then(|v| v.strip_suffix(KEYPART)) {
                return match VaultId::parse(id) {
                    Some(id) if method == "GET" => Match::Route(Route::KeyPartGet(id)),
                    Some(id) if method == "PUT" => Match::Route(Route::KeyPartPut(id)),
                    Some(_) => Match::MethodNotAllowed("GET, PUT"),
                    None => Match::NotFound,
                };
            }
            match vault.and_then(VaultId::parse) {
                Some(id) if method == "GET" => Match::Route(Route::VaultGet(id)),
                Some(id) if method == "PUT" => Match::Route(Route::VaultPut(id)),
                Some(_) => Match::MethodNotAllowed("GET, PUT"),
                None => Match::NotFound,
            }
        }
    }
}

/// The routes under `/v1/approvals/{approval_id}`: `rest` is the path
/// after `/v1/approvals/`. An id that is not 32 lowercase hex digits names
/// no route.
fn approval(method: &str, rest: &str) -> Match {
    let (id, tail) = rest
        .split_once('/')
        .map_or((rest, None), |(a, b)| (a, Some(b)));
    let Some(id) = Id::parse(id) else {
        return Match::NotFound;
    };
    match tail {
        None => match method {
            "GET" => Match::Route(Route::ApprovalGet(id)),
            "DELETE" => Match::Route(Route::ApprovalDelete(id)),
            _ => Match::MethodNotAllowed("GET, DELETE"),
        },
        Some("commit") => post(method, Route::ApprovalCommit(id)),
        Some("keys") => post(method, Route::ApprovalKeys(id)),
        Some("reveal") => post(method, Route::ApprovalReveal(id)),
        Some("seal") => post(method, Route::ApprovalSeal(id)),
        Some(_) => Match::NotFound,
    }
}

fn post(method: &str, route: Route) -> Match {
    if method == "POST" {
        Match::Route(route)
    } else {
        Match::MethodNotAllowed("POST")
    }
}

/// The session token of the `Authorization` field lines (SYN-01.5; RFC
/// 6750 section 2.1): exactly one line, the scheme `Bearer` in any case
/// (RFC 9110 section 11.1), one or more spaces, then 43 base64url
/// characters that decode to 32 bytes with the unused low bits zero.
/// Anything else, a second line included, is `None`: 401 with one body for
/// every reason. Untrusted bytes; never panics.
#[must_use]
pub fn bearer(lines: &[&[u8]]) -> Option<SecretBytes> {
    let [line] = lines else {
        return None;
    };
    let line = trim(line);
    let (scheme, rest) = line.split_at_checked(6)?;
    if !scheme.eq_ignore_ascii_case(b"bearer") || rest.first() != Some(&b' ') {
        return None;
    }
    let token = skip(rest, |c| c == b' ');
    let url = |c: &u8| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_';
    if token.len() != 43 || !token.iter().all(url) {
        return None;
    }
    base64::decode_secret(Form::Url, token)
        .ok()
        .filter(|t| t.len() == 32)
}

/// The ETag of a version: `"` + the version in decimal + `"` (SYN-01.6).
#[must_use]
pub fn etag(version: u64) -> String {
    format!("\"{version}\"")
}

/// The version a reply's `ETag` names (the client's read, SYN-01.6): one
/// strong ETag of a version from 1 up, in the canonical form the server
/// writes; `None` for anything else (weak, a list, `"03"`, `"0"`).
#[must_use]
pub fn etag_version(value: &str) -> Option<u64> {
    let tag = value.trim_matches(|c| c == ' ' || c == '\t');
    let inner = tag.strip_prefix('"')?.strip_suffix('"')?;
    version(inner.as_bytes()).filter(|v| *v >= 1)
}

/// What a vault PUT asks for (SYN-01.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precondition {
    /// `If-None-Match: *`: a new vault; 412 when the id exists.
    Create,
    /// `If-Match` with one ETag: an update of that version. `None` when the
    /// ETag names no version the server ever gives (weak, or not a decimal
    /// number as the server writes one): always 412.
    Update(Option<u64>),
}

/// Why a PUT is refused before the store is asked (SYN-01.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreconditionError {
    /// 428: no precondition, `If-Match: *`, or an `If-None-Match` other
    /// than `*`. The server never takes a blind overwrite.
    Required,
    /// 400: both headers, a list of ETags, or a field that is not `*` or an
    /// entity tag (RFC 9110 section 8.8.3).
    Bad,
}

/// The precondition of a vault PUT from every field line of `If-Match` and
/// of `If-None-Match` (none, one or more each; RFC 9110 section 5.3 reads
/// several lines as one list). Untrusted bytes; never panics.
///
/// # Errors
/// [`PreconditionError::Required`] (428) or [`PreconditionError::Bad`] (400).
pub fn put_precondition(
    if_match: &[&[u8]],
    if_none_match: &[&[u8]],
) -> Result<Precondition, PreconditionError> {
    match (if_match.is_empty(), if_none_match.is_empty()) {
        (true, true) => Err(PreconditionError::Required),
        (false, false) => Err(PreconditionError::Bad),
        (false, true) => match single(if_match)? {
            Tag::Any => Err(PreconditionError::Required),
            Tag::Weak => Ok(Precondition::Update(None)),
            Tag::Strong(tag) => Ok(Precondition::Update(version(tag))),
        },
        (true, false) => match single(if_none_match)? {
            Tag::Any => Ok(Precondition::Create),
            Tag::Weak | Tag::Strong(_) => Err(PreconditionError::Required),
        },
    }
}

/// True when a GET's `If-None-Match` lines name `version`: `*`, or a strong
/// ETag equal to the version's. A weak ETag, another version or a field
/// that cannot be read never matches, so the bytes are sent (SYN-01.6).
#[must_use]
pub fn not_modified(if_none_match: &[&[u8]], version: u64) -> bool {
    let want = version.to_string();
    let mut hit = false;
    let read = tags(if_none_match, |tag| {
        hit |= match tag {
            Tag::Any => true,
            Tag::Strong(tag) => tag == want.as_bytes(),
            Tag::Weak => false,
        };
    });
    read && hit
}

/// One member of an `If-Match` or `If-None-Match` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag<'a> {
    /// `*`.
    Any,
    /// `"…"`: the bytes between the quotes.
    Strong(&'a [u8]),
    /// `W/"…"`: never matches here.
    Weak,
}

/// The one member of the lines; more than one, none, or a field that
/// cannot be read is [`PreconditionError::Bad`].
fn single<'a>(lines: &[&'a [u8]]) -> Result<Tag<'a>, PreconditionError> {
    let (mut count, mut first) = (0usize, None);
    let read = tags(lines, |tag| {
        count = count.saturating_add(1);
        first = first.or(Some(tag));
    });
    match first {
        Some(tag) if read && count == 1 => Ok(tag),
        _ => Err(PreconditionError::Bad),
    }
}

/// Calls `each` for every member over all the lines; false when a line is
/// neither `*` nor a list of entity tags (RFC 9110 sections 5.6.1, 8.8.3:
/// `entity-tag = [ "W/" ] DQUOTE *etagc DQUOTE`; empty list members and
/// spaces around the commas are skipped). Allocates nothing.
fn tags<'a>(lines: &[&'a [u8]], mut each: impl FnMut(Tag<'a>)) -> bool {
    lines.iter().all(|line| {
        let mut rest = trim(line);
        if rest == b"*" {
            each(Tag::Any);
            return true;
        }
        loop {
            rest = skip(rest, |c| c == b',' || ows(c));
            if rest.is_empty() {
                return true;
            }
            let (weak, quoted) = match rest.strip_prefix(b"W/") {
                Some(after) => (true, after),
                None => (false, rest),
            };
            let Some(body) = quoted.strip_prefix(b"\"") else {
                return false;
            };
            let Some(end) = body.iter().position(|c| *c == b'"') else {
                return false;
            };
            let (tag, after) = body.split_at(end);
            if !tag.iter().all(|c| etagc(*c)) {
                return false;
            }
            each(if weak { Tag::Weak } else { Tag::Strong(tag) });
            rest = skip(after.strip_prefix(b"\"").unwrap_or(after), ows);
            if !(rest.is_empty() || rest.starts_with(b",")) {
                return false;
            }
        }
    })
}

/// The version a strong ETag names: decimal digits as the server writes
/// them (no sign, no leading zero), or `None`. `"0"` reads as 0, which no
/// vault ever has.
fn version(tag: &[u8]) -> Option<u64> {
    let digits = !tag.is_empty() && tag.iter().all(u8::is_ascii_digit);
    if !digits || (tag.len() > 1 && tag.first() == Some(&b'0')) {
        return None;
    }
    std::str::from_utf8(tag).ok()?.parse().ok()
}

/// `etagc = %x21 / %x23-7E / obs-text` (RFC 9110 section 8.8.3).
fn etagc(c: u8) -> bool {
    c == 0x21 || (0x23..=0x7e).contains(&c) || c >= 0x80
}

/// Space or tab (RFC 9110 section 5.6.3).
fn ows(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn skip(bytes: &[u8], drop: impl Fn(u8) -> bool) -> &[u8] {
    let start = bytes.iter().position(|c| !drop(*c)).unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or_default()
}

fn trim(bytes: &[u8]) -> &[u8] {
    let bytes = skip(bytes, ows);
    let end = bytes
        .iter()
        .rposition(|c| !ows(*c))
        .map_or(0, |i| i.saturating_add(1));
    bytes.get(..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn syn01_3_known_path_other_method_unknown_path() {
        assert_eq!(find("GET", "/v1/health"), Match::Route(Route::Health));
        for method in ["POST", "PUT", "DELETE", "HEAD", "get"] {
            assert_eq!(find(method, "/v1/health"), Match::MethodNotAllowed("GET"));
        }
        for path in [
            "/v1/nothing",
            "/v1/health/",
            "/v1/Health",
            "/v2/health",
            "/",
            "",
        ] {
            assert_eq!(find("GET", path), Match::NotFound, "{path}");
        }
    }

    #[test]
    fn syn04_routes_and_their_methods() {
        for (path, route) in [
            ("/v1/accounts", Route::Accounts),
            ("/v1/signin/challenge", Route::Challenge),
            ("/v1/signin", Route::SignIn),
            ("/v1/signout", Route::SignOut),
        ] {
            assert_eq!(find("POST", path), Match::Route(route));
            for method in ["GET", "PUT", "DELETE", "post"] {
                assert_eq!(
                    find(method, path),
                    Match::MethodNotAllowed("POST"),
                    "{path}"
                );
            }
        }
        let id = DeviceId::parse(ID).unwrap();
        let path = format!("/v1/devices/{ID}");
        assert_eq!(find("DELETE", &path), Match::Route(Route::DeviceDelete(id)));
        for method in ["GET", "POST", "delete"] {
            assert_eq!(find(method, &path), Match::MethodNotAllowed("DELETE"));
        }
        for bad in [
            "/v1/devices/",
            "/v1/devices/0123456789ABCDEF0123456789ABCDEF",
            "/v1/devices/0123456789abcdef0123456789abcdef/",
            "/v1/signin/",
            "/v1/accounts/x",
        ] {
            assert_eq!(find("DELETE", bad), Match::NotFound, "{bad}");
            assert_eq!(find("POST", bad), Match::NotFound, "{bad}");
        }
    }

    /// SYN-01.4: which routes need a session, which count as sign-in
    /// routes for the rate limit, and the log names.
    #[test]
    fn syn01_4_sessions_signin_limit_and_log_names() {
        let id = VaultId::parse(ID).unwrap();
        let all = [
            (Route::Health, false, false, "health"),
            (Route::Accounts, false, true, "accounts"),
            (Route::Challenge, false, true, "challenge"),
            (Route::SignIn, false, true, "signin"),
            (Route::SignOut, true, false, "signout"),
            (Route::DeviceDelete(id), true, false, "device_delete"),
            (Route::Vaults, true, false, "vaults"),
            (Route::VaultGet(id), true, false, "vault_get"),
            (Route::VaultPut(id), true, false, "vault_put"),
            (Route::KeysPut, true, false, "keys_put"),
            (Route::KeysGet, true, false, "keys_get"),
            (Route::KeyPartPut(id), true, false, "keypart_put"),
            (Route::KeyPartGet(id), true, false, "keypart_get"),
            (Route::RecoveryChallenge, false, true, "recovery_challenge"),
            (Route::RecoverySignIn, false, true, "recovery_signin"),
            (Route::Approvals, true, false, "approvals"),
            (Route::ApprovalClaim, false, true, "approval_claim"),
            (Route::ApprovalGet(id), false, false, "approval_get"),
            (Route::ApprovalCommit(id), false, false, "approval_commit"),
            (Route::ApprovalKeys(id), true, false, "approval_keys"),
            (Route::ApprovalReveal(id), false, false, "approval_reveal"),
            (Route::ApprovalSeal(id), true, false, "approval_seal"),
            (Route::ApprovalDelete(id), false, false, "approval_delete"),
        ];
        for (route, session, signin, name) in all {
            assert_eq!(
                (route.needs_session(), route.is_signin(), route.name()),
                (session, signin, name),
                "{route:?}"
            );
            assert!(!route.name().contains(ID));
        }
    }

    /// SYN-01.5, SYN-01 T05: the one form of the session header; anything
    /// else is refused alike.
    #[test]
    fn syn01_5_bearer_token() {
        let token = [0xa5u8; 32];
        let text = base64::encode(Form::Url, &token);
        assert_eq!(text.len(), 43);
        let read = |line: &str| bearer(&[line.as_bytes()]).map(|t| t.expose().to_vec());
        assert_eq!(read(&format!("Bearer {text}")), Some(token.to_vec()));
        assert_eq!(read(&format!("bearer {text}")), Some(token.to_vec()));
        assert_eq!(read(&format!("BEARER   {text} ")), Some(token.to_vec()));
        for bad in [
            String::new(),
            "Bearer".to_owned(),
            "Bearer ".to_owned(),
            text.clone(),
            format!("Bearer{text}"),
            format!("Basic {text}"),
            format!("Bearer {}", &text[1..]),
            format!("Bearer {text}A"),
            format!("Bearer {text}="),
            format!("Bearer {}", text.replace('p', "+")),
            format!("Bearer {text} x"),
            format!("Bearer\t{text}"),
            format!("Bearer {}", base64::encode(Form::Url, &[1u8; 31])),
        ] {
            assert_eq!(read(&bad), None, "{bad:?}");
        }
        // Unused low bits set: the same 32 bytes in a second spelling.
        let mut odd = text.clone().into_bytes();
        odd[42] = odd[42].wrapping_add(1);
        assert_eq!(read(std::str::from_utf8(&odd).unwrap()), None);
        // No line, or two lines (even two equal ones): refused.
        let line = format!("Bearer {text}");
        assert!(bearer(&[]).is_none());
        assert!(bearer(&[line.as_bytes(), line.as_bytes()]).is_none());
        assert!(bearer(&[b"Bearer \xff\xfe"]).is_none());
    }

    #[test]
    fn syn01_6_vault_routes() {
        let id = VaultId::parse(ID).unwrap();
        assert_eq!(find("GET", "/v1/vaults"), Match::Route(Route::Vaults));
        for method in ["PUT", "POST", "DELETE", "get"] {
            assert_eq!(find(method, "/v1/vaults"), Match::MethodNotAllowed("GET"));
        }
        let path = format!("/v1/vaults/{ID}");
        assert_eq!(find("GET", &path), Match::Route(Route::VaultGet(id)));
        assert_eq!(find("PUT", &path), Match::Route(Route::VaultPut(id)));
        for method in ["DELETE", "POST", "HEAD", "put"] {
            assert_eq!(find(method, &path), Match::MethodNotAllowed("GET, PUT"));
        }
        // An id that is not 32 lowercase hex digits names no route.
        for bad in [
            "/v1/vaults/0123456789ABCDEF0123456789ABCDEF",
            "/v1/vaults/0123456789abcdef0123456789abcde",
            "/v1/vaults/0123456789abcdef0123456789abcdef0",
            "/v1/vaults/",
            "/v1/vaults//0123456789abcdef0123456789abcdef",
            "/v1/vaults/0123456789abcdef0123456789abcdef/",
            "/v1/vaults/0123456789abcdef0123456789abcdef/keypart/",
            "/v1/vaults/0123456789ABCDEF0123456789ABCDEF/keypart",
            "/v1/vaults/0123456789abcdef0123456789abcdef/keyparts",
            "/v1/vaults/keypart",
            "/v1/vaults/../health",
            "/v1/vaults/%30123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(find("GET", bad), Match::NotFound, "{bad}");
            assert_eq!(find("PUT", bad), Match::NotFound, "{bad}");
        }
    }

    /// SYN-01.4, SYN-06.6, SYN-06.9, SYN-06.12: E17-S1's routes and their
    /// methods; a key-file part path whose id is not 32 lowercase hex digits
    /// names no route.
    #[test]
    fn syn06_routes_and_their_methods() {
        let id = VaultId::parse(ID).unwrap();
        assert_eq!(
            find("GET", "/v1/account/keys"),
            Match::Route(Route::KeysGet)
        );
        assert_eq!(
            find("PUT", "/v1/account/keys"),
            Match::Route(Route::KeysPut)
        );
        for method in ["POST", "DELETE", "get", "put"] {
            assert_eq!(
                find(method, "/v1/account/keys"),
                Match::MethodNotAllowed("GET, PUT")
            );
        }
        let path = format!("/v1/vaults/{ID}/keypart");
        assert_eq!(find("GET", &path), Match::Route(Route::KeyPartGet(id)));
        assert_eq!(find("PUT", &path), Match::Route(Route::KeyPartPut(id)));
        for method in ["POST", "DELETE", "put"] {
            assert_eq!(find(method, &path), Match::MethodNotAllowed("GET, PUT"));
        }
        for (path, route) in [
            ("/v1/recovery/challenge", Route::RecoveryChallenge),
            ("/v1/recovery/signin", Route::RecoverySignIn),
        ] {
            assert_eq!(find("POST", path), Match::Route(route));
            for method in ["GET", "PUT", "post"] {
                assert_eq!(find(method, path), Match::MethodNotAllowed("POST"));
            }
        }
        for bad in [
            "/v1/account/keys/",
            "/v1/account",
            "/v1/recovery",
            "/v1/recovery/",
            "/v1/vaults/0123456789abcdef0123456789abcde/keypart",
        ] {
            assert_eq!(find("GET", bad), Match::NotFound, "{bad}");
            assert_eq!(find("PUT", bad), Match::NotFound, "{bad}");
        }
    }

    /// SYN-01.4 with ruling (2) of E17-S2: the approval routes and their
    /// methods; an id that is not 32 lowercase hex digits names no route.
    #[test]
    fn syn06_11_approval_routes_and_their_methods() {
        let id = Id::parse(ID).unwrap();
        assert_eq!(
            find("POST", "/v1/approvals"),
            Match::Route(Route::Approvals)
        );
        assert_eq!(
            find("POST", "/v1/approvals/claim"),
            Match::Route(Route::ApprovalClaim)
        );
        for path in ["/v1/approvals", "/v1/approvals/claim"] {
            for method in ["GET", "PUT", "DELETE", "post"] {
                assert_eq!(
                    find(method, path),
                    Match::MethodNotAllowed("POST"),
                    "{path}"
                );
            }
        }
        let path = format!("/v1/approvals/{ID}");
        assert_eq!(find("GET", &path), Match::Route(Route::ApprovalGet(id)));
        assert_eq!(
            find("DELETE", &path),
            Match::Route(Route::ApprovalDelete(id))
        );
        for method in ["POST", "PUT", "get"] {
            assert_eq!(find(method, &path), Match::MethodNotAllowed("GET, DELETE"));
        }
        for (tail, route) in [
            ("commit", Route::ApprovalCommit(id)),
            ("keys", Route::ApprovalKeys(id)),
            ("reveal", Route::ApprovalReveal(id)),
            ("seal", Route::ApprovalSeal(id)),
        ] {
            let p = format!("/v1/approvals/{ID}/{tail}");
            assert_eq!(find("POST", &p), Match::Route(route));
            for method in ["GET", "PUT", "DELETE"] {
                assert_eq!(find(method, &p), Match::MethodNotAllowed("POST"), "{p}");
            }
        }
        for bad in [
            "/v1/approvals/",
            "/v1/approvals/0123456789ABCDEF0123456789ABCDEF",
            "/v1/approvals/0123456789abcdef0123456789abcde",
            "/v1/approvals/0123456789abcdef0123456789abcdef/",
            "/v1/approvals/0123456789abcdef0123456789abcdef/claim",
            "/v1/approvals/0123456789abcdef0123456789abcdef/commit/",
            "/v1/approvals/claim/x",
        ] {
            assert_eq!(find("GET", bad), Match::NotFound, "{bad}");
            assert_eq!(find("POST", bad), Match::NotFound, "{bad}");
        }
    }

    #[test]
    fn syn01_6_etag_is_the_version_in_quotes() {
        assert_eq!(etag(1), "\"1\"");
        assert_eq!(etag(9_007_199_254_740_991), "\"9007199254740991\"");
    }

    fn put(m: &[&str], n: &[&str]) -> Result<Precondition, PreconditionError> {
        let m: Vec<&[u8]> = m.iter().map(|s| s.as_bytes()).collect();
        let n: Vec<&[u8]> = n.iter().map(|s| s.as_bytes()).collect();
        put_precondition(&m, &n)
    }

    /// T07: neither, `If-Match: *`, both, another version, a weak ETag,
    /// `If-None-Match: *` and the current version, as the store sees them.
    #[test]
    fn syn01_6_put_needs_exactly_one_precondition() {
        use Precondition::{Create, Update};
        use PreconditionError::{Bad, Required};
        assert_eq!(put(&[], &[]), Err(Required));
        assert_eq!(put(&["*"], &[]), Err(Required));
        assert_eq!(put(&[" * "], &[]), Err(Required));
        assert_eq!(put(&["\"3\""], &["*"]), Err(Bad));
        assert_eq!(put(&["*"], &["*"]), Err(Bad));
        assert_eq!(put(&["\"2\""], &[]), Ok(Update(Some(2))));
        assert_eq!(put(&["\"3\""], &[]), Ok(Update(Some(3))));
        assert_eq!(put(&[" \"3\" "], &[]), Ok(Update(Some(3))));
        assert_eq!(put(&[], &["*"]), Ok(Create));
        // The strong compare only: a weak ETag never matches.
        assert_eq!(put(&["W/\"3\""], &[]), Ok(Update(None)));
        // No such version: 0, a sign, a leading zero, not a number, too big.
        assert_eq!(put(&["\"0\""], &[]), Ok(Update(Some(0))));
        for none in [
            "\"-1\"",
            "\"+3\"",
            "\"03\"",
            "\"abc\"",
            "\"3.0\"",
            "\"\"",
            "\"18446744073709551616\"",
        ] {
            assert_eq!(put(&[none], &[]), Ok(Update(None)), "{none}");
        }
        assert_eq!(
            put(&["\"18446744073709551615\""], &[]),
            Ok(Update(Some(u64::MAX)))
        );
        // A list of ETags, in one line or in two: 400.
        assert_eq!(put(&["\"1\", \"2\""], &[]), Err(Bad));
        assert_eq!(put(&["\"1\"", "\"2\""], &[]), Err(Bad));
        assert_eq!(put(&["*", "\"2\""], &[]), Err(Bad));
        assert_eq!(put(&[], &["*", "*"]), Err(Bad));
        assert_eq!(put(&[], &["\"1\", \"2\""]), Err(Bad));
        // Not an entity tag: 400.
        for bad in [
            "3", "\"3", "w/\"3\"", "\"3\" x", "**", "\"a\"b\"", "", ",", "\"\x7f\"",
        ] {
            assert_eq!(put(&[bad], &[]), Err(Bad), "{bad:?}");
        }
        // Empty list members are skipped (RFC 9110 section 5.6.1).
        assert_eq!(put(&[", \"4\" ,"], &[]), Ok(Update(Some(4))));
        // A comma inside the quotes belongs to the one tag.
        assert_eq!(put(&["\"1,2\""], &[]), Ok(Update(None)));
        // If-None-Match with an ETag is not the precondition a PUT takes.
        assert_eq!(put(&[], &["\"3\""]), Err(Required));
        assert_eq!(put(&[], &["W/\"3\""]), Err(Required));
    }

    #[test]
    fn syn01_6_get_not_modified_by_the_strong_compare_only() {
        let nm = |lines: &[&str], v| {
            let lines: Vec<&[u8]> = lines.iter().map(|s| s.as_bytes()).collect();
            not_modified(&lines, v)
        };
        assert!(nm(&["\"1\""], 1));
        assert!(nm(&["*"], 7));
        assert!(nm(&["\"2\", \"3\""], 3));
        assert!(nm(&["\"2\"", "\"3\""], 3));
        // An older version, a weak ETag, another spelling: the bytes go out.
        assert!(!nm(&["\"1\""], 2));
        assert!(!nm(&["W/\"1\""], 1));
        assert!(!nm(&["\"01\""], 1));
        assert!(!nm(&[], 1));
        // A field that cannot be read never matches.
        assert!(!nm(&["1"], 1));
        assert!(!nm(&["\"1\" junk"], 1));
    }

    /// SYN-01.6 (the client's read): a reply's ETag names a version only
    /// in the strong, canonical form the server writes.
    #[test]
    fn syn01_6_client_reads_only_canonical_strong_etags() {
        assert_eq!(etag_version(&etag(7)), Some(7));
        assert_eq!(etag_version(" \"12\" "), Some(12));
        for bad in [
            "W/\"7\"",
            "\"07\"",
            "\"0\"",
            "7",
            "\"7\", \"8\"",
            "\"-1\"",
            "\"\"",
            "*",
        ] {
            assert_eq!(etag_version(bad), None, "{bad}");
        }
    }
}
