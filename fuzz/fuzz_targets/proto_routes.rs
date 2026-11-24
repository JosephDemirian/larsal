//! Fuzz target `proto_routes` (E16-S4, SYN-01.15, AT-L09): larsal-proto's route
//! match and its `If-Match` and `If-None-Match` readers (SYN-01.3,
//! SYN-01.6) on arbitrary bytes, as a hostile client sends them. Must never
//! panic or hang. The input splits at newlines: the method, the path, then
//! the `If-Match` lines up to an empty line, then the `If-None-Match` lines.
//! A vault or device route names only the canonical spelling of its id; a
//! PUT gets exactly one precondition or a refusal; the ETag of a version
//! reads back as that version. The `If-Match` lines are also read as
//! `Authorization` lines (SYN-01.5, E16-S5): a token that reads is 32 bytes
//! and reads back from its canonical line.
#![no_main]

use larsal_crypto::base64::{self, Form};
use larsal_proto::messages::VaultId;
use larsal_proto::routes::{self, Match, Precondition, PreconditionError, Route};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut lines = data.split(|b| *b == b'\n');
    let method = String::from_utf8_lossy(lines.next().unwrap_or_default());
    let path = String::from_utf8_lossy(lines.next().unwrap_or_default());
    if let Match::Route(Route::VaultGet(id) | Route::VaultPut(id)) = routes::find(&method, &path) {
        assert_eq!(format!("/v1/vaults/{id}"), path);
        assert_eq!(VaultId::parse(&id.to_string()), Some(id));
    }
    if let Match::Route(Route::DeviceDelete(id)) = routes::find(&method, &path) {
        assert_eq!(format!("/v1/devices/{id}"), path);
    }
    let rest: Vec<&[u8]> = lines.collect();
    let (if_match, after) =
        rest.split_at(rest.iter().position(|l| l.is_empty()).unwrap_or(rest.len()));
    let if_none_match = after.get(1..).unwrap_or_default();
    match routes::put_precondition(if_match, if_none_match) {
        Ok(Precondition::Create) => assert!(if_match.is_empty() && !if_none_match.is_empty()),
        Ok(Precondition::Update(version)) => {
            assert!(!if_match.is_empty() && if_none_match.is_empty());
            if let Some(v) = version {
                let tag = routes::etag(v);
                let again = routes::put_precondition(&[tag.as_bytes()], &[]);
                assert_eq!(again, Ok(Precondition::Update(Some(v))));
                assert!(routes::not_modified(&[tag.as_bytes()], v));
            }
        }
        Err(PreconditionError::Required) => {
            assert!(if_match.is_empty() || if_none_match.is_empty())
        }
        Err(PreconditionError::Bad) => assert!(!if_match.is_empty() || !if_none_match.is_empty()),
    }
    if if_match.is_empty() && if_none_match.is_empty() {
        assert_eq!(
            routes::put_precondition(if_match, if_none_match),
            Err(PreconditionError::Required)
        );
    }
    let _ = routes::not_modified(if_none_match, 1);
    if let Some(token) = routes::bearer(if_match) {
        assert_eq!(if_match.len(), 1);
        assert_eq!(token.len(), 32);
        let line = format!("Bearer {}", base64::encode(Form::Url, token.expose()));
        let again = routes::bearer(&[line.as_bytes()]).unwrap();
        assert_eq!(again.expose(), token.expose());
    }
});
