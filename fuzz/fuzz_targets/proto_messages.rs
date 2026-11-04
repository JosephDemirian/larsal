//! Fuzz target `proto_messages` (E16-S3, E16-S5, SYN-01.15, AT-L09):
//! larsal-proto's readers on arbitrary bytes, as a hostile client or server
//! gives them: the record reader of SYN-01.8, the health record of
//! SYN-01.14, the account and sign-in records of SYN-04 (E16-S5), the wrap
//! record of CRY-04.6, and the route match of SYN-01.3 on a method and a
//! path (the text before and after the first newline). Must never panic or
//! hang. A record over the JSON limit is refused before it is parsed, a wrap
//! record over 4 KiB before it is parsed (LD-305 (5)); each record that
//! reads is written back and reads back the same.
#![no_main]

use larsal_proto::Error;
use larsal_proto::limits::{MAX_JSON, MAX_WRAP};
use larsal_proto::messages::{
    AccountCreate, AccountCreated, Challenge, ChallengeRequest, Health, Session, SignIn,
    read_record,
};
use larsal_proto::{routes, wrap};
use libfuzzer_sys::fuzz_target;

/// A record that reads is a record, and reads back the same once written.
macro_rules! round_trip {
    ($data:expr, $record:expr, $($kind:ty),+) => {$(
        if let Ok(r) = <$kind>::read($data) {
            assert!($record.is_ok(), "a {} is a record", stringify!($kind));
            assert_eq!(<$kind>::read(&r.to_json()), Ok(r));
        }
    )+};
}

fuzz_target!(|data: &[u8]| {
    // A lowered limit, so the fuzzer reaches the size check too.
    let limit = data.first().map_or(0, |b| usize::from(*b) * 4);
    if data.len() > limit {
        assert_eq!(read_record(data, limit), Err(Error::TooLarge));
    }
    let record = read_record(data, MAX_JSON);
    if let Err(e) = record {
        assert_ne!(e, Error::TooLarge, "the input is under the JSON limit");
    }
    round_trip!(
        data,
        record,
        Health,
        AccountCreate,
        AccountCreated,
        ChallengeRequest
    );
    round_trip!(data, record, Challenge, SignIn);
    if let Ok(session) = Session::read(data) {
        assert!(record.is_ok(), "a session is a record");
        let again = Session::read(&session.to_json()).unwrap();
        assert_eq!(again.token.expose(), session.token.expose());
        assert_eq!(
            (again.idle_seconds, again.expires),
            (session.idle_seconds, session.expires)
        );
    }
    match wrap::read(data) {
        Ok(w) => {
            assert!(data.len() <= MAX_WRAP);
            assert_eq!(wrap::read(&wrap::to_json(&w)), Ok(w));
        }
        Err(Error::TooLarge) => assert!(data.len() > MAX_WRAP),
        Err(_) => assert!(data.len() <= MAX_WRAP, "refused before it is parsed"),
    }
    let text = String::from_utf8_lossy(data);
    let (method, path) = text.split_once('\n').unwrap_or((&text, ""));
    let _ = routes::find(method, path);
});
