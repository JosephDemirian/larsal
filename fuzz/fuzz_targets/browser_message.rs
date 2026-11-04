//! Fuzz target `browser_message` (E7-S1, INT-01.48, T65): Larsal's side of the
//! browser bridge on arbitrary bytes, as a hostile extension or local
//! process sends them. The bytes are a socket stream for the frame reader
//! (INT-01.2, INT-01.3), and each frame it reads goes to the bridge on both
//! routes: the JSON reader with its limits (INT-01.25) and the hello and box
//! decoder (INT-01.20, INT-01.21). Then the same bytes are the content of a
//! box sealed for a live session, so the request decoder reads them too
//! (INT-01.24, INT-01.25, INT-01.28, INT-01.30); inputs over
//! `MAX_CONTENT + 1` skip this part, because the target's own `seal` of a
//! 1 MiB content would allocate 2 MiB (LD-312). Must never panic or hang;
//! every frame and reply stays within INT-01.3, every opened reply within
//! INT-01.24. T65 runs it with `-max_len=1048580 -len_control=0
//! -malloc_limit_mb=2`: with a growing length limit, libFuzzer's own
//! mutation buffer doubles past 2 MiB.
#![no_main]

use larsal_browser::{Bridge, Handler, MAX_CONTENT, MAX_FRAME, Request, Route, read_frame};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::bridge::{self, Secret};
use larsal_model::json::{self, Map, Value};
use libfuzzer_sys::fuzz_target;
use std::time::Instant;

/// The vault side's stand-in: every request gets a reply with no fields.
struct Nothing;

impl Handler for Nothing {
    fn handle(&mut self, _: &Request<'_>) -> Result<Map, u8> {
        Ok(Map::new())
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::encode(Form::Padded, bytes)
}

/// A reply Larsal sent: at most one frame, one JSON object.
fn reply(bytes: &[u8]) -> Map {
    assert!(bytes.len() <= MAX_FRAME, "INT-01.3");
    match json::from_slice(bytes) {
        Ok(Value::Object(m)) => m,
        other => panic!("a reply is one JSON object: {other:?}"),
    }
}

fn text<'a>(m: &'a Map, key: &str) -> &'a str {
    m.get(key).and_then(Value::as_str).expect("a text member")
}

fuzz_target!(|data: &[u8]| {
    let now = Instant::now();
    let mut stream = data;
    let mut bridge = Bridge::new("1.0", Box::new(Nothing));
    while let Some(frame) = read_frame(&mut stream) {
        assert!(!frame.is_empty() && frame.len() <= MAX_FRAME, "INT-01.3");
        for (conn, route) in [(1, Route::Port), (2, Route::Safari)] {
            if let Some(r) = bridge.take(conn, route, &frame, now) {
                reply(&r);
            }
        }
    }

    // The bytes as the content of a box for a fresh session: one byte over
    // INT-01.24 still tests the limit.
    if data.len() > MAX_CONTENT + 1 {
        return;
    }
    let mut bridge = Bridge::new("1.0", Box::new(Nothing));
    let client = Secret::generate().expect("random");
    let key = client.public();
    let hello = format!(
        r#"{{"type":"hello","versions":[1],"key":"{}","browser":"Chrome"}}"#,
        b64(&key)
    );
    let answer = reply(
        &bridge
            .take(1, Route::Port, hello.as_bytes(), now)
            .expect("a hello reply"),
    );
    let app: [u8; 32] = base64::decode(Form::Padded, text(&answer, "key"))
        .expect("base64")
        .try_into()
        .expect("32 bytes");
    let z = client.agree(&app).expect("Larsal's key is not low order");
    let request_key = bridge::request_key(&z, &key, &app).expect("a key");
    let reply_key = bridge::reply_key(&z, &key, &app).expect("a key");
    let nonce = [1u8; 12];
    let sealed = bridge::seal(&request_key, &nonce, data).expect("sealed");
    let message = format!(
        r#"{{"type":"box","sid":"{}","nonce":"{}","box":"{}"}}"#,
        text(&answer, "sid"),
        b64(&nonce),
        b64(&sealed)
    );
    let boxed = reply(
        &bridge
            .take(1, Route::Port, message.as_bytes(), now)
            .expect("a reply"),
    );
    assert_eq!(
        text(&boxed, "type"),
        "box",
        "INT-01.21: an opened box is answered in a box"
    );
    assert_eq!(text(&boxed, "nonce"), b64(&nonce), "INT-01.23");
    let sealed = base64::decode(Form::Padded, text(&boxed, "box")).expect("base64");
    let opened = bridge::open(&reply_key, &nonce, &sealed).expect("opens with the reply key");
    assert!(opened.len() <= MAX_CONTENT, "INT-01.24");
    reply(opened.expose());
});
