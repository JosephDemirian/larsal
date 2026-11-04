//! E7-S1: writes the seed corpus of the `browser_message` fuzz target in
//! fuzz/corpus/ from INT-01's cases, so no seed is made by hand. Ignored by
//! default because it writes files; run it once after the card's cases or
//! the target change:
//! `cargo test -p larsal-browser --test fuzz_seeds -- --ignored`
//!
//! The target reads each seed twice (fuzz/fuzz_targets/browser_message.rs):
//! as a stream of frames, and as the content of a box for a live session.
//! So the seeds are framed messages and plain request contents.

use larsal_crypto::base64::{self, Form};
use std::path::PathBuf;

fn b64(bytes: &[u8]) -> String {
    base64::encode(Form::Padded, bytes)
}

/// INT-01.2: a 4-byte little-endian length, then the bytes.
fn framed(messages: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in messages {
        out.extend_from_slice(&u32::try_from(m.len()).unwrap().to_le_bytes());
        out.extend_from_slice(m);
    }
    out
}

/// Seeds of `browser_message`: INT-01's frame cases (T02 to T06), hellos
/// (T28 to T30, T44), boxes (T33, T82) and request contents (T35, T41 to
/// T43, T45 to T47, T56, T69, T71, T72, T75, T77, F-203, F-204), and the
/// two large frames of LD-318 (2).
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_browser_message_seeds() {
    // X25519's base point, a key of full order (RFC 7748).
    let mut point = [0u8; 32];
    point[0] = 9;
    let key = b64(&point);
    let hello = format!(r#"{{"type":"hello","versions":[1],"key":"{key}","browser":"Chrome"}}"#);
    let sixteen = format!(
        r#"{{"type":"hello","versions":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],"key":"{key}"}}"#
    );
    let low = format!(
        r#"{{"type":"hello","versions":[1],"key":"{}"}}"#,
        b64(&[0; 32])
    );
    let boxed = format!(
        r#"{{"type":"box","sid":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"{}","box":"{}"}}"#,
        b64(&[1; 12]),
        b64(&[2; 40])
    );
    let proof = |kind: &str| {
        format!(
            r#"{{"type":"{kind}","req":2,"id_key":"{key}","proof":"{}"}}"#,
            b64(&[7; 48])
        )
    };
    let nest = |levels: usize| {
        format!(
            r#"{{"type":"status","req":1,"n":{}{}}}"#,
            "[".repeat(levels - 1),
            "]".repeat(levels - 1)
        )
    };
    let url = "u".repeat(8_193);
    let at = "u".repeat(8_192);
    let contents: Vec<String> = vec![
        r#"{"type":"status","req":1}"#.into(),
        r#"{"type":"status","req":0}"#.into(),
        r#"{"type":"status","req":9007199254740992}"#.into(),
        r#"{"type":"status","type":"lock","req":1}"#.into(),
        r#"{"type":"entries.delete","req":2}"#.into(),
        r#"{"type":"lock","req":3,"extra":{"a":[1,2,{"b":null}]}}"#.into(),
        r#"{"type":"connect","req":2,"name":"x"}"#.into(),
        proof("connect"),
        proof("check"),
        nest(32),
        nest(33),
        format!(r#"{{"type":"status","req":1,"t":"a\"{}"}}"#, "[".repeat(40)),
        format!(r#"{{"type":"logins.find","req":3,"url":"{url}"}}"#),
        format!(r#"{{"type":"logins.find","req":3,"url":"{at}","top_url":"x","form_url":"y"}}"#),
        format!(
            r#"{{"type":"logins.find","req":3,"url":"{}"}}"#,
            "é".repeat(4_097)
        ),
        format!(
            r#"{{"type":"logins.search","req":4,"text":"{}"}}"#,
            "x".repeat(257)
        ),
        format!(
            r#"{{"type":"autotype.start","req":6,"search":"{}"}}"#,
            "y".repeat(256)
        ),
        "[]".into(),
        "   ".into(),
    ];
    let mut seeds: Vec<Vec<u8>> = vec![
        framed(&[hello.as_bytes()]),
        framed(&[hello.as_bytes(), boxed.as_bytes()]),
        framed(&[sixteen.as_bytes(), b"[1]", b"{\"type\":\"hello\xff\"}"]),
        framed(&[low.as_bytes(), b"{\"type\":\"connect\"}"]),
        framed(&[b"   ", b"null", b"{\"type\":\"box\"} {}"]),
        framed(&[r#"{"type":"status","req":1}"#.as_bytes()]),
        // T04: length 0; T05: over 1 MiB; T06: the stream ends inside a frame.
        0u32.to_le_bytes().to_vec(),
        1_048_577u32.to_le_bytes().to_vec(),
        [&100u32.to_le_bytes()[..], b"{\"t"].concat(),
    ];
    seeds.extend(contents.into_iter().map(String::into_bytes));
    // LD-318 (2): the smoke run grows its own inputs only to about 33 KB,
    // so the large frames come from seeds: the length FF FF FF FF
    // (INT-01.3, T06) and a frame of 1,048,575 bytes, a flat list of
    // 524,287 numbers (F-211, T88 (a)).
    seeds.push(vec![0xFF; 4]);
    let flat = format!("[{}0]", "0,".repeat(524_286));
    assert_eq!(flat.len(), 1_048_575);
    seeds.push(framed(&[flat.as_bytes()]));
    let dir = PathBuf::from(format!(
        "{}/../../fuzz/corpus/browser_message",
        env!("CARGO_MANIFEST_DIR")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, s) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:02}")), s).unwrap();
    }
}

/// E7-S3: seeds of `url_match` from INT-03's cases. Each seed's lines are
/// the page URL, the form URL (empty for none) and up to four entry URL
/// values (fuzz/fuzz_targets/url_match.rs).
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_url_match_seeds() {
    let long_path = "a".repeat(8_000);
    let seeds: Vec<String> = vec![
        "https://example.com/\n\nhttps://example.com\nexample.com\nexample.com:443".into(),
        "https://mail.example.com/x\n\nhttps://example.com\nhttps://b.example.com".into(),
        "https://example.com.attacker.example/\n\nhttps://*.example.com\nhttps://example.com"
            .into(),
        "https://xn--bcher-kva.example/\n\nhttps://bücher.example\nhttps://BÜCHER.example/"
            .into(),
        "https://xn--exmple-4nf.com/\n\nhttps://example.com\nhttps://exаmple.com".into(),
        "https://example.com:8443/x\n\nhttps://example.com:8443\nhttps://example.com".into(),
        "http://192.168.1.1/\n\nhttp://192.168.001.001\nhttp://0x7f.1\nhttp://192.168.1.1".into(),
        "http://[::1]:8080/\n\nhttp://[0:0:0:0:0:0:0:1]:8080\nhttp://[2001:db8::*]/".into(),
        "https://name.github.io/\n\nhttps://github.io\nhttps://*.github.io\nhttps://co.uk".into(),
        "https://sub.x.example.com/a/second\n\nhttps://sub.*.example.com/*/second\n\"https://sub.x.example.com/a/second\""
            .into(),
        "https://127.160.8.2/login\n\nhttps://127.160.*.2/login\nhttps://127.128.*/".into(),
        "https://app-eu.example.com/\n\nhttps://app-*.example.com\nhttp*://example.com\nhttps://**.example.com"
            .into(),
        "https://www.example.com/login\nhttps://example.com/session\nhttps://example.com/session\nhttps://example.com/other"
            .into(),
        "file:///Users/demo/page.html\n\nfile:///Users/demo/page.html\nhttps://example.com".into(),
        "chrome://settings\n\nhttps://example.com".into(),
        "https://example.com/\n\nmailto:alex@example.com\nlocalhost:3000\ncmd://open https://example.com"
            .into(),
        "https://a.tenant.example/\n\nhttps://b.tenant.example\nhttps://*.tenant.example".into(),
        format!(
            "https://example.com/{long_path}\n\nhttps://example.com/{}b",
            "*a".repeat(15) + "*"
        ),
        "https://example.com./\n\nhttps://example.com..\nhttps://example.com\\@evil.example/".into(),
        // F-230: a tenant below the private suffix user.srcf.net.
        "https://alex.user.srcf.net/\n\nhttps://*.srcf.net\nhttps://srcf.net\nhttps://alex.*.srcf.net"
            .into(),
        // F-232: a quoted exact URL on a public suffix page, also from a reference.
        "https://github.io/\n\n\"https://github.io/\"\n{TITLE}\"https://github.io/\"".into(),
    ];
    let dir = PathBuf::from(format!(
        "{}/../../fuzz/corpus/url_match",
        env!("CARGO_MANIFEST_DIR")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, s) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:02}")), s).unwrap();
    }
}
