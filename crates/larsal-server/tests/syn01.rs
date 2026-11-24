//! SYN-01 checks of E16-S3 and E16-S4 against an in-process server on
//! 127.0.0.1:0, with a fresh data folder under the system's temp folder.
//! Every client here connects to 127.0.0.1 only; nothing reaches another
//! host. From E16-S5 the vault routes need a session: [`start`] signs one
//! device in, and every vault request carries its `Authorization` line.

mod common;

use common::{Reply, Running, block_on, client, exchange, read_all, scratch, start, tls};
use larsal_server::Server;
use larsal_server::http::Config;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ProtocolVersion, version};

const HEALTH: &[u8] = b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

async fn assert_no_http_reply<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, send: &[u8]) {
    stream.write_all(send).await.unwrap();
    let got = read_all(stream).await;
    assert!(
        !got.starts_with(b"HTTP/"),
        "{:?}",
        String::from_utf8_lossy(&got)
    );
    // Nothing, or one TLS alert record.
    assert!(got.is_empty() || got[0] == 0x15, "{got:?}");
}

fn tls11_client_hello() -> Vec<u8> {
    let mut body = vec![0x03, 0x02]; // TLS 1.1, no supported_versions extension
    body.extend([0u8; 32]); // random
    body.push(0); // no session id
    body.extend([0x00, 0x04, 0xc0, 0x13, 0x00, 0x2f]); // two TLS 1.1 suites
    body.extend([0x01, 0x00]); // no compression
    let mut hello = vec![0x01, 0x00, 0x00, u8::try_from(body.len()).unwrap()];
    hello.extend(body);
    let mut record = vec![0x16, 0x03, 0x01, 0x00, u8::try_from(hello.len()).unwrap()];
    record.extend(hello);
    record
}

#[test]
fn syn01_1_tls13_and_tls12_answer_health() {
    block_on(async {
        let s = start(Config::default()).await;
        for (v, want) in [
            (&version::TLS13, ProtocolVersion::TLSv1_3),
            (&version::TLS12, ProtocolVersion::TLSv1_2),
        ] {
            let mut stream = tls(&s, v).await;
            assert_eq!(stream.get_ref().1.protocol_version(), Some(want));
            assert_eq!(stream.get_ref().1.alpn_protocol(), None);
            stream.write_all(HEALTH).await.unwrap();
            let r = Reply::parse(&read_all(&mut stream).await);
            assert_eq!(r.status, 200);
            assert_eq!(r.body, br#"{"api":1,"service":"sync"}"#);
            assert_eq!(r.header("content-type"), Some("application/json"));
            assert_eq!(r.header("cache-control"), Some("no-store"));
        }
    });
}

#[test]
fn syn01_1_tls11_hello_gets_no_http_reply() {
    block_on(async {
        let s = start(Config::default()).await;
        let mut tcp = TcpStream::connect(s.addr).await.unwrap();
        assert_no_http_reply(&mut tcp, &tls11_client_hello()).await;
    });
}

#[test]
fn syn01_1_plain_http_gets_no_http_reply() {
    block_on(async {
        let s = start(Config::default()).await;
        let mut tcp = TcpStream::connect(s.addr).await.unwrap();
        assert_no_http_reply(&mut tcp, HEALTH).await;
    });
}

#[test]
fn syn01_2_certificate_names_localhost_and_127_0_0_1() {
    block_on(async {
        let s = start(Config::default()).await;
        let tcp = TcpStream::connect(s.addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        client(&s.cert, &version::TLS13)
            .connect(name, tcp)
            .await
            .unwrap();
        let tcp = TcpStream::connect(s.addr).await.unwrap();
        let other = ServerName::try_from("other.example").unwrap();
        assert!(
            client(&s.cert, &version::TLS13)
                .connect(other, tcp)
                .await
                .is_err()
        );
    });
}

#[test]
fn syn01_3_unknown_path_404_other_method_405() {
    block_on(async {
        let s = start(Config::default()).await;
        let r = exchange(
            &s,
            b"GET /v1/nothing HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        r.assert_error(404, "not_found");
        let r = exchange(
            &s,
            b"DELETE /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        r.assert_error(405, "method_not_allowed");
        assert_eq!(r.header("allow"), Some("GET"));
    });
}

fn vault_put(s: &Running, len: u64) -> Vec<u8> {
    format!(
        "PUT /v1/vaults/0123456789abcdef0123456789abcdef HTTP/1.1\r\nHost: x\r\n{}\
         If-None-Match: *\r\nConnection: close\r\nContent-Length: {len}\r\n\r\n",
        s.auth
    )
    .into_bytes()
}

/// T09: one byte over the vault limit gets 413 before one body byte is
/// read (only the head is sent, and the reply comes); at the limit the body
/// is stored.
#[test]
fn syn01_10_t09_body_over_limit_gets_413_before_read() {
    block_on(async {
        let limit = Config {
            max_body: 1024,
            ..Config::default()
        };
        let s = start(limit).await;
        // The client asks to keep the connection; the server ends it all
        // the same, so the unread body is never read.
        let started = Instant::now();
        let keep = String::from_utf8(vault_put(&s, 1025))
            .unwrap()
            .replace("Connection: close\r\n", "");
        let r = exchange(&s, keep.as_bytes()).await;
        r.assert_error(413, "too_large");
        assert_eq!(r.header("connection"), Some("close"));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(files(&s.data.0.join("tmp")).is_empty(), "nothing written");
        // At the limit the body is stored, byte for byte.
        let mut at = vault_put(&s, 1024);
        at.extend([7u8; 1024]);
        assert_eq!(exchange(&s, &at).await.status, 201);
        let r = exchange(&s, &get(&s, ID, "")).await;
        assert_eq!((r.status, r.body), (200, vec![7u8; 1024]));

        // FMT-01.31's limit itself.
        let s = start(Config::default()).await;
        let r = exchange(&s, &vault_put(&s, 1_140_850_689)).await;
        r.assert_error(413, "too_large");
        // At the limit the size check passes: with only the head sent, an
        // `If-Match` for a vault that does not exist gets 412 at once.
        let head = String::from_utf8(vault_put(&s, 1_140_850_688))
            .unwrap()
            .replace("If-None-Match: *", "If-Match: \"1\"");
        exchange(&s, head.as_bytes())
            .await
            .assert_error(412, "precondition_failed");
    });
}

#[test]
fn syn01_10_head_limits() {
    block_on(async {
        let s = start(Config::default()).await;
        let path = |n: usize| {
            format!(
                "GET /v1/{} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                "a".repeat(n)
            )
            .into_bytes()
        };
        // A 9 KiB request line: Larsal's own check, 414.
        let r = exchange(&s, &path(9 * 1024)).await;
        r.assert_head_reply(414);
        assert_eq!(r.header("connection"), Some("close"));
        assert_eq!(r.header("cache-control"), Some("no-store"));
        // The edge: a request line ("GET ", the target, " HTTP/1.1") of
        // exactly 8 KiB passes the check (no such route: 404); one byte more
        // gets 414.
        let line = |n: usize| format!("GET /v1/{} HTTP/1.1", "a".repeat(n - 17));
        assert_eq!(line(8 * 1024).len(), 8 * 1024);
        let at = format!("{}\r\nHost: x\r\nConnection: close\r\n\r\n", line(8 * 1024));
        exchange(&s, at.as_bytes())
            .await
            .assert_error(404, "not_found");
        let over = format!(
            "{}\r\nHost: x\r\nConnection: close\r\n\r\n",
            line(8 * 1024 + 1)
        );
        exchange(&s, over.as_bytes()).await.assert_head_reply(414);
        // The query counts too: the same edge on the health route, with the
        // length in a query (200 at 8 KiB, 414 one byte more).
        let query = |n: usize| format!("GET /v1/health?{} HTTP/1.1", "q".repeat(n - 24));
        assert_eq!(query(8 * 1024).len(), 8 * 1024);
        let at = format!(
            "{}\r\nHost: x\r\nConnection: close\r\n\r\n",
            query(8 * 1024)
        );
        assert_eq!(exchange(&s, at.as_bytes()).await.status, 200);
        let over = format!(
            "{}\r\nHost: x\r\nConnection: close\r\n\r\n",
            query(8 * 1024 + 1)
        );
        exchange(&s, over.as_bytes()).await.assert_head_reply(414);
        // A 40 KiB request line: the head is over 32 KiB, hyper's 431.
        exchange(&s, &path(40 * 1024)).await.assert_head_reply(431);
        // One 9 KiB header field: Larsal's own check, 431. No Connection: close
        // in it: the server ends the connection itself.
        let field = format!(
            "GET /v1/health HTTP/1.1\r\nHost: x\r\nX: {}\r\n\r\n",
            "b".repeat(9 * 1024)
        );
        exchange(&s, field.as_bytes()).await.assert_head_reply(431);
        // A field of exactly 8 KiB ("x: " and the value) is taken.
        let at = format!(
            "GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\nx: {}\r\n\r\n",
            "b".repeat(8 * 1024 - 3)
        );
        assert_eq!(exchange(&s, at.as_bytes()).await.status, 200);
        // One byte more ("x: " and 8,190 bytes): 431.
        let over = format!(
            "GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\nx: {}\r\n\r\n",
            "b".repeat(8 * 1024 - 2)
        );
        exchange(&s, over.as_bytes()).await.assert_head_reply(431);
        // A 33 KiB head in fields of 4 KiB: hyper's 431.
        let mut head = String::from("GET /v1/health HTTP/1.1\r\nHost: x\r\n");
        for i in 0..9 {
            head.push_str(&format!("f{i}: {}\r\n", "c".repeat(4000)));
        }
        head.push_str("\r\n");
        assert!(head.len() > 33 * 1024);
        exchange(&s, head.as_bytes()).await.assert_head_reply(431);
        // 101 header fields: hyper's 431; 100 are taken.
        let fields = |n: usize| {
            let mut h = String::from("GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
            for i in 2..n {
                h.push_str(&format!("f{i}: 1\r\n"));
            }
            h.push_str("\r\n");
            h.into_bytes()
        };
        exchange(&s, &fields(101)).await.assert_head_reply(431);
        assert_eq!(exchange(&s, &fields(100)).await.status, 200);
        // 128 KiB of fields with no end of the head: answered 431 while it
        // is still being sent.
        let stream = tls(&s, &version::TLS13).await;
        let (mut read, mut write) = tokio::io::split(stream);
        let sender = tokio::spawn(async move {
            let _ = write.write_all(b"GET /v1/health HTTP/1.1\r\n").await;
            for _ in 0..128 {
                if write.write_all(&[b'h'; 1024]).await.is_err() {
                    break;
                }
            }
        });
        Reply::parse(&read_all(&mut read).await).assert_head_reply(431);
        sender.abort();
    });
}

fn quick() -> Config {
    Config {
        handshake: Duration::from_millis(500),
        head: Duration::from_millis(500),
        gap: Duration::from_millis(1500),
        ..Config::default()
    }
}

/// Waits for the server to close; the time it took, at most 60 s.
async fn closes_after<S: AsyncRead + Unpin>(stream: &mut S) -> (Duration, Vec<u8>) {
    let started = Instant::now();
    let got = read_all(stream).await;
    (started.elapsed(), got)
}

/// A close at quick()'s 500 ms timer: not before it, and well before the
/// 1,500 ms gap, so a timer that runs on the gap's value fails.
fn assert_own_timer(took: Duration) {
    assert!(took >= Duration::from_millis(450), "{took:?}");
    assert!(took < Duration::from_millis(1400), "{took:?}");
}

#[test]
fn syn01_11_cut_off_handshake_closes_after_its_timeout() {
    block_on(async {
        let s = start(quick()).await;
        let mut tcp = TcpStream::connect(s.addr).await.unwrap();
        let hello = tls11_client_hello();
        tcp.write_all(&hello[..hello.len() / 2]).await.unwrap();
        let (took, got) = closes_after(&mut tcp).await;
        assert!(got.is_empty(), "{got:?}");
        assert_own_timer(took);
    });
}

#[test]
fn syn01_11_half_head_closes_after_head_timeout() {
    block_on(async {
        let s = start(quick()).await;
        let mut stream = tls(&s, &version::TLS13).await;
        stream.write_all(b"GET /v1/hea").await.unwrap();
        let (took, got) = closes_after(&mut stream).await;
        assert!(got.is_empty(), "{:?}", String::from_utf8_lossy(&got));
        assert_own_timer(took);
    });
}

#[test]
fn syn01_11_silent_client_after_handshake_closes_after_head_timeout() {
    block_on(async {
        let s = start(quick()).await;
        let mut stream = tls(&s, &version::TLS13).await;
        let (took, got) = closes_after(&mut stream).await;
        assert!(got.is_empty(), "{:?}", String::from_utf8_lossy(&got));
        assert_own_timer(took);
    });
}

#[test]
fn syn01_11_idle_connection_closes_after_its_reply() {
    block_on(async {
        let s = start(quick()).await;
        let mut stream = tls(&s, &version::TLS13).await;
        stream
            .write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        // One whole reply (its length is known), then nothing more.
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.ends_with(br#"{"api":1,"service":"sync"}"#) {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "closed before the reply");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(Reply::parse(&got).status, 200);
        let (took, rest) = closes_after(&mut stream).await;
        assert!(rest.is_empty());
        assert_own_timer(took);
    });
}

#[test]
fn syn01_11_unread_replies_close_after_the_gap() {
    block_on(async {
        // Only the gap can end this connection: the handshake and head
        // timers stay at 30 s.
        let gap = Duration::from_millis(1500);
        let s = start(Config {
            gap,
            ..Config::default()
        })
        .await;
        // The client sends requests and never reads a reply, so the server's
        // writes back up until one waits longer than the gap.
        let (_unread, mut write) = tokio::io::split(tls(&s, &version::TLS13).await);
        let started = Instant::now();
        let sending = async {
            while write
                .write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .is_ok()
            {}
        };
        tokio::time::timeout(Duration::from_secs(20), sending)
            .await
            .expect("the server kept a stalled reply past the gap");
        assert!(started.elapsed() >= gap, "{:?}", started.elapsed());
    });
}

#[test]
fn syn01_11_a_silent_connection_leaves_other_clients_served() {
    block_on(async {
        // Default timers: the silent connection holds its handshake 30 s
        // (AT-L03: one slow client must not stop the others).
        let s = start(Config::default()).await;
        let _silent = TcpStream::connect(s.addr).await.unwrap();
        let started = Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(5), exchange(&s, HEALTH))
            .await
            .expect("a second client waited for the silent one");
        assert_eq!(r.status, 200);
        assert!(started.elapsed() < Duration::from_secs(5));
    });
}

/// Stops the server process it holds (by its own PID) when dropped.
struct Stop(std::process::Child);

impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn syn01_2_binary_prints_its_address_and_the_fingerprint() {
    use std::io::BufRead;
    // A free port on 127.0.0.1, given back before the server takes it.
    let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let data = scratch();
    let mut server = Stop(
        Command::new(env!("CARGO_BIN_EXE_larsal-server"))
            .arg("--data")
            .arg(&data.0)
            .arg("--port")
            .arg(port.to_string())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let out = server.0.stdout.take().unwrap();
    let lines: Vec<String> = std::io::BufReader::new(out)
        .lines()
        .take(2)
        .map(Result::unwrap)
        .collect();
    drop(server);
    assert_eq!(
        lines[0],
        format!("Larsal sync server (demo): https://127.0.0.1:{port}")
    );
    // The SHA-256 of the stored certificate, 8 groups of 8 uppercase hex
    // digits: the line a user compares with the Mac's.
    let der = std::fs::read(data.0.join("tls").join("cert.der")).unwrap();
    let hex: String = larsal_crypto::hash::sha256(&[&der])
        .expose()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let groups: Vec<&str> = (0..8).map(|i| &hex[i * 8..i * 8 + 8]).collect();
    assert_eq!(
        lines[1],
        format!("Certificate fingerprint (SHA-256): {}", groups.join(" "))
    );
}

#[test]
fn syn01_flags_argument_not_utf8_exits_2_in_words() {
    use std::os::unix::ffi::OsStrExt;
    let out = Command::new(env!("CARGO_BIN_EXE_larsal-server"))
        .arg("--data")
        .arg(std::ffi::OsStr::from_bytes(b"/tmp/\xff"))
        .arg("--port")
        .arg("1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let words = String::from_utf8_lossy(&out.stderr);
    assert!(words.contains("is not UTF-8 text"), "{words}");
    assert!(!words.contains("panicked"), "{words}");
}

// E16-S4: the vault routes (SYN-01.6) and the store behind them (SYN-02).

const ID: &str = "0123456789abcdef0123456789abcdef";

/// A PUT of `body` to vault `id` with the precondition lines `pre` (each
/// ending in CRLF).
fn put(s: &Running, id: &str, pre: &str, body: &[u8]) -> Vec<u8> {
    let path = format!("/v1/vaults/{id}");
    common::request("PUT", &path, &format!("{}{pre}", s.auth), body)
}

fn get(s: &Running, id: &str, extra: &str) -> Vec<u8> {
    format!(
        "GET /v1/vaults/{id} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{}{extra}\r\n",
        s.auth
    )
    .into_bytes()
}

/// `GET /v1/vaults` with the session of `s`.
fn vault_list(s: &Running) -> Vec<u8> {
    format!(
        "GET /v1/vaults HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{}\r\n",
        s.auth
    )
    .into_bytes()
}

fn if_match(version: u64) -> String {
    format!("If-Match: \"{version}\"\r\n")
}

const CREATE: &str = "If-None-Match: *\r\n";

/// Every file under `dir`, as paths below it, sorted.
fn files(dir: &std::path::Path) -> Vec<String> {
    let mut all = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(p) = todo.pop() {
        for e in std::fs::read_dir(&p).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                todo.push(e.path());
            } else {
                all.push(e.path().strip_prefix(dir).unwrap().display().to_string());
            }
        }
    }
    all.sort();
    all
}

/// Where the store keeps these bytes: `<h[0..2]>/<h>` under `blobs/`.
fn blob_name(bytes: &[u8]) -> String {
    let hex: String = larsal_crypto::hash::sha256(&[bytes])
        .expose()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{}/{hex}", &hex[..2])
}

fn blob_names(all: &[&[u8]]) -> Vec<String> {
    let mut names: Vec<String> = all.iter().map(|b| blob_name(b)).collect();
    names.sort();
    names.dedup();
    names
}

/// Bytes no other test body has: every byte value, then `seed`.
fn vault_bytes(len: usize, seed: u8) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len).map(|i| (i % 251) as u8 ^ seed).collect();
    v.push(seed);
    v
}

/// Reads the server's store with a second connection (reads only).
fn store(s: &Running) -> rusqlite::Connection {
    rusqlite::Connection::open(s.data.0.join("store.sqlite")).unwrap()
}

/// T06 and the round trip: create, read back byte for byte, 304, and the
/// file in `blobs/` named by the SHA-256 of the bytes.
#[test]
fn syn01_6_t06_create_read_304_and_bytes_identical() {
    block_on(async {
        let s = start(Config::default()).await;
        let v1 = vault_bytes(300 * 1024, 1);
        let r = exchange(&s, &put(&s, ID, CREATE, &v1)).await;
        assert_eq!(r.status, 201, "{r:?}");
        assert_eq!(r.header("etag"), Some("\"1\""));
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert_eq!(r.header("content-type"), Some("application/json"));
        let want = format!(r#"{{"id":"{ID}","size":{},"version":1}}"#, v1.len());
        assert_eq!(r.body, want.as_bytes());

        let r = exchange(&s, &get(&s, ID, "")).await;
        assert_eq!(r.status, 200);
        assert!(r.body == v1, "the bytes come back exactly as uploaded");
        assert_eq!(r.header("etag"), Some("\"1\""));
        assert_eq!(r.header("content-type"), Some("application/octet-stream"));
        assert_eq!(r.header("content-length"), Some(&*v1.len().to_string()));
        assert_eq!(r.header("cache-control"), Some("no-store"));
        let file = s.data.0.join("blobs").join(blob_name(&v1));
        assert!(std::fs::read(file).unwrap() == v1);

        for same in ["If-None-Match: \"1\"\r\n", "If-None-Match: *\r\n"] {
            let r = exchange(&s, &get(&s, ID, same)).await;
            assert_eq!(r.status, 304, "{same}");
            assert!(r.body.is_empty());
            assert_eq!(r.header("etag"), Some("\"1\""));
            assert_eq!(r.header("cache-control"), Some("no-store"));
        }
        // Another version, a weak ETag (the strong compare only), a field
        // that is not an ETag: the bytes.
        for other in [
            "If-None-Match: \"0\"\r\n",
            "If-None-Match: W/\"1\"\r\n",
            "If-None-Match: 1\r\n",
        ] {
            let r = exchange(&s, &get(&s, ID, other)).await;
            assert_eq!(r.status, 200, "{other}");
            assert!(r.body == v1);
        }
        // An unknown id.
        let r = exchange(&s, &get(&s, "ffffffffffffffffffffffffffffffff", "")).await;
        r.assert_error(404, "not_found");
    });
}

/// T07: exactly one precondition: 428 for none and for `If-Match: *`, 400
/// for both or a list, 412 for another version, a weak ETag, a version
/// that cannot exist, or `If-None-Match: *` on an id that exists.
#[test]
fn syn01_6_t07_preconditions() {
    block_on(async {
        let s = start(Config::default()).await;
        let body = |n: u8| vault_bytes(64, n);
        assert_eq!(
            exchange(&s, &put(&s, ID, CREATE, &body(1))).await.status,
            201
        );
        assert_eq!(
            exchange(&s, &put(&s, ID, &if_match(1), &body(2)))
                .await
                .status,
            200
        );
        assert_eq!(
            exchange(&s, &put(&s, ID, &if_match(2), &body(3)))
                .await
                .status,
            200
        );
        for (pre, status, code) in [
            ("", 428, "precondition_required"),
            ("If-Match: *\r\n", 428, "precondition_required"),
            (
                "If-Match: \"3\"\r\nIf-None-Match: *\r\n",
                400,
                "bad_request",
            ),
            ("If-Match: \"2\", \"3\"\r\n", 400, "bad_request"),
            ("If-Match: \"2\"\r\nIf-Match: \"3\"\r\n", 400, "bad_request"),
            ("If-Match: 3\r\n", 400, "bad_request"),
            ("If-Match: \"2\"\r\n", 412, "precondition_failed"),
            ("If-Match: W/\"3\"\r\n", 412, "precondition_failed"),
            ("If-Match: \"0\"\r\n", 412, "precondition_failed"),
            ("If-Match: \"-1\"\r\n", 412, "precondition_failed"),
            ("If-Match: \"abc\"\r\n", 412, "precondition_failed"),
            ("If-Match: \"03\"\r\n", 412, "precondition_failed"),
            (CREATE, 412, "precondition_failed"),
        ] {
            let r = exchange(&s, &put(&s, ID, pre, &body(9))).await;
            assert_eq!(r.status, status, "{pre:?}");
            r.assert_error(status, code);
        }
        // `If-Match` for an id that does not exist.
        let r = exchange(
            &s,
            &put(
                &s,
                "ffffffffffffffffffffffffffffffff",
                &if_match(1),
                &body(9),
            ),
        )
        .await;
        r.assert_error(412, "precondition_failed");
        // Nothing above was stored.
        let r = exchange(&s, &get(&s, ID, "")).await;
        assert_eq!((r.status, r.header("etag")), (200, Some("\"3\"")));
        assert!(r.body == body(3));
        assert!(files(&s.data.0.join("tmp")).is_empty());
        assert_eq!(
            files(&s.data.0.join("blobs")),
            blob_names(&[&body(1), &body(2), &body(3)])
        );
        let r = exchange(&s, &put(&s, ID, &if_match(3), &body(4))).await;
        assert_eq!((r.status, r.header("etag")), (200, Some("\"4\"")));
    });
}

/// Writes all of `request` but its last byte; returns the stream.
async fn all_but_last(s: &Running, request: &[u8]) -> TlsStream<TcpStream> {
    let mut stream = tls(s, &version::TLS13).await;
    stream
        .write_all(&request[..request.len() - 1])
        .await
        .unwrap();
    stream.flush().await.unwrap();
    stream
}

/// Waits until `dir` holds `n` files (at most 60 s).
async fn until_files(dir: &std::path::Path, n: usize) {
    let started = Instant::now();
    while files(dir).len() != n {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{:?}",
            files(dir)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// T08 (AT-L02): two clients race a PUT on one version; one gets 200, the
/// other 412, and the loser's file is gone. First in a fixed order: both
/// bodies are in the server's temp files, past the first look at the
/// version, before either ends, so the commit's compare-and-swap decides.
/// Then eight clients at once.
#[test]
fn syn01_6_t08_two_clients_race_one_version_one_gets_412() {
    block_on(async {
        let s = start(Config::default()).await;
        let v1 = vault_bytes(1000, 1);
        assert_eq!(exchange(&s, &put(&s, ID, CREATE, &v1)).await.status, 201);
        let (a, b) = (vault_bytes(1000, 2), vault_bytes(1000, 3));
        let (pa, pb) = (put(&s, ID, &if_match(1), &a), put(&s, ID, &if_match(1), &b));
        let mut sa = all_but_last(&s, &pa).await;
        let mut sb = all_but_last(&s, &pb).await;
        until_files(&s.data.0.join("tmp"), 2).await;
        sa.write_all(&pa[pa.len() - 1..]).await.unwrap();
        sa.flush().await.unwrap();
        let ra = Reply::parse(&read_all(&mut sa).await);
        assert_eq!((ra.status, ra.header("etag")), (200, Some("\"2\"")));
        sb.write_all(&pb[pb.len() - 1..]).await.unwrap();
        sb.flush().await.unwrap();
        Reply::parse(&read_all(&mut sb).await).assert_error(412, "precondition_failed");
        let r = exchange(&s, &get(&s, ID, "")).await;
        assert_eq!(r.header("etag"), Some("\"2\""));
        assert!(r.body == a, "the winner's bytes");
        assert_eq!(files(&s.data.0.join("blobs")), blob_names(&[&v1, &a]));
        assert!(files(&s.data.0.join("tmp")).is_empty());

        // Eight at once on version 2.
        let bodies: Vec<Vec<u8>> = (10..18).map(|n| vault_bytes(1000, n)).collect();
        let mut tasks = Vec::new();
        for body in &bodies {
            let request = put(&s, ID, &if_match(2), body);
            let stream = tls(&s, &version::TLS13).await;
            tasks.push(tokio::spawn(async move {
                let mut stream = stream;
                let _ = stream.write_all(&request).await;
                let _ = stream.flush().await;
                Reply::parse(&read_all(&mut stream).await).status
            }));
        }
        let mut statuses = Vec::new();
        for t in tasks {
            statuses.push(t.await.unwrap());
        }
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 412, 412, 412, 412, 412, 412, 412]);
        let r = exchange(&s, &get(&s, ID, "")).await;
        assert_eq!(r.header("etag"), Some("\"3\""));
        let winner = bodies.iter().find(|b| **b == r.body).expect("one body won");
        assert_eq!(
            files(&s.data.0.join("blobs")),
            blob_names(&[&v1, &a, winner])
        );
        assert!(files(&s.data.0.join("tmp")).is_empty());
    });
}

/// T10 and LD-314 (4): a PUT with no `Content-Length` (chunked) gets 411,
/// and so does a chunked PUT that also names a `Content-Length` over the
/// limit (hyper drops that length, RFC 9112 section 6.1, so the 413 check
/// sees no length); only the head is sent, so no body byte was read, and
/// nothing is stored.
#[test]
fn syn01_6_t10_chunked_put_gets_411_nothing_stored() {
    block_on(async {
        let s = start(Config {
            max_body: 1024,
            ..Config::default()
        })
        .await;
        let head = |extra: &str| {
            format!(
                "PUT /v1/vaults/{ID} HTTP/1.1\r\nHost: x\r\n{}{CREATE}{extra}\
                 Transfer-Encoding: chunked\r\n\r\n",
                s.auth
            )
        };
        for extra in [
            "",
            "Content-Length: 1025\r\n",
            "Content-Length: 1140850689\r\n",
        ] {
            let started = Instant::now();
            // No `Connection: close` in the request: the server ends the
            // connection itself, since the body stays unread.
            let r = exchange(&s, head(extra).as_bytes()).await;
            r.assert_error(411, "length_required");
            assert_eq!(r.header("connection"), Some("close"));
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        // A whole chunked body after the head: still 411.
        let mut whole = head("").into_bytes();
        whole.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        exchange(&s, &whole)
            .await
            .assert_error(411, "length_required");
        assert!(files(&s.data.0.join("tmp")).is_empty());
        assert!(files(&s.data.0.join("blobs")).is_empty());
        exchange(&s, &get(&s, ID, ""))
            .await
            .assert_error(404, "not_found");
    });
}

/// SYN-01.6: a PUT with neither `Content-Length` nor a chunked body gets
/// 411, as a create and as an update. hyper reads such a request as a body
/// of 0 bytes (RFC 9112 section 6.3), so without the header check an empty
/// vault would be stored. `Content-Length: 0` sent on purpose is an upload.
#[test]
fn syn01_6_put_without_content_length_gets_411() {
    block_on(async {
        let s = start(Config::default()).await;
        let bare = |pre: &str| {
            format!(
                "PUT /v1/vaults/{ID} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{}{pre}\r\n",
                s.auth
            )
            .into_bytes()
        };
        exchange(&s, &bare(CREATE))
            .await
            .assert_error(411, "length_required");
        exchange(&s, &get(&s, ID, ""))
            .await
            .assert_error(404, "not_found");
        assert!(files(&s.data.0.join("blobs")).is_empty());

        let v1 = vault_bytes(100, 7);
        assert_eq!(exchange(&s, &put(&s, ID, CREATE, &v1)).await.status, 201);
        exchange(&s, &bare(&if_match(1)))
            .await
            .assert_error(411, "length_required");
        let r = exchange(&s, &get(&s, ID, "")).await;
        assert_eq!(r.header("etag"), Some("\"1\""));
        assert!(r.body == v1, "version 1 is still served");

        let r = exchange(&s, &put(&s, ID, &if_match(1), b"")).await;
        assert_eq!(r.status, 200, "{r:?}");
        assert_eq!(r.header("etag"), Some("\"2\""));
    });
}

/// T10 of SYN-02 (P15, LD-267 (7)): after the 7th upload of one vault the
/// store holds version 7 and the 5 old versions 2 to 6; version 1's row and
/// file are gone.
#[test]
fn syn02_5_seventh_upload_keeps_current_and_five_old_versions() {
    block_on(async {
        let s = start(Config::default()).await;
        let bodies: Vec<Vec<u8>> = (1..=7).map(|n| vault_bytes(500, n)).collect();
        assert_eq!(
            exchange(&s, &put(&s, ID, CREATE, &bodies[0])).await.status,
            201
        );
        for (n, body) in (1u64..).zip(&bodies[1..]) {
            let r = exchange(&s, &put(&s, ID, &if_match(n), body)).await;
            assert_eq!(r.status, 200, "upload {}", n + 1);
        }
        let db = store(&s);
        let current: i64 = db
            .query_row("SELECT version FROM vaults", [], |r| r.get(0))
            .unwrap();
        assert_eq!(current, 7);
        let kept: Vec<i64> = db
            .prepare("SELECT version FROM vault_versions ORDER BY version")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(kept, [2, 3, 4, 5, 6]);
        let names: Vec<&[u8]> = bodies[1..].iter().map(Vec::as_slice).collect();
        assert_eq!(files(&s.data.0.join("blobs")), blob_names(&names));
        let r = exchange(&s, &get(&s, ID, "")).await;
        assert!(r.body == bodies[6]);
    });
}

/// `GET /v1/vaults`: id, version and size of each vault, sorted by id,
/// and nothing else (SYN-01.6); 405 for other methods on the vault paths,
/// 404 for an id that is not 32 lowercase hex digits (T04).
#[test]
fn syn01_6_vault_list_sorted_by_id_and_vault_paths() {
    block_on(async {
        let s = start(Config::default()).await;
        let list = vault_list(&s);
        let list = list.as_slice();
        let r = exchange(&s, list).await;
        assert_eq!(
            (r.status, r.body.as_slice()),
            (200, &br#"{"vaults":[]}"#[..])
        );
        assert_eq!(r.header("cache-control"), Some("no-store"));
        let ids = [
            "ffffffffffffffffffffffffffffffff",
            "0000000000000000000000000000000a",
            "80000000000000000000000000000000",
        ];
        for (n, id) in ids.iter().enumerate() {
            let body = vault_bytes(10 * n, n as u8);
            assert_eq!(exchange(&s, &put(&s, id, CREATE, &body)).await.status, 201);
        }
        assert_eq!(
            exchange(&s, &put(&s, ids[2], &if_match(1), b"x"))
                .await
                .status,
            200
        );
        let r = exchange(&s, list).await;
        let want = format!(
            r#"{{"vaults":[{{"id":"{}","size":11,"version":1}},{{"id":"{}","size":1,"version":2}},{{"id":"{}","size":1,"version":1}}]}}"#,
            ids[1], ids[2], ids[0]
        );
        assert_eq!(String::from_utf8(r.body).unwrap(), want);

        let other = |m: &str, path: &str| {
            format!("{m} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").into_bytes()
        };
        let r = exchange(&s, &other("DELETE", "/v1/vaults")).await;
        r.assert_error(405, "method_not_allowed");
        assert_eq!(r.header("allow"), Some("GET"));
        let r = exchange(&s, &other("DELETE", &format!("/v1/vaults/{ID}"))).await;
        r.assert_error(405, "method_not_allowed");
        assert_eq!(r.header("allow"), Some("GET, PUT"));
        // An id with upper-case digits names no route: nothing is stored
        // under it.
        let upper = ID.to_uppercase();
        let r = exchange(&s, &other("GET", &format!("/v1/vaults/{upper}"))).await;
        r.assert_error(404, "not_found");
        let r = exchange(&s, &put(&s, &upper, CREATE, b"x")).await;
        r.assert_error(404, "not_found");
    });
}

/// SYN-02.4 step 1: a body cut off before its `Content-Length` stores
/// nothing, and its temp file is deleted.
#[test]
fn syn02_4_cut_off_body_stores_nothing() {
    block_on(async {
        let s = start(Config::default()).await;
        let body = vault_bytes(100_000, 1);
        let request = put(&s, ID, CREATE, &body);
        let mut stream = tls(&s, &version::TLS13).await;
        stream
            .write_all(&request[..request.len() - 50_000])
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let tmp = s.data.0.join("tmp");
        until_files(&tmp, 1).await;
        stream.shutdown().await.unwrap();
        drop(stream);
        until_files(&tmp, 0).await;
        assert!(files(&s.data.0.join("blobs")).is_empty());
        exchange(&s, &get(&s, ID, ""))
            .await
            .assert_error(404, "not_found");
    });
}

/// T12 (SYN-02.7): a GET that streams while later commits prune its
/// version and delete its file still gives that version's bytes complete.
#[test]
fn syn02_7_t12_read_during_commits_gives_the_whole_version() {
    block_on(async {
        let s = start(Config::default()).await;
        let big = vault_bytes(8 * 1024 * 1024, 1);
        assert_eq!(exchange(&s, &put(&s, ID, CREATE, &big)).await.status, 201);
        // The GET's reply waits on a client that does not read yet.
        let mut reading = tls(&s, &version::TLS13).await;
        reading.write_all(&get(&s, ID, "")).await.unwrap();
        reading.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        for n in 1..=6u64 {
            let r = exchange(
                &s,
                &put(&s, ID, &if_match(n), &vault_bytes(10, n as u8 + 1)),
            )
            .await;
            assert_eq!(r.status, 200);
        }
        let path = s.data.0.join("blobs").join(blob_name(&big));
        assert!(!path.exists(), "version 1's file was deleted");
        let r = Reply::parse(&read_all(&mut reading).await);
        assert_eq!((r.status, r.header("etag")), (200, Some("\"1\"")));
        assert!(r.body == big, "the whole of version 1");
    });
}

/// SYN-02 edge case: a row whose file is missing or cut short (outside
/// damage) gets 500 `server_error`, and the row is not changed.
#[test]
fn syn02_7_missing_file_gets_500_row_unchanged() {
    block_on(async {
        let s = start(Config::default()).await;
        let body = vault_bytes(100, 1);
        assert_eq!(exchange(&s, &put(&s, ID, CREATE, &body)).await.status, 201);
        let file = s.data.0.join("blobs").join(blob_name(&body));
        std::fs::write(&file, &body[..50]).unwrap();
        exchange(&s, &get(&s, ID, ""))
            .await
            .assert_error(500, "server_error");
        std::fs::remove_file(&file).unwrap();
        exchange(&s, &get(&s, ID, ""))
            .await
            .assert_error(500, "server_error");
        let r = exchange(&s, &vault_list(&s)).await;
        let want = format!(r#"{{"vaults":[{{"id":"{ID}","size":101,"version":1}}]}}"#);
        assert_eq!(String::from_utf8(r.body).unwrap(), want);
    });
}

/// T15 (SYN-02.8): many uploads to different vaults at once all succeed
/// on the one writer, with no busy error.
#[test]
fn syn02_8_t15_parallel_uploads_all_succeed() {
    block_on(async {
        let s = start(Config::default()).await;
        let mut tasks = Vec::new();
        for n in 0..20u8 {
            let id = format!("{n:032x}");
            let request = put(&s, &id, CREATE, &vault_bytes(2000, n));
            let mut stream = tls(&s, &version::TLS13).await;
            tasks.push(tokio::spawn(async move {
                stream.write_all(&request).await.unwrap();
                stream.flush().await.unwrap();
                Reply::parse(&read_all(&mut stream).await).status
            }));
        }
        for t in tasks {
            assert_eq!(t.await.unwrap(), 201);
        }
        let count: i64 = store(&s)
            .query_row("SELECT count(*) FROM vaults", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 20);
    });
}

/// SYN-02.8 and SYN-02.6 (F-223): a second server on a data folder that a
/// running server uses is refused before its store opens, so its sweep
/// never deletes the running server's upload; that upload then ends with
/// 201 and is served.
#[test]
fn syn02_8_second_server_on_one_folder_is_refused() {
    block_on(async {
        let s = start(Config::default()).await;
        let body = vault_bytes(100_000, 1);
        let request = put(&s, ID, CREATE, &body);
        let mut stream = all_but_last(&s, &request).await;
        let tmp = s.data.0.join("tmp");
        until_files(&tmp, 1).await;
        let refused = Server::start(&s.data.0, 0, Config::default())
            .await
            .err()
            .expect("the second server started");
        assert_eq!(
            refused.to_string(),
            format!(
                "another server uses {}; this one does not start",
                s.data.0.display()
            )
        );
        assert_eq!(files(&tmp).len(), 1, "the upload's temp file is kept");
        stream
            .write_all(&request[request.len() - 1..])
            .await
            .unwrap();
        stream.flush().await.unwrap();
        assert_eq!(Reply::parse(&read_all(&mut stream).await).status, 201);
        let r = exchange(&s, &get(&s, ID, "")).await;
        assert_eq!((r.status, r.header("etag")), (200, Some("\"1\"")));
        assert!(r.body == body, "the upload's bytes");
    });
}
