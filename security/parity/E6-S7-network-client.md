# E6-S7 Network client for opt-in features (SN-01 to SN-05)

Story: E6-S7 Network client for opt-in features. Decisions: LD-194 (TLS stack), LD-197 (AT-J03 for its crates).
Date: 2026-10-28.
Role: Verify. I did not build or review this story. No reference access was needed, and none was used.
Result: **signed.**

The story's checks are "network capture on first start shows no traffic" and "a bad certificate is refused". Both pass:

- **First start:** a hidden debug App and the release `app` tool were each watched for 20 s from their first instruction. Neither had an internet socket. Neither links the network client.
- **Certificates:** the product client refused every local certificate. With the demo root trusted in memory only, the good leaf and a good chain worked. Self-signed, expired, not yet valid, wrong host and untrusted chain were refused with plain words, before any HTTP byte was sent.
- **The rest:** TLS 1.0 and 1.1 servers are refused, and 1.2 and 1.3 work. SNI is sent. Redirects, cookies and proxy variables are ignored. Size and time limits hold, including the handshake budget. The AT-J03 conditions checked here hold. `cargo test -p app-platform --features net` passes.

Nothing reached the internet. Every server listened on 127.0.0.1 only (`lsof` shows each listener's address). No root was added to any keychain, and I ran no keychain command. App's trust evaluation reads the system trust settings, as designed. No window was opened.

## Setup

- **Sources.** Rust tests and the cargo checks ran in the project with `CARGO_TARGET_DIR=/tmp/v-e6s7-target`.
- **Copy for the app builds.** `scripts/build-core.sh` writes into the source tree, so the app builds ran in a copy. It was made with `rsync -a --exclude target` to `/tmp/v-e6s7-src`, and its `target` links to `/tmp/v-e6s7-target`. `diff -rq` printed `crates identical`, `vendor identical`, `macos identical` and `scripts identical`. `cmp` printed `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml identical`.
- **Builds** (in the copy):
  - `scripts/build-core.sh`, then `xcodebuild -project macos/App.xcodeproj -scheme App -configuration Debug -destination platform=macOS -derivedDataPath /tmp/v-e6s7-xcode build`, which printed `** BUILD SUCCEEDED **`.
  - `cargo build --release -p app-cli`, which printed `Finished release profile`.
- **Other stories during the run.** Other stories (E9-S2 and app-ffi work) changed `Cargo.toml`, app-crypto and app-ffi in the project while this run went on.
  - The binaries watched below come from the snapshot.
  - `diff -rq` of `crates/app-platform` against the snapshot printed `app-platform unchanged since snapshot`.
  - The cargo tree check was re-run on the current tree, with the same result.
- **Tools:** cargo and rustc 1.99.1, macOS 26.6, Xcode 27.0, OpenSSL 3.6.4 (`openssl s_server` and `s_client`), and Python 3.9.6 `ssl` (LibreSSL 2.8.3, which has no TLS 1.3).
- **Work files**, all in `/tmp/v-e6s7-work`, with no product code changed:
  - `gen-certs.sh`: demo certificates made with OpenSSL, P-256 and SHA-256, with no AIA or CRL address, so the trust evaluation has nothing to look up online.
  - `servers.py`: eleven Python TLS and plain servers that log SNI, TLS version and every request head.
  - `watch.sh`: the per-process sampler.
  - `driver/`: the Verify driver crate.
- **Driver crate.**
  - It depends on the real `app-platform` (path dependency, `default-features = false, features = ["net"]`) for every product-client case.
  - To reach the test-only anchor path, `src/net.rs` is a copy of app-platform's `net.rs`, compiled only in the driver's tests. `cmp` printed `net.rs copy identical`, and the driver's lock has the same versions as the workspace lock.
  - `src/net/tests.rs` is the Verify code (10 tests).
  - `src/bin/probe.rs` is a release probe over the real `app_platform::net::Client`.
- **Raw packet capture** (`tcpdump`, or `nettop` across all processes with packet detail) needs root, so it was not used. The capture is per process: `nettop -n -L 21 -s 1 -p <pid>` (one sample a second) and `lsof -nP -a -i -p <pid>` (every 0.2 to 0.3 s). Without `-a`, `lsof -i -p` would OR the two filters.

## 1. No traffic on first start (SN-01, SN-05)

**Method.**
- Each process was started stopped: `sh -c 'kill -STOP $$; exec env HOME=<throwaway> ... <binary>'`. The watcher attached to that PID, then the process got `kill -CONT`. So the watch covers the program from its first instruction.
- Each run was ended by its own PID (rule 11).

**Hidden debug App.**
- Started as `HOME=/tmp/v-e6s7-work/home-app APP_TEST_HIDDEN=1 APP_TEST_INSTANCE_DIR=/tmp/v-e6s7-work/inst-app .../Debug/App.app/Contents/MacOS/App`, with an empty HOME, so this is a first start.
- It was still running (`SN`) at the end and was ended with `kill -KILL 86289`.
- It wrote only its instance socket and lock (`com.app.desktop-debug.sock`, `.lock`) in the private folder, and nothing in HOME.

```
app pid=86289 alive_at_end=yes lsof_samples=68 samples_with_inet_socket=0 max_inet_sockets=0 nettop_socket_rows=0 nettop: 0 summary rows, bytes_in 0, bytes_out 0 children:[]
```

**Release `app`.**
- Started as `HOME=/tmp/v-e6s7-work/home-cli /tmp/v-e6s7-target/release/app open demo.appvault`. The vault is a copy of `testdata/password-only.appvault`, and stdin was a FIFO.
- It waited at `Vault password:` for 5 s. Then the FIFO gave `demo-pass-1`, `ls` and `show "Demo login"`, and the entry was printed (password `(hidden)`, URL `https://example.com/login`).
- At the end of the 20 s, `quit` ended it.

```
cli pid=87202 alive_at_end=yes lsof_samples=65 samples_with_inet_socket=0 max_inet_sockets=0 nettop_socket_rows=0 nettop: 0 summary rows, bytes_in 0, bytes_out 0 children:[]
```

Both `nettop` logs hold 21 header lines and 0 other lines.

**Control: the watcher sees traffic when there is some.** The release probe was pointed at the silent local server, where it holds a TLS handshake. The same script saw it:

```
control pid=88741 alive_at_end=yes lsof_samples=11 samples_with_inet_socket=9 max_inet_sockets=1 nettop_socket_rows=6 ...
probe   88741 ... TCP 127.0.0.1:50622->127.0.0.1:50019 (ESTABLISHED)
08:44:37.850372,tcp4 127.0.0.1:50622<->127.0.0.1:50019,lo0,Established,0,218,...
```

**Neither product binary links the network client (SN-05).**
- `cargo tree --offline -p app-ffi -p app-cli -e normal | grep -ciE 'ureq|rustls|ring v|webpki|security-framework|rcgen|hyper|reqwest|native-tls|openssl'` printed `0` (278 lines). It still printed `0` on the current tree after the other stories' changes.
- `cargo tree -p app-ffi -p app-cli -e normal,features -i app-platform` lists the app-platform features `appkit` and `memory` only, never `net`. No manifest enables `net`.
- `cargo tree --workspace -e normal -i ureq` gave `package ID specification 'ureq' did not match any packages`: without `net`, ureq is not in the build graph at all.
- `nm -a` on the binaries:

| Binary | Symbols | Matching `ureq\|rustls\|webpki\|ring_core\|rcgen\|platform_verifier` |
|---|---|---|
| release `app` | 109 | 0 |
| debug `App.app/Contents/MacOS/App` | 185,192 | 0 |
| debug `libapp_ffi.a` | 81,273 | 0 |
| release probe (control, links `net`) | 5,668 | 2,149 |

- The release `app` is stripped (109 symbols), so for it, two more checks:
  - `strings -a | grep -ciE 'rustls|ureq'` printed `0` for `app` and for `App`.
  - The dep-info files `release/app.d` and `debug/libapp_ffi.d` list app-platform's `clipboard.rs hardening.rs instance.rs lib.rs memory.rs mod.rs pasteboard.rs pipe.rs process.rs signals.rs system.rs terminal.rs`, and no `net.rs`.
- No other network code:
  - `grep -rnE "TcpStream|TcpListener|UdpSocket|ToSocketAddrs|getaddrinfo|std::net::" crates` (outside tests and `net.rs`) finds only `app-core/src/url.rs:420`, an `Ipv6Addr` parse.
  - `macos/App` and `macos/AppCore/Sources` have no `URLSession`, `NWConnection`, `NWPathMonitor`, `CFStream`, `SocketPort` or `URLRequest`.
- `tests/net_start.rs` `sn01_nothing_runs_until_asked` passes: making a `Client` opens no file or socket, and the module has no global, thread or start-up hook.

## 2. A bad certificate is refused (SN-03)

**Certificates.**
- The roots are "Verify demo root" and "Verify other demo root", from 2019 to 2028.
- Intermediates: one under each root.
- Leaves, valid from 30 days ago to 300 days ahead unless noted:
  - `good` (IP 127.0.0.1, DNS localhost, under root 1);
  - `chaingood` (under root 1's intermediate; the server sends the leaf and the intermediate);
  - `selfsigned`;
  - `expired` (2020 to 2021, under root 1);
  - `notyet` (from one year ahead);
  - `wronghost` (DNS other.example);
  - `untrusted` (under root 2's intermediate; the server sends the leaf, the intermediate and root 2).
- Root 1 reaches only `Client::with_anchors` (`#[cfg(test)]`), in memory. No keychain was used.

**Product client** (the real `app_platform::net::Client::new`, no test anchor), from `v1_product_client_refuses_every_local_certificate`:

```
product selfsigned: the server's certificate was refused: it is not issued by an authority this Mac trusts
product expired: the server's certificate was refused: it is not issued by an authority this Mac trusts
product notyet: the server's certificate was refused: it is not issued by an authority this Mac trusts
product wronghost: the server's certificate was refused: it is not issued by an authority this Mac trusts
product untrusted: the server's certificate was refused: it is not issued by an authority this Mac trusts
product good: the server's certificate was refused: it is not issued by an authority this Mac trusts
product chaingood: the server's certificate was refused: it is not issued by an authority this Mac trusts
```

**Test-anchor path** (the copy of `net.rs`, root 1 in memory), from `v2_test_anchor_path_good_works_bad_refused`:

```
anchored good: ok "hello"
anchored chaingood: ok "hello"
anchored selfsigned: the server's certificate was refused: it is not issued by an authority this Mac trusts
anchored expired: the server's certificate was refused: it has expired
anchored notyet: the server's certificate was refused: it has expired
anchored wronghost: the server's certificate was refused: it was issued for a different site
anchored untrusted: the server's certificate was refused: it is not issued by an authority this Mac trusts
```

**No HTTP request was ever sent to a bad server.** The server side (LibreSSL) logged these counts:

| Server | Connections | Requests | Server error |
|---|---|---|---|
| selfsigned | 4 | 0 | `SSLV3_ALERT_CERTIFICATE_UNKNOWN` |
| expired | 4 | 0 | `SSLV3_ALERT_CERTIFICATE_UNKNOWN` |
| notyet | 4 | 0 | `SSLV3_ALERT_CERTIFICATE_UNKNOWN` |
| wronghost | 3 | 0 | `SSLV3_ALERT_BAD_CERTIFICATE` |
| untrusted | 3 | 0 | `SSLV3_ALERT_CERTIFICATE_UNKNOWN` |

So the client aborts the handshake with an alert.

**A not-yet-valid certificate is reported as "it has expired".** `v10_raw_macos_reason_for_time_errors` calls the platform verifier directly. It shows that macOS itself returns code -67818 for both cases:

```
expired: raw InvalidCertificate(Other(OtherError("“expired” certificate is expired: -67818"))) -> shown "it has expired"
notyet: raw InvalidCertificate(Other(OtherError("“notyet” certificate is expired: -67818"))) -> shown "it has expired"
```

So the `-67819` ("it is not valid yet") branch of `net.rs` `reason` is not reached on macOS 26.6. The refusal is right, so this is not a failed check. See Open items.

## 3. TLS 1.2 or newer only; SNI

**The servers.** Each `openssl s_server -www -<version> -cipher 'DEFAULT:@SECLEVEL=0'` really speaks its version. `openssl s_client` with the same version printed:
- `Protocol : TLSv1` (tls1 server);
- `Protocol : TLSv1.1` (tls1_1 server);
- `Protocol : TLSv1.2` (tls1_2 server);
- `New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384` (tls1_3 server).

The 1.2-only server refuses a TLS 1.0 client with `alert protocol version`.

**App's client** (anchored, so only the version decides), from `v3_only_tls12_and_newer`:

```
anchored tls1-only server: the connection failed: received fatal alert: ProtocolVersion | Network("received fatal alert: ProtocolVersion")
anchored tls1_1-only server: the connection failed: received fatal alert: ProtocolVersion | Network("received fatal alert: ProtocolVersion")
anchored tls1_2-only server: ok, 4188 bytes, server says "Protocol  : TLSv1.2"
anchored tls1_3-only server: ok, 4269 bytes, server says "Protocol  : TLSv1.3"
```

The Python servers (no TLS 1.3) logged `28 TLSv1.2` handshakes and nothing older.

**SNI** (`v4_sni_sent_for_names`, server `sni_callback`):
- `https://localhost` from the anchored client, then `https://localhost` from the product client (sent, then the certificate was refused);
- then `https://127.0.0.1`, where an IP address is never SNI (RFC 6066 section 3).

```
server saw: ["good sni localhost", "good sni localhost", "good sni None"]
```

## 4. No redirects, no cookies, no proxy, size limits, timeouts

**Redirects** (`v5_redirects_never_followed`). Each call made exactly one request to the server, and the plain server, the other host, logged 0 hits to `/hello-other`.

```
anchored /redirect-same: the server sent a redirect (HTTP 302)
anchored /redirect-other: the server sent a redirect (HTTP 302)        (to http://127.0.0.1:<plain>/hello-other)
anchored /redirect-301-https: the server sent a redirect (HTTP 301)
product get_icon /redirect-same: the server sent a redirect (HTTP 302)
```

**Cookies and headers** (`v6_no_cookies`, then the server log):
- `/cookie` answers with two `Set-Cookie` headers, then `/hello` was asked twice over https and once over plain http.
- The log has 52 request heads: 0 with a `Cookie:` header, and 0 with `Referer`, `Accept-Encoding`, `Accept-Language` or `Authorization`.
- Every head is the same shape:

```
'GET /hello HTTP/1.1\r\nuser-agent: App\r\naccept: */*\r\nhost: 127.0.0.1:50018\r\n\r\n'
```

**Proxy variables ignored.**
- `HTTPS_PROXY`, `https_proxy` and `ALL_PROXY` were all set to the plain server, and the release probe asked the good server.
- The probe printed `refused: the server's certificate was refused: it is not issued by an authority this Mac trusts`. The server log shows `proxy (plain) server new connections: 0; good server new connections: 1`.

**Size limits** (`v7_size_limits`):

```
anchored /size/1000 max 1000: Ok(1000)
anchored /size/1001 max 1000: Err(TooLarge)
anchored /chunked/1000 max 1000: Ok(1000)
anchored /chunked/1001 max 1000: Err(TooLarge)
anchored /size/0 max 0: Ok(0)
anchored /size/1 max 0: Err(TooLarge)
anchored /size/5000000 max 4000000: Err(TooLarge)
product get_icon /size/1001 max 1000: Err(TooLarge)
anchored /404: Err(Status(404))
```

**Timeouts and the handshake budget** (`v8_timeouts_and_handshake_budget`; each must fire at or after its limit and less than 150 ms later). The server setups:
- **silent:** takes the TCP connection and never speaks.
- **trickle:** sends a 16 KiB handshake record header, then one byte every 200 ms. This shows the limit is a deadline, not reset by each read.
- **slow700:** waits 700 ms, then does a normal handshake.
- **slow TCP:** my own 600 ms delay connector before the TLS step, standing in for a slow TCP connect.

```
silent server, connect 500: Err(Timeout) after 502.327542ms (limit 500 ms)
silent server, total 700: Err(Timeout) after 702.278375ms (limit 700 ms)
trickled handshake, connect 800: Err(Timeout) after 802.356791ms (limit 800 ms)
trickled handshake, total 900: Err(Timeout) after 900.709166ms (limit 900 ms)
700 ms handshake, connect 500: Err(Timeout) after 502.35775ms (limit 500 ms)
700 ms handshake, connect 2000: Ok(5) after 715.363625ms
slow TCP 600 + silent, connect 1000: Err(Timeout) after 1.002183792s (limit 1000 ms)
slow TCP 600 + silent, total 900: Err(Timeout) after 902.161125ms (limit 900 ms)
no answer, read 500: Err(Timeout) after 507.930875ms (limit 500 ms)
body 1 byte per 100 ms, total 600: Err(Timeout) after 602.269ms (limit 600 ms)
product get_icon no answer, read 500: Err(Timeout) after 503.692875ms
product defaults: Timeouts { connect: 15s, read: 30s, total: 30s }
```

The slow-TCP cases end at about 1,000 ms and 900 ms, not 1,600 ms and 1,500 ms. So the handshake gets only what is left of the connect and total limits (the Checker 1 item 1 fix).

**Address rules** (`v9_address_rules`, product client). All of these were refused with `the address is not allowed`, and the plain server got no request:
- `http://` through `get`;
- `https://demo:demo-pw@…` and `https://demo@…`;
- `file:///etc/hosts`;
- `ftp://`;
- `http://demo:demo-pw@…` through `get_icon`.

The full driver run printed `test result: ok. 10 passed; 0 failed` in 13.66 s (`--test-threads=1`).

The first driver run had 2 failures, both mine, fixed in the driver only:
- `v6` matched the word "cookie" in the request path `/cookie`, not a header. It now looks for a `\r\ncookie:` header line.
- `v2` expected "it is not valid yet" for the `notyet` leaf. It now expects macOS's own reason, see section 2.

## 5. AT-J03 conditions (LD-197)

**Only `net.rs` uses the crates.**
- `grep -rlE "\b(ureq|rustls|rustls_platform_verifier|rcgen|ring|webpki|security_framework)::" crates fuzz macos` lists only `crates/app-platform/src/net.rs` and its test module `net/tests.rs`.
- Only `crates/app-platform/Cargo.toml` depends on them, with rcgen under `[dev-dependencies]`.
- ring is reached only as `rustls::crypto::ring::default_provider()` (`net.rs:248`).

**Exact pins.** In `Cargo.toml`:
- `ureq = { version = "=3.5.0", default-features = false }`
- `rustls = { version = "=0.23.46", default-features = false, features = ["std", "tls12", "ring"] }`
- `rustls-platform-verifier = "=0.7.1"`
- `rcgen = { version = "=0.14.10", default-features = false, features = ["crypto", "ring"] }`

`Cargo.lock` matches the LD-197 list exactly: ureq 3.5.0, ureq-proto 0.6.5, rustls 0.23.46, rustls-webpki 0.103.16, rustls-pki-types 1.15.1, ring 0.17.14, untrusted 0.9.0, rustls-platform-verifier 0.7.1, security-framework 3.7.0, security-framework-sys 2.17.0, core-foundation 0.10.1, core-foundation-sys 0.8.7, http 1.5.0, httparse 1.10.1, percent-encoding 2.3.2, utf8-zero 0.8.1, rcgen 0.14.10 and yasna 0.6.0.

**Features.** `cargo tree -p app-platform --features net -e features`:
- ureq has no feature at all, so no `rustls`, `native-tls`, `platform-verifier`, `cookies`, `gzip`, `brotli` or `socks-proxy`.
- rustls-platform-verifier has only `default`, so no `ffi-testing`, `dbg` or `cert-logging`.
- rustls has `ring`, `std` and `tls12`.
- `openssl`, `native-tls`, `aws-lc` and `webpki-roots` appear 0 times in the `net` tree.

**The release build has no test-anchor code.**
- `with_anchors` is `#[cfg(test)]` (`net.rs:113`).
- In the release probe over the real crate, `nm | grep -ciE "with_anchors|rcgen|yasna"` printed `0`, and `strings | grep -c "Verify demo root|App test root"` printed `0`.
- `nm -u` shows only the SecTrust calls LD-197 lists (`SecTrustCreateWithCertificates`, `SecTrustEvaluateWithError`, `SecTrustSetAnchorCertificates`, `…Only`, `SecTrustSetOCSPResponse`, `SecTrustSetVerifyDate`), and no `SecItem` or `SecKeychain` call.
- `Client::new` passes an empty root list (`Vec::new()`).

**No logger.** No product crate sets a `log` logger: no `env_logger`, `set_logger`, `set_boxed_logger` or `tracing_subscriber`.

## 6. Tests

`cargo test --offline -p app-platform --features net` printed:

- `test result: ok. 33 passed; 0 failed; 7 ignored` (unit tests, including the 8 `net::tests`: `sn03_good_certificate_from_test_anchor_works`, `sn03_bad_certificates_refused`, `sn03_http_only_for_icons`, `timeouts_fire`, `size_limit_stops_big_body`, `no_cookie_kept_or_sent`, `redirect_not_followed` and `handshake_gets_only_what_is_left`).
- `test result: ok. 1 passed` (`tests/net_start.rs` `sn01_nothing_runs_until_asked`).

The ignored 7 are child-process helpers. The clipboard tests use `Clipboard::private()`, never the general pasteboard.

## Open items (not blocking)

1. **Not-yet-valid wording.** macOS 26.6 reports -67818 (expired) for a certificate that is not valid yet, so App says "it has expired" in both cases, and the `-67819` branch in `reason` is not reached. If a Mac's clock is set too early, every site would show "it has expired". Smallest fix: make the expired text "it has expired or is not valid yet (check this Mac's date and time)".
2. **Callers are not built yet.** These are the breach button (E5-S7), the icon download (MOD-06) and the update check (E14). The SN-01, SN-02 and SN-04 captures during those features come with them, and the security.md rows stay as they are.
3. **Raw packet capture was not run (root needed).** The per-process `nettop` and `lsof` capture stands in for it, with a positive control.

## Processes and clean-up

- Every process I started was stopped by its PID: App 86289, `app` 87202 (ended by `quit`), probe 88741, the Python servers 79646, and `s_server` 79658, 79661, 79664 and 79677.
- `/tmp/v-e6s7-target`, `/tmp/v-e6s7-xcode` and `/tmp/v-e6s7-src` were deleted afterwards. `/tmp/v-e6s7-work` (scripts, certificates, driver source, logs) was kept as evidence.
- CPU: the app and CLI builds took 4 min 13 s wall (925 s user). The other runs took under 20 s each. No run came near 30 minutes.
