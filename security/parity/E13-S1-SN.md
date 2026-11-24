# E13-S1 parity sign-off: Network (SN)

Rows: SN-01 to SN-05 in [plan/security.md](../../plan/security.md). Story: E13-S1.
Date: 2026-10-29. Verify agent, group SN. I did not build any of the network code.

| Row | Result |
|---|---|
| SN-01 | **Verified** on today's tree. Re-run the capture when the update check (E14) or an icon download lands. |
| SN-02 | Waits for a story. Larsal has no icon download yet, and no story in plan/epics.md builds one. The parts that exist were re-checked. |
| SN-03 | **Verified** |
| SN-04 | Waits for Larsal's release feed (E14). Larsal has no update check. The parts that exist were re-checked. |
| SN-05 | **Verified**. A build without the `net` feature has no network code. One Low finding: no build script has a switch for it. |

## How it was run

- **Reference.** I read the reference source read only. I also looked at the installed reference bundle (2.7.11) with `otool -L` and `nm -u`, and ran its command line tool twice (`--help`, `--debug-info`) with a throwaway HOME under /tmp. The reference GUI was never started: every reference capture would need a visible window.
- **Our side.**
  - Private copy: `rsync -a --exclude target --exclude larsal-shots` to `/tmp/e13s1-SN-copy` at 20:42, with its own `target` folder and Xcode derived data in `/tmp/e13s1-SN-xcode`.
  - Builds in the copy: `scripts/build-core.sh` (593 s wall under a load average near 300), then `xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -configuration Debug -destination platform=macOS -derivedDataPath /tmp/e13s1-SN-xcode build`, which printed `** BUILD SUCCEEDED **`.
  - Every cargo test ran in the copy.
- **Probe code**, in the copy only:
  - `crates/larsal-platform/examples/sn_probe.rs`: one GET through the product `Client::new`.
  - one test appended to the copy's `crates/larsal-ffi/src/reports.rs`: `e13s1_sn05_probe_no_net_build`, compiled only without `net`.
  - line 36 of the copy's `scripts/build-core.sh` without `--features net`, for the SN-05 build.
- **Today's tree.** Other agents edited the tree during the run. Afterwards I compared the copy with the project:
  - `crates/larsal-platform/src/net.rs` and `src/net/tests.rs`: identical.
  - `crates/larsal-ffi/src/reports.rs`: identical to the snapshot.
  - `macos/Larsal`: only `Platform/ShownPasswordField.swift` changed, which has no network code.
  - larsal-platform `Cargo.toml`: only its comment changed (the F-068 fix).
  - I re-ran the `cargo tree` checks on the project itself (`--offline --locked`, read only), with the same results.
- **Captures.** Packet capture needs root, so I watched each process instead:
  - `nettop -n -L <n> -s 1 -p <pid>`, one sample a second;
  - `lsof -nP -a -i -p <pid>`, every 0.2 s;
  - `pgrep -P` for child processes.
  - Each process was started stopped (`sh -c 'kill -STOP $$; exec …'`), the watcher was attached, then the process got `kill -CONT`. So each watch covers the program from its first instruction.
  - A positive control (a Python process that connects to its own 127.0.0.1 listener) was seen.
- **Rule 10.** The Larsal ran only as a hidden debug launch (`LARSAL_TEST_HIDDEN=1`, activation policy prohibited, no window, never active), with a throwaway HOME and instance folder.
- **Rule 11.** Every process I started was ended by its PID: Larsal 37854, 41961 and 90005; control 36317; `openssl s_server` 56172 to 56175 and the second set.
- Nothing left this Mac. Every server listened on 127.0.0.1 only (lsof below), and no keychain or trust setting was touched.
- CPU: the two core builds, two Xcode builds and four test builds took about 20 minutes of wall time in all.

## SN-01 No network connection until the user acts

**Reference (source).**
- The update check runs only when the update build option is on.
- On the first start, a question asks whether to check for updates at start-up, with Yes as the default button. The answer is stored with a "question shown" flag.
- After that, a check starts 0.5 s after start-up and on an hourly timer. Each time, it only sends when the setting is on and the stored next-check time has passed.
- The breach check's requests start only from the report page's button.
- Icon downloads start only from the entry editor's button, the "selected entries" and "whole group" actions, or a browser save that asks for the icon.

**Larsal.**
- The only code that can open an internet connection is larsal-platform `net.rs`.
  - Its one product user is larsal-ffi `reports.rs`: `Net::new` is called only from `breach_start` (`reports.rs:871`).
  - The Swift caller of `breachStart` is only `ReportsModel.startBreach` (`ReportsModel.swift:123`). Its only caller is the "Check passwords online" button (`ReportsView.swift:243`).
  - `get_icon` has no caller outside its tests.
  - No Swift file uses `URLSession`, `NWConnection`, `URLRequest`, `CFStream`, `SocketPort`, the Network framework or `AsyncImage`. `import` lines name only LarsalCore, AppKit, Carbon.HIToolbox, CoreText, Darwin, Dispatch, Foundation, Observation, ServiceManagement, SwiftUI, UniformTypeIdentifiers and os.
  - Rust's `std::net` is used only for an `Ipv6Addr` parse (`larsal-core/src/url.rs:420`) and a Unix socket `Shutdown` (`larsal-sshagent/src/server.rs:322`).
- There is no update check. `update.check` and `update.include_beta` default to off (`app01_2_app_defaults`). The settings switches are disabled with "Update checks come with Larsal's release feed (E14). Nothing is sent until then." The menu item "Check for Updates…" is disabled. There is no first-start question (D-01-2, LD-200).
- There is no icon download, and `icons.download` defaults to off. The editor's "Website logo" uses the logo set that ships with Larsal.

**Commands and output.**

The positive control, then the hidden debug Larsal as the product builds it (core with `--features net`) on a first start (empty HOME, no arguments, 25 s):

```
control pid=36317 alive_at_end=no lsof_samples=37 samples_with_inet_socket=32 max_inet_sockets=3 nettop_socket_rows=32 nettop: 14 summary rows, bytes_in 60, bytes_out 60 children:[]
larsal-first-start pid=37854 alive_at_end=yes lsof_samples=72 samples_with_inet_socket=0 max_inet_sockets=0 nettop_socket_rows=0 nettop: 0 summary rows, bytes_in 0, bytes_out 0 children:[]
```

The first start wrote only `app.larsal.desktop-debug.sock`, `.lock`, `settings/settings_debug.json` (`{}`, so every default) and `settings/state_debug.json` in the private instance folder. It wrote nothing in HOME.

The same Larsal started with a copy of `testdata/option-a-personal.larsalvault` and `--pw-stdin`, with the demo password on stdin, watched for 30 s. This starts the unlock at once (APP-06.24). The state file then lists the vault as last active, open and recent.

```
larsal-unlocked pid=41961 alive_at_end=yes lsof_samples=65 samples_with_inet_socket=0 max_inet_sockets=0 nettop_socket_rows=0 nettop: 0 summary rows, bytes_in 0, bytes_out 0 children:[]
```

Tests (copy, `cargo test --offline -p larsal-ffi --features net --lib -- reports::tests larsal_settings::tests::app01_2_app_defaults`):

```
test reports::tests::fea_06_01_nothing_is_sent_before_the_press ... ok
test reports::tests::fea_06_11_nothing_to_check_sends_nothing ... ok
test larsal_settings::tests::app01_2_app_defaults ... ok
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 91 filtered out
```

From `cargo test --offline -p larsal-platform --features net`: `sn01_nothing_runs_until_asked ... ok`. Making a `Client` opens nothing.

The command line tool has no network code at all. On today's tree, `cargo tree --offline --locked -p larsal-cli -e normal | grep -ciE 'ureq|rustls|ring v|webpki|security-framework|rcgen|hyper|reqwest|native-tls|openssl|curl'` printed `0`. The reference's command line tool links its toolkit's network library (`otool -L`), even though it has no network command.

**Result: verified.** Larsal is at least as strict as the reference: the reference asks with Yes preselected, and Larsal has no update check. The one network feature that exists starts only on the user's press.

Open: this capture must be repeated when the update check (APP-01.19 e) or an icon download (APP-01.21 d) is built. A capture of a real check after the press reaches the outside service, so it needs the owner's go (rule 7). It is on E5-S7's Mac QA list.

## SN-02 Website icons

**Reference (source).**
- Downloads start only on request: the editor button, selected entries, a whole group, or a browser save that asks for the icon.
- The address is built like this:
  - with no scheme, https is used;
  - other schemes than http and https are dropped;
  - the query and fragment are dropped.
- With the privacy option on (off by default), the outside icon service is tried first for the full host, then for the base domain.
- Then the site's own `favicon.ico` paths are tried: next to the entry's path, at the root, then at the base domain. The user name, password and port written in the URL are kept on all but the last try.
- The time limit is 10 s by default, and covers the whole attempt.
- The app's own loop follows at most 5 redirects for each address. In the source (new toolkit), the toolkit already follows redirects, so that loop never sees one.
- The installed 2.7.11 imports no redirect-policy call (`nm -u`: only `get`, `setRawHeader`, `attribute`, `url`, `error`). The row's claim "installed 2.7.11: unlimited" therefore still needs the network capture. That capture needs the reference GUI, so it needs the owner's go.

**Larsal.**
- There is no download. `get_icon` has no product caller, and no story in plan/epics.md builds MOD-06.11, APP-01.21 or the browser's icon request. E6-S7 says "callers come with … MOD-06 icons", but no story owns them.
- The parts that exist hold:
  - `icons.download` (S-ENTRY-11) defaults to off;
  - `get_icon` takes http or https only and refuses any user name or password in the URL;
  - no redirect is ever followed, since a 3xx is an error (E6-S7);
  - the decoder takes only PNG and ICO (LD-109, so not JPEG as the row text says), with the 16 MiB and 4,096-pixel limits, and re-encodes as PNG.

**Commands and output** (copy):

```
cargo test --offline -p larsal-platform --features net
test net::tests::sn03_http_only_for_icons ... ok
test net::tests::redirect_not_followed ... ok
cargo test --offline -p larsal-core --test mod06
test mod_06_7_formats_and_limits ... ok
test mod_06_11_downloads ... ok
test mod_06_19_hostile_images ... ok
test mod_06_hostile_set_never_panics ... ok
test result: ok. 24 passed; 0 failed
```

**Result: waits for a story.** The row cannot be proven until the download exists, or until the lead rules that this release has no icon download. In that case the row would read "Larsal has no icon download", which is stricter than the reference.

Two notes:
- The row text says PNG, JPEG and ICO. LD-109 narrowed this to PNG and ICO.
- The row's 2.7.11 redirect claim does not match a static reading of the installed binary (see above).

## SN-03 TLS with certificate checks; plain http only for icons

**Reference.**
- Every request goes through its toolkit's network manager, and the source has no TLS error handler at all: no `ignoreSslErrors`, no `sslErrors` slot, no TLS configuration and no peer-verify setting. So certificate errors always fail the request.
- The breach and update addresses are https constants.
- An icon fetch uses http when the entry URL does.
- The installed 2.7.11 bundles its toolkit's network library with OpenSSL 3 (`libssl.3.dylib`, `libcrypto.3.dylib`). `nm -u` on its main binary finds no `ignoreSslErrors`, `sslErrors`, `QSslConfiguration` or `setPeerVerifyMode` import.

**Larsal.**
- TLS 1.2 and 1.3 come from rustls. Every certificate is checked by macOS trust evaluation (Security.framework, through rustls-platform-verifier). `Client::new` adds no extra root.
- `get` takes https only, and `get_icon` takes https or http.
- The breach address is `https://api.pwnedpasswords.com/range/` (`larsal-core/src/breach.rs:26`).
- There is no switch to skip certificate checks. The rustls `dangerous()` call at `net.rs:256` is how rustls installs any verifier, here the platform one.

**Commands and output.**

The in-tree tests (copy, `cargo test --offline -p larsal-platform --features net`):

```
test net::tests::sn03_good_certificate_from_test_anchor_works ... ok
test net::tests::sn03_bad_certificates_refused ... ok
test net::tests::sn03_http_only_for_icons ... ok
test result: ok. 34 passed; 0 failed; 7 ignored
test sn01_nothing_runs_until_asked ... ok
test result: ok. 1 passed; 0 failed
```

An independent probe through the product client (`sn_probe`, `Client::new(Timeouts::default())`, no test anchor):
- The certificates were made today with OpenSSL 4.0.3, P-256:
  - "good": 127.0.0.1 and localhost, under a demo root that only this folder knows;
  - "selfsigned";
  - "expired": 2020 to 2021, under the demo root;
  - "wronghost": `other.example`, under the demo root.
- Each one was served by `openssl s_server -accept 127.0.0.1:<port> -www`.

```
--- listeners:
openssl 56172 127.0.0.1:47811
openssl 56173 127.0.0.1:47812
openssl 56174 127.0.0.1:47813
openssl 56175 127.0.0.1:47814
https://127.0.0.1:47811/hello: refused: the server's certificate was refused: it is not issued by an authority this Mac trusts
https://127.0.0.1:47811/favicon.ico: refused: the server's certificate was refused: it is not issued by an authority this Mac trusts
https://127.0.0.1:47812/hello: refused: the server's certificate was refused: it is not issued by an authority this Mac trusts
https://127.0.0.1:47813/hello: refused: the server's certificate was refused: it is not issued by an authority this Mac trusts
https://127.0.0.1:47814/hello: refused: the server's certificate was refused: it is not issued by an authority this Mac trusts
https://localhost:47811/hello: refused: the server's certificate was refused: it is not issued by an authority this Mac trusts
http://127.0.0.1:47811/hello: refused: the address is not allowed
--- an s_client control on the good server (the server does answer HTTP):
HTTP/1.0 200 ok
```

The icon calls (`get_icon`) to the self-signed, expired and wrong-host servers were refused with the same words.

Each server's own count from the first run, after the probe's two tries:

```
   2 server accepts (SSL_accept())
   0 server accepts that finished
```

So no handshake finished, and no HTTP request could have been sent. The control `s_client` trusts the demo root, completes the handshake and gets the page. So the servers work, and only Larsal's checks refused them.

**Result: verified.** Like the reference, Larsal never ignores a certificate error, and it uses the Mac's trust settings for roots. It is stricter in three ways: TLS 1.2 or newer only, and redirects and proxies are ignored (E6-S7). Plain http is reachable only through the icon call, as in the reference.

## SN-04 Update checks

**Reference (source).**
- The first-start question has Yes as the default.
- Then the check runs at start-up after 0.5 s and on an hourly timer. It sends only when the setting is on and the stored next-check time has passed. That time is set 7 days ahead after each successful answer.
- A manual check in the menu ignores the time.
- The beta option asks for the full release list instead of the latest release.
- One GET with `Accept: application/json` goes to the project's public release feed, over https.
- A separate build option leaves the update check out, and it is forced off when networking is off.

**Larsal.**
- There is no update check, by design until Larsal's release feed exists (D-01-2, LD-200: off and no question; the manual check always there).
- `update.check` and `update.include_beta` default to off (`app01_2_app_defaults ... ok`).
- The switches and the menu item are disabled (`LarsalSettingsPages.swift:37-42`, `LarsalCommands.swift:66`).
- No code builds an update request: the only `Client` is made in `reports.rs:275`.
- The first-start capture above shows no connection.

**Result: waits for Larsal's release feed (E14).** No E14 story names the update check yet. At that time, check APP-01.19 a to f, including a 2-hour capture of a fresh install (APP-01.19 e).

## SN-05 A build with no network code

**Reference (source).**
- A build option leaves out every part that reaches outside networks (on by default). It removes the breach, update and icon code and their dialogs.
- With the option off, the breach report page shows a page saying the build has no networking, instead of the button.
- A second build option covers the update check, and is turned off with the first.

**Larsal.**
- larsal-ffi has the cargo feature `net` (off by default), which is the only way larsal-platform `net` gets in.
- `scripts/build-core.sh:36` turns it on for the Mac app (LD-208 (1): "SN-05 … stays a build option"). The `larsal` command line tool never has it.
- Without it, `Net::get` answers "this build of Larsal has no network code".

**Commands and output.**

On today's tree:

```
cargo tree --offline --locked -p larsal-ffi -e normal | grep -ciE '<network crates>'                 -> 0
cargo tree --offline --locked -p larsal-ffi --features net -e normal | grep -ciE '<network crates>'  -> 13
cargo tree --offline --locked --workspace -e normal -i ureq
error: package ID specification `ureq` did not match any packages
```

The 13 are ureq, ureq-proto, rustls, rustls-pki-types, rustls-webpki, rustls-platform-verifier, ring, security-framework and security-framework-sys, some listed twice.

I built the Mac app twice in the copy: as the product builds it, and with line 36 of `build-core.sh` without `--features net`. For the second build, the core took 85 s and Xcode 46 s, and printed `** BUILD SUCCEEDED **`. The symbol match is case-sensitive, `ureq|rustls|webpki|ring_core|rcgen|platform_verifier`. A case-blind match also counts 70 Swift mangled names that contain "ureQ".

| Binary | Symbols | Network crate symbols | `_SecTrust*` imports |
|---|---|---|---|
| Larsal, core with `net` | 330,266 | 9,430 | 15 |
| Larsal, core without `net` | 292,597 | 0 | 0 |
| `liblarsal_ffi.a` with `net` | 132,282 | 8,537 | |
| `liblarsal_ffi.a` without `net` | 102,733 | 0 | |

- `strings -a | grep -ciE 'rustls|ureq'` printed `0` for the no-net Larsal.
- The no-net core's dep-info (`liblarsal_ffi.d`) lists 13 larsal-platform sources and no `net.rs`.
- The no-net Larsal holds the text "this build of Larsal has no network code", and the net Larsal does not.

The no-net Larsal on a first start with the demo vault unlocked from stdin, 30 s:

```
larsal-nonet-unlocked pid=90005 alive_at_end=yes lsof_samples=77 samples_with_inet_socket=0 max_inet_sockets=0 nettop_socket_rows=0 nettop: 0 summary rows, bytes_in 0, bytes_out 0 children:[]
```

The probe test (copy, without `net`, `cargo test --offline -p larsal-ffi --lib -- reports::tests::e13s1_sn05_probe_no_net_build reports::tests::fea_06_01 --nocapture`):

```
start BreachProgress { done: 0, total: 20, finished: false }
step BreachProgress { done: 0, total: 20, finished: true }
error Some("The online check stopped early: this build of Larsal has no network code")
test reports::tests::e13s1_sn05_probe_no_net_build ... ok
test reports::tests::fea_06_01_nothing_is_sent_before_the_press ... ok
test result: ok. 2 passed; 0 failed
```

**Result: verified.** Larsal can be built with no network code at all, and the result runs and sends nothing.

Low finding: no build script has a switch for this. `build-core.sh:36` and `scripts/repro-build.sh:49` both hard-code `--features net`, and no document says how to leave it out, so a packager must edit a script. The reference's option is one documented build flag. Also, the no-net Larsal still shows "Check passwords online", and answers the press with that error. The reference shows a page instead.

Smallest fix: a `--no-net` argument in `build-core.sh` (and `repro-build.sh`) that drops `--features net`, and one README line. Optionally, an FFI flag so the breach page can say that this build has no network code.

## Open items

1. SN-02 has no owning story: icon download from the editor, selected entries, a group, and the browser's save (MOD-06.11, APP-01.21, LD-64). Either the lead adds a story, or rules that the first release has none.
2. SN-04 waits for Larsal's release feed. No E14 story names the update check yet.
3. SN-05 build switch (Low, above).
4. A side note for the settings page: the update row's subtitle says "Asks GitHub once a week. Nothing else leaves this Mac." The breach check also leaves the Mac when pressed, and the feed is to be chosen in E14 (D-01-2).
5. The reference captures of SN-02 (redirects in 2.7.11) and a capture of Larsal's real breach check after the press need the owner's go: a visible reference window, and traffic to an outside service.

## Clean-up

`/tmp/e13s1-SN-copy`, `/tmp/e13s1-SN-xcode`, `/tmp/e13s1-SN-work` and `/tmp/e13s1-SN-refhome` were deleted at the end. No process of mine is left.
