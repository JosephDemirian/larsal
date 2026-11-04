# E5-S1 Tauri shell, part 1: shell security (AT-E04, AT-E05, AT-E08)

**Superseded 2026-10-28** by [E5-S1-to-E5-S4.md](E5-S1-to-E5-S4.md). Everything below proves the withdrawn Tauri shell (LD-150 to LD-154, withdrawn by LD-155 and LD-156): AT-E04 and AT-E05 are retired, and AT-E08 was re-run on the native app. Kept for history only.

Story: E5-S1 Tauri shell. Part 1 covers shell security only. The single-instance part is reworked to card APP-09 and verified later.
Date: 2026-10-27.
Role: Verify (no reference access needed; none used).
Result: **not signed.**
- AT-E05 and AT-E08 are proven.
- AT-E04 fails: F-054 (Medium). Tauri adds a nonce to every `<script src="http…">` in Larsal's own HTML, so a remote script in `ui/` runs despite `script-src 'self'`.
- F-055 (Low): `<link rel=preconnect>` opens a TCP connection that the policy cannot stop.
- The fix for F-054 was tried in a /tmp copy and works (see F-054 below).
- The screenshot is parked for the owner (macOS Screen Recording permission). It moves to E5-S12 Mac QA.

## Setup

- Real build: `target/release/larsal-desktop` and `target/debug/larsal-desktop` in the project. `cargo build -p larsal-desktop --release` printed `Finished ... in 0.45s`, so the binary matched the sources. No file in `crates/larsal-desktop`, `ui`, `Cargo.toml` or `Cargo.lock` was newer than it.
- Hostile and probe builds: a copy made with `rsync -a --exclude target` to `/tmp/verify-e5s1/ws`, with the build cache cloned in (`cp -c -R`). Only `larsal-desktop` recompiled.
- The probe is a `setup` hook added to the copy's `src/main.rs`. It only reads, and it prints:
  - the served policy, from `app.asset_resolver().get("index.html").csp_header`;
  - the WKWebView's `isInspectable`;
  - the preference `_developerExtrasEnabled`;
  - `websiteDataStore.isPersistent`;
  - after 4 s, the footer text, which `app.js` fills through the `larsal_info` command.
- I chose the probe over a debugger because Developer mode is off on this Mac (`DevToolsSecurity -status`), so attaching a debugger would show an authorization prompt.
- No product file was changed. Files written: this file and two rows in `security/findings.md`. All /tmp copies have been removed.

## AT-E08 Local listeners: proven

The real release binary was started, given 8 s, inspected, then stopped (script `e08.sh`). Its WebKit helpers are the three WebKit processes that appeared after launch, with parent launchd:

```
app pid 33713 alive: yes
== new WebKit helpers since launch:
33780  1 Tue Oct 27 14:34:22 2026  .../com.apple.WebKit.GPU.xpc/Contents/MacOS/com.apple.WebKit.GPU
33781  1 Tue Oct 27 14:34:22 2026  .../com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking
33782  1 Tue Oct 27 14:34:22 2026  .../com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent
== lsof -nP -p <pid>, counted:
pid 33713 (larsal-desktop): fds=54 IPv4=0 IPv6=0 TCP=0 UDP=0 LISTEN=0 unix=1
larsal-deskt 33713 josephilhan    4u  unix 0xa12bcaa28f0fedc5  0t0  ->0xa76f71f3e7a72a82
pid 33780 (com.apple.WebKit.GPU): fds=22 IPv4=0 IPv6=0 TCP=0 UDP=0 LISTEN=0 unix=0
pid 33781 (com.apple.WebKit.Networking): fds=13 IPv4=0 IPv6=0 TCP=0 UDP=0 LISTEN=0 unix=0
pid 33782 (com.apple.WebKit.WebContent): fds=18 IPv4=0 IPv6=0 TCP=0 UDP=0 LISTEN=0 unix=0
== lsof -nP -a -i -p 33713,33780,33781,33782:
(empty)
== netstat -anv -p tcp | grep LISTEN: before 31 lines, after 31 lines
== new TCP LISTEN addresses (diff before/after): (none)
== netstat tcp LISTEN lines naming larsal-desktop or these pids: (none)
== netstat -anv -p udp lines naming larsal-desktop or these pids: (none)
```

The only Unix socket is the app's fd 4. It is a datagram socket with no address of its own, connected to the system log socket. It does not listen:

```
netstat -anv -f unix (app):  a12bcaa28f0fedc5 dgram ... conn a76f71f3e7a72a82 ... larsal-desktop:33713
netstat -anv -f unix (peer): a76f71f3e7a72a82 dgram ... logd:334 ... /private//var/run/syslog
```

- Other processes (`loginwindow`, `distnoted`, ...) hold the same kind of connection to that peer.
- The WebKit helpers have no Unix sockets: they talk over XPC.
- Result: no listener of any kind, and no TCP or UDP socket.
- Note for APP-09: APP-09.14 will add one Unix socket listener (mode 0600, with a same-user peer check). It will be the only listener allowed, and no TCP or UDP socket ever is. This check must be re-run when that is built.

## AT-E05 Developer tools: proven

1. No `devtools` feature anywhere in the build:

```
cargo tree -p larsal-desktop -e features,normal --target aarch64-apple-darwin --prefix none | grep -c '"devtools"'   -> 0
cargo tree -p larsal-desktop -e features,normal --target all --prefix none | grep -c '"devtools"'                   -> 0
cargo tree -p larsal-desktop -e features --target all --prefix none | grep -c devtools                              -> 0
tauri features on: custom-protocol, wry (plus the runtime crate links)
```

2. The inspector code is in the debug binary only:

| `strings <binary> \| grep -c` | release | debug |
|---|---|---|
| `developerExtrasEnabled` | 0 | 1 |
| `setInspectable` | 0 | 1 |

3. The WebKit inspectable flag is off in a release build. Probe output in the release profile, with the real `ui/` and `tauri.conf.json`:

```
PROBE isInspectable=false (selector true); developerExtrasEnabled=false (selector true); websiteDataStore.isPersistent=false
```

The same probe in a debug build reads `true`, which shows the probe can see the flag when it is set:

```
PROBE isInspectable=true (selector true); developerExtrasEnabled=true (selector true); websiteDataStore.isPersistent=false
```

Safari's Develop menu lists only web views whose `isInspectable` is true, or apps that may be debugged. Neither holds for the release build:
- the binary is linked against SDK 26.2 (`otool -l`: `minos 11.0`, `sdk 26.2`). On SDKs 13.3 and later, `isInspectable` defaults to false, and nothing in the release binary sets it.
- the signature is `adhoc,linker-signed` with no entitlements, so there is no `get-task-allow`.

The probe binary itself contains the text `developerExtrasEnabled` twice. Those are the probe's own read-only selector names, not wry's.

4. The inspector command is refused: `cargo test -p larsal-desktop` → `tests/shell.rs` `only_granted_commands_run ... ok` (it asserts that `plugin:webview|internal_toggle_devtools` is "not allowed"), and `unlisted_command_is_refused ... ok`.

## AT-E04 Remote content: fails (F-054); F-055 noted

### The served policy of the real build

- The release binary holds the configured policy as one string: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src ipc:; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'`.
- It also holds three `'sha256-…'` values, equal to `openssl dgst -sha256 -binary | base64` of `ui/icons.js` (`aoEl…`), `ui/app.js` (`uHcP…`) and `ui/api.js` (`w5/h…`). There is none for `styles.css`.
- The asset resolver's view for the real `ui/index.html` (probe, release):

```
font-src 'self'; default-src 'none'; form-action 'none'; connect-src ipc:; frame-src 'none'; style-src 'self';
script-src 'self' 'sha256-aoEleELdh+bZ47juBOpXmV+Bid4Nv3iVnOrywckGZ9Q=' 'sha256-uHcPQjZxraELLGn2dCNs/gSLkcWAiVsm0BI2tRU9Klo=' 'sha256-w5/hTq0IT3x37yxaalH/CFWmBkZ7xDNy79xRr+NbPYA=';
img-src 'self'; object-src 'none'; base-uri 'none'
```

The real page has no remote script and no `<style>` element, so it gets no nonce today.

### The hostile page (/tmp copy only)

Remote targets: a raw TCP logger (`logger.py`). It records every accepted connection and the first request line, on `127.0.0.1:8765`, `127.0.0.1:8766` and `[::1]:8766`. Later runs added `127.0.0.1:8767` and `127.0.0.1:8768`. The page refers to them as `http://127.0.0.1:8765` and `http://localhost:8766`, so `'self'` (`tauri://localhost`) can never match.

- `index.html`:
  - `<base href>` to the logger, plus one image with a relative URL;
  - remote `<link rel=stylesheet>` ×2, `prefetch`, `preload` (font and script), `preconnect`, `icon` and `manifest`;
  - remote `<script>` and `<script type=module>`;
  - inline `<style>@import …>` and a `style=` attribute with `url()`;
  - `<img>`, `srcset`, SVG `<image>`;
  - `<iframe>` ×2, `<object>`, `<embed>`;
  - `<video>` (with `poster`) and `<audio>`;
  - a `<form action=remote>`, submitted by script after 4 s.
- `app.js`: the real code, then:
  - `fetch` (cors and no-cors), `XMLHttpRequest`;
  - `WebSocket` ×2, `EventSource`, `sendBeacon`;
  - `new Image`, a created `<script>`, `import()`, `new Worker`, `FontFace.load`;
  - a created `<iframe>` and `<link>` (stylesheet, prefetch, preconnect).
- `styles.css`: `@import`, `@font-face` (used by a paragraph), `background-image`, `cursor`, `list-style-image` and `content: url()`.

Each app run lasted 10 s, then the app and the logger were stopped (`run-e04.sh`).

| Run | Build | Served policy (probe) | Logger |
|---|---|---|---|
| 1 | release, real `tauri.conf.json`, hostile `ui/` | `script-src 'self' 'nonce-9437591810200281659' 'nonce-4310933755286786723' 'sha256-…'×3`; `style-src 'self' 'nonce-13075250725152740845'` | **3 connections** (below) |
| 2 | release, plus `"dangerousDisableAssetCspModification": true` (the F-054 fix); preconnects moved to ports 8767 (HTML) and 8768 (script) | exactly the configured string, no nonce, no hash | **0 requests**; 2 connections that sent nothing (preconnect, F-055) |
| control A | release, same hostile page, `"csp": null` | none | **40 connections** |
| control B | `curl` of 3 hostile URLs | n/a | 3 requests |

Run 1 logger:

```
14:38:35 127.0.0.1:8765 from 127.0.0.1:59573 GET /html-script.js HTTP/1.1
14:38:35 127.0.0.1:8766 from 127.0.0.1:59574 GET /html-module.js HTTP/1.1
14:38:37 127.0.0.1:8766 from 127.0.0.1:59572 <no data: timeout>
```

Run 2 logger, and Larsal's own code still working under the fixed policy:

```
14:40:59 127.0.0.1:8767 from 127.0.0.1:59704 <no data: timeout>      (HTML <link rel=preconnect>)
14:41:00 127.0.0.1:8768 from 127.0.0.1:59705 <no data: timeout>      (preconnect <link> made by app.js)
PROBE page title after eval: FOOTER:Larsal 0.1.0                        (app.js ran; larsal_info answered over IPC)
```

Control A logged each of these, so the zero in run 2 comes from the policy and not from WebKit or Larsal Transport Security:
- `html-script.js`, `html-module.js`, `html-preload-script.js`, `js-script.js`, `js-import.js`;
- `html-stylesheet.css`, `html-stylesheet-2.css`, `html-inline-style-import.css`, `css-import.css`, `js-stylesheet.css`;
- `html-img.png`, `base/html-img-via-base.png`, `html-srcset.png`, `html-svg-image.png`, `html-style-attr.png`, `html-poster.png`, `js-image.png`, `css-cursor.png`, `css-list.png`, `css-content.png`;
- `css-font.woff2`, `js-font.woff2`, `html-preload-font.woff2`;
- `html-iframe.html`, `html-iframe-2.html`, `js-iframe.html`;
- `html-video.mp4`, `html-audio.mp3`, `html-manifest.json`;
- `js-fetch`, `js-fetch-no-cors`, `js-xhr`, `js-websocket`, `js-websocket-2`, `js-eventsource`, `js-beacon`;
- `html-form-submit`;
- the two preconnects.

Six loads were not seen even with no policy, so the zero says nothing about them:
- `prefetch` (HTML and script), the `icon` link, `<object>`, `<embed>`: WebKit does not fetch these in this setup;
- `new Worker` to another origin: always refused;
- `css-background.png`: overridden by the page's own `style=` attribute.

Control B (`curl`) logged `GET /html-script.js`, `GET /css-font.woff2` and `GET /html-iframe-2.html`, so the logger itself records requests.

## Web data on disk (LD-152 (5), incognito)

After the AT-E08 run of the real release build, these are all absent:
- `~/Library/WebKit/larsal-desktop`, `~/Library/Caches/larsal-desktop`, `~/Library/HTTPStorages/larsal-desktop`;
- `~/Library/WebKit/app.larsal.desktop`, `~/Library/Caches/app.larsal.desktop`.

A `find -maxdepth 2 -newer <marker>` over `~/Library/WebKit`, `Caches`, `HTTPStorages`, `Saved Application State`, `Preferences` and `Application Support` found nothing named for Larsal.

`~/Library/Application Support/Larsal` holds only `instance.lock` (mode 0600, 0 bytes). The probe reads `websiteDataStore.isPersistent=false` in both release and debug.

## Tests

`cargo test -p larsal-desktop`: 10 passed, 0 failed.
- `instance::tests::a_second_lock_is_refused_until_the_first_is_released`
- the 7 tests in `tests/messages.rs`
- `tests/shell.rs`: `only_granted_commands_run`, `unlisted_command_is_refused`

`check.sh` was not re-run (it passed earlier today, and no product file has changed since).

## Findings and fixes

**F-054 (Medium, blocks AT-E04): Tauri gives Larsal's own remote script tags a nonce.**
- tauri-codegen 2.7.4 (`context.rs` `map_core_assets`) calls tauri-utils 2.10.2 `html.rs` `inject_nonce_token`. That function adds `nonce` to every `script[src^='http']` and every `<style>` in Larsal's HTML.
- At serve time, tauri 2.12.5 `manager/mod.rs` `set_csp` replaces each token with a fresh random nonce and adds it to `script-src` or `style-src`.
- So a `<script src="http://…">` written into `ui/*.html` (by mistake, or by a hostile change to `ui/`) runs, although the policy says `script-src 'self'`. Run 1 above shows it.
- Fix (tried in the copy, run 2): add `"dangerousDisableAssetCspModification": true` to `app.security` in `crates/larsal-desktop/tauri.conf.json`.
  - The served policy becomes exactly the configured string. Larsal's scripts are external files under `'self'`, so they still run (footer `Larsal 0.1.0`).
  - Tauri's own scripts are WebKit page scripts, which the policy does not cover, so nothing else changes.
- After the fix:
  - COMMANDS.md: replace the sentence about the added `'sha256-…'` hashes with "no hash, no nonce: Tauri may not change the policy".
  - Add an LD entry: the flag is a Tauri option that tightens the policy here. LD-151 (2) covers features, not config, so it needs no change.
  - Re-run AT-E04 run 1. Pass: 0 requests.

**F-055 (Low): `<link rel=preconnect>` opens a TCP connection; WebKit's policy has no directive for it.**
- Both the HTML link and a link made by script connected to their host and sent nothing (run 2).
- It needs Larsal-authored markup or script, which `script-src` and Larsal's text-only rule already restrict. Even so, it is a way to reach a remote host: an IP connection, and a DNS lookup for named hosts.
- Fix: a check in `scripts/check.sh` that fails when a file in `ui/` contains:
  - `preconnect`, `dns-prefetch` or `prefetch`;
  - or a URL with `http:`, `https:`, `ws:`, `wss:` or `//host`. The SVG namespace string in `icons.js` is allowed by exact match.
- Also add a line to the `ui/app.js` header rule: script never creates `<link>` elements.

## CPU used

About 8 minutes of CPU in total. No run kept the CPU busy for more than about 3 minutes.
- Release builds of the copy: 4 × about 28 s (27.9, 28.1, 27.3, 29.4 s user).
- Debug probe build: about 2 to 3 min. Not measured exactly: its timing line was cut from the output.
- `cargo test -p larsal-desktop`: 179.8 s user and 7.0 s sys (the test build).
- Larsal runs: about 0.2 s CPU each (`ps -o time`).
