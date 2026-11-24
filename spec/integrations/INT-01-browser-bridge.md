# INT-01 Browser bridge protocol

Status: reviewed (LD-189, LD-191); the channel rules INT-01.20 to INT-01.23, INT-01.26, INT-01.28, INT-01.47, INT-01.49 and INT-01.50 rewritten 2026-11-01 for LD-274 (1) (E7-S7a, "Channel rewrite 2026-11-01" below), and E7-S7a's third Spec review found nothing in them; INT-01.8's Chromium and Arc rows and INT-01.30's `disconnect` row, added 2026-11-01 (LD-295 (3)), had E7-S7a's round-4 Spec review; its two fixes here (the overview's browser list, and the "Assoc." sentence in INT-01.30's `disconnect` paragraph) passed the round-5 Spec review; the lead's LD-298 edits (INT-01.30, INT-01.40's rows 1 and 8, line 65) passed the re-read, and E7-S7a's Verify round 4 signed 2026-11-01
Epics: E7-S1 (channel, messages, limits), E7-S6 (manifests, the host program, the Safari route); every other E7 story speaks it: E7-S2 (INT-02), E7-S3 (INT-03), E7-S4 (fill, codes, HTTP sign-in), E7-S5 (INT-04), E7-S7a to E7-S7n (Larsal's own extension, INT-11; E7-S7c builds the channel's WebCrypto side)
Parity rows: SI-01, SI-12, SR-15, SR-16 (the lock notice), SB-01 (signing, for the Safari route)

## What it does

Larsal's browser extension never stores a password. It asks Larsal for each fill. This card is the wire between them:

```
extension  ──native messaging (stdin/stdout)──>  host program  ──Unix socket──>  Larsal
(Chrome, Firefox, Edge, Brave, Vivaldi, Opera,   larsal-bridge, in Larsal's bundle      larsal-browser in Rust
 Chromium, Arc)

Safari extension ──sendNativeMessage──> Larsal's Safari app extension ──Unix socket (app group)──> Larsal
```

- The browser starts the **host program** `larsal-bridge` because a small JSON **manifest** in the browser's folder names it. The host program is a dumb relay: it copies framed messages between the browser and Larsal's socket and answers only "Larsal is not running" and "browser integration is off" by itself.
- On top of the relay runs Larsal's **channel**: a fresh key exchange per session (X25519), two keys from it with HKDF-SHA256 (one per direction), then every request and reply sealed with AES-256-GCM: through larsal-crypto's approved crates in Larsal, and through the browser's own WebCrypto in the extension (LD-274 (1), INT-11). Larsal refuses replayed nonces.
- Inside the channel the extension proves it holds its long-term **identification key**; a vault that stores that key under a name (an association, INT-02) lets the extension use it.
- The requests: status, connect, check, unlock, lock, find logins, get logins, search, recent, save, update, one-time code, groups, generate a password, start Auto-Type, passkeys (INT-04).

All names on the wire are Larsal's own. The reference's extension can never reach Larsal (its host name and its manifests' extension ids belong to the reference, README D4), so nothing on the wire has to match the reference. What must match the reference is vault data (INT-02, INT-03, FMT-14), the WebAuthn member names inside passkey requests (W3C, INT-04), and, for INT-04's sake, the meaning of the error numbers 1 to 34 (INT-01.40).

Neighbor cards: INT-02 (associations, site access, what a reply carries), INT-03 (URL matching), INT-04 (passkey requests), APP-01 (S-BRW-01 to S-BRW-27), APP-02 (lock request, SR-16), APP-06 (the unlock panel), APP-09 (the instance socket, same folder rules), APP-11 (hardening, D-APP11-1), FEA-02 and FEA-03 (the generator engine), FEA-04 (codes), MOD-08 (placeholders), MOD-12.18 (vault settings page), FMT-14 (custom data keys).

Public standards a Builder needs: Chrome "Native messaging" (developer.chrome.com/docs/extensions/develop/concepts/native-messaging); MDN "Native messaging" and "Native manifests" (developer.mozilla.org, WebExtensions); Apple "Messaging between the app and JavaScript in a Safari web extension" (Safari Services); RFC 7748 (X25519; section 6.1 and its test vector); RFC 5869 (HKDF; appendix A); NIST SP 800-38D (GCM) and the NIST CAVP GCM test vectors; W3C Web Cryptography API Level 2 (X25519, HKDF and AES-GCM in the extension, INT-11); RFC 4648 section 4 (base64) and section 5 (base64url); RFC 8259 (JSON).

## Inputs and outputs

### Larsal's names

| Thing | Larsal's name | Must it match the reference? |
|---|---|---|
| Host id (manifest `name`) | `app.larsal.browser` (placeholder, renamed with D1) | No: the reference's host id contains a banned word and only its own extension calls it |
| Host program | `larsal-bridge`, in `Larsal.app/Contents/MacOS/` next to Larsal's main program | No |
| Manifest file | `app.larsal.browser.json` | No |
| Bridge socket | `app.larsal.browser.sock` in the Darwin user temp folder (debug builds: `app.larsal.browser-debug.sock`) | No |
| Safari socket | `bridge.sock` in Larsal's app-group container `~/Library/Group Containers/‹team id›.app.larsal.browser/` | No |
| Allowed extensions | Larsal's own store ids only (INT-01.9) | No |
| Message types and fields | the tables of INT-01.30 to INT-01.38 | No |
| Error numbers | 1 to 34 keep the reference's meanings; Larsal's own from 40 (INT-01.40) | Numbers only, so INT-04's codes stay true |
| Association keys in the vault | INT-02.1 | Yes: vault data |
| Passkey option members | WebAuthn names (`challenge`, `rp`, `user`, ...) | Yes: a public standard |

### Limits

| Limit | Value | Rule |
|---|---|---|
| One framed message, either hop, either direction | 1,048,576 bytes (1 MiB) of JSON after the 4-byte length; Chrome and Firefox refuse host messages over 1 MB | INT-01.3 |
| Decrypted content of one box | 655,360 bytes (640 KiB, the reference's message limit, SI-01) | INT-01.24 |
| JSON nesting | 32 levels | INT-01.25 |
| JSON size in values | 16,384 commas and opening brackets (`[`, `{`) outside strings, counted together, per message (LD-312) | INT-01.25 |
| URL fields (`url`, `form_url`, `top_url`) | 8,192 bytes each | INT-01.25 |
| Search text, Auto-Type search | 256 characters (the reference's Auto-Type limit) | INT-01.33, INT-01.36 |
| Connections to Larsal's sockets at once | 16 | INT-01.44 |
| Requests in flight per session | 8, of which at most 4 wait for the user | INT-01.44 |
| Requests per session | 100,000, then a new hello is needed | INT-01.22 |
| Safari session idle time | 15 minutes | INT-01.14 |
| Safari sessions at once | 32; a hello past it ends the Safari session idle the longest (LD-318) | INT-01.44 |
| Host program connect to Larsal | 1 second per try | INT-01.5 |
| Waiting for the user | connect dialog 120 s; site access, update and group prompts 60 s (INT-02); unlock panel: as long as it shows (APP-06); passkeys: INT-04's countdown | INT-01.45 |

### Settings used (APP-01)

S-BRW-01 browser integration (off), S-BRW-02 to S-BRW-08 the browser switches (INT-01.8; Chromium and Arc get S-BRW-28 and S-BRW-29 in E7-S7l, LD-298), S-BRW-10 ask to unlock (on), S-BRW-14 search every vault (off), S-BRW-21 rewrite setup files at start (on), S-BRW-23 and S-BRW-24 own proxy program (off, empty). The others belong to INT-02 and INT-03.

## Rules

Numbers INT-01.16 to INT-01.19, INT-01.39 and INT-01.43 are not used and are retired: the card was written on 2026-10-28 with free numbers at section breaks, and no rule, test case or other card or plan file has ever cited them (searched 2026-10-28). They are never reused; a new rule takes the next free number (INT-01.49 and INT-01.50 were added 2026-11-01; the next is INT-01.51). No rule is missing.

### Transport

INT-01.1 **Native messaging frames.** Between the browser and the host program every message is a 32-bit unsigned length in native byte order (little-endian on every Mac Larsal supports: arm64 and x86_64) followed by that many bytes of UTF-8 JSON, one object. This is the browsers' own format (Chrome and MDN docs). The host program reads standard input and writes standard output only; nothing else may ever be written to standard output.

INT-01.2 **Socket frames.** Between the host program (or the Safari app extension) and Larsal the same frame is used: a 4-byte little-endian length, then the JSON bytes. Larsal reads exactly the length; a short read, a length of 0, or a stream that ends inside a frame closes the connection. Reference difference: its relay writes the raw JSON to its socket without a length and its host splits the stream at every `}` and guesses at fragments; Larsal frames every message.

INT-01.3 **Frame size.** A length over 1,048,576 is refused before any byte of the body is read or any memory is reserved for it: the host program writes the plain error 43 (INT-01.41) to the browser and exits; Larsal closes the socket. Larsal never sends a frame over 1,048,576 bytes (INT-01.24 keeps every reply below it).

INT-01.4 **The host program's start.** The browser starts `larsal-bridge` with its own arguments (Chrome-family: the caller origin `chrome-extension://‹id›/`; Firefox: the manifest path and the add-on id). The host program first applies APP-11's hardening (D-APP11-1), then ignores the arguments except for an optional debug log of the caller id (no content). Its working folder is whatever the browser gives. It holds no secret and never parses the boxes.

INT-01.5 **Relay.** The host program connects to Larsal's bridge socket (INT-01.6), waiting at most 1 second. Then it copies each browser frame to the socket and each socket frame to standard output, in order, unchanged. When Larsal is not reachable, each browser frame gets one plain error reply from the host program: 45 when a process with Larsal's bundle id `app.larsal.desktop` runs for this user (Larsal runs but integration is off), else 44 (Larsal is not running); the host program then tries to connect again at the next frame, so a browser port survives Larsal starting later. When Larsal closes the socket, the host program goes back to that "not reachable" state; the extension has to say hello again (INT-01.20). End of standard input (the browser closed the port): the host program exits at once. SIGTERM, SIGINT, SIGHUP: exit at once (Firefox sends SIGTERM, then SIGKILL; MDN).

INT-01.6 **Larsal's bridge socket.** While S-BRW-01 is on and Larsal runs, Larsal listens on `app.larsal.browser.sock` in the Darwin user temp folder read from the OS (`confstr(_CS_DARWIN_USER_TEMP_DIR)`, mode 0700, never `TMPDIR`; the same folder rule as APP-09.7, so the path stays under the 104-byte socket limit). Mode 0600. At start Larsal removes a leftover file of that name only when it is a socket owned by the user; anything else there: MI01-06 on the settings page, no listener. After `accept` Larsal checks the peer's user id (`getpeereid`) equals its own and closes the connection otherwise. Turning S-BRW-01 off closes the listener and every connection (waiting requests: INT-01.45). Reference: the same folder (it also bypasses `TMPDIR`), owner-only socket, no peer check.

INT-01.7 **Peer program check** (D-INT01-8). In builds signed with Larsal's team id, Larsal also checks the code signature of the connecting process (through its audit token): it must be Larsal's `larsal-bridge` or Larsal's Safari app extension, signed by the same team. Failure closes the connection. Unsigned development builds skip this check and say so once in the debug log.

### Manifests per browser

INT-01.8 **Browsers and folders** (D-INT01-6). One switch per browser on the settings page (frame `settings-settings-browser-integration`, the "Browsers" group). For each browser but Safari, the switch is on exactly when Larsal's manifest file exists in that browser's folder (APP-01.30). User-level folders, all under `~/Library/Application Support/`:

| Browser | Folder | Key for allowed callers |
|---|---|---|
| Chrome | `Google/Chrome/NativeMessagingHosts/` (Chrome docs) | `allowed_origins` |
| Firefox | `Mozilla/NativeMessagingHosts/` (MDN) | `allowed_extensions` |
| Edge | `Microsoft Edge/NativeMessagingHosts/` | `allowed_origins` |
| Brave | `BraveSoftware/Brave-Browser/NativeMessagingHosts/` | `allowed_origins` |
| Vivaldi | `Vivaldi/NativeMessagingHosts/` | `allowed_origins` |
| Opera | Chrome's folder: Opera reads it (forum reports, V-INT01-1); the file is shared with Chrome and exists while either switch is on | `allowed_origins` |
| Chromium | `Chromium/NativeMessagingHosts/` (Chrome docs) | `allowed_origins` |
| Arc | `Arc/User Data/NativeMessagingHosts/` (a community report only, spec/research/browser-and-web.md section 1; V-INT01-4) | `allowed_origins` |
| Safari | no file: INT-01.12 | — |

Chromium and Arc are two of "the other Chromium browsers" of LD-272 (1) (research B5); E7-S7l writes their manifests, Arc's after V-INT01-4. Tor Browser and a custom folder (the reference's S-BRW-25 to S-BRW-27) are not offered in Larsal 1.0 (D-INT01-6). Edge, Chromium and Arc are not in the frame: E7-S7k draws their rows in `design/option-a/proposals.html` for the owner's one-pass review (AT-K05, LD-268), which never blocks the build.

INT-01.9 **Manifest content.** UTF-8 JSON, two-space indent, final LF, these members in this order: `name` = `app.larsal.browser`; `description` = `Larsal browser bridge`; `path` = the absolute path of `larsal-bridge` inside the running Larsal bundle with links resolved (or S-BRW-24 when S-BRW-23 is on); `type` = `stdio`; then for Firefox `allowed_extensions` = [Larsal's Firefox add-on id], for the others `allowed_origins` = [`chrome-extension://‹id›/` for each of Larsal's store ids: Chrome Web Store, Edge Add-ons, Opera add-ons]. No wildcards (the browsers refuse them). The ids are fixed at E7-S7 when the extension is first published; debug builds add one developer id from a debug-only setting (as the reference's S-DEBUG-01). Reference difference: its manifests list its own extension ids.

INT-01.10 **Writing and removing.** Larsal writes a manifest to a temporary file in the same folder and renames it over the old one; the folder is created when missing (only the last level: never a browser's own profile folder above it). Mode 0644. When the file exists, cannot be written, but holds the same JSON Larsal would write (member order and spacing aside), that counts as success (reference). The folders of INT-01.8 lie under the user's home folder; test builds never read that base folder from HOME or from the account: it is always `home` under the test's own folder (a test launch's instance folder, or the folder a test names), so no test ever writes into the owner's browser folders (AGENTS rule 10, LD-332 (2)). Any other failure: MI01-01 naming the browser; the switch goes back to off. Switching off removes the file only when its `name` member is `app.larsal.browser` (Larsal never deletes another program's file). Opera and Chrome share one file (INT-01.8): it is removed only when both are off.

INT-01.11 **Rewrite at start** (S-BRW-21, on). When Larsal starts with S-BRW-01 on, every manifest Larsal finds in the folders of INT-01.8 is written again with the current path (Larsal was moved or updated). With S-BRW-21 off, Larsal only shows MI01-02 on the settings page when a manifest's `path` does not name an existing `larsal-bridge`. While S-BRW-01 and S-BRW-23 are on and S-BRW-24 names no existing file, the settings page shows MI01-05 (APP-01.30).

### Safari route

INT-01.12 **Parts** (D-INT01-7). Safari loads extensions only from inside a Mac app. Larsal's bundle holds a Safari web extension (Larsal's extension code) and its native app extension (`Larsal.app/Contents/PlugIns/`). Safari sends every native message from the extension's background script to that app extension, whatever application id the script names (Apple docs); content scripts cannot send native messages. The app extension and Larsal run in separate sandboxes; they share data only through an app group.

INT-01.13 **Relay in the app extension.** For each message (`browser.runtime.sendNativeMessage`, read from the request's `SFExtensionMessageKey`), the app extension connects to `bridge.sock` in the app-group container, sends the message as one socket frame (INT-01.2), waits for one reply frame and completes the request with it. It handles no content and keeps no state. Larsal not reachable: the plain error 44 or 45 as in INT-01.5. Larsal listens on that socket while S-BRW-01 and the Safari switch are on (INT-01.6 rules apply, with the app-group folder instead of the temp folder). The user also has to turn the extension on in Safari's own settings; Larsal's settings page links there (MI01-03).

INT-01.14 **Sessions without a port.** A Safari message may reach Larsal on a new connection each time, so a Safari session is found by its session id (`sid`, INT-01.21), not by its connection. Safari sessions end after 15 minutes without a request, when Larsal quits, or when the Safari switch turns off. Larsal sends no notices on this route (INT-01.46); the extension asks `status` when it needs to.

INT-01.15 **Signing.** The app group and the app extension need Larsal signed with a team id (Apple's app group rules). Until Larsal has one (owner item D7), the Safari switch is shown disabled with MI01-04.

### The channel

INT-01.20 **Hello: the key exchange.** The first message of a session is plain (not boxed):

`{"type":"hello","versions":[1],"key":"‹base64 of the client's 32-byte X25519 session public key›","browser":"Chrome"}`

- `versions`: the protocol versions the client speaks, 1 to 16 integers. Larsal picks the highest one it also speaks (Larsal 1.0 speaks only 1). None in common: plain error 40 with `"versions":[1]`.
- `key`: exactly 32 bytes after strict base64 decoding (INT-01.26). Larsal makes a fresh X25519 key pair for this session (random from larsal-crypto only), computes the X25519 result Z with the client's key (RFC 7748 section 6.1), and refuses a client key that gives an all-zero Z (a low-order point): plain error 10. Then it derives the request key and the reply key (INT-01.49).
- `browser`: one of `Safari`, `Chrome`, `Firefox`, `Edge`, `Brave`, `Vivaldi`, `Opera`, `Chromium`, `Arc`; anything else is taken as `Browser`. Used only in Larsal's dialogs (INT-02).
- Reply (plain): `{"type":"hello","version":1,"key":"‹Larsal's session public key›","sid":"‹base64url of 16 random bytes›","app":"‹Larsal's version, for example 1.0›"}`. The client derives the same two keys from Larsal's key; when its own X25519 result is all zero (WebCrypto throws `OperationError`), it drops the session and says hello again (INT-11.7).
- The hello carries no nonce: both session key pairs are fresh, so every session has its own keys, and a reply is bound to its request by INT-01.23. A `nonce` member, as the first version of this card had, is ignored like any unknown member.
- A hello on a connection that already has a session replaces it: the old keys are wiped, its waiting requests are dropped without a reply (nothing can be sealed for them any more) and their dialogs close as Deny.
- Reference difference: its key exchange carries no version list, and its session state is keyed by a client-chosen id string that any local process can reuse (INT-01.21).

INT-01.21 **Boxed messages.** Every later message, both ways:

`{"type":"box","sid":"‹session id›","nonce":"‹base64, 12 bytes›","box":"‹base64 of the AES-256-GCM ciphertext followed by its 16-byte tag›"}`

- The box is AES-256-GCM (NIST SP 800-38D) with the given 12-byte nonce, a 128-bit tag and no associated data: the ciphertext, as long as the content, then the tag (the form WebCrypto's `encrypt` returns and the `aes-gcm` crate writes). The client seals with the request key and Larsal opens with it; Larsal seals everything it sends with the reply key (INT-01.49).
- Larsal finds the session by `sid`. For a Chromium-family or Firefox connection the `sid` must belong to that same connection; for the Safari socket any connection may carry it. Unknown `sid`, or a `sid` of another connection: plain error 3 ("say hello again").
- Larsal checks in this order and stops at the first failure: the `sid` (plain error 3); the nonce's encoding (INT-01.26, plain error 4); the nonce is not in the session's set (INT-01.23, plain error 41); the box's encoding and a length of at least 16 bytes (plain error 4); the box opens with the request key (plain error 4). Nothing else about the failure is told.
- The content is one UTF-8 JSON object. Requests carry `"type"` (INT-01.30) and `"req"`: an integer 1 to 9,007,199,254,740,991 chosen by the client; Larsal echoes `req` in the reply so replies may come out of order (INT-01.44). Larsal's replies carry the same `type` and `req`, plus either the reply fields or `"error": n`. A request without a usable `req` gets a boxed error 12 without `req`, and nothing is done.
- Unknown members are ignored; a member of the wrong JSON type counts as missing.

INT-01.22 **Session state.** Per session Larsal keeps: its own key pair (secret part in a wiping type, AGENTS rule 4), the client's session key, the request key and the reply key (INT-01.49, wiping types), the `sid`, the set of nonces seen and sent (INT-01.23), the proven identification key (INT-01.28), the `browser` name, and its waiting requests. Nothing of it is written anywhere. Sessions end when their connection closes (Chromium-family and Firefox), by INT-01.14 (Safari), at a new hello, when S-BRW-01 turns off, at quit, and after 100,000 requests (then every further box gets error 41 and the client says hello again).

INT-01.23 **Nonces.**
- The client makes a fresh random 12-byte nonce for every request (WebCrypto `crypto.getRandomValues`, INT-11.7). Random 96-bit nonces under one key are safe for up to 2^32 messages (NIST SP 800-38D sections 8.2.2 and 8.3); a session ends after 100,000 requests (INT-01.22), far below that.
- Larsal's reply to a request is sealed with the reply key and that request's own nonce. The client takes a reply only when its nonce equals the nonce of its request with that `req` (INT-11.10), so a reply is bound to its request. The request and the reply use different keys, so one nonce is never used twice under one key.
- Larsal's own messages that answer nothing (notices, INT-01.46) use a fresh random nonce that is not in the session's set; Larsal draws again when it is.
- Larsal keeps one set per session of every nonce it has seen in a request or used itself, and refuses (plain error 41, nothing done) a request whose nonce is in the set. So a replayed box is refused (AT-F02); a request that reuses the nonce of a Larsal notice is refused, because its reply would reuse that nonce under the reply key; and a box Larsal sent, sent back to Larsal as a request, is refused (by its nonce, and it would not open under the request key either). Larsal never seals two messages with the same nonce under one key.
- Reference difference: it answers with the request nonce plus one but keeps no record of nonces, so a resent box is processed again (SI-01: "It does not track used nonces").

INT-01.24 **Content size.** Content over 655,360 bytes is refused: a request with error 43 (boxed when the box opened), a reply is never made that large: Larsal shortens result lists first (INT-02 caps them) and sends error 43 if it is still too large.

INT-01.25 **JSON reading.** Strict RFC 8259 JSON, UTF-8 only (an invalid byte sequence refuses the message), one top-level object, at most 32 levels of nesting, at most 16,384 commas and opening brackets (`[`, `{`) outside strings counted together (checked before the message is read, so a long flat list or many short chains never reach the reader, and a message over the limit is refused like one nested too deep; LD-312), no duplicate member names (a duplicate refuses the message), numbers that fit a 64-bit float. Plain messages that are not a valid object: plain error 13 when empty, else 12. String limits of the Limits table; a longer value gives error 43.

INT-01.26 **Encodings.** Keys, nonces, boxes and proofs: base64 with the standard alphabet and `=` padding (RFC 4648 section 4), decoded strictly: other characters, missing or extra padding, or non-zero trailing bits refuse the value (error 10 for keys, plain error 4 for nonces and boxes, error 8 for proofs). Keys decode to exactly 32 bytes, nonces to exactly 12, proofs to exactly 48, and boxes to at least 16 (the tag). `sid` and vault ids: base64url without padding (section 5).

INT-01.27 **What the extension sends about pages.** `url`: the URL of the frame that holds the field, as the browser serializes it (lower-case scheme and host, the host in ASCII, no default port). `top_url`: the address of the tab's top page. `form_url`: where the form sends its data, when known. INT-02 and INT-03 decide what they mean; INT-01 only bounds their length.

INT-01.49 **Key schedule** (LD-274 (1); B3). Three AES-256-GCM keys, each from HKDF-SHA256 (RFC 5869: extract, then expand) with an empty salt (as RFC 9180's DHKEM extracts its X25519 result, section 4.1; RFC 5869 section 2.2 makes it equal to 32 zero bytes), an X25519 result (RFC 7748 section 6.1) as input key material, 32 bytes of output, and an info made of an ASCII label followed by raw 32-byte public keys:

| Key | Input key material | info | Seals |
|---|---|---|---|
| request key | Z = X25519(c, A) = X25519(a, C) | `browser-bridge request key v1` ‖ C ‖ A | requests, client to Larsal |
| reply key | Z | `browser-bridge reply key v1` ‖ C ‖ A | replies and notices, Larsal to client |
| proof key | Z_id = X25519(i, A) = X25519(a, I) | `browser-bridge proof key v1` ‖ C ‖ A ‖ I | INT-01.28's proof |

C and c: the client's session public and secret keys; A and a: Larsal's; I and i: the identification key's. The labels are written without quotes or a terminator; the public keys have one fixed size, so each info has one layout. Both session public keys are in every info, as RFC 7748 section 6.1 advises ("a key-derivation function that includes K, K_A, and K_B"); one key per direction, as TLS 1.3 keeps a client write key and a server write key (RFC 8446 section 7.3). The labels hold no product name, so renaming Larsal (D1) does not change the channel. Larsal: `x25519-dalek`, `hkdf` and `aes-gcm` in larsal-crypto `bridge.rs` (E16-S2's crates; plan/architecture.md); every secret and derived key in a wiping type (INT-01.47). Extension: WebCrypto only, every key non-extractable (INT-11.7).

INT-01.50 **Known answers** (gate G3, AT-B01). larsal-crypto's bridge tests (E7-S1) and WebCrypto in headless Chrome through E7-S7b's driver (E7-S7c) each compute every vector below; both must give the listed bytes. Two independent computations: a mismatch stops both stories until it is explained. In WebCrypto a private key from these tables is imported as PKCS #8 (RFC 8410's form) or as a JWK with `d` (RFC 8037), because `raw` import takes only public keys (W3C WebCrypto, X25519 "Import Key"); a public key is imported `raw`.

Published vectors, quoted exactly from their sources (read 2026-11-01):

| Vector | Values (hex) | Source |
|---|---|---|
| X25519 | Alice's private key a: `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a`; Alice's public key X25519(a, 9): `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a`; Bob's private key b: `5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb`; Bob's public key X25519(b, 9): `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f`; their shared secret K: `4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742` | RFC 7748 section 6.1, <https://www.rfc-editor.org/rfc/rfc7748.txt> |
| HKDF-SHA256 A.1 | IKM `0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b` (22 octets); salt `000102030405060708090a0b0c` (13); info `f0f1f2f3f4f5f6f7f8f9` (10); L 42; PRK `077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5`; OKM `3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865` | RFC 5869 appendix A.1, <https://www.rfc-editor.org/rfc/rfc5869.txt> |
| HKDF-SHA256 A.2 | IKM `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f` (80); salt `606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf` (80); info `b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff` (80); L 82; PRK `06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244`; OKM `b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87` | RFC 5869 appendix A.2 |
| HKDF-SHA256 A.3 | IKM `0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b` (22); salt and info empty; L 42; PRK `19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04`; OKM `8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8` | RFC 5869 appendix A.3 (the empty salt this card uses) |
| AES-256-GCM G1 | Key `b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4`; IV `516c33929df5a3284ff463d7`; PT and AAD empty; Tag `bdc1ac884d332457a1d2664f168c76f0` | NIST CAVP `gcmEncryptExtIV256.rsp` (CAVS 14.0, generated 2012-08-31), section [Keylen = 256] [IVlen = 96] [PTlen = 0] [AADlen = 0] [Taglen = 128], Count = 0; in `gcmtestvectors.zip`, <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip> |
| AES-256-GCM G2 | Key `31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22`; IV `0d18e06c7c725ac9e362e1ce`; PT `2db5168e932556f8089a0622981d017d`; AAD empty; CT `fa4362189661d163fcd6a56d8bf0405a`; Tag `d636ac1bbedd5cc3ee727dc2ab4a9489` | the same file, [PTlen = 128] [AADlen = 0] [Taglen = 128], Count = 0 |
| AES-256-GCM G3 | Key `24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f`; IV `9ff18563b978ec281b3f2794`; PT `27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb158bd9abb3868fdc0d0b074b5f01b2c`; AAD `adb5ec720ccf9898500028bf34afccbcaca126ef`; CT `eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae82057ad55994cf59ad7f67c0fa5e85fab8`; Tag `bc95c532fecc594c36d1550286a7a3f0` | the same file, [PTlen = 408] [AADlen = 160] [Taglen = 128], Count = 0 |

WebCrypto gives HKDF's OKM only, so its HKDF check compares OKM; larsal-crypto also compares PRK. Larsal's whole CAVP and Wycheproof runs stay CRY-04.13's.

Larsal's own channel vectors. Fixed inputs: c = RFC 7748's Alice private key and a = its Bob private key (so C, A and Z are the published values above); i = `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`; N1 = `000000000000000000000001`, N2 = `000000000000000000000002`; P1 = the 25 UTF-8 bytes `{"type":"status","req":1}` (hex `7b2274797065223a22737461747573222c22726571223a317d`); P2 = the 37 bytes `{"type":"status","req":1,"vaults":[]}` (hex `7b2274797065223a22737461747573222c22726571223a312c227661756c7473223a5b5d7d`). In the hello, C is `hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=` and A is `3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=` (RFC 4648 base64 of the published bytes). The outputs are not invented here: E7-S1 fills each from larsal-crypto into this table and its test, and E7-S7c checks that WebCrypto gives the same bytes.

| Vector | Derivation | Output |
|---|---|---|
| CV-1 | info of the request key = `62726f777365722d6272696467652072657175657374206b6579207631` (the 29 ASCII bytes of `browser-bridge request key v1`) ‖ C ‖ A; the reply key's info starts with `62726f777365722d627269646765207265706c79206b6579207631` (27 bytes, `browser-bridge reply key v1`), the proof key's with `62726f777365722d6272696467652070726f6f66206b6579207631` (27 bytes, `browser-bridge proof key v1`) | the concatenations themselves (93, 91 and 123 bytes) |
| CV-2 | request key = HKDF-SHA256(salt empty, IKM Z, info CV-1 request, L 32) | `e4b77f9fa8df1e045efa982b7a70fe6194b4cdb32153a5c034d80a5d63ec1e74` |
| CV-3 | reply key = HKDF-SHA256(salt empty, IKM Z, `browser-bridge reply key v1` ‖ C ‖ A, L 32) | `999ff990adb5b4328ba790203c0e5e09e22b7cc989d2ba515754f70922b20da7` |
| CV-4 | box of P1: AES-256-GCM with the request key, nonce N1, no associated data (41 bytes: 25 + tag) | `5c843e032bda41a65a5cbe0903401ab186ef872add0a69ee862fa035dbe679eeaf1de73c93cafc6e7f` |
| CV-5 | box of P2: AES-256-GCM with the reply key, nonce N1 (Larsal's reply to CV-4; 53 bytes) | `d58bf61c8472d102d307203c8a89d13e5d8205fd0ad99803d18551dd97216027aa9eae11a9e2f08823592d7c41c7703f78a589837a` |
| CV-6 | I = X25519(i, 9) | `8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f` |
| CV-7 | Z_id = X25519(i, A), equal to X25519(a, I) | `d0bda120f120bed6b1c132f737ab678e1a4358c0984a617d2fe14f665460932f` (both ways) |
| CV-8 | proof key = HKDF-SHA256(salt empty, IKM Z_id, `browser-bridge proof key v1` ‖ C ‖ A ‖ I, L 32) | `2bb001852cfa20c1028578b07956ef04efa252c1d2659bae42fac46c5a3be859` |
| CV-9 | proof: AES-256-GCM of C with the proof key, nonce N2 (48 bytes); its base64 is the `proof` member | `3206e2599b88ce227a7a9a6a09d2b52e7279593b2a02c502b476917c592ead05e1440ebc6f879ac3fba856cd6c3e8652` |

Filled 2026-11-01 by E7-S1 from larsal-crypto (`crates/larsal-crypto/src/bridge.rs`, test `t79_channel_vectors_cv1_to_cv9`; CV-1 and Z = K are asserted there too). WebCrypto in headless Chrome, through E7-S7b's driver, gives the same bytes, both by `deriveBits` and by INT-11.7's non-extractable `deriveKey` path (`extension/test/test_channel_vectors.py`); HKDF's outputs were also recomputed with Python's `hmac`. E7-S7c runs the same check on the extension's own channel code.

### Identity

INT-01.28 **The identification key and its proof** (D-INT01-4). Each browser profile's extension keeps one long-term X25519 key pair, its identification key, as a non-extractable WebCrypto key (INT-11.6). A vault stores the public half under a name (INT-02.1). Requests that name it carry:

- `id_key`: base64 of the 32-byte public key I;
- `proof`: base64 of 48 bytes: the AES-256-GCM seal (INT-01.21's form, no associated data) of the client's 32-byte session public key C from the hello, under the proof key (INT-01.49) with this request's own nonce.

Larsal first refuses with error 10, before any proof work, an `id_key` that does not decode to 32 bytes, that gives an all-zero X25519 result with Larsal's session secret key (a low-order point: anyone could make its proof), or that equals the session's client key C (the proof key and the session keys would then come from one X25519 result). Then Larsal derives the proof key, opens the proof with the request's nonce, and compares its content with C in constant time. A proof that does not decode to 48 bytes, does not open or holds anything but C: error 8. Then the session's identity is that key, until the session ends. Because the stored value is a public key and the proof needs the secret half, a copy of the vault's custom data (a backup, a merge partner, an export of the item) cannot be used to act as the browser. Reference difference: it only compares the presented key with the stored text, so whoever knows the stored public key passes.

INT-01.29 **Which vaults a session may use.** For each request Larsal takes the unlocked vaults that store the session's identification key under some name (INT-02.1): the shown vault only, or every unlocked vault when S-BRW-14 is on. Vaults that are locked, or whose MOD-13 forced change prompt is open, are not used (MOD-13.8). INT-02 owns the details.

### Requests

INT-01.30 **Request types.** "Assoc." means the session must have a proven identity held by at least one usable vault (INT-01.29); without it the reply is error 8 (no proof yet, or no unlocked vault the request may use stores the key) or error 1 (no vault the request may use is unlocked). Every waiting request ends with error 6 when the user cancels, the time of INT-01.45 runs out, or the vault locks.

| Type | Assoc. | Request fields | Reply fields | Owner |
|---|---|---|---|---|
| `status` | no | — | `vaults`: list of `{"name","state","shown"}` (`name`: the vault's file name without the extension) with state `locked` or `unlocked`; for unlocked vaults that hold the session's proven key also `"id"` (vault id, INT-01.31) and `"connection"` (the association name) | INT-01.31 |
| `connect` | no | `id_key`, `proof`, `name` (a suggested name, optional) | `name`, `vault` | INT-02.3 to INT-02.6 |
| `check` | no | `id_key`, `proof` | `vaults`: list of `{"id","name","connection"}`; none: error 8 | INT-02.7 |
| `unlock` | no | — | `vault` once the shown vault is unlocked; S-BRW-10 off: error 1 at once | INT-02.11 |
| `lock` | yes | — | empty; Larsal locks the shown vault (APP-02, T34) | INT-01.35 |
| `disconnect` | yes | — | `unchanged`: list of vault names; Larsal removes the session's association items from the unlocked vaults (below the table) | INT-01.30, INT-02.8 |
| `logins.find` | yes | `url`, `top_url`, `form_url` (optional), `http_auth` (boolean, default false) | `entries`: list of entry summaries (INT-02.20), best match first; none: error 15 | INT-02.13 to INT-02.17, INT-02.20, INT-03 |
| `logins.get` | yes | the fields of `logins.find`, plus `ids`: 1 to 20 entry references `{"vault","id"}` | `entries`: list of full entries (INT-02.21); none allowed: error 15 | INT-02.13 to INT-02.21 |
| `logins.search` | yes | `text` | `entries`: up to 50 summaries, never with secrets | INT-02.22 |
| `logins.recent` | yes | — | `entries`: up to 5 summaries this association used last (INT-02.9) | INT-02.22 |
| `logins.save` | yes | `url`, `form_url` (optional), `username`, `password`, `title` (optional), `group` (optional group id), `icon` (boolean, optional) | `entry`: `{"vault","id"}` | INT-02.24 |
| `logins.update` | yes | `url`, `form_url` (optional), `vault`, `id`, `username`, `password` | `updated`: true, false when nothing differed (INT-02.25), or error 6 when the user said no | INT-02.25 |
| `code.get` | yes | `url`, `top_url`, `vault`, `id` | `code`, `period`, `remaining` (seconds) | INT-02.23 |
| `groups.list` | yes | `vault` (optional) | `groups`: the tree, each `{"id","name","children"}` | INT-02.26 |
| `groups.create` | yes | `vault` (optional), `path` | `group`: `{"id","name"}` | INT-02.26 |
| `password.generate` | yes | `kind`: `password` or `passphrase`; `options` (optional) | `value`, `bits` | INT-01.34 |
| `autotype.start` | yes | `search` (optional) | empty | INT-01.36 |
| `passkey.create` | yes | `public_key`, `origin`, `group` | `response` | INT-04 |
| `passkey.get` | yes | `public_key`, `origin` | `response` | INT-04 |

`disconnect` (LD-191, R01-1; the options page's Disconnect, INT-11.40). No Larsal dialog: the extension's Disconnect button is the user's confirm, as for `logins.save`. The "Assoc." check of INT-01.29 runs first, so with S-BRW-14 off the shown vault must hold the key, else the reply is error 8 or 1 and nothing changes (the extension's answer to them: INT-11.40). Once it passes, Larsal acts on every unlocked vault, the shown one or not: in every unlocked vault that is not behind MOD-13's forced prompt and stores the session's proven identification key, whatever S-BRW-14 says, Larsal removes, for each name under which the vault stores that key, the association item, its `_CREATED_` item and its `_LAST_USED_` item, as INT-02.8 does after its question (a data change, APP-05). Reply `unchanged`: the names (as in `status`) of the other open vaults, which Larsal could not change because they are locked or behind MOD-13's prompt; an empty list when there are none. They keep their items until the user disconnects the browser in Larsal (INT-02.8). After the reply the session's next "Assoc." request gets error 8 (INT-02.8).

Any other `type`: error 12. Entry and vault ids on the wire: an entry id is the 32 lowercase hex digits of the entry's id; a vault id is INT-01.31's. An entry id that is not 32 hex digits: error 18.

INT-01.31 **Vault id.** `vault` = base64url without padding of the first 16 bytes of SHA-256 over the ASCII bytes `browser-bridge vault id v1` followed by the 16 raw bytes of the vault's root group id. It changes when the root group gets a new id (MOD-12.18 `vault.act.new_root_id`). Reference difference: it sends the hex SHA-256 of the root group id's hex text to any client after the key exchange, without an association (LD-73, SI-12); Larsal gives a vault id only to a session whose proven key that vault holds.

INT-01.32 **Names in INT-04.** INT-04 was first written with the reference's member names. The mapping: action `passkeys-register` = `passkey.create`; `passkeys-get` = `passkey.get`; member `publicKey` = `public_key` (its content, the WebAuthn options object, is unchanged, with WebAuthn member names); `groupName` = `group`; `keys` = the session's proven identification key (INT-01.28), so INT-04's "one of the request's keys pairs matches a stored association" reads "the vault holds the session's identification key". The error numbers are the same. INT-04 uses Larsal's names since this card's second review (2026-10-28, LD-189); `response.publicKey` inside the credential object keeps its WebAuthn name.

INT-01.33 **Search text.** `logins.search` `text` is 1 to 256 characters; longer: error 43. INT-02.22 owns the search.

INT-01.34 **Generate a password** (D-INT01-5). Larsal makes the value with its own generator engine (FEA-02 for `password`, FEA-03 for `passphrase`) and returns it with `bits`: FEA-05's estimate of the value, rounded down to a whole number (the extension maps it to FEA-02.15's quality words). `options` members, each optional (a missing one takes the saved setting): for `password`, `length` (1 to 999, the screen's bounds), `classes` (a non-empty list of FEA-02 class ids out of `lower`, `upper`, `digits`, `special`, `extended`: the frame's chips A–Z, a–z, 0–9, !@#$, Äéß) and `exclude_lookalike` (boolean); for `passphrase`, `words` (1 to 100), `separator` (text within FEA-03's bound, D-03-5) and `case` (`lower`, `upper`, `title`, `mixed`). A value out of bounds or of the wrong type, or any other member inside `options`, gives error 43 (an exception to INT-01.21, so a client never believes an option was applied). Without `options` Larsal uses its saved generator settings. Larsal never saves options that came over the bridge and never keeps the value. No Larsal window opens. Reference difference: it opens its own generator window and sends the value after the user presses Apply, without an association check (SI-12); Larsal's extension shows the generator itself (frames `extension-popup-generator` and `extension-in-page-new-password`).

INT-01.35 **Lock.** Locks the shown vault as an automatic trigger (APP-02.14, APP-02 T34); other vaults stay as they are. Reference difference: it locks without an association (SI-12).

INT-01.36 **Start Auto-Type.** Starts global Auto-Type (INT-05.25) with the optional search text (at most 256 characters, else error 43 like every overlong field). Reference differences: it answers an overlong search with error 14 ("no URL"), and it accepts the request without an association (SI-12).

INT-01.37 **Requests Larsal leaves out** (D-INT01-10). Delete an entry, list every entry of every vault (the reference's option S-BRW-22) and the reference's special lookup scheme for an entry by id or path: none of Larsal's frames needs them; an entry is reached by the ids that `logins.find`, `logins.search` and `logins.recent` give. They answer error 12.

INT-01.38 **Plain messages the host program makes.** `{"type":"error","error":44}` and `{"type":"error","error":45}` (INT-01.5), and `{"type":"error","error":43}` (INT-01.3). The host program never makes any other message.

### Errors

INT-01.40 **Error numbers.** Plain errors are `{"type":"error","error":n}` (for a refused hello also `"versions"`); boxed errors are the request's `type` and `req` with `"error": n`. No error carries text, an entry name, a URL or any vault content (AT-F07). The extension shows its own text for each number.

| n | Meaning in Larsal | Plain or boxed |
|---|---|---|
| 1 | No vault the request may use is unlocked (INT-01.29, INT-01.30), or the user cancelled the vault picker | boxed |
| 3 | No session: say hello again | plain |
| 4 | The box did not open | plain |
| 6 | Cancelled or denied by the user, timed out, or ended by a lock | boxed |
| 8 | Identity not proven, or no unlocked vault the request may use holds the identification key (INT-01.30) | boxed |
| 10 | A key is not a usable X25519 public key | plain (hello) or boxed (`id_key`) |
| 12 | Unknown type, or a message that is not one JSON object | plain or boxed |
| 13 | Empty message | plain |
| 14 | A needed URL is missing or not usable (INT-03.1) | boxed |
| 15 | No entry found or allowed | boxed |
| 16 | No groups | boxed |
| 17 | The group could not be made | boxed |
| 18 | An entry id or vault id is missing, malformed, unknown, or not one the site may use | boxed |
| 20 to 33 | Passkey results (INT-04.54) | inside `response`, except 24 and 25, which INT-04 sends as boxed errors |
| 34 | A username or password holds a placeholder or reference (MOD-08.28) | boxed |
| 40 | No protocol version in common | plain |
| 41 | Nonce already seen, or the session's request count is used up | plain |
| 42 | Busy: too many requests in flight or waiting (INT-01.44) | boxed |
| 43 | Too large: frame, content or a field | plain or boxed |
| 44 | Larsal is not running (host program or Safari app extension) | plain |
| 45 | Larsal runs, but browser integration is off | plain |

Numbers 2, 5, 7, 9, 11 and 19 are never sent by Larsal (their reference meanings have no place in Larsal's protocol). Reference differences: its errors are plain text replies with an English message, also for requests that decrypted.

INT-01.41 **Errors that tell nothing.** The replies to a box that does not open (4), to an unknown `sid` (3) and to a replay (41) are checked and sent before Larsal looks at any vault, so their content and timing do not depend on whether a vault is locked or the session has an identity; a local process learns nothing about Larsal's state from them.

### Versions

INT-01.42 **Version negotiation.** The hello's version list decides one version per session (INT-01.20). Within a version, new optional members may be added; old clients ignore them (INT-01.21). A change that old clients cannot ignore gets a new version number. Larsal keeps answering every version it ever shipped for at least one year after the next one ships. Larsal's product version goes in the hello reply's `app` member only for display (frame `extension-extension-options`: "Connected to Larsal 1.0").

### Limits, flood and waiting

INT-01.44 **Flood** (AT-F07). At most 16 connections to each socket at once; a 17th is closed at once. Per session at most 8 requests in flight; a 9th gets error 42. Requests that wait for the user (`connect`, `unlock`, `logins.get` and `code.get` when they ask, `logins.update`, `groups.create`, passkeys): at most 4 per session, and Larsal shows one dialog at a time across all sessions with a queue of at most 16 (INT-02.15); beyond: error 42. Requests that do not wait are answered while others wait, so replies can come out of order (matched by `req`). Hellos: each costs one key pair; Larsal answers at most 20 hellos per second over all connections and closes further connections in that second. At most 32 Safari sessions live at once: a Safari hello past that ends the Safari session that has been idle the longest, which then gets error 3 like any ended session (LD-318). Bridge sessions are bounded by the 16 connections, one session each. Larsal's window and menus stay responsive under any message rate: bridge work runs off the main thread.

INT-01.45 **Waiting times.** The connect dialog closes after 120 seconds as Deny; site access, update and create-group prompts after 60 seconds as Deny without remembering (INT-02.15); the unlock panel has no time limit (APP-06; it closes only by the user or by quit); passkey dialogs follow INT-04. A waiting request also ends with error 6 when its vault locks (SR-16). When its session ends or S-BRW-01 turns off, its dialog closes as Deny and the request is dropped without a reply (the connection is gone).

### Notices

INT-01.46 **Notices.** On the Chromium-family and Firefox route Larsal sends each session a boxed notice (fresh random nonce, no `req`): `{"type":"notice","event":"locked"}` when a vault the session may use locks, `"unlocked"` when one unlocks, `"shown"` when the shown vault changes. Notices carry nothing else. Reference difference: it broadcasts plain lock and unlock notices to every connection, also to ones without an association.

### Hardening and logging

INT-01.47 **No secret leaves the channel in clear.** Passwords, codes, usernames, titles, URLs and field values appear only inside boxes. They never go to a log (Rust rule 9, LD-67), an error value, the host program's standard error (Firefox shows it in the browser console, MDN) or the screen layer, except the dialogs of INT-02 and INT-04 which show titles and usernames. Session secret keys, the X25519 results, the request, reply and proof keys (INT-01.49) and decrypted contents live in wiping types and are wiped when the session ends or the content has been parsed.

INT-01.48 **Parsers are fuzzed.** The frame reader, the JSON reader with its limits and the request decoder have a fuzz target ("browser message", plan/architecture.md); no input makes them panic, hang or allocate past INT-01.3 and INT-01.24.

### Messages

Larsal's own wording; IDs are ours; ‹…› marks a placeholder. No text is taken from the reference.

| ID | Kind | Rule | Larsal text |
|---|---|---|---|
| MI01-01 | error | INT-01.10 | Larsal couldn't set up ‹browser›. Check that its folder ‹folder› can be written, then try again. |
| MI01-02 | warning | INT-01.11 | The setup for ‹browser› points to an old copy of Larsal. Turn the browser off and on again here, or turn on "Rewrite the browser setup files at start". |
| MI01-03 | hint | INT-01.13 | Also turn on the Larsal extension in Safari › Settings › Extensions. Button: "Open Safari Settings" |
| MI01-04 | hint | INT-01.15 | Safari needs a signed copy of Larsal. This build is not signed. |
| MI01-05 | error | INT-01.11 | The proxy program at ‹path› is missing. Browsers can't reach Larsal until it is back or the setting is turned off. |
| MI01-06 | error | INT-01.6 | Larsal can't open its browser connection: ‹path› is in the way. Remove it, then turn browser integration off and on. |

## Edge cases and errors

- **Larsal not running when the browser starts:** the host program answers 44 for each frame and connects as soon as Larsal listens; the extension's popup shows frame `extension-popup-app-not-reachable`.
- **Larsal running, integration off:** 45; the popup tells the user to turn it on (frame: "Browser Integration is on for Chrome").
- **Larsal quits while a request waits:** the socket closes; the host program sends nothing for the lost request; the extension's own timeout handles it, then a new hello after Larsal is back.
- **Two browsers at once:** two connections, two sessions, each with its own keys and identity; a dialog for one never answers the other.
- **The same extension with two ports** (two windows of a Chromium browser): two sessions; both may prove the same identification key.
- **A hello with the same client key twice:** allowed; Larsal's key pair is new each time, so the request and reply keys differ.
- **Clock changes:** nothing in the channel depends on time except the waiting limits, which use a monotonic clock.
- **A frame split over several reads, or several frames in one read:** the length prefix decides; Larsal and the host program never look for `}`.
- **Non-UTF-8 bytes from a page in a URL:** the browser sends URLs percent-encoded; a raw invalid byte sequence refuses the whole message (INT-01.25).
- **A huge length prefix (4 GiB):** refused before reading (INT-01.3).
- **Manifest folder missing** (browser never started): Larsal creates the last folder level only; when the browser's own folder (for example `Google/Chrome`) is missing, Larsal still creates the path, because Chrome reads it on first start.
- **Larsal moved to another folder:** the manifests point to the old path until S-BRW-21 rewrites them at the next start (or MI01-02 shows).
- **Two copies of Larsal** (debug and release): each has its own socket name; the manifest points to whichever copy wrote it last.
- **Not on Mac.** The reference also writes manifests for Windows (registry), Linux, Flatpak and Snap and uses a named pipe on Windows; Larsal 1.0 is Mac only.

## Lead decisions

| ID | Question | Options | Recommended, with evidence |
|---|---|---|---|
| D-INT01-1 | Wire compatibility with the reference's extension | (a) Larsal's own names everywhere on the wire, keeping only the error numbers 1 to 34; (b) the reference's action and member names, so its extension could talk to Larsal | (a). The reference's extension calls only its own host id, which holds a banned word, and its manifests list its own ids (README D4: its extension cannot be used). So (b) buys nothing and would make Larsal's protocol look like a translation (AGENTS rule 2). The numbers stay because INT-04 already uses them; numbers are facts |
| D-INT01-2 | Channel crypto. Decided: spec/decisions.md LD-274 (1) (2026-10-31), which replaced the first recommendation (a) of 2026-10-28 (under LD-189) | (a) NaCl box: X25519 plus XSalsa20-Poly1305, `crypto_box`; (b) Bitwarden's: the extension makes an RSA-2048 key pair, the desktop sends an AES-256-CBC-HMAC session key encrypted with RSA (SHA-1 hash), messages are encrypted strings; (c) X25519, HKDF-SHA256 with one key per direction and AES-256-GCM with 12-byte nonces (INT-01.49): WebCrypto in the extension, `x25519-dalek`, `hkdf` and `aes-gcm` in larsal-crypto | (c), decided. WebCrypto has no XSalsa20-Poly1305, so (a) would make Larsal ship a JavaScript crypto copy or WebAssembly in the extension, and `crypto_box` has no stable release on Larsal's crypto generation (spec/research/browser-and-web.md section 8, B3). (c) uses only the browser's own crypto (LD-272 (6)), works where WebAssembly is off (Edge's Enhanced Security mode, Safari's Lockdown Mode; research section 6), keeps the identification key non-extractable, takes the primitives of the HPKE suite Larsal already uses (CRY-04.5), and needs no crate beyond E16-S2's. (b) needs RSA and a separate MAC (its `nativeMessaging.background.ts` and `biometric-message-handler.service.ts`); proven, but heavier |
| D-INT01-3 | Replay protection (AT-F02) | (a) A per-session set of seen nonces, each reply bound to its request's nonce (since LD-274 (1) the same nonce under the reply key, INT-01.23; the first channel used the request nonce plus one); (b) a timestamp inside each message with a time window (Bitwarden: 10 seconds, `MessageValidTimeout`) | (a). Sessions are short and fresh keys make cross-session replay impossible; (a) refuses every repeat with no clock; (b) still accepts repeats inside the window and breaks when clocks jump |
| D-INT01-4 | Proof of the identification key (INT-01.28) | (a) Proof of possession with a box from the identification key to Larsal's session key; (b) compare the presented key with the stored text, as the reference | (a). It costs one more box open; the stored value becomes truly public (FMT-14's note that association keys are public keys is then right), so a vault copy, backup or merge partner cannot act as the user's browser |
| D-INT01-5 | Generator over the bridge (INT-01.34) | (a) Larsal's generator window opens, the value goes back after Apply (reference, FEA-02.17); (b) the extension shows its own generator page, Larsal makes the value with its engine and returns it; (c) the extension makes values in JavaScript | (b). The locked frames `extension-popup-generator` and `extension-in-page-new-password` draw the generator inside the extension, so (a) does not fit; (c) would be a second generator outside Larsal's tested engine (FEA-02 and FEA-03 tests, AT-J). FEA-02.17's browser row and its "only after Apply" note then read: an associated session gets a value; no Larsal window |
| D-INT01-6 | Browsers in Larsal 1.0 (INT-01.8) | (a) The frame's six (Safari, Chrome, Firefox, Brave, Vivaldi, Opera) plus Edge; (b) the reference's list (Chrome, Chromium, Firefox, Vivaldi, Brave, Tor Browser, Edge, custom); (c) the frame's six only | (a). The frame is locked and E7-S6 names Edge; Bitwarden's desktop writes Edge too (`native-messaging.main.ts`). Chromium, Tor Browser and custom folders are rare on Mac and add a settings group the frame does not have. Adding the Edge row needs the owner's approval of a mockup change (AT-K05). APP-01's S-BRW-02 to S-BRW-08 list follows this decision. Since LD-272 (1) (2026-10-31, "the other Chromium browsers") Chromium and Arc are added too (INT-01.8, research B5); Tor Browser and custom folders stay out |
| D-INT01-7 | Safari route (INT-01.12 to INT-01.15) | (a) Larsal's Safari web extension and app extension inside Larsal, relaying the same protocol to an app-group socket; (b) a Safari-only protocol without the channel (Bitwarden's Safari path sends plain messages, because Safari routes only to the app's own extension) | (a). One protocol and one set of tests for every browser; the hop from the app extension to Larsal is a socket that other programs could reach, so the channel still matters. Needs a signing team id (owner item D7) |
| D-INT01-8 | Peer program check (INT-01.7) | (a) Check the connecting program's code signature in signed builds; (b) user id check only, as APP-09.14 | (a) in signed builds. The socket accepts only Larsal's own relays, so other same-user programs cannot even reach the connect dialog. Unsigned builds fall back to (b) |
| D-INT01-9 | Lists before secrets | (a) `logins.find` gives summaries without passwords and never asks; `logins.get` gives secrets for chosen entries and asks when needed; (b) one request that asks and returns passwords at once, as the reference | (a). The frames list matches (popup, in-page menu, badge count) before the user picks one; with (a) a page load never opens a dialog and passwords cross only when the user fills. The extension must draw lists in its own frame where the page cannot read them (E7-S7) |
| D-INT01-10 | Requests left out (INT-01.37) | leave out delete, list-all and the lookup scheme; or keep them | Leave out: no frame uses them; list-all is a known exposure (off by default in the reference) |
| D-INT01-11 | Association for lock, Auto-Type and the generator | (a) required; (b) not required, as the reference (SI-12) | (a). A same-user program without an association can still lock through APP-09's channel, so (a) loses nothing and keeps the bridge's rule simple: nothing but `status`, `connect`, `check` and `unlock` works without an association |

Check with Verify:

| ID | What to check |
|---|---|
| V-INT01-1 | Which folder Opera on macOS reads native messaging manifests from (Chrome's, or its own), with a throwaway user profile and a test HOME, never the owner's profile; a run that shows a browser window waits for the owner's go (AGENTS rule 10) |
| V-INT01-2 | How long Safari keeps an app extension request open while Larsal shows a dialog (INT-01.13), with a demo extension in a throwaway Safari profile, after the owner's go (needs a window) |
| V-INT01-3 | That Chrome refuses a host message of 1,048,577 bytes and accepts 1,048,576 (Chrome docs say "1 MB"), in a throwaway profile and a test HOME; a run that shows a browser window waits for the owner's go (AGENTS rule 10) |
| V-INT01-4 | That Arc on macOS reads native messaging manifests from `~/Library/Application Support/Arc/User Data/NativeMessagingHosts/` (INT-01.8; only a community report names it, research section 1), with a test HOME in E7-S7l, never the owner's profile; installing Arc waits for the owner's yes (AGENTS rule 7), and a run that shows a browser window waits for the owner's go (AGENTS rule 10) |

## Security notes

- **SI-01** (parity row): the reference encrypts the bridge with X25519 and XSalsa20-Poly1305; Larsal keeps its other parts (a small relay program and an owner-only local socket, manifests that allow only Larsal's extension ids, a user-confirmed named association per browser kept in the vault (INT-02), messages up to 640 KiB) and encrypts with X25519, HKDF-SHA256 and AES-256-GCM, one key per direction (INT-01.21, INT-01.49; LD-274 (1)). Larsal goes further: replays refused (INT-01.23, AT-F02), peer user id and, when signed, program checks (INT-01.6, INT-01.7), proof of the identification key (INT-01.28), versioned hello, boxed errors.
- **SI-12:** the vault id, lock, Auto-Type and the generator need an association in Larsal (INT-01.30, D-INT01-11, LD-73).
- **SR-15:** the only listeners are owner-only Unix sockets in the user's temp folder and in Larsal's app-group container; no network port (AT-E08 lists them).
- **AT-F01:** an unknown client gets nothing beyond `status` (vault names and lock states, which the user's own files already show to same-user programs). **AT-F03:** a wrong or corrupted key, nonce or box gives errors 10 or 4 and nothing else; a low-order client key is refused; a box sealed for the other direction does not open (INT-01.49). **AT-F04:** association only through INT-02's dialog. **AT-F07:** the limits of INT-01.44; errors carry numbers only.
- **What the channel does not protect against:** a program running as the same user can talk to Larsal's socket like the extension does (unless the program check of INT-01.7 is on) and must still pass the user's confirm to associate. The identification key is a non-extractable WebCrypto key, so no script of the browser can read its secret (INT-11.6); a same-user program that reads the browser's profile files or memory may still take it. Same-user malware is out of scope (plan/security.md).
- **What must never happen:** a reply in clear text that holds vault content; an association without the user's confirm; a replayed box acted on; a crash or hang from any frame; a manifest written outside the folders of INT-01.8 or over another program's file.

## Test cases

All tests run without a real browser and never touch the owner's browser folders or Safari: manifests go under a test HOME (`/tmp/spec-int01/home`), Larsal runs hidden with a test settings file (AGENTS rule 10), and a **test client** written for the tests speaks the protocol: it starts `larsal-bridge` as a child process and talks to its standard input and output exactly as a browser would, or talks to Larsal's socket directly. The test client uses its own X25519 keys (demo values below), seals and opens with INT-01.49's keys, and stops every process it starts by PID. The Safari relay is tested by calling the app extension's handler with a test request object.

Demo keys (base64): client session key C = `wcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcE=`; Larsal session key A (fixed only in test builds) = `oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaE=`; identification key I = `HR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0=` (bytes C1, A1 and 1D repeated; used where only hashing is tested; channel tests use real key pairs made at test start, and the known-answer tests INT-01.50's fixed keys). T36 to T38 are retired (2026-11-01): they tested the 24-byte nonce increment of the first channel, which LD-274 (1) removed; the numbers are not reused. Demo vault V (`bridge-demo.larsalvault`, password `demo-bridge-vault`) with the association `demo` holding a test identification key; vault W without associations.

| Case | Given | When | Then |
|---|---|---|---|
| T01 INT-01.1 | `larsal-bridge` started by the test client, Larsal running | Frame of a hello (length little-endian, then JSON) | One reply frame on stdout with a hello reply; nothing else on stdout |
| T02 INT-01.2 | Test client on Larsal's socket | Send a hello as two writes: 2 bytes of the length, then the rest | One hello reply |
| T03 INT-01.2 | Socket | Two complete frames in one write | Two replies, in order |
| T04 INT-01.2 | Socket | A frame whose length says 100 and the stream ends after 50 bytes | Connection closed; Larsal keeps running and accepts a new connection |
| T05 INT-01.3, INT-01.38 | `larsal-bridge` | Length prefix 1,048,577 | Plain error 43 on stdout, `larsal-bridge` exits; no 1 MiB buffer reserved (allocation counter in the test build) |
| T06 INT-01.3 | Socket | Length prefix `FF FF FF FF` | Connection closed at once; peak memory unchanged |
| T07 INT-01.5, INT-01.38 | Larsal not running, no Larsal process | Frame of a hello | `{"type":"error","error":44}` |
| T08 INT-01.5, INT-01.38 | Larsal running, S-BRW-01 off | Frame of a hello | `{"type":"error","error":45}` |
| T09 INT-01.5 | T07, then Larsal starts with S-BRW-01 on | Next frame: a hello | A hello reply on the same `larsal-bridge` process |
| T10 INT-01.5 | Session open | Larsal quits | Next frame gets 44 |
| T11 INT-01.5 | `larsal-bridge` running | Close its stdin | Exits within 1 second |
| T12 INT-01.6 | Darwin temp folder | Start Larsal with S-BRW-01 on | Socket `app.larsal.browser.sock` exists there, mode 0600; `TMPDIR` set to `/tmp/x` changes nothing |
| T13 INT-01.6 | A regular file named `app.larsal.browser.sock` in the folder | Start Larsal | MI01-06 on the settings page; the file is untouched; no listener |
| T14 INT-01.6 | A process running as another user (CI fixture) | Connects to the socket | Closed right after accept; no reply |
| T15 INT-01.7 | Signed test build | A test program signed differently connects | Closed; with an unsigned build: accepted and one debug log line |
| T16 INT-01.8 | Test HOME, S-BRW-01 on | Turn Chrome on | `‹HOME›/Library/Application Support/Google/Chrome/NativeMessagingHosts/app.larsal.browser.json` exists |
| T17 INT-01.8 | T16 | Turn Opera on, then Chrome off | The Chrome-folder file still exists; then Opera off: removed |
| T18 INT-01.9 | T16 | Read the file | Members in order `name`, `description`, `path`, `type`, `allowed_origins`; `path` is the resolved path of `larsal-bridge` in the test bundle; two-space indent, final LF; no `*` anywhere |
| T19 INT-01.9 | Test HOME | Turn Firefox on | `Mozilla/NativeMessagingHosts/app.larsal.browser.json` with `allowed_extensions` holding Larsal's add-on id and no `allowed_origins` |
| T20 INT-01.10 | Chrome's folder made read-only with a file holding exactly Larsal's content | Turn Chrome on | Success, no message |
| T21 INT-01.10 | Read-only folder with a file of other content | Turn Chrome on | MI01-01 naming Chrome; switch back off |
| T22 INT-01.10 | A file `app.larsal.browser.json` whose `name` is `other.host` | Turn Chrome off | File not removed |
| T23 INT-01.11 | Manifest with `path` `/Applications/Old/Larsal.app/Contents/MacOS/larsal-bridge`, S-BRW-21 on | Start Larsal | `path` rewritten to the current bundle |
| T24 INT-01.11 | Same, S-BRW-21 off | Open the settings page | MI01-02 for that browser |
| T25 INT-01.13 | Safari handler test with Larsal listening on the test app-group socket | Handler gets a hello in `SFExtensionMessageKey` | Completes with the hello reply |
| T26 INT-01.14 | Safari route, session made at T0 | Boxed `status` at T0+14 min on a new connection; another at T0+30 min | First answered; second gets plain error 3 |
| T27 INT-01.15 | Unsigned build | Open the settings page | Safari switch disabled with MI01-04 |
| T28 INT-01.20 | Socket | Hello with `versions` `[2,3]` | Plain error 40 with `"versions":[1]` |
| T29 INT-01.20 | Socket | Hello with `versions` `[1,2]` | Reply `"version":1`, a 32-byte key and a 16-byte `sid`, no `nonce` member; a boxed `status` sealed with the request key derived from that reply is answered |
| T30 INT-01.20 | Socket | Hello whose key is 32 zero bytes, then one with the low-order point of order 8 (RFC 7748) | Plain error 10 both times |
| T31 INT-01.20 | Session with a waiting `connect` dialog | A second hello on the same connection | Dialog closes as Deny, nothing stored; no reply for the old `connect`; the new hello is answered |
| T32 INT-01.21 | Session | Boxed `status` with a correct box | Boxed reply, same `type` and `req` |
| T33 INT-01.21 | Session | The same request with one bit of the box flipped | Plain error 4; nothing else happens |
| T34 INT-01.21 | Two connections X and Y with sessions | Send X's `sid` on Y | Plain error 3 |
| T35 INT-01.21 | Session | Box content `{"type":"status","req":"7"}` (`req` as text) | Boxed error 12 without `req`; no status reply |
| T39 INT-01.23 | Session, a `status` request already answered (AT-F02) | Send exactly the same frame again | Plain error 41; Larsal's request counter shows one `status` handled |
| T40 INT-01.23 | Session | Send Larsal's last reply frame back to Larsal as a request | Plain error 41 |
| T41 INT-01.24 | Session | Box content of 655,361 bytes (valid JSON) | Boxed error 43 |
| T42 INT-01.25 | Session | Content `{"type":"status","type":"lock","req":1}` | Error 12; the vault is not locked |
| T43 INT-01.25 | Session | Content nested 33 levels deep | Error 12 or 43, no crash |
| T44 INT-01.26 | Hello | `key` with a `-` character, or without its `=` | Plain error 10 |
| T45 INT-01.28 | Session, I's secret known to the client | `check` with a proof made for another session's client key | Error 8 |
| T46 INT-01.28 | Session | `check` with the right proof | `vaults` lists V with `connection` `demo` |
| T47 INT-01.28 | Session; the stored public key copied out of V's custom data | `check` with that public key and a proof made with a different secret key | Error 8 |
| T48 INT-01.30 | Session without proof | `logins.find` | Error 8 |
| T49 INT-01.30 | Session with proof, V locked, W unlocked | `logins.find` | Error 1 |
| T50 INT-01.30, INT-01.37 | Session with proof | `type` `entries.delete` | Error 12 |
| T51 INT-01.31 | Root group id bytes `00 01 … 0F` | Compute the vault id | `RpmvWIIvs0ZGs1aaWkG24Q` |
| T52 INT-01.31 | Session without proof, V unlocked | `status` | V listed with name and state, without `id` and `connection` |
| T53 INT-01.34 | Session with proof | `password.generate` `{"kind":"password","options":{"length":20}}` | `value` of 20 characters, `bits` > 0; no Larsal window; the saved generator settings unchanged |
| T54 INT-01.34 | Same | `options` `{"length":1000000}` | Error 43, nothing allocated past FEA-02's bound |
| T55 INT-01.35 | V shown and unlocked, W unlocked, session proven for V | `lock` | V locked, W unlocked; a `locked` notice arrives |
| T56 INT-01.36 | Session with proof | `autotype.start` with a 257-character `search` | Error 43; Auto-Type not started |
| T57 INT-01.40 | Every error case above | Inspect each reply | Holds only `type`, `req`, `error` (and `versions` for 40); no text, no title, no URL |
| T58 INT-01.41 | V locked, then unlocked; a session with and one without proof | Send a box that does not open, 1,000 times in each state | The same reply bytes every time; median answer times differ by less than 1 ms |
| T59 INT-01.44 | Session | 9 `logins.get` requests that each wait for a prompt | The 5th waiting one gets 42 (4 wait); after the limit of 8 in flight, 42 |
| T60 INT-01.44 | 17 test clients | Connect at once | The 17th is closed at once; Larsal's main thread answers a UI ping within 100 ms during the run |
| T61 INT-01.44 | Session (AT-F07) | 10,000 `status` requests as fast as possible | All answered or 42; no crash; no reply holds text; Larsal's window stays responsive (UI ping) |
| T62 INT-01.45 | `connect` dialog shown (fake clock) | 120 s pass | Error 6; nothing stored |
| T63 INT-01.46 | Two sessions, one proven for V, one not | Lock V | Only the proven session gets a boxed `locked` notice, sealed with its reply key; its nonce is not the nonce of any request of that session |
| T64 INT-01.47 | Every test above, debug build | Search the logs and `larsal-bridge`'s standard error | No demo password, username, title, URL or key appears |
| T65 INT-01.48 | Fuzz target "browser message" | 10 minutes | No crash, no timeout, no allocation over 2 MiB |
| T66 INT-01.4 | Larsal running | Start `larsal-bridge` with Chrome's argument `chrome-extension://abc/`, then with Firefox's two arguments (a manifest path and an add-on id); send a hello each time | Both answered alike; standard output holds only frames |
| T67 INT-01.12 | Release build of Larsal | List `Larsal.app/Contents/PlugIns/` and read the app extension's Info.plist | The Safari app extension is there and names the Safari web extension handler as its principal class |
| T68 INT-01.22 | Session; test build starts the request counter at 99,999 | Two boxed `status` requests, then a new hello and a `status` | The first is answered, the second gets plain error 41; after the new hello `status` is answered |
| T69 INT-01.25, INT-01.27 | Session with proof | `logins.find` with a `url` of 8,193 bytes | Boxed error 43; nothing searched |
| T70 INT-01.29 | Session proven for V; V unlocked behind MOD-13's forced key change prompt | `logins.find` | Error 1 |
| T71 INT-01.33 | Session with proof | `logins.search` with a 257-character `text` | Error 43 |
| T72 INT-01.28 | Session | `check` with an `id_key` of 32 zero bytes, then with an `id_key` equal to the hello's client key (each with a proof made for it) | Error 10 both times; nothing opened or stored |
| T73 INT-01.23 | Session that got a `locked` notice with nonce M | A request with nonce M | Plain error 41, nothing done (its reply would reuse M under the reply key) |
| T74 INT-01.11 | S-BRW-01 and S-BRW-23 on, S-BRW-24 `/tmp/spec-int01/missing-proxy` | Open the settings page | MI01-05 naming that path |
| T75 INT-01.27 | Session with proof | `logins.find` with a `top_url` of 8,193 bytes; again with a `form_url` of 8,193 bytes; again with `url`, `top_url` and `form_url` of exactly 8,192 bytes each | Boxed error 43 the first two times, nothing searched; the third request is searched (entries or error 15) |
| T76 INT-01.32 | Session proven for INT-04's demo vault (its entry P1 and its requests R1 and A1); dialogs answered by the test's scripted answerer | `passkey.create` with `public_key` = R1's options, `origin` `https://example.com`, `group` empty, answer Register (and Create at the group question, INT-04.24); then `passkey.get` with `public_key` = A1's options and `origin` `https://example.com`, answer Authenticate; then each request again with `type` `passkeys-register` and `passkeys-get`; then `passkey.create` that sends R1's options under `publicKey` instead of `public_key` | INT-04's create and sign-in dialogs show; the replies' `response` hold the credential objects (the create reply with `response.publicKey`, the WebAuthn name); the reference's action names get error 12; the options under `publicKey` count as missing: error 24 (INT-04.9) |
| T77 INT-01.42 | Socket | A hello with an extra member `"future":1`, then a boxed `status` whose content adds `"future":{"x":1}`; then the same two messages to a test build that reports its product version as `9.9` instead of `1.0` | Both answered as without the extra member; the two builds' replies are equal except the hello reply's `app` text, and both pick `"version":1` |
| T78 INT-01.50 | The published vectors of INT-01.50 (RFC 7748 section 6.1, RFC 5869 A.1 to A.3, CAVP G1 to G3) | Compute each in larsal-crypto (E7-S1) | Every value equals the table byte for byte (PRK and OKM for HKDF; CT and Tag for GCM) |
| T79 INT-01.49, INT-01.50 | INT-01.50's fixed inputs | Compute CV-1 to CV-9 in larsal-crypto (E7-S1), then in WebCrypto in headless Chrome through E7-S7b's driver (E7-S7c) | CV-1 equals its concatenation; Z equals RFC 7748's K; CV-7 is the same both ways; the WebCrypto results equal the larsal-crypto results byte for byte |
| T80 INT-01.49, INT-01.21 | Session | A request sealed with the reply key instead of the request key | Plain error 4; nothing done |
| T81 INT-01.23 | Session | Boxed `status` with nonce N | The reply's nonce is N; it opens with the reply key and not with the request key |
| T82 INT-01.26 | Session | A box with a nonce of 11 bytes, one of 13 bytes, and a box of 15 bytes | Plain error 4 each time |
| T83 INT-01.21 | Session | A box with an unknown `sid` and a bad nonce; then a box whose nonce was already seen and whose box is not valid base64 | Plain error 3, then plain error 41 (the order of INT-01.21) |
| T84 INT-01.28 | Session, I's secret known to the client | `check` with a proof of 47 bytes; a proof sealed with the right key but another request's nonce; a proof whose content is A instead of C | Error 8 each time; nothing stored |
| T85 INT-01.20 | Socket | Hello whose `browser` is `Arc`, then one with `browser` `NoSuchBrowser` | Both answered; Larsal's connect dialog names Arc, then Browser |
| T86 INT-01.30 | Session proven for its key I; vaults V (shown) and W unlocked, V stores I under `demo` and W under `work`, each with its `_CREATED_` and `_LAST_USED_` items; X locked; S-BRW-14 off | `disconnect`. Again, with only W storing I (V shown, unlocked, without it). Again, with V locked and shown, W storing I | No Larsal dialog; V and W no longer hold the `demo` and `work` association items or their `_CREATED_` and `_LAST_USED_` items; X's file is unchanged; the reply is `disconnect` with the request's `req` and `"unchanged":["X"]`; the next `logins.find` gives error 8. Only W: error 8, and W still holds `work` and its two items. V locked: error 1, and W still holds them |
| T87 INT-01.8 | Test HOME whose `Library/Application Support/` holds the folders `Chromium/` and `Arc/User Data/`, S-BRW-01 on | Turn Chromium on, then Arc on; then both off | `‹HOME›/Library/Application Support/Chromium/NativeMessagingHosts/app.larsal.browser.json` and `‹HOME›/Library/Application Support/Arc/User Data/NativeMessagingHosts/app.larsal.browser.json` exist, each with `allowed_origins` and no `allowed_extensions`; Larsal made only the last folder level (INT-01.10); off removes each file |
| T88 INT-01.25, INT-01.48 | Session | (a) A plain frame of 1,048,575 bytes, `[0,0,…,0]`; (b) a box whose content is 600,000 bytes, `{"type":"status","req":1,"a":[0,…]}`; (c) a box whose content is a list of 16,385 empty lists (`[[],[],…]`); (d) a box with 16,384 commas and brackets in all, a valid `status` | (a) plain error 12, (b) and (c) boxed error 12, and the handler sees none of them; (d) answered; no allocation over 2 MiB |
| T89 INT-01.44 Safari sessions | Safari route, injected clock | 33 Safari hellos, one per second, then a box for the first session and one for the 33rd | 32 sessions live after the 33rd hello; the first session gets error 3; the 33rd is answered |

## How this was learned

- Read in the reference source (development branch): the relay program (its standard-input reader that assembles a 4-byte length little-endian, byte by byte, and then reads byte by byte with a 100 ms pause loop, its socket writer without framing, its reply writer that puts the length in front, its signal handling and its quit on socket close); the shared browser constants (the 1 MiB socket buffer and the 640 KiB message limit, the list of supported browsers, the per-user temp folder that bypasses `TMPDIR`); the host's local server (owner-only option, readyRead handling, the splitting of coalesced data at every closing brace, the fragment buffer and its length limit, the broadcast to every socket); the message builder (key pair creation, the error reply with English text, the response with version, success flag and nonce, box sealing and opening with their length checks, the nonce increment, strict base64 decoding); the action handler (the list of request names, the check that a session key exists, the unlock trigger flag, the associate and test-associate handlers, the per-request association flag, the generator, lock and Auto-Type requests that skip the association check, the vault-hash reply); the service's client table keyed by a client-chosen id; the lock and unlock notices; the manifest installer (host name, allowed ids, the macOS folders per browser, the manifest members, the read-only file case, the path rewrite on start); the settings defaults; the browser unit tests (the fixed test keys and nonce pair, which Larsal does not reuse).
- Read in the reference's documentation: the browser integration topic (setup steps, the custom browser folder, the managed Edge manifest).
- Not run: no browser, no extension and no manifest was installed anywhere; the reference app was not started.
- Channel rewrite (2026-11-01, E7-S7a): public sources only, read 2026-11-01; the reference was not opened. RFC 7748 (section 6.1 and its test vector), RFC 5869 (sections 2.2 and 3.1, appendix A), RFC 9180 section 4.1 (the empty-salt extract of an X25519 result), RFC 8446 section 7.3 (a write key per direction), NIST SP 800-38D (sections 8.2.2 and 8.3) and the NIST CAVP file `gcmEncryptExtIV256.rsp` in `gcmtestvectors.zip`, the W3C Web Cryptography API Level 2 editor's draft of 22 October 2026 (X25519 derive bits with its all-zero check, raw import of public keys only, non-extractable HKDF keys); spec/research/browser-and-web.md B3 and section 8.
- Proven standards (AGENTS rule 9), read 2026-10-28: Chrome "Native messaging" (manifest members, the name rule, no wildcards in `allowed_origins`, the macOS folders for Chrome and Chromium, 32-bit native-order length, host messages at most 1 MB, browser messages at most 64 MiB, the caller origin as first argument, one process per port); MDN "Native messaging" (native byte order, 1 MB from the app and 4 GB to it, the manifest path and add-on id as arguments, SIGTERM then SIGKILL, standard error shown in the browser console) and MDN "Native manifests" (members, `allowed_extensions`, the macOS per-user folder); Apple "Messaging between the app and JavaScript in a Safari web extension" (the `nativeMessaging` permission, background scripts only, the app extension's request handler and `SFExtensionMessageKey`, the ignored application id, `connectNative` and `SFSafariApplication.dispatchMessage`, separate sandboxes joined by app groups). Bitwarden source on GitHub (`apps/browser/src/background/nativeMessaging.background.ts`, `apps/desktop/src/main/native-messaging.main.ts`, `apps/desktop/src/services/biometric-message-handler.service.ts`): host name and manifests per browser including Edge, Brave, Vivaldi and an Opera extension id, a separate proxy program next to the app, an RSA-2048 key exchange from the extension, an AES-256-CBC-HMAC session key, a 10-second timestamp window, a 60-second reply timeout, connected apps keyed by an app id, and a Safari path without encryption. Bitwarden help "Unlock with biometrics" (the "Require verification for browser integration" option). Proton Pass support "Biometric unlock" (its extension and desktop app are set up separately; no desktop-to-extension link is described). Opera forum threads on its macOS manifest folder (inconclusive; V-INT01-1).

## Review 2026-10-28

Second Spec review. Read again in the reference source: the relay program, the host's socket reader, the message builder, the action handler, the service's client table and notices, the manifest installer and the shared constants. Nothing was run and nothing touched a browser.

Confirmed against the reference source: every "Reference difference" and "(reference)" note of this card: no framing on the socket and the split at every `}`; a 4-byte length read on standard input; quit when Larsal closes the socket; the client table keyed by a client-chosen id; the stored key compared as text; no record of nonces; libsodium's increment for the reply nonce; English error text in every error; the vault hash sent to any client; lock, Auto-Type and the generator without an association; plain lock and unlock notices to every socket; the macOS folders for each browser; the read-only manifest case; the 1 MiB and 640 KiB limits; the 256-character Auto-Type search. Error numbers 1 to 34 match the reference's table. Recomputed and correct: T36 to T38 (nonce increment), T51 (vault id), the demo keys.

Channel check: fresh X25519 keys on both sides per session, then `crypto_box` (XSalsa20-Poly1305) with one shared key for both directions; reply nonce = request nonce plus one, checked by the client; replays and reflected replies refused. Two gaps fixed (below): a reply nonce could still hit a nonce the client had used, and a low-order or reused `id_key` made the proof worthless.

Fixes made (13): INT-01.10 counts the same JSON as success (the reference compares JSON documents) and takes the manifest base folder from the test settings in tests (AGENTS rule 10); INT-01.11 says when MI01-05 shows; INT-01.23 also refuses a request whose nonce plus one was seen or used; INT-01.28 refuses a low-order `id_key` or one equal to the session key (error 10); INT-01.30 `status` names vaults by file name (so AT-F01's claim holds) and `logins.update` may answer `updated` false (INT-02.25); INT-01.34 names the `options` members and defines `bits`; INT-01.36 answers an overlong search with 43, not the reference's 14 ("no URL"); INT-01.40 notes that 24 and 25 are boxed errors (INT-04.54); V-INT01-1 and V-INT01-3 wait for the owner's go when a browser window would show; "How this was learned" says little-endian; new tests T66 to T74 for INT-01.4, .11, .12, .22, .23, .25, .28, .29 and .33.

Findings, each with a proposed ruling:

| ID | Finding | Proposed ruling |
|---|---|---|
| R01-1 | The locked frame `extension-extension-options` has "Disconnect this browser" with "Larsal forgets this browser", but INT-01 has no request for it | Add `disconnect` (association needed; no Larsal dialog, the extension's button is the confirm, as for `logins.save`): in every unlocked vault that holds the session's key Larsal removes the association item, `_CREATED_` and `_LAST_USED_` for each name holding it (a data change); the reply lists the locked vaults it could not change; the extension then drops its identification key, so any leftover is useless (INT-01.28) |
| R01-2 | INT-01.10 creates only the last folder level, but the edge case "Manifest folder missing" creates the whole path. Opera depends on it when it reads Chrome's folder and Chrome is not installed | Last level only (Bitwarden writes manifests only where the browser's folder exists). A missing browser folder: the switch goes back to off with a new MI01-07 "‹browser› wasn't found on this Mac. Open it once, then turn it on here."; Opera follows V-INT01-1; fix the edge case to match |
| R01-3 | plan/attacks-and-checks.md AT-E08 expects the instance socket as the only listener, and plan/security.md SR-15 names only the temp folder; this card adds the bridge socket and the Safari socket in the app-group container | The lead adds both bridge sockets to AT-E08's expected result and the app-group socket to SR-15 |
| R01-4 | The locked frames `extension-in-page-save-sign-in` ("Strong") and `extension-in-page-update-password` ("Reused", "Strong · 22 characters", "eBay still uses it") need strength and reuse data for a typed password, which no request gives. A "reused" answer would tell any associated client whether a guessed password is stored | Larsal sends no strength or reuse data for typed passwords. The reuse note goes into Larsal's own update question MI02-07 (Larsal computes it locally, FEA-05); the lines leave the extension frames (a mockup change for the owner, AT-K05). Larsal's question after the extension's card stays, as in the reference (SI-10). Generated values keep `bits` (INT-01.34) |
| R01-5 | D-INT01-6 (the Edge row) and D-INT02-4 (four mockup gaps) need the owner's approval of mockup changes (AT-K05); with R01-2, R01-4 and R02-3 the list grows, but spec/decisions.md "Waiting for the owner" is empty | The lead puts one owner item there listing every mockup addition of INT-01 to INT-03 before E7-S2 starts |

## Channel rewrite 2026-11-01

E7-S7a, for LD-274 (1) (B3: the extension's half of the channel uses only WebCrypto). Changed: INT-01.20 (no hello nonce; `Chromium` and `Arc` names), INT-01.21 (AES-256-GCM boxes, 12-byte nonces, the order of checks), INT-01.22 (the request and reply keys), INT-01.23 (one key per direction; the reply uses its request's nonce; the nonce increment is gone), INT-01.26 (12-byte nonces, 48-byte proofs), INT-01.28 (the proof is an AES-GCM seal under a key from the identification key's X25519 result), INT-01.47 (the new keys), new INT-01.49 (key schedule) and INT-01.50 (known answers), D-INT01-2 (decided (c)), D-INT01-3's wording of option (a), the overview, the standards line, SI-01 and AT-F03 in the security notes, T29, T63, T73, new T78 to T85; T36 to T38 retired. Unchanged in their results: the request table (INT-01.30 to INT-01.38), the errors (INT-01.40, INT-01.41: every case that gave an error number still gives the same one), the relay and transport (INT-01.1 to INT-01.15), the identity rules (INT-01.28's errors 10 and 8 for the same cases, INT-01.29) and the tests that cover them. The 2026-10-28 review above describes the first channel and is kept as it was.

Added later on 2026-11-01 (E7-S7a, LD-295 (3)): INT-01.8's Chromium and Arc rows and the paragraph under its table, D-INT01-6's last sentence and V-INT01-4; INT-01.30's `disconnect` row and its paragraph (LD-191, R01-1); T86 and T87. Round-4 fixes (same day): the overview names Chromium and Arc; INT-01.30's `disconnect` paragraph says the "Assoc." check runs first and points to INT-11.40 for its errors. Every other request keeps its result.
