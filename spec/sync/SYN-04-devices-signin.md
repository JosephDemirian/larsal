# SYN-04 Devices, sign-in and sessions

Status: reviewed
Epics: E16-S5 (server: accounts, challenges, signature check, sessions, revoke, 401 and 429), E16-S6 (the device key in larsal-platform `device_key.rs`), E16-S7a (the client side), E17-S3 (the device list, revoke, sign out everywhere)
Parity rows: none in the reference app (it has no server). Larsal's own rows: SV-01 and SV-03 (plan/security.md); AT-L06 to AT-L08 (plan/attacks-and-checks.md)

## What it does

Each Mac signs in to Larsal's server with its own P-256 key, kept in the Secure Enclave where the Mac has one. The server sends a one-time nonce; the Mac signs it together with a fixed label, the server's origin and its device id; the server checks the signature with the public key it stored and hands out a session token. No password goes to the server, in any form. The server keeps public keys and the SHA-256 of each token only.

Other cards: SYN-01 owns the routes and headers, SYN-06 a new Mac (approval or Recovery Kit) and the account keys, CRY-04 the P-256 check.

Design and sources: spec/research/sync-server.md P5 (decided: spec/decisions.md LD-263 (4), LD-267 (4), LD-273 (1)).

## Inputs and outputs

- In: the device key (SYN-04.1); the routes of SYN-01.4 marked SYN-04.
- Out: a session token held in memory by the client; device rows on the server.
- Limits: SYN-01.10 and SYN-01.12.

## Rules

SYN-04.1 **The device key** (P5; Apple, "Protecting keys with the Secure Enclave"; TN3137). One P-256 key per Mac per server account, made through `security-framework` in larsal-platform `device_key.rs`:
- with a Secure Enclave: `kSecAttrTokenIDSecureEnclave`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, usage "sign" only;
- without one: a software P-256 key in the data protection keychain, this device only;
- until W-02 gives the keychain entitlement (TN3137: both stores need it): cargo tests use an in-memory software key behind a test seam, never written; the app keeps a software key in the login keychain. The this-device-only checks stay open until W-02.
No call returns the private key's bytes; `device_key.rs` only signs (ECDSA with SHA-256 over the message, X9.62 DER signature) and gives the public key as 65 SEC1 bytes (CRY-04.4).

SYN-04.2 **A new account** (E16-S5). `POST /v1/accounts` with `{"device_public_key":…,"device_name":…}` makes an account row and its first device row and answers 201 with `{"account_id":…,"device_id":…}`, both 16 bytes from larsal-crypto's random source on the server. A public key that is already registered gets 409. A `device_public_key` that is not a valid P-256 point (CRY-04.4) gets 400, and no row is made: such a key could never pass a sign-in (LD-327 (3)). The name is 1 to 64 Unicode scalar values, none of them in the Unicode category Cc (this holds for every `device_name`, also those of SYN-06.11 and SYN-06.12); Larsal fills in "Mac" and never the Mac's computer name, which often holds a person's name. The client then signs in (SYN-04.4). From E17-S1 sign-up also uploads the account keys (SYN-06.6).

SYN-04.3 **Challenge.** `POST /v1/signin/challenge` with `{"device_id":…}` answers `{"nonce":…,"expires":…}`: 32 random bytes, valid 300 s, bound to that device id. 300 s is the default ceremony timeout of WebAuthn Level 3 section 15.1; section 13.4.3 asks for a challenge of at least 16 bytes, valid about as long as the upper limit of that range, 600 s, and Larsal takes the shorter default, because this sign-in asks the user nothing. An unknown or revoked device id gets the same reply, so ids cannot be probed; its sign-in then fails. No count of open challenges per device is kept, so nobody can push out a device's own challenge; the rate limits of SYN-01.12 and the expiry bound them.

SYN-04.4 **Sign-in** (P5). The Mac signs the CRY-04.2 field list (`sync-signin-v1`, origin, nonce, `device_id`) with its device key and sends `POST /v1/signin` with `{"device_id":…,"nonce":…,"signature":…}`. Origin is the server's origin as the client connected to it: `https://`, the host in lower case, `:`, the port in decimal, always written: unlike RFC 6454 section 6.2, which leaves out a scheme's default port, so both sides build the same bytes. The server checks, and any failure gets 401 with one body for every reason:
1. the nonce exists, is unused, not expired and bound to that `device_id`;
2. the device exists and is not revoked;
3. the signature verifies with the stored device public key over the field list built with the server's own origin (its start flag, or `https://127.0.0.1:<bound port>`) (CRY-04.4).
The nonce is deleted at the first sign-in attempt that names it and passes SYN-01.8's body checks, whether the sign-in then passes or fails (one use). A body that fails SYN-01.8 (for example a signature of the wrong length) gets 400 and leaves its nonce, because no signature was checked (LD-327 (3)).

SYN-04.5 **Session** (P5; OWASP Session Management). A passed sign-in makes a 32-byte token from larsal-crypto's random source and answers `{"token":…,"idle_seconds":900,"expires":…}`. The server stores only the token's SHA-256 and looks sessions up by it: an index lookup, with no compare of a token or its hash in Larsal's code, so a timing difference can show only bits of the hash of a 256-bit random value (CRY-04.11 holds; LD-329 (3)). A session ends 15 minutes after its last use (idle) and 8 hours after it was made (absolute), on the server's clock (OWASP: 15 to 30 minutes idle for low-risk applications; 4 to 8 hours absolute for a working day); then it gets 401 and its row is deleted. There are no refresh tokens: the Mac signs in again with its device key, which asks the user nothing.

SYN-04.6 **The client's token.** Larsal keeps the token in memory only: never on disk, in the state file, a log or the pasteboard. On a 401 it signs in again once (SYN-03.10).

SYN-04.7 **Sign out.** `POST /v1/signout` deletes this session's row: 204. The token gets 401 from then on.

SYN-04.8 **Devices** (E17-S3). `GET /v1/devices` lists the account's devices: `{"devices":[{"device_id","name","added","last_seen","this_device"}]}`. `last_seen` is the time of the device's last session use, kept to the minute. `DELETE /v1/devices/{device_id}` revokes a device of this account: its row, its sessions and its open challenges go, and its next call and its next sign-in get 401. A Mac may revoke itself. Revoking the account's last device gets 409 (the account would be reachable only by its Recovery Kit, SYN-06.12, and before E17 not at all). Another account's device id gets 404.

SYN-04.9 **Sign out everywhere** (E17-S3). `POST /v1/devices/signout-everywhere` deletes every session of the account, this one included, and every device but this one: 204. This Mac then signs in again. Each other Mac, at its next contact, gets 401 and then 401 on sign-in; it then drops its cached account data for that server: its device key, the account secret and keys (SYN-06.8), its pinned keys and its sync links (SYN-03.3). It keeps every local vault file unchanged and every key-file part a local vault still needs to open (SYN-03.15); Larsal offers to save each part as a key file (SYN-03.12).

SYN-04.10 **What the server holds and sees** (P5; plan/architecture.md, "What the server sees"). Account ids; device ids, public keys, names, added and last-seen times; the SHA-256 of each session token; open nonces; IP addresses. Never a password or a value made from one (except the account blob of SYN-06.4, which also needs the account secret), a private key in plain form or a token.

SYN-04.11 **A second device before E17-S2.** A server test helper registers a second device key for an account (tests only: built only for tests, never in a release server or app). E17-S2 replaces it with SYN-06.11's approval.

## Edge cases and errors

- A nonce used for a sign-in with another device id: 401, and the nonce is gone for its own device too.
- A sign-in 301 s after its challenge: 401 (expired).
- A signature over the origin `https://localhost:8443` sent to a server whose origin is `https://127.0.0.1:8443`: 401 (another origin).
- A signature with a high S value from the Secure Enclave: accepted (CRY-04.4).
- Revoking a device while its sync run is in the middle of a PUT: the PUT that started before the revoke may finish; the next call gets 401.
- The Mac's clock is wrong: no effect; every expiry is checked on the server's clock.
- A device name of 65 Unicode scalar values, or one with a line feed (U+000A, category Cc): 400.

## Security notes

- **No password, no verifier (SV-01, AT-L08).** SRP and OPAQUE both leave a record a corrupted server can attack offline (RFC 5054 section 3.3; RFC 9807 section 10.11); Larsal's vaults never depend on the server, so sign-in needs no password at all. The server holds public keys, which cannot be guessed back into anything (P5).
- **Replay and relay (AT-L07).** The nonce is one-time and short-lived, the origin binds the signature to this server, and the device id binds it to this device; a signature captured by another server or replayed later does not sign in.
- **Stolen database (SV-03).** Token hashes cannot be turned back into tokens; a copy of the sessions table signs in nobody.
- **Device names are seen by the server.** Larsal never fills in the computer name, so the default holds no personal data.
- **Rate limits** (SYN-01.12). A signature cannot be guessed, so the rate limits only slow the spraying of nonces and signatures.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| T01 SYN-04.1 software key (E16-S6) | The test-seam key | Sign a message through `device_key.rs`; verify with larsal-crypto (CRY-04.4) | Verifies; no function of `device_key.rs` returns 32 private bytes |
| T02 SYN-04.2 new account | Empty server | `POST /v1/accounts` with key K and name "Mac"; again with K; then, each with a new key, a name of 0 characters, one of 65 ASCII letters, "Ma" U+0007 "c", one of 65 "ä" (U+00E4, 130 bytes in UTF-8), one of 64 ASCII letters, and one of 64 "ä" (128 bytes) | 201 with two 32-hex ids; then 409; then 400, 400, 400 and 400, with no row made; then 201 and 201 |
| T03 SYN-04.3 probe | Server with device d1; unknown id d9 | Challenge for d1 and d9 | Both replies have the same fields and sizes |
| T04 SYN-04.4 valid sign-in | d1 with key K | Challenge, sign with K, sign in | 200 with a 43-character token; the `sessions` row holds only its SHA-256 (SYN-02.3) |
| T05 SYN-04.4 each failure (E16-S5) | d1, d2 | Sign in with: a reused nonce; the nonce of d2; another origin; d2's id with d1's signature; one changed byte of the signature; one changed byte of the message; a nonce 301 s old | 401 each time with equal bodies |
| T06 SYN-04.4 one use | d1 | Sign in with a wrong signature, then with the right one on the same nonce | Both 401 |
| T07 SYN-04.5 expiry | Test clock | Use a session at 0 and at 14 min; then wait 16 min; separately use it every 10 min for 8 h 10 min | Works at 14 min; 401 after 16 min idle; 401 after 8 h even with use |
| T08 SYN-04.6 token stays in memory | A client that signed in | Search the state file, logs and the client's files | No token |
| T09 SYN-04.7 sign out | A session | Sign out; then `GET /v1/vaults` | 204; then 401 |
| T10 SYN-04.8 revoke (E16-S5, E17-S3) | d1 and d2 of one account | d1 revokes d2; d2 calls `GET /v1/vaults`; d2 signs in; d1 revokes itself while d2 is gone | 204; 401; 401; 409 (the last device) |
| T11 SYN-04.8 list | d1, d2 | `GET /v1/devices` from d1 | Two items; `this_device` true for d1 only; `last_seen` to the minute |
| T12 SYN-04.9 sign out everywhere (E17-S3) | d1, d2, d3; d2 has vault D linked | d1 signs out everywhere; d2 syncs | d1 signs in again; d2 gets 401 twice, drops its account data and link; D's file on d2 byte-identical and still opens with its password and part; the `sessions` table holds only d1's new session |
| T13 SYN-04.10 no password | A full E16-S7a run | A test proxy reads every request | No password and no value made from one (P5) |
| T14 SYN-04.11 helper only in tests | A release build of larsal-server | Look for the helper's route or symbol | Absent |
| T15 SYN-04.3 lifetime, no push-out | d1; test rate limit raised to 100 | Get challenge c1; get 20 more challenges for d1; sign in with c1 at 299 s | 200: c1 was not pushed out and had not expired |

## How this was learned

- Public sources only; the reference app has no server.
- spec/research/sync-server.md P5 and sections 4 (SRP, OPAQUE, WebAuthn, the Secure Enclave, TN3137) and 8 (OWASP, NIST).
- Apple, Protecting keys with the Secure Enclave: <https://developer.apple.com/tutorials/data/documentation/security/protecting-keys-with-the-secure-enclave.md>; TN3137: <https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains>.
- OWASP Session Management Cheat Sheet (token entropy, hashed storage, idle 15 to 30 minutes for low-risk applications, absolute 4 to 8 hours): <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>, read 2026-10-31.
- RFC 6454 (origin serialization): <https://www.rfc-editor.org/rfc/rfc6454.html>. RFC 5054: <https://www.rfc-editor.org/rfc/rfc5054.html>. RFC 9807: <https://www.rfc-editor.org/rfc/rfc9807.html>. Web Authentication Level 3, sections 13.4.3 (a challenge: at least 16 bytes, valid about as long as the upper limit of the ceremony timeout range, 600 s; Larsal takes the shorter default of 300 s, because this sign-in asks the user nothing) and 15.1 (ceremony timeouts: 300,000 to 600,000 ms, default 300,000 ms), read 2026-10-31: <https://www.w3.org/TR/webauthn-3/>.
- Larsal's own value, decided: spec/decisions.md LD-273 (1) (no proven server's default found): a device name of 1 to 64 Unicode scalar values, none in the category Cc (SYN-04.2, SYN-02.3, pinned by T02). Unicode scalar values and the General_Category value Cc (U+0000 to U+001F and U+007F to U+009F), read 2026-10-31: <https://www.unicode.org/glossary/#unicode_scalar_value> and <https://www.unicode.org/reports/tr44/#General_Category_Values>.
- Written by E16-S1 (2026-10-31).
