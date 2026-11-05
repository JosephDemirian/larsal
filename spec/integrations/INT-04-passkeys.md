# INT-04 Passkeys

Status: draft
Epics: E7-S5 (the Passkeys report screen is built in E5-S7 from INT-04.52 and INT-04.53)
Parity rows: SI-05, SF-09, SD-07, SD-09, SR-16, SI-01, SI-04

## What it does

Larsal acts as a software WebAuthn authenticator for the browser extension. A site asks the extension to create a passkey (registration) or to sign in with one (authentication). The extension sends the request over the browser bridge. Larsal checks the request, asks the user to confirm in a dialog with a countdown, creates or uses a key pair, and replies with the WebAuthn response. The private key and the account data live in entry fields of the vault, so passkeys sync and merge like any other entry data.

Larsal also lets the user import and export single passkeys as `.passkey` files, remove a passkey from an entry, and list all passkeys on the Passkeys tab of the Reports screen.

Neighbor cards: INT-01 (bridge envelope, association, bridge error replies, action names), INT-02 (hide-from-browser and association restriction options, search in all vaults, the vault picker, the create-group prompt, window raise), INT-03 (public suffix list; the relying party field as an additional URL), FMT-14.22 (field keys and their protection), MOD-01.8 (passkey fields left out of custom-field lists), MOD-03 (history), MOD-06 (icon 13), MOD-07.11 (the "Passkey" tag), FEA-01 (search), FEA-07.13 (passkey count), FEA-08.47 (passkeys inside the JSON import), FEA-09 (other exports), APP-01 (setting S-BRW-19, last-folder role), APP-02 (lock).

Public standards a Builder needs: W3C Web Authentication Level 2 and 3 (client data, authenticator data, attestation object, "none" attestation), RFC 8949 (CBOR), RFC 9052 and RFC 9053 (COSE keys), RFC 8230 (COSE RSA keys), RFC 8032 (Ed25519), FIPS 186-5 and RFC 6979 (ECDSA), RFC 8017 (RSASSA-PKCS1-v1_5), RFC 5958 and RFC 8410 (PKCS#8), RFC 5915 (EC private keys), RFC 5280 (SubjectPublicKeyInfo), RFC 7468 (PEM), RFC 4648 section 5 (base64url), the WHATWG HTML rule "is a registrable domain suffix of or is equal to", the Public Suffix List.

## Inputs and outputs

**Entry fields** (stored as entry strings; FMT-14.22 owns the keys and protection flags). "Prefix" below means the 12 characters `KPEX_PASSKEY`.

| Field key | Value | Protected | Larsal writes it |
|---|---|---|---|
| `KPEX_PASSKEY_RELYING_PARTY` | RP ID, for example `example.com` | no | yes |
| `KPEX_PASSKEY_USERNAME` | the site's `user.name` | no | yes |
| `KPEX_PASSKEY_CREDENTIAL_ID` | credential id as base64url text without padding (Larsal: 32 random bytes, 43 characters) | yes | yes |
| `KPEX_PASSKEY_USER_HANDLE` | the site's `user.id` exactly as received (base64url text, not decoded) | yes | yes |
| `KPEX_PASSKEY_PRIVATE_KEY_PEM` | unencrypted PKCS#8 private key in PEM (INT-04.3) | yes | yes |
| `KPEX_PASSKEY_FLAG_BE`, `KPEX_PASSKEY_FLAG_BS` | `1` | no | yes (not in installed 2.7.11) |
| `KPEX_PASSKEY_GENERATED_USER_ID` | credential id written by another password manager | as read | never |
| `4B 50 58 43 5F 50 41 53 53 4B 45 59 5F 55 53 45 52 4E 41 4D 45` (stored encoded, name rule) | passkey user name written by other apps | as read | never |

**Bridge requests** (inside the box, INT-01.21): `passkey.create` (registration) and `passkey.get` (authentication), INT-01.30. The reference uses its own action and member names; INT-01.32 maps them (aligned in the second review of INT-01, LD-189).

| Member | Register | Get | Type |
|---|---|---|---|
| `public_key` | creation options | request options | JSON object with WebAuthn member names; binary values are base64url text |
| `origin` | yes | yes | text, the page origin as the extension sees it |
| `group` | yes | no | text, a group path; empty means the default (INT-04.24) |
| (none) | | | no association member: the vault must hold the session's proven identification key (INT-01.28, INT-01.29); the reference sends a list of association pairs here |

Members of `public_key` that Larsal reads. Register: `challenge`, `rp.id`, `rp.name`, `user.id`, `user.name` (`user.displayName` is ignored), `pubKeyCredParams`, `attestation`, `authenticatorSelection` (`authenticatorAttachment`, `residentKey`, `requireResidentKey`, `userVerification`), `excludeCredentials`, `extensions`, `timeout`. Get: `challenge`, `rpId`, `allowCredentials`, `userVerification`, `extensions`, `timeout`. Unknown members are ignored. Size: bounded by the bridge message limit (SI-01, INT-01).

**Bridge replies**: a normal encrypted reply whose `response` member holds either the credential object (INT-04.27, INT-04.43) or `{"errorCode": n}` (INT-04.54).

**Files**: `.passkey` JSON files (INT-04.47 to INT-04.50).

**Setting**: S-BRW-19 `browser.passkeys_localhost` (APP-01), default off.

**Crypto** (larsal-crypto, `sign.rs`): make a key pair for ES256, EdDSA or RS256; read and write PKCS#8 PEM; give the public key as COSE parts and as SubjectPublicKeyInfo DER; sign a message. Private key bytes live only in secret types (AGENTS rule 4).

## Rules

### Storage

INT-04.1 **Fields.** A passkey is the set of fields in the table above, plus the tag "Passkey" (MOD-07.11). The three protected fields are always written protected, whatever the vault's protection flags say (SF-09). The two foreign fields are kept as read and never created.

INT-04.2 **"Has a passkey".** An entry has a passkey when at least one of its string fields has a key that starts with the prefix (case-sensitive; any key that starts with those 12 characters counts, also the key with bytes `4B 50 45 58 5F 50 41 53 53 4B 45 59 58`, stored encoded (name rule)). The encoded foreign user-name field alone does not count. This test drives: the Remove passkey action (INT-04.46), the overwrite question (INT-04.6), the passkey lookup (together with the RP match, INT-04.41), the detail and edit rows (INT-04.51), the `passkey` flag of the bridge's entry summaries (INT-02.20) and the statistics count (FEA-07.13). The report uses another test (INT-04.52).

INT-04.3 **Private key form.** PKCS#8 without encryption, PEM label `PRIVATE KEY`.
- **Larsal writes**: the header line `-----BEGIN PRIVATE KEY-----`, the DER in standard base64 in lines of 64 characters, the footer line `-----END PRIVATE KEY-----`, LF line ends, and a final LF.
- **DER Larsal writes**: ES256: `id-ecPublicKey` with `prime256v1`, holding an EC private key of version 1 with the 32-byte scalar and the `[1]` public key, without `[0]` parameters (138 bytes: `30 81 87`, a sequence of 135 bytes; base64 starts `MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg`). EdDSA: RFC 8410 version 1, 48 bytes: `30 2E 02 01 00 30 05 06 03 2B 65 70 04 22 04 20` then the 32-byte seed. RS256: `rsaEncryption` with an RSA private key, 2048-bit modulus, public exponent 65537. That the reference writes exactly these forms and this line layout: from the source, not run (check with Verify, V-INT04-4).
- **Larsal reads**: any whitespace or none between header and footer (the JSON import writes none, FEA-08.47), CR LF line ends, EC keys with or without the public key and the `[0]` parameters, Ed25519 keys of version 1 or 2.
- **Algorithm from the key**: EC on P-256 signs as ES256, RSA as RS256, Ed25519 as EdDSA. Any other curve or key type cannot sign (error 31). The reference loads any EC curve and signs with SHA-256 anyway; Larsal refuses curves other than P-256.

INT-04.4 **Which id and name an entry answers with.** Credential id: the value of `KPEX_PASSKEY_GENERATED_USER_ID` when that field exists (even empty), else the value of `KPEX_PASSKEY_CREDENTIAL_ID`. Passkey user name: the value of the encoded foreign field when it exists, else `KPEX_PASSKEY_USERNAME`. All id, user-handle and RP comparisons in this card are exact, case-sensitive text compares of stored text; nothing is decoded first.

INT-04.5 **Backup flags.** Field missing: set. Value exactly `1` or `true`: set. Any other value (`0`, `TRUE`, empty): clear. Installed 2.7.11 neither writes nor reads these fields and always sends both flags clear (differs in installed version).

INT-04.6 **Storing a passkey into an entry.**
1. If the entry has a passkey (INT-04.2), ask the overwrite question MI04-01, which names the entry title and its passkey user name, with Replace (MI04-11) and Cancel, Cancel the default. Cancel stops here (INT-04.23 says what the site then gets).
2. Larsal removes every field with the prefix and the encoded foreign user-name field (decided by default, D-INT04-11). The reference only overwrites the seven fields it writes, so a kept `KPEX_PASSKEY_GENERATED_USER_ID` would still win (INT-04.4) and the entry would answer with the old id and the new key.
3. Set the seven fields: RP ID, passkey user name, credential id, private key, user handle, `KPEX_PASSKEY_FLAG_BE` = `1`, `KPEX_PASSKEY_FLAG_BS` = `1`.
4. Add the tag "Passkey" (MOD-07.11).
Steps 2 to 4 are one edit session (MOD-03.4). Title, user name, password and URL do not change.

INT-04.7 **New passkey entry.** In the chosen group: a new random id, title "‹name› (Passkey)", user name = passkey user name, URL = the origin (registration) or the file's `url` (import), icon 13 (MOD-06), empty password. Then INT-04.6 steps 3 and 4, then the history is emptied (MOD-03.5). ‹name› is `rp.name` for the Register button (INT-04.23) and the RP ID for imports and for the path "Pick an entry…" (MI04-10) then "Save as a new entry" (MI04-17). When ‹name› is empty after trimming, Larsal uses the RP ID (decided by default, D-INT04-14); the reference writes " (Passkey)".

INT-04.8 **The RP field as a URL.** The value of `KPEX_PASSKEY_RELYING_PARTY` joins the entry's additional URLs for login matching and for any list of the entry's URLs (INT-03 applies its rules for an additional URL without a scheme). So a passkey entry for `example.com` is also offered for password fill on `example.com`.

### Checks on every request

INT-04.9 **Origin gate.** Done after the bridge checks of INT-01 and after the check that `public_key` is a non-empty object (else error 24), both as bridge error replies. The origin passes when its text starts with `https://` (case-sensitive). With S-BRW-19 on, these also pass: text starting with `file://`, and any origin whose host is `localhost` or `localhost.` or ends with `.localhost` or `.localhost.`, whatever the scheme. Else error 25. In practice `file://` and hosts ending with a dot then fail INT-04.10 with error 27. Larsal also requires the serialized origin form: scheme, `://`, host, optional `:port`, nothing after it, scheme and host in lower case; else error 25 (decided by default, D-INT04-9).

INT-04.10 **Effective domain.** The origin's host, lower case, in IDNA ASCII form (punycode); the port is dropped. Empty origin: error 26. The host must be a valid domain, else error 27. A valid domain is not empty, is ASCII only, does not end with `.`, holds no whitespace and none of `^ # | / : < > ? @ [ ] \`, and is not an IPv4 or IPv6 address (with or without brackets). Installed 2.7.11 takes the host in Unicode form, so every internationalized host fails with error 27 (differs in installed version).

INT-04.11 **RP ID.** Register reads `rp.id`, Get reads `rpId`. Missing or null: the RP ID is the effective domain. Otherwise, with R = the given RP ID and H = the effective domain, all compared in lower-case ASCII form, and PS(x) = the public suffix of x by the Public Suffix List, ICANN and private sections, with the default rule that an unlisted last label is a public suffix (INT-03 owns the list):
1. R empty: error 28.
2. R equals H: accept.
3. R not a valid domain (INT-04.10): error 28.
4. H does not end with "." + R: error 28.
5. PS(R) equals R (R is itself a public suffix): error 28.
6. PS(H) empty: error 28.
7. PS(H) ends with "." + R: error 28.
8. R does not end with "." + PS(H): error 28.
9. Accept.
The accepted RP ID is H when R equals H. Otherwise the reference keeps R exactly as the site wrote it, case and Unicode included, and hashes and stores that text; Larsal uses the lower-case ASCII form (decided by default, D-INT04-8). A given RP ID with a scheme, port or path is error 28 in Larsal; the reference compares only its host part and hashes the whole text (check with Verify, V-INT04-8).

INT-04.12 **Challenge.** Register: `challenge` must be text of at least 16 characters, else error 32. The length is counted in characters of the base64url text, not in decoded bytes (16 characters are 12 bytes). The reference does not check the challenge on Get. Larsal applies the same check on Get, and on both accepts only base64url characters (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `_`), else error 32 (decided by default, D-INT04-9).

INT-04.13 **User id.** Register: `user.id` decoded from base64url must be 1 to 64 bytes, else error 33. The reference skips characters that are not base64url while decoding; Larsal decodes strictly (padding optional) and treats a decode failure as error 33 (D-INT04-9).

INT-04.14 **Algorithm.** From `pubKeyCredParams`, keep the items whose `type` is `public-key` and whose `alg` is -7 (ES256), -257 (RS256) or -8 (EdDSA), in the site's order. List missing or empty: use [-7, -257]. List not empty but nothing kept: error 29. The key type is the first kept item. RS256 needs an RSA crate, which is not on the approved list (lead decision D-INT04-2).

INT-04.15 **Attestation.** Every value of `attestation` is accepted. The response always uses the "none" format with an empty statement. Error 20 is never sent.

INT-04.16 **Authenticator selection.** `authenticatorAttachment` must be missing, empty, `platform` or `cross-platform`, else error 30. The response's attachment is the requested value, or `platform` when none was requested. `residentKey` and `requireResidentKey` are accepted with any value: every passkey Larsal makes is discoverable, because it is an entry. `userVerification`: missing means `preferred`; `required` and `preferred` mean "verification wanted"; `discouraged` and unknown values mean "not wanted"; an unknown value is only logged (error 23 is never sent). The flags never depend on this (INT-04.33); Larsal uses it only for the timeout (INT-04.18).

INT-04.17 **Extensions.** Of `extensions`, only `credProps` and `uvm` count; all other members are dropped. Client extension results: when `credProps` is `true`, `{"credProps":{"rk":true}}`; when `uvm` is `true`, `{"uvm":[[1,1,1]]}`; both can appear. With neither, the results are `{}`. The authenticator extension data is in INT-04.36.

INT-04.18 **Timeout.** The countdown lasts `timeout` milliseconds divided by 1000, rounded down, in seconds. The reference uses the site's number as it is: no upper bound, and a missing value or a value under 1000 gives a countdown of 0, which closes the dialog about one second after it opens (from the source, not run: check with Verify, V-INT04-2). Larsal: a missing value, or one of 0 or less, means 300 seconds (120 seconds when verification is not wanted, INT-04.16); every value is then held between 30 and 600 seconds (decided by default, D-INT04-6).

### Registration

INT-04.19 **Order of steps.**
1. Bridge checks (INT-01), `public_key` present (24), origin gate (25).
2. Option checks: challenge (32), user id (33), effective domain (26, 27), RP ID (28), algorithm (29), attestation, authenticator selection (30), extensions, timeout. The first failure is the reply.
3. Vault choice (INT-04.20).
4. Exclude list (INT-04.21).
5. Entries with the same account (INT-04.22).
6. Show the confirm dialog (INT-04.45), in front as INT-04.28 says.
7. On a confirm, make the key pair and the response (INT-04.25 to INT-04.27). A failure here: error 31.
8. Store the passkey (INT-04.23, INT-04.24), restore Larsal's earlier state (INT-04.28), reply.
The reference runs step 3 first, so its vault picker can open for a request that then fails, and it checks that `excludeCredentials` is a list only at step 7: a request without it fails with error 31 after the user pressed Register (from the source, not run: check with Verify, V-INT04-6). Larsal runs the steps in the order above and treats a missing `excludeCredentials` as an empty list (decided by default, D-INT04-7).

INT-04.20 **Vault choice** (LD-191). The passkey goes into one of the usable vaults of INT-02.10: unlocked, holding the session's proven identification key, not behind MOD-13's forced prompt. With S-BRW-14 on and more than one usable vault, Larsal shows INT-02.27's vault picker with the title MI04-19 (the shown vault selected); Cancel: error 1. Otherwise the shown vault. No usable vault: error 1, which INT-01.30 already sends before any step of this card. Reference difference: its picker lists every unlocked vault, associated with the browser or not and whatever its search-all setting, and the passkey goes into the one chosen; Larsal never writes a passkey into a vault the browser is not connected to.

INT-04.21 **Exclude list.** Take the `id` text of every item of `excludeCredentials`. If any candidate entry for the RP ID (INT-04.41, all searched vaults) answers with one of these ids (INT-04.4), the reply is error 21. The reference replies at once, with no dialog, so a site can probe which of its credential ids this vault holds. Larsal first shows the notice MI04-02 with one OK button, then replies error 21 (decided by default, D-INT04-10).

INT-04.22 **Same account.** Candidate entries (INT-04.41) whose user handle field equals `user.id` exactly. When there are any, the dialog opens in "existing" mode (INT-04.45) and lists them.

INT-04.23 **Dialog outcomes.**

| Dialog mode | User action | Result |
|---|---|---|
| any | Cancel, close, or countdown at 0 | error 22, nothing stored |
| new | Register | new entry (INT-04.7, name `rp.name`) in the group of INT-04.24, in the chosen vault |
| existing | Add another (MI04-12) | same as Register |
| existing | Replace (MI04-11), a listed entry selected | store into that entry (INT-04.6, overwrite question MI04-01) |
| new | Pick an entry… (MI04-10) | the placement dialog of INT-04.48, used to choose the entry that gets the new passkey: title MI04-13, text MI04-14, button Register; Cancel there gives error 22 |
| existing | Replace with no entry selected | same as "Pick an entry…" |

When the user answers Cancel to the overwrite question, the reference still sends the new credential to the site although nothing was stored, so the site believes a passkey exists. Larsal replies error 22 instead (decided by default, D-INT04-5).

INT-04.24 **Group for a new entry.** The group path is `group`, or Larsal's default "Browser Passkeys" when it is empty (decided by default, D-INT04-12). The reference's default is the name `4B 65 65 50 61 73 73 58 43 2D 42 72 6F 77 73 65 72 20 50 61 73 73 6B 65 79 73` (stored encoded, name rule), which Larsal never writes. Paths are relative to the root, `/` separates levels, a leading or trailing `/` is optional, names match exactly (case-sensitive), and the first match in tree order wins.
- Path found: use it, no question.
- Path not found: INT-02's create-group question MI02-08 (INT-02.26, SI-12). Create: every missing level is created under the previous one with a new random id; every created level gets the group custom data `BrowserHideEntry` = `false` (FMT-14); the last level also gets icon 13. Cancel, or no answer within 60 seconds (INT-01.45): the entry goes to INT-02's default group for new logins, which is created without a question when missing. The default "Browser Passkeys" is looked up and asked for like any other path (reference: the same for its own default name).
- Installed 2.7.11 creates missing groups in the current vault even when another vault was chosen, so the passkey then lands in the chosen vault's default login group (differs in installed version).

INT-04.25 **Key pair.** Made only after the confirm, from larsal-crypto's random source.
- ES256: a random P-256 private key. In the COSE key, x and y are exactly 32 bytes each, padded with leading zero bytes when shorter. The reference drops leading zero bytes, so about 1 key in 128 gets a 31-byte coordinate (from the source and its crypto library's number encoding, not run: check with Verify, V-INT04-1).
- EdDSA: a random 32-byte Ed25519 seed.
- RS256: a 2048-bit RSA key with public exponent 65537 (D-INT04-2).

INT-04.26 **Credential id.** 32 random bytes. Stored and sent as 43 base64url characters without padding.

INT-04.27 **Registration response.**

| Member | Value |
|---|---|
| `type` | `public-key` |
| `id` | credential id text (INT-04.26) |
| `authenticatorAttachment` | INT-04.16 |
| `response.clientDataJSON` | base64url of the client data (INT-04.30) |
| `response.attestationObject` | base64url of the attestation object (INT-04.37) |
| `response.authenticatorData` | base64url of authenticator data (see below) |
| `response.publicKey` | base64url of the SubjectPublicKeyInfo DER: ES256 91 bytes, `30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07 03 42 00 04` then x and y; EdDSA 44 bytes, `30 2A 30 05 06 03 2B 65 70 03 21 00` then the public key; RS256 294 bytes (`rsaEncryption`). Missing in installed 2.7.11 |
| `response.publicKeyAlgorithm` | -7, -8 or -257 |
| `response.clientExtensionResults` | INT-04.17 |

The reference sends as `authenticatorData` a short form without attested credential data (37 bytes, flags `1D`, or `9D` with extension data). Larsal sends exactly the authenticator data that is inside the attestation object, as WebAuthn requires for this value (decided by default, D-INT04-3).

INT-04.28 **Window.** Passkey dialogs come to the front like every bridge dialog (INT-02.15): over Larsal's window, or alone when Larsal's window is hidden. Afterwards Larsal restores the state from before: hidden again when it was hidden, back to the menu bar when it was there, minimized when it was minimized, otherwise the previously active app (the browser) is activated again. Reference: it raises its main window and waits half a second before each confirm dialog.

INT-04.29 **One prompt at a time, and lock.** Passkey dialogs (confirm, the notice MI04-02, the overwrite question, the group question, placement) are bridge dialogs and share INT-02.15's line: a passkey request that arrives while any bridge dialog shows waits its turn, at most 4 waiting requests per session and 16 in all; beyond that: boxed error 42 (INT-01.44). Its countdown (INT-04.18) starts when its confirm dialog shows.
- When a vault the request uses locks, Larsal closes the open passkey dialog and the waiting passkey requests leave the line; each gets error 22 inside `response` (for passkey requests 22 takes the place of INT-01.30's error 6) and nothing is stored (APP-02, SR-16).
- When the session ends or S-BRW-01 turns off, the dialog closes the same way and no reply is sent (INT-01.45).
- Reference differences: a second request can stack a second dialog on top of the first; the passkey dialog stays open after a lock, holding entries of the locked vault (from the source, not run: check with Verify, V-INT04-9).

### Byte layouts

INT-04.30 **Client data.** UTF-8 bytes of exactly this text, with no spaces and members in this order:
`{"type":"‹T›","challenge":"‹C›","origin":"‹O›","crossOrigin":false}`
‹T› is `webauthn.create` for registration and `webauthn.get` for authentication. ‹C› is the `challenge` text and ‹O› the `origin` text, both exactly as received. The reference inserts them without JSON escaping; Larsal's checks (INT-04.9, INT-04.12) make escaping unnecessary.

INT-04.31 **RP ID hash.** SHA-256 of the UTF-8 bytes of the RP ID (INT-04.11). `example.com` gives `A3 79 A6 F6 EE AF B9 A5 5E 37 8C 11 80 34 E2 75 1E 68 2F AB 9F 2D 30 AB 13 D2 12 55 86 CE 19 47`.

INT-04.32 **Authenticator data.**

| Offset | Bytes | Field |
|---|---|---|
| 0 | 32 | RP ID hash (INT-04.31) |
| 32 | 1 | flags (INT-04.33) |
| 33 | 4 | signature counter, big-endian, always `00 00 00 00` |
| 37 | 16 | AAGUID (registration only, INT-04.34) |
| 53 | 2 | credential id length, big-endian: `00 20` |
| 55 | 32 | credential id bytes |
| 87 | 77, 42 or 271 | COSE public key (INT-04.35) |
| end | rest | extension data, only when flag ED is set (INT-04.36) |

Total without extensions: registration 164 bytes (ES256), 129 (EdDSA), 358 (RS256); authentication 37.

INT-04.33 **Flags.** Bits: UP `01`, UV `04`, BE `08`, BS `10`, AT `40`, ED `80`. UP and UV are always set: the confirm click counts as user presence and as user verification, whatever `userVerification` asked. AT is set only in registration. ED is set when extension data follows.

| Case | Flags |
|---|---|
| registration | `5D` (`DD` with extension data) |
| authentication, both backup flags set (INT-04.5) | `1D` (`9D`) |
| authentication, BE set, BS clear | `0D` (`8D`) |
| authentication, BE clear, BS set | `15` (`95`); sent as stored, although WebAuthn forbids BS without BE |
| authentication, both clear | `05` (`85`) |
| installed 2.7.11: registration / authentication | `45` (`C5`) / `05` (`85`) |

INT-04.34 **AAGUID.** The reference sends its own registered AAGUID `FD B1 41 B2 5D 84 44 3E 8A 35 46 98 C2 05 A5 02`. Larsal never sends it. Larsal sends its own fixed AAGUID `75 8D 40 80 A2 83 44 BA BC 65 8D 03 9D 85 27 32` (UUID 758d4080-a283-44ba-bc65-8d039d852732; lead decision D-INT04-1).

INT-04.35 **COSE public key** (CBOR map, keys in this order, shortest integer forms).

| Algorithm | Bytes | Length |
|---|---|---|
| ES256 | `A5 01 02 03 26 20 01 21 58 20` ‹x, 32 bytes› `22 58 20` ‹y, 32 bytes› (kty 2 EC2, alg -7, crv 1 P-256) | 77 |
| EdDSA | `A4 01 01 03 27 20 06 21 58 20` ‹public key, 32 bytes› (kty 1 OKP, alg -8, crv 6 Ed25519) | 42 |
| RS256 | `A4 01 03 03 39 01 00 20 59 01 00` ‹modulus, 256 bytes› `21 43 01 00 01` (kty 3 RSA, alg -257, n, e) | 271 |

INT-04.36 **Extension data.** Larsal writes it only when `uvm` is `true`: the CBOR map `A1 63 75 76 6D 81 83 01 01 01` ("uvm" → [[1, 1, 1]]: presence check inside the authenticator, software key protection, software matcher protection), and sets ED. The reference also puts `credProps` there: its map holds one pair per member left after INT-04.17's filter, `credProps` first (`69 63 72 65 64 50 72 6F 70 73 A1 62 72 6B F5`, "credProps" → {"rk": true}), then `uvm`; it writes nothing when neither is `true`. WebAuthn defines `credProps` as a client-only result, so Larsal keeps it out of the authenticator data (decided by default, D-INT04-4). The reference's map header counts members, not written pairs, so `{"credProps": true, "uvm": false}` gives a malformed map (from the source, not run: check with Verify, V-INT04-5).

INT-04.37 **Attestation object.** The CBOR map `A3 63 66 6D 74 64 6E 6F 6E 65 67 61 74 74 53 74 6D 74 A0 68 61 75 74 68 44 61 74 61` ("fmt" → "none", "attStmt" → {}, "authData" →), then the authenticator data as a CBOR byte string: header `58 A4` for 164 bytes, `58 81` for 129, `59 01 66` for 358 (`58 nn` below 256 bytes, `59 nn nn` from 256). Size: 30 + the authenticator data for lengths 24 to 255.

INT-04.38 **Signature** (authentication only). The message is the authenticator data followed by the SHA-256 of the client data bytes. ES256: ECDSA on P-256 with SHA-256, encoded as a DER sequence of r and s. RS256: RSASSA-PKCS1-v1_5 with SHA-256, 256 bytes. EdDSA: Ed25519 over the message itself (not pre-hashed), 64 bytes. The reference's ECDSA signatures are deterministic (RFC 6979); a site only verifies, so any valid signature is correct.

INT-04.39 **Base64url.** Everything Larsal sends in binary form is base64url (RFC 4648 section 5) without padding: credential ids, client data, authenticator data, attestation object, signature, public key.

### Authentication

INT-04.40 **Order of steps.**
1. Bridge checks (INT-01), `public_key` present (24), origin gate (25).
2. A usable vault (INT-02.10) exists; INT-01.30 answers error 8 or 1 before this step. The reference needs its current vault unlocked and sends error 1 inside `response`.
3. Effective domain (26, 27), RP ID (28), challenge (Larsal only, 32), extensions, verification, timeout.
4. Allowed entries (INT-04.42). None: error 15.
5. Show the confirm dialog (INT-04.45), in front as INT-04.28 says.
6. Cancel, close or countdown at 0: error 22.
7. Authenticate with an entry selected: read its private key, id (INT-04.4), user handle and backup flags (INT-04.5); build authenticator data and signature; reply (INT-04.43). No entry selected, or the key cannot sign: error 31.

INT-04.41 **Candidate entries** (also used by INT-04.21 and INT-04.22).
- Vaults: the usable vaults of INT-02.10 (the shown vault, or with S-BRW-14 on every unlocked vault, holding the session's proven identification key, INT-01.28; none behind MOD-13's forced prompt), in the order they are open.
- Groups in tree order (pre-order from the root, children in their stored order); vaults in the order they are open. Groups in the recycle bin, groups hidden from the browser, and groups restricted to an association that is not among the matching ones are skipped (INT-02, SI-04).
- Entries in group order; recycled entries and entries hidden from the browser are skipped (INT-02).
- The entry must have a passkey (INT-04.2) and its `KPEX_PASSKEY_RELYING_PARTY` must equal the RP ID exactly. There is no parent-domain fallback.
- Expired entries are not skipped, unlike password fill (SI-04). Larsal keeps this.
- No site-access question (SI-02) and no remembered allow or deny: the passkey confirm dialog takes their place.

INT-04.42 **Allowed entries.** An item of `allowCredentials` is accepted when its `type` is `public-key`, its `id` is not empty, and `transports` is missing, empty, or holds `internal`, `nfc` or `usb`.
- Items given but none accepted: error 15.
- Some accepted: the candidates whose id (INT-04.4) equals an accepted id.
- `allowCredentials` missing or empty: the candidates that have the `KPEX_PASSKEY_USER_HANDLE` field (any value).

INT-04.43 **Authentication response.**

| Member | Value |
|---|---|
| `type` | `public-key` |
| `id` | the entry's credential id text (INT-04.4) |
| `authenticatorAttachment` | always `platform` |
| `response.authenticatorData` | base64url, 37 bytes plus any extension data |
| `response.clientDataJSON` | base64url (INT-04.30) |
| `response.signature` | base64url (INT-04.38) |
| `response.userHandle` | the stored user handle text, unchanged (empty text when the field is empty) |
| `response.clientExtensionResults` | INT-04.17 |

INT-04.44 **No change on use.** Signing changes nothing in the vault's data: no field, no modification time, no history item, no usage count. The counter stays 0. The only write is INT-02.9's last-use record (a sign-in records it like a registration), a view-state change that does not mark the vault changed. The reference records no use.

### Confirm dialog

INT-04.45 **Content and behavior.** It stays on top, centered on the active screen, with a countdown bar and the countdown text MI04-03, N counting down once per second. N reaching 0 is a Cancel. Cancel is the default button, so Return cancels.

| Mode | Purpose | Heading | Lines | List | Buttons |
|---|---|---|---|---|---|
| new (registration) | confirm a new passkey for a site and account | MI04-04 | the relying party line MI04-07 (‹RP ID›), the account line MI04-08 (‹user.name›) | none | Cancel, Pick an entry… (MI04-10), Register |
| existing (registration) | the account already has a passkey: add another or replace one | MI04-05 | same, plus the select-and-replace hint MI04-06 | the entries of INT-04.22 | Cancel, Replace (MI04-11), Add another (MI04-12) |
| authentication | confirm a sign-in | MI04-09 | the relying party line MI04-07 | the entries of INT-04.42 | Cancel, Authenticate |

List rows read "‹title› - ‹entry user name›" in INT-04.41 order. The first row is selected. A double click on a row confirms. Whether the reference counts that first row as chosen when the user presses Authenticate without clicking a row is unclear: its list marks the row selected but may not make it current (check with Verify, V-INT04-3). Larsal counts the selected row.

### Remove, import, export

INT-04.46 **Remove passkey.** Offered in the entry menu when exactly one entry is selected and it has a passkey, and as the Remove button on the edit screen (INT-04.51). The question MI04-34 (frame `dialogs-remove-passkey`) with Cancel and Remove Passkey. Remove deletes every field with the prefix, Larsal also deletes the encoded foreign user-name field (D-INT04-11), and the tag "Passkey" is removed (MOD-07.11). From the entry menu this makes no history item, as in the reference: the entry's modification and access times move to now, and the private key is gone unless older history items hold it. From the edit screen it is part of the editor's edit session (MOD-03.4).

INT-04.47 **Reading a `.passkey` file.** Entry points: the vault menu's "Import Passkey…", the Passkeys report's Import button (both vault level), and the entry menu's "Import Passkey…" (exactly one entry selected; the passkey goes into that entry). The file chooser offers the passkey filter MI04-18 and "All files" and remembers the passkey folder role (APP-01.15). Checks, first failure wins; each message names the file:

| Check | Message |
|---|---|
| file cannot be opened | MI04-20 (cannot open the file) |
| Larsal: file over 1 MiB (D-INT04-13) | MI04-21 (file too large) |
| not a JSON object, or an empty one | MI04-22 (no passkey data) |
| member missing; checked in the order `relyingParty`, `url`, `username`, `credentialId`, `userHandle`, `privateKey` | MI04-23 (missing data list: the missing names joined by ", ") |
| `privateKey` does not start with `-----BEGIN PRIVATE KEY-----`, or does not end with `-----END PRIVATE KEY-----` after trimming white space (spaces, tabs, line ends) at both ends | MI04-24 (private key missing or malformed) |
| Larsal: the key does not parse, or cannot sign (INT-04.3) (D-INT04-13) | MI04-24 |

Members that are present but not text count as empty text. Empty values are accepted. Then the placement dialog (INT-04.48) opens.

INT-04.48 **Placement dialog.** It lets the user choose where a passkey goes. It shows the relying party line MI04-07 (‹relyingParty›) and the account line MI04-08 (‹username›), and has Cancel and Import buttons.
- **Vault level**: a vault list (unlocked vaults by name, the current one preselected, usable only when more than one is unlocked; opened from registration, INT-04.23, it holds only the vault chosen by INT-04.20 and cannot be changed, LD-191; the reference lists every unlocked vault there too); a group list (first the default imported passkeys group item MI04-16, then every group by full path except the recycle bin and groups inside it); an entry list (first the create new entry item MI04-17, then the chosen group's entries outside the recycle bin, sorted by title with placeholders resolved, case-insensitive). The entry list is refilled when the group changes; with the default group item it holds only MI04-17.
- **Entry level**: no lists, and the import to this entry text MI04-15.
- **Import**: an existing entry chosen, or entry level: store into it (INT-04.6). MI04-17 chosen: a new entry (INT-04.7, name = `relyingParty`, URL = `url`) in the chosen group or, with the default item, in the root group named exactly "Imported Passkeys", which is created at the root when missing (plain group, default icon, no options).
- Values: `relyingParty` goes to the RP field, `username` to the passkey user name, `credentialId`, `userHandle` and `privateKey` (text as it is) to their fields; both backup flags `1`. A file's `url` is used only for a new entry.

INT-04.49 **The `.passkey` file.** A JSON object with six text members: `credentialId` (INT-04.4 id), `privateKey` (the PEM field text), `relyingParty`, `url` (the entry URL field as stored, not resolved), `userHandle`, `username` (INT-04.4 name). Backup flags are not written. The reference writes the members sorted by name, indented by 4 spaces, with `": "` after each name, LF line ends and a final LF, UTF-8, `/` not escaped. Larsal writes the same.

INT-04.50 **Exporting.** From the Passkeys report, with one or more rows selected.
1. Warning MI04-30 with Yes and No, No the default. Both the source and installed 2.7.11 warn here (SD-07).
2. A list of the selected entries ("‹title› - ‹entry user name›"), all preselected, with the file name note MI04-31. Export Selected works while at least one is chosen.
3. A folder chooser (passkey folder role, APP-01.15).
4. For each chosen entry: the file is ‹folder›/‹clean title›.passkey. Clean title: `/` becomes `_`, the characters `: * ? " < > |` are removed, then white space at both ends is trimmed. If the file exists: the question MI04-32, Yes or No; No skips this entry. A write failure shows MI04-33 and the next entry follows.
Larsal writes each file with mode 0600 (SD-09; the reference uses default permissions). When the clean title is empty, Larsal uses the RP ID (D-INT04-14; the reference writes a hidden file named `.passkey`).

INT-04.51 **Detail and edit screens** (mockup).
- Detail: for an entry with a passkey, one "Passkey" field reads "Sign in to ‹RP ID› as ‹passkey user name›". No passkey value can be shown or copied. The mockup's second line, "Saved ‹date›", needs a time the vault does not store (lead decision D-INT04-15).
- Entry menu: "Remove passkey" (INT-04.46).
- Edit screen: a "Passkey" row reads "‹RP ID› · ‹passkey user name›" with a Remove button. Without a passkey it reads "None. The browser extension saves passkeys here." The raw passkey fields stay out of the editor's custom-field list (lead decision D-INT04-16; the reference lists them there, MOD-01.8).

### Passkeys report

INT-04.52 **Rows.** One row per entry outside the recycle bin that has a `KPEX_PASSKEY_PRIVATE_KEY_PEM` field (any value). This test differs from INT-04.2, so the statistics count (FEA-07.13) and the report can disagree. Larsal's columns follow the mockup: Title (entry icon and title), Username (INT-04.4 name), Relying Party, Path (group names from the root down, joined with " › "). Sorted by title, ascending, locale-aware. With no rows: MI04-35. The reference also has a URLs column (the entry URL with placeholders resolved, then the additional URLs including the RP field, one per line), marks expired titles, and hides expired entries unless a show-expired checkbox is ticked (off by default). Whether Larsal keeps that checkbox and the Import and Export buttons, which the mockup does not show, is lead decision D-INT04-15.

INT-04.53 **Actions.** A click or double click opens the entry. The context menu has "Edit entry" (one row) and "Delete entries" (any rows, MOD-04 rules and question). The Delete key deletes the selected entries. Import (INT-04.47) and Export (INT-04.50). The list is rebuilt after each action, and each time the tab opens.

### Errors and other surfaces

INT-04.54 **Error codes.** Codes inside `response` are `{"errorCode": n}` with no text. Codes 1, 15, 24 and 25, and 42 (busy, INT-04.29), are bridge error replies (boxed `"error": n`, INT-01.40). Reference difference: it sends 1 and 15 inside `response` too.

| Code | Larsal id | When |
|---|---|---|
| 1 | (INT-01) | no unlocked vault; vault picker cancelled |
| 15 | (INT-01) | no allowed passkey entry (INT-04.42) |
| 20 | `pk.attestation` | never sent |
| 21 | `pk.excluded` | INT-04.21 |
| 22 | `pk.cancelled` | Cancel, close, countdown at 0, placement dialog cancelled; in Larsal also: overwrite declined, lock (INT-04.23, INT-04.29) |
| 23 | `pk.user_verification` | never sent |
| 24 | `pk.empty_options` | `public_key` missing or empty |
| 25 | `pk.bad_url` | INT-04.9 |
| 26 | `pk.origin` | empty origin; never sent in practice, because the origin gate (INT-04.9) answers an empty or missing origin with 25 first (the same in the reference) |
| 27 | `pk.domain` | INT-04.10 |
| 28 | `pk.rp_mismatch` | INT-04.11 |
| 29 | `pk.algorithms` | INT-04.14 |
| 30 | `pk.attachment` | INT-04.16. The reference's text for this code wrongly says to wait for a timer; Larsal's text: MI04-36 |
| 31 | `pk.unknown` | key pair or signature failed, no entry selected, stored key unusable |
| 32 | `pk.challenge` | INT-04.12 |
| 33 | `pk.user_id` | INT-04.13 |

INT-04.55 **Other surfaces.** The command line `show` with all attributes lists the passkey fields, protected ones as `(hidden)` unless asked (INT-10, LD-172; the reference prints `PROTECTED`, observed in installed 2.7.11). Search over custom fields skips passkey fields (FEA-01). CSV and HTML exports leave them out (FEA-09). The database-info command and the Statistics tab count passkeys (FEA-07.13; not in installed 2.7.11). Merge treats passkey fields as ordinary strings (MOD-11).

### Messages

Larsal's own wording; IDs are ours. The reference has dialogs for the same purposes, but none of its text is used. ‹…› marks a placeholder. Buttons not listed here (Register, Authenticate, Import, Cancel, OK, Yes, No, Export Selected) are plain verbs.

| ID | Kind | Purpose (rule) | Larsal text |
|---|---|---|---|
| MI04-01 | question | the overwrite question: the entry already has a passkey (INT-04.6) | ‹title› - ‹passkey user name› already has a passkey. Replace it with the new one? Buttons: Replace (MI04-11), Cancel (default) |
| MI04-02 | notice | the site already knows a passkey from this vault (INT-04.21) | A passkey for this site and account is already in your vault. |
| MI04-03 | countdown | time left in the confirm dialog (INT-04.45) | N seconds left to answer |
| MI04-04 | heading | confirm a new passkey (INT-04.45, new mode) | Create a new passkey? |
| MI04-05 | heading | the account already has a passkey (INT-04.45, existing mode) | You already have a passkey for this account. Create another one? |
| MI04-06 | hint | select and update: replace a listed passkey instead (INT-04.45, existing mode) | Or pick one below and choose Replace to swap it for the new one. |
| MI04-07 | line | the relying party line (INT-04.45, INT-04.48) | Site: ‹RP ID› |
| MI04-08 | line | the account name line (INT-04.45, INT-04.48) | Account: ‹user name› |
| MI04-09 | heading | confirm a sign-in (INT-04.45, authentication) | Sign in with a passkey? |
| MI04-10 | button | add to an existing entry instead of a new one (INT-04.23, INT-04.45) | Pick an entry… |
| MI04-11 | button | store into the selected entry (INT-04.23, INT-04.45); also the yes button of MI04-01 | Replace |
| MI04-12 | button | make another passkey entry (INT-04.23, INT-04.45) | Add another |
| MI04-13 | title | placement dialog opened from registration (INT-04.23) | Choose an entry |
| MI04-14 | text | register to this entry: the chosen entry gets the new passkey (INT-04.23) | Pick the entry that should hold the new passkey. |
| MI04-15 | text | import to this entry: entry-level import (INT-04.48) | This passkey will be added to the selected entry. |
| MI04-16 | list item | the default imported passkeys group (INT-04.48) | Imported Passkeys (created if needed) |
| MI04-17 | list item | create new entry (INT-04.48) | Save as a new entry |
| MI04-18 | file filter | passkey files in the file chooser (INT-04.47) | Passkey (.passkey) |
| MI04-19 | dialog title | the vault picker for a new passkey (INT-04.20; the picker is INT-02.27's, a mockup gap of D-INT02-4) | Save the passkey in which vault? |
| MI04-20 | error | cannot open the file (INT-04.47) | Larsal can't read ‹file›. Check that it exists and that you can open it. |
| MI04-21 | error | Larsal only: file over 1 MiB (INT-04.47) | ‹file› is too big to be a passkey file. |
| MI04-22 | error | not a JSON object, or empty (INT-04.47) | ‹file› has no passkey data. |
| MI04-23 | error | the missing data list (INT-04.47) | ‹file› is incomplete. Missing: ‹names› |
| MI04-24 | error | malformed private key (INT-04.47) | ‹file› does not hold a usable private key. |
| MI04-30 | warning | before export (INT-04.50, SD-07) | A .passkey file is plain text. The private key inside is not encrypted and works for anyone who has the file. Export anyway? |
| MI04-31 | note | how export files are named (INT-04.50) | Each file is named after its entry's title. |
| MI04-32 | question | export target exists (INT-04.50) | A file named ‹title›.passkey is already in this folder. Replace it? |
| MI04-33 | error | export write failed (INT-04.50) | Could not save ‹path›. Moving on to the next passkey. |
| MI04-34 | question | remove a passkey (INT-04.46; the frame `dialogs-remove-passkey`) | Heading: Remove the passkey for ‹RP ID›? Text: You can no longer sign in to ‹RP ID› with it. ‹kept›, where ‹kept› is "The password and the one-time code stay.", "The password stays." or "The one-time code stays." by what the entry keeps, and empty when it keeps neither. Buttons: Cancel, Remove Passkey |
| MI04-35 | empty state | Passkeys report with no rows (INT-04.52) | No passkeys in this vault yet. |
| MI04-36 | error text | error code 30 (INT-04.54) | Unsupported authenticator type |

### Decisions and checks

Lead decisions (spec/decisions.md default rule: the recommended option applies until the lead rules otherwise):

| ID | Question | Options | Recommended |
|---|---|---|---|
| D-INT04-1 | AAGUID (INT-04.34) | (a) Larsal's own fixed AAGUID; (b) 16 zero bytes; (c) the reference's | (a) `758d4080-a283-44ba-bc65-8d039d852732`; (c) would claim to be the reference |
| D-INT04-2 | RS256 (INT-04.14, INT-04.25, INT-04.38) | (a) add an RSA crate after AT-J03 review, checking its advisories then; (b) no RS256: leave -257 out of INT-04.14 and fail stored RS256 keys with error 31 | (a): without it, RS256 passkeys made by the reference cannot be used |
| D-INT04-3 | Registration `authenticatorData` (INT-04.27) | full authenticator data, or the reference's short form | full |
| D-INT04-4 | `credProps` in the authenticator data (INT-04.36) | leave it out, or copy the reference | leave it out |
| D-INT04-5 | Overwrite declined (INT-04.23) | error 22, or the reference's success reply | error 22 |
| D-INT04-6 | Timeout (INT-04.18) | default and range, or the site's value as is | default and range |
| D-INT04-7 | Step order, missing exclude list (INT-04.19) | check first and treat a missing list as empty, or copy the reference | check first |
| D-INT04-8 | RP ID form (INT-04.11) | lower-case ASCII, or the site's text | lower-case ASCII |
| D-INT04-9 | Strict inputs (INT-04.9, INT-04.12, INT-04.13) | strict origin, challenge and user id, or the reference's loose reading | strict |
| D-INT04-10 | Exclude-list probe (INT-04.21) | a notice before error 21, or an immediate error | notice |
| D-INT04-11 | Old passkey fields (INT-04.6, INT-04.46) | remove all prefix fields and the foreign name field, or only overwrite seven | remove all |
| D-INT04-12 | Default group (INT-04.24) | "Browser Passkeys" | "Browser Passkeys" |
| D-INT04-13 | Import limits (INT-04.47) | 1 MiB and a key check, or none | 1 MiB and a key check |
| D-INT04-14 | Empty names (INT-04.7, INT-04.50) | the RP ID, or the reference's empty text | the RP ID |
| D-INT04-15 | Mockup gaps (INT-04.51, INT-04.52) | "Saved" date: drop it, use the entry's modification time, or store a time in Larsal's own custom data. Report: keep or drop the show-expired box and the Import and Export buttons | drop the date; keep the box and both buttons under the table (owner approval needed, AT-K05) |
| D-INT04-16 | Raw passkey fields in the editor (INT-04.51) | hide them behind the Passkey row, or list them as the reference does | hide them |

Check with Verify (all read from the source, not run, because the reference's window must not be launched):

| ID | What to check |
|---|---|
| V-INT04-1 | ES256 COSE coordinates with a leading zero byte come out 31 bytes long (INT-04.25) |
| V-INT04-2 | A missing timeout, or one under 1000 ms, closes the dialog after about one second (INT-04.18) |
| V-INT04-3 | Authenticate without clicking a row uses the first row, or fails with 31 (INT-04.45) |
| V-INT04-4 | PEM line layout and DER forms of the keys the reference writes (INT-04.3) |
| V-INT04-5 | Malformed extension map for `{"credProps": true, "uvm": false}` (INT-04.36) |
| V-INT04-6 | A request without `excludeCredentials` fails with 31 after Register (INT-04.19) |
| V-INT04-7 | The JSON import reads a credential id in its `b64.` form as hex digits and stores the wrong id (FEA-08.47) |
| V-INT04-8 | An RP ID given with upper case, Unicode, a port or a path is hashed as given (INT-04.11) |
| V-INT04-9 | The passkey dialog stays open after the vault locks (INT-04.29) |

## Edge cases and errors

- **Passkey and password in one entry.** Allowed. Password fill and passkey use are independent; the RP field also makes the entry match the RP's site for password fill (INT-04.8).
- **Several passkeys for one site and account.** "Add another" (MI04-12) makes another entry with the same RP and user handle. Both are listed at sign-in (with an empty `allowCredentials`) or only the listed id (with a list).
- **Field present, value empty.** An empty user handle field still makes the entry discoverable (INT-04.42); the reply carries an empty `userHandle`. An empty private key gives error 31 at signing.
- **Foreign id field.** An entry with `KPEX_PASSKEY_GENERATED_USER_ID` answers with that id everywhere (INT-04.4), also in exports.
- **Hostile vault.** Passkey fields are data. A malformed PEM, a huge PEM (bounded by FMT limits) or an unknown key type gives error 31 at signing; nothing crashes, and nothing about the key is logged.
- **RP ID with a different case in a stored entry** (for example `Example.com` from an import): it never matches Larsal's lower-case RP ID (INT-04.41); the user must fix the field.
- **Origin on a port** (`https://example.com:8443`): the effective domain is `example.com`; the client data holds the full origin with its port.
- **Countdown and site timeout.** The site may give up before the user answers; Larsal still stores a passkey confirmed later, and the site never learns of it. Same in the reference.
- **The JSON import's `b64.` ids** (FEA-08.47): the reference keeps only the hex digits and decodes them, which gives a wrong id for ids in the `b64.` + base64url form (V-INT04-7). FEA-08 owns the fix.
- **Not on Mac.** On Windows and Linux the reference lowers its window after a prompt (or hides it again when it was hidden), instead of reactivating the previous app; on Linux and Windows it brings the window to the front only when forced.

## Security notes

- **Private keys never leave Larsal over the bridge.** Only the public key, the credential id, the user handle and the signature go out (SI-05). Private keys, user handles and credential ids are stored protected (SF-09). They are never logged, never put in an error text, and never sent to the screen; the screen only shows RP and user name (INT-04.51, AGENTS rule 4).
- **Every use needs a confirm** with a countdown and Cancel as the default; there is no remembered consent and no "always allow" (SI-05). A lock closes the prompt (INT-04.29, SR-16).
- **Wrong site (AT-F08).** The RP ID comes from the extension's origin and must be the origin's host or a registrable parent of it (INT-04.11), so `evil.example` cannot ask for `example.com` (error 28), and lookalike or punycode hosts get different RP IDs with no matching entries (error 15). Entries match by exact RP field, never by parent domain (INT-04.41). Plain http is refused (error 25) unless the user turned on S-BRW-19, and then only for localhost.
- **Subdomains.** Any subdomain of the RP may use the RP's passkeys; WebAuthn intends this. The public suffix list keeps tenants of shared hosting suffixes apart (INT-04.11 steps 5 to 8).
- **The origin is only as trustworthy as the extension.** Larsal cannot check it. The association (SI-01, INT-02) is the trust boundary; a compromised associated extension can request a passkey for any site, still behind the confirm dialog that names the RP.
- **What the flags claim.** UV is set after a click in an unlocked vault, without a fresh biometric or password check; sites read it as "the user was verified". BE and BS tell sites the key is backed up and synced. The counter is always 0, so a site cannot detect a copied vault.
- **Leftover copies.** Replacing or removing a passkey can leave older private keys in history items (MOD-03); deleting history removes them. Exported `.passkey` files hold the private key in plain text: Larsal warns (SD-07) and writes them owner-only (SD-09).
- **Probing.** The exclude list must not answer silently (INT-04.21).
- **Parsing.** The bridge message is bounded (SI-01). Import files are bounded (INT-04.47). PEM and DER parsing goes through larsal-crypto's approved crates and never panics. Key bytes are wiped after each signature (SR-07).
- **Signing.** Only the approved crates sign (`p256`, `ed25519-dalek`, and an RSA crate only if D-INT04-2 adds one). Each signature is computed only after the user confirmed, over client data Larsal built itself.

## Test cases

Demo vault V (password `demo-pass`), associated with the extension, the only unlocked vault, S-BRW-19 off:
- Root group "Root" with entries P1 and L1; group "Work" with entry P2.
- P1 "Example (Passkey)": user name `alice`, URL `https://example.com`, tag Passkey. Fields: RP `example.com`, passkey user name `alice`, credential id C1 = `oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8` (bytes A0 to BF), user handle `ZGVtby11c2VyLTE` ("demo-user-1"), BE `1`, BS `1`, private key K1:

  `-----BEGIN PRIVATE KEY-----`
  `MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFO0mBiERh5J1d0+Z`
  `GtQqZRub8OxZ2f2ES/PiR8GdzBmhRANCAAS6B148QyqG2wZnYQS6trlr6Z5GLMH8`
  `QrizCy9u7t9LQw48eo88I5vZRshTQUzcJGCcuQ5FKOfhfj447uQxVgK7`
  `-----END PRIVATE KEY-----`

  (P-256 scalar `14ED26062111879275774F991AD42A651B9BF0EC59D9FD844BF3E247C19DCC19`; x = `BA075E3C432A86DB06676104BAB6B96BE99E462CC1FC42B8B30B2F6EEEDF4B43`, y = `0E3C7A8F3C239BD946C853414CDC24609CB90E4528E7E17E3E38EEE4315602BB`)
- P2 "Shop (Passkey)": user name `bob`, URL `https://shop.example`. Fields: RP `shop.example`, passkey user name `bob`, credential id C2 = `wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t8`, user handle `ZGVtby11c2VyLTI`, no backup-flag fields, private key K2 = `-----BEGIN PRIVATE KEY-----` / `MC4CAQAwBQYDK2VwBCIEIJz4DANKB5wE/aun9YNvMxcb01J08p7XHSBBA11G5GlI` / `-----END PRIVATE KEY-----` (Ed25519 seed `9CF80C034A079C04FDABA7F5836F33171BD35274F29ED71D2041035D46E46948`, public key `B96352AB8BAA1DAEB327A6D3FB83658F5F9A8E9E23E40F1D5241818F0665C079`).
- L1 "Login only": URL `https://login.example.com`, password `pw-demo`, no passkey fields.

Request R1 (register): origin `https://example.com`; `challenge` = `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8` (bytes 00 to 1F); `rp` = {id `example.com`, name `Example`}; `user` = {id `ZGVtby11c2VyLTM`, name `carol`}; `pubKeyCredParams` = [{public-key, -7}]; `excludeCredentials` = []; `timeout` = 60000; `group` empty.
Request A1 (get): origin `https://example.com`; `challenge` = `EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8` (bytes 10 to 2F); `rpId` = `example.com`; `allowCredentials` = [{id C1, type public-key, transports [internal]}]; `userVerification` = `required`; `timeout` = 60000.
Tests that need fixed bytes use a test-only hook that injects the credential id and the key pair.
The requests come from INT-01's test client. Larsal runs hidden with a test settings file; dialogs are answered by a scripted answerer or rendered offscreen, the window raise and restore of INT-04.28 run against a fake window service, and file choosers take paths under `/tmp/spec-int04/`. No case shows a window on the owner's screen or takes focus (AGENTS rule 10).

| Case | Given | When | Then |
|---|---|---|---|
| T01 INT-04.1 | V | Register R1, Register, Create at the group question | The new entry holds the seven fields; credential id, private key and user handle saved with `Protected="True"`; RP, user name and flags plain (FMT-14 14-34) |
| T02 INT-04.2 | Entry X with only the field whose key bytes are `4B 50 45 58 5F 50 41 53 53 4B 45 59 58` (stored encoded, name rule) = `1`; entry Y with only the encoded foreign user-name field | Open the entry menu on each | X offers Remove passkey and counts in FEA-07.13; Y does neither |
| T03 INT-04.3 | K1 stored with no line breaks between header and footer, as the JSON import writes it | A1, Authenticate | Signs as with the 64-character layout; the signature verifies with P1's public key |
| T04 INT-04.3 | A new ES256 passkey | Read its PEM field | Header line, base64 lines of 64 characters, footer, final LF; DER of 138 bytes starting `30 81 87 02 01 00` |
| T05 INT-04.3 | P1's PEM replaced by a P-384 EC key | A1, Authenticate | Error 31; nothing logged about the key |
| T06 INT-04.4 | P1 plus field `KPEX_PASSKEY_GENERATED_USER_ID` = `Zm9yZWlnbi1pZA` | A1 with `allowCredentials` [{id `Zm9yZWlnbi1pZA`, type public-key}] | P1 is listed; the reply `id` is `Zm9yZWlnbi1pZA`. A1 as given (id C1): error 15 |
| T07 INT-04.4 | P1 plus the encoded foreign user-name field = `alice-other` | Open the Passkeys report | Username column shows `alice-other` |
| T08 INT-04.5 | P2 (no flag fields) | Get for `shop.example` (origin `https://shop.example`), Authenticate | authenticatorData byte 32 = `1D`. Installed 2.7.11 sends `05` |
| T09 INT-04.5 | P1 with BE `true`, BS `0` | A1, Authenticate | Flags `0D` |
| T10 INT-04.6 | V | Register with `user.id` `ZGVtby11c2VyLTE` for `example.com`, Replace on P1, then Replace at the overwrite question MI04-01 | P1 has a new credential id and key, the same title, user name and URL; one new history item holds the old key; tag list still `Passkey` once |
| T11 INT-04.6 | P1 plus `KPEX_PASSKEY_GENERATED_USER_ID` = `Zm9yZWlnbi1pZA` | Store a new passkey into P1 (T10 path) | The foreign id field is gone; the reply and later sign-ins use the new id |
| T12 INT-04.7 | V | Register R1 with `rp.name` `"  "` | New entry title `example.com (Passkey)` (reference: ` (Passkey)`) |
| T13 INT-04.7 | V | Register R1, Register, Create | New entry "Example (Passkey)" in group "Browser Passkeys": user name `carol`, URL `https://example.com`, icon 13, password empty, no history items |
| T14 INT-04.8 | P1 | The extension asks for logins on `https://example.com/login` (INT-02) | P1 is offered for password fill through its RP field |
| T15 INT-04.9 | V | A1 with origin `http://example.com` | Bridge error reply, code 25 |
| T16 INT-04.9 | V; S-BRW-19 on; P3 with RP `localhost` and a key | Get with origin `http://localhost:8080`, `rpId` missing | Accepted, RP ID `localhost`; with S-BRW-19 off: error 25 |
| T17 INT-04.9 | V | A1 with origin `https://example.com/path` | Larsal: error 25 (the reference accepts it and writes the path into the client data) |
| T18 INT-04.10 | V | A1 with origin `https://127.0.0.1`, `rpId` missing | Error 27 |
| T19 INT-04.10 | V | Register R1 with origin `https://xn--bcher-kva.example`, `rp.id` missing | RP ID `xn--bcher-kva.example`, accepted. Installed 2.7.11: error 27 |
| T20 INT-04.11 | V | A1 with origin `https://www.example.com` | RP ID `example.com`; P1 listed |
| T21 INT-04.11 | V | Register R1 with origin `https://example.com` and `rp.id` `com`; again with `another.com`; again with `example.com.` | Error 28 each time |
| T22 INT-04.11 | V | Register with origin `https://demo.github.io` and `rp.id` `github.io`; then origin `https://app.demo.github.io` and `rp.id` `demo.github.io` | First: error 28 (public suffix); second: accepted, RP ID `demo.github.io` |
| T23 INT-04.11 | V | Register R1 with `rp.id` `Example.COM` | Larsal: RP ID `example.com`, hash `A379…1947`, RP field `example.com` |
| T24 INT-04.12 | V | Register R1 with a 15-character challenge `AAECAwQFBgcICQo`; then 16 characters `AAECAwQFBgcICQoL` | 15: error 32; 16: dialog opens |
| T25 INT-04.12 | V | A1 with challenge `abc"def0123456789` | Larsal: error 32 |
| T26 INT-04.13 | V | Register R1 with `user.id` empty; with base64url of 64 bytes; with base64url of 65 bytes | Error 33; accepted; error 33 |
| T27 INT-04.14 | V | Register R1 with `pubKeyCredParams` [{public-key, -257}, {public-key, -7}] | RS256 key (with D-INT04-2 (a)): COSE key 271 bytes, `publicKeyAlgorithm` -257 |
| T28 INT-04.14 | V | Register R1 with [{public-key, -35}]; with []; with [{private-key, -7}, {public-key, -8}] | Error 29; ES256; EdDSA (COSE key 42 bytes) |
| T29 INT-04.15 | V | Register R1 with `attestation` `direct` | Attestation object `fmt` is `none`, `attStmt` empty |
| T30 INT-04.16 | V | Register R1 with `authenticatorAttachment` `cross-platform`; with `usb` | Reply attachment `cross-platform`; error 30 |
| T31 INT-04.16 | V | Register R1 with `userVerification` `discouraged` | Flags still `5D` |
| T32 INT-04.17 | V | Register R1 with `extensions` {credProps: true, devicePubKey: true} | `clientExtensionResults` = {"credProps":{"rk":true}}; Larsal: flags `5D`, no extension data (reference: flags `DD` plus `A1 69 63 72 65 64 50 72 6F 70 73 A1 62 72 6B F5`) |
| T33 INT-04.18 | V | Register R1 with `timeout` 60000; missing; 5000000 | Countdown 60 s; Larsal 300 s; Larsal 600 s |
| T34 INT-04.19 | Two unlocked vaults | Register R1 with `rp.id` `another.com` | Larsal: error 28, no vault picker shown |
| T35 INT-04.19 | V | Register R1 without `excludeCredentials`, Register | Larsal: stored, normal reply (reference: error 31, V-INT04-6) |
| T36 INT-04.20 | V and a second unlocked vault W, both holding the session's identification key; S-BRW-14 on | Register R1, Cancel in the picker | The picker's title is MI04-19 and it lists V and W; error 1, nothing stored |
| T37 INT-04.21 | V | Register R1 with `excludeCredentials` [{id C1, type public-key}] | Larsal: notice MI04-02, OK, then error 21; no entry made |
| T38 INT-04.22 | V | Register with `user.id` `ZGVtby11c2VyLTE` for `example.com` | Dialog in existing mode (heading MI04-05, hint MI04-06) lists "Example (Passkey) - alice", buttons Cancel, Replace, Add another |
| T39 INT-04.23 | V | Register R1, Cancel; again and wait out the countdown | Error 22 both times; vault unchanged |
| T40 INT-04.23 | T10 setup | Replace on P1, then Cancel at the overwrite question MI04-01 | Larsal: error 22, P1 unchanged (reference: sends the credential) |
| T41 INT-04.23 | V | Register R1, Pick an entry… (MI04-10), choose group Root and entry L1 in the placement dialog (title MI04-13, text MI04-14), Register | L1 gets the passkey fields and the tag; title `Login only` and password `pw-demo` kept |
| T42 INT-04.24 | V | Register R1 with `group` `Web/Keys`, Register, Create | Groups "Web" and "Web/Keys" made; both have `BrowserHideEntry` = `false`; only "Keys" has icon 13; the entry is in "Keys" |
| T43 INT-04.24 | V | Register R1, Register, Cancel at the group question | The entry lands in INT-02's default login group, created silently |
| T44 INT-04.25 | Test hook makes an ES256 key whose x starts with byte `00` | Register R1 | COSE `-2` value is 32 bytes (`58 20 00 …`); authenticator data 164 bytes |
| T45 INT-04.26 | V | Register R1 three times | Three credential ids, each 43 base64url characters, all different |
| T46 INT-04.27, INT-04.32, INT-04.37 | Hook: credential id bytes A0 to BF, key K1, Larsal AAGUID | Register R1 | Authenticator data (164 bytes) = `A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947` `5D` `00000000` `758D4080A28344BABC658D039D852732` `0020` `A0A1…BEBF` `A5010203262001215820BA07…4B43` `225820` `0E3C…02BB`. Attestation object, 194 bytes = `A363666D74646E6F6E656761747453746D74A068617574684461746158A4` + authenticator data; base64url starts `o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVik`. `response.authenticatorData` (Larsal) = the same 164 bytes |
| T47 INT-04.27 | T46 | Read `response.publicKey` | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEugdePEMqhtsGZ2EEura5a-meRizB_EK4swsvbu7fS0MOPHqPPCOb2UbIU0FM3CRgnLkORSjn4X4-OO7kMVYCuw` |
| T48 INT-04.28 | Larsal hidden in the menu bar (fake window service) | A1, Authenticate | The dialog comes to the front without Larsal's main window; afterwards Larsal is back in the menu bar and the browser is the active app again |
| T49 INT-04.29 | V; the A1 dialog is open | A second A1 arrives on the same session, then three more; then V locks | The second, third and fourth wait without a dialog or a reply; the fifth gets boxed error 42. On lock: the dialog closes; the first four each get `response` {"errorCode": 22}; nothing is stored |
| T50 INT-04.30 | T46 | Decode `clientDataJSON` | Exactly `{"type":"webauthn.create","challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","origin":"https://example.com","crossOrigin":false}` |
| T51 INT-04.31 | — | SHA-256 of `shop.example` | `0F59463C606C5B0E5D3DA81F36E3F7C175AC230C60E75C2144CE3B752247607C` |
| T52 INT-04.33 | — | Flags for registration with `uvm` true | `DD`; the authenticator data ends with `A16375766D8183010101` and is 174 bytes |
| T53 INT-04.34 | Any registration | Read bytes 37 to 52 | `758D4080A28344BABC658D039D852732`, never `FDB141B2…A502` |
| T54 INT-04.35 | Hook: Ed25519 key K2 | Register R1 with -8 | COSE = `A4010103272006215820B96352AB8BAA1DAEB327A6D3FB83658F5F9A8E9E23E40F1D5241818F0665C079`; `response.publicKey` decodes to 44 bytes starting `302A300506032B6570032100` |
| T55 INT-04.36 | V | Register R1 with {credProps: true, uvm: false} | Larsal: no extension data, flags `5D`, results {"credProps":{"rk":true}} |
| T56 INT-04.38, INT-04.43 | V | A1, Authenticate (first row P1) | `authenticatorData` = `o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcdAAAAAA`; client data = `{"type":"webauthn.get","challenge":"EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8","origin":"https://example.com","crossOrigin":false}` (SHA-256 `DDC51723899433A28C205DD63B4C180BF478D13CCE2CE0FE39BF116F76E4801B`); signature verifies with P1's public key over the 69-byte message; with RFC 6979 it is exactly `MEQCIEJXDTD3P2Q3NGqVofE4S7Mk3TQc217Xx5adalAkVglnAiAMDI9UMy4iWgQ8FPZa77GYsDxDb3ZErWslQaxqcJzT4A`; `userHandle` `ZGVtby11c2VyLTE`; `id` C1; attachment `platform` |
| T57 INT-04.38 | K2, the 69-byte message of T56 | Sign (larsal-crypto unit test) | `B8FD0C152E74C99C619944CFCAEF55EA1B4374361E16DF535CF672BAE6B7879BF9C45D4CC18742CF1F368D89006B0D60AB00EE5BB88A7EF4BD5A1F169242FE0E` |
| T58 INT-04.39 | T46 | Inspect every binary member | No `=`, `+` or `/` in any of them |
| T59 INT-04.40, INT-04.54 | V locked | A1 | Boxed error 1 (INT-01.30), not inside `response`; no dialog |
| T60 INT-04.41 | P1 moved to the recycle bin; then P1 back, group Root set to hide from the browser | A1 | Error 15 both times |
| T61 INT-04.41 | P1 expired yesterday | A1 | P1 is listed and can sign in |
| T62 INT-04.41 | V | A1 with origin `https://www.example.com` and `rpId` `www.example.com` | Error 15: P1's RP `example.com` does not equal `www.example.com` |
| T63 INT-04.42 | V | A1 with `allowCredentials` []; with [{id C1, transports [hybrid]}] | P1 listed; error 15 |
| T64 INT-04.42, AT-F08 | V | Get from origin `https://evil.example` with `rpId` `example.com`; then with `rpId` missing and `allowCredentials` [C1] | Error 28; error 15 |
| T65 INT-04.44 | V; fake time T | A1, Authenticate | The vault shows no unsaved changes; P1's fields, times and history unchanged; the association's `_LAST_USED_` item and P1's `BrowserLastUse` hold T (INT-02.9) |
| T66 INT-04.45 | V | A1, press Return at once | Error 22 (Cancel is the default) |
| T67 INT-04.46 | P1 with two history items | Entry menu, Remove passkey, confirm | All seven fields and the tag gone; no new history item; modification time = now; L1 offers no Remove passkey |
| T68 INT-04.47 | File `a.passkey` = `{"relyingParty":"example.com","url":"https://example.com","username":"dan"}` | Import Passkey | MI04-23 for `a.passkey` with the missing list "credentialId, userHandle, privateKey" in that order |
| T69 INT-04.47 | A `.passkey` whose `privateKey` is ` -----BEGIN PRIVATE KEY-----…` with a leading space; another that is a JSON list `[]` | Import each | MI04-24; MI04-22 |
| T70 INT-04.47 | A 2 MiB `.passkey` file | Import | Larsal: MI04-21, nothing read into a vault |
| T71 INT-04.48 | The file of T73 below, re-imported into a copy of V without P1 | Vault menu, Import Passkey, the default group item MI04-16, the new entry item MI04-17, Import | Group "Imported Passkeys" made at the root; entry "example.com (Passkey)", user name `alice`, URL `https://example.com`, icon 13, fields as in P1, BE and BS `1`, no history |
| T72 INT-04.48 | Same file | Select L1, entry menu Import Passkey, Import | L1 gets the passkey; its URL stays `https://login.example.com` |
| T73 INT-04.49 | P1 | Export P1 | The file `Example (Passkey).passkey` is 469 bytes: `{`, then the lines `    "credentialId": "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8",`, `    "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGH…VgK7\n-----END PRIVATE KEY-----\n",`, `    "relyingParty": "example.com",`, `    "url": "https://example.com",`, `    "userHandle": "ZGVtby11c2VyLTE",`, `    "username": "alice"`, then `}` and LF |
| T74 INT-04.50 | P1 and P2 selected in the report | Export, answer No | Nothing written |
| T75 INT-04.50 | Entry titled `a/b:c?` with a passkey; folder already holds `a_bc.passkey` | Export, Yes at MI04-30, Export Selected, choose the folder, No at the file overwrite question MI04-32 | File untouched. Answering Yes: file rewritten with mode 0600 |
| T76 INT-04.51 | P1 | Open the detail view and the edit screen | Detail: "Sign in to example.com as alice"; no Show or Copy for passkey data. Edit: "example.com · alice" with Remove; no raw passkey field listed. L1 edit: "None. The browser extension saves passkeys here." |
| T77 INT-04.52 | V plus P1 copy in the recycle bin, plus entry Z with only `KPEX_PASSKEY_RELYING_PARTY` | Open the Passkeys tab | Rows P1, P2 (sorted: "Example (Passkey)", "Shop (Passkey)"); Path of P2 "Root › Work"; Z and the recycled copy not listed, while FEA-07.13 counts Z |
| T78 INT-04.53 | Report open, P2 selected | Press Delete, confirm | P2 goes to the recycle bin (MOD-04) and the list shows only P1 |
| T79 INT-04.54 | V | A1 with `public_key` = {} | Bridge error reply code 24 (not inside `response`) |
| T80 INT-04.54 | V | Register R1 with `authenticatorAttachment` `usb` | `response` = {"errorCode": 30} |
| T81 INT-04.55 | V made with the reference command line import (demo, in /tmp, with a throwaway HOME) | `show` with all attributes; search `attr:alice` | Larsal lists `KPEX_PASSKEY_CREDENTIAL_ID: (hidden)` (the reference: `PROTECTED`), `KPEX_PASSKEY_RELYING_PARTY: example.com` and the other fields; the search finds nothing (observed in installed 2.7.11) |
| T82 INT-04.20 | V holds the session's identification key; W unlocked but without it; S-BRW-14 on | Register R1, Register, Create | No vault picker; the new entry is in V; W unchanged |

## How this was learned

- Read in the reference source (development branch): the bridge's two passkey request handlers (association, decrypt and action checks, the empty-options and origin checks, the reply wrapping); the passkey client routine that turns the extension's options into creation and assertion options; the passkey utility routines (limits, origin gate, effective domain, domain validity, RP ID and registrable-suffix checks, algorithm list, attestation, authenticator selection, verification, extensions, client data text, allowed credentials, the foreign id and user-name fallbacks); the passkey builder (authenticator data, flags, attestation object, AAGUID, key pairs, public key encodings, signatures); the small CBOR helper; the browser service's passkey prompts, the store-into-entry and new-entry routines, the entry search, the exclude and same-account checks, the group creation and default group routines, the vault picker call and the window raise and restore; the passkey confirmation dialog and its screen definition; the passkey import and export routines, their dialogs and screen definitions; the Passkeys report page and its screen definition; the reports dialog's page order; the main window menus and their enable rules; the entry and entry-attribute passkey helpers; the JSON importer's passkey part; the browser settings screen's advanced tab and the settings default table; the message builder's error texts and base64url helpers; the filename cleaner.
- Read the reference's passkey unit tests and passkey import test to see which edge cases it covers; no test value was copied. Every key, id, challenge and vector in this card is Larsal demo data.
- Compared the source with installed version 2.7.11 through the reference's change history (read only): 2.7.11 has no backup-flag fields (flags `45` and `05`), no `publicKey` member in the registration reply, rejects internationalized hosts, creates missing groups in the current vault; both ask before export.
- Ran the installed command line tool 2.7.11 on a demo vault built from a demo XML in `/tmp/spec-INT-04/` (password `demo-pass`): import, database info (no passkey row), show with all attributes (passkey fields listed, protected ones as `PROTECTED`), search (`attr:alice` finds nothing, `attr:blue` finds the entry's ordinary field), CSV export (no passkey columns).
- Computed every hash, CBOR byte string, base64url value and signature with python3 and OpenSSL 4.0 in that scratch folder; the ES256 signature uses RFC 6979 nonces and both signatures were verified with the public keys.

## Review 2026-10-28

Second Spec review (the Checker sample of E1-S6 found none recorded, F3). Read again in the reference source at the studied commit: the bridge's two passkey request handlers; the service's register and sign-in prompts, the store-into-entry and new-entry routines, the passkey entry search, the exclude and same-account checks, the group creation and default group routines, the vault picker and the window raise and restore; the passkey client's option builder; the passkey utilities; the passkey builder and the CBOR helper; the confirm dialog and its screen definition; the passkey importer, its dialog and the exporter; the Passkeys report page; the main window's passkey menu items and their enable rules; the entry's passkey helpers and the remove action. Read again in this project: INT-01, INT-02 and INT-03 after their review (LD-189, LD-191) and the locked frames `extension-in-page-save-passkey`, `extension-in-page-sign-in-with-passkey`, `dialogs-remove-passkey` and `reports-reports-passkeys`. Recomputed with python3 and OpenSSL 4.0.3 in a private `/tmp` folder (deleted after): the RP ID hashes (INT-04.31, T51), C1, C2 and the user handles, the SubjectPublicKeyInfo of T47, the authenticator data and the 194-byte attestation object of T46, the client data hash and `authenticatorData` of T56, the RFC 6979 ES256 signature of T56, the Ed25519 public key and signature of T54 and T57, the 469-byte export file of T73; all match except the DER length (fix 1). Nothing of the reference was run; no network.

Confirmed against the reference source: the association check comes before the box is opened; the empty options (24) and origin (25) checks; the option checks in the order 32, 33, 26 or 27, 28, 29, 30; the default algorithm list [-7, -257]; the RP ID steps of INT-04.11, including that it keeps the site's text when it differs from the effective domain; the effective domain in punycode form; the transports rule and the empty `allowCredentials` rule; the foreign id and user-name fields winning when present; the AAGUID, the flags and the 37-byte short authenticator data; the extension map whose header counts members, not written pairs; the vault picker before the option checks; the success reply after a declined overwrite; the group question with icon 13 on the last made level and `BrowserHideEntry` = `false` on every made level, and the default login group when it is declined; codes 1 and 15 sent inside `response`; the half-second wait after raising the window; Cancel as the confirm dialog's default, one-second steps, and a timeout of 0 that closes the dialog after about a second; rows "‹title› - ‹user name›" with the first one marked; the import checks and their order and the "Imported Passkeys" group at the root; the export file name cleaner, overwrite question and write-failure message; the report's rows (a private-key field, the recycle bin left out) and its show-expired box; remove without a history item.

Fixes made (13):
1. INT-04.3 and T04: the DER Larsal writes for ES256 is 138 bytes (`30 81 87`: a sequence of 135 bytes), not 135.
2. INT-04.20 (LD-191: "a passkey request uses only an associated vault (INT-04's own review)"): the vault is one of INT-02.10's usable vaults; the picker shows only with S-BRW-14 on and more than one usable vault, titled by the new MI04-19; T36 changed, new T82; INT-02.10's note now says passkeys follow it.
3. INT-04.48: opened from registration, the placement dialog's vault list holds only INT-04.20's vault (the reference lists every unlocked vault there too).
4. INT-04.40 step 2 and INT-04.41's vault line point to INT-01.30 and INT-02.10 (so a vault behind MOD-13's forced prompt is never used); T59 expects the boxed error 1.
5. INT-04.54: 1, 15, 24, 25 and 42 are boxed bridge errors, as INT-01.40's table says; the reference sends 1 and 15 inside `response`. Code 26 is never sent in practice (the origin gate answers an empty origin with 25 first, in both apps).
6. INT-04.29: passkey dialogs share INT-02.15's line instead of refusing a second request with 22 at once (INT-01.44 and INT-02.15 already said so); a full line gives 42; for passkey requests 22 takes the place of INT-01.30's error 6; a session end closes the dialog without a reply (INT-01.45). T49 rewritten.
7. INT-04.28, INT-04.19 step 6 and INT-04.40 step 5: dialogs come to the front as every bridge dialog does (INT-02.15), not by raising Larsal's main window; T48 runs against a fake window service.
8. INT-04.24: the group question is INT-02.26's MI02-08 with Create and Cancel (Cancel and its 60-second timeout send the entry to the default login group, as the reference's No); T01, T13, T42 and T43 answer it after Register, where it comes. INT-02.26's note that passkeys find their default group "the same way" is corrected: the passkey default is a path from the root and is asked for, as in the reference.
9. INT-04.44: the one write on use is INT-02.9's last-use record, a view-state change; T65 checks it.
10. INT-04.47 and INT-04.50: the private key's end is checked, and the export file name cleaned, after trimming all white space at both ends (the reference trims tabs and line ends too, not only spaces).
11. INT-04.2: the test also drives the `passkey` flag of INT-02.20's summaries.
12. INT-04.46 and MI04-34 follow the frame `dialogs-remove-passkey`: its heading names the site, the text names what the entry keeps, the button is "Remove Passkey".
13. Test cases: the setup states AGENTS rule 10 (Larsal hidden, scripted answers, fake window service, files under `/tmp/spec-int04/`, no window on the owner's screen); T81 runs the reference's command line tool with a throwaway HOME.

Every rule has a test case naming it (82 cases, T01 to T82).

Finding, with a proposed ruling (it waits for the lead's ruling before E7-S5 starts, LD-215; until then the card's dialog flow stands):

| ID | Finding | Proposed ruling |
|---|---|---|
| R04-1 | INT-04 was written before the Option A frames were locked. The frames draw both passkey prompts inside Larsal's extension: `extension-in-page-save-passkey` ("Save a passkey for ‹site›?", a choice between adding it to a matching entry, which "keeps its password", and a new entry in a named group, then Cancel and Save Passkey) and `extension-in-page-sign-in-with-passkey` (the matching passkey rows, Cancel and Continue, "Larsal confirms with Touch ID before it signs in"). INT-04.45's Larsal dialog with a countdown, Register, Pick an entry…, Replace and Add another (MI04-03 to MI04-14) has no frame. INT-04.33 also sets UV after a click, which WebAuthn calls user presence, not user verification (W3C WebAuthn Level 3, terms "User Present" and "User Verification": a biometric, PIN or password check). | Follow the frames, in two steps like D-INT01-9: the extension lists passkey entries from `logins.find` (summaries already carry `passkey`, INT-02.20) and draws both prompts; `passkey.create` gains the user's target (`{"vault","id"}` of a listed entry, or a group id for a new entry) and `passkey.get` the chosen entry `{"vault","id"}`, each checked by INT-02.13. After the user's Save Passkey or Continue, Larsal asks for Touch ID (the vault password through APP-06 when Touch ID is off or fails) with a system prompt naming the site, and signs or stores only after it passes; UV is set only then. The exclude check (INT-04.21), the overwrite question (MI04-01), the vault picker and the group question stay in Larsal. Larsal's countdown dialog and the Pick an entry… path go. A Spec agent rewrites INT-04.19 to INT-04.29, INT-04.33, INT-04.40 to INT-04.45, the messages and the tests before E7-S5 starts. Evidence: the locked frames; WebAuthn's meaning of UV; Bitwarden's browser extension draws its own passkey prompts in the browser (from earlier reading, not re-opened in this review: no network; the rewrite cites their sources, AGENTS rule 9). |


## E24-S1 proposed extension — 2026-11-05

Status: DRAFT, unadopted. Builds E24-S4/S5/S6; full order and capability map in [research](../research/passkeys-and-ssh.md). This appendix changes none of the preceding implemented requirements, IDs, T01–T82 or historical evidence. Where proposed behavior conflicts, Lead must explicitly amend the old clauses before implementation; proposed conflict aftertexts are outside this tree. Source links P01–P17 are primary reads dated 2026-11-05, with release/draft status and custody gates stated there. All cases below are new, unrun obligations.

### E24 proposed rules

INT-04.E24.01 **Platform capability.** The native provider accepts create/get requests on macOS 14.0 or later, after user enablement and a signed build. Exchange separately requires macOS 26.0 or later. Intel and Apple silicon targets use the same contract; platform/device success is unproved. Older OS, missing entitlement, disabled provider, unavailable account and unsupported request return an explicit unavailable/error state, never a browser fallback labelled native success. D7/W-02 gate S4, not S1. Source: [P02](../research/passkeys-and-ssh.md#p02).

INT-04.E24.02 **Signed target.** Use a distinct embedded credential-provider extension, the extension point and both-app/extension AutoFill entitlement of P03. Enable sandbox on extension; reuse the existing team-qualified E7 group relay with a distinct endpoint, matching app-group entitlement on each participant. Set ProvidesPasskeys=true in the credential-provider capability dictionaries of both the host app and its extension; provide extension configuration UI. Do not add associated domains for every credential site, private key access groups or general network entitlements. Provisioned identifiers/profile, exact bundle signing and distributed-route eligibility require G01; enabling a plist flag alone is insufficient. Source: [P03](../research/passkeys-and-ssh.md#p03).

INT-04.E24.03 **Enablement and suggestions.** Settings shows Enable in System Settings as an explicit user action and distinguishes disabled, enabled, locked and unavailable. Publish identities only from eligible unlocked vaults with browser visibility restrictions honored; no private key in identity store. Remove identities on lock/close/remove/replacement/feature-off and rebuild only after unlock. OS cache retention and purge latency are OPEN measurements; locked stale suggestions never produce a credential or label leaks from Larsal. Source: [P05](../research/passkeys-and-ssh.md#p05).

INT-04.E24.04 **Rust boundary and relay.** Reuse E7 local authenticated transport/owner-only group socket and existing session ownership, with a provider purpose distinct from browser association. Check peer code/team identity, same user, bounded authenticated request ID and fresh vault generation. Swift controller receives view data and opaque request/entry handles only; no master key, private key, passphrase or raw protected entry field. The Rust-held vault is authoritative; no decrypted app-group file or Keychain mirror. Missing verified transport is an implementation gate, never permission to serialize secrets in Swift. Source: [P04](../research/passkeys-and-ssh.md#p04).

INT-04.E24.05 **Trusted native request.** Use ASPasskeyCredentialRequest/Parameters from the OS. Bind RP ID, clientDataHash, user handle, assertion allowed IDs, any OS-supplied registration exclusion list, algorithms and request kind to one operation; assertion allowed IDs are not registration exclusions; do not reconstruct clientDataJSON/origin from a service URL or trust a process-supplied app title. OS validates associated-domain entitlement for native relying apps; Larsal independently applies RP/credential equality and bounds. Service identifiers alone authorize no passkey. Source: [P05](../research/passkeys-and-ssh.md#p05).

INT-04.E24.06 **Choice and matching.** Native picker lists only live non-recycled eligible entries of the bound RP and allowed IDs, comparing canonical decoded bytes for IDs/user handles. Empty allow-list permits discoverable credentials. Display account and vault/group, never credential/user-handle/private bytes. Selecting another entry/vault invalidates a prior selection. Browser E7 association rules remain independent and cannot be bypassed by presenting a native handle. Source: [P01](../research/passkeys-and-ssh.md#p01).

INT-04.E24.07 **Verification and flags.** For each E24 create/get require deliberate consent and fresh Touch ID after E6-S3 signing is available, otherwise a vault-password verification performed in Rust through existing protected input. Failure/cancel signs nothing. An already unlocked vault or confirm click is not fresh verification. UV/UP and BE/BS describe actual ceremony/storage semantics; BS without BE is refused, no invented attestation or extension output. Old .16/.33/.36 and R04-1 conflicts remain UNADOPTED amendments; do not claim their old cases prove this rule. Source: [P01](../research/passkeys-and-ssh.md#p01).

INT-04.E24.08 **Create and commit.** After the required privacy-preserving consent/verification, check registration exclusions against live credentials using the same RP/type and canonical credential-ID bytes. A match prevents generation, overwrite, save and registration success; cancellation must not disclose credential existence. Create a key in approved Rust crypto only if no exclusion matches. Empty or absent exclusions and nonmatching RP/ID cases retain the valid registration success path. Save using existing protected passkey entry layout and writable-vault/group/overwrite validation; never drop unrelated password/code fields. Bind source draft revision and vault generation. Persist with normal atomic save before completing OS registration; save/collision/lock failure yields no success response. Cancellation before commit discards draft. A cancellation arriving after durable commit leaves a clearly reported saved credential, never deletes an unacknowledged key silently. Source: [P01](../research/passkeys-and-ssh.md#p01).

INT-04.E24.09 **Assertion and lifecycle.** An assertion performs no credential-key/counter mutation beyond existing allowed view-state use record. Capture request/entry/key revisions and vault generation; recheck before signing and immediately before response handoff. Lock request, sleep, user switch, close, replacement, delete, provider disable, session loss, OS cancellation or deadline revokes queued/in-flight work. Wipe Rust transient buffers; close own UI; no automatic resume/retry after unlock. A response already delivered cannot be recalled. Source: [P05](../research/passkeys-and-ssh.md#p05).

INT-04.E24.10 **Bounds and concurrency.** Inherit E7 message bounds; native envelope and response at most 256 KiB, at most 4 waiting requests per client and 16 overall, one visible ceremony at a time. Proposed native UI deadline: earlier of OS deadline and 60 seconds from admission, including queue; never extend it on a re-render. Validate types/lengths before allocations/crypto. Full queue, unsupported extension/algorithm or malformed values returns bounded error; no cryptographic downgrade or fake extension support. Source: [P01](../research/passkeys-and-ssh.md#p01).

INT-04.E24.11 **OS response custody.** Rust produces only the public WebAuthn registration/assertion outputs needed by ASPasskeyRegistrationCredential/AssertionCredential. OS response can contain credential ID/user handle, signature and public key, never a private key. Bind completion once; account labels/IDs are retained outside Rust only for the operation and cleared on closure. Document OS/accessibility/capture retention; never claim OS object deallocation proves wiping or that a static frame excludes capture. Source: [P05](../research/passkeys-and-ssh.md#p05).

INT-04.E24.12 **Exchange profile.** Implement CXF 1.0 with 2026-03-09 errata, and explicitly record the OS negotiated format version and protected transport. CXF alone is a readable data model; base64/PKCS#8 is not encryption. CXP 1.0 linked by FIDO is a 2024-10-03 working draft; do not label it a final standard or claim Apple wire equivalence without proof. No homemade encryption, archive scheme or readable legacy export is an E24 exchange fallback. Source: [P06](../research/passkeys-and-ssh.md#p06).

INT-04.E24.13 **Exchange API and availability.** For supported macOS 26+ use ASCredentialExportManager requestExport(for:) then exportCredentials(_:); receive the exported exchange-activity value (P08 documents the article/SDK symbol-name mismatch) with ASCredentialImportToken UUID and call ASCredentialImportManager.importCredentials(token:). Configure SupportsCredentialExchange and SupportedCredentialExchangeVersions=["1.0"] plus NSUserActivityTypes as P08 states. Recheck version and selected target, reject stale/replayed/wrong-recipient tokens. API/entitlement runtime failure leaves the feature unavailable with a retry path; no unsupported-platform PASS. Source: [P08](../research/passkeys-and-ssh.md#p08).

INT-04.E24.14 **Selection and authorization.** Before migration show eligible selected sites/accounts and destination provider, warn that the recipient can use and retain the keys, and require fresh verification for this exact export/import. Bind receiver identity from OS chooser, selection IDs/revisions, vault and generation; do not trust a supplied display name as receiver identity. Cancel is default. Unselected/hidden/recycled/history credentials never ride along; importer chooses writable vault/group explicitly. Source: [P08](../research/passkeys-and-ssh.md#p08).

INT-04.E24.15 **Lossless passkey mapping.** Map CXF RP, credential ID, handle and key exactly to existing protected fields through Rust; PKCS#8 DER converts only in Rust to the established protected representation. Keep username/display name distinct using Larsal metadata if necessary (G02 schema review); URL is not RP authority. Preserve supported FIDO2 extension state losslessly and scoped to the same credential. Unknown optional data is ignored only as CXF permits and disclosed if it prevents lossless round trip; required unsupported state blocks that item and cannot pass its migration case. No key/RP/id edits to make a rejected key appear compatible. Source: [P06](../research/passkeys-and-ssh.md#p06).

INT-04.E24.16 **Hostile import transaction.** Treat decrypted exchange data as hostile input even after OS transport succeeds. Use bounded secret-aware Rust parsing, not larsal-model JSON's public-data path. Proposed cap 16 MiB total decoded credential metadata/private-key data, 10,000 selected credentials, nesting 32 and 1 MiB per key; check before allocation/KDF/DER work and surface documented limits. Validate every selected passkey, RP/id/handle types, key/public consistency, version and allowed algorithm; unknown non-passkey items are excluded with count. Broken selected input fails the entire staged batch with nothing saved; no path writes, URL execution or network fetch from data. Source: [P06](../research/passkeys-and-ssh.md#p06).

INT-04.E24.17 **Duplicate and conflict policy.** Identity is (RP ID, credential-ID bytes). Same identity and same key/handle is a duplicate: preserve existing entry and report skipped count. Same identity with different key or handle fails the entire selected import; never overwrite. Different credential ID for same RP/account is a distinct passkey and can be added. Recheck concurrent revisions at commit; changed vault/target restarts review, never last-writer-wins. Source: [P06](../research/passkeys-and-ssh.md#p06).

INT-04.E24.18 **Imported success.** Import commits all validated new items through existing atomic vault save before publishing native/extension identities or reporting success. Imported counters are zero and never incremented. Complete only when saved; later sign-in through E7 demo pages and native provider must verify with the original relying-party public key. OS transport completion is not import persistence proof. Original provider keeps its copy unless the user separately removes it. Source: [P06](../research/passkeys-and-ssh.md#p06).

INT-04.E24.19 **Export exclusions and completion.** Export only selected live credentials the standard permits. Nonzero-counter/device-bound/non-exportable or unsupported-extension entries have named excluded counts before consent; do not silently omit them. Never rekey, reset a nonzero source counter or export history. No automatic source deletion after success. Receiver acceptance and Larsal durable import result are separate results; errors/rejection are explicit. Required eligible success cases stay OPEN until real peer interoperability. Source: [P06](../research/passkeys-and-ssh.md#p06).

INT-04.E24.20 **Secret custody gate.** Private migration data remains Rust-owned/wipeable inside the protected exchange operation until the precisely identified OS handoff. No private key appears in Swift view/controller state, JS/DOM, ordinary Codable/JSON values, log, crash report, clipboard, readable file or temp. P09 shows a Swift data API, so the bridge/allocation/OS protection review is OPEN; this rule describes required final behavior, not an achieved route. Keep the original single-Show exception unchanged; private passkey export has no Show escape. If no compliant route exists, escalate the acceptance conflict to Lead rather than reducing S5. Source: [P09](../research/passkeys-and-ssh.md#p09).

INT-04.E24.21 **Handoff, cancel and lock.** The first API call that receives readable credential material is the custody boundary, possibly before the OS reports success. Before it, cancellation/lock/revision change prevents handoff and wipes stage. After it, revoke new operations and close own view, request supported cancellation, but disclose that OS/recipient may retain or use delivered data; do not promise recall/secure erasure. Late token/completion callbacks cannot mutate a new/locked vault. The receiving user's local key custody does not give Larsal servers a secret, password hash or offline password verifier (LD-340). Source: [P07](../research/passkeys-and-ssh.md#p07).

INT-04.E24.22 **List and delete everywhere.** Mac app, extension, web vault and larsal CLI list live passkeys with title, RP, account and vault/path; empty/error/locked states explicit. Delete Passkey removes credential data through existing Rust edit/save and confirms what remains; deleting whole entry uses MOD-04. Removal makes no call to the relying site and cannot revoke copies in history/backups/other providers. Purge native identities and invalidate active operations on the removed revision. Web deletion is an E20 encrypted Rust/Wasm edit/save boundary, not an HTTP private-key management API. Source: [P01](../research/passkeys-and-ssh.md#p01).

INT-04.E24.23 **Display and command boundaries.** Proposed CLI commands: larsal passkey list VAULT, larsal passkey show VAULT ENTRY_ID, larsal passkey remove VAULT ENTRY_ID (interactive confirmation or explicit --yes). Show means public metadata, no private/credential-ID/user-handle dump, including --all/--show-protected flags. No private-key export/copy/reveal through generic attributes, attachments, history or web APIs for E24 data. Keep legacy .49/.50/.55 and T73/T81 unchanged as an unadopted conflict requiring explicit Lead amendment and regression checks; they are not permission for a new bypass. Source: [P06](../research/passkeys-and-ssh.md#p06).

INT-04.E24.24 **Keyboard, accessibility and capture.** Use Option A tokens/assets/parts, light/dark, labelled native controls and VoiceOver order. Tab/Shift-Tab reach every actionable element; Escape cancels, Return chooses Cancel in destructive/migration prompts; sign/verify requires deliberate focused activation and never consumes the keystroke that opened the dialog. Site/account names are plain text with direction/control characters neutralized and full RP available. Fresh verification/unlock protected input uses APP-10; private key is never displayed/accessibility text. Visible metadata can be captured; no exclusion guarantee. Source: [P17](../research/passkeys-and-ssh.md#p17).

INT-04.E24.25 **Error/state catalog.** Use fixed messages: Provider unavailable → Check System Settings; Unlock Larsal to use passkeys; No passkeys for this site; Request expired. Start again; This request could not be completed; Credential exchange requires macOS 26 or later; These credentials could not be imported. Nothing was saved; Transfer cancelled before handoff; Transfer may have reached the other app. Check there. Busy/error/cancel/unsupported/lock have distinct accessible states; OS completion uses appropriate ASExtensionErrorDomain code (interaction-required, user-cancelled, identity-not-found, failed), never detailed private parser errors. Source: [P02](../research/passkeys-and-ssh.md#p02).

INT-04.E24.26 **Adoption and evidence.** E24 amendments remain DRAFT. Neither an old test nor a static frame satisfies a new success/security/OS check. Keep original E24 Order, locked design and all historical IDs/cases. Fresh second Spec review must resolve the external conflict register, then independent Verify proves mappings/static checks; later Builders prove each implementation case and attacks. Signing/dependency/custody failures remain explicit gates, not reasons to mark S1 or runtime work Done. Source: [P01](../research/passkeys-and-ssh.md#p01).

### E24 rule-to-case map and cases

Demo only; fake OS/clock/transport barriers for unit tests, signed isolated OS fixtures later; no owner account, clipboard, vault or keychain. Mutation/removal controls run only in private proof copies. Expected results are requirements, not reported passes.

| Case and rule | Given | When | Then |
|---|---|---|---|
| E24-P01 · INT-04.E24.01 | macOS 13, 14, 15 and 26 demo fixtures; signed and unsigned configurations | request each capability | Provider available only for eligible signed/enabled 14+; exchange only for 26+; unsupported paths return no credential, no new entry and an accessible explanation. |
| E24-P02 · INT-04.E24.02 | a signed demo bundle/profile pair; wrong team, missing host entitlement, absent extension entitlement, missing/false host or extension ProvidesPasskeys and changed group variants | validate configuration, then invoke registration | Only the valid matching pair receives a request; every invalid pair is refused with no decrypted store shared; no signing/team value is invented. |
| E24-P03 · INT-04.E24.03 | enabled provider with two demo identities, one hidden; cache retaining old identities | lock, remove one entry and request an old suggestion | Rust yields no identity/credential while locked; purge attempted and measured; stale selection receives identity-not-found or interaction-required without metadata disclosure. |
| E24-P04 · INT-04.E24.04 | forged same-user peer, stale session handle and valid provider peer | list/select/sign | Forged/stale peers get no metadata/signature; valid peer gets only permitted view data and protocol result; app-group storage and controller state contain no demo private bytes. |
| E24-P05 · INT-04.E24.05 | OS requests for example.com and evil.example; a forged title/site service identifier; matching, empty/absent and nonmatching registration exclusions | attempt assertion and registration, including cancel before consent | Only exact OS request RP and allowed credential match can proceed; no credential for another site; signed authenticator data hashes the bound RP and uses the supplied client-data hash; a same-RP/type byte-ID exclusion blocks creation without existence disclosure on cancel, while empty/absent or nonmatching exclusions allow valid creation. |
| E24-P06 · INT-04.E24.06 | two accounts for example.com, one foreign-site key and equal IDs encoded with different padding | choose then switch vault or narrow allow-list | Only eligible byte-identical candidates show; old selection becomes invalid; foreign key never signs; cancellation changes no vault data. |
| E24-P07 · INT-04.E24.07 | vault unlocked; fake fresh-verification succeeds, fails, cancels, and expires | register/assert with required/preferred/discouraged verification | Only a valid fresh event for the same request permits a truthful response; failure/cancel/expiry produce no signature/store; click alone never sets UV; invalid backup combination is refused. |
| E24-P08 · INT-04.E24.08 | new entry or existing entry with password/code; save fails; replacement changes revision; cancel races save; excluded live credential and nonmatching RP/type/ID variants on macOS 14/15+ | register in Safari and then sign in again | Durable successful nonexcluded key signs in; a matching exclusion generates/overwrites/saves nothing and returns no registration success; macOS 15+ uses the OS list and macOS 14 requires equivalent signed OS mediation under G01, with no fabricated field or minimum-version reduction; unrelated fields preserved; failed/stale operation emits no success; after-commit cancellation reports the saved local result and offers explicit removal. |
| E24-P09 · INT-04.E24.09 | queued and signing requests with injected pre-sign/pre-response barriers | lock/delete/replace/cancel at each barrier, then unlock | No post-revocation response; old callback cannot act on new generation; buffers wiped and own UI cleared; already-delivered response is recorded as external custody. |
| E24-P10 · INT-04.E24.10 | oversize envelope, 5/17 queued operations, malformed fields and expired queued request | submit while one UI is open | Caps enforced before expensive work, exactly one UI; expired/full requests fail once; healthy request remains responsive; no secret in error. |
| E24-P11 · INT-04.E24.11 | one valid callback followed by duplicate and late callback; instrumentation of screen/OS result | complete then lock | Exactly one completion; OS result has no private bytes; own view data cleared, foreign retention measured separately; no capture/wipe guarantee inferred from object release. |
| E24-P12 · INT-04.E24.12 | eligible demo passkeys and a plain CXF JSON file | request protected export/import and inspect profile metadata | Protected exchange records version/transport; readable JSON is rejected as unprotected exchange; draft status stays explicit; successful migration remains required. |
| E24-P13 · INT-04.E24.13 | 26+ valid OS token, replay, missing token, wrong type and wrong-recipient token; numeric exchange-version element instead of the required string; macOS 14/15 | validate configuration and begin import/export | Only a string-version valid configuration and valid one-use OS handoff proceed; a numeric version and all invalid variants save nothing; older OS shows Requires macOS 26 or later without preparing private data. |
| E24-P14 · INT-04.E24.14 | three passkeys, one unselected; user selects provider A then OS target changes to B | confirm, change target or cancel | Only exact reviewed selection can transfer to A; changed target/selection requires new review/verification; cancel leaves vault and source unchanged. |
| E24-P15 · INT-04.E24.15 | demo credential with binary ID/handle, display name unlike username and supported extension data | export/import then request assertion | Same public key, RP, ID, handle, display name and supported extension behavior survive; no invented account or RP; unsupported state is enumerated separately from completed items. |
| E24-P16 · INT-04.E24.16 | authenticated payload with malformed DER, excessive nesting/count/size, unknown version and mixed valid/broken selected passkeys | import after review | Each hostile batch refuses atomically before vault save; original bytes unchanged; no fetch/path side effect; fixed error contains no embedded payload or secret. |
| E24-P17 · INT-04.E24.17 | exact duplicate, conflicting key, second valid account key and simultaneous edit | review/import | Duplicate skipped without history churn; conflict writes nothing; distinct key added only with reviewed count; concurrent edit invalidates consent. |
| E24-P18 · INT-04.E24.18 | demo exchanged passkey with counter zero; persistence failure and successful save | import then authenticate via E7 and native demo relying app | Both supported assertions verify with original public key; failure publishes no identity/success; existing source copy is retained and disclosed. |
| E24-P19 · INT-04.E24.19 | eligible keys plus nonzero-counter and non-exportable demo items; recipient cancels | export selected set | Review names every exclusion; eligible passkey arrives unchanged and signs in at receiver; source stays; rejection produces no completed-migration claim. |
| E24-P20 · INT-04.E24.20 | instrument every Rust/FFI/controller/OS buffer, cancellation and allocation failure with demo markers | perform a supported exchange | A supported successful path proves no unauthorized plaintext custody and wipes owned copies; if the API requires forbidden copies the test is unresolved/FAIL, never waived by unsupported UI. |
| E24-P21 · INT-04.E24.21 | cancel/lock before handoff, during OS call and after recipient acknowledgement; late callback | run boundary-controlled exchange | Pre-handoff receives nothing; later callbacks do not save/sign after revocation; UI accurately says result unknown or delivered; logs/server store contain no private key or password verifier. |
| E24-P22 · INT-04.E24.22 | passkey plus password/code and earlier history, across all four surfaces | remove only passkey, cancel or lock during save | Cancel preserves all data; success leaves password/code, hides credential everywhere after refreshed save, revokes active handles; history/recipient retention is disclosed and no site revocation claimed. |
| E24-P23 · INT-04.E24.23 | CLI and web generic reveal/export paths; metadata list/show; cancel remove and noninteractive remove without --yes | request passkey/private data | Metadata succeeds while unlocked; forbidden paths return fixed refusal, not private bytes; noninteractive removal requires explicit acknowledgement; existing historical cases remain labelled historical scope. |
| E24-P24 · INT-04.E24.24 | every new frame in both themes, long account/RP, keyboard-only and VoiceOver user | complete/cancel/list/remove; increase text size and Reduce Motion | No clipped action or ambiguous name, visible focus, semantic status/errors, no color-only meaning; no private key in accessibility tree/screenshot; actual native accessibility/capture proof remains OPEN. |
| E24-P25 · INT-04.E24.25 | wrong RP, locked vault, full queue, stale token, malformed payload and post-handoff cancellation | surface each outcome | Correct fixed state/action and one matching OS completion; no key/handle/credential payload in error/log; no error shown as successful sign-in/import. |
| E24-P26 · INT-04.E24.26 | old-card proofs and new static frame screenshots only | assess E24-S1 and downstream acceptance | Report distinguishes draft/static evidence from unrun runtime checks, leaves status/board/parity untouched and requests fresh second Spec then independent Verify. |

### E24 frame links

Coverage, including rules with no standalone screen, is in [research frame coverage](../research/passkeys-and-ssh.md#frame-coverage). Proposed [provider](../../design/option-a/proposals.html#e24-s1-provider), [exchange review](../../design/option-a/proposals.html#e24-s1-exchange-review) and [passkey management](../../design/option-a/proposals.html#e24-s1-passkeys) are layout/state illustrations only. All native/transport/secret wiping/capture/signed OS proof remains OPEN.


## E24-S1 review and adoption record

2026-11-05: the exact revised specification and static proposals received fresh second Spec and independent Verify APPROVE, with R1–R4/N1 closed. The sealed pre-adoption complete source manifest is `8e0f22f647e509c5263995837624f57a5b2f6fb136a8b7f8c28c87ae54a1f4a1`; second Spec seal `5d3c7d944de41b109064b0d3cf51ec8b10c68825dc6c89a8962c48e762a91091`; Verify seal `f345bd00ee81226d2219d17909092c3b686d2be29850231feeb380e19c6d0dc2`. Proof covers56 rule/case/source pairs,112 fresh removal controls,80 themed source-bound PNGs plus2 accepted long captures and129 older frames/rectangles preserved per theme. Verify corrected contact-sheet accounting without changing the images or earlier proof. The full canonical frozen-source guard passed11604 scanned files plus19 vault names; actual-current adoption guard remains Root's separate requirement.

The DRAFT/unadopted status labels in the sealed appendices describe their pre-adoption state. This record and LD-380–396 adopt their written contracts only and explicitly supersede the listed legacy clauses for E24 implementation; historical rules/cases/proof keep their old scope. AT-KEY-01–18 and KEY-P1–7 are final catalog IDs with all runtime proof OPEN/todo. All17 acceptance conflicts remain visible in those rulings and their implementing gates; no successful capability is waived. G01–G05, Apple receiver identity, private Data/copy/transport custody, provisioned signing, signer backends, peer identity, descriptor feasibility and every implementing positive/hostile/removal/native/AX/capture obligation remain OPEN. Static evidence proves no running provider, exchange, generation, signing or secure custody. Detector/storage/bootstrap findings remain recorded externally. Original187-story scope, E24 Order and all S2–S7 acceptance/status lines are unchanged. Root closes only S1 after selective current-source equality, actual-current canonical guard and its owner-only commit; no implementation or runtime PASS follows.
