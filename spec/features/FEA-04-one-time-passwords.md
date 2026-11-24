# FEA-04 One-time passwords: storage forms and codes

Status: reviewed
Epics: E4-S10 (screens: E5-S4 live codes, E5-S5 editor; browser fill: E7-S4)
Parity rows: SF-09, SR-07, SC-01, SC-02, SC-03, SC-04 (option to hide one-time codes), SC-05

## What it does

An entry can hold a time-based one-time password (TOTP, RFC 6238) secret. Larsal reads the secret and its settings from the entry's string fields, computes the current code, shows how many seconds it stays valid, shows the settings as a QR code, and writes new settings from a setup screen.

The settings are never stored on their own. They are derived from the entry's string fields every time a field changes (FEA-04.2), so a file written by any tool works.

This card owns: the four storage forms and which one wins, parsing, Base32 secrets, code computation, display, the write rule, the setup screen, the QR screen and the actions that use codes. Other cards own: the field names in the file and their protected flags (FMT-14.22, FMT-11), the `{TOTP}` placeholder engine (MOD-08), history on change (MOD-03), clipboard rules (APP-03), Auto-Type timing (INT-05), browser fill (INT-01), the command line (INT-10), import and export conversions (FEA-08, FEA-09), search `has:totp` (FEA-01), the statistics count (FEA-07), merge comparison (MOD-11).

Words used here:
- **Form U**: the `otpauth://` URI form, usually in the field `otp`.
- **Form K**: the key-query form `key=…&size=…&step=…`, written by an older plug-in of another app, in `otp`.
- **Form L**: the legacy pair `TOTP Seed` (secret) plus `TOTP Settings` (`period;digits`).
- **Form T**: another app's four fields `TimeOtp-Secret-Base32`, `TimeOtp-Algorithm`, `TimeOtp-Length`, `TimeOtp-Period` (read only).
- **Settings**: secret text, digits, period (seconds), algorithm (SHA-1, SHA-256, SHA-512), encoder (decimal or Steam), form.
- **V**: the 31-bit number from RFC 4226 dynamic truncation.
- "2.7.11" is the installed reference version; "source" is the newer reference source.

## Inputs and outputs

| In | Type and limits |
|---|---|
| Entry string fields | `otp`, `TOTP Seed`, `TOTP Settings`, `TimeOtp-*` (FMT-14.22); text, size bounded by FMT limits |
| Time | Unix seconds, UTC, from the system clock |
| Setup screen input | secret text; choice Standard, Steam or Custom; algorithm, time step 1 to 86400, code size 6 to 10 |

| Out | Type |
|---|---|
| Settings | none, or settings that are valid, or settings with an error kind: invalid key, invalid step, invalid digits |
| Code | text of `digits` characters, decimal digits or Steam letters |
| Seconds left | integer 1 to period |
| URI | text (form U), for the QR screen, copy and CSV export |
| Fields to write | the field changes of FEA-04.16 |

Builder note: the code function takes the time as an argument. Time 0 is a real time (counter 0), not "now". The reference uses 0 to mean "now"; Larsal must not copy that.

## Rules

FEA-04.1 **Which form wins.** A field is "present" when its key exists, whatever its value (empty counts). Larsal checks in this order and stops at the first match:

| Step | Condition | Result |
|---|---|---|
| 1 | `TOTP Settings` present | Parse its value as settings text (FEA-04.3) with the value of `TOTP Seed` (empty if absent) as fallback secret. If that gives none, the entry has no one-time password; later steps are not tried |
| 2 | `otp` present | Parse its value as settings text with an empty fallback secret |
| 3 | `TimeOtp-Secret-Base32` present | Form T (FEA-04.7) |
| 4 | otherwise | none |

So `TOTP Seed` alone gives none, an empty `TOTP Settings` hides a valid `otp`, and `otp` beats form T. Observed with 2.7.11 for every row (test case 04-22).

FEA-04.2 **Derived, never stored.** The settings are recomputed whenever any string field of the entry is added, changed or removed. Larsal keeps no other copy in the file.

FEA-04.3 **Settings text.** Start from the defaults (FEA-04.8) and the fallback secret. If the text and the fallback secret are both empty, the result is none. Otherwise try these forms in order:

(a) **Form U.** The text is a URI whose scheme is `otpauth`, compared without case (`OTPAUTH://` works). Nothing is trimmed: a leading space makes it not a URI (observed: none). The query is the part after the first `?` up to `#` or the end; no `?` means an empty query. Query items are `name=value` pairs split on `&`. Names are exact and case-sensitive (`SECRET=` is not `secret`). The first item with a name wins. Values are percent-decoded by FEA-04.5.

| Item | Effect |
|---|---|
| `secret` | secret text; a missing item gives an empty secret (no fallback in form U) |
| `digits` | number (FEA-04.4) |
| `period` | number (FEA-04.4) |
| `encoder` | FEA-04.6 |
| `algorithm` | FEA-04.6 |

Everything else is ignored: the type after `otpauth://` (`totp`, `hotp`, anything), the label, `issuer`, `counter`, unknown items (lead decision D-04-3 for `hotp`).

(b) **Form K.** Else read the whole text as a query (split on `&`, then on the first `=`, decoded by FEA-04.5). If an item named `key` exists: secret = its value; `size` gives digits, `step` gives period, `otpHashMode` gives the algorithm (FEA-04.6). Encoder is decimal.

(c) **Form L.** Else, if the fallback secret is empty, the result is none. Otherwise secret = fallback secret and the text is split on `;`:
- fewer than 2 parts: defaults (so an empty `TOTP Settings` with a seed gives 30 seconds, 6 digits);
- part 2 is exactly `S` (uppercase only): Steam encoder, 5 digits; the period stays 30 and part 1 is ignored (`60;S` gives 30 seconds);
- otherwise: period = number(part 1), digits = number(part 2). Parts after the second are ignored.

Then, for (a), (b) and (c): digits are clamped to 1..10 and the period to 1..86400. So `digits=0` gives 1 digit, `digits=12` gives 10, `period=0` gives 1, `period=90000` gives 86400.

FEA-04.4 **Numbers.** A number is a decimal unsigned 32-bit value. Spaces before and after and one leading `+` are allowed. Anything else gives 0: empty text, a minus sign, letters (`8abc`), hex, overflow above 4294967295. Observed: ` 8`, `+8` and `%208` give 8; `-3` and `abc` give 0.

FEA-04.5 **Percent-decoding (forms U and K).** Each `%XX` (hex digits, any case) becomes its byte, except `%25` and `%2B`, which stay as the three literal characters. `+` stays `+` (not a space). Bytes are read as UTF-8. Observed with 2.7.11: `%3D`, `%20`, `%26`, `%23`, `%38` and `%C3%A9` are decoded; `%2B` and `%25` are not (in a secret, their `2`, `B` and `5` survive cleaning and change the key). Escapes of control characters, observed by Verify in Sprint 3 with the installed command line tool: the reference keeps `%00` to `%1F` and `%7F` as the three literal characters, like `%25` and `%2B`, so FEA-04.9's cleaning turns their digits into key characters (`%00` adds `OO`, `%1F` adds `LF`, `%7F` adds `7F`, `%0A` adds `OA`; `%09` adds `O` and drops `9`, which leaves a length that cannot be decoded, invalid key). Larsal decodes them to their bytes, which the cleaning drops, so such a secret gives a different key in Larsal: a difference for the lead to rule on. Larsal (LD-128): a secret that holds a control character after decoding (an escape from `%00` to `%1F`, or `%7F`) is invalid, so there is no code; the reference keeps such escapes as text.

FEA-04.6 **Algorithm and encoder names.** Algorithm, compared without case: `SHA512` or `HMAC-SHA-512` gives SHA-512; `SHA256` or `HMAC-SHA-256` gives SHA-256; anything else gives SHA-1, including `SHA-256` with one hyphen, `SHA1` and empty (observed). Encoder: exactly `steam` (case-sensitive) gives Steam; anything else gives decimal (`STEAM` and `S` give decimal, observed). In form U the encoder does not change the digits: `encoder=steam` without `digits` gives 6 Steam characters (observed).

FEA-04.7 **Form T.** If `TimeOtp-Secret-Base32` is empty, the result is none. Otherwise start from the defaults with that secret, then for each of `TimeOtp-Algorithm` (FEA-04.6), `TimeOtp-Length` (digits, FEA-04.4) and `TimeOtp-Period` (period, FEA-04.4): a non-empty value replaces the default. The reference does not clamp these: 0 gives the invalid digits or invalid step state, and large values are used as they are (`TimeOtp-Length` = `12` gave a 12-character code, observed). Larsal: lead decision D-04-8. Larsal reads form T but never writes, converts or removes it on its own (FMT-14.22), except as D-04-7 says.

FEA-04.8 **Defaults.** SHA-1, 6 digits, period 30, decimal encoder, form U. Steam always means 5 characters when chosen in the setup screen or by `;S`.

FEA-04.9 **Base32 secret.** Turn the secret text into key bytes in two steps.
1. *Clean.* Go through the characters: `0` becomes `O`, `1` becomes `L`, `8` becomes `B`; `A`–`Z`, `a`–`z` and `2`–`7` stay; every other character is dropped (spaces, `-`, `=`, `9`, `+`, `;`, any non-ASCII character). Then look at the length modulo 8: 0 stays; 2, 4, 5 or 7 get `=` padding up to a multiple of 8; 1, 3 or 6 cannot be decoded (invalid key).
2. *Decode.* RFC 4648 Base32, letters in any case. Bits left over in the last group are ignored, not checked: `GEZDGNBVGY3TQOJ` and `GEZDGNBVGY3TQOK` give the same 9 bytes (observed). Builder note: the `data-encoding` crate checks trailing bits by default; turn that check off.

An empty cleaned secret gives empty key bytes (FEA-04.10).

FEA-04.10 **Validity.** Checked in this order before a code is made:

| Error kind | When | State text (paraphrase, our ID) |
|---|---|---|
| invalid key | the secret cannot be decoded (FEA-04.9); in Larsal also when the key bytes are empty (D-04-1) | `MSG-OTP-INVALID-KEY` "Invalid key" |
| invalid step | period is 0 (only form T can give this) | `MSG-OTP-INVALID-STEP` "Invalid step" |
| invalid digits | digits is 0 (only form T can give this) | `MSG-OTP-INVALID-DIGITS` "Invalid digits" |

What the reference does with an empty secret: 2.7.11 makes a code with an empty HMAC key (observed: `otpauth://totp/x?issuer=y`, `key=` and `otpauth:secret=X` all give the empty-key code). From reading the source, the newer build does the same for every undecodable secret, so it would never show "invalid key": check with Verify. Larsal shows invalid key for both (D-04-1).

FEA-04.11 **Code: the number V.** RFC 6238 with T0 = 0 and step X = period:
1. counter = floor(unix seconds / period), as 8 bytes big-endian;
2. H = HMAC (SHA-1, SHA-256 or SHA-512 per settings) with the key bytes as key and the counter as message;
3. offset = low 4 bits of the last byte of H (for all three hashes, as RFC 6238 does);
4. V = the 4 bytes of H at offset, big-endian, with the top bit cleared (31 bits).

FEA-04.12 **Decimal code.** Code = V mod 10^digits, written in decimal and padded on the left with `0` to exactly `digits` characters. Compute in 64 bits: for 10 or more digits the code is V itself, padded (`digits=12` gives `001094287082` at time 59 with the RFC secret, observed with form T).

FEA-04.13 **Steam code.** Alphabet of 26 characters: `23456789BCDFGHJKMNPQRTVWXY`. For i = 0 to digits − 1: character i (counted from the left) = alphabet[(V div 26^i) mod 26]. So the least significant symbol comes first. Compute in 64 bits. With digits other than 5 (form U `digits=`), use that count (observed: 6 and 10 characters).

FEA-04.14 **Seconds left.** R = period − (unix seconds mod period). R runs from period down to 1; the code changes when R goes from 1 back to period. Every place that shows a countdown uses this R and refreshes at least once a second. (The reference's code window shows R + 1, and 1 at the exact period start; its entry preview shows R. Larsal uses R everywhere: D-04-10.)

FEA-04.15 **Showing a code.** The shown code gets one space after the first floor(length / 2) characters: `123 456`, `1234 5678`, `PV 9M4`, `123 4567`, `10942 87082`. The space is only for the screen: copy, type, browser fill and placeholders never include it. An entry with settings in an error state shows its state text (FEA-04.10), no countdown, and its copy actions do nothing (D-04-4).

FEA-04.16 **Which form the setup screen writes.** On Save in the setup screen (FEA-04.22), with S = the existing settings:

| Existing | Choice | Form written |
|---|---|---|
| none | any | U |
| form U or form T | any | U |
| form K | Standard or Custom | K (Steam: D-04-6) |
| form L | Standard or Steam | L |
| form L | Custom | U (the legacy pair cannot hold an algorithm) |

Field changes:
- Always first remove `otp`, `TOTP Seed` and `TOTP Settings`.
- Form U or K: set `otp` = the text of FEA-04.17 or FEA-04.18, protected.
- Form L: set `TOTP Seed` = the secret as stored by the setup screen (FEA-04.22), protected; set `TOTP Settings` = FEA-04.19, not protected.
- The reference leaves form T fields alone (D-04-7).

After the write, FEA-04.2 derives the settings from the new fields again, so the written text must give back the same settings. The whole Save is one change of the entry; MOD-03 decides the history item (the reference adds one per Save).

FEA-04.17 **Form U text.** Exactly:

`otpauth://totp/` L `:` N `?secret=` K `&period=` P `&digits=` D `&issuer=` L

then `&encoder=steam` if the encoder is Steam, then `&algorithm=SHA256` or `&algorithm=SHA512` if the algorithm is not SHA-1. Where:
- L = the entry title with placeholders resolved (MOD-08), percent-encoded; if empty, the product name. The reference writes its own name, `4B 65 65 50 61 73 73 58 43` (stored encoded, name rule); Larsal writes `Larsal` (D-04-2).
- N = the username with placeholders resolved, percent-encoded; if empty, `none`.
- Percent-encoding: the UTF-8 bytes; every byte except `A`–`Z`, `a`–`z`, `0`–`9`, `-`, `.`, `_`, `~` becomes `%` plus two uppercase hex digits. So `:` is `%3A`, space `%20`, `@` `%40`.
- K = the cleaned and padded secret of FEA-04.9 step 1, percent-encoded (each `=` becomes `%3D`).
- P and D = period and digits in decimal.

FEA-04.18 **Form K text.** `key=` K `&size=` D `&step=` P, then `&otpHashMode=SHA256` or `&otpHashMode=SHA512` if not SHA-1. K is cleaned and padded (FEA-04.9 step 1) and not percent-encoded. The Steam encoder cannot be stored in this form.

FEA-04.19 **Form L text.** `TOTP Settings` = P `;S` for Steam, otherwise P `;` D.

FEA-04.20 **Remove.** Removing the one-time password removes `otp`, `TOTP Seed` and `TOTP Settings`, and every field whose name starts with `TimeOtp-` (D-04-7 option (b), widened by LD-125). It is one change of the entry (MOD-03).

FEA-04.21 **Non-default settings.** Settings are "custom" when digits ≠ 6, or period ≠ 30, or the algorithm is not SHA-1. Steam settings are custom (5 digits). Used by FEA-04.22 and FEA-04.23.

FEA-04.22 **Setup screen** (`ACT-OTP-SETUP`, our ID; title "Set up one-time password").

| Control | Values | Default |
|---|---|---|
| Secret key | text; tooltip says Base32 | the current secret with every `=` removed, or empty |
| Choice | `OTP-CHOICE-STANDARD` "Standard (RFC 6238)", with the note "30 seconds, 6 digits, SHA-1"; Steam (5 characters, 30 seconds, SHA-1); Custom | Standard |
| Algorithm (Custom only) | SHA-1, SHA-256, SHA-512 | SHA-1 |
| Time step (Custom only) | 1 to 86400 seconds | 30 |
| Code size (Custom only) | 6 to 10 digits | 6 |

- The Custom controls are disabled unless Custom is chosen.
- Pre-fill from the current settings: the time step always; Steam if the encoder is Steam; else Custom with digits and algorithm if the settings are custom (FEA-04.21); else Standard. A banner `MSG-OTP-SETUP-INVALID` ("the secret key is invalid") shows at the top when the current settings are in an error state.
- On Save, the secret text is uppercased, every space and `=` is removed, and the ends are trimmed. The result must contain only `A`–`Z` and `2`–`7`. Otherwise the screen shows `MSG-OTP-BAD-SECRET` ("This secret key can't be used. It may hold only the letters A to Z and the digits 2 to 7, for example JBSWY3DPEHPK3PXP.") and stays open. The reference accepts a cleaned length of 1, 3 or 6 modulo 8 and only later shows invalid key; Larsal refuses it with the same message (D-04-5).
- Empty secret: if the entry has a one-time password, ask `MSG-OTP-CONFIRM-REMOVE` ("Remove the one-time password settings of this entry?", buttons Delete and Cancel, default Cancel); Delete removes it (FEA-04.20). If the entry has none, close with no change.
- Values used: Standard: 6, 30, SHA-1. Steam: 5, 30, SHA-1, Steam encoder. Custom: the three controls.
- The stored secret is the cleaned text (uppercase, no padding); FEA-04.17 and FEA-04.18 add the padding.
- Cancel and lock close the screen without change.

FEA-04.23 **QR screen** (`ACT-OTP-QR`, enabled when the entry has a one-time password).
- Content: the form U text of FEA-04.17, built from the current settings, always form U whatever the stored form. The reference uses the title and username here without resolving placeholders (unlike FEA-04.17 on Save). Larsal does the same.
- QR symbol: error correction level H, the smallest version that fits, byte mode, a quiet zone of 4 modules (source, re-read by Verify in Sprint 3: the encoder is called with error correction level High by default, automatic version, byte mode, and the picture is drawn with a margin of 4 modules).
- When the settings are custom or Steam: note `MSG-OTP-QR-CUSTOM` ("Not every authenticator app can use these settings. Check that its codes match before you rely on it.").
- If the text does not fit in a QR symbol: message `MSG-OTP-QR-ERROR` ("The QR code could not be made") and the screen closes.
- A Copy button (and Cmd+C) copies the URI text under APP-03 rules.
- Auto-close: a countdown `MSG-OTP-QR-CLOSING` ("N seconds until this window closes") shows 44 when the screen opens, goes down by one each second and closes the screen when it reaches 0. Lock also closes it.
- QR encoder crate: D-04-9.

FEA-04.24 **Actions and where codes appear.** IDs are ours; shortcuts are owned by APP-08 (the reference uses Cmd+T, Cmd+Y and Cmd+Shift+T on Mac).

| ID | Action | Enabled when | Does |
|---|---|---|---|
| `ACT-OTP-COPY` | Copy one-time code | one entry selected | valid settings: copy the code (APP-03). No valid settings: open the setup screen instead |
| `ACT-OTP-COPY-PW` | Copy password and code | one entry selected and it has settings | copy the password (placeholders resolved) directly followed by the code, no separator. Larsal: only with valid settings (D-04-4) |
| `ACT-OTP-SHOW` | Show code window | one entry selected and it has settings | window with the code (FEA-04.15), a progress bar for R (FEA-04.14), Copy button and Cmd+C. Closes on lock |
| `ACT-OTP-QR` | Show QR code | as above | FEA-04.23 |
| `ACT-OTP-SETUP` | Set up one-time password | one entry selected | FEA-04.22 |

Other places:
- Entry preview and detail: the live code and countdown. Hidden while the APP-01 setting "hide one-time code in the entry preview" (our ID `SET-OTP-HIDE-PREVIEW`, APP-01 S-CONV-04 `display.hide_totp_in_preview`, default off) is on; a toggle shows it. Double-click on the code copies it.
- Entry list: an indicator column with two looks, valid and invalid; sort key "has one-time password". Double-click on it copies a valid code, else opens the setup screen.
- Search `has:totp` matches entries with settings in any state (FEA-01). Statistics count entries with settings (FEA-07).
- Browser fill sends a code only when the settings are valid (INT-01).
- Auto-Type `{TOTP}` computes the code at the moment of typing, including the delays before it, and stops with an error when the settings are invalid (INT-05).
- CSV export writes the form U text of FEA-04.17 (with resolved title and username) whatever the stored form (FEA-09).

FEA-04.25 **Placeholder.** `{TOTP}` (any case) resolves to the current code without the space. No settings: empty text. Error state: the reference inserts the state text (observed: `x{TOTP}y` gives `xInvalid Keyy`); Larsal inserts empty text (D-04-4). The source also accepts `{TIMEOTP}` as the same placeholder; 2.7.11 leaves `{TIMEOTP}` as literal text (differs in installed version, observed). Larsal accepts both (D-04-11). MOD-08 owns the engine and nesting.

FEA-04.26 **Clock.** Codes use the system clock in UTC seconds. There is no time offset setting.

## Edge cases and errors

| Case | Result |
|---|---|
| `otp` = a bare secret such as `JBSWY3DPEHPK3PXP` | none (not form U, no `key`, no fallback). Observed |
| `otp` empty | none |
| `TOTP Seed` without `TOTP Settings` | none. Observed |
| `TOTP Settings` = `otpauth://…` or `key=…` | that form is read; the seed is ignored. Observed |
| `TOTP Settings` = `abc;def` with a seed | period 1, 1 digit (numbers give 0, then clamped). Observed |
| `TOTP Settings` = `60;s` (lowercase) | period 60, digits 1. Observed |
| `TOTP Settings` = `30;S;9` | Steam, 5 characters. Observed |
| Form U with two `secret` items | the first wins. Observed |
| Form U `otpauth:secret=X` (no `?`) | empty secret: reference makes the empty-key code; Larsal invalid key. Observed |
| Form U `otpauth://hotp/…&counter=5` | reference: read as TOTP, counter ignored (observed). Larsal: D-04-3 |
| Secret `GEZDGNBV=GY3TQOJQ`, `GEZDGNBV+GY3TQOJQ` or with `é` inside | the character is dropped: same key as `GEZDGNBVGY3TQOJQ`. Observed |
| Secret `ABC`, `GEZDGNBVG` (9) or `GEZDGN` (6) | invalid key. Observed |
| Secret with `9` | `9` dropped; the rest decides. Observed |
| Form T `TimeOtp-Length` = `0` / `TimeOtp-Period` = `0` or `abc` | invalid digits / invalid step. Observed |
| Form T `TimeOtp-Algorithm` = `SHA-256` | SHA-1 (one hyphen is not a known name). Observed |
| Form K with Steam chosen in setup | reference writes form K without the encoder; it reads back as 5 decimal digits. Larsal: D-04-6 |
| Existing digits outside 6..10 (for example 5 from form K, or 1) with Custom pre-filled | the reference's code size control cannot show it and shows its nearest limit; Save then writes that value. Larsal: D-04-12 |
| User removes the one-time password of an entry that also has form T fields | reference: `otp`, `TOTP Seed`, `TOTP Settings` go, form T stays, so the entry still has a one-time password. Larsal: D-04-7 |
| Placeholder `{TOTP}` in a field of an entry without settings | empty text |
| QR text too long | `MSG-OTP-QR-ERROR`, screen closes |
| Lock while the setup, code or QR screen is open | the screen closes; nothing is saved from the setup screen |

**Lead decisions** (open; until ruled, the default rule of spec/decisions.md applies: the recommended option):

| ID | Question | Options | Recommended |
|---|---|---|---|
| D-04-1 | Empty or undecodable secret | (a) compute with an empty HMAC key, as 2.7.11 does for empty and the source does for all; (b) invalid key | (b) |
| D-04-2 | Label and issuer when the title is empty | (a) the reference's own name; (b) `Larsal` (renamed with D1) | (b) |
| D-04-3 | Form U type other than `totp` | (a) ignore the type, as the reference; (b) `totp` or an empty type only; anything else is an error state "unsupported type" (our ID `MSG-OTP-UNSUPPORTED`), field kept | (b): a counter-based secret never gives a right code from the clock |
| D-04-4 | Settings in an error state, for `{TOTP}`, copy-with-password and preview double-click | (a) insert or copy the state text, as the reference; (b) empty text, no copy | (b) |
| D-04-5 | Setup screen secret whose cleaned length is 1, 3 or 6 modulo 8 | (a) accept, as the reference; (b) refuse with `MSG-OTP-BAD-SECRET` | (b) |
| D-04-6 | Steam chosen for an entry in form K | (a) write form K and lose Steam; (b) write form U | (b) |
| D-04-7 | Form T fields on setup Save or Remove | (a) leave them, as the reference (Remove then does not remove); (b) remove the four `TimeOtp-*` fields on Save and on Remove | (b): Remove must remove, and an old secret must not stay behind in a plain field |
| D-04-8 | Form T bounds | (a) unbounded, as the reference; (b) 0 stays invalid; digits above 10 become 10 and periods above 86400 become 86400 | (b) |
| D-04-9 | QR encoder | (a) add a QR crate after an AT-J03 review and a new line in the approved crate table; (b) write our own encoder (not crypto, so allowed) | (a) |
| D-04-10 | Countdown formula | one formula R everywhere (FEA-04.14) | as written |
| D-04-11 | `{TIMEOTP}` | (a) only `{TOTP}`, as 2.7.11; (b) both, as the source | (b) |
| D-04-12 | Existing digits outside the setup screen's 6..10 | (a) as the reference: the control shows its nearest limit and Save writes it; (b) keep the existing digits unless the user changes the code size | (b) |

## Security notes

- The secret is a credential. `otp` and `TOTP Seed` are written protected (FMT-14.22, SF-09). In memory the secret, the decoded key bytes and the form U text live in secret types and are wiped after use (SR-07, AT-C01, AT-C02). They never go to logs, error text or the screen layer, except the QR picture and URI the user asked for.
- The QR screen and its Copy button reveal the secret. The screen closes itself after 44 seconds and on lock; window capture protection applies (SC-05, AT-D04). Copying the URI follows the clipboard rules: concealed, cleared after the timeout and on lock (SC-01 to SC-03, AT-D01 to AT-D03).
- A code is short-lived but still a credential: copies follow the same clipboard rules.
- Never compute a code from an empty or broken secret and show it as real (D-04-1): a wrong code that looks valid leads users to lock themselves out.
- Hostile text in `otp` must not crash or hang: parsing is bounded by the field size, numbers are bounded by FEA-04.4 and FEA-04.3, and form T values must be bounded before any allocation (the reference allocates a code of `TimeOtp-Length` characters, up to about 4 billion). Fuzz target `totp_link` (architecture, AT-A10).
- Title and username in the label are percent-encoded; on screen every value is set as text (AT-E01).
- Auto-Type of `{TOTP}` must stop on invalid settings rather than type state text (INT-05, AT-G03).

## Test cases

Secrets used: R = `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` (ASCII `12345678901234567890`, the RFC SHA-1 seed); R32 = `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====` (the RFC SHA-256 seed, 32 bytes); R64 = the Base32 of the RFC SHA-512 seed (`1234567890` six times then `1234`, 64 bytes), which is `GEZDGNBVGY3TQOJQ` repeated 6 times, then `GEZDGNA=`; J = `JBSWY3DPEHPK3PXP` (the rich-v4 demo entry, `otp` = `otpauth://totp/Demo:demo-user?secret=JBSWY3DPEHPK3PXP`). Values computed with python3 from RFC 6238 and RFC 4226; the "observed" rows were run with 2.7.11 on demo vaults (`show -t`), compared with the same computation at the same second.

| Case | Given | When | Then |
|---|---|---|---|
| 04-01 RFC 6238 SHA-1 | form U `otpauth://totp/a:b?secret=R&digits=8` | codes at 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000 | `94287082`, `07081804`, `14050471`, `89005924`, `69279037`, `65353130`. FEA-04.11, 04.12 |
| 04-02 RFC 6238 SHA-256 | secret R32, SHA-256, 8 digits | same times | `46119246`, `68084774`, `67062674`, `91819424`, `90698825`, `77737706`. FEA-04.11 |
| 04-03 RFC 6238 SHA-512 | secret R64, SHA-512, 8 digits | same times | `90693936`, `25091201`, `99943326`, `93441116`, `38618901`, `47863826`. FEA-04.11 |
| 04-04 RFC 4226 via counter | secret R, defaults | codes at 0, 30, 60, … 270 (counters 0 to 9) | `755224`, `287082`, `359152`, `969429`, `338314`, `254676`, `287922`, `162583`, `399871`, `520489`. Time 0 is counter 0, not "now". FEA-04.11 |
| 04-05 default 6 digits | form U `otpauth://totp/Demo:alice?secret=R&period=30&digits=6&issuer=Demo` | codes at 59 and 1234567890 | `287082`, `005924`. Observed 2.7.11 match. FEA-04.1, 04.3, 04.12 |
| 04-06 demo vault | rich-v4 "Full demo entry" (J) | codes at 59, 1700000000, 1700000009, 1700000010 | `996554`, `324550`, `324550`, `367665`. FEA-04.3, 04.11 |
| 04-07 seconds left | period 30 | R at 1700000000, 1700000009, 1700000010, 1700000039 | 10, 1, 30, 1. FEA-04.14 |
| 04-08 Steam | form U `…?secret=R&encoder=steam&digits=5` | codes at 59, 1111111109, 1234567890, 2000000000 | `PV9M4`, `PY4YB`, `VHHQY`, `9N776`. Observed 2.7.11 match for the 5-character form. FEA-04.6, 04.13 |
| 04-09 Steam without digits | form U `…?secret=R&encoder=steam` | code at 59 | `PV9M4J` (6 characters). Observed. FEA-04.6, 04.13 |
| 04-10 Steam legacy | `TOTP Seed` = R, `TOTP Settings` = `60;S` | settings; code at 59 | Steam, 5 characters, period 30 (not 60): `PV9M4`. Observed. FEA-04.3 (c) |
| 04-11 encoder name case | form U `…&encoder=STEAM&digits=5`; second entry `…&encoder=S` | code at 59 | `87082` (decimal, 5 digits); second entry `287082`. Observed. FEA-04.6 |
| 04-12 algorithm names | form U with `algorithm=` `sha256`; `SHA-256`; `HmAc-ShA-512`; `SHA1` (secret R, 8 digits) | code at 59 | `32247374` (SHA-256); `94287082` (SHA-1); `69342147` (SHA-512); `94287082`. Observed for the first three. FEA-04.6 |
| 04-13 clamps | form U secret R with `digits=0`; `digits=12`; `digits=10`; `period=0`; `period=90000` | code at 59 | `2` (1 digit); `1094287082`; `1094287082`; `083773` (period 1); `755224` (period 86400). Observed. FEA-04.3, 04.12 |
| 04-14 numbers | form U secret R with `digits=8abc`; `digits=-3`; `digits=+8`; `digits=%208`; `period=abc` | settings | digits 1; 1; 8; 8; period 1. Observed. FEA-04.4 |
| 04-15 scheme case, no trim | `otp` = `OTPAUTH://totp/Demo:alice?secret=R`; second entry `otp` = ` otpauth://totp/Demo:alice?secret=R` (leading space) | settings | first: defaults, code at 59 `287082`; second: none. Observed. FEA-04.3 (a) |
| 04-16 names case-sensitive | `otp` = `otpauth://totp/Demo:alice?SECRET=R` | settings | form U with an empty secret: Larsal invalid key; 2.7.11 shows the empty-key code (`812658` at 59). Observed. FEA-04.3, 04.10 |
| 04-17 form K | `otp` = `key=R&size=8&step=60&otpHashMode=Sha256` | code at 59 and 1111111109 | `74875740`, `69648066`. Observed match. FEA-04.3 (b), 04.6 |
| 04-18 form K decoding | `otp` = `key=GEZDGNBVGY3TQOJQ%3d&size=6` | settings | key text `GEZDGNBVGY3TQOJQ=`, 10 key bytes; code at 59 `263420`. Observed. FEA-04.3 (b), 04.5 |
| 04-19 form L | `TOTP Seed` = R, `TOTP Settings` = `30;8` | code at 59 | `94287082`. Observed. FEA-04.3 (c) |
| 04-20 form L spaces in seed | `TOTP Seed` = `gezd gnbv gy3t qojq gezd gnbv gy3t qojq`, `TOTP Settings` = `30;6` | code at 59 | `287082`. Observed. FEA-04.9 |
| 04-21 form L defaults | seed R with `TOTP Settings` = `30`; another with `TOTP Settings` empty | settings | both: 6 digits, 30 seconds. Observed. FEA-04.3 (c) |
| 04-22 precedence | entry A: `TOTP Settings` empty plus valid `otp`; B: `TOTP Seed` = R only; C: `otp` = `…secret=R&digits=8` plus `TimeOtp-Secret-Base32` = `AAAAAAAA`; D: `TOTP Seed` = `AAAAAAAA`, `TOTP Settings` = `otpauth://totp/Demo:alice?secret=R&digits=8` | settings | A none; B none; C the `otp` settings (8 digits, secret R); D secret R, 8 digits. Observed. FEA-04.1 |
| 04-23 form T | `TimeOtp-Secret-Base32` = R, `TimeOtp-Length` = `8`, `TimeOtp-Algorithm` = `HMAC-SHA-512` | code at 59 | `69342147`. Observed match. FEA-04.7 |
| 04-24 form T errors | form T secret R with `TimeOtp-Length` = `0`; another with `TimeOtp-Period` = `0`; another with `TimeOtp-Secret-Base32` empty | state | invalid digits; invalid step; none. Observed. FEA-04.7, 04.10 |
| 04-25 form T large | `TimeOtp-Secret-Base32` = R, `TimeOtp-Length` = `12` | code at 59 | reference `001094287082` (observed). Larsal: per D-04-8 (recommended: `1094287082`, clamped to 10). FEA-04.7, 04.12 |
| 04-26 Base32 cleaning | form U secrets `GEZDGNBVGY3TQ0J8` and `GEZDGNBVGY3TQOJB` | key bytes | equal (0 becomes O, 8 becomes B). Observed same code. FEA-04.9 |
| 04-27 Base32 trailing bits | secrets `GEZDGNBVGY3TQOJ` and `GEZDGNBVGY3TQOK` | key bytes | equal, 9 bytes; code at 59 `053248`. Observed same code. FEA-04.9 |
| 04-28 Base32 dropped characters | secret `GEZDGNBVGY3TQOJ9` | key | cleaned `GEZDGNBVGY3TQOJ=`, 9 bytes, code at 59 `053248`. Observed. FEA-04.9 |
| 04-29 Base32 invalid lengths | secrets `ABC`, `GEZDGNBVG`, `GEZDGN` | state | invalid key, all three. Observed. FEA-04.9, 04.10 |
| 04-30 percent rules | secrets `GEZDGNBV%3DGY3TQOJQ`, `GEZDGNBV%26GY3TQOJQ`, `GEZDGNBV%2BGY3TQOJQ`, `GEZDGNBV%25GY3TQOJQ` | key text after cleaning | `GEZDGNBVGY3TQOJQ`, `GEZDGNBVGY3TQOJQ`, `GEZDGNBV2BGY3TQOJQ` + padding, `GEZDGNBV25GY3TQOJQ` + padding. Observed by code. FEA-04.5 |
| 04-31 empty secret | `otp` = `otpauth://totp/x?issuer=y`; `otp` = `key=` | state | Larsal: invalid key, no code, copy actions do nothing. 2.7.11: shows a code from an empty HMAC key (`812658` at 59). FEA-04.10 |
| 04-32 write form U | new entry, title `Demo Site`, username `alice@example.com`, setup: secret `jbsw y3dp ehpk 3px`, Standard | Save | `otp` (protected) = `otpauth://totp/Demo%20Site:alice%40example.com?secret=JBSWY3DPEHPK3PX%3D&period=30&digits=6&issuer=Demo%20Site`; no `TOTP Seed`, no `TOTP Settings`. FEA-04.16, 04.17, 04.22 |
| 04-33 write form U custom | title `Bank`, username empty, setup: secret J, Custom SHA-256, 60 s, 8 digits | Save | `otp` = `otpauth://totp/Bank:none?secret=JBSWY3DPEHPK3PXP&period=60&digits=8&issuer=Bank&algorithm=SHA256`. FEA-04.17 |
| 04-34 write form U Steam, empty title | title empty, username `bob`, setup: secret J, Steam | Save | Larsal: `otp` = `otpauth://totp/Larsal:bob?secret=JBSWY3DPEHPK3PXP&period=30&digits=5&issuer=Larsal&encoder=steam`. The reference writes its own name in both places (D-04-2). FEA-04.17 |
| 04-35 write keeps form L | entry with `TOTP Seed` = J, `TOTP Settings` = `30;6`; setup: Steam | Save | `TOTP Seed` (protected) = `JBSWY3DPEHPK3PXP`, `TOTP Settings` (plain) = `30;S`; no `otp`. FEA-04.16, 04.19 |
| 04-36 legacy to URI on Custom | same entry; setup: Custom SHA-1, 30 s, 7 digits | Save | `TOTP Seed` and `TOTP Settings` removed; `otp` = `otpauth://totp/…?secret=JBSWY3DPEHPK3PXP&period=30&digits=7&issuer=…`. FEA-04.16 |
| 04-37 write keeps form K | entry `otp` = `key=JBSWY3DPEHPK3PXP&size=6&step=30`; setup: Custom SHA-512, 30 s, 6 digits | Save | `otp` = `key=JBSWY3DPEHPK3PXP&size=6&step=30&otpHashMode=SHA512`. FEA-04.18 |
| 04-38 round trip | each text written in 04-32 to 04-37 | read back by FEA-04.1 | the same settings that were saved. FEA-04.16, 04.20 |
| 04-39 setup rejects | setup secret `JBSWY3DP-EHPK3PXP`; `JBSWY3DPEHPK3PX1`; `ABC` | Save | `MSG-OTP-BAD-SECRET`, screen stays open, entry unchanged (the third only in Larsal, D-04-5). FEA-04.22 |
| 04-40 setup remove | entry with form U settings; setup secret emptied | Save, then Delete | `otp`, `TOTP Seed`, `TOTP Settings` gone; entry has no one-time password; one history item (MOD-03). With Cancel: unchanged. FEA-04.20, 04.22 |
| 04-41 setup pre-fill | entry `otp` = `otpauth://totp/a:b?secret=JBSWY3DPEHPK3PXP%3D%3D&period=45&digits=8` | open setup | secret field `JBSWY3DPEHPK3PXP`; Custom chosen; time step 45; code size 8; algorithm SHA-1. FEA-04.21, 04.22 |
| 04-42 display | codes `287082`, `94287082`, `PV9M4`, `1094287082` | shown | `287 082`, `9428 7082`, `PV 9M4`, `10942 87082`; copy gives the code without the space. FEA-04.15 |
| 04-43 QR content | entry title `{USERNAME} site` (a placeholder), username `alice`, form L `TOTP Seed` = J, `TOTP Settings` = `30;6` | open QR screen | QR encodes `otpauth://totp/%7BUSERNAME%7D%20site:alice?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=%7BUSERNAME%7D%20site` (unresolved title); no custom note; countdown shows 44. FEA-04.23 |
| 04-44 QR custom note and close | entry with Steam settings | open QR screen; wait | custom note shown; screen closes 44 seconds after opening; locking earlier closes it at once. FEA-04.23 |
| 04-45 copy actions | entry A valid (secret R, at time 59), password `pw`; entry B with `otp` = `otpauth://totp/x?secret=ABC`; entry C without settings | `ACT-OTP-COPY` and `ACT-OTP-COPY-PW` on each | A: `287082`, then `pw287082`. B: copy opens the setup screen; copy-with-password does nothing (Larsal). C: copy opens the setup screen; copy-with-password disabled. FEA-04.24 |
| 04-46 placeholder | A: secret R, password `a{TOTP}b\|{totp}\|{TIMEOTP}`; B: secret `ABC`, password `x{TOTP}y`; C: no settings, password `x{TOTP}y` | resolve the password at time 59 | Larsal: A `a287082b\|287082\|287082`; B `xy`; C `xy`. 2.7.11 (observed): A ends in the literal `{TIMEOTP}`; B `xInvalid Keyy`. FEA-04.25 |
| 04-47 hotp URI | `otp` = `otpauth://hotp/Demo:alice?secret=R&counter=5` | settings | reference: TOTP code as in 04-05 (observed). Larsal: per D-04-3 (recommended: invalid, state "unsupported type"). FEA-04.3 |
| 04-48 derived on change | entry `otp` = `…secret=R`; then the field is edited to `…secret=R&digits=8` without the setup screen | settings | 8 digits right after the edit. FEA-04.2 |
| 04-49 defaults | `otp` = `otpauth://totp/a:b?secret=R` | settings; code at 59 | SHA-1, 6 digits, period 30, decimal, form U; `287082`. FEA-04.8 |
| 04-50 clock in UTC | secret R, defaults; system clock at 1234567890 (2009-02-13 23:31:30 UTC); Mac time zone set to UTC+2, then UTC−8 | code | `005924` in both time zones. FEA-04.26 |

## How this was learned

- Read the reference's one-time password core (forms, parsing, writing, code computation, encoders), its Base32 routines, the entry's one-time password functions (precedence, write and remove), the setup screen and its screen definition (choices, ranges, secret check, confirm text), the code window, the QR screen and the QR helper (error correction, quiet zone, auto-close), the entry preview, the entry list column, the main window's entry menu and shortcuts, the placeholder table, the Auto-Type placeholder handling, the browser credential reply, the CSV import and export and the JSON importers, and the reference's own tests for one-time passwords.
- Compared the installed version's sources with the newer source for the core and Base32 files (only the Base32 padding check and its return type changed; the newer source moved to a newer UI toolkit, which changes how an empty decoded key is treated: check with Verify).
- Ran the installed command line tool 2.7.11 (`import` of demo XML documents, then `show -t` and `show -s -a Password`) on about 80 demo entries in `/tmp/spec-fea04-06/`, demo password `demo`, and compared every code with an RFC 6238 computation in python3 at the same second.
- Not observed: the setup screen, the QR screen and the write forms (the command line tool cannot set up one-time passwords); these come from reading the source.
