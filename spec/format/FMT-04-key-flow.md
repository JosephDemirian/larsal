# FMT-04 Key flow: composite key and derived keys

Status: reviewed
Epics: E3-S3 (the hardware-key steps are used again by E10-S1)
Parity rows: SF-04, SF-02, SF-05, SF-07, SI-08, SR-07

## What it does

This card says how the user's credentials become the keys that open and save a vault file.

The flow has four stages:

1. **Components.** Each credential becomes a 32-byte value: the password component `P`, the key file component `F` (made by FMT-18), and, when a hardware key is used, a part `R` made from the hardware key's answer to a challenge.
2. **Composite key.** The components are joined in a fixed order and hashed with SHA-256 into one 32-byte composite key `C`.
3. **Transformed key.** The KDF (Argon2d, Argon2id or AES-KDF, settings from FMT-03, algorithms in CRY-02) turns `C` into the 32-byte transformed key `T`. This is the slow step.
4. **Final keys.** `T` is mixed with the file's 32-byte master seed `S`. Version 4 gets the cipher key `K_enc` and the HMAC base key `K_mac`. Version 3 gets only a cipher key `K_enc`.

The hardware key enters at a different place in each version:

- Version 4: the challenge is the KDF seed. The answer goes **into the composite key, before the KDF**.
- Version 3: the challenge is the master seed. The answer goes **into the final key, after the KDF**.

How a wrong key is found (header HMAC, start bytes) is in FMT-05. How the cipher key and the HMAC base key are used is in FMT-06, FMT-07 and FMT-08. Talking to the hardware key over USB or NFC is in INT-07.

## Inputs and outputs

Notation:

- `||` joins byte strings. Hex bytes are written in file order.
- `SHA256(x)` and `SHA512(x)` are the FIPS 180-4 hashes. `HMAC-SHA1` is RFC 2104 with SHA-1.
- `[x]` means "x, only when present". An absent part adds no bytes at all.
- `S`: the master seed, header field id 4, exactly 32 bytes (FMT-02).
- `KS`: the KDF seed. Version 4: the byte string stored in the KDF settings map (FMT-03) under the entry whose name is the single letter S (byte `53`), 8 to 32 bytes. App always writes a fresh 32-byte `KS` on every save (decided: spec/decisions.md LD-15; CRY-03.4). The reference writes 32 bytes for a new vault and when the KDF is changed; on a normal save it makes the new seed with the same length as the seed it read (FMT-03, CRY-03). It is the Argon2 salt or the AES-KDF seed. Version 3: the transform seed, header field id 5, exactly 32 bytes (FMT-17).

Inputs:

| Input | Type | Notes |
|---|---|---|
| Password text | Unicode text, optional | Exactly as typed or pasted. "No password" and "empty password" are different inputs (FMT-04.2). |
| Key file component `F` | 32 bytes, optional | Output of FMT-18. |
| Hardware key | one slot of one device, optional | Programmed for HMAC-SHA1 challenge-response. Gives a 20-byte answer (FMT-04.10). |
| File version, `S`, KDF id, `KS`, KDF settings | from the outer header | FMT-02, FMT-03, FMT-17. |

Outputs (every one is secret):

| Output | Size | Used by |
|---|---|---|
| Composite key `C` | 32 bytes | KDF input |
| Transformed key `T` | 32 bytes | final keys |
| Payload cipher key `K_enc`, version 4 (FMT-04.13) | 32 bytes | payload cipher (FMT-08, CRY-01) |
| HMAC base key `K_mac`, version 4 only (FMT-04.14) | 64 bytes | header HMAC (FMT-05) and block HMACs (FMT-06) |
| Payload cipher key `K_enc`, version 3 (FMT-04.15) | 32 bytes | payload cipher and start-bytes check (FMT-05, FMT-17) |

Key names, one per key, for every card: `K_enc` is the 32-byte payload cipher key of either version; FMT-05, FMT-08, FMT-17 and CRY-01 call it "the final key". `K_mac` is the 64-byte HMAC base key; FMT-05.4 and FMT-06 write it as `K`. These are the same values under other names. The 32-byte cipher key and the 64-byte HMAC base key are never the same value and are never swapped.

Outcomes: one of the outputs above, or one of the error kinds in FMT-04.21, or the "ask the user first" decision of CRY-02.14 (FMT-04.21).

## Rules

FMT-04.1 **Password component.** `P = SHA256(UTF-8 bytes of the password text)`. The text is used exactly as given: no Unicode normalization (NFC and NFD forms of the same word give different keys), no trimming of leading or trailing spaces or tabs, no case change, no removal of any character. Only the line end that ends a typed line on the command line is not part of the password.

FMT-04.2 **No password versus empty password.** "No password" means there is no `P` at all. "Empty password" means `P = SHA256(empty string) = e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855`. The two give different composite keys, so a vault made with one never opens with the other. App must let the user supply either one (APP-06 decides the screen flow). Reference behavior, for that card: the unlock screen treats an empty password field as "no password" and, after a failed unlock with an empty field, offers one retry with "empty password"; the command line tool adds `P` for whatever line is typed (an empty line gives the empty password) unless its no-password option is given; the command line create command asks for confirmation before making a vault with an empty password; the key settings screen treats an empty field as "no password" (after a warning).

FMT-04.3 **Key file component.** `F` is the 32-byte key that FMT-18 returns for the key file. It is used as it is; this card adds no hashing of its own.

FMT-04.4 **Order.** Components always go in this order: `P`, then `F`, then `R`. The order is fixed and is not stored in the file. Any other order gives a different composite key.

FMT-04.5 **Composite key, version 4.** `C = SHA256([P] || [F] || [R])`. `C` is always 32 bytes, even when only one component is present (it is hashed again, never used raw).

FMT-04.6 **Hardware-key part `R`.** With hardware keys, `R = SHA256(answer_1 || answer_2 || ...)`, the answers in the order the keys were added. With one hardware key, `R = SHA256(answer)`. Without a hardware key, `R` is absent: nothing is added, and in particular `SHA256(empty)` is **not** added. The reference's screens and command line add at most one hardware key; App supports one (parity), and the formula above is what any count would give.

FMT-04.7 **Composite key, version 3.** `C3 = SHA256([P] || [F])`. It never contains `R`, even when a hardware key is used; the hardware key enters later (FMT-04.15). Without a hardware key, `C3` equals the version 4 `C` for the same credentials.

FMT-04.8 **What the hardware key is asked.** Version 4: the challenge is `KS`, the KDF seed of the file being opened or written. Version 3: the challenge is `S`, the master seed.

FMT-04.9 **Challenge padding.** The challenge of `n` bytes (8 to 32) is padded to exactly 64 bytes before it is sent: append `64 - n` bytes, each with the value `64 - n`. A 32-byte challenge gets 32 bytes of `20`; a 16-byte challenge gets 48 bytes of `30`; an 8-byte challenge gets 56 bytes of `38`. All 64 bytes go to the device. What the device then hashes depends on how its slot is programmed (INT-07; see Edge cases).

FMT-04.10 **Hardware-key answer.** The device returns the 20-byte HMAC-SHA1 answer of the chosen slot (slot 1 or 2). App uses exactly 20 bytes. If the device is missing, times out, is not configured, or fails in any way, key derivation stops with the error kind `HardwareKey` (FMT-04.21) before the KDF runs. This error is not `WrongKey` (AT-H03). Reference order, for comparison: in version 4 it sends the challenge first, still runs the KDF after a failed challenge, and only then fails; when it opens a version 3 file it runs the KDF first and sends the challenge after. App stopping first is its own stricter choice; it changes no key and no message, only saves the KDF time. A different device or slot that answers is a wrong key, found by FMT-05 like a wrong password (AT-H04).

FMT-04.11 **KDF, version 4.** `T = KDF(C)`, with the KDF and its settings from the settings map (FMT-03) and the algorithms in CRY-02. Output: 32 bytes.
- Argon2d and Argon2id: password input = `C`, salt = `KS`, tag length 32, memory, iterations and lanes from the map, no secret key and no associated data. The reference ignores map entries `K` and `A` (FMT-03, CRY-02).
- AES-KDF: both AES-KDF ids, `c9d9f39a-628a-4460-bf74-0d08c18a4fea` and `7c02bb82-79a7-4ac0-927d-114a00648238`, are handled the same way in version 4: the input is `C` **including** `R`. For reference (CRY-02 is normative): `T = SHA256(E^rounds(C))`, where `E` is AES-256 encryption in ECB mode with the 32-byte key `KS`, applied to the two 16-byte halves of `C` separately, `rounds` times.

FMT-04.12 **KDF, version 3.** `T = AES-KDF(C3)` with seed `KS` (header field id 5) and the round count from header field id 6. Same AES-KDF as FMT-04.11. The sizes and the allowed round count (1 to 2,147,483,646) are owned by FMT-02.16 and FMT-02.17, with the reference's observed behavior in CRY-02.13; this card does not repeat them.

FMT-04.13 **Cipher key, version 4.** `K_enc = SHA256(S || T)`. 32 bytes, for every cipher (CRY-01, FMT-08).

FMT-04.14 **HMAC base key, version 4.** `K_mac = SHA512(S || T || 01)`, where `01` is one byte of value 1. 64 bytes. The key of each HMAC is derived from `K_mac` and an index (FMT-05 for the header, which uses index `FF FF FF FF FF FF FF FF`; FMT-06 for blocks). Version 3 has no `K_mac`.

FMT-04.15 **Cipher key, version 3.** `K_enc = SHA256(S || [R3] || T)`, where `R3 = SHA256(answer)` from the hardware key challenged with the padded `S` (FMT-04.8, FMT-04.9), present only when a hardware key is used. Without a hardware key: `K_enc = SHA256(S || T)`, the same formula as FMT-04.13.

FMT-04.16 **At least one component.** App refuses to create a vault, change the credentials, or save, when there is no component at all (no password, no key file, no hardware key). The refusal is the error kind `NoCredentials` (FMT-04.21), raised before any KDF work and before anything is written. The reference refuses the same on create and on credential change. Opening with no component is refused the same way: `NoCredentials` before the KDF, never `WrongKey` (decided: spec/decisions.md LD-13, D-04-1). Reference behavior on open, kept as a fact: it does not check and tries `C = SHA256(empty)` (Edge cases).

FMT-04.17 **Every save derives again.** Each save makes a fresh 32-byte `S` and a fresh 32-byte `KS` (CRY-03, SF-07; `KS` length decided: spec/decisions.md LD-15). So each save runs the KDF again and, when a hardware key is used, asks the hardware key again with the new `KS` (the user may have to touch it). To do this App keeps the components `P` and `F` (32 bytes each, in secret memory) while the vault is open, plus which hardware-key slot was used. App never keeps the password text after computing `P`. `F` is not read again from the key file on save: a key file changed on disk after unlock does not affect saving; it only matters at the next unlock. If a hardware-key answer fails during a save, the save stops and the file on disk stays as it was (AT-H03).

FMT-04.18 **Version 3 read, version 4 written.** App writes only version 4. When a vault read as version 3 is saved, its keys are made by the version 4 rules: `R` (when a hardware key is used) goes into `C` before the KDF, and the KDF seed becomes the challenge. When the KDF stays AES-KDF, App keeps the round count and makes a new 32-byte seed (decided: spec/decisions.md LD-07, LD-15). The reference does the same when it upgrades a file. The id App writes for AES-KDF is in FMT-03. A save must never drop `R`: a vault opened with a hardware key is saved with the hardware key unless the user removed it.

FMT-04.19 **Secrets.** `P`, `F`, every hardware-key answer, `R`, `R3`, `C`, `C3`, `T`, `K_enc`, `K_mac` and every per-block HMAC key are secret. They live only in App's secret types (wiped on drop), never go into logs, error values, crash reports or the screen layer, and are wiped as soon as they are no longer needed. `T` and the final keys are dropped on lock together with `P` and `F`.

FMT-04.20 **AES-KDF seed length.** For AES-KDF, App accepts only a 32-byte `KS` and refuses any other length as `Unsupported` before deriving (decided: spec/decisions.md LD-14, D-04-2; the rule is owned by FMT-03.16 and CRY-02.12). App itself always writes a 32-byte seed (FMT-04.17). Reference behavior, observed with the installed command line tool (CRY-02.12, FMT-03.16): the settings map accepts 8 to 32 bytes, but with a seed shorter than 32 bytes its AES step does nothing and it uses `T = SHA256(C)`, which means no key stretching at all; on save it writes a new seed of the same short length.

FMT-04.21 **Order of steps and outcomes.** FMT-05.7 owns the whole open order; this rule lists the key flow's own steps and their outcomes, and where each one runs in FMT-05.7. Step 1 runs first, at FMT-05.7 step 0, before any header field is parsed. Then come the header and KDF settings checks (FMT-02, FMT-03, CRY-02.5 to CRY-02.13, including the seed rule of FMT-04.20) at FMT-05.7 step 1 and the header hash check at FMT-05.7 step 3; their failures are `Corrupt` or `Unsupported` as those cards and CRY-02.16 say. Steps 2 to 4 run at FMT-05.7 step 4 and step 5 at FMT-05.7 step 5. App stops at the first step that does not succeed. Each failure has one error kind of `app-format/error.rs`:

| Step | What can stop it | Outcome |
|---|---|---|
| 1. Components | No component at all (FMT-04.16, on create, credential change, save and open; decided: spec/decisions.md LD-13) | `NoCredentials` |
| 1. Components | Any key file error (FMT-18.19) | `KeyFile`, with the key file reason of FMT-18.19 |
| 2. Cost check (CRY-02.14) | Cost above a refuse ceiling | `TooLarge` |
| 2. Cost check (CRY-02.14) | Cost in the "ask" band | Not an error: a returned decision "ask the user first", carrying the cost report of CRY-02.14 (memory, estimated time and the other settings). The caller shows them; on yes it calls the key flow again with the user's consent, and on no it stops with nothing done and nothing reported as an error. |
| 3. Hardware key (FMT-04.8 to FMT-04.10) | Device missing, removed, timed out, slot not configured, answer not 20 bytes, any other device failure | `HardwareKey`, with a reason (the reasons and their texts are owned by INT-07; the device's own error text may be included, it holds no key material) |
| 4. KDF (FMT-04.11, FMT-04.12) | The KDF library fails | `Unsupported` (CRY-02.16) |
| 5. Final keys, then the check of FMT-05 | Header HMAC (version 4) or start bytes (version 3) do not match | `WrongKey`, and only here |

The cost check comes before the hardware key, so the user is never asked to touch the device for a file that is then refused or that needs a yes first. On save, steps 1 to 5 run in the same order with fresh seeds (FMT-04.17), and step 5 is the writing of the file instead of a check. Before anything is written, the new transformed key is compared with the previous one (CRY-03.16). No error value holds any secret of FMT-04.19.

Needed change to plan/architecture.md, `error.rs` row (not yet made there; this card's list stands by the default rule of spec/decisions.md): add `NoCredentials`, `KeyFile` (with a reason: FMT-18.19) and `HardwareKey` (with a reason: INT-07) to `WrongKey`, `Corrupt`, `Unsupported`, `TooLarge` and `Io`; `WrongKey` stays only for the header HMAC (and the version 3 start bytes, FMT-01.21); the CRY-02.14 "ask" is not an error kind. `Io` stays for the vault file itself; a key file that cannot be read is `KeyFile` (reason I/O), so the screen can say which file failed.

## Edge cases and errors

- **Password text that is not valid Unicode** (an unpaired UTF-16 surrogate from the screen layer): Rust text cannot hold it. App refuses such a password with a plain message instead of changing it. What the reference does with such text was not tested (check with Verify); it cannot be typed on a normal keyboard.
- **NFC versus NFD.** A password typed on this Mac is usually NFC; the same word pasted from elsewhere may be NFD. The reference does not normalize, so App must not either (FMT-04.1). Seen: a reference vault made with the NFD form opens only with the NFD form.
- **No components on open.** App: `NoCredentials` before the KDF (FMT-04.16; decided: spec/decisions.md LD-13). Reference, kept as a fact: its open path does not check for this. It computes `C = SHA256(empty) = e3b0c442...` and tries it; the command line tool then reports invalid credentials. No reference tool can make such a vault.
- **Hardware key slot modes.** A slot can be programmed for a fixed 64-byte challenge or a variable-length challenge. In variable mode the device treats its last input byte, and every byte before it with the same value, as padding and drops them before hashing. So, for a 32-byte seed, a variable-mode slot hashes the seed alone, and if the seed itself ends in bytes of value `20` those are dropped too. This is device behavior. App does not change it and sends the same 64 bytes as the reference (FMT-04.9). The reference's own test data uses variable mode: its hardware-key test vault opens only with the variable-mode answer, and its hardware-key unit test expects the variable-mode result. Both were recomputed (FMT-01 Vector HK and FMT-01.28; test case FMT-04.6-e). So variable mode is the main vector here (FMT-04.6-a, FMT-04.15-b, FMT-04.6-e), and fixed mode is the second vector for INT-07 (FMT-04.6-d, FMT-04.15-c). Which mode the keys users own are set to is for INT-07 and E10 (check with Verify on a real device).
- **The reference's own recovery helper** (a small tool shipped in its source) shows the same math: it computes `HMAC-SHA1(secret, padded challenge)` over all 64 bytes and writes the 20-byte answer as a key file. As a key file, 20 bytes is the hashed kind (FMT-18), so `F = SHA256(answer) = R`, and `C = SHA256(P || R)` matches FMT-04.5 for a vault without a real key file. This is useful for INT-07 tests (source, re-read by Verify in Sprint 2: the helper takes the `S` value of the version 4 KDF map, pads it to 64 bytes with bytes that hold the padding length, computes HMAC-SHA1 over all 64 bytes and writes the 20-byte answer to a new key file. Observed by Verify with the installed CLI: the reference's hardware-key test vault, password `a`, opened with a 20-byte key file holding the variable-mode answer of FMT-04.6-e, and gave the wrong-credentials message with the fixed-mode answer, which is what the helper writes. So the helper's key file works only for a fixed-mode slot). Fixed-mode vectors: FMT-04.6-d and FMT-04.15-c.
- **Argon2 version 0x10.** The settings map can say Argon2 version 0x10 or 0x13. The reference source now always computes version 0x13. The installed command line tool (2.7.11) used a library that computed 0x10 when asked (differs in installed version). App saves such a file as 0x13 (decided: spec/decisions.md LD-17). This is owned by CRY-02 and FMT-03.
- **Version 3 round count.** Owned by FMT-02.17 (App: 1 to 2,147,483,646, otherwise `Unsupported`). The reference's silent fall-back to 1 round and its 32-bit cut were observed with the installed tool (CRY-02.13).
- **Version 4 AES-KDF round count.** Owned by FMT-03.16 and FMT-03.18 (App: the full stored value must be 1 to 2,147,483,646, otherwise `Unsupported`). The reference cuts the value to 32 bits before its range check; observed: a stored 2^32 + 15,000,000 opened as 15,000,000 rounds (FMT-03.18, test D39 there; CRY-02.12).
- **Hardware key answer not 20 bytes.** `HardwareKey` (FMT-04.10, FMT-04.21).
- **Hardware key present on open but missing on save.** The save fails with `HardwareKey` and the old file stays (FMT-04.17, AT-H03).
- **Messages.** For a wrong key, in both versions, the reference says the credentials are invalid, asks the user to try again, and adds that the file may be damaged if this keeps happening (FMT-05). For a hardware-key failure it says that it could not compute the key or could not complete the challenge-response, followed by the device error. App's texts come from APP-06.
- **Decided D-04-1 (spec/decisions.md LD-13): opening with no credentials.** Refuse before the KDF with `NoCredentials` (FMT-04.16, FMT-04.21). History: the other option, trying `C = SHA256(empty)` as the reference does, was not chosen.
- **Decided D-04-2 (spec/decisions.md LD-14): AES-KDF seed not 32 bytes.** `Unsupported` (FMT-04.20). History: the other option, copying the reference's `T = SHA256(C)` with no stretching, was not chosen.

## Security notes

- What could go wrong: a normalized, trimmed or re-encoded password locks the user out. Treating "empty password" as "no password" (or the reverse) locks the user out. Putting `R` in the version 3 place in a version 4 file, or forgetting it on save, either locks the user out or silently saves the vault without its hardware-key protection. The second must never happen (FMT-04.18).
- A missing hardware key must not be reported as a wrong password. A wrong hardware key must give exactly the same result and message as a wrong password (AT-A01, AT-H04).
- No value in this card is ever written to disk, logged, put in an error, or sent to the screen (rule 4 in AGENTS.md, SR-07, AT-C06). After lock none of them stays in memory (AT-C01). Quick unlock (APP-04) is separate and must not reuse these values outside its own rules.
- The KDF cost must be checked against the limits before the KDF runs (FMT-03, CRY-02, AT-A05). The KDF runs on a worker thread.
- AES-KDF with a short seed would give no key stretching (FMT-04.20). App refuses it.
- Fresh `S` and `KS` on every save (CRY-03, AT-B03) mean the derived keys change on every save, even with the same credentials.
- Parity rows: SF-04 (combination of credentials), SF-02 (KDF), SF-05 (keys used by the header check), SF-07 (fresh seeds), SI-08 (hardware keys), SR-07 (key material in memory). Attacks: AT-A01, AT-A05, AT-B02, AT-B03, AT-C01, AT-C06, AT-H03, AT-H04.

## Test cases

Demo values used below:

- Demo password `demo-pass`: UTF-8 `64656d6f2d70617373`, `P = 02ccf27105554b9a7fc512ba9f40b863ff974c35487512a7ea8b0e661f831b12`.
- Demo key file H: the 39 ASCII bytes `App demo key file for the hashed kind.` followed by `0a`. It is the hashed kind (FMT-18), `F_H = 19de591b532e010acde3146d4b07881deaf736b8098d8aa115ab30ea40779978`.
- Demo key file X: an XML key file, version 2.0, whose data is the 32 bytes `60 61 ... 7f` (FMT-18 test cases). `F_X = 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f`.
- Demo hardware-key secret: the 20 ASCII bytes `App demo HMAC secret` = `4170702064656d6f20484d414320736563726574`. Answers are computed as a variable-mode slot would compute them: `HMAC-SHA1(secret, challenge without its padding)`. Rows FMT-04.6-d and FMT-04.15-c give the fixed-mode answers instead: `HMAC-SHA1(secret, all 64 padded bytes)`, as the reference's recovery helper computes them.

| Case | Given | When | Then |
|---|---|---|---|
| FMT-04.1-a | Password `demo-pass` | Make `P` | `P = 02ccf27105554b9a7fc512ba9f40b863ff974c35487512a7ea8b0e661f831b12` |
| FMT-04.1-b | Password "Pässwörd" in NFC (`50c3a4737377c3b67264`) and in NFD (`5061cc887373776fcc887264`) | Make `P` for each | NFC: `b9fdf96f902f18de9c513b0b05383d0f47a06890832799cc0af2f583df530f61`; NFD: `7d73593078ce5f4906e8d2167b03b5883111eb854fe1146c4e3a3a4f88b6ce16`; they differ and neither is changed into the other |
| FMT-04.1-c | Password: space, `sp`, space, `ace`, space, tab (`20 73 70 20 61 63 65 20 09`) | Make `P` | `P = 5d6787e78636482da925e09ac4e3015ecd9f5fde66d4c448197b5076c010ac53` (no trimming) |
| FMT-04.1-d | Password "🔑" (`f09f9491`) | Make `P` | `P = c5c75521402748f523eee2f15d74f10f38acbb134ebd026d5777958c3df862cb` |
| FMT-04.1-e | A vault made by the reference command line tool with the NFC password "Pässwörd-日本-🔑", and one made with its NFD form | Open each with the NFC form | First opens; second fails with wrong key (seen with the reference tool) |
| FMT-04.2-a | Empty password, no key file | Make `P` and `C` | `P = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; `C = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456` |
| FMT-04.2-b | A vault made by the reference command line tool with an empty password (confirmed with "y") | Open with "empty password"; open with "no password" | Empty password opens it. No password and no other key part: App gives NoCredentials before any key work (LD-13, FMT-04.16); the reference reports a wrong key here (seen) |
| FMT-04.3-a | Demo key file H | Make `F` (FMT-18) and use it | `F = 19de591b...779978` is used as is; `C` for key file only = `c244f9efbdbcf5c8f3848fddefd09ba0e61587443b9fbb02553221525e2a555a` |
| FMT-04.4-a | `demo-pass` and key file H | Make `C`; also hash in the wrong order `F \|\| P` | `C = d230afbd10c06dc1e18292eab64a8c9d436d8ed2341e5182bc5059408b672b7a`; wrong order gives `7d7e61505de5652e2215ddacb736182d421014f9caf6199e5e65da141ca353ad`, which must not open a reference vault made with both (seen) |
| FMT-04.5-a | `demo-pass` only | Make `C` | `C = dc00c46876f8ab6f1ea1f5fcd0a29e2a7a808bcd6e1d32076dbf779df06dcdb6` |
| FMT-04.5-b | `demo-pass` and key file X | Make `C` | `C = 2c6c7513daf938019ed5af937a20c41dab110d59228f7b7b355636143c44f4e1` |
| FMT-04.6-a | `demo-pass`, key file X, hardware key with the demo secret; version 4 file with `KS = 3481483a67fb365da911c5095420ce2bfd2161793b47d7a6561cedf921899e63` | Answer, `R`, `C` | answer `5744a1267b30e12442156bbd9d54715541765d89`; `R = 42a98ddc572e2b0544d137fff9b9ad6085d9ec90dd88916e362d53b8e62cd0ec`; `C = 3d23a499d7507e100fadf6c03da0684c4b65b7f6e00f514dbbb3f3f86d100f75` (computed; recomputed by Verify in Sprint 2 with a simulated variable-mode key, python3 hmac and hashlib: the same three values; a real device waits for OD-01, E10) |
| FMT-04.6-d | As FMT-04.6-a, but the slot is in fixed mode (it hashes all 64 bytes of the challenge of FMT-04.8-a) | Answer, `R`, `C` | answer `c66e7366f1946a047868cb828a4ed86cbfd02464`; `R = 4b53360059a9e83ea2232a2fc274d9d04118d75dae079be95ec01b31a52c4ef3`; `C = ee3fe4b7315239c2433795d805290e37b3d5b93fc8783a4f37904b13f5374850` (computed; recomputed by Verify in Sprint 2 with a simulated fixed-mode key, python3 hmac and hashlib: the same three values; a real device waits for OD-01, E10) |
| FMT-04.6-e | The reference's hardware-key test vault of FMT-01 Vector HK (read only): version 4, `KS = 828824cbe1a43319be44b303ddce4fcbf3daa0a02fe5d65fa73c5c903a8485d8`, password `a`, HMAC-SHA1 secret `1ce30fd78d20dcfa40b50c18779afb0f02288db7`, answered as a variable-mode slot | Answer, `R`, `C` | answer `ec5f7c1427d8b26b9984228abb98621b1165ba18`; `R = 709b0674aa1124dab024c7d50e428badb26829ca8485e03844300daadff5bf6a`; `C = df5d072b8c138f85dea5d2f04ceefcf3c001f3c83c25d9a2a5c0f548fbd8bfa1`. With these, the header HMAC matches the stored one (FMT-01.28, observed by recomputation). Fixed mode gives answer `9c401f62a28029f837efbec2c66c5a0ff89a19c0`, `C = 2311208091a3912b3eac398e867873f08db702c7c9c8e9982d9ec16378f06d6e`, and the header HMAC differs (wrong-key result) |
| FMT-04.6-b | `demo-pass` and key file X, no hardware key | Make `C` | Equals FMT-04.5-b; it is not `SHA256(P \|\| F \|\| SHA256(empty))` |
| FMT-04.6-c | V4 values of FMT-04.11-d with the hardware-key `C` of FMT-04.6-a, AES-KDF 1,000,000 rounds | Derive `T`, `K_enc`, `K_mac` | `T = 273a95f2d17f7ca859019251dfff82af0b5cadb989b922c8292abb945019729b`; `K_enc = cd8ae928e9ec6c9cce85695ec649e0814b27fec8f6e14aea4ba48330a7f4103e`; `K_mac = a8a43a88a4f5af7cedb42830c0a904c5f10d8ac64d05accd45db9e1f93429e33df7be11aadd2ba7564f5960d7c0dc84c3b26eaaf9a728fb68d3416d7feddf3c5` (computed; recomputed by Verify in Sprint 2 with AES-256 from libgcrypt 1.12.1 for the 1,000,000 rounds and python3 hashlib: the same three values; the same code gives the `T` of FMT-04.11-d) |
| FMT-04.7-a | Version 3 file, `demo-pass`, hardware key used | Make `C3` | `C3 = dc00c468...06dcdb6` (same as FMT-04.5-a; `R` is not inside) |
| FMT-04.8-a | Version 4 file with the `KS` of FMT-04.6-a | Build the challenge | The 32 bytes `3481483a67fb365da911c5095420ce2bfd2161793b47d7a6561cedf921899e63` followed by 32 bytes `20`, 64 bytes in all |
| FMT-04.8-b | Version 3 file with `S = 8ca3a3bbc9f2fb20c2ba098d9a1caf09ff8d05884cf9064f8ee674dab167c043` | Build the challenge | `S` followed by 32 bytes `20` (the transform seed is not used) |
| FMT-04.9-a | KDF seeds `a0 a1 ... a7` (8 bytes) and `a0 ... af` (16 bytes) | Build the challenges | 8 bytes followed by 56 bytes `38`; 16 bytes followed by 48 bytes `30`; both exactly 64 bytes |
| FMT-04.10-a | Vault that needs a hardware key; no device connected | Open | Fails with `HardwareKey` before the KDF; not `WrongKey` (AT-H03) |
| FMT-04.10-b | Simulated device that returns 19 or 21 bytes | Open | `HardwareKey` |
| FMT-04.10-c | Vault made with a hardware key whose slot 2 holds the demo secret; another hardware key whose slot 2 holds a different secret is connected and answers | Open | Wrong-key result, same as a wrong password (AT-H04) |
| FMT-04.11-a | `C = dc00c468...06dcdb6`, AES-KDF, `KS = 00 01 ... 1f` | `rounds` = 1, 2, 1000 | One AES step (before the hash) gives `65f8d392b68c6170cfdd0a55592a9fdceb29327078dee440e6f156d076e4a168`; `T` = `ab1a9f624218636aac0df21a44480809c00d515186aafec4bb17748df8275099` (1), `bb44b70521f4a3490b25ac09bf16154278926b52addf70050bb462ed9c24f3ac` (2), `2305dd9b08c603a1b3b2e3a71c98830a7d5e951732a92df7810af59576af7eed` (1000) |
| FMT-04.11-b | `C = dc00c468...06dcdb6`, salt `00 01 ... 1f`, memory 64 KiB, 2 iterations, 2 lanes, version 0x13, tag 32 bytes | Argon2d; Argon2id | Argon2d `T = a5aba766c577d0aec14ae550dc428182d49fa7b933642f4b858d92935e7a0962`; Argon2id `T = 088bafc94c3fd1ad3e2035b7500d3cf640b2f6bb562166d20ba60ac170a262e3` (computed with OpenSSL 3.6) |
| FMT-04.11-c | One version 4 settings map with AES-KDF id `c9d9f39a-...` and one with `7c02bb82-...`, same seed and rounds, with a hardware key | Derive `T` | Same `T` for both, and `R` is inside `C` for both |
| FMT-04.11-d | Demo vault V4 (made by the reference command line tool 2.7.11, version 4.0, AES-KDF id `c9d9f39a-...`, 1,000,000 rounds), credentials `demo-pass` and key file X | Derive | `KS = 3481483a67fb365da911c5095420ce2bfd2161793b47d7a6561cedf921899e63`; `C = 2c6c7513...c44f4e1`; `T = 1513b1f95c2087fea5e1e396be862b7796464d4bf18449d7a3dca59e0c4f82c0` |
| FMT-04.11-e | The reference test vault with stem `Format400` (in `REF_TESTDATA`, read only; password `t`; Argon2d, memory 1 MiB, 2 iterations, 2 lanes, version 0x13) | Derive | `C = 7415e100520c4fc2de9429958c0b64500a076b48ef2ad0648c7243c52046c671`; salt `56ac066d2d862ab0c50c00f6143a349df441f2e6910b297da88f50c3c302d9a5`; `T = 5ef06327c2aa395e04aa9a94fb837b58030cf202eddc61f408046070c256a2e8` |
| FMT-04.12-a | Demo vault V3 (made by the reference command line tool 2.7.11 with password `demo-pass`; version 3.1, AES-256) | Derive | `C3 = dc00c468...06dcdb6`; transform seed `e0d76aeae02eaa39ddc28327e61f1ce94f2dea34b82e8cffc424b4f984bb8e37`; rounds 1,000,000; `T = 816e7edddfe738c48b0d6fac9862eeb01295c8d3fc28bf56e381b066ad7d6199` |
| FMT-04.13-a | V4: `S = 0eeaa8a41e9d10b6901ec07f2de0698b3d2d996e86be1b2285b3c4e03fcae277`, `T` from FMT-04.11-d | Make `K_enc` | `K_enc = d386a895a6ea6f3e9b249157d83c497558b7ebb9b55fd89132add0617069809f` |
| FMT-04.13-b | `Format400`: `S = 3bfa79c0795325db317f99f475b559f195d73368da522c12a061a0c2b9efcb13`, `T` from FMT-04.11-e | Make `K_enc` | `K_enc = fe24792c0ffb62dbec19139addf06e6fb2ebb3924c1bbd23053caa453ab7d175` |
| FMT-04.14-a | V4 values above; V4 header bytes (207 bytes) `03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff03040000000100000004200000000eeaa8a41e9d10b6901ec07f2de0698b3d2d996e86be1b2285b3c4e03fcae27707100000008142ce41d6b614dee8a3c19f220f86640b5d00000000014205000000245555494410000000c9d9f39a628a4460bf740d08c18a4fea0501000000520800000040420f0000000000420100000053200000003481483a67fb365da911c5095420ce2bfd2161793b47d7a6561cedf921899e630000040000000d0a0d0a` | Make `K_mac`, the header HMAC key and the header HMAC (FMT-05) | `K_mac = 25580261b98d28d8443c5c6f98111ed6a21419ce3517a395f70bfb5d75eabb5e443aeda405facb650015a42f19ddf40e2dc763229ab7650d158842c7aac9fe97`; header HMAC key `SHA512(FFFFFFFFFFFFFFFF \|\| K_mac) = 870b9e35ae27c6b5bcba99560ca214a087bf09e5779a0d41834779cec16ad80493d55a46d92570919a10935c3a50a1ceb5b6d2e48d8c30fc63cec5300956c04b`; HMAC `ab47e216d18d93e538ae83d10e8546f19c70038adbcf8e2291f4bdaf7c146a79`, equal to the value stored in the file; header SHA-256 `cd7ee6365f1016dcfaa5df2479258a08a9f88f8691ec9020be18b324a396c4d9` |
| FMT-04.14-b | `Format400` values above | Make `K_mac` and the header HMAC | `K_mac = 5f9f7be123af6d249558f4fa3b68d2d63405f8d72b90ae4ba670a2aa6fa1c235c12ea142ffbc3a6faa218bc2a5842cb7050407f95a4d0e6556ea1e5ad7b180f9`; HMAC `73b7738e9e5ce6e5ae3d24a2bf7e94a698cc3901f5effd80b8041d49128cb669`, equal to the stored value |
| FMT-04.15-a | V3: `S = 8ca3a3bb...b167c043`, `T` from FMT-04.12-a, no hardware key; IV `f15b240fd05118f3f35de05aecd72d25`; first 32 payload bytes `9cf64ca3743991b6b667b5c0f98aa3cbd4fa6e2b70691db3f31ec226ccc3bec7` | Make `K_enc`; AES-256-CBC decrypt those 32 bytes | `K_enc = 67c681bc88295a0dd625a20d3cd40068b33bf2736104dddf979caca38878b96e`; plaintext equals the stored start bytes `8341f1326a7284ea021998e2455a97c1ba90da7cad9d9279cb323780f1c51dd1` |
| FMT-04.15-b | V3 values above plus the demo hardware key | Answer, `R3`, `K_enc` | challenge = `S` followed by 32 bytes `20`; answer `0572a30d40209b873d3d826255b34dc7ebd70c6d`; `R3 = 55c6d78cee577f92becfe0c083fff2aed16a36eb8a46c19d8cb75df57994c87d`; `K_enc = 56f4b639a069cc51f7c3bd442443664e58ec258fef3077eaeb538d008183362b` (computed; recomputed by Verify in Sprint 2 with a simulated variable-mode key, python3 hmac and hashlib: the same three values; the order `S`, `R3`, `T` matches the version 3 reader in the source) |
| FMT-04.15-c | As FMT-04.15-b, but the slot is in fixed mode (it hashes all 64 bytes: `S` followed by 32 bytes `20`) | Answer, `R3`, `K_enc` | answer `3e19910428e0ebefe2b379fc97fe999f3974336a`; `R3 = 127004b586ad2d0c1266357c373034e02377dc0c7f49db79a954e8a126468281`; `K_enc = 390d122f4aa6976b503c591d2a3b52b4e25ec771fdda711ba9b42da06be3828f` (computed; recomputed by Verify in Sprint 2 with a simulated fixed-mode key, python3 hmac and hashlib: the same three values) |
| FMT-04.16-a | No password, no key file, no hardware key | Create a vault; change credentials to none; save | Refused with `NoCredentials` and a plain message; no KDF run; nothing written (the reference command line tool reports that no credential was given and stops) |
| FMT-04.16-b | A vault and no credentials at all | Open | `NoCredentials` before any KDF work, never `WrongKey` (decided: spec/decisions.md LD-13). Reference, for comparison: tries `C = SHA256(empty)` and reports invalid credentials |
| FMT-04.17-a | One vault, same credentials | Save twice | `S`, `KS`, `T`, `K_enc` and `K_mac` all differ between the two files; both open with the same credentials. Also a version 4 Argon2 vault whose stored salt is 16 bytes: after one save, `KS` in the new file is 32 bytes (LD-15) |
| FMT-04.17-b | Vault unlocked with key file H; then H is changed on disk | Save; then lock and unlock with the changed H | Save works and the file opens with the old H content; unlock with the changed H fails with wrong key |
| FMT-04.17-c | Vault with a hardware key; device removed after unlock | Save | `HardwareKey`; the file on disk is byte-for-byte unchanged (AT-H03) |
| FMT-04.18-a | Version 3 demo vault with `demo-pass` and a hardware key | Open in App, save (written as version 4), open in the reference with the same credentials | Opens; the new file's `C` contains `R` from the new `KS`, which is 32 bytes (interop, check with Verify in E10; the run with the reference needs a physical key and waits for spec/decisions.md OD-01) |
| FMT-04.19-a | Debug build, full unlock, save and lock run at the highest log level | Search logs, errors and a memory dump after lock for `P`, `F`, `C`, `T`, `K_enc`, `K_mac` of the demo vault | None found (AT-C01, AT-C06) |
| FMT-04.20-a | A version 4 file using AES-KDF with a 16-byte `KS`; and one with an 8-byte `KS` | Open | App: `Unsupported` before any derivation (decided: spec/decisions.md LD-14). Reference: opens both with `T = SHA256(C)`, zero KDF work (observed, CRY-02.12 test T22) |
| FMT-04.21-a | A vault whose KDF cost is above the ceiling of CRY-02.14 and that needs a hardware key; no device connected | Open | `TooLarge`; the device is never asked; not `HardwareKey` |
| FMT-04.21-b | A vault whose KDF cost is in the ask band of CRY-02.14 (for example Argon2 memory 2 GiB with the memory hook at 16 GiB), right password | Open; answer no; open again and answer yes | First: the key flow returns the decision "ask the user first" with memory and estimated time, not an error kind; after no, nothing ran and no error is shown. Second: the vault opens |
| FMT-04.21-c | A vault made with password `demo-pass` only; an empty key file (FMT-18.2) | Open with `demo-pass` plus the empty key file; open with password `wrong-pass` alone | First: `KeyFile` (reason: key file empty), no KDF run. Second: `WrongKey`, only after the header HMAC check |

## How this was learned

- Read in the reference source: the composite key routine, the password component, the key file component, the challenge-response component and its device drivers (the USB path and the smart-card path, including their challenge padding), the version 3 and version 4 readers and writers, the writer's file-version choice and its KDF upgrade step, the KDF settings reader, the AES-KDF and Argon2 routines, the database's set-key and challenge steps, the command line tool's unlock helper and its create command, the unlock screen, and the database key settings screen with its password, key file and hardware-key parts. Also the reference's key tests, its mock challenge-response key, and the hardware-key recovery helper in its utilities folder.
- Compared the source with the installed version's tag (2.7.11) for these parts. The only difference found that changes keys is the Argon2 library (version 0x10 handling, see Edge cases).
- Ran the reference command line tool 2.7.11 in `/tmp/spec-fmt04-fmt18/` with demo passwords only. Made demo vaults V3 (create with a password: version 3.1, AES-KDF), V4 (import of a demo XML export with group custom data, which forces version 4.0 with AES-KDF), plus vaults with an empty password, NFC and NFD passwords, whitespace passwords, and password plus key file. Opened them with right and wrong credentials.
- Recomputed every key with python3 (hashlib, hmac), AES through the system crypto library, and Argon2 through OpenSSL 3.6. The checks matched for all of them: the header HMAC for version 4, the start bytes for version 3. The same checks passed on the reference test vaults with stems `Format400`, `KeyFileProtected` (password `a` plus its key file, Argon2d) and `KeyFileProtectedNoPassword` (key file only, Argon2d).
- Review round 1: read again in the source the seed refresh on save (new random bytes of the current seed's length), the order of challenge and KDF in the version 4 key transform and in the version 3 reader (FMT-04.10), and added the fixed-mode hardware-key vectors (FMT-04.6-d, FMT-04.15-c), computed with python3 hmac.
- Review round 2 (cross-check findings): read again in the source the AES-KDF settings reader (rounds read through a signed 32-bit conversion, seed taken as given) and pointed FMT-04.12, FMT-04.20 and the round-count edge cases to the observations already made with the installed tool in CRY-02.12, CRY-02.13, FMT-03.16 and FMT-03.18, which own those rules. Renamed the derived keys to `K_enc` and `K_mac`. Added FMT-04.21 (order of steps, error kinds, the CRY-02.14 ask as a returned decision) from App's own design; the reference has no cost check and, in version 4, asks the hardware key before its KDF (FMT-04.10).
- Review round 3 (cross-check findings): read the reference's hardware-key unit test and recomputed its expected value with python3 hmac and hashlib. It is the variable-mode result for its demo secret and challenge, as FMT-01 Vector HK states. Recomputed the variable-mode and fixed-mode answers for the reference's hardware-key test vault (FMT-04.6-e); they match FMT-01 Vector HK.
- Not proven with the reference: the hardware-key vectors with a real device (no device here; a physical key waits for spec/decisions.md OD-01; check with Verify in E10). Verify (Sprint 2) recomputed every hardware-key vector with a simulated key and saw the installed CLI open the reference's hardware-key test vault with the variable-mode answer given as a 20-byte key file. Argon2id on a reference-made vault, observed by Verify in Sprint 2: a scratch version 4.1 AES-256 Argon2id vault (1 MiB, 2 iterations, 2 lanes, version 0x13), keyed with Argon2id from OpenSSL 4.0.3, opened in the installed CLI; the CLI re-saved it with `mkdir`, and the re-saved file (still Argon2id, a new 32-byte salt) decrypted with OpenSSL's Argon2id and opened in App's reader.
- Sprint 1 close-out: the opening of FMT-04.21 now follows FMT-05.7 (credentials at step 0, before any header field; header checks and the hash check after it), and the save note points to the new key-change check of CRY-03.16.
