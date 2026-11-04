# E4-S13 Import and export: Verify proof

Story: E4-S13 Import and export (FEA-08, FEA-09).
Date: 2026-10-27.
Role: Verify (reference access allowed; nothing from the reference was copied into this folder).
Result: **signed** at the re-check of 2026-10-27 (section "Re-check 2026-10-27": F1, N1, N3 and N4 fixed and matching the reference; N2 a Larsal choice by LD-148; new note N5, not blocking). First run: **not signed**, one failure (F1, UTF-16 without a byte order mark). Every other acceptance case is proven or is a screen part for E5, and every LD-143 and LD-146 parity point is settled. Four small differences outside the parity list are noted for the lead (N1 to N4).

## Setup

- Reference: source at commit 09e34ba8 (read only) and the installed app 2.7.11 with its command line tool. Every reference run used a throwaway home folder under `/tmp/verify-e4s13/home`. The reference app's window was not started and its settings folder was not read.
- Reference test files were copied to `/tmp/verify-e4s13/ref/` and used only there (read only, demo data).
- Larsal's readers and exporters were run through a throwaway probe crate in `/tmp/verify-e4s13/probe/` that depends on `larsal-core`, `larsal-format`, `larsal-model` and `larsal-crypto` by path (own target folder, the project's `Cargo.lock` copied in). It calls the public `import::*` and `export::*` functions and prints the result tree (fields with their protected flag, tags, times, attachments, Auto-Type, TOTP settings, history). Import time in the probe: 2026-10-26T07:33:20Z, zone UTC.
- No product code, test or fuzz file was changed. Files changed: the two cards (markers closed, facts recorded) and this file.

## 1. check.sh

PASS on every gate (summary in "check.sh run" at the end).

## 2. Reference test files through Larsal's readers

Every value below is Larsal's output on the reference's own test file, compared with the card's expected value and with the reference's own test assertions (read in its import and version 1 reader tests). All match.

| Case | Input | Larsal result | Verdict |
|---|---|---|---|
| 08-29 | the reference's .1pux test file | Group "Personal": "Login" Username `team@` + reference domain, Password `password`, Notes `Note to self`, URL and `KP2A_URL_1` set, TOTP set (form U), `otp_1` set, tags `Favorite` and `website`; the logo entry has 1 attachment named like its file (18,422 bytes); "Credit Card" `Credit Card Fields_verification number` = `123` protected, cardholder name, `expiry date` = `202206`; "Identity" `Address_address` = `123 Avenue Rd` LF `Boston, MA 12345` LF `us`; "Login Archived" tag `Archived`; group "Shared" has a custom icon (PNG, 9,036 bytes); "UUID 005 Password" Password `uuid005password` | matches |
| 08-33 | the reference's OPVault test folder | Password `a` opens; password `b` gives Wrong password. Python on the same profile: 100,000 PBKDF2-SHA512 rounds, `masterKey` 336 bytes, L = 256, P = 16, its HMAC verifies with `a` and fails with `b` | matches |
| 08-34 | same folder, password `a` | Login: the entry named after the reference has Password `opvault`, `KP2A_URL_1` set, TOTP set (form L, `30;6`), one attachment `attachment.txt` = `attachment`; "Expired Login" expires 2017-11-01T12:01:00Z; "My Credit Card" `cardholder name` set, `valid from` set, `Additional Details_PIN` = `1234` protected; Identity entry `address_street` = `123 Password Lane`; "Complex Password" TOTP 8 digits, 45 s; "Trashed Password" marked trashed (1 entry, placed in the bin by FEA-08.8, test `fea08_07_trashed`); root children Login, Credit Card, Secure Note, Identity, Password, Server, all non-empty; 0 items skipped | matches |
| 08-41 | the reference's plain Bitwarden test file | "My Folder/Login Name": Username `myusername@gmail.com`, Password `mypassword`, `KP2A_URL_1` `https://google.com`, `KP2A_URL_2` `https://gmail.com`, modified 2024-12-25T12:00:00Z, created 2024-12-01T12:00:00Z, one history item Password `oldpassword` modified 2024-12-01T12:00:00Z; "My Identity" `identity_address` exactly ` 1 North Calle Cesar Chavez ` LF `Santa Barbara, CA 93103` LF `United States `, `identity_name` `Mrs Jane A Doe`, `identity_ssn` protected; "Second Folder/Card Name" `card_code` protected, `card_number` `1234567891011121` not protected | matches |
| 08-41 (nested) | the reference's nested-folder Bitwarden file | Groups SecondTest, Test, Test/Subfolder, Test/SubFolder, Test/SubFolder/AnotherSubFolder; every entry in the group the reference test expects (both `Subfolder` folders share one group, as there) | matches |
| 08-42 | the reference's passkey Bitwarden file | `KPEX_PASSKEY_CREDENTIAL_ID` = `o-FfiyfBQq6Qz6YVrYeFTw`, `KPEX_PASSKEY_RELYING_PARTY` = `webauthn.io`, the whole PEM equal to the reference test's value (starts `-----BEGIN PRIVATE KEY-----MIGHAgEA`), user handle equal, tag `Passkey` | matches |
| 08-43 | the reference's encrypted Bitwarden file (PBKDF2, 100,000) | Password `a` opens; `b` and no password give Wrong password. Python on the same file: K starts `9d1a914981dad5b0`, enc `e05d98c318787571`, MAC `80b149d20e614ec5`; validation and `data` MACs verify; both values type `2` | matches |
| 08-44 | vectors | Python: K `3f4717b7…a41f6084`, enc `52c30d8b…d596a79d`, mac `0bdbdb72…4a00fb70`, Argon2 salt `f0135775…efcb87b5`: all equal to the card | matches |
| 08-45 | the reference's Argon2id file (3, 64 MiB, 4) | Password `a` opens (0.1 s); `b` Wrong password; a copy with one `data` ciphertext bit flipped gives Bitwarden damaged; a copy without `salt` gives account-key export | matches |
| 08-46 | the reference's Proton Pass file | "Personal/Test Login": Username `Username`, `KP2A_URL_1` `https://example2.com/`, TOTP set, `hidden field` protected, `second 2fa secret` = `TOTPCODE`; "Personal/Test Card": Username `1234222233334444`, Password `333`, `card_pin` `1234` protected, `card_expirationDate` `2025-01`; "My Deleted Note" expires; "Unknown Type" `content_attr1` = `value1`, `content_attr2` = `value2`; group order Personal, Test ("Test/Other vault login" present) | matches |
| 08-49 | the basic version 1 test file, `masterpw` | Opens. Independent Python and openssl decryption: flags 3, version 0x30002, 6 groups, 7 entry records, rounds 713, plaintext 2,345 bytes, SHA-256 equals the header hash | matches |
| 08-50 | binary, hex and hashed key-file files; composite file with `mypassword` and the hex key file; Twofish file with `masterpw` | Each opens; the single top group is named FileKeyBinary, FileKeyHex, FileKeyHashed, CompositeKey, Twofish; the composite file without its key file gives Wrong credentials; Twofish file flags 9 | matches |
| 08-51 | the Windows-1252 version 1 file, `„password”` | Opens, top group `CP-1252`. Python: the Windows-1252 bytes `84 70 61 73 73 77 6F 72 64 94` decrypt it (content hash verifies) | matches |
| 08-52 | basic file | Root `Root`: Internet (icon 1) with Subgroup 1/Unexpanded/abc and Subgroup 2; eMail (icon 19). Internet: "Test entry" (Username `I`, URL `http://example.com/`, Password `secretpassword`, Notes `Lorem ipsum` LF `dolor sit amet`, attachment `attachment.txt` = `hello world` LF, expiry 2012-05-09T10:32:00Z) and an empty-title entry; fresh ids. Group times are the import time because every group time in the file is the "never" value (Python) | matches |
| 08-54 | basic file | No "Meta-Info" entry; one custom icon (PNG, 119 bytes) used by "Custom Icon"; Internet and Subgroup 1 expanded, Unexpanded collapsed | matches |
| 08-55 | basic file, Subgroup 1 | Entry 1: Notes `last line`, default sequence `{USERNAME}{ENTER}`, associations (`a window`, ``), (`a second window`, ``), (`Window Nr 1a`, `{PASSWORD}{ENTER}`), (`Window Nr 1b`, `{PASSWORD}{ENTER}`), (`Window 2`, ``), the reference test's order; entry 2: Notes `start line` LF `end line`, (`Main Window`, ``), (`Test Window`, ``). The "see Auto-Type: x" part is Larsal's own (test `fea08_55_v1_auto_type`) | matches |

No CSV file is among the reference's test data; its CSV parser tests use inline text, which the card's cases 08-13 to 08-21 already copy (Builder tests, Checker 1).

## 3. Parity points

| Point | Verdict | Evidence |
|---|---|---|
| LD-143 (1) UTF-16 without a byte order mark (built: big-endian) | **differs** (F1) | The reference sets the CSV decoder by name, "UTF-16" (CSV parser, set-codec routine, lines 348 to 353 of the source; same in 2.7.11 with the older decoder call). The installed app's bundled text library was called directly from a small C++ program: bytes `61 00 62 00` give U+0061 U+0062, bytes `00 61 00 62` give U+6100 U+6200, `FE FF 00 61` gives U+0061 (BOM wins). So the reference reads UTF-16 without a byte order mark in the computer's byte order: little-endian on every Mac. Larsal, same bytes `Title,UserName` LF `ab,cd` in UTF-16LE with Encoding UTF-16: 0 entries (the whole file decodes as one line of wrong characters). Card fixed (FEA-08.14, case 08-13). |
| LD-143 (3) FEA-08.52 source keys for SSH keys, Wi-Fi and cards | matches | Reference Proton Pass reader, item routine (lines 101 to 126): card `number`, `verificationNumber`, `cardholderName`, `pin` (protected), `expirationDate`; Wi-Fi `ssid`, `password`, `security`; SSH key `publicKey`, `privateKey` (protected). Larsal's proton.rs reads the same keys. Card table now names the source keys. |
| LD-143 (8) plain bin group when the target's bin is off (built: under the moved import root) | matches (place) | The reference's OPVault reader sends a trashed item to the result's own bin (band entry routine, lines 116 to 118), which the vault creates as a child of the result's root; on "existing vault" the tab view's import handler (lines 275 to 290) moves the result's whole root under the chosen group, so that bin group lands under the moved import root, as Larsal's last child there. Note N3 for its icon and switches. |
| LD-143 (11) FEA-09.9 heading for a group whose entries are all left out (built: kept) | matches | Reference HTML exporter, group routine (lines 231 to 254): heading when the group has entries or notes, before entries are filtered. Black box: a demo vault made with the reference tool (group `OnlyTitle` holding one title-only entry); the reference's HTML export has `<h2>Passwords &rarr; OnlyTitle</h2>` and no row; Larsal's has `<h2>Passwords › OnlyTitle</h2>` and no entry. |
| LD-143 (12) FEA-09.14 empty attachments element (built: always written) | matches | Reference XML writer, pool routine (lines 217 to 260): writes the pool element whenever it writes a pool, also with no attachments. Black box: the reference's XML export of `password-only.larsalvault` (3.1, no attachments) and of the new demo vault (3.1) holds `<Binaries/>`; Larsal's exports of both hold `<Binaries/>`. |
| LD-143 (14) cases 08-41/42/43/45/46 on the reference's files | matches | Section 2. |
| LD-146 (1) LD-45 item check value | matches | The reference's OPVault test folder has 8 items in 6 band files (members `category`, `created`, `d`, `hmac`, `k`, `o`, `tx`, `updated`, `uuid`, one with `trashed` true). Larsal imports all 8 with 0 skipped, so the built check value (HMAC-SHA256, overview MAC key, other members in sorted key order, key then value as text, whole numbers in decimal, true `1`) is right on real data, booleans included. Negative check: a copy with one bit of one item's `hmac` flipped skips exactly that item with reason CheckFailed; the other 7 import. |
| LD-146 (7) OPVault `updated` sets only the modified time | matches | Reference band entry routine (lines 148 to 164): a fresh time block (every time = now) gets `created` and `updated`, then replaces the entry's times, so last access is the import time. Larsal: last access = import time on every OPVault entry. |
| LD-146 (9) version 1 notes lose every CR | matches | Reference version 1 reader, notes routine (lines 718 to 721): split at LF, then every CR is removed from each line before the lines are joined again. Larsal removes every CR the same way. Basic test file: no CR in any notes (Python), results equal. |

## 4. Interop of the XML document

Demo vaults: `rich-v3.larsalvault` (`demo-pass-4`, 3.1) and `rich-v4.larsalvault` (`demo-pass-5`, 4.1) from testdata, copied to `/tmp/verify-e4s13/work/`.

**Larsal export, reference import.** Larsal's XML export of each vault, imported with the reference tool's `import -p -t 100` into a new vault, then opened with Larsal and exported again with Larsal's XML exporter. `diff` of the two Larsal XML documents, both vaults: nothing lost or changed. The only differences are values the reference writes on every save: the vault custom data items `_LAST_MODIFIED` (new date) and the reference's random slug item (new value), the same `_LAST_MODIFIED` item on the root group and on "Full demo entry" (new date, item order changed), and for the 3.1 vault `SettingsChanged` (the reference's save time). Ids, times, fields and protection flags, history, attachments (all 5, bytes equal), custom icons, deleted objects, Auto-Type, colors, group switches and metadata all came back the same.

**Reference export, Larsal import.** The reference tool's XML export (`export -f xml`) of each vault read with Larsal's XML import and compared with Larsal opening the vault itself: 3.1 vault equal (text times and the gzipped pool read; attachments restored), except `_LAST_MODIFIED`, which the reference's export itself changes. 4.1 vault equal except attachments, which come back empty: the reference's 4.x export writes `Ref="0"` and no pool (FEA-09.14, known). The reference tool importing its own 4.x export gives the same empty attachments, so Larsal's reading matches it.

**CSV.** Larsal's CSV export and the reference tool's `export -f csv` of both vaults are byte for byte identical (1,621 bytes each, the FEA-09.3 header, TOTP regenerated the same way).

## 5. Security proof (08-62, 09-23; AT-C01, AT-C06)

Method: the probe's global allocator looks at every block when it is freed, before it goes back to the system, and counts blocks that still hold a demo secret (a freed block holding it was not wiped). A positive control (one plain `String` copy freed) is counted, so the scan works.

Flow per file: read the file, import it with its password, build the review preview, place the result into a new vault (FEA-08.5), export the vault as CSV, XML and HTML, write each with the atomic export writer (`storage::write_export`), drop the exports, drop the vault and the file bytes.

| File | Secrets scanned | Import and placement | 3 exports | Final drop | Control |
|---|---|---|---|---|---|
| Larsal's `bw-encrypted-pbkdf2.json` (password `demo-pass`) | `enc-demo-pw`, `demo-pass` | 0 of 218 freed blocks | 0 of 113 | 0 of 19 | 1 (11 bytes) |
| the reference's encrypted Bitwarden file (password `a`) | its entry password, its TOTP secret | 0 of 252 | 0 of 135 | 0 of 25 | 1 (14 bytes) |
| the reference's Argon2id file (password `a`) | same | 0 of 270 | 0 of 110 | 0 of 25 | not run |

So no demo secret is left in freed memory by the import, placement or export. The accepted residues do not apply to this flow: F-034 is the deflate window (the .1pux reader and compressed vaults), F-053 is numbers kept as `f64` (these files hold every secret as a string). The written exports are mode 0600.

Logs and error text: `larsal-core/src/import`, `larsal-core/src/export`, `storage.rs` and `larsal-format/src/document` hold no print, log or debug-print call. Error texts seen: wrong password `wrong password`; broken JSON after a password value `not valid JSON at byte 54: a separator or closing bracket is missing`; text renamed `.1pux` `not a valid .1pux file: not a ZIP archive`; bad XML `the XML document cannot be read`. None holds a value from the file; every error type holds no text from the file (ImportError is `Copy`).

The screen half of 08-62 and 09-23 (the screen gets only the path, a dump of the running app) waits for the E5 screen layer.

## 6. Acceptance cases

FEA-08: 08-01 to 08-64 and FEA-09: 09-01 to 09-24 each have a Builder test of the same number (`fea08_NN_…`, `fea09_NN_…`; 08-32 is `fea08_32_opdata01` in opvault.rs), passed by Checker 1 and, for the crypto and secret parts, Checker 2, and they pass in the check.sh run below. This run adds the reference-file proof of section 2 and the memory proof of section 5. Parts that need the screen layer and are therefore E5's: the assistant's clicks and switching (08-01, 08-02), the preview cell and command view (08-03), responsiveness and Cancel on screen (08-11), the CSV screen (08-12, 08-22 question), the menus, question default and dialogs (09-01, 09-02, 09-08), desktop icons (09-14), and the dump of the running app (08-62, 09-23). Failing: case 08-13's new UTF-16 line (F1).

## Failures

**F1. UTF-16 without a byte order mark is read big-endian; the reference reads it little-endian.** LD-143 (1) says the card follows the reference, so FEA-08.14 and case 08-13 now say little-endian. Fix: `import::csv` Encoding UTF-16 without a byte order mark decodes little-endian (update the enum's doc comment), plus a test with case 08-13's bytes `61 00 2C 00 62 00` giving `a`/`b`. A byte order mark still wins.

## Notes for the lead (not blocking)

- **N1. Proton Pass extra field types.** Larsal compares an extra field's `type` with `totp` and `hidden` exactly; the reference ignores case (item routine, lines 152 and 158). Real exports write lower case. Proposed: compare ignoring case and say so in FEA-08.52.
- **N2. Time forms outside the card's list** (FEA-08.28). The installed 2.7.11 and a current release of the same time library both accept a one-digit zone hour (`2024-03-10T12:00:00+2:00` gives 10:00Z); Larsal refuses it. The two library releases disagree on four more edge forms, which Larsal refuses. Proposed: accept `±H:mm` too, or record the refusal as a Larsal choice.
- **N3. Plain bin group properties** (FEA-08.8). In the reference, the result's bin group that lands in a target with the bin off keeps the bin icon (43) and search and Auto-Type off; Larsal's plain group has the default icon and inherits both switches. Proposed: give it the bin icon and switches off, or leave it a plain group as L08-6 says.
- **N4. Version 1 Auto-Type line spacing** (FEA-08.59). The reference recognizes only `Auto-Type…: ` with one space and at least one character after it, and keeps further spaces in the value. Larsal also takes `Auto-Type:` with no space or with nothing after it and trims all leading white space. A notes line `Auto-Type:` alone stays in the reference's notes and is removed by Larsal. Proposed: require `: ` and a non-empty value, keep the rest as it is.

## check.sh run

`. "$HOME/.cargo/env" && scripts/check.sh`, started 2026-10-27 03:24:04, ended 03:58:03, exit 0, run once with the long fuzz runs still loading the CPU (load average about 55). The timing test `fea01_32` passed the first time, so it was not rerun.

```
G1 static ......... PASS (unsafe count 0 in 7 crates)
G2 tests .......... PASS
deny .............. PASS
audit ............. PASS
fuzz smoke ........ PASS (18 targets, 30s each)
Overall ........... PASS
```

From `target/check/test.log`: `tests/fea08.rs` 81 passed, 0 failed; `tests/fea09.rs` 24 passed, 0 failed. From `target/check/test-release.log`: `fea01_32_limits`, `fea01_32_fuzz_regressions`, `fea01_32_hostile_runs_stay_bounded` and `fea01_32_field_heavy_vaults_stay_bounded` ok. The name guard passed again after this file and the card edits were written (`scripts/check-names.sh`: PASS, 1790 files).

## Re-check 2026-10-27

Role: Verify (reference access allowed, read only; nothing copied into this folder). What was checked: the lead's fixes for F1, N1, N3 and N4 (LD-148) against the reference, on the current code. N2 stays a Larsal choice (LD-148) and was not re-run. No product code, test or card was changed.

Setup: the throwaway probe crate from the first run (`/tmp/verify-e4s13/probe/`, its own target folder, the project's current `Cargo.lock`) rebuilt against the current crates, with one new mode that parses given bytes with a chosen CSV encoding and prints the code points of each cell. Reference side: small C++ programs in `/tmp/verify-recheck/qt/` linked against the text library bundled in the installed reference app (2.7.11), the reference source at 09e34ba8, and the source of the 2.7.11 release (its git tag). The reference's CSV, Proton Pass, OPVault and version 1 imports exist only in its window, not in its command line tool, so the library run and the source are the reference evidence, as in the first run.

### F1 CSV UTF-16 without a byte order mark (FEA-08.14, case 08-13): matches

The reference 2.7.11 sets the stream decoder by name and lets a byte order mark pick the decoder (the stream's Unicode check); the source does the same with the newer decoder. Same bytes through both:

| Bytes | Chosen encoding | Reference (bundled library) | Larsal (`import::csv::parse`) |
|---|---|---|---|
| `61 00 2C 00 62 00` | UTF-16 | U+0061 U+002C U+0062 | cells `a`, `b` |
| `00 61 00 62` | UTF-16 | U+6100 U+6200 | U+6100 U+6200 |
| `FE FF 00 61 00 62` | UTF-16 | U+0061 U+0062 (mark wins, big-endian) | U+0061 U+0062 |
| `FF FE 61 00 62 00` | UTF-16 | U+0061 U+0062 | U+0061 U+0062 |
| `FE FF 00 61 00 62` | UTF-16LE | U+0061 U+0062 (mark wins over the choice) | U+0061 U+0062 |
| `61 00 62 00` | UTF-16LE | U+0061 U+0062 | U+0061 U+0062 |
| `FE FF 00 61` | UTF-8 | U+0061 | U+0061 |

Whole import: `Title,UserName` LF `ab,cd` LF in UTF-16LE without a mark, Encoding UTF-16, now gives one entry, Title `ab`, UserName `cd` (the first run: 0 entries). Code: `csv.rs` `decode` reads UTF-16 little-endian unless the file starts with `FE FF`. Test `fea08_13_decoding` holds case 08-13's bytes and passes.

### N1 Proton Pass extra field types (FEA-08.52): matches

Reference (source and 2.7.11): `type` compared with `totp` and `hidden` ignoring case; `totp` takes `data.totpUri`, every other type `data.content`; protected only for `hidden`. Larsal `proton.rs` uses an ASCII case-blind compare; for these two words that equals the reference's Unicode compare (Python over every code point: no non-ASCII character folds to t, o, p, h, i, d, e or n). Demo file with one login and seven extra fields, Larsal's result:

| Field type | Data | Larsal | Reference rule gives |
|---|---|---|---|
| `Text` | content `plain-1`, totpUri `WRONG` | `plain-1`, not protected | same |
| `Hidden`, `HIDDEN`, `hidden` | content | value, protected (all three) | same |
| `TOTP`, `tOtP` | totpUri `DEMOTOTPA` / `DEMOTOTPB`, content `WRONG` | the totpUri value, not protected | same |
| `hiddenx` | content `plain-2` | `plain-2`, not protected | same (whole word must match) |

### N3 plain bin group when the target's bin is off (FEA-08.8): matches

Reference (source `createRecycleBin`, same in 2.7.11): the bin group gets icon 43, search off and Auto-Type off; an OPVault trashed item goes there, and the whole result root is moved under the chosen group. Larsal: the reference's OPVault test folder (password `a`) placed with `import::into_group` into a vault with the bin off:

```
bin_on=false bin=None
import root "keep" children ["Login", "Credit Card", "Secure Note", "Identity", "Password", "Server", "Recycle Bin"]
plain bin: icon=43 search=Off autotype=Off entries=["Trashed Password"]
```

Test `placement_trashed_rules` asserts icon 43 and both switches off, and passes.

### N4 version 1 Auto-Type lines (FEA-08.59): matches

The installed 2.7.11 matches each notes line in full against `Auto-Type(?:-(\d+))?: (.+)` and `Auto-Type-Window(?:-(\d+))?: (.+)`, ignoring case (the source matches anywhere in a line; Larsal's start-of-line rule L08-7d is what the installed app does). The bundled library's regular expression engine on each line, and Larsal reading a demo version 1 vault (`/tmp/verify-recheck/at-lines.v1`, password `demo-v1-pass`, made by a throwaway script with openssl; Larsal's `v1::read`):

| Notes line | Reference 2.7.11 (bundled engine) | Larsal |
|---|---|---|
| `Auto-Type:` | stays in notes | stays in notes |
| `Auto-Type: ` (one space, nothing after) | stays in notes | stays in notes |
| `Auto-Type:x` | stays in notes | stays in notes |
| `Auto-Type:   {USERNAME}  ` | default sequence `  {USERNAME}  ` | default sequence `  {USERNAME}  ` |
| `Auto-Type-Window:  W one ` | window ` W one ` | window ` W one ` |
| `AUTO-TYPE-2: two  x` and `auto-type-window-2: W2` | sequence 2 `two  x`, window `W2` | association (`W2`, `two  x`) |
| empty line after a recognized line | removed | removed |
| `see Auto-Type: x` | stays in notes | stays in notes |

Larsal's result for that entry: notes `keep 1` LF `Auto-Type:` LF `Auto-Type: ` LF `Auto-Type:x` LF `after blank` LF `see Auto-Type: x`; default sequence `  {USERNAME}  `; associations (` W one `, ``) and (`W2`, `two  x`), the reference's order. Unit test `auto_type_lines` passes.

### New note (not blocking)

- **N5. Version 1 Auto-Type numbers above 2,147,483,647.** The reference reads `<n>` as a signed 32-bit number, and a number that does not fit counts as 0 (bundled library: `4294967296` and `99999999999999999999` both give 0); the line is still recognized. Larsal reads `<n>` as a 64-bit number and keeps the line in notes when it does not fit. Demo vault: `Auto-Type-0: zero` with `Auto-Type-Window-4294967296: W32` gives the reference (`W32`, `zero`) and Larsal (`W32`, ``); `Auto-Type-99999999999999999999: big` with the matching window line gives the reference notes `end` and association (`Wbig`, `big`), Larsal keeps both lines in notes and no association. Only absurd notes reach this. Proposed: a number above 2,147,483,647 counts as 0 (FEA-08.59 says so), or record it as a Larsal choice.

### check.sh

`. "$HOME/.cargo/env" && scripts/check.sh`, run once, 2026-10-27 12:24:52 to 12:46:19, exit 0 (`/usr/bin/time`: real 1288 s, user 1427 s, sys 101 s).

```
G1 static ......... PASS (unsafe count 0 in 7 crates)
G2 tests .......... PASS
deny .............. PASS
audit ............. PASS
fuzz smoke ........ PASS (18 targets, 30s each)
Overall ........... PASS
```

From `target/check/test.log`: `tests/fea08.rs` 81 passed, 0 failed (`fea08_13_decoding`, `placement_trashed_rules`, `fea08_55_v1_auto_type` ok); `import::v1::tests::auto_type_lines` ok.

### Re-check result

**Signed.** F1 is fixed and matches the reference; N1, N3 and N4 now match; N2 is a Larsal choice (LD-148). N5 is a new small difference for the lead, not blocking. The screen parts listed in section 6 stay with E5.
