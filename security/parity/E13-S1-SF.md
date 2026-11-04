# E13-S1 parity sign-off: File and crypto (SF-01 to SF-18)

Rows: the SF table in [plan/security.md](../../plan/security.md). Story: E13-S1 (final verification fleet, parity group SF).
Date: 2026-10-29. Role: Verify, group SF. I did not build any of these stories.

| Row | Result |
|---|---|
| SF-01 | **Verified** |
| SF-02 | **Verified** |
| SF-03 | Waits: needs a quiet Mac (Mac QA). Range and default verified; the unlock-time band could not be measured under today's load |
| SF-04 | **Verified** |
| SF-05 | **Verified** |
| SF-06 | **Verified** |
| SF-07 | **Verified** |
| SF-08 | **Verified** |
| SF-09 | **Verified** |
| SF-10 | **Verified** |
| SF-11 | **Verified** |
| SF-12 | **Failed** (Low): the header writer is clean, but a same-vault merge copies the reference's public id item into the target (finding 2). Quick unlock (APP-04.8) waits for E6-S3 |
| SF-13 | **Verified** for parity. App's window reminder (MOD-13.7 to .10) is not built and no story owns it (finding 3, Low) |
| SF-14 | **Verified** |
| SF-15 | **Verified** (the window app's alert itself needs a visible window: Mac QA) |
| SF-16 | **Verified** |
| SF-17 | **Verified** |
| SF-18 | **Failed** (Low): the early-kind key file note keeps direction marks in the file name (finding 4) |

## How it was run

- **Reference.** Source read only. The reference command line tool (installed 2.7.11) ran only with `HOME=/tmp/e13s1-SF-home`, on demo vaults and on copies of the reference's own test files in /tmp. Its real settings folder was never read.
- **Our tree, read only.** `cargo test -p app-crypto -p app-format -p app-core -p app-ffi -p app-cli --no-fail-fast` with `CARGO_TARGET_DIR=/tmp/e13s1-target` (11 min 33 s). App's command line tool: the debug `app` from that target.
- **Private copy.** `rsync -a --exclude target --exclude app-shots --exclude fuzz/target` to /tmp/e13s1-SF-copy, with its own `target`. Probe code lived only there: an app-core example `sfprobe` (open, save, settings apply, OTP, imports, merge), an app-ffi example that calls `start::start()`, and one app-ffi test module. The one mutation (SF-15) was made there and reverted. No product file was changed.
- **My own independent reader.** `/tmp/e13s1-SF/hdr.py`: python `hashlib`, `hmac` and the `openssl` command for AES-ECB; no App code. It lists header fields and checks a version 4 header HMAC from a key built by the reference source's formula.
- **Load.** Other agents kept the Mac busy: load average 120 to 255 on 14 cores during most runs, 35 to 50 later. This only matters for SF-03.
- **Rules.** Demo vaults and demo passwords only. No window, no pasteboard, no ssh-agent, no keychain. Every /tmp folder of mine was deleted at the end.

Test results of the full run that matter here (all pass): app-crypto `cipher` 21, `kdf` 35, `hash` 6, `mac` 8, `stream` 19, lib 47; app-format `attacks` 13, `keys` 40, `keyfile` 154, `open` 68, `version3` 51, `write_file` 53, `write_version` 32, `write_pool` 53, `write_groups` 45, `header` 78, `redteam_s2` 8, `testdata` 4; app-core `mod12` 28, `mod13` 11, `fea05` 46, `fea08` 81; app-ffi `new_vault` 11, `vault_settings` 6, `messages` 7, lib 108; app-cli lib 11, `int10` 113 of 114 (see SF-03). Two failures outside or at the edge of this group are described under "Other observations".

## SF-01 Ciphers: AES-256-CBC, ChaCha20, Twofish-CBC, read and written

**Reference.** The cipher id in the outer header picks AES-256 in CBC mode, Twofish-256 in CBC mode or ChaCha20; it reads and writes all three, and its start-up self-test checks AES-256-CBC, Twofish and ChaCha20 known answers.

**Ours.** The known-answer tests pass today (`cipher` 21, `stream` 19). Then the full matrix both ways: the probe opened `testdata/rich-v4.appvault` and saved it 18 times with `app_format::save`: 3 ciphers × 3 key derivations × gzip on and off (AES-KDF 200,000 rounds; Argon2d 2 iterations, 64 MiB, 2 lanes; Argon2id 3 iterations, 32 MiB, 4 lanes).

1. **App writes, the reference reads.** `db-info` names the cipher and KDF that were set, for all 18 files. `scripts/testdata/interop_compare.py` (the reference exports the original and the copy) gives `equal 18 of 18`, each `export equal (10 entries, 3 history items), 5 of 5 attachments byte-equal`.
2. **The reference writes, App reads.** A copy of each file got a new group from the reference (`mkdir`), so the reference wrote every combination itself. App opened all 18 (the probe shows `version 4.1`, the cipher, the KDF and its numbers, the compression and 8 groups). `app ls -R -f` and the reference's `ls -R -f` are identical for 18 of 18, once App's `(empty group)` is read as the reference's `[empty]` (a wording difference already listed in INT-10).

```
aes-aeskdf-gz | Cipher: AES 256-bit KDF: AES (200000 rounds)
chacha-argon2d-raw | Cipher: ChaCha20 256-bit KDF: Argon2d (2 rounds, 65536 KB)
twofish-argon2id-gz | Cipher: Twofish 256-bit KDF: Argon2id (3 rounds, 32768 KB)
equal 18 of 18
ls -R -f identical after the [empty] wording: 18 of 18
```

**Result: verified.**

## SF-02 Key derivation: Argon2d, Argon2id, AES-KDF, settings in the file

**Reference.** The KDF and its parameters live in the header's KDF map: AES-KDF (rounds, seed), Argon2d and Argon2id (iterations, memory, lanes, version, salt).

**Ours.** RFC 9106 and AES-KDF tests pass (`kdf` 35). The SF-01 matrix covers all three KDFs both ways, and the reference's `db-info` shows the exact numbers App wrote. My own header reader shows field 11 holding the KDF id and a 32-byte seed or salt in all 18 files.

**Result: verified.**

## SF-03 KDF benchmark to a target unlock time, 1 s default, 0.1 to 5 s

**Reference (source).** `Kdf::DEFAULT_ENCRYPTION_TIME` 1,000 ms, `MIN_ENCRYPTION_TIME` 100, `MAX_ENCRYPTION_TIME` 5,000; the settings slider runs in steps of 100 ms; `Argon2Kdf::benchmark` scales one timed run, `AesKdf::benchmark` times 3 runs of 1,000,000 rounds.

**Ours.**
- Range and default, side by side:

```
App -t 99:   app: the unlock time must be 100 to 5000 ms.
ref -t 99:   Target decryption time must be between 100 and 5000.
App -t 5001: app: the unlock time must be 100 to 5000 ms.
ref -t 5001: Target decryption time must be between 100 and 5000.
```

  `-t 100` passes the range check in both (each then stops at the key step, as no key was given). In code: app-crypto `TARGET_MS = 100..=5_000`; the wizard measures for 1,000 ms; the window's time slider is `range: 1...50` tenths of a second (`NewVaultParts.swift:46`) and the settings view clamps to 100 to 5,000.
- The band tests (`benchmark_argon2id_default_lands_in_band`, `benchmark_aes_kdf_lands_in_band`, median of 5 unlocks within 1,000 to 1,200 ms) ran three times. They fail on today's Mac, in both directions, because the measured run and the timed unlocks see different loads:

| Run | Load average | AES-KDF | Argon2id |
|---|---|---|---|
| 1 | 173 | 15,725,975 rounds, 1,192 ms, pass | 12 iterations, 1,886 ms, fail |
| 2 | 166 | 40,068,052 rounds, 3,088 ms, fail | 10 iterations, 2,034 ms, fail |
| 3 | 35 to 47 | 59,279,053 rounds, 4,099 ms, fail | 13 iterations, 1,167 ms, pass |

- Side by side, `db-create -t 1000` then three unlocks (load about 135): App (Argon2id, 9 iterations, 64 MiB, 4 lanes) 2.44, 2.32, 2.14 s; the reference (AES-KDF, 19,354,838 rounds) 0.87, 0.75, 0.67 s. `/usr/bin/time` on App's unlock: real 1.77 s, user 0.49 s: the process got about a quarter of a core.

**Result: waits for a quiet Mac (Mac QA).** Nothing here shows App weaker; the timing simply cannot be proven while other agents load the Mac. Next step: on an idle Mac, `cargo test --release -p app-crypto --test kdf -- --ignored benchmark_` and the side-by-side above.

## SF-04 Composite key: password, key file and hardware key in any combination

**Reference (source).** `CompositeKey::rawKey` hashes the password part (SHA-256 of the password), the key file part, then, for version 4, `SHA-256(response)` of each challenge-response key, all in one SHA-256. The challenge is the KDF seed, padded to 64 bytes with the pad length; the answer is the 20-byte HMAC-SHA1.

**Ours.** The probe wrote 7 vaults from `testdata/password-only.appvault` with AES-KDF 10 rounds, one per combination, with `testdata/key-xml-v2.appkey` and a software hardware key (my own HMAC-SHA1 `ChallengeResponse` in the probe, secret `0102…14`).

1. **Independent key check** (my python reader; composite built by the reference's formula; AES-KDF through `openssl`): every header hash right and every header HMAC matches, for all 7. Negative controls: the wrong password, or a dropped hardware part, gives `no match`.

```
P.appvault: header sha256 ok, header HMAC with the reference composite: MATCH
F … H … PF … PH … FH … PFH.appvault: … MATCH   (7 of 7)
PFH.appvault with the hardware part left out: no match
```

2. **App opens each with its parts, and refuses when one part is missing:** `P`, `F`, `H` alone give `NoCredentials` without their part; for `PF`, `PH`, `FH`, `PFH` every dropped part gives `WrongKey`.
3. **The reference opens the combinations it can take:** `P`, `F`, `PF` directly; `H` and `PH` with a 20-byte file holding the answer (the reference hashes such a key file with SHA-256, which is exactly its hardware part). All exit 0; without the key file, without the answer, or with the other vault's answer: exit 1. The reference tool cannot take a key file and an answer together without a real key, so `FH` and `PFH` rest on point 1.
4. **The reference writes, App reads.** The reference made `P`, `F` and `PF` vaults (`db-create -p`, `--set-key-file`; it writes version 3.1 with AES-KDF); App's `ls` opens each, and `PF` without the key file gives the wrong-key message.
5. Today's tests: `fmt_04_5_a_and_b`, `fmt_04_6_e_vector_hk`, `fmt_04_hardware_key_vault_opens` (the reference's hardware-key test vault) pass.

**Result: verified.**

## SF-05 Header hash and header HMAC before decrypting

**Reference.** It checks the header's SHA-256, then the keyed header HMAC; a wrong key fails at the HMAC ("Invalid credentials …").

**Ours.** AT-A01 and AT-A02 pass today (`at_a01_wrong_credentials`, `at_a01_version_4_wrong_password_decrypts_nothing`, the three `at_a02_*_header_byte_sweep`). Writing: my python reader confirms the hash and HMAC in all 7 SF-04 files. One byte flipped in a copy of an App-written 4.1 vault, both tools with the right password:

| Byte | App | Reference |
|---|---|---|
| compression flag (40) | not supported | Unsupported compression algorithm |
| master seed (50) | damaged | Header SHA256 mismatch |
| stored hash (header end + 5) | damaged | Header SHA256 mismatch |
| stored HMAC (header end + 37) | wrong password, key file or security key | Invalid credentials were provided |
| wrong password, file intact | wrong password, key file or security key | Invalid credentials were provided |

**Result: verified.**

## SF-06 Block HMAC and index (version 4); hashed blocks (version 3)

**Reference.** Each version 4 block carries an HMAC over its index, length and data; version 3 uses SHA-256 hashed blocks.

**Ours.** AT-A03 and AT-A04 pass today (`at_a03_version_4_payload`, `at_a03_version_3_payload`, `at_a04_truncation`, `at_a04_rich_v4_truncation`), with the block tests in `keys` and `version3`. Same flip run:

| Change | App | Reference |
|---|---|---|
| first block's HMAC, early data, later data | damaged | Invalid inner header id size |
| file cut 50 bytes into the block stream | damaged | Invalid inner header id size |

Writing: the reference reads every file App wrote today (SF-01, SF-04, SF-08).

**Result: verified.**

## SF-07 Fresh random values on every save; the key-unchanged guard

**Reference (source).** Each save draws a new master seed, IV, KDF seed and inner stream key, and adds a random padding item. `Database::writeDatabase` keeps the old transformed key only when the key is empty, so its "key not transformed" guard catches only that case.

**Ours.** Tests pass today: `cry_03_t10_at_b03_ten_thousand_saves` (AT-B03), `cry_03_t1` to `t9`, `t11`, `t14` to `t16`, and the guard `tests::cry_03_t21_key_change_check` (CRY-03.16, App goes further). Independent check: 40 resaves (20 ChaCha20 AES-KDF, 20 AES Argon2id) read with my python reader:

```
master_seed lengths [32] distinct 40 of 40
iv lengths [12, 16] distinct 40 of 40
kdf_seed lengths [32] distinct 40 of 40
distinct across kinds 120 of 120
```

**Result: verified.**

## SF-08 Protected fields encrypted again with a stream cipher

**Reference.** Protected values are encrypted with the inner stream (ChaCha20 in version 4, Salsa20 in version 3) and written as base64.

**Ours.** `row_11_22_protected_read`, `row_11_23_protected_write_and_keystream`, `t09_02_fmt_09_4_inner_header_on_write`, `t09_30`, `t09_31` pass today. The G4 run in the private copy (`REF_CLI=<reference CLI> scripts/interop.sh`), whose comparison covers every value and its protection flag:

```
     rich-v3: version 3.1 saved as 4.0
PASS rich-v3.appvault: export equal (10 entries, 3 history items), 5 of 5 attachments byte-equal
     big-10000: version 3.1 saved as 4.0
PASS big-10000.appvault: export equal (10000 entries, 0 history items), 0 of 0 attachments byte-equal
interop: 12 of 12 cases pass
```

The 18 matrix files of SF-01 add the same comparison with every cipher.

**Result: verified.**

## SF-09 Protection flags on save; OTP and passkey fields always protected

**Reference (source).** The XML writer protects a standard field when its vault-wide flag is on, and any field whose own flag is set. The OTP setter and the passkey import set their fields protected (credential id, private key, user handle); the passkey user name and relying party are not.

**Ours.** Through App's real paths, then read in the reference's XML export:
- `settings::apply` with the field protection page all on: the reference shows `ProtectTitle`, `ProtectUserName`, `ProtectURL`, `ProtectNotes` True and protects every Title (12), UserName (6), URL (1), Notes (2), Password (10). All off: only Password (always on, MOD-12.17), the custom field that had its own flag, and `otp`.
- `totp::write` on an entry without one-time password: the new `otp` value is protected in the reference's export, and the reference's `show -t` prints a code for it (exit 0).
- The reference's passkey JSON test sample imported by App's JSON reader into a new vault: credential id, private key and user handle protected; user name and relying party not.
- `row_14_34_passkey_field_protection`, `mod12_16_field_protection_page`, `mod12_17_passwords_always_protected`, `mod12_15_flags_take_effect_on_save` pass today.

**Result: verified.**

## SF-10 Every key file kind; new key files random and owner read-only

**Reference (source).** `FileKey::create` writes the XML 2.0 form only for a name with the XML key extension, else 128 random raw bytes, then sets the file to owner read.

**Ours.**
- All the reference's key-file test vaults (raw 32 bytes, 64 hex, hashed, XML 1.0, XML 2.0, the 128-byte protected sample): App's `ls -R` equals the reference's for 6 of 6. The three broken key files fail in both: App says damaged (twice) and "its built-in check failed"; the reference says "Unexpected key file data" (twice) and "Checksum mismatch".
- Created by App (`app db-create --set-key-file new-app.appkey`): `-r-------- 278`, XML 2.0, 32 data bytes, check value right; the reference opens the vault with it (exit 0). Given an existing key file, App reads it and does not rewrite it (same mode and size afterwards).
- Created by the reference: any other name gives `-r-------- 128` raw bytes; the XML key extension gives the 278-byte XML 2.0 form; App opens both vaults.
- `at_a12_key_file_attacks` and `keyfile` 154 pass today.

**Result: verified.** App makes only the XML form, as LD-31 says.

## SF-11 Compression inside the encryption

**Reference.** Header field 3: 0 none, 1 gzip; the payload is compressed, then encrypted.

**Ours.** The SF-01 matrix: field 3 read independently is 1 in the 9 gzip files and 0 in the 9 others; both directions equal. `t08_18_fmt_08_9_gzip_on_write`, `t08_19_fmt_08_10_compression_off`, `at_a06_decompression_bomb_default_limit` and `at_a06_decompression_bomb_lowered_limit` pass today.

**Result: verified.**

## SF-12 Public header data free of secrets; no public id added

**Reference (source).** The clear header can hold a public name, colour and icon, and the quick unlock code adds a random public id item when it looks up a key (`Database.cpp` around line 1172). Its merge (`Merger::mergeMetadata`) never touches public header data.

**Ours.**
- Header writer: all 18 matrix files and all 7 SF-04 files hold fields `[2, 3, 4, 7, 11, 0]` and nothing else. `d50_fmt_03_23`, `c51_fmt_02_29`, `d58_fmt_03_23` pass today. No code in app-format, app-core or app-ffi makes the public id.
- **Merge (fail).** `merge.rs:1228` takes every source item whose name starts with the 12-byte public prefix, which includes the public id item, not only the name, colour and icon of MOD-11.19. Probe: the same vault twice, the source copy given the public id item and settings one hour newer:

```
CommandLine: target public id items before 0, after merge 1
Window: target public id items before 0, after merge 1
```

  So App adds the id to a file that did not have it (APP-04.8: "never adds or uses"). The id is public by design and both copies are the same vault, so this is not a weakness against the reference: Low (finding 2).
- Quick unlock is not built yet (E6-S3, todo, needs a signing team), so the "never uses" side waits for it.

**Result: failed (Low).**

## SF-13 Key change reminder and force settings kept; App reminds and forces

**Reference (source).** The reminder and force days and the change time are read and written with the vault, but no code outside the reader, writer and metadata uses them: it never reminds or forces.

**Ours.** `settings::apply` set "recommend after 30 days" and "force after 365" (or 60), `settings::key_changed` set the change time to 2026-05-28, then a save. The reference's export shows `MasterKeyChangeRec 30`, `MasterKeyChangeForce 365` (60) and that change time. On unlock the reference prints nothing; App's command line tool goes further (MOD-13.16):

```
Note: a master key change is recommended (last changed 153 days ago, recommended every 30 days)
Note: this vault requires a master key change (last changed 153 days ago, required every 60 days); use the vault edit command
```

`mod13` 11 pass today. The window side (MOD-13.7 to .10: the check after unlock, the forced prompt, the notice) is not in app-ffi or the Swift screens, and no story in plan/epics.md owns it (E4-S14 is Done for app-core only).

**Result: verified for parity** (App keeps and records what the reference does; App never does less). The window extra is finding 3, Low.

## SF-14 Changing cipher, KDF and cost later

**Reference (source).** The settings page warns above 10,000 Argon2 iterations and below 100,000 AES-KDF rounds, Cancel by default.

**Ours.** `settings::apply` changed rich-v4 to Twofish, Argon2id 4 iterations 32 MiB 2 lanes, history 2 items, and saved. The reference shows `Cipher: Twofish 256-bit`, `KDF: Argon2id (4 rounds, 32768 KB)`, `HistoryMaxItems 2`, at most 2 history items per entry (3 before). A second apply with 1 KiB memory was refused (`Confirm(BelowSafeMinimum)`) and left the encryption as it was (`unchanged: true`). `mod12` 28 pass today, among them `mod12_kdf_warnings_and_refusal`, `mod12_02_apply_is_all_or_nothing`, `app07_9_safe_minimum_asks_before_the_slow_warning`.

**Result: verified.**

## SF-15 Start-up self-test, refuse to start on a wrong answer

**Reference (source).** `Crypto::init` runs SHA-256, SHA-512, AES-256-CBC, AES-KDF, Twofish, Salsa20 and ChaCha20 known answers; both the app's and the command line tool's `main` stop with an error when it fails.

**Ours.** App runs those seven plus HMAC-SHA-256 and Argon2id, in the app (`start.rs` step 9) and the tool (`main.rs` step 5). Today: `app11_10_each_wrong_answer_stops_the_run_at_that_check`, `app11_10_d_every_check_passes`, `app11_10_self_test_passes_and_m11_02_names_the_check`, `int10_1_a_self_test_failure_before_any_prompt` pass. Mutation in the private copy (the SHA-256 expected value's first digit `2` → `3`), no test hook used:

```
window start probe, unchanged code: LAUNCH Run
window start probe, mutated:        App cannot start: a self-check of its encryption code failed. SHA-256 gave a wrong answer.
                                    LAUNCH Refuse { message: "…SHA-256 gave a wrong answer.", alert: false }
app ls <vault>, mutated:            App cannot start: … SHA-256 gave a wrong answer.   exit 1 (no password prompt)
app generate, mutated:              same message, exit 1
```

`alert: false` because the probe ran with the test instance folder set; in a normal launch the Swift side shows the alert and exits 1. That alert needs a visible window (Mac QA). The mutation was reverted (`diff -q` against the tree: equal).

**Result: verified.**

## SF-16 Master key guards

**Reference (source).** No-password and weak-password questions with Cancel as default, an optional minimum quality, no key with no part, not the vault as its own key file, warnings for a vault-like key file and the old key file format.

**Ours.** Today `new_vault` 11, `vault_settings` 6, `fea05_28_master_password_minimum`, `fea05_29_master_password_warning`, `int10_13_b_vault_as_its_own_key_file`, `wizard::tests::fmt18_24_vault_like_names` pass. They cover M07-21 (no password), M07-23 (weak), M07-22 (below the minimum, T31 and MOD-12 T18), M07-24 (no part), M06-30 (the vault itself), M06-31 (vault-like name) and the early-kind note. In `QuestionCard` Cancel carries `.keyboardShortcut(.defaultAction)`. The screens were proven offscreen in E5-S8 (Done 2026-10-28). Side by side in the command line tools:

| Case | App | Reference |
|---|---|---|
| no key part | "a vault needs a password, a key file or both" | "No key is set. Aborting database creation." |
| vault as its own key file | refused before anything is written | writes a 128-byte key file under the vault's name, then "Existing file … is not writable", exit 1 |
| XML 1.0 key file | note: an early kind of key file, `db-edit --set-key-file` moves to a new one | warning: an old key file format, consider generating a new key file |
| a vault file as key file of a new vault | accepted (command line, as the reference) | accepted |

**Result: verified.** App is stricter in the second case.

## SF-17 Encrypted import files

**Reference (source).** OPVault: PBKDF2-SHA512, AES-256-CBC, HMAC-SHA256 checked with `actualHmac != hmacSig` (`OpData01.cpp`). The encrypted JSON export: PBKDF2-SHA256 or Argon2id, HMAC checked with `!=` on base64 text; `kdfIterations` and `kdfMemory` used as read. Version 1 files: AES-256 or Twofish, AES-KDF with the rounds as read.

**Ours.** App's readers on copies of the reference's own encrypted test samples, with the passwords its tests use:

| Sample | App |
|---|---|
| OPVault test folder, password `a` | 8 entries in 7 groups; the reference test's two password checks equal; wrong password `WrongPassword` |
| encrypted JSON, PBKDF2 | 1 entry; wrong password `WrongPassword` |
| encrypted JSON, Argon2id | 1 entry; wrong password `WrongPassword` |
| version 1 basic | 5 entries in 7 groups, "Test entry" password as the reference test expects; wrong password `WrongCredentials` |
| version 1 Twofish, composite key, three key file kinds, CP-1252 password | each opens with root plus one group, as the reference tests expect; composite without its key file `WrongCredentials` |

Bounded costs (App goes further): the PBKDF2 export with `kdfIterations` 2,147,483,647, the Argon2id export with 4 GiB memory, and with 1,000,000 iterations each gave `ERR KdfCost` at once (`real 0.00`). Constant time (App goes further): every import MAC check goes through `mac::verify_hmac_sha256` → `tags_equal` → `secret::ct_eq` (`subtle`); version 1's content hash uses `ct_eq`. `fea08` 81 pass today. The AT-B05 timing test belongs to the E13-S2 attack group.

**Result: verified.**

## SF-18 No vault or key file text in messages

**Reference.** One header error prints the raw cipher id bytes; one key file error prints the key file's version text.

**Ours.** `f039_key_file_version_text_in_error`, `t40_app_06_18_crafted_files_show_no_file_text`, `t40_app_06_18_no_secret`, `m06_texts_match_the_table`, `t41_app_06_18_names` pass today. Side by side:

| Crafted input | App | Reference |
|---|---|---|
| key file version `9.9 CALL-THIS-NUMBER-555` | "has a version App cannot read" | "Unsupported key file version: 9.9 CALL-THIS-NUMBER-555" |
| cipher id bytes changed to `41 42 …` | "uses a file version or setting that App does not support yet" | prints the changed id `{4142f2e6-…}` and "Unsupported cipher" |
| key file name with U+202E, damaged | the open error shows the name without the mark | |

**Fail.** The early-kind key file note keeps the mark. Probe test in the private copy, `wizard::choose_key_file` with an XML 1.0 key file named `evil` U+202E `gpj.appkey`:

```
NAME "evil\u{202e}gpj.appkey"
NOTE Some("\"evil\u{202e}gpj.appkey\" is a key file of an early kind. It still works, …")
```

`session::read_key` (`session.rs:1014`) returns `file_name(&path)` uncleaned; `choose_key_file` builds the note from it (`wizard.rs:767`), and `NewVaultView.swift:287` shows it. Only errors go through `messages::for_open_error`, which cleans.

**Result: failed (Low, finding 4).**

## Findings

| # | Severity | Area | Steps (demo data) | Smallest fix |
|---|---|---|---|---|
| 1 | Low | app-cli `db-create` (SF-03) | `int10_12_d_end_of_input_is_the_empty_password` failed once in the full run under load average about 200 ("could not save e.appvault: the vault could not be written"), then passed alone. Likely cause, not proven: `write_vault` tunes with a wall clock, then `save` calibrates again with a host that has no speed record; a load swing between the two can put the estimate in the ask band, and `Saved::Ask` is reported as a write failure | Pass the benchmark's own record to `save` (`host.argon2_record` or `aes_record = Some(b.record)`), as the wizard does |
| 2 | Low | app-core merge (SF-12, APP-04.8) | Same vault twice, source given the public id item and newer settings, `merge::merge` (CommandLine or Window): the target gets the item (0 → 1) | Filter `merge.rs:1228` and `settings_differ` to the three display names (MOD-11.19), not the 12-byte prefix |
| 3 | Low | MOD-13.7 to .10 (SF-13) | A vault with "force after 60 days" and a change 153 days ago: the command line tool asks for a change, the window opens it with no prompt or notice; no story in plan/epics.md builds the window part | Name a story for MOD-13.7 to .10, or note in the row that App's extra is command line only for now |
| 4 | Low | app-ffi key file note (SF-18, APP-06.18) | Choose `testdata/key-xml-v1.appkey` copied as `evil` U+202E `gpj.appkey` in the wizard: the early-kind note and the key file name keep U+202E | `session.rs:1014`: return `messages::clean_name(&name)` |

No row is weaker than the reference.

## Other observations (other groups)

- app-ffi `ssh` `int06_22_unlock_adds_off_the_calling_thread_and_mi06_18_names_the_failures` failed in the full run: "unlock waited for the agent: 1.361316875s" under load average about 200. Not an SF row; for the SI group.
