# E5-S8 New vault wizard and vault settings: Verify proof

Story: E5-S8 New vault wizard and vault settings (plan/epics.md). Checks: a new vault opens in the reference CLI; encryption changes re-encrypt on save.
Cards: APP-07, MOD-12 (MOD-12.22), CRY-02.14 and CRY-02.22 to CRY-02.28, CRY-01.19, FMT-18.20 to FMT-18.24, FEA-05.7, FEA-05.20, FMT-16. Decisions: LD-72, LD-98, LD-99, LD-163 (4), LD-167, LD-210.

## Round 2 (2026-10-28): signed

Verify agent, round 2. I did not build or check this story. Round 1 (failed, 3 items) is kept below as history.

**Verdict: signed.** All three round-1 fails are closed:
- **Fail 1.** S-CFG-02 is now read on both screens. Proof below, at every minimum from 0 to 4.
- **Fails 2 and 3.** The lead accepted the two card-word parity differences in LD-210. I wrote that acceptance into design/parity/tools/notes.mjs, narrowly and with proof. Both story checks pass again on today's code.

| Check | Result |
|---|---|
| A. Design parity, section `vault` and the two APP-07 dialogs | **vault 8 of 8 PASS, dialogs-weak-vault-password and dialogs-create-key-file PASS**, light and dark. Missing strings: 0. Boxes and text runs more than 2 pt off: 0. Controls: 89, 0 without a name. Static tokens: 45 of 45. Contrast: 42 pairs, the lowest 4.87:1. Step 2 dark is 7.07 %, with 1.24 % outside the accepted areas (LD-210); with the 20 pt shift undone, it differs by 1.66 %. 18 of 20 shots are byte-equal to the builder's. Report: [design/parity/vault/report.md](../../design/parity/vault/report.md) and report.html. |
| B1. A wizard vault opens in the reference CLI | **PASS.** I made 6 vaults through the app-ffi calls the Swift model makes: Recommended Argon2id; Custom Argon2id with Twofish; Custom Argon2d with ChaCha20; Custom AES-KDF with AES; password only; key file only. Each key-file vault got a new key file. 12 files in all (each vault fresh and after a group save): every one opens in REF_CLI with exit 0. REF lists the same name, description, groups, cipher, KDF numbers, recycle bin, history limits, protection flags, maintenance days, key change values and unlock time item as our reader. |
| B2. Encryption changes re-encrypt on save | **PASS.** Two runs through `VaultSettings`. In each I changed the cipher, the KDF and its parameters, the password and the key file, then saved. Changed in the header: cipher id, KDF id and parameters, salt, master seed and IV. Old credentials and every old/new mix fail in both tools (M06-06; REF exit 1, "Invalid credentials … (HMAC mismatch)"). Only the new pair opens. |
| B3. APP-07 and MOD-12 cases | Every case the drawn screens reach passes, **APP-07 T31 and MOD-12 T18 included**. Cases for controls Option A does not draw wait for a mockup addition. Table in section R3. |
| B4. Secrets (rule 4) | **PASS.** A memory scan of the test process finds each typed master password while typed. After lock, close and Cancel: 0 UTF-8 and 0 UTF-16 copies. While the new vault is open, 1 copy sits in Rust's save key parts, as designed. |
| B5. Mutations (private copy) | **10 mutants: 6 caught by the builder's tests, all 10 by builder plus Verify tests.** Both S-CFG-02 sites (M1, M2) are caught by the builder's new tests. Three gaps are advisories, not fails (R7 advisory 1): the boundary mutants M3 and M4, and the Swift notice mutants S1 and S2, are caught only by my drivers. |

### R0. Setup and rules

- **Private copy.** At 18:03: `rsync -a --exclude /target --exclude /app-shots --exclude /fuzz/target` from the tree to /tmp/e5s8-verify3-copy. `target` there was a link to /tmp/e5s8-verify3-target (`CARGO_TARGET_DIR` too). I used `-derivedDataPath /tmp/e5s8-verify3-dd`. Scratch files went to /tmp/e5s8-verify3-work and scripts to /tmp/e5s8-verify3-scripts.
- **A leftover I did not touch.** /tmp/e5s8-verify2-copy, -target and -work were not mine: made at 16:20, a build log stopped at 16:21, no process using them. I did not touch them (rule 11), so I used the prefix `verify3`.
- **The code checked.** `shasum` of 21 files was taken at 18:03, before the copy. These were all equal at the end:
  - `wizard.rs`, `vault_settings.rs`, app-platform `macos/system.rs`;
  - `NewVault*.swift`, `VaultSettings*.swift`;
  - `NewVaultTests.swift`, `VaultSettingsTests.swift`, `tests/new_vault.rs`, `tests/vault_settings.rs`.

  The E5-S8 Swift files were last changed at 14:55, before round 1, so round 1's Swift proof covers the same code.
- **Shared files changed by another story after my copy.** At 18:15 to 18:20, E5-S10 (saving, in progress) changed `edit.rs`, `session.rs` and `lib.rs`: it moves `Session::save` into a new `saving.rs`. At 18:28 I ran the builder's E5-S8 Rust tests on the tree's code: `new_vault` 11 passed, `vault_settings` 6 passed, lib `app07`/`cry02_14` 3 passed. E5-S10's own Checker and Verify should keep them green (open issue 2).
- **My own tests lived only in the copy.** `crates/app-ffi/tests/verify_e5s8.rs` (drivers b1, b2, b3, b5) and `macos/AppTests/VerifyE5S8Tests.swift` (suite `VerifyE5S8Tests`), both deleted with the copy. I edited no product code.
- **Rule 10.** No window was ordered front. The save panel, the folder panel and the key file panels were all replaced by the tests' seams. Chrome ran headless. The general pasteboard was never read or written by me. The one ScreenTests issue was the builder's own change-count check (LD-206).
- **Rule 5.** Demo vaults only: the ones my drivers made, and copies of testdata `option-a-family`, `option-a-personal` and `password-only`. Demo passwords only: `Verify-demo-E5S8-r2-wizard-58`, `Verify-demo-E5S8-r2-changed-27`, `Verify-demo-E5S8-r2-cancel-39`, `password`, `password1`, `Tr0ub4dor&3`, `correct horse battery`, `kT7#pQ2vZ9mW4x`, `demo-pass-1`, `demo-pass-9`.
- **The reference CLI.**
  - Version: `REF_CLI --version` prints `2.7.11`.
  - Home: every vault run used `HOME=CFFIXED_USER_HOME=/tmp/e5s8-verify3-work/refhome`, so the reference's settings went there, not to the owner's.
  - Commands: only `db-info`, `ls -R` and `export -f xml`. The export went into a script that printed only meta values, custom data keys as hex, and group names; wizard vaults hold no entries.
  - No clip command, no window, no real file.
  - **A slip.** One `REF_CLI db-info --help` call (help text only, no vault) ran without the throwaway home.
- **Rule 11.** I stopped no process. Load average was 6 to 36.

### R1. Part A: design parity (BUILD-AND-VERIFY.md, "Prompt for the Verify fleet")

1. `node design/option-a/tools/export-reference.mjs` in the copy:
   - printed `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`; `56.225 total`, exit 0;
   - the manifest is byte-equal to the tree's;
   - 18 of the 20 E5-S8 references are byte-equal. `light/vault-new-vault-step-3` and `dark/vault-vault-settings-security` differ in bytes only: pixelmatch (threshold 0.1) finds `0` and `0` changed pixels.
2. `scripts/build-core.sh` printed `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`; `1:40.38 total`, exit 0.
3. `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e5s8-verify3-dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` (log copied to target/parity/behaviour.log):
   - `✔ Suite NewVaultSnapshotTests passed after 40.582 seconds.`
   - `✔ Suite VaultSettingsSnapshotTests passed after 50.862 seconds.`
   - `✔ Suite NewVaultBehaviourTests passed after 63.230 seconds.`
   - `✔ Suite VaultSettingsBehaviourTests passed after 27.147 seconds.`
   - `✔ Suite VerifyE5S8Tests passed after 37.393 seconds.`
   - `✘ Test run with 167 tests in 29 suites failed after 83.637 seconds with 1 issue.` The one issue was `ScreenTests.swift:210:9: Expectation failed: NSPasteboard.general.changeCount == before`. That is the general pasteboard change count (LD-206): something else on the Mac copied during the run.
   - The same suite alone: `xcodebuild … test-without-building -only-testing:AppTests/ScreenTests` → `✔ Test run with 9 tests in 1 suite passed after 3.913 seconds.`, `** TEST EXECUTE SUCCEEDED **`.
4. `node design/parity/tools/mockup-dom.mjs vault,dialogs` printed `light: 29 frames, 319 text runs` and `dark: 29 frames, 319 text runs`.
5. `swift design/parity/tools/ocr.swift app-shots/{light,dark}/vault-*.png app-shots/{light,dark}/dialogs-*.png` read 22 images per theme.
6. **The general page's path (live value).** The copy is outside the home folder, so the general shots showed a /private/tmp path, and notes.mjs's live rule expects `~/…`.
   - I rendered that suite again with `TEST_RUNNER_HOME=/private/tmp/e5s8-verify3-target … test-without-building -only-testing:AppTests/VaultSettingsSnapshotTests`.
   - The general tree then reads `~/option-a/settings-shots/Passwords/Personal.appvault`.
   - As in round 1, the security frame of that run printed `The new key file "personal.appkey" was not written: the folder no longer exists`. Nothing was written: `ls /Users/…/option-a` says No such file.
   - I kept only the two general shots from that run and put the four other pages back from the normal run (step 3).
7. `node design/parity/tools/compare.mjs vault` and `dialogs`, with notes.mjs as it was, printed `vault: 7/8 PASS` (`vault-new-vault-step-2 FAIL L 2.63% (2.21) D 7.07% (6.65)`) and `dialogs: 13/14 PASS` (`dialogs-weak-vault-password FAIL … 3 box(es) off by more than 2 pt (button "Use It Anyway" Δ 0,-44,25,0; button "Choose Another" Δ 59,-44,-59,0; dialog "This password is easy to" Δ 0,0,0,-44)`). These are the builder's numbers.
8. **LD-210 written into notes.mjs.** LD-210 says compare.mjs should count these differences as accepted. That rule was not in notes.mjs, so I added it with two small exact edits to the tree's design/parity/tools/notes.mjs, re-read just before:
   - **`vault-new-vault-step-2`: `mask: [[36, 200, 648, 23], [36, 288, 648, 22]]`.** These are only the two strips where the Recommended card's accent fill moved. I measured the card's edges in the images: drawn at x 36 to 684, y 200 to 290 pt; in the app at y 221 to 309.5 pt.
     - **Proof that the shift explains the rest.** I moved the app's rows 200 to 660 pt up by 20 pt and compared again (pixelmatch threshold 0.1, anti-aliasing ignored):
       - `light/vault-new-vault-step-2.png: whole image 2.63 % -> 1.72 % …; band 180-640 pt alone 3.15 % -> 1.72 %`
       - `dark/vault-new-vault-step-2.png: whole image 7.07 % -> 1.66 % …; band 180-640 pt alone 10.14 % -> 1.67 %`
     - The diff image of the corrected dark frame shows only glyph edges and the accepted M07-05 words.
     - Text, tokens and geometry did not change: 0 missing strings, 0 colour issues, 0 boxes and 0 text runs off after the recorded 20 pt shift.
   - **`dialogs-weak-vault-password`: `geoSkip: ['button:Use It Anyway', 'button:Choose Another', 'dialog:This password is easy to']`.**
     - The sheet is 44 pt shorter, with x, y and width equal (Δ 0,0,0,-44).
     - "Use this password" keeps the drawn left edge (Δx 0, 25 pt wider).
     - Cancel keeps the drawn right edge (Δx +59, width −59, so x + width is equal).
     - Both buttons sit 44 pt higher.
     - The images are 460 × 148 pt in the app against 460 × 192 pt drawn, so compare.mjs measures no pixels or colour shares here. By eye, the icon tile, title style, the outlined left button and the filled default right button match the mockup.
   - `node --check design/parity/tools/notes.mjs` → ok. Later, another agent (E5-S10) added its own notes. My two entries are still there (`grep -c "LD-210, Verify E5-S8 round 2"` → `2`).
9. `node design/parity/tools/compare.mjs vault` with the final notes:

```
vault: 8/8 PASS
vault-new-vault-step-1                         PASS                   L 2.13% (1.83) D 2.83% (2.53)
vault-new-vault-step-2                         PASS                   L 2.63% (1.2) D 7.07% (1.24)
vault-new-vault-step-3                         PASS                   L 2.36% (1.16) D 3.24% (2.02)
vault-vault-settings-general                   PASS                   L 1.89% (1.69) D 1.89% (1.69)
vault-vault-settings-security                  PASS                   L 1.77% (1.61) D 1.76% (1.61)
vault-vault-settings-recycle-bin               PASS                   L 0.68% (0.63) D 0.66% (0.62)
vault-vault-settings-history                   PASS                   L 0.95% (0.85) D 0.93% (0.84)
vault-vault-settings-browser-keys              PASS                   L 1.08% (0.9) D 1.07% (0.9)
```

   `node design/parity/tools/compare.mjs dialogs` → `dialogs: 14/14 PASS`, `dialogs-weak-vault-password PASS L -% (-) D -% (-)`, `dialogs-create-key-file PASS L 2.29% (2.29) D 2.16% (2.09)`.
10. **Into the tree.**
    - The copy's design/parity/vault/ (report.md, report.html, findings.json, app/, diff/) went to the tree, with a "Verify run for E5-S8, round 2" section added to report.md.
    - In design/parity/dialogs/, which E5-S10 had regenerated at 18:25:58, I changed only the weak dialog: its result object in findings.json, its section and summary row in report.html, and its row and section in report.md. The section count went from 16 of 17 to 17 of 17. I also added one Verify line under create-key-file.
    - Checks that nothing else moved: a diff shows findings.json changed in 11 lines, all in that frame. A script check says report.html is equal outside the weak frame's section, its row and the count.
11. **Reproducible.** `cmp` of my shots against the builder's checked images: 18 of 20 byte-equal, both dialogs included. The two general shots differ only in the path text: pixelmatch 2,642 px (light) and 2,661 px (dark), 0.11 %.

Snapshot paths (offscreen, 1440×1440, 1800×1280, 920×296 and 920×544 px at 2×), each with its `.ax.json`. Copies are in design/parity/vault/app/ and design/parity/dialogs/app/.
- `app-shots/{light,dark}/vault-new-vault-step-{1,2,3}.png`
- `app-shots/{light,dark}/vault-vault-settings-{general,security,recycle-bin,history,browser-keys}.png`
- `app-shots/{light,dark}/dialogs-weak-vault-password.png` and `dialogs-create-key-file.png`

**Check 6, behaviour.** These tests passed in the full run (step 3):
- `Parity vault-new-vault-step-1: Continue, Back and Cancel move as APP-07.4 says; values kept`
- `Parity vault-new-vault-step-2: Recommended and Custom choose; Custom's rows edit and measure again`
- `Parity vault-new-vault-step-3: Show, Generate, the match mark and M07-20 (APP-07.11, APP-07.16)`
- `Parity vault-vault-settings-general: the pages switch; name, default username and colour apply`
- `Parity vault-vault-settings-security: the password changes after Change…; a cipher change saves`
- `Parity vault-vault-settings-recycle-bin: the switch turns the bin off after MOD-04.12's question`
- `Parity vault-vault-settings-history: the steppers change the limits; Delete all history… asks first`
- `Parity vault-vault-settings-browser-keys: Disconnect and Remove all… ask, then act (MOD-12.18)`
- `Parity dialogs-weak-vault-password: Cancel keeps step 3; Use this password goes to the save panel`
- `Parity dialogs-create-key-file: Create Key File makes the file and fills the key file part (APP-07.13)`
- the builder's `APP-07.17, APP-07.18: …`, `APP-07.9, APP-07.16: …`, `APP-07.17: a name typed without the extension never replaces a vault the panel did not ask about`, `MOD-12.12: Cancel on M07-33 …` and `MOD-12.21: the settings of a vault go when it locks`

**Check 7, accessibility.**
- Controls per frame (light trees): create-key-file 3, weak 2, step-1 5, step-2 7, step-3 11, browser-keys 8, general 16, history 11, recycle-bin 9, security 17. In all 89, 0 without a name.
- Keyboard: unchanged since round 1 (Swift files unchanged): Escape → Cancel, Return → the primary button, ⌃H and ⌃G, and secure input on focus.
- Mac QA (owner's go): the focus ring on a key window, the VoiceOver walk (T43) and the event-tap probe (T21).

### R2. Part B1 and B2: the story checks

Commands (in the copy, `CARGO_TARGET_DIR=/tmp/e5s8-verify3-target E5S8_WORK=/tmp/e5s8-verify3-work`):

```
cargo test -p app-ffi --test verify_e5s8 -- --ignored --nocapture --test-threads=1 b1_  → test result: ok. 1 passed … finished in 33.88s
cargo test -p app-ffi --test verify_e5s8 -- --ignored --nocapture --test-threads=1 b2_  → test result: ok. 1 passed … finished in 15.90s
/tmp/e5s8-verify3-scripts/ref.sh <vault> <password|-> [keyfile]   (REF_CLI db-info -q, ls -R -q, export -q -f xml | meta.py)
/usr/bin/python3 -I /tmp/e5s8-verify3-scripts/header.py <files>  (outer header fields, FMT-02/FMT-03 layout)
```

The b1 driver makes the same app-ffi calls as `NewVaultModel`, in the same order:
1. `Wizard::new(session)` and `defaults()`.
2. `measure(defaults)` when step 2 appears, and `measure(custom)` for Custom.
3. `check_encryption(choice, recommended, answers)`, answering yes to every question and keeping the yeses (`stepAnswers`).
4. `set_password` and `set_repeat`.
5. `new_key_file(path)`.
6. `create(name, description, "", …, stepAnswers + createAnswers)` → `Done`. This is where the save panel would open.
7. `create(…, path, …)` → `Created`.

Then a second session opened a copy, added Email › Work mail and Banking with `add_group`, and called `save`.

#### B1: our side (b1.log, excerpts)

```
simple-argon2id: defaults EncryptionChoice { cipher: Aes256, kdf: Argon2id, memory_mib: 64, lanes: 4, unlock_ms: 1000 }
  step 2 asked [] -> Done; meter ("Excellent", 118); match Some(true)
  key file simple-argon2id.appkey 278 bytes mode 400
  Create Vault asked [] -> Done; write asked [] -> Created { vault: 1 }
  written in 1.172879209s; vault file 1733 bytes mode 600
  OURS simple-argon2id-fresh.appvault: version 4.0 cipher Aes256 kdf Argon2 { kind: Id, iterations: 47, memory_kib: 65536, lanes: 4 } compression Gzip
  OURS name "Verify simple-argon2id" description "Recommended (simple mode, 1.0 s)" groups ["Root"] entries 0
  OURS recycle_bin_enabled true recycle_bin None history 10 / 6291456 protect title false user false pass true url false notes false maintenance 365 keychange -1 -1 unlock-time-item Some("1000")
  save after groups: SaveStatus { changes: 0, saved_at: Some(1793207311), failure: None }
  OURS … groups ["Root", "  Email", "    Work mail", "  Banking"] entries 0
  OURS without the key file: Some("WrongKey")
argon2id-twofish: kdf Argon2 { kind: Id, iterations: 30, memory_kib: 32768, lanes: 2 } cipher Twofish256; key file 278 bytes mode 400; vault 1877 bytes mode 600; item "300"
argon2d-chacha:   kdf Argon2 { kind: D, iterations: 36, memory_kib: 24576, lanes: 1 } cipher ChaCha20;   key file 278 bytes mode 400; vault 1543 bytes mode 600; item "300"
aeskdf-aes:       kdf AesKdf { rounds: 25963649 } cipher Aes256;                                       key file 278 bytes mode 400; vault 1623 bytes mode 600; item "300"
password-only:    kdf Argon2 { kind: Id, iterations: 44, memory_kib: 65536, lanes: 4 } cipher Aes256; vault 1493 bytes mode 600; item "1000"
keyfile-only:     meter None match None; Create Vault asked ["M07-21"] -> Done; vault 1893 bytes mode 600; item "1000"
```

- Every vault has Root only and 0 entries; the recycle bin on with no bin group; history 10 items and 6,291,456 bytes; Password protection only; maintenance 365 days; key change −1 / −1 (MOD-12.22, T41, T46).
- In every case `password()` is empty after the write (asserted).
- Every vault was open and unlocked in the wizard's session afterwards (`shown [(1, false)]`, APP-07.18).

#### B1: the reference CLI (ref-b1.log, 372 lines; 12 files, 12 × `exit 0`)

```
REF db-info simple-argon2id-fresh.appvault -k simple-argon2id.appkey (password given):
  | Name: Verify simple-argon2id
  | Description: Recommended (simple mode, 1.0 s)
  | Cipher: AES 256-bit
  | KDF: Argon2id (47 rounds, 65536 KB)
  | Recycle bin is enabled.
  | Number of groups: 1
  | Number of entries: 0
  exit 0
REF ls -R:
  | [empty]
  REF name 'Verify simple-argon2id' description 'Recommended (simple mode, 1.0 s)'
  REF recycle_bin_enabled True recycle_bin AAAAAAAAAAAAAAAAAAAAAA== history 10 / 6291456 maintenance 365 keychange -1 -1
  REF protect Title=False UserName=False Password=True URL=False Notes=False
  REF custom data keys (hex): [('4b5058435f52414e444f4d5f534c5547', '<434 chars>'), ('4b5058435f44454352595054494f4e5f54494d455f505245464552454e4345', '1000'), ('5f4c4153545f4d4f444946494544', '<28 chars>')]
  REF groups ['Root'] entries 0
REF db-info simple-argon2id.appvault -k simple-argon2id.appkey:  Number of groups: 4 … exit 0
REF ls -R:
  | Email/
  |   Work mail/
  |     [empty]
  | Banking/
  |   [empty]
REF argon2id-twofish(-fresh):  Cipher: Twofish 256-bit   KDF: Argon2id (30 rounds, 32768 KB)   exit 0; item '300'; groups as ours
REF argon2d-chacha(-fresh):    Cipher: ChaCha20 256-bit  KDF: Argon2d (36 rounds, 24576 KB)    exit 0; item '300'; groups as ours
REF aeskdf-aes(-fresh):        Cipher: AES 256-bit       KDF: AES (25963649 rounds)           exit 0; item '300'; groups as ours
REF password-only(-fresh):     Name: Verify password only  Description: (empty)  KDF: Argon2id (44 rounds, 65536 KB)  exit 0
REF keyfile-only(-fresh) --no-password -k keyfile-only.appkey:  Name: Verify key file only  Description: No password (M07-21 answered yes)  KDF: Argon2id (43 rounds, 65536 KB)  exit 0
```

For all 12 files, both tools agree on: name, description, groups, cipher, KDF numbers, recycle bin, history limits, protection flags, maintenance days, key change values and the unlock time item.

#### B2: encryption and credentials changed in the vault settings, then saved

Each case started from a copy of the Recommended wizard vault and its key file. The b2 driver opened it in a new session and called, in order:
- `VaultSettings::apply` (name, description, history 25 items and 12 MiB);
- `set_cipher`;
- `measure`, then `set_kdf`;
- `set_password`, `set_repeat`, `change_password`;
- `new_key_file`;
- `Session::save`.

```
to-argon2d-chacha:
  view before EncryptionChoice { cipher: Aes256, kdf: Argon2id, memory_mib: 64, lanes: 4, unlock_ms: 1000 } iterations 47
  general apply -> Done; set_cipher asked [] -> Done; set_kdf asked [] -> Done; change_password asked [] -> Done; new_key_file -> Then { outcome: Done }
  view after EncryptionChoice { cipher: ChaCha20, kdf: Argon2d, memory_mib: 48, lanes: 3, unlock_ms: 700 } iterations 42 key file Some("to-argon2d-chacha-new.appkey")
  save -> SaveStatus { changes: 0, saved_at: Some(1793207398), failure: None } in 779.978416ms
  OURS session unlock with old password + old key: Failed M06-06
  OURS session unlock with new password + old key: Failed M06-06
  OURS session unlock with old password + new key: Failed M06-06
  OURS session unlock with new password, no key: Failed M06-06
  OURS session unlock with new password + new key: Unlocked
  OURS … cipher ChaCha20 kdf Argon2 { kind: D, iterations: 42, memory_kib: 49152, lanes: 3 }; history 25 / 12582912; item "700"
to-aeskdf-twofish:
  view after EncryptionChoice { cipher: Twofish256, kdf: AesKdf, … unlock_ms: 400 } iterations 34242911 key file Some("to-aeskdf-twofish-new.appkey")
  save -> SaveStatus { changes: 0, … failure: None } in 467.399667ms
  (the same five unlock results)
  OURS … cipher Twofish256 kdf AesKdf { rounds: 34242911 }; history 25 / 12582912; item "400"
```

The header bytes (`header.py` on the file before and after the save):

```
to-argon2d-chacha-before.appvault: signature 03d9a29a67fb4bb5, version 4.0, header 253 bytes, header sha256 eeb06b73dbda5889
  cipher id       31c1f2e6bf714350be5805216afc5aff (AES-256)
  master seed     52247af818925e45619b35f6b94fdd06…
  encryption IV   42651337f1a6e2abce465d9277fdd6e2
  KDF parameters  $UUID 9e298b1956db4773b23dfc3ec6f0a1e6 (Argon2id), I 47, M 67108864, P 4, S(salt) 623d520ce8a3b148…, V 19
to-argon2d-chacha-after.appvault: signature 03d9a29a67fb4bb5, version 4.0, header 249 bytes, header sha256 bc04fa2ddbeb0391
  cipher id       d6038a2b8b6f4cb5a524339a31dbb59a (ChaCha20)
  master seed     e30ad4be433cde0618912d4767621b95…
  encryption IV   29f032130327cc9081d3ac73
  KDF parameters  $UUID ef636ddf8c29444b91f7a9a403e30a0c (Argon2d), I 42, M 50331648, P 3, S(salt) 303f9548a1cfd372…, V 19
to-aeskdf-twofish-after.appvault: signature 03d9a29a67fb4bb5, version 4.0, header 207 bytes, header sha256 50c8504f68ad8c5e
  cipher id       ad68f29f576f4bb9a36ad47af965346c (Twofish-256)
  master seed     3a6b8f7ff8fc4e4bd2f92c8a6d13b549…
  encryption IV   8e5eb76706aacf4fca9a322eb3a7f59c
  KDF parameters  $UUID c9d9f39a628a4460bf740d08c18a4fea (AES-KDF), R 34242911, S(salt) 2ddcbe622fb70bcb…
```

All of these changed: cipher id, KDF id and parameters, salt, master seed and IV. ChaCha20's IV is 12 bytes (CRY-01). Compression stays 1 (gzip).

The reference CLI on the same files (ref-b2.log):

```
== to-argon2d-chacha, the file before the change, old password + old key:  Name: Verify simple-argon2id  Cipher: AES 256-bit  KDF: Argon2id (47 rounds, 65536 KB)  exit 0
-- old password + old key: exit 1
-- new password + old key: exit 1
-- old password + new key: exit 1
-- new password, no key:   exit 1
-- new password + new key: Name: Changed to-argon2d-chacha  Description: Changed by the vault settings  Cipher: ChaCha20 256-bit  KDF: Argon2d (42 rounds, 49152 KB)  Number of groups: 4  exit 0
   REF history 25 / 12582912; unlock time item '700'; groups ['Root', '  Email', '    Work mail', '  Banking']
== to-aeskdf-twofish: the same four exit 1; new password + new key: Cipher: Twofish 256-bit  KDF: AES (34242911 rounds)  exit 0; history 25 / 12582912; item '400'
REF_CLI db-info to-aeskdf-twofish.appvault with the new password and no key file (no -q): "Error while reading the database: Invalid credentials were provided, please try again. … (HMAC mismatch)", exit 1
```

### R3. Part B3: the card cases

Sources:
- **R:** builder Rust tests, rerun in the copy: `cargo test --no-fail-fast -p app-core -p app-ffi -p app-platform` → 47 suites, **922 passed, 0 failed, 35 ignored**. The 35 include my 3 drivers. This covers `new_vault.rs` (11), `vault_settings.rs` (6), app-core `mod12.rs` (28), `wizard::tests`, `vault_settings::tests::cry02_14_…`, `app_settings::tests::app01_13_bad_values_clamp_or_read_the_default` and `macos::system::tests::thread_cpu_time_…`.
- **S:** builder Swift tests (section R1, step 3).
- **VR:** my Rust drivers b1, b2, b3, b5 (round 2).
- **VS:** my `VerifyE5S8Tests` (round 2).
- **R1:** round 1's Verify proof (below). It still holds because the E5-S8 Swift code has not changed since 14:55.

**S-CFG-02, the round-1 fail (VR b3, `cargo test … b3_` → `test result: ok. 1 passed`).** The store was set through `Session::save_settings`; the line "store reads N" is read back from it. First the levels of the demo passwords:

```
rating "password": level Poor segments 1 · "password1": Poor 1 · "Tr0ub4dor&3": Weak 2 · "correct horse battery": Weak 2 · "kT7#pQ2vZ9mW4x": Good 3 · "Verify-demo-E5S8-r2-wizard-58": Excellent 4
WIZARD S-CFG-02 set 0 (store reads 0), "password" (quality 1): no answer -> Ask M07-23 ("Use this password"); with the WeakPassword yes -> Done; file written false
WIZARD S-CFG-02 set 0, "kT7#pQ2vZ9mW4x" (quality 3): no answer -> Created { vault: 1 }; file written true
WIZARD S-CFG-02 set 2 (store reads 2), "password1" (quality 1): no answer -> Refused M07-22; with the WeakPassword yes -> Refused M07-22; file written false
WIZARD S-CFG-02 set 2, "Tr0ub4dor&3" (quality 2): no answer -> Ask M07-23 ("Use this password"); with the WeakPassword yes -> Done; file written false
WIZARD S-CFG-02 set 3 (store reads 3), "password" (quality 1): no answer -> Refused M07-22; with the WeakPassword yes -> Refused M07-22; file written false
WIZARD S-CFG-02 set 3, "password1" (quality 1): Refused M07-22 both ways; file written false
WIZARD S-CFG-02 set 3, "Tr0ub4dor&3" / "correct horse battery" (quality 2): Refused M07-22 both ways; file written false
WIZARD S-CFG-02 set 3, "kT7#pQ2vZ9mW4x" (quality 3): no answer -> Created { vault: 1 }; file written true
WIZARD S-CFG-02 set 4 (store reads 4), "kT7#pQ2vZ9mW4x" (quality 3): Refused M07-22 both ways; file written false
WIZARD S-CFG-02 set 4, "Verify-demo-E5S8-r2-wizard-58" (quality 4): no answer -> Created { vault: 1 }; file written true
SETTINGS S-CFG-02 = 0, Change… with "password1": no answer -> Ask M07-23 ("Use this password"); with the WeakPassword yes -> Done
SETTINGS S-CFG-02 = 3, Change… with "password1": no answer -> Refused M07-22; with the WeakPassword yes -> Refused M07-22
SETTINGS S-CFG-02 = 3, Change… with "password": no answer -> Refused M07-22; with the WeakPassword yes -> Refused M07-22
SETTINGS S-CFG-02 = 3, New Key File… with the old password kept -> Then { outcome: Done }
  save -> SaveStatus { changes: 0, … failure: None }; reopen with demo-pass-9 + new key: Unlocked; reopen with password1 + new key: Failed … M06-06
```

The M07-22 text is "This password is weaker than App allows. Choose a stronger one." (FEA-05.20 MSG-MK-TOO-WEAK). What this shows:
- A password exactly at the minimum passes.
- One level below the minimum is refused, even with the WeakPassword yes. Nothing is written.
- The minimum checks only a new typed password, so adding a key file to a vault whose stored password is weak still works.

In the screens (VS `minimumNotice`):

```
VERIFY E5S8 wizard sheet with the minimum at 3: Optional(AppTests.NewVaultModel.Sheet.notice(id: "M07-22", text: "This password is weaker than App allows. Choose a stronger one.")); panel opened false
VERIFY E5S8 settings sheet with the minimum at 3: Optional(AppTests.VaultSettingsModel.Sheet.notice("This password is weaker than App allows. Choose a stronger one."))
```

The store refuses values outside 0 to 4 from the screen side (`save_settings` with 9 → `Err(Invalid("security.min_master_quality"))`). A settings file holding one is clamped when it is read (D-01-5, R `app01_13_bad_values_clamp_or_read_the_default`). `wizard::min_quality` clamps again.

**Earlier VR cases, run again on today's code (b5):**

```
APP-07 T03: after Cancel the key file has 278 bytes, mode 400; vault files in the folder: 0
APP-07 T06: create with an empty name -> Created { vault: 1 }; vault list name ["Unnamed"]; OURS name ""
APP-07 T39: recent top Some("/private/tmp/e5s8-verify3-work/b5/Unnamed.appvault"); after lock, unlock with no password -> Failed M06-05; unlock with the password -> Unlocked
APP-07 T24: new key file in a read-only folder -> Then { outcome: Refused { id: "M07-25", text: "The new key file \"k.appkey\" was not written: App is not allowed to write there." } }; file exists afterwards: false
MOD-12 T31: set_cipher(same Aes256) -> Done, changes 0 -> 0
MOD-12 T29: set_cipher(ChaCha20) asked [] -> Done; save -> failure: None; version before 3.1, after 4.0
```

#### APP-07

| Case | Result | Proof |
|---|---|---|
| T01 | PASS | R1 VS `oneWizard` (Swift unchanged). ⇧⌘N in `AppMain.swift`. |
| T02 | PASS (model) | `.onExitCommand` → `cancel()`; S `steps`. A real Escape press is Mac QA. |
| T03 | PASS | VR b5. |
| T04 | PASS | S `steps` (passed in R1 step 3). |
| T05 | PASS | VR b1: DatabaseName equals step 1's name in both tools. The "Passwords" default is in the step-1 frame. |
| T06 | PASS | VR b5. |
| T07 | PASS | VR b1 Recommended: AES-256, Argon2id, 65,536 KiB, P 4, measured iterations, item `1000`; R `app07_6_the_defaults`. |
| T08 | PASS (unit) | R `app07_8_iterations_for_any_time_from_one_run`. |
| T09 | PASS | The three lists; S `encryption`. |
| T10 | PASS | S `encryption`. |
| T11 | PASS | VS `sameFamily`: `after Argon2d: memory 128, lanes 3, measuring false`. |
| T12 | PASS | VS `sameFamily`: `while measuring: measuring true, canContinue false`. |
| T13 | PASS (unit) | R `app07_8_…`: capped at 1,000,000,000. |
| T14 | PASS (code) | The speed record is stored after a measurement (`wizard.rs`). No direct test: open issue 4. |
| T15 | PASS (core); screen waits | app-core `app07_9_safe_minimum_asks_before_the_slow_warning`; R `cry02_14_…`. M07-31 cannot be reached through Option A's Custom. |
| T16 | PASS | R `app07_9_step_two_checks_and_m07_35`; S `encryption`. |
| T17 | waits for a mockup addition | No Rounds field in Option A; app-core `mod12_kdf_warnings_and_refusal`. |
| T18 | waits for a mockup addition | No advanced mode with typed iterations. Custom writes the unlock time item (`300`): open issue 3. |
| T19, T20 | PASS | S `password`. |
| T21 | Mac QA | Secure input on focus; the event-tap probe needs the owner's go. |
| T22 | PASS | R `app07_13_t22_t36_…`; VR b1: 278 bytes, mode 0400, and REF opens with `-k`. |
| T23 | PASS | R `app07_13_t23_never_over_an_existing_file`. |
| T24 | PASS | VR b5 (M07-25, no file). |
| T25 to T27 | PASS | R `app07_14_t25_t26_t27_chosen_key_files`. |
| T28 | PASS | R `app07_16_the_checks_in_the_cards_order`; S `password`. |
| T29 | PASS | R `app07_16_t29_…`; VR b1 key-file-only: `asked ["M07-21"]`, and REF `--no-password -k` exits 0. |
| T30 | PASS | VR b3 with S-CFG-02 = 0: `password` gets M07-23 "Use this password". S `weak`: Cancel keeps step 3. |
| **T31** | **PASS** (round-1 fail fixed) | VR b3 with S-CFG-02 = 3: `password` and `password1` get `Refused M07-22` with and without the yes, and nothing is written. VS `minimumNotice`: the M07-22 notice, no save panel, still on step 3. R `app07_16_t31_a_password_below_the_set_minimum_is_refused`. |
| T32 | PASS | R `app07_16_the_checks_in_the_cards_order`. |
| T33 | PASS in part; panel is Mac QA | Panel title, name and type are in the code; S-STATE-06 is a later pass (E5-S9 inventory). |
| T34 | PASS | R `app07_17_t34_…`. |
| T35 | PASS | VR b1 and REF: mode 0600, version 4.0, gzip; opens in both tools. |
| T36 | PASS | VR b1: all 5 key-file vaults open in REF with `-k`. |
| T37 | PASS | R `app07_17_…_and_t37_no_partial_file`. |
| T38 | PASS | S `create`. |
| T39 | PASS | S `create`; VR b5. |
| T40 | later story | FEA-08.5 import (E5-S11). |
| T41 | PASS | VR b1 in both tools. |
| T42 | PASS | R `fmt18_24_the_vault_itself_is_never_its_key_file`. |
| T43 | Mac QA | VoiceOver; the trees have 0 unnamed controls. |
| T44 | not in Option A | — |
| T45 | E10 | The security key is drawn and disabled. |

#### MOD-12

| Case | Result | Proof |
|---|---|---|
| T01 | waits for a mockup addition | Option A draws General, Security, Recycle Bin, History and Browser Keys. |
| T02 | not in Option A | app-core `mod12_02_apply_is_all_or_nothing`. |
| T03, T04 | PASS | app-core `mod12_03_…`; S `general`; R `mod12_3_to_mod12_6_general_bin_and_history`. |
| T05 | waits for a mockup addition | No Clear control. Open issue 3 (the "not encrypted" notice). |
| T06, T08 (reference), T47 | reference only | — |
| T07, T08 (App), T09, T09b, T10 | PASS | app-core `mod12_05_history_limits`; S `history`; R `mod12_3_to_mod12_6_…`. |
| T11, T12 | PASS | S `bin`; app-core `mod12_06_recycle_bin`. |
| T13 to T15 | waits for a mockup addition | app-core `mod12_07`, `mod12_08`. |
| T16 | PASS | app-core `mod12_09_settings_time`. |
| T17 | PASS | R `mod12_10_…`. |
| **T18** | **PASS** (round-1 fail fixed) | VR b3: Change… with `password1` and with `password` at S-CFG-02 = 3 gives `Refused M07-22` with and without the yes. VS `minimumNotice`: the notice shows. R `mod12_10_t18_a_password_below_the_set_minimum_is_refused`. |
| T19 | PASS | VR b3 at S-CFG-02 = 0: M07-23, Cancel default. |
| T20 | PASS | R `mod12_10_…`: M07-24. |
| T21 | PASS | B2; R `mod12_10_a_credential_change_needs_the_new_credentials_to_open`. |
| T22 | PASS | app-core `mod12_10_changing_the_key`. |
| T23 | PASS | M07-28 note (R `app07_14_…`). |
| T23b | E5-S10 | MSG-KEY-OLD-COPIES. |
| T24 | PASS | B2 `view before … unlock_ms: 1000` read from the item. |
| T25 | waits; PASS (core) | app-core `mod12_kdf_warnings_and_refusal`. |
| T26, T27 | PASS | R `mod12_14_…`, `cry02_14_an_approved_costly_kdf_saves_without_asking`. |
| T28 | waits for a mockup addition | No advanced mode. |
| T29 | PASS | VR b5: 3.1 → 4.0. |
| T30 | PASS | B2 in both tools. |
| T31 | PASS | VR b5: changes 0 → 0. |
| T32 to T36 | waits for a mockup addition | app-core `mod12_15`, `mod12_16`, `mod12_17`. |
| T37, T39 | PASS | R `mod12_18_browser_keys_and_site_permissions`; S `browser`. |
| T38, T40 | waits for a mockup addition | — |
| T41 | not built | S-BRW-01 is not read: open issue 3. |
| T42, T43 | waits for a mockup addition | No maintenance page. |
| T44 | PASS | app-core `mod12_20_values_with_no_control_are_kept`. |
| T45 | E5-S10 | APP-05's save error flow. |
| T46 | PASS | VR b1. |

### R4. Part B4: secrets (rule 4)

VS `memory` scans this test process's own readable and writable regions:
- it walks them with `mach_vm_region_recurse` on `mach_task_self_`;
- it reads each 1 MiB chunk with `mach_vm_read_overwrite` into a scratch buffer, which the scan skips and which is zeroed with `memset_s` after each chunk;
- it searches with `memchr`.

The needles are kept only reversed, in source and in memory. They are matched from the reversed bytes (UTF-8 and UTF-16LE), so the forward text is never built for the search. Output of the full run (section R1, step 3):

```
VERIFY E5S8 memory A typed: utf8 2 utf16 0
VERIFY E5S8 memory A after the write, vault open (Rust keeps the key parts for saves): utf8 1 utf16 0
VERIFY E5S8 memory A after lock: utf8 0 utf16 0
VERIFY E5S8 memory B typed in Change…: utf8 2 utf16 0
VERIFY E5S8 memory after close: A utf8 0 utf16 0; B utf8 0 utf16 0
VERIFY E5S8 reopen with B: unlocked
VERIFY E5S8 reopen with A: failed(message: AppCore.UnlockMessage(id: "M06-06", text: "Wrong password, key file or security key. Check them and try again.", …))
VERIFY E5S8 memory C typed: utf8 2 utf16 0
VERIFY E5S8 memory C after Cancel: utf8 0 utf16 0
✔ Test "Verify rule 4: typed master passwords in memory while typed, after write, lock, close and Cancel" passed after 25.291 seconds.
```

What the numbers mean:
- **Typed (2 copies).** One is the test's own Swift argument; the other is Rust's `SecretString`. The model keeps only the length and the meter.
- **While the new vault is open (1 copy).** Rust's save key parts, in a wiping type.
- **After lock, close and Cancel: none.** The test asserts 0.
- **Also checked.** My b1 and b2 assert that `password()` is empty after the write and after the change.
- **Limit (Mac QA, as in E5-S6).** The rendered SecureField, and a dump of the real App.app.

### R5. Part B5: mutations (private copy only)

Each mutant was put in with an exact single replace (`mut.py` asserts one match), run, then the file was restored from /tmp/e5s8-verify3-work/orig. `cmp` printed "restored" every time.

Rust (`cargo test -q --no-fail-fast -p app-ffi --test new_vault --test vault_settings`, plus the listed extras):

| Id | Mutation | Result |
|---|---|---|
| M1 | `wizard.rs` `min_quality: min_quality(&self.session)` → `0` (the round-1 fail) | CAUGHT: `app07_16_t31_a_password_below_the_set_minimum_is_refused` (new_vault.rs:387) |
| M2 | `vault_settings.rs` `min_quality: wizard::min_quality(&self.session)` → `0` | CAUGHT: `mod12_10_t18_a_password_below_the_set_minimum_is_refused` (vault_settings.rs:189); new_vault 11 passed |
| M3 | `min_quality` clamp `(0, 4)` → `(0, 2)` | SURVIVED the builder's tests (11 and 6 passed). CAUGHT by VR b3: `set 3, "Tr0ub4dor&3" (quality 2): Ask M07-23` instead of Refused. Advisory 1. |
| M4 | app-core `*quality < k.min_quality` → `<=` | SURVIVED the builder's tests and all of app-core (`29 suites, 712 passed, 0 failed`). CAUGHT by VR b3: `set 3, "kT7#pQ2vZ9mW4x" (quality 3): Refused M07-22`. Advisory 1. |
| M5 | key file `.mode(0o400)` → `0o600` | CAUGHT: `app07_13_t22_t36_a_new_key_file_and_a_vault_that_needs_both` (new_vault.rs:187) |
| M6 | `kdf_for`: Argon2d always written as Argon2id | CAUGHT: `mod12_14_a_changed_cipher_and_kdf_are_in_the_saved_header` (vault_settings.rs:96) |
| M7 | `cipher_of`: ChaCha20 → AES-256 | CAUGHT: `app07_17_t35_…` (new_vault.rs:135) and `mod12_14_…` (vault_settings.rs:66) |
| M8 | `edit_for`: unlock time item never written | CAUGHT: `app07_9_step_two_checks_and_m07_35` (new_vault.rs:496) and `app07_17_t35_…` (new_vault.rs:158) |

Swift (`xcodebuild … test -only-testing:AppTests/NewVaultBehaviourTests -only-testing:AppTests/VaultSettingsBehaviourTests -only-testing:AppTests/VerifyE5S8Tests`, 18 tests):

| Id | Mutation | Result |
|---|---|---|
| S1 | `NewVaultModel.handle`: a refusal (M07-22, M07-25, M07-30 …) shows no notice | SURVIVED the builder's tests. CAUGHT only by VS `minimumNotice` (VerifyE5S8Tests.swift:210, "no notice"). Advisory 1. |
| S2 | `VaultSettingsModel.done`: a refusal shows no notice | SURVIVED the builder's tests. CAUGHT only by VS `minimumNotice` (VerifyE5S8Tests.swift:227). Advisory 1. |

**Checks of the code state (copy, 18:03 state, my test files moved out first).**
- `cargo clippy -q -p app-ffi -p app-core -p app-platform --all-targets -- -D warnings` → exit 0.
- `swift format lint --strict --recursive macos` → exit 0.
- `swiftlint 0.65.1 lint --strict --quiet` → exit 0.

**Checks in the tree.**
- `cargo fmt -p app-ffi -p app-core -p app-platform -- --check` → exit 0.
- `scripts/check-names.sh` → `names: PASS (3055 files scanned, 15 vault files name-only)`.
- The tree's whole-folder `swift format` and `swiftlint` runs report findings only in E5-S10's files being edited now: `Saving.swift`, `SavingSheets.swift`, and `VaultModel.swift` length after its 18:20 edit. Neither tool finds anything in an E5-S8 file (`swift format lint --strict` and `swiftlint lint --strict` on `NewVault*.swift`, `VaultSettings*.swift` and their tests → exit 0 and 0).

### R6. Fails

None.

### R7. Open issues and advisories (not fails)

1. **Test gaps (mutants M3, M4, S1, S2).** The builder's tests pin only "quality 1 below a minimum of 3".
   - No test holds the boundary: equal to the minimum passes, one below is refused, and a minimum of 4 refuses Good.
   - No Swift test shows that a refusal reaches the user as a notice, in either screen.
   - Smallest fix: add a Good password at minimum 3 (Created) and a Weak password at minimum 3 (M07-22) to `app07_16_t31_…` and `mod12_10_t18_…`, and one Swift test per model with the store at 3 that expects the M07-22 notice.
2. **E5-S10 is changing the save path now.** It moves `Session::save` into `saving.rs` (18:15 to 18:20, after my copy). The builder's E5-S8 Rust tests pass on the tree's code at 18:28. E5-S10's Checker and Verify should run `cry02_14_an_approved_costly_kdf_saves_without_asking`, `mod12_14_…`, `mod12_10_…` and the two `…_below_the_set_minimum_is_refused` tests again before they sign.
3. **Carried over from round 1, unchanged.** Each needs a lead ruling or a mockup addition:
   - Custom mode writes the unlock time item (Option A's Custom picks a time; card T18 says advanced mode writes none).
   - There is no "not encrypted" notice on the General page (MOD-12.4, SF-12).
   - The Browser Keys page ignores S-BRW-01 (MOD-12 T41; the off state is not drawn).
   - The Touch ID switch is drawn on and disabled in the wizard.
   - The list items read "AES-256" and "Argon2id" where M07-07 says "(default)" and "(recommended)".
4. **Round-1 test gaps still open.**
   - No builder test covers T12 (my `sameFamily` covers it) or T14.
   - No test pins `thread_cpu_time` as the clock that `wizard::measure` uses.
   - Round 1's Swift mutant S2 (Cancel keeps the Show values until the model is freed) is unchanged.
5. **The parity tool skips pixels when sizes differ.** compare.mjs measures no pixels or colour shares when the image sizes differ (the weak dialog). That is the tool's rule, not this story's; the dialog was checked by eye.
6. **Mac QA (needs the owner's go).**
   - The real save panel: the `.appvault` type, and its own replace question when "Work" is typed next to Work.appvault.
   - T21 secure input, T43 VoiceOver, and the focus ring on a key window.
   - Escape and Return in the real window.
   - The wizard as its own window (APP-07.2 says sheet; Option A draws a window).
7. **ScreenTests' general pasteboard check (LD-206).** It failed once in the full run while something else on the Mac copied, and passed alone.

### R8. Cleanup

Deleted: /tmp/e5s8-verify3-copy, /tmp/e5s8-verify3-target, /tmp/e5s8-verify3-dd, /tmp/e5s8-verify3-work (the demo vaults, key files, logs, the reference's throwaway home and the backups) and /tmp/e5s8-verify3-scripts. Kept:
- /tmp/parity-tools, shared by every parity run;
- /tmp/e5s8-verify2-*, not mine.

Files changed in the tree:
- this file (round 2 added on top; round 1 kept below);
- design/parity/tools/notes.mjs (the two LD-210 entries);
- design/parity/vault/ (report.md, report.html, findings.json, app/ and diff/, regenerated, with the round 2 Verify section);
- design/parity/dialogs/ (report.md, report.html and findings.json: only the weak dialog's rows and one Verify line under each E5-S8 dialog);
- plan/epics.md (the E5-S8 status line).

---

## Round 1 (2026-10-28, history): failed (3)

Verify agent, round 1, 2026-10-28. I did not build or check this story before.

**Verdict: failed (3).** Both story checks pass. One card guard is missing: the minimum master password quality (S-CFG-02) is ignored. Two parity FAILs come from the card's own words; they need the lead's acceptance.

| Check | Result |
|---|---|
| A. Design parity, section `vault` and the two APP-07 dialogs | **vault 7 of 8 PASS**, dialogs 13 of 14, light and dark. The two FAILs are `vault-new-vault-step-2` (dark 7.07 %) and `dialogs-weak-vault-password` (3 boxes off by 44 pt). Both come from card words (M07-05; FEA-05.20 MSG-MK-WEAK) and need the lead's acceptance. Every other frame: 0 missing strings, 0 boxes or text runs more than 2 pt off, and pixels between 0.66 and 3.24 % (at most 2.53 % outside the accepted areas). 89 controls, 0 unnamed. Static tokens 45 of 45. Contrast: 42 pairs, lowest 4.87:1. 18 of my 20 shots are byte-equal to the builder's. Report: [design/parity/vault/report.md](../../design/parity/vault/report.md) and report.html. |
| B1. A wizard vault opens in the reference CLI | **PASS.** 6 vaults went through the app-ffi calls the Swift model makes: Recommended (Argon2id), Custom Argon2id with Twofish, Custom Argon2d with ChaCha20, Custom AES-KDF with AES, password only, and key file only. Each opens in the reference CLI with exit 0. The reference lists the same name, description, groups (Root, then Email › Work mail and Banking after a session save), cipher, KDF with its numbers, recycle bin, history limits, protection flags, maintenance days, key change values and unlock time item as our reader does. |
| B2. Encryption changes re-encrypt on save | **PASS.** Two runs through `VaultSettings`: AES-256/Argon2id 64 MiB P4 became ChaCha20/Argon2d 48 MiB P3, and it became Twofish/AES-KDF 34,471,819 rounds. Each run also set a new password, a new key file, a name, a description and history limits, then saved. The header's cipher id, KDF parameters, salt, master seed and IV changed as expected. In both tools, the old credentials and every mix of old and new fail (exit 1 / M06-06), and only the new password plus the new key file opens. |
| B3. APP-07 and MOD-12 cases | All reachable cases pass except **APP-07 T31 and MOD-12 T18 (FAIL)**: S-CFG-02 is ignored. The table is in section 3. Cases for controls Option A does not draw wait for a mockup addition. |
| B4. Secrets (rule 4) | **PASS.** I scanned this test process's own memory (the E5-S6 Verify method, rebuilt here). Each typed master password was found while typed (control). After the lock, the close and a Cancel it is gone: 0 UTF-8 and 0 UTF-16 copies. While the new vault is open, Rust's save key parts hold 1 copy, as designed. |
| B5. Mutations (private copy) | **12 of 13 caught.** All 10 Rust mutants were caught by the builder's tests. 2 of 3 Swift mutants were caught: S1 only by my Verify test, S3 by the builder's. The survivor is S2 (Cancel keeps the Show values on the model until it is freed): advisory 5. |

### 0. Setup and rules

- **Private copy.** At 15:36: `rsync -a --exclude /target --exclude /app-shots --exclude /fuzz/target` from the tree to /tmp/e5s8-verify-copy. `target` was a link to /tmp/e5s8-verify-target, I used `CARGO_TARGET_DIR=/tmp/e5s8-verify-target` and `-derivedDataPath /tmp/e5s8-verify-dd`, and scratch files went to /tmp/e5s8-verify-work.
- **The code checked is the tree's code.** `shasum -c` at 16:00 and again at the end over these files gave OK for every one: `wizard.rs`, `vault_settings.rs`, `edit.rs`, `session.rs`, `lib.rs`, app-platform `system.rs`, `NewVault*.swift`, `VaultSettings*.swift`, `NewVaultTests.swift` and `VaultSettingsTests.swift`.
- **My own tests lived only in the copy.** They were `crates/app-ffi/tests/verify_e5s8.rs` (drivers b1 to b5) and `macos/AppTests/VerifyE5S8Tests.swift` (suite `VerifyE5S8Tests`). Both were deleted with the copy. No product code was edited.
- **Rule 10.** No window was ordered front. `AuxWindows.present`, the save panel, the folder panel and the key file panels were all replaced by the tests' seams. Chrome ran headless. The general pasteboard was never read or written.
- **Rule 5.** Demo vaults only: the ones my drivers made in /tmp/e5s8-verify-work and copies of testdata. Demo passwords only: `Verify-demo-E5S8-wizard-41`, `Verify-demo-E5S8-changed-73`, `password1`, `demo-pass-4`, and the reversed needles in section 4.
- **The reference CLI.** Version 2.7.11 (`REF_CLI --version` prints `2.7.11`). Every run used `HOME=/tmp/e5s8-verify-work/refhome`, so its real settings were never read. I ran only `db-info`, `ls -R`, `export` (my script printed only meta values and group names) and `db-create` (on one throwaway vault, as a control). No clip command, no window, no real file. In this file it is called REF_CLI.
- **Rule 11.** I stopped no process. The Mac's load average was 95 to 164 during the run.

### 1. Part A: design parity (BUILD-AND-VERIFY.md, "Prompt for the Verify fleet")

1. `node design/option-a/tools/export-reference.mjs` (in the copy)
   - Printed `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`; `17.18s user 2.72s system 42% cpu 47.319 total`, exit 0.
   - `cmp` of the manifest against the tree's: equal.
   - 14 of the 20 E5-S8 references are byte-equal to the tree's.
   - The other 6 differ in a few bytes, and pixelmatch (threshold 0.1) finds 0 changed pixels in each: `light/vault-new-vault-step-2.png raw-bytes-differ 24 pixelmatch 0`, `light/…security 81 / 0`, `light/…recycle-bin 18 / 0`, `dark/…step-3 36 / 0`, `dark/…general 16 / 0`, `dark/…recycle-bin 24 / 0`. This is rasteriser noise, so the tree's references are current.
2. `scripts/build-core.sh` printed `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`; `503.48s user … 1:48.73 total`, exit 0.
3. `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e5s8-verify-dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES > target/parity/behaviour.log` printed:
   - `✔ Suite NewVaultSnapshotTests passed after 43.372 seconds.`
   - `✔ Suite VaultSettingsSnapshotTests passed after 54.904 seconds.`
   - `✔ Suite NewVaultBehaviourTests passed after 73.174 seconds.`
   - `✔ Suite VaultSettingsBehaviourTests passed after 26.937 seconds.`
   - `✔ Test run with 164 tests in 28 suites passed after 104.123 seconds.`
   - `** TEST SUCCEEDED **`
4. `node design/parity/tools/mockup-dom.mjs vault,dialogs` printed `light: 29 frames, 319 text runs`, `dark: 29 frames, 319 text runs`.
5. `swift design/parity/tools/ocr.swift app-shots/{light,dark}/vault-*.png app-shots/{light,dark}/dialogs-*.png` read 22 images per theme.
6. `node design/parity/tools/compare.mjs vault`, first run: `vault: 6/8 PASS`. The extra FAIL was `vault-vault-settings-general`, `1 missing string`: `~/Documents/Passwords/Personal.appvault`.
   - The cause is my copy, not the app. The copy lives outside the home folder, so the app showed `/private/tmp/e5s8-verify-target/option-a/settings-shots/Passwords/Personal.appvault`, and notes.mjs's live rule expects `~/…/Passwords/Personal.appvault`.
   - I re-rendered with `TEST_RUNNER_HOME=/private/tmp/e5s8-verify-target xcodebuild … -only-testing:AppTests/VaultSettingsSnapshotTests`. Location now read `~/option-a/settings-shots/Passwords/Personal.appvault`.
   - The security frame then failed in that run: its key file folder expands `~` with the real home, and the run printed `The new key file "personal.appkey" was not written: the folder no longer exists`. Nothing was written there: `ls /Users/…/option-a` says No such file.
   - So I kept only the two general shots from that run and rendered the suite again normally: `✔ Suite VaultSettingsSnapshotTests passed`.
7. `node design/parity/tools/compare.mjs vault`, second run:

```
vault: 7/8 PASS
vault-new-vault-step-1                         PASS                   L 2.13% (1.83) D 2.83% (2.53)
vault-new-vault-step-2                         FAIL                   L 2.63% (2.21) D 7.07% (6.65) dark: 7.07 % pixels (6.65 % outside accepted areas)
vault-new-vault-step-3                         PASS                   L 2.36% (1.16) D 3.24% (2.02)
vault-vault-settings-general                   PASS                   L 1.89% (1.69) D 1.89% (1.69)
vault-vault-settings-security                  PASS                   L 1.77% (1.61) D 1.76% (1.61)
vault-vault-settings-recycle-bin               PASS                   L 0.68% (0.63) D 0.66% (0.62)
vault-vault-settings-history                   PASS                   L 0.95% (0.85) D 0.93% (0.84)
vault-vault-settings-browser-keys              PASS                   L 1.08% (0.9) D 1.07% (0.9)
```

8. `node design/parity/tools/compare.mjs dialogs` (in the copy) printed `dialogs: 13/14 PASS`, with `dialogs-create-key-file PASS L 2.29% (2.29) D 2.16% (2.09)` and `dialogs-weak-vault-password FAIL … 3 box(es) off by more than 2 pt (button "Use It Anyway" Δ 0,-44,25,0; button "Choose Another" Δ 59,-44,-59,0; dialog "This password is easy to" Δ 0,0,0,-44)`. These are the same numbers as the tree's design/parity/dialogs/report.md, so I added only a Verify line under those two frames there.
9. **Reproducible.** `cmp` of my shots against the builder's checked images in design/parity/vault/app and design/parity/dialogs/app:
   - byte-equal for all 8 vault frames except general, and for both dialogs, in light and dark;
   - general differs only in the path text: pixelmatch 2,642 px (0.11 %).

Snapshot paths (offscreen, 1440×1440, 1800×1280, 920×296 and 920×544 at 2×):
- `app-shots/{light,dark}/vault-new-vault-step-{1,2,3}.png`
- `app-shots/{light,dark}/vault-vault-settings-{general,security,recycle-bin,history,browser-keys}.png`
- `app-shots/{light,dark}/dialogs-weak-vault-password.png` and `dialogs-create-key-file.png`
- each with its `.ax.json`. Copies are in design/parity/vault/app/ and design/parity/dialogs/app/.

What I checked by eye, with the mockup and the app stacked:

- **Accepted differences (card words over mockup, BUILD-AND-VERIFY order 2).**
  - Step 2: the M07-05 step line takes two lines, so the choices sit 20 pt lower. In dark, the moved accent fill is most of the 7.07 %.
  - Step 3: the title "Password and keys" (step table), M07-09, "Verify password" (M07-10), "New Key File…" and "Choose Key File…" (M07-12), and "Create Vault" (M07-14).
  - Step 3 rates the password "Good, about 79 bits"; the mockup says "Strong, about 78 bits" (FEA-05.4 levels, LD-163 (4)).
  - Step 3: Show reveals both fields together (APP-07.11), so the repeat field is in clear.
  - The weak-password dialog is MSG-MK-WEAK as one sentence with "Use this password" and "Cancel", so it is 44 pt shorter.
- **Live values.** Path, version and size, history size, connected dates, and the MasterKeyChanged date of the test copy.
- **Not built yet.** The window buttons are masked, and the security key and Touch ID rows are drawn and disabled (E10, E6-S3, LD-163).
- **Check 6, behaviour.** These Parity tests press each frame's controls through the accessibility tree; all passed in run 3:
  - `Parity vault-new-vault-step-1: Continue, Back and Cancel move as APP-07.4 says; values kept`
  - `Parity vault-new-vault-step-2: Recommended and Custom choose; Custom's rows edit and measure again`
  - `Parity vault-new-vault-step-3: Show, Generate, the match mark and M07-20 (APP-07.11, APP-07.16)`
  - `Parity vault-vault-settings-general: the pages switch; name, default username and colour apply`
  - `Parity vault-vault-settings-security: the password changes after Change…; a cipher change saves`
  - `Parity vault-vault-settings-recycle-bin: the switch turns the bin off after MOD-04.12's question`
  - `Parity vault-vault-settings-history: the steppers change the limits; Delete all history… asks first`
  - `Parity vault-vault-settings-browser-keys: Disconnect and Remove all… ask, then act (MOD-12.18)`
  - `Parity dialogs-weak-vault-password: Cancel keeps step 3; Use this password goes to the save panel`
  - `Parity dialogs-create-key-file: Create Key File makes the file and fills the key file part (APP-07.13)`
- **Check 7, accessibility.**
  - A count over the 10 light `.ax.json` trees: create-key-file 3 controls, weak 2, step-1 5, step-2 7, step-3 11, browser-keys 8, general 16, history 11, recycle-bin 9, security 17. In all, 89 controls and 0 without a name.
  - Escape is mapped to Cancel (`NewVaultView.swift:45` `.onExitCommand`), Return to the primary button (`.keyboardShortcut(.defaultAction)`), and ⌃H and ⌃G to Show and Generate (`NewVaultView.swift:216-218`).
  - Secure input turns on while a password field has the focus (`SecureInput.set`, `NewVaultView.swift:277`, `VaultSettingsPages.swift:250`).
  - Needs Mac QA with the owner's go: the VoiceOver walk (T43), the event-tap probe (T21), and the focus ring on a key window.

### 2. Part B1 and B2: the story checks

#### Commands

```
cd /tmp/e5s8-verify-copy; . "$HOME/.cargo/env"; export CARGO_TARGET_DIR=/tmp/e5s8-verify-target
cargo test -p app-ffi --test verify_e5s8 -- --ignored --nocapture --test-threads=1 b1_   → test result: ok. 1 passed … finished in 40.30s
cargo test -p app-ffi --test verify_e5s8 -- --ignored --nocapture --test-threads=1 b2_   → test result: ok. 1 passed … finished in 16.46s
/tmp/e5s8-verify-scripts/ref.sh <vault> <password|-> [keyfile]   (REF_CLI db-info -q, ls -R -q, export -q | meta.py; HOME=/tmp/e5s8-verify-work/refhome)
/usr/bin/python3 -I /tmp/e5s8-verify-scripts/header.py <files>  (outer header fields, FMT-02/FMT-03 layout)
```

The b1 driver follows `NewVaultModel` step by step, with the same app-ffi calls:

1. `Wizard::new(session)` and `defaults()`.
2. `measure(defaults)` once step 2 appears, then `measure(custom)`.
3. `check_encryption(choice, recommended, answers)`; each question is answered yes, and the yeses are kept (`stepAnswers`).
4. `set_password` and `set_repeat`.
5. `new_key_file(path)`.
6. `create(name, description, "", choice, recommended, stepAnswers + createAnswers)`; `Done` stands for the save panel.
7. `create(…, path, …)` gives `Created`.

After that the driver called `session.add_group` three times and `session.save`.

#### B1 output: our side (b1 driver, excerpts)

```
simple-argon2id: defaults EncryptionChoice { cipher: Aes256, kdf: Argon2id, memory_mib: 64, lanes: 4, unlock_ms: 1000 }
  step 2 asked [] -> Done
  key file simple-argon2id.appkey 278 bytes mode 400
  Create Vault asked [] -> Done
  write asked [] -> Created { vault: 1 } in 1.160698s
  vault file 1989 bytes mode 600
  OURS …/simple-argon2id-fresh.appvault: version 4.0 cipher Aes256Cbc kdf Argon2 { kind: Id, version: 19, iterations: 45, memory_kib: 65536, lanes: 4, salt: […] } compression Gzip
  OURS name "Verify simple-argon2id" description "Recommended (simple mode, 1.0 s)" groups ["Root"] entries 0
  OURS recycle_bin_enabled true recycle_bin None history 10 / 6291456 protect title false user false pass true url false notes false maintenance 365 keychange -1 -1
  save after groups: SaveStatus { changes: 0, saved_at: Some(1793198415), failure: None }
  OURS name "Verify simple-argon2id" … groups ["Root", "  Email", "    Work mail", "  Banking"] entries 0
argon2id-twofish:  kdf Argon2 { kind: Id, iterations: 29, memory_kib: 32768, lanes: 2 } cipher Twofish256Cbc; key file 278 bytes mode 400; vault 1509 bytes mode 600
argon2d-chacha:    kdf Argon2 { kind: D, iterations: 35, memory_kib: 24576, lanes: 1 } cipher ChaCha20;     key file 278 bytes mode 400; vault 1635 bytes mode 600
aeskdf-aes:        kdf AesKdf { rounds: 22935695 } cipher Aes256Cbc;                                         key file 278 bytes mode 400; vault 1959 bytes mode 600
password-only:     kdf Argon2 { kind: Id, iterations: 39, memory_kib: 65536, lanes: 4 } cipher Aes256Cbc; vault 1541 bytes mode 600
keyfile-only:      meter None match None; Create Vault asked ["M07-21"] -> Done; vault 1877 bytes mode 600
```

Unlock time item (custom data key `4b5058435f44454352595054494f4e5f54494d455f505245464552454e4345`): `1000` in Recommended, `300` in Custom.

Our session, for every vault: password plus key file gives `Unlocked`; password without the key file does not. Every vault holds Root only, 0 entries, the recycle bin on with no bin group, history 10 items and 6,291,456 bytes, Password protection only, maintenance 365 days, and key change −1 / −1 (MOD-12.22, T41, T46).

#### B1 output: the reference CLI

Each vault was opened as its fresh file and again after the group save. A wizard vault has no entries, so the password statistics rows are all 0 and are left out.

```
REF db-info simple-argon2id-fresh.appvault -k simple-argon2id.appkey (password given):
  | Name: Verify simple-argon2id
  | Description: Recommended (simple mode, 1.0 s)
  | Cipher: AES 256-bit
  | KDF: Argon2id (45 rounds, 65536 KB)
  | Recycle bin is enabled.
  | Number of groups: 1
  | Number of entries: 0
  exit 0
REF ls -R:
  | [empty]
REF export (meta and groups only):
  REF name 'Verify simple-argon2id' description 'Recommended (simple mode, 1.0 s)'
  REF recycle_bin_enabled True recycle_bin AAAAAAAAAAAAAAAAAAAAAA== history 10 / 6291456 maintenance 365 keychange -1 -1
  REF protect Title=False UserName=False Password=True URL=False Notes=False
  REF custom data keys (hex): [('4b5058435f44454352595054494f4e5f54494d455f505245464552454e4345', '1000'), ('4b5058435f52414e444f4d5f534c5547', '<836 chars>'), ('5f4c4153545f4d4f444946494544', '<28 chars>')]
  REF groups ['Root'] entries 0
REF db-info simple-argon2id.appvault -k simple-argon2id.appkey:   Number of groups: 4 … exit 0
REF ls -R:
  | Email/
  |   Work mail/
  |     [empty]
  | Banking/
  |   [empty]
REF db-info argon2id-twofish(.fresh).appvault -k …:  Cipher: Twofish 256-bit  KDF: Argon2id (29 rounds, 32768 KB)  exit 0; item '300'; groups as ours
REF db-info argon2d-chacha(.fresh).appvault -k …:    Cipher: ChaCha20 256-bit KDF: Argon2d (35 rounds, 24576 KB)   exit 0; item '300'; groups as ours
REF db-info aeskdf-aes(.fresh).appvault -k …:        Cipher: AES 256-bit      KDF: AES (22935695 rounds)          exit 0; item '300'; groups as ours
REF db-info password-only.appvault:                  Name: Verify password only  Description: (empty)  KDF: Argon2id (39 rounds, 65536 KB)  exit 0
REF db-info keyfile-only.appvault --no-password -k keyfile-only.appkey:  Name: Verify key file only  Description: No password (M07-21 answered yes)  exit 0
```

For all 10 files, the name, description, groups, cipher, KDF numbers, recycle bin, history limits, protection flags, maintenance days, key change values and unlock time item are equal on both sides. The full log was /tmp/e5s8-verify-work/ref-b1.log, deleted at the end.

The reference prints "Database created" one hour before "Last saved" for every file. It does the same for a vault it made itself (`REF_CLI db-create -p --decryption-time 100`: `Database created: 10/28/26 2:43 PM`, `Last saved: 10/28/26 3:43 PM` at 15:43 CET), so this is the reference's own display.

#### B2: encryption and credentials changed in the vault settings, then saved

Each case started from a copy of the Recommended wizard vault and its key file. The b2 driver opened it in a new session and called these, in order:
- `VaultSettings::apply` (name, description, history 25 items and 12 MiB);
- `set_cipher`;
- `measure`, then `set_kdf`;
- `set_password`, `set_repeat`, `change_password`;
- `new_key_file`;
- `Session::save`.

```
to-argon2d-chacha:
  view before EncryptionChoice { cipher: Aes256, kdf: Argon2id, memory_mib: 64, lanes: 4, unlock_ms: 1000 } iterations 45
  general apply -> Done
  set_cipher asked [] -> Done
  set_kdf asked [] -> Done
  change_password asked [] -> Done
  new_key_file -> Then { outcome: Done }
  view after EncryptionChoice { cipher: ChaCha20, kdf: Argon2d, memory_mib: 48, lanes: 3, unlock_ms: 700 } iterations 39 key file Some("to-argon2d-chacha-new.appkey")
  save: 5 changes -> SaveStatus { changes: 0, saved_at: Some(1793198638), failure: None } in 826.158542ms
  OURS session unlock with old password + old key: Failed { … id: "M06-06" … }
  OURS session unlock with new password + old key: Failed { … id: "M06-06" … }
  OURS session unlock with old password + new key: Failed { … id: "M06-06" … }
  OURS session unlock with new password + new key: Unlocked
  OURS session unlock with new password, no key: Failed { … id: "M06-06" … }
to-aeskdf-twofish:
  view after EncryptionChoice { cipher: Twofish256, kdf: AesKdf, … unlock_ms: 400 } iterations 34471819 key file Some("to-aeskdf-twofish-new.appkey")
  save: 5 changes -> SaveStatus { changes: 0, … failure: None } in 645.501917ms
  (the same five unlock results)
```

The header bytes, from `header.py` on the file before and after the save:

```
to-argon2d-chacha-before.bin: signature 03d9a29a67fb4bb5, version 4.0, header 253 bytes, header sha256 7b324f2776255d35
  cipher id       31c1f2e6bf714350be5805216afc5aff (AES-256)
  master seed     d888a4362b7911b0631bae670c95d55a…
  encryption IV   6d002fca33da047d6602cb30e9d640d8
  KDF parameters  $UUID 9e298b1956db4773b23dfc3ec6f0a1e6 (Argon2id), I 45, M 67108864, P 4, V 19, S(salt) f1179e6dfca052ed…
to-argon2d-chacha-after.bin: signature 03d9a29a67fb4bb5, version 4.0, header 249 bytes, header sha256 3c255ea498852ad2
  cipher id       d6038a2b8b6f4cb5a524339a31dbb59a (ChaCha20)
  master seed     3c28fb627ca9dd30ec77c94ce5d878a4…
  encryption IV   99c1d4520e80aa31fa9f1b14
  KDF parameters  $UUID ef636ddf8c29444b91f7a9a403e30a0c (Argon2d), I 39, M 50331648, P 3, V 19, S(salt) 993aa5800cccfdf6…
to-aeskdf-twofish-after.bin: signature 03d9a29a67fb4bb5, version 4.0, header 207 bytes, header sha256 e545a50a4a075e5b
  cipher id       ad68f29f576f4bb9a36ad47af965346c (Twofish-256)
  master seed     25284ae4b393e8d385a11167c783862f…
  encryption IV   384b54f331260f7bf5c42cd71746a1a8
  KDF parameters  $UUID c9d9f39a628a4460bf740d08c18a4fea (AES-KDF), R 34471819, S(salt) 59732a434996d482…
```

The cipher id, KDF id and parameters, salt, master seed and IV all changed. ChaCha20's IV is 12 bytes, as CRY-01 says.

The reference CLI on the same files (ref-b2.log):

```
== to-argon2d-chacha, the file before the change, old credentials:  Cipher: AES 256-bit  KDF: Argon2id (45 rounds, 65536 KB)  exit 0
-- old password + old key:   exit 1
-- new password + old key:   exit 1
-- old password + new key:   exit 1
-- new password, no key:     exit 1
-- new password + new key:   Name: Changed to-argon2d-chacha  Description: Changed by the vault settings  Cipher: ChaCha20 256-bit  KDF: Argon2d (39 rounds, 49152 KB)  exit 0
   REF … history 25 / 12582912 …; unlock time item '700'
== to-aeskdf-twofish:  the same four exit 1;  new password + new key: Cipher: Twofish 256-bit  KDF: AES (34471819 rounds)  exit 0; history 25 / 12582912; item '400'
```

### 3. Part B3: the card cases

Test sources:
- **R:** builder Rust tests: app-ffi `tests/new_vault.rs` (10) and `tests/vault_settings.rs` (5), the `wizard::tests` and `vault_settings::tests` unit tests (5), and app-core `tests/mod12.rs` (28).
- **S:** builder Swift tests: `NewVaultBehaviourTests` (8), `VaultSettingsBehaviourTests` (7) and the two snapshot suites.
- **VR:** my Rust drivers b1 to b5.
- **VS:** my `VerifyE5S8Tests`.

Rerun in the copy:
- `cargo test -p app-ffi --test new_vault --test vault_settings`: `10 passed`, `5 passed`.
- `cargo test -p app-ffi --lib -- wizard:: vault_settings::`: `5 passed`.
- `cargo test -p app-core --test mod12`: `28 passed`.
- `cargo test -p app-platform --lib thread_cpu`: `thread_cpu_time_stands_still_while_the_thread_sleeps ... ok`.
- My `VerifyE5S8Tests`: `✔ Test run with 18 tests in 3 suites passed` (together with the two builder behaviour suites).

#### APP-07

| Case | Result | Proof |
|---|---|---|
| T01 | PASS | VS `oneWizard`: `presented 2 times, same model true, same window true, title New Vault`. ⇧⌘N is in `AppMain.swift:31-32`. |
| T02 | PASS (model) | `.onExitCommand` → `cancel()` (`NewVaultView.swift:45`). S `steps`: Cancel closes and nothing is written. A real Escape key press is Mac QA. |
| T03 | PASS | VR b3: `after Cancel the key file has 278 bytes, mode 400; vault files in the folder: 0`. |
| T04 | PASS | S `steps`: after Back, Back, Continue, Continue, Rust still holds `demo-new-1` with 10 dots, and step 1 keeps "Family". |
| T05 | PASS | VR b1: DatabaseName equals step 1's name, read by our reader and by REF. "Passwords" is the default (`NewVaultModel.name`). The selected Name field is in the step-1 frame. |
| T06 | PASS | VR b3: `vault list name "Unnamed"`; DatabaseName `""`. |
| T07 | PASS | VR b1 Recommended: AES-256, Argon2id, 65,536 KiB, P 4 = min(4, 14), measured iterations, item `1000`. R `app07_6_the_defaults`. |
| T08 | PASS (unit) | R `app07_8_iterations_for_any_time_from_one_run`: 2.5 s computed from the 1 s run, no new run. |
| T09 | PASS | The lists are AES-256, Twofish-256, ChaCha20 and Argon2id, Argon2d, AES-KDF (`NewVaultParts.swift:22-24`). The defaults are in S `encryption`. |
| T10 | PASS | S `encryption`: AES-KDF, then Argon2id, gives 64 MiB and the default lanes again, with a measurement after each. |
| T11 | PASS | VS `sameFamily`: `after Argon2d: memory 128, lanes 3, measuring false`. |
| T12 | PASS | VS `sameFamily`: `measuring true, canContinue false`. The run happens in `Task.detached` (`NewVaultModel.measure`). |
| T13 | PASS (unit) | R `app07_8_…`: capped at 1,000,000,000. |
| T14 | PASS (code) | `wizard.rs:275-277` stores `host.aes_record` and `host.argon2_record` (F4: thread CPU clock). There is no direct test (advisory 4). |
| T15 | PASS (core); screen waits | app-core `app07_9_safe_minimum_asks_before_the_slow_warning` checks M07-33 then M07-31. R `cry02_14_…` checks M07-33 then M07-34. M07-31 cannot be reached through Option A's Custom, which has no Iterations field. |
| T16 | PASS | S `encryption` and R `app07_9_step_two_checks_and_m07_35`: M07-35 shows and Continue is off. |
| T17 | waits for a mockup addition | Custom has no Rounds field, and AES-KDF at 100 ms already gives millions of rounds here. app-core `mod12_kdf_warnings_and_refusal` checks M07-32. |
| T18 | waits for a mockup addition | Option A has no advanced mode with typed iterations. Custom writes the unlock time item (`300` in VR b1); see open issue 1. |
| T19 | PASS | S `password`: the M07-20 line and the check mark. |
| T20 | PASS | S `password`: Generate fills both fields. |
| T21 | Mac QA | `SecureInput.set` runs on focus. The event-tap probe needs the owner's go. |
| T22 | PASS | R `app07_13_t22_t36_…`. VR b1: 278 bytes at mode 0400, and REF opens with `-k`, so the key file's data is used. |
| T23 | PASS | R `app07_13_t23_never_over_an_existing_file`. Mutant R2 is caught. |
| T24 | PASS | VR b5: `Refused { id: "M07-25", text: "The new key file \"k.appkey\" was not written: App is not allowed to write there." }; file exists afterwards: false`. |
| T25 to T27 | PASS | R `app07_14_t25_t26_t27_chosen_key_files`. |
| T28 | PASS | R `app07_16_the_checks_in_the_cards_order` and S `password`. |
| T29 | PASS | R `app07_16_t29_…`. VR b1 key-file-only: `asked ["M07-21"]`, and REF `--no-password -k` exits 0. |
| T30 | PASS | S `weak` (Cancel keeps step 3; "Use this password" goes on). VR b3 with S-CFG-02 = 0 gives `M07-23`. |
| **T31** | **FAIL** | VR b3, `S-CFG-02 = 3 (store reads 3)`: Create Vault with `password1` gives `Ask { question: Question { id: "M07-23", … confirm: "Use this password" … } }` instead of M07-22. `wizard.rs:1119` passes `min_quality: 0`. |
| T32 | PASS | R `app07_16_the_checks_in_the_cards_order`: M07-21, then M07-24. |
| T33 | PASS in part; panel is Mac QA | The panel is titled "Save the New Vault", with `<name>.appvault` (`Passwords.appvault` by default) and the type `appvault`. It starts in Documents. The last-folder memory (S-STATE-06) is a later pass, as the E5-S9 inventory says. |
| T34 | PASS | R `app07_17_t34_…`. Mutant R5 is caught. |
| T35 | PASS | VR b1 and REF: 0600, version 4.0, AES-256, Argon2id, gzip; it opens in both tools. |
| T36 | PASS | VR b1: all 5 key file vaults open in REF with `-k`. |
| T37 | PASS | R `app07_17_…_and_t37_no_partial_file`. |
| T38 | PASS | S `create`: Cancel in the panel stays on step 3 and the password is kept. |
| T39 | PASS | S `create`: the window shows the new vault, unlocked. VR b3: `recent top Some("/private/tmp/e5s8-verify-work/b3/Unnamed.appvault")`. After the lock, an unlock without a password gives `M06-05` and with it `Unlocked`, so there is no quick unlock. |
| T40 | later story | The FEA-08.5 import (E5-S11). |
| T41 | PASS | VR b1, our reader and REF (see B1). |
| T42 | PASS | R `fmt18_24_the_vault_itself_is_never_its_key_file` gives M06-30. |
| T43 | Mac QA | VoiceOver. The trees have 0 unnamed controls. |
| T44 | not in Option A | Option A always draws the "More protection" rows; there is no "Add a Key File or Security Key" button. |
| T45 | E10 | The security key is drawn and disabled. |

#### MOD-12

| Case | Result | Proof |
|---|---|---|
| T01 | waits for a mockup addition | Option A draws General, Security, Recycle Bin, History and Browser Keys. It has no field protection, key change reminders, remote sync, shared groups or maintenance pages, and no secret service page. |
| T02 | not in Option A | Option A applies each control at once (no Apply drawn). app-core `mod12_02_apply_is_all_or_nothing` passes. |
| T03 | PASS | app-core `mod12_03_…`. S `general`. |
| T04 | PASS | S `general` sets the default username. app-core `edit.rs:255` fills it into new entries. |
| T05 | waits for a mockup addition | Option A has no Clear control. See open issue 2 about the "not encrypted" notice. |
| T06, T08 (reference), T47 | reference only | — |
| T07 | PASS | app-core `mod12_05_history_limits`. The page sends only touched values (`SettingsChange` `None`). |
| T08 (App), T09b | PASS | The steppers never store more than 2,047 MiB or 100,000 items: past the top they give "no limit", −1 (`VaultSettingsActions.swift:122,129`). |
| T09, T10 | PASS | app-core `mod12_05`. S `history`. |
| T11, T12 | PASS | S `bin` and app-core `mod12_06_recycle_bin`. |
| T13, T14, T15 | waits for a mockup addition | Option A has no compression or autosave control. app-core `mod12_07` and `mod12_08` pass. |
| T16 | PASS | app-core `mod12_09_settings_time`. |
| T17 | PASS | R `mod12_10_…`: M07-21, then a vault that opens with the key file only. |
| **T18** | **FAIL** | VR b3, S-CFG-02 = 3: Change… with `password1` gives `Ask { … "M07-23" … }` instead of the refusal. `vault_settings.rs:221` passes `min_quality: 0`. |
| T19 | PASS | VR b3 with S-CFG-02 = 0: M07-23, with Cancel as the default. |
| T20 | PASS | R `mod12_10_…`: M07-24. |
| T21 | PASS | B2 and R `mod12_10_…`: MasterKeyChanged moves, and only the new key opens. The force-once flag is checked in app-core `mod12_force_once_and_same_values`. Quick unlock is E6-S3. |
| T22 | PASS | app-core `mod12_10_changing_the_key`. |
| T23 | PASS | M07-28 note for early key file kinds (R `app07_14_…`). The settings page uses the same `choose_key_file`. |
| T23b | E5-S10 | MSG-KEY-OLD-COPIES needs backups. |
| T24 | PASS | The view reads the item: B2 shows `unlock_ms: 1000` from the item. R `mod12_14_…` checks `view.encryption == choice`. |
| T25 | waits; PASS (core) | The iteration and rounds fields are not drawn. app-core `mod12_kdf_warnings_and_refusal` passes. |
| T26 | PASS | R `mod12_14_…`: M07-33 shows the time. |
| T27 | PASS | R `cry02_14_an_approved_costly_kdf_saves_without_asking`: M07-34 is asked before any work. |
| T28 | waits for a mockup addition | Option A has no advanced mode. |
| T29 | PASS | VR b3: `MOD-12 T29: before 3.1`, then `after 4.0`. |
| T30 | PASS | B2: REF `Cipher: ChaCha20 256-bit`. In Swift, the save runs off the screen thread. |
| T31 | PASS | VR b3: `set_cipher(same) -> Done, changes 0 -> 0`. |
| T32 to T36 | waits for a mockup addition | Option A has no field protection page. app-core `mod12_15`, `mod12_16` and `mod12_17` pass. |
| T37 | PASS | R `mod12_18_browser_keys_and_site_permissions` and S `browser`: Disconnect asks first. |
| T38, T40 | waits for a mockup addition | Neither control is drawn (MOD-12.18 "No screen yet"). |
| T39 | PASS | R `mod12_18_…` and S `browser`: Remove all… asks first. |
| T41 | not built | The page does not read S-BRW-01, which is off by default. The off state and its notice are not drawn. See open issue 3. |
| T42, T43 | waits for a mockup addition | Option A has no maintenance page. |
| T44 | PASS | app-core `mod12_20_values_with_no_control_are_kept`. |
| T45 | E5-S10 | APP-05's save error flow. `Session::save` keeps the change count and the failure. |
| T46 | PASS | VR b1 (see B1). |

**The smallest fix for T31 and T18, checked in the copy.** I replaced `min_quality: 0` in `wizard.rs:1119` and `vault_settings.rs:221` with `u8::try_from(self.session.settings().number("security.min_master_quality".into()).clamp(0, 4)).unwrap_or(0)`. b3 then printed `S-CFG-02 = 3 … wizard Create Vault with password1 -> Refused { id: "M07-22", text: "This password is weaker than App allows. Choose a stronger one." }`, and the same `Refused` for Change…. With S-CFG-02 = 0 it still gave M07-23. Both files were then restored, and `cmp` showed them equal to the originals.

### 4. Part B4: secrets (rule 4)

**Code reading.**
- The wizard passes each SecureField's text straight to Rust (`passwordTyped` → `core.setPassword`). Swift keeps only the length and the meter.
- Show values exist only while Show is on.
- Rust keeps the pair in `SecretString`s. A key file's bytes never leave Rust.
- `Wizard::password()` and `repeat()` return the text only for Show.

**Memory scan, model level (AT-C02).** VS `memory` scans this test process's own readable and writable regions:
- it walks them with `mach_vm_region_recurse` on `mach_task_self_`;
- it reads each 1 MiB chunk with `mach_vm_read_overwrite` into a scratch buffer, which is skipped by the scan and zeroed after each chunk;
- it searches with `memchr`.

The needle is kept only reversed, in UTF-8 and UTF-16LE. The output, from `xcodebuild … test '-only-testing:AppTests/VerifyE5S8Tests/memory()'`:

```
VERIFY E5S8 memory A typed: utf8 2 utf16 0
VERIFY E5S8 memory A after the write, vault open (Rust keeps the key parts for saves): utf8 1 utf16 0
VERIFY E5S8 memory A after lock: utf8 0 utf16 0
VERIFY E5S8 memory B typed in Change…: utf8 2 utf16 0
VERIFY E5S8 memory after close: A utf8 0 utf16 0; B utf8 0 utf16 0
VERIFY E5S8 reopen with B: unlocked
VERIFY E5S8 reopen with A: failed(message: AppCore.UnlockMessage(id: "M06-06", …))
VERIFY E5S8 memory C typed: utf8 2 utf16 0
VERIFY E5S8 memory C after Cancel: utf8 0 utf16 0
✔ Test "Verify rule 4: the typed master passwords in memory while typed, after the write, lock and close, and after Cancel" passed after 21.657 seconds.
```

- **While typed.** There are 2 copies: Swift's typed string and Rust's `SecretString`.
- **While the new vault is open.** Rust's save key parts hold 1 copy, in a wiping type, so each save can derive with a fresh salt.
- **After lock, close and Cancel.** None.
- **API checks.** R `mod12_10_…` and my b1 assert `password() == ""` after the change and after the write.
- **Limit.** The rendered SecureField and a dump of the real App.app are Mac QA, as in E5-S6.
- **One run under load average about 100 failed.** In the first version of this test, one session unlocked the vault with A and then with B. After A's failure, B's result was not `.unlocked`. I did not capture the value. Three later runs of the same steps passed, among them `probe same session: wrong failed(… M06-06 …); right unlocked`. Rust `b4` (wrong then right in one session) also gives `Unlocked`. My guess is the M06-34 cost question from a wall-clock calibration on a heavily loaded Mac. That is APP-06, not this story: see advisory 6.

### 5. Part B5: mutations (private copy only)

Each mutant was put in with an exact replace, run, then the file was restored from /tmp/e5s8-verify-work/orig. `cmp` said "restored, cmp equal" every time.

Rust (`cargo test -p app-ffi --test new_vault --test vault_settings`):

| Id | Mutation | Result |
|---|---|---|
| R1 | key file `.mode(0o400)` → `0o600` | CAUGHT: `app07_13_t22_t36_a_new_key_file_and_a_vault_that_needs_both` (new_vault.rs:186) |
| R2 | existing-file refusal off (`if false`) | CAUGHT: `app07_13_t23_never_over_an_existing_file` |
| R3 | match check off in `create` | CAUGHT: `app07_16_the_checks_in_the_cards_order` |
| R4 | key file left out of the composite key at the write | CAUGHT: `app07_16_t29_…` and `app07_13_t22_t36_…` |
| R5 | M07-29 own key file check off | CAUGHT: `app07_17_t34_never_over_its_own_key_file_and_t37_no_partial_file` |
| R6 | `set_cipher` always AES-256 | CAUGHT: `mod12_14_a_changed_cipher_and_kdf_are_in_the_saved_header` |
| R7 | step 1 name not applied | CAUGHT: `app07_17_t35_…` (new_vault.rs:130) |
| R8 | unlock time item never written | CAUGHT: `app07_9_step_two_checks_and_m07_35` and `app07_17_t35_…` |
| R9 | default lanes `clamp(1, 4)` → `clamp(1, 8)` | CAUGHT: `app07_6_the_defaults` |
| R10 | typed passwords kept after a key change | CAUGHT: `mod12_10_a_credential_change_needs_the_new_credentials_to_open` (vault_settings.rs:127) |

Swift (`xcodebuild … -only-testing:AppTests/NewVaultBehaviourTests -only-testing:AppTests/VaultSettingsBehaviourTests -only-testing:AppTests/VerifyE5S8Tests`; baseline `✔ Test run with 18 tests in 3 suites passed after 17.223 seconds.`):

| Id | Mutation | Result |
|---|---|---|
| S1 | Continue on step 2 allowed while measuring | CAUGHT only by VS: `Expectation failed: model.measuring && !model.canContinue`. No builder test covers T12 (advisory 3). |
| S2 | `cancel()` without `hidePasswords()` | SURVIVED (advisory 5) |
| S3 | no new measurement after a memory or lanes change | CAUGHT: `APP-07.9, APP-07.16: Create Vault after a step 2 yes asks no step 2 question again` |

### 6. Fails, each with its smallest fix

1. **APP-07 T31 and MOD-12 T18, the minimum master password quality (S-CFG-02; APP-07.16 check 3, MOD-12.10 step 3, SF-16).**
   - The settings store holds `security.min_master_quality`, and the E5-S9 inventory hands it to E5-S8. But `wizard.rs:1119` and `vault_settings.rs:221` pass `min_quality: 0`.
   - So with a minimum of 3, a too-weak password only gets "Use this password" and is accepted.
   - Smallest fix: read the store, as shown in section 3 (`u8::try_from(self.session.settings().number("security.min_master_quality".into()).clamp(0, 4)).unwrap_or(0)` in both places). Add one test per screen: the store at 3, then `password1` must give M07-22.
2. **Parity `vault-new-vault-step-2`, dark 7.07 % (over 3 %).**
   - The whole difference is the card's two-line M07-05 step line, which moves the choices 20 pt. The shift is recorded, and every text run is within 2 pt after it.
   - Smallest fix: the lead accepts it as a card-words difference (an LD line, so compare.mjs counts it as accepted), or the owner puts the card's line into the mockup.
3. **Parity `dialogs-weak-vault-password`, 3 boxes 44 pt off.**
   - The cause is the card's one-sentence MSG-MK-WEAK, with "Use this password" and "Cancel".
   - Smallest fix: the same as fail 2.

### 7. Open issues and advisories (not fails)

1. **The unlock time item in Custom mode.**
   - A vault made in Custom mode gets the item (VR b1: `300`).
   - The card says advanced mode writes none (APP-07.10, T18, MOD-12.12). But Option A's Custom has no Iterations field: the user picks an unlock time, and MOD-12.22 writes the item "when the user picks a time".
   - Needs a lead ruling. Today's behaviour is consistent with Option A.
2. **MOD-12.4 and SF-12: no "not encrypted" notice.**
   - The General page shows the mockup's line, "Shown in the sidebar and on the lock screen".
   - The card says the group says that these values are not encrypted and that anyone with the file can read them.
   - Lead ruling: keep the mockup's line, or add the card's sentence.
3. **MOD-12 T41: the Browser Keys page does not follow "Let browsers use App" (S-BRW-01).**
   - That setting is off by default, and the page stays usable when it is off.
   - The off state and its notice are not drawn. Its actions only remove access and they ask first.
   - Lead ruling, or a mockup addition.
4. **Test gaps.**
   - No builder test covers T12, Continue disabled while measuring (mutant S1).
   - No builder test covers T14, the speed record kept after a measurement (code at `wizard.rs:275-277`).
   - The Checker's advisory still holds: no test pins `thread_cpu_time` as the clock that `wizard::measure` uses.
5. **Mutant S2 survived.** `cancel()` without `hidePasswords()` fails no test. The Show strings go with the model when the wizard window is freed (`AuxWindows`), so the risk is low.
6. **Load-dependent unlock (APP-06, not E5-S8).** One run under load average about 100 may have hit the M06-34 cost question on a second unlock in one test session; see section 4. That calibration is app-crypto `assess` → `calibrate`. Worth a look when the Mac is quiet.
7. **Touch ID in the wizard.** The switch is drawn on and disabled (`.constant(true)`, mockup look). APP-07.18 makes no quick unlock slot, which VR b3 confirms. A disabled "on" switch may suggest that Touch ID was set up. Lead or owner.
8. **Wording.** The cipher and KDF list items read "AES-256" and "Argon2id", where M07-07 has "AES-256 (default)" and "Argon2id (recommended)". The open list is not drawn in Option A.
9. **Mac QA (needs the owner's go).**
   - The real save panel: the `.appvault` type and its own replace question (type "Work" next to Work.appvault).
   - T21 secure input, T43 VoiceOver, and the focus ring on a key window.
   - Escape and Return in the real window.
   - The wizard is its own window, not a sheet: APP-07.2 says sheet, Option A draws a window.
10. **Builder's not-built list, unchanged.** The Caps Lock note, the 30 s field clear, MSG-KEY-OLD-COPIES (E5-S10), the Browser Keys gate (item 3), S-STATE-06 folders (E5-S9 later pass), and S-CFG-02 (fail 1).

### 8. Cleanup

I deleted /tmp/e5s8-verify-copy, /tmp/e5s8-verify-target, /tmp/e5s8-verify-dd, /tmp/e5s8-verify-work (the demo vaults, key files, logs and the throwaway reference home) and /tmp/e5s8-verify-scripts. /tmp/parity-tools (pixelmatch and pngjs, shared by every parity run) was left in place.

Files changed in the tree:
- this file;
- design/parity/vault/ (report.md, report.html, findings.json, app/ and diff/, regenerated, with a "Verify run for E5-S8" section);
- design/parity/dialogs/report.md (one Verify line under each of the two E5-S8 frames);
- plan/epics.md (the E5-S8 status line).
