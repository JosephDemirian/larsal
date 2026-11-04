# E13-S6 part e: re-test of F-085, F-086, F-087, F-088, F-089, F-073, F-075, SD-07, F-090, F-091, F-092

Story: E13-S6 part e ([plan/epics.md](../../plan/epics.md)). Rows: [security/findings.md](../findings.md), SD-07 and SI-14 in [plan/security.md](../../plan/security.md). Earlier proof: [E13-S1-SD.md](E13-S1-SD.md) (SD-01, SD-03, SD-05, SD-11, SD-12), [E13-S1-SF.md](E13-S1-SF.md) (SF-03, SF-12), [E13-S1-SI.md](E13-S1-SI.md) (SI-06, SI-07, SI-14). Rulings: LD-223 (owners), LD-50 and APP-02.16 (automatic locks never wait), LD-52 and LD-200 (APP-05.14), LD-53 (APP-05.33), LD-129 (APP-05.11 step 5), LD-220.
Date: 2026-10-29 (the clock read 2026-10-30, 01:20 to 01:45). Role: Verify, round 1. I did not find, build or check these fixes.

| Row | Result | One line |
|---|---|---|
| F-085 (High) | **fixed, re-tested** | Merge, Discard, the sheet's Cancel and the silent reload of a file re-keyed elsewhere all behave as APP-05.29 says; every saved file opens with the new password only. |
| F-086 (High) | **fixed, re-tested**; residual for the lead | The row's steps now ask after 0.57 s and Save stores the outside edit. A lock still wipes a changed copy (automatic: by design; manual: APP-02.15 step 7 is not built, new finding proposed). |
| F-087 | **fixed, re-tested** | The third failed safe save asks; Turn off saves this vault directly; a read-only folder never asks (LD-200). |
| F-088 | **fixed, re-tested** | The key-change save lists the backup (opens with the old password) and the recovery copy; Delete checked removes them; later saves list nothing. |
| F-089 | **fixed, re-tested** | Through App's own save: birth date 2020-01-01, Finder tags and the ACL entry survive the rename. |
| F-073 | **fixed, re-tested** | The public id stays the target's in every merge kind; NAME still merges. |
| F-075 | **fixed, re-tested** | The save after `tune` estimates from the tune's run and measures nothing again. |
| SD-07 | Rust half **re-tested**; row stays todo | `export_vault` and `export_passkey` write nothing without the warning; `app export` warns; the window has no export path yet. |
| F-090 | **fixed, re-tested** | With the flag never seen, the fixed loop ends in 1.22 s with its message; the old loop spun for 62 s until stopped by its PID. |
| F-091 | **fixed, re-tested** | SI-14 now says what the reference does (both permissions) and what App does (Accessibility only). |
| F-092 | **fixed, re-tested**; note | t40 and int05_match bound CPU time; int06_22 is event based, with the agent client's 2 s timeout as the one time bound left. |

Eleven rows re-tested; no re-test failed. SD-07 stays todo until the export screens exist.

## Setup

- Private copy: `rsync -a --exclude target --exclude app-shots` to `/tmp/e13s6e-verify-copy`, `CARGO_TARGET_DIR=/tmp/e13s6e-verify-target`, `-derivedDataPath /tmp/e13s6e-verify-dd`. Two changes in the copy only, as the builder and Checker 1 made: `Option<crate::hwkey::Choice>` became `Option<()>` in app-ffi edit.rs (part f had not landed, so app-ffi did not build in the shared tree), and LockSignalsTests.swift:323 became `allSatisfy { $0.locked }` (the known 'call can throw' compile error).
- Baseline in the copy: `cargo test --locked -p app-ffi --lib --features net`: 130 passed, 0 failed (`sd_07_every_plain_export_warns`, `f_085`, `f_086`, `f_087`, `f_088` ok). `cargo test --locked -p app-core`: 31 `test result: ok`, 0 FAILED (`f_073_merge_leaves_the_public_id_alone`, `f_075_tune_keeps_the_record_for_the_save`, `f_089_safe_save_keeps_creation_date_tags_and_acl` ok). `cargo test -p app-ffi --test session --test ssh`: 11 and 17 passed. `cargo test -p app-autotype`: all ok (int05 51, int05_match 37). `cargo test -p app-platform`: all ok.
- Swift: `scripts/build-core.sh` ('build-core (debug): target/app-core/AppFFI.xcframework'), then `xcodebuild ... test -only-testing:AppTests/DataSafetyTests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: 8 of 8 passed, '** TEST SUCCEEDED **'. Nearby suites (DataSafetyTests, EditorSnapshotTests, ParitySavingTests, ParityEditorFilesTests, SavingSnapshotTests), same flags: 'Test run with 31 tests in 5 suites passed', '** TEST SUCCEEDED **'. Tests run under XCTest offscreen: the file opener and the key file panel are stubs; no window ordered front, no pasteboard.
- Mutations: each in the copy only, one exact replacement, the test run, the file restored from its backup and compared with `cmp` (Rust: 13 mutants one at a time; Swift: 9 mutants in two batches). All mutated files are byte-identical to the shared tree afterwards (edit.rs apart from the stub above).
- Shared tree, read only: `xcrun swift format lint --strict` on VaultEdits.swift, Saving.swift, SavingSheets.swift and DataSafetyTests.swift: exit 0. `cargo fmt --check`: no diff in part e's files. A build of app-ffi in the shared tree with its own target failed on other parts' work in progress (`duplicate definitions with name after_unlock`, `no method named auto_open`), so all runs above are from the copy. While I worked, part f (F-107) changed saving.rs in the shared tree: the kept hardware key now joins the credentials of `take_disk_version` and the save. Part e's logic is unchanged by it.

## F-085: a file re-keyed elsewhere (APP-05.29)

- **Steps (the row's, demo vault option-a-family, password demo-pass-9):** window A unlocks and adds 'Mine unsaved' without saving; a second session adds 'Theirs', changes the password (vault settings, MOD-12.10) and saves. A's `check_disk`, then each answer, then the unlock sheet's password (first the old one, then the new one), then a save. Probe test `verify_probe_f085_row_steps` in the copy.
- **Before** (the row): Merge and Discard returned `NewKey` and Swift only showed a notice; Keep mine plus save wrote the old password and lost 'Theirs'.
- **After:**
  - Merge: `check=Ask { ask: Unsaved, changes: 1 } first=NewKey old_password=NewKey new_password=Reloaded open=["Mine unsaved", "Theirs"] save=(changes 0, ...) file_new=Some(["Mine unsaved", "Theirs"]) file_old=None`.
  - Discard: `... new_password=Reloaded open=["Theirs"] ... file_new=Some(["Theirs"]) file_old=None`.
  - The sheet's Cancel (Later, as APP-05.27 Cancel): `first=None ... open=["Mine unsaved"] save=(changes 1, on_disk Some(OnSave))`: nothing written, the next save asks again.
  - Silent reload (no unsaved change): `check=NewKey new_password=Reloaded save_changes=0 file_new=Some(["After reload", "Theirs"]) file_old=None`.
  - Swift: `DataSafetyTests/f085RekeyedFileUnlocksAndMerges` (the sheet 'Unlock the changed “Personal.appvault”', a wrong password keeps it with 'That password or key file does not open the changed file.', the new one merges and saves) and `f085BrowsePicksTheKeyFile` (a file re-keyed to a key file only; Browse… with the panel stubbed; both sides kept; the file opens with the key file) pass.
- **Mutants:** the entered key ignored in `take_disk_version` (`match &None::<NewKey>`): `f_085 ... FAILED`, saving.rs:1690 `left: NewKey right: Reloaded`. The key not kept (no `set_key`): FAILED, the saved file no longer opens with the new password (saving.rs:886). Swift: `handle(.newKey)` back to the old notice: f085Rekeyed fails at DataSafetyTests.swift:71, :73, :78; the Browse… button removed: f085Browse fails at :254 `screen.node("Browse…")`.
- **Note:** Browse… uses the New Vault key file panel (`NewVaultModel.openKeyFile`), not the unlock screen's, so the panel's words differ from APP-06's (Checker 1 saw the same; behaviour right).

## F-086: outside edits of an open attachment copy (MOD-05.13)

- **Steps (the row's):** Personal demo vault, the editor on the entry holding github-recovery-codes.txt (1229 bytes), Open (fake opener), wait 0.3 s, another app saves 130 bytes into the copy by writing a temp file and renaming it over (as most editors save), wait up to 6 s, answer, commit. Swift probe `VerifyProbeTests` in the copy.
- **Before** (the row): no watcher; after 6 s and a commit or lock the copy was wiped and the attachment kept its old 1229 bytes, with no question.
- **After:** `PROBE86 original=1229 dialog=Optional(...changedAttachment(name: "github-recovery-codes.txt")) after=0.574s`; after Save and commit: `editor=false copyExists=false stored=130 bytes (edit 130)`. Rust `f_086` and the four AppTests (`f086ChangedCopyAsksAndSaves`, `f086LeaveSaveAsksAboutTheChangedCopy`, `f086LeaveWithoutChangesAsksAboutTheChangedCopy`, `f086FileEventAsksBeforeTheCheck`) pass.
- **Mutants:** Rust, the sum compare never true: `f_086 ... FAILED` at saving.rs:1818 (`left: [] right: ["codes.txt"]`). Swift batch 1: the watch never asks (`lookAtCopies`): f086ChangedCopy fails at :152 and f086FileEvent at :224; `askChangedCopy` removed from `askLeave`: f086LeaveWithoutChanges fails at :209 to :211; `dialog = nil` removed from `answerLeave`: f086LeaveSave fails at :191 to :193. Batch 2: the DiskWatch per copy removed: f086FileEvent fails at :224 while f086ChangedCopy passes in 5.5 s through the 5-second check; `askChangedCopy` removed from `saveEditor`: f086LeaveSave fails at :191 to :193.
- **Residual (for the lead; the row's last sentence understates it):**
  - Manual lock: `PROBE86 lock: question before the lock=Optional(...changedAttachment...) dialog after=nil locked=true copyExists=false`. The question closes (APP-02.15 step 5) and the copy is wiped with no question. APP-02.15 step 7 asks `MSG-LOCK-DISCARD-EDIT` for a manual lock, quit or close with editor edits; `grep -rn LOCK-DISCARD-EDIT macos crates` finds nothing, and `MainWindowModel.lock(_:)` (line 161) has no `askLeave`, while `close(_:)` (line 192) has one. This is older than part e, also drops plain draft edits, and is outside part e's files: proposed as a new finding.
  - Automatic lock: drops editor edits by design (APP-02.16, LD-50), the changed copy included, also while its question shows (Checker 1's PROBE6). Accept.
  - Cancel at once after the outside save: `PROBE86 cancel: dialog=nil editor=false copyExists=false`. The file event needs about 0.5 s; `cancelEditor` has no synchronous check, unlike `askLeave` and `saveEditor`. Low; one line (`if askChangedCopy() { return }` in its no-change branch) closes it.
  - Minor: `askChangedCopy` (Save, leave) hashes the open copies on the main thread; only `lookAtCopies` runs off it. A copy near the attachment limit can stall the window briefly.

## F-087: repeated failed saves (APP-05.14)

- **Steps:** Personal (test) and option-a-family (probe): a committed change, then the vault's folder moved away (a reason another method can help with), 3 saves; folder back; Turn off; save. Probe `verify_probe_f087_permission_failures_do_not_ask`: the folder made read-only (0500), 4 saves.
- **Before** (the row): `storage::Failures` had no caller; MSG-SAVE-UNSAFE-ASK never showed.
- **After:** `asks == [false, false, true]`; after Turn off the file keeps its inode (direct write) and `save.alternative` is unchanged. Read-only folder: `[(false, Some("This vault's file or its folder cannot be written.")) x 4]`: never asks, as LD-200 rules. AppTests `f087ThirdFailureAsksToTurnOffSafeSaving` passes (Turn off pressed on the sheet, the file then holds 'Demo Shop').
- **Mutants:** the ask never set: `left: [false, false, false] right: [false, false, true]`, FAILED (saving.rs:1728). Turn off a no-op: FAILED at saving.rs:1735 'direct write' (inode 436421260 vs 436421232). Swift, the sheet branch removed: f087 fails at DataSafetyTests.swift:104.

## F-088: old copies after a key change (APP-05.33)

- **Steps (the row's, option-a-family):** settings folder set, a change, a recovery copy written, the password changed in vault settings, save; then Delete checked with the listed paths; then another change and save. Probe `verify_probe_f088_row_steps`.
- **Before** (the row): the save returned no notice; Vault.old.appvault still opened with the old password, unlisted.
- **After:** `old_copies=[".../Vault.old.appvault", ".../settings/recovery/4ea8cb39...bf.appvault"] backup_mode=Ok(384)` (0600) `backup_opens_old=true`; Delete checked: `left=[] still_there=[]`; next save: `old_copies=None`. The test also shows a path not listed is never removed. AppTests `f088OldCopiesAfterAKeyChange` passes.
- **Mutants:** the key-change mark undone (`self.disk.new_key = false`): FAILED at saving.rs:1758 (`left: None`). Swift, the sheet branch removed: f088 fails at DataSafetyTests.swift:123.

## F-089: creation date, Finder tags and ACL on a safe save (APP-05.11 step 5)

- **Steps (the row's, through App's own save):** option-a-family copied; its modification time set to 2020-01-01 (APFS moves the birth date back with it); `xattr -wx com.apple.metadata:_kMDItemUserTags 0102030405`; `chmod +a "everyone allow read"`; a change; `Session::save`. Probe `verify_probe_f089_through_the_session_save`.
- **Before** (the row): the birth date became the save time; tags and ACL were dropped.
- **After:** `birth before=1577836800 after=1577836800 same=true new_inode=true tags="01 02 03 04 05" acl=true`. The safe save replaced the file (new inode) and all three parts were copied. `write_export` passes `keep = false`, so an export never inherits an old file's ACL.
- **Mutant:** the `keep_file_info` call removed: `f_089 ... FAILED` at app05.rs:255 (birth `1793320287` against `1577836800`).
- **Note:** `keep_file_info` returns early when the creation date cannot be copied, so the tags and ACL are then skipped too; the save still succeeds. APFS and HFS+ support all three. The four new unsafe blocks in folder.rs still need the two-person review list (the builder's open item).

## F-073: merge of public header items (MOD-11.19)

- **Steps:** the test (the row's: the source has the public id item and newer settings; kinds CommandLine and Window). Probe `verify_probe_f073_target_id_kept_display_items_merged`: the target has its own public id (first byte 1), the source another (2) plus a NAME 'Theirs', settings one hour newer; kinds CommandLine, Window, ChangeOnDisk.
- **Before** (the row): the target's public id items went from 0 to 1.
- **After:** `PROBE73 CommandLine: target public id first bytes [1], names ["Theirs"]`, the same for Window and ChangeOnDisk.
- **Mutant:** `display_item` reduced to the prefix: FAILED at mod11.rs:2095.

## F-075: db-create under load (`settings::tune`)

- **Steps:** probe `verify_probe_f075_save_after_tune_does_not_measure_again`: `tune` with the test clock (AES-KDF and Argon2, no records), then `app_format::save` with the same host; compare the records before and after the save.
- **Before** (the row): the save calibrated again with no speed record, so a load swing between the two measurements could land in the ask band.
- **After:** `AesKdf { rounds: 1833334 }: records after tune (Some(... ms: 60), None); after save (the same); unchanged=true; file=true` and `Argon2 { iterations: 19, ... }: ... unchanged=true; file=true`. The estimate is about 1.1 times the target (5,500 ms at the 5,000 ms top of `-t`), under the 10,000 ms ask ceiling. `grep -rn 'tune(' crates/*/src`: one caller, app-cli commands.rs:1035; the wizard sets its records at wizard.rs:273 and :275.
- **Mutant:** the two record lines removed: FAILED at mod12.rs:648.

## SD-07: every plain export warns (FEA-09, INT-04.50)

- **Steps:** the test; `grep` for export callers in macos/App, app-ffi and app-cli; read `export_cmd`.
- **Before:** the parity row (the reference warns for CSV, HTML and XML, and not for passkey files).
- **After:** `export_vault` and `export_passkey` refuse with the warning's text unless `warned`, and write 0600 through `write_export`. `app export` prints 'Warning: this export is not encrypted. ...' on standard error for every format (plus the formula line for CSV). The window has no plain export path: File > Export's CSV, HTML and XML items are disabled (AppCommands.swift:104 to 108) and no Swift code calls `exportVault` or `exportPasskey`; there is no Export Selected.
- **Mutants:** `if !warned` disabled in `export_vault`: FAILED at export.rs:249 (`left: Ok(())`); in `export_passkey`: FAILED at export.rs:288 (`left: Ok(Written { ... })`).
- **Result:** the Rust half is re-tested. The row stays todo until the export screens exist; they need an owner (the builder's open item).

## F-090: the unlock-lock test loop and int05_match

- **Steps:** in the copy, `vaults()` changed to never show `unlocking` (the condition of the 16-minute spin); run the fixed test; then the old loop (no deadline, no end) under the same change, as a test binary started in the background.
- **Before:** `app06_16 has been running for over 60 seconds`; at 62 s elapsed with 31 s of CPU it was still spinning; stopped with `kill 23341` (its PID).
- **After:** `panicked at crates/app-ffi/tests/session.rs:449:5: the lock never landed during the unlock in 20 rounds`, `finished in 1.22s`. Unchanged, the test passes (session: 11 passed).
- **int05_match:** `timed` reads the thread's CPU time. A sleep of the limit plus 50 ms inside every timed call: 37 of 37 pass. The same with a wall clock: 5 fail ('8 hostile patterns, 8192-byte title took 1.05s', ...). So waiting for a core no longer counts.

## F-091: SI-14 wording

- **Before:** the reference column said 'no Screen Recording permission' (App's design).
- **After:** the row reads 'Asks macOS for the Accessibility and Screen Recording permissions when global Auto-Type is first used, and stops with a message when either is missing. App asks for Accessibility only and reads window titles through the Accessibility API (LD-176, F-091)'. I read the reference source's global Auto-Type start: it checks both permissions and its message names both. Text fix confirmed.

## F-092: wall-clock test bounds

- **t40:** measures the thread's CPU time. A 300 ms sleep in the measured part passes; with a wall clock it fails (int05.rs:915); a 300 ms busy loop fails (the bound still catches real work). Unchanged: ok.
- **int06_22:** a fake agent answers the add only after the unlock returned. With the unlock made to wait for the agent (`ssh_settled()` inside `unlock`, a mutant): FAILED (the fake's write at ssh.rs:240, then `fake.join()` at :260). Unchanged: ok (ssh: 17 passed).
- **Note:** a stall of 1.5 s before the fake answers passes and 2.5 s fails: the agent client's `TIMEOUT` (2 s, app-sshagent agent.rs:17) is the one time bound left, now over two thread wake-ups instead of an unlock with its KDF (the old 900 ms). The test's comment says a waiting unlock 'returns only after the fake's own 30 s timeout, with answered set'; in fact the client gives up after 2 s and the failure shows at `fake.join()`. The test still catches the regression; the comment should be corrected.
- No load run: I proved the mechanism with sleeps and stalls instead of keeping the owner's Mac busy.

## For the lead

1. F-086 residual: accept the automatic lock under APP-02.16 and LD-50. Do not accept the manual lock for the row's reason ('a lock never waits on a sheet'): `lock(_:)` already waits on `askUnsaved`. File a new finding: APP-02.15 step 7, `MSG-LOCK-DISCARD-EDIT` is not built, so a manual lock drops draft edits and changed copies with no question. Smallest fix: in `MainWindowModel.lock(_:)`, call `askLeave` before `askUnsaved`, as `close(_:)` does, plus one test. The owner is whoever owns MainWindowModel (E5 follow-up), not part e.
2. F-086 Cancel within 0.5 s: optional one-line fix in `cancelEditor`; otherwise name it in the residual.
3. SD-07: the export screens (File > Export, the Passkeys report's Export Selected) need an owner; the row closes when they call `export_warning` first.
4. F-092: correct the int06_22 comment (the 2 s client timeout, not 30 s).
5. F-089's four unsafe blocks go to the two-person review list.
