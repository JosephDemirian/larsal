# E13-S6 part n: test hygiene and small leftovers (Builder, 2026-10-30)

Story: E13-S6 part n ([plan/epics.md](../../plan/epics.md)). Rulings: LD-236 (2), LD-240 (5), LD-241 (2), LD-242 (4), LD-243 (3), LD-244 (2) (with LD-228, LD-230 (5), LD-232 (6), LD-237 (1), which they hand on). Rows: F-014, F-015, F-016, F-018, F-019, F-121 (name guard self-test, V-1 to V-7), F-065, F-092, F-127 in [security/findings.md](../findings.md). Role: Builder. I did not find these problems.

| # | Item | Result | Test or text |
|---|---|---|---|
| 1 | Temp folders left by the larsal-ffi test helpers | fixed | `test_dir::TempDir` (removed on Drop, also on a panic); `test_dir::tests::ld_240_5_temp_dir_removes_itself_on_drop_and_on_panic` |
| 2 | icons.rs `Codec` doc line | fixed (text) | before/after below |
| 3 | int10_14_a runs a valid `-y 2` | fixed | `int10_14_a_hardware_key_slot_values` |
| 4 | F-065 start-up clean never reads `TMPDIR` | test added | `edit::tests::f_065_start_up_clean_reads_only_the_users_own_folder` |
| 5 | F-092 int06_22 comment | fixed (text) | before/after below |
| 6 | the call inside `measure`; write_recovery_copy with no saver | tests added | `wizard::tests::ld_241_measure_passes_measure_clock_to_the_benchmark`, `saving::tests::ld_241_a_vault_with_no_saver_leaves_the_memory_note` |
| 7 | KeyPick slot 1 on a key with only slot 2 | test added | `security_keys::tests::ld_243_3_slot_1_on_a_key_with_only_slot_2_is_refused` |
| 8 | folder.rs creation-date length branch on FAT | **accepted** (FAT does not show the branch) | probe results below |
| 9 | name guard self-test V-1 to V-7, Verify's 10 mutants | fixed | 9 new self-test cases and 1 output check; all 10 mutants fail the self-test |
| 10 | INT-05.32 relock after a failed and a stopped run | test extended | `AutoTypeTests/t74LockAgainAfterAutoType` |
| 11 | `SearchClearTimer.minute` shared by suites | fixed | per-timer `minute`; `ld244SearchClearMinuteIsPerTimer` |
| 12 | Return answers Cancel in MSG-LOCK-DISCARD-EDIT | fixed | `DataSafetyTests/ld244ReturnAnswersCancelInLockDiscardEdit` |
| 13 | UndoOff's already-editing branch (F-127) | test added | `UndoOffEditingTests/f127FieldBeingEditedTurnsProtected` |
| 14 | FEA-01.34 re-run on a quiet Mac | **not quiet**: see below | ScreenTests FEA-01.34, run alone |

## Setup

- Tree runs: `CARGO_TARGET_DIR=/tmp/e13s6n-builder-target`. Swift, `scripts/build-core.sh` and every mutant: private copy `/tmp/e13s6n-builder-copy` (`rsync -a --exclude target --exclude larsal-shots`), its own `CARGO_TARGET_DIR=/tmp/e13s6n-builder-ctarget` (core) and `/tmp/e13s6n-builder-mtarget` (Rust mutants), `-derivedDataPath /tmp/e13s6n-builder-dd`, `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`. After each mutant the file was restored and `cmp` with the tree's: same.
- Demo data only. No window, focus, key event to the owner's session, or general pasteboard: Swift keys go to the offscreen window's own `performKeyEquivalent`. No USB device was opened (item 3 lists devices from IOKit properties only). The FAT image (item 8) was attached with `hdiutil attach -nobrowse -noautoopen` under `/tmp` and detached by its device.

## 1. Temp folders (LD-230 (5), LD-240 (5))

- Before: `ls $TMPDIR` held 435 test folders of larsal-ffi (207 `larsal-ffi-reports-<pid>` from the helper before LD-211 (4), 55 `larsal-ffi-window-<pid>`, and saving, hwkey, auto-open, icons, wizard ones). A clean run of the larsal-ffi unit tests left `larsal-ffi-window-<pid>` every time (window.rs `copy()`); the others were left when a test failed before its last line.
- Fix: `crates/larsal-ffi/src/test_dir.rs` (`#[cfg(test)]`): `TempDir::new(tag)` makes a fresh, canonical `$TMPDIR/larsal-ffi-<tag>-<pid>`; `.file(name)` makes it stand for a file in it; Drop sets 0700 and removes the folder. Used by window.rs `copy()` (one folder per test now, not one shared folder) and its key-file test, reports.rs (its own `Folder` type deleted), auto_open.rs `dir()` (`auto-url`, `auto-keyfile`, …), hwkey.rs `hardware_vault()` (also used by security_keys.rs), icon_fetch.rs, saving.rs `folder()`, security_keys.rs's wizard test.
- After: the unit-test binary run alone by its PID (`larsal_ffi-…` → `exit 0 pid 74236`, 160 passed): `ls $TMPDIR | grep 74236` lists no larsal-ffi folder. Each integration binary (14) run by its PID left none.
- Leftovers: 436 larsal-ffi, a09 and a09u folders; a folder was deleted only when none of the numbers in its name was a running PID (`ps -axo pid=`): **435 deleted, 1 kept** (`larsal-ffi-saving-overwrite-23120`: 23120 was running).
- Not converted (shared files other parts edit now, and they clean up when they pass): edit.rs, autotype.rs, export.rs, start.rs, cli.rs, ssh.rs, vault_settings.rs, instance.rs, wizard.rs's own folders. Each can switch to `TempDir::new` in one line.
- Mutant R1 (Drop does not remove): `ld_240_5_…` FAILED at test_dir.rs:67.

## 2. icons.rs `Codec` doc line (text)

Before:

```
/// The image decoder: turns checked PNG or ICO bytes into PNG bytes of at
/// most 128 × 128 pixels (MOD-06.8: larger images become exactly
/// 128 × 128, smaller ones keep their size). It enforces `limits` again on
/// what it decodes (an ICO can hold a PNG). [`Images`] is Larsal's; tests may
/// give their own.
```

After:

```
/// The image decoder: turns checked PNG or ICO bytes into PNG bytes. It
/// enforces `limits` again on what it decodes (an ICO can hold a PNG).
/// [`Images`] is Larsal's icon decoder and keeps at most 128 × 128 pixels
/// (MOD-06.8: larger images become exactly 128 × 128, smaller ones keep
/// their size); [`FullSize`] keeps the image's own size for the attachment
/// preview. Tests may give their own.
```

## 3. int10_14_a runs a valid `-y 2` (LD-232 (6))

- The binary asks real USB keys, so the valid runs go only when IOKit lists no device with a key vendor id (0x1050, 0x1D50; `UsbBus::list` reads properties and opens nothing, as T53). With a key plugged in the test prints that the valid runs wait (OD-01) and checks only the slot errors.
- On this Mac (no key): `ls -y 2`, `--yubikey 2` and `--hw-key 2` on w.larsalvault each exit 1 with M06-17 'Your security key is not connected. Plug it in, then try again.' `cargo test -p larsal-cli --test int10 -- int10_14_a`: ok.
- Mutant R6 (`hw_key_ok` accepts only slot 1): FAILED at int10.rs:1095 (`-y 2` refused as not a slot).

## 4. F-065: the start-up clean reads only the user's own folder (LD-237 (1))

- `f_065_start_up_clean_reads_only_the_users_own_folder` plants `planted-demo.txt` in `<TempDir>/Larsal/open-attachments`, runs the child `f_065_clean_child` (it calls `clean_open_copies`, as every Larsal start does) with `TMPDIR` set to that folder, and checks the child ran (1 passed) and the file is still there: ok.
- Mutant R2 (`clean_open_copies` reads `std::env::temp_dir().join("Larsal/open-attachments")`, Verify's m8): FAILED at edit.rs:3376 (the planted file was wiped).

## 5. F-092 int06_22 comment (text)

Before:

```
    // (F-092: an event, not a wall-clock bound that a busy Mac breaks). An
    // unlock that waited for the agent returns only after the fake's own
    // 30 s timeout, with `answered` set.
```

After:

```
    // (F-092: an event, not a wall-clock bound that a busy Mac breaks). An
    // unlock that waited for the agent gives up after the agent client's
    // 2 s `TIMEOUT` (larsal-sshagent agent.rs) and closes the socket, so the
    // fake's late answer fails and the test fails at `fake.join()`.
```

`cargo test -p larsal-ffi --test ssh`: 19 passed.

## 6. The call inside `measure`; the memory note with no saver (LD-241 (2))

- `ld_241_measure_passes_measure_clock_to_the_benchmark` reads wizard.rs's own text: the only `kdf::benchmark(` call in `measure` passes `MEASURE_CLOCK` (a source pin, as larsal-crypto mac.rs and larsal-core fea06 do; no clock seam in the product). `ld_72` still pins `MEASURE_CLOCK` itself. Mutant R3 (the call passes a closure clock): FAILED at wizard.rs:1347.
- `ld_241_a_vault_with_no_saver_leaves_the_memory_note`: a vault whose edit state has no saver writes no copy and no marker, and `lost_changes()` holds its copy name. Mutant R4 (no `note_lost` in that branch): FAILED at saving.rs:1645.

## 7. Slot 1 on a key with only slot 2 (LD-243 (3))

- `ld_243_3_slot_1_on_a_key_with_only_slot_2_is_refused`: on the hardware-key demo vault, `set_security_key(KeyPick { slot: 1, ..PICK })` gives `Refused` M06-17, the key stays PICK, 0 changes. Mutant R5 (`plugged()` ignores the slot): FAILED at security_keys.rs:246.

## 8. folder.rs creation-date length branch (LD-242 (4)): accepted

- Probe: a 30-line C program calling `fgetattrlist(ATTR_CMN_CRTIME)` with the same 20-byte buffer as folder.rs, on a file in each image, attached with `hdiutil attach -nobrowse -noautoopen -mountrandom /tmp/…/mnt` and detached by its device (`hdiutil detach /dev/disk11`):

| Volume | `mount` type | Reply |
|---|---|---|
| APFS (/tmp) | apfs | r=0 len=20 |
| `hdiutil create -fs MS-DOS` | msdos | r=0 len=20 |
| `-fs "MS-DOS FAT12"` | msdos | r=0 len=20 |
| `-fs ExFAT` | exfat | r=0 len=20 |
| `makehybrid -udf` | udf | r=0 len=20 |
| `makehybrid -iso` | cd9660 | r=-1 (the call fails; folder.rs returns the error before the branch) |

- FAT keeps creation dates, so no local volume reaches the length branch (`len < 20`). As LD-242 (4) rules, the branch is **accepted**: it rests on the two code reviews (E13-S6j-fixes.md, folder.rs:127). Afterwards `mount | grep e13s6n` and `hdiutil info | grep -c e13s6n` gave nothing and 0.

## 9. Name guard self-test lines V-1 to V-7 (LD-236 (2))

Self-test cases added to scripts/check-names.sh (labels as the guard prints them):

- V-1 (F-014): 'F-014 UTF-16BE at an odd offset': one plain letter then fullwidth letters, UTF-16BE after a 1-byte prefix (with fullwidth letters only, byte order and offset stand in for each other, so the plain letter makes both count).
- V-2 (F-015): 'F-015 SUB ends an OSC' (`ESC ] 0;x SUB`), 'F-015 CAN ends DCS, SOS, PM and APC' (`ESC P`, `ESC X`, `ESC ^`, `ESC _`, each `j CAN`), 'F-015 ESC with no final byte' (`ESC ( ESC [1m`).
- V-3 (F-016): 'F-016 Markdown code mark inside the word' (backticks), 'F-016 Markdown strike inside the word' (`~~`).
- V-4 (F-018): 'F-018 xattr on a link, not followed': a link to the clean file `clean.bin` holding a `user.note` value with a word, set with XATTR_NOFOLLOW.
- V-5 (F-019): 'F-019 Latin letter with a stroke': the first letter as LATIN SMALL LETTER … WITH STROKE.
- V-7 (F-121): 'F-121 backslash in a file name' (the word, a backslash, `x1b.txt`), and a step 1 output check: the printed name must hold `\x5cx1b.txt` ('missed case: F-121 backslash in a printed file name').

Runs:

- `scripts/check-names.sh --self-test`: self-test: PASS. `scripts/check-names.sh`: names: PASS (3208 files scanned, 16 vault files name-only), exit 0.
- Verify's mutants, each written over the copy's guard, `--self-test` run, guard restored (`cmp` with the tree's: same):

| Mutant | Change | Self-test |
|---|---|---|
| M03 | UTF-16 at alignment 0 only | FAIL, 'missed case: F-014 UTF-16BE at an odd offset' |
| M04 | UTF-16LE only | FAIL, same case |
| M10 | SUB does not end an OSC | FAIL, 'missed case: F-015 SUB ends an OSC' |
| M11 | CAN does not end DCS, SOS, PM or APC | FAIL, 'missed case: F-015 CAN ends DCS, SOS, PM and APC' |
| M15 | an ESC code needs its final byte | FAIL, 'missed case: F-015 ESC with no final byte' |
| M45 | MARK without the backtick | FAIL, 'missed case: F-016 Markdown code mark inside the word' |
| M46 | MARK without ~ | FAIL, 'missed case: F-016 Markdown strike inside the word' |
| M51 | XATTR_NOFOLLOW off (links followed) | FAIL, 'missed case: F-018 xattr on a link, not followed' |
| M57 | Latin letters WITH a mark not mapped | FAIL, 'missed case: F-019 Latin letter with a stroke' |
| M91 | the backslash not escaped in printed names | FAIL, 'missed case: F-121 backslash in a printed file name' |

V-6 has no self-test line: LD-236 (3) names it as a Known limit.

## 10. INT-05.32: relock after a failed and a stopped run (LD-244 (2))

- `t74LockAgainAfterAutoType` (AutoTypeRelockTests.swift) now also: adds "GitHub (bad)" whose window rule types `{USERNAME` (helper `addBadEntry`), unlocks through the panel and chooses that row: the log ends 'Auto-Type failed: MI05-11' and the vault is locked again; then a run whose second window read is another app (pid 4444): the log ends with an 'Auto-Type stopped: ' line and the vault is locked again. Fakes only.
- Mutant S4 (Verify's MA6, `failed()` without `ended()`): FAILED at AutoTypeRelockTests.swift:71. Mutant S5 (a stopped run returns before `ended()`): FAILED at :83.

## 11. `SearchClearTimer.minute` per timer (LD-244 (2))

- LarsalSettingsParts.swift: `static var minute` became `var minute` (each timer, so each VaultModel, has its own); the four test users set their own timer's (`clearer.minute`, `main.searchClearer.minute`) and need no reset. `ld244SearchClearMinuteIsPerTimer`: ok. Mutant S2 (back to `static`): the LarsalTests do not build (LarsalSettingsEffectsTests.swift:20, :42 'static member minute cannot be used on instance').

## 12. Return answers Cancel in MSG-LOCK-DISCARD-EDIT (APP-02.15 step 7, LD-244 (2))

- Dialogs.swift: the sheet's Cancel keeps Escape (`.cancelAction`), and a hidden button behind it with the same action takes Return (`.defaultAction`, hidden from accessibility), as Apple's HIG has for a destructive question. Discard has no key.
- `ld244ReturnAnswersCancelInLockDiscardEdit`: with editor edits, `lock` asks; Return (key code 36) and then Escape (53) to the offscreen window's `performKeyEquivalent` each close the sheet, clear `afterLeave`, and keep the vault unlocked with the editor open: ok. Mutant S1 (the hidden Return button removed): FAILED at HygieneFixesTests.swift:36 (Return not handled) and :38.

## 13. UndoOff's already-editing branch (F-127, LD-244 (2))

- `UndoOffEditingTests/f127FieldBeingEditedTurnsProtected` (HygieneFixesTests.swift, its own serialized suite): an AppKit text field with UndoOff's view (`UndoOff.Probe`) behind it, offscreen; editing starts (the field editor keeps undo), then the probe turns protected as `updateNSView` does (`off = true`, `apply()`): the cell and the field editor stop keeping undo, and Undo after typing over brings nothing back. Mutant S3 (the `currentEditor()` branch removed): FAILED at HygieneFixesTests.swift:70, :71.

## 14. FEA-01.34 on a quiet Mac (LD-230 (5), LD-240 (5))

- The load average never went under 4 during the session (15 to 47 from 10:00 to 12:45; other agents' builds). The quiet-Mac run is still open.
- Run alone (`-only-testing:LarsalTests/ScreenTests/searchSpeed()`, a print of the two numbers added in the copy only and removed after, `cmp`: same), three times:

| Run | Load average before | Worst update before rating | After rating | Result |
|---|---|---|---|---|
| 1 | 27.3 | 18.7 ms | 20.9 ms | passed |
| 2 | 20.3 | 17.3 ms | 20.5 ms | passed |
| 3 | 21.5 | 21.7 ms | 18.9 ms | passed |

- In the full LarsalTests runs it failed once (load about 30, 'worst' over 50 ms at ScreenTests.swift:160) and passed in the others. The Rust speed tests `fea01_34_speed_10000_entries` (larsal-core) and `fea01_34_search_speed_on_big_10000` (larsal-ffi) pass.

## Whole runs

- `cargo test -p larsal-ffi -p larsal-cli -p larsal-core` (tree): 51 test binaries, **1158 passed, 0 failed, 31 ignored**.
- `cargo clippy -p larsal-ffi -p larsal-cli -p larsal-core --all-targets -- -D warnings` and `cargo clippy -p larsal-ffi --all-targets --features net -- -D warnings`: No issues found. `cargo fmt --all -- --check`: no diff (two import orders and one assert in my own lines were fixed by exact edits; nothing was reformatted with `cargo fmt`).
- `scripts/check-names.sh --self-test`: self-test: PASS; `scripts/check-names.sh`: names: PASS (3208 files scanned, 16 vault files name-only), exit 0.
- Copy: `scripts/build-core.sh`: exit 0. `xcodebuild … test -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES -only-testing:` AutoTypeTests, DataSafetyTests, ProtectedUndoTests, UndoOffEditingTests, LarsalSettingsEffectsTests, WindowFixesMoreTests and `ld244SearchClearMinuteIsPerTimer()`: **Test run with 54 tests in 6 suites passed**, TEST SUCCEEDED (load 20 to 25).
- Copy, full LarsalTests (345 tests, load 20 to 36), four runs: each ended with 1 to 3 issues in tests part n did not change, each passing when run alone or beside the suites that failed with it: FEA-01.34 (above), the 'F-127 … .notes' case (ProtectedUndoTests.swift:61, :62), CopySelectionTests 'APP-03.7 LD-219 (4) F-081' (:67, :68), and in the last run (with part m's edits of that moment synced in) GeneratorTests :268 and PlatformTests :32 (a 60 s limit). One run without part n's UndoOff test passed all 344.
- CopySelectionTests F-081 is a cross-suite flake that part n's tests do not cause: run beside ProtectedUndoTests, GeneratorTests, PlatformTests and EditorSnapshotTests **without** part n's tests it failed 2 of 4 runs at :67 and :68 (the Cut after the 1 s countdown wait); alone it passes.
- `swift format lint --strict --recursive macos`: exit 0. `swiftlint lint --strict --quiet` (macos): exit 0.

## Open for the lead

- Item 8 accepted (no local volume without creation dates); item 14 as above.
- Two editing tests of other parts fail at times when suites run side by side under load: CopySelectionTests F-081's Cut after its 1 s wait (2 of 4 runs without part n's tests) and ProtectedUndoTests' '.notes' case (2 full runs). Each passes alone. Both read a field editor after an `await` that lets other suites run, which CopySelectionTests' own comment says must not happen; a re-check of the focus right before the command would make them steady.
- Item 13's first version drew a SwiftUI field; it now drives UndoOff's AppKit view (`UndoOff.Probe`) directly, as `updateNSView` does, so it takes no SwiftUI focus beside other suites.

## Verify (2026-10-30, round 1): signed, 13 re-tested, item 8 accepted

Role: Verify. I did not find, build or check these fixes. I re-ran every item with its own steps, wrote my own mutants and probes, and did not edit product code.

Setup: private copy `/tmp/e13s6n-verify-copy` (`rsync -a --exclude /target --exclude /fuzz/target --exclude /larsal-shots`; vendor's `cc-1.10.0/src/target` present), `CARGO_TARGET_DIR=/tmp/e13s6n-verify-target`, `-derivedDataPath /tmp/e13s6n-verify-dd`, `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`. Before the runs every part n file in the copy was `cmp` same as the tree's. After each mutant the file was restored and `cmp` with the tree's: same. The name guard probes ran in their own `/tmp` roots, one probe per root; only the summary line and the count of raw control bytes in the output were kept (hit lines hold the words). Demo data only. No window, focus, key event to the owner's session or general pasteboard; the LarsalTests run as a test bundle with offscreen windows. No USB device was opened. All my `/tmp` folders are deleted.

Whole runs (copy): `cargo test --offline --locked --no-fail-fast -p larsal-ffi -p larsal-cli -p larsal-core`: **51 binaries, 1158 passed, 0 failed, 31 ignored**. `cargo fmt --all -- --check`: exit 0. `cargo clippy -p larsal-ffi -p larsal-cli -p larsal-core --all-targets -- -D warnings`: exit 0; with `-p larsal-ffi --features net`: exit 0. `swift format lint --strict --recursive macos`: exit 0. `swiftlint` 0.65.1 `lint --strict --quiet` (macos): exit 0. `xcodebuild build-for-testing … SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: TEST BUILD SUCCEEDED. LarsalTests AutoTypeTests, DataSafetyTests, ProtectedUndoTests, UndoOffEditingTests, LarsalSettingsEffectsTests, WindowFixesMoreTests and `ld244SearchClearMinuteIsPerTimer()`: **Test run with 54 tests in 6 suites passed** (load 8.6 to 17.3). Tree: `scripts/check-names.sh --self-test`: self-test: PASS, exit 0; `scripts/check-names.sh`: names: PASS (11618 files scanned, 16 vault files name-only), exit 0.

| # | Steps | Before | After | Proof |
|---|---|---|---|---|
| 1 | Run the larsal-ffi unit-test binary directly and keep its PID; list `$TMPDIR` for folders with that PID | window.rs `copy()` left `larsal-ffi-window-<pid>` on every clean run; the other helpers left a folder when a test failed (Builder: 435 leftovers) | `larsal_ffi-7408f40cb9c21ba8 -q`, PID 97077: exit 0, 164 passed, 4 ignored; 0 folders with that PID; 0 `larsal-ffi-*` folders in `$TMPDIR` before and after. After the whole cargo run of 51 binaries the only `larsal-ffi-*` folder was the one my R1 mutant left (PID not running; removed) | `test_dir::tests::ld_240_5_temp_dir_removes_itself_on_drop_and_on_panic`: ok. Mutant R1 (Drop without `remove_dir_all`): FAILED at test_dir.rs:67 (the dropped folder still exists). Tags are unique per caller in window.rs, auto_open.rs, saving.rs and reports.rs |
| 2 | Read the `Codec` doc line against the code | The line said every decoder keeps at most 128 × 128 | icons.rs:53-58 says `Images` keeps at most 128 × 128 and `FullSize` keeps the image's own size. In the code `Images::to_png` calls `scale()` (icons.rs:142) and `FullSize::to_png` (:153-160) does not | text check, as quoted above |
| 3 | `cargo test -p larsal-cli --test int10 int10_14_a -- --nocapture` | int10_14_a ran only the invalid slot values; a valid `-y 2` was never run | ok, and the 'a security key is plugged in' line was not printed, so the valid `ls -y 2`, `--yubikey 2` and `--hw-key 2` runs went ahead (no key on this Mac) | Mutant R6 (`hw_key_ok` accepts only "1"): FAILED at int10.rs:1095 |
| 4 | `cargo test -p larsal-ffi --lib edit::tests::f_065` | Verify's probe (a file planted in `TMPDIR`'s Larsal/open-attachments) was not a product test: the mutant that makes the start-up clean read `TMPDIR` passed every test | `f_065_opened_attachments_live_in_the_users_own_temp_folder` and `f_065_start_up_clean_reads_only_the_users_own_folder`: ok | Mutant R2 (`clean_open_copies` reads `std::env::temp_dir().join("Larsal/open-attachments")`): `f_065_start_up_clean` FAILED at edit.rs:3376 (the planted file was wiped). Mutant R7 (`open_folder` from `std::env::temp_dir()`, the original F-065): `f_065_opened_attachments` FAILED at edit.rs:3340 |
| 5 | Read the int06_22 comment against larsal-sshagent; delay the fake's answer in the copy | The comment said the unlock 'returns only after the fake's own 30 s timeout, with answered set' | The comment (ssh.rs:218-221) names the agent client's 2 s `TIMEOUT` and the failure at `fake.join()`. agent.rs:17 is `pub const TIMEOUT: Duration = Duration::from_secs(2)`. Probe R8 (the fake answers 2.5 s after the unlock): the fake's `write_all` fails (ssh.rs:241) and the test fails at `fake.join()` (:261). Probe R8b (1.5 s): ok | `cargo test -p larsal-ffi --test ssh`: 19 passed; `cargo test -p larsal-autotype --test int05 t40`: ok |
| 6 | `cargo test -p larsal-ffi --lib wizard::tests::ld_241 saving::tests::ld_241` | No test pinned the clock passed inside `measure`, and none covered write_recovery_copy's memory note for a vault with no saver | `ld_241_measure_passes_measure_clock_to_the_benchmark` and `ld_241_a_vault_with_no_saver_leaves_the_memory_note`: ok | Mutant R3 (`measure` passes a wall clock, `UNIX_EPOCH.elapsed`): FAILED at wizard.rs:1347. Mutant R4 (no `note_lost` in the no-saver branch): FAILED at saving.rs:1648 |
| 7 | `cargo test -p larsal-ffi --lib security_keys::tests::ld_243_3` | No test set slot 1 on a key that has only slot 2 | ok: `Refused` M06-17, the key stays the same, 0 changes | Mutant R5 (`plugged()` ignores the slot): FAILED at security_keys.rs:246 |
| 8 | Confirm the ruling | The length branch could not be reached on this Mac | **Accepted untested, as LD-250 (1) rules** (no local disk type reaches folder.rs's creation-date length branch; it rests on the two code reviews, as LD-242 (4) allows; not a finding). The Builder's section above cites LD-242 (4) only; this section adds the LD-250 (1) citation. Not re-probed | spec/decisions.md LD-250 (1) |
| 9 | Name guard self-test in the tree; my own 10 mutants of Verify's list in `/tmp/e13s6n-verify-mut`, each run with `--self-test`; one probe per V item with the tree's guard and with its mutant | Each mutant passed the self-test (V-1 to V-5, V-7) | Each mutant: self-test: FAIL, exit 1, with its own line: M03 and M04 'F-014 UTF-16BE at an odd offset'; M10 'F-015 SUB ends an OSC'; M11 'F-015 CAN ends DCS, SOS, PM and APC'; M15 'F-015 ESC with no final byte'; M45 'F-016 Markdown code mark inside the word'; M46 'F-016 Markdown strike inside the word'; M51 (XATTR_NOFOLLOW off in all 4 calls of `xattrs()`) 'F-018 xattr on a link, not followed'; M57 (no `(?: WITH .*)?` in LATIN) 'F-019 Latin letter with a stroke'; M91 (no backslash in CONTROL) 'F-121 backslash in a printed file name'. Probes: tree FAIL, exit 1 and mutant PASS, exit 0 for V-1 (with M03 and with M04), V-2 (3), V-3 (2), V-4 and V-5; V-7: tree prints `\x5cx1b` once, M91 prints it 0 times | guard `cmp` same as the tree's after the run |
| 10 | LarsalTests `AutoTypeTests/t74LockAgainAfterAutoType()` | The test covered a typed run and an Escape only | passed (it now also covers the MI05-11 failed run and the stopped run, each locked again) | Mutant S4 (`failed()` without `ended()`): FAILED at AutoTypeRelockTests.swift:71. Mutant S5 (a stopped run returns before `ended()`): FAILED at :83 |
| 11 | LarsalTests `ld244SearchClearMinuteIsPerTimer()` and LarsalSettingsEffectsTests | `SearchClearTimer.minute` was static, so suites shared it | passed; APP-01.27 a, b and c passed | Mutant S2 (mine, not the Builder's: a computed `minute` that reads and writes one static store, so it compiles): FAILED at HygieneFixesTests.swift:15 |
| 12 | LarsalTests `DataSafetyTests/ld244ReturnAnswersCancelInLockDiscardEdit()` | Return did not answer Cancel in MSG-LOCK-DISCARD-EDIT | passed: Return (36) and Escape (53) to the offscreen window's `performKeyEquivalent` each close the sheet and keep the vault unlocked with the editor open | Mutant S1 (the hidden Return button removed): FAILED at HygieneFixesTests.swift:36 and :38 |
| 13 | LarsalTests UndoOffEditingTests and ProtectedUndoTests | UndoOff's already-editing branch had no test | `f127FieldBeingEditedTurnsProtected` passed; ProtectedUndoTests' F-127 test passed with 4 test cases, and the custom field test passed | Mutant S3 (the `currentEditor()` branch removed from `UndoOff.Probe.set`): FAILED at HygieneFixesTests.swift:70 and :71 |
| 14 | `xcodebuild test-without-building -only-testing:'LarsalTests/ScreenTests/searchSpeed()'`, run alone (no other test of mine running), started by a script when the 1-minute load average fell under 4 | Builder: load 15 to 47 all session; alone at load 20 to 27, 17 to 22 ms, 3 of 3 passed | **load under 4**: 3 of 3 passed (table below) | the times are printed by the test (ScreenTests.swift:169-170) |

Item 14, the quiet runs (`uptime` right before each run; limit 50 ms):

| Run | Time | Load average (1, 5, 15 min) | Worst update before rating | After rating | Result |
|---|---|---|---|---|---|
| 1 | 17:31:32 | 3.99, 7.90, 8.54 | 16.9 ms | 18.5 ms | passed |
| 2 | 17:31:36 | 3.99, 7.84, 8.51 | 17.4 ms | 18.2 ms | passed |
| 3 | 17:31:38 | 3.91, 7.76, 8.48 | 17.9 ms | 18.1 ms | passed |

The times at load 4 match the Builder's at load 20 to 27, so the margin to 50 ms does not come from the load.

Rows: F-014, F-015, F-016, F-018, F-019, F-121, F-065, F-092 and F-127 are set to 'fixed, re-tested (Verify 2026-10-30)' in [security/findings.md](../findings.md). No new finding. CopySelectionTests and PlatformTests APP-09.27 belong to part o and were not run.
