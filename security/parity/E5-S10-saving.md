# E5-S10 Saving: Verify proof

Story: E5-S10 Saving (plan/epics.md): auto-save, backup, the changed-on-disk question with merge (APP-05). Check: AT-I05 passes through the screen (plan/attacks-and-checks.md: two writers, two windows edit one vault, cloud conflict copies: merge without lost entries).
Cards: APP-05, MOD-11 (merge), APP-01 (S-FILE keys), APP-02.15 and APP-02.16. Decisions: LD-07, LD-50, LD-52, LD-129, LD-163 (4), LD-167, LD-199, LD-200, LD-206, LD-211 (5), LD-216, LD-217, W-16.

## Round 3 (2026-10-28): signed

Verify agent, round 3. I did not build or check this story. Scope: round 2's fail (the lock flag, LD-217 (4)), the probes moved into the builder's suites, then Parts A to D again on the code as it is now.

| Part | Result |
|---|---|
| Round 2 fail 1 (the lock flag drops unsaved changes) | **Fixed.** Round 2's probe, now through the window: `PROBE lock flag: on_lock true, after_every_change true, file has the change true, recovery folder exists false; locked true; lockAll returned in 5 µs`. End to end (hidden launch, `app --lock` from a second process): answered in 37 to 75 ms, exit 0, `All open vaults were locked.`; the change is in the file, or in a 0600 recovery copy when it cannot be saved. |
| The moved probes bite | **Yes.** SM2 to SM6 each fail a builder test (R-OFF half of the lock request test, V-B1 "Merge then save", V-B3, V-B4, V-B6); RM4 fails `at_i05_a_change_made_during_a_discard_is_kept`. |
| A. Design parity, 3 frames, light and dark | **PASS, 3 of 3, unchanged.** References, manifest and the 6 offscreen shots byte-equal to the tree (same shasums as rounds 1 and 2); `compare.mjs dialogs`: `dialogs: 17/17 PASS`. |
| B. AT-I05 through the screen | **PASS.** 3 Verify screen tests (two windows, sync rename, conflict copy) plus the builder's V-B1 second half, V-B3, V-B4, V-B6. Sheet 522 to 577 ms after the write (alone). Merge kept every entry and change: 27 = 23 + 4, 29 = 23 + 6, 25 = 23 + 2 twice. The reference CLI opens every result (exit 0). |
| C. APP-05 and APP-02.16 card cases | Every reachable case passes, now also through the lock request (R-OFF, T60, T47, T58, two vaults, editor open, a newer copy, the marker). Waiting items unchanged (W-16, LD-217 (3)). |
| D. Mutations (private copy) | **13 of 13 caught, 12 by the builder's tests.** Rust 5 of 5, Swift 8 of 8; only SW2 (the answer waits) is caught by a Verify test alone (advisory 1). |
| E. Regression | app-ffi + app-core: 44 binaries, **933 passed, 0 failed**, 25 ignored. Swift full run: 278 tests in 39 suites; all 37 suites of the tree (259 tests) pass, incl. ParitySavingTests (14), SavingSnapshotTests, LockSignalsTests, MenuKeysTests. clippy `-D warnings`, fmt, swift format `--strict` and SwiftLint 0.65.1 `--strict` on the whole macos tree, check-names: clean. |

### R3-0. Setup and rules

- At 23:03 `shasum` of 425 shared files (app-ffi and app-core sources, macos/App and AppTests, the dialogs parity files, testdata, scripts, plan/epics.md, spec/decisions.md, Cargo.toml, Cargo.lock) went to /tmp/e5s10x-verify3-work/start.sha. Then `rsync -a --exclude /target --exclude /app-shots --exclude /fuzz/target` to /tmp/e5s10x-verify3-copy, `target` a link to /tmp/e5s10x-verify3-target (also `CARGO_TARGET_DIR`), xcodebuild `-derivedDataPath /tmp/e5s10x-verify3-dd`. `scripts/build-core.sh` in the copy: `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`; the generated `AppEvents` protocol has `lockAll()`.
- The code checked: at the end start.rs, saving.rs, session.rs, instance.rs, Front.swift, Saving.swift, SavingSheets.swift, DiskWatch.swift, SavingTests.swift and SavingWatchTests.swift of the copy are byte-equal to the shared tree (`cmp`). Changed meanwhile by other workflows: AppDelegate.swift (one Auto-Type line), MainWindowModel.swift (E8-S2 posts one notification after `session.lockAll()` in `lockAll`; E5-S11's `textCommand`), AutoType*.swift, WindowRules.swift, UnlockView.swift, MenuKeysTests.swift, AutoTypeTests.swift, plan/epics.md. The E5-S10 path (`saveAll`, the recovery copy, the lock) is unchanged. A build of the copy with those newer files failed in AutoTypeTests.swift (E8-S2 was still editing it, 23:33 to 23:34), so I did not re-run on them.
- My tests lived only in the copy: macos/AppTests/VerifyE5S10R3Tests.swift, suites `VerifyE5S10R3ScreenTests` (3) and `VerifyE5S10R3LockTests` (16). For the end-to-end probe the copy's DebugUI.swift got a debug-only hook (env `APP_VERIFY_ADD`: one committed, unsaved entry once the vault is unlocked; env `APP_VERIFY_STATE`: the lock states after each refresh), removed after the probe (`diff -r` against the pristine sources: equal). I edited no product code in the shared tree. Shared files I edited: this file and the E5-S10 status line.
- Rule 5: demo vaults only (testdata `option-a-personal.appvault`, demo-pass-7; Work, demo-pass-8). Rule 10: offscreen borderless windows at x −20000; the end-to-end app ran with `APP_TEST_HIDDEN` (activation policy prohibited, no window) and its own `APP_TEST_INSTANCE_DIR` in /tmp, so its settings and recovery folder were in /tmp; the general pasteboard was never read, written or cleared (test sessions use the private clipboard). Rule 11: the 3 probe apps (PIDs 68714, 68810, 68891) were stopped by their PIDs with TERM; I stopped no other process. Load average 15 to 44 (other agents).
- Settings: every recovery test used its own settings folder in /tmp/e5s10x-verify3-work (`useFolder`). `ls "$HOME/Library/Application Support/App/recovery"`: `No such file or directory`.
- The reference CLI: `--version` 2.7.11, throwaway `HOME=CFFIXED_USER_HOME=/tmp/e5s10x-verify3-work/refhome`, only `ls -R -f -q`, `show -q -a UserName -a Notes` and `db-info -q`, demo files only.

### R3-1. Round 2's fail: the lock flag

Code read: start.rs `answer` gives `Request::Lock => lock(Some(events))`; `lock` calls `events.lock_all()` and answers true at once; with no events (`lock(None)`) it falls back to `session::lock_all()`. Swift `WindowEvents.lockAll` (Front.swift) only queues `Task { @MainActor [window] in window.lockAll() }`, the same `lockAll()` LockSignals run: `saveAll(asks: false)` saves by the settings, writes the recovery copy for each change it could not save, then `session.lockAll()`. In the shipped flow the channel waits for the window's events (`primary.events.wait()`), so only the Rust test reaches the fallback (as the ruling allows).

Swift probes (copy, `VerifyE5S10R3LockTests`, the request sent as Rust sends it: `WindowEvents.lockAll()` from a detached task; log /tmp/e5s10x-verify3-work/log.txt):

| Probe | Result |
|---|---|
| V3-R0 round 2's probe | `PROBE lock flag: on_lock true, after_every_change true, file has the change true, recovery folder exists false; locked true; lockAll returned in 5 µs`. The same with the change in its 150 ms window: `file has the change true, locked true`. |
| V3-R1 R-OFF (both save settings off) | locked; file byte-unchanged; `recovery` 700 holds `c2c4cf77….appvault` 600 = SHA-256 of `/private/tmp/e5s10x-verify3-target/option-a/v3-r1/Personal.appvault`; it holds the change |
| V3-R2 T60 (file changed on disk) | locked; the file keeps `T60 Theirs`, not `T60 Mine`; the copy (600) holds `T60 Mine` |
| V3-R3 T47 (read-only folder, the save fails) | locked; the file lacks the change; the copy holds it |
| V3-R4 T58 (⌘L's `.onSave` question open) | locked; the copy holds the change; the file does not |
| V3-R5 two changed vaults (Personal, Work) | both locked, both files hold their change, no copy |
| V3-R6 answered at once | `lockAll` returned in **0 ms** while the main queue was blocked 500 ms; then locked and saved |
| V3-R7 the editor open | locked; the committed change is in the file |

End to end (copy's App with the probe hook; script /tmp/e5s10x-verify3-scripts/e2e.sh; `echo demo-pass-7 | App --password-stdin Personal.appvault` hidden, then `App --lock`; log e2e.log):
```
on: --lock exit 0, 'All open vaults were locked. ', 75 ms; state 'locked=true'; file changed yes; file has E2E Mine 1, Outside Entry 0
  recovery folder exists: no
off: --lock exit 0, 'All open vaults were locked. ', 53 ms; state 'locked=true'; file changed no; file has E2E Mine 0, Outside Entry 0
  recovery 700: 097352e3….appvault ; expected name 097352e3….appvault
  097352e3….appvault mode 600; ref ls: E2E Mine 1, exit 0
disk: --lock exit 0, 'All open vaults were locked. ', 37 ms; state 'locked=true'; file changed no; file has E2E Mine 0, Outside Entry 1
  recovery 700: 351f84fd….appvault ; expected name 351f84fd….appvault
  351f84fd….appvault mode 600; ref ls: E2E Mine 1, exit 0
```
"on" uses the default settings (save after every change and on lock), "off" both off, "disk" save on lock with our CLI's `add` (exit 0) writing "Outside Entry" into the file before the request. The state file shows each run went `locked=false` → `locked=true`. The times include starting the second process.

### R3-2. Parts A and B

**Part A (copy):** `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0, 46.3 s; manifest and the 6 references `cmp`-equal to the tree. The full run wrote app-shots/{light,dark}/dialogs-changed-on-disk (1120 × 870, a33bfaf0 / d9e35f8c), -close-with-unsaved-changes (920 × 304, 656c1e67 / 500ee513), -save-failed (920 × 344, 9427765b / bbdc4cb6): all 6 `cmp`-equal to design/parity/dialogs/app/. `mockup-dom.mjs dialogs` → `light: 21 frames, 147 text runs`, `dark: 21 frames, 147 text runs`; `ocr.swift` on the dialogs shots; `compare.mjs dialogs` → `dialogs: 17/17 PASS`, close 1.91 % / 1.97 %, save-failed 0.33 % / 0.38 %, changed-on-disk `-%` (size difference, as before). The 3 records equal the stored ones except `themes` (round 1's common-area numbers) and `verify`; `contrast` and `tokensStatic` equal; behaviour lists 2/2, 2/2, 1/1. Shots and references are the same bytes as rounds 1 and 2, so the common-area numbers stand: 2.14 % light, 2.13 % dark. Keyboard on the sheets still **needs Mac QA (owner's go)**.

| Frame | Light | Dark | Pixels light / dark | Missing strings | Token mismatches | Unnamed controls | Behaviour | Verdict |
|---|---|---|---|---|---|---|---|---|
| dialogs-changed-on-disk | present | present | 2.14 % / 2.13 % (common area) | 0 | 0 / 0 | 0 | 2 Parity + V3-B1, B2, B5 + builder V-B1 to V-B6 | **PASS** |
| dialogs-close-with-unsaved-changes | present | present | 1.91 % / 1.97 % | 0 | 0 / 0 | 0 | 2 Parity + V3-T07, T57 | **PASS** |
| dialogs-save-failed | present | present | 0.33 % / 0.38 % | 0 | 0 / 0 | 0 | 1 Parity + V3-R3 | **PASS** |

**Part B** (`-only-testing:AppTests/VerifyE5S10R3ScreenTests` alone → `✔ Test run with 3 tests in 1 suite passed after 20.345 seconds.`; setup as rounds 1 and 2, the sheets pressed through the accessibility tree offscreen):

| Test | Result |
|---|---|
| V3-B1 two windows | B's sheet after **577 ms**: `.unsaved, changes: 4`; text "Personal.appvault changed on disk", "“Personal.appvault” was changed by another program, and this vault has unsaved changes.", Merge / Discard ("Your 4 changes are lost.") / Ignore / Cancel. File = A's bytes until the answer; A's own save asked nothing. Merge, then B saves: **27 = 23 + 4**; A reloaded, "Reloaded.". B's watch off: B's save asks `.onSave, 1`, file unchanged; Merge then save: **29 = 23 + 6**. Folder: Personal.appvault 644 (kept), Personal.old.appvault 600 = A's file before B's save. |
| V3-B2 sync rename | inode 430120401 → 430121345; sheet after **522 ms** `.unsaved, 2`; nothing written; Merge and ⌘S: **25 = 23 + 2**; backup = the synced bytes, 600 |
| V3-B5 conflict copy | copy alone: no question in 2 s, file unchanged, changes 2; swap: sheet after **528 ms** `.unsaved, 2`; Merge and ⌘S: **25 = 23 + 2**; the conflict copy byte-untouched |
| Builder V-B1 second half, V-B3, V-B4, V-B6 (SavingWatchTests.swift) | pass in the full run; they follow round 2's probes (in place: reload, Discard, Keep; delete and move: no question, written anew 0600 and watched; re-arm after App's rename) |

In the parallel full run (load about 40) the same sheets took 2.5 to 8.2 s; alone 0.5 s (advisory 4).

The reference CLI on the results (`echo demo-pass-7 | … ls -R -f -q`; counts include the 2 entries in the Recycle Bin):
```
b1-two-windows: exit 0, 31 entries, mode 644, new: A1 Demo Shop;A2 Demo Bank 2;B1 Demo Mail 2;B2 Demo Wiki;A3 Demo Shop 3;B3 Demo Wiki 3;
b1-backup: exit 0, 30 entries, mode 600, new: A1 Demo Shop;A2 Demo Bank 2;B1 Demo Mail 2;B2 Demo Wiki;A3 Demo Shop 3;
b2-sync-swap: exit 0, 27 entries, mode 644, new: Remote Demo Shop;Local Demo Mail 2;
b5-conflict: exit 0, 27 entries, mode 644, new: Theirs Conflict;Mine Unsaved;
b5-conflicted-copy: exit 0, 26 entries, mode 644, new: Theirs Conflict;
builder-merge-then-save: exit 0, 27 entries, new: Demo Bank 2;Demo Shop;
builder-in-place: exit 0, 28 entries, new: In Place 1;In Place 2;In Place 3;
builder-deleted-after-move: exit 0, 28 entries, mode 600, new: After Delete;After Recreate Remote;After Move;
builder-deleted-moved: exit 0, 27 entries, mode 600, new: After Delete;After Recreate Remote;
builder-rearm: exit 0, 27 entries, new: Demo Shop;In Place After Save;
builder-lock-request: exit 0, 26 entries, new: Demo Shop;
r0-lock-request: exit 0, 27 entries, new: R0 Mine;R0 Window;
r1-recovery: exit 0, 26 entries, mode 600, new: R1 Mine;
r2-t60-recovery: exit 0, 26 entries, mode 600, new: T60 Mine;
b1-two-windows Banking/Wise: user-from-B||    Work/GitHub: alex-dev|notes-from-B|
b2-sync-swap Banking/Wise: alex.morgan@posteo.de|mine|    Email/Google: alex.morgan@gmail.com|theirs|
b5-conflict Banking/Wise: alex.morgan@posteo.de|mine|    Email/Google: alex.morgan@gmail.com|theirs|
```
`db-info -q b1-two-windows.appvault`: `Cipher: AES 256-bit`, `KDF: Argon2id (2 rounds, 1024 KB)`, `Number of entries: 29`. `db-info -q r1-recovery.appvault`: `Name: Personal`, `Unsaved changes: no`, `Number of entries: 24`.

### R3-3. Part C: card cases

`-only-testing:AppTests/VerifyE5S10R3LockTests` (with the screen suite) → `✔ Test run with 19 tests in 2 suites passed after 57.141 seconds.`; T03 alone after.

| Case | Result | Proof |
|---|---|---|
| **APP-02.12 + APP-02.16 lock flag with unsaved changes** | **PASS** (round 2's fail): saved, or kept in a recovery copy, then locked; answered at once | R3-1 |
| APP-05 T60 / APP-02 T56 | **PASS** by LockSignals (builder test) and by the request | V3-R2, E2E "disk" |
| APP-02 T47 | **PASS** by the request | V3-R3 |
| APP-02.16 both save settings off (R-OFF) | **PASS** (builder test, V3-R1, E2E "off") | — |
| APP-02.16 quit signal (`mayQuit(asks: false)`) | **PASS**: true, no question, the copy holds the change, `quit()` locks every vault | V3-QUIT |
| APP-02.16 a newer copy replaces the older | **PASS**: one file, holds the second change only (advisory 5) | V3-NEWER |
| APP-02.16 `.lost` marker | **PASS**: the name taken by a folder: locked, `<name>.appvault.lost` 600, 0 bytes | V3-LOST |
| APP-02 T55 | locks, no prompt **PASS**; `recovery 500: []`, no marker (LD-217 (3), Spec) | V3-T55 |
| APP-02 T57 / APP-05 T50 | **PASS**: `.onSave`; Later: still unlocked, file unchanged, no `recovery` folder | V3-T57 |
| APP-02 T58 | **PASS** by LockSignals and by the request | V3-T58, V3-R4 |
| APP-02 T53, T54, T59 (next-unlock offer) | Waiting (W-16, LD-217 (2)) | — |
| T03 APP-05.2 | **PASS** alone: 2 inodes (one save), the new file at **183 ms** (the 150 ms window plus the save), all three changes in the file; 1224 ms in the parallel run (load) | V3-T03 |
| T07 APP-05.4 | **PASS**: locked 51 ms after ⌘L, no question, the change in the file | V3-T07 |
| T40 APP-05.24 | **PASS**: with no file event the tick looks once, at **30.00 s** | V3-T40 |
| T43 APP-05.25 | **PASS**: editor open 2 s, no question, `pending` true; the question 5 ms after the editor closed | V3-T43 |
| T52 APP-05.30 | **PASS**: notice "App could not read the file on disk. Your open copy is unchanged. It may still be syncing.", changes 0; ⌘S → `.overwriteOnly` | V3-T52 |
| T41, T42, T44 to T49, T17, T18, T30, T32 | **PASS** | V3-B1, B2, B5; builder V-B1 to V-B6 |
| T04, T11, T16, T21 to T24, T27 to T29, T34 to T38, T54 | **PASS** in Rust (re-run in the 933) | cargo-test.log |
| T06, T19, T26, T39, T51, T53 and the not-reached or waiting cases | As rounds 1 and 2: Saving.swift (20:42), SavingSheets.swift and DiskWatch.swift did not change after round 2 began; T06's builder test passes again | rounds 1 and 2 |

### R3-4. Part D: mutations (private copy only)

Each mutant applied in /tmp/e5s10x-verify3-copy, built with my own target and derived data, tested, restored from the pristine copy (`diff -r` equal after each batch).

Rust (`cargo test -p app-ffi --lib -- saving:: start::`, 24 tests):

| Mutant | Result |
|---|---|
| R1 `Request::Lock => session::lock_all()` (the fix undone) | **caught**: `app09_12_a_lock_request_goes_to_the_window_else_rust_locks` (start.rs:435) |
| R2 no fallback (`return true`) | **caught**: the same test (start.rs:438, "no window: Rust locks") |
| R3 Rust locks too after the callback | **caught**: the same test (start.rs:436, "not Rust: the window saves first") |
| RM4 Discard/Load ignores a change made during its KDF (`Some(u32::MAX)`) | **caught**: `at_i05_a_change_made_during_a_discard_is_kept` (saving.rs:1220); survived rounds 1 and 2 |
| RM4c the silent reload ignores it (`check_disk` → `Some(u32::MAX)`) | **caught**: `at_i05_a_change_made_during_a_silent_reload_is_kept` |

Swift (`build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, then `ParitySavingTests` + my 2 suites, 33 tests):

| Mutant | Builder `ParitySavingTests` (14) | Verify tests |
|---|---|---|
| SW1 `WindowEvents.lockAll` = Rust lock-all + refresh (the old behaviour) | **fails**: the lock request test | 9 fail (V3-R0 to R7, V3-QUIT) |
| SW2 the answer waits for the lock (semaphore, up to 2 s) | 14 pass | **V3-R6 fails** (488 ms) |
| SW3 a lock request asks (`lockAll(asks: true)`) | **fails**: the lock request test | 6 fail (R1 to R4, T55, QUIT) |
| SM2 recovery copy only when a save was tried | **fails**: the lock request test (R-OFF half) | V3-R1, V3-QUIT |
| SM3 the watch on the folder only | **3 fail**: V-B3, V-B4, V-B6 | V3-T52 |
| SM4 the watch on the file only | **fails**: V-B4 | — |
| SM5 no re-arm after an event | **2 fail**: V-B4, V-B6 | — |
| SM6 "Merge then save" does not save at once | **fails**: V-B1 "Merge then save saves" | V3-B1 |

13 mutants, 13 caught, 12 by the builder's tests (round 2: 10 of 12 caught; SM2 to SM6 and RM4 not by the builder's tests).

### R3-5. Regression and checks

- `cargo test -p app-ffi -p app-core` (copy): 44 `test result` lines, **933 passed, 0 failed, 25 ignored**, exit 0. Includes `start::tests::app09_12_a_lock_request_goes_to_the_window_else_rust_locks`, `saving::tests::at_i05_a_change_made_during_a_discard_is_kept`, `…during_a_silent_reload_is_kept`, `app_02_16_an_unattended_lock_keeps_the_change_in_a_recovery_copy`, `ld_199_4_vault_settings_during_a_reload_or_a_save_never_hangs`, and the E5-S8 save tests `cry02_14_an_approved_costly_kdf_saves_without_asking`, `mod12_14_*` (2), `mod12_10_*` (3, incl. t18), `app07_16_t31_*`, `ld_199_4_*`.
- `cargo clippy -p app-ffi -p app-core --all-targets -- -D warnings`: exit 0. `cargo fmt -p app-ffi -p app-core --check`: exit 0.
- Swift full run (copy, pristine code + my 2 suites, 23:09 to 23:11): `✘ Test run with 278 tests in 39 suites failed after 141.821 seconds with 2 issues.` All 37 suites of the tree pass, incl. `✔ Suite ParitySavingTests`, `✔ Suite SavingSnapshotTests`, `✔ Suite LockSignalsTests`, `✔ Suite MenuKeysTests`. Both issues were mine: V3-QUIT read the window's stale list after `quit()` (which does not refresh; fixed to read the session) and T03's 3 s wait under load; both pass after (19 of 19 alone, above).
- Shared tree: `xcrun swift format lint --strict --recursive macos`: exit 0, no findings. SwiftLint 0.65.1 `lint --strict --quiet` in macos/: exit 0, no findings. `scripts/check-names.sh`: `names: PASS (3117 files scanned, 15 vault files name-only)`.
- Rule 4: the recovery copies are encrypted (they open only with the password in the reference CLI); no log line carries vault content.

### R3-6. Open issues and advisories (not fails)

1. **"Answered at once" has no builder test.** SW2 (the answer waits up to 2 s, longer than the sender's 1 s, so `app --lock` would report it was not locked) passes every builder test; only V3-R6 catches it. Smallest guard (the Checker's): call `events.lockAll()` from a detached task in the lock request test and require under 50 ms.
2. **The fallback is test-only.** `session::lock_all()` runs only for `lock(None)`; the channel waits for the window's events first. As the ruling asks.
3. **Out-of-date comments** (no behaviour): LockSignalsTests `channelLock` ("what `answer(Request::Lock)` … do"), session.rs `lock_all()` ("an automatic trigger (APP-09.12 `lock`)"), saving.rs `at_i05_a_change_made_during_a_discard_is_kept` ("only the changes the question counted are discarded": such a Discard turns into a merge and discards nothing).
4. **Load.** In the parallel full run the watch-to-sheet time stretched to 8.2 s and T03 to 1.2 s (the main actor is shared by 39 suites); alone 0.5 s and 183 ms. Round 1 advisory 7 stands.
5. Still open from earlier rounds: W-16 (the next-unlock offer; until then a newer copy replaces the older), LD-217 (3) (T55 and the marker, Spec), and R2-6 item 5.
6. **Mac QA (owner's go):** the sheets' keyboard (arrows, Return, Escape) on a key window, and `app --lock` against a visible App.

### R3-7. Cleanup

- Removed /tmp/e5s10x-verify3-{copy,target,dd,work,scripts}; then `ls -d /tmp/e5s10x-verify3*` → no matches.
- The failing Rust mutants left 5 folders in `$TMPDIR` (23:17 to 23:18: `app-ffi-start-lock-69693`, `-69911`, `-70153`, `app-ffi-saving-during-discard-70244`, `app-ffi-saving-during-reload-70325`); I removed those 5. Older folders of that name (19:29, 19:49) are other runs' and stay (rule 11).

## Round 2 (2026-10-28): failed (1)

Verify agent, round 2. I did not build or check this story. Scope: the two round 1 fails and their fixes (LD-216, LD-217), then Parts A to D again on the code as it is now.

| Part | Result |
|---|---|
| Round 1 fail 1 (the disk watch choice has no row) | **Fixed.** LD-216 records the native kqueue watch (Swift `DispatchSource` on the folder and the file, 500 ms join, 30 s tick, Rust decides by checksum) with the reference's system watch plus 30 s check, Apple's File System Events guide and its kernel-queue chapter, the SDK headers, and `notify`'s own macOS backends. APP-05.24 and the plan/architecture.md row "File change watch" say so. `grep notify Cargo.toml Cargo.lock`: no match. |
| Round 1 fail 2 (an automatic lock drops changes it cannot save) | **Fixed for idle, screen lock, sleep, user switch, minimize (LockSignals → `lockAll()`) and a quit signal or logout (`mayQuit(asks: false)`). Not fixed for the lock flag (APP-02.12): fail 1 below.** |
| A. Design parity, 3 frames, light and dark | **PASS, 3 of 3, unchanged.** Fresh references and manifest byte-equal; fresh offscreen shots byte-equal to design/parity/dialogs/app/ (same shasums as round 1); `compare.mjs dialogs`: `dialogs: 17/17 PASS`, the 3 records equal to the stored ones except the Verify notes; changed-on-disk on the common area light 2.14 %, dark 2.13 %; close 1.91 % / 1.97 %; save-failed 0.33 % / 0.38 %. |
| B. AT-I05 through the screen | **PASS.** 6 Verify screen tests (real `MainWindowModel`, `VaultModel`, `DiskWatch`, sheets pressed through the accessibility tree offscreen): two windows saving in turn, a sync rename while edits wait, in-place edits, delete and move, a conflict copy, re-arm after App's own save. Sheet 513 to 529 ms after the write. Merge kept every entry and change (27 = 23 + 4, then 29 = 23 + 6; 25 = 23 + 2 twice). Nothing written before the answer. Backup `Personal.old.appvault` 0600, one, the bytes before the save. The reference CLI opens every result, backup, conflict copy and recovery copy (exit 0). |
| C. APP-05 and APP-02.16 card cases | Every reachable case passes except the lock flag (fail 1). New: T60, APP-02 T47, T56, T57, T58 pass; T55 locks but cannot leave the marker (LD-217 (3), Spec). Table in R2-3. |
| D. Mutations (private copy) | **12 mutants: 10 caught, 1 equivalent, 1 survives.** Swift 6 of 6 caught (only SM1 by a builder test, all 6 by Verify tests). Rust: RM3 caught by 5 builder tests; RM2 caught by the builder's and my Swift tests; RM1 equivalent (open keeps the real path); RM4 (Discard during the KDF) survives, as in round 1. |
| E. Regression | app-ffi + app-core: 43 binaries, **917 passed, 0 failed**, 25 ignored, incl. the 18 saving tests and the E5-S8 save tests. Swift full run: the 216 tests of the tree all pass; my 19 pass alone. clippy `-D warnings`, fmt, swift format `--strict` and SwiftLint `--strict` on the E5-S10 files, check-names: clean. testdata unchanged (34 OK). |

**Fail (1):**
1. **The lock flag (APP-02.12) drops unsaved changes: no save, no recovery copy (APP-02.16 names the lock flag as an automatic trigger; APP-05.4 "Locking runs APP-02.15 step 8"; LD-50).** The instance channel answers `Request::Lock` with `session::lock_all()` (crates/app-ffi/src/start.rs:350), which is `Session::shared().lock_all()` (session.rs:985): each slot is locked and its changes wiped. Swift's `lockAll()`, where the step 8 save and the recovery copy now live, never runs. Probe (copy only, the same method on a `Session::new()` with a settings folder): `PROBE lock flag: on_lock true, after_every_change true, file has the change false, recovery folder exists false`. So with a change in its 150 ms window or the per-vault autosave delay, after a failed save, after a change on disk, or with save after every change off, `app --lock` (or any process of the user sending the flag) loses it without a trace. The builder found this and left it open in LD-217 (4) "for the lead", but no story owns it by name, and round 1's fail 2 asked for exactly that or a fix. **Smallest fix:** in `answer()`, answer `Request::Lock` at once (APP-02.12: the sender does not wait for the outcome) and hand the lock to Swift through a new `AppEvents` callback that runs `MainWindowModel.lockAll()` on the main queue (save, recovery copy, lock, as LockSignals); keep `session::lock_all()` as the fallback when no events are set. Add a Rust test that the request calls the callback and a Swift test that the change ends in the file or a recovery copy. Or the lead routes LD-217 (4) by name to a follow-up story in an LD row; then this point leaves E5-S10.

### R2-0. Setup and rules

- At 21:02 `shasum` of 216 shared files (app-ffi and app-core sources, all of macos/App and AppTests, the dialogs parity files, plan/epics.md, spec/decisions.md, testdata/*, Cargo.toml, Cargo.lock) went to /tmp/e5s10-verify2-work/start.sha. Then `rsync -a --exclude /target --exclude /app-shots --exclude /fuzz/target` to /tmp/e5s10-verify2-copy, `target` a link to /tmp/e5s10-verify2-target (also `CARGO_TARGET_DIR`), xcodebuild `-derivedDataPath /tmp/e5s10-verify2-dd`.
- The code checked: at the end the copy's saving.rs, edit.rs, Saving.swift, SavingSheets.swift, DiskWatch.swift and SavingTests.swift are byte-equal to the shared tree (`cmp`). 31 shared files changed during the run, all by other workflows (auto-type, screen protection, secure input, menus, settings, plan/epics.md, spec/decisions.md); the diffs of start.rs, session.rs, MainWindowModel.swift and AppDelegate.swift only add lines of those stories. The E5-S10 hooks are intact (`lock: { [window] in window.lockAll() }`, `mayQuit(asks:` in AppDelegate; start.rs:350 still `Request::Lock => session::lock_all()`).
- My tests lived only in the copy: macos/AppTests/VerifyE5S10Tests.swift, suites `VerifyE5S10Tests` (6) and `VerifyE5S10CardTests` (13). I edited no product code. Shared files I edited: this file, the 3 frames' rows in design/parity/dialogs/ (report.md, report.html, findings.json: one note each), and the E5-S10 status line in plan/epics.md.
- Rule 5: demo vaults only (testdata `option-a-personal.appvault`, demo-pass-7, copied into the copy's target and /tmp/e5s10-verify2-work). testdata/* unchanged: `shasum -c` 34 OK at the end.
- Rule 10: borderless offscreen windows at x −20000, never ordered front; headless Chrome for the export; the save panel never opened; the general pasteboard never read, written or cleared. Rule 11: I stopped no process. Load average 8 to 37 (other agents).
- Settings: every recovery test set its own settings folder in /tmp (`useFolder`). `ls "$HOME/Library/Application Support/App/recovery"` at the end: `No such file or directory`.
- The reference CLI: `--version` 2.7.11, throwaway `HOME=CFFIXED_USER_HOME=/tmp/e5s10-verify2-work/refhome`, only `ls -R -f -q`, `show -q -a UserName -a Notes` and `db-info -q`, demo files only.

### R2-1. The round 1 fixes

- Fix 1: `grep -n "LD-216" spec/decisions.md` → line 239 (the row above); `grep -c LD-216 spec/app/APP-05-saving.md` → 1 (APP-05.24: "with the system's kqueue file watch (Decided: spec/decisions.md LD-216)"); plan/architecture.md:269 "File change watch | None: the system's kqueue vnode sources through Swift's `DispatchSource` (`macos/App/Platform/DiskWatch.swift`, APP-05.24; LD-216)"; `grep -n notify Cargo.toml Cargo.lock` → nothing. The row cites one proven open source password manager (the reference: a system watch plus a 30 s check) and the platform sources; the watch works (Part B, mutants SM3 to SM5).
- Fix 2, code read: `Session::write_recovery_copy` (saving.rs:567) takes the save lock, then the session lock (LD-199 (4) order), duplicates the vault in memory, names the copy `sha256(real path)` in lowercase hex + `.appvault`, creates `recovery` with mode 0700, builds the file under `sv.key` (the current key) with the save's own `build`, and writes it with app-core's safe `storage::save`; else it leaves an empty `.lost` (0600). A memory-only store (`folder()` is `None`) writes nothing. Swift `saveAll(asks: false)` calls it for each changed vault whose save did not run, failed or met a changed file, then `session.lockAll()` runs.

### R2-2. Parts A and B

**Part A commands (copy):**
1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0, 47.6 s. `cmp` against the tree: manifest and the 6 references of the 3 frames equal.
2. `scripts/build-core.sh` → `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`, exit 0, 1:37.
3. `xcodebuild … build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → exit 0. The full run (`test-without-building -skip-testing:AppUITests`) gave `✔ Suite SavingSnapshotTests passed` and wrote app-shots/{light,dark}/dialogs-changed-on-disk (1120 × 870, a33bfaf0 / d9e35f8c), -close-with-unsaved-changes (920 × 304, 656c1e67 / 500ee513), -save-failed (920 × 344, 9427765b / bbdc4cb6), each with `.ax.json`. All 6 `cmp`-equal to design/parity/dialogs/app/.
4. `node design/parity/tools/mockup-dom.mjs dialogs` → `light: 21 frames, 147 text runs`, `dark: 21 frames, 147 text runs`; `swift design/parity/tools/ocr.swift app-shots/{light,dark}/dialogs-*.png` → 34 images read; the full-run log copied to target/parity/behaviour.log.
5. `node design/parity/tools/compare.mjs dialogs` → `dialogs: 17/17 PASS`:
   ```
   dialogs-changed-on-disk                        PASS                   L -% (-) D -% (-)
   dialogs-close-with-unsaved-changes             PASS                   L 1.91% (0) D 1.97% (0)
   dialogs-save-failed                            PASS                   L 0.33% (0.33) D 0.38% (0.38)
   ```
   Python `==` on the records: changed-on-disk differs from the stored one only in `themes` (round 1's common-area numbers) and `verify`; the other two only in `verify`. `contrast` and `tokensStatic` equal. Behaviour lists: changed-on-disk 2 of 2 pass, close 2 of 2, save-failed 1 of 1.
6. Common area (compare.mjs skips pixels on a size difference): /tmp/e5s10-verify2-scripts/crop.mjs, pixelmatch threshold 0.1, `includeAA: false`, best offset: `light: ref 1120x868 app 1120x870 common 1120x868 best dx 0 dy 1: 2.14 %`, `dark: … 2.13 %`.
7. Accessibility names (ax.json, light and dark equal): changed-on-disk group "Personal.appvault changed on disk", buttons Merge, Discard, Ignore, Cancel, Merge; close group "Personal was changed. Save the changes?", Discard, Cancel, Save; save-failed group "App could not save “Personal”", Save As…, Close, Try Again. Keyboard (arrows, Return, Escape) still **needs Mac QA (owner's go)** (an offscreen window is never key, LD-169).

| Frame | Light | Dark | Pixels light / dark | Missing strings | Token mismatches | Unnamed controls | Behaviour | Verdict |
|---|---|---|---|---|---|---|---|---|
| dialogs-changed-on-disk | present | present | 2.14 % / 2.13 % (common area) | 0 | 0 / 0 | 0 | 2 Parity + 6 Verify AT-I05 | **PASS** |
| dialogs-close-with-unsaved-changes | present | present | 1.91 % / 1.97 % | 0 | 0 / 0 | 0 | 2 Parity + R-T07, R-T57/T58 | **PASS** |
| dialogs-save-failed | present | present | 0.33 % / 0.38 % | 0 | 0 / 0 | 0 | 1 Parity + R-T47 | **PASS** |

**Part B** (`xcodebuild … test-without-building -only-testing:AppTests/VerifyE5S10Tests` → `✔ Test run with 6 tests in 1 suite passed after 23.765 seconds.`). Setup as round 1: each window is `Session()` + `open` + `unlock` + `switchTo` + `MainWindowModel(session:)` + `refresh()` (which starts the real `DiskWatch`); a change is `beginNew`/`beginEdit` → `setText` → `commitEdit` → `afterChange(select:)`; ⌘S is `saveNow(asks: true)`; "another program" saves a copy elsewhere with its own `Session`; a sync service copies it to `.Personal.appvault.sb-<random>` in the folder and `rename(2)`s it over; "in place" is truncate + write + sync on the same inode. Log (/tmp/e5s10-verify2-work/b/log.txt):

| Test | Result |
|---|---|
| V-B1 two windows edit one vault and save in turn | B's sheet after **513 ms**: `changedOnDisk(ask: .unsaved, changes: 4)`; sheet text "Personal.appvault changed on disk", "“Personal.appvault” was changed by another program, and this vault has unsaved changes.", Merge / Discard ("Your 4 changes are lost.") / Ignore / Cancel. File bytes = A's until the answer; A's own save asked nothing. Merge, then B saves: **27 = 23 + 4**. A reloaded silently after **507 ms** ("Reloaded."). B's watch off, both add one: B's ⌘S asks `.onSave, changes: 1` (Merge then save / Discard / Overwrite / Cancel), file unchanged; Merge then save: **29 = 23 + 6**. Folder: `Personal.appvault 644` (mode kept), `Personal.old.appvault 600` = A's file before B's save. |
| V-B2 sync rename while edits wait | Inode 428313164 → 428313181; sheet after **522 ms** `.unsaved, 2`; nothing written; Merge and ⌘S: **25 = 23 + 2**; the backup = the synced version, 0600. |
| V-B3 in place: reload, Discard, Keep | (1) same inode, silent reload after **529 ms**, "Reloaded."; (2) sheet after **522 ms** `.unsaved, 1`, Discard: "In Place 2" shown, "Local Lost" gone, changes 0; (3) `save.reload_on_change` off: sheet after **513 ms** `.reload` ("… Load the changes?", Load / Keep); Keep: changes 1; ⌘S → `.onSave, 1`, file unchanged. |
| V-B4 delete, then move | No question in 2 s; the next change wrote the file anew, mode **600**, "The vault file was missing. App saved it again at …"; no backup; an in-place edit of the new file seen after 275 ms; move: no question, the old path written anew (600), Moved.appvault byte-unchanged. |
| V-B5 conflict copy | Copy alone: no question in 2 s, vault file unchanged; swap: sheet after **513 ms** `.unsaved, 2`; Merge and ⌘S: **25 = 23 + 2**; the conflict copy byte-untouched. |
| V-B6 re-arm | Inodes 428313641 → 428313661 (App's rename) → 428313661 (in place); reloaded after **514 ms**. |

The reference CLI on the results (`echo demo-pass-7 | REF_CLI ls -R -f -q`, `show -q -a UserName -a Notes`, `db-info -q`):
```
b1-two-windows: exit 0, 31 entries (2 in the Recycle Bin), mode 644, new: A1 Demo Shop;A2 Demo Bank 2;B1 Demo Mail 2;B2 Demo Wiki;A3 Demo Shop 3;B3 Demo Wiki 3;
b1-backup: exit 0, 30 entries (2 in the Recycle Bin), mode 600, new: A1 Demo Shop;A2 Demo Bank 2;B1 Demo Mail 2;B2 Demo Wiki;A3 Demo Shop 3;
b2-sync-swap: exit 0, 27 entries (2 in the Recycle Bin), mode 644, new: Remote Demo Shop;Local Demo Mail 2;
b4-after-move: exit 0, 28 entries (2 in the Recycle Bin), mode 600, new: After Delete;After Recreate Remote;After Move;
b4-moved: exit 0, 27 entries (2 in the Recycle Bin), mode 600, new: After Delete;After Recreate Remote;
b5-conflict: exit 0, 27 entries (2 in the Recycle Bin), mode 644, new: Theirs Conflict;Mine Unsaved;
b5-conflicted-copy: exit 0, 26 entries (2 in the Recycle Bin), mode 644, new: Theirs Conflict;
t60-recovery: exit 0, 26 entries (2 in the Recycle Bin), mode 600, new: T60 Mine;
b1-two-windows Banking/Wise exit 0: user-from-B|
b1-two-windows Work/GitHub exit 0: alex-dev|notes-from-B|
b2-sync-swap Banking/Wise exit 0: alex.morgan@posteo.de|mine|
b2-sync-swap Email/Google exit 0: alex.morgan@gmail.com|theirs|
b5-conflict Banking/Wise exit 0: alex.morgan@posteo.de|mine|
b5-conflict Email/Google exit 0: alex.morgan@gmail.com|theirs|
```
`db-info -q b1-two-windows.appvault`: `Cipher: AES 256-bit`, `KDF: Argon2id (2 rounds, 1024 KB)`, `Number of entries: 29`. `db-info -q t60-recovery.appvault`: `Name: Personal`, `Number of entries: 24`, `Unsaved changes: no`. The recovery copy is a normal vault file under the vault's key.

### R2-3. Part C: card cases

Round 2 runs (`-only-testing:AppTests/VerifyE5S10CardTests` → `✔ Test run with 13 tests in 1 suite passed after 45.815 seconds.`). Recovery tests give each window its own settings folder in /tmp (`useFolder`), next to the vault folder. The vault is opened through the copy's `target` link, so its real path differs from the open path; the expected name is `sha256(realpath(path))`. Waiting = waiting for a mockup addition (not a fail).

| Case | Result | Proof (log line) |
|---|---|---|
| APP-05 T60 / APP-02 T56 (automatic lock meets a changed file) | **PASS**: no question, locked, the file keeps the other side (`T60 Theirs`, not `T60 Mine`), `recovery` 700 holds `e758cfe0….appvault` 600 = SHA-256 of `/private/tmp/e5s10-verify2-target/option-a/v2-t60/Personal.appvault`; it opens with demo-pass-7 and holds `T60 Mine` (24 entries); the plain title is not in its bytes | R-T60 |
| APP-02 T47 (save failed, folder read-only) | **PASS**: the auto-save failed ("This vault's file or its folder cannot be written."); the automatic lock wrote `9c097155….appvault` 600 in `recovery` 700; it holds the change; the vault file does not | R-T47 |
| APP-02.16 "save does not run" (both save settings off) | **PASS**: file byte-unchanged, copy 600 holds the change, locked | R-OFF |
| APP-02.16 quit signal or logout (`mayQuit(asks: false)`) | **PASS**: returns true with no question, the copy holds the change, `quit()` locks every vault | R-QUIT |
| APP-02.16 "a newer copy replaces the older one" | **PASS**: one file in `recovery`; it holds the second change, not the first (see open issue 2) | R-NEWER |
| APP-02.16 `.lost` marker | **PASS**: with the copy's name taken by a folder, locked, `<name>.appvault.lost` 600, 0 bytes | R-LOST |
| APP-02 T55 (recovery folder read-only) | Locks with no prompt **PASS**; no copy and no marker (`recovery 500: []`): the marker's folder is the read-only one (LD-217 (3), Spec to look at T55); MSG-LOCK-LOST waits for W-16 | R-T55 |
| APP-02 T57 / APP-05 T50 (manual ⌘L meets a changed file) | **PASS**: `changedOnDisk(ask: .onSave, changes: 1)`; Cancel: the vault stays unlocked, the file unchanged, no `recovery` folder | R-T57 |
| APP-02 T58 (automatic lock while the manual question is open) | **PASS**: locked, the copy holds the change | R-T57 second half |
| APP-02 T53, T54, T59 (next-unlock Merge/Discard, old key) | Waiting (W-16, LD-217 (2)) | — |
| **APP-02.12 + APP-02.16 lock flag with unsaved changes** | **FAIL** (fail 1): no save, no copy | Rust probe, start.rs:350 |
| T03 APP-05.2 | **PASS** alone: 2 inodes (one save), the new file at **171 ms** (150 ± 20) and 180 ms on a re-run; all three changes in the file | R-T03 |
| T07 APP-05.4 | **PASS**: locked 45 ms after ⌘L, no question, the change in the file | R-T07 |
| T40 APP-05.24 | **PASS**: watch 507 to 529 ms (Part B); with no file event the tick looks once, at **30.00 s** | R-T40 |
| T41, T42 | **PASS**: V-B1 (A's own save), V-B4 (deleted, moved: no question) | V-B1, V-B4 |
| T43 APP-05.25 | **PASS**: editor open 2 s, no question, `pending` true; the question 12 ms after the editor closed | R-T43 |
| T44, T45, T46, T48 | **PASS** | V-B3 (1), V-B3 (3), V-B1/V-B2/V-B5, V-B3 (2) |
| T17, T49 APP-05.10, .28 | **PASS** | V-B1 second half; builder "Parity dialogs-changed-on-disk: … Overwrite saves over it" |
| T52 APP-05.30 | **PASS** alone: notice "App could not read the file on disk. …", changes 0; ⌘S → `.overwriteOnly` | R-T52 |
| T18, T30, T32 | **PASS**: recreated 0600 with MSG-SAVE-RECREATED; only the vault and its backup in the folder; backup = bytes before the save, 0600 | V-B4, V-B1, V-B2 |
| T04, T11, T16, T21 to T24, T27 to T29, T34 to T38, T54 | **PASS** in Rust (re-run in the 917): `ld_199_4_a_waiting_save_writes_the_change…`, `app_05_6_save_as…`, app-core `app05_09_*`, `at_i01_*`, `at_i06_*`, `at_i03_*`, `app05_15_*`, `app05_16_*`, `app05_20_*`, `app05_21_*`, `app_05_32_…` | cargo-test.log |
| T06, T19, T26, T39, T47 (APP-05), T51, T53 | Round 1 results stand: these code paths did not change (only `write` was split into `build` + `write`; the Rust tests re-ran green). T06 builder test passes again. | round 1 R3; full run |
| T01, T02, T05, T08, T10, T12, T13, T25, T31, T55 (APP-05), T56 to T59 (APP-05) | As round 1: not reached, not built or waiting (no frame), see round 1 R3 | — |

### R2-4. Part D: mutations (private copy only)

Each mutant: applied in /tmp/e5s10-verify2-copy from a pristine copy, built with my own target and derived data, tested, restored; `cmp` against the shared tree after each batch: equal.

Rust (`cargo test -p app-ffi --lib saving`, 18 tests):

| Mutant | Rust tests | Swift (core rebuilt, `ParitySavingTests` + `VerifyE5S10CardTests`) |
|---|---|---|
| RM1 copy named by the open path, not the real path | 18 pass | 21 pass: **equivalent** (session.rs:441 `open` stores `canonicalize(given)`, so path = real path) |
| RM2 `.lost` marker left even when the copy is written | 18 pass | **caught**: R-NEWER and the builder's "APP-02.16 T56, APP-05.28 T60 …" (2 files in `recovery`) |
| RM3 Merge never merges (`if false`) | **5 fail**: `app_05_27_merge_keeps_both_sides_and_saves`, `at_i05_a_change_made_during_a_silent_reload_is_kept`, `at_i05_a_conflict_copy…`, `at_i05_a_sync_swap…`, `at_i05_two_windows…` | — |
| RM4 Discard/Load ignores a change made during its KDF (`Some(u32::MAX)`) | **survives** (18 pass), as round 1 R7 | — |

Swift (`build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, then `test-without-building`; `tick()` skipped):

| Mutant | Builder `ParitySavingTests` (9) | Verify tests |
|---|---|---|
| SM1 automatic lock: no recovery copy | **1 fails** ("APP-02.16 T56, APP-05.28 T60 …") | **7 fail**: R-T60, R-T47, R-OFF, R-QUIT, R-NEWER, R-LOST, R-T57 (T58) |
| SM2 copy only when a save was tried (not when both save settings are off) | 9 pass | **3 fail**: R-OFF, R-NEWER, R-LOST |
| SM3 the watch on the folder only | 9 pass | **2 fail**: V-B3 (3 issues), V-B6 |
| SM4 the watch on the file only | 9 pass | **V-B4 fails** (nothing re-arms after a delete and recreate) |
| SM5 no re-arm after an event | 9 pass | **V-B6 fails** |
| SM6 "Merge then save" does not save at once | 9 pass | **V-B1 fails** (2 issues) |

SM4's first try did not build (an unused `let folder` under warnings-as-errors); the result above is from the rebuilt mutant with `_ = folder`.

### R2-5. Regression and checks

- `cargo test -p app-ffi -p app-core` (copy): 43 `test result` lines, **917 passed, 0 failed, 25 ignored**, exit 0, 1:42. Includes the 18 `saving::tests` (with `app_02_16_an_unattended_lock_keeps_the_change_in_a_recovery_copy`) and the E5-S8 save tests `cry02_14_an_approved_costly_kdf_saves_without_asking`, `mod12_14_*` (2), `mod12_10_*` (3), `app07_16_t31_*`, `ld_199_3_kept_password_is_page_locked`, `ld_199_4_*` (3).
- `cargo clippy -p app-ffi -p app-core --all-targets -- -D warnings`: exit 0. `cargo fmt -p app-ffi -p app-core --check`: exit 0.
- Swift, final full run (copy, pristine code + my 2 suites): `✘ Test run with 235 tests in 35 suites failed after 163.430 seconds with 4 issues.` All 4 issues are my R-T03 and R-T52 waits at load average 37; the other 233 pass, including `✔ Suite SavingSnapshotTests`, `✔ Suite ParitySavingTests` and every suite of the tree (no LD-206 pasteboard miss this run). Alone right after: `✔ Test run with 2 tests in 1 suite passed after 3.769 seconds.` (T03 180 ms, T52 notice and `.overwriteOnly`).
- `xcrun swift format lint --strict` and SwiftLint 0.65.1 `--strict` on Saving, SavingSheets, DiskWatch, MainWindowModel, AppDelegate, AppCommandsVault, Menus, MenuBarIcon and SavingTests: exit 0. On the whole tree, swift format lists 13 and SwiftLint 17 findings, all in SecureInput, ScreenProtection, their tests and MenuKeysTests, changed by other workflows at 21:17 to 21:30 (not E5-S10).
- `scripts/check-names.sh`: `names: PASS (3116 files scanned, 15 vault files name-only)`.
- Rule 4: the recovery copy is encrypted (no plain title in its bytes, opens only with the password); no log line or message carries vault content.

### R2-6. Open issues and advisories (not fails)

1. **Tests that bite.** The builder's Swift tests catch only SM1; SM2 to SM6 and RM4 pass them. Smallest fix: move V-B1's second half, V-B3, V-B4, V-B6, R-OFF and the Checker's Discard-during-KDF probe into the builder's suites (round 1 advisory 1, still open).
2. **Until W-16 the copy is never offered, and the next one replaces it.** R-NEWER: after a second automatic lock the first change ("NEWER One") is in neither the file nor the copy. This follows the card ("a newer recovery copy replaces the older one") because the next unlock is meant to merge first; it waits for W-16.
3. **T55 and the marker** (LD-217 (3)): a read-only `recovery` folder stops the `.lost` marker too, so T55's MSG-LOCK-LOST can never show. Spec.
4. **Load.** Under load average 30 to 37 the watch-to-notice time and the 150 ms save window stretch past several seconds in the parallel run (the main actor is shared by 35 suites, and `saveAll` runs the KDF on it, now also for the recovery copy). Round 1 advisory 7 stands.
5. Still open from round 1 and the build: APP-05.11 creation date, Finder tags and ACL (LD-129, LD-200); the APP-05.29 unlock sheet, APP-05.14, APP-05.18, APP-05.33, Save a Copy, MSG-DISK-RELOADING (not drawn); Lock Everything stops at the first vault that asks; `saveAll(asks: true)` shows the close question for a save refused by a changed file; compare.mjs prints "undefined %" on a size difference.

### R2-7. Cleanup

- `scripts/check-names.sh` (shared tree, after this file, the parity rows and the epics line): `names: PASS (3116 files scanned, 15 vault files name-only)`.
- `rm -rf /tmp/e5s10-verify2-copy /tmp/e5s10-verify2-target /tmp/e5s10-verify2-dd /tmp/e5s10-verify2-work /tmp/e5s10-verify2-scripts`; then `ls -d /tmp/e5s10-verify2*` → `no matches found`.
- RM3's 5 failing Rust tests left `$TMPDIR/app-ffi-saving-{conflict,during-reload,merge,sync,two-windows}-19791` (21:21:25, the 5 tests that failed in that run); I removed those 5. Older folders of that name (19:02 to 20:57) are other runs' and stay (rule 11).

## Round 1 (2026-10-28): failed (2)

Verify agent, round 1. I did not build or check this story.

| Part | Result |
|---|---|
| A. Design parity, the 3 dialog frames, light and dark | **PASS, 3 of 3.** References and manifest byte-equal after a fresh export; fresh offscreen shots byte-equal to the parity images. dialogs-changed-on-disk: light 2.14 % (1.01 % outside accepted areas), dark 2.13 % (1.02 %), measured on the common area because the shot is 1 pt taller (compare.mjs printed "undefined %"); close-with-unsaved-changes 1.91 % / 1.97 % (0 % outside); save-failed 0.33 % / 0.38 %. 0 missing strings, 0 colour issues, 0 boxes or runs more than 2 pt off, 0 unnamed controls; lowest contrast 4.87:1. Rows updated in design/parity/dialogs/. |
| B. AT-I05 through the screen | **PASS.** 6 Verify screen tests drive the real `MainWindowModel` and `VaultModel` with the real `DiskWatch`, the sheets pressed through the accessibility tree offscreen: two windows save in turn; a sync service renames a new version in while edits wait; another program edits in place; the file is deleted and moved; a conflict copy appears. The sheet shows 0.52 to 0.55 s after the write. Merge kept every entry and every change of both sides (counted). Nothing was written before the user answered. Backups: one `Personal.old.appvault`, mode 0600, the bytes before the last save. The reference CLI opens every merged file, every backup and the conflict copy (exit 0, the same entries and fields). |
| C. APP-05 card cases | Every case the drawn screens reach passes, except the not-drawn ones, which wait for a mockup addition. One case outside the drawn screens fails: **T60** (fail 2). Table in R3. |
| D. Mutations (private copy) | **12 mutants (5 Swift, 7 Rust): 6 caught by the builder's tests, 11 by builder plus Verify tests.** The builder's Swift tests catch none of the 5 Swift watch and flow mutants; my tests catch all 5. Rust: 6 of 7 caught; R7 (the Checker's advisory: Discard during the KDF) survives. |
| E. Regression | app-ffi + app-core: 43 binaries, **916 passed, 0 failed**, 25 ignored, including the E5-S8 save tests. Swift: every suite passes (3 suites failed in the parallel full run on the general pasteboard count, LD-206, and a 50 ms timing; each passed when run alone). clippy `-D warnings`, fmt, swift format `--strict`, SwiftLint on E5-S10's files, and check-names are clean. testdata is unchanged. |

**Fails (2):**
1. **The disk watch choice is not recorded (AGENTS.md rule 9; the story brief: "record the choice with sources").** APP-05.24 says App watches "with the approved file watch crate", and plan/architecture.md names `notify` for "File change watch". The build uses Swift `DispatchSource.makeFileSystemObjectSource` (kqueue vnode events) on the folder and on the file. It also joins events within 500 ms and adds a 30 s tick (macos/App/Platform/DiskWatch.swift). The mechanism works (Part B). But spec/decisions.md has no row for this choice, and no sources (grep `kqueue`, `DispatchSource`, `DiskWatch`, `file watch`: nothing). **Smallest fix:** add one LD row. It records the native kqueue watch on the folder and the file in place of `notify`, with sources from proven Mac apps and Apple's documentation. The row also aligns the APP-05.24 wording and the architecture table row. No code change.
2. **An automatic lock drops unsaved changes when their save fails or meets a changed file. No recovery copy is written (APP-05.4, APP-05.28, T60; APP-02.16, LD-50).** Probe `V-C T60`: the vault has an unsaved change, and a sync service replaced the file. `lockAll()` (what LockSignals runs on sleep, screen lock and idle) leaves the vault locked. The file does not hold the change, and nothing else does: no recovery copy is written anywhere. The only `recovery` code is the old-copies listing in app-core storage.rs:791. `saveAll(asks: false)` skips the vault and `session.lockAll()` drops the change, without a word. The same path runs for a quit signal and for a save that fails (sync service holding the file, read-only folder, disk gone). This is the AT-I05 scenario (two writers) losing an entry. No other story owns it: the E6-S2 Verify routed recovery copies to "the session, save and unlock stories (APP-02.15, APP-02.16, APP-05, APP-06)". The builder and Checker 1 listed it as open. **Smallest fix:** before an automatic lock or a quit signal, when a changed vault's save fails or answers `on_disk`, Rust writes the recovery copy that APP-02.16 describes. That is the vault in memory, encrypted with its current key, written with the safe method at 0600, in `recovery/` (0700) of App's settings folder. Its name is the SHA-256 of the real path plus `.appvault`; if that write fails too, a `.lost` marker. Then it locks. Add a test that the change is in the recovery copy. The next-unlock offer (Merge or Discard) has no frame: it waits for a mockup addition. Or, if the lead routes this by name to a follow-up story in an LD row, this point leaves E5-S10.

### R0. Setup and rules

- **Private copy.** At 19:56 `shasum` of 58 shared files went to /tmp/e5s10-verify-work/start.sha. These were the E5-S10 Rust and Swift files, the shared Swift files the story touches, the parity files, plan/epics.md and testdata/*. Then `rsync -a --exclude /target --exclude /app-shots --exclude /fuzz/target` copied the tree to /tmp/e5s10-verify-copy, with `target` a link to /tmp/e5s10-verify-target (also `CARGO_TARGET_DIR`). xcodebuild used `-derivedDataPath /tmp/e5s10-verify-dd`. Work files went to /tmp/e5s10-verify-work and scripts to /tmp/e5s10-verify-scripts.
- **The code checked.** At the end the copy's `saving.rs`, `Saving.swift` and `DiskWatch.swift` were byte-equal to the shared tree's (`cmp`). `shasum -c start.sha` showed 53 of 58 files unchanged. The other 5: my 3 parity files; plan/epics.md and AppCommandsVault.swift, changed by other workflows. The AppCommandsVault.swift change is one comment, LD-212 to LD-214; the E5-S10 hooks `lockAll(asks: true)` in AppCommandsVault, Menus and MenuBarIcon, and `lockAll()` in AppDelegate, are intact.
- **My tests lived only in the copy:** `macos/AppTests/VerifyE5S10Tests.swift`, with suites `VerifyE5S10Tests` (6 tests) and `VerifyE5S10CardTests` (13 tests). They were deleted with the copy. I edited no product code.
- **Rule 5.** Demo vaults only: copies of testdata `option-a-personal.appvault` (demo-pass-7) and `password-only.appvault` (demo-pass-1), all under /tmp/e5s10-verify-work/b and the copy's target. testdata/* stayed unchanged (`shasum -c`: 34 OK).
- **Rule 10.** No window was ordered front. The app views rendered in borderless windows at x −20000. Chrome ran headless for the export. The save panel was never opened (the tests' seam). I never read, wrote or cleared the general pasteboard. The two pasteboard issues below are the other suites' own change-count checks (LD-206).
- **Rule 11.** I stopped no process. Load average was 18 to 25.
- **The reference CLI.** `REF_CLI --version` printed `2.7.11`. Every run used a throwaway home (`HOME=CFFIXED_USER_HOME=/tmp/e5s10-verify-work/refhome`). Only `ls -R -f -q`, `show -q -a UserName -a Notes` and `db-info -q` were used, on demo files only: no clip command, no window.

### R1. Part A: design parity (BUILD-AND-VERIFY.md, "Prompt for the Verify fleet")

1. `node design/option-a/tools/export-reference.mjs` (copy) printed `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0, 46.9 s. The manifest and the 6 references of the 3 frames are byte-equal to the tree's (`cmp`).
2. `scripts/build-core.sh` printed `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`, exit 0, 2:34.
3. `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e5s10-verify-dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` gave `✔ Suite SavingSnapshotTests passed`. It wrote app-shots/{light,dark}/dialogs-changed-on-disk, -close-with-unsaved-changes and -save-failed `.png` and `.ax.json`. All 6 PNGs are byte-equal to design/parity/dialogs/app/ (`cmp`). Sizes: 1120 × 870, 920 × 304 and 920 × 344 px. shasum light/dark: changed-on-disk a33bfaf0…/d9e35f8c…, close 656c1e67…/500ee513…, save-failed 9427765b…/bbdc4cb6….
4. `node design/parity/tools/mockup-dom.mjs dialogs` printed `light: 21 frames, 147 text runs` and `dark: 21 frames, 147 text runs`. `swift design/parity/tools/ocr.swift app-shots/light/dialogs-*.png app-shots/dark/dialogs-*.png` read 34 images. The full-run log went to target/parity/behaviour.log.
5. `node design/parity/tools/compare.mjs dialogs` (copy) printed `dialogs: 17/17 PASS`, with:
   ```
   dialogs-changed-on-disk                        PASS                   L -% (-) D -% (-)
   dialogs-close-with-unsaved-changes             PASS                   L 1.91% (0) D 1.97% (0)
   dialogs-save-failed                            PASS                   L 0.33% (0.33) D 0.38% (0.38)
   ```
   The three records in findings.json are equal to the shared ones (`==` in Python), and so are `contrast` and `tokensStatic`.
6. **The common area.** compare.mjs skips colours and pixels when the sizes differ (changed-on-disk: 1120 × 870 against 1120 × 868 px, 0.5 pt per edge, inside the 2 pt geometry limit). So I ran a copy of the tool, `compare-crop.mjs`, in the private copy only. It compares an app shot up to 4 px larger on the common area, at the offset with the fewest changed pixels. It printed:
   ```
   dialogs-changed-on-disk                        PASS                   L 2.14% (1.01) D 2.13% (1.02)
   ```
   The best offset was dx 0, dy 1 px. Colour shares, light: #ffffff 75.5 → 75.7 %, accent-soft #e2eff2 17.1 → 16.6 %. Dark: #1a1a1d 73.9 → 74.7 %, #10303a 17.1 → 16.6 %. 0 issues.

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / runs > 2 pt | Unnamed controls | Behaviour | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| dialogs-changed-on-disk | present | present | 2.14 % (1.01 %) / 2.13 % (1.02 %), common area | 0 of 9 (4 by card words) | 0 / 0 | 0 + 0 (Cancel narrower by the card's word: geoSkip) | 0 | 2 Parity + 6 Verify screen tests pass | **PASS** |
| dialogs-close-with-unsaved-changes | present | present | 1.91 % (0 %) / 1.97 % (0 %) | 0 of 5 (2 by card words) | 0 / 0 | 0 + 0 | 0 | 2 Parity + V-C T07, T50 pass | **PASS** |
| dialogs-save-failed | present | present | 0.33 % (0.33 %) / 0.38 % (0.38 %) | 0 of 5 | 0 / 0 | 0 + 0 | 0 | 1 Parity + V-C T19, T26 pass | **PASS** |

- **Text.** The card words over the mockup (BUILD-AND-VERIFY order 2, LD-163 (4)) are listed in notes.mjs:
  - changed-on-disk: MSG-DISK-UNSAVED; Reload → Discard, Keep mine → Ignore, Decide Later → Cancel;
  - close-with-unsaved-changes: MSG-LOCK-SAVE; Don't Save → Discard.
- **Glyphs.** arrows-clockwise, floppy-disk and warning-circle (fill) are all drawn. 45 of 45 colour assets equal app.css. Contrast: 42 pairs, the lowest 4.87:1 (light, symbol on surface).
- **Accessibility tree** (ax.json):
  - changed-on-disk: the group "Personal.appvault changed on disk"; AXButton choice rows Merge (`selected`), Discard and Ignore, each with its note; buttons Cancel and Merge.
  - close-with-unsaved-changes: Discard, Cancel, Save.
  - save-failed: Save As…, Close, Try Again.
- **Keyboard** (arrows move the choice, Return runs it, Escape cancels): an offscreen window is never key, so this **needs Mac QA (owner's go)**, as LD-169.
- **Shared files updated (these 3 frames' rows only):**
  - design/parity/dialogs/report.md: the changed-on-disk row's pixel cell, and one Verify bullet under each of the 3 frames;
  - report.html: the summary cells, the changed-on-disk section from the common-area run with its image-size line, and one Verify note in each of the 3 sections;
  - findings.json: changed-on-disk `pixels`, `residual`, `colours` and `commonArea` for light and dark, and a `verify` note on the 3 records;
  - diff/light/ and diff/dark/dialogs-changed-on-disk.png: added, since there were none before.

### R2. Part B: AT-I05 through the screen

**Setup of each test.** Each window is `Session()`, then `open`, `unlock` (demo-pass-7) and `switchTo`, then `MainWindowModel(session:)` and `refresh()`. `refresh()` makes the `VaultModel` and starts the real `DiskWatch`. Then a `Screen` (the real MainWindow, offscreen, read and pressed through the accessibility tree). A change is `beginNew`/`beginEdit` → `setText` → `commitEdit` → `main.afterChange(select:)`, the call the editor's Save makes. ⌘S is `saveNow(asks: true)`, what the File menu's Save runs. "Another program" is a second `Session` that edits a copy elsewhere and saves. A "sync service" copies that file to `.Personal.appvault.sb-<random>` in the vault's folder and `rename(2)`s it over the vault. "In place" is `FileHandle` truncate + write + sync on the same inode.

Both suites alone: `xcodebuild … test-without-building -only-testing:AppTests/VerifyE5S10Tests` gave `✔ Test run with 6 tests in 1 suite passed after 27.909 seconds.`, `** TEST EXECUTE SUCCEEDED **`. `-only-testing:AppTests/VerifyE5S10CardTests` gave `✔ Test run with 13 tests in 1 suite passed after 58.448 seconds.`, `** TEST EXECUTE SUCCEEDED **`. Log lines below come from that run (/tmp/e5s10-verify-work/b/log.txt).

| Test | What it does | Result (log) |
|---|---|---|
| **V-B1** "two windows edit one vault and save in turn; the watch asks, Merge keeps both" | Windows A and B on one file, `save.after_every_change` off in both. A: 2 new entries and Wise's user name. B, 1.1 s later: 2 new entries, GitHub's notes and Wise's user name. A saves (⌘S). B's watch raises the question. Press Merge, then B saves. A has no unsaved changes, so it reloads silently. Then, with B's watch off (as a share whose events are lost): A adds and saves; B adds and saves, so the save finds the change; press Merge then save. | B's sheet after **523 ms**: `changedOnDisk(ask: .unsaved, changes: 4)`. Sheet: "Personal.appvault changed on disk", "“Personal.appvault” was changed by another program, and this vault has unsaved changes.", Merge, Discard ("Your 4 changes are lost."), Ignore, Cancel. Nothing written before the answer (bytes = A's file). A's own save raised no question. A reloaded after **551 ms**, toast "Reloaded.". File: **27 entries = 23 + 4**. Wise UserName `user-from-B`; Wise history holds `user-from-A` (the older side goes to history, MOD-11). GitHub notes `notes-from-B`. B's later save asked `changedOnDisk(ask: .onSave, changes: 1)` (Merge then save, Discard, Overwrite, Cancel) and wrote nothing. After Merge then save: **29 entries = 23 + 6**, B changes 0. Folder: `Personal.appvault 644` (mode kept), `Personal.old.appvault 600`, which holds A's file from before B's save. 0 temp files. |
| **V-B2** "a sync service renames a new version over the file while edits wait; Merge keeps both" | Edits wait: a new entry and Wise's notes "mine". The other side: a new entry and Google's notes "theirs". Atomic rename over the file. | Inode 427852668 → 427853830. Sheet after **543 ms**: `.unsaved, changes: 2`. Nothing written before the answer. After Merge and ⌘S: **25 entries = 23 + 2**, Wise notes `mine`, Google notes `theirs`. The backup holds the synced version (bytes equal), 0600. |
| **V-B3** "another program edits the file in place; reload, Discard and Keep" | (1) Unchanged vault, in-place write. (2) An unsaved change, in-place write, press Discard. (3) `save.reload_on_change` off, in-place write, press Keep, then ⌘S. | (1) Same inode 427856334; silent reload after **552 ms**, toast "Reloaded.", changes 0. (2) Sheet after **545 ms** `.unsaved, 1` ("Your 1 change is lost."). Discard: "In Place 2" shown, "Local Lost" gone, changes 0. (3) Sheet after **543 ms** `.reload` ("Load the changes?", Load, Keep). Keep: changes 1. Next ⌘S: `.onSave, changes: 1`, file unchanged. |
| **V-B4** "the file is deleted, then moved; no question; the next save writes it anew (0600)" | `save.after_every_change` on. Delete the file, then make a change. Another program edits the new file in place. Move the file to Moved.appvault, then make a change. | Delete: no question in 2 s, vault still unlocked. The change saved a new file, mode **600**, toast "The vault file was missing. App saved it again at /private/tmp/e5s10-verify-work/b/b4/Personal.appvault." (MSG-SAVE-RECREATED), no backup (folder: `Personal.appvault 600` only). The watch saw the in-place edit after that. Move: no question; the old path written anew (600); Moved.appvault byte-unchanged. |
| **V-B5** "a conflict copy appears: no question, nothing written; the sync puts it in place: Merge keeps both" | Edits wait. A conflict copy `Personal (conflicted copy 2026-10-28).appvault` (the other side's version) appears in the folder. Then the sync service renames it over the vault. | The copy alone: no question in 2 s, the vault file byte-unchanged, changes still 2 (APP-05.17: App does not look for conflict copies). Swap: sheet after **541 ms** `.unsaved, 2`. After Merge and ⌘S: **25 entries = 23 + 2**, Wise `mine`, Google `theirs`. The conflict copy is byte-untouched. |
| **V-B6** "after App's own save (a rename), an in-place edit by another program is still seen at once" | App saves (inode changes). 1.5 s later another program writes in place. | Inode 427856436 → 427856438 (App's rename); the in-place write keeps 427856438. Reloaded after **521 ms**, toast "Reloaded.". This proves the watch re-arms on the new file. |

**The reference CLI on the results** (`REF_CLI ls -R -f -q`, demo-pass-7 on stdin; `show -q -a UserName -a Notes`):

```
b1-two-windows.appvault: exit 0, 31 entries (2 in the Recycle Bin), new: A1 Demo Shop;A2 Demo Bank 2;B1 Demo Mail 2;B2 Demo Wiki;A3 Demo Shop 3;B3 Demo Wiki 3;
b2-sync-swap.appvault: exit 0, 27 entries (2 in the Recycle Bin), new: Remote Demo Shop;Local Demo Mail 2;
b4-after-move.appvault: exit 0, 28 entries (2 in the Recycle Bin), new: After Delete;After Recreate Remote;After Move;
b5-conflict.appvault: exit 0, 27 entries (2 in the Recycle Bin), new: Theirs Conflict;Mine Unsaved;
b1-two-windows Banking/Wise exit 0: user-from-B||
b1-two-windows Work/GitHub exit 0: alex-dev|notes-from-B|
b2-sync-swap Banking/Wise exit 0: alex.morgan@posteo.de|mine|
b2-sync-swap Email/Google exit 0: alex.morgan@gmail.com|theirs|
b5-conflict Banking/Wise exit 0: alex.morgan@posteo.de|mine|
b5-conflict Email/Google exit 0: alex.morgan@gmail.com|theirs|
b1/Personal.old.appvault: exit 0, 30 entries, mode 600
b2/Personal.old.appvault: exit 0, 26 entries, mode 600
b5/Personal (conflicted copy 2026-10-28).appvault: exit 0, 26 entries, mode 644
b4/Moved.appvault: exit 0, 27 entries, mode 600
```
`db-info -q` on b1 printed `Number of entries: 29`, `Cipher: AES 256-bit`, `KDF: Argon2id (2 rounds, 1024 KB)`. The live entries (29, 25, 26, 25) are the counts our reader gave.

**Rust, the same flows below the screen:** the builder's `saving::tests` pass (17 of 17 in the 916). They include `at_i05_two_windows_save_in_turn_and_keep_every_change`, `at_i05_a_sync_swap_with_unsaved_edits_merges_without_loss`, `at_i05_a_conflict_copy_merges_without_lost_entries` and `at_i05_a_change_made_during_a_silent_reload_is_kept`, as well as app-core `at_i05_two_writers`.

**Under load.** In the parallel full run (35 suites share the main actor; `saveAll` runs the save's KDF on it), the same sheets showed after 0.6 to 7.9 s. V-C T03, V-C T47 and V-B3 then missed their waits (10 s), because of the test harness. Alone, every test passes. This is advisory 6, not a fail.

### R3. Part C: the APP-05 card cases

Waiting = waiting for a mockup addition (not drawn in Option A; not a fail).

| Case | Result | Proof |
|---|---|---|
| T01, T02 APP-05.1 | Not reached: the built sidebar has no collapse control, so no view-state change exists yet | no expand API in app-ffi |
| T03 APP-05.2 | **PASS**: one save (2 inodes seen), its task starts at **166 ms** (window 150 ms ± 20) | V-C T03 |
| T04 APP-05.2 | **PASS** (saves one at a time; a waiting save writes the change made meanwhile) | `edit::tests::ld_199_4_a_waiting_save_writes_the_change_made_while_it_wai…` |
| T05 APP-05.3 | Not run (a 2-minute timer). The code restarts an N-minute timer on each change (`scheduleSave`). | advisory 5 |
| T06 APP-05.3 | **PASS** | builder "APP-05.3 T06: S-FILE-01 turned off …" |
| T07 APP-05.4 | **PASS**: ⌘L saved, then locked after 171 ms, no question | V-C T07 |
| T08 APP-05.4 | Not reached (no view-state change) | — |
| T09 APP-05.5 | E5-S9's settings (link tested in app_settings.rs) | — |
| T10 APP-05.6 | **PASS** for the save. "Save disabled afterwards" differs: Save stays enabled while unlocked (APP-08's `action.save` row); a card conflict | advisory 3 |
| T11 APP-05.6 | **PASS** | `app_05_6_save_as_moves_the_vault_to_the_new_file`; builder "Parity dialogs-save-failed … Save As…" |
| T12, T55 | Not built: Save a Copy is disabled in the File menu | waiting / later |
| T13 APP-05.7 | Footer "N changes not saved yet" **PASS** (states-unsaved-changes, E5-S4). The close button's edited mark and the switcher dot are not built and not drawn. | waiting (advisory 4) |
| T14, T15 | Not run here (test hooks); the session answers during a save (`ld_199_4_vault_settings_during_a_reload_or_a_save_never_hangs`) | — |
| T16, T23 | **PASS** in app-core | `app05_09_real_path_and_links`, `at_i04_link_tricks` |
| T17 APP-05.10 | **PASS** | `app_05_10_…`, V-B1 (2nd half), V-C T50 |
| T18 | **PASS** | V-B4 |
| T19 | **PASS**: sheet "The vault file cannot be read.", nothing written | V-C T19 |
| T20 | Mode kept (V-B1: 0644 stays 0644, new inode) **PASS**. Creation date, Finder tags and ACL are not copied. | open (LD-129, LD-200) |
| T21, T22 | **PASS** in app-core | `at_i01_killed_mid_save`, `at_i06_owner_only_permissions`; V-B4 0600 |
| T24 | app-core | `at_i03_no_permission` (and E4-S15) |
| T25 APP-05.14 | Not built (MSG-SAVE-UNSAFE-ASK has no frame) | waiting |
| T26 | **PASS, with a known difference**: 3 failures, each with the reason "This vault's file or its folder cannot be written."; no unsafe question. The sheet shows once per run of failures, later ones only in the footer (the card: a banner for each) | V-C T26, advisory 2 |
| T27, T28, T29 | **PASS** in app-core | `app05_15_temp_move`, `app05_16_direct`, `ld131_*` |
| T30 | **PASS**: only the vault and `Personal.old.appvault` in the folder | V-B1, V-B2 listings |
| T31 APP-05.18 | Not built | waiting |
| T32 | **PASS** | `app_05_19_…`, V-B1 (backup = A's bytes, 0600) |
| T33 | **PASS** for a recreated file (no backup, V-B4); a new vault: E5-S8 | — |
| T34 to T38 | **PASS** in app-core | `app05_20_backup_path_pattern`, `app05_20_pattern_survivors`, `app05_21_backup_path_resolution`, `app05_19_backup_before_save` |
| T39 APP-05.22 | **PASS**: the first save gave "The backup copy could not be written: … The vault was still saved."; the second showed none; both changes are in the file | V-C T39 |
| T40 APP-05.24 | **PASS**: watch 0.52 to 0.55 s (well under 2 s); with no file events, the tick looks once between 29 and 31.5 s | V-B1 to V-B6, V-C T40 |
| T41, T42 | **PASS** | V-B1 (A's own save), V-B4 (deleted, moved), `app_05_24_…` |
| T43 APP-05.25 | **PASS**: no question or reload while the editor is open (2 s, `pending` true); the reload ran 72 ms after Cancel | V-C T43 |
| T44 | **PASS** ("Reloaded.") | V-B3 (1), V-B1 |
| T45 | **PASS** | V-B3 (3) |
| T46 | **PASS** | V-B1, V-B2, V-B5 |
| T47 | **PASS**: Ignore paused the watch (no question for a second swap); the next ⌘S replaced the file and said "The file on disk was replaced."; neither of the other side's entries is in the file | V-C T47 |
| T48 | **PASS** | V-B3 (2) |
| T49 | **PASS** | builder "Parity dialogs-changed-on-disk: … Overwrite saves over it", `app_05_28_…` |
| T50 | **PASS**: ⌘L showed the `.onSave` question; Cancel left the vault unlocked, changes 1, the file untouched | V-C T50 |
| T51 APP-05.29 | Open vault unchanged and marked changed, with the MSG-DISK-NEW-KEY text as a notice. The unlock sheet is not drawn. | V-C T51; waiting |
| T52 APP-05.30 | **PASS**: notice MSG-DISK-UNREADABLE after 529 ms; the vault is unchanged and not changed; ⌘S then offers only Overwrite and Cancel; Overwrite writes a vault again | V-C T52 |
| T53 APP-05.31 | **PASS**: Wise is still selected after a silent reload | V-C T53 |
| T54 APP-05.32 | **PASS** in Rust; the notice sheet has no frame | `app_05_32_…`; waiting (look) |
| T56 to T59 APP-05.33 | Not built | waiting |
| T60 APP-05.28, .4 automatic | **FAIL**: the change is dropped, and there is no recovery copy | V-C T60 probe: `locked true; dialog nil; file has T60 Mine false, T60 Theirs true` → fail 2 |

### R4. Part D: mutations (private copy only)

Each mutant was applied in /tmp/e5s10-verify-copy, built with its own target and derived data, then restored from /tmp/e5s10-verify-work/pristine (`cmp` OK after each).

Swift (`xcodebuild build-for-testing`, then `test-without-building` of the builder's `ParitySavingTests` and my suite):

| Mutant | Builder ParitySavingTests (8) | Verify tests |
|---|---|---|
| S1 DiskWatch watches the folder only | 8 pass | **V-B3 fails** (3 issues: no reload, no question for in-place edits) |
| S2 DiskWatch watches the file only | 8 pass | **V-B4 fails** (`seen != nil`: after a delete and recreate, nothing re-arms) |
| S3 no re-arm after an event | 8 pass | **V-B6 fails** (in-place edit after App's own rename not seen in 10 s) |
| S4 "Merge then save" does not save at once (`atOnce` only for Overwrite only) | 8 pass | **V-B1 fails** (file 28, not 29 entries; backup not A's bytes) |
| S5 a lock's save that meets a changed file shows the close question over the disk question | 8 pass | **V-C T50 fails** (dialog is not `.onSave`) |
| P0 (an attempt at a no-op run) | the runner refused it: `self?.arm()` occurs twice | — |

Two first tries of S2 and S4 did not build (an unused `let` under warnings-as-errors). Their test results came from the previous build, so I discarded them and rebuilt with the mutations above.

Rust (`cargo test -p app-ffi --lib saving`, 17 tests):

| Mutant | Result |
|---|---|
| R1 Merge never merges (`if false`) | **5 fail**: `app_05_27_merge_keeps_both_sides_and_saves` and 4 `at_i05_*` |
| R2 `check_disk` reloads over unsaved changes (`changes > 999`) | **3 fail**: `app_05_27_merge…`, `at_i05_a_conflict_copy…`, `at_i05_a_sync_swap…` |
| R3 no pre-save check (`ignore_disk_changes = true`) | **5 fail**: `app_05_10`, `app_05_26`, `app_05_28`, `app_05_30`, `at_i05_two_windows…` |
| R4 the watch does not move with App's own save (`sv.watched = …` removed) | **1 fails**: `app_05_24_own_saves_raise_no_event…` |
| R5 Keep mine does not set "ignore" | **1 fails**: `app_05_28_keep_mine_saves_over_the_disk_version` |
| R6 no backup | **1 fails**: `app_05_19_the_backup_holds_the_file_before_each_save` |
| R7 Discard/Load ignores a change made during its KDF (`Some(u32::MAX)`) | **survives**: 17 pass (the Checker's advisory, confirmed) |

### R5. Regression and checks

- `cargo test -p app-ffi -p app-core` (copy) printed 43 `test result` lines, **916 passed, 0 failed, 25 ignored**, exit 0, 2:39. E5-S8's save tests pass: `mod12_10_changing_the_key`, `mod12_14_when_encryption_changes_take_effect`, `vault_settings::tests::cry02_14_an_approved_costly_kdf_saves_without_ask…`, `app07_16_t31_a_password_below_the_set_minimum_is_refused`, `ld_199_3_kept_password_is_page_locked`, `ld_199_4_*`.
- `cargo clippy -p app-ffi -p app-core --all-targets -- -D warnings`: `Finished`, exit 0. `cargo fmt -p app-ffi -p app-core --check`: exit 0.
- Swift, final full run (copy, pristine code plus my two suites): `✘ Test run with 232 tests in 35 suites failed after 153.582 seconds with 7 issues.` 30 suites passed, including `✔ Suite SavingSnapshotTests` and `✔ Suite ParitySavingTests` (8 of 8). The 7 issues:
  - 3 in my suites, waits under load (above);
  - `FEA-01.34 … under 50 ms` (ScreenTests.swift:160, parallel-load timing);
  - `NSPasteboard.general.changeCount` at GeneratorTests.swift:137 and ParityStatesTests.swift:137 (LD-206).
  
  Alone (`test-without-building -only-testing`): ScreenTests `9 tests … passed`, ParityGeneratorTests `10 tests … passed`, ParityStatesTests `16 tests … passed`, VerifyE5S10Tests 6 passed, VerifyE5S10CardTests 13 passed.
- `xcrun swift format lint --strict --recursive macos` (shared tree): exit 0. SwiftLint `--strict` on the E5-S10 files (Saving, SavingSheets, DiskWatch, MainWindowModel, AppCommandsVault, Menus, MenuBarIcon, SavingTests): exit 0. On the whole tree, 2 findings sit in MenuBarIconTests.swift:95 and MenuBarTests.swift:402. Another workflow (E5-S11 menus) changed both files at 20:23 to 20:24, during this run; they are not E5-S10's.
- `scripts/check-names.sh`: `names: PASS (3097 files scanned, 15 vault files name-only)` (R7).
- **Secrets (rule 4).** Every text the three sheets and the notices show is a file name, a count, a path or the system's reason (the strings above). Rust's `reason()` and the notices hold no vault content.

### R6. Open issues and advisories (not fails)

1. **Tests that would catch regressions.** The builder's Swift tests catch none of S1 to S5, and R7 survives. Smallest fix: move V-B3 (in place), V-B4 (delete and recreate), V-B6 (re-arm), V-B1's "Merge then save" half and V-C T50 into SavingTests, and add the Checker's Discard-during-KDF probe as a Rust test.
2. **MSG-SAVE-FAILED.** It shows as the mockup's sheet once per run of failures; later failures show only in the footer (its tooltip holds the reason). APP-05.13 says a banner for each failure, for 15 s. This is a known difference to record (mockup look over card).
3. **Save menu item.** APP-05.6 enables Save only while the vault is changed (T10: "Save disabled afterwards"), but APP-08's `action.save` row enables it while unlocked. The app follows APP-08. The cards should agree.
4. **APP-05.7.** The close button's edited mark and the switcher's dot are not built. states-unsaved-changes draws only the footer: waiting for a mockup addition.
5. **No test for T05** (the per-vault autosave delay).
6. **Events during a check.** A disk event that arrives while a check runs (a silent reload's KDF) only sets `pending`. It is handled by the next save, by the closing of a sheet or the editor, or by the 30 s tick, not when the reload ends (APP-05.25). Code reading of Saving.swift `checkDisk`/`handle`.
7. **Main-thread saves.** `saveAll` runs each changed vault's save (the KDF) on the main thread, for Lock Everything, automatic locks and quit (the Checker's advisory). Under a busy main actor the watch-to-sheet time grew to 7.9 s in the parallel test run.
8. **The parity tool.** design/parity/tools/compare.mjs skips checks 3 and 5 on a size difference and still gives PASS (the Checker's advisory). The next regeneration of the dialogs report will print "undefined %" again for changed-on-disk (and weak-vault-password). Smallest fix: compare the common area, as compare-crop.mjs did here.
9. **Still open from the build and Checker reports:**
   - APP-05.11's creation date, Finder tags and ACL (app-platform, LD-129, LD-200);
   - the APP-05.29 unlock sheet, APP-05.14, APP-05.18, APP-05.33, Save a Copy and MSG-DISK-RELOADING (not drawn);
   - Lock Everything stops at the first vault that asks;
   - `saveAll(asks: true)` shows the close question for a save refused by a changed file.

### R7. Commands at the end, cleanup

- `scripts/check-names.sh` (shared tree, after this file and the parity edits): `names: PASS (3097 files scanned, 15 vault files name-only)`.
- Cleanup: `rm -rf /tmp/e5s10-verify-copy /tmp/e5s10-verify-target /tmp/e5s10-verify-dd /tmp/e5s10-verify-work /tmp/e5s10-verify-scripts`. Afterwards `ls -d /tmp/e5s10-verify*` printed `no matches found`.
- The Rust mutants whose tests failed left 16 demo-vault folders `$TMPDIR/app-ffi-saving-<tag>-<pid>`. The panicking tests skip their own cleanup. The pids match my runs R1 to R6, all at 20:23, and I removed those 16. 32 older folders of that name, from 19:02 to 19:54, come from other runs. I left them alone (rule 11). The builder's tests leave them only when a test fails; advisory: remove them on drop, as LD-211 (4) asks for the reports tests.
