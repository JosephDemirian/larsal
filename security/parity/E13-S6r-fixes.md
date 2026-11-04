# E13-S6 part r: F-135 and one test that fails only in the full run (Builder, 2026-10-30)

Story: E13-S6 part r ([plan/epics.md](../../plan/epics.md)), after Done (LD-253), Low only. Rulings: LD-241 (1). Row: F-135 (Low) in [security/findings.md](../findings.md). Role: Builder. I did not find these problems.

| # | Item | Result | Test |
|---|---|---|---|
| a | F-135: AT-K06 fails on the unlock screen with Caps Lock down; the walk reads the Mac's key | (2) fixed; (1) for the lead to accept (the picture is AppKit's own) | `AccessibilityWalkTests/walk(_:capsLock:)` (48 cases), `AccessibilityWalkTests/f135SecureFieldCapsLockPicture()` |
| b | ProtectedUndoTests F-127 (Notes) fails in the full LarsalTests run of 2026-10-30, 20:23, passes alone | fixed in Larsal after Checker 1: the cause is F-136 (Low), fixed in `UndoOff` (round 2 below) | `MenuKeysTests/f127ProtectedStandardFieldKeepsNoUndo(_:afterClosedEdit:)` (8 cases, in ProtectedUndoTests.swift) |

Files: `macos/LarsalTests/AccessibilityWalkTests.swift`, `macos/LarsalTests/ProtectedUndoTests.swift`, and in round 2 `macos/Larsal/EditorProtected.swift` (F-136). `macos/Larsal/CapsLock.swift` (its `capsLockFake` seam is used as it is) and `macos/Larsal/UnlockView.swift` stay as they were (see a (1)).

The Mac's Caps Lock was never pressed, toggled or sent as an event. Every run below read it as up (`CGEventSource.flagsState(.combinedSessionState)` and `.hidSystemState`, no `.maskAlphaShift`; `NSEvent.modifierFlags` without `.capsLock`). All runs were in the private copy `/tmp/e13s6r-builder-copy` with its own derived data, offscreen, with demo vaults.

## a. F-135

**What the picture is.** It is not a view of Larsal. The unlock screen's password is a SwiftUI `SecureField`. AppKit edits it in its secure field editor (`NSSecureTextView`), which keeps its own Caps Lock flag (`_sdvFlags._capsLockDown`) from the real key. While the flag is set, AppKit's secure field cell (`NSSecureTextFieldCell`, the "Password" text field) lists one more accessibility child: an `NSAccessibilityImageMockUIElement`, role `AXImage`, label "caps lock down" (AppKit's own accessibility string table), that allows a press. Larsal's own Caps Lock note (M06-37, `CapsLockNote`) is a text line, and it reads the key only through `capsLockFake` or `NSEvent.modifierFlags`.

Proof (private copy, a probe test only): with the editor's own Caps Lock flag set by hand (no key, no event), the old walk gives exactly the failure of the lead's run: `unlock: AXImage at (572.0, 815.0, 36.0, 52.0): clickable but not a control (caps lock down)`, with its parent `NSSecureTextFieldCell`. Faking `NSEvent.modifierFlags` alone does not draw it: AppKit reads the key elsewhere.

**(1) The picture takes a press: for the lead.** Larsal cannot change the picture without private AppKit calls. It belongs to AppKit's secure field, it is the same in every AppKit password field on the Mac, VoiceOver reads it as "caps lock down", and the field it sits in is a named control that the keyboard reaches. Replacing SwiftUI's secure field with one of Larsal's own, only to drop or rename AppKit's picture, would take a standard system signal away from VoiceOver users, and it would touch the password entry path that F-069 and APP-10.9 protect. This is in the builder's decisions for the lead (accept, not fix).

**(2) The walk depends on the key: fixed.**
- Every walked screen is built twice, with `capsLockFake` false and true (`walk(_:capsLock:)`, 24 screens x 2 = 48 cases): the main window screens through the hosting view's root (`.environment(\.capsLockFake, ...)` on the `Screen`'s root view), the settings, vault settings and new vault windows on their own root view. Larsal's own note then shows only when the fake says Caps Lock is down, whatever the key is.
- On "unlock" the walk also checks that the note follows the fake: shown with the fake down, not shown with the fake up (`the note is not the fake's`). So the Caps Lock down state is really walked, and a real key down cannot show it in the up case.
- The clickable-picture rule skips one thing only: an `AXImage` whose accessibility parent is an `NSSecureTextFieldCell`, that is AppKit's own Caps Lock picture. A clickable picture anywhere else still fails. So AppKit's picture, which only the real key can draw, no longer changes the result.

**Test.** `f135SecureFieldCapsLockPicture()`: a host offscreen with two pictures that allow a press, one whose parent is a secure field cell ("caps lock down"), one whose parent is a plain text field cell ("a picture"). The walk must report only the plain one.

**Mutant proof (private copy).**
| Mutant | What is undone | Result |
|---|---|---|
| M1 | the skip of AppKit's picture (`appKitCapsLock = false`) | `f135SecureFieldCapsLockPicture()` failed: `["clickable but not a control (caps lock down)", "clickable but not a control (a picture)"]`. The probe with AppKit's real picture failed in both fake states with `unlock: AXImage at (572.0, 815.0, 36.0, 52.0): clickable but not a control (caps lock down)`. Load 6.6 to 7.9 |
| M2 | the fake (the walk sets no `capsLockFake`) | `walk(_:capsLock:)` failed for `"unlock", capsLock: true` only: `unlock: AXStaticText at (0.0, 0.0, 0.0, 0.0): the note is not the fake's`. Load 6.2 to 7.0 |
| none | the fix | the probe with AppKit's real picture passed in both fake states (the picture listed, no walk failure); `AccessibilityWalkTests` 50 tests passed (48 walk cases, F-135, the secret check). Load 8.8 to 11 |

## b. ProtectedUndoTests, Notes, in the full run

**Cause.** SwiftUI uses one field editor for the text fields of every window in the process (`_SystemTextFieldFieldEditor`, the same object in every test window, seen in each case). AppKit sets that editor's undo on when an edit starts in a cell that keeps undo (`_setFieldEditorUndoManager:`, from `NSTextField.becomeFirstResponder`) and off when that edit ends (`NSCell.endEditing`) or a field takes the editor over from a live window. A window released in the middle of an edit never ends that edit, so the editor keeps its undo on (F-136, found by Checker 1). An edit that starts in a cell that keeps no undo, as the shown protected field (F-127), leaves the editor as it is. Proof: with the editor's undo set on by hand while no edit is live, `makeFirstResponder(shown)` keeps it on. A spy on the setter in two full runs showed the other suites' windows turn it on 23 times per run (20 from SwiftUI moving the focus in their windows, 3 from MenuKeysTests' cut and copy tests). So the test trusted state that another suite's window can change during its awaits. The failure in the lead's run matches that state exactly: the field editor edits the shown Notes field (724 x 18), its undo is on, and Undo gives back `demo-protected-7Kq2`. Which suite left it on at 20:23 is not recorded: four full runs in the copy (load 4.1 to 24.8) did not fail again (one had the APP-01.27 c timing issue only, a known timing test).

Shapes tried that a real Larsal window can make, each with another window editing first: taken over while live, its content removed, its view torn down, locked, closed (kept and released), ordered out, its edit aborted, its value set while editing, typed into. Each time the takeover by the shown protected field turned undo off. Corrected after Checker 1: that was wrong. In the "closed and released" shape here the window was still alive at the takeover (it is freed only when the run loop turns), so it was a takeover from a live window. A window freed before the takeover leaves the editor's undo on, and Larsal frees a closed Settings window (`LarsalSettingsWindow.current = nil`). That is F-136; F-127's fix did not cover it. Round 2 below fixes it in `UndoOff`.

**Fix, round 1 (removed in round 2: it hid F-136).** Right before `makeFirstResponder(shown)`, with no await between, the test sets the shared field editor's undo off: the state an ended edit leaves. Nothing another suite did with that editor during the awaits above is trusted. The test's claim is unchanged: the edit starts from the cell, and a cell that keeps undo turns the editor's undo on.

**Mutant proof (private copy).** The clash is injected in the copy only, after the test's last await: the shared field editor's undo is set on, as another suite's window leaves it.
| Run | Shape | Result |
|---|---|---|
| U1 | the old test (no restore) with the clash | failed 3 of 3 with 8 issues each: for each of Title, UserName, URL and Notes, `!fieldEditor.allowsUndo` and `Self.textAfterUndo(fieldEditor) == "second"` (the two lines of the lead's run). Load 5.5 to 6.1 |
| U2 | the fix with the same clash | passed 3 of 3. Load 4.5 to 4.8 |
| U3 | the fix, no clash, Larsal's `UndoOff` mutated to leave the cell's undo on | failed with 12 issues: per field the cell check and both field editor checks. So the restore does not hide a Larsal fault. Load 4.0 to 4.3 |

## Full LarsalTests runs

Private copy, the same Swift files as the shared tree (`diff -rq` of macos/Larsal and macos/LarsalTests: no difference), core from `scripts/build-core.sh` in the copy, built with `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, then `test-without-building -skip-testing:LarsalUITests`:

| Run | Result | Load (start, end) |
|---|---|---|
| 1 | `Test run with 349 tests in 51 suites passed after 199.393 seconds` | 12.67, 5.30 |
| 2 | `Test run with 349 tests in 51 suites passed after 202.100 seconds` | 5.30, 4.41 |
| 3 | `Test run with 349 tests in 51 suites passed after 202.802 seconds` | 4.41, 22.56 |

349 is the 348 of before plus the F-135 test; the walk's 48 cases count as one test.

Shared tree, with the core already built there and a derived data folder of my own under /tmp: AccessibilityWalkTests, ProtectedUndoTests, UndoOffEditingTests, WindowFixesTests (the other `capsLockFake` user), CopySelectionTests and MenuKeysTests (the other users of the shared field editor) with `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `Test run with 27 tests in 6 suites passed`, `** TEST SUCCEEDED **`. Load 21.86 to 14.86.

## Checks

- `swift format lint --strict --recursive macos`: exit 0.
- `swiftlint lint --strict` in macos/: exit 0.
- `scripts/check-names.sh`: `names: PASS (11525 files scanned, 16 vault files name-only)`.
- `scripts/check.sh` was not run (another agent owns that run).

## Checker 1 (2026-10-30): sent back (2)

Role: Checker 1. I did not build this part. Private copy `/tmp/e13s6r-checker1-copy` with its own derived data, offscreen, demo vaults; the shared Swift files were copied back over every mutant and `diff -rq` of macos/ against the shared tree showed no difference before the last run. The Mac's Caps Lock was never pressed, toggled or sent; read only, it was up in this session (`CGEventSource.flagsState`, combined and HID state: no `.maskAlphaShift`).

**F-135: confirmed.**
- The picture is AppKit's own. A probe on the unlock screen found the editor is `NSSecureTextView` (flags ivar `{"_secureInput"b1"_capsLockDown"b1"_numLockDown"b1...}`). With its Caps Lock bit set by hand, the walk listed `NSAccessibilityImageMockUIElement` "caps lock down", parent `NSSecureTextFieldCell`, press allowed, at (572.0, 815.0, 36.0, 52.0): the lead's frame exactly. The fixed walk reported nothing; with the skip undone (`appKitCapsLock = false`) it gave `unlock: AXImage at (572.0, 815.0, 36.0, 52.0): clickable but not a control (caps lock down)`, and `f135SecureFieldCapsLockPicture()` failed at AccessibilityWalkTests.swift:142. After one settle AppKit put the bit back to the key's state, so the picture follows the real key. UnlockView.swift draws no Caps Lock picture of its own (the password is a SwiftUI `SecureField`). I agree that (1) is for the lead to accept.
- The fake undone (`fake()` made a no-op): only `walk(_:capsLock:)` with "unlock", true failed: `the note is not the fake's`. Fixed: AccessibilityWalkTests 50 cases passed (48 walk cases in 34.5 s). Load 8.6 to 6.9.
- Other users of the note (WindowFixesTests) all set `capsLockFake`.

**Item b: the test passes, but its cause is in Larsal: F-136 (Low, filed).**
- The 20:23 failure comes from a real Larsal path, not only from tests running side by side. A window released in the middle of an edit leaves SwiftUI's shared field editor with its undo on, and a shown protected field's edit then keeps it on. Probe (two offscreen windows, each with a SwiftUI text field, the second cell with no undo): a takeover from a live window, a sleep, a torn-down view, ordered out and closed (still held) all turned undo off, as the builder found; a window closed and released, or released, left it on (3 of 3), and the no-undo field's edit kept it on.
- Larsal does this: LarsalSettingsWindow and the aux windows drop their window on close. Shape: an `OtherWindow` with `LarsalSettingsView`, "Search settings" made first responder, the window closed and released, then the F-127 test's makeFirstResponder. Old test (no reset): 8 issues, `!fieldEditor.allowsUndo` and `Self.textAfterUndo(fieldEditor) == "second"` for all four fields (the lead's two lines; :69 and :70 of the mutant file). Part r's test (with the reset): the same shape passed, so the reset hides it. Load 4.4 to 4.3.
- Larsal's `UndoOff` mutated to keep the cell's undo on, with the test unchanged: 12 issues (:55, :70, :71 per field). So the reset does not hide a fault in the cell.
- A product fix works: a prototype in the copy where UndoOff's probe watches `window.firstResponder` and runs `set()` then (two lines) passed the closed Settings shape for all four fields with no test-side reset, and `UndoOffEditingTests` passed. Built with `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`. Load 6.6 to 6.9.

**Full LarsalTests** (private copy, the shared Swift files, `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, `-skip-testing:LarsalUITests`): `Test run with 349 tests in 51 suites passed after 200.459 seconds`. Load 5.51 to 5.49.

**Lints:** `swift format lint --strict --recursive macos` exit 0; swiftlint 0.65.1 `lint --strict --quiet` in macos/ exit 0; `scripts/check-names.sh`: `names: PASS (11525 files scanned, 16 vault files name-only)`.

**Sent back:**
1. F-136: fix the cause in UndoOff (EditorProtected.swift, which part r does not own: the lead gives it, or another part takes F-136). Then add the closed-and-released window shape as a ProtectedUndoTests case that fails with the fix undone, and drop the test-side reset or keep it only as a guard against other suites.
2. Section b above and ProtectedUndoTests.swift:59-65 say AppKit turns the editor's undo off when an edit ends and that no Larsal path leaves it on. A window released in the middle of an edit never ends it. Correct both and name F-136.

## Builder, round 2 (2026-10-30): Checker 1's two items

Role: Builder. Private copy `/tmp/e13s6r-builder-copy`, derived data `/tmp/e13s6r-builder-dd`; its core is a copy of the shared `target/larsal-core` (no Rust file changed). Offscreen, demo vaults. The Mac's Caps Lock was not touched. The lead's brief gave part r F-136, so part r took `macos/Larsal/EditorProtected.swift` for the fix.

**1. F-136: fixed in Larsal.** `UndoOff`'s probe now also observes its window's `firstResponder` (key-value observing) and runs `set()` at once when it changes. So when the shown protected field's edit starts, its editor's undo goes off, whatever another window left it as. Four lines: one property and one observation in `viewDidMoveToWindow`. The rest of `UndoOff` is as it was.

**Test.** `f127ProtectedStandardFieldKeepsNoUndo(_:afterClosedEdit:)` in ProtectedUndoTests.swift: Title, UserName, URL and Notes, each without and with `ProtectedUndoTests.closeInMidEdit()` right before the click. The helper puts Larsal's Settings view in an `OtherWindow`, makes "Search settings" the first responder (its edit keeps undo), closes the window and lets the run loop free it (50 ms; the test checks that the window is gone). Round 1's test-side reset is removed, so only Larsal's fix passes the test.

**Why round 1 missed it.** Probe (copy only, then removed): with a Settings window closed in the middle of an edit, the editor's undo after the takeover was off while the window was still alive (no run loop pass: 2 of 2), and on when the window was freed first (a sleep, a yield, or freed with no close: 3 of 3). Round 1's "closed and released" shape was of the first kind.

**The test joins MenuKeysTests' serialized group (LD-241 (1)).** The first 3 full runs, with the test in its own suite, each failed "APP-08.14: ↓ and ↑ in the search field move the list's selection" (MenuKeysTests.swift:131, :140 or :143), each time while a closed-edit case ran: every case takes SwiftUI's one field editor from that search field in the middle of the test. With the closed-edit cases taken out (the same fix), 2 full runs passed APP-08.14. So the test is now in `extension MenuKeysTests` (as MenuKeysMoreTests is) and never runs beside the search keys. `ProtectedUndoTests` keeps the custom field test and the helpers (HygieneFixesTests uses `textAfterUndo`).

| Run | What | Result |
|---|---|---|
| M3 | the fix undone (no observation), the test in its own suite | failed 3 of 3 with 8 issues each: for each field with `afterClosedEdit: true`, `!fieldEditor.allowsUndo` and `Self.textAfterUndo(fieldEditor) == "second"`, the lead's two lines; the 4 cases without a closed edit passed. Load 9.0 to 7.0 |
| M3 again | the fix undone, the test in MenuKeysTests | failed with the same 8 issues (:145 and :146 for each field). Load 7.0 to 6.7 |
| fix | ProtectedUndoTests and UndoOffEditingTests | passed 3 of 3. Load 8.4 to 9.3 |
| fix | MenuKeysTests (with the moved test), ProtectedUndoTests, UndoOffEditingTests | `Test run with 15 tests in 3 suites passed`. Load 5.9 to 5.7 |
| full, own suite | the 3 full runs before the move | APP-08.14 failed 3 of 3 (see above); APP-01.27 c failed 2 of 3. Load 5.6 to 10.2 |
| full, no closed edit | the fix, the 4 closed-edit cases taken out | 349 passed; then 348 passed with only APP-01.27 c failed. Load 10.0 to 6.2 |

**Full LarsalTests, final** (private copy with the shared Swift files: `diff -rq` of macos/Larsal and macos/LarsalTests showed no difference; `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, `-skip-testing:LarsalUITests`):

| Run | Result | Load (start, end) |
|---|---|---|
| 1 | `Test run with 349 tests in 51 suites passed after 200.486 seconds` | 8.41, 4.82 |
| 2 | `Test run with 349 tests in 51 suites passed after 199.603 seconds` | 4.82, 5.70 |
| 3 | 1 issue: only APP-01.27 c (`main.search == "o"`, LarsalSettingsEffectsTests.swift:73), the known timing test; alone it passed 3 of 3 (4.2 s each, load 5.34 to 5.13). APP-08.14 and the F-127 F-136 test passed | 5.70, 5.43 |

The count stays 349: the moved test is one test with 8 cases.

**2. Text corrected.** Section b above (the cause, the shapes tried, the round 1 fix), the comment in the test, and the F-136 row.

**Checks:** `swift format lint --strict --recursive macos` exit 0; swiftlint 0.65.1 `lint --strict --quiet` in macos/ exit 0; `scripts/check-names.sh`: `names: PASS (11525 files scanned, 16 vault files name-only)`. `scripts/check.sh` was not run. F-136's own steps need a visible window: Mac QA (W-08, the owner's go).

## Checker 1 re-check, round 2 (2026-10-30): passed

Role: Checker 1. I did not build this part. Private copy `/tmp/e13s6r-checker1-copy`, derived data `/tmp/e13s6r-checker1-dd`, its core a copy of the shared `target/larsal-core` (part r changes no Rust file). Offscreen, demo vaults. The Mac's Caps Lock was not touched; read only, it was up at 22:55 (`CGEventSource.flagsState`, combined and HID state: no `.maskAlphaShift`).

**F-136: fixed.**
- Code: `UndoOff.Probe` observes its window's `firstResponder` (block key-value observing; the observation holds the window weakly, so it keeps no window alive) and runs `set()` at once. `UndoOff` has one user, `ProtectedText`; `UndoOff.Probe` is also used by `UndoOffEditingTests`, which still tests the already-editing branch. The shown password field (F-069) has its own field editor (`NoCopyCell.fieldEditor(for:)`), so the shared editor cannot reach it.
- Mutant M-A (the observation removed): `MenuKeysTests/f127ProtectedStandardFieldKeepsNoUndo(_:afterClosedEdit:)` failed 3 of 3 with 8 issues each: for each field with `afterClosedEdit: true`, ProtectedUndoTests.swift:145 `!fieldEditor.allowsUndo` and :146 `Undo.textAfterUndo(fieldEditor) == "second"`. The 4 cases without the closed edit passed. Load 10.09 to 6.37.
- Mutant M-G (the test back in its own suite, `extension ProtectedUndoTests`, the fix kept): 2 full LarsalTests runs. Run 1: "APP-08.14: ↓ and ↑ in the search field move the list's selection" failed at MenuKeysTests.swift:143 `main.selection == ids[0]`; run 2: it passed. The F-127 F-136 test passed in both. The other issues were timing tests only (APP-01.27 c, FEA-01.34). Load 6.61 to 4.87. So the test needs MenuKeysTests' serialized group.

**Full LarsalTests with the fix** (the shared Swift files, `diff -rq` of macos/: no difference; `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, `-skip-testing:LarsalUITests`):

| Run | Result | Load (start, end) |
|---|---|---|
| 1 | 1 issue: "Parity dialogs-delete-forever" at ParityEditorPagesTests.swift:211 `main.sidebar?.bin == bin - 1` | 8.87, 5.26 |
| 2 | 1 issue: APP-01.27 c at LarsalSettingsEffectsTests.swift:73 `main.search == "o"` (timing test) | 5.26, 18.77 |
| 3 | 1 issue: "Parity dialogs-delete-forever", the same line | 18.77, 10.90 |
| 4 | `Test run with 349 tests in 51 suites passed after 198.866 seconds` | 4.08, 16.72 |

The F-127 F-136 test (8 cases), APP-08.14's search keys, AT-K06 (48 cases) and the F-135 test passed in all 4 runs. Alone: APP-01.27 c passed 3 of 3 (4.1 to 4.2 s, load 4.83 to 4.40); "dialogs-delete-forever" passed 3 of 3 alone (load 4.40 to 4.26), ParityEditorPagesTests 3 of 3 (16 tests, load 11.15 to 8.61), and ParityEditorPagesTests beside MenuKeysTests 2 of 2 (29 tests, load 8.61 to 8.77). That test is not part r's; part d's run (E13-S6d-fixes.md) saw the same line fail under load. It is for the lead.

**F-135:** AccessibilityWalkTests.swift, CapsLock.swift and UnlockView.swift were not changed in round 2; the walk and the F-135 test passed in all 4 full runs. (1) stays for the lead to accept.

**Text:** section b, the test comments and the F-136 row match the code and the runs. The F-127 row still names `ProtectedUndoTests f127ProtectedStandardFieldKeepsNoUndo`; its ID is now `MenuKeysTests/f127ProtectedStandardFieldKeepsNoUndo(_:afterClosedEdit:)` (not part r's row: for the lead).

**Checks:** `swift format lint --strict --recursive macos` exit 0; swiftlint 0.65.1 `lint --strict --quiet` in macos/ exit 0; `scripts/check-names.sh`: `names: PASS (11380 files scanned, 16 vault files name-only)`. The mutants were put back and `cmp` of the shared files against the copy showed no difference. `scripts/check.sh` was not run.

## Verify (2026-10-30): signed (2 re-tested)

Role: Verify. I did not find, build or check these fixes. I changed no product code. Private copy `/tmp/e13s6r-verify-copy` (`rsync -a --exclude /target --exclude /fuzz/target --exclude /larsal-shots`, 23:30), derived data `/tmp/e13s6r-verify-dd`, its core a copy of the shared `target/larsal-core` (part r changes no Rust file; `LarsalCore.swift` cmp equal). Tests ran with `TEST_RUNNER_HOME`, `TEST_RUNNER_LARSAL_TEST_INSTANCE_DIR` and `TEST_RUNNER_SSH_AUTH_SOCK` under /tmp; LarsalTests has no host app, so nothing showed on screen. Demo vaults only. The Mac's Caps Lock was read only (`CGEventSource.flagsState`, combined and HID state): up at 23:30, so not on as the brief said; it was never pressed, toggled or posted. My probes were one file, `VerifyE13S6rTests.swift`, in the copy only, removed before the full runs.

| # | Item | Result |
|---|---|---|
| a | F-135 (2): the walk no longer depends on the key; (1) accepted (LD-256) | re-tested, passed |
| b | F-127 Notes in the full run, cause F-136 | re-tested, passed |

**a. F-135.**
- Steps: the row's own step needs the key down, and the key was up, so the probe stands in for it. On the unlock screen with the fake up and down, the probe set the secure field editor's own Caps Lock bit by hand (`NSSecureTextView`, `_sdvFlags` `{?="_secureInput"b1"_capsLockDown"b1...}`), with no key and no event, then walked the screen.
- Before (mutant M1, the skip undone, copy only): AppKit listed `caps lock down at (572.0, 815.0, 36.0, 52.0) press=true`, and the walk gave `unlock: AXImage at (572.0, 815.0, 36.0, 52.0): clickable but not a control (caps lock down)` with the fake down and up, the lead's line. `f135SecureFieldCapsLockPicture()` failed at AccessibilityWalkTests.swift:142. Mutant M2 (the walk sets no `capsLockFake`): of 48 walk cases only "unlock", `capsLock: true` failed, `unlock: AXStaticText at (0.0, 0.0, 0.0, 0.0): the note is not the fake's`. Load 5.85 to 8.11.
- After (the shared files): the same picture was listed at the same frame, the walk reported nothing in both fake states, and Larsal's note showed only with the fake down (`note=true` / `note=false`). The picture is not listed with the bit clear. Load 7.23 to 6.82.
- (1): the picture's parent is `NSSecureTextFieldCell`; UnlockView.swift and CapsLock.swift are as before. Accepted by LD-256; I agree.

**b. F-127 (Notes) in the full run, F-136.**
- Steps: the row's own steps need a visible window (Mac QA, W-08). Offscreen: `-only-testing:"LarsalTests/MenuKeysTests/f127ProtectedStandardFieldKeepsNoUndo(_:afterClosedEdit:)"`, and a probe of my own with a window other than Settings: a plain SwiftUI text field in its own window, edited, then closed and freed in the middle of the edit (`closed == nil`), then the shown protected field takes the editor. The probe saw the same shared field editor object in both windows (`same editor=true`).
- Before (mutant, `UndoOff.Probe`'s `firstResponder` observation removed, copy only): the test failed with 8 issues, ProtectedUndoTests.swift:145 `!fieldEditor.allowsUndo` and :146 `Undo.textAfterUndo(fieldEditor) == "second"` for each field with `afterClosedEdit: true`; the 4 cases without the closed edit passed. My probe: `allowsUndo=true afterUndo=demo-protected-7Kq2` for Title, UserName, URL and Notes, so Undo brings the protected value back. UndoOffEditingTests still passed. Load 6.15 to 5.85.
- After (the shared files): the test passed 8 cases; my probe gave `allowsUndo=false afterUndo=second` for all four fields. Load 7.23 to 6.82.
- The grouping: the test is `extension MenuKeysTests`, whose suite is `@Suite(.serialized)` (LD-241 (1)); Checker 1's mutant M-G showed the clash with APP-08.14 without it. I did not repeat that mutant.

**Full LarsalTests** (the copy with the shared Swift files: `diff -rq` of macos/ no difference, `cmp` of AccessibilityWalkTests.swift, CapsLock.swift, EditorProtected.swift, ProtectedUndoTests.swift, MenuKeysTests.swift and UnlockView.swift equal; `build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `** TEST BUILD SUCCEEDED **`, then `test-without-building -skip-testing:LarsalUITests`):

| Run | Result | Load (start, end) |
|---|---|---|
| 1 | `Test run with 349 tests in 51 suites passed after 195.272 seconds` | 10.10, 3.69 |
| 2 | `Test run with 349 tests in 51 suites passed after 199.077 seconds` | 3.81, 2.90 |
| 3 | `Test run with 349 tests in 51 suites passed after 203.201 seconds` | 3.14, 3.81 |

In each run the F-127 F-136 test (8 cases), "APP-08.14: ↓ and ↑ in the search field move the list's selection", AT-K06 (48 cases) and the F-135 test passed.

**Checks (shared tree):** `swift format lint --strict --recursive macos` exit 0; swiftlint 0.65.1 `lint --strict --quiet` in macos/ exit 0; `scripts/check-names.sh` after my text edits: `names: PASS (11380 files scanned, 16 vault files name-only)`. `scripts/check.sh` was not run, and no test ran in the shared tree. Left for Mac QA (W-08): F-136's visible-window steps (close Settings in the middle of an edit, Show, type, ⌘Z).
