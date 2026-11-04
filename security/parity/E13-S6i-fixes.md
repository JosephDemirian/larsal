# E13-S6 part i: re-test of F-122, LD-228 (1), INT-05.32, F-125, F-127 and the F-083 test

Story: E13-S6 part i ([plan/epics.md](../../plan/epics.md)). Rows: [security/findings.md](../findings.md) F-122, F-125, F-127 (and F-083's test). Rulings: LD-227 (1) and (2), LD-228 (1) and (3), LD-230 (5), LD-232 (5), LD-237 (2), LD-239 (1); LD-199 (2) for the close.
Date: 2026-10-29 (the runs took place from 10:19 to 10:58 on 2026-10-30 by the Mac's clock). Role: Verify, round 1. I did not find, build or check these fixes.

| Item | Result | One line |
|---|---|---|
| F-122 (Medium) | **fixed, re-tested** | The row's own steps through the real Lock button: MSG-LOCK-DISCARD-EDIT shows and the vault stays unlocked; Cancel keeps the draft. With the question undone: 'dialog=nil locked=true', the row's 'before'. Cancel in an unchanged editor right after an outside save asks about the copy. Before: the copy was wiped. |
| LD-228 (1) | **fixed, re-tested** | Behind a 3 s save, Lock Everything returns in 11 µs and the quit returns `.terminateLater` in 27 µs. The main actor ticked 75 and 82 times during the saves. With the save back on the main actor it ticked once. |
| INT-05.32 (S-AT-06) | **fixed, re-tested** | T74 passes. My probes also cover a run that fails before typing (MI05-11), a run stopped after 3 keys, and save-first: the relock saved a change made while the picker showed. One gap: no product test covers the failed run (see Notes). |
| F-125 | **fixed, re-tested** | `open(O_EVTONLY)` on a FIFO was still blocked after 3.0 s. With `O_NONBLOCK` it returns in 0.000 s. With the FIFO at the vault path, folder changes still reach the watch, and so do writes to a real file put back there. |
| F-127 | **fixed, re-tested** | Protected Title, UserName, URL and Notes: the cell and the field editor keep no undo, and Undo does not bring back the earlier value. With the fix undone, 12 checks fail (3 per field kind). |
| F-083 test (LD-230 (5)) | **re-tested** | The direct restart check (an hour, then 200 ms) passed in all 3 runs: at load average 46, in the full run (77 s at load 15 to 25), and on the re-synced tree. With `screenChanged` emptied, all 4 cases fail. |

All 6 items re-tested and fixed. No new finding. Notes for the lead are at the end.

## Setup

- **Private copy.** `rsync -a --exclude target --exclude larsal-shots --exclude fuzz/target` to `/tmp/e13s6i-verify-copy` at 10:19. Its own Cargo target was `/tmp/e13s6i-verify-target` and its DerivedData `/tmp/e13s6i-verify-dd`. Tests ran with `TEST_RUNNER_LARSAL_TEST_INSTANCE_DIR=/tmp/e13s6i-verify-inst`, so test settings went to `/tmp`, never to `~/Library/Application Support/Larsal`. LarsalTests is a logic bundle with no host app, and `WindowRules` uses its inert calls under XCTest, so nothing opened on screen.
- **My probes:** `macos/LarsalTests/VerifyE13S6iTests.swift`, in the copy only. It has 4 tests: `verifyF122RowSteps`, `verifyLD228Timings`, `verifyInt0532` and `VerifyDiskWatchTests/verifyF125`. Each prints `VERIFY …` lines, which are quoted below.
- **Build:** `scripts/build-core.sh`: 'build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift'.
- **Run 1, part i suites plus probes.** `xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e13s6i-verify-dd test -only-testing:LarsalTests/{DataSafetyTests,ParitySavingTests,MenuBarIconTests,AutoTypeTests,DiskWatchTests,ProtectedUndoTests,WindowFixesMoreTests,VerifyDiskWatchTests} SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, at load average 46: 92 tests in 8 suites, 91 passed.
  - The one failure was part g's "F-101: a FIFO at the vault's path …" (SavingWatchTests.swift:195, no recovery folder yet). Run alone with `test-without-building`, it passed in 0.290 s. Part i did not change `lockAll()`'s automatic path or `saveBeforeLock`.
- **Full LarsalTests in the copy.** `… test -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: 337 tests in 47 suites, 335 passed. The 2 failures are load timing tests, not part i's:
  - "APP-01.27 c: a change of selected entry restarts …" took 33.3 s. Part g's Verify saw the same failure. It failed at log line 805, before the F-083 test started at line 999, so the F-083 test did not cause it.
  - "Parity editor-editor-entry: the Expires switch …" took 52.5 s.
  - Run alone, both passed (11.7 s and 8.8 s): 'Test run with 2 tests in 2 suites passed'.
- **Run 2, on the current tree.** At 10:54 I re-synced the copy to the tree, because parts k and m had since changed VaultEdits.swift (the new `.export` dialog case), Dialogs.swift and others. Then build-core and the same 8 suites again: '✔ Test run with 92 tests in 8 suites passed after 115.119 seconds', ** TEST SUCCEEDED **.
  - Part i's files are byte-identical between the first copy and the tree: MainWindowModel.swift, Saving.swift, AppDelegate.swift, AutoType.swift, Platform/DiskWatch.swift, Forms.swift, EditorProtected.swift, VaultModelParts.swift and the part i tests (`diff -rq`). VaultEdits.swift differs only by the `.export` case.
- **Lints (the tree).**
  - `swift format lint --strict` on the 8 part i source files and 5 test files: exit 0.
  - `swiftlint 0.65.1 lint --strict --quiet` in macos: exit 0.
  - `swift format lint --strict --recursive macos` fails only at macos/Larsal/ContextMenus.swift:23:1 (Indentation). That file belongs to part m (LD-239 (2)).
- **Mutants.** Made in the private copy only, each restored from a saved original. Independent mutants in separate areas were built together and run against their own tests: batch A (MA1 to MA4) and batch C (MA5, MA6). Each F-122 and LD-228 mutant (MB1 to MB6) ran alone.

## F-122: a manual lock, quit or close with editor edits or a changed copy asks first

**Steps (the row's own, demo vault Personal, `DataSafetyTests.window`: no autosave, no folder watch):**
1. Edit Wise's title in the editor. Press the toolbar's **Lock** button: the real button, found by its accessibility label and pressed offscreen.
2. Press Cancel. Close the vault. Send a quit signal (`quitReply(asks: false)`), then the user's quit (`quitReply(asks: true)`). Lock again and press Discard.
3. In a second window, attach `codes.txt` to Wise, save, open the editor and open the attachment. The fake opener records the copy. Write "outside edit" into the copy, then lock.
4. Cancel. Write the copy again, then at once press Cancel in the unchanged editor. Then the user's quit. Then an automatic lock (`lockAll()`).

**Before** (MB1: `askLock` never asks, the code before the fix): 'VERIFY F122-1 lockButton=true dialog=nil locked=true text=false'. The vault locked with no question, as in the row. Before for step 4 (MB2: `cancelEditor` without `askChangedCopy`): 'VERIFY F122-2 cancelEditor dialog=nil editor=false copyExists=false'. The copy was wiped with no question.

**After:**
- 'VERIFY F122-1 lockButton=true dialog=Optional(…lockDiscardEdit) locked=false text=true'. The sheet's text "Lock now and lose your unsaved edits?" is on screen.
- 'VERIFY F122-1 cancel dialog=nil editor=true title=Wise (verify edit) locked=false'. Cancel keeps the vault unlocked and the draft as typed.
- 'VERIFY F122-1 close dialog=Optional(…leaveEditor)'. The close asks LD-199 (2)'s question (Save, Discard, Cancel).
- 'VERIFY F122-1 quitSignal reply=…(rawValue: 1) dialog=nil'. A quit signal never asks (APP-02.16): `.terminateNow`.
- 'VERIFY F122-1 userQuit reply=…(rawValue: 0) dialog=Optional(…lockDiscardEdit)'. The user's quit asks and stops: `.terminateCancel`.
- 'VERIFY F122-1 discard locked=true'.
- 'VERIFY F122-2 lock dialog=Optional(…lockDiscardEdit) locked=false copyExists=true'.
- 'VERIFY F122-2 cancelEditor dialog=Optional(…changedAttachment(name: "codes.txt")) editor=true copyExists=true'. The 0.5 s gap is closed.
- 'VERIFY F122-2 userQuit reply=…(rawValue: 0) dialog=Optional(…lockDiscardEdit)'. A changed copy alone stops the quit too.
- 'VERIFY F122-2 autoLock dialog=nil locked=true copyExists=false'. The automatic lock drops both by design (APP-02.16, LD-227 (1)).

**Product tests (run 1 and run 2, all passed):**
- DataSafetyTests `f122ManualLockAsksAboutEditorEdits` (1.900 s), `f122ChangedCopyAsksBeforeCancelAndLock` (4.183 s) and `f122QuitAndLockEverythingAsk` (0.931 s).
- ParitySavingTests `f122EditDuringLockOrCloseSaveAsks` (22.186 s) and `f122DiscardUnsavedThenEditorAsks` (0.250 s).
- MenuBarIconTests `f122AsksInFront` (4.885 s).

**Mutants (each caught):**

| Mutant | Caught by |
|---|---|
| MB1 `askLock`: `guard false` (step 7 never asks) | 6 of 6 tests fail: LockLeaveTests.swift:34, :36, :70, :85, :86, :90, :220, :252, :253, :267, plus my probe at :37 |
| MB2 `cancelEditor`: no `askChangedCopy()` | LockLeaveTests.swift:67 (Cancel asks first), :70, :71; probe :90 |
| MB3 `lockAll(asks: true)`: no `askEditors` | LockLeaveTests.swift:90, :160, :252, :253, :267 |
| MB4 `quitReply`: no `askEditors` | LockLeaveTests.swift:85, :86, :148 |
| MB6 the automatic lock asks step 7 (against APP-02.16) | LockLeaveTests.swift:49 ('locked(model, id) && again.dialog == nil'); probe :103 |

The builder's and Checker 1's mutants on `lockNow`, `closeNow` and saveAll's Discard path were not repeated. MB1 covers the shared question that all of them reach.

**Callers read:** every manual lock goes through `lock(_:)`, then `lockNow`:
- the Lock button (VaultView.swift:116), the vault menu (Menus.swift:38) and the Lock menu item (LarsalCommandsVault.swift:12);
- the key change prompt;
- the Auto-Type relock (AppDelegate.swift:60).

Lock Everything (Menus.swift:41, LarsalCommandsVault.swift:15, MenuBarIcon.swift:179) calls `lockAll(asks: true)`. The automatic locks (LockSignals, the channel's WindowEvents) call `lockAll()`, which never asks.

## LD-228 (1): Lock Everything and the quit save off the main thread

**Steps:** `ParitySavingTests.slowSaves`: Personal saved on lock only, with a 3 s key derivation, so each save takes about 3 s. I added "Verify Shop" and started a main-actor ticker (one tick per 50 ms). Then the menu's Lock Everything (`lockAll(asks: true)`). Then I unlocked, added "Verify Quit Shop" and made the user's quit (`quitReply(asks: true)`).

**After:**
- 'VERIFY LD228-LOCK returned=1.0709e-05 seconds total=4.119926209 seconds mainTicksDuringSave=75 locked=true onDisk=true'
- 'VERIFY LD228-QUIT reply=NSApplicationTerminateReply(rawValue: 2) returned=2.6667e-05 seconds total=4.405414875 seconds mainTicksDuringSave=82 replies=[true] onDisk=true'

Both calls return at once. The main actor keeps running for the whole save. The vault locks, or the quit replies `true`, only after the change is on disk. A fresh reader then finds "Verify Shop" and "Verify Quit Shop".

**Before** (MB5: saveAll saves on the main actor, `(try? session.save(vault: id))` with no `Task.detached`):
- 'VERIFY LD228-LOCK … total=3.881118541 seconds mainTicksDuringSave=1'
- 'VERIFY LD228-QUIT … total=3.198909375 seconds mainTicksDuringSave=1'

The window was frozen for the whole save. Part g measured 3.86 s for the original synchronous Lock Everything.

**Product test:** ParitySavingTests `ld228SavesLeaveTheMainThreadFree` passed (22.542 s). MB5 fails it at LockLeaveTests.swift:146 ('replies.isEmpty': the quit's save ran on the main thread) and :158 (Lock Everything's).

**Not proven offscreen:** AppKit's own `terminateLater` wait in a real quit. The model returns `.terminateLater` and calls `reply(toApplicationShouldTerminate:)` through AppDelegate.swift:117. Swift's main actor runs on the main queue, which AppKit keeps serving while it waits for the reply. A real ⌘Q behind a slow save needs Mac QA (W-08).

## INT-05.32: lock again after Auto-Type (S-AT-06)

**Steps (fakes only: FakeHotKeys, FakeWindows, the inline runner):**
1. Personal with an extra entry "GitHub (bad)" whose window rule types `{USERNAME` (MI05-11). Save it, lock it, and turn S-AT-06 on.
2. The shortcut, then unlock in the panel. Choose the bad row: the run fails before typing.
3. A new run whose front window changes after 3 keys: typing stops.
4. With saving on lock only, and the app's wiring (`refreshed = window.refresh`, `relock = window.lock`): unlock in the panel, add an entry while the picker shows, then type.

**After:**
- 'VERIFY T74-FAIL stopped=1 lines=["Auto-Type failed: MI05-11"] relocked=[1] locked=true'
- 'VERIFY T74-STOP lines=["Auto-Type stopped: window-changed after 3 keys"] relocked=[1, 1] locked=true'
- 'VERIFY T74-SAVE relocked=[1, 1, 1] locked=true savedOnDisk=true'. The relock went through MainWindowModel's lock, so step 8 saved first (LD-232 (5)).

**Product test:** AutoTypeTests `t74LockAgainAfterAutoType` passed (2.159 s). It covers typed (locked after the last key), Escape (locked at once, nothing typed), a vault that was already unlocked (stays unlocked) and S-AT-06 off.

**Mutants:**

| Mutant | Caught by |
|---|---|
| MA4 `ended()` never calls `relock` | AutoTypeRelockTests.swift:41; probe :198 |
| MA5 the picker closed untyped does not call `ended()` | AutoTypeRelockTests.swift:47 ('locked, nothing typed'), :49, :52, :58 |
| MA6 `failed()` does not call `ended()` | **only my probe** ('VERIFY T74-FAIL stopped=1 … relocked=[] locked=false', :198). T74 has no failed-run case. |

**Code read:** AppDelegate.swift:59-60 sets `refreshed = window.refresh()` and `relock = window.lock($0)`. A hidden launch registers no shortcut and makes no AutoType (rule 10).

## F-125: DiskWatch opens without blocking

**Steps (syscall level):** `mkfifo /tmp/e13s6i-verify-fifo/vault.larsalvault`, then `os.open(path, O_EVTONLY)` and `os.open(path, O_EVTONLY | O_NONBLOCK)` from `python3 -I`, using O_EVTONLY = 0x8000 from the SDK's sys/fcntl.h. Each runs as a child that is stopped by its own PID after 3 s.

- **Before:** 'block: open still blocked after 3.0 s (stopping my PID 2083)'.
- **After:** 'nonblock: open returned fd>=0 after 0.000 s'. On a real file: 'nonblock: open returned fd>=0 after 0.000 s'.

**Steps (DiskWatch):** a FIFO at the watched vault path. Then the FIFO is removed and a real file is written in its place. Then an in-place append to that file.
- **After:** 'VERIFY F125 init=4.9666e-05 seconds looksAfterFilePutBack=1 looksAfterInPlaceWrite=1'. The watch was never held, it followed the real file once it was back, and it saw in-place writes.

**Product test:** DiskWatchTests `f125FifoDoesNotHoldTheWatch` passed (4.903 s).

**Mutant MA1** (`open(path, O_EVTONLY)`): fails DiskWatchTests.swift:25 ('seen > 0') and my probe at :283.

## F-127: no undo copies of protected editor fields

**Steps:** these are the product tests, offscreen (Screen's borderless window at -20 000, never ordered front). Open the editor and set the field to a demo secret. Show it as Rust does for a protected field (the flag and no value, then Show). Then:
- check the AppKit cell of the shown field and of an unprotected neighbour;
- start editing as a click does (`makeFirstResponder` in the hidden window);
- type over the value with a private undo manager, then undo once.

**After:** ProtectedUndoTests passed in run 1 and run 2:
- `f127ProtectedStandardFieldKeepsNoUndo`, 4 cases (Title, UserName, URL, Notes), 16.901 s. The shown cell's `allowsUndo` is false and the neighbour's is true. The field editor's `allowsUndo` is false. Undo leaves "second", so the earlier value is not kept.
- `f127ProtectedCustomFieldIsNeverEdited`, 11.217 s. A shown protected custom value is drawn as text, and no NSTextField holds it.

**Mutant MA2** (`field.cell?.allowsUndo = true`): 12 issues, 3 per field kind, at ProtectedUndoTests.swift:55 (cell), :61 (field editor) and :62 (the earlier text comes back). The custom field test still passes, as expected: there is no text field to fix.

**Not covered by a test:** UndoOff's branch for a field already being edited when its value turns protected (`currentEditor()`, `breakUndoCoalescing`, then undo off). Low: it needs a vault-wide protection flag to change during typing.

## F-083 test made robust under load (LD-230 (5))

**Design (WindowFixesMoreTests `f083ScreenChangeRestarts`, 4 cases):** the countdown started at the focus loss reads a one-hour minute. The restart reads 200 ms. So only a restart, from the editor or the reports opening or closing, can clear the search within the test's 30 s. That holds at any load. The reports screen is covered (2 of the 4 cases).

**After:** passed in run 1 (13.881 s, load average 46), in the full run (77.195 s) and in run 2.

**Mutant MA3** (`screenChanged` emptied, in VaultModelParts.swift): all 4 cases fail at WindowFixesMoreTests.swift:154 ('main.search.isEmpty').

## Needs Mac QA (owner's go, W-08)

- A real ⌘Q and Lock Everything behind a slow save, with the window visible: the window stays live and the quit ends after the save.
- A real manual lock or Close Vault with an edit made in the visible window during the save.
- The S-AT-06 relock after a real Auto-Type into another app.

## Notes for the lead (none blocks the sign-off)

1. **INT-05.32 test gap.** No product test covers the relock after a failed run (MA6 survives the product suite). My probe proves the behaviour. T74 as written in the card has only the typed and Escape rows. Suggestion: add the probe's MI05-11 case and the stopped-run case to `t74LockAgainAfterAutoType` (fakes only, about 15 lines).
2. **Shared test minute.** `SearchClearTimer.minute` is one static. WindowFixesMoreTests (F-083) and LarsalSettingsEffectsTests (APP-01.27 a to c) both set it, from suites that run side by side. In this run, APP-01.27 c failed before the F-083 test began, so it was load, not the shared static. An overlap could still make either test flaky. A `.serialized` parent suite or a per-timer minute would remove that.
3. **Close question.** Close keeps LD-199 (2)'s Save, Discard and Cancel question rather than MSG-LOCK-DISCARD-EDIT. It asks first and Cancel keeps the vault open, which meets LD-227 (2). I accepted it as built under LD-199 (2).
4. **Cancel as default.** APP-02.15 step 7 says Cancel is the default button. In the sheet, Cancel has `.cancelAction` (Escape) and Discard has no key, so Return does nothing. That is data-safe; a Return key on Cancel would match the card's words exactly. Low; it is the house pattern of the other danger sheets.
