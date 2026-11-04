# E13-S6 part o: F-131 and two test fixes (Builder, 2026-10-30)

Story: E13-S6 part o ([plan/epics.md](../../plan/epics.md)). Rulings: LD-249 (3) and (4), LD-241 (1). Row: F-131 (Low) in [security/findings.md](../findings.md). Role: Builder. I did not find these problems. Earlier builder attempts left edits in the four Swift files below; I read them, kept what held and changed what did not (each change is named in its section).

| # | Item | Result | Test |
|---|---|---|---|
| a | F-131: a window AppKit makes lists sharing state 1 before the run loop pass adopts it | fixed (residual for the lead, below) | `ScreenProtectionTests/f131AdoptedWhenNumbered()`, `ScreenProtectionTests/f131OwnWindowDeferred()`, `ScreenProtectionTests/f131HiddenLaunchListings()` |
| b | PlatformTests APP-09.27-a, -b: a slow run overruns the 60 s limit and the whole test process restarts | fixed (test) | `PlatformTests/Signals/quitSignals()` |
| c | CopySelectionTests: Cut (Command-X) loses the focus to another suite under load | fixed (test) | `CopySelectionTests/notesSelection()` |

Files: `macos/App/Platform/ScreenProtection.swift`, `macos/AppTests/ScreenProtectionLaunchTests.swift` (new), `macos/AppTests/PlatformTests.swift` (APP-09.27 only), `macos/AppTests/CopySelectionTests.swift`.

## a. F-131

**Checker 1 sent part o back (3 findings), 2026-10-30.** All three are fixed below. (1) The first launch test read App's windows from the test process. The window server reports sharing state 0 for every window of another process when the reader has no screen capture access, so that test could not fail. (2) With the fix, App's own listing still showed sharing 1 at 0 x 0 for a short time. (3) The first test read the arguments and environment of every process that owns a window. **Correction:** the first build said that "the window server published the window only after the pass" (14 of 14 probe launches) and that "every test run listed sharing 0 from the first listing". Both were wrong: they came from masked reads.

**Cause.** `ScreenProtection` reached a window that AppKit or SwiftUI makes for App only on the next pass of the main run loop. The window server makes each window with sharing state 1. AppKit numbers it inside `NSWindow.init`, and App changed the type only later. This held for `TUINSWindow` (the text input window that the focused unlock field brings) and also for App's own snapshot window from `window(_:style:)`, which was made with `defer: false`.

**Fix.**
1. `ScreenProtection.window(_:style:)` makes App's own windows **deferred** (`defer: true`, the default in Interface Builder). The window server makes no window for one until it is needed (ordered in), and the type is already set when it does. In a hidden launch, the snapshot window got no window server window in 7 of 7 launches by hand and in 3 of 3 runs of the final test, and the snapshot was still written (it draws through `cacheDisplay`). The callers are Settings, the New Vault and Vault Settings windows, and the debug snapshot. None reads `windowNumber` before it orders the window in. The full AppTests run passed (below).
2. `ScreenProtection.start` observes `_NSWindowDidChangeWindowNumber`, which AppKit posts inside each window's init once the window server has numbered it. It adopts a window AppKit or SwiftUI makes there, before its init returns. The notice is not in AppKit's headers, so the run loop pass and the sheet and popover notices stay as the net. One posted off the main thread is left to the pass.
3. Debug builds only: `WindowListing` (in `ScreenProtection.swift`, which the test target also compiles). In a hidden launch with `APP_TEST_WINDOW_LISTING=1`, `start` begins a background thread before the first window. The thread reads `CGWindowListCopyWindowInfo([.optionAll])` again and again, with a 0.5 ms pause between reads (one read takes about 1.5 to 2.6 ms here, median; Verify text fix), keeps App's own PID, and appends each change to `window-listing.txt` in `APP_TEST_INSTANCE_DIR`. Its first line is `pid <n>, windows <count>`. Each later line has a window number, sharing state, size and on screen. It records metadata only, never pixels or names.

**Residual, for the lead.** No public hook comes before the window server makes a window. So a window AppKit or SwiftUI makes lists sharing 1 at 0 x 0 from the moment the window server makes it until AppKit's notice inside its init. The recorder saw that state in one read each time, so it lasted less than about two reads (one read takes about 1.5 to 2.6 ms here, median; Verify text fix, replacing "less than one 0.5 ms poll"). That covers the text input window here, and the main window, alerts and menus in a normal launch. It then lists sharing 0 before it has a size. With the fix, the text input window showed `sharing 1, [0, 0]` in 2 of 7 hidden launches. It never had a size or content while at 1, and it was never on screen. An offscreen probe (a script, never ordered in) found the same for a deferred window: when AppKit makes its window server window (here forced through `windowRef`), it lists `sharing 1, [0, 0]` and then `sharing 0` before any size. The order-in path needs a visible window, so it is Mac QA (W-08). The two Auto-Type panels (the picker and the unlock panel, in `AutoTypePicker.swift`, which is not this part's file) are made with `defer: false`. The notice adopts them inside their init, so they have the same residual. Making them deferred is a one-word change in each, for that file's owner. The other way, swizzling `NSWindow`'s initializer, would still come after the window server makes the window.

**Tests.**
- `f131AdoptedWhenNumbered()`: protection is started on a private center, and AppKit's notice is forwarded to it only while one `NSWindow(defer: false)` is made. The test expects the window to be numbered and `sharingType == .none` right after init.
- `f131OwnWindowDeferred()` (new): a window from `window(_:style:)` has `windowNumber <= 0` and `sharingType == .none`.
- `f131HiddenLaunchListings()` (rewritten): `open -n -g -j` with `APP_TEST_HIDDEN=1`, `APP_TEST_WINDOW_LISTING=1`, and `APP_TEST_INSTANCE_DIR` and `HOME` in a throwaway folder under /tmp, plus a copy of `testdata/option-a-personal.appvault` and the debug snapshot. The snapshot draws the main view in a window that is never ordered in and focuses the unlock field, so AppKit makes its text input window. The test reads App's listing file. It fails in these cases:
  - the listing did not start with 0 windows;
  - App's own window (the snapshot's, 1320 x 820) appears in the listing at all;
  - any window lists sharing other than 0 with a size other than 0 x 0;
  - any window lists on screen;
  - no window is listed;
  - the snapshot was not written.

  App reports its own PID in the file. If App is still running after the wait, the test checks that PID's executable path (`proc_pidpath`, compared with the built `App.app/Contents/MacOS/App`, symlinks resolved) before it stops that PID. It reads no other process's arguments or environment, which fixes Checker 1's item 3. The test is `@concurrent`, so the other suites cannot hold its wait on the main actor.

**Mutant proof (private copy `/tmp/e13s6o-builder-copy`, its own `-derivedDataPath`).**

| Mutant | What is undone | Result |
|---|---|---|
| A2 | the notice observer (it watches a name that is never posted) and the run loop pass | `f131HiddenLaunchListings` failed 3 of 3 with the final test file, and 3 of 3 before the last change to the test: `window 3812 capturable with a size: ["sharing 1, [0, 0], on screen false", "sharing 1, [500, 500], on screen false"]`. `f131AdoptedWhenNumbered` failed 3 of 3. Load 5.1 to 5.6 |
| D | `defer: false` in `window(_:style:)` (item 2 undone) | `f131OwnWindowDeferred` failed 7 of 7 (`window.windowNumber <= 0`). `f131HiddenLaunchListings` failed 3 of 3 with the final test file: `App's own window 3819 is in the window server, so it can list sharing 1: ["sharing 1, [0, 0], ...", "sharing 0, [0, 0], ...", "sharing 0, [1320, 820], ..."]`. Load 6.3 to 16. Before the last change, the test failed only on a sharing 1 line of App's own window, and it caught D in 6 of 10 runs. That is why it now fails on App's own window being listed at all |
| none | the fix | 3 tests passed in 3 of 3 runs (load 5.2 to 5.6). Also 3 of 3 runs before the last change (load 5.1 to 5.3) |

Hidden launches of the fixed App, read by hand from the listing file (load 5.6 to 9.0): the snapshot window was never listed in 7 of 7. The text input window listed `sharing 0` from its first entry in 5 of 7, and `sharing 1, [0, 0]` then `sharing 0, [0, 0]` then `sharing 0, [500, 500]` in 2 of 7. No window was ever on screen.

## b. PlatformTests APP-09.27-a, -b

**Cause.** The test sends SIGHUP, SIGINT, SIGTERM and SIGQUIT to its own process and waits for `QuitSignals`' dispatch sources, which answer on the main queue. Under load the other suites keep the main actor busy. The old test waited without a bound, on the main actor, and set the default actions back in a `defer`. When the wait passed the 60 s limit, Xcode ended the test process ("Restarting after unexpected exit, crash, or test timeout"), and the results of every suite still running in that process were lost (E5-S11, E6-S5 and E13-S1 notes).

**Fix.** The test is in its own nested suite, `PlatformTests.Signals`, marked `nonisolated`, and the test is `@concurrent`. Only `install` and the read of `quitting` go to the main actor. The wait, and the end of the test, run off the main actor, so the test ends itself 40 s after it starts waiting. Each signal is sent while all four are ignored, after the previous one was seen or the bound has passed. The default actions come back only once every signal sent was seen, so a signal still on its way finds them ignored and cannot end the process. A cancelled wait throws and leaves the signals ignored.
- Kept from the earlier attempt: the 40 s bound and the "back only once all were seen" rule.
- Changed: `try await` in place of `try?` (a cancelled test no longer spins until the bound), and the nested `nonisolated` suite. With the bound but still on the main actor, the starved run below still overran the limit and restarted: the test had stopped waiting at 40 s, but its end waited for the main actor.

**Mutant proof (private copy).** Both runs used the same injected load: the main queue was blocked for 70 s, from just before the first signal. Each run had ScreenProtectionTests, PlatformTests and CopySelectionTests side by side.
- Mutant B (the old shape: on the main actor, an `AsyncStream` wait with no bound, defaults back in a `defer`): `Time limit was exceeded: 60.000 seconds`, then `Restarting after unexpected exit, crash, or test timeout`. The first process reported none of the other 18 tests, and the restart ran 0 tests. Load 29 to 12.
- The fix with the same block: the signal test failed by itself after 46.3 s (3 expectations: the sources had not answered yet). There was no time-limit issue and no restart. All 19 tests in 4 suites reported, and ScreenProtectionTests and CopySelectionTests passed. Load 11 to 34.
- No injection: passed in every run below.

## c. CopySelectionTests Cut (Command-X)

**Cause.** Suites run side by side on the main actor. The test copies, then waits about 1 s for the clipboard countdown. Other suites run in that wait, and each main window they draw attaches itself to `WindowRules` (`WindowChromeView`). The Notes field can also lose its focus. Cut then saw another window as App's main window, or no focused field. `vaultSelection` said no, the plain AppKit cut ran, and the test failed (2 of 4 runs under load in part n's notes).

**Fix (LD-241 (1), restore before the await).** `inFront` sets everything up again right before each synchronous command: the key window override, the attached main window, the focus in the Notes field and the selection. Right after the command it puts back the key window override and the window that was attached before. Nothing of this test is left set across an await, and nothing set by another suite is trusted after one.
- Kept from the earlier attempt: `inFront` with the key window, attach, focus and selection.
- Added: the window that was attached before is put back after the command, so this test leaves no change for the other suites across its await.

**Mutant proof (private copy).** Both runs used the same injected clash, put in the countdown wait: another window attaches to `WindowRules`, and the Notes field loses the focus. This is what another suite does in that wait.
- Mutant C (only the key window override is set and restored around each command, as before the batch; no attach, no new focus): failed with 2 issues, `board.string(forType: .string) == "demo-note-41"` and `text.string == "keep  here"`. Load 27 to 23.
- The fix with the same clash: passed.

## Runs under parallel load

First build (private copy, the same four files): 3 runs of the nine suites below side by side, at load 13.55 to 18.36. The four part o tests passed 3 of 3. Run 1 had a FEA-01.34 timing failure, which passed when re-run alone. The full AppTests run had 347 tests, with 1 timing issue (APP-01.27 c, passed alone).

After Checker 1 (this round):
- Full AppTests in the private copy with the fix (`test-without-building -skip-testing:AppUITests`, built with warnings as errors): **Test run with 348 tests in 51 suites passed**, no restart. Load 8.53 to 6.04. So the deferred windows break no other test.
- Shared tree, the nine suites side by side (ScreenProtectionTests, PlatformTests, CopySelectionTests, MenuKeysTests, MenuKeysMoreTests, MenuBarTests, ScreenTests, ParityTests, HygieneFixesTests): **Test run with 60 tests in 7 suites passed** in 3 of 3 runs. The loads were 24.26 to 18.09 (with build), 16.24 to 13.07, and 13.07 to 11.16.

## Shared tree

- `CARGO_TARGET_DIR=/tmp/e13s6o-builder-target scripts/build-core.sh`: exit 0, `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift` (load 15.09 to 27.75).
- `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e13s6o-builder-dd-shared test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, with `-only-testing:` for the nine suites above: **Test run with 60 tests in 7 suites passed**, TEST SUCCEEDED.
- `swift format lint --strict --recursive macos`: exit 0. `swiftlint lint --strict --quiet` in macos/: exit 0. `scripts/check-names.sh`: `names: PASS`.
- The four Swift files in the private copy are byte-identical to the shared tree (`cmp`). No mutant was ever written in the shared tree.

## Clean-up

First build: every App launched by its runs was mine and ended by itself after its snapshot. Three early probe launches without the snapshot were stopped with TERM by their PIDs (77201, 78490, 80735), all found by their bundle path in my private derived data folder.

This round: every App launch (7 by hand, the rest through the tests) ended by itself after its snapshot; none had to be stopped. The offscreen probe script ordered no window in and ended by itself. No process of mine is running. My /tmp folders (`e13s6o-builder-copy`, `-target`, `-dd`, `-dd-shared`, `-probe`) are deleted. The general pasteboard was never read or written.

## Verify (2026-10-30, round 1)

Role: Verify. I did not find, build or check these fixes. I read AGENTS.md, plan/team.md, the F-131 and F-081 rows, LD-241, LD-249, LD-250, LD-251 and this file. No product code changed. Everything ran in a private copy (`/tmp/e13s6o-verify-copy`, `CARGO_TARGET_DIR=/tmp/e13s6o-verify-target`, `-derivedDataPath /tmp/e13s6o-verify-dd`), built with `scripts/build-core.sh` (exit 0) and `xcodebuild ... build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` (TEST BUILD SUCCEEDED). Each run: `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e13s6o-verify-dd test-without-building -skip-testing:AppUITests -only-testing:<tests>`. Each mutant was written in the copy only, rebuilt, run, and put back from my saved copy of the file.

| # | Item | Result |
|---|---|---|
| a | F-131 | fixed, re-tested (residual for the lead) |
| b | PlatformTests APP-09.27-a, -b | fixed, re-tested |
| c | CopySelectionTests Cut (Command-X) | fixed, re-tested |
| F-081 | copy of selected text (LD-251 (1)) | fixed, re-tested |

### a. F-131

**Steps.** The row's steps, with the reader moved into App (a reader in another process sees sharing 0 for every window): `open -n -g -j --env APP_TEST_HIDDEN=1 --env APP_TEST_INSTANCE_DIR=<d> --env HOME=<d> --env APP_DEBUG_SNAPSHOT=<d>/shot.png --env APP_TEST_WINDOW_LISTING=1 App.app --args <d>/v.appvault`, with `<d>` a new folder under /tmp and a copy of `testdata/option-a-personal.appvault`; then read `<d>/window-listing.txt` (metadata only). Plus the three F-131 tests, 3 runs per state.

**Before.** The code before part o put back (the notice observer watches a name that is never posted; `defer: false` in `window(_:style:)`): all three tests failed in 3 of 3 runs, at ScreenProtectionLaunchTests.swift:25 (`window.sharingType == .none`), :31 (`window.windowNumber <= 0`) and :100 (`!own`). Load 18.3 to 22.5. In 3 launches by hand, App's own snapshot window was in the window server (`sharing 1, [0, 0]`, later `sharing 0, [1320, 820]`), and the text input window listed `sharing 1, [0, 0]` then `sharing 0`.

**After.**

| Run | Result |
|---|---|
| Fix, the 3 tests | `Test run with 3 tests in 1 suite passed`, 3 of 3 (load 11.2 to 14.6) |
| Fix, 10 launches by hand (load 20.5 to 23.7) | each listing started `windows 0`; the snapshot window was never listed; the text input window listed `sharing 1, [0, 0], on screen false` in one entry in 5 of 10, then `sharing 0, [0, 0]` and `sharing 0, [500, 500]`; it listed `sharing 0` from its first entry in the other 5; never on screen; snapshot 2640 x 1640 each time; every App ended by itself |
| Mutant: observer and run loop pass both off | the launch test failed 3 of 3 at :102 (`line.hasPrefix("sharing 1, [0, 0],")`), `f131AdoptedWhenNumbered` failed 3 of 3 at :25; a launch listed `sharing 1, [500, 500]`, so App's own reader sees the true state (load 16.9 to 20.9) |
| Mutant: only the run loop pass off (the notice alone) | 3 of 3 passed; 3 launches: `sharing 0` from the first entry in 2, `sharing 1, [0, 0]` then `sharing 0` before any size in 1 (load 13.7 to 15.1). So the notice alone protects the text input window before it has a size |

One window list read, timed by a script (200 reads, 0.5 ms pause, metadata only, nothing kept), load 19.5: median 1.5 and 2.6 ms in two runs, 90th percentile 5.1 and 7.7 ms, worst 28 ms. So the recorder reads about every 2 to 3 ms, not every 0.5 ms, as Checker 1 said. The sharing 1 state was always seen in one read, so it lasted less than about two reads.

**Text fixes made here** (Checker 1's note): in this file, fix item 3 and the residual paragraph; in the F-131 row, "every 0.5 ms" and "for less than one 0.5 ms poll". The doc comment in `ScreenProtection.swift` (lines 121 to 122, "every 0.5 ms") is product code, so I left it for the builder. Not re-run by me: the builder's offscreen probe of a deferred window's late window server window, and the order-in path (Mac QA, W-08).

**Proof result.** F-131 fixed, re-tested. App's own windows never reach the window server before they are protected, and a window AppKit makes is protected inside its init. The residual (a window AppKit makes lists sharing 1 at 0 x 0 for a moment, with no size, no content, never on screen) stays for the lead to accept.

### b. PlatformTests APP-09.27-a, -b

**Steps.** ScreenProtectionTests, PlatformTests and CopySelectionTests side by side, with the main queue blocked for 70 s from just before the first quit signal (`DispatchQueue.main.async { sleep(70) }`, copy only).

**Before.** The old shape (on the main actor, an `AsyncStream` wait with no bound, the defaults back in a `defer`) with the same block: `Time limit was exceeded: 60.000 seconds`, then `Restarting after unexpected exit, crash, or test timeout`; the first process reported no suite result, and the restart ran `0 tests`. Load 5.8 to 3.7.

**After.** The fix with the same block: the signal test failed by itself after 43.7 s with 3 issues (PlatformTests.swift:53, the sources had not answered yet), no time limit issue, no restart: `Test run with 20 tests in 4 suites failed after 73.741 seconds with 3 issues`, and ScreenProtectionTests and CopySelectionTests passed. Load 10.9 to 6.2. Without the block: passed in every run below.

### c. CopySelectionTests Cut (Command-X)

**Steps.** `CopySelectionTests` alone, with a clash put into the countdown wait (copy only): another window attaches to `WindowRules`, and the Notes field loses its focus. This is what another suite does in that wait.

**Before.** The old shape (only the key window override set and put back around each command; no attach, no new focus): failed 3 of 3 at CopySelectionTests.swift:72 (`board.string(forType: .string) == "demo-note-41"`) and :73 (`text.string == "keep  here"`). Load 3.3 to 13.6.

**After.** The fix with the same clash: `Test run with 1 test in 1 suite passed`, 3 of 3. Load 3.9 to 4.0.

### F-081 (LD-251 (1))

**Steps.** The row's steps as `CopySelectionTests/notesSelection()` does them offscreen: an editor with unprotected Notes, part of the notes selected, Edit > Copy (`copyCommand`, Command-C), then Edit > Cut (`textCommand`, Command-X), on the session's private named pasteboard. AppCommands.swift binds Copy to `copyCommand()` and Cut to `textCommand(cut)`. Plus a probe test, in the copy only: `copySelection("demo-note-41")` with a 30 s countdown, checked on the private pasteboard, then `lockAll()`; again with `clearClipboard()`, which quit calls.

**Before.** The plain AppKit copy and cut put back (`copyCommand` without `vaultSelection`, `textCommand` without the Cut branch): failed 3 of 3 with 8 issues each: :58 and :71 AppKit's copy and cut ran (the spy records them and never runs them, so the general pasteboard was not written), :59 no "Copied." notice, :61 and :72 nothing on the private pasteboard, :63 no concealed or transient marker, :73 the text not cut, :74 the private pasteboard never written. Load 24 to 30.

**After.** `CopySelectionTests` and the probe: `Test run with 2 tests in 2 suites passed`, 3 of 3 (load 21.3 to 35.1). So the copy has the markers and the countdown clears it, Cut copies the same way, and lock and quit each clear it.

**Proof result.** F-081 fixed, re-tested. The key press in a visible window is Mac QA (W-08).

### Runs under parallel load (the fix, private copy)

- The nine suites side by side (ScreenProtectionTests, PlatformTests, CopySelectionTests, MenuKeysTests, MenuKeysMoreTests, MenuBarTests, ScreenTests, ParityTests, HygieneFixesTests): `Test run with 60 tests in 7 suites passed`, 3 of 3. Load 16.9 to 13.4, 13.4 to 10.3, 10.3 to 10.8.
- Full AppTests (`test-without-building -skip-testing:AppUITests`): `Test run with 348 tests in 51 suites passed after 197.734 seconds` and `after 193.293 seconds`, no restart. Load 10.1 to 9.0 and 9.0 to 3.8.

### Shared tree

- `swift format lint --strict --recursive macos`: exit 0. The pinned swiftlint 0.65.1 `lint --strict --quiet` in macos/: exit 0. `scripts/check-names.sh`: see the last line.
- `cmp`: ScreenProtection.swift, ScreenProtectionLaunchTests.swift, ScreenProtectionTests.swift, PlatformTests.swift, CopySelectionTests.swift, MainWindowModel.swift, Copy.swift, QuitSignals.swift and crates/app-ffi/src/session.rs in the copy match the shared tree after every mutant was put back; `shasum -c` of the sums I took at the start: 9 of 9 OK. No mutant or probe was written in the shared tree.

### Clean-up

Every App launch (17 by hand, the rest through the tests) ended by itself after its snapshot; none had to be stopped. No process of mine is running. My /tmp folders (`e13s6o-verify-copy`, `-target`, `-dd`, `-probe`, `-sums`, `-launch-*`) are deleted. The general pasteboard was never written and its contents never read (the project's tests read only its change count, for a log note, LD-206).
