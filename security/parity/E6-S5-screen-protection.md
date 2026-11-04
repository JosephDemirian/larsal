# E6-S5 Screen protection and secure input (SC-05, SR-06; APP-09 F07; AT-D04, AT-D05)

Story: E6-S5 Screen protection and secure input.
- Card: [APP-10](../../spec/app/APP-10-screen-protection.md) (every rule); APP-09 flag F07; LD-153 (D-APP09-1: the reference spelling as a hidden alias), LD-155, LD-156 (7), LD-200 (2) and (10).
- Rows: plan/security.md SC-05, SR-06; plan/attacks-and-checks.md AT-D04, AT-D05.
- Code:
  - `macos/App/Platform/ScreenProtection.swift`: `adopt`, `window(_:style:)`, `alert()`, the run loop pass, `allow`;
  - `macos/App/Platform/SecureInput.swift`: the `SecureEventInput` seam and the controller;
  - `NoCopyTextField` in `macos/App/Platform/ShownPasswordField.swift`;
  - the hooks in `AppDelegate`, `main.swift`, `WindowChromeView`, `MainWindowModel.refresh`, `AutoTypePicker.swift` (two panels), `AutoType.swift`, `AuxWindows`, `AppSettingsWindow` and `Snapshot`;
  - Rust `allows_screen_capture()` and `capture_at_start` (`crates/app-ffi/src/start.rs`), F07 parsing (`cli.rs`);
  - the tests `ScreenProtectionTests` and `ScreenProtectionListTests` (13 together) and `SecureInputTests` (9).

Round 2. Runs 2026-10-29 20:32 to 21:30 on this Mac's clock.
Role: Verify. I did not build or check this story. No reference access was needed, and none was used.

Result: **signed.** Both round 1 findings are fixed, and each fix fails its test when undone. Every product rule I could reach without the owner's screen holds. Three notes do not block (section 5).

| Check | Result |
|---|---|
| 1. Every window type is protected from creation; my list compared with the test's | PASS. Every window-making line in `macos/App` belongs to a listed kind. The list has 12 kinds and 22 "not yet covered" patterns. |
| 2. Hidden debug App: the window server's sharing state of App's own windows | PASS. 7 launches. Every window is 0 from its first listing, or 1 with F07 or its alias. It is 0 again at the next start, and 0 after a secondary's F07. |
| 3. Secure input through the seam | PASS. 9 shown secret fields in 7 places. In each, App's call is on with the focus. It goes off on blur, deactivation, hide, another key window, window close and quit, and when the field is removed. It comes back on becoming active or key. The calls alternate. The 4 real lock paths behave as APP-10.8 says. |
| 4. APP-10 cases | Every case the build reaches passes (section 4). Real capture paths, the event-tap logger with real typing, and the ioreg holder with App in front are **needs Mac QA (owner's go)**. |
| 5. Mutations in a private copy | 30 mutations. The story's tests catch 27. Verify's probe catches 1 more (p13). 2 survive, both noted: t7 and p19. |
| Full run, lint, names | E6-S5 suites pass in the full run. The only failures are other stories' (section 6). swift format, SwiftLint, names: pass. |

## Setup

- **Private copy.**
  - Made at 20:32 with `rsync -a --exclude target --exclude app-shots`, into `/tmp/e6s5-verify3-copy`.
  - Its own target folder `/tmp/e6s5-verify3-target` (linked as the copy's `target`), and its own derived data `/tmp/e6s5-verify3-dd`.
  - `scripts/build-core.sh` printed `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`.
  - `xcodebuild build-for-testing … SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` printed `** TEST BUILD SUCCEEDED **`.
  - I used new names (`verify3`). The `/tmp/e6s5-verify2-*` folders from 2026-10-29 01:01 belong to an earlier agent, and no process uses them. I did not touch them.
- **The owner's session was never touched:**
  - no screen capture, no ScreenCaptureKit, no recording;
  - no window ordered front, no focus taken, no key events, no event tap;
  - the general pasteboard was never read or written;
  - the real `EnableSecureEventInput` and `DisableSecureEventInput` were never called. Every probe used the seam with a recorder. The hidden Apps had no focused field and were never active.
  - Each launch logged the front app before and after it. The front app was always one of the owner's apps (WhatsApp, Brave, T3 Code, Claude, Terminal), never the App I started.
- **The window-state reader.** `/tmp/e6s5-verify3-scripts/winstates.swift` calls `CGWindowListCopyWindowInfo([.optionAll])`, which reads window metadata only. It keeps only rows whose `kCGWindowOwnerPID` is the App I started. For each, it prints the window number, `kCGWindowSharingState`, layer, on-screen flag and bounds whenever one changes. It polls every 20 ms. No pixels are read, and no permission is needed.
- **The probe.** `VerifyR2Probe.swift` (8 tests, `.serialized`) lived in the copy only. I deleted it before the full run.

## 1. Every window type: my enumeration against the test's list

**What I searched for.** I grepped `macos/App` (comment lines left out) for every way to make or show a window:
- `NSWindow`, `NSPanel`, `NSAlert`, `Window(`, `WindowGroup`, `Settings {`, `MenuBarExtra`, `DocumentGroup`, `UtilityWindow`;
- `.sheet(`, `.popover(`, `NSPopover`, `.alert(`, `confirmationDialog`, file importers, exporters and movers, `.inspector(`;
- `NSOpenPanel`, `NSSavePanel`, `NSMenu(`, `NSHostingMenu`, `.contextMenu`, `Menu(`/`Menu {`, `Picker(`, `DatePicker`, `CommandMenu`, `CommandGroup`;
- `NSStatusBar`, `NSStatusItem`, `beginSheet`, `runModal`, `NSWindowController`, `contentViewController`, `contentRect:`;
- `orderFront`, `makeKeyAndOrderFront`, `orderWindow`, `setIsVisible`, `runModal(for:`, `orderBack`, `showWindow`;
- `ColorPicker`, `ShareLink`, `NSPrint*`, `NSPageLayout`, `NSSharingService*`, color and font panels;
- `.help(`, `toolTip`, `QLPreviewPanel`, `NSComboBox`, `NSPopUpButton`, `openWindow`, `searchSuggestions`, `NSDrawer`, `NSHostingController`, `presentAs`, `fullScreenCover`, `onDrag`/`draggable`.

| Window (where) | How it is protected | Kind in the test's list |
|---|---|---|
| Main window: SwiftUI `Window("App")` (AppMain.swift:10) | `WindowChromeView` adopts it as its content moves in. The run loop pass covers it too. | "Main window" (`chrome`) |
| Settings (AppSettingsWindow.swift:18); New Vault and Vault Settings (AuxWindows.swift:89, which then sets `contentViewController`); debug snapshot (Snapshot.swift:25) | `ScreenProtection.shared.window(_:style:)`: adopted at creation, before any show | "Settings, New Vault, …" (`made`) |
| M09-06 alert (main.swift:28); MI05-10 alert (AutoType.swift:296) | `ScreenProtection.shared.alert()` | "Alerts App runs" (`made`) |
| Auto-Type picker panel `AutoTypePanel` (AutoTypePicker.swift:275 to 307) | `adopt(panel)` at :302, before `makeKeyAndOrderFront` at :305 | "Window subclasses" (`adoptedBeforeShown`); `shows` reads both panels |
| Auto-Type unlock panel (AutoTypePicker.swift:325 to 345; it holds the master password form) | `adopt(panel)` at :340, before `makeKeyAndOrderFront` at :343 | same kind; now checked (t1, t2) |
| Popovers (DialogSheets:67, :211; VaultSettingsView:252; AppSettingsView:329; NewVaultParts:108; EditorEntryPage:97, :138, :197) | Run loop pass, plus `NSPopover.willShowNotification` | "Popovers" (`swept`) |
| SwiftUI `.alert(` (UnlockView.swift:63) | Run loop pass, plus `willBeginSheetNotification` | "SwiftUI alerts" |
| Open and save panels (NewVaultModel:320, EditorPages:121, :164, Saving:120, MainWindowModel:109, AuxWindows:115, :126, :135, UnlockModel:122) | Run loop pass (APP-10.3: optional) | "Open and save panels" |
| Menus: `CommandGroup`/`CommandMenu` (AppCommands:15 to 29), `Menu(` (AppCommands:104, :132; AppCommandsVault:93, :101, :112), `Picker(` (AppCommandsVault:150), `DatePicker(` (EditorEntryPage:222), `.contextMenu` (ReportsView, SidebarView, EntryListView, ReportTabs, UnlockView), `NSMenu(` (MenuBarIcon:60, ShownPasswordField) | Run loop pass | "Menus App builds" (round 1's finding 2: now named) |
| Tooltips (`.help(` in 8 files, `toolTip` in MenuBarIcon) | Run loop pass | "Tooltips" |
| Menu bar icon (`NSStatusBar`, MenuBarIcon:18) | Run loop pass | "Menu bar icon" |
| About panel (the App menu's default; `CommandGroup(after: .appInfo)` keeps it) | Run loop pass | "About panel" (no marker) |

- **Nothing outside the list.** No other spelling from the search occurs in `macos/App`. App uses none of `setIsVisible`, `runModal(for:`, `orderBack` or `showWindow`. WindowRules.swift:137 orders in the main window, which is already adopted.
- **Secret fields in those windows.** The fields are:
  - `UnlockView` (masked `SecureField`, or `ShownPasswordField` when shown);
  - `EditorPasswordField` / `MaskedPasswordField` (editor and one-time password setup);
  - `GeneratedField` (generator);
  - `SecretField` (New Vault ×2, Vault Settings ×2).

  Every shown one is a `NoCopyTextField`, and every masked one is an `NSSecureTextField` (`FocusSecureField` or SwiftUI's). The Auto-Type picker's `TextField` (AutoTypePicker.swift:178) is a search filter, not a secret.

## 2. Hidden debug App: the window server's sharing state

**How each run worked.**
- Command: `open -n -g -j --env APP_TEST_HIDDEN=1 --env APP_TEST_INSTANCE_DIR=<own> --env APP_DEBUG_SNAPSHOT=<png> [--stdin pw.txt] App.app --args …`, from `/tmp/e6s5-verify3-scripts/launch.sh`.
- The vault is a copy of `testdata/option-a-personal.appvault`, password `demo-pass-7`, given through F06 for the unlocked runs.
- Each App renders its main window view into an offscreen window that is never ordered front, then quits by itself after about 2 s. Every run printed `pid … ended by itself`, so no `kill` was needed. The script would have stopped only the pid it started.

| Run | Args | App's windows (`kCGWindowSharingState`) | Card |
|---|---|---|---|
| locked | `Personal.appvault` | 95026 (offscreen main view, 1320×820): 0 from its first listing (0×0). 95027 (500×500, made by AppKit/SwiftUI): 0 | APP-10.1-a, APP-10.7-a |
| f07 | `… --allow-screen-capture` | 95028: 1. 95029: 1 | APP-10.5-a, APP-10.2-c (states) |
| after-f07 | `Personal.appvault` (the next start) | 95030: 0. 95031: 0 | APP-10.1-b, APP-10.4-b |
| alias | `… --allow-screencapture` | 95032: 1. 95033: 1 | LD-153 D-APP09-1 |
| unlocked | `… --password-stdin` | 95034: 0 (the render shows the unlocked vault) | APP-10.7-a |
| unlocked-f07 | `… --password-stdin --allow-screen-capture` | 95035: 1 | APP-10.5-a |
| second-f07 | Primary `… --password-stdin`; 0.6 s later the secondary `App --lock --allow-screen-capture` | Secondary: exit 0, "All open vaults were locked." Primary: 95036: 0, 95037: 0. Its render shows "Locked at 20:37". | APP-10.5-b, APP-09.10, APP-10.7-a |

- **The window server agrees with APP-10.2.** On macOS 26.6, App's protected windows report 0 and allowed windows report 1, from their first listing. That includes the window AppKit or SwiftUI makes, which only the run loop pass reaches. Live p3 (section 5) shows it stays at 1 without that pass.
- **F07 in debug and release.**
  - APP-09 gives F07 one behaviour in both builds (only the lock and socket names differ, APP-09.7, APP-09.29). No `cfg!(debug_assertions)` or `#if DEBUG` touches the F07 path: `cli.rs` uses it only for the debug-info lines, and `AppDelegate` only for `DebugUI` and `Snapshot`.
  - `cargo test -p app-ffi --features net --lib`: 105 passed (debug). `cargo test --release … -- app10 app09_2 app09_3`: 9 passed, including `start::tests::app10_1_protected_unless_the_primary_had_f07`, `cli::tests::app09_2_reference_spellings_are_aliases` and `app09_3_help_lists_every_flag_and_no_alias`.
  - A release App is not launched. A hidden launch is debug only, and a release App would show a window on the owner's screen.
- **Flag text.** `App --help` printed `--allow-screen-capture    Allow screen capture while App runs.` with exit 0, and lists no alias. `App --allow-screen-capture=yes` printed `Unknown flag: --allow-screen-capture=yes. Run App --help for the list of flags.` with exit 1, as APP-09 M09-09 says.

## 3. Secure input through the seam, in every secret field

Each real view rendered offscreen. In each window, the probe found every shown password field (`NoCopyTextField`) and checked that it drives `SecureInput.shared`. It then gave the field a private controller with a recorder and a private notification center, and ran these steps: focus, blur, focus, resign active, become active, hide, become active, another window key, back key, window close, focus, quit, focus. Last, it removed the field the way App does (Show off, the sheet closed, the generator closed).

| Place | Shown fields | Result |
|---|---|---|
| Unlock form, Show on (APP-06 UL-PW) | 1 | `shared=true focus=on blur=off focus=on resignActive=off becomeActive=on hide=off unhide=on otherKey=off backKey=on close=off focus=on quit=off focus=on`; removed by Show off: `fieldsGone=true on=false calls=14 alternate=true` |
| Auto-Type unlock panel's form (`AutoTypeUnlockPanel.view`), Show on | 1 | same; removed by Show off: off, 14 calls, alternating |
| Entry editor password, shown (`EditorPasswordField`) | 1 | same; removed by Hide: off |
| One-time password setup secret (`.totpSetup` sheet) | 1 | same; removed by closing the sheet: off |
| Generator password (`GeneratedField`) | 1 | same; removed by closing the generator: off |
| New Vault wizard, Show on (`SecretField` ×2) | 2 | same, for each; removed by Show off: off |
| Vault Settings, Change the password, Show on (`SecretField` ×2) | 2 | same, for each; removed by Show off: off |

- **Masked fields** are AppKit secure fields, which turn on their own secure input (V-A10-2, Mac QA). Each place has one with Show off: unlock 1, editor 1, wizard 2, settings 2.
- **The real lock paths** (`SecureInput.shared` with a recorder, App active, every window key):
  - Editor's shown password, then `lockAll`: `before: on=true calls=["enable"]`, `right after: on=true` (the field still edits), then `settled: on=false inWindow=false calls=["enable", "disable"]`.
  - The same with `lockNow` of the shown vault: same result.
  - Unlock form with Show on, while another vault locks: `on=false reveal=false calls=["enable", "disable"]`.
  - New Vault wizard field, which stays open on a lock: `lockAll` gives `on=true editing=true calls=["enable"]`. Then blur: `on=false calls=["enable", "disable"]`.
  - So a lock ends App's call for every field the lock removes. A field that still edits in the key window of an active App keeps it, as APP-10.8 says. I accept the builder's and Checker's reading. APP-10.12's sentence about locks should say "for a field the lock removes" (Spec wording, for the lead).
- **Not built yet** (APP-10.9): the import password fields (FEA-08), shared groups (INT-08) and the pick-characters dialog (INT-05). When they are built, they must use one of App's password field views.

## 4. APP-10 cases

| Case | Result |
|---|---|
| APP-10.1-a | PASS: hidden launch "locked", every window 0 |
| APP-10.1-b | PASS: "after-f07" all 0. Nothing is saved: `startFlag` shows `ScreenProtection().allowed == false`, and there is no settings key. |
| APP-10.1-c | PASS in tests (`beforeFirstFrame`: the factory window, the alert, and the main window through `WindowChromeView`). Live, App's windows were 0 at their first listing. The first frame of windows AppKit and SwiftUI put on screen: **needs Mac QA (owner's go)** |
| APP-10.2-a, -b; AT-D04 capture paths (`screencapture`, ScreenCaptureKit, QuickTime, screen sharing) | **needs Mac QA (owner's go)**, V-A10-1 and V-A10-7 |
| APP-10.2-c | States 1 with F07: PASS ("f07", "alias", "unlocked-f07"). The picture: **needs Mac QA** |
| APP-10.3-a | Tooltips and menus are swept (`everyKindIsProtected`, `runLoopPass`). A live tooltip or completion list: **needs Mac QA** |
| APP-10.3-b | The site access prompt (INT-02) is not built |
| APP-10.4-a | PASS in tests (`allowAndBack`, `menuAction`). The running App's toggle: **needs Mac QA** |
| APP-10.4-b | PASS ("after-f07"; nothing saved) |
| APP-10.5-a | PASS ("f07", "alias", "unlocked-f07": states 1). The check mark follows `allowed` (`menuAction`). |
| APP-10.5-b | PASS ("second-f07": the secondary's F07 is ignored, and the primary stays at 0) |
| APP-10.6-a | PASS (`refusedBanner`; `startedAtLaunch` wires M10-01 to the banner) |
| APP-10.7-a | PASS (locked 0, unlocked 0, locked by the channel 0) |
| APP-10.8-a, -c, -e; APP-10.9-a; APP-10.13-a | App's call: on and off through the seam, PASS (section 3; `focusAndBlur`, `deactivateAndBack`, `keyWindow`). The holder's process id with App in front: **needs Mac QA** (V-A10-6) |
| APP-10.8-b | PASS through the seam. ioreg: **needs Mac QA** |
| APP-10.8-d, AT-D05 | The event-tap logger with real typing: **needs Mac QA (owner's go)** |
| APP-10.10-a | PASS (`neverLeftOn`: alternating calls over 400 steps; probe: 14 alternating calls per field) |
| APP-10.11-a | PASS (`staleReport`, `lockRechecks`, `deactivateAndBack`) |
| APP-10.12-a | Verified by Spec (V-A10-8). App's own crash: **needs Mac QA** |
| APP-10.12-b | App's own call: PASS (lock paths, section 3). A masked field's AppKit secure input after a lock: **needs Mac QA** (V-A10-2) |
| APP-10.13-b | PASS through the seam (editor field, resign active) |
| Dock picture of a minimized window | **needs Mac QA** (V-A10-4) |

## 5. Mutations (private copy; each file restored and checked with `cmp`)

The runner (`/tmp/e6s5-verify3-scripts/mutate.py`):
1. Changes exact text that must occur once.
2. Runs the suites: ScreenProtectionTests for protection; SecureInputTests plus the probe for secure input.
3. Copies the file back from a backup and checks it with `cmp`. Every restore printed `cmp equal`. New files were removed.

**Test-design mutations (round 1's findings):**

| # | Mutation | Caught by |
|---|---|---|
| t1 | The Auto-Type unlock panel's `adopt` removed (round 1's m9c) | `everyKindIsProtected`, 2 issues: "AutoTypePicker.swift shows panel before adopting it" |
| t2 | The unlock panel adopted after `makeKeyAndOrderFront` | same, 2 issues |
| t3 | The picker panel's `adopt` removed | same, 2 issues |
| t4 | The Menus marker set back to round 1's `\bNS(Hosting)?Menu\(\|\.contextMenu\b` | `listNamesSpellings`, 6 issues (Menu ×2, Picker, DatePicker, CommandMenu, CommandGroup) |
| t5 | New files with `NSPanel()` and `.sheet(` | `listIsComplete`, 2 issues ("…makes a window as Window constructors where the list does not expect it", "…(\.sheet\() no kind covers") |
| t6 | A third `AutoTypePanel` shown with `orderFrontRegardless()` and no adopt | `everyKindIsProtected`: "shows other before adopting it" |
| t7 | The unlock panel shown with `setIsVisible(true)`, no adopt | **not caught**: 13 of 13 pass (note N1) |
| t8 | AuxWindows makes a plain `NSWindow(` | `listIsComplete`, 3 issues |

**Product mutations:**

| # | Mutation | Caught by | Live |
|---|---|---|---|
| p1 | `sharing` always `.readOnly` | 6 tests, 24 issues (`everyKindIsProtected` 14, …) | every window 1 |
| p2 | Launch `start(allowCapture: true)` | `startedAtLaunch` | every window 1 |
| p3 | Run loop pass not added | `runLoopPass` (2) | The AppKit-made 500×500 window stays 1; App's own window stays 0 |
| p4 | `update` ignores App active | `deactivateAndBack`, `neverLeftOn` (40), 7 probe tests; 52 issues | – |
| p5 | Shown field does not report focus | 7 SecureInputTests, 8 probe tests; 46 issues | – |
| p6 | Window close does not release | `hiddenRemovedClosed`, 7 probe tests | – |
| p7 | Lock does not re-check (`MainWindowModel.swift:68` removed) | `lockRechecks` | – |
| p9 | M10-01 never raised | `refusedBanner` (3) | – |
| p10 | `allow` does not sweep open windows | `allowAndBack` (2), `refusedBanner` | – |
| p11 | `WindowChromeView` does not adopt the main window | `beforeFirstFrame`, `everyKindIsProtected` | – |
| p12 | The factory does not adopt | `beforeFirstFrame`, `everyKindIsProtected`, `allowAndBack` | – |
| p13 | `didHideNotification` not observed | **only Verify's probe** (7 tests); the story's tests pass (note N2) | – |
| p14 | Quit not observed | `neverLeftOn`, 7 probe tests | – |
| p15 | Sheet and popover notices not observed | `sheetAndPopover` (2) | – |
| p16 | `alert()` does not adopt | `everyKindIsProtected` (3), `beforeFirstFrame` | – |
| p17 | Another key window not observed | `keyWindow`, `neverLeftOn`, 7 probe tests | – |
| p18 | `abortEditing` not reported | `hiddenRemovedClosed` | – |
| p19 | Removal from the window (`viewDidMoveToWindow`) not reported | **not caught**: 17 of 17 pass (note N3) | – |
| p20 | Becoming active or key does not turn it back on | `deactivateAndBack`, `backAfterRelease`, `keyWindow`, 7 probe tests | – |
| r1 | Rust `capture_at_start`: `primary.is_some()` | `app10_1_protected_unless_the_primary_had_f07` panicked at start.rs:472 | – |
| r2 | Rust `capture_at_start` always `true` | the same test panicked at start.rs:461 | – |
| r3 | F07's spelling changed in `cli.rs` | `app09_2_reference_spellings_are_aliases` panicked at cli.rs:310 | – |

No mutation called the real system calls in a test run, because rule 10 forbids it. `inertInTests` checks that guard.

**Notes (not blocking):**
- **N1 (test hardening).** `shows` recognises `makeKeyAndOrderFront`, `orderFront`, `orderFrontRegardless` and `orderWindow`. It does not recognise `setIsVisible(true)`, `orderBack` or `NSApp.runModal(for:)`. App uses none of these today, and the run loop pass would still protect such a window before Core Animation's commit. Smallest fix: add `setIsVisible\(true\)|orderBack|runModal\(for:` to the regex in `ScreenProtectionListTests.shows`.
- **N2 (test hardening).** `deactivateAndBack` posts hide only after resign active. So the hide observer itself is not pinned by the story's tests. In AppKit, hiding the active App also resigns active, so the behaviour stands, and my probe pins it. Smallest fix: a `SecureInputTests` step that posts `didHideNotification` alone.
- **N3 (backstop).** When a focused shown field is removed, its editing ends first, so `textDidEndEditing` reports it. `viewDidMoveToWindow(nil)` is a second report that no path I found needs. It is equivalent in every flow I ran (Show off, sheet closed, generator closed, `removeFromSuperview`). Keep it as a backstop.

## 6. Runs, lint, names

- **E6-S5 suites, unchanged copy.** `xcodebuild test-without-building -only-testing:AppTests/ScreenProtectionTests -only-testing:AppTests/SecureInputTests` printed `Test run with 22 tests in 2 suites passed after 3.792 seconds`.
- **Probe.** `Test run with 8 tests in 1 suite passed after 33.232 seconds`.
- **Full run.** The copy at 20:32, plus the shared tree's newer `ShownPasswordField.swift` and `ShownPasswordFieldTests.swift` from another story's F-069 work, copied in at 21:21. The copy then matched the shared `macos/`. Command: `xcodebuild test -scheme App -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, with load averages from 59 to over 300 from other agents.
  - The first launch passed 69 tests. It failed FEA-01.34 (the 50 ms search timing) and APP-09.27 (the signals test, 60 s limit). After that test's SIGQUIT the test process ended, and xcodebuild restarted it.
  - The restart printed `Test run with 176 tests in 30 suites passed`. `Suite ScreenProtectionTests passed` and `Suite SecureInputTests passed`.
  - Rerun alone: APP-09.27 passed, and `ScreenTests/searchSpeed()` printed `Test run with 1 test in 1 suite passed`.
  - F-069 `shownPasswordNoUndo` (another story's work in progress on the shared tree, changed at 20:58) fails, also alone (`ShownPasswordFieldTests.swift:57`). It is not E6-S5's.
  - None of these touches E6-S5's code.
- **Lint (shared tree).**
  - `swift format lint --strict --recursive macos`: exit 0.
  - SwiftLint 0.65.1 `lint --strict --quiet` in `macos/`: exit 0, with no output.
  - `cargo fmt --all -- --check`: diffs only in `crates/app-ffi/src/edit.rs` and `crates/app-platform/src/macos/signals.rs`. Both were changed by other agents at 20:39 and 20:42 today. `start.rs` and `cli.rs` are clean.
- **Names.** `scripts/check-names.sh` after this file and the epics.md line: `names: PASS (3145 files scanned, 15 vault files name-only)`.

## Mac QA (owner's go), unchanged

- AT-D04: each capture path (`screencapture`, ScreenCaptureKit, QuickTime, screen sharing).
- AT-D05: the event-tap logger with real typing.
- The ioreg holder with App in front (APP-10.8-a, -c, -e, APP-10.9-a, APP-10.13-a; V-A10-6), and APP-10.12-b for a masked field.
- The first frame of windows AppKit and SwiftUI put on screen (tooltips, menus, the About panel, the menu bar icon).
- The running App's Permit Screen Capture toggle and the settings Privacy switch.
- The Dock picture (V-A10-4).

## Cleanup

- I unregistered the copy's App.app from Launch Services, then deleted `/tmp/e6s5-verify3-copy`, `-target`, `-dd`, `-run`, `-scripts` and `-orig`.
- Every App I started ended by itself, and `pgrep -f e6s5-verify3` is empty.

## History: round 1 (2026-10-28): failed (2)

- **The product code passed.**
  - Hidden launches: every window 0, and 1 with F07 or its alias.
  - Secure input: 9 shown fields in 7 places.
  - 8 product mutations, all caught.
  - Full run: 263 tests.
- **Two test findings failed the round:**
  1. The adopt-before-show check proved only the first panel in `AutoTypePicker.swift`. Removing the Auto-Type unlock panel's `adopt` passed all 11 tests (m9c).
  2. The window list did not name SwiftUI `Menu(`, `Picker(` and `DatePicker(`, which App uses.
- **Both are fixed.** Fix 1: `shows` and `showsNeedAdopt`; round 2's t1, t2, t3 and t6. Fix 2: the Menus marker and `listNamesSpellings`; round 2's t4.
