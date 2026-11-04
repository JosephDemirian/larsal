# E5-S9 Larsal settings: Verify report

Story E5-S9 (plan/epics.md): Larsal settings from the settings inventory (APP-01); APP-09.20, 09.21, 09.28 (LD-153). Check: every setting has a control or a written reason why not.
Verify agent, round 2, 2026-10-28. I did not build or check this story. Round 1 (failed (1), F1) is kept below for history.

**Verdict: signed (Done).** Part A (design parity) passes 7 of 7 frames in light and dark. Part B passes: 175 of 175 card ids are in the inventory with a control or a written reason, keys, scopes and defaults equal APP-01, 51 settings on 6 pages were driven through their controls and stored under the card's keys, and the round-1 finding F1 is fixed (the tree's test now fails when Reset drops the SSH values). 17 of 17 mutations were caught. The checks that need a visible window, the real login item or the owner's session are listed under "Needs Mac QA (owner's go)".

## How I ran it

- Private copy: `rsync -a --exclude target --exclude larsal-shots` of the project to `/tmp/e5s9-verify2-copy` at 19:07. One later shared change in the story's files was synced in before the final render: `macos/Larsal/LarsalSettingsView.swift` (19:13, the AT-K06 accessibility work: the nav's back and forward glyphs are no longer hidden). The copy also held another agent's probe test `macos/LarsalTests/ZProbeTests.swift`, which had been removed from the shared tree; I removed it from the copy. Own build folders: `/tmp/e5s9-verify2-dd` (xcodebuild), `/tmp/e5s9-verify2-target` (cargo). Every folder was deleted at the end.
- My own test files lived only in the copy: `macos/LarsalTests/VerifyE5S9Tests.swift` (the driver, 3 tests) and `crates/larsal-ffi/tests/verify_e5s9.rs` (4 tests).
- Canary: `SSH_AUTH_SOCK` (and `TEST_RUNNER_SSH_AUTH_SOCK` for xcodebuild) pointed at a socket of my own, `/tmp/e5s9-verify2-canary/agent.sock` (pid 40735), which logs every connection. Result: **0 connections** over every run.
- Throwaway homes: `HOME=/tmp/e5s9-verify2-home` for every cargo run, `TEST_RUNNER_HOME=/tmp/e5s9-verify2-home3` for every xcodebuild test run, `HOME=/tmp/e5s9-verify2-home4` for the hidden Larsal launches. All three were still empty at the end. Every Rust session of my tests calls `set_ssh_options` with a throwaway socket first (the round-1 lesson).
- No visible window, no focus taken. Chrome ran headless. Views rendered in borderless windows at x −20000 that were never ordered front. Larsal ran only as hidden launches (`LARSAL_TEST_HIDDEN`, own `LARSAL_TEST_INSTANCE_DIR`), each rendering offscreen and quitting by itself.
- The reference app was not used. The spot check of defaults is optional, and the card's defaults table already holds them.

## Part A: design parity, section `settings`

Report: [design/parity/settings/report.md](../../design/parity/settings/report.md) (with [report.html](../../design/parity/settings/report.html) and findings.json). Its last section lists the round-2 commands and their output.

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / runs > 2 pt | Verdict |
|---|---|---|---|---|---|---|---|
| settings-settings-general | present | present | 0.68 % (0.43 %) / 0.69 % (0.45 %) | 0 (3 card words accepted) | 0 / 0 | 0 | PASS |
| settings-settings-security | present | present | 0.61 % (0.56 %) / 0.60 % (0.56 %) | 0 | 0 / 0 | 0 | PASS |
| settings-settings-auto-type | present | present | 0.48 % (0.43 %) / 0.48 % (0.44 %) | 0 | 0 / 0 | 0 | PASS |
| settings-settings-browser-integration | present | present | 0.33 % (0.28 %) / 0.33 % (0.29 %) | 0 | 0 / 0 | 0 | PASS |
| settings-settings-ssh-agent | present | present | 0.32 % (0.27 %) / 0.33 % (0.28 %) | 0 | 0 / 0 | 0 | PASS |
| settings-settings-shared-groups | present | present | 0.34 % (0.29 %) / 0.34 % (0.30 %) | 0 | 0 / 0 | 0 | PASS |
| settings-settings-shortcuts | present | present | 0.36 % (0.31 %) / 0.37 % (0.33 %) | 0 | 0 / 0 | 0 (1 run explained) | PASS |

Commands (in the copy, in this order):
1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0. `cmp` against the shared files: manifest.json equal; 10 of the 14 settings PNGs equal; light security and shortcuts and dark general and shortcuts differ by 1, 1, 20 and 22 raw pixels, with pixelmatch (threshold 0.1) 0 changed pixels each. The shared reference is current.
2. `scripts/build-core.sh` → `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`, exit 0 (1 min 33 s).
3. `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s9-verify2-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `** TEST BUILD SUCCEEDED **`.
4. `xcodebuild … test-without-building -skip-testing:LarsalUITests` (canary env, throwaway TEST_RUNNER_HOME) → `✘ Test run with 207 tests in 34 suites failed after 104.622 seconds with 12 issues`:
   - 11 issues in `AccessibilityWalkTests` "AT-K06: every control on every built screen is named and reachable". This is another story's new test: the file was new in the shared tree at 19:06 and changed again at 19:15. Its 16 screens are main-window screens (unlock, list and detail, editor, generator, reports and so on), none of them settings. Example: "unlock: AXButton at (812.0, 379.0, 32.0, 33.0): the focus cannot reach it (Show password)". Not E5-S9.
   - 1 issue in my driver: it looked for the vault file "option-a-work.larsalvault", but the test copy names it "Work.larsalvault". I fixed my test; it then passed 3 of 3 (below).
   - `LarsalSettingsEffectsTests`, `LarsalSettingsFrameTests`, `LarsalSettingsParityTests` and `LarsalSettingsTests` passed. The general pasteboard change count was 10330 before and 10330 after this run.
5. After the sync of `LarsalSettingsView.swift`: build-for-testing → `** TEST BUILD SUCCEEDED **`; `xcodebuild … test-without-building -only-testing:LarsalTests/LarsalSettingsFrameTests -only-testing:LarsalTests/LarsalSettingsTests -only-testing:LarsalTests/LarsalSettingsEffectsTests -only-testing:LarsalTests/LarsalSettingsParityTests -only-testing:LarsalTests/VerifyE5S9Tests` → `✔ Test run with 25 tests in 5 suites passed after 10.992 seconds`.
6. Snapshots: "Option A settings frame, offscreen, light and dark" wrote `larsal-shots/{light,dark}/settings-settings-*.png` and `.ax.json` (the old ones were deleted first). All 28 files are byte-equal (`cmp`) to the shared `larsal-shots/`: `compared 28, differ 0`. The copies checked are in `design/parity/settings/app/`, the diffs in `design/parity/settings/diff/`.
7. `node design/parity/tools/mockup-dom.mjs settings` → `light: 7 frames, 215 text runs`, `dark: 7 frames, 215 text runs`, exit 0.
8. `swift design/parity/tools/ocr.swift larsal-shots/light/settings-settings-*.png larsal-shots/dark/settings-settings-*.png` → 14 images read, exit 0.
9. `node design/parity/tools/compare.mjs settings` → `settings: 7/7 PASS` (the table above). notes.mjs is unchanged: the round-1 Verify notes still hold (3 card-word rules on general: "Save changes as you make them" for "Save after every change" (S-FILE-01, LD-167, W-04), "once a week" for "once a day" (S-START-09, APP-01.19), `{FILE_NAME}.old.larsalvault` for `{DB_FILENAME}.old.larsalvault` (APP-01.2, APP-05.20); and the "⌘⌫" run on shortcuts, 4 pt wider because the bundled IBM Plex Sans has no ⌘, ⇧ or ⌫ glyph).

Checks 2 to 7, with their numbers:
- Text: 272 strings found per theme over the 7 frames, 0 missing, 3 accepted (the card words above).
- Tokens: 0 mismatches per frame; the static check of every colour asset against app.css gives 45 of 45 equal.
- Geometry: 0 boxes or text runs off by more than 2 pt, apart from the explained "⌘⌫" run.
- Behaviour: the 7 `Parity settings-settings-*` tests pass (nav, back and forward, switches, steppers, the login item through a fake, the controls of later stories disabled). My driver pressed 49 more controls (Part B).
- Accessibility: a script over the 14 ax.json trees found 298 controls (174 buttons, 110 switches, 14 text fields), 0 without a name. Contrast: 42 pairs, lowest 4.87:1.
- By eye: I compared app and reference for general (light) and ssh-agent (dark). Layout, type, tiles and switches are the same. The only differences are the window buttons (the window draws them) and the card words. The light security diff shows only anti-aliasing (yellow) and the window buttons (red).

## Part B: every setting has a control or a written reason

### B1. Count of setting ids

I counted the ids myself with `/tmp/e5s9-verify2-scripts/count.py`. It reads every table row of spec/app/APP-01-settings.md before "## Rules", expands the ranges (S-BRW-02 to -08, S-STATE-07 to -13), takes both ids of each generator row, and adds the S-NOMAC bullets and S-DEBUG-01. It then compares the result with security/parity/E5-S9-settings-inventory.md.

```
card ids: 175
inventory rows: 175 unique 175
in card not in inventory: []
in inventory not in card: []
duplicate inventory rows: []
rows with neither control nor reason: []
rows with a control: 85
per area: START 12, FILE 8, ENTRY 11, UI 12, AT 10, TIME 6, LOCK 4, CONV 5, PRIV 1, BRW 27, KEYS 1, SSH 3, SHARE 4, VIEW 7, SEARCH 2, PWGEN 22, MSG 3, STATE 17, CFG 5, NOMAC 14, DEBUG 1
```

The other 90 rows each carry a reason. I read all 90:
- not drawn in Option A, with a mockup request, W-06 or W-07;
- skipped by D-01-8, D-01-4, LD-189 or D-01-2;
- in another menu: View menu (E5-S11) or the search field menu;
- waits for W-10 (generator) or for its story (E7, E8, E10, E11, E14);
- state Larsal keeps on its own;
- file only;
- not on Mac.

The card's count table says 174 because its Entry management line counts 10 ids for 11 rows (S-ENTRY-01 to -11). The inventory notes this.

### B2. Keys, scopes and defaults against the card

`/tmp/e5s9-verify2-scripts/keys.py` compares the Key column of every card row with every `d("S-…", "<key>", scope, kind)` in `crates/larsal-ffi/src/larsal_settings.rs`.
- Result: `code definitions: 137`, `key mismatches: 0`.
- The rows not stored are exactly the card's S rows: S-START-01, S-UI-02, -03, -05, -06, S-BRW-20, -22, -25 to -27, S-VIEW-02, S-MSG-02, -03, S-CFG-03 to -05. Three more are kept elsewhere: S-START-02 by the OS, S-BRW-03 to -08 as browser files, S-STATE-07 to -13 as checked keys.
- The range ids checked by hand: S-BRW-02 is `browser.safari`, and S-STATE-07 to -13 are `state.window_frame`, `state.window_layout`, `state.columns`, `state.columns_search`, `state.split_preview`, `state.split_main` and `state.split_groups`.
- Scopes: every "Mac" row is this-Mac in the code (S-FILE-08, S-UI-04, S-LOCK-01, S-SSH-02, S-SSH-03, S-VIEW-05, S-CFG-02), and every S-STATE row is state.
- Defaults: every default equals the card's, with the Larsal column's D values: S-START-08 off, S-START-09 off, S-FILE-05 on, S-FILE-06 `{FILE_NAME}.old.larsalvault`, S-TIME-04 300, S-ENTRY-11 off, S-UI-01 `system`/`en`.

### B3. Settings driven through their controls (Verify driver, 51 ids on 6 pages)

`VerifyE5S9Tests` (private copy) does the following for each test:
1. Makes a `Session()` whose store uses a throwaway folder under `/tmp/e5s9-verify2-tests`.
2. Builds the settings window offscreen (`SettingsScreen`).
3. Presses each control through the accessibility tree, the nth one where a label repeats ("More", "Less").
4. Presses OK (`model.ok()`, the call the window's close makes).
5. Reads `settings.json` and `state.json` and prints the card key, `defaultValue(key)` and the stored value.
6. Checks the part of Larsal that uses the value.

Run alone: `xcodebuild … test-without-building -only-testing:LarsalTests/VerifyE5S9Tests` → `✔ Test run with 3 tests in 1 suite passed after 10.261 seconds`, exit 0. It also passes in step 5 of Part A.

Tests:
- "Verify2 E5-S9 General: pressed controls store under the card keys and reach their users"
- "Verify2 E5-S9 Security: timeouts and lock switches reach the clipboard, the lock timers and the search"
- "Verify2 E5-S9 Auto-Type, Browser, Shared groups and Shortcuts: switches and steppers store under their keys"

Driver output (JSON booleans print as 0 and 1):

| Id | Page | Control pressed | Key | Default | Stored after OK |
|---|---|---|---|---|---|
| S-START-02 | General | Login | none (OS) | off | `LoginItem` calls `[true]`; no login key in either file |
| S-START-05 | General | Recent | recent.remember | true | settings.json 0 |
| S-START-06 | General | Less ×4 | recent.count | 5 | settings.json 1 |
| S-START-07 | General | Reopen | recent.reopen_at_start | true | settings.json 0 |
| S-FILE-01 | General | Autosave | save.after_every_change | true | settings.json 0 |
| S-FILE-02 | General | Save on lock | save.on_lock | true | settings.json 0 |
| S-FILE-04 | General | Reload | save.reload_on_change | true | settings.json 0 |
| S-FILE-05 | General | Backup | backup.enabled | true | settings.json 0 |
| S-ENTRY-02 | General | Confirm | entry.confirm_recycle | false | settings.json 1 |
| S-ENTRY-03 | General | Autogen | entry.autogen_password | false | settings.json 1 |
| S-VIEW-01 | General | Dark | ui.theme | "auto" | settings.json dark |
| S-UI-07 | General | Colour | display.color_passwords | false | settings.json 1 |
| S-UI-08 | General | Mono notes | display.monospace_notes | false | settings.json 1 |
| S-UI-09 | General | Hide on close | window.close_hides | false | settings.json 1 |
| S-TIME-01 | Security | Clipboard | clipboard.clear.enabled | true | settings.json 0 |
| S-TIME-02 | Security | More #1 | clipboard.clear.seconds | 10 | settings.json 15 |
| S-TIME-03 | Security | Idle lock | lock.idle.enabled | true | settings.json 0 |
| S-TIME-04 | Security | More #2 | lock.idle.seconds | 300 | settings.json 360 |
| S-TIME-05 | Security | Clear search | search.clear_when_idle | false | settings.json 1 |
| S-TIME-06 | Security | More #3 (disabled until S-TIME-05 is on, APP-01.5, checked) | search.clear_after_minutes | 5 | settings.json 6 |
| S-LOCK-02 | Security | Screen lock | lock.on_screen_lock | true | settings.json 0 |
| S-LOCK-03 | Security | User switch | lock.on_user_switch | true | settings.json 0 |
| S-LOCK-04 | Security | Minimize | lock.on_minimize | false | settings.json 1 |
| S-CONV-01 | Security | Dots | display.dots_for_empty | false | settings.json 1 |
| S-CONV-02 | Security | Editor | display.hide_password_in_editor | true | settings.json 0 |
| S-CONV-03 | Security | Preview | display.hide_password_in_preview | true | settings.json 0 |
| S-CONV-04 | Security | Codes | display.hide_totp_in_preview | false | settings.json 1 |
| S-CONV-05 | Security | Notes | display.hide_notes | false | settings.json 1 |
| S-AT-01 | Auto-Type | Title | autotype.match_title | true | settings.json 0 |
| S-AT-02 | Auto-Type | URL | autotype.match_url | true | settings.json 0 |
| S-AT-05 | Auto-Type | Expired | autotype.hide_expired | false | settings.json 1 |
| S-AT-06 | Auto-Type | Relock | lock.relock_after_autotype | false | settings.json 1 |
| S-AT-08 | Auto-Type | More #3 | autotype.retype_seconds | 15 | settings.json 16 |
| S-AT-09 | Auto-Type | More #1 (step 100) | autotype.start_delay_ms | 500 | settings.json 600 |
| S-AT-10 | Auto-Type | More #2 (step 5) | autotype.key_delay_ms | 25 | settings.json 30 |
| S-BRW-01 | Browser Integration | Browser ("Never ask" disabled before it, checked) | browser.enabled | false | settings.json 1 |
| S-BRW-10 | Browser Integration | Unlock | browser.unlock_on_request | true | settings.json 0 |
| S-BRW-12 | Browser Integration | Best | browser.best_match_only | false | settings.json 1 |
| S-BRW-14 | Browser Integration | All vaults | browser.search_all_vaults | false | settings.json 1 |
| S-BRW-15 | Browser Integration | Never ask | browser.never_ask_access | false | settings.json 1 |
| S-BRW-19 | Browser Integration | Localhost | browser.passkeys_localhost | false | settings.json 1 |
| S-BRW-21 | Browser Integration | Rewrite | browser.rewrite_manifests | true | settings.json 0 |
| S-SHARE-01 | Shared Groups | Import | share.import | false | settings.json 1 |
| S-SHARE-02 | Shared Groups | Export | share.export | false | settings.json 1 |
| S-SHARE-03 | Shared Groups | Quiet | share.quiet | false | settings.json 1 |
| S-KEYS-01 | Shortcuts | (read-only list; "Copy Username" found) | shortcuts.custom | empty | absent: nothing stored without an edit (APP-01.29) |

How each value reaches the code that uses it (driver output):
- General:
  - `VERIFY2 reach S-START-06=1: recent ["Work.larsalvault"]`: after a second demo vault opens, the recent list holds 1.
  - S-START-07: with the default (on), `rememberOpenVaults()` writes `state.open_at_quit`. After OK with it off, `state.open_at_quit` is absent.
  - `VERIFY2 reach S-ENTRY-02 askBeforeBin=true S-FILE-01 autosave=false S-FILE-02 savesOnLock=false`: `MainWindowModel.main` after an unlock.
  - `VERIFY2 reach S-ENTRY-03 new entry passwordChars=20`: `beginNew` fills a password of the generator's stored length.
  - `VERIFY2 reach S-VIEW-01 appearance=NSAppearanceNameDarkAqua`: `Appearance.apply` on the test process's own `NSApp`, restored after.
  - `VERIFY2 reach S-START-05 off: recent []`: APP-01.7 and APP-01.14. `state.recent` is absent after the next open.
  - S-START-02: the fake `LoginItem` got `[true]` on OK.
- Security:
  - `VERIFY2 reach S-TIME-02 countdown=15 S-TIME-04 idle=360 S-LOCK-02 false S-LOCK-03 false S-LOCK-04 true`: `copyField` of a demo password (private pasteboard) counts down 15 s, where it counted 10 s before OK. `LockSettings(store:)` reads the timers and lock switches.
  - `VERIFY2 reach S-TIME-05/06 search cleared after 0.150717459 seconds (6 minutes of 25 ms)`: `SearchClearTimer` with a 25 ms minute kept "mail" at 90 ms and cleared it after 6 × 25 ms.
  - `VERIFY2 reach S-TIME-01 off countdown=0 S-TIME-03 off idleEnabled=false`.
- Auto-Type, Browser, Shared groups:
  - `VERIFY2 reach LD-54 import list: ["S-BRW-15 off -> on", "S-BRW-19 off -> on"]`: an export of these values, imported into fresh settings, lists exactly the two that lower protection. Apply then stores them (`share.quiet` and key delay 30 read back).
  - `VERIFY2 reach APP-01.9 reset: browser.never_ask_access true share.quiet true autotype.match_title true`: Reset keeps the Browser and shared-groups values and puts Auto-Type back to its defaults.
  - Auto-Type (E8), browser integration (E7) and shared groups (E11) read these keys when those stories come, as the inventory says.

SSH page (S-SSH-01 to -03). `set_ssh_options` is not exported to Swift. A Swift OK with S-SSH-01 on would start Larsal's agent at its default socket in the user's settings folder. So, as in round 1, the SSH reach is proven in Rust with throwaway agent options. The page's switch press is covered by "Parity settings-settings-ssh-agent".
- `verify2_s_ssh_01_to_03_reach_apps_agent_in_a_throwaway_folder` → `VERIFY2 S-SSH-01..03: on -> Larsal's agent at /tmp/e5s9-verify2-rust/ssh-42223/agent.sock, -02 and -03 in state.json (this Mac), -01 in settings.json, kept by Reset, off -> stopped`.
- Tree test `larsal_settings::tests::s_ssh_01_ok_turns_apps_agent_on_and_off` passes.
- Generator (S-PWGEN): tree tests `ld204_generator_options_persist_in_the_store` and `edit::tests::app01_25_s_entry_03_new_entry_password` pass.

### B4. APP-09.20, APP-09.21, APP-09.28

APP-09.20 (reopen, locked, order, last shown). The script `/tmp/e5s9-verify2-scripts/a0920.sh` makes hidden launches of the copy's debug Larsal:
- environment: `LARSAL_TEST_HIDDEN=1`, its own `LARSAL_TEST_INSTANCE_DIR`, `LARSAL_DEBUG_SNAPSHOT`, throwaway `HOME` and canary `SSH_AUTH_SOCK`;
- vaults: copies of testdata/option-a-personal.larsalvault in `/tmp/e5s9-verify2-a0920/v`;
- each launch rendered its main window offscreen and quit by itself (exit 0).

Output:
- `reopen`: state `open_at_quit [a, b, c-deleted]`, `last_active a`. Result: `state.recent` = `[a, b]`. So a and b opened, c (no file) was skipped, and a opened last as the shown vault. Snapshot [proof/app09-20-reopen-a-b-shown-a.png](../../design/parity/settings/proof/app09-20-reopen-a-b-shown-a.png): "Unlock a" is shown and locked; "Other vaults: b" carries the lock glyph.
- `reopen-arg`: `open_at_quit [a, b]`, `last_active b`, file argument k. Result: `state.recent` = `[k, b, a]`. Snapshot [proof/app09-20-reopen-then-file-argument-k.png](../../design/parity/settings/proof/app09-20-reopen-then-file-argument-k.png): "Unlock k" is shown; "Other vaults: a · b" are both locked, in the saved order.
- `reopen-off`: settings `recent.reopen_at_start: false`. Result: no `state.recent`, nothing opened. Snapshot [proof/app01-17-reopen-off.png](../../design/parity/settings/proof/app01-17-reopen-off.png) shows the welcome screen.
- `pgrep`: no copy Larsal left running.

Tree tests:
- `cargo test -p larsal-ffi --test app09` (copy's Larsal.app from `xcodebuild … -derivedDataPath target/xcode build`, `** BUILD SUCCEEDED **`) → `test result: ok. 18 passed`, including `app09_20_a_start_reopens_the_previous_vaults_then_the_file_argument`.
- lib tests `app09_20_app01_17_reopen_in_saved_order_then_the_shown_one` and `app09_20_session_remembers_its_open_vaults_and_reopens_them` pass.

APP-09.21 (start minimized):
- `start::tests::app09_21_start_minimized_by_flag_or_setting` passes (F08 or S-START-03).
- `AppDelegate.applicationDidFinishLaunching` calls `startsMinimized()`, then hides to the menu bar icon when S-UI-10 is on, else `miniaturize`.
- The minimize of a real window: **needs Mac QA (owner's go)**.

APP-09.28 (launch at login, with the fake service). `LarsalSettingsTests` "APP-09.28 launch at login: the switch shows the system's state and OK registers through the service" passes:
- Cancel registers nothing; OK calls `set(true)`.
- The switch follows the system after a reload; a refused registration shows the error.
- A debug build (APP-09.29) never registers.
- In the driver, OK gives `LoginItem calls [true]` and no login key in either file.
- Mutation S2 (OK registers the old value) fails both.
- `SMAppService` appears only in `SystemLoginItem` (LarsalSettingsParts.swift:49 to 55). No test constructs `SystemLoginItem`, and every test model passes a `FakeLoginItem`.
- The real login item in System Settings › Login Items: **needs Mac QA (owner's go)**.

### B5. The settings file survives broken, huge and wrong-type input

`cargo test -p larsal-ffi --test verify_e5s9 -- --nocapture --test-threads 1` (copy, throwaway HOME, canary) → `test result: ok. 4 passed; 0 failed`. With the default threads → `4 passed` (verify-rust2.log). An earlier run with the default threads failed 2 tests, but the cause was my own probe: two tests shared one scratch folder. I gave each thread its own folder.

```
VERIFY2 APP-01.13: clipboard 0 -> 1, idle "abc" -> 300, recent 0 -> 1, theme classic -> auto, idle.enabled "yes" -> true, font 7 -> 4, min quality 9 -> 4; X-99 kept; settings.json mode 600
VERIFY2 bad file empty (0 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file not-json (39 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file truncated (42 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file array (7 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file number (2 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file null (4 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file bad-utf8 (8 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file nul-bytes (4096 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file deep-nesting (400000 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file huge-valid-json (1048618 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 bad file huge-garbage-50mib (52428800 bytes): defaults, .bad kept, one notice, next OK writes a good file
VERIFY2 settings.json a folder + state.json broken: defaults, notice: Larsal could not read its settings file …/settings.json, so it uses the default settings. Larsal could not read its settings file …/state.json, so it uses the default settings. The old file was kept as …/state.json.bad.
VERIFY2 wrong types: 300 rounds x 119 keys x 2 files, export and import each round, all values typed and in range, no panic
```

What the tests check:
- Each bad file: every one of the 119 listed settings keeps its type, and every number stays in its range (learned by writing i64::MIN and i64::MAX). The notice names the file and comes only once, and the next OK writes a good file.
- Wrong types: each round writes both files with a random hostile value for each of the 119 keys and 9 state keys: null, bool, −1, i64 max and min, u64 max, 1.5e300, −0.0, a 5,000-character text, a mixed array, a 2,000-item list and object, `"auto"` and `""`. Each round then exports and imports the result into a fresh session.
- At start-up, the hidden launch `broken` (settings file `{"clipboard.clear.seconds": 30, oops`) exits 0. It leaves only `settings_debug.json.bad` and shows the D-01-1 notice naming both files: [proof/d01-1-broken-settings-file-notice.png](../../design/parity/settings/proof/d01-1-broken-settings-file-notice.png).
- Tree tests pass: `d01_1_bad_file_reads_defaults_renamed_bad_one_notice`, `d01_1_files_are_owner_only_atomic_and_keep_unknown_keys`, `app01_13_bad_values_clamp_or_read_the_default` and `app01_12_not_writable_names_the_file_and_stores_nothing`.

### B6. The owner's Mac state

Before (19:07) and after (19:29):
- `~/Library/Application Support/Larsal` holds only `instance.lock` (0 B, Oct 27 13:09:39). The folder's modified time is Oct 28 18:32:12 both times. That time comes from round 1's incident; this round did not change it.
- No `com.app` file in the Chrome, Firefox, Brave, Vivaldi, Edge or Chromium host folders.
- `launchctl print gui/$UID | grep -c app.larsal.desktop` = 0; `~/Library/LaunchAgents` has 0 `com.app` files.
- The canary log holds only `listening Wed Oct 28 19:13:20 2026 pid 40735`: **0 connections**. The cargo runs before 19:13 (build only) contacted no agent. With no client connected, `~/.ssh` is never read.
- The throwaway homes `/tmp/e5s9-verify2-home`, `-home3` and `-home4` are empty.
- General pasteboard: the tests only read `changeCount`, and every session in the settings tests is `Session()`, which uses a private pasteboard. Over the 2-minute full Swift run the count stayed at 10330 (10330 → 10330). Over the whole session it went 10327 (19:07) → 10338 (19:29), outside that window. I took a 90 s sample at 19:29:32 to 19:31:02 with no test running: the count rose by itself from 10338 to 10341 at 19:30:17. I attribute the rises outside the test windows to the owner's use of the Mac (LD-206).

### B7. Mutations (private copy, each restored and `cmp`-identical to the shared tree)

Rust, `crates/larsal-ffi/src/larsal_settings.rs`. Each run was `cargo test -p larsal-ffi --lib larsal_settings` plus `--test verify_e5s9 -- --test-threads 1` (`/tmp/e5s9-verify2-scripts/mut-rust.sh`). After the last one: `restored: identical to the pre-mutation file`, `restored: identical to the shared tree`.

| Id | Mutation | Caught by |
|---|---|---|
| R1 | numbers not clamped | `app01_13_bad_values_clamp_or_read_the_default`, `verify2_app01_13_…` |
| **R2** | **Reset no longer keeps `ssh.*` (round-1 F1)** | **`app01_9_reset_keeps_browser_ssh_and_share` (the tree's test, fixed)**, `verify2_s_ssh_01_to_03_…` |
| R3 | S-TIME-04 default 900 | `app01_2_app_defaults`, `app01_11_b_c_d_…`, `app01_11_e_f_g_…`, `app01_13_…`, `verify2_app01_13_…` |
| R4 | S-BRW-15 left out of the weakening list | `app01_11_b_c_d_weakening_list_and_apply` |
| R5 | `MAX_FILE` 64 MiB | `d01_1_bad_file_reads_defaults_renamed_bad_one_notice`, `verify2_broken_and_huge_files_…` |
| R6 | a wrong-typed flag reads the opposite of its default | only `verify2_app01_13_…` (advisory A1) |
| R7 | the shown vault not reopened last | `app09_20_app01_17_reopen_in_saved_order_then_the_shown_one`, `app09_20_session_remembers_…` |
| R8 | files written 0644 | `d01_1_files_are_owner_only_atomic_and_keep_unknown_keys`, `verify2_app01_13_…` |
| R9 | forgetting (S-START-05 off) keeps `state.recent` | `app01_7_forgetting` |
| R10 | S-START-04 no longer turns S-LOCK-04 off | `app01_8_minimize_after_unlock_stores_lock_on_minimize_off` |

Swift (`/tmp/e5s9-verify2-scripts/mut-swift.sh`): each mutation ran build-for-testing, then `LarsalSettingsTests`, `LarsalSettingsEffectsTests`, `LarsalSettingsParityTests` and `VerifyE5S9Tests`. Each was restored and checked `identical to the shared tree`. After the last one I rebuilt the original: `rebuilt original: exit 0`.

| Id | Mutation | Caught by (exit 65) |
|---|---|---|
| S1 | `LockSettings(store:)` reads S-LOCK-02 from `lock.on_minimize` | only the Verify driver, VerifyE5S9Tests.swift:265 (advisory A2) |
| S2 | OK registers the old login value | "APP-09.28 launch at login…" (LarsalSettingsTests.swift:284), the driver (:157) |
| S3 | S-FILE-01 on forces nothing | "APP-01.6 auto-save forces its partners on and disables them" (:233, :236) |
| S4 | dependent controls never disabled | "APP-01.5 dependent controls are disabled and keep their values" (:215, :218, :222), the driver (:226) |
| S5 | S-VIEW-01 dark gives the light look | "Mac QA snapshots keep the look they asked for over S-VIEW-01" (LarsalSettingsEffectsTests.swift:65), the driver (:185) |
| S6 | the search clear waits a constant 5 minutes | "APP-01.27 a, b" (LarsalSettingsEffectsTests.swift:48) |
| S7 | Cancel keeps the edits | "APP-01.3 Cancel drops every edit" (LarsalSettingsTests.swift:205, :206) |

17 of 17 caught; 15 by the tree's own tests.

### B8. Other suites and linters

- `cargo test -p larsal-ffi` (copy, throwaway HOME, canary) gave these results:
  - all suites of the tree ok: lib 96, clipboard 9, edit 19, generator 12, key_pages 2 (1 ignored), memory 1, messages 7, new_vault 11, option_a 8 (1 ignored), reports 3, session 11, ssh 16 and vault_settings 6;
  - the 25 E5-S9 lib tests (`app01_*`, `app09_20_*`, `app09_21_*`, `d01_1_*`, `ld204_*`, `s_ssh_01_*`, `app01_25_*`) are all ok;
  - the run stopped at my own verify_e5s9 (the shared-folder slip, fixed above), so `--test app09` ran on its own: 18 passed.
- `cargo test -p larsal-core` → 29 suites, 712 passed, 0 failed, 23 ignored.
- In the copy, without my private test: `cargo clippy -p larsal-ffi --all-targets -- -D warnings` → exit 0; `cargo clippy -p larsal-ffi --test app09 -- -D warnings` → exit 0; `cargo fmt -p larsal-ffi --check` and `-p larsal-core --check` → exit 0.
- Shared tree:
  - `swift format lint --strict` on the 6 `LarsalSettings*.swift` files and the 3 settings test files → exit 0;
  - `swiftlint 0.65.1 lint --strict --quiet` on the same 9 files → exit 0;
  - `scripts/check-names.sh` → `names: PASS (3093 files scanned, 15 vault files name-only)`.

## Fails

None.

## Needs Mac QA (owner's go), not fails

- The real login item (APP-09.28-a, APP-01.37 a): System Settings › Login Items lists Larsal; turning it off removes it, and the switch follows the list.
- Start minimized on a real window (APP-09.21-a and b).
- On the real settings window (key window): closing it is OK (APP-01.3), Escape is Cancel, plus the focus ring and the Tab order.
- Appearance auto following a macOS dark-mode switch (APP-01.28 a). This would change the owner's system appearance, so I did not run it.

## Advisories (not blocking)

- A1. D-01-5: a flag of the wrong type reads as its default. My probe pins this, but no tree test does (mutation R6). Add one assert to `app01_13_bad_values_clamp_or_read_the_default`: `"lock.idle.enabled": "yes"` reads true.
- A2. S-LOCK-02 to -04 reach `LockSettings(store:)`, but only the Verify driver checks it (mutation S1). Add to "APP-01.3 OK stores every page…": after storing them, check `!lock.onScreenLock && !lock.onUserSwitch && lock.onMinimize`.
- A3. An imported settings file with S-SSH-01 on starts Larsal's agent at once. APP-01.11 allows this. The lead may add S-SSH-01 "turned on" to the LD-54 list.
- A4. The APP-01 count table should say 11 ids for Entry management and 175 in total.
- A5. APP-01.27's restart of the countdown on a change of selected entry or screen has no test of its own (the Builder's open issue).
- A6. These wait for the lead, as the Builder listed: no drawn OK/Cancel/Reset/Import/Export, the S-START-08 mockup line, W-04 to W-07 and W-10 rows, S-UI-07, and the E5-S8 `min_quality` handoff.
- Outside E5-S9: `AccessibilityWalkTests` (AT-K06, another story's work in progress) fails 11 cases in the full Swift run of the 19:07 tree. Its screens are not settings screens.

## Cleanup

- Stopped my canary by its PID (40735).
- Deleted `/tmp/e5s9-verify2-copy`, `/tmp/e5s9-verify2-dd`, `/tmp/e5s9-verify2-target`, `/tmp/e5s9-verify2-a0920`, `/tmp/e5s9-verify2-rust`, `/tmp/e5s9-verify2-tests`, `/tmp/e5s9-verify2-home*`, `/tmp/e5s9-verify2-canary`, `/tmp/e5s9-verify2-scripts` and `/tmp/e5s9-verify2-logs` (after this report took their numbers).
- Also removed `/tmp/e5s9-tests`, the empty folder the tree's Swift tests left behind in my runs (`rmdir`, it was empty).
- Not mine, left alone: `/tmp/parity-tools` (shared check tools) and `/tmp/a09-manual`.
- Afterwards: `pgrep -fl e5s9-verify2` finds no process, and no `/tmp/e5s9-*` folder is left.

Files changed in the shared tree:
- this report (round 2 on top, round 1 below);
- `design/parity/settings/`: report.md, report.html, findings.json, app/, diff/, and the 4 proof images replaced by round-2 ones;
- the E5-S9 status line in plan/epics.md.

No product code was edited.

---

## Round 1 (2026-10-28): failed (1), kept for history

Story E5-S9 (plan/epics.md): Larsal settings from the settings inventory (APP-01); APP-09.20, 09.21, 09.28 (LD-153). Check: every setting has a control or a written reason why not.
Verify agent, round 1, 2026-10-28. I did not build or check this story.

**Verdict: failed (1).** Part A (design parity) passes 7 of 7 frames in light and dark. Part B passes, with one gap: card case APP-01.9 a ("S-SSH-01 still on" after Reset) is not proven by any test of the tree. The behaviour is right (my probe passes), but a reset that drops the SSH values passes every test of the story (mutation R5). The fix is one line in a test (F1 below).

### How I ran it

- Private copy: `rsync -a --exclude target --exclude larsal-shots` of the project to `/tmp/e5s9-verify-copy` at 18:13, then crates/ and macos/ again at 18:15. Own build folders: `/tmp/e5s9-verify-dd` (xcodebuild), `/tmp/e5s9-verify-target` (cargo). Every folder was deleted at the end.
- Another story was being built in the shared tree at the same time (E5-S10: `crates/larsal-ffi/src/saving.rs`, new at 18:16, and `edit.rs`). The copy holds that work in progress. The only change I made outside my own test files was in that story's code, so it would build: one test in `saving.rs` (line 683) called the private `LarsalSettingsStore::save`. In the copy only, I changed it to the public `Session::save_settings`. No E5-S9 file was changed, except for the mutation runs, each restored and `cmp`-identical to the shared tree.
- My own test files lived only in the copy: `macos/LarsalTests/VerifyE5S9Tests.swift` (the driver, 3 tests) and `crates/larsal-ffi/tests/verify_e5s9.rs` (5 tests).
- Canary: `SSH_AUTH_SOCK` (and `TEST_RUNNER_SSH_AUTH_SOCK` for xcodebuild) pointed at a socket of my own, `/tmp/e5s9-verify-canary/agent.sock` (pid 12421), which logs every connection. Result: **0 connections** over all runs.
- No visible window, no focus taken. Chrome ran headless. Views rendered in borderless windows at x −20000 that were never ordered front. Larsal ran only as a hidden launch (`LARSAL_TEST_HIDDEN`, own `LARSAL_TEST_INSTANCE_DIR`).
- The reference app was not used. The spot check of defaults is optional, and the card's defaults table already holds them.

### Part A: design parity, section `settings`

Report: [design/parity/settings/report.md](../../design/parity/settings/report.md) (with [report.html](../../design/parity/settings/report.html) and findings.json). It lists every command and its output.

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / runs > 2 pt | Verdict |
|---|---|---|---|---|---|---|---|
| settings-settings-general | present | present | 0.68 % (0.43 %) / 0.69 % (0.45 %) | 0 (3 card words) | 0 / 0 | 0 | PASS |
| settings-settings-security | present | present | 0.61 % / 0.60 % | 0 | 0 / 0 | 0 | PASS |
| settings-settings-auto-type | present | present | 0.48 % / 0.48 % | 0 | 0 / 0 | 0 | PASS |
| settings-settings-browser-integration | present | present | 0.33 % / 0.33 % | 0 | 0 / 0 | 0 | PASS |
| settings-settings-ssh-agent | present | present | 0.32 % / 0.33 % | 0 | 0 / 0 | 0 | PASS |
| settings-settings-shared-groups | present | present | 0.34 % / 0.34 % | 0 | 0 / 0 | 0 | PASS |
| settings-settings-shortcuts | present | present | 0.36 % / 0.37 % | 0 | 0 / 0 | 0 (1 run explained) | PASS |

Commands (in the copy, in this order):
1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0. Against the shared reference, manifest.json is byte-equal. Of the 14 settings PNGs, 11 are byte-equal and 3 (light browser-integration, security, shortcuts) differ by 68, 1 and 1 raw pixels, with pixelmatch 0 changed pixels each. The shared reference is current.
2. `scripts/build-core.sh` → exit 0, `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`.
3. `xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s9-verify-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `** TEST BUILD SUCCEEDED **`.
4. `xcodebuild … test-without-building -skip-testing:LarsalUITests` (canary env) → `✔ Test run with 167 tests in 29 suites passed after 87.818 seconds`, `** TEST EXECUTE SUCCEEDED **`. These are the tree's 164 tests plus my 3. `LarsalSettingsEffectsTests`, `LarsalSettingsFrameTests`, `LarsalSettingsParityTests`, `LarsalSettingsTests` and `VerifyE5S9Tests` all pass. Output: target/parity/behaviour.log.
5. Snapshots: `LarsalSettingsFrameTests` "Option A settings frame, offscreen, light and dark" wrote `larsal-shots/{light,dark}/settings-settings-*.png` and `.ax.json`. All 28 files are byte-equal (`cmp`) to the shared `larsal-shots/`. The copies checked are in `design/parity/settings/app/`, and the diffs in `design/parity/settings/diff/`.
6. `node design/parity/tools/mockup-dom.mjs settings` → `light: 7 frames, 215 text runs`, `dark: 7 frames, 215 text runs`.
7. `swift design/parity/tools/ocr.swift larsal-shots/{light,dark}/settings-settings-*.png` → 14 images read.
8. `node design/parity/tools/compare.mjs settings`. The first run gave `settings: 5/7 PASS`: general had 3 missing strings, and in shortcuts "⌘⌫" was Δ −4, 0.5. After the Verify notes it gave `settings: 7/7 PASS`.

Verify notes added to `design/parity/tools/notes.mjs` (two small insertions, one in RULES and one in NOTES, marked "E5-S9 settings (Verify 2026-10-28)"):
- Card words over the mockup (BUILD-AND-VERIFY order 2). Each rule still checks the app's text against a pattern:
  - "Save after every change" is shown as "Save changes as you make them" (S-FILE-01 "Shown as", LD-167, W-04).
  - "Asks GitHub once a day. …" is shown as "… once a week. …" (S-START-09 "once a week", APP-01.19: next check now + 7 days).
  - "{DB_FILENAME}.old.larsalvault" is shown as "{FILE_NAME}.old.larsalvault" (APP-01.2, APP-05.20).
- Shortcuts "⌘⌫" (Delete Entry): the run is 4 pt wider than drawn. Its right edge is equal (847 in both themes) and y is within 0.5 pt. The bundled `ibm-plex-sans-latin-400-normal.woff2`, the mockup's own file, has no ⌘, ⇧ or ⌫ glyph. I checked this with Core Text (`CTFontGetGlyphsForCharacters`: "⌘ no glyph", "⌫ no glyph", "⇧ no glyph", "E has glyph"). So Chrome and Core Text each fall back to a system face. Every ⌘ run is 1 to 1.5 pt wider for this reason, and ⌫ adds 2.5 pt. This is a font fallback, not layout. The rows and the key column are within 2 pt.

Checks 6 and 7: the 7 `Parity settings-settings-*` tests pass (nav, back and forward, switches, steppers, the login item through a fake, and the controls of later stories disabled). Every control has a name: 0 unnamed in 14 trees. Contrast: 42 pairs, lowest 4.87:1. By eye, app against reference for general (light) and shortcuts (dark): same layout, type, tiles and switches. The only differences are the window buttons (the window draws them) and the texts above.

### Part B: every setting has a control or a written reason

#### B1. Count of setting ids

The script `/tmp/e5s9-verify-scripts/count.py` reads every table row of spec/app/APP-01-settings.md before "## Rules". It expands the ranges (S-BRW-02 to -08, S-STATE-07 to -13), adds both ids of each generator row, and adds the S-NOMAC bullets and S-DEBUG-01. It then compares the result with security/parity/E5-S9-settings-inventory.md.

```
card ids: 175
inventory rows: 175 unique 175
in card not in inventory: []
in inventory not in card: []
rows with neither control nor reason: []
rows with a control: 85
per area: START 12, FILE 8, ENTRY 11, UI 12, AT 10, TIME 6, LOCK 4, CONV 5, PRIV 1, BRW 27, KEYS 1, SSH 3, SHARE 4, VIEW 7, SEARCH 2, PWGEN 22, MSG 3, STATE 17, CFG 5, NOMAC 14, DEBUG 1
```

The card's count table says 174 because its Entry management line counts 10 ids for 11 rows (S-ENTRY-01 to -11). The inventory notes this. The card's count table should say 11 and 175 (advisory A4).

#### B2. Keys, scopes and defaults against the card

`/tmp/e5s9-verify-scripts/keys.py` compares the Key column with every `d("S-…", "<key>", scope, kind)` in `crates/larsal-ffi/src/larsal_settings.rs` (137 definitions). Every key is equal. The 2 "mismatches" the script printed are its own parsing: the card cells hold "`generator.password.special` (simple view)" and "`generator.password.signs` (advanced view's special group)". The range ids S-BRW-02 (`browser.safari`) and S-STATE-07 to -13 were checked by hand. Every "Mac" row is in state.json (S-FILE-08, S-UI-04, S-LOCK-01, S-VIEW-05, S-SSH-02, S-SSH-03, S-CFG-02). Every default equals the card's, with the Larsal column's D values: S-START-08 off, S-START-09 off, S-FILE-05 on, S-FILE-06 `{FILE_NAME}.old.larsalvault`, S-TIME-04 300, S-ENTRY-11 off, S-UI-01 `system`/`en`. The rows not stored are exactly the card's S rows plus S-START-02 (kept by the OS) and S-BRW-03 to -08 (browser files).

#### B3. Settings driven through their controls (Verify driver, 34 ids on 5 pages)

`VerifyE5S9Tests` (private copy) builds the settings window offscreen (`SettingsScreen`), presses each control through the accessibility tree, and presses OK (`model.ok()`, the same call the window's close makes). It then reads `settings.json` / `state.json` in a throwaway folder under `/tmp/e5s9-verify-tests`. Before the press it checks that the key is absent from the files and that `defaultValue(key)` is the card's default. After OK it checks the part of the app that uses the value. Run alone:

`xcodebuild … test-without-building -only-testing:LarsalTests/VerifyE5S9Tests` → `✔ Test run with 3 tests in 1 suite passed after 9.925 seconds`. It also passes in the full run.

Tests:
- "Verify E5-S9 General: switches, stepper, appearance and login item reach their users"
- "Verify E5-S9 Security: timeouts and lock switches reach the clipboard, the lock timers and the search"
- "Verify E5-S9 Auto-Type, Browser and Shared groups: switches store under their keys"

| Id | Page | Control pressed | Key | Card default | Stored after OK |
|---|---|---|---|---|---|
| S-START-02 | General | "Login" | none (OS) | off | `LoginItem.set(true)` on OK, calls `[true]`; no login key in either file |
| S-START-05 | General | "Recent" | recent.remember | true | false |
| S-START-06 | General | "Less" ×4 | recent.count | 5 | 1 |
| S-START-07 | General | "Reopen" | recent.reopen_at_start | true | false |
| S-FILE-01 | General | "Autosave" | save.after_every_change | true | false |
| S-FILE-02 | General | "Save on lock" | save.on_lock | true | false |
| S-FILE-05 | General | "Backup" | backup.enabled | true | false |
| S-ENTRY-02 | General | "Confirm" | entry.confirm_recycle | false | true |
| S-ENTRY-03 | General | "Autogen" | entry.autogen_password | false | true |
| S-UI-07 | General | "Colour" | display.color_passwords | false | true |
| S-VIEW-01 | General | "Dark" | ui.theme | "auto" | "dark" |
| S-TIME-01 | Security | "Clipboard" | clipboard.clear.enabled | true | false |
| S-TIME-02 | Security | "More" | clipboard.clear.seconds | 10 | 15 |
| S-TIME-03 | Security | "Idle lock" | lock.idle.enabled | true | false |
| S-TIME-04 | Security | "More" #2 | lock.idle.seconds | 300 | 360 |
| S-TIME-05 | Security | "Clear search" | search.clear_when_idle | false | true |
| S-TIME-06 | Security | "More" #3 (enabled only after S-TIME-05, APP-01.5) | search.clear_after_minutes | 5 | 6 |
| S-LOCK-02 | Security | "Screen lock" | lock.on_screen_lock | true | false |
| S-LOCK-03 | Security | "User switch" | lock.on_user_switch | true | false |
| S-LOCK-04 | Security | "Minimize" | lock.on_minimize | false | true |
| S-CONV-02 | Security | "Editor" | display.hide_password_in_editor | true | false |
| S-CONV-05 | Security | "Notes" | display.hide_notes | false | true |
| S-AT-01 | Auto-Type | "Title" | autotype.match_title | true | false |
| S-AT-05 | Auto-Type | "Expired" | autotype.hide_expired | false | true |
| S-AT-06 | Auto-Type | "Relock" | lock.relock_after_autotype | false | true |
| S-AT-08 | Auto-Type | "More" #3 | autotype.retype_seconds | 15 | 16 |
| S-AT-10 | Auto-Type | "More" #2 (step 5) | autotype.key_delay_ms | 25 | 30 |
| S-BRW-01 | Browser Integration | "Browser" | browser.enabled | false | true |
| S-BRW-10 | Browser Integration | "Unlock" | browser.unlock_on_request | true | false |
| S-BRW-12 | Browser Integration | "Best" | browser.best_match_only | false | true |
| S-BRW-15 | Browser Integration | "Never ask" | browser.never_ask_access | false | true |
| S-SHARE-01 | Shared Groups | "Import" | share.import | false | true |
| S-SHARE-02 | Shared Groups | "Export" | share.export | false | true |
| S-SHARE-03 | Shared Groups | "Quiet" | share.quiet | false | true |

How each value reaches the code that uses it (driver output):
- General:
  - S-START-07 off: with the default (on), `rememberOpenVaults()` writes `state.open_at_quit`; after OK with it off, `state.open_at_quit` is absent.
  - S-START-06 = 1: after a second demo vault opens, `recentVaults().count` = 1.
  - S-ENTRY-03: `beginNew(…).passwordChars` is 0 before and 20 after (the stored generator length).
  - S-ENTRY-02: `MainWindowModel.main.askBeforeBin` = true.
  - S-VIEW-01 dark: `Appearance.apply` gives `NSApp.appearance` = darkAqua.
  - S-START-05 off: `recent.reopen_at_start` is stored false (APP-01.7), and the recent list after an open is empty (APP-01.14).
- Security:
  - S-TIME-02: `copyField` on a demo entry (private pasteboard) returns a countdown of 15 s; with S-TIME-01 off it returns 0.
  - S-TIME-03/04 and S-LOCK-02 to -04: `LockSettings(store:)` reads idle 360 s, and screen false, user false, minimize true; with S-TIME-03 off, `idleEnabled` is false.
  - S-TIME-05/06: `SearchClearTimer` with a 25 ms minute keeps "mail" at 80 ms and clears it after 6 × 25 ms.
- Browser: S-BRW-15 on, exported and imported into fresh settings, lists `["S-BRW-15 off -> on"]` (LD-54).
- Reset keeps `share.quiet` and `browser.never_ask_access` (APP-01.9).
- Auto-Type (E8), Browser (E7), Shared groups (E11): the store reads the new values. Their users come with those stories, as the inventory says.

SSH page (S-SSH-01 to -03). Turning S-SSH-01 on and pressing OK in a Swift test would start Larsal's agent at its default socket in the user's settings folder. So the SSH reach is proven in Rust, with throwaway agent options. The page's switch press is covered by "Parity settings-settings-ssh-agent".
- `verify_s_ssh_01_to_03_reach_apps_agent_in_a_throwaway_folder` → `S-SSH-01..03: on -> Larsal's agent at /tmp/e5s9-verify-rust/ssh-26978/agent.sock, -02 and -03 in state.json (this Mac), off -> stopped`.
- Tree test `larsal_settings::tests::s_ssh_01_ok_turns_apps_agent_on_and_off` passes.
- Generator (S-PWGEN): tree tests `ld204_generator_options_persist_in_the_store` and `edit::tests::app01_25_s_entry_03_new_entry_password` pass.

#### B4. APP-09.20, APP-09.21, APP-09.28

- APP-09.20 (reopen, locked, order, last shown). Hidden launches of the debug Larsal (`/tmp/e5s9-verify-scripts/a0920.sh`: `LARSAL_TEST_HIDDEN=1`, own `LARSAL_TEST_INSTANCE_DIR`, `LARSAL_DEBUG_SNAPSHOT`). Each launch rendered its main window offscreen and quit. Vaults are copies of testdata/option-a-personal.larsalvault in `/tmp/e5s9-verify-a0920/v`.
  - `reopen`: state `open_at_quit [a, b, c-deleted]`, `last_active a`. Exit 0. `state.recent` = `[a, b]`: a, b opened, c skipped, a opened last. Snapshot [proof/app09-20-reopen-a-b-shown-a.png](../../design/parity/settings/proof/app09-20-reopen-a-b-shown-a.png): "Unlock a" is shown and locked; "Other vaults: b" carries the lock glyph.
  - `reopen-arg`: `open_at_quit [a, b]`, `last_active b`, file argument k. `state.recent` = `[k, b, a]`. Snapshot [proof/app09-20-reopen-then-file-argument-k.png](../../design/parity/settings/proof/app09-20-reopen-then-file-argument-k.png): "Unlock k" is shown; "Other vaults: a · b" are both locked, in the saved order.
  - `reopen-off`: settings `recent.reopen_at_start: false`. No `state.recent`, nothing opened. Snapshot [proof/app01-17-reopen-off.png](../../design/parity/settings/proof/app01-17-reopen-off.png) shows the welcome screen.
  - Tree tests pass: `cargo test -p larsal-ffi --test app09` → 18 passed, including `app09_20_a_start_reopens_the_previous_vaults_then_the_file_argument`. Also lib `app09_20_app01_17_reopen_in_saved_order_then_the_shown_one` and `app09_20_session_remembers_its_open_vaults_and_reopens_them`. `pgrep`: no Larsal left running.
- APP-09.21 (start minimized): `start::tests::app09_21_start_minimized_by_flag_or_setting` passes (F08 or S-START-03). `AppDelegate` calls `startsMinimized()` and then `miniaturize`. The minimize of a real window: **needs Mac QA (owner's go)**.
- APP-09.28 (launch at login with the fake service): `LarsalSettingsTests` "APP-09.28 launch at login: the switch shows the system's state and OK registers through the service" passes:
  - Cancel registers nothing; OK calls `set(true)`.
  - The switch follows the system after a reload; a refused registration shows the error.
  - A debug build (APP-09.29) never registers.
  - In the driver, OK gives calls `[true]` and no key in either file.
  - Mutation S2 (OK sets the old value) fails both tests.
  - The real `SMAppService` login item (System Settings › Login Items): **needs Mac QA (owner's go)**.

#### B5. The settings file survives broken, huge and wrong-type input

`cargo test -p larsal-ffi --test verify_e5s9 -- --nocapture --test-threads 1` (private copy) → 4 passed (5 with the F1 probe):

```
VERIFY APP-01.13: 0 -> 1, "abc" -> 300, 7 -> 4, 9 -> 4, recent 0 -> 1, classic -> auto; X-99 kept; mode 600
VERIFY bad file empty (0 bytes): defaults, .bad kept, one notice
VERIFY bad file not-json (37 bytes): defaults, .bad kept, one notice
VERIFY bad file truncated (42 bytes): defaults, .bad kept, one notice
VERIFY bad file array (7 bytes): defaults, .bad kept, one notice
VERIFY bad file number (2 bytes): defaults, .bad kept, one notice
VERIFY bad file null (4 bytes): defaults, .bad kept, one notice
VERIFY bad file bad-utf8 (8 bytes): defaults, .bad kept, one notice
VERIFY bad file nul-bytes (4096 bytes): defaults, .bad kept, one notice
VERIFY bad file deep-nesting (200000 bytes): defaults, .bad kept, one notice
VERIFY bad file huge-valid-json (1048625 bytes): defaults, .bad kept, one notice
VERIFY bad file huge-garbage-50mib (52428800 bytes): defaults, .bad kept, one notice
VERIFY settings.json a folder + state.json broken: defaults, notice
VERIFY wrong types: 400 rounds x 126 keys x 2 files, all values in range, no panic
VERIFY S-SSH-01..03: on -> Larsal's agent at /tmp/e5s9-verify-rust/ssh-26978/agent.sock, -02 and -03 in state.json (this Mac), off -> stopped
```

What the tests check:
- Each bad file: every setting is still listed with its type, numbers are in the card's range, the notice names the file once, and the next OK writes a good file.
- Wrong types: each round writes both files with values of the wrong type or out of range for every key: null, bool, −1, i64 max and min, u64 max, 1.5e300, −0.0, 5,000-character texts, mixed arrays, 2,000-item lists and objects. Each round then exports and imports the result.
- At start-up, the hidden launch `broken` (settings file `{"clipboard.clear.seconds": 30, oops`) exits 0, leaves `settings_debug.json.bad`, and shows the D-01-1 notice naming both files: [proof/d01-1-broken-settings-file-notice.png](../../design/parity/settings/proof/d01-1-broken-settings-file-notice.png).
- Tree tests `d01_1_bad_file_reads_defaults_renamed_bad_one_notice`, `d01_1_files_are_owner_only_atomic_and_keep_unknown_keys`, `app01_13_bad_values_clamp_or_read_the_default` and `app01_12_not_writable_names_the_file_and_stores_nothing` pass.

#### B6. The owner's Mac state

Before (18:12) and after (18:36):
- `~/Library/Application Support/Larsal` holds only `instance.lock` (0 B, Oct 27 13:09).
- No `app.larsal.browser.json` in the Chrome, Firefox, Brave, Vivaldi or Edge host folders.
- `launchctl print gui/$UID | grep -c app.larsal.desktop` = 0; `~/Library/LaunchAgents` has 0 `com.app` files.

One thing changed, and my own test caused it (see "Incident" below): the folder's modified time moved from Oct 27 13:09:39 to Oct 28 18:32:12, while its contents stayed the same.

Clean runs of the tree's tests with a throwaway home:
- Rust: `HOME=/tmp/e5s9-verify-home2 cargo test -p larsal-ffi --lib --test clipboard … --test vault_settings` → 13 suites, 199 passed, 0 failed. `--test app09` → 18 passed. Afterwards `/tmp/e5s9-verify-home2` is still empty, and the owner's folder time is unchanged (18:32:12).
- Swift: `TEST_RUNNER_HOME=/tmp/e5s9-verify-home3 xcodebuild … test-without-building -skip-testing:LarsalUITests` → `✔ Test run with 167 tests in 29 suites passed after 88.728 seconds`. `/tmp/e5s9-verify-home3` is still empty, and the owner's folder time is unchanged.

The tree's tests write nothing under a home folder:
- Swift sessions are `Session()` (memory store, private pasteboard).
- Settings folders are under `/tmp/e5s9-tests`.
- The login item is `FakeLoginItem`.
- The SSH probe is a fake.
- No Swift test of the story presses OK with S-SSH-01 on.
- `SMAppService` appears only in `SystemLoginItem`.

Other checks:
- ssh-agent: the canary got 0 connections. Rust SSH tests use `set_ssh_options` with throwaway paths.
- General pasteboard: the tests only read `changeCount`, and no test or app path in a test session writes to it. Over my whole session the count went 10254 → 10284, and over the 89 s Swift run 10284 → 10291. The tree's change-count tests (`GeneratorTests`, `LockSignalsTests`, `ScreenTests`, `ParityStatesTests`) passed in both runs, so nothing changed it inside their windows. I attribute the rest to the owner's use of the Mac (LD-206). In a 90 s sample with no test running, the count rose 3 times on its own (10291 → 10294, at 40, 66 and 70 s).

**Incident (my test, not the product):**
- What happened: my Rust robustness test `verify_wrong_types…` imported hostile settings into a `Session` without throwaway SSH options. When an import set `ssh.enabled: true`, `apply_ssh` started Larsal's own agent at its default socket, `~/Library/Application Support/Larsal/agent.sock`, and removed the socket when the agent stopped. That was at 18:27 to 18:32: in the full larsal-ffi run and in the Rust mutation runs.
- How I confirmed it: I re-ran the test with `HOME=/tmp/e5s9-verify-home`. `agent.sock` appeared there at 18:37:51 and was gone after the run.
- What was left: nothing. The owner's folder holds only `instance.lock`, and the canary had 0 connections, so the owner's ssh-agent was not contacted. With no client connected, `~/.ssh/known_hosts` is never read.
- The product behaved as designed: APP-01.11 Apply applies an imported S-SSH-01. The card does not list S-SSH-01 among the weakening imports.
- Lesson for later Verify runs: run import tests with a throwaway HOME, or call `set_ssh_options` first.

#### B7. Mutations (private copy, each restored, `cmp`-identical to the shared tree)

Rust, `crates/larsal-ffi/src/larsal_settings.rs`. Each run was `cargo test -p larsal-ffi --lib larsal_settings` plus `--test verify_e5s9`:

| Id | Mutation | Caught by |
|---|---|---|
| R1 | numbers not clamped | `app01_13_bad_values_clamp_or_read_the_default`, `verify_app01_13_examples`, `verify_wrong_types…` |
| R2 | `if fits` removed from read_json | none: equivalent mutant (an over-size file is never read, so its empty bytes fail to parse anyway) |
| R2b | `MAX_FILE` 64 MiB | `d01_1_bad_file_reads_defaults_renamed_bad_one_notice`, `verify_broken_files…` |
| R3 | S-BRW-15 not in the weakening list | `app01_11_b_c_d_weakening_list_and_apply` |
| R4 | reopen keeps deleted files | `app09_20_app01_17_reopen_in_saved_order_then_the_shown_one` |
| **R5** | **Reset no longer keeps `ssh.*`** | **none of the tree's tests** (F1); my probe `verify_app01_9_a_ssh_on_survives_reset` fails with it and passes without it |
| R6 | S-TIME-04 default 900 | `app01_2_app_defaults`, `app01_13_…`, `app01_11_e_f_g_…`, `app01_11_b_c_d_…`, `verify_app01_13_examples` |
| R7 | files 0644 | `d01_1_files_are_owner_only_atomic_and_keep_unknown_keys`, `verify_app01_13_examples` |
| R8 | the shown vault not reopened last | `app09_20_app01_17_…`, `app09_20_session_remembers…` |
| R9 | a wrong-typed flag reads the opposite of its default | none (advisory A1) |

Swift (build-for-testing, then the 4 settings suites plus the driver):

| Id | Mutation | Caught by |
|---|---|---|
| S1 | `LockSettings(store:)` reads S-LOCK-02 from `lock.on_minimize` | only the Verify driver, at "Verify E5-S9 Security", line 243 (advisory A2) |
| S2 | OK registers the old login value | "APP-09.28 launch at login…" at LarsalSettingsTests.swift:284, and the driver at line 176 |
| S3 | dependent controls never disabled | "APP-01.5 dependent controls are disabled and keep their values" at LarsalSettingsTests.swift:215, 218, 222 |

After the mutations I rebuilt the original: `build-for-testing` exit 0.

#### B8. Other suites and linters

- `cargo test -p larsal-ffi` (copy, canary) → all suites ok: lib 95 (80 of E5-S9 and before, plus E5-S10's new ones), clipboard 9, edit 19, generator 12, key_pages 2, memory 1, messages 7, new_vault 11, option_a 8, reports 3, session 11, ssh 15, vault_settings 6, verify_e5s9 4.
- `cargo test -p larsal-core` → 29 suites, 712 passed, 0 failed.
- `cargo clippy -p larsal-ffi --all-targets`: no finding in an E5-S9 file. The only findings are 4 in `edit.rs` (E5-S10's unused imports, work in progress) and 1 in my private test. `cargo fmt -p larsal-ffi --check`: diffs only in E5-S10's `saving.rs` and my private test. `cargo fmt -p larsal-core --check` → exit 0.
- `swift format lint --strict` on the 6 `LarsalSettings*.swift` files and the 3 settings test files (shared tree) → exit 0. `swiftlint 0.65.1 lint --strict --quiet` on the same files → exit 0.
- `scripts/check-names.sh` (shared tree, after my writes): result in the epics line.

### Fails

**F1. APP-01.9 a: no test proves that S-SSH-01 stays on after Reset.**

The tree test `app01_9_reset_keeps_browser_ssh_and_share` stores `ssh.enabled` **false**, which is the default. A reset that drops the SSH page's values therefore passes it, and passes every other test of the story (mutation R5). The card's case says "S-BRW-01 and S-SSH-01 still on".

Smallest fix: in `crates/larsal-ffi/src/larsal_settings.rs` `app01_9_reset_keeps_browser_ssh_and_share`, store `flag("ssh.enabled", true)` and add `assert!(s.flag("ssh.enabled".into()))` after `s.reset()`. A store-level save does not start Larsal's agent. The test must then fail with `"ssh."` removed from the kept prefixes.

### Needs Mac QA (owner's go), not fails

- The real login item (APP-09.28-a): System Settings › Login Items lists Larsal, turning it off removes it, and the switch follows the list.
- Start minimized on a real window (APP-09.21-a and b).
- On the real settings window (key window): closing it is OK (APP-01.3), Escape is Cancel, plus the focus ring and the Tab order.
- Appearance auto following a macOS dark-mode switch (APP-01.28 a). This would change the owner's system appearance, so I did not run it.

### Advisories (not blocking)

- A1. D-01-5: a flag of the wrong type reads as its default, but no test pins this (mutation R9 survives). Add one assert to `app01_13_bad_values_clamp_or_read_the_default`, for example `"lock.idle.enabled": "yes"` reads true.
- A2. S-LOCK-02 to -04 and S-START-04 reach `LockSettings(store:)`, but only the Verify driver checks it (mutation S1). Add the driver's line to "APP-01.3 OK stores every page…": `!lock.onScreenLock && !lock.onUserSwitch && lock.onMinimize` after storing them.
- A3. An imported settings file with S-SSH-01 on starts Larsal's agent at once. The card allows this (APP-01.11 does not list S-SSH-01), but Larsal's agent publishes a socket that other programs on this Mac can use. The lead may add S-SSH-01 "turned on" to the LD-54 list.
- A4. The APP-01 count table should say 11 ids for Entry management and 175 in total. 175 is the number the card's rows give.
- A5. These wait for the lead, as the Builder listed: no drawn OK/Cancel/Reset/Import/Export, the S-START-08 mockup line, W-04 to W-07 and W-10 rows, S-UI-07, and the E5-S8 `min_quality` handoff.

### Cleanup

- Stopped my canary by its PID (12421).
- Deleted `/tmp/e5s9-verify-copy`, `/tmp/e5s9-verify-dd`, `/tmp/e5s9-verify-target`, `/tmp/e5s9-verify-a0920`, `/tmp/e5s9-verify-tests`, `/tmp/e5s9-verify-rust`, `/tmp/e5s9-verify-home*`, `/tmp/e5s9-verify-canary`, `/tmp/e5s9-verify-scripts` and `/tmp/e5s9-verify-logs` (after this report took their numbers).
- Also removed `/tmp/e5s9-tests`, the empty folder the tree's Swift tests leave behind (`rmdir`).
- Not mine, left alone: `/tmp/parity-tools` (shared check tools).

Files changed in the shared tree:
- this report
- `design/parity/settings/` (report.md, report.html, findings.json, app/, diff/, proof/)
- two insertions in `design/parity/tools/notes.mjs`
- the E5-S9 status line in plan/epics.md
