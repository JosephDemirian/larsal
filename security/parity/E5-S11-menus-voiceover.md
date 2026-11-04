# E5-S11 Menus, shortcuts, VoiceOver, light and dark: Verify

Date 2026-10-28. Story E5-S11 (plan/epics.md), cards APP-08 (all rules), APP-09.21 and APP-09.22, APP-01.23 for S-VIEW-06, check AT-K06 (plan/attacks-and-checks.md). I did not build or check this story. Inputs for round 3: the Builder's fix report for round 2's two fails, Checker 1's round 2 finding and the LD-219 addendum, and Checker 1's "passed" on those fixes. Rounds 2 and 1 of this Verify are kept below as history. Round 5 (next section) is round 4 run again after the fixes of round 4's two fails; rounds 4 and 3 stay below it as history. Round 4 is round 3 run again after the Builder's fix of round 3's fail; round 3 stays below it as history.

## Round 5 (round 4 run again, 2026-10-30)

**Verdict: SIGNED.** Round 4's two fails are fixed. Round 3's fail, round 2's fails, Checker 1's round 2 target fix and the LD-219 addendum still hold under my own driver, probes and mutants. My walk is wider than round 4's: 517 screen states, 16 753 controls, 0 failures. It covers every place by every tab with the empty lists, the sheets opened from the editor and the list, the attachment preview and every earlier version. The APP-08 menus match the card in 11 states. Parity passes: menubar-menu-bar-icon L 0.54 %, D 0.53 %, and states 15/15. 17 of 17 mutants are caught, 12 from round 4 and 5 for this round's fixes. The full run passes: 309 tests in 41 suites. One advisory is new, on a screen no earlier round walked: AppKit's own scroll bar parts on the text preview sheet (Advisory 1). They are not Larsal's controls, so they are not a fail.

Nothing left this Mac. No window was shown, ordered front or made key. No status item was added, no real key event was posted, and VoiceOver was not turned on. The general pasteboard was not read, written or cleared. `CopySpy` recorded Cut and Copy on the field editors. During the probes, AppKit's "general pasteboard" was a private named one of the test, and its change count did not move. I did not edit any product code.

### Round 4's fails and the earlier fixes, re-checked

| Item | Fix (Builder) | My re-check (driver, private copy) | Result |
|---|---|---|---|
| Round 4 fail 1: the one-time code setup sheet's "Secret key" has no name | `field.cell?.setAccessibilityLabel(label)` in `EditorPasswordField.makeNSView` (EditorPasswordField.swift:28); walk case "totp setup" | Personal is unlocked and Amazon (no code) is in the editor. "Add one-time code…" is pressed through the accessibility tree, and the sheet opens. The field reads `NoCopyCell AXTextField label 'Secret key'`, and the walk is clean. The change sheet for GitHub (it has a code) is clean too. Mutant M13 (the cell label removed) fails the Builder's case `totp setup` and 3 lines of my walk: `editor totp setup (button): AXTextField at (489.0, 175.0, 372.0, 18.0): no name`, the same for the change sheet, and no field named "Secret key". | **Holds** |
| Round 4 fail 2: "No entries match … clear the search." is a button that VoiceOver cannot press and Tab cannot reach | `.focusable().accessibilityAction { model.setSearch("") }` on the joined `Text` inside `if model.searching` (EntryListView.swift:243). The box keeps `.onTapGesture`, the button trait and the hint only while searching. Walk cases "search none" and "empty tab". | "zzzz-none" in Personal and in Work: `AXButton` at (273, 237, 622, 62), focusable, hint "Clears the search". A press returns true, and afterwards the search is "" and not searching. With no search, every place by every tab was walked: 42 empty lists (23 in Personal, 19 in Work) read `AXStaticText`, and none can be pressed. Family is the empty vault: a search there shows the empty-vault page, which has no list (Advisory 3). Mutants M14 (`.focusable()` removed), M15 (`.accessibilityAction` removed), M16 (round 4's box modifiers back) and M17 (the button trait always on) are each caught (Part D). states-search-with-no-result passes at L 0.42 %, D 0.43 %. Its .ax.json reads `AXButton` [273, 237, 622, 62], help "Clears the search", in both themes. | **Holds** |
| Round 3 fail: the unlock form's shown field has no name | `ShownPasswordField.makeNSView` also labels the cell | In all three vaults, "demo-typed-pass-11" is typed. The walk with it as a secret is clean. With Show on, the field is `NoCopyCell`, named "Password", with value "demo-typed-pass-11", and the walk is clean. Hidden again, the walk with the secret is clean. M11 is caught. | **Holds** |
| Round 2 fail 1: the detail's Passkey row shows the user name | `MaskedUser(user:site:shown:)` (DetailFields.swift:61) | All 25 Personal details (the bin's 2 included) were walked with the vault's 23 user names as secrets. With the mask off, 23 of 23 entries read their own name. With it on, all 25 are clean. The 4 passkey rows read "<site>, hidden". After Show, 22 read the name, the same count as round 4. M6 is caught: 3 issues in the Builder's tests, 4 in mine. | **Holds** |
| Round 2 fail 2: Cut and Copy are off while the shown vault is locked | `.disabled` removed; `copyCommand()` sends the plain copy | Edit while locked: `Cut ⌘X, Copy ⌘C, Paste ⌘V, Select All ⌘A, Find… ⌘F (off)`, with and without Work unlocked. The Settings search field is in front of the locked window's typed password: log `["cut demo text", "copy demo text"]`, and the unlock password keeps 19 characters. M4 and M5 are caught. | **Holds** |
| Checker 1 round 2: the target AppKit really uses | `textCommand()`: the focused responder if it takes the action, else `NSApp.target(forAction:to:from:)`; then the `validateUserInterfaceItem` check | 22 probes: ⌘X and ⌘C through `NSHostingMenu(EditMenuItems)`, with NSApp's `keyWindow` and `mainWindow` answered per instance. There are 4 password fields with all their text selected: the unlock form masked (`NSSecureTextView`, 19 of 19) and shown (`NoCopyEditor`, 19 of 19), and the editor's Password masked (`NSSecureTextView`, 18 of 18) and shown (`NoCopyEditor`, 18 of 18). Each has 5 windows in front: the main window, Settings with nothing focused, Settings with its hosting view focused, a bare `NSPanel`, and the wizard with nothing focused. The 2 editor fields were also probed under the leave-editor dialog. Every log is `[]`, and every length is kept. A plain field still works. With nothing focused in Settings, the main window's search field behind takes both keys (`["cut git", "copy git"]`), and no notice shows. M1 trips 16 probes, M2 trips all 22, and M3 crashes xctest. | **Holds** |
| LD-219 addendum: the editor's Passkey row | `MaskedUser(user:site:)` (EditorEntryPage.swift:368) | 23 entries × 8 pages = 184 masked editor states. The only hits are 21 Username text fields on the Entry page, which APP-01.23's editor rule keeps in clear. M7 is caught: 2 issues in the Builder's tests, 4 in mine. | **Holds** |
| LD-219 addendum: the History sheet | `VersionText` uses `MaskedUser` | All 21 earlier versions were opened. With the mask off, 21 of 21 read the version's user name. With it on, all 21 are clean. M8 is caught: 1 issue in the Builder's tests, 21 in mine. | **Holds** |
| LD-219 addendum: the Wi-Fi QR title | `DialogCard(user:)`, `Masked.text` and `Masked.spoken` | With the mask off, it reads `Join “Morgan-Home 5G”` twice. With it on, it reads `Join “hidden”` twice, and the walk with the 23 names and the network as secrets is clean. M9 and M10 are caught. | **Holds** |

### Summary of the checks

| Part | Check | Result |
|---|---|---|
| A | Reference current | mockup.html and mockup.js (10-27 22:25), app.css (10-28 00:22), the reference PNGs and manifest (10-28 01:36) and target/parity/dom-*.json (10-28 19:18) are unchanged since rounds 3 and 4. The DOM dump was copied into my copy. |
| A | menubar-menu-bar-icon, light and dark | **PASS**: L 0.54 % (0.5 % outside the accepted areas), D 0.53 % (0.48 %). 0 missing strings, 0 token mismatches, 0 boxes or runs off by more than 2 pt. I viewed the dark snapshot by eye: Vaults with Personal Unlocked and Work and Family locked; Search Entries… ⌥⌘Space; Password Generator ⌥⌘G; Lock Everything ⇧⌘L; Show Window; Settings… ⌘,; Quit Larsal ⌘Q. |
| A | states | **PASS 15/15**. The highest is states-needs-attention D 1.92 %. states-search-with-no-result is L 0.42 %, D 0.43 %. |
| B | AT-K06 offscreen walk | The Builder's 23 cases and the secret check pass. My walk has **517 screen states, 16 753 controls (802 disabled), 0 failures**. By vault: Personal 362, Work 44 (1 entry), Family 31 (the empty vault). The rest: 21 locked states (per vault: plain, vault switcher, Touch ID form, typed, typed and shown, hidden again, wrong password), 22 list sheets, 18 editor sheets and 19 states of the other windows. Per unlocked vault, the walk covers: every place, group and tag by the 4 tabs; a search with hits and one with none; every entry's detail hidden, with every Show on, and its More actions; the sort menu, the toolbar generator, the vault switcher and the search tips; the 5 report tabs; every editor page of every entry, the shown password and the editor's generator. The list sheets are move to bin, delete forever, empty bin (set and real), discard, clone, new group (empty and typed), save failed, changed on disk (4 asks), close unsaved, format notice, the disk new-key sheet (2), ask unsafe, old copies, changed attachment, the delete sheet and the Wi-Fi QR. The editor sheets are the one-time code setup through its button, its change sheet, the one-time code QR, remove passkey, field, custom data and attachment, overwrite attachment, big file, open risky, replace file, leave editor, discard, GitHub's 3 earlier versions and 2 attachment previews. The other windows are the welcome screen, every settings and vault settings page, Change the password typed and shown, and the wizard's 3 steps with step 3 shown and hidden. No hidden secret was read: every entry's password and protected values were secrets everywhere except that entry's own Show states. 7 AppKit scroll bar parts on the text preview sheet are counted apart (Advisory 1). |
| B | Masked user names (S-VIEW-06) | Clean on 25 details, 184 editor states (only the 21 Username fields, by the editor rule), 21 earlier versions and the Wi-Fi QR sheet. |
| C | APP-08 menus against the card | 11 states, 899 menu lines. In the Google state, every menu's titles and shortcuts equal `MenuCard`. That table matches the card's tables APP-08.2 to APP-08.11, and the card is unchanged since 10-28 09:50. Hidden rules: Restore Entry ⌘R and Empty Recycle Bin… show only for a bin entry. Remove Passkey shows only for GitHub. Arrange Subgroups shows only for "Work", the 1 of 7 groups with subgroups (checked for every group). Move Up and Move Down never show. Enabled rules (APP-08.12): in the editor, Save As…, Reports, Passkeys…, New, Edit, Clone, Expire, Delete, Open URL, Fetch Site Icon, New Group… and Password Generator are off, while Save and the copy items stay on. With a sheet open (New Group, Wi-Fi QR), every Entry and Group item and Find… are off, while Edit > Copy and Lock Everything stay on. While locked: see above. With no vault, Close Vault is off with no key, and Close Window takes ⌘W. Mask User Names is checked only while S-VIEW-06 is on. |
| C | Builder's suites | In the full run: AccessibilityWalkTests (23 cases and the secret check), MenuKeysTests, MenuBarTests, MenuBarIconTests, ScreenProtectionTests, ShownPasswordFieldTests, SnapshotTests, EditorSnapshotTests, ParityStatesTests, ScreenTests and PlatformTests all pass. |
| D | 17 mutants in a private copy | 17 of 17 caught. Each is caught by a Builder test and by my driver. Each restored file is identical to the original (`filecmp`), and `diff -rq` shows `Larsal/` equal to the snapshot after every batch. |
| – | Full run (private copy, `-skip-testing:LarsalUITests`) | `✔ Test run with 309 tests in 41 suites passed after 165.742 seconds`. FEA-01.34 passed in it (worst 18 ms before rating, 19 ms after). My driver alone, after all mutants, warnings as errors: `✔ Test run with 5 tests in 1 suite passed after 184.494 seconds`. |
| – | swift format, SwiftLint 0.65.1 strict, check-names (shared tree) | `swift format lint --strict` and `swiftlint lint --strict --quiet` on EntryListView.swift, EditorPasswordField.swift and AccessibilityWalkTests.swift: exit 0, exit 0. check-names: the last command below. |

### How I worked

- **Private copy.** `rsync -a --exclude target --exclude larsal-shots --exclude node_modules --exclude .build ./ /tmp/e5s11z-verify-copy/` at 06:39:26. A snapshot of `macos/` went to /tmp/e5s11z-verify-orig. Another agent wrote crates/larsal-core/src/auto_open.rs and crates/larsal-ffi/src/auto_open.rs at that same second, and my copy caught the first file before the change. The first `build-core.sh` stopped on `no method named expose found for struct String` (larsal-ffi/src/auto_open.rs:71). I synced crates/ again (`diff -rq` equal to the shared tree) and touched the file, because the old and new copies had the same mtime and cargo kept the stale build. Then `CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/tmp/e5s11z-verify-copy/target scripts/build-core.sh` gave `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift` in 1 m 00 s. Derived data was /tmp/e5s11z-verify-dd.
- **Driver**, in the copy only, deleted with it. VerifyE5S11R5Tests.swift holds the wide walk. VerifyE5S11R5MoreTests.swift holds the 22 probes and 2 plain-field checks, the masks and the menus in 11 states. VerifyE5S11R5DiagTests.swift dumps the preview sheet's nodes. They form one serialized suite, because the mask setting is the process's own store, and it ran alone. For the probes, a guard swapped `+[NSPasteboard generalPasteboard]` for a private named pasteboard and recorded any Cut or Copy that reached an NSTextView no spy watched. Both were restored after the test. Every run: `unspied []`, `stand-in pasteboard written false`.
- **Same code as the shared tree.** At 07:30, `cmp` showed the shared tree's MainWindowModel, LarsalCommands, LarsalCommandsVault, DetailFields, EditorEntryPage, Dialogs, DialogSheets, ViewOptions, ShownPasswordField, EntryListView, EditorPasswordField, PreviewSheet, AccessibilityWalkTests, MenuKeysTests, MenuKeysMoreTests and MenuBarTests equal to my snapshot. Only NewVaultTests.swift (another story) changed in the shared tree after my copy.
- **Parity.** Run in the copy: snapshots from the full run, OCR (`swift design/parity/tools/ocr.swift`, 17 frames × 2 themes), the DOM dump copied, and the full run's log as behaviour.log. `node design/parity/tools/compare.mjs menubar` gave `menubar: 2/2 PASS`, and `… states` gave `states: 15/15 PASS`. The shared design/parity reports were not rewritten.
- **Driver fixes before the result.** My first walk stopped at my own `#require` for the "No entries match" node in Family. The diagnostic showed Family is the empty vault: a search shows its empty-vault page ("The vault is saved and encrypted. Add your first entry…"), not a list. The driver now skips that check in an empty vault. My first empty-list count read 0 because static text holds its words in the value, not the label. It now reads both and counts 42.

### Part D: mutations

`/tmp/e5s11z-verify-mut.py` applies each mutant by exact string, outside the project. Each mutant is built without warnings as errors, so the tests catch it, not the compiler. Then the Builder's suite and my matching driver test run, the file is restored, and it is compared with `filecmp` (`identical to the original: True` ×17).

| # | Mutant (file) | Caught by |
|---|---|---|
| M1 | MainWindowModel.swift `textCommand()`: no target from the chain (`… ? focused : nil`) | Builder "another window in front, nothing focused…"; my probes (16 password probes log the password) |
| M2 | `textCommand()`: the `validateUserInterfaceItem` guard removed | Builder "another window in front…" and "…leave a selected typed password alone"; my probes (all 22) |
| M3 | `textCommand()`: the target is the focused responder only | xctest crashes with `-[LarsalTests.OtherWindow cut:]` and `-[NSWindow copy:]: unrecognized selector`, exit 65. Run again with only my probes, it crashes the same way (`-[LarsalTests.OtherWindow cut:]`, exit 65). |
| M4 | LarsalCommands.swift: Cut `.disabled(window.unlock != nil)` again | Builder "…⌘C and ⌘X act in a settings and a wizard field" (2); my menus (Cut off in both locked states) and plain-field probe (`["copy demo text"]`) |
| M5 | `copyCommand()`: `guard unlock == nil else { return }` again | Builder (1); my plain-field probe (`["cut demo text"]`) |
| M6 | DetailFields.swift: the detail's Passkey row `shown: true` | Builder "the Passkey row's user name is masked…" (3); my masks (4: Apple Account, GitHub, Linear, Mastodon) |
| M7 | EditorEntryPage.swift: the editor's Passkey row as plain `Text` | Builder (2); my masks (4) |
| M8 | Dialogs.swift `VersionText`: an earlier Username as plain `Text` | Builder (1); my masks (21 versions) |
| M9 | Dialogs.swift: the Wi-Fi QR sheet without `user: network` | Builder (2); my masks |
| M10 | Dialogs.swift `DialogCard`: the heading's spoken label back to `title` | Builder (1); my masks |
| M11 | ShownPasswordField.swift: the cell label removed | Builder case `unlock typed, shown`; my walk (6: all three vaults) |
| M12 | ViewOptions.swift `MaskedUser`: the mask inverted | 4 Builder tests (20 issues); my masks (47) |
| M13 | EditorPasswordField.swift: `field.cell?.setAccessibilityLabel(label)` removed (round 4 fail 1) | Builder case `totp setup`; my walk (3) |
| M14 | EntryListView.swift: `.focusable()` removed from the search text | Builder case `search none`; my walk (4: Personal and Work, not focusable and not a usable button) |
| M15 | EntryListView.swift: `.accessibilityAction` removed | Builder case `search none`; my walk (2: a press keeps the search) |
| M16 | EntryListView.swift: round 4's box modifiers back (`.focusable(model.searching)` and the action on the box) | Builder case `empty tab`; my walk (84: every empty list reads as a pressable button the focus cannot reach) |
| M17 | EntryListView.swift: the button trait always on | Builder case `empty tab`; my walk (84) |

### Needs Mac QA (owner's go), not fails

The same as round 4: real VoiceOver on unlock, list, detail and editor (AT-K06 live); Tab order and the focus ring on a key window (APP-08.25); the real menu bar, its order and the system items; the status item on a real menu bar; APP-09.21-a live; ⌃H in a focused password field against "Load into SSH Agent" (V-A08-5); Cut and Copy with real key events and a real key window. New this round: a mouse click on the "clear the search" box, Tab and Space to it, and where the focus ring draws. `.focusable()` sits on the inner text, while the accessibility node has the box's frame (622 × 62).

### Advisories (not fails)

1. **AppKit's scroll bar parts on the text attachment preview.** No earlier round walked the preview sheet. With GitHub's 43-line github-recovery-codes.txt, its `ScrollView` (PreviewSheet.swift:38, MOD-05.9, edited by another story at 10-30 01:13) shows an overlay `NSScroller`. AppKit exposes its parts as `NSAccessibilityScrollerPart` nodes with role `AXButton` under `AXScrollBar`: subroles AXIncrementArrow and AXDecrementArrow (0 × 0, since overlay scrollers draw no arrows), AXIncrementPage and AXDecrementPage (6 pt wide). Their role descriptions are "increment arrow button" and so on, and their label is empty, so `AccessWalk.check` reports 4 "no name" and 3 "outside the window". These are the system scroll bar that every scrolling AppKit text view has, not Larsal's controls, and VoiceOver reads them by role description. If the lead wants a clean walk there: add `.scrollIndicators(.never)`, as Larsal's 8 other scroll views have, or teach `AccessWalk` to skip `AXScrollBar` parts. Then add a preview case to `AccessibilityWalkTests`.
2. **A search in the empty vault shows the empty-vault page,** not "No entries match". It is no accessibility gap. FEA-01's owner may want to confirm it is meant.
3. **The Wi-Fi QR title masks by text replacement** (round 3's advisory 1; the code is unchanged).
4. **Stale folders from an earlier Checker 1 run are still in /tmp** (/tmp/e5s11y-checker1-*). They are not mine, so I left them (rule 11).

### Commands run (round 5, in order) and their output

1. `rsync … /tmp/e5s11z-verify-copy/`; `cp -R macos /tmp/e5s11z-verify-orig/`. `CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=… scripts/build-core.sh` failed: `error[E0599]: no method named expose found for struct String` (another agent's edit caught mid-write, see How I worked). `rsync -a crates/ …` gave `crates-equal`. The file was touched, and the rerun gave `Finished dev profile … in 44.27s`, `build-core (debug): …`, exit 0.
2. `xcodebuild build-for-testing -project Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s11z-verify-dd SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` gave `** TEST BUILD SUCCEEDED **`.
3. `xcodebuild test-without-building … -skip-testing:LarsalUITests` gave `✔ Test run with 309 tests in 41 suites passed after 165.742 seconds`, exit 0.
4. OCR of `larsal-shots/{light,dark}/menubar-*.png states-*.png`, then `node design/parity/tools/compare.mjs menubar` gave `menubar: 2/2 PASS`, and `… states` gave `states: 15/15 PASS`.
5. Driver added and rebuilt with warnings as errors (`** TEST BUILD SUCCEEDED **`). Run alone, the probes, masks and menus passed. The walk stopped at my `#require` in Family (see How I worked). The diagnostic run gave `R5 DIAG node NSAccessibilityScrollerPart role AXButton subrole AXIncrementPage desc 'increment page button' label '' frame (909.0, 276.0, 6.0, 177.0)` and 3 more like it, plus `R5 DIAG scroller NSScroller style 1`.
6. `swift format lint --strict` on the three files gave exit 0. `swiftlint lint --strict --quiet` (0.65.1) gave exit 0. `cmp` showed the three shared files equal to my snapshot.
7. `/tmp/e5s11z-verify-mut.sh M1 … M17` (Part D): 17 of 17 test runs exit 65, every build exit 0, and `Larsal equal to the original after all mutants` after each batch. M3 again with `-only-testing:LarsalTests/VerifyE5S11R5Tests/probes()` gave `-[LarsalTests.OtherWindow cut:]: unrecognized selector`, exit 65, then `restored … identical to the original: True`.
8. Final driver run, warnings as errors: `R5 WALK all: 517 screen states, 16753 controls (802 disabled), 0 failures`, `R5 MENUS 11 states, 899 menu lines; Arrange Subgroups for ["Work"] of 7 groups`, `R5 PROBE guard: unspied [], stand-in pasteboard written false`, `✔ Test run with 5 tests in 1 suite passed after 184.494 seconds`.
9. `scripts/check-names.sh`, run after this file and the status line were written → `names: PASS (3189 files scanned, 16 vault files name-only)`.

Cleanup: I removed /tmp/e5s11z-verify-copy (with the driver, its core, larsal-shots and parity reports), -dd, -orig, -driver, the -*.log files, -mut.py and -mut.sh. /tmp/parity-tools is shared and not mine, so I left it. No process I started is still running.

## Round 4 (round 3 run again, 2026-10-30)

**Verdict: FAILED (2).** Round 3's fail is fixed. After Show on the unlock form, the walk reads `AXTextField` "Password" with the typed value in all three vaults, whether Show comes from the tree's button or from ⌃H, and also while the field is focused. Round 2's two fails, Checker 1's round 2 target fix and the LD-219 addendum still hold under my own driver, probes and mutants. The APP-08 menus match the card. Parity passes: menubar-menu-bar-icon L 0.54 %, D 0.53 %, and states 15/15. 12 of 12 mutants are caught. My walk was wider than any earlier round: 399 screen states beyond the Builder's 20 cases. It found two AT-K06 gaps, on screens no earlier round walked. Neither gap is in this story's files, but AT-K06 is this story's check ("Checks: AT-K06 passes"), so the story is not Done.

| # | Fail | Card | Failure scenario (proof) | Smallest fix |
|---|---|---|---|---|
| 1 | The one-time code setup sheet's "Secret key" field has no VoiceOver name. VoiceOver reads a text field with no label in the sheet where the user pastes a TOTP secret. | AT-K06 ("every control is named"), APP-08.25 | Personal is unlocked and Amazon (no code) is in the editor. "Add one-time code…" is pressed through the accessibility tree, and the sheet "Set up one-time password" opens. `AccessWalk.check` reports `totp setup (button): AXTextField at (489.0, 175.0, 372.0, 18.0): no name`. The tree element is the field's `NoCopyCell`, and its label is nil. The `NoCopyTextField` holds "Secret key" (`EditorPasswordField.makeNSView`, EditorPasswordField.swift:27, `field.setAccessibilityLabel(label)`), but the label never reaches the cell. This is the same cause as round 3's fail. The editor's shown Password is named only because EditorEntryPage.swift:266 adds a SwiftUI `.accessibilityLabel`. The sheet's call (DialogSheets.swift:26) adds none. | In `EditorPasswordField.makeNSView`, add `field.cell?.setAccessibilityLabel(label)` after line 27. This one line covers every caller. I tried it in my private copy: the walk reads `NoCopyCell AXTextField label Secret key` and is clean. I restored the file, and it is byte-equal to the shared tree. Also add a "totp setup" case to `AccessibilityWalkTests.screens`: edit an entry with no code, then press "Add one-time code…". EditorPasswordField.swift (E5-S5) and DialogSheets.swift (LD-199 (5), edited 10-29 22:01) belong to other stories, so the lead decides who makes the change. |
| 2 | After a search with no result, the text "No entries match “…”. Try fewer words, or clear the search." is read as a button. VoiceOver cannot press it, and Tab cannot reach it. | AT-K06 ("every control is named and usable"), APP-08.25 ("every control can be reached with Tab") | Personal or Work is unlocked, and "zzzz-none" is typed into "Search entries" (in Work, "git" too). The node is an enabled `AXButton` (`.accessibilityAddTraits(.isButton)`). `isAccessibilitySelectorAllowed` is false both for `setAccessibilityFocused:` and for `accessibilityPerformPress`. `accessibilityPerformPress()` returns false, and the search stays "zzzz-none". `AccessWalk.check` reports `search none v0: AXButton at (273.0, 237.0, 622.0, 62.0): the focus cannot reach it (No entries match “zzzz-none”. Try fewer words, or clear the search.)`, and the same for Work. Only a mouse click clears the search (`.onTapGesture`, EntryListView.swift:257). Escape still clears it (APP-08.14), so no action is lost, but VoiceOver announces a button that does nothing. | In `EntryListView.empty`, after `.accessibilityAddTraits(…)`, add `.focusable(model.searching)` and `.accessibilityAction { if model.searching { model.setSearch("") } }`, or make the text a real `Button` with the `Bare()` style. I tried the two modifiers in my copy: the node is focusable and pressable, a press clears the search, and the walk is clean in Personal and Work. I restored the file, and it is byte-equal to the shared tree. After the fix, re-check states-search-with-no-result (PASS now: L 0.41 %, D 0.42 %). The focus ring on a key window is Mac QA. EntryListView.swift (FEA-01, edited 10-28 21:26) belongs to another story. |

Everything else I checked holds. Nothing left this Mac. No window was shown, ordered front or made key. No status item was added, no real key event was posted, and VoiceOver was not turned on. The general pasteboard was not read, written or cleared: `CopySpy` recorded Cut and Copy on the field editors. I did not edit any product code.

### Round 3's fail, round 2's fails and the fixes, re-checked

| Item | Fix (Builder) | My re-check (driver, private copy) | Result |
|---|---|---|---|
| Round 3 fail: the unlock form's shown field has no name | `ShownPasswordField.makeNSView` also sets `field.cell?.setAccessibilityLabel("Password")`; new case "unlock typed, shown" in `AccessibilityWalkTests.screens` | Driver "V4 R3 fail", in Personal, Work and Family. "demo-typed-pass-11" is typed, and the walk with it as a secret is clean. "Show password" is pressed through the tree, and the field reads `NoCopyCell AXTextField label Password value demo-typed-pass-11`. The walk is clean, and also clean with the field focused (field editor `NoCopyEditor`). After "Hide password", the walk with the secret is clean again. ⌃H shows it again, and the walk is clean. Mutant M11 (the cell label removed) fails my test (12 issues) and the Builder's walk case `unlock typed, shown`. | **Holds** |
| Round 2 fail 1: the detail's Passkey row shows the user name | `MaskedUser(user:site:shown:)` (DetailFields.swift:61) | "masked every detail" covers all 25 entries of Personal, the bin included, with the 15 user names of the vault as secrets. With the mask off, each entry's own name is read (23 of the 23 that have one). With it on, all 25 are clean. The 4 passkey rows read "<site>, hidden". After "Show username" or "Show network name", the name is read (22 entries). Mutant M6 (the row always shown) is caught: 9 issues in my test, 3 in the Builder's. | **Holds** |
| Round 2 fail 2: Cut and Copy are off while the shown vault is locked | `.disabled` removed; `copyCommand()` sends the plain copy | Edit while locked reads `Cut ⌘X, Copy ⌘C, Paste ⌘V, Select All ⌘A, Find… ⌘F (off)`. That holds both in "locked" and in "locked, Work unlocked". With Settings' search field focused in front and the typed unlock password behind, the log is `["cut demo text", "copy demo text"]`, and the unlock password keeps its 19 characters. Mutants M4 (Cut `.disabled` while locked) and M5 (`copyCommand()` returns while locked) are caught. | **Holds** |
| Checker 1 round 2: the target AppKit really uses | `textCommand()` uses the focused responder if it takes the action, else `NSApp.target(forAction:to:from:)`. Then the `validateUserInterfaceItem` check, then `sendAction`. | 22 probes, ⌘X and ⌘C through `NSHostingMenu(EditMenuItems)`, with NSApp's `keyWindow` and `mainWindow` answered per instance (`V4Front`). The fields: the unlock form masked (`NSSecureTextView`) and shown (`NoCopyEditor`), and the editor's Password masked (`NSSecureTextView`) and shown (`NoCopyEditor`). The windows in front: the main window itself, Settings (the window, then its hosting view, as first responder), a bare `NSPanel` and the new vault wizard with nothing focused. The editor fields were also probed under the leave-editor dialog. Every log is `[]`, and every text is kept. A plain field still works: with nothing focused in Settings, the main window's search field takes ⌘X and ⌘C (`["cut git", "copy git"]`, no notice). Mutants M1, M2 and M3 are caught. | **Holds** |
| LD-219 addendum: the editor's Passkey row | `MaskedUser(user:site:)` (EditorEntryPage.swift:368) | "masked every editor": 23 entries × 8 pages = 184 states, with the 15 user names as secrets. The only hits are 21 `AXTextField[Username]`, which APP-01.23's editor rule keeps in clear. The Passkey rows of the 4 passkey entries read "<site> · <user>" with the mask off and "<site>, hidden" with it on. Mutant M7 is caught. | **Holds** |
| LD-219 addendum: the History sheet | `VersionText` uses `MaskedUser` for an unprotected Username | "masked every version" opens all 21 earlier versions. With the mask off, the version's user name is read in 21 of 21. With it on, all 21 are clean. Mutant M8 is caught: 22 issues in my test, 1 in the Builder's. | **Holds** |
| LD-219 addendum: the Wi-Fi QR title | `DialogCard(user:)`, `Masked.text` and `Masked.spoken` | With the mask off, the title reads `Join “Morgan-Home 5G”` twice (heading and sheet). With it on, it reads `Join “hidden”` twice, and the walk with the 15 names and the network as secrets is clean. Mutants M9 (no `user:`) and M10 (spoken label back to the title) are caught. | **Holds** |

### Summary of the checks

| Part | Check | Result |
|---|---|---|
| A | Reference current | mockup.html and mockup.js (10-27 22:25), app.css (10-28 00:22) and the reference PNGs and manifest (10-28 01:36) are unchanged since round 3. target/parity/dom-*.json (10-28 19:18) was copied into my copy. |
| A | menubar-menu-bar-icon, light and dark | **PASS**: L 0.54 % (0.5 % outside the accepted areas), D 0.53 % (0.48 %). 0 missing strings, 0 token mismatches, 0 boxes or runs off. I viewed the dark snapshot by eye: Vaults with Personal Unlocked and Work and Family locked; Search Entries… ⌥⌘Space; Password Generator ⌥⌘G; Lock Everything ⇧⌘L; Show Window; Settings… ⌘,; Quit Larsal ⌘Q. menubar-auto-type-picker (E8-S2's) also reads PASS. |
| A | states | **PASS 15/15**. The highest is states-needs-attention D 1.92 %. states-search-with-no-result is L 0.41 %, D 0.42 %. |
| B | AT-K06 offscreen walk | The Builder's 20 cases plus my 399 screen states. My states hold 13 287 controls (646 disabled). They are: per vault, every place, tag and group; the 4 tabs; two searches; every entry's detail, hidden, then shown, and its More actions; every editor page of every Personal entry, plus the shown password; the editor generator; the dialogs (15 list dialogs, 9 editor dialogs, the one-time code setup sheet and, when Rust gives one, its QR sheet, and the Wi-Fi QR sheet); the sort and more menus; the toolbar generator; the vault switcher; 5 report tabs; 4 locked forms per vault (plain, Touch ID form, typed and shown, wrong password); and the wizard's first two steps. Separately: wizard step 3 typed and shown, and Vault Settings' "Change the password" typed and shown (4 states, clean). **4 failures:** 3 are fail 2 (Personal "zzzz-none", Work "git" and "zzzz-none") and 1 is fail 1. No hidden secret is shown: every entry's password was a secret on its hidden detail and on all 8 editor pages. |
| B | Masked user names (S-VIEW-06) | Clean on 25 details, 184 editor states (only the Username fields, by the editor rule), 21 earlier versions and the Wi-Fi QR sheet. The Builder's report case passes. |
| C | APP-08 menus against the card | 11 states. In the Google state, every menu's titles and shortcuts equal `MenuCard`, which matches the card's tables APP-08.2 to APP-08.11 (the card is unchanged since 10-28 09:50). Hidden rules: Restore Entry ⌘R and Empty Recycle Bin… show only for a bin entry; Remove Passkey only for GitHub; Arrange Subgroups only for "Work", the 1 of 7 groups with subgroups; Move Up and Move Down never. Enabled rules (APP-08.12): in the editor, Save As…, Reports, Passkeys…, New, Edit, Clone, Expire, Delete, Open URL, Fetch Site Icon, New Group… and Password Generator are off, while Save and the copy items stay on. With a sheet open, every Entry and Group item and Find are off, and Edit > Copy is on. Lock stays on ("Locking stays one key away", the Builder's sheet test). While locked, see above. With no vault, Close Vault is off with no key, and Close Window takes ⌘W. Mask User Names is checked while S-VIEW-06 is on. |
| C | Builder's suites | MenuKeysTests 12/12, MenuBarTests, MenuBarIconTests, AccessibilityWalkTests (20 cases + the secret check), ScreenProtectionTests, ShownPasswordFieldTests, SnapshotTests and ParityStatesTests pass in the full run. |
| D | 12 mutants in a private copy | 12 of 12 caught, 11 of them also by my driver. Each restored file is identical to the original (`filecmp`). |
| – | Full run (private copy, warnings as errors) | First run: PlatformTests "APP-09.27-a, -b" hit its 60 s limit at load average 50 to 60, xctest restarted, and 62 in-flight tests lost their results. Rerun without PlatformTests: 316 tests in 43 suites (14 of them my driver), 6 issues. 2 are my driver's (the 2 fails). The other 3 tests, outside this story, each pass alone: FEA-01.34 (22 ms), ParitySavingTests `lockAllSavesFirst` and ParityEditorPagesTests `deleteForever`. PlatformTests alone: 3 of 3. |
| – | swift format, SwiftLint 0.65.1 strict, check-names (shared tree) | swift format and SwiftLint exit 0 on this story's 15 files. The tree-wide runs fail only on other stories' files (ContextMenus.swift, CopySelectionTests.swift, PasteboardProof.swift, NewVaultTests.swift), as the Builder reported. check-names: PASS (3183 files) on the final run. A first run had 2 hits at spec/decisions.md:254, another agent's edit at 03:20, gone by the rerun (command 12). |

### How I worked

- **Private copy.** `rsync -a --exclude target --exclude larsal-shots --exclude node_modules --exclude .build ./ /tmp/e5s11y-verify4-copy/` at 02:17. In it, `CARGO_NET_OFFLINE=true scripts/build-core.sh` gave exit 0 (`build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`, 1 m 46 s). The shared core (10-28 22:47) lacks the newer bindings that other stories' Swift uses. Derived data was `/tmp/e5s11y-verify4-dd`. A snapshot of `macos/` went to `/tmp/e5s11y-verify4-orig` for restores.
- **Driver**, in the copy only, deleted with it. `VerifyE5S11R4Tests.swift`: the unlock-shown names, masks over every detail, editor page and version, the Wi-Fi title, the 22 Cut and Copy probes and the plain-field checks. `VerifyE5S11R4WalkTests.swift`: the 399-state walk and the menus in 11 states. `VerifyE5S11R4DiagTests.swift`: both fails through the real path, Arrange Subgroups, wizard step 3 and Change the password.
- **Same code as the shared tree.** Before and after my runs, `cmp` showed the shared tree's EditorPasswordField, DialogSheets, EntryListView, ShownPasswordField, MainWindowModel, EditorEntryPage, Dialogs, ViewOptions, DetailFields, LarsalCommands, MenuKeysTests, MenuKeysMoreTests and AccessibilityWalkTests equal to my snapshot. `diff -rq` showed the copy's `Larsal/` equal to the snapshot after every restore.
- **Parity.** Run in the copy: snapshots from the rerun, OCR (`swift design/parity/tools/ocr.swift`, 17 frames × 2 themes), the DOM dump copied, and the rerun's log as behaviour.log. `node design/parity/tools/compare.mjs menubar` → `menubar: 2/2 PASS`. `… states` → `states: 15/15 PASS`. The shared design/parity reports were not rewritten.
- **A note on the History sheet.** An earlier version's password shows in clear in the version sheet (21 of 21). That is by design: MOD-03.12 makes it the sheet's Show value ("gone when the sheet closes", Dialogs.swift VersionSheet), opened by the History row's "Show". My first driver run counted it; I dropped that check.

### Part D: mutations

`/tmp/e5s11y-verify4-mut.py` applies each mutant by exact string, outside the project. Then `xcodebuild build-for-testing`, then the Builder's suite and my matching driver tests. Then the file is restored and compared with `filecmp`: `identical to the original: True` ×12.

| # | Mutant (file) | Caught by |
|---|---|---|
| M1 | MainWindowModel.swift `textCommand()`: no target from the chain (`… ? focused : nil`) | Builder "another window in front, nothing focused…" (1 issue); my probes (18 issues: every field behind Settings, the panel or the wizard) and my plain-field check (the main search field behind Settings gets nothing) |
| M2 | `textCommand()`: the `validateUserInterfaceItem` guard removed | Builder "another window in front…" and "with the shown vault locked, ⌘X and ⌘C leave a selected typed password alone"; my probes (22 issues) |
| M3 | `textCommand()`: target is the focused responder only | xctest crashes: `-[LarsalTests.OtherWindow cut:]` and `-[NSWindow copy:]: unrecognized selector`, exit 65 (Builder's tests and my probes) |
| M4 | LarsalCommands.swift: Cut `.disabled(window.unlock != nil)` again (round 2 fail 2) | Builder "with the shown vault locked, ⌘C and ⌘X act in a settings and a wizard field" (3 issues); my plain-field check (2) |
| M5 | `copyCommand()`: `guard unlock == nil else { return }` again | Builder (2 issues); my plain-field check (1) |
| M6 | DetailFields.swift: the detail's Passkey row `shown: true` (round 2 fail 1) | Builder "the Passkey row's user name is masked until Show…" (3); my "masked every detail" (9) |
| M7 | EditorEntryPage.swift: the editor's Passkey row as `Text(site · user)` | Builder "…editor's Passkey row and the History sheet…" (2); my "masked every editor" (4) |
| M8 | Dialogs.swift `VersionText`: an earlier Username as plain `Text` | Builder (1); my "masked every version" (22) |
| M9 | Dialogs.swift: the Wi-Fi QR sheet without `user: network` | Builder "…Wi-Fi QR dialog's title" (2); my "Wi-Fi QR title" (2) |
| M10 | Dialogs.swift `DialogCard`: the heading's spoken label back to `title` | Builder (1); my "Wi-Fi QR title" (2) |
| M11 | ShownPasswordField.swift: the cell label removed (round 3 fail) | Builder AT-K06 case `unlock typed, shown` (1); my "V4 R3 fail" (12) |
| M12 | ViewOptions.swift `MaskedUser`: masks only when shown (inverted) | 4 Builder tests (15 issues: list and detail, Passkey row, editor and History, reports); my "masked every detail" (27) |

### Needs Mac QA (owner's go), not fails

The same as round 3: real VoiceOver on unlock, list, detail and editor (AT-K06 live); Tab order and the focus ring on a key window (APP-08.25); the real menu bar, its order and the system items; the status item on a real menu bar; APP-09.21-a live; ⌃H in a focused password field against "Load into SSH Agent" (V-A08-5); Cut and Copy with real key events and a real key window.

### Advisories (not fails)

1. **The Wi-Fi QR title masks by text replacement** (round 3's advisory 1; the code is unchanged).
2. **A test that hits its time limit loses other tests' results.** PlatformTests "APP-09.27-a, -b" (60 s limit) under load made xctest restart, and 62 results were lost, my walk among them. Checker 1 saw the same. That is not this story's test; the lead may want the limit raised or the suite run alone.
3. **The shared target/larsal-core (10-28 22:47) is older than the Swift in the tree** (the Builder's note). The shared tree builds only after `scripts/build-core.sh`.
4. **Stale folders from an earlier Checker 1 run are still in /tmp** (/tmp/e5s11y-checker1-*). They are not mine, so I left them (rule 11).

### Commands run (round 4, in order) and their output

1. `rsync … /tmp/e5s11y-verify4-copy/`; `CARGO_NET_OFFLINE=true scripts/build-core.sh` in the copy → `Finished dev profile … in 1m 46s`, `build-core (debug): …`, exit 0.
2. Driver added. `xcodebuild build-for-testing … -derivedDataPath /tmp/e5s11y-verify4-dd SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `** TEST BUILD SUCCEEDED **` (after 3 driver compile fixes).
3. `xcodebuild test-without-building … -only-testing:` my two driver suites, MenuKeysTests and AccessibilityWalkTests → MenuKeysTests 12/12 and AccessibilityWalkTests passed. My walk gave `399 screen states, 13287 controls counted … 4 failures, 1 unnamed, 0 secrets`. My version check also flagged the earlier version's password, which is by design (see How I worked), so I dropped that check.
4. Diag through the real path: `totp walk: [totp setup (button): AXTextField at (489.0, 175.0, 372.0, 18.0): no name]`, `totp field: NoCopyCell AXTextField label nil … control NoCopyTextField control label Secret key`. Search: `search v0 node: … AXButton … focusable false pressable false`, `press: false`, `after press: search 'zzzz-none'`; Work the same.
5. Fixes tried in the copy: the cell label → `totp walk: []`, `label Secret key`. Then `.accessibilityAction` alone → pressable, still not focusable. Then with `.focusable(model.searching)` → `search v0 walk: []`, `focusable true pressable true`, `after press: search ''`. Both files restored; `cmp` equal to the shared tree.
6. Full run, `-skip-testing:LarsalUITests` → PlatformTests' time limit, a restart, `230 tests in 37 suites … 1 issue` with 62 tests lost. Rerun `-skip-testing:LarsalTests/PlatformTests` → `✘ Test run with 316 tests in 43 suites failed after 478.763 seconds with 6 issues` (Summary). `-only-testing:LarsalTests/PlatformTests` → `✔ Test run with 3 tests in 1 suite passed`.
7. Password forms: `wizard: step password`, `password forms walk: 4 states, 0 failures`.
8. OCR; `compare.mjs menubar` → `menubar: 2/2 PASS`; `compare.mjs states` → `states: 15/15 PASS`.
9. `/tmp/e5s11y-verify4-mut.sh M1 … M12` → Part D, 12 of 12 exit 65.
10. Alone: `searchSpeed()` → `FEA-01.34 search worst: 0.022098709 seconds before rating, 0.022086916 seconds after rating`, passed; `lockAllSavesFirst()` passed; `deleteForever()` passed.
11. `swift format lint --strict` and `swiftlint lint --strict --quiet` (0.65.1, DEVELOPER_DIR set) on this story's 15 files → exit 0, exit 0. Tree-wide: exit 1 and exit 2, other stories' files only.
12. `scripts/check-names.sh`, run after this file and the status line were written → `names: FAIL (2 hits, 3183 files scanned, 16 vault files name-only)`. Both hits are `./spec/decisions.md: content holds word 1` and `word 2 near line 254`, in a file another agent edited at 10-30 03:20. This report and plan/epics.md are not among the hits. I did not touch decisions.md (rule 11). A rerun a few minutes later, after the last edits to this file and the status line → `names: PASS (3183 files scanned, 16 vault files name-only)`.

Cleanup: I removed /tmp/e5s11y-verify4-copy (with the driver, its core, larsal-shots and parity reports), -dd, -orig, the -*.log files, -frames.txt, -mut.py and -mut.sh. /tmp/parity-tools is shared and not mine, so I left it. No process I started is still running.

## Round 3 (2026-10-28)

**Verdict: FAILED (1).** Round 2's two fails are fixed, and so are Checker 1's round 2 finding and the LD-219 addendum: my own driver walk, probes and mutants prove each one. The APP-08 menus match the card, parity passes (menubar-menu-bar-icon light and dark, states 15/15), and 12 of 12 mutants are caught. One AT-K06 gap is new in this round's wider walk: the unlock form's password field has no name once Show is on. Earlier walks never pressed Show on the unlock form.

| # | Fail | Card | Failure scenario (proof) | Smallest fix |
|---|---|---|---|---|
| 1 | After Show on the unlock form, its password field has no VoiceOver name. The field holds the typed password in clear, so VoiceOver reads a text field with no label. Every other control on the 314 screen states I walked is named. | AT-K06 ("every control … named"), APP-08.25, the story's check "AT-K06 passes" | Personal locked, "demo-typed-pass-11" typed. Then "Show password" is pressed through the accessibility tree, the real path. The driver walk reads `AXTextField` with name "" and value `demo-typed-pass-11`, and `AccessWalk.check` reports `unlock after Show password: AXTextField at (506.0, 386.0, 298.0, 19.0): no name`. The driver's case "unlock typed shown", where the test sets `reveal`, fails the same way. The tree element is the field's `NoCopyCell`, and its label is nil. The `NoCopyTextField` itself holds "Password" (`setAccessibilityLabel("Password")`, ShownPasswordField.swift:30), but that label never reaches the cell. The editor's and the wizard's shown fields are named ("Password", "Verify password"). The Builder's AT-K06 suite has no unlock-shown case, and neither did rounds 1 and 2. This is not a regression: the label code is the same in a copy of the tree from 2026-10-28 21:26. | In `ShownPasswordField.makeNSView`, add `field.cell?.setAccessibilityLabel("Password")` after line 30. Add an "unlock typed, shown" case to `AccessibilityWalkTests.screens` that types a password, then sets `reveal`. I tried the one-line fix in my private copy: the walk then reads `AXTextField Password demo-typed-pass-11`, and the copy was restored afterwards. ShownPasswordField.swift was last edited by another story (F-069, 20:58), so the lead decides who makes this change. |

Everything else I checked holds. Nothing left this Mac. No window was shown, ordered front or made key, no status item was added, no real key event was posted, VoiceOver was not turned on, and the general pasteboard was not read, written or cleared: Cut and Copy were recorded by `CopySpy` on the field editors, and Rust's copy goes to the test session's private pasteboard. I did not edit any product code.

### Round 2's fails and this round's fixes, re-checked

| Item | Fix (Builder) | My re-check (driver, private copy) | Result |
|---|---|---|---|
| Round 2 fail 1: the detail's Passkey row shows the user name | `MaskedUser(user:site:shown:)` in DetailFields.swift:53, shown with the Username row's Show | "masked every detail" walks all 25 entries of Personal, the 2 bin entries included. With the mask off, each entry's own user name is read (25 of 25). With the mask on, the walk with that name as its secret is clean (25 of 25). After "Show username" or "Show network name", the name is read in all 24 entries that have one. The four passkey entries (GitHub, Apple Account, Linear, Mastodon) are in that set. Mutant M7 (Passkey row always shown) fails the Builder's test and my walk. | **Holds** |
| Round 2 fail 2: Cut and Copy are off while the shown vault is locked | `.disabled` removed; `copyCommand()` sends the plain copy | Menu dump with "locked" and "locked work unlocked": `Cut ⌘X`, `Copy ⌘C`, `Paste ⌘V` and `Select All ⌘A` are all on, and `Find… ⌘F (off)`. Every Entry and Group item is off. Lock Everything is on only while Work is unlocked. Probe "Settings search focused in front, unlock masked behind": the Settings field logs `["cut demo text", "copy demo text"]`, and the unlock field keeps its 19 characters. Mutants M8 (Cut `.disabled` while locked) and M9 (`copyCommand()` returns while locked) are caught. | **Holds** |
| Checker 1 round 2: Cut skips the field's check when the window in front has nothing focused | `textCommand()`: the focused responder if it takes the action, else `NSApp.target(forAction:to:from:)`; then `validateUserInterfaceItem`; then `sendAction` | 21 probes, ⌘X and ⌘C through `NSHostingMenu(EditMenuItems)`. NSApp's `keyWindow` and `mainWindow` are answered per instance (`V3Front`). No masked or shown password reached Cut or Copy, and every text was kept (log `[]`). The fields: the unlock form's masked field (`NSSecureTextView`), the unlock form's shown field (`NoCopyEditor`), the editor's masked Password (`NSSecureTextView`) and its shown Password (`NoCopyEditor`), and the new vault wizard's Password on step 3 (in its frame state, the shown `NoCopyEditor`). The windows in front: the main window itself, Settings (window, then hosting view first responder), the new vault wizard, a bare `NSPanel`, and the leave-editor dialog over the editor. A plain field still works as on a Mac. With Settings' search field focused, only that field acts. With nothing focused in Settings, the main window's search field takes ⌘X and ⌘C (`["cut git", "copy git"]`). With a typed password selected in the editor, ⌘C shows no "Password copied." notice. Mutants M1, M2 and M12 are caught. | **Holds** |
| LD-219 addendum: the editor's Passkey row | `MaskedUser(user:site:)` in EditorEntryPage.swift:367 | "masked every editor" covers 23 entries × 8 pages = 184 states, with every user name of the vault as a secret (15 names; "admin" and "root" are left out because titles hold them). The only hits are the 21 Username text fields, which APP-01.23's editor rule keeps in clear. The Passkey rows of GitHub, Apple Account, Mastodon and Linear read "<site>, hidden". Mutant M3 makes all four editors hit. | **Holds** |
| LD-219 addendum: the History sheet | `VersionText` uses `MaskedUser` for an unprotected Username | "masked every version" opens all 21 earlier versions of every entry's history. With the mask off, the version's user name is read in 21 of 21. With it on, none is read. Mutant M4 makes all 21 hit. | **Holds** |
| LD-219 addendum: the Wi-Fi QR title | `DialogCard(user:)`, `Masked.text` and `Masked.spoken` | With the mask off, it reads `Join “Morgan-Home 5G”` (heading and sheet). With it on, it reads `Join “hidden”` twice, and the walk with all 15 user names and the network as secrets is clean. Mutants M5 (no `user:`) and M6 (spoken label back to the title) are caught. | **Holds** |

### Summary of the checks

| Part | Check | Result |
|---|---|---|
| A | Reference current | The reference PNGs and manifest (10-28 01:36) are newer than mockup.html, mockup.js (10-27 22:25) and app.css (10-28 00:22). Round 2 re-exported them and found 0 changed pixels, and these sources have not changed since. target/parity/dom-*.json (10-28 19:18) is newer than the mockup too. |
| A | menubar-menu-bar-icon, light and dark | **PASS**: L 0.54 % (0.5 % outside the accepted areas), D 0.53 % (0.48 %); 0 missing strings, 0 token mismatches, 0 boxes or runs off by more than 2 pt; behaviour "the menu's items; Hide Window hides, then it reads Show Window (T38)" passed; lowest contrast 4.87:1. I viewed the dark snapshot by eye: the Vaults rows, Search Entries… ⌥⌘Space, Password Generator ⌥⌘G, Lock Everything ⇧⌘L, Show Window, Settings… ⌘, and Quit Larsal ⌘Q. menubar-auto-type-picker (E8-S2) also reads PASS. I did not check it. |
| A | states | **PASS 15/15** (states-more-menu L 1.3 % D 1.31 %, states-sort-menu 1.29 % / 1.32 %, states-vault-switcher 1.37 % / 1.41 %; the highest is states-needs-attention D 1.92 %) |
| B | AT-K06 offscreen walk: 51 cases, 314 screen states | 11 172 controls, **1 unnamed** (fail 1), 520 that the focus cannot reach, all 520 disabled (`nofocus_enabled 0`). No masked value holds its secret. The typed unlock password reads `••••••••••••••••••`, and the demo password is found only on "detail shown password". |
| B | Masked user names (S-VIEW-06) | Clean on 5 places, 25 details, 184 editor states (only the Username fields, by the editor rule), 21 earlier versions, the Wi-Fi QR sheet and 5 report tabs |
| C | APP-08 menus against the card | 12 states, 1082 menu lines. In the Google state, every menu's titles and shortcuts equal the card's tables APP-08.2 to APP-08.11 (asserted per menu; I re-read the card's tables against `MenuCard` line by line). The hidden rules hold: Restore Entry ⌘R and Empty Recycle Bin… show only for a bin entry; Remove Passkey only for an entry with a passkey; Arrange Subgroups only for Work; Move Up and Move Down never. The enabled rules (APP-08.12) also hold. While locked, see above. In the editor, Save As, Reports, Passkeys…, New, Edit, Clone, Expire, Delete, Open URL, New Group and Password Generator are off, and the copy items and Save stay on. With a sheet (New Group, Wi-Fi QR), every vault item and Find are off, and Edit > Copy stays on. With no vault, Close Vault is off with no key, and Close Window takes ⌘W. Mask User Names is checked while S-VIEW-06 is on. |
| C | Builder's suites | MenuKeysTests 12/12, MenuBarTests, MenuBarIconTests, AccessibilityWalkTests (19 cases + the secret check), ScreenProtectionTests and ParityStatesTests pass in the full run |
| D | 12 mutants in a private copy | 12 of 12 caught, 11 of them also by my driver. Each restored file is byte-identical to the original. |
| – | Full run (private copy, warnings as errors) | 274 tests in 39 suites, 3 tests missed: FEA-01.34's 50 ms search under load (model only, passes alone), ShownPasswordFieldTests "F-069 … keep no undo copies" (another story's test, which also fails alone), and my driver's "unlock typed shown" (fail 1). Without my 4 driver tests: 270 tests, 268 pass. |
| – | swift format, SwiftLint 0.65.1 strict, check-names (shared tree) | swift format exit 0. SwiftLint exit 0 on the whole tree. check-names: the last line of this report. |

### How I worked

- **Private copy.** `rsync -a --exclude target --exclude larsal-shots --exclude node_modules --exclude .build ./ /tmp/e5s11y-verify3-copy/`, then `cp -R target/larsal-core` into the copy, so its `macos/LarsalCore/Generated` link points to the copy's own core. Derived data was `/tmp/e5s11y-verify3-dd`. The core is the shared one built 10-28 22:47. Some Rust files of other stories are newer, and I did not run `scripts/build-core.sh`: it is not mine to rebuild while others work.
- **Driver.** `macos/LarsalTests/VerifyE5S11R3Tests.swift` (walk listing, menu dump, Cut and Copy probes) and `VerifyE5S11R3DiagTests.swift` (the shown fields' names) existed only in the copy and were deleted with it.
- **Same code as the shared tree.** At 21:45, `cmp` showed the shared tree's MainWindowModel, EditorEntryPage, Dialogs, ViewOptions, DetailFields, LarsalCommands, ReportParts, ReportTabs, ShownPasswordField, UnlockView, MenuKeysTests and MenuKeysMoreTests equal to the copy's originals. Between 22:01 and 22:11, while my mutants ran, another agent edited MainWindowModel, EditorEntryPage, Dialogs, ViewOptions and DetailFields in the shared tree. This looks like the E5 follow-up batch (LD-219 (4)): `textCommand()` now starts with `if action == #selector(NSText.cut(_:)), vaultSelection(cut: true) { return }`, and the detail's masked password rows use `Masked.line()`. At 22:13 the code this round verified is still there word for word: the `target` line, the `validateUserInterfaceItem` guard and `sendAction` in `textCommand()`, `MaskedUser`, the editor's Passkey row (EditorEntryPage.swift:368), the History sheet's `MaskedUser(user: value)` (Dialogs.swift:355), the Wi-Fi title's `shown` and `spoken` (Dialogs.swift:24-25) and the detail's Passkey row (DetailFields.swift:60). LarsalCommands.swift, MenuKeysTests.swift and MenuKeysMoreTests.swift are unchanged. My results are for the code as of 21:20. The new lines belong to the follow-up batch's own checks.
- **Parity.** Run in the copy with its own larsal-shots (from the full run), OCR (`swift design/parity/tools/ocr.swift`, 34 images) and the DOM dump copied from target/parity. The full run's log served as behaviour.log. `node design/parity/tools/compare.mjs menubar` → `menubar: 2/2 PASS`, and `… states` → `states: 15/15 PASS`. The shared design/parity reports were not rewritten: another story wrote the menubar report at 10-29 20:41.

### Part D: mutations

Each mutant is applied to the copy by a script outside the project (`/tmp/e5s11y-verify3-mut.py`, exact strings). Then `xcodebuild build-for-testing`, then `-only-testing:LarsalTests/MenuKeysTests` plus my probes and menu dump; the mask mutants also run my walk listing. The file is restored and compared with `filecmp` (`identical to the original: True` ×12). In the runs that include my walk listing, it also carries fail 1's issue ("unlock typed shown"), which every such run has.

| # | Mutant (file) | Caught by |
|---|---|---|
| M1 | MainWindowModel.swift `textCommand()`: no target from the chain (`… ? focused : nil`), round 3 fix 1 undone | Builder "another window in front, nothing focused…" (MenuKeysMoreTests.swift:44). Also 11 of my probes: every masked or shown field behind Settings, the wizard or a bare panel logs `["cut …", "copy …"]`. The main search field probe still passes, as it should. |
| M2 | `textCommand()`: the `validateUserInterfaceItem` guard removed | Builder "with the shown vault locked, ⌘X and ⌘C leave a selected typed password alone" (:279) and "another window in front…" (:44); 17 of my probes, the under-dialog one included (19 issues) |
| M12 | `textCommand()`: target is the focused responder only (no chain) | 3 tests crash with `-[LarsalTests.OtherWindow cut:]` and `-[NSWindow copy:]: unrecognized selector`, and xctest restarts (exit 65): Builder "another window in front…", "⌘C in a dialog or another of Larsal's windows…", and my probes |
| M8 | LarsalCommands.swift: Cut `.disabled(window.unlock != nil)` again (round 2 fail 2) | Builder "with the shown vault locked, ⌘C and ⌘X act in a settings and a wizard field" (:216, :245 ×2); my menu dump (Cut off in both locked states) and my probe (log only `["copy demo text"]`); 6 issues |
| M9 | MainWindowModel.swift `copyCommand()`: `guard unlock == nil else { return }` again | Builder :245 ×2; my probe (log only `["cut demo text"]`) |
| M3 | EditorEntryPage.swift: the editor's Passkey row as `Text(site · user)` | Builder :66, :67; my walk "masked every editor": the Passkey rows of GitHub, Apple Account, Linear and Mastodon read their user names |
| M4 | Dialogs.swift `VersionText`: an earlier Username as plain `Text` | Builder :71; my walk "masked every version": 21 of 21 versions read their user names |
| M5 | Dialogs.swift: the Wi-Fi QR sheet without `user: network` | Builder :91, :92; my walk "masked wifi qr" |
| M6 | Dialogs.swift `DialogCard`: the spoken title back to `title` | Builder :91, :92; my walk "masked wifi qr" (the sheet's group reads the network) |
| M7 | DetailFields.swift: the detail's Passkey row always `shown: true` (round 2 fail 1) | Builder "the Passkey row's user name is masked until Show…" (:167, :168, :174); my walks "masked every detail" (Apple Account, GitHub, Linear, Mastodon) and "masked places" |
| M10 | ViewOptions.swift `MaskedUser`: never masks | 4 Builder tests with 13 issues (list and detail, editor and History sheet, Health and Passkeys reports, Passkey row); my walks "masked places", "every detail", "every editor", "every version" and "reports" (19 issues) |
| M11 | ViewOptions.swift `Masked.line`: no spoken "hidden" label | 4 Builder tests (:47 the row reads hidden, :67, :168, :205 ×2). My walk does not catch it: it checks for secrets, and "●●●●●●" is none. |

12 of 12 mutants are caught. M12 shows why the chain step is needed: without it, a window with nothing focused gets Cut and Copy itself and crashes.

### Needs Mac QA (owner's go), not fails

1. Real VoiceOver on unlock, list, detail and editor (AT-K06 live), including the masked rows and titles read as "hidden".
2. Tab order and the mockup's focus ring on a key window (APP-08.25).
3. The real menu bar: its top-level order (LD-214 (1)), the macOS standard items, and no second ⌘F or ⌘W item.
4. The status item on a real menu bar: the template image in light and dark, the M08-03 tooltip, a click opening the menu, and the accessory policy while hidden.
5. APP-09.21-a live.
6. ⌃H in a focused password field against "Load into SSH Agent" (V-A08-5).
7. Cut and Copy with real key events and a real key window. The probes prove the path through `NSHostingMenu` and AppKit's own `target(forAction:to:from:)` offscreen.

### Advisories (not fails)

1. **The Wi-Fi QR title masks by text replacement.** `title.replacingOccurrences(of: user, with: …)` also replaces the network name where it occurs inside "Join". A network named "o" would read "J●●●●●●in “●●●●●●”". Nothing leaks; it only looks odd. Masking only the part between the quotes would be exact.
2. **The History sheet's masked user name has no Show** (the Builder's own note). The user can turn the mask off, or read the editor's Username field behind the sheet.
3. **The One-Time Password submenu's last item flips to "Add One-Time Code…" while a sheet is open,** even though Google has a code ("new group sheet" state; the item is off). Label only.
4. **ShownPasswordFieldTests "F-069" fails in the shared tree today.** It is not this story's test (ShownPasswordField.swift was edited at 20:58 by another story), and it fails alone in my copy.
5. **Stale folders from an earlier Checker 1 run are still in /tmp** (/tmp/e5s11y-checker1-*). They are not mine, so I left them (rule 11).

### Commands run (round 3, in order) and their output

1. `rsync … /tmp/e5s11y-verify3-copy/` and `cp -R target/larsal-core …` (How I worked). `xcodebuild build-for-testing -project Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s11y-verify3-dd SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `** TEST BUILD SUCCEEDED **`; the only warnings were appintentsmetadataprocessor's.
2. `xcodebuild test-without-building … -only-testing:LarsalTests/MenuKeysTests` (baseline) → `✔ Test run with 12 tests in 1 suite passed after 23.574 seconds.` This includes the 3 new tests: "another window in front, nothing focused: ⌘X and ⌘C leave the password alone", "Mask User Names hides the editor's Passkey row and the History sheet's user name" and "Mask User Names hides the network name in the Wi-Fi QR dialog's title".
3. Driver added, rebuilt with warnings as errors → `** TEST BUILD SUCCEEDED **`. First driver run → 51 walk cases with 1 issue ("unlock typed shown"). The menu dump and probes had two driver mistakes, which I fixed: I expected ⇧⌘W on Close Window with no vault, and I read the field editor's class after the spy had subclassed it. Rerun of the menu dump, the probes and the diag → `✔ Test run with 3 tests in 2 suites passed`.
4. Diag: the bare `NoCopyTextField` label is "Password" and its `NoCopyCell` label is nil. Unlock shown: the tree element is `NoCopyCell` with label nil. Pressing "Show password" gives `no name`. The editor's shown `NoCopyCell` label is "Password", and the wizard's shown fields read "Password" and "Verify password". The one-line fix tried in the copy (fail 1) reads `AXTextField Password demo-typed-pass-11`. The copy was restored, and `cmp` matches the shared file.
5. Full run `xcodebuild test-without-building … -skip-testing:LarsalUITests` (21:37 to 21:42, load average about 30) → `✘ Test run with 274 tests in 39 suites failed after 281.626 seconds with 3 issues` (Summary of the checks).
6. OCR, then `compare.mjs menubar` and `compare.mjs states` in the copy (Part A rows).
7. `/tmp/e5s11y-verify3-mut.sh M1 M2 M12 M8 M9 M3 M4 M5 M6 M7 M10 M11`: Part D.
8. FEA-01.34 and F-069 alone in the copy: `-only-testing:"LarsalTests/ScreenTests/searchSpeed()"` → `FEA-01.34 search worst: 0.023230916 seconds before rating, 0.036256958 seconds after rating`, `✔ … passed`. `-only-testing:"LarsalTests/ShownPasswordFieldTests/shownPasswordNoUndo()"` → `✘ … failed … with 1 issue` (ShownPasswordFieldTests.swift:57; another story's F-069 work, Advisory 4).
9. `swift format lint --strict --recursive macos` → exit 0, no output. `scripts/install-swiftlint.sh --path` → `/Users/josephilhan/.local/share/swiftlint/0.65.1/swiftlint`, version `0.65.1`. `swiftlint lint --strict --quiet` in macos/ → exit 0, no output.
10. `scripts/check-names.sh` after writing this file and the status line → `names: PASS (3166 files scanned, 16 vault files name-only)`.

Cleanup: I removed /tmp/e5s11y-verify3-copy (with the driver, its target, larsal-shots and parity reports), -dd, -orig, -proof, the -M*.log, -build*.log, -drv*.log, -diag*.log, -full.log, -fea.log, -f069.log, -base.log, -fmt.log and -lint.log files, -mut.py, -mut.sh and -round3.md. /tmp/parity-tools is shared and not mine, so I left it. No process I started is still running.

## Round 2 (2026-10-28)

**Verdict: FAILED (2).** Round 1's three fails are fixed as far as the Builder's tests reach, and each new test fails when its fix is undone (10 of 11 mutants caught; the 11th is equivalent). AT-K06 offscreen passes: 64 screen states, 1693 controls, none unnamed, the 92 the focus cannot reach are all disabled, and no masked value holds its text. Parity passes (menubar-menu-bar-icon light and dark, states 15/15). 31 tests pass in this story's suites (247 of 247 in the full run). Two card rules still do not hold, and no decision records them:

| # | Fail | Card | Failure scenario (proof) | Smallest fix |
|---|---|---|---|---|
| 1 | With View > Mask User Names on, the detail still shows the user name in clear in the Passkey row. Round 1's fail 1 is fixed for the Username row only. | APP-01.23 ("Preview panel: user name hidden behind a show button when S-VIEW-06 is on"), APP-08.8 (S-VIEW-06), APP-08.25, SC-04 ("options to hide usernames"). | Personal unlocked, `display.hide_usernames` on, GitHub selected. The Username row reads ●●●●●● ("hidden") with "Show username", but the Passkey row right below it reads `github.com · alex-dev`, and GitHub's user name field is `alex-dev`. Verify driver "Verify AT-K06 listing" cases "masked github" and "masked passkeys": `AXStaticText at (938.0, 591.0, 136.0, 19.0): shows a hidden secret`, `#secret-hit github.com · alex-dev`. Cause: DetailFields.swift:47-48 draws `Text(verbatim: passkey.site + " · " + passkey.user)` without reading `maskUserNames`. The Builder's test checks only Google, which has no passkey. With the mask on, the Passkeys report also lists the passkey users of Apple Account, Linear and Mastodon, which are their user names (advisory 1), so their detail rows probably leak the same way. Only GitHub was walked. | In the Passkey row, read `@Environment(\.maskUserNames)` as `UserRow` does. While the mask is on and the user name is not shown, draw `passkey.site + " · " + Masked.text` and give it the accessibility label `"\(site), hidden"`. Add a GitHub case to "Mask User Names hides the user name…" that passes `alex-dev` to the walk as a secret. |
| 2 | Edit > Cut (⌘X) and Copy (⌘C) are disabled whenever the shown vault is locked, in every window. So ⌘X and ⌘C do nothing in a text field of the Settings window, the new vault wizard or any other Larsal window while the shown vault is locked, which is how Larsal starts when it reopens a vault. | APP-08.4 ("Cut (⌘X), Copy (⌘C) … act on the focused text field, as on every Mac; AppKit text fields take these keys through the native menu items, so the items must exist"; Copy "in a dialog's own field … is the plain copy"), APP-08.12 (while locked, only "every item that needs an unlocked vault is disabled"). The Builder's report lists this as an open issue, and no decision covers it. | Verify driver "Verify APP-08.4: Edit's Cut and Copy with the shown vault locked and Settings in front" reads the native Edit menu with Personal shown and locked: `Cut ⌘X (off)`, `Copy ⌘C (off)`, `Paste ⌘V`, `Select All ⌘A`, so both expectations fail. Code: LarsalCommands.swift `EditMenuItems` puts `.disabled(window.unlock != nil)` on Cut and Copy, and `copyCommand()` starts with `guard unlock == nil else { return }`. The unlock form does not need this guard: its `SecureField` refuses copy and cut natively, and `ShownPasswordField` overrides `copy`/`cut` to do nothing (APP-03.19, ShownPasswordFieldTests). | Remove `.disabled(window.unlock != nil)` from Cut and Copy. In `copyCommand()`, when `unlock != nil`, send the plain `NSText.copy(_:)` instead of returning. Add a test that reads Edit with the shown vault locked and runs Copy with a settings window in front through the `keyWindow` seam. |

Everything else I checked holds. Details, commands and outputs follow. Nothing left this Mac. No window was shown or ordered front, no status item was added, no real key event was posted (the key events went to offscreen windows' own methods), VoiceOver was not turned on, and the general pasteboard was not read, written or cleared. I did not edit any product code.

### Round 1's fails, re-checked

| Round 1 fail | Fix (Builder) | Re-check | Result |
|---|---|---|---|
| 1 Mask User Names masks nothing | `EntryRow.secondLine(maskUser:)` (ViewOptions.swift), `EntryRowView` reads `\.maskUserNames`, `UserRow` in DetailFields.swift with "Show username" | Test "APP-08.8 APP-01.23 APP-08.25: Mask User Names hides the user name in the list and detail until Show" passes. My walk with mask on, using every user name of the vault as a secret (15 names; "root" and "admin" were left out because they are also in titles), passes on All entries, Favorites, One-time codes and the Google detail. Every row reads "<title>, hidden, …" (for example `Google, hidden, Google, 144 741, Excellent, Oct 20`). After Show, only the detail holds the name (`#shown-user-hits` = 1). A new selection clears `shown` (VaultModel.select). Mutants M1, M2, M9 and M11 each fail the test. | Holds for the list and the Username row. **Fail 1** for the Passkey row. |
| 2 Edit > Copy copies the password in a sheet or another window | `copyCommand()` runs `copy.password` only when `MenuState.copyEntry != nil` and the key window is the main window or none; otherwise it sends `NSText.copy(_:)` | Test "APP-08.4 APP-08.12: ⌘C in a dialog or another of Larsal's windows is the plain copy, never the password" passes. Verify driver "Verify F2…" passes: with the main window key (through `attach` and the `keyWindow` seam) the result is "Password copied."; with another window key (an `NSPanel`, as an alert or popover) there is no toast; with the editor open and the main window key the result is "Password copied." (APP-08.12, "the copy items act on the edited entry"); with the move-to-bin question open there is no toast. Mutants M3 and M4 fail the test. | Holds. **Fail 2** is a different case: the shown vault locked. |
| 3 APP-08.14 and APP-08.18 keys | ⌃H on the unlock and editor Show/Hide buttons, a hidden ⌃G button beside the editor's generator, ↑ ↓ `onKeyPress` on the search field; the start view's ⌫ and "Remove from List" recorded in LD-214 (4) | The four MenuKeysTests key tests pass. Verify driver "Verify F3…" passes: in the list view, ⌃H and ⌃G are not handled (`performKeyEquivalent` returns false), and ↑ on the first row from the search field stays on that row. The hidden ⌃G button is not in the accessibility tree: the editor walk finds no unnamed button, even with its `.accessibilityHidden(true)` removed (mutant M10, equivalent: SwiftUI leaves an opacity-0 view out of the tree). LD-214 (4) now names the start view's ⌫ and Remove from List (no Rust call removes one path from APP-01.14's list) and records ⌃H and ⌃G as key equivalents while the form shows. Mutants M5 to M8 each fail their test. | Holds. Whether a focused field gets ⌃H before a menu item with the same key stays Mac QA (V-A08-5). |

### Summary of the checks

| Part | Check | Result |
|---|---|---|
| A | Reference current (export into a private copy, compared) | PASS: manifest identical. 23 of 182 PNGs differ in bytes, and all 23 have 0 changed pixels. |
| A | menubar-menu-bar-icon, light and dark | PASS: 0.54 % / 0.53 % pixels (0.5 % / 0.48 % outside the accepted areas), 0 missing strings ("Show Larsal" accepted as the card's "Show Window", APP-08.21, LD-214 (2)), 0 token mismatches, 0 boxes or runs off by more than 2 pt, behaviour test passed, 0 unnamed, lowest contrast 4.87:1 |
| A | menubar-auto-type-picker | Not in this story (E8-S2, INT-05). compare.mjs reports it as E8-S2's PASS; I did not check it. |
| A | states (its menus) | PASS 15/15 (states-more-menu, states-sort-menu, states-vault-switcher among them) |
| B | AT-K06 offscreen walk: 46 cases, 64 screen states | PASS for names and reach: 1693 controls, 0 unnamed, 92 the focus cannot reach and all 92 disabled. The walk fails only in the 2 masked passkey states (fail 1). |
| B | Masked fields | PASS: the typed unlock password reads as `•••••••••••`, the editor's masked Password reads as empty, masked rows read "hidden", and the demo password is found only after Show. Fail 1 is the passkey user name. |
| B | Tab order and focus ring on a key window | Needs Mac QA (owner's go). Round 1 showed that an offscreen window never becomes key. |
| C | Every menu item against the card | 75 card items, as in round 1: 4 from SwiftUI, 71 from Larsal, every one either built or hidden by the card's own rules. The Google state has 41 distinct shortcuts, with ⌘C on two items as V-A08-3 requires. The menu dump has 992 lines over 11 states. |
| C | Enabled rules | As the card and LD-214, except fail 2 (Cut and Copy while locked). Mask User Names is checked while S-VIEW-06 is on. Edit > Copy stays on while a sheet is open and then does the plain copy. |
| C | Standard Mac items | By code, unchanged since round 1. The real menu bar is Mac QA. |
| C | APP-09.21, APP-09.22, APP-08.19 to APP-08.22 through the seams | PASS: the 20 MenuBarIconTests pass in the full run. |
| D | 11 mutants in a private copy | 10 each fail their test. M10 is equivalent, because the opacity-0 ⌃G button is already out of the accessibility tree. Each restored file is byte-identical to the shared tree. |
| – | swift format, SwiftLint 0.65.1 strict, check-names | All three pass (exit 0) |

### How I worked

- Shared tree, read-only for product code. I built and ran the full suite with my own derived data (`/tmp/e5s11-verify2-dd`). I did not run `scripts/build-core.sh`: `find crates -name '*.rs' -newer target/larsal-core/Swift/LarsalCore.swift` printed nothing, so the bindings were current.
- Private copy for the Verify driver and the mutants: `rsync -a --exclude target --exclude larsal-shots --exclude node_modules --exclude .build --exclude .swiftpm ./ /tmp/e5s11-verify2-copy/`, then `cp -R target/larsal-core /tmp/e5s11-verify2-copy/target/larsal-core` (the relative `macos/LarsalCore/Generated` link then points to the copy's core). It had its own derived data, `/tmp/e5s11-verify2-mdd`. Before mutating, `cmp` showed the 9 files involved (EntryListView, DetailFields, MainWindowModel, UnlockView, EditorEntryPage, VaultView, ViewOptions, LarsalCommands, MenuKeysTests) identical to the shared tree. The driver `macos/LarsalTests/VerifyE5S11R2Tests.swift` existed only in the copy and was deleted with it.
- Files I wrote in the shared tree: this file; design/parity/menubar/{report.md, report.html, findings.json, app/, diff/} and design/parity/states/{…}, written by compare.mjs, plus a "Verify E5-S11 round 2" section in the menubar report.md and report.html and a `verify` key in its findings.json; target/parity/ocr/<theme>/{menubar,states}-*.json (OCR of the current snapshots); the E5-S11 status line in plan/epics.md. I swapped in my full-run log as target/parity/behaviour.log for the compare run, then put the earlier log back (`cmp` against the backup: same).

### Part A: design parity

Section menubar, frame menubar-menu-bar-icon, light and dark; section states re-run. Full commands are in design/parity/menubar/report.md, section "Verify E5-S11 round 2".

1. Reference current: `rsync -a --exclude reference --exclude first-draft.html design/option-a /tmp/e5s11-verify2-ref/`; then `node option-a/tools/export-reference.mjs` in /tmp/e5s11-verify2-ref (headless Chrome) → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`. `cmp manifest.json` printed `manifest-identical`. 23 PNGs differ in bytes: light editor-editor-advanced, extension-popup-entry, extension-popup-matches-for-this-site, main-main-window-dark, menubar-auto-type-picker, settings-settings-security, settings-settings-shortcuts, states-copied, states-search-tips, states-server-with-ssh-key; dark dialogs-wi-fi-as-qr, editor-editor-advanced, editor-editor-auto-type, editor-editor-entry, extension-popup-app-not-reachable, extension-popup-entry, extension-popup-search-everything, generator-generator-in-the-window, lock-locked-vault-switcher, menubar-menu-bar-icon, reports-reports-browser, settings-settings-shortcuts, states-card. Pixelmatch (threshold 0.1, AA ignored, /tmp/parity-tools) gave `0.000 % 0 px` for every one of them.
2. Snapshots: the full run wrote larsal-shots/{light,dark}/menubar-menu-bar-icon.png and .ax.json at 21:44:59 and 21:45:02 (test "Option A frame menubar-menu-bar-icon, offscreen, light and dark").
3. OCR: `swift design/parity/tools/ocr.swift larsal-shots/{light,dark}/menubar-*.png larsal-shots/{light,dark}/states-*.png`. DOM: target/parity/dom-*.json (10-28 19:18) is newer than mockup.html and mockup.js (10-27 22:25) and app.css (10-28 00:22), so I did not re-run mockup-dom.mjs.
4. `node design/parity/tools/compare.mjs menubar` → `menubar: 2/2 PASS`, `menubar-menu-bar-icon PASS L 0.54% (0.5) D 0.53% (0.48)`, `menubar-auto-type-picker PASS L 0.63% (0.63) D 1.41% (1.41)`. That last row is E8-S2's and was not checked by this story.
5. `node design/parity/tools/compare.mjs states` → `states: 15/15 PASS` (states-more-menu L 1.29 % D 1.3 %, states-vault-switcher L 1.37 % D 1.41 %, states-sort-menu L 1.29 % D 1.33 %; the highest is states-needs-attention D 1.92 %).

| Frame | Light | Dark | Pixels (outside accepted) | Missing strings | Tokens | Geometry > 2 pt | Behaviour | Verdict |
|---|---|---|---|---|---|---|---|---|
| menubar-menu-bar-icon | present | present | 0.54 % (0.5 %) / 0.53 % (0.48 %) | 0 (accepted: "Show Larsal" → "Show Window") | 0 / 0 | 0 + 0 / 0 + 0 | "Parity menubar-menu-bar-icon: the menu's items; Hide Window hides, then it reads Show Window (T38)" passed | PASS |
| menubar-auto-type-picker | – | – | – | – | – | – | – | E8-S2, not this story |

Images: design/parity/menubar/app/{light,dark}/menubar-menu-bar-icon.png and diff/{light,dark}/menubar-menu-bar-icon.png, compared with design/option-a/reference/{light,dark}/menubar-menu-bar-icon.png. Viewed by eye (light app, dark app, dark reference): the items, glyphs, badges, keys and spacing match. The only visible differences are the two accepted ones: the bar's order (Larsal, File, Edit, View, Vault, Entry, per LD-214 (1)) and "Show Window". The snapshot is drawn from the live NSMenu's items, so it proves the items, keys, badges, enabled states and order. The real menu is drawn by macOS, which is Mac QA.

### Part B: AT-K06 offscreen

Method, as in round 1. Each screen is the real SwiftUI view in a borderless window at x −20000 that is never ordered front. I read it through the AppKit accessibility tree in the test process. For every element with a control role, I recorded:

- the role;
- the name VoiceOver reads (label and title);
- the value;
- whether it is enabled;
- whether the focus may move to it (`isAccessibilitySelectorAllowed(setAccessibilityFocused:)`).

I also ran the Builder's `AccessWalk.check` on the same tree, with secrets: the Google demo password on every main-window screen, the typed unlock password, and with the mask on, every user name of the vault.

Driver test "Verify AT-K06 listing" has 46 cases and covers 64 states:

- **Start and unlock:** welcome; unlock; unlock with a typed password; unlock with a key file; the Touch ID form; the unlock vault switcher.
- **List and detail:** list and detail; detail with the password shown; Favorites; One-time codes; Passkeys; search "git"; search tips; the sort menu; More actions; the vault switcher; Recycle Bin; empty vault.
- **Dialogs and questions (new in round 2):** New Group, move to Recycle Bin, clone, empty bin, discard, leave editor, remove passkey, remove field, big file, risky file, replace file.
- **Editor:** every page, plus its generator.
- **Toolbar generator.**
- **Reports (new):** all 5 tabs.
- **Mask on (new):** list and detail; GitHub; the user name shown; Favorites; One-time codes; Passkeys.
- **Other windows:** settings (7 pages); vault settings (5 pages); the new vault wizard.

The Builder's suite "AT-K06: every control on every built screen is named and reachable" (19 cases) and "AT-K06: the walk finds a password on screen once Show was chosen, and never before" pass in the full run.

Result: `✘ Test "Verify AT-K06 listing" with 46 test cases failed … with 2 issues`. The 2 issues are the masked passkey row (fail 1). Every other case passed.

- **Totals:** 1693 controls, 0 unnamed, 92 that the focus cannot reach, all 92 disabled (`awk`: `notfocusable_enabled=0`).
- **Most common unreachable, all disabled:** "Type login" ×14, "Forward" ×7, Touch ID and security key items, "Expiry date" ×3.
- **Per screen (controls/unnamed/unreachable):**
  - Start and unlock: welcome 3/0/1; unlock 7/0/2; unlock typed password 7/0/2; unlock key file 7/0/2; unlock touch id 3/0/1; unlock vault switcher 9/0/3.
  - List and detail: list and detail 57/0/1; detail shown password 57/0/1; favorites 43/0/1; codes 45/0/1; passkeys 42/0/1; search 40/0/1; search tips 64/0/1; sort menu 5/0/0; more actions 11/0/3; vault switcher 9/0/1; recycle bin 32/0/0; empty vault 17/0/2.
  - Dialogs: dialog 18/0/1; delete question 3/0/0; clone question 5/0/0; empty bin question 2/0/0; discard 2/0/0; leave editor 3/0/0; remove passkey 2/0/0; remove field 2/0/0; big file 2/0/0; risky file 2/0/0; replace file 2/0/0.
  - Editor: editor 47/0/2; editor entry 47/0/2; advanced 32/0/0; icon 73/0/0; autoType 35/0/1; browser 36/0/0; ssh 41/0/10; properties 31/0/0; history 46/0/3; editor generator 61/0/2; generator 71/0/1.
  - Reports: reports 40/0/0; breach 27/0/0; stats 26/0/0; passkeys 30/0/0; browser 26/0/0.
  - Mask on: masked list and detail 58/0/1; masked github 58/0/1; masked shown username 58/0/1; masked favorites 44/0/1; masked codes 46/0/1; masked passkeys 43/0/1.
  - Settings: general 37/0/7; security 29/0/4; autoType 23/0/3; browser 25/0/15; ssh 12/0/2; share 14/0/2; keys 10/0/1.
  - Vault settings: general 16/0/0; security 17/0/3; bin 9/0/3; history 11/0/0; browser 8/0/0.
  - New vault: 5/0/0.

  Every control is listed in the appendix.

Masked fields (rule 4, LD-206, LD-207):

- The unlock field with the typed demo password reads `•••••••••••`; the secret check on the typed password finds nothing.
- The editor's masked Password field reads empty.
- Masked rows read 12 dots.
- Masked user names read "hidden". The detail's Username shows ●●●●●● read as "hidden", with "Show username" and "Copy username"; after Show, "Hide username".
- The Google demo password is found only on "detail shown password", where the user chose Show.

Not provable offscreen (Mac QA, owner's go): real VoiceOver listening, and the Tab order and focus ring on a key window.

### Part C: APP-08 against the card

Method, as in round 1. Each menu's items are the same view Larsal puts in its SwiftUI commands. `NSHostingMenu` turns that view into the native NSMenu, which the driver read in 11 states:

- no vault;
- the shown vault locked;
- the shown vault locked with Work unlocked;
- Personal unlocked with its first row (GitHub) selected by default;
- Google selected;
- Google selected with the mask on;
- GitHub selected;
- the Work group;
- the editor open;
- the New Group sheet open;
- a Recycle Bin entry.

Driver test "Verify APP-08 menu dump in each state" passed; the dump has 992 lines. The Builder's MenuBarTests (19) and MenuBarIconTests (20) pass in the full run.

Items per menu, Google state, unchanged from round 1:

- **Larsal:** Check for Updates… (off).
- **Settings:** Settings… ⌘,.
- **File, 10 items:** New Vault… ⇧⌘N, Open Vault… ⌘O, Open Recent ▸ (Family, Work, Personal; Clear Menu off), Close Vault ⌘W, Close Window ⇧⌘W, Save ⌘S, Save As… ⇧⌘S, Save a Copy… (off), Import… (off), Export ▸ CSV…, HTML…, XML… (off).
- **Edit, 5 own:** Cut ⌘X, Copy ⌘C, Paste ⌘V, Select All ⌘A, Find… ⌘F.
- **Vault, 8 items:** Lock Personal ⌘L, Lock Everything ⇧⌘L, Vault Settings… ⇧⌘,, Change Credentials…, Reports ⇧⌘R, Passkeys…, Import Passkey… (off), Merge Another Vault… (off).
- **Entry, 16 shown:**
  - New Entry ⌘N, Edit Entry ⌘E, Clone Entry… ⌘D, Expire Entry, Delete Entry ⌘⌫.
  - Copy Username ⌘B, Copy Password ⌘C, Copy URL ⇧⌘U.
  - Copy Field ▸ (Title ⌘I, Notes).
  - One-Time Password ▸ (Copy One-Time Password ⌘T; Copy Password with Code ⌘Y, Show Code ⇧⌘T, Show as QR Code and Change One-Time Code… are off).
  - Tags (off).
  - Open URL ⌘U, Fetch Site Icon ⇧⌘D (off), Type Login ⇧⌘V (off), Auto-Type Username Only and Password Only (off).
  - In their own states: Restore Entry ⌘R (bin entry) and Remove Passkey (GitHub, off).
- **Group, 5 shown:** New Group…, then Edit Group…, Clone Group…, Delete Group… and Fetch Site Icons for Group… (all off). Arrange Subgroups A to Z and Z to A show in the Work group (off); Empty Recycle Bin… shows for a bin entry.
- **View, 7 items:** Appearance ▸ (System ✓, Light, Dark), Hide Sidebar ⌃⌘S, Hide Details, Mask User Names ⇧⌘B (✓ with the mask on), Mask Passwords ⇧⌘C ✓, Keep Window on Top ⇧⌘A, Permit Screen Capture (now on, built by E6-S5).
- **Tools:** Password Generator ⌥⌘G.
- **Window:** Minimize ⌘M, Zoom, Show Next Vault ⌃Tab, Show Previous Vault ⌃⇧Tab, Personal ⌘1 ✓, Work ⌘2, Family ⌘3.
- **Help:** Keyboard Shortcuts ⌘/.

Enabled rules seen in the dump:

- **No vault:** Close Window takes ⌘W, and Save, Find, every Vault item and every Entry item are off.
- **Shown vault locked:** every Vault, Entry and Group item is off, and so are Password Generator, Save, Save As and Find. Lock Everything stays on while Work is unlocked (T09). **Cut and Copy are off as well (fail 2).**
- **Editor open:** Save As…, Reports, Passkeys…, New, Edit, Clone, Expire, Delete, Open URL, New Group and Password Generator are off; the copy items and Save stay on.
- **New Group sheet:** every vault item and Find are off, and Edit > Copy stays on, now doing the plain copy.
- **Bin entry:** New, Edit and Clone are off; Restore Entry ⌘R and Empty Recycle Bin… are on.

Keys inside the window (APP-08.14):

- **List:** ↑ ↓ (EntryListView.swift:194-201); Return and ⌫/⌦ (ContextMenus.swift).
- **Escape:** for dialogs, menus, the editor and the search.
- **Editor:** ⌘S.
- **Generator:** ⌘Return.
- **New since round 1:** ⌃H on unlock and in the editor, ⌃G in the editor, ↑ ↓ from the search field. These are tested in MenuKeysTests and the driver.
- **Not built, recorded in LD-214 (4):** the start view's ⌫ and Remove from List.

APP-09.21 and APP-09.22 through the seams: in the full run, every test passes for APP-09.21 (both branches), APP-09.22 (×4), the two rule 10 cases, APP-08.19 (×4), APP-08.20 (×2), APP-08.21, APP-08.22 T39 and Rule 9.

The reference app's installed resources were not read. That step is optional, and the card's labels were already verified against the reference source (V-A08-1 to V-A08-4).

### Part D: mutations

In the private copy, one mutant at a time. Each run was: a python script outside the project replaces one exact string, then `xcodebuild build-for-testing … -derivedDataPath /tmp/e5s11-verify2-mdd`, then the named suite runs. After each run the file is restored and `filecmp` checks it against the shared tree.

| # | Mutant (file) | Suite run | Caught by |
|---|---|---|---|
| M1 | EntryListView.swift: `row.secondLine(maskUser: maskUser)` → `maskUser: false` (list row unmasked) | MenuKeysTests | "APP-08.8 APP-01.23 APP-08.25: Mask User Names hides…": 5 issues at :44 `shown().isEmpty`, :45 the walk with the user name as secret, :47 the row reads "hidden", :52, :54 |
| M2 | DetailFields.swift `UserRow`: `let masked = false` (detail user name unmasked) | MenuKeysTests | the same test: 3 issues (:44, :45, and `node("Show username")` missing at ParityTests.swift:360) |
| M3 | MainWindowModel.swift `copyCommand()`: drop the key-window condition | MenuKeysTests | "APP-08.4 APP-08.12: ⌘C in a dialog or another of Larsal's windows…": 1 issue at :78 (the settings window in front gets "Password copied.") |
| M4 | `copyCommand()`: drop the `copyEntry` condition (round 1's fallback) | MenuKeysTests | the same test: 2 issues at :68 (New Group dialog) and :78 |
| M5 | UnlockView.swift: ⌃H removed | MenuKeysTests | "APP-08.14: ⌃H shows and hides the unlock password": 3 issues (:90, :91, :93) |
| M6 | EditorEntryPage.swift: ⌃H removed | MenuKeysTests | "APP-08.14: in the editor ⌃H … and ⌃G …": 3 issues (:107, :108, :110) |
| M7 | EditorEntryPage.swift: ⌃G removed from the hidden button | MenuKeysTests | the same test: 2 issues (:113, :114) |
| M8 | VaultView.swift: the search field's ↑ ↓ `onKeyPress` → Page Up only | MenuKeysTests | "APP-08.14: ↓ and ↑ in the search field…": 1 issue at :140 |
| M9 | ViewOptions.swift: the masked second line without its "hidden" label | MenuKeysTests | "Mask User Names hides…": 1 issue at :47 (the row does not read "hidden") |
| M10 | EditorEntryPage.swift: `.accessibilityHidden(true)` removed from the hidden ⌃G button | AccessibilityWalkTests | Not caught, and an equivalent mutant: `✔ Test run with 2 tests in 1 suite passed`. SwiftUI already leaves the opacity-0 button out of the tree, so the walk (which fails any unnamed AXButton) finds no button with the modifier or without it. The modifier is belt and braces. |
| M11 | DetailFields.swift: "Show username" label → "" | MenuKeysTests | "Mask User Names hides…": 2 issues, the AT-K06 walk at :45 (`no name`) and the press at ParityTests.swift:360 |

10 of 11 mutants are caught; M10 changes nothing observable. Every restored file is byte-identical to the shared tree (`restored, identical to shared tree: True` ×11, and a final `cmp` of the 8 product files and MenuKeysTests.swift).

### Needs Mac QA (owner's go), not fails

1. Real VoiceOver on unlock, list, detail and editor (AT-K06 live, T43), including the masked rows read as "hidden".
2. Tab order and the mockup's focus ring on a key window (APP-08.25).
3. The real menu bar: its top-level order (LD-214 (1)), the macOS standard items, and no second ⌘F or ⌘W item.
4. The status item on a real menu bar: the template image in light and dark, the M08-03 tooltip, a click opening the menu, and the accessory policy while hidden.
5. APP-09.21-a live: `Larsal --minimized` with S-UI-10 on.
6. ⌃H in a focused password field against "Load into SSH Agent" (V-A08-5). In the real app the window's key equivalent should come first; this was not provable offscreen.

### Advisories (not fails)

1. **Reports show user names with Mask User Names on.** Health check has 9 strings (for example "Zalando, alex.morgan@posteo.de") and Passkeys has 4 (alex.morgan@icloud.com, alex-dev, alex@morgan-labs.dev, @alex@mastodon.social). APP-01.23 names only the list, the preview and the editor; the Builder lists this as an open issue. The lead should decide whether the reports follow S-VIEW-06 (E5 follow-up batch).
2. **Wi-Fi label mismatch.** With the mask on, a Wi-Fi entry's masked "Network name" row reads "Show username" / "Copy username". Its buttons would read better as "Show network name" and "Copy network name".
3. **LD-181 (5)'s condition no longer holds.** The condition was "no unprotected vault text is selectable", but the editor's Title, Username, Website and Notes fields are selectable vault text. `copyCommand()` copies a selection with AppKit's own `copy(nil)`, with no markers and no timer, while APP-03.7 and APP-08.4 want `copy.selection` through Rust. This belongs to APP-03 (E6 follow-up), not to this story's fixes.
4. **LD-214 (7) ponytail limit, as recorded.** A user name equal to the URL's host shows, and a custom field in place of a missing user name is masked too. A user-name flag on `EntryRow` from Rust would make the rule exact.
5. **Round 1's advisories 1 and 2 are still open.** The Builder's AT-K06 walk has no typed-password unlock case (my driver covers it: the value is bullets), and no product test reads the right-click menus or `entryKeys`.
6. **Round 1 never walked the delete question.** Its "delete question" case called `askDelete()`, which deletes at once while S-ENTRY-02 is off, so that case walked the list. Round 2 walks the move-to-bin question itself: 3 controls, all named. Its "Do not ask again" toggle is exposed as an AXButton with the value "off" rather than as an AXCheckBox (E5 dialogs).

### Commands run (round 2, in order) and their output

1. `find crates -name '*.rs' -newer target/larsal-core/Swift/LarsalCore.swift` → no output, so the bindings were current.
2. `xcodebuild build-for-testing -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s11-verify2-dd SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` (shared tree, 21:42:39 to 21:43:05) → `** TEST BUILD SUCCEEDED **`, no warnings or errors from Swift.
3. `xcodebuild test-without-building … -derivedDataPath /tmp/e5s11-verify2-dd -only-testing:LarsalTests` (21:43:09 to 21:45:42) → `✔ Test run with 247 tests in 37 suites passed after 129.810 seconds.` This included `✔ Suite MenuKeysTests passed`, `✔ Suite AccessibilityWalkTests passed`, `✔ Suite MenuBarIconTests passed`, `✔ Suite MenuBarTests passed` and `✔ Suite ParityStatesTests passed`. The LD-206 pasteboard miss did not occur.
4. Reference export, OCR and `compare.mjs menubar` / `states`: Part A. Backup of design/parity/{menubar,states}, target/parity/behaviour.log and the OCR files in /tmp/e5s11-verify2-pbak first.
5. Private copy and core copy (How I worked). Driver added. `xcodebuild build-for-testing … -derivedDataPath /tmp/e5s11-verify2-mdd` → `** TEST BUILD SUCCEEDED **`.
6. `xcodebuild test-without-building … -only-testing:LarsalTests/VerifyE5S11R2Tests`, final run → `✘ Test run with 6 tests in 1 suite failed … with 4 issues`:
   - "Verify AT-K06 listing" (46 cases): 2 issues, "masked github" and "masked passkeys" (fail 1).
   - "Verify APP-08.4: Edit's Cut and Copy with the shown vault locked and Settings in front": 2 issues (fail 2).
   - "Verify APP-08 menu dump in each state", "Verify F2: ⌘C with the main window key copies the password; with an alert window key the plain copy", "Verify F1: reports and Wi-Fi with Mask User Names on" and "Verify F3: ⌃H and ⌃G do nothing in the list; ↑ ↓ from the search field stop at the ends" passed.
   - The two earlier driver runs failed only on driver mistakes, which I fixed: user names that are also part of a title ("root", "admin"), and `askDelete()` deleting at once.
7. Mutants M1 to M11: Part D.
8. `swift format lint --strict --recursive macos` → exit 0, no output. `scripts/install-swiftlint.sh --path` → `$HOME/.local/share/swiftlint/0.65.1/swiftlint`, version `0.65.1`. `swiftlint lint --strict --quiet` in macos/ → exit 0, no output.
9. `scripts/check-names.sh` after writing these files: the result is the last line of this report.

Test names of the Builder's suites for this story (all passed in the full run):

- **MenuKeysTests:**
  - "APP-08.8 APP-01.23 APP-08.25: Mask User Names hides the user name in the list and detail until Show"
  - "APP-08.4 APP-08.12: ⌘C in a dialog or another of Larsal's windows is the plain copy, never the password"
  - "APP-08.14: ⌃H shows and hides the unlock password"
  - "APP-08.14: in the editor ⌃H shows and hides the password and ⌃G opens the generator"
  - "APP-08.14: ↓ and ↑ in the search field move the list's selection"
- **MenuBarTests:** "APP-08.2 to APP-08.11: every menu's items, labels and shortcuts as the card's tables" (11 menus), plus 18 more (APP-08.1, T04, T09, T11, T12, T16, T18, T20, T21, V-A08-3, ⌘W with no vault and the rest).
- **MenuBarIconTests:** APP-08.19 T33, T34, T35 and the Dock case; ⌘W with Settings in front; APP-09.21 ×2; Rule 10 ×2; APP-09.22 ×4; APP-08.20 ×2; Parity menubar-menu-bar-icon (T38); APP-08.22 T39; APP-08.21; the Option A frame; Rule 9.
- **AccessibilityWalkTests:** "AT-K06: every control on every built screen is named and reachable" (19 cases); "AT-K06: the walk finds a password on screen once Show was chosen, and never before".

Snapshot paths:

- larsal-shots/light/menubar-menu-bar-icon.png and .ax.json, and larsal-shots/dark/menubar-menu-bar-icon.png and .ax.json.
- design/parity/menubar/app/{light,dark}/ and diff/{light,dark}/.
- design/parity/states/app and diff, for the 15 states frames.

Cleanup: removed /tmp/e5s11-verify2-copy, -dd, -mdd, -ref, -orig, -pbak, -tools, -proof and -logs (the listing in the appendix was copied from -proof first), and target/option-a/{v2walk*, v2menu*, v2copy, v2cut, v2mask-more, v2keys} were never in the shared tree (they lived in the copy's target). No process I started is still running.

## Round 1 (history, 2026-10-28)

Round 1 as written then. Its appendix (1457 controls over 52 states) is replaced by the round 2 appendix below, which covers the same screens plus the new ones.

Date 2026-10-28. Story E5-S11 (plan/epics.md), cards APP-08 (all rules), APP-09.21 and APP-09.22, check AT-K06 (plan/attacks-and-checks.md). I did not build or check this story. Builder report and Checker 1 round 3 ("passed") were the inputs.

**Verdict: FAILED (3).** AT-K06 offscreen passes (52 screen states, 1457 controls: none unnamed, none enabled and unreachable, no masked value holds its text). Parity passes (menubar-menu-bar-icon light and dark, states 15/15). Ten mutants each fail a test. Three card rules of APP-08 do not hold, and no decision records them:

| # | Fail | Card | Failure scenario (proof) | Smallest fix |
|---|---|---|---|---|
| 1 | View > Mask User Names (⇧⌘B, S-VIEW-06) is stored and checked, but nothing on screen is masked. | APP-08.8 (S-VIEW-06, APP-01.23), APP-08.25 ("the masked text of APP-01.23 is read as 'hidden'"), parity row SC-04; E5-S9's inventory routes S-VIEW-06 to E5-S11 (security/parity/E5-S9-settings-inventory.md). | Personal unlocked, Google selected, `display.hide_usernames` on and `window.view.load(...)`: the menu's check mark is on and the setting is stored, but the list row still reads "Google, alex.morgan@gmail.com, …" and the detail still reads "alex.morgan@gmail.com" (2 strings before, 2 after). Verify driver "Verify S-VIEW-06: Mask User Names hides the user names in the list and the detail (APP-01.23)" fails at `after.isEmpty`. `grep` finds `maskUserNames` read only by ViewOptions.swift and the menu (LarsalCommandsVault.swift:164). | Read `window.view.maskUserNames` in the entry row (EntryListView.swift `EntryRowView`, the subtitle shows `●●●●●●` and reads "hidden") and in the detail's Username field (hidden behind a Show button, APP-01.23), plus a test like the driver's. |
| 2 | Edit > Copy (⌘C) copies the selected entry's password while a sheet or dialog is open, or while another Larsal window is in front, when no text is selected. | APP-08.4 ("in a dialog's own field it is the plain copy"), APP-08.12 ("while a sheet or alert is open on the main window, items that act on the vault are disabled"), APP-08 security note "Clipboard keys". | Personal unlocked, Google selected, New Group dialog open (`main.dialog = .newGroup`): Vault Settings… and every Entry item (Copy Password too) are off, but Edit > Copy is on, and running it gives the toast "Password copied." (driver "Verify APP-08.4 APP-08.12: Edit > Copy with a sheet open and no text selected", fails at `toast == nil`). By code: `MainWindowModel.copyCommand()` falls back to `main?.copy("Password")` whenever the first responder is not a text view with a selection, whatever the key window is, so ⌘C in the Settings window or the new vault wizard with no selection copies the password too. | In `copyCommand()`: run `copy.password` only when `MenuState(window:).copyEntry != nil` and the key window is the main window (`WindowRules.shared.keyWindow()` nil or `=== WindowRules.shared.window`); otherwise send the plain `NSText.copy(_:)` to the first responder. Test: the driver's dialog case, plus Settings in front through the `keyWindow` seam. |
| 3 | Keys inside the window that the card lists are not built and are not recorded as deferred. | APP-08.14 (⌃H "a focused password-kind field: show or hide its text"; ⌃G "a focused password field that offers the generator"; ↑ ↓ "entry list, or the search field"), APP-08.18 (start view: ⌫ and "Remove from List" remove a recent row). | `grep -rn 'keyboardShortcut("h", modifiers: .control)'` finds ⌃H only in NewVaultView.swift:216 and VaultSettingsPages.swift:228, not in UnlockView.swift (unlock password) or EditorEntryPage.swift (editor password); ⌃G only in NewVaultView.swift:218 (the editor's generator button has ⌥⌘G only, EditorEntryPage.swift:282); the search field (VaultView.swift:140-157) has Escape but no ↑ ↓; WelcomeView.swift has no `onDeleteCommand`, `onKeyPress` or `contextMenu`. LD-214 (4) lists ⇧⌘] and ⇧⌘[ and Clear Menu as not built, but none of these. | Either add them (`.keyboardShortcut("h", modifiers: .control)` on the Show/Hide password buttons of the unlock form and the editor, `.keyboardShortcut("g", modifiers: .control)` on the editor's generator button, `.onKeyPress(.upArrow/.downArrow) { model.move(∓1) }` on the search field, ⌫ and "Remove from List" on the start view's rows once APP-01.14 has its Rust call) with a test, or record each in LD-214 (4) with its reason. |

Everything else checked holds; details, commands and outputs below. Nothing left this Mac. No window was shown or ordered front, no status item was added, no real key event was posted, VoiceOver was not turned on, and the general pasteboard was not read, written or cleared.

### Summary of the checks

| Part | Check | Result |
|---|---|---|
| A | Reference current (export into a private copy, compared) | PASS: manifest identical; 171 of 182 PNGs byte-identical, the other 11 have 0 changed pixels |
| A | menubar-menu-bar-icon light and dark | PASS: 0.54 % / 0.53 % pixels (0.5 % / 0.48 % outside accepted), 0 missing strings ("Show Larsal" accepted as the card's "Show Window", APP-08.21, LD-214 (2)), 0 token mismatches, 0 boxes or runs off by more than 2 pt, behaviour test passed, contrast lowest 4.87:1 |
| A | menubar-auto-type-picker | E8-S2's (INT-05): listed as a later story, not checked |
| A | states (its menus) | PASS 15/15 (states-more-menu, states-sort-menu, states-vault-switcher among them) |
| B | AT-K06 offscreen walk, 34 cases, 52 screen states | PASS: 1457 controls, 0 unnamed, 90 not focusable and all 90 disabled, 0 walk failures |
| B | Masked fields | PASS: the typed unlock password reads as bullets, the editor's masked password as empty, masked rows as dots; the demo password is found only after Show |
| B | Tab order on a key window | Needs Mac QA: an offscreen window never ordered front does not become key (`isKeyWindow=false`), so Tab cannot be measured offscreen |
| C | Every menu item against the card | 75 card items (APP-08.2 to APP-08.11, a submenu counted once, the vault items once): 4 come from SwiftUI (About, Quit, Undo, Redo), 71 from Larsal's commands; 68 of the 71 show in at least one of the 10 states read, and the other 3 are hidden by the card's own rules (Move Up and Move Down while sorted, Larsal Help until E14); 27 are drawn disabled for later stories (LD-214 (4)); 41 distinct shortcuts in the main state, as the card except the recorded ⇧⌘] and ⇧⌘[; one key on two items, ⌘C, as V-A08-3 requires |
| C | Enabled rules across 10 states | As the card and LD-214, except fail 2 and the advisories below |
| C | Standard Mac items | By code: LarsalCommands keeps SwiftUI's About, Services, Hide, Hide Others, Show All, Quit, Undo and Redo, Enter Full Screen, Bring All to Front and the window list; the real menu bar is Mac QA |
| C | APP-08.19 to APP-08.22, APP-09.21, APP-09.22 through the seam | PASS: 13 Builder tests (APP-09.21 ×2, APP-09.22 ×4, rule 10 ×2, APP-08.19 ×4, APP-08.22 ×1) and 5 Verify driver tests |
| C | S-VIEW-06 | FAIL 1 |
| C | Edit > Copy | FAIL 2 |
| C | APP-08.14 and APP-08.18 keys | FAIL 3 |
| D | 10 mutants in a private copy | Each fails at least one test; each restored file is byte-identical to the shared tree |

### How I worked

- Shared tree, read only for product code. Build and full test run with my own derived data (`-derivedDataPath /tmp/e5s11-verify-dd`); `scripts/build-core.sh` was not run, because no `crates/larsal-ffi/src/*.rs` file was newer than `target/larsal-core/Swift/LarsalCore.swift` when I built (20:37), and its `rm -rf` of the shared `target/larsal-core` would hit the other agents' builds.
- Private copy for the Verify driver and the mutants: `rsync -a --exclude target --exclude larsal-shots --exclude node_modules --exclude .build --exclude .swiftpm ./ /tmp/e5s11-verify-copy/`, then `cp -R target/larsal-core /tmp/e5s11-verify-copy/target/larsal-core` (the relative `macos/LarsalCore/Generated` link then points at the copy's core). Own derived data `/tmp/e5s11-verify-mdd`. The driver file `macos/LarsalTests/VerifyE5S11Tests.swift` lived only in the copy and was deleted with it.
- Files I wrote in the shared tree: this file; design/parity/menubar/{report.md, report.html, findings.json, app/, diff/} and design/parity/states/{…} (written by compare.mjs; a Verify section appended to the menubar report.md); target/parity/behaviour.log and target/parity/ocr/<theme>/{menubar,states}-*.json; three small entries in design/parity/tools/notes.mjs (a LATER entry for the auto-type picker, which E8-S2's agent replaced at 21:12 after it built that frame; the APP-08.21 rule; the frame's notes); the E5-S11 status line in plan/epics.md. No product code.
- Other agents worked at the same time (E5-S10 saving, E8-S2 Auto-Type, E9-S2 Verify). Between my build (20:37) and the end, only their files changed (`find … -newer`: crates/larsal-ffi/src/{larsal_settings,saving}.rs, macos/Larsal/Saving.swift, macos/LarsalTests/SavingTests.swift, specs, notes.mjs); no E5-S11 file changed, and every mutated file in the copy was byte-identical to the shared tree after restore.

### Part A: design parity

Section menubar, frame menubar-menu-bar-icon (light and dark); section states re-run. Full commands and outputs in design/parity/menubar/report.md ("Verify E5-S11 run").

1. Reference current. `rsync -a --exclude reference --exclude first-draft.html design/option-a /tmp/e5s11-verify-ref/`; `cd /tmp/e5s11-verify-ref && node option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames` (20:37:48 to 20:38:59). `cmp` with the shared set: `manifest-identical`; 11 PNGs differ in bytes (dialogs-wi-fi-as-qr, editor-editor-auto-type, extension-in-page-one-time-code, extension-in-page-save-sign-in, generator-generator-in-the-window, menubar-auto-type-picker, settings-settings-auto-type, settings-settings-browser-integration, settings-settings-security, states-search-tips, vault-vault-settings-recycle-bin, all light); pixelmatch (threshold 0.1, AA ignored) on each: `0.000 % 0 px`. Both menubar-menu-bar-icon images are byte-identical. So the shared reference was not rewritten.
2. Snapshots: the full run below wrote larsal-shots/<theme>/menubar-menu-bar-icon.png and .ax.json (test "Option A frame menubar-menu-bar-icon, offscreen, light and dark", borderless window at x −20000, never ordered front, sRGB).
3. OCR: `swift design/parity/tools/ocr.swift larsal-shots/{light,dark}/menubar-*.png larsal-shots/{light,dark}/states-*.png`. DOM: target/parity/dom-*.json (19:18) is newer than mockup.html, mockup.js (Oct 27 22:25) and app.css (Oct 28 00:22), so mockup-dom.mjs was not re-run.
4. Behaviour log: full-run log with the 16 `ParityStatesTests` names removed (their pasteboard check missed in the full run, LD-206), then the alone run of `ParityStatesTests` (16 of 16 passed) appended → target/parity/behaviour.log.
5. `node design/parity/tools/compare.mjs menubar` (before my notes): `menubar: 0/2 PASS`, `menubar-menu-bar-icon FAIL L 0.54% (0.54) D 0.53% (0.53) light: 1 missing string(s) | dark: 1 missing string(s)`, `menubar-auto-type-picker FAIL … frame missing`.
6. notes.mjs: rule `frames: ['menubar-menu-bar-icon'], test: m === 'Show Larsal', app: /^(Show|Hide) Window$/` (APP-08.21 card words over the mockup, LD-214 (2), BUILD-AND-VERIFY order 2); LATER `menubar-auto-type-picker: E8-S2 (INT-05)`; frame notes. Then `node design/parity/tools/compare.mjs menubar` → `menubar: 1/1 PASS`, `menubar-menu-bar-icon PASS L 0.54% (0.5) D 0.53% (0.48)`, `menubar-auto-type-picker later story (E8-S2 (INT-05))`.
7. `node design/parity/tools/compare.mjs states` → `states: 15/15 PASS` (states-more-menu L 1.29 % D 1.3 %, states-vault-switcher L 1.37 % D 1.41 %, states-sort-menu L 1.29 % D 1.32 %, the highest states-needs-attention D 1.92 %).

| Frame | Light | Dark | Pixels (outside accepted) | Missing strings | Tokens | Geometry > 2 pt | Behaviour | Verdict |
|---|---|---|---|---|---|---|---|---|
| menubar-menu-bar-icon | present | present | 0.54 % (0.5 %) / 0.53 % (0.48 %) | 0 (accepted: "Show Larsal" → "Show Window") | 0 / 0 | 0 + 0 / 0 + 0 | "Parity menubar-menu-bar-icon: the menu's items; Hide Window hides, then it reads Show Window (T38)" passed | PASS |
| menubar-auto-type-picker | – | – | – | – | – | – | – | E8-S2, not this story |

Images: design/parity/menubar/app/{light,dark}/menubar-menu-bar-icon.png, diff/{light,dark}/menubar-menu-bar-icon.png, against design/option-a/reference/{light,dark}/menubar-menu-bar-icon.png. Looked at by eye: the menu's items, glyphs, badges, keys and spacing match; the two visible differences are the accepted ones (the bar's order File, Edit, View, Vault, Entry, LD-214 (1); "Show Window"). What the picture proves: the snapshot is drawn by test code (`MenuBarIconFrame`) from the live NSMenu's items, so it proves the items, keys, badges, enabled states and order; the real menu is a native NSMenu that macOS draws (APP-08.24 "native menus and panels follow macOS", APP-08.25), so its look on screen is Mac QA. Accessibility of the frame: the status item's button is named "Larsal" with M08-03 as tooltip (`SystemStatusSlot.show`), and the menu is native, which VoiceOver reads with no extra work (APP-08.25).

### Part B: AT-K06 offscreen

Method. Each screen is the real SwiftUI view in a borderless window at x −20000, never ordered front, read through the AppKit accessibility tree in the test process (`accessibilityEnhancedUserInterface` set for this process only, `AppleKeyboardUIMode` 2 in the volatile argument domain). For every element with a control role (button, check box, radio, text field, text area, pop-up, menu button, slider, link, disclosure, combo box, incrementor, menu item, search field, segmented control, colour well, date field) I recorded its role, the name VoiceOver reads (label and title), its value, enabled, and whether the focus may move to it (`isAccessibilitySelectorAllowed(setAccessibilityFocused:)`); and I ran the Builder's `AccessWalk.check` on the same tree (name rule: a non-space character outside U+E000 to U+F8FF; inside the window or a scroll area; focus allowed when enabled; no clickable picture that is not a control; no value holding a secret). Tests: Verify driver "Verify AT-K06 listing" (34 cases), plus the Builder's "AT-K06: every control on every built screen is named and reachable" (19 cases) and "AT-K06: the walk finds a password on screen once Show was chosen, and never before".

Screens (34 cases, 52 states with the editor's 8 pages, the settings' 7 pages and the vault settings' 5 pages): welcome; unlock; unlock with a typed password; unlock with a key file; unlock Touch ID form (not reachable in the app until E6-S3); unlock vault switcher; list and detail; detail with the password shown; Favorites; One-time codes; Passkeys; search "git"; search tips; sort menu; More actions; vault switcher; Recycle Bin with a bin entry; empty vault; New Group dialog; delete question; clone question; Empty Recycle Bin question; editor (every page); editor with its generator; toolbar generator; Reports (Health check, Breach check, Statistics, Passkeys, Browser); settings (every page); vault settings (every page); new vault wizard step 1.

Result. `✔ Test "Verify AT-K06 listing" with 34 test cases passed`. 1457 controls: 0 unnamed; 90 that the focus may not reach, and all 90 are disabled (`awk` on the listing: `90 disabled`, none enabled); 0 walk failures. Per screen (control count, unnamed, not focusable, walk failures): welcome 3/0/1/0; unlock 7/0/2/0; unlock typed password 7/0/2/0; unlock key file 7/0/2/0; unlock touch id 3/0/1/0; unlock vault switcher 9/0/3/0; list and detail 57/0/1/0; detail shown password 57/0/1/0; favorites 43/0/1/0; codes 45/0/1/0; passkeys 42/0/1/0; search 40/0/1/0; search tips 64/0/1/0; sort menu 5/0/0/0; more actions 11/0/3/0; vault switcher 9/0/1/0; recycle bin 32/0/0/0; empty vault 17/0/2/0; dialog 18/0/1/0; delete question 56/0/1/0; clone question 5/0/0/0; empty bin question 2/0/0/0; editor 47/0/2/0; editor entry 47/0/2/0; editor advanced 32/0/0/0; editor icon 73/0/0/0; editor autoType 35/0/1/0; editor browser 36/0/0/0; editor ssh 41/0/10/0; editor properties 31/0/0/0; editor history 46/0/3/0; editor generator 61/0/2/0; generator 71/0/1/0; reports 40/0/0/0; reports breach 27/0/0/0; reports stats 26/0/0/0; reports passkeys 30/0/0/0; reports browser 26/0/0/0; settings general 37/0/7/0; settings security 29/0/5/0; settings autoType 23/0/3/0; settings browser 25/0/15/0; settings ssh 12/0/2/0; settings share 14/0/2/0; settings keys 10/0/1/0; vault general 16/0/0/0; vault security 17/0/3/0; vault bin 9/0/3/0; vault history 11/0/0/0; vault browser 8/0/0/0; new vault 5/0/0/0. The full list of every control is the appendix.

Masked fields (rule 4, LD-206, LD-207). The walk takes the demo password of Google (read from Rust only for the comparison, demo data) as a secret on every main-window screen: no node's label, title or value holds it, except on "detail shown password", where the user chose Show (the Builder's secret check proves both directions). Values seen: the unlock field with a typed demo password reads `•••••••••••` (secret check on the typed password: no hit); the editor's masked Password field reads empty; masked rows read 12 dots (`MaskedRow`, EditorProtected.swift:59). An entry row reads "Google, alex.morgan@gmail.com, Google, 396 188, Excellent, Oct 20" (title, user name, logo, the live code the list draws, strength, date), never a password.

What the offscreen method cannot prove (Mac QA, owner's go): real VoiceOver listening; the Tab order and the focus ring on a key window. Proof that Tab cannot be measured offscreen: driver "Verify Tab order offscreen" (unlock, list and detail, editor) made a key-capable borderless window at x −20000 and called `makeKey()` without ordering it front: `isKeyWindow=false isVisible=false appActive=false`, and 45 `selectNextKeyView` steps left the first responder where it was (unlock: `NSSecureTextView` from the start, which also shows the password field takes the first focus).

### Part C: APP-08 against the card

Method. Each menu's items are the same view Larsal puts in its SwiftUI commands; `NSHostingMenu` turns it into the native NSMenu, which the driver read in 10 states (no vault; shown vault locked; Personal unlocked with no selection; Google selected; GitHub (passkey, code); SSH agent on with "Server root · web-01"; the Work group with subgroups; editor open; New Group sheet; Recycle Bin with a bin entry). The dumps were written under /tmp (deleted at the end); the counts and excerpts are below. Driver test "Verify APP-08 menu dump in each state" passed. The Builder's `MenuBarTests` (19) and `MenuBarIconTests` (20) pass in the full run.

Items per menu (card table rows; a submenu counts once):

| Menu | Card | Built | Shown in the dump | Not shown, and why |
|---|---|---|---|---|
| Larsal (08.2) | 4: About Larsal, Check for Updates…, Settings… ⌘,, Quit Larsal ⌘Q (+ Services, Hide Larsal ⌘H, Hide Others ⌥⌘H, Show All) | Check for Updates… (off, E14), Settings… ⌘,; About, Quit and the macOS items are SwiftUI's (`.appInfo`, `.appVisibility`, `.systemServices`, `.appTermination` kept) | 2 own | – |
| File (08.3) | 10 | 10 + 2 separators | New Vault… ⇧⌘N, Open Vault… ⌘O, Open Recent ▸ (names, Clear Menu off), Close Vault ⌘W (the key only while a vault shows), Close Window ⇧⌘W (⌘W with no vault), Save ⌘S, Save As… ⇧⌘S, Save a Copy… (off), Import… (off), Export ▸ CSV…, HTML…, XML… (off) | – |
| Edit (08.4) | 7: Undo ⌘Z, Redo ⇧⌘Z, Cut ⌘X, Copy ⌘C, Paste ⌘V, Select All ⌘A, Find… ⌘F | Cut, Copy, Paste, Select All, Find…; Undo and Redo are SwiftUI's (`.undoRedo` kept) | 5 own | – |
| Vault (08.5) | 8 | 8 | Lock Personal ⌘L, Lock Everything ⇧⌘L, Vault Settings… ⇧⌘,, Change Credentials…, Reports ⇧⌘R, Passkeys…, Import Passkey… (off), Merge Another Vault… (off) | – |
| Entry (08.6) | 22 | 22 | 16 always; Restore Entry ⌘R (bin entry); Load into SSH Agent ⌃H, Remove from SSH Agent ⌃⇧H (agent on, SSH entry; off); Remove Passkey (GitHub; off) | Move Up ⌥↑, Move Down ⌥↓: hidden while the list is sorted, and Larsal's list is always sorted (LD-214 (4)) |
| Group (08.7) | 8 | 8 | New Group…, Edit, Clone, Delete Group… (off), Fetch Site Icons for Group… (off); Arrange Subgroups A to Z / Z to A (Work; off); Empty Recycle Bin… (bin) | – |
| View (08.8) | 7 | 7 (+ Enter Full Screen, macOS) | Appearance ▸ System ✓, Light, Dark; Hide Sidebar ⌃⌘S; Hide Details; Mask User Names ⇧⌘B; Mask Passwords ⇧⌘C ✓; Keep Window on Top ⇧⌘A; Permit Screen Capture (off, unchecked) | – |
| Tools (08.9) | 2 | 2 | Password Generator ⌥⌘G; Remove All Keys from SSH Agent… (agent on; off) | – |
| Window (08.10) | Minimize ⌘M, Zoom, Show Next Vault ⌃Tab (also ⇧⌘]), Show Previous Vault ⌃⇧Tab (also ⇧⌘[), one item per vault ⌘1…⌘8, ⌘9 last (+ Bring All to Front, window list) | 5 own (vault items once) | Minimize ⌘M, Zoom, Next ⌃Tab, Previous ⌃⇧Tab, Personal ⌘1 ✓, Work ⌘2, Family ⌘3 | ⇧⌘] and ⇧⌘[ not built (LD-214 (4)) |
| Help (08.11) | 2: Larsal Help ⇧⌘/ (hidden until E14), Keyboard Shortcuts ⌘/ | Keyboard Shortcuts ⌘/ (opens the settings' Shortcuts page, LD-214 (5)) | 1 | Larsal Help: the card hides it until E14 |

Shortcuts. The main state (Google selected) has 41 distinct shortcuts: ⇧⌘, ⇧⌘A ⇧⌘B ⇧⌘C ⇧⌘D ⇧⌘L ⇧⌘N ⇧⌘R ⇧⌘S ⇧⌘T ⇧⌘U ⇧⌘V ⇧⌘W ⌃Tab ⌃⇧Tab ⌃⌘S ⌘, ⌘/ ⌘1 ⌘2 ⌘3 ⌘A ⌘B ⌘C ⌘D ⌘E ⌘F ⌘I ⌘L ⌘M ⌘N ⌘O ⌘S ⌘T ⌘U ⌘V ⌘W ⌘X ⌘Y ⌘⌫ ⌥⌘G; ⌘R, ⌃H and ⌃⇧H appear in their states. Each sits on the item the card names (T14's list checked item by item). Keys on two items: only `⌘C: Edit > Copy; Entry > Copy Password` (V-A08-3: Edit > Copy owns it). Labels: title case and one "…" character (Builder test "APP-08.1: labels in title case…" passes).

Enabled rules (APP-08.12 and each row), from the dump: no vault: New, Open, Close Window ⌘W, Edit's text items, Settings, View, Window's Minimize and Zoom, Help on; Save, Save As, Export, Find, every Vault, Entry and Group item off. Locked shown vault: every Vault, Entry and Group item off; Lock Everything off when nothing is unlocked, on while another vault is (T09). Editor open: New, Edit, Clone, Expire, Delete, Open URL, Save As, Reports, Passkeys, Password Generator off; copy items and Save on. Sheet: Vault Settings, Change Credentials, Reports, Passkeys, Find and every Entry item (Copy Password too) off; Lock Personal and Lock Everything stay on; Edit > Copy stays on (fail 2). Bin entry: New Entry, Edit Entry, Clone off; Restore Entry ⌘R on; New Group off; Empty Recycle Bin… on. Differences from the card that LD-214 (4) records: Import… and Password Generator off with no unlocked vault (card: always), and the later-story items. Not recorded (advisories below): Edit Entry off for a bin entry; Save As…, Reports and Passkeys… off while the editor is open. Not holding: fail 2 (Edit > Copy with a sheet).

In-window menus (APP-08.13). Vault switcher, More actions and the sort menu are the states frames (15/15 PASS); Escape closes them (`MenuLayer.onExitCommand`). Right-click menus, driver "Verify APP-08.13: right-click menus of an entry row (as More actions) and of a group" passed: entry row = Copy Username, Copy Password, Copy URL, Copy One-Time Code, —, Type Login (off), Open URL, Show Code as QR (off), —, Clone Entry…, Move to Group (off), History, —, Move to Recycle Bin, the More actions items in the mockup's order; bin entry = Restore entry, Delete permanently; group (Work) = New Group…, Edit, Clone, Delete Group… (off), Arrange A to Z, Z to A (off), Fetch Site Icons for Group… (off).

Keys inside the window (APP-08.14), by code: ↑ ↓ in the list (EntryListView.swift:194-201), Return edits and ⌫ ⌦ delete in the list (ContextMenus.swift `entryKeys`), Escape for dialogs, menus, the editor and the search (VaultView.swift:45, PopMenu.swift:113, EditorScreen.swift:36, VaultView.swift:154), ⌘S in the editor (File > Save), ⌘Return in the generator (GeneratorPanel.swift:33). Missing: fail 3.

Standard Mac items (APP-08.1), by code: `LarsalCommands` replaces only `.appSettings`, `.newItem`, `.saveItem`, `.importExport`, `.printItem`, `.pasteboard`, `.toolbar`, `.sidebar`, `.windowSize` and `.help`, and adds after `.appInfo`; SwiftUI keeps About, Services, Hide Larsal, Hide Others, Show All, Quit, Undo, Redo, the text editing items (AutoFill, Dictation, Emoji & Symbols), Enter Full Screen, Bring All to Front and the window list, and macOS adds the Help search field. The test process is not a hosted app, so `NSApp.mainMenu` cannot be read offscreen; the real menu bar (top-level order, these items, no second ⌘F or ⌘W item) is Mac QA.

Menu bar icon (APP-08.20 to APP-08.22) and APP-09.21, APP-09.22 through the seams (`StatusSlot`, `LarsalCalls`, a recording window): Builder tests pass (APP-08.19 T33, T34, T35 and the Dock case; APP-08.20 T36, T37 and S-UI-10 off; APP-08.21 choose a vault; APP-08.22 T39; APP-09.21 both branches; APP-09.22 bring, hidden launch, activated, `Front.bring()` shared; rule 10 slot and hidden launch started minimized; "Parity menubar-menu-bar-icon … (T38)"). Verify driver, all passed: "Verify APP-09.21 to the icon, then a channel activate brings it back (APP-09.22)" (log `accessory, regular, unhide, activate`, window `hide, front`, `inFront` after); "Verify APP-09.21 to the Dock, then Larsal activated brings it back, policy untouched" (`minimize, unminimize, front`, app `unhide, activate`, no policy call); "Verify APP-08.19: minimize with S-UI-12 on and S-UI-10 off goes to the Dock; close counts as a minimize" (and S-UI-10 off while hidden brings the window back; off while shown does nothing); "Verify rule 10: inside a test run the shared rules' calls are inert" (`LarsalCalls.system.policy() == .prohibited`); "Verify APP-08.20 APP-08.21: M08-03, template images, and Show Window while minimized" (tooltips for 0, 1, 2 and 5 unlocked name no vault; both monochrome images are templates and differ; colourful is not a template; the item reads "Show Window" while minimized or Larsal is not active, "Hide Window" while in front). By code: the Dock click (`applicationShouldHandleReopen`), Larsal becoming active (`applicationDidBecomeActive` → `activated()`), the channel's `activate` and `open` (`WindowEvents.bringToFront`) and the icon's menu all go through `Front.bring()`; `startsMinimized()` (Rust, F08 or `window.start_minimized`) runs `WindowRules.startMinimized()` after launch; a hidden launch gets `NoStatusSlot` and stays `.prohibited`. The reference app's installed resources were not read (optional; the card's labels were already verified against the reference source, V-A08-1 to V-A08-4).

### Part D: mutations

In the private copy, one mutant at a time (python script outside the project: replace one exact string, `xcodebuild build-for-testing` with `-derivedDataPath /tmp/e5s11-verify-mdd`, run `VerifyE5S11Tests`, `MenuBarTests`, `MenuBarIconTests`, `AccessibilityWalkTests`, restore, `filecmp` with the shared tree). Baseline in the copy: `Test run with 51 tests in 4 suites failed … with 2 issues`, the two issues being fails 1 and 2; final copy run with the context-menu test added: `52 tests in 4 suites … 2 issues`, the same two. Every mutant below adds failures beyond those two, and every restored file was identical (`restored, identical to shared tree: True`).

| # | Mutant | Caught by |
|---|---|---|
| M1 | Controls.swift `IconButton`: glyph `.accessibilityHidden(false)` → `true` (LD-214 (6)) | "AT-K06: every control on every built screen is named and reachable" fails on 10 screens ("…: AXButton at (206.0, 10.0, 32.0, 32.0): the focus cannot reach it (Hide sidebar (⌃⌘S))", "unlock: AXButton at (812.0, 379.0, 32.0, 33.0): the focus cannot reach it (Show password)"), the secret check, and the driver listing (22 cases); 35 issues |
| M2 | UnlockView.swift: the password `SecureField` → `TextField` (the typed password readable) | Driver listing "unlock typed password: AXTextField at (506.0, 386.0, 298.0, 19.0): shows a hidden secret". The Builder's AT-K06 walk does not catch it; in the full product suite (215 tests) only ShownPasswordFieldTests "Parity lock-locked-password-key-file-security-key: the shown password has no Copy or Cut…" fails, at its `NSSecureTextField != nil` check (advisory 1) |
| M3 | WindowRules.bring(): the `.prohibited` guard removed (rule 10) | "APP-09.22: a hidden test launch (prohibited) never comes to front", "Rule 10: a hidden launch started minimized to the icon stays prohibited…" |
| M4 | MenuBarIcon.update(): tooltip + the shown vault's name (M08-03) | "APP-08.20 T36 T37: … a template image with no vault name" |
| M5 | Edit Entry on ⇧⌘E | "APP-08.2 to APP-08.11: every menu's items, labels and shortcuts as the card's tables" |
| M6 | Lock <name> without `.disabled(window.main == nil)` | "APP-08.12 T04 …", "APP-08.12 T09 T22 …", "APP-08.5 T09 …" |
| M7 | hideToIcon() without `minimized()` (APP-02.8, SR-03) | "APP-08.19 T34 … counts as a minimize", driver "Verify APP-08.19 … close counts as a minimize" |
| M8 | `MenuState.vault` ignores an open sheet | "APP-08.12: a sheet on the window turns the vault's items off" |
| M9 | icon menu: no separator before Show/Hide Window | "Parity menubar-menu-bar-icon: the menu's items; Hide Window hides, then it reads Show Window (T38)" |
| M10 | ⌘9 on the ninth vault (`index < 9`) | "APP-08.10 T20: ⌘1 to ⌘8 for the first eight vaults, ⌘9 for the last…" |

### Needs Mac QA (owner's go), not fails

1. Real VoiceOver on unlock, list, detail and editor (AT-K06 live, T43): names, row reading, announcements of the unlock error, toasts and banners.
2. Tab order and the mockup's focus ring on a key window (APP-08.25).
3. The real menu bar: top-level order (LD-214 (1)), the macOS items of Part C, and no SwiftUI "Find ▸ Find…" or "Close" item that would also hold ⌘F or ⌘W.
4. The status item on a real menu bar: template image in light and dark menu bars, M08-03 tooltip, a click opens the menu, the accessory policy while hidden (APP-08.22).
5. APP-09.21-a live: `Larsal --minimized` with S-UI-10 on. `startMinimized()` runs in `DispatchQueue.main.async` after `applicationDidFinishLaunching`; the icon branch hides `WindowRules.window`, which `WindowChromeView` attaches in `viewDidMoveToWindow`. If the window were not attached yet, nothing would be hidden while Larsal turns accessory (the Dock branch has a fallback, the icon branch has none). Not provable offscreen.
6. ⌃H in a focused password field against "Load into SSH Agent" (V-A08-5), once fail 3's ⌃H exists.

### Advisories (not fails)

1. The AT-K06 walk has no case with a typed unlock password (M2 above); add an "unlock typed password" case with the typed demo password as the secret.
2. No product test reads the right-click menus (`EntryContextMenu`, `GroupContextMenu`) or the list keys (`entryKeys`); the driver's test above could move into `MenuBarTests`.
3. Enabled rules that differ from the card and are not in LD-214: Edit Entry is off for a bin entry (the card's row says "one entry"; its Clone row is the one that says "not in the recycle bin"); Save As…, Reports and Passkeys… are off while the editor is open (card: "the shown vault is unlocked").
4. S-VIEW-07 Mask Passwords changes nothing visible: Option A's list draws a strength column, not a password cell, so T16's "list cells change at once" has no target. Worth one line in LD-214.
5. The icon's menu lists the open vaults by name (frame and LD-214 (2)), while the card's security note says menus "never show a vault name"; APP-08.10's Window menu lists them too, so the card contradicts itself. Lead to confirm LD-214 (2).
6. notes.mjs's LATER table labels `dialogs-import` and `dialogs-export-warning` "E5-S11 (FEA-08/FEA-09)", but E5-S11's scope and LD-214 (4) leave Import… and Export ▸ disabled for their own story. Route those two dialogs to a story and fix the label.
7. An entry row reads the logo's name after the user name ("Google, alex.morgan@gmail.com, Google, …"); hiding the logo from accessibility would shorten it.
8. The Touch ID unlock form is walked by my driver (3 controls, all named) but is not in the Builder's walk; add it when E6-S3 makes it reachable (Checker's advisory).

### Commands run (in order) and their output

1. `xcodebuild build-for-testing -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s11-verify-dd SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` (shared tree, 20:37:47 to 20:38:09) → `** TEST BUILD SUCCEEDED **`.
2. Reference export in /tmp/e5s11-verify-ref (Part A step 1) → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`; `cmp` and pixelmatch as above.
3. `xcodebuild test-without-building … -derivedDataPath /tmp/e5s11-verify-dd -only-testing:LarsalTests` (20:38:17 to 20:40:34) → `✘ Test run with 215 tests in 33 suites failed after 118.899 seconds with 2 issues`; the 2 issues: `ParityStatesTests.swift:137` and `:179` `NSPasteboard.general.changeCount == before` (states-copied, LD-206). `✔ Suite MenuBarTests passed`, `✔ Suite MenuBarIconTests passed`, `✔ Suite AccessibilityWalkTests passed`, `✔ Suite LockSignalsTests passed`, `✔ Suite SnapshotTests passed`; `✔ Test "AT-K06: every control on every built screen is named and reachable" with 19 test cases passed`.
4. `xcodebuild test-without-building … -only-testing:LarsalTests/ParityStatesTests` (20:47:58 to 20:48:21) → `✔ Test run with 16 tests in 1 suite passed after 20.748 seconds`.
5. OCR, behaviour log, `compare.mjs menubar` (twice) and `compare.mjs states`: Part A steps 3 to 7. design/parity/{menubar,states} were copied to /tmp/e5s11-verify-pbak first; states changed only in live values (for example states-needs-attention light 1.7 % → 1.69 %).
6. Private copy (How I worked), driver added, `xcodebuild build-for-testing … -derivedDataPath /tmp/e5s11-verify-mdd SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `** TEST BUILD SUCCEEDED **`; `-only-testing:LarsalTests/VerifyE5S11Tests` → `Test run with 10 tests in 1 suite failed … with 3 issues` (fails 1 and 2, and one wrong expectation of mine in the minimize test: after a Dock minimize, `bring()` also un-minimizes, log `["minimize", "hide", "unminimize", "front"]`, which is right; I fixed my expectation).
7. Copy baseline, driver and the three E5-S11 suites → `Test run with 51 tests in 4 suites failed … with 2 issues` (fails 1 and 2 only).
8. Mutants M1 to M10 (Part D): one build and one 4-suite run each, results as in the table; M2 also against the full product suite → `Test run with 215 tests in 33 suites failed … with 1 issue` (ShownPasswordFieldTests.swift:40).
9. Final copy run with the context-menu test → `Test run with 52 tests in 4 suites failed after 41.988 seconds with 2 issues` (fails 1 and 2).
10. `swift format lint --strict` on the E5-S11 files (LarsalCommands.swift, LarsalCommandsVault.swift, ViewOptions.swift, ContextMenus.swift, Platform/WindowRules.swift, MenuBarIcon.swift, AppDelegate.swift, LarsalTests/MenuBarTests.swift, MenuBarIconTests.swift, MenuBarIconFrame.swift, MenuLine.swift, AccessibilityWalkTests.swift) → exit 0, no output. SwiftLint 0.65.1 (`scripts/install-swiftlint.sh --path`) `lint --strict --quiet` on the same files in macos/ → exit 0.
11. `scripts/check-names.sh` after writing these files → see the last line of this report.

Test names of the Builder's suites that cover this story (all passed in the full run): MenuBarTests "APP-08.2 to APP-08.11: every menu's items, labels and shortcuts as the card's tables" (11 menus), "APP-08.1: labels in title case, an ellipsis only on items that ask for more", "APP-08.12 T04: …", "APP-08.12 T09 T22: …", "APP-08.5 T09: …", "APP-08.6 T11: …", "APP-08.6 T12: …", "APP-08.6: Remove Passkey shows …", "APP-08.6 T14 APP-08.7 T15: …", "APP-08.12: while the editor is open …", "APP-08.12: a sheet on the window …", "APP-08.10 T20: …", "APP-08.10: Show Next Vault wraps around …", "APP-08.8 T16: …", "APP-08.3 T05: …", "APP-08.9 T18: …", "APP-08.11 T21: …", "APP-08.4 V-A08-3: …", "APP-08.3 APP-08.19: ⌘W with no vault open …"; MenuBarIconTests "APP-08.19 T33 …", "APP-08.19 T34 …", "APP-08.19: S-UI-09 on, S-UI-10 off …", "APP-08.19 T35 …", "APP-08.3: ⌘W with Settings in front …", "APP-09.21: … S-UI-10 on …", "APP-09.21: … S-UI-10 off …", "Rule 10: a hidden launch … gets no status item …", "APP-09.22: bring to front …", "APP-09.22: a hidden test launch …", "APP-09.22: Larsal becoming active …", "APP-09.22: Front.bring() …", "APP-08.20 T36 T37 …", "APP-08.20: S-UI-10 off: no status item", "Parity menubar-menu-bar-icon: … (T38)", "APP-08.22 T39 …", "APP-08.21: choosing a vault …", "Option A frame menubar-menu-bar-icon, offscreen, light and dark", "Rule 10: a hidden launch started minimized …", "Rule 9: each decision ID names one row …"; AccessibilityWalkTests "AT-K06: every control on every built screen is named and reachable" (19 cases), "AT-K06: the walk finds a password on screen once Show was chosen, and never before".

Snapshot paths: larsal-shots/light/menubar-menu-bar-icon.png and .ax.json, larsal-shots/dark/menubar-menu-bar-icon.png and .ax.json; design/parity/menubar/app/{light,dark}/ and diff/{light,dark}/; design/parity/states/app and diff for the 15 states frames.

Cleanup: removed /tmp/e5s11-verify-copy, /tmp/e5s11-verify-dd, /tmp/e5s11-verify-mdd, /tmp/e5s11-verify-ref, /tmp/e5s11-verify-pbak, /tmp/e5s11-verify-tools and /tmp/e5s11-verify-proof (the listing below is copied from it). I started no process that is still running.

## Appendix: every control the walk met (round 2)

Role, the name VoiceOver reads, enabled state and whether the focus can reach it, from the Verify driver "Verify AT-K06 listing". Values are left out: they are demo data, and the one shown password is the Show case. The main window chrome is listed once.

#### Main window chrome (sidebar, top bar, list header): on every unlocked main-window screen below, left out of their tables

| Role | Name (what VoiceOver reads) | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Sort by Modified | enabled | focusable |
| AXButton | More actions | enabled | focusable |
| AXButton | Copy password | enabled | focusable |
| AXButton | Copy username | enabled | focusable |
| AXButton | Show password | enabled | focusable |

#### big file question: 2 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | No | enabled | focusable |
| AXButton | Yes | enabled | focusable |

#### clone question: 5 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Mark the copy's title with ' - Clone' | enabled | focusable |
| AXButton | Link user name and password to the original | enabled | focusable |
| AXButton | Copy the history | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Clone | enabled | focusable |

#### codes: 45 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 7 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Passkeys, 1 | enabled | focusable |
| AXButton | Needs attention, 0 | enabled | focusable |
| AXButton | GitHub, alex-dev ·, passkey, GitHub, 240 944, Excellent, 5 days | enabled | focusable |
| AXButton | Google, alex.morgan@gmail.com, Google, 786 564, Excellent, Oct 20 | enabled | focusable |
| AXButton | Hetzner Cloud, alex@morgan-labs.dev, Hetzner, 140 505, Excellent, Oct 18 | enabled | focusable |
| AXButton | Proton Mail, alex.morgan@proton.me, Proton Mail, 945 004, Excellent, Oct 14 | enabled | focusable |
| AXButton | Instagram, alex.morgan.photos, Instagram, 611 537, Good, Oct 2 | enabled | focusable |
| AXButton | Wise, alex.morgan@posteo.de, Wise, 019 696, Excellent, Sep 28 | enabled | focusable |
| AXButton | AWS root account, alex@morgan-labs.dev, 907 552, Excellent, Jul 8 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### delete question: 3 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Do not ask again | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Move to Recycle Bin | enabled | focusable |

#### detail shown password: 57 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 23 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Needs attention, 7 | enabled | focusable |
| AXButton | GitHub, alex-dev ·, passkey, GitHub, 240 944, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, alex.morgan@icloud.com ·, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Google, alex.morgan@gmail.com, Google, 786 564, Excellent, Oct 20 | enabled | focusable |
| AXButton | Hetzner Cloud, alex@morgan-labs.dev, Hetzner, 140 505, Excellent, Oct 18 | enabled | focusable |
| AXButton | Proton Mail, alex.morgan@proton.me, Proton Mail, 945 004, Excellent, Oct 14 | enabled | focusable |
| AXButton | Server root · web-01, root, —, Weak, Oct 11 | enabled | focusable |
| AXButton | PayPal, alex.morgan@posteo.de, PayPal, —, Good, Oct 9 | enabled | focusable |
| AXButton | Instagram, alex.morgan.photos, Instagram, 611 537, Good, Oct 2 | enabled | focusable |
| AXButton | Wise, alex.morgan@posteo.de, Wise, 019 696, Excellent, Sep 28 | enabled | focusable |
| AXButton | Figma, alex@morgan-labs.dev, Figma, —, Good, Sep 22 | enabled | focusable |
| AXButton | Mastodon, @alex@mastodon.social ·, passkey, Mastodon, —, Passkey only, Sep 18 | enabled | focusable |
| AXButton | Linear, alex@morgan-labs.dev ·, passkey, Linear, —, Good, Sep 15 | enabled | focusable |
| AXButton | Visa Debit, Card ending 1111, —, —, Sep 10 | enabled | focusable |
| AXButton | Zalando, alex.morgan@posteo.de, Zalando, —, Expired, Sep 2 | enabled | focusable |
| AXButton | Amazon, alex.morgan@posteo.de, —, Reused, Aug 27 | enabled | focusable |
| AXButton | Deutsche Bahn, alex.morgan@posteo.de, Deutsche Bahn, —, Good, Aug 19 | enabled | focusable |
| AXButton | Slack, alex@morgan-labs.dev, —, Poor, Aug 4 | enabled | focusable |
| AXButton | eBay, alexmorgan88, eBay, —, Reused, Jul 21 | enabled | focusable |
| AXButton | AWS root account, alex@morgan-labs.dev, —, Excellent, Jul 8 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Hide password | enabled | focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### dialog: 18 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXTextField | Name | enabled | focusable |
| AXButton | Inside, Top level | enabled | focusable |
| AXButton | blue | enabled | focusable |
| AXButton | green | enabled | focusable |
| AXButton | orange | enabled | focusable |
| AXButton | pink | enabled | focusable |
| AXButton | purple | enabled | focusable |
| AXButton | cyan | enabled | focusable |
| AXButton | airplane | enabled | focusable |
| AXButton | suitcase | enabled | focusable |
| AXButton | map-pin | enabled | focusable |
| AXButton | globe-simple | enabled | focusable |
| AXButton | house-line | enabled | focusable |
| AXButton | car | enabled | focusable |
| AXButton | train | enabled | focusable |
| AXButton | boat | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Create Group | disabled | not-focusable |

#### discard question: 2 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Keep Editing | enabled | focusable |
| AXButton | Discard Changes | enabled | focusable |

#### editor generator: 61 controls, 0 unnamed, 2 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXButton | Password | enabled | focusable |
| AXButton | Passphrase | enabled | focusable |
| AXTextField | Generated password | enabled | focusable |
| AXButton | New password | enabled | focusable |
| AXButton | Copy | enabled | focusable |
| AXSlider | Length | enabled | focusable |
| AXButton | A–Z | enabled | focusable |
| AXButton | a–z | enabled | focusable |
| AXButton | 0–9 | enabled | focusable |
| AXButton | !@#$ | enabled | focusable |
| AXButton | Äéß | enabled | focusable |
| AXButton | Leave out look-alikes l I 1 O 0 | enabled | focusable |
| AXButton | Copy | enabled | focusable |
| AXButton | Use password | enabled | focusable |
| AXTextField | Title | enabled | focusable |
| AXTextField | Username | enabled | focusable |
| AXTextField | Password | enabled | focusable |
| AXButton | Show password | enabled | focusable |
| AXButton | Open generator (⌥⌘G) | enabled | focusable |
| AXTextField | Website | enabled | focusable |
| AXButton | Open website | enabled | focusable |
| AXButton | + Add another website | enabled | focusable |
| AXButton | Show QR | enabled | focusable |
| AXButton | Change… | enabled | focusable |
| AXButton | Group, Email | enabled | focusable |
| AXButton | Remove #2fa | enabled | focusable |
| AXTextField | Add a tag | enabled | focusable |
| AXCheckBox | Expires | enabled | focusable |
| AXTextField | Expiry date | disabled | not-focusable |
| AXButton | In 3 months | disabled | not-focusable |
| AXTextField | Notes | enabled | focusable |

#### editor pages: 47 controls, 0 unnamed, 2 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXTextField | Title | enabled | focusable |
| AXTextField | Username | enabled | focusable |
| AXTextField | Password | enabled | focusable |
| AXButton | Show password | enabled | focusable |
| AXButton | Open generator (⌥⌘G) | enabled | focusable |
| AXTextField | Website | enabled | focusable |
| AXButton | Open website | enabled | focusable |
| AXButton | + Add another website | enabled | focusable |
| AXButton | Show QR | enabled | focusable |
| AXButton | Change… | enabled | focusable |
| AXButton | Group, Email | enabled | focusable |
| AXButton | Remove #2fa | enabled | focusable |
| AXTextField | Add a tag | enabled | focusable |
| AXCheckBox | Expires | enabled | focusable |
| AXTextField | Expiry date | disabled | not-focusable |
| AXButton | In 3 months | disabled | not-focusable |
| AXTextField | Notes | enabled | focusable |

#### editor entry: 47 controls, 0 unnamed, 2 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXTextField | Title | enabled | focusable |
| AXTextField | Username | enabled | focusable |
| AXTextField | Password | enabled | focusable |
| AXButton | Show password | enabled | focusable |
| AXButton | Open generator (⌥⌘G) | enabled | focusable |
| AXTextField | Website | enabled | focusable |
| AXButton | Open website | enabled | focusable |
| AXButton | + Add another website | enabled | focusable |
| AXButton | Show QR | enabled | focusable |
| AXButton | Change… | enabled | focusable |
| AXButton | Group, Email | enabled | focusable |
| AXButton | Remove #2fa | enabled | focusable |
| AXTextField | Add a tag | enabled | focusable |
| AXCheckBox | Expires | enabled | focusable |
| AXTextField | Expiry date | disabled | not-focusable |
| AXButton | In 3 months | disabled | not-focusable |
| AXTextField | Notes | enabled | focusable |

#### editor advanced: 32 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXButton | Add field | enabled | focusable |
| AXButton | choose files… | enabled | focusable |

#### editor icon: 73 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXButton | Website logo | enabled | focusable |
| AXButton | Symbol and colour | enabled | focusable |
| AXButton | The group's icon | enabled | focusable |
| AXButton | key | enabled | focusable |
| AXButton | lock-simple | enabled | focusable |
| AXButton | globe-simple | enabled | focusable |
| AXButton | envelope-simple | enabled | focusable |
| AXButton | bank | enabled | focusable |
| AXButton | credit-card | enabled | focusable |
| AXButton | shopping-bag | enabled | focusable |
| AXButton | briefcase | enabled | focusable |
| AXButton | house-line | enabled | focusable |
| AXButton | wifi-high | enabled | focusable |
| AXButton | hard-drives | enabled | focusable |
| AXButton | terminal-window | enabled | focusable |
| AXButton | database | enabled | focusable |
| AXButton | cloud | enabled | focusable |
| AXButton | device-mobile | enabled | focusable |
| AXButton | desktop | enabled | focusable |
| AXButton | game-controller | enabled | focusable |
| AXButton | film-strip | enabled | focusable |
| AXButton | music-notes | enabled | focusable |
| AXButton | airplane | enabled | focusable |
| AXButton | car | enabled | focusable |
| AXButton | heart | enabled | focusable |
| AXButton | student | enabled | focusable |
| AXButton | certificate | enabled | focusable |
| AXButton | identification-card | enabled | focusable |
| AXButton | shield-check | enabled | focusable |
| AXButton | users-three | enabled | focusable |
| AXButton | chat-circle | enabled | focusable |
| AXButton | printer | enabled | focusable |
| AXButton | star | enabled | focusable |
| AXButton | blue | enabled | focusable |
| AXButton | teal | enabled | focusable |
| AXButton | green | enabled | focusable |
| AXButton | orange | enabled | focusable |
| AXButton | pink | enabled | focusable |
| AXButton | red | enabled | focusable |
| AXButton | purple | enabled | focusable |
| AXButton | brown | enabled | focusable |
| AXButton | slate | enabled | focusable |
| AXButton | gray | enabled | focusable |

#### editor autoType: 35 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXCheckBox | Auto-Type | enabled | focusable |
| AXButton | Use the group's sequence | enabled | focusable |
| AXButton | Custom sequence | enabled | focusable |
| AXTextField | Custom sequence | enabled | focusable |
| AXButton | Add window | disabled | not-focusable |

#### editor browser: 36 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXButton | Remove accounts.google.com | enabled | focusable |
| AXTextField | Also allowed on | enabled | focusable |
| AXTextField | Never on | enabled | focusable |
| AXCheckBox | Hide from browser | enabled | focusable |
| AXCheckBox | Do not submit | enabled | focusable |
| AXCheckBox | HTTP only | enabled | focusable |

#### editor ssh: 41 controls, 0 unnamed, 10 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXCheckBox | SSH agent | disabled | not-focusable |
| AXButton | From an attachment | enabled | focusable |
| AXButton | From a file on this Mac | disabled | not-focusable |
| AXCheckBox | Add on unlock | disabled | not-focusable |
| AXCheckBox | Remove on lock | disabled | not-focusable |
| AXCheckBox | Confirm | disabled | not-focusable |
| AXButton | Less | disabled | not-focusable |
| AXButton | More | disabled | not-focusable |
| AXCheckBox | Lifetime | disabled | not-focusable |
| AXButton | Add to agent now | disabled | not-focusable |
| AXButton | Remove from agent | disabled | not-focusable |

#### editor properties: 31 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXButton | Remove | enabled | focusable |

#### editor history: 46 controls, 0 unnamed, 3 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save, ⌘S | enabled | focusable |
| AXButton | Entry | enabled | focusable |
| AXButton | Advanced, 0 | enabled | focusable |
| AXButton | Icon | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Properties | enabled | focusable |
| AXButton | History, 4 | enabled | focusable |
| AXButton | Show | disabled | not-focusable |
| AXButton | Restore | disabled | not-focusable |
| AXButton | Delete version | disabled | not-focusable |
| AXButton | Show | enabled | focusable |
| AXButton | Restore | enabled | focusable |
| AXButton | Delete version | enabled | focusable |
| AXButton | Show | enabled | focusable |
| AXButton | Restore | enabled | focusable |
| AXButton | Delete version | enabled | focusable |
| AXButton | Show | enabled | focusable |
| AXButton | Restore | enabled | focusable |
| AXButton | Delete version | enabled | focusable |
| AXButton | Show | enabled | focusable |
| AXButton | Restore | enabled | focusable |
| AXButton | Delete version | enabled | focusable |
| AXButton | Delete all history | enabled | focusable |

#### empty bin question: 2 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Cancel | enabled | focusable |
| AXButton | Empty Recycle Bin | enabled | focusable |

#### empty vault: 17 controls, 0 unnamed, 2 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 0 | enabled | focusable |
| AXButton | Favorites, 0 | enabled | focusable |
| AXButton | One-time codes, 0 | enabled | focusable |
| AXButton | Passkeys, 0 | enabled | focusable |
| AXButton | Password health, 0 | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 0 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | New Entry | disabled | not-focusable |
| AXButton | New entry, A login, card or note | enabled | focusable |
| AXButton | Import, CSV and other managers | disabled | not-focusable |
| AXButton | New group, Sort entries like folders | enabled | focusable |

#### favorites: 43 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 5 | enabled | focusable |
| AXButton | Two-step codes, 3 | enabled | focusable |
| AXButton | Passkeys, 2 | enabled | focusable |
| AXButton | Needs attention, 0 | enabled | focusable |
| AXButton | GitHub, alex-dev ·, passkey, GitHub, 240 944, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, alex.morgan@icloud.com ·, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Google, alex.morgan@gmail.com, Google, 786 564, Excellent, Oct 20 | enabled | focusable |
| AXButton | Proton Mail, alex.morgan@proton.me, Proton Mail, 945 004, Excellent, Oct 14 | enabled | focusable |
| AXButton | Home Wi-Fi, Morgan-Home 5G, —, Good, May 3 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### generator: 71 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 23 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Needs attention, 7 | enabled | focusable |
| AXButton | GitHub, alex-dev ·, passkey, GitHub, 934 177, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, alex.morgan@icloud.com ·, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Google, alex.morgan@gmail.com, Google, 750 343, Excellent, Oct 20 | enabled | focusable |
| AXButton | Hetzner Cloud, alex@morgan-labs.dev, Hetzner, 983 420, Excellent, Oct 18 | enabled | focusable |
| AXButton | Proton Mail, alex.morgan@proton.me, Proton Mail, 125 348, Excellent, Oct 14 | enabled | focusable |
| AXButton | Server root · web-01, root, —, Weak, Oct 11 | enabled | focusable |
| AXButton | PayPal, alex.morgan@posteo.de, PayPal, —, Good, Oct 9 | enabled | focusable |
| AXButton | Instagram, alex.morgan.photos, Instagram, 540 839, Good, Oct 2 | enabled | focusable |
| AXButton | Wise, alex.morgan@posteo.de, Wise, 745 918, Excellent, Sep 28 | enabled | focusable |
| AXButton | Figma, alex@morgan-labs.dev, Figma, —, Good, Sep 22 | enabled | focusable |
| AXButton | Mastodon, @alex@mastodon.social ·, passkey, Mastodon, —, Passkey only, Sep 18 | enabled | focusable |
| AXButton | Linear, alex@morgan-labs.dev ·, passkey, Linear, —, Good, Sep 15 | enabled | focusable |
| AXButton | Visa Debit, Card ending 1111, —, —, Sep 10 | enabled | focusable |
| AXButton | Zalando, alex.morgan@posteo.de, Zalando, —, Expired, Sep 2 | enabled | focusable |
| AXButton | Amazon, alex.morgan@posteo.de, —, Reused, Aug 27 | enabled | focusable |
| AXButton | Deutsche Bahn, alex.morgan@posteo.de, Deutsche Bahn, —, Good, Aug 19 | enabled | focusable |
| AXButton | Slack, alex@morgan-labs.dev, —, Poor, Aug 4 | enabled | focusable |
| AXButton | eBay, alexmorgan88, eBay, —, Reused, Jul 21 | enabled | focusable |
| AXButton | AWS root account, alex@morgan-labs.dev, —, Excellent, Jul 8 | enabled | focusable |
| AXButton | Password | enabled | focusable |
| AXButton | Passphrase | enabled | focusable |
| AXTextField | Generated password | enabled | focusable |
| AXButton | New password | enabled | focusable |
| AXButton | Copy | enabled | focusable |
| AXSlider | Length | enabled | focusable |
| AXButton | A–Z | enabled | focusable |
| AXButton | a–z | enabled | focusable |
| AXButton | 0–9 | enabled | focusable |
| AXButton | !@#$ | enabled | focusable |
| AXButton | Äéß | enabled | focusable |
| AXButton | Leave out look-alikes l I 1 O 0 | enabled | focusable |
| AXButton | Copy | enabled | focusable |
| AXButton | New entry with it | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### leave editor question: 3 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Discard | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Save | enabled | focusable |

#### list and detail: 57 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 23 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Needs attention, 7 | enabled | focusable |
| AXButton | GitHub, alex-dev ·, passkey, GitHub, 240 944, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, alex.morgan@icloud.com ·, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Google, alex.morgan@gmail.com, Google, 786 564, Excellent, Oct 20 | enabled | focusable |
| AXButton | Hetzner Cloud, alex@morgan-labs.dev, Hetzner, 140 505, Excellent, Oct 18 | enabled | focusable |
| AXButton | Proton Mail, alex.morgan@proton.me, Proton Mail, 945 004, Excellent, Oct 14 | enabled | focusable |
| AXButton | Server root · web-01, root, —, Weak, Oct 11 | enabled | focusable |
| AXButton | PayPal, alex.morgan@posteo.de, PayPal, —, Good, Oct 9 | enabled | focusable |
| AXButton | Instagram, alex.morgan.photos, Instagram, 611 537, Good, Oct 2 | enabled | focusable |
| AXButton | Wise, alex.morgan@posteo.de, Wise, 019 696, Excellent, Sep 28 | enabled | focusable |
| AXButton | Figma, alex@morgan-labs.dev, Figma, —, Good, Sep 22 | enabled | focusable |
| AXButton | Mastodon, @alex@mastodon.social ·, passkey, Mastodon, —, Passkey only, Sep 18 | enabled | focusable |
| AXButton | Linear, alex@morgan-labs.dev ·, passkey, Linear, —, Good, Sep 15 | enabled | focusable |
| AXButton | Visa Debit, Card ending 1111, —, —, Sep 10 | enabled | focusable |
| AXButton | Zalando, alex.morgan@posteo.de, Zalando, —, Expired, Sep 2 | enabled | focusable |
| AXButton | Amazon, alex.morgan@posteo.de, —, Reused, Aug 27 | enabled | focusable |
| AXButton | Deutsche Bahn, alex.morgan@posteo.de, Deutsche Bahn, —, Good, Aug 19 | enabled | focusable |
| AXButton | Slack, alex@morgan-labs.dev, —, Poor, Aug 4 | enabled | focusable |
| AXButton | eBay, alexmorgan88, eBay, —, Reused, Jul 21 | enabled | focusable |
| AXButton | AWS root account, alex@morgan-labs.dev, —, Excellent, Jul 8 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### masked codes: 46 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 7 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Passkeys, 1 | enabled | focusable |
| AXButton | Needs attention, 0 | enabled | focusable |
| AXButton | GitHub, hidden, passkey, GitHub, 934 177, Excellent, 5 days | enabled | focusable |
| AXButton | Google, hidden, Google, 750 343, Excellent, Oct 20 | enabled | focusable |
| AXButton | Hetzner Cloud, hidden, Hetzner, 983 420, Excellent, Oct 18 | enabled | focusable |
| AXButton | Proton Mail, hidden, Proton Mail, 125 348, Excellent, Oct 14 | enabled | focusable |
| AXButton | Instagram, hidden, Instagram, 540 839, Good, Oct 2 | enabled | focusable |
| AXButton | Wise, hidden, Wise, 745 918, Excellent, Sep 28 | enabled | focusable |
| AXButton | AWS root account, hidden, 666 470, Excellent, Jul 8 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Show username | enabled | focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### masked favorites: 44 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 5 | enabled | focusable |
| AXButton | Two-step codes, 3 | enabled | focusable |
| AXButton | Passkeys, 2 | enabled | focusable |
| AXButton | Needs attention, 0 | enabled | focusable |
| AXButton | GitHub, hidden, passkey, GitHub, 934 177, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, hidden, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Google, hidden, Google, 750 343, Excellent, Oct 20 | enabled | focusable |
| AXButton | Proton Mail, hidden, Proton Mail, 125 348, Excellent, Oct 14 | enabled | focusable |
| AXButton | Home Wi-Fi, hidden, —, Good, May 3 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Show username | enabled | focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### masked github: 58 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 23 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Needs attention, 7 | enabled | focusable |
| AXButton | GitHub, hidden, passkey, GitHub, 934 177, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, hidden, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Google, hidden, Google, 750 343, Excellent, Oct 20 | enabled | focusable |
| AXButton | Hetzner Cloud, hidden, Hetzner, 983 420, Excellent, Oct 18 | enabled | focusable |
| AXButton | Proton Mail, hidden, Proton Mail, 125 348, Excellent, Oct 14 | enabled | focusable |
| AXButton | Server root · web-01, hidden, —, Weak, Oct 11 | enabled | focusable |
| AXButton | PayPal, hidden, PayPal, —, Good, Oct 9 | enabled | focusable |
| AXButton | Instagram, hidden, Instagram, 540 839, Good, Oct 2 | enabled | focusable |
| AXButton | Wise, hidden, Wise, 745 918, Excellent, Sep 28 | enabled | focusable |
| AXButton | Figma, hidden, Figma, —, Good, Sep 22 | enabled | focusable |
| AXButton | Mastodon, hidden, passkey, Mastodon, —, Passkey only, Sep 18 | enabled | focusable |
| AXButton | Linear, hidden, passkey, Linear, —, Good, Sep 15 | enabled | focusable |
| AXButton | Visa Debit, hidden, —, —, Sep 10 | enabled | focusable |
| AXButton | Zalando, hidden, Zalando, —, Expired, Sep 2 | enabled | focusable |
| AXButton | Amazon, hidden, —, Reused, Aug 27 | enabled | focusable |
| AXButton | Deutsche Bahn, hidden, Deutsche Bahn, —, Good, Aug 19 | enabled | focusable |
| AXButton | Slack, hidden, —, Poor, Aug 4 | enabled | focusable |
| AXButton | eBay, hidden, eBay, —, Reused, Jul 21 | enabled | focusable |
| AXButton | AWS root account, hidden, —, Excellent, Jul 8 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open github.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Show username | enabled | focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 3 earlier versions | enabled | focusable |

#### masked list and detail: 58 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 23 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Needs attention, 7 | enabled | focusable |
| AXButton | GitHub, hidden, passkey, GitHub, 934 177, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, hidden, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Google, hidden, Google, 750 343, Excellent, Oct 20 | enabled | focusable |
| AXButton | Hetzner Cloud, hidden, Hetzner, 983 420, Excellent, Oct 18 | enabled | focusable |
| AXButton | Proton Mail, hidden, Proton Mail, 125 348, Excellent, Oct 14 | enabled | focusable |
| AXButton | Server root · web-01, hidden, —, Weak, Oct 11 | enabled | focusable |
| AXButton | PayPal, hidden, PayPal, —, Good, Oct 9 | enabled | focusable |
| AXButton | Instagram, hidden, Instagram, 540 839, Good, Oct 2 | enabled | focusable |
| AXButton | Wise, hidden, Wise, 745 918, Excellent, Sep 28 | enabled | focusable |
| AXButton | Figma, hidden, Figma, —, Good, Sep 22 | enabled | focusable |
| AXButton | Mastodon, hidden, passkey, Mastodon, —, Passkey only, Sep 18 | enabled | focusable |
| AXButton | Linear, hidden, passkey, Linear, —, Good, Sep 15 | enabled | focusable |
| AXButton | Visa Debit, hidden, —, —, Sep 10 | enabled | focusable |
| AXButton | Zalando, hidden, Zalando, —, Expired, Sep 2 | enabled | focusable |
| AXButton | Amazon, hidden, —, Reused, Aug 27 | enabled | focusable |
| AXButton | Deutsche Bahn, hidden, Deutsche Bahn, —, Good, Aug 19 | enabled | focusable |
| AXButton | Slack, hidden, —, Poor, Aug 4 | enabled | focusable |
| AXButton | eBay, hidden, eBay, —, Reused, Jul 21 | enabled | focusable |
| AXButton | AWS root account, hidden, —, Excellent, Jul 8 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Show username | enabled | focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### masked passkeys: 43 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 4 | enabled | focusable |
| AXButton | Two-step codes, 1 | enabled | focusable |
| AXButton | Needs attention, 0 | enabled | focusable |
| AXButton | GitHub, hidden, passkey, GitHub, 934 177, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, hidden, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Mastodon, hidden, passkey, Mastodon, —, Passkey only, Sep 18 | enabled | focusable |
| AXButton | Linear, hidden, passkey, Linear, —, Good, Sep 15 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open github.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Show username | enabled | focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 3 earlier versions | enabled | focusable |

#### masked shown username: 58 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 23 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Needs attention, 7 | enabled | focusable |
| AXButton | GitHub, hidden, passkey, GitHub, 934 177, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, hidden, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Google, hidden, Google, 750 343, Excellent, Oct 20 | enabled | focusable |
| AXButton | Hetzner Cloud, hidden, Hetzner, 983 420, Excellent, Oct 18 | enabled | focusable |
| AXButton | Proton Mail, hidden, Proton Mail, 125 348, Excellent, Oct 14 | enabled | focusable |
| AXButton | Server root · web-01, hidden, —, Weak, Oct 11 | enabled | focusable |
| AXButton | PayPal, hidden, PayPal, —, Good, Oct 9 | enabled | focusable |
| AXButton | Instagram, hidden, Instagram, 540 839, Good, Oct 2 | enabled | focusable |
| AXButton | Wise, hidden, Wise, 745 918, Excellent, Sep 28 | enabled | focusable |
| AXButton | Figma, hidden, Figma, —, Good, Sep 22 | enabled | focusable |
| AXButton | Mastodon, hidden, passkey, Mastodon, —, Passkey only, Sep 18 | enabled | focusable |
| AXButton | Linear, hidden, passkey, Linear, —, Good, Sep 15 | enabled | focusable |
| AXButton | Visa Debit, hidden, —, —, Sep 10 | enabled | focusable |
| AXButton | Zalando, hidden, Zalando, —, Expired, Sep 2 | enabled | focusable |
| AXButton | Amazon, hidden, —, Reused, Aug 27 | enabled | focusable |
| AXButton | Deutsche Bahn, hidden, Deutsche Bahn, —, Good, Aug 19 | enabled | focusable |
| AXButton | Slack, hidden, —, Poor, Aug 4 | enabled | focusable |
| AXButton | eBay, hidden, eBay, —, Reused, Jul 21 | enabled | focusable |
| AXButton | AWS root account, hidden, 666 470, Excellent, Jul 8 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Hide username | enabled | focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### more actions: 11 controls, 0 unnamed, 3 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Copy Username, ⌘B | enabled | focusable |
| AXButton | Copy Password, ⌘C | enabled | focusable |
| AXButton | Copy URL, ⇧⌘U | enabled | focusable |
| AXButton | Copy One-Time Code, ⌘T | enabled | focusable |
| AXButton | Type Login, ⇧⌘V | disabled | not-focusable |
| AXButton | Open URL, ⌘U | enabled | focusable |
| AXButton | Show Code as QR | disabled | not-focusable |
| AXButton | Clone Entry…, ⌘D | enabled | focusable |
| AXButton | Move to Group ▸ | disabled | not-focusable |
| AXButton | History | enabled | focusable |
| AXButton | Move to Recycle Bin, ⌘⌫ | enabled | focusable |

#### new vault: 5 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXTextField | Name | enabled | focusable |
| AXTextField | Description | enabled | focusable |
| AXButton | Change… | enabled | focusable |
| AXButton | Cancel | enabled | focusable |
| AXButton | Continue | enabled | focusable |

#### passkeys: 42 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 4 | enabled | focusable |
| AXButton | Two-step codes, 1 | enabled | focusable |
| AXButton | Needs attention, 0 | enabled | focusable |
| AXButton | GitHub, alex-dev ·, passkey, GitHub, 240 944, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, alex.morgan@icloud.com ·, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Mastodon, @alex@mastodon.social ·, passkey, Mastodon, —, Passkey only, Sep 18 | enabled | focusable |
| AXButton | Linear, alex@morgan-labs.dev ·, passkey, Linear, —, Good, Sep 15 | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open github.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 3 earlier versions | enabled | focusable |

#### recycle bin: 32 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Empty Recycle Bin | enabled | focusable |
| AXButton | Deleted entries | enabled | focusable |
| AXButton | Twitter (old account), @alexmorgan, X, —, Good, Oct 3 | enabled | focusable |
| AXButton | MySpace, alexm1999, —, Poor, Sep 12 | enabled | focusable |
| AXButton | Open x.com | enabled | focusable |
| AXButton | Restore | enabled | focusable |
| AXButton | Delete forever | enabled | focusable |

#### remove field question: 2 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Cancel | enabled | focusable |
| AXButton | Remove | enabled | focusable |

#### remove passkey question: 2 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Cancel | enabled | focusable |
| AXButton | Remove Passkey | enabled | focusable |

#### replace file question: 2 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Cancel | enabled | focusable |
| AXButton | Overwrite | enabled | focusable |

#### reports: 40 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Check again | enabled | focusable |
| AXButton | Health check, 7 | enabled | focusable |
| AXButton | Breach check | enabled | focusable |
| AXButton | Statistics | enabled | focusable |
| AXButton | Passkeys | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | Change password of Zalando | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Change password of Amazon | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Change password of eBay | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Change password of Reddit | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Change password of Router admin | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Change password of Slack | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Change password of Server root · web-01 | enabled | focusable |
| AXButton | More | enabled | focusable |

#### reports breach: 27 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Check again | enabled | focusable |
| AXButton | Health check, 7 | enabled | focusable |
| AXButton | Breach check | enabled | focusable |
| AXButton | Statistics | enabled | focusable |
| AXButton | Passkeys | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | Check passwords online | enabled | focusable |

#### reports browser: 26 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Check again | enabled | focusable |
| AXButton | Health check, 7 | enabled | focusable |
| AXButton | Breach check | enabled | focusable |
| AXButton | Statistics | enabled | focusable |
| AXButton | Passkeys | enabled | focusable |
| AXButton | Browser | enabled | focusable |

#### reports passkeys: 30 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Check again | enabled | focusable |
| AXButton | Health check, 7 | enabled | focusable |
| AXButton | Breach check | enabled | focusable |
| AXButton | Statistics | enabled | focusable |
| AXButton | Passkeys | enabled | focusable |
| AXButton | Browser | enabled | focusable |
| AXButton | Remove the passkey of Apple Account | enabled | focusable |
| AXButton | Remove the passkey of GitHub | enabled | focusable |
| AXButton | Remove the passkey of Linear | enabled | focusable |
| AXButton | Remove the passkey of Mastodon | enabled | focusable |

#### reports stats: 26 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Hide sidebar (⌃⌘S) | enabled | focusable |
| AXTextField | Search entries | enabled | focusable |
| AXButton | Lock, ⌘L | enabled | focusable |
| AXButton | Switch vault | enabled | focusable |
| AXButton | All entries, 23 | enabled | focusable |
| AXButton | Favorites, 5 | enabled | focusable |
| AXButton | One-time codes, 7 | enabled | focusable |
| AXButton | Passkeys, 4 | enabled | focusable |
| AXButton | Password health, 7 need attention | enabled | focusable |
| AXButton | New group | enabled | focusable |
| AXButton | Email, 2 | enabled | focusable |
| AXButton | Banking, 3 | enabled | focusable |
| AXButton | Social, 3 | enabled | focusable |
| AXButton | Shopping, 3 | enabled | focusable |
| AXButton | Work, 7 | enabled | focusable |
| AXButton | Servers, 3 | enabled | focusable |
| AXButton | Devices, 2 | enabled | focusable |
| AXButton | Tags | enabled | focusable |
| AXButton | Recycle Bin, 2 | enabled | focusable |
| AXButton | Settings, ⌘, | enabled | focusable |
| AXButton | Check again | enabled | focusable |
| AXButton | Health check, 7 | enabled | focusable |
| AXButton | Breach check | enabled | focusable |
| AXButton | Statistics | enabled | focusable |
| AXButton | Passkeys | enabled | focusable |
| AXButton | Browser | enabled | focusable |

#### risky file question: 2 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Cancel | enabled | focusable |
| AXButton | Open | enabled | focusable |

#### search: 40 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Clear search | enabled | focusable |
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | All, 23 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Needs attention, 7 | enabled | focusable |
| AXButton | GitHub, alex-dev ·, passkey, GitHub, 240 944, Excellent, 5 days | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open github.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 3 earlier versions | enabled | focusable |

#### search tips: 64 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Generator | enabled | focusable |
| AXButton | New Entry | enabled | focusable |
| AXButton | is:weak, Weak, reused or expired passwords | enabled | focusable |
| AXButton | is:expired, Entries past their expiry date | enabled | focusable |
| AXButton | All, 23 | enabled | focusable |
| AXButton | Two-step codes, 7 | enabled | focusable |
| AXButton | Needs attention, 7 | enabled | focusable |
| AXButton | group:Work, Entries in a group and its subgroups | enabled | focusable |
| AXButton | url:github, Only the website field | enabled | focusable |
| AXButton | GitHub, alex-dev ·, passkey, GitHub, 240 944, Excellent, 5 days | enabled | focusable |
| AXButton | Apple Account, alex.morgan@icloud.com ·, passkey, Apple, —, Good, 6 days | enabled | focusable |
| AXButton | Google, alex.morgan@gmail.com, Google, 786 564, Excellent, Oct 20 | enabled | focusable |
| AXButton | Hetzner Cloud, alex@morgan-labs.dev, Hetzner, 140 505, Excellent, Oct 18 | enabled | focusable |
| AXButton | Proton Mail, alex.morgan@proton.me, Proton Mail, 945 004, Excellent, Oct 14 | enabled | focusable |
| AXButton | Server root · web-01, root, —, Weak, Oct 11 | enabled | focusable |
| AXButton | PayPal, alex.morgan@posteo.de, PayPal, —, Good, Oct 9 | enabled | focusable |
| AXButton | Instagram, alex.morgan.photos, Instagram, 611 537, Good, Oct 2 | enabled | focusable |
| AXButton | Wise, alex.morgan@posteo.de, Wise, 019 696, Excellent, Sep 28 | enabled | focusable |
| AXButton | Figma, alex@morgan-labs.dev, Figma, —, Good, Sep 22 | enabled | focusable |
| AXButton | Mastodon, @alex@mastodon.social ·, passkey, Mastodon, —, Passkey only, Sep 18 | enabled | focusable |
| AXButton | Linear, alex@morgan-labs.dev ·, passkey, Linear, —, Good, Sep 15 | enabled | focusable |
| AXButton | Visa Debit, Card ending 1111, —, —, Sep 10 | enabled | focusable |
| AXButton | Zalando, alex.morgan@posteo.de, Zalando, —, Expired, Sep 2 | enabled | focusable |
| AXButton | Amazon, alex.morgan@posteo.de, —, Reused, Aug 27 | enabled | focusable |
| AXButton | Deutsche Bahn, alex.morgan@posteo.de, Deutsche Bahn, —, Good, Aug 19 | enabled | focusable |
| AXButton | Slack, alex@morgan-labs.dev, —, Poor, Aug 4 | enabled | focusable |
| AXButton | eBay, alexmorgan88, eBay, —, Reused, Jul 21 | enabled | focusable |
| AXButton | AWS root account, alex@morgan-labs.dev, —, Excellent, Jul 8 | enabled | focusable |
| AXButton | tag:2fa, Entries with a tag | enabled | focusable |
| AXButton | -amazon, Leave out entries with this word | enabled | focusable |
| AXButton | "exact words", Match the words in this order | enabled | focusable |
| AXButton | Edit entry (⌘E) | enabled | focusable |
| AXButton | Open accounts.google.com | enabled | focusable |
| AXButton | Open site | enabled | focusable |
| AXButton | Type login | disabled | not-focusable |
| AXButton | Copy one-time code | enabled | focusable |
| AXButton | 4 earlier versions | enabled | focusable |

#### settings general: 37 controls, 0 unnamed, 7 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXTextField | Search settings | enabled | focusable |
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser Integration | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Shared Groups | enabled | focusable |
| AXButton | Shortcuts | enabled | focusable |
| AXButton | Back | disabled | not-focusable |
| AXButton | Forward | disabled | not-focusable |
| AXCheckBox | Login | enabled | focusable |
| AXCheckBox | Reopen | enabled | focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXCheckBox | Recent | enabled | focusable |
| AXButton | Expiry days, Within 3 days | enabled | focusable |
| AXCheckBox | Expiry | enabled | focusable |
| AXCheckBox | Updates | disabled | not-focusable |
| AXCheckBox | Beta | disabled | not-focusable |
| AXCheckBox | Autosave | enabled | focusable |
| AXCheckBox | Save on lock | disabled | not-focusable |
| AXCheckBox | Reload | enabled | focusable |
| AXCheckBox | Backup | enabled | focusable |
| AXButton | Safe saving, Through a temporary file | enabled | focusable |
| AXCheckBox | Confirm | enabled | focusable |
| AXCheckBox | Autogen | enabled | focusable |
| AXButton | Double-click, Nothing | enabled | focusable |
| AXButton | Hide by, Minimize | disabled | not-focusable |
| AXCheckBox | Hide | enabled | focusable |
| AXButton | System | enabled | focusable |
| AXButton | Light | enabled | focusable |
| AXButton | Dark | enabled | focusable |
| AXCheckBox | Colour | enabled | focusable |
| AXCheckBox | Mono notes | enabled | focusable |
| AXButton | Menu bar icon, Monochrome icon | disabled | not-focusable |
| AXCheckBox | Menu bar | enabled | focusable |
| AXCheckBox | Hide on close | enabled | focusable |

#### settings security: 29 controls, 0 unnamed, 4 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXTextField | Search settings | enabled | focusable |
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser Integration | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Shared Groups | enabled | focusable |
| AXButton | Shortcuts | enabled | focusable |
| AXButton | Back | enabled | focusable |
| AXButton | Forward | disabled | not-focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXCheckBox | Clipboard | enabled | focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXCheckBox | Idle lock | enabled | focusable |
| AXButton | Less | disabled | not-focusable |
| AXButton | More | disabled | not-focusable |
| AXCheckBox | Clear search | enabled | focusable |
| AXCheckBox | Touch ID | disabled | not-focusable |
| AXCheckBox | Screen lock | enabled | focusable |
| AXCheckBox | User switch | enabled | focusable |
| AXCheckBox | Minimize | enabled | focusable |
| AXCheckBox | Editor | enabled | focusable |
| AXCheckBox | Preview | enabled | focusable |
| AXCheckBox | Codes | enabled | focusable |
| AXCheckBox | Notes | enabled | focusable |
| AXCheckBox | Dots | enabled | focusable |
| AXCheckBox | Capture | enabled | focusable |

#### settings autoType: 23 controls, 0 unnamed, 3 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXTextField | Search settings | enabled | focusable |
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser Integration | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Shared Groups | enabled | focusable |
| AXButton | Shortcuts | enabled | focusable |
| AXButton | Back | enabled | focusable |
| AXButton | Forward | disabled | not-focusable |
| AXLink | Open Privacy & Security | disabled | not-focusable |
| AXButton | Change | disabled | not-focusable |
| AXCheckBox | Title | enabled | focusable |
| AXCheckBox | URL | enabled | focusable |
| AXCheckBox | Ask | enabled | focusable |
| AXCheckBox | Expired | enabled | focusable |
| AXCheckBox | Relock | enabled | focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |

#### settings browser: 25 controls, 0 unnamed, 15 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXTextField | Search settings | enabled | focusable |
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser Integration | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Shared Groups | enabled | focusable |
| AXButton | Shortcuts | enabled | focusable |
| AXButton | Back | enabled | focusable |
| AXButton | Forward | disabled | not-focusable |
| AXCheckBox | Browser | enabled | focusable |
| AXCheckBox | Safari | disabled | not-focusable |
| AXCheckBox | Chrome | disabled | not-focusable |
| AXCheckBox | Firefox | disabled | not-focusable |
| AXCheckBox | Brave | disabled | not-focusable |
| AXCheckBox | Vivaldi | disabled | not-focusable |
| AXCheckBox | Opera | disabled | not-focusable |
| AXCheckBox | Notify | disabled | not-focusable |
| AXCheckBox | Unlock | disabled | not-focusable |
| AXCheckBox | Best | disabled | not-focusable |
| AXCheckBox | All vaults | disabled | not-focusable |
| AXCheckBox | Never ask | disabled | not-focusable |
| AXCheckBox | Localhost | disabled | not-focusable |
| AXCheckBox | Proxy | disabled | not-focusable |
| AXCheckBox | Rewrite | disabled | not-focusable |

#### settings ssh: 12 controls, 0 unnamed, 2 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXTextField | Search settings | enabled | focusable |
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser Integration | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Shared Groups | enabled | focusable |
| AXButton | Shortcuts | enabled | focusable |
| AXButton | Back | enabled | focusable |
| AXButton | Forward | disabled | not-focusable |
| AXCheckBox | SSH | enabled | focusable |
| AXCheckBox | Socket | disabled | not-focusable |

#### settings share: 14 controls, 0 unnamed, 2 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXTextField | Search settings | enabled | focusable |
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser Integration | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Shared Groups | enabled | focusable |
| AXButton | Shortcuts | enabled | focusable |
| AXButton | Back | enabled | focusable |
| AXButton | Forward | disabled | not-focusable |
| AXCheckBox | Import | enabled | focusable |
| AXCheckBox | Export | enabled | focusable |
| AXCheckBox | Quiet | enabled | focusable |
| AXButton | Export certificate… | disabled | not-focusable |

#### settings keys: 10 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXTextField | Search settings | enabled | focusable |
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Auto-Type | enabled | focusable |
| AXButton | Browser Integration | enabled | focusable |
| AXButton | SSH Agent | enabled | focusable |
| AXButton | Shared Groups | enabled | focusable |
| AXButton | Shortcuts | enabled | focusable |
| AXButton | Back | enabled | focusable |
| AXButton | Forward | disabled | not-focusable |

#### sort menu: 5 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Modified | enabled | focusable |
| AXButton | Title | enabled | focusable |
| AXButton | Created | enabled | focusable |
| AXButton | Newest first | enabled | focusable |
| AXButton | Oldest first | enabled | focusable |

#### unlock: 7 controls, 0 unnamed, 2 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Switch vault | enabled | focusable |
| AXTextField | Password | enabled | focusable |
| AXButton | Show password | enabled | focusable |
| AXButton | Key file | enabled | focusable |
| AXCheckBox | Use a security key | disabled | not-focusable |
| AXButton | Unlock | enabled | focusable |
| AXButton | Use Touch ID | disabled | not-focusable |

#### unlock key file: 7 controls, 0 unnamed, 2 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Switch vault | enabled | focusable |
| AXTextField | Password | enabled | focusable |
| AXButton | Show password | enabled | focusable |
| AXButton | Key file | enabled | focusable |
| AXCheckBox | Use a security key | disabled | not-focusable |
| AXButton | Unlock | enabled | focusable |
| AXButton | Use Touch ID | disabled | not-focusable |

#### unlock touch id: 3 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Switch vault | enabled | focusable |
| AXButton | Unlock with Touch ID | disabled | not-focusable |
| AXButton | Use password instead | enabled | focusable |

#### unlock typed password: 7 controls, 0 unnamed, 2 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Switch vault | enabled | focusable |
| AXTextField | Password | enabled | focusable |
| AXButton | Show password | enabled | focusable |
| AXButton | Key file | enabled | focusable |
| AXCheckBox | Use a security key | disabled | not-focusable |
| AXButton | Unlock | enabled | focusable |
| AXButton | Use Touch ID | disabled | not-focusable |

#### unlock vault switcher: 9 controls, 0 unnamed, 3 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Personal, locked | enabled | focusable |
| AXButton | Work, locked | enabled | focusable |
| AXButton | Family, locked | enabled | focusable |
| AXButton | New Vault…, ⇧⌘N | enabled | focusable |
| AXButton | Open Vault…, ⌘O | enabled | focusable |
| AXButton | Import… | disabled | not-focusable |
| AXButton | Vault Settings…, ⇧⌘, | disabled | not-focusable |
| AXButton | Lock Personal, ⌘L | disabled | not-focusable |
| AXButton | Lock Everything, ⇧⌘L | enabled | focusable |

#### vault general: 16 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Recycle Bin | enabled | focusable |
| AXButton | History | enabled | focusable |
| AXButton | Browser Keys | enabled | focusable |
| AXTextField | Name | enabled | focusable |
| AXTextField | Default username | enabled | focusable |
| AXTextField | Description | enabled | focusable |
| AXButton | teal | enabled | focusable |
| AXButton | blue | enabled | focusable |
| AXButton | green | enabled | focusable |
| AXButton | orange | enabled | focusable |
| AXButton | pink | enabled | focusable |
| AXButton | purple | enabled | focusable |
| AXButton | slate | enabled | focusable |
| AXButton | Show in Finder | enabled | focusable |

#### vault security: 17 controls, 0 unnamed, 3 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Recycle Bin | enabled | focusable |
| AXButton | History | enabled | focusable |
| AXButton | Browser Keys | enabled | focusable |
| AXButton | Change… | enabled | focusable |
| AXButton | Change… | enabled | focusable |
| AXButton | Remove | disabled | not-focusable |
| AXButton | Change… | disabled | not-focusable |
| AXCheckBox | Touch ID | disabled | not-focusable |
| AXButton | Cipher | enabled | focusable |
| AXButton | Key derivation | enabled | focusable |
| AXSlider | Unlock time on this Mac | enabled | focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |

#### vault bin: 9 controls, 0 unnamed, 3 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Recycle Bin | enabled | focusable |
| AXButton | History | enabled | focusable |
| AXButton | Browser Keys | enabled | focusable |
| AXCheckBox | Bin | enabled | focusable |
| AXButton | Less | disabled | not-focusable |
| AXButton | More | disabled | not-focusable |
| AXCheckBox | Auto empty | disabled | not-focusable |

#### vault history: 11 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Recycle Bin | enabled | focusable |
| AXButton | History | enabled | focusable |
| AXButton | Browser Keys | enabled | focusable |
| AXCheckBox | History | enabled | focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Less | enabled | focusable |
| AXButton | More | enabled | focusable |
| AXButton | Delete all history… | enabled | focusable |

#### vault browser: 8 controls, 0 unnamed, 0 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | General | enabled | focusable |
| AXButton | Security | enabled | focusable |
| AXButton | Recycle Bin | enabled | focusable |
| AXButton | History | enabled | focusable |
| AXButton | Browser Keys | enabled | focusable |
| AXButton | Disconnect Firefox on MacBook | enabled | focusable |
| AXButton | Disconnect Safari | enabled | focusable |
| AXButton | Remove all… | enabled | focusable |

#### vault switcher: 9 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | Personal, open | enabled | focusable |
| AXButton | Work, locked | enabled | focusable |
| AXButton | Family, locked | enabled | focusable |
| AXButton | New Vault…, ⇧⌘N | enabled | focusable |
| AXButton | Open Vault…, ⌘O | enabled | focusable |
| AXButton | Import… | disabled | not-focusable |
| AXButton | Vault Settings…, ⇧⌘, | enabled | focusable |
| AXButton | Lock Personal, ⌘L | enabled | focusable |
| AXButton | Lock Everything, ⇧⌘L | enabled | focusable |

#### welcome: 3 controls, 0 unnamed, 1 the focus cannot reach (0 of them enabled)

| Role | Name | State | Keyboard |
|---|---|---|---|
| AXButton | New vault, An encrypted file for your passwords | enabled | focusable |
| AXButton | Open vault…, A vault file on this Mac or a synced folder | enabled | focusable |
| AXButton | Import…, From CSV or another password manager | disabled | not-focusable |

## Name check

Round 2: `scripts/check-names.sh` after writing this file, the parity report and the plan/epics.md line: `names: PASS (3117 files scanned, 15 vault files name-only)`.

Round 3: `scripts/check-names.sh` after writing the Round 3 section and the plan/epics.md line: `names: PASS (3166 files scanned, 16 vault files name-only)`.
