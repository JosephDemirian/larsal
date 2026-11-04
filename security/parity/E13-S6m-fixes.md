# E13-S6 part m: re-test of the export and preview screens, the small Mac gaps and the tree-wide Swift lint

Story: E13-S6 part m ([plan/epics.md](../../plan/epics.md)). Rulings: LD-227 (3) (SD-07 window screens), LD-230 (4), (5) (MOD-05.9 gaps, the SD-13 Swift case), LD-239 (2) (part m's list, the lint), LD-241 (1) (MenuKeysTests.swift:241, EditorEntryPage.swift's length), LD-243 (1), (3) (Fetch Site Icons for Group…, the wizard's step 3 while creating), LD-244 (2) (No as the Return answer). Rows: SD-07 in [plan/security.md](../../plan/security.md). None of these items has an F- row in [security/findings.md](../findings.md): they come from the rulings above, so no findings.md row was changed.
Date: 2026-10-29, as the brief dates it (the runs took place from 12:13 to about 12:45 on 2026-10-30 by the Mac's clock). Role: Verify, round 1. I did not find, build or check these fixes.

| Item | Result | One line |
|---|---|---|
| SD-07: File > Export CSV, HTML, XML and the Passkeys report's Export | **fixed, re-tested** | CSV and XML ask MSG-EXP-CONFIRM (Rust's `export_warning`) before the save panel; HTML shows the warning as its dialog's banner; the Passkeys export asks MI04-30 (`passkey_export_warning`) before the list, the folder and MI04-32. No, Escape and Return write nothing. Files are 0600. |
| MOD-05.9: image off the main thread | **fixed, re-tested** | `PreviewSheet.decoder` runs in `Task.detached`; a decoder that answers only off the main thread still shows the image. |
| MOD-05.9: Open and Save… in the preview | **fixed, re-tested** | Both run the editor's own actions on the entry's draft (Advanced page). Open keeps MOD-05.12's ask-first for a risky file. |
| MOD-05.9: `.scrollIndicators(.never)` and the AT-K06 preview case | **fixed, re-tested** | The walk's `preview` case (80 lines of text) passes; it fails with the modifier removed. |
| SD-13 Swift case (LD-230 (5)) | **fixed, re-tested** | A link in HTML and in Markdown shows as typed, with no AXLink node. |
| LD-243 (1): Fetch Site Icons for Group… | **fixed, re-tested** | On for a group with entries and for All entries; off for an empty group, the bin and while the editor is open; the press reaches Rust's `fetch_site_icons`. |
| LD-243 (3): the wizard's step 3 while creating | **fixed, re-tested** | `PasswordStep(...).disabled(model.creating)`: four controls go off while 'Creating the vault…' shows. |
| LD-241 (1): MenuKeysTests.swift:241 | **fixed, re-tested** | `rules.keyWindow = { other }` is restored right after the two synchronous `performKeyEquivalent` calls, before any `await`. |
| Tree-wide lint (LD-239 (2), LD-241 (1)) | **fixed, re-tested** | `swift format lint --strict --recursive macos` and `swiftlint lint --strict` (0.65.1) both exit 0 on the whole tree; EditorEntryPage.swift is 399 lines. |

All 7 items were re-tested (MOD-05.9 counted once), and none failed. Every new test failed on a mutant of its fix (14 mutants, 12 caught, 2 probes outside the tests' reach: see "Advisories").

## Setup

- Private copy: `rsync -a --exclude target --exclude app-shots --exclude .build` of the tree to `/tmp/e13s6m-verify-copy`, with its own `CARGO_TARGET_DIR=/tmp/e13s6m-verify-target` and `-derivedDataPath /tmp/e13s6m-verify-dd`. `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`, `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` on every xcodebuild run.
- `scripts/build-core.sh` in the copy: exit 0 (`build-core (debug): target/app-core/AppFFI.xcframework ...`).
- Demo data only: the Option A Personal, Work and Family demo vaults (`testdata/option-a-*.appvault`, passwords `demo-pass-7`, `-8`, `-9`), copied per test into the copy's `target/option-a/`. My own files: a 64 × 48 PNG, a `run.command` holding `echo demo`, a `Linear.passkey` holding `x`.
- Nothing was shown on screen. Keys go to the offscreen window's own `performKeyEquivalent`; menus are `NSHostingMenu` objects that are never opened; attachment Open goes to the tests' `FakeOpener`; the save and folder panels are replaced in every test (AGENTS.md rule 10). No pasteboard was used. No network: downloads stay off (S-ENTRY-11), so Rust refuses the icon fetch before any request.
- Lints and the name guard ran on the shared tree in lint mode only. The shared files of part m were not changed by my runs: their md5 after the runs matches the snapshot taken before them, and `cmp` shows the copy I mutated was restored to the tree's text after each batch.
- My own repro tests (`VerifyMReproTests`, 3 tests) were written in the copy only and deleted with it.

## SD-07: plain exports from the window (LD-227 (3))

Steps (demo data):
1. Personal unlocked. File > Export ▸ CSV… through the real File menu (`NSHostingMenu(FileMenuItems)`, `performActionForItem`). Read the sheet. Press No. Then Return, then Escape, each on a fresh question. Then Yes; the save panel answers a private folder.
2. The same for XML…. Then HTML…: read the banner and the sort choices; Cancel; then Name, Z to A and OK.
3. Passkeys report: Export Passkeys… (MI04-30), No, Return, Escape; then Yes, untick GitHub, Export Selected. Put `x` in `Linear.passkey` and export Linear again (MI04-32): No, Return, Escape, then Yes.
4. Verify's own: the File menu with the shown vault locked; CSV with the save panel cancelled; MI04-32 for Linear in a list of Linear and Mastodon, answered No.

Before: the File > Export CSV, HTML and XML items were disabled and the Passkeys report had no export (E13-S6e Verify, the SD-07 row), so the row waited for these screens. Mutant V1 below rebuilds the unsafe form of the screen (no question).

After:
- CSV and XML: `main.dialog == .export(.ask(format, warning))` right after the menu press, with Rust's text on the sheet and no panel asked. No, Return and Escape each end it with no panel and no file. Yes asks the panel once (`csv Personal`, `xml Personal`); the file starts with `"Group"` or `<?xml` and has mode 0600.
- HTML: the dialog with the warning as its banner and Name, A to Z / Name, Z to A / Order in the vault; Cancel writes nothing; OK with Z to A writes a page whose Work section comes before Banking, 0600.
- Passkeys: MI04-30 with Rust's text first; No, Return and Escape leave the folder empty and ask no panel. Yes shows the list ("Each file is named after its entry's title."); with GitHub unticked, Export Selected asks the folder once and writes `Apple Account.passkey`, `Linear.passkey`, `Mastodon.passkey`, each 0600. MI04-32: No, Return and Escape leave `x` in place; Yes replaces it (content holds `linear.app`), 0600.
- Verify's own: with the vault locked, File > Export is off (FEA-09.1, case 09-01). A cancelled save panel after Yes leaves no dialog and no file. MI04-32 No for Linear leaves `x` and still writes `Mastodon.passkey`.
- Every path to a file goes through a warning: `askExport` is the only caller of the CSV, HTML and XML export (AppCommands.swift:106-108); `.export(.passkeys(rows))` is set only by MI04-30's Yes, and MI04-32 is reached only from `exportPasskeys` (grep of macos/App). Rust's own gate still holds: `cargo test -p app-ffi --features net sd_07` → `export::tests::sd_07_every_plain_export_warns ... ok`.

Proof: ExportScreensTests `sd07CsvAndXmlAskFirst` (csv, xml), `sd07HtmlBanner`, `sd07PasskeyExportWarns`, all passed (baseline in the copy and the full run); VerifyMReproTests 3 of 3 passed, run alone. Mutants V1, V2, V3, V4 below.

## MOD-05.9: the preview (LD-230 (4), LD-239 (2))

Steps: draw `PreviewSheet` offscreen with the demo PNG while `PreviewSheet.decoder` answers nil on the main thread; look for the AXImage named `demo.png`. Select GitHub, preview its attachment, press Open; preview again, press Save… with the folder panel cancelled, then answering a private folder. Verify's own: add `run.command` to GitHub, save, preview it, press Open. AT-K06 walk, case `preview` (80 lines of text).

Before (LD-230 (4), E5-S11 Verify advisory 1): the preview decoded the image on the main thread, had no Open or Save…, and its text preview showed AppKit scroll bars whose parts have no names; the walk had no preview case.

After:
- The image shows although the decoder refuses the main thread (`mod059ImageDecodedOffMain`). Mutant V11 (`Task.detached { @MainActor in ... }`) fails it at MacGapsTests.swift:59. The Checker's M1 (inline) and M2 (plain `Task`) were caught too.
- Open opens the entry's editor on Advanced and hands a copy with the attachment's extension to the opener; the preview closes. Save… with a cancelled panel keeps the preview and opens no editor; with a folder it writes the attachment there (`mod059PreviewOpenAndSave`).
- Open on a risky attachment from the preview asks first: `main.dialog == .openRisky(name: "run.command")` and no `.command` file reached the opener (Verify's own test). The preview uses `VaultModel.openAttachment`, the editor's own action, so MOD-05.12's ask-first and the F-086 copy watch apply.
- The walk's `preview` case passes; with `.scrollIndicators(.never)` removed (V5) it fails at AccessibilityWalkTests.swift:120.

## SD-13 Swift case (LD-230 (5))

Steps: the text preview with `<p>Hi <a href="https://example.com/x">demo link</a></p>` (page.html) and `Read [demo link](https://example.com/x) and <https://example.com/y>` (notes.md); read the strings and every node's role.

Before: no Swift test had a link in HTML or Markdown (LD-230 (5)).

After: each text is on the sheet exactly as typed; no AXLink node (`sd13LinkIsText`). Mutant V6 (the text drawn through `AttributedString(markdown:)`) fails it at MacGapsTests.swift:109 (both texts) and :111 (an AXLink for notes.md).

## LD-243 (1): Fetch Site Icons for Group…

Steps: Group menu (`GroupMenuItems`) with Email, All entries, a new empty group and the bin chosen; the group context menu for Email and for the empty group; press the Group menu item with Email chosen.

Before: the item existed in the Vault menu and the group context menu but was not wired (LD-243 (1)).

After: on for Email and All entries, off for the empty group and the bin, in both menus; off while the editor is open (`MenuState.list` is nil then; the context menu checks `model.editor`). The press reaches Rust: the toast reads "Website icon downloads are off. Turn them on in Settings › Entries." (`ld243FetchGroupIcons`). Mutants V7 (Group menu always on) and V8 (context menu on for an empty group) fail it at MacGapsTests.swift:134 and :138. The entries sent are the group's live entries through `session.list(view: .group(id:))` (OpenURL.swift:65), read in code; see advisory 1.

## LD-243 (3): the wizard's step 3 while creating

Steps: the wizard at step 3 offscreen; read New Key File…, Choose Key File…, Hide password and Generate password; start the write; read them again while `model.creating`.

Before: the step 3 body stayed enabled while 'Creating the vault…' showed (LD-243 (3)).

After: on before, off while creating (`ld243Step3DisabledWhileCreating`). Mutant V9 (the modifier removed) fails it 4 times at MacGapsTests.swift:169.

## LD-241 (1): MenuKeysTests.swift:241

Read: in `cutCopyWhileLocked` the override `rules.keyWindow = { other }` (line 241) is followed by two synchronous `menu.performKeyEquivalent` calls and restored at line 247, with no `await` between; the outer `defer` still restores it on a throw. The other overrides in the file (lines 75 and 278) have no `await` after them either. MenuKeysTests and CopySelectionTests (the suite it clashed with) both passed side by side in the full run.

## Tree-wide lint (LD-239 (2), LD-241 (1))

- `swift format lint --strict --recursive macos`: exit 0 (shared tree, 12:13).
- `swiftlint lint --strict --quiet` in macos/ with `scripts/install-swiftlint.sh --path` (0.65.1): exit 0.
- `wc -l macos/App/EditorEntryPage.swift`: 399 (under SwiftLint's 400-line limit); part h has signed (plan/epics.md).
- `scripts/check-names.sh`: `names: PASS (3209 files scanned, 16 vault files name-only)`, exit 0.
- No change in behaviour: the full app test run in the copy below.

## Full app test run (copy)

`xcodebuild ... test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: 345 tests in 50 suites, 342 passed, 3 failed under load: ScreenTests FEA-01.34 (50 ms search timing), ParityEditorFilesTests `openAndRemove` (see advisory 3) and `expiry` (a 5 s clock bound, the test took 26 s). Run alone: ParityEditorFilesTests 5 of 5 passed, `ScreenTests/searchSpeed()` passed. ExportScreensTests, MacGapsTests, AccessibilityWalkTests, MenuKeysTests, CopySelectionTests, MenuBarTests and ReportsTests all passed in the full run.

## Mutants (private copy, three batches; each batch's files restored and compared with the tree)

| # | Change | Caught by |
|---|---|---|
| V1 | `askExport` writes at once: `export(format, type: warning.extension)` | `sd07CsvAndXmlAskFirst` (csv, xml: :79, :81, :82), `sd07HtmlBanner` (:120, :123, :125), Verify's export test (:35) |
| V2 | HTML dialog without the warning text | `sd07HtmlBanner` (:123) |
| V3 | `askPasskeyExport` skips MI04-30 | `sd07PasskeyExportWarns` (:166, :168) |
| V4 | MI04-32's No replaces the file | `sd07PasskeyExportWarns` (:202, :53 twice), Verify's MI04-32 test (:60) |
| V5 | `.scrollIndicators(.never)` removed | AT-K06 walk, case `preview` (:120) |
| V6 | text preview through `AttributedString(markdown:)` | `sd13LinkIsText` (:109 twice, :111) |
| V7 | Group menu item never disabled | `ld243FetchGroupIcons` (:134, empty group and bin) |
| V8 | context menu ignores `group.count == 0` | `ld243FetchGroupIcons` (:138) |
| V9 | `.disabled(model.creating)` removed from step 3 | `ld243Step3DisabledWhileCreating` (:169, 4 controls) |
| V10 | Open and Save… do not turn to the Advanced page | `mod059PreviewOpenAndSave` (:74, :91) |
| V11 | decoder run as `Task.detached { @MainActor in ... }` | `mod059ImageDecodedOffMain` (:59) |
| P13 | context menu fetches `.all` in place of the group | survived (probe; advisory 1) |
| P14 | the Passkeys row menu's "Export Passkeys…" removed | survived (probe; advisory 2) |

Batch A (V1, V3, V5, V8, V9): TEST FAILED, 24 issues; batch B (V2, V4, V6, V7, V10): 12 issues; batch C (V11, P13, P14): 1 issue (V11 only). The mutants of each batch are in different tests, so each failure names its own mutant.

## Advisories for the lead (none blocks the sign-off)

1. **The group fetch's entries are not pinned by a test (P13 survived).** The context-menu press is never tested, and the Group-menu press is checked only up to Rust's "downloads are off" refusal, which Rust makes before it reads the ids. The code sends `session.list(view: .group(id: group.id))`, the group's live entries, bin left out. Pinning the ids needs a fake transport seam in Swift (not built; no network may be used). Low, test-only.
2. **The Passkeys row menu item is not pressed by a test (P14 survived).** The test calls `askPasskeyExport()` directly. No file can skip the warning: `.passkeys(rows)` is set only by MI04-30's Yes. Low, test-only; a test could read the row's menu once W-12 draws Export under the table.
3. **Shared `FakeOpener` in ParityEditorFilesTests.openAndRemove (not part m's file).** It takes `FakeOpener.opened.dropFirst(before).first`; in the full run another suite's copy, already wiped, came first, and the test failed (it passed alone). Part m's `mod059PreviewOpenAndSave` is one more opener. Smallest fix: match the copy by the attachment's extension, as part m's own test does.
4. **Panel seams are process-wide.** `VaultModel.exportPanel`, `passkeyFolderPanel`, `attachmentFolderPanel` and `PreviewSheet.decoder` are each replaced by one serialized suite today, so they do not clash. A second suite replacing the same seam could put the real panel back in the middle of the other suite's test (rule 10). My own repro test did share `exportPanel` with ExportScreensTests in the baseline and mutant runs; no panel was shown (each run ended in under a minute, and a modal panel would have stopped it), and it was then run alone.
5. **Mac QA (W-08):** Return on the export questions in a real visible window, whether Tab stops on the hidden default button with Full Keyboard Access on (the Checker's note, also true of MSG-LOCK-DISCARD-EDIT), and the real save and folder panels.
