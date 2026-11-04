# Design parity: section `menubar`

Date 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). Larsal: offscreen snapshots of SnapshotTests.

**Result: 2 of 2 built frames PASS** (2 frames in the section; 0 belong to later stories).

Check tools: pixelmatch 8.0.0, pngjs 7.0.0 (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |
|---|---|---|---|---|---|---|---|
| menubar-menu-bar-icon | present | present | 0.54 % (0.5 %) / 0.53 % (0.48 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| menubar-auto-type-picker | present | present | 0.63 % (0.63 %) / 1.41 % (1.41 %) | 0 | 1 / 1 | 0 + 0 / 0 + 0 | PASS |

Token mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): 45 of 45 equal.

## Findings per frame

### menubar-menu-bar-icon: PASS

- Built by E5-S11. The live menu is a native NSMenu that macOS draws (APP-08.24, APP-08.25, LD-214 (2)); the snapshot is MenuBarIconFrame (test code) drawing that NSMenu's items, keys, badges and enabled states with Option A's menu parts over the mockup's desktop and bar, so its pixels prove the items, not macOS's own menu look (Mac QA).
- Accepted (LD-214 (1)): the drawn menu bar reads Larsal, File, Edit, View, Vault, Entry, the real SwiftUI order (Apple HIG: app menus after View); the mockup draws View after Entry.
- The status item itself is never added in tests (FakeSlot; NoStatusSlot in a hidden launch); the icon on a real menu bar is Mac QA (owner's go).

Images: light `app/light/menubar-menu-bar-icon.png` against `../../option-a/reference/light/menubar-menu-bar-icon.png`, diff `diff/light/menubar-menu-bar-icon.png`; dark likewise.

### menubar-auto-type-picker: PASS

- Built by E8-S2. The search field has the keyboard focus as the picker appears (INT-05.26): its accent ring and soft halo are drawn, as on vault-new-vault-step-1; the mockup draws no focus. The snapshot is AutoTypePickerFrame (test code): the mockup's desktop with the real AutoTypePickerView over the Personal demo vault plus the frame's "GitHub (work bot)" entry, with GitHub's second window rule left out in memory so the list holds the frame's two rows. ⏎ is drawn in the system font, as the mockup's font stack falls back to it.
- Not drawn until the owner's mockup changes (W-06): the app name under the header (D-INT05-16 (3)), the small line's sequence and vault additions, the empty list MI05-45 and the row menu MI05-44 (D-INT05-16 (4)), and R05-6's hint line; MI05-43 stays as drawn.

Images: light `app/light/menubar-auto-type-picker.png` against `../../option-a/reference/light/menubar-auto-type-picker.png`, diff `diff/light/menubar-auto-type-picker.png`; dark likewise.

## Contrast (check 7)

Token pairs that carry words, WCAG ratio, both themes: 42 pairs, lowest 4.87:1; under 4.5:1: none.

## Commands run

Run from the project root on 2026-10-28, in this order. No window was opened: Chrome ran headless, the app views rendered in borderless windows at x −20000 that were never ordered front, and the test process is not a hosted app.

1. `node design/option-a/tools/export-reference.mjs` (reference images and manifest from the current mockup)
   → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames` (5 min 23 s).
2. `npm install --prefix /tmp/parity-tools pixelmatch pngjs` → `added 2 packages`; versions pixelmatch 8.0.0, pngjs 7.0.0 (outside the project).
3. `scripts/build-core.sh` → `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`, exit 0.
4. `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath target/xcode test -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` (the check.sh G2 test step)
   → `✔ Suite SnapshotTests passed`, `✔ Suite ParityLockTests passed`, `✔ Suite ParityMainTests passed`, `✔ Suite ParityStatesTests passed`, `✔ Suite ScreenTests passed`, `✔ Suite ParityFontTests passed`, `✔ Test run with 41 tests in 10 suites passed after 30.276 seconds`, `** TEST SUCCEEDED **`. SnapshotTests wrote larsal-shots/<theme>/<frame-id>.png and, new for this check, the accessibility tree next to each (`<frame-id>.ax.json`, test only). The Parity suites are new (test only, 27 tests): they press the mockup's controls through the accessibility tree. Log: target/parity/behaviour.log.
5. `swift format lint --strict macos/LarsalTests/*.swift` and `swiftlint lint --strict --quiet LarsalTests/` (in macos/) → no findings.
6. `node design/parity/tools/mockup-dom.mjs lock,main,states` (mockup boxes, text runs, fonts, glyphs, controls; headless) → `light: 21 frames, 2586 text runs`, `dark: 21 frames, 2586 text runs`.
7. `swift design/parity/tools/ocr.swift larsal-shots/light/*.png larsal-shots/dark/*.png` (on-device text recognition, only for strings kept out of the accessibility tree) → 36 images read.
8. `node design/parity/tools/compare.mjs <section>` (pixelmatch threshold 0.1, includeAA false; text, tokens, geometry, behaviour; writes this report).

Measured looks (LD-169): `ParityFontTests` (new, test only). "Font check" reads the large code's font runs from the accessibility tree and compares the drawn glyphs of the large code and a row code with the same string set by Core Text in IBM Plex Mono 500 and in the system face. "Focus check" renders the focused row offscreen in light and dark and reads the outline back. A probe in /tmp showed that the font runs in the tree name the requested font even where the glyphs drawn differ, so the glyph comparison is the deciding check.

E6-S1 re-run (Builder, 2026-10-28, sections lock, main and states; states-copied added): steps 1, 2 and 6 were not repeated (mockup.js and app.css are older than the reference images and target/parity/dom-*.json).
3. `scripts/build-core.sh` → `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift` (bindings with `copyField`, `clearClipboard`, `Copied`).
4. The check.sh G2 test step as above → `✔ Suite SnapshotTests passed`, `✔ Suite ParityStatesTests passed`, `✔ Test run with 45 tests in 10 suites passed after 32.980 seconds`, `** TEST SUCCEEDED **`. New: the states-copied snapshot and three "Parity states-copied" tests. The offscreen windows are now pinned to sRGB: on 2026-10-28 the Mac's screen gave Display P3 renders (accent #1b6c80 read as 53,107,126), which failed the Focus check and would shift every colour; the reference images are sRGB. Log: target/parity/behaviour.log.
7. `swift design/parity/tools/ocr.swift larsal-shots/light/*.png larsal-shots/dark/*.png` → 38 images read.
8. `node design/parity/tools/compare.mjs lock` → `lock: 4/4 PASS`; `node design/parity/tools/compare.mjs main` → `main: 2/2 PASS`; `node design/parity/tools/compare.mjs states` → `states: 13/13 PASS` (states-copied light 1.57 %, dark 1.6 %).

E6-S1 second pass (Builder, 2026-10-28, LD-181): larsal-ffi `copy_code` and `copy_fingerprint`; Copy One-Time Code (⌘T), the code row's Copy and Copy fingerprint work; the unlock form's shown password is an AppKit field whose own field editor has no Copy or Cut (APP-03.19).
3. `scripts/build-core.sh` → bindings with `copyCode` and `copyFingerprint`.
4. The check.sh G2 test step → `✔ Test run with 47 tests in 10 suites passed after 30.581 seconds`, `** TEST SUCCEEDED **`; general pasteboard change count 10124 before and after the run. Log: target/parity/behaviour.log.
7. OCR as above → 38 images read.
8. `node design/parity/tools/compare.mjs lock`, `main`, `states`: counts in each report's result line.

E6-S1 Checker fix (Builder, 2026-10-28): the shown password's editor matches the system's password editor (no writable pasteboard types, no single- or multi-type selection write, no Services send, no drag, no Writing Tools, no corrections, replacements or completion, a context menu of Paste, Delete, Select All only). Test moved to ShownPasswordFieldTests.swift with a plain text view as control.
4. The G2 test step with `-derivedDataPath /tmp/e6s1/dd` → `✔ Test run with 47 tests in 11 suites passed after 31.305 seconds`, `** TEST SUCCEEDED **`; general pasteboard change count 10124 before and after. Log: target/parity/behaviour.log.
8. `node design/parity/tools/compare.mjs lock` → result line of design/parity/lock/report.md.

This report: `node design/parity/tools/compare.mjs menubar` printed:

```
menubar: 2/2 PASS
menubar-menu-bar-icon                          PASS                   L 0.54% (0.5) D 0.53% (0.48)
menubar-auto-type-picker                       PASS                   L 0.63% (0.63) D 1.41% (1.41)
```
