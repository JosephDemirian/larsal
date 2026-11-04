# Design parity: section `editor`

Date 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). App: offscreen snapshots of SnapshotTests.

**Result: 9 of 9 built frames PASS** (9 frames in the section; 0 belong to later stories).

Check tools: pixelmatch 8.0.0, pngjs 7.0.0 (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |
|---|---|---|---|---|---|---|---|
| editor-editor-entry | present | present | 0.52 % (0.4 %) / 0.53 % (0.42 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| editor-editor-advanced | present | present | 0.92 % (0.85 %) / 0.93 % (0.87 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| editor-editor-icon | present | present | 0.65 % (0.61 %) / 0.66 % (0.62 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| editor-editor-auto-type | present | present | 0.94 % (0.86 %) / 0.95 % (0.87 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| editor-editor-browser | present | present | 0.45 % (0.37 %) / 0.46 % (0.39 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| editor-editor-ssh-agent | present | present | 0.95 % (0.69 %) / 0.97 % (0.71 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| editor-editor-properties | present | present | 0.52 % (0.47 %) / 0.56 % (0.51 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| editor-editor-history | present | present | 0.71 % (0.63 %) / 0.72 % (0.65 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| editor-new-entry | present | present | 0.52 % (0.43 %) / 0.73 % (0.66 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |

Token mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): 45 of 45 equal.

## Findings per frame

### editor-editor-entry: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.052 to IBM Plex Mono 500 against 0.360 to the system face; 14.0 pt code: ink distance 0.118 to IBM Plex Mono 500 against 0.282 to the system face.

Images: light `app/light/editor-editor-entry.png` against `../../option-a/reference/light/editor-editor-entry.png`, diff `diff/light/editor-editor-entry.png`; dark likewise.

### editor-editor-advanced: PASS

- The drop line in the card's words is shorter, so its centred text starts 4.3 pt further right (LD-192 (3)).
- Custom fields sorted by name (MOD-01, LD-192 (5)); the API token shows dots only (rule 4).
- Accepted (LD-192 (5)): card and data over the mockup where the rules above name them; LD-167 wordings.

Images: light `app/light/editor-editor-advanced.png` against `../../option-a/reference/light/editor-editor-advanced.png`, diff `diff/light/editor-editor-advanced.png`; dark likewise.

### editor-editor-icon: PASS


Images: light `app/light/editor-editor-icon.png` against `../../option-a/reference/light/editor-editor-icon.png`, diff `diff/light/editor-editor-icon.png`; dark likewise.

### editor-editor-auto-type: PASS


Images: light `app/light/editor-editor-auto-type.png` against `../../option-a/reference/light/editor-editor-auto-type.png`, diff `diff/light/editor-editor-auto-type.png`; dark likewise.

### editor-editor-browser: PASS


Images: light `app/light/editor-editor-browser.png` against `../../option-a/reference/light/editor-editor-browser.png`, diff `diff/light/editor-editor-browser.png`; dark likewise.

### editor-editor-ssh-agent: PASS

- The demo key's line and comment are data; the agent settings come with E9.
- Accepted (LD-192 (5)): card and data over the mockup where the rules above name them; LD-167 wordings.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/editor-editor-ssh-agent.png` against `../../option-a/reference/light/editor-editor-ssh-agent.png`, diff `diff/light/editor-editor-ssh-agent.png`; dark likewise.

### editor-editor-properties: PASS


Images: light `app/light/editor-editor-properties.png` against `../../option-a/reference/light/editor-editor-properties.png`, diff `diff/light/editor-editor-properties.png`; dark likewise.

### editor-editor-history: PASS

- The pill word "changed" stands in two rows and is matched to the first; both rows are drawn alike.
- Accepted (LD-192 (5)): card and data over the mockup where the rules above name them; LD-167 wordings.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- light: recorded shift (53 pt, LD-192 (5): MOD-03.11 lists the current entry and every item, one row more than drawn) applies to 1 boxes and 3 text runs; left after the shift, at most 104 pt.
- dark: recorded shift (53 pt, LD-192 (5): MOD-03.11 lists the current entry and every item, one row more than drawn) applies to 1 boxes and 3 text runs; left after the shift, at most 104 pt.

Images: light `app/light/editor-editor-history.png` against `../../option-a/reference/light/editor-editor-history.png`, diff `diff/light/editor-editor-history.png`; dark likewise.

### editor-new-entry: PASS


Images: light `app/light/editor-new-entry.png` against `../../option-a/reference/light/editor-new-entry.png`, diff `diff/light/editor-new-entry.png`; dark likewise.

## Contrast (check 7)

Token pairs that carry words, WCAG ratio, both themes: 42 pairs, lowest 4.87:1; under 4.5:1: none.

## Commands run

Run from the project root on 2026-10-28, in this order. No window was opened: Chrome ran headless, the app views rendered in borderless windows at x −20000 that were never ordered front, and the test process is not a hosted app.

1. `node design/option-a/tools/export-reference.mjs` (reference images and manifest from the current mockup)
   → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames` (5 min 23 s).
2. `npm install --prefix /tmp/parity-tools pixelmatch pngjs` → `added 2 packages`; versions pixelmatch 8.0.0, pngjs 7.0.0 (outside the project).
3. `scripts/build-core.sh` → `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`, exit 0.
4. `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath target/xcode test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` (the check.sh G2 test step)
   → `✔ Suite SnapshotTests passed`, `✔ Suite ParityLockTests passed`, `✔ Suite ParityMainTests passed`, `✔ Suite ParityStatesTests passed`, `✔ Suite ScreenTests passed`, `✔ Suite ParityFontTests passed`, `✔ Test run with 41 tests in 10 suites passed after 30.276 seconds`, `** TEST SUCCEEDED **`. SnapshotTests wrote app-shots/<theme>/<frame-id>.png and, new for this check, the accessibility tree next to each (`<frame-id>.ax.json`, test only). The Parity suites are new (test only, 27 tests): they press the mockup's controls through the accessibility tree. Log: target/parity/behaviour.log.
5. `swift format lint --strict macos/AppTests/*.swift` and `swiftlint lint --strict --quiet AppTests/` (in macos/) → no findings.
6. `node design/parity/tools/mockup-dom.mjs lock,main,states` (mockup boxes, text runs, fonts, glyphs, controls; headless) → `light: 21 frames, 2586 text runs`, `dark: 21 frames, 2586 text runs`.
7. `swift design/parity/tools/ocr.swift app-shots/light/*.png app-shots/dark/*.png` (on-device text recognition, only for strings kept out of the accessibility tree) → 36 images read.
8. `node design/parity/tools/compare.mjs <section>` (pixelmatch threshold 0.1, includeAA false; text, tokens, geometry, behaviour; writes this report).

Measured looks (LD-169): `ParityFontTests` (new, test only). "Font check" reads the large code's font runs from the accessibility tree and compares the drawn glyphs of the large code and a row code with the same string set by Core Text in IBM Plex Mono 500 and in the system face. "Focus check" renders the focused row offscreen in light and dark and reads the outline back. A probe in /tmp showed that the font runs in the tree name the requested font even where the glyphs drawn differ, so the glyph comparison is the deciding check.

E6-S1 re-run (Builder, 2026-10-28, sections lock, main and states; states-copied added): steps 1, 2 and 6 were not repeated (mockup.js and app.css are older than the reference images and target/parity/dom-*.json).
3. `scripts/build-core.sh` → `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift` (bindings with `copyField`, `clearClipboard`, `Copied`).
4. The check.sh G2 test step as above → `✔ Suite SnapshotTests passed`, `✔ Suite ParityStatesTests passed`, `✔ Test run with 45 tests in 10 suites passed after 32.980 seconds`, `** TEST SUCCEEDED **`. New: the states-copied snapshot and three "Parity states-copied" tests. The offscreen windows are now pinned to sRGB: on 2026-10-28 the Mac's screen gave Display P3 renders (accent #1b6c80 read as 53,107,126), which failed the Focus check and would shift every colour; the reference images are sRGB. Log: target/parity/behaviour.log.
7. `swift design/parity/tools/ocr.swift app-shots/light/*.png app-shots/dark/*.png` → 38 images read.
8. `node design/parity/tools/compare.mjs lock` → `lock: 4/4 PASS`; `node design/parity/tools/compare.mjs main` → `main: 2/2 PASS`; `node design/parity/tools/compare.mjs states` → `states: 13/13 PASS` (states-copied light 1.57 %, dark 1.6 %).

E6-S1 second pass (Builder, 2026-10-28, LD-181): app-ffi `copy_code` and `copy_fingerprint`; Copy One-Time Code (⌘T), the code row's Copy and Copy fingerprint work; the unlock form's shown password is an AppKit field whose own field editor has no Copy or Cut (APP-03.19).
3. `scripts/build-core.sh` → bindings with `copyCode` and `copyFingerprint`.
4. The check.sh G2 test step → `✔ Test run with 47 tests in 10 suites passed after 30.581 seconds`, `** TEST SUCCEEDED **`; general pasteboard change count 10124 before and after the run. Log: target/parity/behaviour.log.
7. OCR as above → 38 images read.
8. `node design/parity/tools/compare.mjs lock`, `main`, `states`: counts in each report's result line.

E6-S1 Checker fix (Builder, 2026-10-28): the shown password's editor matches the system's password editor (no writable pasteboard types, no single- or multi-type selection write, no Services send, no drag, no Writing Tools, no corrections, replacements or completion, a context menu of Paste, Delete, Select All only). Test moved to ShownPasswordFieldTests.swift with a plain text view as control.
4. The G2 test step with `-derivedDataPath /tmp/e6s1/dd` → `✔ Test run with 47 tests in 11 suites passed after 31.305 seconds`, `** TEST SUCCEEDED **`; general pasteboard change count 10124 before and after. Log: target/parity/behaviour.log.
8. `node design/parity/tools/compare.mjs lock` → result line of design/parity/lock/report.md.

This report: `node design/parity/tools/compare.mjs editor` printed:

```
editor: 9/9 PASS
editor-editor-entry                            PASS                   L 0.52% (0.4) D 0.53% (0.42)
editor-editor-advanced                         PASS                   L 0.92% (0.85) D 0.93% (0.87)
editor-editor-icon                             PASS                   L 0.65% (0.61) D 0.66% (0.62)
editor-editor-auto-type                        PASS                   L 0.94% (0.86) D 0.95% (0.87)
editor-editor-browser                          PASS                   L 0.45% (0.37) D 0.46% (0.39)
editor-editor-ssh-agent                        PASS                   L 0.95% (0.69) D 0.97% (0.71)
editor-editor-properties                       PASS                   L 0.52% (0.47) D 0.56% (0.51)
editor-editor-history                          PASS                   L 0.71% (0.63) D 0.72% (0.65)
editor-new-entry                               PASS                   L 0.52% (0.43) D 0.73% (0.66)
```

## Verify re-check for E5-S5 (2026-10-28, after the F-060, LD-207 and expiry fixes)

Run by the E5-S5 Verify agent in a private copy of the tree (`rsync -a --exclude target` at 13:45; deleted after the run). No window opened; attachment Open went to the test fake. Full proof: security/parity/E5-S5-editor.md, "Re-check".

1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`; manifest.json byte-identical to the shared one.
2. `scripts/build-core.sh` → `build-core (debug): …`, exit 0.
3. `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e5s5r/dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `✔ Test run with 127 tests in 21 suites passed after 72.895 seconds`; 75 `Parity …` tests passed, 0 failed (target/parity/behaviour.log).
4. `node design/parity/tools/mockup-dom.mjs editor,dialogs,states` → `light: 45 frames, 2903 text runs`, `dark: 45 frames, 2903 text runs`.
5. `swift design/parity/tools/ocr.swift app-shots/light/*.png app-shots/dark/*.png` (the split expression now in the shared tool) → 100 images read, exit 0.
6. `node design/parity/tools/compare.mjs editor` → `editor: 9/9 PASS (9 frames)`.
