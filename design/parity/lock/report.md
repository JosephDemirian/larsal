# Design parity: section `lock`

Date 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). App: offscreen snapshots of SnapshotTests.

**Result: 4 of 4 built frames PASS** (4 frames in the section; 0 belong to later stories).

Check tools: pixelmatch 8.0.0, pngjs 7.0.0 (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |
|---|---|---|---|---|---|---|---|
| lock-locked-touch-id | present | present | 0.53 % (0.11 %) / 0.51 % (0.09 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| lock-locked-password-key-file-security-key | present | present | 0.65 % (0.31 %) / 0.64 % (0.3 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| lock-locked-vault-switcher | present | present | 0.61 % (0.35 %) / 0.81 % (0.55 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| lock-welcome | present | present | 1.07 % (0.46 %) / 1.04 % (0.44 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |

Token mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): 45 of 45 equal.

## Findings per frame

### lock-locked-touch-id: PASS

- Accepted: "Unlock Personal" (APP-06 UL-TITLE) and "Use password instead" (APP-04.15), LD-163 (4); the footer reason comes with E6-S2 (LD-166, LD-169). Window buttons are drawn by macOS (accepted).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/lock-locked-touch-id.png` against `../../option-a/reference/light/lock-locked-touch-id.png`, diff `diff/light/lock-locked-touch-id.png`; dark likewise.

### lock-locked-password-key-file-security-key: PASS

- Accepted: "Unlock Personal", placeholder "Password", key file row in the card's words with the test's key file, security key row of E10 drawn disabled (LD-163 (2), (4)); footer reason with E6-S2; empty field after a failed unlock (APP-06.11, LD-166). The Yubico logo now carries its name.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/lock-locked-password-key-file-security-key.png` against `../../option-a/reference/light/lock-locked-password-key-file-security-key.png`, diff `diff/light/lock-locked-password-key-file-security-key.png`; dark likewise.

### lock-locked-vault-switcher: PASS

- Vault menu and its 9 items at 0 pt difference. With the menu open only the menu is in the tree; names behind it are found on the same view without the menu.
- Accepted as in the password frame; footer reason with E6-S2.
- Closing menus with Escape or a click outside: Mac QA on a real screen (LD-166).

Images: light `app/light/lock-locked-vault-switcher.png` against `../../option-a/reference/light/lock-locked-vault-switcher.png`, diff `diff/light/lock-locked-vault-switcher.png`; dark likewise.

### lock-welcome: PASS

- Accepted: license line with the live version (LD-163 (5)). Recent paths are live.
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/lock-welcome.png` against `../../option-a/reference/light/lock-welcome.png`, diff `diff/light/lock-welcome.png`; dark likewise.

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

This report: `node design/parity/tools/compare.mjs lock` printed:

```
lock: 4/4 PASS
lock-locked-touch-id                           PASS                   L 0.53% (0.11) D 0.51% (0.09)
lock-locked-password-key-file-security-key     PASS                   L 0.65% (0.31) D 0.64% (0.3)
lock-locked-vault-switcher                     PASS                   L 0.61% (0.35) D 0.81% (0.55)
lock-welcome                                   PASS                   L 1.07% (0.46) D 1.04% (0.44)
```
