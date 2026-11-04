# Design parity: section `states`

Date 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). App: offscreen snapshots of SnapshotTests.

**Result: 15 of 15 built frames PASS** (15 frames in the section; 0 belong to later stories).

Check tools: pixelmatch 8.0.0, pngjs 7.0.0 (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |
|---|---|---|---|---|---|---|---|
| states-needs-attention | present | present | 1.69 % (1.48 %) / 1.92 % (1.71 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-card | present | present | 0.57 % (0.4 %) / 0.84 % (0.67 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-server-with-ssh-key | present | present | 1.21 % (0.77 %) / 1.37 % (0.85 %) | 0 | 1 / 1 | 0 + 0 / 0 + 0 | PASS |
| states-wi-fi | present | present | 0.6 % (0.46 %) / 0.62 % (0.48 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-favorites-tags-open | present | present | 1.06 % (0.7 %) / 1.09 % (0.73 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-search-tips | present | present | 1.53 % (0.96 %) / 1.52 % (0.97 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-search-with-no-result | present | present | 0.42 % (0.37 %) / 0.42 % (0.38 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-more-menu | present | present | 1.3 % (0.89 %) / 1.31 % (0.9 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-vault-switcher | present | present | 1.39 % (0.93 %) / 1.43 % (0.96 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-sort-menu | present | present | 1.3 % (0.89 %) / 1.33 % (0.92 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-recycle-bin | present | present | 0.58 % (0.44 %) / 0.6 % (0.46 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-copied | present | present | 1.55 % (1.04 %) / 1.57 % (1.08 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-unsaved-changes | present | present | 1.35 % (0.85 %) / 1.38 % (0.89 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-delete-as-a-sheet | present | present | 1.6 % (1.42 %) / 1.33 % (1.16 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| states-new-empty-vault | present | present | 0.24 % (0.19 %) / 0.24 % (0.19 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |

Token mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): 45 of 45 equal.

## Findings per frame

### states-needs-attention: PASS

- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Accepted: the 7th entry heads the list, so the mockup's rows sit 91 pt lower (LD-163 (4), LD-166; rows not judged); the card's reason text and level (LD-169). The reason wraps to two lines (35.5 pt against one line of 17), so the actions and fields below move 17.5 pt; after that shift every box and text run there is within 0.6 pt.
- The Slack letter tile "S" is drawn but kept out of the tree like every letter tile; text recognition missed the single letter, the crop shows it (proof/slack-tile-light.png, proof/slack-tile-dark.png); "A" of the same tile code was read.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- light: recorded shift (17.5 pt, LD-169: the card's reason text wraps one more line) applies to 3 boxes and 7 text runs; left after the shift, at most 0.6 pt.
- dark: recorded shift (17.5 pt, LD-169: the card's reason text wraps one more line) applies to 3 boxes and 7 text runs; left after the shift, at most 0.6 pt.

Images: light `app/light/states-needs-attention.png` against `../../option-a/reference/light/states-needs-attention.png`, diff `diff/light/states-needs-attention.png`; dark likewise.

### states-card: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.355 to the system face; 14.0 pt code: ink distance 0.082 to IBM Plex Mono 500 against 0.307 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Accepted: card number in dots only (rule 4), levels and count from the card; Visa Debit has a letter tile (logos by URL host only).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/states-card.png` against `../../option-a/reference/light/states-card.png`, diff `diff/light/states-card.png`; dark likewise.

### states-server-with-ssh-key: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.355 to the system face; 14.0 pt code: ink distance 0.082 to IBM Plex Mono 500 against 0.307 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Accepted (LD-169): the card's estimator rates the passphrase Weak, so the attention notice appears (the extra --neg-bg area); the SSH agent row ("Loaded", "Removed when the vault locks") comes with E9. Fields between the notice and the agent row move 77.5 pt, fields after it 16.5 pt (77.5 − the mockup's 61 pt agent row); after those shifts every box and text run is within 0.6 pt. Header and buttons are within 2 pt.
- The fingerprint is computed from the demo key (format only, LD-166).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.
- light: recorded shift (77.5 pt, LD-169: the card's Weak notice (66 pt block and its 11.5 pt gap); 16.5 pt, LD-169: the notice minus the E9 SSH agent row (77.5 − 61)) applies to 4 boxes and 10 text runs; left after the shift, at most 0.5 pt.
- dark: recorded shift (77.5 pt, LD-169: the card's Weak notice (66 pt block and its 11.5 pt gap); 16.5 pt, LD-169: the notice minus the E9 SSH agent row (77.5 − 61)) applies to 4 boxes and 10 text runs; left after the shift, at most 0.5 pt.

Images: light `app/light/states-server-with-ssh-key.png` against `../../option-a/reference/light/states-server-with-ssh-key.png`, diff `diff/light/states-server-with-ssh-key.png`; dark likewise.

### states-wi-fi: PASS

- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Levels from the card.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/states-wi-fi.png` against `../../option-a/reference/light/states-wi-fi.png`, diff `diff/light/states-wi-fi.png`; dark likewise.

### states-favorites-tags-open: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.355 to the system face; 14.0 pt code: ink distance 0.082 to IBM Plex Mono 500 against 0.307 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Tags open with the five tags; levels from the card.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/states-favorites-tags-open.png` against `../../option-a/reference/light/states-favorites-tags-open.png`, diff `diff/light/states-favorites-tags-open.png`; dark likewise.

### states-search-tips: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.355 to the system face; 14.0 pt code: ink distance 0.082 to IBM Plex Mono 500 against 0.307 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- All seven tips with their words (is:weak wording from FEA-01.17, accepted).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/states-search-tips.png` against `../../option-a/reference/light/states-search-tips.png`, diff `diff/light/states-search-tips.png`; dark likewise.

### states-search-with-no-result: PASS

- The empty result keeps its frame and the one-line message.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/states-search-with-no-result.png` against `../../option-a/reference/light/states-search-with-no-result.png`, diff `diff/light/states-search-with-no-result.png`; dark likewise.

### states-more-menu: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.355 to the system face; 14.0 pt code: ink distance 0.082 to IBM Plex Mono 500 against 0.307 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Menu and its 11 items within 2 pt; items of later stories disabled with the reason. Strings behind the menu are found on main-main-window-light.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Closing menus with Escape or a click outside: Mac QA on a real screen (LD-166).

Images: light `app/light/states-more-menu.png` against `../../option-a/reference/light/states-more-menu.png`, diff `diff/light/states-more-menu.png`; dark likewise.

### states-vault-switcher: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.355 to the system face; 14.0 pt code: ink distance 0.082 to IBM Plex Mono 500 against 0.307 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Menu and items within 2 pt; Lock Personal and Work act (tests).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Closing menus with Escape or a click outside: Mac QA on a real screen (LD-166).

Images: light `app/light/states-vault-switcher.png` against `../../option-a/reference/light/states-vault-switcher.png`, diff `diff/light/states-vault-switcher.png`; dark likewise.

### states-sort-menu: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.355 to the system face; 14.0 pt code: ink distance 0.082 to IBM Plex Mono 500 against 0.307 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Sort menu within 2 pt; Title and the order marked. The header's "Title" button lies under the open menu and is not compared.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Closing menus with Escape or a click outside: Mac QA on a real screen (LD-166).

Images: light `app/light/states-sort-menu.png` against `../../option-a/reference/light/states-sort-menu.png`, diff `diff/light/states-sort-menu.png`; dark likewise.

### states-recycle-bin: PASS

- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Restore, Delete forever and Empty Recycle Bin drawn and disabled (E5-S10). The X logo now carries its name.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/states-recycle-bin.png` against `../../option-a/reference/light/states-recycle-bin.png`, diff `diff/light/states-recycle-bin.png`; dark likewise.

### states-copied: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.355 to the system face; 14.0 pt code: ink distance 0.082 to IBM Plex Mono 500 against 0.307 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Built by E6-S1. Copy password (rail, field button, entry menu, ⌘C) copies in Rust; the value never reaches the screen layer. Known difference, card over mockup: APP-03.21 "Password copied. Clears in 10 s." for the mockup's "Password copied · clipboard clears in 30 s" (10 s is App's clear delay); the box is narrower for the shorter words (about 245 against 301 pt, centred on the same x); its place (centred, 20 above the foot), height 40, radius 10, --primary fill, ink, glyph and shadow are as drawn. The notice goes after 2.6 s, as in the mockup.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/states-copied.png` against `../../option-a/reference/light/states-copied.png`, diff `diff/light/states-copied.png`; dark likewise.

### states-unsaved-changes: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.355 to the system face; 14.0 pt code: ink distance 0.082 to IBM Plex Mono 500 against 0.307 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).

Images: light `app/light/states-unsaved-changes.png` against `../../option-a/reference/light/states-unsaved-changes.png`, diff `diff/light/states-unsaved-changes.png`; dark likewise.

### states-delete-as-a-sheet: PASS

- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- With the sheet open only the sheet is in the tree; names behind it are found on the same view without it (states-needs-attention).
- Accepted (LD-192 (5)): card and data over the mockup where the rules above name them; LD-167 wordings.

Images: light `app/light/states-delete-as-a-sheet.png` against `../../option-a/reference/light/states-delete-as-a-sheet.png`, diff `diff/light/states-delete-as-a-sheet.png`; dark likewise.

### states-new-empty-vault: PASS

- The three first steps drawn and disabled until their stories. Save line: live (the demo file has a save time).
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/states-new-empty-vault.png` against `../../option-a/reference/light/states-new-empty-vault.png`, diff `diff/light/states-new-empty-vault.png`; dark likewise.

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

This report: `node design/parity/tools/compare.mjs states` printed:

```
states: 15/15 PASS
states-needs-attention                         PASS                   L 1.69% (1.48) D 1.92% (1.71)
states-card                                    PASS                   L 0.57% (0.4) D 0.84% (0.67)
states-server-with-ssh-key                     PASS                   L 1.21% (0.77) D 1.37% (0.85)
states-wi-fi                                   PASS                   L 0.6% (0.46) D 0.62% (0.48)
states-favorites-tags-open                     PASS                   L 1.06% (0.7) D 1.09% (0.73)
states-search-tips                             PASS                   L 1.53% (0.96) D 1.52% (0.97)
states-search-with-no-result                   PASS                   L 0.42% (0.37) D 0.42% (0.38)
states-more-menu                               PASS                   L 1.3% (0.89) D 1.31% (0.9)
states-vault-switcher                          PASS                   L 1.39% (0.93) D 1.43% (0.96)
states-sort-menu                               PASS                   L 1.3% (0.89) D 1.33% (0.92)
states-recycle-bin                             PASS                   L 0.58% (0.44) D 0.6% (0.46)
states-copied                                  PASS                   L 1.55% (1.04) D 1.57% (1.08)
states-unsaved-changes                         PASS                   L 1.35% (0.85) D 1.38% (0.89)
states-delete-as-a-sheet                       PASS                   L 1.6% (1.42) D 1.33% (1.16)
states-new-empty-vault                         PASS                   L 0.24% (0.19) D 0.24% (0.19)
```
