# Design parity: section `generator`

Date 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). Larsal: offscreen snapshots of SnapshotTests.

**Result: 3 of 3 built frames PASS** (3 frames in the section; 0 belong to later stories).

Check tools: pixelmatch 8.0.0, pngjs 7.0.0 (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |
|---|---|---|---|---|---|---|---|
| generator-generator-in-the-window | present | present | 1.28 % (0.75 %) / 1.28 % (0.77 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| generator-password | present | present | 1.08 % (0.56 %) / 0.98 % (0.48 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| generator-passphrase | present | present | 1.53 % (0.38 %) / 1.39 % (0.25 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |

Token mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): 45 of 45 equal.

## Findings per frame

### generator-generator-in-the-window: PASS

- Font check passed: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; 28.0 pt code: ink distance 0.016 to IBM Plex Mono 500 against 0.402 to the system face; 14.0 pt code: ink distance 0.084 to IBM Plex Mono 500 against 0.285 to the system face.
- Focus check passed: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).
- Built by E5-S6. The value and its bits are live (format only). The strength word is FEA-05.4's level of the live value (passphrase: FEA-03.7's 64.62 bits for 5 words is Weak, the mockup draws Strong; LD-163 (4)); the bar is coloured by that level (FEA-05.5) on the mockup's 130-bit scale. The popover sits under the toolbar button (top 118, right 166) over the main window; Generator, ⌥⌘G, a click outside and Escape close it; the value goes on close and lock (D-02-5).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/generator-generator-in-the-window.png` against `../../option-a/reference/light/generator-generator-in-the-window.png`, diff `diff/light/generator-generator-in-the-window.png`; dark likewise.

### generator-password: PASS

- Built by E5-S6. The value and its bits are live (format only). The strength word is FEA-05.4's level of the live value (passphrase: FEA-03.7's 64.62 bits for 5 words is Weak, the mockup draws Strong; LD-163 (4)); the bar is coloured by that level (FEA-05.5) on the mockup's 130-bit scale. The popover alone, 404 × 340.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/generator-password.png` against `../../option-a/reference/light/generator-password.png`, diff `diff/light/generator-password.png`; dark likewise.

### generator-passphrase: PASS

- Built by E5-S6. The value and its bits are live (format only). The strength word is FEA-05.4's level of the live value (passphrase: FEA-03.7's 64.62 bits for 5 words is Weak, the mockup draws Strong; LD-163 (4)); the bar is coloured by that level (FEA-05.5) on the mockup's 130-bit scale. The popover alone, 404 × 368; the snapshot keeps a phrase that takes two lines, as drawn.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/generator-passphrase.png` against `../../option-a/reference/light/generator-passphrase.png`, diff `diff/light/generator-passphrase.png`; dark likewise.

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

This report: `node design/parity/tools/compare.mjs generator` printed:

```
generator: 3/3 PASS
generator-generator-in-the-window              PASS                   L 1.28% (0.75) D 1.28% (0.77)
generator-password                             PASS                   L 1.08% (0.56) D 0.98% (0.48)
generator-passphrase                           PASS                   L 1.53% (0.38) D 1.39% (0.25)
```

## Verify run for E5-S6 (Verify agent, 2026-10-28)

The Verify agent re-ran this section from scratch. It did not build these screens. It worked in a private copy of the tree (`rsync -a --exclude /target --exclude /fuzz/target` to /tmp/e5s6v-copy at 12:48, `target` linked to /tmp/e5s6v-target, `-derivedDataPath /tmp/e5s6v-dd`). The copy was deleted afterwards. The generator code it checked (`crates/larsal-ffi/src/generator.rs`, `session.rs`, `larsal-core/src/generator/mod.rs`, `macos/Larsal/Generator.swift`, `GeneratorPanel.swift`) has the same bytes as the shared tree at 13:11 (checked with `cmp`). No window was opened: Chrome ran headless and the snapshots rendered offscreen.

1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0, 51 s.
   - The manifest is byte-equal to the tree's.
   - generator-password and generator-passphrase are byte-equal to the tree's, light and dark.
   - generator-generator-in-the-window differs in 13 pixels of 4,329,600, with pixelmatch 0 (0.000 %). That is font rasterisation noise.
2. `scripts/build-core.sh` → `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`, 56 s.
3. `node design/parity/tools/mockup-dom.mjs generator` → `light: 3 frames, 280 text runs`, `dark: 3 frames, 280 text runs`.
4. `xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s6v-dd test -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES > target/parity/behaviour.log` → `✔ Suite GeneratorSnapshotTests passed`, `✔ Suite ParityGeneratorTests passed`, `✔ Test run with 110 tests in 18 suites passed after 73.104 seconds`, `** TEST SUCCEEDED **`.
   - The first try stopped on a compile error in ParityEditorPagesTests.swift:316, which was unfinished E5-S5 work. The fixed file from the tree was copied in, and the run then passed.
5. Final generator run: `xcodebuild … test -only-testing:LarsalTests/GeneratorSnapshotTests -only-testing:LarsalTests/ParityGeneratorTests -only-testing:LarsalTests/VerifyE5S6Tests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `✔ Test run with 13 tests in 3 suites passed`, `** TEST SUCCEEDED **`. The general pasteboard change count was 10145 before and 10145 after. This run wrote the snapshots checked here.
6. `swift design/parity/tools/ocr.swift larsal-shots/light/generator-*.png larsal-shots/dark/generator-*.png` → 6 images read.
7. `node design/parity/tools/compare.mjs generator` → the result printed above: 3/3 PASS. Static tokens 45 of 45. Contrast: 42 pairs, lowest 4.87:1.

Checked by eye on the images:

- **Accepted differences.**
  - Passphrase: "Weak" in the warning colour where the mockup draws "Strong". The card rules here: FEA-03.7 gives 64.62 bits for 5 words, and FEA-05.4 makes that Weak (LD-163 (4), LD-204).
  - Window frame: the window buttons, the live codes, and the counts by the card rules (as in section main).
- **Text runs.** Every other text run is in place.
- **Two small rendering differences**, both inside the pixel limit:
  - The check box tick: the app draws Phosphor `check` at 12 pt; the mockup draws a 2-px CSS tick. This is the shared CheckMark, the same in other sections.
  - White text on the primary button looks slightly heavier: Core Text against Chrome rasterisation, at the same weight 500.
- **Extra accessibility strings.** "Generated password" names the output field, "on" is the look-alikes value, and "closed" comes from the window behind the popover. These are VoiceOver names that the mockup lacks; they are not drawn.

Behaviour (check 6) is the `Parity generator-…` rows above, plus VerifyE5S6Tests, which ran only in the copy:

- Saving on Use, and not on closing a popup (FEA-02.18).
- The tab and word count come back (FEA-03.15).
- Copy markers, the LD-181 notice, the popover staying open, and the clear after 10 s (FEA-02.20).
- The strength line shows the level and bits that Rust rated.

Full proof: security/parity/E5-S6-generator.md.
