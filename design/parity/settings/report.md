# Design parity: section `settings`

Date 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). Larsal: offscreen snapshots of SnapshotTests.

**Result: 7 of 7 built frames PASS** (7 frames in the section; 0 belong to later stories).

Check tools: pixelmatch 8.0.0, pngjs 7.0.0 (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |
|---|---|---|---|---|---|---|---|
| settings-settings-general | present | present | 0.68 % (0.43 %) / 0.69 % (0.45 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| settings-settings-security | present | present | 0.61 % (0.56 %) / 0.6 % (0.56 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| settings-settings-auto-type | present | present | 0.48 % (0.43 %) / 0.48 % (0.44 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| settings-settings-browser-integration | present | present | 0.33 % (0.28 %) / 0.33 % (0.29 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| settings-settings-ssh-agent | present | present | 0.32 % (0.27 %) / 0.33 % (0.28 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| settings-settings-shared-groups | present | present | 0.34 % (0.29 %) / 0.34 % (0.3 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| settings-settings-shortcuts | present | present | 0.36 % (0.31 %) / 0.37 % (0.33 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |

Token mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): 45 of 45 equal.

## Findings per frame

### settings-settings-general: PASS

- Built by E5-S9. Card words over the mockup: "Save changes as you make them" (LD-167, W-04), "once a week" (APP-01.19), "{FILE_NAME}.old.larsalvault" (APP-01.2). Check for updates and Include beta versions drawn and disabled until E14 (D-01-2: off, nothing is sent). Open Larsal at login goes through the LoginItem protocol (SMAppService; tests use a fake). Option A draws no OK or Cancel: closing the window is OK, Escape is Cancel (APP-01.3).
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/settings-settings-general.png` against `../../option-a/reference/light/settings-settings-general.png`, diff `diff/light/settings-settings-general.png`; dark likewise.

### settings-settings-security: PASS

- Built by E5-S9. Unlock with Touch ID (E6-S3) and the capture switch (APP-10, E6-S5, never stored) drawn and disabled. The stored values reach the copy countdown, the lock timers and the search timer (Verify driver).
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/settings-settings-security.png` against `../../option-a/reference/light/settings-settings-security.png`, diff `diff/light/settings-settings-security.png`; dark likewise.

### settings-settings-auto-type: PASS

- Built by E5-S9. Values stored under their APP-01 keys; Auto-Type reads them in E8; Change (the shortcut recorder) drawn and disabled. The mockup's row words stay until INT-05's mockup change (LD-167, D-INT05-12).
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/settings-settings-auto-type.png` against `../../option-a/reference/light/settings-settings-auto-type.png`, diff `diff/light/settings-settings-auto-type.png`; dark likewise.

### settings-settings-browser-integration: PASS

- Built by E5-S9. Every row follows "Let browsers use Larsal" (APP-01.5); the browser boxes write their setup files with E7 (INT-01.8), Safari waits for signing (INT-01.15). "Use my own proxy program" (LD-167) sits below the frame's fold, as the mockup's row does.
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/settings-settings-browser-integration.png` against `../../option-a/reference/light/settings-settings-browser-integration.png`, diff `diff/light/settings-settings-browser-integration.png`; dark likewise.

### settings-settings-ssh-agent: PASS

- Built by E5-S9. The status row is the frame's (a fake probe in tests; the user's agent is never asked). "Use a different socket" waits for W-05.
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/settings-settings-ssh-agent.png` against `../../option-a/reference/light/settings-settings-ssh-agent.png`, diff `diff/light/settings-settings-ssh-agent.png`; dark likewise.

### settings-settings-shared-groups: PASS

Since E11-S5 (2026-11-01, LD-310 (4)) the W-15 frame `w-15-larsal-settings` replaces this frame (option (b) signer rows, LD-270 (3)); its parity is in [../w-15/report.md](../w-15/report.md). This row records the 2026-10-28 run.

- Built by E5-S9. The identity is the frame's data; the key pair comes with E11 (D-01-6: Keychain, never in a settings file or export).
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/settings-settings-shared-groups.png` against `../../option-a/reference/light/settings-settings-shared-groups.png`, diff `diff/light/settings-settings-shared-groups.png`; dark likewise.

### settings-settings-shortcuts: PASS

- Built by E5-S9. "⌘⌫" (Delete Entry) is 4 pt wider than drawn, right edge equal, y within 0.5 pt: the bundled IBM Plex Sans 400 (the mockup's own file) has no ⌘, ⇧ or ⌫ glyph, so Chrome and Core Text each fall back to a system face; every ⌘ run is 1 to 1.5 pt wider for the same reason and ⌫ adds 2.5 pt. Read-only list (APP-01.29's shortcut dialog is not drawn).

Images: light `app/light/settings-settings-shortcuts.png` against `../../option-a/reference/light/settings-settings-shortcuts.png`, diff `diff/light/settings-settings-shortcuts.png`; dark likewise.

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

This report: `node design/parity/tools/compare.mjs settings` printed:

```
settings: 7/7 PASS
settings-settings-general                      PASS                   L 0.68% (0.43) D 0.69% (0.45)
settings-settings-security                     PASS                   L 0.61% (0.56) D 0.6% (0.56)
settings-settings-auto-type                    PASS                   L 0.48% (0.43) D 0.48% (0.44)
settings-settings-browser-integration          PASS                   L 0.33% (0.28) D 0.33% (0.29)
settings-settings-ssh-agent                    PASS                   L 0.32% (0.27) D 0.33% (0.28)
settings-settings-shared-groups                PASS                   L 0.34% (0.29) D 0.34% (0.3)
settings-settings-shortcuts                    PASS                   L 0.36% (0.31) D 0.37% (0.33)
```

## Verify E5-S9 run, round 2 (this section, 2026-10-28)

Verify agent for E5-S9, round 2; it did not build these screens. Everything ran in a private copy of the tree (`rsync -a --exclude target --exclude larsal-shots` to `/tmp/e5s9-verify2-copy` at 19:07, plus the shared `LarsalSettingsView.swift` of 19:13 synced in before the final render), with own build folders `/tmp/e5s9-verify2-dd` and `/tmp/e5s9-verify2-target`; the copy was deleted at the end. No window was opened: Chrome ran headless, the views rendered in borderless windows at x −20000 that were never ordered front. Full proof: [security/parity/E5-S9-settings.md](../../../security/parity/E5-S9-settings.md).

1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0. manifest.json is byte-equal to the shared one. Of the 14 settings PNGs, 10 are byte-equal; 4 (light security and shortcuts, dark general and shortcuts) differ by 1, 1, 20 and 22 raw pixels, with pixelmatch 0 changed pixels each. The shared reference is current.
2. `scripts/build-core.sh` → `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`, exit 0.
3. `xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s9-verify2-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `** TEST BUILD SUCCEEDED **`.
4. `xcodebuild … test-without-building -skip-testing:LarsalUITests` (SSH_AUTH_SOCK and TEST_RUNNER_SSH_AUTH_SOCK = a canary socket, TEST_RUNNER_HOME = an empty throwaway folder) → `Test run with 207 tests in 34 suites failed after 104.622 seconds with 12 issues`: 11 in `AccessibilityWalkTests` "AT-K06" (another story's new test, file changed in the shared tree at 19:06 and 19:15; its 16 screens are main-window screens, none of them settings) and 1 in the Verify driver (its own wrong file name, fixed). `LarsalSettingsEffectsTests`, `LarsalSettingsFrameTests`, `LarsalSettingsParityTests` and `LarsalSettingsTests` passed.
5. After the sync of `LarsalSettingsView.swift` (19:13, AT-K06 work: the nav's back and forward glyphs no longer hidden): build-for-testing → `** TEST BUILD SUCCEEDED **`; `-only-testing` of the 4 settings suites and the Verify driver → `✔ Test run with 25 tests in 5 suites passed after 10.992 seconds`. `LarsalSettingsFrameTests` wrote larsal-shots/<theme>/settings-settings-*.png and .ax.json again: 28 files, all byte-equal (`cmp`) to the shared larsal-shots.
6. `node design/parity/tools/mockup-dom.mjs settings` → `light: 7 frames, 215 text runs`, `dark: 7 frames, 215 text runs`.
7. `swift design/parity/tools/ocr.swift larsal-shots/light/settings-settings-*.png larsal-shots/dark/settings-settings-*.png` → 14 images read, exit 0.
8. `node design/parity/tools/compare.mjs settings` (behaviour.log = the logs of steps 4 and 5 and of the driver) → `settings: 7/7 PASS`, printed above. No change to notes.mjs: the round-1 Verify notes (3 card-word rules on settings-settings-general, the "⌘⌫" font-fallback run on settings-settings-shortcuts) still hold, and nothing else needed a note.

Text: 272 strings found per theme over the 7 frames, 0 missing, 3 accepted (the card words of settings-settings-general). Accessibility trees: 14, with 298 controls (174 buttons, 110 switches, 14 text fields), 0 without a name. Contrast: 42 pairs, lowest 4.87:1. By eye, app against reference for general (light) and ssh-agent (dark): same layout, type, tiles and switches; the only differences are the window buttons (drawn by the window) and the card words.
