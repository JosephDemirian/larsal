# Design parity: section `reports`

Date 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). App: offscreen snapshots of SnapshotTests.

**Result: 5 of 5 built frames PASS** (5 frames in the section; 0 belong to later stories).

Check tools: pixelmatch 8.0.0, pngjs 7.0.0 (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |
|---|---|---|---|---|---|---|---|
| reports-reports-health-check | present | present | 1.78 % (1.3 %) / 1.92 % (1.39 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| reports-reports-breach-check | present | present | 1.49 % (1.46 %) / 1.54 % (1.51 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| reports-reports-statistics | present | present | 0.78 % (0.64 %) / 0.82 % (0.67 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| reports-reports-passkeys | present | present | 0.7 % (0.64 %) / 0.73 % (0.66 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| reports-reports-browser | present | present | 0.59 % (0.52 %) / 0.69 % (0.62 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |

Token mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): 45 of 45 equal.

## Findings per frame

### reports-reports-health-check: PASS

- Built by E5-S7. Card over mockup (LD-208, LD-163 (4)): 7 rows by the card rules, sorted by health score (FEA-05.16), so Zalando (score 0) leads and the Amazon and eBay rows sit one row (57.5 pt) lower, x equal; pill words are FEA-05.4 levels, reasons FEA-05.6, FEA-05.13, FEA-05.14; the Weak KPI says "under 75 bits" (FEA-05.4) and the footer counts 14 (21 − 7). The letter tiles "A" and "S" are drawn and kept out of the tree (proof/amazon-tile-<theme>.png, proof/slack-tile-<theme>.png).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/reports-reports-health-check.png` against `../../option-a/reference/light/reports-reports-health-check.png`, diff `diff/light/reports-reports-health-check.png`; dark likewise.

### reports-reports-breach-check: PASS

- Built by E5-S7. The frame's results are set as the screen state (the online check itself runs in Rust tests against a fake service; nothing leaves this Mac). Card over mockup: FEA-06.9 exposure bands in the Seen column, the count in its help; "Check with a downloaded list instead" drawn and disabled (the offline check is the command line tool, FEA-06.14). Before a press the page shows the consent text (FEA-06.1, LD-208 (4), W-12).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/reports-reports-breach-check.png` against `../../option-a/reference/light/reports-reports-breach-check.png`, diff `diff/light/reports-reports-breach-check.png`; dark likewise.

### reports-reports-statistics: PASS

- Built by E5-S7. Live values of the demo copy: size, key derivation (1 MiB, 2 iterations), 3 attachments. Card over mockup: Groups 8 counts the root (FEA-07.2), average length a whole number (FEA-07.12). The FEA-07 rows the frame lacks wait for W-12 (LD-208 (5)).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/reports-reports-statistics.png` against `../../option-a/reference/light/reports-reports-statistics.png`, diff `diff/light/reports-reports-statistics.png`; dark likewise.

### reports-reports-passkeys: PASS

- Built by E5-S7. Card over mockup: rows sorted by title (INT-04.52), so GitHub and Apple Account, Mastodon and Linear change places; each moved text run sits exactly one row (58 to 60 pt) up or down with x within 1 pt. "Added" is the entry's last change (LD-208 (6)).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/reports-reports-passkeys.png` against `../../option-a/reference/light/reports-reports-passkeys.png`, diff `diff/light/reports-reports-passkeys.png`; dark likewise.

### reports-reports-browser: PASS

- Built by E5-S7. Card over mockup: rows in title order (INT-02.32), so Amazon leads and the runs move one row (58 to 59.5 pt), x equal; GitHub's hosts are sorted (gist.github.com before github.com), the card names no order. The "A" tile is drawn (proof/amazon-browser-tile-<theme>.png).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/reports-reports-browser.png` against `../../option-a/reference/light/reports-reports-browser.png`, diff `diff/light/reports-reports-browser.png`; dark likewise.

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

This report: `node design/parity/tools/compare.mjs reports` printed:

```
reports: 5/5 PASS
reports-reports-health-check                   PASS                   L 1.78% (1.3) D 1.92% (1.39)
reports-reports-breach-check                   PASS                   L 1.49% (1.46) D 1.54% (1.51)
reports-reports-statistics                     PASS                   L 0.78% (0.64) D 0.82% (0.67)
reports-reports-passkeys                       PASS                   L 0.7% (0.64) D 0.73% (0.66)
reports-reports-browser                        PASS                   L 0.59% (0.52) D 0.69% (0.62)
```

## Verify run for E5-S7, round 1 (Verify agent, 2026-10-28; history)

The Verify agent ran this section from scratch. It did not build these screens. It worked in a private copy of the tree (`rsync -a --exclude /target --exclude /fuzz/target --exclude .build --exclude node_modules --exclude /app-shots` to /tmp/e5s7-verify-copy at 14:47, `target` linked to /tmp/e5s7-verify-target, `-derivedDataPath /tmp/e5s7-verify-dd`); the copy was deleted afterwards. The E5-S7 code it checked has the same bytes as the shared tree at 15:08 (`cmp`: reports.rs, views.rs, session.rs, tests/reports.rs, app-core breach.rs and tests/fea06.rs, ReportsModel, ReportsView, ReportTabs, ReportParts, VaultModel, VaultEdits, ReportsTests). No window was opened: Chrome ran headless, the snapshots rendered offscreen in borderless windows at x −20000 that were never ordered front.

1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0, 46 s. The manifest and 8 of the 10 reports images are byte-equal to the tree's; light browser (97 bytes) and dark breach-check (8 bytes) differ with pixelmatch 0 (0.000 %), font rasterisation noise.
2. `scripts/build-core.sh` → `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`, exit 0, 1 min 30 s.
3. `node design/parity/tools/mockup-dom.mjs reports` → `light: 5 frames, 419 text runs`, `dark: 5 frames, 419 text runs`.
4. `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e5s7-verify-dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES > target/parity/behaviour.log` → `✔ Test run with 161 tests in 28 suites passed after 126.513 seconds`, `** TEST SUCCEEDED **` (159 tests of the tree plus 2 Verify tests that lived only in the copy; a third Verify test ran later on its own: `-only-testing:AppTests/VerifyE5S7Tests` → `✔ Test run with 3 tests in 1 suite passed`). `✔ Test "Option A reports frame, offscreen, light and dark" with 5 test cases passed` wrote app-shots/{light,dark}/reports-reports-*.png and .ax.json.
5. `swift design/parity/tools/ocr.swift app-shots/light/reports-*.png app-shots/dark/reports-*.png` → 10 images read.
6. `node design/parity/tools/compare.mjs reports` → first `reports: 1/5 PASS` (breach); the four FAILs were card words, live values of the demo copy, the card's row orders, rows read together, and letter tiles out of the tree. Each was checked against its card (below) and written into notes.mjs as a rule limited to its frame (an accepted string still needs the app's counterpart on screen). Second run → the result printed above: 5/5 PASS. Static tokens 45 of 45. Contrast: 42 pairs, lowest 4.87:1.
7. `scripts/check-names.sh` then failed on findings.json and report.html: the informational "extra strings" list held runs that compare.mjs joins for reading ("Oct 21" + "password"), and such a join spelled a banned product name. compare.mjs now leaves joined runs out of that list (one condition, `s.field !== 'line'`; verdicts never read the list). Rerun: `reports: 5/5 PASS`, the same numbers, report.md unchanged; `names: PASS (3035 files scanned)`.

Checked by eye on the images and against the cards:

- **Health check.** 7 rows by FEA-05.15 (mockup 6; the count rule of LD-163 (4)), sorted by health score lowest first (FEA-05.16): Zalando (expired, score 0) leads, so the Amazon and eBay runs sit 57.5 pt lower with x equal. Pills are FEA-05.4 levels (Poor, Weak), reasons FEA-05.6 "Very easy to guess" / "Somewhat easy to guess", FEA-05.13 "Same password on 2 entries", FEA-05.14 "Past its expiry date". KPI Weak "under 75 bits" (FEA-05.4: below Good is a score up to 74). Footer 14 = 21 − 7. Bits are the card estimator's (FEA-05.1 passes the entry's title, user name and host, so admin1234 with user name "admin" rates 11 bits). Letter tiles A and S drawn: proof/amazon-tile-<theme>.png, proof/slack-tile-<theme>.png.
- **Breach check.** PASS as measured. The exposure column shows FEA-06.9's bands ("Seen 100,001 to 1,000,000 times"), the exact count is the help text. "Check with a downloaded list instead" is drawn and disabled with the reason (the offline check is `app analyze`). The four rows are the frame's, set as screen state; the same four come out of the Rust check with the fake service (security/parity/E5-S7-reports.md).
- **Statistics.** Live values of the demo copy: 9.7 KB, AES-256 · Argon2id, 1 MiB, 2 iterations (the demo file's fast settings, APP-07 M07-07 words), 3 attachments · 1.7 KB (the demo vault holds 3 in live entries, measured). Groups 8 counts the root (FEA-07.2; mockup 7). Average 19 characters: FEA-07.12 rounds to a whole number (mockup 18.6). Length and age bars equal the mockup's (3, 3, 9, 6; 9, 11, 1).
- **Passkeys.** Rows by title (INT-04.52): Apple Account, GitHub, Linear, Mastodon; every moved run is exactly one row (58 to 60 pt) up or down, x within 1 pt. "Added" is the last change (LD-208 (6)).
- **Browser.** Rows in title order (INT-02.32): Amazon, Figma, GitHub, Google; runs move one row, x equal. GitHub's hosts are sorted (gist.github.com, github.com), as the editor's site access list (E5-S5); the mockup lists them in stored order and the card names no order. Small, written here for the lead. Letter tile A: proof/amazon-browser-tile-<theme>.png.
- **Window frame.** The window buttons are drawn by macOS and masked, as in every section; the remaining changed pixels are glyph edges (Core Text against Chrome) under 2 % in every frame.

Behaviour (check 6): the `Parity reports-…` rows plus `FEA-06.12, AT-E07: a lock closes the reports and drops every report`, `FEA-05.18: Skip in Reports…`, `LD-137, LD-139: an is:weak search runs again…` and three Verify tests run only in the copy (`enter()` fills the cache off the screen thread and re-runs a typed is:weak; a lock right after Reports opens drops it and nothing fills later; a lock while the reports wait drops them). All passed.

Accessibility (check 7): no control without a name in any frame (compare `unnamed` 0); every report control is a button or row in the tree with its name ("Change password of Router admin", "Remove the passkey of Linear", "More"); contrast lowest 4.87:1; no row list with the list focus outline in this section. Keyboard focus ring and Tab order on a real key window: needs Mac QA (owner's go), as for every section (LD-169).

Story verdict: the parity section passes 5/5; story E5-S7 is not signed for another reason (the rating fill holds the session lock, security/parity/E5-S7-reports.md, Fail 1).

## Verify run for E5-S7, round 2 (Verify agent, 2026-10-28)

A second Verify agent ran this section again after the Builder's round-2 fix (the rating runs outside the session lock; no Swift or frame change). It did not build or check this story before. It worked in a private copy (`rsync -a --exclude /target --exclude /fuzz/target --exclude .build --exclude node_modules --exclude /app-shots` to /tmp/e5s7-verify2-copy at 15:48, `target` linked to /tmp/e5s7-verify2-target, `-derivedDataPath /tmp/e5s7-verify2-dd`); the copy and the build folders were deleted afterwards. At the end `cmp` showed the copy's E5-S7 files equal to the shared tree (views.rs, reports.rs, session.rs, lib.rs, tests/reports.rs, app-core breach.rs and health.rs, ReportsModel, ReportsView, ReportTabs, ReportParts, VaultModel, ReportsTests). No window was opened: Chrome ran headless, the snapshots rendered offscreen, the general pasteboard was not touched.

1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0, 3 min 9 s. The manifest and all 10 reports images are byte-equal to the tree's.
2. `scripts/build-core.sh` → `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`. The `rate`, `ratingProgress` and `searchWaitsForRatings` bindings are line-for-line the same as the tree's (`rate(vault: UInt64, max: UInt32, utcOffset: Int32) throws -> Bool`): no API change.
3. `node design/parity/tools/mockup-dom.mjs reports` → `light: 5 frames, 419 text runs`, `dark: 5 frames, 419 text runs`.
4. `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e5s7-verify2-dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES > target/parity/behaviour.log` → `✔ Test "Option A reports frame, offscreen, light and dark" with 5 test cases passed after 48.316 seconds.`, `✔ Test run with 166 tests in 29 suites passed after 88.420 seconds.`, `** TEST SUCCEEDED **` (the tree's 164 tests plus 2 Verify tests that lived only in the copy). The first try stopped at compile time on my own test file (a wrong `import`); fixed in the copy and run again.
5. `swift design/parity/tools/ocr.swift app-shots/light/reports-*.png app-shots/dark/reports-*.png` → 10 images read.
6. `node design/parity/tools/compare.mjs reports` → the result printed above, `reports: 5/5 PASS`, with the same numbers as round 1. findings.json and report.html are byte-equal to round 1's, and the 10 app images are byte-equal too. Static tokens 45 of 45. Contrast: 42 pairs, lowest 4.87:1. Unnamed controls 0 in every frame and theme.

Checked by eye: the diff images show only the accepted card-over-mockup areas of round 1 (health rows by FEA-05.15/16, the FEA-05.4 pills and reasons, the FEA-06.9 exposure bands, the card counts) plus glyph edges and the masked window buttons.

Behaviour (check 6), in the full run: the six `Parity reports-…` tests, `FEA-06.12, AT-E07: a lock closes the reports and drops every report`, `FEA-05.18: Skip in Reports…`, `LD-137, LD-139: an is:weak search runs again once the ratings are in`, and the two copy-only tests `Verify E5-S7 r2: enter() fills the cache off the screen thread and re-runs a typed is:weak` and `Verify E5-S7 r2: a lock while the fill and the reports work drops them; nothing fills later`. All passed. Run on their own (`test-without-building -only-testing:AppTests/ReportsTests -only-testing:AppTests/VerifyE5S7R2Tests`, `✔ Test run with 13 tests in 2 suites passed`): `VERIFY r2 Swift enter(): notice gone after 0.32 s … worst list() 0.000149 s; progress 21 of 21; weak 6, shown 6`.

Accessibility (check 7): as round 1. No unnamed control, contrast lowest 4.87:1. Keyboard focus ring and Tab order on a real key window need Mac QA (owner's go), as in every section (LD-169).

Story verdict: the section passes 5/5 in light and dark, and E5-S7 is signed. Proof: security/parity/E5-S7-reports.md.
