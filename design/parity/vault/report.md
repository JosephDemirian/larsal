# Design parity: section `vault`

Date 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). App: offscreen snapshots of SnapshotTests.

**Result: 8 of 8 built frames PASS** (8 frames in the section; 0 belong to later stories).

Check tools: pixelmatch 8.0.0, pngjs 7.0.0 (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |
|---|---|---|---|---|---|---|---|
| vault-new-vault-step-1 | present | present | 2.13 % (1.83 %) / 2.83 % (2.53 %) | 0 | 1 / 1 | 0 + 0 / 0 + 0 | PASS |
| vault-new-vault-step-2 | present | present | 2.63 % (1.2 %) / 7.07 % (1.24 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| vault-new-vault-step-3 | present | present | 2.36 % (1.16 %) / 3.24 % (2.02 %) | 0 | 1 / 1 | 0 + 0 / 0 + 0 | PASS |
| vault-vault-settings-general | present | present | 1.89 % (1.69 %) / 1.89 % (1.69 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| vault-vault-settings-security | present | present | 1.77 % (1.61 %) / 1.76 % (1.61 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| vault-vault-settings-recycle-bin | present | present | 0.68 % (0.63 %) / 0.66 % (0.62 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| vault-vault-settings-history | present | present | 0.95 % (0.85 %) / 0.93 % (0.84 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| vault-vault-settings-browser-keys | present | present | 1.08 % (0.9 %) / 1.07 % (0.9 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |

Token mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): 45 of 45 equal.

## Findings per frame

### vault-new-vault-step-1: PASS

- Built by E5-S8. The Name field has the focus with "Family" selected as the step appears (APP-07.5): its accent ring and soft halo are drawn; the mockup draws no focus. The window buttons are the real ones (masked). Card words: M07-01, M07-03.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/vault-new-vault-step-1.png` against `../../option-a/reference/light/vault-new-vault-step-1.png`, diff `diff/light/vault-new-vault-step-1.png`; dark likewise.

### vault-new-vault-step-2: PASS

- Built by E5-S8. Recommended is simple mode at 1.0 s (APP-07.6); Custom shows the drawn rows editable plus Parallel threads (APP-07.7). Card words: M07-05 (two lines, so the choices sit 20 pt lower; in dark the moved accent fill is most of the changed pixels).
- Accepted (LD-210, Verify E5-S8 round 2): only the two strips where the Recommended card's accent fill moved (x 36 to 684; y 200 to 223 and 288 to 310 pt: the card is 200 to 290 pt drawn, 221 to 309.5 pt in the app) are masked for pixels and colours. With the 20 pt shift undone (the app's rows 200 to 660 pt moved up), the whole frame differs 1.72 % (light) and 1.66 % (dark).
- light: recorded shift (20 pt, APP-07 M07-05: the card's step line takes two lines) applies to 0 boxes and 9 text runs; left after the shift, at most 2 pt.
- dark: recorded shift (20 pt, APP-07 M07-05: the card's step line takes two lines) applies to 0 boxes and 9 text runs; left after the shift, at most 2 pt.

Images: light `app/light/vault-new-vault-step-2.png` against `../../option-a/reference/light/vault-new-vault-step-2.png`, diff `diff/light/vault-new-vault-step-2.png`; dark likewise.

### vault-new-vault-step-3: PASS

- Built by E5-S8. The Password field has the focus as the step appears (APP-07.11). Show shows both fields (APP-07.11), so the repeat is in clear. Card words: step title, M07-09, M07-10, M07-12, M07-14; the key file buttons are wider for M07-12's "New Key File…" and "Choose Key File…", so their boxes are not compared. Security key and Touch ID drawn and disabled (E10, E6-S3).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.
- light: recorded shift (16 pt, APP-07 M07-12: the card's key file note takes two lines) applies to 1 boxes and 4 text runs; left after the shift, at most 1 pt.
- dark: recorded shift (16 pt, APP-07 M07-12: the card's key file note takes two lines) applies to 1 boxes and 4 text runs; left after the shift, at most 1 pt.

Images: light `app/light/vault-new-vault-step-3.png` against `../../option-a/reference/light/vault-new-vault-step-3.png`, diff `diff/light/vault-new-vault-step-3.png`; dark likewise.

### vault-vault-settings-general: PASS

- Built by E5-S8. Each control applies itself (no Apply drawn); the path is the test copy's.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/vault-vault-settings-general.png` against `../../option-a/reference/light/vault-vault-settings-general.png`, diff `diff/light/vault-vault-settings-general.png`; dark likewise.

### vault-vault-settings-security: PASS

- Built by E5-S8. The key file is a new one the test made (personal.appkey); encryption Argon2id 64 MiB, 2 threads, 1.0 s. Security key and Touch ID drawn and disabled (E10, E6-S3). The unlock time slider is linear from 0.1 to 5 s (APP-07.6), so its thumb sits at 18 % (drawn at 40 %).
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/vault-vault-settings-security.png` against `../../option-a/reference/light/vault-vault-settings-security.png`, diff `diff/light/vault-vault-settings-security.png`; dark likewise.

### vault-vault-settings-recycle-bin: PASS

- Built by E5-S8. "Empty entries older than" has no card rule yet: drawn and disabled with the reason.
- Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.

Images: light `app/light/vault-vault-settings-recycle-bin.png` against `../../option-a/reference/light/vault-vault-settings-recycle-bin.png`, diff `diff/light/vault-vault-settings-recycle-bin.png`; dark likewise.

### vault-vault-settings-history: PASS

- Built by E5-S8 on the demo vault's history.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/vault-vault-settings-history.png` against `../../option-a/reference/light/vault-vault-settings-history.png`, diff `diff/light/vault-vault-settings-history.png`; dark likewise.

### vault-vault-settings-browser-keys: PASS

- Built by E5-S8: the demo vault's two associations and four entries with site permissions; Disconnect and Remove all… ask first.
- Live, format only: codes, countdowns, the save and lock times, the test copies' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".

Images: light `app/light/vault-vault-settings-browser-keys.png` against `../../option-a/reference/light/vault-vault-settings-browser-keys.png`, diff `diff/light/vault-vault-settings-browser-keys.png`; dark likewise.

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

This report: `node design/parity/tools/compare.mjs vault` printed:

```
vault: 8/8 PASS
vault-new-vault-step-1                         PASS                   L 2.13% (1.83) D 2.83% (2.53)
vault-new-vault-step-2                         PASS                   L 2.63% (1.2) D 7.07% (1.24)
vault-new-vault-step-3                         PASS                   L 2.36% (1.16) D 3.24% (2.02)
vault-vault-settings-general                   PASS                   L 1.89% (1.69) D 1.89% (1.69)
vault-vault-settings-security                  PASS                   L 1.77% (1.61) D 1.76% (1.61)
vault-vault-settings-recycle-bin               PASS                   L 0.68% (0.63) D 0.66% (0.62)
vault-vault-settings-history                   PASS                   L 0.95% (0.85) D 0.93% (0.84)
vault-vault-settings-browser-keys              PASS                   L 1.08% (0.9) D 1.07% (0.9)
```

## Verify run for E5-S8, round 2 (2026-10-28)

Verify agent, not the builder. Everything ran in a private copy (/tmp/e5s8-verify3-copy, deleted afterwards); this report and its images were copied from there.

- `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0. The manifest is byte-equal to the tree's. 18 of the 20 E5-S8 references are byte-equal; `light/vault-new-vault-step-3` and `dark/vault-vault-settings-security` differ in bytes only (pixelmatch 0 and 0).
- `scripts/build-core.sh` → `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`, exit 0.
- `xcodebuild … test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `✔ Suite NewVaultSnapshotTests passed`, `✔ Suite VaultSettingsSnapshotTests passed`, `✔ Suite NewVaultBehaviourTests passed`, `✔ Suite VaultSettingsBehaviourTests passed`; 167 tests in 29 suites with one issue, in ScreenTests (`NSPasteboard.general.changeCount == before`, LD-206). That suite alone → `✔ Test run with 9 tests in 1 suite passed`.
- `node design/parity/tools/mockup-dom.mjs vault,dialogs` → `29 frames, 319 text runs` per theme. `swift design/parity/tools/ocr.swift` on the 22 shots per theme.
- The general page's live path: the copy lives outside the home folder, so its two general shots come from `TEST_RUNNER_HOME=/private/tmp/e5s8-verify3-target … -only-testing:AppTests/VaultSettingsSnapshotTests`. They show `~/option-a/settings-shots/Passwords/Personal.appvault`. The other four pages come from the normal run. Nothing was written under the real home: `ls /Users/…/option-a` says No such file.
- `node design/parity/tools/compare.mjs vault` → `vault: 8/8 PASS`. Before LD-210 was written into notes.mjs, the same shots gave `vault: 7/8 PASS`, with step 2 at `D 7.07% (6.65)`.
- **LD-210, step 2 (dark).** The lead accepted the M07-05 shift (LD-210). notes.mjs now masks only the two strips where the Recommended card's accent fill moved: x 36 to 684, y 200 to 223 and 288 to 310 pt. The card is drawn at 200 to 290 pt and sits at 221 to 309.5 pt in the app. Proof that the 20 pt shift explains the rest: with the app's rows 200 to 660 pt moved up 20 pt, the whole frame differs 2.63 % → 1.72 % (light) and 7.07 % → 1.66 % (dark), and the band alone 3.15 % → 1.72 % and 10.14 % → 1.67 %. Text, tokens and geometry are unchanged: 0 missing, 0 colour issues, 0 boxes and 0 text runs off after the recorded shift.
- **Reproducible.** 18 of 20 shots (both dialogs included) are byte-equal to the builder's. The two general shots differ only in the path text: pixelmatch 2,642 px (light) and 2,661 px (dark), 0.11 %.
- **Accessibility.** The 10 light trees have 89 controls and 0 without a name. Contrast: 42 pairs, the lowest 4.87:1. Static tokens: 45 of 45.
- **Mac QA (owner's go).** The focus ring on a key window, VoiceOver, and the real save panel.

Full proof: [security/parity/E5-S8-vault-wizard.md](../../../security/parity/E5-S8-vault-wizard.md).
