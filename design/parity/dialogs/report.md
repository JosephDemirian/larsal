# Design parity: section `dialogs`

Date 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). App: offscreen snapshots of SnapshotTests.

**Result: 17 of 17 built frames PASS** (21 frames in the section; 4 belong to later stories).

Check tools: pixelmatch 8.0.0, pngjs 7.0.0 (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).

| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |
|---|---|---|---|---|---|---|---|
| dialogs-move-to-recycle-bin | present | present | 0.35 % (0.35 %) / 0.36 % (0.36 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-delete-forever | present | present | 0.3 % (0.3 %) / 0.34 % (0.34 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-empty-recycle-bin | present | present | 0.56 % (0.56 %) / 0.58 % (0.58 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-discard-changes | present | present | 0.66 % (0.32 %) / 0.69 % (0.34 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-clone-entry | present | present | 1.37 % (0.38 %) / 1.42 % (0.4 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-add-one-time-code | present | present | 2.19 % (0 %) / 2.12 % (0 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-one-time-code-as-qr | present | present | 7.42 % (0.14 %) / 37.14 % (0.16 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-wi-fi-as-qr | present | present | 7.72 % (0.1 %) / 38.81 % (0.12 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-new-group | present | present | 1.38 % (1.38 %) / 1.36 % (1.36 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-remove-passkey | present | present | 1.04 % (0 %) / 1.06 % (0 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-earlier-version | present | present | 0.94 % (0.94 %) / 0.96 % (0.96 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-changed-on-disk | present | present | 2.14 % (1.01 %) / 2.13 % (1.02 %) (common area, see below) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-close-with-unsaved-changes | present | present | 1.91 % (0 %) / 1.97 % (0 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-save-failed | present | present | 0.33 % (0.33 %) / 0.38 % (0.38 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-export-warning | – | – | – | – | – | – | later story (E5-S11 (FEA-09)) |
| dialogs-import | – | – | – | – | – | – | later story (E5-S11 (FEA-08)) |
| dialogs-browser-asks-for-an-entry | – | – | – | – | – | – | later story (E7) |
| dialogs-connect-a-browser | – | – | – | – | – | – | later story (E7) |
| dialogs-ssh-key-use | present | present | 0.38 % (0.38 %) / 0.4 % (0.4 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-weak-vault-password | present | present | undefined % (undefined %) / undefined % (undefined %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |
| dialogs-create-key-file | present | present | 2.29 % (2.29 %) / 2.16 % (2.09 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS |

Token mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): 45 of 45 equal.

## Findings per frame

### dialogs-move-to-recycle-bin: PASS


Images: light `app/light/dialogs-move-to-recycle-bin.png` against `../../option-a/reference/light/dialogs-move-to-recycle-bin.png`, diff `diff/light/dialogs-move-to-recycle-bin.png`; dark likewise.

### dialogs-delete-forever: PASS


Images: light `app/light/dialogs-delete-forever.png` against `../../option-a/reference/light/dialogs-delete-forever.png`, diff `diff/light/dialogs-delete-forever.png`; dark likewise.

### dialogs-empty-recycle-bin: PASS


Images: light `app/light/dialogs-empty-recycle-bin.png` against `../../option-a/reference/light/dialogs-empty-recycle-bin.png`, diff `diff/light/dialogs-empty-recycle-bin.png`; dark likewise.

### dialogs-discard-changes: PASS


Images: light `app/light/dialogs-discard-changes.png` against `../../option-a/reference/light/dialogs-discard-changes.png`, diff `diff/light/dialogs-discard-changes.png`; dark likewise.

### dialogs-clone-entry: PASS


Images: light `app/light/dialogs-clone-entry.png` against `../../option-a/reference/light/dialogs-clone-entry.png`, diff `diff/light/dialogs-clone-entry.png`; dark likewise.

### dialogs-add-one-time-code: PASS


Images: light `app/light/dialogs-add-one-time-code.png` against `../../option-a/reference/light/dialogs-add-one-time-code.png`, diff `diff/light/dialogs-add-one-time-code.png`; dark likewise.

### dialogs-one-time-code-as-qr: PASS

- The QR symbol is the live one; dark modules on a light panel in both themes (LD-192 (4)); the panel and the added countdown and Copy of the card (FEA-04.23, LD-192 (5)) are masked for pixels and colours, nothing else (LD-199 (8)).

Images: light `app/light/dialogs-one-time-code-as-qr.png` against `../../option-a/reference/light/dialogs-one-time-code-as-qr.png`, diff `diff/light/dialogs-one-time-code-as-qr.png`; dark likewise.

### dialogs-wi-fi-as-qr: PASS

- The QR symbol is the live one; dark modules on a light panel in both themes (LD-192 (4)); the panel is masked for pixels and colours, nothing else (LD-199 (8)).

Images: light `app/light/dialogs-wi-fi-as-qr.png` against `../../option-a/reference/light/dialogs-wi-fi-as-qr.png`, diff `diff/light/dialogs-wi-fi-as-qr.png`; dark likewise.

### dialogs-new-group: PASS


Images: light `app/light/dialogs-new-group.png` against `../../option-a/reference/light/dialogs-new-group.png`, diff `diff/light/dialogs-new-group.png`; dark likewise.

### dialogs-remove-passkey: PASS


Images: light `app/light/dialogs-remove-passkey.png` against `../../option-a/reference/light/dialogs-remove-passkey.png`, diff `diff/light/dialogs-remove-passkey.png`; dark likewise.

### dialogs-earlier-version: PASS


Images: light `app/light/dialogs-earlier-version.png` against `../../option-a/reference/light/dialogs-earlier-version.png`, diff `diff/light/dialogs-earlier-version.png`; dark likewise.

### dialogs-changed-on-disk: PASS

- Built by E5-S10: APP-05.27 (the vault has unsaved changes) with the card's message and buttons in the mockup's choice rows; the drawn descriptions stay. The same sheet asks APP-05.26 (Load, Keep), APP-05.28 (Merge then save, Discard, Overwrite) and APP-05.30 (Overwrite). Rust decides by checksum; the folder and file watch raises it (AT-I05 test).
- Verify E5-S10 2026-10-28 (private copy): `export-reference.mjs` gave references and manifest byte-equal to the tree's; fresh offscreen shots (SavingSnapshotTests) are byte-equal to `app/`; `compare.mjs dialogs` gave this record unchanged (PASS). The app shot is 1120 × 870 px against 1120 × 868 px (0.5 pt per edge, inside the 2 pt geometry limit), so compare.mjs skipped checks 3 and 5 ('undefined %'). On the common area, the app shot 1 px down (the best offset), same pixelmatch settings: light 2.14 % (1.01 % outside accepted areas), dark 2.13 % (1.02 %); colour shares: no issue; diff images added. 9 of 9 strings (4 by card words), glyph arrows-clockwise, 0 boxes or text runs off (the Cancel button is narrower by the card's word, geoSkip), 0 unnamed controls. Behaviour: the 2 Parity tests pass, and the Verify AT-I05 screen tests (Merge, Merge then save, Discard, Ignore, Load and Keep, Overwrite only) pass. Proof: [security/parity/E5-S10-saving.md](../../../security/parity/E5-S10-saving.md).
- Verify E5-S10 round 2, 2026-10-28 (private copy): unchanged PASS. Fresh references and manifest byte-equal; fresh shots byte-equal to `app/` (light a33bfaf0, dark d9e35f8c); `compare.mjs dialogs` gave `dialogs: 17/17 PASS` and this record equal to the stored one except the Verify notes; common area again light 2.14 %, dark 2.13 % (best offset dy 1 px). Behaviour: the 2 Parity tests and 6 Verify AT-I05 screen tests pass (the sheet 513 to 529 ms after the write). Proof: [security/parity/E5-S10-saving.md](../../../security/parity/E5-S10-saving.md), Round 2.

Images: light `app/light/dialogs-changed-on-disk.png` against `../../option-a/reference/light/dialogs-changed-on-disk.png`, diff `diff/light/dialogs-changed-on-disk.png`; dark likewise.

### dialogs-close-with-unsaved-changes: PASS

- Built by E5-S10: APP-02.15 step 8 MSG-LOCK-SAVE for Close Vault, Lock and Quit when the save on lock is off or failed; Save saves again, Discard lets the vault go, Cancel keeps it.
- Verify E5-S10 2026-10-28 (private copy): reproduced PASS, light 1.91 % (0 %), dark 1.97 % (0 %); shots, record and diff images byte-equal to these. 5 of 5 strings (2 by card words), 0 unnamed controls. Behaviour: the 2 Parity tests pass; Verify T07 (save on lock on: ⌘L saves, then locks, no question) and T50 (⌘L meets a changed file: the disk question shows, Cancel keeps the vault unlocked and changed) pass. Proof: [security/parity/E5-S10-saving.md](../../../security/parity/E5-S10-saving.md).
- Verify E5-S10 round 2, 2026-10-28 (private copy): unchanged PASS, light 1.91 % (0 %), dark 1.97 % (0 %); fresh shots byte-equal (656c1e67, 500ee513); the record equal except the Verify notes. Behaviour: the 2 Parity tests pass; Verify R-T07 (⌘L saves, then locks after 45 ms, no question) and R-T57/T58 (⌘L meets a changed file: the disk question, Cancel keeps it unlocked, no recovery copy; an automatic lock over the open question writes the copy and locks) pass. Proof: [security/parity/E5-S10-saving.md](../../../security/parity/E5-S10-saving.md), Round 2.

Images: light `app/light/dialogs-close-with-unsaved-changes.png` against `../../option-a/reference/light/dialogs-close-with-unsaved-changes.png`, diff `diff/light/dialogs-close-with-unsaved-changes.png`; dark likewise.

### dialogs-save-failed: PASS

- Built by E5-S10: APP-05.13 MSG-SAVE-FAILED as the mockup's sheet; the reason is the system's (the snapshot shows the mockup's demo reason). Save As… (APP-05.6), Close, Try Again.
- Verify E5-S10 2026-10-28 (private copy): reproduced PASS, light 0.33 %, dark 0.38 %; shots, record and diff images byte-equal to these. 5 of 5 strings, 0 unnamed controls. Behaviour: the Parity test passes; Verify T19 (an unreadable file: 'The vault file cannot be read.', nothing written) and T26 (folder read-only, three failures with the reason, the sheet once, no unsafe-save question) pass. Proof: [security/parity/E5-S10-saving.md](../../../security/parity/E5-S10-saving.md).
- Verify E5-S10 round 2, 2026-10-28 (private copy): unchanged PASS, light 0.33 %, dark 0.38 %; fresh shots byte-equal (9427765b, bbdc4cb6); the record equal except the Verify notes. Behaviour: the Parity test passes; Verify R-T47 (folder read-only: the sheet with "This vault's file or its folder cannot be written."; an automatic lock then writes the recovery copy, 0600) passes. Proof: [security/parity/E5-S10-saving.md](../../../security/parity/E5-S10-saving.md), Round 2.

Images: light `app/light/dialogs-save-failed.png` against `../../option-a/reference/light/dialogs-save-failed.png`, diff `diff/light/dialogs-save-failed.png`; dark likewise.

### dialogs-export-warning: later story (E5-S11 (FEA-09))

Not built yet: E5-S11 (FEA-09). Not checked.

### dialogs-import: later story (E5-S11 (FEA-08))

Not built yet: E5-S11 (FEA-08). Not checked.

### dialogs-browser-asks-for-an-entry: later story (E7)

Not built yet: E7. Not checked.

### dialogs-connect-a-browser: later story (E7)

Not built yet: E7. Not checked.

### dialogs-ssh-key-use: PASS


Images: light `app/light/dialogs-ssh-key-use.png` against `../../option-a/reference/light/dialogs-ssh-key-use.png`, diff `diff/light/dialogs-ssh-key-use.png`; dark likewise.

Verify (E9-S2) 2026-10-28, in a private copy: `export-reference.mjs` (references and manifest byte-equal to the tree's), `SshKeyUseTests` offscreen (3 of 3 pass; PNGs and ax.json rendered at 18:25 byte-equal to the tree's), `mockup-dom.mjs dialogs`, `ocr.swift`, `compare.mjs dialogs`: PASS, light 0.38 %, dark 0.40 %, 5 of 5 strings found, 0 token mismatches, 3 boxes within 0.5 pt, behaviour test passed; this frame's record in findings.json equal to the one here. R06-6 test bites (first second widened to 0 s: 2 expectations fail). Round 2 (19:35 to 19:45, new private copy): references and manifest byte-equal again; `SshKeyUseTests` 3 of 3 (PNGs and ax.json rendered 19:36 byte-equal to the tree's); `compare.mjs dialogs`: 17/17 PASS, this frame PASS, light 0.38 %, dark 0.40 %; record equal apart from this note, `app/` and `diff/` images byte-equal; R06-6 (first second 0 s: 2 issues) and the ended-question close (1 issue) each bite. Proof: [E9-S2-ssh-keys.md](../../../security/parity/E9-S2-ssh-keys.md).

### dialogs-weak-vault-password: PASS

- Built by E5-S8: FEA-05.20 MSG-MK-WEAK in the dialog look, one sentence as the title, so the sheet is shorter than drawn; it never names the password (rule 4).
- Accepted (LD-210, Verify E5-S8 round 2): the sheet is 44 pt shorter (x, y and width equal); both buttons sit 44 pt higher, "Use this password" keeps the drawn left edge (25 pt wider) and Cancel the drawn right edge (59 pt narrower). These three boxes are not compared. The image sizes differ (460 × 148 against 460 × 192 pt), so pixels and colour shares are not measured; icon, title style and button styles were checked by eye.
- Verify E5-S8 round 2 (private copy): `compare.mjs dialogs` → `dialogs-weak-vault-password PASS`. Before LD-210 went into notes.mjs, the same shots gave the 3 boxes above, 44 pt off. The shots are byte-equal to the builder's. 0 missing strings, 2 controls, 0 without a name. Behaviour: `Parity dialogs-weak-vault-password: Cancel keeps step 3; Use this password goes to the save panel` passed. Proof: security/parity/E5-S8-vault-wizard.md.

Images: light `app/light/dialogs-weak-vault-password.png` against `../../option-a/reference/light/dialogs-weak-vault-password.png`, diff `diff/light/dialogs-weak-vault-password.png`; dark likewise.

### dialogs-create-key-file: PASS

- Built by E5-S8: APP-07.13's "<vault name>.appkey".
- Verify E5-S8 round 2 (private copy): `compare.mjs dialogs` → `dialogs-create-key-file PASS L 2.29% (2.29) D 2.16% (2.09)`. The shots are byte-equal to the builder's. 0 missing strings, 3 controls, 0 without a name. Behaviour: `Parity dialogs-create-key-file: Create Key File makes the file and fills the key file part (APP-07.13)` passed.

Images: light `app/light/dialogs-create-key-file.png` against `../../option-a/reference/light/dialogs-create-key-file.png`, diff `diff/light/dialogs-create-key-file.png`; dark likewise.

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

This report: `node design/parity/tools/compare.mjs dialogs` printed:

```
dialogs: 13/14 PASS
dialogs-move-to-recycle-bin                    PASS                   L 0.35% (0.35) D 0.36% (0.36)
dialogs-delete-forever                         PASS                   L 0.3% (0.3) D 0.34% (0.34)
dialogs-empty-recycle-bin                      PASS                   L 0.56% (0.56) D 0.58% (0.58)
dialogs-discard-changes                        PASS                   L 0.66% (0.32) D 0.69% (0.34)
dialogs-clone-entry                            PASS                   L 1.37% (0.38) D 1.42% (0.4)
dialogs-add-one-time-code                      PASS                   L 2.19% (0) D 2.12% (0)
dialogs-one-time-code-as-qr                    PASS                   L 7.42% (0.14) D 37.14% (0.16)
dialogs-wi-fi-as-qr                            PASS                   L 7.72% (0.1) D 38.81% (0.12)
dialogs-new-group                              PASS                   L 1.38% (1.38) D 1.36% (1.36)
dialogs-remove-passkey                         PASS                   L 1.04% (0) D 1.06% (0)
dialogs-earlier-version                        PASS                   L 0.94% (0.94) D 0.96% (0.96)
dialogs-changed-on-disk                        later story (E5-S10)   L -% (-) D -% (-)
dialogs-close-with-unsaved-changes             later story (E5-S10)   L -% (-) D -% (-)
dialogs-save-failed                            later story (E5-S10)   L -% (-) D -% (-)
dialogs-export-warning                         later story (E5-S11 (FEA-09)) L -% (-) D -% (-)
dialogs-import                                 later story (E5-S11 (FEA-08)) L -% (-) D -% (-)
dialogs-browser-asks-for-an-entry              later story (E7)       L -% (-) D -% (-)
dialogs-connect-a-browser                      later story (E7)       L -% (-) D -% (-)
dialogs-ssh-key-use                            PASS                   L 0.38% (0.38) D 0.4% (0.4)
dialogs-weak-vault-password                    FAIL                   L -% (-) D -% (-)
dialogs-create-key-file                        PASS                   L 2.29% (2.29) D 2.16% (2.09)
```
