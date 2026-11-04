# Design parity: section `w-15` (E11-S5, shared groups)

Date 2026-11-01. Builder's Mac QA; Verify still checks it. Reference: design/option-a/proposals.html section W-15 (E11-S4), proposals/w-15-light.png and w-15-dark.png. App: offscreen snapshots by ShareSnapshotTests (8 frames) and AppSettingsFrameTests (w-15-app-settings), in app-shots/<light|dark>/<frame>.png and .ax.json. No window shown, no focus taken (rule 10).

Result: 9 of 9 frames built, light and dark.

Strings, strict (byte for byte, so U+0027 and U+2019 differ): every text run, aria-label and placeholder of each W-15 frame, made by proposals.html's own frame functions (node, no browser), looked up in the labels and values of the app's .ax.json. Found: 400 of 532 in each theme. The other 132: 80 are behind the Approve sheet in w-15-list-approval (the sheet is modal, so VoiceOver reads only the sheet); 19 are frame notes on the two card frames (rule and message ids, difference 8); 2 are MI08-17 texts of the not-saved form (difference 2); 31 are demo data (difference 1). No W-15 .ax.json holds U+2019; ShareSnapshotTests checks this (F-175).

Pixel diff: W-15 has no per-frame reference images (LD-268), so Verify rendered each W-15 frame alone from proposals.html (headless Chrome, 2x, no network) and compared it with pixelmatch 8.0.0 (threshold 0.1, anti-aliasing ignored). Verify round 2: all 7 full frames under 3 %, light and dark. Verify round 3, after the F-214 fix: w-15-sharing-sync 0.72 % light, 0.70 % dark; w-15-sharing-inactive 0.52 % light, 0.52 % dark. The two card frames differ in size because the app does not draw the frame notes (difference 8), so they were compared by eye.

| Frame | Strings light · dark | Test |
|---|---|---|
| w-15-sharing-sync | 70/76 · 70/76 | ShareSnapshotTests.frame, ShareFlowTests.controls, .secureInput, .passwordKeys, WindowFixesTests.f207SharePassword |
| w-15-sharing-inactive | 66/68 · 66/68 | ShareSnapshotTests.frame, ShareFlowTests.makeExportImport |
| w-15-messages-labels | 48/66 · 48/66 | ShareSnapshotTests.frame |
| w-15-list-banner | 72/85 · 72/85 | ShareSnapshotTests.frame |
| w-15-banner-kinds | 15/18 · 15/18 | ShareSnapshotTests.frame |
| w-15-list-inside-share | 69/79 · 69/79 | ShareSnapshotTests.frame, ShareFlowTests.allowChanges |
| w-15-list-approval | 17/97 · 17/97 (modal sheet) | ShareSnapshotTests.frame, ShareFlowTests.approveMerged |
| w-15-vault-settings | 27/27 · 27/27 | ShareSnapshotTests.frame |
| w-15-app-settings | 16/16 · 16/16 | AppSettingsFrameTests.frame, AppSettingsParityTests 'Parity w-15-app-settings' |

Known differences:

- (1) Demo data, not design: the status line ('Personal.appvault', 'Saved at 08:50 · encrypted'), entry dates, 'Modified', earlier versions and the detail pane's URL come from the clock and the demo; strength words follow FEA-05 (Good, not Strong); 'Full path:' shows the test copy's folder, not /Users/alex/Documents/Passwords/.
- (2) MI08-17 'Vault not saved to a file yet' is not drawn: an open vault always has a file (INT-08.5). The open-vault form is drawn.
- (3) The group editor's other five pages are drawn but disabled, with 'come with group editing (MOD-02)' (LD-163).
- (4) Vault settings has 6 pages now, so the locked vault-settings frames show one row fewer in the nav.
- (5) w-15-app-settings replaces the locked settings-settings-shared-groups frame (option (b) signer rows, LD-270 (3)).
- (6) Browse… uses the system panel with no file filter; the last folder is kept for the run only.
- (7) LD-270 (3): MI08-14 keeps the card's words, '…in App's settings, Shared groups.', while the Settings page title is 'Shared Groups' (title case, like every Settings page title).
- (8) The card frames' notes (for example '· case 1 · MI08-10 · warning') name rules and message ids; the app's card views show the item titles only.
- (9) INT-08.24's Share tab in the group preview is not drawn: Option A has no group preview (LD-270 (3)).

Commands: xcodebuild build-for-testing ... SWIFT_TREAT_WARNINGS_AS_ERRORS=YES (TEST BUILD SUCCEEDED); xcodebuild test-without-building ... -skip-testing:AppUITests (390 tests in 54 suites passed, Builder round 5, with the F-214 fix; Verify gives the final count).
