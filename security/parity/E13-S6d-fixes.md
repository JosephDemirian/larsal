# E13-S6 part d: re-test of F-076, F-077, F-082, F-078, F-083, F-084, F-072, F-074 and SD-13

Story: E13-S6 part d ([plan/epics.md](../../plan/epics.md)). Rows: [security/findings.md](../findings.md), SD-13 in [plan/security.md](../../plan/security.md). Earlier proof: [E13-S1-SR.md](E13-S1-SR.md) (SR-03 = F-078, SR-06 = F-076, SR-08 = F-077), [E13-S1-SC.md](E13-S1-SC.md) (SC-04 = F-082 and F-084, SC-08 = F-083), [E13-S1-SF.md](E13-S1-SF.md) (SF-13 = F-074, SF-18 = F-072), [E13-S1-SD.md](E13-S1-SD.md) (SD-13). Rulings: LD-223 (owners), LD-220 (1) (crossings to Swift), LD-65 and LD-109 (image decoding), L05-3 (markup in previews), D-13-3 and D-13-4 (MOD-13.8, MOD-13.9).
Date: 2026-10-29 (the runs took place from 02:14 to 03:05 on 2026-10-30 by the Mac's clock). Role: Verify, round 1. I did not find, build or check these fixes.

| Row | Result | One line |
|---|---|---|
| F-076 (High) | **fixed, re-tested**; Mac QA note | The Caps Lock note shows on the wizard's Password, the vault settings' new password, the editor's password, the setup secret, the disk-change sheet and the unlock form, and never on a repeat field. |
| F-077 (High) | **fixed, re-tested** | GitHub expired yesterday: the first unlock gives `is:expired-3`, 'Expired or due to expire in 3 days', with GitHub and Zalando. Nothing after a lock and unlock. It shows again after a close and open. |
| F-082 (High) | **fixed, re-tested** | With Hide notes and Hide one-time codes on, GitHub's notes and live code are hidden in the detail pane until Show. The editor hides the notes until its reveal button. |
| F-078 | **fixed, re-tested** | 10 s right after a copy, 7 s after 3.1 s, 0 after a lock. The app's lock on minimize waits for this countdown, not 1 s. |
| F-083 | **fixed, re-tested**; test note | Opening the editor restarts a running search clear countdown from full. The test is timing based: run alone it catches the fix undone, but beside other suites under load it missed it once. |
| F-084 | **fixed, re-tested** | With 'Show dots for empty passwords' on, an empty password shows as the six-dot mask. With it off, it shows nothing. |
| F-072 | **fixed, re-tested** | A key file named `evil` U+202E `gpj.appkey` comes back as `evilgpj.appkey` in the wizard, the credentials page, its early-kind note, a refusal and an unlock failure. |
| F-074 | **fixed, re-tested**; residual for the lead | Force 60 days, changed 153 days ago: the prompt shows its reason, and nothing of the vault is on screen (0 of 58 names). Auto-Type and SSH count the vault as locked. Change Now, Cancel, Lock and T16 (the save fails, the vault opens unsaved with the error) all work. Change Now offers the password only (residual 1). |
| SD-13 | **re-tested** (App's extra built); row stays todo for the lead | HTML, Markdown and SVG show as plain text with no link and no image node. PNG and ICO go through the Rust decoder and are written again as PNG at their own size, with the input's chunks gone. JPEG, PDF, images over 4,096 pixels and a forged size show the note. |

All 9 rows were re-tested. No re-test failed. The residuals and notes below go to the lead.

## Setup

- **Private copy.** `rsync -a --exclude target --exclude app-shots --exclude .build` to `/tmp/e13s6d-verify-copy` at 02:14. It had its own `CARGO_TARGET_DIR=/tmp/e13s6d-verify-target` and `-derivedDataPath /tmp/e13s6d-verify-dd`. The copy needed **no** copy-only fixes: app-ffi and the Swift tests both build from the tree as it is now. My only additions to the copy were the probes `crates/app-ffi/src/verify_probe.rs` (plus its `mod` line in lib.rs) and `macos/AppTests/VerifyProbeTests.swift`. Before I deleted the copy, every part d file in it (30 files, lib.rs included after I took the probe line out) was byte-identical to the shared tree (`cmp`). The shared tree did not change these files while I worked.
- **Rust, copy.**
  - `cargo test --locked -p app-ffi --lib --features net` -> 'test result: ok. 139 passed; 0 failed; 2 ignored'. This includes `window::tests::f_072_key_file_name_is_cleaned`, `f_074_forced_key_change_counts_as_locked_until_changed`, `f_074_recommended_notice_once_per_unlock`, `f_077_expiry_notice_after_the_first_unlock`, `f_078_session_reports_the_clipboard_countdown`, `sd_13_preview_decodes_images_in_rust_and_shows_markup_as_plain_text` and `ssh::tests::f_074_the_forced_prompt_ends_with_the_ssh_record_under_the_state_lock`, all ok.
  - `cargo test -p app-ffi --features net --test ssh` -> 'ok. 17 passed', with `mod13_8_a_forced_key_change_adds_no_key_until_the_key_is_changed ... ok`.
  - `cargo test -p app-platform --lib clipboard` -> 'ok. 9 passed', with `f_078_seconds_left_follows_the_countdown ... ok`.
  - `cargo test -p app-core --lib icons` -> 2 passed.
- **Swift, copy.** `scripts/build-core.sh` -> 'build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift'. `xcodebuild build-for-testing … SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` -> '** TEST BUILD SUCCEEDED **'.
  - `xcodebuild test-without-building -only-testing:AppTests/WindowFixesTests -only-testing:AppTests/WindowFixesMoreTests -only-testing:AppTests/AutoTypeTests` -> 'Test run with 35 tests in 3 suites passed after 13.159 seconds'. All 17 part d tests are named in the log and passed.
  - Full suite: see "Full Swift suite" at the end.
  - Every test runs under XCTest offscreen (windows at -20,000, never ordered front), with a private pasteboard and the fake file opener. No key events, no focus taken. No secure field was focused, so the real secure input never turned on.
- **Mutants.** Each mutant was made in the copy only, then the file was restored from a backup and checked with `cmp` ('cmp same=True' for each). Rust: 10 mutants, one at a time. Swift: 10 mutants in two batches of five, each mutant aimed at a different test, plus 2 re-run alone. They are listed under each row.
- **Shared tree, read only.**
  - `xcrun swift format lint --strict` on the 12 part d Swift files -> exit 0.
  - SwiftLint 0.65.1 `lint --strict --quiet` on the 22 Swift files part d touched (the password fields, AppDelegate, LockSignals and the 3 test files included) -> exit 0, no line.
  - `rustfmt --edition 2024 --check` on window.rs, session.rs, ssh.rs, tests/ssh.rs, app-core icons.rs and app-platform clipboard.rs -> exit 0.

## F-076: Caps Lock warning on every password field (APP-06.6, APP-07.11)

- **Steps (the row's):** turn Caps Lock on, then type in New Vault > Password and keys > Password, in Vault Settings > change password, and in the entry editor's password. In the tests, Caps Lock is the view's `capsLockFake` environment value. The real key state comes from `NSEvent.modifierFlags`, read on focus, on every key and flags change, and when App becomes active.
- **Before** (the row): only UnlockView had the M06-37 note.
- **After:**
  - `grep -rn "capsLockNote" macos/App` finds the shared modifier (CapsLock.swift) on 6 fields: UnlockView.swift:158 (the unlock form, also used by Auto-Type's unlock panel), NewVaultView.swift:220 (Password), VaultSettingsPages.swift:230 (the new password), EditorEntryPage.swift:293 (the editor's password), DialogSheets.swift:30 (the one-time code setup secret) and SavingSheets.swift:185 (the 'Unlock the changed …' sheet).
  - I searched every password-kind field in macos/App (`SecureField`, `SecretField(`, `EditorPasswordField(`, `MaskedPasswordField`, `ShownPasswordField(`). The only fields without the note are the two repeat fields, NewVaultView.swift:226 and VaultSettingsPages.swift:234, as APP-06.6 says.
  - All 4 tests passed: 'F-076, APP-07.11: the wizard's Password … Verify password never', 'F-076, MOD-12.10: the vault settings' new password …', 'F-076, APP-06.6: the entry editor's password …' and 'F-076, APP-06.6: the unlock form keeps its note …'.
- **Mutant (mine):** the note ignores focus (`if capsOn && !error`). Three tests fail: WindowFixesTests.swift:97 and :113 ('not on the repeat field') and :128 ('not before the focus'). The builder's three mutants (each field's note removed) were not repeated.
- **Mac QA (owner's go):** the native Caps Lock read, and the disk-change sheet's real secure field. No test focuses a real secure field (rule 10).

## F-077: expired and expiring entries after unlock (APP-01.18, MOD-09.7)

- **Steps (the row's, demo vault option-a-personal, password demo-pass-7):**
  1. GitHub's expiry was set to yesterday through the editor calls (`begin_edit`, `set_expiry`, `commit_edit`) and saved.
  2. A new session (S-START-11 on by default) unlocks the vault for the first time.
  3. I ran a lock and unlock, then a close and open.

  Probe `verify_probe_f077_row_steps` in the copy.
- **Before** (the row): `app_core::expiry::notice` had no caller, so nothing showed.
- **After:**
  - First unlock: `PROBE f077 first unlock: AfterUnlock { expiry_search: Some("is:expired-3"), expiry_title: Some("Expired or due to expire in 3 days"), key_change: None } hits=Some(2) expired rows=["Zalando", "GitHub"]`.
  - A second call: empty. After a lock and unlock: `AfterUnlock { expiry_search: None, … }`, which is APP-01.18 b. After a close and open: the notice again, because MOD-09.7 counts from when the vault was opened.
  - The Rust test covers a to c, plus 'off'. The Swift test 'F-077, APP-01.18 a, b …' checks that the window's search field holds `is:expired-3` with that title, and is empty after a lock.
- **Mutants (mine):**
  - Every unlock counts as the first (`Ok(Some(true))` in `take_fresh`): `f_077 … FAILED` at window.rs:294 (b).
  - S-START-12 ignored (always 3 days): FAILED at window.rs:305 (c, `is:expired-0`).
  - Swift: the window never calls `afterUnlock` (MainWindowModel `screen`): the F-077 test fails at WindowFixesTests.swift:168 and :169.

## F-082: Hide notes (S-CONV-05) and Hide one-time codes (S-CONV-04) (APP-01.23)

- **Steps (the row's):** store `display.hide_notes` and `display.hide_totp_in_preview`, load them into the window's options (`window.view.load`, which is what the settings' OK does through `AppDelegate.settingsApplied`), select GitHub in Personal, then open the editor.
- **Before** (the row): notes and code on screen, with both flags on.
- **After:** all 4 tests passed:
  - 'F-082, F-084: the stored switches reach the detail options';
  - '… S-CONV-05 hides the notes behind Show in the detail pane': hidden, then shown by 'Show notes';
  - '… in the editor with a reveal button': hidden, then shown by 'Show Notes';
  - '… S-CONV-04 hides the live code until its button': no 'New code in' until 'Show one-time code'.

  VaultView sets `.environment(\.detailOptions, window.view.detail)` over the list, the detail pane and the editor (VaultView.swift:24, :59). App's entry list has no notes or password cell, so APP-01.23's list part does not apply.
- **Mutants (mine):**
  - The editor's notes not concealed unless both switches are on: '… in the editor …' fails at WindowFixesMoreTests.swift:86, and 'Show Notes' is not found.
  - The code row's `hidden` needs both switches: '… S-CONV-04 …' fails at WindowFixesMoreTests.swift:101, and 'Show one-time code' is not found.

## F-078: lock on minimize waits for the clipboard countdown (APP-02.8)

- **Steps (the row's):** copy GitHub's password (10 s clear time), then read the countdown right away and 3.1 s later, then lock. Probe `verify_probe_f078_row_steps` (private pasteboard).
- **Before** (the row): AppDelegate passed no `secondsLeft`, so the delay was always 1 s.
- **After:**
  - `PROBE f078 right after the copy=10 after 3.1 s=7`, `after lock=0`. This is APP-02.8's own case: 'Minimize 3 s after a copy with a 10-second clear time: r = 7'.
  - AppDelegate.swift:36 builds `LockSignals.app(session:)`, which passes `{ Int(session.clipboardSecondsLeft()) }` (LockSignals.swift:110). All copies go through Rust: `grep -rn "NSPasteboard\|setString(" macos/App` finds only ShownPasswordField's write refusals.
  - The Swift test 'F-078, APP-02.8 …': no lock 2 s after the minimize while the countdown runs, and the lock comes at 11 s.
- **Mutants (mine):**
  - `seconds_left` rounds down: app-platform `f_078 … FAILED` at clipboard.rs:367 ('rounded up').
  - `clipboard_seconds_left` exported as 0: app-ffi `f_078 … FAILED` at window.rs:448.
  - Swift: `LockSignals.app` without `secondsLeft`: the test fails at WindowFixesMoreTests.swift:31 (`locks == 0`).

## F-083: a change of screen restarts the search clear countdown (APP-01.27)

- **Steps (the row's):** S-TIME-05 on, 1 minute (the test makes a minute 1 s long). Search 'git', leave the field, open the editor after 0.6 s, then check 0.6 s later.
- **Before** (the row): the countdown ran on and cleared the search while the editor was open.
- **After:** `VaultModel.editor` and `.reports` call `screenChanged()` when they open or close (VaultModel.swift:58, :62). That call restarts a running countdown from full (VaultModelParts.swift:43). A change of selection already restarted it (VaultView.swift:205). The test 'F-083, APP-01.27: opening the editor restarts the search clear countdown from full' passed.
- **Mutant (mine):** `screenChanged` emptied.
  - Run alone, the test **fails** at WindowFixesMoreTests.swift:141 (`main.search == "git"`), at load average 76.
  - In a batch beside 3 other suites, at load average 47, the same mutant **passed** once. The countdown's task starts only when the main actor is free, so under contention its 1 s can start late and end after the test's check. My brief says timing tests under load are re-run alone, and alone it is caught.
  - Test note for the lead: a 1 s window is tight. Smallest fix: a longer test minute (for example 3 s, checked at 2 s and 4.5 s), or a check that the countdown restarted. No test covers the reports screen's restart.

## F-084: dots for an empty password (S-CONV-01, APP-01.23 a)

- **Steps:** empty GitHub's password through the editor and save it, then draw the detail rail with the switch off and then on.
- **Before** (the row): nothing read `display.dots_for_empty`.
- **After:** 'F-084, APP-01.23 a …' passed. Off: no Password row. On: 'Password' with the six-dot mask (spoken as `Masked.spoken`). An empty user name is not masked in the detail pane, which matches APP-01.23 (the preview's S-CONV-01 rule is about the password only).
- **Mutant (mine):** the dots branch also needs Hide codes: the test fails at WindowFixesMoreTests.swift:121.

## F-072: key file names cleaned (APP-06.18)

- **Steps (the row's):** copy testdata/key-xml-v1.appkey to `evil` U+202E `gpj.appkey`. Choose it in the new vault wizard (`Wizard::choose_key_file`) and on the credentials page (`VaultSettings::choose_key_file`, Personal). I also tried an empty key file named `bad` U+202E `txt.appkey` in the wizard and at unlock. Probe `verify_probe_f072_rlo_key_file_name`.
- **Before** (the row): the name and the early-kind note kept U+202E, so the name showed reversed.
- **After:**
  - Wizard: `name="evilgpj.appkey"`, with the note '"evilgpj.appkey" is a key file of an early kind. …'. No U+202E in the name or the note.
  - Credentials page: `Chosen { file: KeyFileView { name: "evilgpj.appkey", … } }` and `view.key_file=Some("evilgpj.appkey")`.
  - Empty file: `Refused { id: "M07-27", text: "The key file \"badtxt.appkey\" is empty. …" }`. Unlock: `Failed { … id: "M06-07", text: "The key file \"badtxt.appkey\" is empty. …" }`.
  - `rlo=false` everywhere. `KeyFileView.path` keeps the real path (it is needed to read the file), and Swift does not show it: NewVaultView.swift:287 shows `name`.
- **Mutant:** `read_key` returns the raw name: `f_072 … FAILED` at window.rs:469. This is the same mutant the builder ran, repeated as the row's own check.

## F-074: key change reminder and force in the window (MOD-13.7 to MOD-13.10)

- **Steps (the row's):**
  1. Personal with `MasterKeyChangeForce` 60 and `MasterKeyChanged` 153 days ago. GitHub also expired yesterday, to check the order of the notices.
  2. Unlock, Auto-Type, the notices, then Change Now.
  3. T16 (MOD-13.9): the folder made read-only (0500) before the save.

  Rust probe `verify_probe_f074_row_steps_and_t16`. Swift probes `VerifyProbeTests` in the copy, on the Work key-change demo and on a force-once copy of Personal made by `verify_make_forced_personal`.
- **Before** (the row): no prompt and no notice. app-ffi and macos/App had no MOD-13.7 to .10 code.
- **After:**
  - Unlock: `locked=false key_change=Some("This vault requires a new master key: it was last changed 153 days ago, and it requires a change every 60 days.")`.
  - Auto-Type: `autotype_start while forced: Locked { vault: 1 }`. The Swift Auto-Type test plays the alert sound, shows no second panel, types nothing and brings the target back.
  - `after_unlock while forced: AfterUnlock { expiry_search: None, … }`, and `end_key_change before a change: Ok(false)`.
  - **Nothing of the vault on screen (MOD-13.8):** with forced Personal shown, the window's accessibility strings are exactly `["Change Now", "Change the master key of “Personal”", "Lock", "This vault requires a new master key: it asks for a change at this unlock."]`. `leaked=[]` for all 58 entry titles, subtitles, group names and tag names, and `main=nil`.
  - **Change Now and Cancel:** Change Now gives `sheet=changePassword`. The card's Cancel gives `sheet=nil prompt=true main=nil prompt words=true` (MOD-13.8: 'Cancel on the credentials page returns to the prompt'). Change Now works again after that.
  - **T16 (MOD-13.9), Rust:** `change_password: Done`. A save in the read-only folder gives `failure=true changes=1`. Then `end_key_change=Ok(true) key_change=None locked=false unsaved=1`, and the expiry notice comes after the prompt: `after_unlock=AfterUnlock { expiry_search: Some("is:expired-3"), … }`. Auto-Type no longer reports Locked. With the folder writable again, the save works (`changes=0`). The old password no longer opens the file, the new one does, and the request is gone.
  - **T16, Swift (the window's own flow):** `prompt=false main=set unsaved=1 failure=This vault's file or its folder cannot be written. dialog=…saveFailed(…)`. The vault opens, unsaved, with the save error, and a later save stores the new password. T16 had no test before this probe.
  - SSH: tests/ssh.rs `mod13_8_a_forced_key_change_adds_no_key_until_the_key_is_changed` passed. `ssh_unlocked` has 2 callers, `finish` (only when not forced) and `end_forced`. `with_slots` hides a forced vault from Auto-Type. Vault Settings… is refused behind the prompt (AuxWindows.swift:49, the T13 test).
  - The recommended notice: `f_074_recommended_notice_once_per_unlock` and 'F-074, MOD-13.10 …' passed.
- **Mutants (mine):**
  - `take_fresh` ignores the prompt: `f_074_forced… FAILED` at window.rs:374 (the notices came while forced).
  - `with_slots` stops hiding a forced vault: FAILED at window.rs:370 ('Auto-Type: locked').
  - `end_forced` ends without a key change: FAILED at window.rs:375.
  - The interval no longer forces (force-once only): FAILED at window.rs:405.
  - Swift: the vault screen is made behind the prompt: T13 fails at WindowFixesTests.swift:197 (`window.main == nil`).
  - Swift: `applied()` skips `endKeyChange` (run alone): T13 fails at :214 (`window.keyChange == nil && window.main != nil`).
- **Residual 1, for the lead (Low; MOD-13.8 says 'opens the credentials page alone (MOD-12.10)').** Change Now opens only the password card (`KeyChangeModel.changeNow` calls `askPassword()`). The key file and hardware key parts of the credentials page cannot be changed from the prompt, and Vault Settings stays closed behind it.
  - Probe `verify_probe_f074_key_file_only_vault` on keyfile-xml-v2 (key file only) with force-once: an empty password asks `M07-21` 'Use no password for this vault?'. 'Use No Password' then gives `Done`, `end_key_change=Ok(true)`, and the key file kept (`key_file=Some("key-xml-v2.appkey")`).
  - So no vault is locked out, and the forced change can always be met (MOD-13.11: a confirmed change counts even with the same key). But a user who wants a new key file must first meet the prompt with the password card.
  - Smallest fix: show the Security page's credentials section (password, key file and hardware key rows) in the prompt's sheet in place of the password card alone. Or accept this until the hardware key Mac QA.

## SD-13: attachment previews (MOD-05.9, L05-3, LD-65)

- **Steps (MOD-05 case 05-10 and the row's App extra):**
  - In Personal, GitHub got these attachments: `x.html` (the 05-10 script, link and remote image), `x.md` (a Markdown link and a remote image), `x.svg` (a remote image href), and PNGs of 300 × 20, 4,096 × 1 and 4,097 × 1, each with a tEXt chunk.
  - It also got a PNG whose header claims 100,000 pixels wide, a JPEG, a PDF, and a PNG named `.txt`.
  - Each was previewed through `preview_attachment` (probe `verify_probe_sd13_row_steps`). The Swift `PreviewSheet` was drawn offscreen with the markup and with a PNG (probe `sd13Links`).
- **Before** (E13-S1-SD.md): no preview existed. The row's App extra had no story.
- **After (Rust):**
  - x.html, x.md, x.svg: `Text, same as input=true`. The bytes come back as text and nothing is rendered.
  - wide.png: `Image Some((300, 20)) png_signature=true same_bytes_as_input=false tEXt_kept=false`. big.png: `Some((4096, 1))`, written again. png-named.txt: `Image Some((2, 2))`, because the type comes from the bytes and not the name.
  - toobig.png (4,097), huge-header.png, photo.jpg, doc.pdf: `Unsupported`.
  - Locked vault: `Some(Locked)`.
- **After (Swift):**
  - For both the HTML and the Markdown text: `text shown literally=true link nodes=0 image nodes=0 roles=["AXButton", "AXGroup", "AXHeading", "AXScrollArea", "AXStaticText"]`. No link to click, nothing loaded.
  - A 2,000 × 100 PNG: one AXImage labelled with the file name, drawn within the card.
  - The builder's 'SD-13, MOD-05.9, L05-3: Preview shows a text attachment as plain text inside App' passed.
- **Mutants:**
  - Rust (mine): the 1 MiB text cut removed: `sd_13 … FAILED` at window.rs:513.
  - Swift (mine): PreviewSheet draws the text as Markdown (`Text(LocalizedStringKey(text))`). My probe then shows `text shown literally=false link nodes=2`, but the builder's sd13 test **passes**, because its attachment has no markup. SwiftLint's `no_markdown_text` rule (AT-E01) refuses the mutant: 'PreviewSheet.swift:39:22: error: No Markdown or interpolated Text keys … (no_markdown_text)', exit 2. So the guard holds in the checks.
  - Test note: the Swift test should preview markup with a link and check that no AXLink appears, as my probe does.
- **Notes for the lead:**
  - **The SD-13 row in plan/security.md still says todo.** App's extra is built and re-tested here, and the lead may set it to verified with a pointer to this file. I did not edit plan/security.md, which is not on my file list.
  - **MOD-05.9 parts not built:** zoom (ponytail comment in PreviewSheet.swift), Open and Save from the preview, and an update while the preview is open. None is a security gap.
  - **JPEG shows 'cannot be shown'.** LD-109 refuses JPEG on purpose, so this follows the later ruling (LD-65 lists JPEG).
  - **The decode runs on the main thread** (`VaultModel.previewAttachment` calls Rust synchronously). An image of up to 4,096 × 4,096 means a 64 MiB RGBA buffer and a short stall.
  - **LD-220 (1) should name `preview_attachment`** as an allowed crossing (the Show value). This was carried from the builder and Checker 1.

## Full Swift suite

`xcodebuild test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` in the copy, at load average 35 to 75 -> '✘ Test run with 310 tests in 42 suites failed after 318.281 seconds with 3 issues'. The 310 are the tree's 307 tests plus my 3 probes.

- Every test named after a finding (`F-0…`, `SD-13`) and my probes passed: 28 passed, 0 failed.
- Failure 1: 'FEA-01.34: a search on big-10000 updates the list in under 50 ms …', at ScreenTests.swift:160 and :171. This is a speed test of the search, which part d did not change. Run alone at load average 52, it failed again: 'FEA-01.34 search worst: 0.12774525 seconds before rating, 0.123189875 seconds after rating'. The builder measured 0.017 s alone at a lower load. Not part d's: re-run it alone on a quiet Mac.
- Failure 2: 'Parity dialogs-delete-forever …', at ParityEditorPagesTests.swift:211. Run alone: '✔ … passed after 2.799 seconds'. It failed under load only.
- `cargo clippy --locked -p app-core -p app-platform -p app-ffi --all-targets --features app-ffi/net -- -D warnings` in the copy (probe module removed) -> 'No issues found'.

## Findings and notes for the lead

1. **Residual (Low), F-074 / MOD-13.8:** Change Now offers the password card only, not the whole credentials page. See residual 1 above for the smallest fix, or accept it.
2. **Test note (Low), F-083:** the screen-change test uses a 1 s window. It missed the fix undone once in a parallel batch at load average 47, and catches it when run alone.
3. **Test note (Low), SD-13:** the Swift preview test uses a plain-text attachment, so a Markdown-rendering PreviewSheet passes it. Only SwiftLint's AT-E01 rule refuses such a change. Add a markup-with-link case.
4. **SD-13 row** in plan/security.md: set it to verified (App's extra built and re-tested). MOD-05.9's zoom, Open and Save from the preview, and the live update are not built.
5. **Mac QA (owner's go):** F-076's native Caps Lock read, and the disk-change sheet's secure field.
6. **Not part d's:** FEA-01.34 fails its 50 ms limit at load average 52 (0.128 s), and should be re-run on a quiet Mac. The window tests' `copy()` helper leaves an `app-ffi-window-<pid>` folder in the OS temp folder on every run, which Checker 1 already reported.

## Cleanup

- Deleted `/tmp/e13s6d-verify-copy`, `/tmp/e13s6d-verify-target`, `/tmp/e13s6d-verify-dd`, `/tmp/e13s6d-verify-scripts` and every `/tmp/e13s6d-verify-*.log`. Afterwards `ls -d /tmp/e13s6d-verify*` finds nothing.
- In the OS temp folder I deleted the 9 folders my own runs left, and the DerivedData lock file. I could tell a folder was mine from its time and its contents: a run filtered to one test copies only that test's vault.
  - The folders: `app-ffi-window-86869` (my full lib run), `-21219`, `-22908`, `-28923`, `-32738`, `-38203`, `-40505` and `-43806` (the mutant runs), and `app-ffi-window-key-46341` (the F-072 mutant panicked before its own cleanup).
  - None of those PIDs was running.
  - The probes delete their own `e13s6d-verify-probe-*` folders. I left every other agent's temp folder alone.
- The shared tree's product code is unchanged. My edits: this file, my 8 rows in security/findings.md, and one appended clause in the E13-S6 status line of plan/epics.md. `scripts/check-names.sh` -> 'names: PASS (3183 files scanned, 16 vault files name-only)'.
