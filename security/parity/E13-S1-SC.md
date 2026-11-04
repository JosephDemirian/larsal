# E13-S1 Parity sign-off: Clipboard and screen (SC-01 to SC-08)

Story: E13-S1 (final verification fleet, parity group SC). Rows: the SC table in [plan/security.md](../../plan/security.md). Attacks: AT-D01 to AT-D04 in [plan/attacks-and-checks.md](../../plan/attacks-and-checks.md).
Date: 2026-10-29. Role: Verify. I re-read the reference source for each row and ran the reference command line tool (`estimate` only, throwaway HOME under /tmp). Every check of App below ran today on a copy of today's tree.

| Row | Result |
|---|---|
| SC-01 timed clear | **Verified for every copy action** (cleared at 10 s while still App's, newer content kept). **Fails one part:** text selected in the editor's Notes and copied with ⌘C goes to the clipboard with no marker and is never cleared. The reference marks and clears that copy. Finding 1, High. |
| SC-02 concealed markers | **Verified** (Mac QA open: a real clipboard history app, Universal Clipboard). |
| SC-03 clear on lock and quit | **Verified** (Mac QA open: ⌘L and ⌘Q in the real app on the general pasteboard). |
| SC-04 masking | **Fails.** Passwords are masked by default everywhere, and Mask User Names works. But the Settings switches "Hide notes" and "Hide one-time codes" change nothing on screen. Finding 2, High. Row stays todo; E5-S11 is not signed either. |
| SC-05 hidden from capture | **The product passes every check I can run without the owner's screen.** The row waits for E6-S5's sign-off (its Verify failed on 2 test-design points; the fix is at "Checker next"), then for Mac QA of the real capture paths. Row stays todo. |
| SC-06 strength while typing | **Verified.** The editor, the new vault form, Vault Settings' password change and the generator all rate while typing. The level equals the reference tool's for 8 of 8 samples. |
| SC-07 command line copy | **Verified** on the private pasteboard (Mac QA open: the release tool on the general pasteboard). |
| SC-08 search cleared after idle | **Verified** (Mac QA open: real focus loss in a key window). One Low card difference (finding 3). |

## Setup and rules kept

- **Private copy.** I ran `rsync -a --exclude target --exclude app-shots --exclude fuzz/target` of the tree to `/tmp/e13s1-SC-copy` at 20:43. It had its own `CARGO_TARGET_DIR=/tmp/e13s1-SC-target` and derived data `/tmp/e13s1-SC-dd`. `scripts/build-core.sh` ran in the copy only and printed `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`. `xcodebuild build-for-testing` printed `** TEST BUILD SUCCEEDED **`.
- **The copy matched the tree.** At 21:01, `cmp` showed these files identical to the project tree:
  - `clipboard.rs` (sha256 430197c4fa8bcb4a), `macos/pasteboard.rs` (8721f0801785f74f), `app-ffi` `session.rs` and `app_settings.rs`;
  - `Copy.swift`, `MainWindowModel.swift`, `DetailFields.swift`, `EditorProtected.swift`, `EditorEntryPage.swift`, `EditorModel.swift`, `ViewOptions.swift`, `AppSettingsParts.swift`, `VaultView.swift`, `Platform/ScreenProtection.swift` and `AppDelegate.swift`.
  - Two files had changed in the tree since the copy: `app-cli` `commands.rs` (F-066 title masking in `ls`) and `app-ffi` `edit.rs` (formatting only in tests). Neither touches `clip` or the rating.
- **Probes.** The probes lived in the copy only:
  - `macos/AppTests/VerifyE13S1SCProbeTests.swift` (two Swift tests);
  - one Rust test appended to the copy's `crates/app-ffi/tests/clipboard.rs`;
  - three tools in `/tmp/e13s1-SC-work/tools`. `pbread` reads only pasteboards named `com.app.clipboard.<pid>.<n>`. `winstates` reads only window-list rows of one PID, never pixels. `gencount` prints only the general pasteboard's change count, never its contents.
- **Rule 10.**
  - No screen capture. No window was ordered front. App was launched only with `open -n -g -j` and `APP_TEST_HIDDEN`. The front app was the owner's before and after every launch (`lsappinfo front`). Swift tests render at x −20000.
  - Swift tests ran with `TEST_RUNNER_APP_TEST_INSTANCE_DIR`, so their settings went to `/tmp`, never to `~/Library/Application Support/App`.
  - The general pasteboard was never written. Each of my runs was bracketed with change-count reads, and none changed the count: the Swift run 10909 → 10909, `app clip` 10914 → 10914, the hidden launches 10917 → 10917, the last Swift run 10918 → 10918. Between my runs, the count rose while the owner worked; no run of mine was going then.
  - The reference's `clip` was never run, because it writes the general pasteboard. Its side comes from the source.
- **Rule 11.** Every App I launched ended by itself. `pgrep` for my App path was empty afterwards, so no `kill` was needed.

## SC-01 Clears a copied value after a set time

**Reference, in my words.** Every copy action puts the text on the clipboard. When "clear clipboard" is on (default on, 10 s; range 1 to 999), a one-second timer counts down. The status bar shows a progress bar with "Clearing the clipboard in N second(s)…". At 0 the clipboard is emptied, but only if its text still equals what was copied. With the setting off, nothing is cleared. A ⌘C with selected text also goes through the same routine, marked and cleared, when the focus is in one of three places: the editor's multi-line notes box, the entry preview's notes box, or a selectable preview label. A single-line field in the editor uses the toolkit's own copy, with no marker and no timer.

**App.**
- **Settings.** `clipboard.clear.enabled` is on and `clipboard.clear.seconds` is 10, range 1 to 999 (`app_settings.rs:166`).
- **Rust, private pasteboards.**
  - `cargo test -p app-platform --lib clipboard`: `test result: ok. 7 passed; 0 failed`. The 7 tests include `countdown_clears`, `new_copy_restarts_countdown`, `countdown_leaves_newer_content` and `clear_only_while_still_ours`.
  - `cargo test -p app-ffi --test clipboard`: `test result: ok. 10 passed; 0 failed`.
- **The default 10 s, read from another process** (probe `verify_e13s1_sc_default_countdown_cross_process`; the session uses the default settings):

```
SCPROBE answer Copied { label: "Password", seconds: 10, empty: false }
SCPROBE at 537.811792ms:  com.app.clipboard.44846.0 … public.utf8-plain-text bytes=11 text="demo-pass-1"
SCPROBE at 9.525569584s:  com.app.clipboard.44846.0 … public.utf8-plain-text bytes=11 text="demo-pass-1"
SCPROBE at 10.735827334s: (nothing)
```

- **Swift.** `ScreenTests` "APP-03.7, APP-03.15, APP-03.21: Edit > Copy copies the password; the notice goes; quit locks every vault" passed. Its notice reads "Password copied. Clears in 10 s." App shows this notice instead of a countdown bar (APP-03.11, LD-181 (1)). That is a difference in looks, not in protection.
- **Selected text (the failing part).** A code read of today's tree:
  - The detail pane has no selectable text: no `textSelection` anywhere in `macos/App`.
  - The editor's Notes is a SwiftUI `TextField(axis: .vertical)` (`EditorProtected.swift:73`). Its selection lives in an `NSTextView` field editor.
  - `MainWindowModel.copyCommand()` (Edit > Copy, ⌘C) checks `(key?.firstResponder as? NSTextView)?.selectedRange().length > 0`. With a selection it calls `textCommand(#selector(NSText.copy(_:)))`. That is AppKit's plain copy to the general pasteboard: no concealed or transient marker, no countdown, and lock and quit do not clear it.
  - So notes text selected in the editor and copied stays on the clipboard. The reference marks it and clears it after 10 s.
  - LD-181 (5) assumed "no unprotected vault text is selectable". The editor fields make that untrue. LD-219 (4) routes the fix (`copy.selection` in Rust) to the E5 follow-up batch, which is still todo.
  - I did not run this path live: it would write the owner's general pasteboard.

**Result:** verified for all copy actions; the selected-text part fails (finding 1). The real-app run on the general pasteboard is Mac QA (owner's go).

## SC-02 Marks copies so clipboard managers skip them

**Reference.** On the Mac it adds `org.nspasteboard.ConcealedType` next to the text. The concealed type's data is the text itself. It adds no transient marker and does not limit the copy to the current host.

**App.**
- The cross-process read above shows one item with three types: `org.nspasteboard.ConcealedType bytes=0`, `org.nspasteboard.TransientType bytes=0` and the text. The markers are empty, so the secret is not in them.
- `copy_writes_text_and_both_markers` passed.
- Current host only, by code read: `pasteboard.rs:68` calls `prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly)` before the write.
- App goes further than the reference: it adds the transient marker, keeps the concealed marker empty, and stays on this host.

**Result:** verified. A real clipboard history app and Universal Clipboard are Mac QA.

## SC-03 Clears its clipboard value on lock and quit

**Reference.** A vault lock calls the clipboard clear, and so does the app's about-to-quit signal. Both clear only while the clipboard text still equals the copied text.

**App.**
- `app_03_15_lock_close_and_quit_clear` passed. Quit, lock-all, lock and close each clear App's copy, and content another app wrote after the copy stays. `app_03_15_lock_of_another_vault_clears` passed too.
- Swift: `LockSignalsTests` "APP-02 T52, APP-03.15: a lock signal clears the clipboard in Rust, shown values and live codes" passed.
- `ScreenTests` "…quit locks every vault" passed: `quit()` locks every vault, then clears.

**Result:** verified. ⌘L and ⌘Q in the real app on the general pasteboard are Mac QA.

## SC-04 Masks passwords by default; options to hide user names, notes and codes

**Reference.** Defaults:

| Setting | Default |
|---|---|
| Hide passwords in the list | on |
| Hide passwords in the preview | on |
| Hide passwords in the editor | on |
| Hide user names | off |
| Hide notes | off |
| Hide one-time codes in the preview | off |
| Show dots for empty passwords | off |

- With "hide user names" on, the preview shows the user name behind a show button, and the list masks it.
- With "hide notes" on, the preview's notes box is empty with a show button, the editor's notes box is hidden behind a reveal button, and the list's notes column is masked.
- With "hide one-time codes" on, the preview's code stays hidden until its button is pressed.

**App, the swept probe** (`VerifyE13S1SCProbeTests` "SC-04 probe", Personal demo vault, entry GitHub):

```
SCPROBE defaults: settings hide_notes=false hide_totp=false hide_password_in_preview=true hide_password_in_editor=true
SCPROBE defaults detail: password on screen=false notes on screen=true code 602 023 on screen=true
SCPROBE hide_notes=true hide_totp=true: detail notes on screen=true code 723 145 on screen=true password on screen=false
SCPROBE walk with notes and code as secrets: 1 hits
SCPROBE editor (hide_notes on): password on screen=false shownPassword nil=true notes on screen=true
```

- **Passwords.**
  - The list has no password column: it shows the strength only, as App's own offscreen render of the unlocked hidden launch shows. So passwords are always masked there.
  - The detail shows dots until Show.
  - The editor opens masked (`shownPassword` nil).
  - All three are stricter than or equal to the reference.
- **User names.** `MenuKeysTests` "APP-08.8 APP-01.23 APP-08.25: Mask User Names hides the user name in the list and detail until Show", "…hides the editor's Passkey row and the History sheet's user name" and "…hides the network name in the Wi-Fi QR dialog's title" all passed. E5-S11, which builds this, is at "Checker next".
- **Notes and one-time codes (fail).**
  - `display.hide_notes` and `display.hide_totp_in_preview` are read only by the Settings switches (`AppSettingsPages.swift:183`, `:185`).
  - The detail's Notes row draws `notes.value` without a check (`DetailFields.swift:189` to `:195`), and so does the code row (`CodeRow`). The editor's notes field has no check either.
  - The probe shows notes and code on screen with both switches on.
  - E5-S9's inventory says "Stored; the list and pane follow (APP-01.23) in a later pass". No story in plan/epics.md owns that pass.
  - `display.dots_for_empty` (S-CONV-01) is not applied either. It only shows whether a password is empty (finding 4, Low).

**Result:** failed (finding 2). The row stays todo.

## SC-05 Hides every window from screen capture

**Reference.** On the Mac, each window's sharing type is set to none, so it is left out of captures. A View menu toggle "Allow Screen Capture" and the start flag `--allow-screencapture` allow capture for the run; it is never saved. Protection is applied when a window gets focus, and to every visible window when the toggle changes. The failure warning never shows on the Mac, because the call always reports success.

**App.**
- **Swift tests.** `ScreenProtectionTests` passed: 13 tests, the list tests included. Among them: "the window list is complete", "every kind of window in the list is protected, and read only when allowed", "before its first frame a window is protected", "F07 starts every window allowed", "View > Permit Screen Capture is checked exactly while capture is allowed" and "every show in a function needs that window adopted before it".
- **Hidden debug App, the window server's sharing state** (`kCGWindowSharingState`; 0 = none, 1 = read only). Each launch used `open -n -g -j`, its own instance folder and a copy of the Personal demo vault:

| Run | Args | App's windows |
|---|---|---|
| locked | vault | 95542: 0 from 0×0 on. 95543 (made by AppKit): 1 while 0×0, then 0 before it had a size (as E6-S5 found: the run loop pass) |
| f07 | `--allow-screen-capture` | 95551: 1. 95552: 1 |
| after-f07 | vault (next start) | 95554: 0. 95556: 0 |
| alias | `--allow-screencapture` | 95563: 1. 95564: 1 |
| unlocked | `--password-stdin` | 95565: 0 (the render shows the unlocked Personal vault) |
| unlocked2, locked2 | as above | 0 (change count bracketed, unchanged) |

- Every process ended by itself in about 2.1 to 2.7 s. The front app was unchanged across each launch.
- App protects each window when it is created; the reference waits for focus. So App goes further here.

**Result:** the product behaves as the row says. The row stays todo:
- E6-S5's Verify failed on two test-design points, and the fix waits for its Checker;
- the real capture paths (`screencapture`, ScreenCaptureKit, screen sharing) and the toggle in the running app are Mac QA (owner's go).

## SC-06 Shows password strength while the user types

**Reference.** The editor's password field and the master password field show a quality bar that updates on every change. Its value is the estimate's bits, and its colour and tooltip show Poor (also for Bad), Weak, Good or Excellent. Thresholds: ≤0 Bad, under 40 Poor, under 75 Weak, under 100 Good, else Excellent. The generator shows the same while its text changes. The estimate gets no user inputs.

**Side by side, estimate** (the reference tool's `estimate` and `app estimate`, each reading the password on stdin):

| Password | Reference bits | App bits | Level (both) |
|---|---|---|---|
| correct horse battery staple | 70.881 | 61.016 | Weak |
| Summer2024! | 19.087 | 16.074 | Poor |
| alex-dev | 28.872 | 24.704 | Poor |
| Tr0ub4dor&3 | 46.711 | 44.750 | Weak |
| x7#Kp2!vQ9zL | 76.050 | 75.590 | Good |
| aaaaaaaaaaaa | 5.585 | 8.285 | Poor |
| demo-new-1 | 37.343 | 33.177 | Poor |
| Hn7$wQ2!cV9#tR4@yB6x | 112.160 | 109.400 | Excellent |

The levels are equal for 8 of 8. The bits differ as D-05-1 allows: level parity is the contract (FEA-05.19).

**While typing** (probe "SC-06 probe"; the editor waits for an empty rating between words):

```
editor typed 28 chars "correct horse battery staple": Weak 61 bits
editor typed 11 chars "Summer2024!": Poor 16 bits
editor typed 8 chars "alex-dev": Poor 1 bits      (GitHub's own user name: LD-44, stricter)
editor typed 11 chars "Tr0ub4dor&3": Weak 45 bits
editor typed 12 chars "x7#Kp2!vQ9zL": Good 76 bits
editor typed 12 chars "aaaaaaaaaaaa": Poor 8 bits
editor typed empty: nil
new vault typed …: Weak 61, Poor 16, Poor 25, Weak 45, Good 76, Poor 8
vault settings typed …: Weak 61, Poor 16, Poor 25, Weak 45, Good 76, Poor 8
```

- `ParityGeneratorTests` "typing over the value rates the text; Use takes the edit (FEA-02.16, D-03-7)" passed.
- `NewVaultBehaviourTests` "Parity vault-new-vault-step-3…" passed.
- How the meters are drawn was proven by the E5-S5, E5-S6 and E5-S8 parity frames (all Done).

**Result:** verified.

## SC-07 Command line copy

**Reference.** `clip` runs the system copy tool with the value, so the copy has no marker. The default wait is 10 s. A timeout of 0 or less means the value stays. The tool counts down in the terminal, then runs the copy tool again with an empty text, whatever the clipboard holds by then. If the process is stopped first, nothing is cleared.

**App.**
- `cargo test -p app-cli --test int10 -- int10_29 ld178_1`: `test result: ok. 10 passed; 0 failed`. The 10 tests:
  - `int10_29_a_copied_with_markers_then_emptied`: three types, then empty after the delay;
  - `int10_29_a_countdown_on_a_terminal_pty`;
  - `int10_29_b_newer_content_is_left_alone`;
  - `int10_29_c_zero_seconds_leaves_the_value`;
  - `int10_29_d_quit_signal_clears_at_once`;
  - `_e`, `_f`, `_g`, `_h`;
  - `ld178_1_ignored_sigint_does_not_cut_the_clip_wait`.
- **The default 10 s, black box** (`APP_TEST_PASTEBOARD=1 app clip personal.appvault Email/Google`, no timeout given, read by `pbread` from this shell):

```
-- copy + 9.028 s
com.app.clipboard.52642.0 changeCount=1 item0 org.nspasteboard.ConcealedType bytes=0
com.app.clipboard.52642.0 changeCount=1 item0 org.nspasteboard.TransientType bytes=0
com.app.clipboard.52642.0 changeCount=1 item0 public.utf8-plain-text bytes=20 text="Hn7$wQ2!cV9#tR4@yB6x"
-- copy + 10.821 s
(empty)
stdout: Password of Email/Google copied. The clipboard is emptied in 10 seconds.
        The clipboard is empty again.
exit 0
```

- The test switch is read only under `#[cfg(debug_assertions)]` (`commands.rs:665` in the tree at 21:01). E12-S1 found 0 `APP_TEST` strings in the release tool.
- App goes further: the copy is marked, it is cleared only while still App's, and it is also cleared on a quit signal.

**Result:** verified. The release tool on the general pasteboard is Mac QA.

## SC-08 Clears the search box after it loses focus

**Reference.** The option is off by default; the delay is 5 minutes, range 1 to 1,440. When the search box loses focus, a single-shot timer starts. Focus back stops it. A change of selected entry or of view mode restarts a running timer from full. At the end the search is cleared.

**App.**
- **Settings.** S-TIME-05 `search.clear_when_idle` is off by default, and S-TIME-06 `search.clear_after_minutes` is 5, range 1 to 1,440.
- **Code read.** `SearchClearTimer` (`AppSettingsParts.swift:125`) is driven by `.onChange(of: focused)`, and a new selection restarts it (`VaultView.swift:194` to `:199`).
- **Test.** `AppSettingsEffectsTests` "APP-01.27 a, b: the search clears a while after the field lost focus; focus back stops it" passed. It covers: off by default, so never cleared; focus back stops the timer; cleared after one shortened minute; 20 minutes not cleared early.
- **Difference.** App does not restart the timer when the screen changes, for example when the editor opens (APP-01.27 says "or of screen"). So the search clears earlier, never later: stricter, a card difference (finding 3, Low).

**Result:** verified. A real focus loss in a key window is Mac QA.

## Findings (for the lead; security/findings.md not edited)

1. **High, SC-01: selected editor notes are copied unmarked and never cleared.**
   - Steps: select text in the editor's Notes field and press ⌘C or Edit > Copy. `copyCommand()` takes the plain AppKit copy. The text lands on the general pasteboard with no concealed or transient marker and no countdown, and lock and quit leave it there.
   - The reference marks the same copy (from its editor notes box and its preview notes and labels) and clears it after the timeout.
   - Smallest fix: LD-219 (4). With a selection in a vault view's text, `copyCommand()` passes the selected text to a Rust `copy.selection` that uses `Clipboard::copy` with the countdown, and adds a Swift test. Until then, SC-01 is not complete.
2. **High, SC-04: the Hide notes and Hide one-time codes switches do nothing.**
   - Steps: Settings > Security > turn on Hide notes (S-CONV-05) and Hide one-time codes (S-CONV-04). The detail pane still shows the notes and the live code in clear, and the editor still shows the notes (probe output above).
   - The reference hides both behind a show button.
   - Smallest fix: read both flags where the detail's Notes row and `CodeRow` are drawn, and in the editor's notes field. Show the notes behind a Show button (the masked row App already has) and the code behind a show button, as APP-01.23 says. Add a test per switch. Give the pass a story or put it in the E5 follow-up batch, because no story owns it now.
3. **Low, SC-08: a change of screen does not restart the search-clear timer** (APP-01.27). Smallest fix: also call `clearer.focus(false, model)` while the timer runs when the editor opens or closes, or change the card to say App does not restart. Not a security weakness: App clears earlier.
4. **Low, SC-04: "Show dots for empty passwords" (S-CONV-01) is stored but not applied.** With it on, the reference hides whether a password is empty. Smallest fix: draw dots for an empty password while the switch is on, together with finding 2.

## Mac QA (owner's go)

- AT-D01: a real clipboard history app. Universal Clipboard.
- AT-D02 and AT-D03 in the real app on the general pasteboard: copy and wait 10 s; copy then ⌘L; copy then ⌘Q.
- AT-D04: each capture path, and View > Permit Screen Capture in the running app.
- The release `app clip` on the general pasteboard.
- A real focus loss of the search field.

## Cleanup

- I deleted `/tmp/e13s1-SC-copy`, `/tmp/e13s1-SC-target`, `/tmp/e13s1-SC-dd`, `/tmp/e13s1-SC-work` and `/tmp/e13s1-SC-home`.
- I removed the copy's App from Launch Services first (`lsregister -u`).
- The shared `/tmp/e13s1-target` was only read: I used its debug `app` to list the demo vault.
