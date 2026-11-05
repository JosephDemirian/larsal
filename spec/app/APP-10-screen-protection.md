# APP-10 Screen protection and secure input

Status: reviewed; scoped capture wording/case correction reviewed and independently verified as written-contract-only E21-S1 work, jointly adopted in d413e06 (2026-11-05). Secure-input rules and historical evidence are unchanged; actual capture QA remains OPEN and no prior SC-05/AT-D04 evidence is re-signed.
Epics: E6-S5, E5-S3
Parity rows: SC-05, SR-06

## What it does

A legacy per-window sharing setting and secure input, with different limits against other programs running as the same user. In this card “protected” means the legacy sharing property was applied, never a guarantee that a capture path excludes pixels.

1. **Window-sharing setting.** Apply the legacy `.none` property on every Larsal-created window before its first frame, every start. A start flag or View menu action chooses `.readOnly` for this run only; that choice is never saved. Public macOS APIs do not guarantee exclusion from screenshots, recordings or sharing. Record each real capture path and OS/tool version; a property read-back is separate evidence.
2. **Secure input.** While the keyboard focus is in a password field of Larsal, macOS secure event input is on, so other programs (event taps, key loggers) do not receive the keystrokes. It goes off as soon as the focus leaves the field or Larsal stops being the active app.

The start flag itself is listed in APP-09 (F07). Menus and shortcuts are APP-08. The Caps Lock warning on password fields is APP-06.

Both mechanisms belong to the Swift side of the native app (Decided: spec/decisions.md LD-155, LD-156 (7), LD-200 (2)): it sets each window's sharing type and makes the secure input calls. The Rust core takes no part in either.

## Inputs and outputs

- In: window creation and key-window changes from AppKit; the start flag F07 (APP-09); the View menu action ACT-ALLOW-CAPTURE; focus in and out of password-kind fields, seen by the Swift views; Larsal activation and deactivation (`NSApplication.didBecomeActiveNotification`, `didResignActiveNotification`); lock and quit.
- Out: each window's macOS sharing type; the process's secure event input state; the error banner M10-01 when applying the requested `.none` property fails its read-back, not when a capture is detected.

| ID | What | Values | Default |
|---|---|---|---|
| ACT-ALLOW-CAPTURE | View menu action, label "Permit Screen Capture", checkable | checked = `.readOnly` requested; unchecked = legacy `.none` requested | unchecked at every start, unless F07 |
| F07 | Start flag `--allow-screen-capture` (APP-09) | present or absent | absent |

| ID | Where | When | Text (Larsal) |
|---|---|---|---|
| M10-01 | Error banner in the main window | The requested `.none` property did not read back while allowance is off | Warning: Larsal could not apply its window-sharing setting to one of its windows. |

There is no message, indicator or confirm for allowing capture, and none for secure input (D-APP10-2).

## Rules

APP-10.1 **Property applied from creation.** Set legacy `.none` on every Larsal window before its first frame, every start, unless F07 requests `.readOnly`. The current run state is never saved; no setting, settings file or environment variable can persist an allowance across launches (D-APP10-1). First-frame property coverage is required, not first-frame capture exclusion.

APP-10.2 **macOS mechanism and limits.** Swift sets `NSWindow.sharingType` to `.none` (`NSWindowSharingNone`) while allowance is off, `.readOnly` (`NSWindowSharingReadOnly`) while it is on (LD-156 (7)); the legacy window-list values are `kCGWindowSharingState` 0/1. Read these as property evidence only. [Apple's current enum](https://developer.apple.com/documentation/appkit/nswindow/sharingtype-swift.enum) describes `.none` as legacy, and [Apple DTS](https://developer.apple.com/forums/thread/792152) states that no public API prevents screen capture. No promised blank/omitted image follows from state0; no promise that the toggle controls every capture path. V-A10-1/AT-D04 real captures remain open Mac QA with the owner's go. For every observation record actual OS/build, framework/tool and version, screenshot/recording/sharing path, run allowance and property/read-back, and observed **blank / omitted / shown** pixels. Do not infer this Mac's current path outcome from old observations or a version mentioned in this card; no real capture ran for this revision.

APP-10.3 **Every window.** The requested sharing-property state applies to every window Larsal creates: the main window, sheets, dialogs, alerts, popovers, menus Larsal draws itself, and any secondary window (generator, Auto-Type picker, site access and passkey prompts, reports). It is set when the window is created, not when it first gets focus. File open and save panels show only file names; applying their sharing property is optional. System-drawn surfaces (the menu bar, notifications, the Dock) are outside Larsal's control, so Larsal never puts a secret there. Reference: when the toggle changes, it sets every visible top-level window; it also sets a window each time that window gets focus. Windows that never take focus (tooltips, completion lists, popup menus) and a window's first moments before focus are therefore not covered there. Larsal applies the property to those windows before their first frame; this closes the property-application gap, not the platform capture limit.

APP-10.4 **Run-only allow action.** ACT-ALLOW-CAPTURE sits in the View menu, checkable, checked when `.readOnly` is requested. It is shown where Larsal implements this per-window property (macOS); its presence does not certify capture prevention. Changing it applies at once to every open window; windows created later follow the current state. The state lasts until quit and is never saved. It has no default shortcut; the user may assign one (APP-08). The check mark is its only indicator. Reference: the same action, place and behavior, with its own label.

APP-10.5 **The start flag.** F07 starts Larsal with ACT-ALLOW-CAPTURE checked; every window is then created allowed. A secondary launch ignores F07 (APP-09.10). If Larsal ever relaunches itself, the new process again requests `.none`. Reference: the same flag; its self-relaunch drops all flags, so the legacy `.none` request comes back on.

APP-10.6 **When property application fails.** AppKit's `sharingType` setter reports no failure, so Larsal reads the window's `sharingType` back right after it sets it. When the value read back is not `.none` while capture is not allowed, Larsal shows M10-01 in the main window, each time it happens. The window stays open. The banner covers a read-back mismatch only. It is not capture detection and must not appear merely because a recorder shows a window despite `.none`; such pixels are the path observation of .2. The revised banner text is proposed wording, not a runtime change made by this card. Reference: the same banner; on macOS its protect call cannot report failure, so the banner never appears there.

APP-10.7 **Independent of vault state.** Locking, unlocking, switching vaults, minimizing and hiding do not change the sharing-property state. The unlock screen receives the property like every other view.

APP-10.8 **Secure input: when it is on.** Secure input is on exactly while all of these hold: the keyboard focus is in a password-kind field (APP-10.9), that field's window is Larsal's key window, and Larsal is the active application. It goes off when any of them stops: focus leaves the field, the field is hidden or removed, another window takes key status, the user switches to another app, the window closes, the vault locks, Larsal quits. It does not depend on whether the field shows its text (Show) or dots. Reference: it follows the field's focus-in, focus-out and hide events; leaving the app gives a focus-out, so it also goes off on app switch.

APP-10.9 **Password-kind fields.** Every field that holds a password or another typed secret counts: the master password on the unlock screen (APP-06); both new master password fields when creating a vault (APP-07) or changing credentials; the entry editor's password field; the generator's password field; the password fields of import (FEA-08) and shared groups (INT-08); the pick-characters dialog of Auto-Type (INT-05). In the Swift screens each such field is one of Larsal's password field views (masked: a secure text field; shown: the plain field that takes its place while Show is on, or a secret field Larsal draws as plain text); every such view counts, and new secret fields must use one. Reference: all of the fields above use one shared password field, and secure input is part of it, so every one of them turns it on.

APP-10.10 **macOS mechanism for secure input.** Larsal uses the system secure event input (`EnableSecureEventInput` and `DisableSecureEventInput`). While it is on, keyboard events go only to Larsal; event taps and key loggers of other processes receive no key events. The OS keeps one counter per process and secure input stays on until it returns to 0. Larsal's own calls (APP-10.11) add at most 1 to that counter: Larsal calls enable only when its own state is off, and disable only when its own state is on. Reference: tracks its own flag; on enable it first disables when its flag says on, then enables; on disable it always calls disable, even when its flag says off.

APP-10.11 **The Swift side owns secure input** (LD-156 (7)). A masked secure field turns it on by itself while it has focus; Larsal's own call covers a password-kind field that is not masked (Show on, or a secret field Larsal draws as plain text), and Larsal turns its own call off on focus out, window close, app deactivation, lock and quit, whatever the field reports. Larsal does not rely on the field alone: the shown field is a plain text field, which turns nothing on, and APP-10.8 says secure input must stay on. That the masked secure field turns secure input on and off by itself with its focus, and that its calls and Larsal's own never leave the counter above 0 after both end, needs Mac QA (owner's go), V-A10-2: it takes a focused secure field in Larsal's key window; the SDK documents only the counter (as many disables as enables), not what the secure field calls.

APP-10.12 **Never left on in the background.** Secure input held by a process that is not the active app blocks keyboard shortcuts and input methods in other apps. After Larsal deactivates, locks or quits, Larsal holds no secure input. If Larsal ends abnormally, the OS releases it for the dead process (Verified 2026-10-28, V-A10-3: the SDK's notes on the secure input calls say it is turned off by itself when the program crashes, unless another program has it on too; on this Mac a probe that turned it on and was killed with `kill -9` left no holder).

APP-10.13 **Only while Larsal is active.** Secure input that Larsal turns on with its own call stays on only while Larsal is the active app (Decided: spec/decisions.md LD-200 (10)). When Larsal resigns active (`NSApplication.didResignActiveNotification`), Larsal turns its own call off at once, whatever the focused field reports. When Larsal becomes active again (`didBecomeActiveNotification`) and a field of APP-10.11 still has the focus in the key window and is not masked, Larsal turns it back on. This holds for every place that makes the call (unlock screen, entry editor, dialogs).

## Edge cases and errors

- **Several Larsal windows:** focus moves from the unlock screen's password field to a dialog without a password field: secure input goes off; back in the field: on again.
- **Focus moves from one password-kind field to another** (new password to repeat): Larsal may turn it off and on, or keep it on, but the counter from Larsal's calls never goes above 1.
- **Screen locked or user switched while the field has focus:** Larsal deactivates or locks (APP-02), so secure input goes off.
- **The field is shown while focused** (Show): secure input stays on (APP-10.8).
- **Allow toggled while a sheet or popup is open:** that window changes too (APP-10.3, APP-10.4).
- **Minimized window in the Dock:** the Dock may show a blank or a picture of a protected window. Needs Mac QA (owner's go), V-A10-4: it takes a protected window minimized into the Dock on screen.
- **Capture-path limits:** the public API supplies no universal exclusion guarantee. Verify records each actual path/version outcome under AT-D04, including shown pixels while `.none` reads back. Note that limit in help; do not treat it as an unobserved property failure, an automatic hide signal or a new M10-01 trigger (D-APP10-3).
- **The reference's own launch flag after its relaunch:** see APP-10.5.

### Lead decisions

- **D-APP10-1 Saved setting or start state.** plan/security.md lists "Hide window from screen capture: On" among the settings. (a) Start state only, as the reference does: protected at every start, allowed only by F07 or ACT-ALLOW-CAPTURE for one run; (b) a saved setting. Recommend (a): no saved choice can persist the run-only `.readOnly` allowance; APP-01 lists it as a start state, not a setting. Decided: spec/decisions.md LD-200 (as recommended).
- **D-APP10-2 Warning when capture is allowed.** (a) The check mark only, as the reference does; (b) a banner while allowed. Recommend (a). Decided: spec/decisions.md LD-200 (as recommended).
- **D-APP10-3 A capture path that leaks.** (a) Note the OS limit in Larsal's help; (b) hide vault content while any capture is active. Recommend (a): macOS gives no reliable signal that capture is running. Decided: spec/decisions.md LD-200 (as recommended).

### Not on Mac

- Windows: the historical reference contract uses display affinity "exclude from capture"; a failed call shows its banner. This is not proof of a Larsal Windows implementation or universal path exclusion. Secure input does nothing there.
- Linux: no capture blocking; ACT-ALLOW-CAPTURE is hidden; secure input does nothing.

## Security notes

- **SC-05, AT-D04:** require per-window legacy property application, including nonfocused windows and first frame, plus run-only allowance/reset and read-back-failure reporting. Capture outcomes are recorded per path/version, not guaranteed: shown pixels with `.none` are an OS/path limit, not a fabricated property failure or failed universal exclusion test. V-A10-1/V-A10-5 and all actual capture QA remain open for authorized visible work. Existing hidden-launch state0/1/0 proof remains historical property evidence; no new capture/SC-05/AT-D04 sign-off here.
- **SR-06, AT-D05:** keystrokes in password fields hidden from other processes. Must never happen: an event tap of another process sees a key typed into a password-kind field while Larsal is active. Also must never happen: Larsal leaves secure input on after it deactivates, locks or quits (APP-10.12), which would break other apps.
- **A missed focus-out must not leave secure input on** (APP-10.11, APP-10.13). A view that never reports its focus-out (a focus change that does not fire, a view removed without its disappear handler) could leave Larsal's own call on, so Larsal also ends it on window close, deactivation, lock and quit.
- **F07 and ACT-ALLOW-CAPTURE change the legacy property for one run.** Neither is saved; the next start requests `.none` (APP-10.1, APP-10.5). A real capture path may show pixels in either state.
- **Out of scope:** malware with admin rights or with the user's Screen Recording or Accessibility permission (plan/security.md). Secure input does not stop a kernel or hardware key logger.

## Test cases

The capture rows below prescribe future evidence, not tests executed in this revision. For every actual capture, attach OS/build, framework/tool/version, exact capture path, allowance and property state, and blank/omitted/shown result; state0/1 alone is not a capture result. Preserve previous SC-05/AT-D04 evidence without re-signing it. No visible or actual capture is authorized by this document revision.

Demo vault `/tmp/spec-app10/a.larsalvault`, password `demo-pass-a`, entry "Demo Mail" with password `demo-mail-1`. `APP` stands for `Larsal.app/Contents/MacOS/Larsal`. Window sharing state is read with a small demo script that lists windows of Larsal's process id and prints each window's `kCGWindowSharingState`. The secure input holder is read with `ioreg -l -w 0 | grep kCGSSessionSecureInputPID` (Verified 2026-10-28, V-A10-6: the field is present exactly while some process holds secure input and absent after that process turns it off or is killed; but the process id it gives is not always the holder: while a background probe held secure input, the field named another process, the system's alert process with a panel on screen, not the probe. So these cases read presence and absence; "Larsal's process id" below is confirmed by Mac QA with Larsal as the active app, and a test build may read `IsSecureEventInputEnabled()` instead).

| Case | Given | When | Then |
|---|---|---|---|
| APP-10.1-a | Larsal not running | Start `APP a.larsalvault`; read sharing states | Every Larsal window state 0 |
| APP-10.1-b | Larsal started with F07, then quit | Start `APP` again | ACT-ALLOW-CAPTURE unchecked; states 0 |
| APP-10.1-c | A test build that records each window's first sharing state | Open the generator, an alert and the unlock screen | Each window's state was 0 before its first frame |
| APP-10.2-a | Larsal running, protected, `a` unlocked showing "Demo Mail" | `screencapture -x /tmp/spec-app10/s.png` (full screen) | Record blank/omitted/shown for this actual screenshot path, with .2's property/path/version evidence; shown is a recorded platform limit, not a universal-exclusion failure (AT-D04, actual QA OPEN) |
| APP-10.2-b | As APP-10.2-a | QuickTime screen recording, then screen sharing from a second demo user | Record blank/omitted/shown separately for recording and sharing with .2's evidence; needs Mac QA (owner's go), V-A10-7. Neither path is passed by a property read-back or this revision |
| APP-10.2-c | ACT-ALLOW-CAPTURE checked | Read sharing states; `screencapture -x` | Property states1 required; independently record screenshot blank/omitted/shown with tool/OS/version. The setting does not guarantee path behavior |
| APP-10.3-a | Protected | Show a tooltip and a completion list; read sharing states while they are shown | Every Larsal window, including these, state 0 |
| APP-10.3-b | Capture allowed | Open the site access prompt (INT-02) | Its state 1 |
| APP-10.4-a | Protected, generator popup open | Check ACT-ALLOW-CAPTURE | Main window and popup both state 1 at once; check mark shown |
| APP-10.4-b | Capture allowed | Quit; start `APP` | Protected again (state 0); action unchecked |
| APP-10.5-a | Larsal not running | `APP --allow-screen-capture` | Action checked; states 1 |
| APP-10.5-b | Primary running, protected | `APP --allow-screen-capture` (second launch) | Primary still protected (states 0) |
| APP-10.6-a | A test build whose `sharingType` read-back returns `.readOnly` (test hook) | Open a dialog | Banner M10-01 in the main window; dialog still opens |
| APP-10.7-a | Protected, `a` unlocked | Lock; read states; unlock; read states | State 0 every time |
| APP-10.8-a | Unlock screen of `a` | Click the password field; read the secure input holder | Larsal's process id |
| APP-10.8-b | As APP-10.8-a | Switch to Finder with Cmd-Tab; read holder | Field absent |
| APP-10.8-c | As APP-10.8-a | Press Show; read holder | Still Larsal's process id |
| APP-10.8-d | As APP-10.8-a, a demo event tap logger running (AT-D05) | Type `demo-pass-a` | Logger records no key events for those keys; the vault unlocks |
| APP-10.8-e | `a` unlocked, entry editor open with focus in the title field | Read holder; move focus to the password field; read holder | Absent, then Larsal's process id |
| APP-10.9-a | New-vault wizard (APP-07) | Focus each new password field, then the generator's password field | Holder is Larsal's process id in each |
| APP-10.10-a | A test build that counts Larsal's own enable and disable calls | Focus the field, focus out, focus in twice, quit | Calls alternate enable, disable, starting with enable; never two enables in a row |
| APP-10.11-a | A test build where the shown field's focus-out never reaches Larsal's handler | Focus the unlock field, Show on; switch app | Holder absent after the switch |
| APP-10.13-a | Unlock screen of `a`, focus in the password field, Show on (holder is Larsal's process id) | Cmd-Tab to Finder; read holder; Cmd-Tab back to Larsal; read holder | Absent while Finder is active; Larsal's process id again after the return, field still focused |
| APP-10.13-b | `a` unlocked, entry editor's password field focused | Cmd-Tab to Finder; read holder | Absent |
| APP-10.12-a | Focus in the unlock field | `kill -9` Larsal; read holder | Field absent (OS released it; Verified 2026-10-28, V-A10-8, with a probe that held secure input and was killed with `kill -9`: the field was gone a second later) |
| APP-10.12-b | Focus in the unlock field | Lock with the Lock action; read holder | Field absent |

## How this was learned

- The reference window app's start-up routine (the allow flag and when it is applied) and the main window's routines for the allow action, the per-window apply on focus change, and the failure banner; the main window's menu definition (View menu place, checkable action) and the list of actions whose shortcuts the user can change.
- The macOS utilities: the window sharing type call (none to protect, read only to allow), "can protect" answered yes, and the secure input routine with its own flag; the Windows utilities (display affinity) and Linux utilities (not supported) for the Not on Mac list.
- The shared password field: the event filter that turns secure input on at focus in and off at focus out and hide; the screens that use that field (unlock screen, credential editor, entry editor, generator, shared group settings, import wizard, pick-characters dialog).
- `strings` on the installed 2.7.11 window binary: the same flag, action and banner as the source; the 2.7.11 tag compared with the source commit for these routines (no change). The window app was not launched.
- The secure input holder field in the I/O registry and the window sharing state key are public macOS facts; both were read on this Mac by Verify on 2026-10-28: the holder field as V-A10-6 says; the sharing state key is reported (1 for a normal window), and a protected window's value stays with Mac QA (V-A10-1).

E21-S1 scoped correction sources: current SC-05 in plan/security.md, AT-D04 in plan/attacks-and-checks.md and the preserved E13-S1 property observations; public Apple enum/DTS linked in .2. No reference source/app, real capture, permission prompt or secure-input runtime was accessed for this correction. The original card's learning/verification notes above remain historical, not new proof. LD-362 and the scoped correction were jointly adopted in d413e06 as reviewed specification only; every unpassed actual-capture requirement and the existing first-frame/run-only behavior remain required. Review/adoption proof is recorded in FEA-10's Review and proof footer.
