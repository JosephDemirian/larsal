# APP-10 Screen protection and secure input

Status: reviewed
Epics: E6-S5, E5-S3
Parity rows: SC-05, SR-06

## What it does

Two protections against other programs running as the same user.

1. **Screen protection.** Every Larsal window is hidden from screenshots, screen recordings and screen sharing. It is on from the moment a window exists, on every start. The user can allow capture for the current run only: with a start flag, or with a View menu action. Nothing saves that choice.
2. **Secure input.** While the keyboard focus is in a password field of Larsal, macOS secure event input is on, so other programs (event taps, key loggers) do not receive the keystrokes. It goes off as soon as the focus leaves the field or Larsal stops being the active app.

The start flag itself is listed in APP-09 (F07). Menus and shortcuts are APP-08. The Caps Lock warning on password fields is APP-06.

Both protections belong to the Swift side of the native app (Decided: spec/decisions.md LD-155, LD-156 (7), LD-200 (2)): it sets each window's sharing type and makes the secure input calls. The Rust core takes no part in either.

## Inputs and outputs

- In: window creation and key-window changes from AppKit; the start flag F07 (APP-09); the View menu action ACT-ALLOW-CAPTURE; focus in and out of password-kind fields, seen by the Swift views; Larsal activation and deactivation (`NSApplication.didBecomeActiveNotification`, `didResignActiveNotification`); lock and quit.
- Out: each window's macOS sharing type; the process's secure event input state; the error banner M10-01 when a window cannot be protected.

| ID | What | Values | Default |
|---|---|---|---|
| ACT-ALLOW-CAPTURE | View menu action, label "Permit Screen Capture", checkable | checked = capture allowed; unchecked = windows protected | unchecked at every start, unless F07 |
| F07 | Start flag `--allow-screen-capture` (APP-09) | present or absent | absent |

| ID | Where | When | Text (Larsal) |
|---|---|---|---|
| M10-01 | Error banner in the main window | The OS refused to protect a window while capture is not allowed | Warning: screen capture could not be blocked for one of Larsal's windows. |

There is no message, indicator or confirm for allowing capture, and none for secure input (D-APP10-2).

## Rules

APP-10.1 **Protected from the start.** Every Larsal window is protected from screen capture from its creation, before its first frame is drawn, on every start, unless F07 is given. Protection is not a saved setting: no setting, settings file or environment variable can make Larsal start unprotected (D-APP10-1).

APP-10.2 **macOS mechanism.** Protected means the window's sharing type is "none" (`NSWindowSharingNone`). The window server then refuses to give the window's pixels to other processes: the window is left out of, or blank in, screenshots, recordings and screen sharing, and the system window list reports its sharing state as none (`kCGWindowSharingState` 0). Allowed means sharing type "read only" (`NSWindowSharingReadOnly`, the normal macOS value; `kCGWindowSharingState` 1). The Swift side sets `NSWindow.sharingType` (`.none` or `.readOnly`) on each window (LD-156 (7)). How each capture path honors it on this Mac's macOS (26.6) needs Mac QA (owner's go), V-A10-1 (AT-D04): each path needs a protected window on screen and a capture tool with the Screen Recording permission, so it runs on the owner's screen.

APP-10.3 **Every window.** The protection state applies to every window Larsal creates: the main window, sheets, dialogs, alerts, popovers, menus Larsal draws itself, and any secondary window (generator, Auto-Type picker, site access and passkey prompts, reports). It is set when the window is created, not when it first gets focus. File open and save panels show only file names; protecting them is optional. System-drawn surfaces (the menu bar, notifications, the Dock) are outside Larsal's control, so Larsal never puts a secret there. Reference: when the toggle changes, it sets every visible top-level window; it also sets a window each time that window gets focus. Windows that never take focus (tooltips, completion lists, popup menus) and a window's first moments before focus are therefore not covered there. Larsal closes that gap.

APP-10.4 **The allow action.** ACT-ALLOW-CAPTURE sits in the View menu, checkable, checked when capture is allowed. It is shown only where the OS can protect windows (shown on macOS). Changing it applies at once to every open window; windows created later follow the current state. The state lasts until quit and is never saved. It has no default shortcut; the user may assign one (APP-08). The check mark is its only indicator. Reference: the same action, place and behavior, with its own label.

APP-10.5 **The start flag.** F07 starts Larsal with ACT-ALLOW-CAPTURE checked; every window is then created allowed. A secondary launch ignores F07 (APP-09.10). If Larsal ever relaunches itself, the new process starts protected. Reference: the same flag; its self-relaunch drops all flags, so protection comes back on.

APP-10.6 **When protection fails.** AppKit's `sharingType` setter reports no failure, so Larsal reads the window's `sharingType` back right after it sets it. When the value read back is not `.none` while capture is not allowed, Larsal shows M10-01 in the main window, each time it happens. The window stays open. On macOS this is not expected to happen; the banner covers the case all the same. Reference: the same banner; on macOS its protect call cannot report failure, so the banner never appears there.

APP-10.7 **Independent of vault state.** Locking, unlocking, switching vaults, minimizing and hiding do not change the protection state. The unlock screen is protected like every other view.

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
- **Capture paths that may ignore the sharing type:** newer macOS capture frameworks are reported not to honor it in some versions (not confirmed here). Verify tests each path on this Mac (AT-D04). If one leaks, it is an OS limit to note in Larsal's help; there is no reliable way to detect capture (D-APP10-3).
- **The reference's own launch flag after its relaunch:** see APP-10.5.

### Lead decisions

- **D-APP10-1 Saved setting or start state.** plan/security.md lists "Hide window from screen capture: On" among the settings. (a) Start state only, as the reference does: protected at every start, allowed only by F07 or ACT-ALLOW-CAPTURE for one run; (b) a saved setting. Recommend (a): no saved choice can leave Larsal unprotected; APP-01 lists it as a start state, not a setting. Decided: spec/decisions.md LD-200 (as recommended).
- **D-APP10-2 Warning when capture is allowed.** (a) The check mark only, as the reference does; (b) a banner while allowed. Recommend (a). Decided: spec/decisions.md LD-200 (as recommended).
- **D-APP10-3 A capture path that leaks.** (a) Note the OS limit in Larsal's help; (b) hide vault content while any capture is active. Recommend (a): macOS gives no reliable signal that capture is running. Decided: spec/decisions.md LD-200 (as recommended).

### Not on Mac

- Windows: windows are excluded from capture with the display affinity "exclude from capture"; that call can fail, which shows the banner. Secure input does nothing there.
- Linux: no capture blocking; ACT-ALLOW-CAPTURE is hidden; secure input does nothing.

## Security notes

- **SC-05, AT-D04:** windows hidden from capture. Must never happen: a window that shows vault data appears in a screenshot while capture is not allowed. Weak spots: windows that never take focus (closed by APP-10.3), a window's first frame (closed by APP-10.1), capture paths of newer macOS (needs Mac QA (owner's go) with V-A10-1, V-A10-5: it runs on the owner's screen).
- **SR-06, AT-D05:** keystrokes in password fields hidden from other processes. Must never happen: an event tap of another process sees a key typed into a password-kind field while Larsal is active. Also must never happen: Larsal leaves secure input on after it deactivates, locks or quits (APP-10.12), which would break other apps.
- **A missed focus-out must not leave secure input on** (APP-10.11, APP-10.13). A view that never reports its focus-out (a focus change that does not fire, a view removed without its disappear handler) could leave Larsal's own call on, so Larsal also ends it on window close, deactivation, lock and quit.
- **F07 and ACT-ALLOW-CAPTURE lower protection for one run.** Neither is saved, so the next start is protected (APP-10.1, APP-10.5).
- **Out of scope:** malware with admin rights or with the user's Screen Recording or Accessibility permission (plan/security.md). Secure input does not stop a kernel or hardware key logger.

## Test cases

Demo vault `/tmp/spec-app10/a.larsalvault`, password `demo-pass-a`, entry "Demo Mail" with password `demo-mail-1`. `APP` stands for `Larsal.app/Contents/MacOS/Larsal`. Window sharing state is read with a small demo script that lists windows of Larsal's process id and prints each window's `kCGWindowSharingState`. The secure input holder is read with `ioreg -l -w 0 | grep kCGSSessionSecureInputPID` (Verified 2026-10-28, V-A10-6: the field is present exactly while some process holds secure input and absent after that process turns it off or is killed; but the process id it gives is not always the holder: while a background probe held secure input, the field named another process, the system's alert process with a panel on screen, not the probe. So these cases read presence and absence; "Larsal's process id" below is confirmed by Mac QA with Larsal as the active app, and a test build may read `IsSecureEventInputEnabled()` instead).

| Case | Given | When | Then |
|---|---|---|---|
| APP-10.1-a | Larsal not running | Start `APP a.larsalvault`; read sharing states | Every Larsal window state 0 |
| APP-10.1-b | Larsal started with F07, then quit | Start `APP` again | ACT-ALLOW-CAPTURE unchecked; states 0 |
| APP-10.1-c | A test build that records each window's first sharing state | Open the generator, an alert and the unlock screen | Each window's state was 0 before its first frame |
| APP-10.2-a | Larsal running, protected, `a` unlocked showing "Demo Mail" | `screencapture -x /tmp/spec-app10/s.png` (full screen) | The Larsal window is missing or blank in `s.png`; other windows normal (AT-D04) |
| APP-10.2-b | As APP-10.2-a | QuickTime screen recording, then screen sharing from a second demo user | Larsal window blank or missing in both (needs Mac QA (owner's go), V-A10-7: a screen recording and a second user's screen sharing session) |
| APP-10.2-c | ACT-ALLOW-CAPTURE checked | Read sharing states; `screencapture -x` | States 1; Larsal window visible in the image |
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
