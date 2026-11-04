# APP-03 Clipboard rules

Status: reviewed
Epics: E6-S1
Parity rows: SC-01, SC-02, SC-03

## What it does

The user copies a value from a vault (a password, a username, a one-time code, any field) and pastes it into another app. App puts the value on the macOS general pasteboard with markers that tell clipboard history tools to skip it, then clears it after a set time, but only if the pasteboard still holds App's copy. App also clears it when any vault locks and when App quits. Optionally, App gets out of the way after a copy (minimize or move behind other windows).

This card lists every copy action, the clear timer and its range, the "still ours" check, the markers App writes, clearing on lock and quit, the hide-on-copy options, and drag and drop of values. Which shortcut runs which action is APP-08. How placeholders and references inside a value are resolved is MOD-08. One-time codes are FEA-04. The command line tool's copy command is INT-10.

## Inputs and outputs

In:
- A copy action (APP-03.1) on the shown vault, or a copy request from a dialog.
- The app settings below (APP-01 owns the inventory; if APP-01 gives a different ID, APP-01 wins).

Out:
- The general pasteboard holds one item: the value as text plus the marker types (APP-03.9).
- A short notice on screen (APP-03.21).
- Later: the pasteboard is emptied (APP-03.12), or left alone when the user copied something else.

### Settings

| ID | Meaning | Reference default | App default | Range |
|---|---|---|---|---|
| `clipboard.clear.enabled` | Clear App's copy after a delay | on | on | on / off |
| `clipboard.clear.seconds` | The delay | 10 | 10 | 1 to 999 seconds (APP-03.13) |
| `window.hide_on_copy` | Get the window out of the way after a main-window copy | off | off | on / off |
| `window.hide_on_copy.mode` | How: `minimize` or `background` | `minimize` | `minimize` | one of the two; used only when `window.hide_on_copy` is on |
| `list.copy_on_double_click` | Double-click on the username or password column copies it | off | off | on / off |
| `list.url_double_click` | Double-click on the URL column: `open` (0), `copy` (1), `edit` (2) | `open` | `open` | one of the three |

Same defaults in the installed reference (2.7.11) and the source.

## Rules

APP-03.1 **Copy actions.** These are every copy action App offers. "Hides" says whether `window.hide_on_copy` applies (APP-03.17). "Resolve" says how placeholders and field references in the value are expanded (MOD-08): "full" is the full resolution of MOD-08, used by every copy action (MOD-08.26).

| Action ID | Where the user starts it | Value copied | Resolve | Hides | Enabled when |
|---|---|---|---|---|---|
| `copy.username` | Entry menu, toolbar, entry context menu, shortcut, detail view button | Username | full | yes | one entry selected (or its editor open) and the username is not empty |
| `copy.password` | Same places; Cmd+C when no text is selected (APP-03.7) | Password | full | yes | one entry selected (or its editor open); see APP-03.5 for an empty password |
| `copy.url` | Same places | URL (the main URL, or the chosen extra URL in the detail view) | full | yes | the URL is not empty |
| `copy.title` | Entry menu, "Copy field" submenu | Title | full | yes | the title is not empty |
| `copy.notes` | "Copy field" submenu, detail view | Notes | full | yes | the notes are not empty |
| `copy.field` | "Copy field" submenu (lists every custom field by name), double-click on a field row in the detail view, detail view button | The custom field's value | full | yes | one entry selected and the field exists |
| `copy.totp` | One-time password submenu, shortcut, double-click on the code column, double-click on the code in the detail view | The current code (FEA-04) | none | yes | one entry selected; see APP-03.4 |
| `copy.password_totp` | One-time password submenu | Password (resolved in full) immediately followed by the current code, no separator | full (password part) | yes | the entry has a one-time password set up |
| `copy.selection` | Cmd+C or Edit > Copy while text is selected in the shown vault (detail view, notes, a text field of the editor, a shown value) | The selected text, as shown | none | no | text is selected |
| `copy.generated` | The password generator's Copy button | The generated password | none | no | a password is shown |
| `copy.totp_dialog` | The one-time code display's Copy button | The current code | none | no | always |
| `copy.totp_link` | The QR code and key export dialog's Copy button | The full one-time password link (it contains the secret) | none | no | always |
| `copy.ssh_public_key` | The editor's SSH agent page | The public key text | none | no | a key is loaded |
| `copy.ssh_fingerprint` | The detail view's SSH key row, button "Copy fingerprint" (INT-06.43) | The key's fingerprint, as the row shows it | none | yes | the entry has an SSH key whose public key can be read (Decided: spec/decisions.md LD-181 (4)) |
| `copy.autotype_username`, `copy.autotype_password`, `copy.autotype_totp`, `copy.autotype_url` | The Auto-Type picker (INT-05), with its shortcuts; the picker closes after the copy | Username, password, code or URL of the highlighted entry | full (MOD-08.26) | no | an entry is highlighted |
| `copy.app_info` | The About window's Copy button | Version and system information (no vault data) | none | no | always |

APP-03.2 **One copy path.** Every action in APP-03.1 except `copy.app_info` goes through one copy routine in app-platform (`clipboard.rs`): it writes the markers (APP-03.9), records the "still ours" state (APP-03.10) and starts the timer (APP-03.11). The value goes from app-core to app-platform inside Rust; it never passes through the screen layer (architecture, Copy flow), except for `copy.selection`, whose text the screen already shows (APP-03.19). `copy.app_info` is a plain copy: no markers, no timer, not tracked.

APP-03.3 **Values are copied as resolved text.** Every copy action, the Auto-Type picker included, copies the fully resolved value (MOD-08.26). The reference resolves picker copies through its second, "single" entry point, which is also full except for a value that starts with `{`, ends with `}` and holds several spans (MOD-08.26). A one-time code is computed at the moment of the copy (FEA-04). `copy.password_totp` joins the two parts with nothing between them: password `demo-pass-1` and code `123456` give `demo-pass-1123456`.

APP-03.4 **Copy one-time code without a setup.** When the selected entry has no valid one-time password setup, `copy.totp` from the menu, shortcut or code column opens the one-time password setup for that entry instead of copying (FEA-04). The double-click in the detail view does nothing in that case (the code is not shown there).

APP-03.5 **Empty values.** App copies nothing for an empty value: the pasteboard is left untouched, no timer starts, and the notice says there is nothing to copy (`MSG-COPY-EMPTY`: "‹label› is empty. Nothing to copy.", LD-181). The reference keeps "Copy password" enabled for an entry with an empty password (so that Cmd+C never copies a table cell instead) and then puts empty text on the clipboard, wiping what the user had there. Lead decision D-A03-1 (recommended: copy nothing, as design/mockup.html does). Decided: spec/decisions.md LD-168, (a).

APP-03.6 **Double-click in the entry list.**
- Username or password column: when `list.copy_on_double_click` is on, `copy.username` or `copy.password`; otherwise opens the entry editor.
- One-time code column: `copy.totp` (APP-03.4 when there is no setup).
- URL column, non-empty URL: `list.url_double_click` = `open` opens the URL in the browser (default), `copy` runs `copy.url`, `edit` opens the editor. Empty URL: nothing.
- Any other column: opens the editor.

APP-03.7 **Cmd+C.** When the shown vault has selected text in the focused element, Cmd+C runs `copy.selection`. Otherwise, with one entry selected, Cmd+C runs `copy.password` (APP-08 lists the shortcut). In the reference, the selection case is taken over only for multi-line text areas and selectable labels of the vault view; a selection in a single-line text field (for example a password field switched to visible in the editor) is copied by the toolkit's own copy, with no marker and no timer. App takes over every selection in the vault's views (APP-03.19); a selection inside App's no-copy field copies nothing (APP-03.19). Differs from the reference on purpose.

APP-03.8 **Every tracked copy is concealed and timed, whatever its field.** URLs, titles, public keys and generated passwords get the same markers and the same timer as passwords. App does not try to judge which fields are secret.

APP-03.9 **What App writes on macOS.** App writes to the general pasteboard (`NSPasteboard.general`), replacing all its previous content, one item with these types:

| Type | Data | Why |
|---|---|---|
| `public.utf8-plain-text` | The value as UTF-8 | The text other apps paste |
| `org.nspasteboard.ConcealedType` | Empty data in App; the reference writes the value's UTF-8 bytes again | The published nspasteboard.org marker: the content is a password or similar, clipboard tools must not show or store it |
| `org.nspasteboard.TransientType` | Empty data | The published marker for content that is only there for a moment; App adds it, the reference does not |

Before writing, App prepares the pasteboard with the "current host only" option (`prepareForNewContents(with: .currentHostOnly)`, macOS 12 and later), so Universal Clipboard does not send the value to the user's other Apple devices. The reference does not do this. Lead decision D-A03-2: (a) as the reference: text plus the concealed marker carrying the value again; (b) text, both markers with empty data, current host only. Recommended: (b); AT-D01 must pass with a real clipboard history app either way (needs Mac QA (owner's go), V-A03-1: it takes a third-party clipboard history app watching the general pasteboard, which agents and tests must not touch, AGENTS.md rule 10; the item App writes, text plus both markers with empty data, is proven on a private pasteboard by `copy_writes_text_and_both_markers`). Decided: spec/decisions.md LD-168, (b).

APP-03.10 **"Still ours" state.** Right after writing, App records the pasteboard's change count (`NSPasteboard.changeCount`; the count that `prepareForNewContents` returns, LD-170 (2)). App keeps no copy of the value itself. A new copy replaces the recorded count. Before it writes a new copy, App first clears its previous copy as APP-03.12 does (only while the count still matches), so a write that then fails never leaves a copy of App's on the pasteboard untracked (Decided: spec/decisions.md LD-170 (1); SC-03). The reference instead remembers the copied text in memory until the clear, and later compares texts (APP-03.12). Lead decision D-A03-3 (decided: spec/decisions.md LD-168, change count, as written; it needs no secret kept in memory and does not read the pasteboard, which newer macOS versions may guard with a paste permission prompt; Verified 2026-10-28, V-A03-2: the macOS 26.2 SDK states that from macOS 15.4 a program's access to the general pasteboard asks the user by default, unless the access is a paste the user started, and that its pattern and metadata checks give no access to the contents and so ask nothing; App's change count carries no content either).

APP-03.11 **Timer.** When `clipboard.clear.enabled` is on, a copy starts a countdown at `N = clipboard.clear.seconds`. Each second the remaining count goes down by one; when it reaches 0 (that is, `N` seconds after the copy), App runs the clear (APP-03.12). A new copy while a countdown runs restarts it at the then-current `N`. The remaining whole seconds are available to APP-02.8 (lock on minimize delay); with no countdown running the remaining value is 0. Changing the setting does not change a running countdown. The reference shows the remaining time in its status bar as a bar at `floor(100 × remaining ÷ N)` percent with a text that counts down the seconds left until the clipboard is cleared; App shows the copy notice instead (APP-03.21) and no running countdown.

APP-03.12 **Clear.** When the countdown ends, or on lock or quit (APP-03.15): if the pasteboard's change count still equals the recorded one, App empties the pasteboard (`clearContents`; all types go). If the count differs, the user or another app has put something else there (including the same text copied again from elsewhere, or a Universal Clipboard paste from another device), and App leaves the pasteboard alone. Either way App then forgets the recorded count and stops the countdown. The reference compares the clipboard's current text with the remembered text instead, so it also clears text that another app put there when the text is the same.

APP-03.13 **Range of the delay.** The settings screen accepts whole seconds from 1 to 999, default 10. A stored value outside this range is used as the nearest bound (0 or negative as 1, 5,000 as 999); a value that is not a number is used as 10. The reference's screen has the same range, but a stored value of 0 or less (only possible by editing its settings file) makes it clear the clipboard at once after every copy, which makes copying useless. Lead decision D-A03-4: (a) as the reference; (b) clamp as written; (c) 0 means never clear, as the command line tool does (INT-10). Recommended: (b); decided: spec/decisions.md LD-168. "Never clear" is expressed only by turning `clipboard.clear.enabled` off.

APP-03.14 **Clear turned off.** With `clipboard.clear.enabled` off, no countdown runs, but every copy is still marked (APP-03.9) and tracked (APP-03.10), so it is still cleared on lock and quit if it is still on the pasteboard (APP-03.15). The reference does the same for action copies, but does not track `copy.selection` when the setting is off. App tracks it (stricter).

APP-03.15 **Clear on lock, close and quit.** App runs the clear (APP-03.12):
- at the start of every vault lock, whatever triggered it and whichever vault the copied value came from, even if other vaults stay unlocked, and even if the user then cancels the lock (APP-02.15 step 6);
- when a vault is closed (closing locks first);
- when App quits (APP-02.11), after the vaults are locked.

APP-03.16 **Forced exit.** If App is killed, crashes or the Mac loses power, the value stays on the pasteboard; nothing can clear it. App does not try to clear anything at its next start (it cannot tell whether the pasteboard still holds its copy). This is a known limit, also of the reference.

APP-03.17 **Hide on copy.** When `window.hide_on_copy` is on, actions marked "Hides" in APP-03.1 move the window out of the way right after the copy:
- `minimize`: the window is hidden to the menu bar icon when App is set to hide there on minimize (APP-08), else minimized to the Dock. This counts as a minimize for the lock-on-minimize delay (APP-02.8), so with the default 10-second clear time a lock follows about 10 seconds later.
- `background`: the window moves behind the other apps' windows and the app the user was in before becomes active again, so a paste goes there. The reference only orders its window to the back (Verified 2026-10-28, V-A03-3, from the source and the installed bundle: it calls its toolkit's lower on the main window, and on the dialog that copied; the toolkit's Mac plug-in in the bundle has AppKit's order-back call and no deactivate call; AppKit documents that order-back changes neither the key nor the main window, so the reference stays the active app and a paste goes to the previous app only after the user clicks it; not watched on screen). Lead decision D-A03-5 (recommended: also give focus back to the previous app, as written; decided: spec/decisions.md LD-168).
Copies from dialogs, the generator, the Auto-Type picker and `copy.selection` never hide the window.

APP-03.18 **Drag and drop.** App never puts a field value on a drag pasteboard. Dragging entries in the list carries only the vault id and entry ids, in an App-private type, and is used only to move entries between groups inside App (MOD-02); another app that receives such a drop gets no text. The screen layer turns off dragging of selected text out of value fields, shown values and the detail view. Drops onto App's window: a vault file opens as APP-09.26 says (by its extension, D-APP09-7); a file dropped on the attachments area of the editor adds an attachment (MOD-05); everything else is ignored and nothing opens or runs (AT-E06). The reference behaves the same for entry drags (ids only) and accepts vault files by name extension. Whether an opened file is a vault is still decided by content at unlock (APP-09.15, FMT-01).

APP-03.19 **Copies started in the screen layer.** The Swift screens' own copy (Cmd+C, Edit > Copy, a context menu's Copy, Cut, dragging, Services) must never write a vault value to the pasteboard directly; every copy of APP-03.1 is a Rust call (APP-03.2, LD-156 (6)). A field that shows a secret in clear (the unlock form's password after Show, the editor's password, the one-time secret field) is App's no-copy field: its context menu has no Copy or Cut, and no copy, cut, drag or Services request takes text out of it (Decided: spec/decisions.md LD-181 (4), LD-199 (1), (5)). With a selection in the vault's views, Cmd+C sends the selected text to `copy.selection` (APP-03.2) and the plain AppKit copy does not run; while no unprotected vault text is selectable, this needs no screen copy at all (LD-181 (5)). Without a selection, the menu item runs `copy.password` (APP-03.7). Text fields of dialogs that hold no vault data (for example the search field, the settings screen) may use the plain AppKit copy.

APP-03.20 **Command line tool.** The command line tool's copy command is specified by INT-10. The reference's command line tool on macOS writes through the system's plain copy program, so its copies carry no marker, and after its delay (default 10 seconds, 0 for never) it empties the clipboard without checking whether it still holds its value. App's command line tool uses the same copy routine as App (APP-03.2, APP-03.9, APP-03.12) with its own delay argument, and like App it copies nothing for an empty value (APP-03.5; INT-10.29, M10-98; Decided: spec/decisions.md LD-200 (8)). Lead decision D-A03-6 (decided as written: spec/decisions.md LD-168).

APP-03.21 **Notice.** After each tracked copy App shows a short notice with the field's label: `MSG-COPIED` "<label> copied. Clears in <N> s." when `clipboard.clear.enabled` is on, `MSG-COPIED-NOCLEAR` "<label> copied." when it is off (design/mockup.html). Labels: Username, Password, URL, Title, Notes, the custom field's name, One-time password, Password and one-time password, Public key, Fingerprint, Password (generator), Link (one-time password link); `copy.selection` shows "Copied." The notice never shows the value. A failed write shows `MSG-COPY-FAILED` and starts no timer.

APP-03.22 **Secrets in memory.** The value exists in App's memory only while it is being read from the vault and written to the pasteboard; it is held in a secret type and wiped right after the write (SR-07). The pasteboard copy itself is outside App's control once written.

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| Copy the password, then the username 4 s later (10-second delay) | One countdown, restarted at the second copy; the username is cleared 10 s after its copy (14 s after the first). The password was already replaced on the pasteboard. |
| Copy, then the user copies other text in another app before the delay ends | Change count differs; App leaves the pasteboard alone (AT-D02). |
| Copy `demo-pass-1`, then the user copies the same text `demo-pass-1` from a text editor | Change count differs; App leaves it (the reference would clear it, since the text matches). |
| Copy from vault A, then vault B locks | The pasteboard is cleared (APP-03.15), even though A stays unlocked. |
| Copy, then lock with a save prompt that the user cancels | Pasteboard already cleared; vault stays unlocked. |
| Copy, then quit | Cleared after the vaults lock, before exit. |
| Copy an empty username field via the detail view | `MSG-COPY-EMPTY`; pasteboard unchanged (APP-03.5). |
| `clipboard.clear.seconds` stored as 0 | Used as 1: cleared 1 s after each copy (APP-03.13). |
| The pasteboard cannot be written (system refuses) | `MSG-COPY-FAILED`; no timer; nothing tracked. App's previous copy, if it was still ours, was cleared before the write (APP-03.10, LD-170 (1)), so nothing of App's is left behind. |
| Copy of a 10 MB notes field | Copied as text like any value; the notice is the same. App sets no size limit of its own (the vault's own limits apply, FMT-11). |
| Value with line breaks or non-ASCII text | Copied exactly as resolved, as UTF-8; line breaks unchanged. |
| A clipboard history tool polls the pasteboard every 0.5 s | It sees the marker types and, if it follows nspasteboard.org, skips the item (AT-D01). App cannot stop a tool that ignores the markers. |
| Universal Clipboard is on, an iPhone is nearby | With D-A03-2 (b), the value stays on this Mac. |
| The reference's status-bar percentage for a 7-second delay | 100, 85, 71, 57, 42, 28, 14, then cleared (for comparison only; App shows no countdown). |

### Not on Mac (reference behavior on other systems, for later ports)

- Linux and other X11 systems: the value is also written to the primary selection, and both are cleared. The marker is the type `x-kde-passwordManagerHint` with the data `secret`.
- Linux with a desktop portal: an option lets Auto-Type type through the portal's clipboard; then copy and clear go through the portal. On Wayland the reference's command line tool uses `wl-copy`, on X11 `xclip`.
- Windows: three formats are added: `ExcludeClipboardContentFromMonitorProcessing` (data `1`), and `CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard` (each a 4-byte zero), so clipboard history and cloud clipboard skip the value. The command line tool uses `clip`.

## Security notes

- **What could go wrong:** a copied password stays on the pasteboard forever, lands in a clipboard history tool, syncs to another device, or is cleared at the wrong moment and wipes something the user copied later.
- **Must never happen:** App clearing content that is not its own (AT-D02); a vault value reaching the pasteboard without the markers (SC-02, AT-D01), including through the screens' own copy (APP-03.19) or an empty-value copy; a copied value surviving a lock or a normal quit (SC-03, AT-D03); the value appearing in a notice, a log or an error (SR-07, AT-C06).
- The change count check (APP-03.10, APP-03.12) is stricter than the reference's text comparison and keeps no secret in memory while the countdown runs.
- The markers only ask clipboard tools to behave. A hostile app with normal rights can still read the pasteboard while the value is there; the short default delay limits that window (plan/security.md, "Other apps on the Mac").
- Universal Clipboard: without the current-host-only option the value would leave this Mac (D-A03-2).
- Parity rows: SC-01 (timed clear, only if still ours), SC-02 (markers), SC-03 (clear on lock and quit). Attacks: AT-D01, AT-D02, AT-D03, AT-E06 (drops), AT-C06 (logs).

## Test cases

Demo vault A (password `demo-master-A`): entry "Demo Mail" with username `demo@example.com`, password `demo-pass-1`, URL `https://mail.example.com`, notes `demo note`, custom field "PIN" = `4321`, one-time password setup with the RFC 6238 demo secret (FEA-04); entry "Empty Demo" with an empty password and no URL; entry "Ref Demo" whose username is the field reference to the username of "Demo Mail" (MOD-08). Times in seconds after the first step. Unit tests use the app-platform clipboard trait with a fake pasteboard (types, data, change count); AT-D01 to AT-D03 use the real pasteboard on this Mac.

| Case | Given | When | Then |
|---|---|---|---|
| T01 APP-03.1 | "Demo Mail" selected | `copy.username`, `copy.url`, `copy.notes`, `copy.field` "PIN", one after the other | Pasteboard text after each: `demo@example.com`, `https://mail.example.com`, `demo note`, `4321` |
| T02 APP-03.1 enabled | "Empty Demo" selected | Open the Entry menu | Copy URL disabled; Copy username disabled (empty); Copy password enabled |
| T03 APP-03.1 Auto-Type picker | Picker open, "Demo Mail" highlighted | `copy.autotype_password` | Pasteboard `demo-pass-1`; picker closed; window not hidden even with `window.hide_on_copy` on |
| T03b APP-03.3 picker resolves in full | Picker open; the highlighted entry's user name is `{S:Login} and {S:Pin}`, with Login `al` and Pin `42` | `copy.autotype_username` | Pasteboard `al and 42`, the same as the main-window copy. The installed reference leaves this value unresolved, because it starts with `{`, ends with `}` and holds two spans (MOD-08.26) |
| T04 APP-03.2 | Fake pasteboard; screen-layer spy | `copy.password` on "Demo Mail" | The screen received no message holding `demo-pass-1`; the fake pasteboard got it |
| T05 APP-03.2 plain copy | About window | `copy.app_info` | Text written; no marker types; no countdown; a later lock does not clear it |
| T06 APP-03.3 references | "Ref Demo" selected | `copy.username` | `demo@example.com` (fully resolved) |
| T07 APP-03.3 password and code | Code at that moment `123456` (fixed test clock, FEA-04) | `copy.password_totp` | `demo-pass-1123456` |
| T08 APP-03.4 | "Empty Demo" (no one-time setup) selected | `copy.totp` from the menu | The one-time password setup opens; pasteboard unchanged |
| T09 APP-03.5 | "Empty Demo" selected; pasteboard holds `user text` from another app | `copy.password` | Pasteboard still `user text`; `MSG-COPY-EMPTY`; no countdown |
| T10 APP-03.6 | `list.copy_on_double_click` off | Double-click the password cell of "Demo Mail" | Editor opens; pasteboard unchanged |
| T11 APP-03.6 | `list.copy_on_double_click` on | Double-click the password cell | Pasteboard `demo-pass-1` |
| T12 APP-03.6 URL | `list.url_double_click` = `copy` | Double-click the URL cell | Pasteboard `https://mail.example.com` |
| T13 APP-03.7 | Detail view, the word `demo` selected in the notes | Cmd+C | Pasteboard `demo`, with markers, tracked; notice "Copied." |
| T14 APP-03.7 no selection | "Demo Mail" selected, no text selected | Cmd+C | Pasteboard `demo-pass-1` |
| T15 APP-03.8 | Generator shows `Gen-Demo-123` | `copy.generated` | Markers present; countdown at 10 |
| T16 APP-03.9 | Fake pasteboard | `copy.password` | One item; types exactly `public.utf8-plain-text` = `demo-pass-1`, `org.nspasteboard.ConcealedType` = empty, `org.nspasteboard.TransientType` = empty; prepared with current-host-only |
| T17 APP-03.10 | Fake pasteboard change count 41 before | `copy.password` | Recorded count 42; no copy of `demo-pass-1` held outside the pasteboard (memory check in debug build) |
| T18 APP-03.11 | Delay 10 | Copy at t = 0 | Pasteboard empty at t = 10 (± 0.5), still `demo-pass-1` at t = 9.5 |
| T19 APP-03.11 restart | Delay 10 | `copy.password` at t = 0, `copy.username` at t = 4 | At t = 10 the pasteboard still holds `demo@example.com`; empty at t = 14 (± 0.5) |
| T20 APP-03.11 remaining | Delay 10, copy at t = 0 | Ask the remaining seconds at t = 3.2 | 7 (used by APP-02 T17) |
| T21 APP-03.12 AT-D02 | Delay 10, copy at t = 0 | At t = 5 another app writes `other`; wait to t = 12 | Pasteboard still `other` |
| T22 APP-03.12 same text | Delay 10, copy at t = 0 | At t = 5 another app writes `demo-pass-1` | At t = 12 the pasteboard still holds `demo-pass-1` (count differs) |
| T23 APP-03.13 | Settings file `clipboard.clear.seconds` = 0 | Copy at t = 0 | Pasteboard holds the value at t = 0.5, empty at t = 1 (± 0.5) |
| T24 APP-03.13 upper | Settings file 5000 | Read settings | Effective 999 |
| T25 APP-03.14 | `clipboard.clear.enabled` off | Copy, wait 60 s, then lock A | Value present at t = 60; empty right after the lock |
| T26 APP-03.14 selection | Clear off | `copy.selection` of `demo`, then lock | Empty after the lock |
| T27 APP-03.15 other vault | A and B unlocked; copy from A | Lock B | Pasteboard empty; A unlocked |
| T28 APP-03.15 cancelled lock | Copy; editor with unsaved edits | Cmd+L, Cancel | Pasteboard empty; A unlocked |
| T29 APP-03.15 quit AT-D03 | Copy | Cmd+Q | Pasteboard empty after exit |
| T30 APP-03.15 user content kept | Copy at t = 0; at t = 2 another app writes `other` | Lock A at t = 3 | Pasteboard still `other` |
| T31 APP-03.16 | Copy at t = 0 | Kill App at t = 1; start App again | Pasteboard still holds the value; App does not touch it at start |
| T32 APP-03.17 minimize | `window.hide_on_copy` on, mode `minimize`, menu bar hiding off | `copy.password` | Window minimized to the Dock |
| T33 APP-03.17 with lock | Same, plus `lock.on_minimize` on, delay 10 | `copy.password` at t = 0 | A locked at t = 10 (± 1) (APP-02.8); pasteboard cleared at the lock |
| T34 APP-03.17 background | Mode `background`; a text editor was active before App | `copy.username` | App's window behind the editor's window; the editor is active; Cmd+V there pastes `demo@example.com` |
| T35 APP-03.17 not for dialogs | `window.hide_on_copy` on | `copy.totp_dialog` | Window stays |
| T36 APP-03.18 drag out | Drag "Demo Mail" from the list onto a text editor window | Drop | The editor receives no text |
| T37 APP-03.18 drag text | Show the password in the detail view, select it, drag it | Drag | No drag starts |
| T38 APP-03.18 drops | Drop a `.txt` file and a link on the main window | Drop | Nothing opens or runs (AT-E06) |
| T39 APP-03.19 screen copy | Password shown in the editor field and in the unlock form after Show, fully selected | Edit > Copy, Cut, the context menu | The context menu has no Copy or Cut; the pasteboard's change count is unchanged (nothing written); the plain AppKit copy wrote nothing (Swift test `shownPasswordNoCopy`) |
| T40 APP-03.20 | Command line tool copy of "Demo Mail" password with delay 2 | Run; another app writes `other` at t = 1 | At t = 3 the pasteboard holds `other`; with no interference it is empty at t = 2 (± 0.5); markers present while it was there |
| T41 APP-03.21 | Delay 10 | `copy.field` "PIN" | Notice "PIN copied. Clears in 10 s."; notice text does not contain `4321` |
| T42 APP-03.21 off | Clear off | `copy.username` | Notice "Username copied." |
| T43 APP-03.22 | Debug build with memory scan | `copy.password`, wait 1 s | `demo-pass-1` found only in the pasteboard server, not in App's memory (AT-C02 method) |
| T44 APP-03.10 refused write | `copy.password` done, still ours; the fake pasteboard refuses the next write | `copy.username` | `MSG-COPY-FAILED`; the pasteboard no longer holds `demo-pass-1` (cleared first); no timer; nothing tracked (unit test `refused_copy_leaves_nothing_of_ours`) |
| T45 APP-03.1 fingerprint | An entry with an SSH key in the detail view | "Copy fingerprint" | Pasteboard holds the fingerprint the row shows, with the markers; notice "Fingerprint copied. Clears in 10 s." (test `app_03_copy_fingerprint`) |

## How this was learned

- Read the reference's clipboard object: how it writes the text and the platform marker types, what it remembers, the one-second countdown, the percentage and text it reports, what a delay of 0 does, the clear routine (text comparison with the clipboard and the selection, clearing both), and that it clears when the application is about to quit.
- Read the macOS pasteboard converter that maps the concealed marker to `org.nspasteboard.ConcealedType` with the value's UTF-8 bytes as data.
- Read every call site that copies: the vault view's copy routines (username, password, URL, title, notes, custom fields, one-time code, password plus code), the routine that copies and then minimizes or lowers the window, the copy of selected text and the main window's take-over of the system copy shortcut, the double-click handling of the entry list, the detail view's double-click copies, the generator, the one-time code dialogs, the SSH agent page, the Auto-Type picker and the About window.
- Read the main window's menu definitions (which copy items are enabled when) and the vault view's lock routine (clipboard cleared first).
- Read the entry list's drag code (ids only, private type) and the main window's drop handling (vault files by extension).
- Read the settings screen definitions for the delay range (1 to 999 seconds) and the copy options, and the defaults table; compared with the tag of the installed version 2.7.11 (same behavior; the installed binary contains the concealed marker type name).
- Read the command line tool's copy command and its use of the system copy program on macOS; checked its help text in the installed tool (default 10 seconds, 0 for unlimited). The real clipboard of this Mac was not used; AT-D01 to AT-D03 and V-A03-1 to V-A03-3 are left to Verify.
