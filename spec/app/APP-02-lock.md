# APP-02 Lock rules

Status: reviewed
Epics: E6-S2
Parity rows: SR-01, SR-02, SR-03, SR-09, SR-16, SC-03, SI-07, SD-12

## What it does

Locking turns an unlocked vault back into a locked one: Larsal saves or drops pending changes, wipes every decrypted secret of that vault from memory, and shows the unlock view in its place. The file stays open in the session, so the user can unlock it again with full credentials (APP-06) or with Touch ID (APP-04).

This card lists every event that locks, which vaults each event locks, what happens to unsaved work, what is kept and what is dropped, what the locked window shows, the macOS system events Larsal listens to, and the timings. Saving itself is APP-05. The unlock view and its messages are APP-06. Clipboard clearing is APP-03. Quick unlock is APP-04. Command line flags of the desktop app are APP-09. Menus, shortcuts and the menu bar icon are APP-08.

## Inputs and outputs

In:
- The app settings below (APP-01 owns the inventory; if APP-01 gives a different ID to one of these, APP-01 wins).
- System events from macOS (APP-02.5 to APP-02.8).
- User activity in Larsal's own windows (APP-02.2).
- User actions and requests from other parts of Larsal (menus, the desktop app's lock flag, the browser bridge, Auto-Type).

Out:
- Each affected vault is locked, or stays unlocked when the user cancels a prompt.
- A "vault locked" signal to the integrations (browser bridge INT-01, SSH agent INT-06, menu bar icon APP-08) and to the screen.

### Settings

| ID | Meaning | Reference default | Larsal default | Range |
|---|---|---|---|---|
| `lock.idle.enabled` | Lock all vaults after a period with no activity in Larsal | on | on | on / off |
| `lock.idle.seconds` | Length of that period | 900 | **300** (plan/security.md, stricter) | 10 to 43,200 seconds (12 hours) |
| `lock.on_screen_lock` | Lock all vaults when the screen locks (and, in Larsal, before sleep: APP-02.6) | on | on | on / off |
| `lock.on_user_switch` | Lock all vaults when another macOS user takes over the screen | on | on | on / off |
| `lock.on_minimize` | Lock all vaults shortly after the main window is minimized or hidden | off | off | on / off |
| `lock.relock_after_autotype` | Lock a vault again after a global Auto-Type that needed it unlocked (INT-05) | off | off | on / off |
| `window.minimize_after_unlock` | Minimize the window after an unlock (APP-06) | off | off | on / off; excludes `lock.on_minimize` (APP-02.9) |
| `save.on_lock` | Save unsaved changes when locking (APP-05) | on | on | on / off |
| `save.after_every_change` | Save changes as you make them (APP-05) | on | on | on / off |
| `save.non_data_on_lock` | Save changes that are not user data (APP-05) silently when locking | on | on | on / off |

The installed reference (2.7.11) has the same defaults as the source. The reference's settings screen shows the idle period with the unit "sec". The user-switch option is shown only on macOS.

## Rules

APP-02.1 **Scope.** Every automatic trigger (idle, screen lock, sleep, user switch, minimize, quit, the desktop app's lock flag) locks **every** open vault. There are no per-vault lock settings: all settings above are app settings, the same for every vault. A changed lock setting takes effect as soon as the settings are applied: the idle countdown restarts from the full new period, and a turned-off trigger stops at once.

APP-02.2 **What counts as activity.** Only input delivered to Larsal's own windows (the main window, its sheets and dialogs, the Auto-Type picker, the unlock dialog) counts: a key going down or up, a pointer button going down, up or double-clicked, the pointer moving or hovering over a Larsal window, and a scroll-wheel or trackpad scroll event. Activity in other apps does **not** count; Larsal measures inactivity in Larsal, not idle time of the Mac. These do not count either: browser bridge requests, the global Auto-Type hotkey (a system hotkey, not window input), timers (clipboard countdown, auto-save), saves, file changes on disk, and the system Touch ID sheet. Each counted event restarts the idle countdown, but after a restart further events are ignored for 0.5 seconds (a throttle), so a lock can come up to 0.5 seconds earlier than "period after the last event".

APP-02.3 **Idle lock.** When `lock.idle.enabled` is on and no counted activity happened for `lock.idle.seconds`, Larsal locks all vaults (APP-02.1). A stored value below 10 is used as 10 (the reference does the same); Larsal also uses a stored value above 43,200 as 43,200 (the reference has no upper clamp outside its settings screen). The countdown runs whether or not a vault is unlocked; firing with nothing unlocked does nothing, and the countdown starts again. The countdown runs on the wall clock, so time the Mac spends asleep counts toward it (Decided: spec/decisions.md LD-187). While one idle lock is still running (for example while its save or recovery copy is written, APP-02.16), another idle firing is ignored.

APP-02.4 **Lock is idempotent.** Locking a vault that is already locked succeeds at once and does nothing else. Two triggers that arrive together (for example screen lock and user switch) give one lock per vault.

APP-02.5 **Screen lock (macOS).** Larsal observes the system-wide distributed notification `com.apple.screenIsLocked`. When it arrives and `lock.on_screen_lock` is on, Larsal locks all vaults. Larsal registers this observer for delivery at once (`suspensionBehavior: .deliverImmediately`), because AppKit otherwise holds distributed notifications while Larsal is not the front app; so the lock also happens while Larsal is in the background (Decided: spec/decisions.md LD-187). macOS posts it for the Lock Screen command, for the screen saver or display sleep when macOS asks for the password at once, and when the lid closes and the screen locks. The reference listens to this one notification on macOS.

APP-02.6 **Sleep (macOS).** Larsal also observes the workspace notification that the system **will sleep** (`NSWorkspaceWillSleepNotification`) and locks all vaults under the same setting `lock.on_screen_lock`. The lock runs inside the notification handler, before the handler returns, so the vault is locked before the Mac sleeps. The reference has no sleep listener on macOS: there it locks at sleep only when macOS also locks the screen (APP-02.5). Lead decision D-A02-1 (recommended: listen to sleep, as above; the reference's option text already promises "lid is closed", and plan/security.md lists sleep). Decided: spec/decisions.md LD-200 (as recommended); built so in LD-187.

APP-02.7 **User switch (macOS).** Larsal observes the workspace notification that the user session **did resign active** (`NSWorkspaceSessionDidResignActiveNotification`, fast user switching to another account or to the login window). When it arrives and `lock.on_user_switch` is on, Larsal locks all vaults.

APP-02.8 **Minimize.** When `lock.on_minimize` is on, each of these events schedules a lock of all vaults after a delay `d`: the main window is minimized (yellow button, Window menu, Cmd+M), the window is hidden to the menu bar icon (APP-08), or the window is minimized or hidden by the hide-on-copy option (APP-03.17). The delay is `d = clamp(r, 1, 20)` seconds, where `r` is the number of whole seconds left on the clipboard clear countdown (APP-03.11), or 0 when no countdown runs. So a value copied just before minimizing can still be pasted, and Auto-Type and the browser bridge can still finish. Each new minimize event restarts the delay with a freshly computed `d`. Restoring the window does **not** cancel a scheduled lock. Larsal computes `r` from the countdown that is actually running; the reference reuses the last countdown value even after the clipboard was cleared early (a stale value), which can make its delay up to 20 seconds when nothing is pending. Differs from the reference on purpose (bug fix).

APP-02.9 **Minimize after unlock excludes lock on minimize.** Turning `window.minimize_after_unlock` on turns `lock.on_minimize` off and disables its switch, with a note that the two cannot be used together (message `MSG-LOCK-MIN-CONFLICT`). Otherwise every unlock would minimize the window and then lock again. Larsal enforces the rule in the settings model too: if a settings file holds both as on, `lock.on_minimize` is treated as off.

APP-02.10 **Hide Larsal (Cmd+H).** Hiding the whole app (Larsal menu > Hide Larsal, Cmd+H) is treated like a minimize for APP-02.8. In the reference, hiding the app does not change the window's minimized state, so it does not lock (observed in the source: only the minimized-state change and the hide-to-menu-bar path schedule the lock; Verified 2026-10-28, V-A02-1: the delayed lock has exactly two callers, the window's minimized-state change and the hide routine, and nothing in the reference listens for the app being hidden). Lead decision D-A02-2 (recommended: treat Hide Larsal as minimize; "out of sight" is the user's intent in both cases). Decided: spec/decisions.md LD-200 (as recommended); built so in LD-187.

APP-02.11 **Quit.** Every way of quitting runs the same flow: Larsal menu > Quit (Cmd+Q), Quit from the Dock, Quit from the menu bar icon menu, closing the main window when Larsal is not set to stay running in the menu bar (APP-08), and system logout, restart or shut down. Steps:
1. Try to lock every open vault, one after the other, in the order of the vault list (APP-02.15 for each). A cancelled prompt on one vault does not stop Larsal from trying the next ones (the reference does the same).
2. If any lock failed (the user cancelled a prompt), quitting stops after all vaults were tried. Every vault that locked stays locked; the ones that did not lock stay unlocked.
3. When all are locked, close every vault (each closed vault's quick unlock item is removed, APP-04), clear Larsal's clipboard value if it is still on the clipboard (APP-03.15), and exit.

APP-02.12 **Lock request from the command line.** The desktop app's lock flag (APP-09) sends a lock request to the running instance, which then locks all vaults like `action.lock_all` (APP-02.13), but as an automatic trigger (APP-02.16). The sending process does not wait for the outcome inside the running app. It prints that the vaults have been locked and exits with status 0 once the request was delivered, even if a prompt in the running app later cancels a lock. If the request cannot be delivered to a running instance, it prints that locking failed and exits with status 1. If no instance is running, it prints that Larsal is not running and nothing needs locking, and exits with status 0 (a script that wants "no unlocked vault" has succeeded). Messages and exit codes: M09-02, M09-03 and M09-04 of APP-09 (APP-09.10, APP-09.11).

APP-02.13 **Manual lock actions.**
- `action.lock_vault` "Lock <vault name>" (Cmd+L, the toolbar lock button, the vault switcher menu): locks the vault on screen.
- `action.lock_all` "Lock everything" (vault switcher menu, Vault menu, menu bar icon menu): locks every open vault.
- Both are enabled only when at least one vault (for `action.lock_vault`: the shown vault) is unlocked.
- After `action.lock_vault`, Larsal keeps showing the vault that was just locked, now as its unlock view (as in design/mockup.html). The reference instead switches to the first vault in its list that is still unlocked, if any. Lead decision D-A02-3 (recommended: stay, per the mockup). Decided: spec/decisions.md LD-200 (as recommended).

APP-02.14 **Locks requested by integrations.**
- The browser extension can ask Larsal to lock (INT-01). Larsal locks the vault the bridge is currently using (the shown vault), not all vaults.
- When `lock.relock_after_autotype` is on and a global Auto-Type needed a locked vault to be unlocked first, Larsal locks that one vault again after typing finished or after the retype time ran out (INT-05).

APP-02.15 **What locking does.** For one vault, in this order:
1. If the vault is already locked: success, stop (APP-02.4).
2. If an unlock of this vault is still running (the KDF is working): cancel that unlock and discard its result; the vault stays locked. Lead decision D-A02-4: the reference reports such a vault as already locked and lets the unlock finish, so a screen lock during an unlock can leave the vault unlocked right after (Verified 2026-10-28, V-A02-2: the reference runs the KDF on a worker thread while a nested event loop keeps the window live; a lock that arrives then finds the unlock form still showing, counts the vault as locked and returns, and the unlock then finishes and opens the vault). Recommended: cancel, as written. Decided: spec/decisions.md LD-200 (as recommended).
3. If the vault is being reloaded or merged from a changed file (APP-05): wait until that ends, then continue. The reference refuses the lock in this case and does not retry. Recommended Larsal behavior as written (stricter; no lock is lost).
4. If a save of this vault is running: wait until it ends, then continue. The reference retries every 200 ms; Larsal may wait on the save directly. A quit waits too (the reference aborts the quit when a save is running; Verified 2026-10-28, V-A02-3: its lock refuses while a save runs and tries itself again 200 ms later; a quit needs every vault locked first, so the quit stops there, and the later retry locks that vault while the app keeps running). An automatic trigger waits at most 1 second for the save (APP-02.16; F-101, LD-228 (4)).
5. Close every dialog and sheet that belongs to this vault: one-time code display, one-time code setup, the QR code and key export, website icon download, text prompts, history views. Dialogs of other vaults stay.
6. Clear Larsal's clipboard value if it is still on the clipboard (APP-03.15). This happens even if the user cancels the lock in step 7 or 8.
7. If the entry or group editor has unsaved edits (an attachment copy changed in another app counts, MOD-05.13): see APP-02.16 for automatic triggers. For a manual lock or quit, ask "Lock now and lose your unsaved edits?" with buttons Discard and Cancel, Cancel being the default (`MSG-LOCK-DISCARD-EDIT`; LD-227 (2), LD-244 (2)). Cancel: the lock fails and the vault stays unlocked. Discard: the edits are dropped. Close Vault asks the editor's unsaved-changes question instead (Save, Discard, Cancel; LD-199 (2)); Cancel keeps the vault open (LD-244 (1)). A changed attachment copy alone (the editor otherwise untouched) asks MOD-05.13's question first (Save, Discard), and the close waits: after the answer the user chooses Close Vault again.
8. If the vault has unsaved data changes:
   - When `save.on_lock` or `save.after_every_change` is on, save (APP-05). If the save worked, continue.
   - If that save failed because the file changed on disk and a reload started (APP-05), the lock fails.
   - If the save did not run or failed for another reason, ask "<vault name> was changed. Save the changes?" (or "The vault was changed. Save the changes?" when it has no name) with Save, Discard and Cancel, Save being the default (`MSG-LOCK-SAVE`). Save: save again; if that fails, the lock fails. Discard: changes are lost. Cancel: the lock fails.
   - If the vault has only changes that are not user data and `save.non_data_on_lock` is on, save silently and ignore a failure.
   - For an automatic trigger, APP-02.16 replaces both questions of this step and of step 7.
9. Remember the selected group (the root group when none) and the selected entry, by id only.
10. Remove this vault's keys from the SSH agent (INT-06, SI-07), end any search, and clear the entry editor, the history editor, the group editor and the detail view.
11. Drop the decrypted vault. Every secret of it is wiped (SR-07): entries, attachments, protected values, the composite key and derived keys (FMT-04.19). Keep only what APP-02.17 lists.
12. Show the unlock view for the vault (APP-02.18), send the "vault locked" signal (browser bridge notice INT-01, menu bar icon state APP-08), and report success.
13. A vault that was never saved to a file is closed after it locked (the reference closes it, since there is nothing to unlock from). See APP-07 for when such a vault can exist.

APP-02.16 **Automatic triggers never wait.** For idle, screen lock, sleep, user switch, minimize, the lock flag (APP-02.12) and system logout, Larsal asks neither question of APP-02.15 steps 7 and 8 (Decided: spec/decisions.md LD-50, option (d)):
- Unsaved edits in the entry or group editor are dropped, and so is an attachment copy changed in another app, even while its MOD-05.13 question shows (LD-227 (1); T46, T64).
- Unsaved data changes are saved as step 8 says. Larsal waits at most 1 second for each changed vault's save, one vault after the other (N stalled vaults wait N seconds, LD-228 (2)), then locks; a save still running then goes on and writes the file, or, when it does not write, keeps the change in the recovery copy itself (F-101, LD-228 (4); T63). If the save does not run (both save settings off), fails, or meets a file that changed on disk (APP-05.10 step 3, APP-05.28), Larsal writes a **recovery copy** instead and then locks. A recovery copy is a normal vault file holding the vault as it was in memory, encrypted with the vault's current key, written with the safe method (APP-05.11) at mode 0600 into the folder `recovery` (mode 0700) of Larsal's settings folder. Its file name is the SHA-256 of the vault's real path in lowercase hex plus `.larsalvault`; a newer recovery copy for the same vault replaces the older one.
- If the recovery copy cannot be written either, Larsal still locks. Its session remembers the loss in memory for the rest of the run (keyed by the copy's name; no vault content), also with a memory-only settings store, and Larsal leaves an empty marker file (mode 0600) with the same name plus `.lost` in that folder, so the next unlock can tell the user, also after Larsal was quit. When the marker cannot be written either (the `recovery` folder read-only, a full disk), the memory note is the only trace: an unlock in the same run still tells the user; after a restart nothing does. Larsal tries no second place for the marker, since the real causes (a full disk, a settings folder Larsal cannot write) stop every place alike (Decided: spec/decisions.md LD-224).
- At the next unlock of that vault (APP-06, APP-04): with a recovery copy, Larsal asks `MSG-LOCK-RECOVERY` "<vault name> was locked with changes that could not be saved. Merge them into the vault now?" with Merge (default) and Discard. Merge opens the copy with the key just used (when that key fails, the unlock sheet asks for the copy's credentials; Cancel keeps the copy for the next unlock), merges it into the vault (MOD-11), and saves (APP-05). Discard drops it. After Merge or Discard the copy is deleted. With a `.lost` marker or a loss remembered in memory, Larsal shows `MSG-LOCK-LOST` "Changes made to <vault name> since the last save could not be kept when it was locked." with OK, then deletes the marker and forgets the loss.
- An automatic trigger that arrives while a question of a manual lock, close or quit is open closes that question and goes on as an automatic lock.
A manual lock (`action.lock_vault`, `action.lock_all`, the browser bridge request of APP-02.14), close and quit keep both questions of APP-02.15. The reference asks both questions for every trigger, so an unattended Mac with an open, edited entry, or with a save that fails, never locks.

APP-02.17 **Kept and dropped on lock.**

| Kept while locked | Dropped (wiped) |
|---|---|
| The vault's place in the vault list and its file path | The whole decrypted vault: groups, entries, history, attachments, custom data, metadata (including the vault name and color stored inside) |
| The public header information used by the unlock view (APP-06) | Every protected and unprotected field value, and every value the user had shown with Show |
| The ids of the group and entry selected before the lock | The composite key and every derived key (FMT-04.19) |
| The quick unlock item, when quick unlock is on (APP-04) | The search text and results, the editor and detail view contents, and the vault's dialogs |
| The last used key file path, when the app setting to remember key files is on (APP-06) | The vault's SSH keys in the agent (INT-06) |
| The app settings and the idle countdown | Larsal's clipboard value, if still on the clipboard (APP-03) |
| A recovery copy or `.lost` marker, when APP-02.16 wrote one (encrypted file, outside the session), and APP-02.16's memory note of a lost change (the copy's name only) | |

APP-02.18 **The locked window.** Locking never hides, minimizes or moves the window, and never brings Larsal to the front. The window keeps its size and place and shows the unlock view of the vault that is on screen (APP-06; the Touch ID form when APP-04 offers it). The sidebar, the entry list and the detail view are gone. The vault switcher marks every locked vault with a lock icon (design/mockup.html). The window title shows the vault's file name, because the vault name is stored inside the encrypted part; the reference adds the word "Locked" in brackets to the tab name. Menu items that need an unlocked vault are disabled (APP-08).

APP-02.19 **Unlock after a lock.** After the vault is unlocked again (APP-06, APP-04), Larsal selects the remembered group and entry when they still exist (else the root group and no entry). The list of expired and soon-expiring entries that Larsal may show after an unlock (SR-08, APP-06) appears only on the first unlock of a vault after it was opened, not after a re-lock. A screen unlock, wake from sleep, or switch back to the user never unlocks a vault by itself.

APP-02.20 **Timings.**
- Every automatic trigger starts locking within 1 second of the event (idle: of the moment the period ends; minimize: of the end of the delay `d`).
- Idle: the lock starts between `lock.idle.seconds − 0.5` and `lock.idle.seconds + 1` seconds after the last counted activity.
- When no prompt is needed, a lock finishes within 1 second after it started: secrets dropped, the unlock view shown, SSH keys gone from the agent (AT-H01). A save that step 8 runs may add its own time (APP-05).
- Sleep: the lock finishes before the will-sleep handler returns.

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| Two vaults unlocked, the user cancels the save prompt of the first during "Lock everything" | The first stays unlocked; Larsal still locks the second (the reference tries every vault too). For quit the same, and then quitting stops (APP-02.11 step 2). |
| Idle lock fires while the "Save the changes?" prompt of an earlier manual lock is open | The prompt closes; the vault locks as an automatic lock, with a recovery copy when the save fails (APP-02.16). |
| Screen lock and sleep arrive within the same second | One lock per vault (APP-02.4). |
| `lock.idle.seconds` stored as 5 | Used as 10. Stored as 100,000: used as 43,200. Not a number: the default 300 (APP-01 general rule for bad values). |
| Minimize, then restore after 2 s, with nothing copied | The lock still happens at 1 s after the minimize (APP-02.8): `d = 1`. |
| Minimize 3 s after a copy with a 10-second clear time | `r = 7`, lock 7 s after the minimize, at about the moment the clipboard clears. |
| Minimize right after a copy with a 30-second clear time | `d = 20` (upper bound). |
| Lock requested while the vault is saving | Waits for the save, then locks (APP-02.15 step 4). |
| Lock requested during a reload after a change on disk | Waits for the reload, then locks (APP-02.15 step 3). |
| Lock requested while the vault is being unlocked | The unlock is cancelled; the vault stays locked (APP-02.15 step 2). |
| The vault file was deleted or moved while unlocked, changes pending, lock | The save writes the file anew (APP-05.10 step 1). If its folder is gone too, the save fails: a manual lock asks `MSG-LOCK-SAVE` (Discard locks); an automatic trigger writes a recovery copy and locks (APP-02.16). The unlock view then reports the missing file (APP-06). |
| Lock flag used with no Larsal running | Prints M09-04, exit status 0 (APP-02.12). |
| Lock flag delivered, then the user presses Cancel on a save prompt in Larsal | The flag already printed M09-02 and exited 0; that vault stays unlocked. |
| Fast user switch away and back | The vaults are locked when the user returns; nothing unlocks by itself (APP-02.19). |
| System logout while a vault has an edited entry open | The quit flow runs (APP-02.11). For a manual quit the editor question is asked; for logout Larsal treats the trigger as automatic (APP-02.16) and drops editor edits, then saves, or writes a recovery copy when the save fails. If macOS cancels the logout because Larsal did not finish in time, Larsal keeps whatever state it reached. Reference: asks (Verified 2026-10-28 from the source, V-A02-4: its quit runs the same lock routine for a logout as for a manual quit, so the editor question appears). Whether macOS then stops the logout needs Mac QA (owner's go), V-A02-4: it takes a real logout of a session with the window app running. |
| `lock.on_minimize` and `window.minimize_after_unlock` both on in the settings file | `lock.on_minimize` is treated as off (APP-02.9). |

### Not on Mac (reference behavior on other systems, for later ports)

- Windows: locks on session lock, console disconnect, system suspend and lid closed (power setting change).
- Linux: locks when a screen saver becomes active (freedesktop, GNOME, Xfce, Unity), on the login manager's "prepare for sleep" and session "lock" signals, and when the GNOME session reports the idle presence state. The user-switch option is hidden there; switching users locks the session, which already locks.
- Linux: a desktop-bus method lets other programs lock all vaults, and the freedesktop secret service can lock a vault.
- Windows and Linux: settings that send the window to the tray when it is minimized or closed (the macOS equivalents are in APP-08).

## Security notes

- **The point of locking is to drop secrets.** After a lock, no decrypted vault data, no Show value and no key derived from the master key may remain in Larsal's memory or in the screen layer (SR-07, AT-C01, AT-E07). Only the encrypted quick unlock item of APP-04 may remain, and only when quick unlock is on.
- **Never let a prompt keep a vault open forever.** The reference waits on its editor and save questions for every trigger, so an idle or screen lock can silently fail on an unattended Mac. APP-02.16: no question ever holds an automatic lock; a save that cannot finish goes to an encrypted recovery copy (LD-50, SR-16). Only a manual lock, close or quit asks, with the user at the Mac.
- **Recovery copies** are full encrypted copies of the vault, mode 0600 in a 0700 folder. Like backups, they still open with the key they were written with after a later key change; the key change notice offers to delete them (APP-05.33, LD-53). They are deleted after Merge or Discard.
- **Never finish an unlock after a lock trigger.** APP-02.15 step 2 closes the window where a screen lock during a running KDF would unlock the vault right after the screen locked.
- **Clipboard first.** The clipboard is cleared before any question is asked (APP-02.15 step 6), so a cancelled lock still removes a copied password (SC-03, AT-D03).
- **Larsal inactivity, not Mac idle time.** Activity in other apps never keeps a vault unlocked (APP-02.2). This is stricter than locking on system idle time.
- **The sleep listener** (APP-02.6) must lock before the handler returns; a lock that is merely scheduled may never run before the Mac sleeps.
- **The lock flag** can be sent by any process of the same user. It can only lock, never unlock, so this is safe (SR-09).
- Parity rows: SR-01 (idle), SR-02 (screen lock, sleep, user switch), SR-03 (minimize, quit), SR-09 (command line lock), SC-03 (clipboard on lock and quit), SI-07 (SSH keys on lock), SR-16 (save before lock; no question stops an automatic lock), SD-12 (copies that keep the old key). Attacks: AT-K01 (lock events), AT-C01 (secrets after lock), AT-E07 (screen layer after lock), AT-H01 (SSH keys within 1 second), AT-D03 (clipboard on lock and quit).

## Test cases

Times are seconds after the first step of the case. "Demo vault A" holds one group "Mail" with one entry "Demo Mail" (user `demo@example.com`, password `demo-pass-1`), saved, password `demo-master-A`. "Demo vault B" is the same with "Demo Bank" and `demo-master-B`. Platform events are injected through the `lock_signals` trait of larsal-platform in unit tests; AT-K01 repeats the real events on this Mac.

| Case | Given | When | Then |
|---|---|---|---|
| T01 APP-02.1 | A and B unlocked | Screen-lock event | Both locked |
| T02 APP-02.1 | A unlocked, `lock.idle.seconds` 300, countdown at 120 s left | Settings applied with 60 | The countdown restarts at 60: lock at t = 60, not t = 120 |
| T03 APP-02.2 | A unlocked, idle 10 s | Keys typed in the search field at t = 0, 4, 8; nothing after | Lock between t = 17.5 and t = 19 |
| T04 APP-02.2 throttle | A unlocked, idle 10 s | Pointer moves over the window at t = 0.0 and t = 0.3 only | Lock between t = 9.5 and t = 11 (the event at 0.3 was ignored) |
| T05 APP-02.2 other apps | A unlocked, idle 10 s | At t = 0 Larsal goes to the background; the user types in another app for 30 s | A locked between t = 9.5 and t = 11 |
| T06 APP-02.2 not activity | A unlocked, idle 10 s | Browser bridge requests every 2 s and a clipboard countdown running | A locked between t = 9.5 and t = 11 |
| T07 APP-02.3 minimum | Settings file holds `lock.idle.seconds` = 3 | A unlocked, no activity | Lock between t = 9.5 and t = 11 |
| T08 APP-02.3 maximum | Settings file holds 100000 | Read settings | Effective period 43,200 |
| T09 APP-02.3 off | `lock.idle.enabled` off | A unlocked, no activity for 1 hour | A stays unlocked |
| T10 APP-02.3 nothing unlocked | Only locked vaults, idle 10 s | Wait 25 s, then unlock A at t = 25 with keys typed | No error; A locks about 10 s after the last key |
| T11 APP-02.4 | A locked | `action.lock_all` | Success; no prompt; no save; no signal sent again |
| T12 APP-02.5 | A unlocked, `lock.on_screen_lock` on | Post `com.apple.screenIsLocked` | A locked within 1 s |
| T13 APP-02.5 off | Same, setting off | Post the notification | A stays unlocked |
| T14 APP-02.6 | A unlocked, setting on | Will-sleep notification | A is locked before the handler returns |
| T15 APP-02.7 | A unlocked, `lock.on_user_switch` on | Session-resign-active notification | A locked within 1 s |
| T16 APP-02.8 no copy | A unlocked, `lock.on_minimize` on, nothing copied | Minimize at t = 0 | A locked at t = 1 (± 1) |
| T17 APP-02.8 with copy | Clear time 10 s; copy at t = 0 | Minimize at t = 3 | `r` = 7; lock at t = 10 (± 1) |
| T18 APP-02.8 bound | Clear time 30 s; copy at t = 0 | Minimize at t = 0.5 | `d` = 20; lock at t = 20.5 (± 1) |
| T19 APP-02.8 restore | Nothing copied | Minimize at t = 0, restore at t = 0.5 | A still locked at t = 1 (± 1) |
| T20 APP-02.8 restart | Clear time 10 s; copy at t = 0 | Minimize at t = 1 (`d` = 9, lock due at 10); restore at t = 2; copy again at t = 5; minimize at t = 6 (`r` = 9, `d` = 9) | No lock at t = 10; A locked at t = 15 (± 1) |
| T21 APP-02.8 stale value fixed | A and B unlocked, `lock.on_minimize` on; clear time 10 s; copy from A at t = 0; lock B at t = 2 clears the clipboard early (APP-03.15); A stays unlocked | Minimize at t = 3 (had the countdown not stopped, `r` would be 7) | `d` = 1 (no countdown runs), A locked at t = 4 (± 1) |
| T22 APP-02.8 hide to menu bar | Menu bar icon on, `lock.on_minimize` on | Hide the window via the menu bar icon | Same delay rule; A locked |
| T23 APP-02.9 | `lock.on_minimize` on | Turn `window.minimize_after_unlock` on | `lock.on_minimize` is off and disabled; note `MSG-LOCK-MIN-CONFLICT` shown |
| T24 APP-02.9 file | Settings file with both on | Unlock A (window minimizes) and wait 25 s | A stays unlocked |
| T25 APP-02.10 | `lock.on_minimize` on, nothing copied | Cmd+H | A locked at t = 1 (± 1) (D-A02-2) |
| T26 APP-02.11 | A and B unlocked, no unsaved changes, demo value copied | Cmd+Q | Both locked, both closed, their quick unlock items gone, clipboard cleared, Larsal exits |
| T27 APP-02.11 cancel | A unsaved changes and its save fails; B unlocked; list order A, B | Cmd+Q, press Cancel on A's `MSG-LOCK-SAVE` | Larsal keeps running; A unlocked; B locked |
| T28 APP-02.11 later cancel | Order A, B; B's save fails | Cmd+Q, Cancel on B's prompt | Larsal keeps running; A locked; B unlocked |
| T29 APP-02.12 | Larsal running, A and B unlocked | Run the desktop app with the lock flag | Both locked; the second process prints M09-02, exit 0 |
| T30 APP-02.12 none | Larsal not running | Run with the lock flag | Prints M09-04, exit 0 |
| T31 APP-02.12 undeliverable | A test listener holds the instance lock, accepts the connection and never answers (APP-09.13) | Run with the lock flag | Prints M09-03, exit 1 |
| T32 APP-02.13 | A shown and unlocked, B unlocked | Cmd+L | A locked and still shown (unlock view); B unlocked (D-A02-3) |
| T33 APP-02.13 enabled | All vaults locked | Open the vault menu | Lock items disabled |
| T34 APP-02.14 browser | A shown and unlocked, B unlocked | Browser bridge lock request (INT-01) | A locked; B unlocked |
| T35 APP-02.14 Auto-Type | `lock.relock_after_autotype` on; A locked | Global Auto-Type, unlock A in the dialog, typing ends | A locked again |
| T36 APP-02.15 step 2 | A being unlocked (slow KDF, 3 s) | Screen-lock event at t = 1 | When the KDF ends, A is still locked; no vault data was loaded |
| T37 APP-02.15 step 4 | A saving (slow disk, 2 s) | `action.lock_vault` at t = 0.5 | Lock completes after the save ends; file is the new version |
| T38 APP-02.15 step 5 | A unlocked with the one-time code display of "Demo Mail" open | Lock A | The display is closed; B's open dialogs stay |
| T39 APP-02.15 step 6 | A unlocked, `demo-pass-1` copied, editor with unsaved edits | Cmd+L, then Cancel | Clipboard empty; A still unlocked |
| T40 APP-02.15 step 7 | Editor of "Demo Mail" with the title changed to "Demo Mail 2", not applied | Cmd+L, Discard | A locked; after unlock the title is "Demo Mail" |
| T41 APP-02.15 step 8 save | `save.after_every_change` off, `save.on_lock` on, title changed and applied | Cmd+L | File saved, then locked; after unlock the title is the new one; no prompt |
| T42 APP-02.15 step 8 ask | Both save settings off, change applied | Cmd+L | `MSG-LOCK-SAVE` naming the vault; Discard: locked, the file is unchanged |
| T43 APP-02.15 step 8 unnamed | Vault with empty name, both save settings off, change applied | Cmd+L | The no-name form of `MSG-LOCK-SAVE` |
| T44 APP-02.15 steps 9 to 11 | A unlocked, group "Mail" and "Demo Mail" selected, one SSH key from A in the agent, search "demo" active | Lock A | Agent lists no key of A within 1 s; search cleared; a memory scan (AT-C01, debug build) finds neither `demo-master-A` nor `demo-pass-1` |
| T45 APP-02.15 step 13 | A vault never saved to a file (if APP-07 allows one) | Lock everything | It is closed, not kept as a locked entry |
| T46 APP-02.16 | Editor with unsaved edits, idle 10 s | No activity | A locked between t = 9.5 and t = 11 without a prompt; edits gone |
| T47 APP-02.16 save failed | Vault folder made read-only, a change applied whose auto-save failed | Screen-lock event | No prompt; A locked; one recovery copy in Larsal's settings folder, mode 0600, named by the SHA-256 of A's real path; it opens with `demo-master-A` and holds the change |
| T48 APP-02.17 | A unlocked, key file `demo.larsalkey` used, remember key files on | Lock A | Unlock view shows A's path and the key file path; vault name from inside the file not shown |
| T49 APP-02.18 | A unlocked, window at a known size and place, Larsal in the background | Idle lock | Window size and place unchanged; Larsal not brought to the front; unlock view shown; switcher shows A with a lock icon |
| T50 APP-02.19 | Group "Mail", entry "Demo Mail" selected; one expired demo entry exists; expired-entries option on | Lock, unlock | "Mail" and "Demo Mail" selected; no expired-entries list (it was shown at the first unlock only) |
| T51 APP-02.19 no auto-unlock | A locked by screen lock | Unlock the Mac screen | A stays locked |
| T52 APP-02.20 | A unlocked, no prompt needed | Screen-lock event; measure | Unlock view shown and secrets dropped within 1 s of the event |
| T53 APP-02.16 merge | As T47, then the folder made writable again | Unlock A | `MSG-LOCK-RECOVERY`, Merge the default; Merge: the change is in A and saved to the file; the recovery copy is gone |
| T54 APP-02.16 discard | As T47 | Unlock A, Discard | A without the change; the recovery copy is gone |
| T55 APP-02.16 copy and marker fail | As T47, plus the `recovery` folder made read-only | Screen-lock event, then unlock A in the same run | A locked without a prompt; no copy and no marker in `recovery`; the session holds the memory note for A's copy name; at unlock `MSG-LOCK-LOST` (from memory), and after OK no note is left |
| T56 APP-02.16 changed on disk | A has an unsaved change (both save settings off); another tool rewrites A's file | Idle lock | No `MSG-DISK-ON-SAVE`, no prompt; recovery copy written; A locked |
| T57 APP-02.16 manual keeps the question | As T47 | Cmd+L | `MSG-LOCK-SAVE` shown; A stays unlocked until answered; no recovery copy |
| T58 APP-02.16 automatic closes a manual question | As T57, the question left open; idle 10 s | No activity | The question closes; recovery copy written; A locked between t = 9.5 and t = 11 |
| T59 APP-02.16 old key | As T47; A's password then changed on another Mac and the file synced | Unlock A with the new password | Merge asks for the recovery copy's credentials; `demo-master-A` opens it and the merge runs; Cancel keeps the copy |
| T60 APP-02.3 sleep counts | A unlocked, idle 60 s; a fake clock in place of the one that keeps counting while the Mac sleeps | The clock jumps from t = 0 to t = 120 in one step (as when the Mac wakes), then the timer runs | A locked at that first run, with no further wait (LD-187) |
| T61 APP-02.5 background | A unlocked, `lock.on_screen_lock` on, Finder the front app | Post `com.apple.screenIsLocked` on the system's distributed center | A locked within 1 s, while Larsal is still in the background (LD-187) |
| T62 APP-02.16 copy fails, marker kept | As T47, plus a folder in `recovery` where A's copy would go (the copy's name taken) | Screen-lock event; quit Larsal, start it again, unlock A | A locked without a prompt; an empty `<copy name>.lost` marker, mode 0600, beside that folder; after the restart, at unlock `MSG-LOCK-LOST`; the marker is gone after OK |
| T63 APP-02.16 save deadline | A changed, `save.on_lock` on; a save of A is running (slow test KDF of 3 s) | Screen-lock event | A locked within about 1 s of the event, without waiting for the save; when the save ends, the file holds the change, or, when it did not write, one recovery copy does (F-101, LD-228 (4)) |
| T64 APP-02.16 changed attachment copy | Editor of "Demo Mail" open; one of its attachments opened in another app and changed there; its MOD-05.13 question showing | Idle lock (idle 10 s, no activity) | A locked between t = 9.5 and t = 11 without a prompt; the question is gone; the copy is wiped; after unlock the attachment holds its old content (LD-227 (1)) |
| T65 APP-02.15 step 7 close | Editor of "Demo Mail" with the title changed to "Demo Mail 2", not applied | Close Vault, Cancel; then Close Vault, Discard | The Save, Discard and Cancel question (LD-199 (2)), not `MSG-LOCK-DISCARD-EDIT`. Cancel: A stays open and unlocked, the edit kept. Discard: A closes; the file still has "Demo Mail" (LD-244 (1)) |
| T66 APP-02.15 step 7 quit | As T65 | Cmd+Q, then Return | `MSG-LOCK-DISCARD-EDIT` with Cancel the default; Return answers Cancel: Larsal keeps running, A unlocked with the edit (LD-227 (2), LD-244 (2)) |

## How this was learned

- Read the reference's app-level inactivity timer (the event filter, the event kinds it counts, the 0.5-second throttle, the 10-second minimum, the guard against double firing) and the main window code that arms it from the settings and connects it to "lock all".
- Read the macOS screen-lock listener (the distributed notification it observes), the reference's bridge to macOS workspace services (the workspace notification for user switching, and the absence of any sleep notification), and the Windows and Linux listeners for the "Not on Mac" list.
- Read the main window's minimize, hide-window and close handlers, the tab container's lock-all, lock-current-and-switch, delayed lock (the 1 to 20 second bound from the clipboard countdown) and user-switch handlers, and the vault view's lock routine (order of steps, questions, save attempts, what it remembers and clears, the SSH agent call, and closing of never-saved vaults).
- Read the single-instance socket handler (message id for "lock") and the start-up code that sends the lock request and prints the three results with their exit codes.
- Read the settings screen definitions (security tab and general tab) for option texts, ranges and the minimize-after-unlock exclusion, and the settings defaults table, in the source and in the tag of the installed version 2.7.11 (same defaults, same lock routine).
- Read the browser bridge's lock request handler and the Auto-Type relock handling.
- Checked the installed app's binary strings for the lock flag messages and the screen-lock notification name. The reference app's window was not launched; behavior of real macOS events on this Mac is left to Verify (V-A02-1 to V-A02-4) and AT-K01.
