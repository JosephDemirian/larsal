# APP-06 Unlock screen behavior and messages

Status: reviewed
Epics: E3-S9 (one plain message per error), E5-S3 (the unlock screen)
Parity rows: SF-04, SF-05, SF-16, SF-18, SR-04, SR-06, SR-08, SR-10, SR-12

## What it does

A vault that is open in Larsal's session but locked shows the unlock view in place of the vault. The user gives the vault's credentials (a password, a key file, a hardware key, in any combination), presses Unlock, and Larsal opens the vault or shows one plain message that says what went wrong and what to do next.

This card owns:
- the unlock view as design/mockup.html draws it: its fields, links, buttons, initial state and focus;
- what happens when Unlock is pressed: how the credentials are built, the empty-password case, the KDF cost question, the hardware key touch prompt, progress;
- what is shown, cleared and focused after a failure, and retrying;
- the one plain message for every error kind of `larsal-format/error.rs` (FMT-01.33), every key file reason, every hardware key reason and every limit; E3-S9 builds this map;
- the order of the steps after a successful unlock, including auto-open (SR-10);
- the unlock sheet and the unlock panel, which reuse the same form for in-app needs and for requests from outside;
- credentials passed in from elsewhere (standard input, auto-open, vault links).

Other cards own the rest: the order of checks inside one open and the error kinds (FMT-05.7, FMT-01.33), key files (FMT-18), the key flow (FMT-04), the cost thresholds (CRY-02.14), the Touch ID form and its slot (APP-04), locking (APP-02), saving (APP-05), the app settings (APP-01), the command line flags (APP-09), secure input and screen protection (APP-10), hardware key devices (INT-07), menus and shortcuts (APP-08).

## Inputs and outputs

In:
- A locked vault in the session: its file path, and the outer header read without a key (FMT-02.27) for the name, tile and colour shown before unlock (FMT-03.23).
- The user's input on the form; or credentials passed in (APP-06.24).
- The settings in the table below.
- Results of `larsal-format`: an opened vault, one `Error` (FMT-01.33), or the "ask the user first" decision with a cost report (CRY-02.14).
- Hardware key detection results (INT-07) and macOS Caps Lock state.

Out:
- An unlocked vault in the session, shown in the main window; or the vault still locked with one message on the form.
- Updated remembered key file and hardware key (APP-01.16) and recent list (APP-01.14).

### Settings used

| Setting (APP-01 ID) | Default in Larsal | Used for |
|---|---|---|
| S-START-08 `recent.remember_keys` | off (LD-51) | Pre-filling the key file and hardware key (APP-06.7, APP-06.8) |
| S-MSG-01 `msg.no_old_keyfile_warning` | off | Skipping the old key file warning (APP-06.11) |
| S-START-11, S-START-12 expiring entries after unlock | on, 3 days | APP-06.22 step 9 (APP-01.18) |
| S-START-04 `window.minimize_after_unlock` | off | APP-06.22 step 12 |
| S-LOCK-01 `quick_unlock.enabled` | on | Which form shows (APP-04) |

### Parts of the view

Texts in quotes come from design/mockup.html. IDs are ours.

| ID | Part | Text and behavior |
|---|---|---|
| UL-TILE | Vault tile | The first letter of the shown name in the mockup's tile; hue from the valid public colour (FMT-03.23), else a hue Larsal derives from the file path, the same on every show |
| UL-TITLE | Heading | "Unlock <name>" |
| UL-PATH | Path line | The file path, with the home folder written as `~` |
| UL-PW | Password field | Placeholder "Password", key icon, eye button "Show password" / "Hide password" |
| UL-ERR | Error line | Below the password field, red; empty when there is no message |
| UL-KEY-LINK | Link | "Use a key file"; shown while UL-KEY is closed |
| UL-KEY | Key file row | Label "Key file", field with placeholder "No key file" and a file icon, button "Browse…" |
| UL-HW-LINK | Link | "Use a security key" (LD-100); shown while UL-HW is closed |
| UL-HW | Security key row | Label "Security key", switch "Use a security key" (LD-100), list "Choose a key and slot" with items in Larsal's form "<model> · serial <serial> · slot <n>", for example "YubiKey 5 NFC · serial 24531878 · slot 2", button "Look for keys again". Item form decided in spec/decisions.md LD-101 (1); the mockup was updated. |
| UL-GO | Primary button | "Unlock"; reads "Unlocking…" while an unlock runs |
| UL-SWITCH | Vault switcher | Top left, "Switch vault"; the mockup's vault menu (APP-08) |
| UL-TOUCH | Touch ID form | APP-04.9: "Unlock with Touch ID", "Checking…", "Use password instead" |

### Messages

Our IDs and our wording. `<file>` is the vault's file name and `<keyfile>` the key file's name, as APP-06.18 cleans them; a passed key file path that holds a protected value (APP-06.24) is named `******` in M06-07 to M06-16 (LD-238 (5), F-080). "Line" means UL-ERR; "alert" a sheet on the window with the buttons given (the default button marked); "toast" the mockup's toast; "banner" the main window's error bar.

Errors of an open (`larsal-format` kinds, FMT-01.33):

| ID | Kind and reason | Where | Text (Larsal) |
|---|---|---|---|
| M06-01 | `NotAVault` | line | "<file>" is not a vault file. Open the file that holds your vault. |
| M06-02 | `OldFormat` | line, with a button "Import…" | "<file>" is in the first vault format. Larsal can only import it: Import… makes a new vault from its contents. |
| M06-03 | `Unsupported` | line | This vault uses a file version or setting that Larsal does not support yet. A Larsal update may open it. |
| M06-04 | `Corrupt` | line | "<file>" is damaged and cannot be unlocked. If you have a backup copy, open that instead. |
| M06-05 | `NoCredentials` | line, with the link "Unlock with a blank password" (APP-06.12) | Enter the password for this vault. |
| M06-06 | `WrongKey` | line | Wrong password, key file or security key. Check them and try again. |
| M06-07 | `KeyFile(Empty)` | line | The key file "<keyfile>" is empty. Choose the right key file. |
| M06-08 | `KeyFile(UnsupportedVersion)` | line | With a version text: The key file "<keyfile>" has version <version>, which Larsal cannot read. Choose another key file. With an empty text: The key file "<keyfile>" has a version Larsal cannot read. Choose another key file. |
| M06-09 | `KeyFile(CheckValueMismatch)` | line | The key file "<keyfile>" is damaged: its built-in check failed. Use a backup copy of the key file. |
| M06-10 | `KeyFile(DataUnreadable)` | line | The key file "<keyfile>" is damaged: Larsal cannot read the key in it. Use a backup copy of the key file. |
| M06-11 | `KeyFile(Io(NotFound))` | line | The key file "<keyfile>" cannot be found. Choose it again. |
| M06-12 | `KeyFile(Io(PermissionDenied))` | line | Larsal is not allowed to read the key file "<keyfile>". Check its permissions in Finder, then try again. |
| M06-13 | `KeyFile(Io(any other kind))` | line | Larsal could not read the key file "<keyfile>". Check that its disk is connected, then try again. |
| M06-14 | `KeyFile(NotRegularFile)` | line | "<keyfile>" is a folder or a special file. Choose a normal file as the key file. |
| M06-15 | `KeyFile(Dtd)` | line | Larsal does not accept the key file "<keyfile>" because it declares a document type. Choose another key file. |
| M06-16 | `KeyFile(TooLarge(any limit))` | line | The key file "<keyfile>" is too complex for Larsal to read safely. Choose another key file. |
| M06-17 | `HardwareKey(Missing)` | line | Your security key is not connected. Plug it in, then try again. |
| M06-18 | `HardwareKey(TimedOut)` | line | The security key was not touched in time. Try again, and touch the key when it flashes. |
| M06-19 | `HardwareKey(SlotNotConfigured)` | line | The chosen slot of your security key is not set up for challenge-response. Choose another slot. |
| M06-20 | `HardwareKey(BadAnswer)`, `HardwareKey(Failed)` | line | Larsal could not use your security key. Unplug it, plug it in again, then try again. |
| MI07-01 | `HardwareKey(NotPermitted)` (INT-07.7; Decided: spec/decisions.md LD-173, LD-175 R07-2) | line | macOS did not let Larsal reach your security key. Allow Larsal under System Settings › Privacy & Security › Input Monitoring, then try again. |
| M06-21 | `TooLarge(KdfCost)` | line | This vault's unlock settings ask for more than this Mac can do. Lower them in the app that made the vault, then try again. |
| M06-22 | `TooLarge(TotalFile)` | line | "<file>" is larger than Larsal can open (about 1 GiB). Make it smaller in the app that made it, for example by removing large attachments. |
| M06-23 | `TooLarge(any other limit)` | line, plus a smaller second line "Limit reached: <limit>" | "<file>" holds more than Larsal can open safely. Make it smaller in the app that made it. |
| M06-24 | `Io(NotFound)` | line | "<file>" cannot be found. It may have been moved, renamed or deleted. Open it from its new place. |
| M06-25 | `Io(PermissionDenied)` | line | Larsal is not allowed to read "<file>". Check its permissions in Finder, then try again. |
| M06-26 | `Io(any other kind)` | line | Larsal could not read "<file>". Check that its disk is connected, then try again. |

Other messages of the unlock flow:

| ID | When | Where | Text (Larsal) |
|---|---|---|---|
| M06-30 | The chosen key file is the vault itself (FMT-18.24) | line | This is the vault file itself, so it cannot also be its key file. Leave the key file empty if the vault has none. |
| M06-31 | The key file's name has a vault file extension (FMT-18.24) | alert: "Use Anyway", "Cancel" (default) | "<keyfile>" has a vault file name. A vault changes with every save, and a key file that changes stops the vault from opening. Use this file anyway? |
| M06-32 | The key file is of an early kind (FMT-18.18) | alert: check box "Do not warn me again", "OK" (default) | "<keyfile>" is a key file of an early kind. It still works, but a future version of Larsal may no longer read it. Vault > Change Credentials… makes a new key file. |
| M06-33 | A key file or security key alone gave `WrongKey` (APP-06.12) | alert: "Try Blank Password" (default), "Cancel" | The key file or security key alone did not unlock this vault. Some vaults also use a blank password. Try once more with a blank password? |
| M06-34 | The KDF cost is in the ask band (APP-06.14) | alert: "Unlock", "Cancel" (default) | Message: This vault is slow to unlock. Details: Unlocking it needs about <memory> of memory and about <time> on this Mac. Unlock anyway? For AES-KDF, which uses no memory: Unlocking it needs about <time> on this Mac. Unlock anyway? When the lanes trigger was hit, one more sentence: It also asks for <lanes> parallel lanes, more than Larsal expects. |
| M06-35 | A security key challenge waits for a touch | line, grey, not red | Waiting for a touch on the security key… |
| M06-36 | "Look for keys again" finished | toast | One key: "Found 1 security key." (mockup) Several: Found <n> security keys. None: Larsal sees no security key. Plug one in and look again. Keys without a usable slot: No slot on the plugged-in security key is set up for challenge-response. |
| M06-37 | Caps Lock is on while a password-kind field has focus (APP-06.6) | note under the field, grey | Caps Lock is turned on. |
| M06-38 | The file's version is newer than 4.1 (APP-06.21; LD-96) | alert: "Unlock Anyway" (default), "Cancel" | "<file>" uses a newer vault format than Larsal knows. Larsal can unlock it, but saving may lose settings that only the newer format holds. |
| M06-39 | Auto-open could not find one or more vaults (APP-06.25) | banner | One: 1 vault listed in the AutoOpen group is missing. Check the paths in that group's entries. Several: <n> vaults listed in the AutoOpen group are missing. Check the paths in that group's entries. |
| M06-40 | The unlock panel or sheet says why it is shown (APP-06.27) | line above the form, grey | Browser request: A browser extension asks to use this vault. Auto-Type: Auto-Type needs this vault unlocked. Merge source: Unlock the vault you want to merge in. |

The reference shows its messages in a message bar above the form. Its texts are not used; where useful, the Edge cases section says what it shows, in our words.

## Rules

### The view

APP-06.1 **Where the form appears.** One form, three places:
- the main window, for the shown vault while it is locked (the mockup's unlock screen; APP-02.18);
- the unlock sheet, attached to the main window, when Larsal itself needs a vault unlocked: a merge source (MOD-11), a recovery copy (APP-02.16), a disk version that opens with other credentials (APP-05.29);
- the unlock panel, a small window of its own, when a request comes from outside: the browser bridge (INT-01, INT-02) or global Auto-Type (INT-05).
The sheet and the panel add a purpose line (M06-40, or the owning card's text) and a "Cancel" button (APP-06.27). Everything else in this card applies to all three.

APP-06.2 **What the view shows.** UL-TILE, UL-TITLE, UL-PATH and the form, centred, as in the mockup. The `<name>` in UL-TITLE and in the vault switcher of a locked vault is the public name from the header when it passes FMT-03.23, else the file name without `.larsalvault`. The vault name stored inside the vault is never used here: it is dropped on lock (APP-02.17). The window title shows the file name (APP-02.18). Reference: its heading is a fixed "unlock" phrase with the product name, plus the public name after a colon when one is set; it draws the public colour as a border and shows the public icon.

APP-06.3 **Header look when the view appears.** When the view is shown for a vault (opened, switched to, or locked), Larsal reads the file's outer header without a key (FMT-02.27), on a worker thread. If that read already fails with `NotAVault`, `OldFormat`, `Unsupported`, `TooLarge`, `Corrupt` or `Io`, Larsal shows that kind's message (M06-01 to M06-04, M06-21 to M06-26) at once in UL-ERR. The form stays usable, because the file may change (a sync finishing). Unlock always reads the file again (APP-06.13). The reference reads the header too but shows nothing until Unlock is pressed. Differs on purpose: the user learns before typing that the file cannot be unlocked.

APP-06.4 **Password form or Touch ID form.** APP-04.9 decides which form shows and APP-04.10 when a Touch ID attempt starts. "Use password instead" and Escape on the Touch ID form (APP-04.15) show the password form with UL-PW focused. When Touch ID worked but the open then fails for a reason other than `WrongKey` (file missing, `Corrupt`, hardware key; APP-04.14, last row), the slot is kept, so the Touch ID form stays (APP-04.9): this card's message shows in an error line under the "Unlock with Touch ID" button, drawn like UL-ERR, and the button keeps the focus. The mockup's Touch ID form has no error line yet; it takes UL-ERR's look. Reference: it also stays on its quick unlock form and shows the open error there.

APP-06.5 **The password field.** UL-PW is a password-kind field (APP-10.9): secure input while focused (APP-10.8), masked unless Show is on, no autofill, no spelling or text substitution, no paste-history suggestions. The eye button and Control-H while the field has focus switch Show on and off (APP-08). Show is switched off whenever an unlock starts and whenever the field is cleared. The field's text goes to `larsal-ffi` (the Rust side; LD-156 renamed `larsal-desktop`) only when an unlock starts (APP-06.10); the screen layer keeps no copy after that (APP-06.17). When the window has been hidden or not active for 30 seconds, and when any lock event of APP-02 fires, Larsal clears the field. The reference clears it 30 seconds after the form is hidden or the window loses activation, and stops that countdown when the form is shown again.

APP-06.6 **Caps Lock note.** While a password-kind field has focus and Caps Lock is on, M06-37 shows under the field; it goes away when Caps Lock goes off or the focus leaves. Larsal checks on focus, on every key press and release, and when Larsal becomes active. The note never covers UL-ERR. It applies to every password-kind field of APP-10.9 except the "repeat" fields of APP-07 and MOD-12.10. Reference: a warning icon inside the field plus a tooltip, checked on focus and key events, skipped on repeat fields (SR-06). Larsal reads the state natively from `NSEvent.modifierFlags` (`.capsLock`), as the built unlock view does. That this state is right while secure input is on needs Mac QA (owner's go), V-A06-6: it takes a person pressing Caps Lock while Larsal's password field has focus; a probe cannot set the key's state without changing the owner's keyboard.

APP-06.7 **The key file row.**
- "Use a key file" opens UL-KEY; the link then hides. UL-KEY is open from the start when the field has a value (APP-06.9). Reference: its link opens the file panel at once, and the key file row appears only once the field holds a path.
- "Browse…" opens the macOS open panel: all files allowed (any file can be a key file, FMT-18), starting in the remembered key file folder (APP-01.15) or the home folder. Choosing a file puts its full path in the field. The field also takes a typed path; `~/` at its start means the home folder; a path that is still not absolute is taken from the vault's folder.
- The path is shown in clear: it is not secret (FMT-18.26). The reference masks it like a password by default; Larsal follows the mockup.
- A chosen or typed path is checked with FMT-18.24 when it is chosen and again when Unlock starts: the vault itself shows M06-30 and keeps the previous value; a name ending in `.larsalvault` or the reference's vault extension (compared without letter case) asks M06-31, and Cancel keeps the previous value. The reference does both checks only after "Browse…", not for a typed path, and on this screen compares the vault extension with letter case (FMT-18.24).
- Clearing the field (select and delete, or its clear button) means "no key file". The row stays open.

APP-06.8 **The hardware key row.**
- "Use a security key" opens UL-HW and turns its switch on. UL-HW is open from the start when a remembered slot exists (APP-06.9).
- When the view appears, Larsal looks for keys in the background (INT-07); when a key is plugged in while the view shows, Larsal looks again after 0.5 seconds; "Look for keys again" looks on request and then shows M06-36. While Larsal looks, the switch, the list and the button are disabled and a small spinner shows. Reference: the same three triggers, 0.5 seconds after a plug-in; after a manual look that found nothing it shows a note for 2 seconds.
- The list holds one item per key and challenge-response slot, in the form of UL-HW. When there is exactly one item it is chosen. When a remembered slot (APP-01.16) is in the list, it is chosen and the switch is on; when it is not in the list, the switch stays off. The list is enabled only while the switch is on. Reference: with a remembered slot for the vault it turns the switch on whenever any key is found, and chooses the first item when the remembered one is absent; with exactly one item it hides the list and names the serial number in the switch label.
- When no key or slot is found, the switch is off and disabled.
- Details of devices, slots and touch: INT-07.

APP-06.9 **Initial state and focus.** When the view appears for a vault: UL-PW empty, focused, Show off; UL-ERR empty unless APP-06.3 found a problem; UL-KEY open and filled only when S-START-08 is on and APP-01.16 holds a key file for this path; UL-HW open only when S-START-08 is on and holds a slot for this path; quick unlock form per APP-04.9 (then "Unlock with Touch ID" has the focus). After a lock the same rules apply; nothing typed before the lock survives (APP-02.17).

### Unlocking

APP-06.10 **Starting an unlock.** UL-GO, or Return in UL-PW or UL-KEY, starts an unlock. While one runs, the whole form is disabled, UL-GO reads "Unlocking…", and further presses do nothing. The reference disables the form and shows a busy cursor; it also ignores a second request while one runs.

APP-06.11 **Building the credentials.** Before any vault byte is parsed, in this order (FMT-05.7 step 0):
1. Password: UL-PW not empty gives the password component `P` (FMT-04.1); empty gives no `P`, except in the retry of APP-06.12. The text goes into a secret type at once (APP-11.9) and the field is cleared (APP-06.17).
2. Key file: when UL-KEY holds a path, run the FMT-18.24 checks (APP-06.7), then read the file (FMT-18). A key file error ends the attempt with its message (M06-07 to M06-16). A key file of an early kind (XML 1.0, Raw 32, Hex 64) shows M06-32 once per unlock attempt, unless S-MSG-01 is on; ticking the box sets S-MSG-01 at once (APP-01.38); OK goes on with the key.
3. Hardware key: when UL-HW's switch is on and an item is chosen, add that key and slot. The challenge itself happens later (APP-06.15).
4. No component at all: `NoCredentials`, M06-05, no KDF (LD-13).
APP-01.16 updates the remembered key file and slot at this point, as the reference does at each attempt.

APP-06.12 **No password and the empty password.** FMT-04.2: "no password" and "empty password" are different keys, and Larsal must offer both.
- UL-PW empty and no key file and no hardware key: M06-05 in UL-ERR with the link "Unlock with a blank password". The link starts one unlock with `P` = SHA-256 of the empty string and nothing else. ("Blank password" is the screen's word for FMT-04.2's empty password.)
- UL-PW empty with a key file or a hardware key: Larsal first tries without `P`. If that gives `WrongKey`, Larsal asks M06-33. "Try Blank Password" runs one more unlock with the same key file and hardware key plus the empty password; "Cancel", or a second `WrongKey`, shows M06-06. Any other error of the first try shows its own message and asks nothing.
- Credentials passed in (APP-06.24) are never retried this way.
Reference: an empty field means no password; after any failed unlock with an empty field, it offers once to try again with no password (default button: try again), whatever the failure was. With no key file it runs the KDF on an empty key first; Larsal refuses that before the KDF (LD-13), so the link replaces that first, pointless attempt.

APP-06.13 **The open.** After APP-06.11, Larsal reads the vault file from disk again (never a copy read earlier) and runs the open in the order of FMT-05.7, with the credentials, on a worker thread (CRY-02.15). The first failure ends the attempt with one error kind; APP-06.18 turns it into one message.

APP-06.14 **The KDF cost question.** When the open returns "ask the user first" (CRY-02.14), Larsal shows M06-34 with `<memory>` (m × 1,024 bytes in MiB or GiB, one decimal for GiB) and `<time>` (the estimate in seconds, one decimal under 10 s, whole seconds above, minutes above 120 s), and the lanes sentence when P > 128 was a trigger. For AES-KDF, which uses no memory (CRY-02.14), the Details use M06-34's form without the memory part. No KDF has run. "Unlock" runs the open again with the approval of CRY-02.14 (Larsal does not ask twice in one attempt). "Cancel", Escape, or closing the alert ends the attempt with no message (CRY-02.14: no error); UL-ERR stays empty. Every later attempt asks again. The reference has no such question.

APP-06.15 **Hardware key touch.** When the open reaches the hardware key step (FMT-05.7 step 4b) and the device needs a touch, Larsal shows M06-35 in UL-ERR in grey until the challenge ends. Reference: it shows a touch prompt only in its separate unlock dialog, not in the main window.

APP-06.16 **A lock event during an unlock.** When any event of APP-02 that locks this vault, or every vault, fires while its unlock runs (screen lock, sleep, user switch, the lock flag, lock everything), Larsal lets the worker finish, then drops and wipes the result without showing the vault, and the vault stays locked with no message. A quit during an unlock waits for the worker, wipes, and quits. The reference does not cover this case (source reading: the lock request finds the vault not yet unlocked and does nothing).

APP-06.17 **After a failure.** On any failure of an attempt:
- UL-PW is empty (it was cleared when the attempt started, APP-06.11; Decided: spec/decisions.md LD-95) and Show is off. Key file path and hardware key choice stay.
- The message shows in UL-ERR; UL-PW gets the mockup's error outline; for M06-05 and M06-06 the form shakes once (the mockup's shake, skipped when macOS Reduce Motion is on).
- Focus: `WrongKey`, `NoCredentials` and every vault file error: UL-PW. Key file errors and M06-30: the UL-KEY field. Hardware key errors (M06-17 to M06-20 and MI07-01): the hardware key list, or "Look for keys again" when the list is empty.
- The password the user typed is wiped in Rust as soon as the attempt ends, success or failure.
Reference: it keeps the typed password in the field, selects it all and focuses it, so typing replaces it; the key file and hardware key stay.

APP-06.18 **One message per error, and message rules.** Every value of `larsal-format::Error` maps to exactly one message of the table above; the map is an exhaustive match, so a new kind or reason fails to compile until it has a message. Grouping, and why: every `Limit` inside `KeyFile(TooLarge)` shares M06-16 (the key file reader gives only three: `KeyFileText`, `KeyFileDepth` and `KeyFileAttributes`), and `BadAnswer` shares M06-20 with `Failed`, because the user's next step is the same; `TooLarge` limits other than `KdfCost` and `TotalFile` share M06-23 and name the limit (its `Limit::name()`, our words) on a second line for support; `Io` kinds other than `NotFound` and `PermissionDenied` share M06-13 and M06-26. Every message:
- holds no secret: no password, no key bytes, no key file content, no protected value;
- holds no text taken from the vault file or the key file, except the key file version text of M06-08, which `larsal-format` keeps only when it is at most 16 characters of digits and dots (LD-87);
- names a file only by its file name from the file system, never by its path, its public name or the vault name; before use, control characters, direction marks (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) and zero-width characters (U+200B to U+200D, U+FEFF) are removed (LD-108), and a name longer than 64 characters keeps its first 30 and last 30 characters with "…" between;
- never shows a raw operating system error text: an `io::ErrorKind` picks the message;
- says what to do next in one short sentence.
The debug log may record the kind, the reason and the limit name, never a value (Rust rule 8, LD-67).

APP-06.19 **Retrying.** The user can retry at once, as often as they like; Larsal adds no delay and no attempt limit. Each attempt starts again at APP-06.11. Reference: the same.

APP-06.20 **When a message goes away.** UL-ERR clears when the user types in UL-PW, changes the key file field, flips the hardware key switch or picks another slot, or when a new attempt starts. A message from APP-06.3 also clears when a new header look succeeds. The mockup clears its message on typing; the reference hides its message when a new attempt starts.

APP-06.21 **A newer minor version.** When the open succeeds and the file's version is 4.x with x above 1, Larsal asks M06-38 before it shows the vault, at every unlock of that vault until the user has answered "Unlock Anyway" once in this session. "Unlock Anyway" goes on; "Cancel" wipes the opened vault, leaves it locked, and shows no message. Decided: spec/decisions.md LD-96, which replaces LD-05's "no notice" for the window; unknown document parts are still kept on save (SD-06), while unknown outer header fields are dropped (LD-21), which is why the notice speaks of settings. Reference: its window asks after every successful open of such a file, with its open button as the default; Cancel reopens the file header-only and shows an "unlock cancelled" error message; its command line tool does not ask.

### After a successful unlock

APP-06.22 **Order of steps.** After the open succeeds, in this order:
1. M06-38 when it applies (APP-06.21).
2. Wipe the typed credentials; keep the opened vault in the session.
3. Quick unlock slot, when APP-04.3 allows it.
4. A recovery copy or lost-changes marker of this vault: APP-02.16 asks its questions.
5. Forced master key change: MOD-13.8's blocking prompt, before any entry, group or tag is shown.
6. Show the vault in the main window (the sheet or panel closes) and restore the selection (APP-02.19).
7. The recommended key change notice (MOD-13.10).
8. Auto-open (APP-06.25).
9. Expiring entries (APP-01.18), only on the first unlock of this vault in this session.
10. Read-only check (APP-05.18) and the "vault unlocked" signal to the integrations (browser bridge INT-01, SSH agent INT-06, menu bar icon APP-08).
11. For the unlock panel: hand the result to the request that asked (INT-02, INT-05).
12. Minimize after unlock when S-START-04 is on (APP-01.8; hides to the menu bar icon when APP-08 says so).
The reference does, in its order: version mismatch question, quick unlock slot, show the vault, auto-open, restore selection, expiring entries (first unlock only), SSH agent, minimize.

APP-06.23 **Remembered values and the recent list.** APP-01.16 keeps the key file path and hardware key slot per vault (only while S-START-08 is on); APP-01.14 keeps the recent list, which Larsal updates when a vault is opened (APP-09.15). The menus and the start view show the recent list (APP-08).

### Credentials from elsewhere

APP-06.24 **Credentials passed in.** A password from standard input with a key file flag (APP-09.16, APP-09.17), an auto-open entry (APP-06.25), or a vault link (MOD-08, "Vault link") start one unlock without the user pressing Unlock:
- the password never goes into UL-PW or anywhere in the screen layer; it stays in a secret type and is wiped when the attempt ends;
- a passed key file path is put into UL-KEY (paths are not secret), so a retry by hand can use it; a path that holds a protected value (from a protected field or a placeholder that masks, MOD-08.23) is used but never put into UL-KEY, remembered or named: messages call it `******` (LD-238 (5), F-080);
- the remembered hardware key slot is used when S-START-08 is on and that key is present; no other hardware key;
- no quick unlock slot is made (APP-04.3);
- no M06-33 retry. An M06-32 warning, an M06-34 question or an M06-38 notice shows only when the vault is the shown vault; for a vault opened in the background the attempt stops there with no message (after M06-38's point the opened vault is wiped), and the user unlocks it by hand;
- on failure the vault stays locked, and its message waits in UL-ERR until the user shows that vault.
Reference: it puts the passed password into the password field and presses Unlock for the user, so the password sits in its form; after a failure it may ask its empty-password question.

APP-06.25 **Auto-open** (SR-10). After each unlock (step 8 of APP-06.22) and after each reload or merge from disk (APP-05.31), Larsal looks for a group named exactly `AutoOpen` (letter case counts) directly under the root group; when several have that name, the first in group order. For each entry directly in that group, in group order:
1. Skip it unless its URL is not empty and its UserName or Password is not empty.
2. If it has a custom field named `IfDevice`, split its value at commas and trim spaces. Start with "do not open". For each item in order: an item starting with `!` that equals the Mac's host name (without letter case) means "do not open" and ends the loop; an item starting with `!` that does not match means "open"; any other item that equals the host name means "open". Skip the entry if the result is "do not open". So `!work-mac` opens on every other Mac, and `alice-mac, !work-mac` also opens everywhere except on `work-mac`. The host name is the one the reference compares: it asks its toolkit for the local host name, which on Unix systems is the system host name (what `hostname` prints, often ending in `.local` on a Mac), not the computer name of the Sharing settings (observed by Verify in Sprint 3, V-A06-4: on this Mac a scratch program asked the reference's installed toolkit for the local host name, through the same call the device rule uses, and got exactly what `hostname` and `uname -n` print: the Bonjour local host name of the Sharing settings followed by `.local`, since no other host name was set; the computer name, with its spaces and apostrophe, was not used).
3. Resolve placeholders and references in the URL, UserName and Password (MOD-08).
4. Vault path: the resolved URL. A leading vault link prefix (MOD-08, bytes `6b 64 62 78 3a 2f 2f`, stored encoded (name rule)) is removed. A `file://` URL becomes a local path. A relative path is taken from the folder of the vault being unlocked. If no regular file exists there, count it as not found and go on. A path built from a protected value still opens: it is a local file Larsal opens itself and hands to no other app, and it reaches the recent list only when a regular file exists at that exact path (LD-238 (3)); Open URL's `MSG-08-4` refusal of a URL holding a protected value (MOD-08.31; LD-232 (2), LD-245 (1)) is for URLs handed to another app.
5. Key file path: the resolved UserName, with the same path rules; empty means no key file. A key file path that does not exist is passed on as it is, so the unlock shows M06-11. A key file path that holds a protected value is used but never kept or named (APP-06.24, LD-238 (5)). Reference: it turns the key file path into its canonical form, which is empty for a missing file, so a missing key file silently becomes "no key file".
6. Open the path through APP-09.15 in the background (the shown vault does not change). If it is already open and unlocked: nothing. If it is open and locked, or newly opened: start one unlock with the resolved Password and the key file (APP-06.24).
After the loop, if any entry was not found, show M06-39 once. Loops end by themselves: a vault that is already open is never opened twice (APP-09.15 compares canonical paths). Reference: the same group, filter, device rule and path rules; it shows one message per missing file, naming the URL.

APP-06.26 **Auto-open and shared groups.** Larsal skips auto-open when the `AutoOpen` group is the target of an imported shared group, or lies inside one (INT-08). Decided: spec/decisions.md LD-97. The reference has no such check.

### Sheet, panel and keys

APP-06.27 **The unlock sheet and the unlock panel.**
- The sheet covers the main window, which stays visible and disabled behind it. The panel is a small window centred on the active screen; showing it brings Larsal to the front without showing the main window when that is hidden.
- Both show M06-40 or the owning card's purpose text above the form, and a "Cancel" button left of "Unlock". "Cancel" or Escape closes them: the request that asked is told "cancelled" (MOD-11, APP-02.16, APP-05.29, INT-02, INT-05), nothing else changes.
- When a browser or Auto-Type request may use any of several locked vaults, the panel shows the mockup's vault switcher (UL-SWITCH) listing only those vaults; switching reloads the form for that vault (APP-06.9). The reference shows one tab per vault.
- Touch ID starts by itself 0.1 seconds after the panel appears (APP-04.10).
- Any lock-everything event of APP-02 (screen lock, sleep, user switch, the lock flag, lock everything) closes the panel and the sheet as a cancel.
- Only one panel at a time. A second outside request while one shows waits for it (INT-02 owns the queue).
Reference: an application-modal dialog with tabs, at least 700 points wide, centred on the active screen; it starts quick unlock after 100 ms; on Linux it stays on top.

APP-06.28 **Escape and closing.** On the main window's password form Escape does nothing, except closing an open menu (the mockup). Closing a locked vault is "Close Vault" (Cmd+W, APP-08). On the Touch ID form Escape means "Use password instead" (APP-04.15). In the sheet and panel Escape is Cancel. The reference's main-window form closes the vault on two Escape presses within 3 seconds, showing a warning after the first; Larsal drops this, because on a Mac Escape does not close documents.

APP-06.29 **Accessibility.** UL-ERR is a live region: VoiceOver reads a new message as soon as it appears. Every control has the name the mockup gives it (UL-PW "Password", the eye button "Show password" or "Hide password", UL-KEY "Key file", the list "Choose a key and slot", the look button "Look for keys again", UL-SWITCH "Switch vault"). The form works with the keyboard alone: Tab order UL-PW, eye button, UL-KEY field, "Browse…", hardware key switch, list, look button, UL-GO, then the links. AT-K06 checks it.

### Messages outside the unlock screen

APP-06.30 **Reasons for save and create messages.** When creating or saving a vault fails in `larsal-format`, APP-05 shows `MSG-SAVE-FAILED` (and APP-07 its create failure) with a `<reason>`. The reason for each kind that a save or create can give:

| Kind | `<reason>` |
|---|---|
| `NoCredentials` | the vault has no password, key file or security key |
| `HardwareKey(Missing)` | the security key is not connected |
| `HardwareKey(TimedOut)` | the security key was not touched in time |
| `HardwareKey(SlotNotConfigured)` | the security key slot is not set up for challenge-response |
| `HardwareKey(BadAnswer)`, `HardwareKey(Failed)` | Larsal could not use the security key |
| `HardwareKey(NotPermitted)` | macOS did not let Larsal reach the security key (INT-07 MI07-02; LD-175 R07-2) |
| `KeyFile(…)` (credential change, MOD-12.10) | the M06-07 to M06-16 text for that reason, without its last sentence |
| `TooLarge(limit)` | the vault is over Larsal's <limit> limit |
| `Unsupported` | Larsal cannot write this setting |
| `Io(kind)` | APP-05.13: the operating system's reason, as words Larsal picks per kind (no space left on the disk; Larsal is not allowed to write there; the folder no longer exists; the disk cannot be written); any other kind, including the random-source failures of LD-76 and LD-92: an unexpected system error |

Kinds that only an open gives (`NotAVault`, `OldFormat`, `Corrupt`, `WrongKey`) never appear on save. The same message rules apply (APP-06.18).

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| Empty password field, no key file, Return pressed | M06-05 with the link; no KDF; the form shakes; UL-PW focused. |
| Vault made with an empty password (by the reference command line tool, which takes a typed empty line as an empty password) | M06-05; the link unlocks it. |
| `keyfile-hashed.larsalvault` with `key-hashed.larsalkey`, password field empty | Unlocks with the key file alone; no question. |
| Same vault, wrong key file | First try without a password gives `WrongKey`; M06-33; "Try Blank Password" gives `WrongKey` again; M06-06; focus on UL-PW. |
| `password-only.larsalvault` with a wrong password, then with a key file it does not use | M06-06 both times, the same text (AT-A01). |
| Vault needs a hardware key; the user did not turn on UL-HW | The composite key lacks the key's part: `WrongKey`, M06-06 (AT-A01). |
| UL-HW on, the key unplugged after it was found | `HardwareKey(Missing)`, M06-17; focus on "Look for keys again" if the list is now empty. |
| Key file field holds a folder | M06-14. The reference command line tool reports that the file to open is a folder (observed). |
| Key file is a FIFO, a socket or `/dev/zero` | M06-14 (`NotRegularFile`); nothing is read. |
| Key file is the vault itself, chosen with "Browse…" | M06-30 at once; the field keeps its old value. Typed: M06-30 when Unlock starts. The reference command line tool has no such check and reports wrong credentials (observed). |
| Key file named `backup.LARSALVAULT` | M06-31; "Cancel" keeps the old value. |
| `keyfile-xml-v1.larsalvault` with `key-xml-v1.larsalkey` | M06-32 once, then it unlocks; with the box ticked, never again. The reference command line tool prints an old-format warning and goes on (observed). |
| Vault file moved away while the view shows | APP-06.3 on the next show, or M06-24 on Unlock. |
| Vault file replaced by a text file | M06-01. |
| A version 1 vault (old format) | M06-02 with "Import…", which opens the import assistant with the old-format kind and this file chosen (FEA-08.1). |
| File cut short while syncing | M06-04 (or M06-23 for a cut header that misreads a length, LD-77); a later Unlock reads the file again. |
| Damaged header MAC, or header changed with its plain hash fixed | M06-06: the format cannot tell this from a wrong key (FMT-05.8). |
| Argon2 memory above the Mac's memory, or more than 1,000,000,000 iterations | M06-21, no KDF, no question. |
| Argon2 at 2 GiB on a 16 GiB Mac | M06-34 with "about 2.0 GiB"; "Cancel": no message, no KDF; "Unlock": one KDF run. |
| 300,000,000 AES-KDF rounds, estimated 40 s | M06-34 with "about 40 seconds" and no memory part. |
| Touch ID works, then the vault file is missing | M06-24 under the Touch ID button; the slot is kept; the Touch ID form stays (APP-06.4). |
| Screen locks while the KDF runs | The result is dropped; the vault stays locked; no message (APP-06.16). |
| Unlock pressed twice quickly | One attempt (APP-06.10). |
| Typed password, then the window is hidden for 30 seconds | UL-PW cleared. |
| Version 4.2 file (a newer writer) | M06-38 until answered "Unlock Anyway" once in the session; "Cancel" leaves it locked with no message. |
| Vault opened with `--password-stdin` and a wrong password | Locked, M06-06 in UL-ERR, UL-PW empty (APP-06.24); no M06-33. |
| Auto-open entry pointing to the vault that holds it | Already open: nothing. |
| Auto-open entry whose path is missing | Counted; one M06-39 after the loop. |
| Auto-open vault in the ask band, opened in the background | Stays locked, no question; the user unlocks it by hand. |
| Browser request while the main window is hidden | The panel appears on the active screen; the main window stays hidden. |
| Panel open, screen locks | The panel closes; the browser request gets "cancelled". |
| A file name with a right-to-left override in it | The override is removed before the name goes into a message (APP-06.18). |
| `KeyFile(UnsupportedVersion)` with the text `2.0` and then with an empty text | M06-08 first form with "2.0"; second form with no version. |

What the reference shows, for comparison (from its source; its window was not run; Verified 2026-10-28 against the source, V-A06-1: the open routine's error prefix, the reader's cipher-id error that prints the raw bytes, the wrong-credentials text, the missing-file text with the full path, the key file prefix, and the hardware key texts with the serial number or the device's own error):
- File errors read "could not read the vault", then the reader's own detail, in its message bar. Some details hold file content: for a cipher id of the wrong length its detail includes the raw header bytes, and for an unsupported key file version the version text (F-039). Larsal never does this (APP-06.18).
- Wrong credentials: the same text as in FMT-05 (credentials invalid, try again, the file may be damaged if it keeps happening).
- A missing vault file: its message names the full path.
- Key file errors: a short "could not open the key file" prefix plus the key file reader's reason (FMT-18.19), which is empty for an empty file (observed with its command line tool).
- Hardware key errors name the device's serial number, or report the device's error text.

### Not on Mac

- Windows: quick unlock through Windows Hello appears in the same place as Touch ID (APP-04).
- Linux: the separate unlock dialog stays above other windows; hardware keys may also be read through smart card readers (INT-07).

## Lead decisions

| ID | Question | Options | Recommended |
|---|---|---|---|
| D-A06-1 | What happens to the typed password after a failed attempt (APP-06.17) | (a) It is gone: the field is cleared when the attempt starts, so the screen layer never holds it during or after the KDF; the user types it again, as on the Mac's login window. (b) As the reference: keep it in the field, selected, so typing replaces it. (c) Keep it only when the failure is not about the credentials (file, key file or hardware key errors). | Decided: spec/decisions.md LD-95, option (a). |
| D-A06-2 | Files with a minor version above 4.1 (APP-06.21) | (a) Keep LD-05 as written: open without a notice. (b) Ask M06-38 before showing the vault, default "Unlock Anyway", as the reference window does. | Decided: spec/decisions.md LD-96, option (b); it replaces LD-05's "no notice". |
| D-A06-3 | Auto-open entries that arrive through a shared group (APP-06.26) | (a) As the reference: process them. (b) Skip auto-open when the `AutoOpen` group is, or lies inside, an imported shared group. | Decided: spec/decisions.md LD-97, option (b). |

## Security notes

- **Secrets stay in Rust.** The typed password leaves the screen layer once, when Unlock starts, and the field is cleared at that moment (LD-95). A passed-in password never reaches the screen (APP-06.24). Every password, key file key and hardware key answer is wiped when the attempt ends (SR-07, AT-C01, AT-E07).
- **Messages hold no secret and no file text** (APP-06.18, LD-87, parity row SF-18). The reference puts raw header bytes into one of its header errors and the key file's version text into another; Larsal's map takes only the kind, the reason, the `Limit` and an `io::ErrorKind`. File names are cleaned of direction marks and control characters, so a crafted file name cannot make a message read differently.
- **One wrong-key message** for every wrong combination of password, key file and hardware key (AT-A01, SF-05). The empty-password retry (M06-33) appears only when the user left the password empty and gave another part; it reveals nothing about the vault.
- **No KDF before the cost check** (CRY-02.14, AT-A05): a hostile file in the ask band cannot make Larsal spend memory or time without a yes, and a refused file costs nothing.
- **A lock wins over an unlock in progress** (APP-06.16): a screen lock during the KDF never leaves an unlocked vault behind a locked screen.
- **Secure input and Caps Lock** on every password-kind field (SR-06, APP-10.8, AT-D05).
- **Header values before unlock** (public name, colour) are unauthenticated; Larsal shows them only as FMT-03.23 allows and never in messages.
- **Auto-open** (SR-10) opens only regular files, never opens a vault twice, runs one KDF per opened vault, and ignores entries from shared groups (LD-97). A hostile document inside valid encryption (AT-A08) can at most make Larsal open files the user can already read, each with its own cost check.
- **Retry limits.** Larsal adds none: an attacker with the file does not use the screen, and each attempt already costs one KDF run. Same as the reference.
- What must never happen: a password in UL-ERR, a log line or a crash report; a key file's content or a vault's text in a message; a different message for a wrong key file than for a wrong password; a KDF run on an ask-band file without a yes; an unlocked vault after a lock event that arrived during the unlock.
- Parity rows: SF-04 (any combination of parts), SF-05 (wrong key found at the header), SF-16 (vault as its own key file refused, vault-like key file warned, old key file format warned), SF-18 (error messages and notices hold no text from the vault or key file, beyond the file name and LD-87's version text), SR-04 (Touch ID, through APP-04), SR-06 (secure input, Caps Lock warning), SR-08 (expiring entries after unlock, APP-01.18), SR-10 (auto-open), SR-12 (remembered key files, off by default). Attacks: AT-A01, AT-A05, AT-A08, AT-C01, AT-D05, AT-E07, AT-K02, AT-K04, AT-K06.

## Test cases

Unit tests use `larsal-ffi`'s unlock controller with a fake `larsal-format` (scripted results), a fake hardware key driver, a fake clock and a fake Caps Lock source. Screen tests run the real screen against the controller. Demo vaults are those of testdata/ (passwords in testdata/README.md); `slow.larsalvault` is a test vault with Argon2 at m = 2 GiB made by a test helper; `v42.larsalvault` is a version 4.2 file made by the test vault builder.

| Case | Given | When | Then |
|---|---|---|---|
| T01 APP-06.1 | A locked vault shown; a merge started; a browser request while the window is hidden | Look | Main window form; a sheet with M06-40 merge text and "Cancel"; a panel with the browser text, main window still hidden |
| T02 APP-06.2 | `rich-v4.larsalvault` never unlocked in this session, no public name | Show | "Unlock rich-v4", tile "R", path with `~` |
| T03 APP-06.2 inner name not kept | Same vault unlocked once (inner name "Rich demo"), then locked | Show | Still "Unlock rich-v4" |
| T04 APP-06.2 public name | Header with a valid public name `Demo vault` (test builder) | Show | "Unlock Demo vault"; with a control character in it, the character is left out |
| T05 APP-06.3 | A text file opened as a vault | Show | M06-01 at once in UL-ERR, form usable |
| T06 APP-06.3 recovers | A cut file shows M06-04; the full file is copied back | Press Unlock with the password | The vault unlocks |
| T07 APP-06.4 | Vault with a quick unlock slot | Press Escape on the Touch ID form | Password form, UL-PW focused (APP-04.15) |
| T08 APP-06.5 secure input | View shown | Focus UL-PW | Secure input on; Tab away: off (APP-10.8) |
| T09 APP-06.5 show | Type `demo-pass-1`, eye button on | Press Unlock | Show off when the attempt starts |
| T10 APP-06.5 30 s | Type text, hide the window | Fake clock +29 s, then +1 s | Text still there at 29 s, gone at 30 s |
| T11 APP-06.5 lock event | Text typed | Fake screen lock | UL-PW empty |
| T12 APP-06.6 | Caps Lock on | Focus UL-PW; then turn Caps Lock off | M06-37 shown, then gone; never shown on APP-07's repeat field |
| T13 APP-06.7 browse | Open panel returns `key-hex64.larsalkey` | Press "Browse…" | Full path in the field, in clear |
| T14 APP-06.7 typed | Type `~/x.larsalkey` | Unlock | The path read is the home folder plus `x.larsalkey` |
| T15 APP-06.7 self | Choose the vault file itself | Browse | M06-30; field keeps its old value |
| T16 APP-06.7 vault name | Choose `backup.LARSALVAULT` | Browse; "Cancel" | M06-31; old value kept |
| T17 APP-06.8 detect | Fake driver lists one key with one slot | Show | UL-HW list shows "YubiKey 5 NFC · serial 24531878 · slot 2", chosen; switch enabled |
| T18 APP-06.8 plug | View shown, no key | Fake plug-in event | A new look 0.5 s later |
| T19 APP-06.8 look | Fake driver: none; then keys without a usable slot; then 3 slots | Press "Look for keys again" three times | M06-36 none text; no-slot text; "Found 3 security keys." |
| T20 APP-06.9 | S-START-08 on, key file and slot remembered for this path | Show | UL-KEY open and filled; UL-HW open, slot chosen; UL-PW focused |
| T21 APP-06.9 default | S-START-08 off (default) | Show after a lock | UL-KEY and UL-HW closed and empty |
| T22 APP-06.10 | Slow fake open | Press Unlock twice | One open; UL-GO reads "Unlocking…"; form disabled |
| T23 APP-06.11 order | Key file missing and vault file damaged | Unlock | M06-11 (the key file error wins, FMT-05.7 step 0) |
| T24 APP-06.11 old key file | `keyfile-xml-v1.larsalvault`, `key-xml-v1.larsalkey` | Unlock; tick the box; lock; unlock | M06-32 the first time; the vault opens; S-MSG-01 on; no warning the second time |
| T25 APP-06.11 none | Everything empty | Unlock | M06-05; fake `larsal-format` never called; no KDF |
| T26 APP-06.12 link | Vault made by a test helper with the empty password | Press the M06-05 link "Unlock with a blank password" | The vault unlocks; the composite key holds `P` = SHA-256("") |
| T27 APP-06.12 retry | `keyfile-hashed.larsalvault`, wrong key file `key-hex64.larsalkey`, field empty | Unlock; "Try Blank Password" | M06-33; second `WrongKey`; M06-06 |
| T28 APP-06.12 no retry | `keyfile-hashed.larsalvault` with a missing key file | Unlock | M06-11, no M06-33 |
| T29 APP-06.13 reread | File replaced on disk after the view showed | Unlock | The new bytes are read (fake records two reads) |
| T30 APP-06.14 ask | `slow.larsalvault`, test hook: 16 GiB Mac | Unlock; "Cancel" | M06-34 with "about 2.0 GiB"; no KDF; UL-ERR empty |
| T31 APP-06.14 yes | Same | Unlock; "Unlock" | One KDF run with the approval; the vault opens |
| T32 APP-06.14 refuse | Argon2 m above the hooked memory size | Unlock | M06-21; no question; no KDF |
| T33 APP-06.15 | Fake key needs a touch, answers after 2 s | Unlock | M06-35 in grey for 2 s, then gone |
| T34 APP-06.16 | Fake open takes 1 s | Unlock; screen lock at 0.5 s | The vault stays locked; no message; result wiped (spy) |
| T35 APP-06.17 wrong key | `password-only.larsalvault`, `wrong` | Unlock | M06-06; UL-PW empty and focused; shake; key file path kept |
| T36 APP-06.17 key file focus | Missing key file | Unlock | M06-11; focus on the UL-KEY field |
| T37 APP-06.17 hardware focus | Fake driver returns Missing, list now empty | Unlock | M06-17; focus on "Look for keys again" |
| T38 APP-06.17 wipe | Debug build memory probe | Failed unlock with `demo-pass-1-x` | The text is not found in the screen layer's storage or in Rust memory after the attempt |
| T39 APP-06.18 every kind | A table of every `Error` value: each kind, each key file reason with each `io::ErrorKind` group, each hardware key reason (`NotPermitted` included), `TooLarge` with each of the 28 `Limit`s | Map to a message | Exactly the IDs of the table, MI07-01 for `HardwareKey(NotPermitted)` included; M06-23 shows "Limit reached: <name>" with `Limit::name()` |
| T40 APP-06.18 no secret | Every value of T39, plus `KeyFile(UnsupportedVersion("2.0.1"))` | Map with the vault password `demo-pass-1` in the session | No message holds the password, any byte of the key, or any text of the file other than `2.0.1` |
| T41 APP-06.18 names | Vault file named with U+202E and a line feed, 80 characters | M06-04 | The two characters are gone; the name is cut to 30 + "…" + 30 characters |
| T42 APP-06.19 | Five wrong passwords, then `demo-pass-1` | Unlock six times | Each attempt runs at once; the sixth opens |
| T43 APP-06.20 | M06-06 shown | Type one character | UL-ERR empty |
| T44 APP-06.21 | `v42.larsalvault` | Unlock, "Cancel"; unlock, "Unlock Anyway"; lock; unlock | M06-38, then locked with no message; M06-38 again, then it opens; after the lock no M06-38 |
| T45 APP-06.22 order | Vault with a recovery copy, a forced key change and expiring entries; spies on each step | Unlock | The steps run in the order of APP-06.22; no entry is visible before the forced prompt |
| T46 APP-06.22 expiring | Vault with expired entries (AT-K04) | First unlock, lock, unlock | The expiring search shows the first time only |
| T47 APP-06.23 | S-START-08 on | Unlock `password-and-keyfile.larsalvault` with `key-hex64.larsalkey` | APP-01.16 holds that path for the vault |
| T48 APP-06.24 stdin | `printf 'wrong\n' \| APP --password-stdin password-only.larsalvault` | Start | Vault locked; M06-06 in UL-ERR; UL-PW empty; no M06-33; no quick unlock slot |
| T49 APP-06.24 key file shown | `--password-stdin --key-file key-hex64.larsalkey password-and-keyfile.larsalvault` with a wrong password | Start | UL-KEY shows the key file path; UL-PW empty |
| T50 APP-06.25 open | `rich-v4.larsalvault` copy with a group `AutoOpen` holding an entry: URL `password-only.larsalvault` (relative), Password `demo-pass-1` | Unlock it | `password-only` opens unlocked in the background; the shown vault does not change |
| T51 APP-06.25 device | Entries with `IfDevice` = `!<this Mac>`; `other-mac`; `other-mac, !third-mac`; `<this Mac>` in capitals | Unlock | Skipped; skipped; opened; opened |
| T52 APP-06.25 filter | Entry with a URL but empty UserName and Password; entry in a subgroup of `AutoOpen` | Unlock | Neither is used |
| T53 APP-06.25 missing | Two entries with missing paths | Unlock | One M06-39 with "2 vaults" |
| T54 APP-06.25 loop | Vault A auto-opens B, B auto-opens A | Unlock A | A and B open once each; no further opens |
| T55 APP-06.25 link prefix | URL is the vault link prefix plus an absolute path | Unlock | That path opens |
| T56 APP-06.26 | `AutoOpen` is the target of an imported shared group (INT-08 test fixture) | Unlock | No auto-open runs |
| T57 APP-06.27 cancel | Merge source sheet | Press Escape | Sheet closed; MOD-11 told "cancelled"; target unchanged |
| T58 APP-06.27 several | Browser request for any of two locked vaults | Panel shows | The switcher lists the two vaults only |
| T59 APP-06.27 lock | Panel shown | Fake sleep | Panel closed; request cancelled |
| T60 APP-06.28 | Main window form | Press Escape twice | Nothing happens; the vault stays open, locked |
| T61 APP-06.29 VoiceOver | VoiceOver on (AT-K06) | Wrong password | VoiceOver reads M06-06; every control has its mockup name |
| T62 APP-06.30 | Fake save returns `HardwareKey(TimedOut)`; `Io(StorageFull)` | Save | `MSG-SAVE-FAILED` with "the security key was not touched in time"; with "no space left on the disk" |
| T63 APP-06.4 Touch ID open error | Vault with a quick unlock slot; fake open returns `Io(NotFound)` after Touch ID | Press "Unlock with Touch ID" | M06-24 under the button; Touch ID form still shown, button focused; slot present |
| T64 APP-06.14 AES-KDF | AES-KDF vault estimated at 40 s (fake speed record) | Unlock | M06-34 Details without a memory part, "about 40 seconds"; no KDF until "Unlock" |
| T65 APP-06.8 remembered slot absent | S-START-08 on, slot `1:2` remembered; fake driver lists only `3:1` | Show | One item, chosen; the switch is off |
| T66 APP-06.24 newer version in the background | Auto-open target is `v42.larsalvault` | Unlock the holding vault | `v42` stays locked, no M06-38 and no message; the opened copy is wiped (spy); showing it and unlocking by hand asks M06-38 |
| T67 APP-06.24 protected key file path | `recent.remember_keys` on; an auto-open entry for `password-only.larsalvault` whose UserName is `{PASSWORD}.larsalkey` (the entry's Password protected); no such key file | Unlock the holding vault, then show `password-only` | UL-ERR shows M06-11 with `******` as the key file's name; UL-KEY is empty and no key file is remembered for it (LD-238 (5), F-080) |

## How this was learned

- Read the reference source: the unlock form (its fields, the key file link, the hardware key part and its detection, plug-in and refresh handling, the busy state, how it builds the composite key, the old key file warning with its do-not-show box, the checks after choosing a key file, the empty-password retry, the version-mismatch question, the field clearing timer, the two-Escape close, focus and selection after a failure, quick unlock hand-off), its screen definition (labels, tab order), the shared password field component (Caps Lock warning, secure input on focus, show and generator shortcuts with the Control key on Mac), the separate unlock dialog (tabs, modality, auto quick unlock after 100 ms), the vault open routine and its error texts, the reader's error texts, the hardware key driver's error texts, the tab container's open routine (recent list update, existing tab reuse), and the vault view's after-unlock routine (selection, expiring entries, SSH agent, minimize) and auto-open routine (group path, entry filter, device list, placeholder resolution, path rules).
- Ran the reference command line tool 2.7.11 with a throwaway home folder on demo vaults: a folder as the vault (refused as not a plain file), a folder as the key file (a folder reason), an empty key file (empty reason), an XML 1.0 key file (old-format warning, then it opens), the vault as its own key file (wrong credentials), an empty typed line on a password vault (wrong credentials). It wrote nothing to the throwaway home.
- The reference window was not run: on this Mac it may read its real settings folder. Its texts and dialogs above come from the source (Verified 2026-10-28, V-A06-1, see above). The host name used by the device rule was observed in Sprint 3 (V-A06-4, APP-06 auto-open step 2). Verified 2026-10-28 from the source: the 30-second clear (V-A06-2: a 30,000 ms one-shot timer starts when the form is hidden or the window loses activation, stops when the form is shown or activated again, and when it fires empties the password and turns Show off), the two-Escape close (V-A06-3: main window only; the first Escape shows a warning for 3,000 ms, and a second one within that time closes the vault), the touch prompt (V-A06-5: shown only when the form is not in the main window). Still open: whether `NSEvent.modifierFlags` reports Caps Lock under secure input (V-A06-6, Mac QA).
- design/mockup.html: the unlock screen, its texts, the error line, the shake, the key file and hardware key rows, the toast after a key search, the vault switcher and the Touch ID form.
- Second review (E1-S5): checked every rule again against the reference source (the unlock form, the separate unlock dialog and its intents, the vault open routine, the version-mismatch flag and the newest known version, the after-unlock routines of the main window and the dialog, the auto-open routine and the group path lookup, the open-with-credentials routine, the password field component, the CLI unlock routine) and against `larsal-format`'s `error.rs` and `limits.rs`: every `Error` kind, `KeyFileReason`, `HardwareKeyReason` and each of the 28 `Limit`s maps to exactly one message. Compared every Larsal text with the reference's English UI strings by word overlap and rewrote the near matches (M06-01 to M06-03, M06-05's link, M06-30 to M06-33, M06-35 to M06-39, the hardware key list item). Applied LD-95 to LD-97 and LD-100.
