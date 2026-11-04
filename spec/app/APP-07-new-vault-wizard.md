# APP-07 New vault wizard

Status: reviewed
Epics: E5-S8
Parity rows: SF-01, SF-02, SF-03, SF-04, SF-10, SF-16, SD-09, SC-06

## What it does

The new vault wizard makes a new, empty vault in three steps: a name and description, the encryption settings with a measurement of this Mac's speed, and the credentials (a password, and optionally a key file, which it can create, and a hardware key). It ends with a save panel. App writes the file, then opens the new vault, unlocked.

This card owns the wizard's steps, controls, defaults, checks, messages and the moment the file is written. Others own: the vault settings screen, which reuses the encryption and credentials controls of steps 2 and 3 (MOD-12); the values a new vault holds (MOD-12.22); the KDF facts and the benchmark (CRY-02.22 to CRY-02.28); ciphers (CRY-01.19); the cost thresholds (CRY-02.14); key file layout and creation (FMT-18.20 to FMT-18.24); password strength and the master password gate (FEA-05.7, FEA-05.20); the generator (FEA-02); the file version (FMT-16); saving (APP-05); the import that ends in a new vault (FEA-08.5).

## Inputs and outputs

In:
- A start: File > New Vault… (Shift-Cmd-N), "New vault…" in the vault switcher menu (design/mockup.html), the start view's new vault button (APP-08), or the import assistant's Finish (FEA-08.5).
- The user's input; the Mac's logical processor count and physical memory; the speed record (CRY-02.14); app settings S-CFG-01 (default file name), S-CFG-02 (minimum master password quality), S-STATE-06 (last folders) (APP-01).

Out:
- A new vault file on disk, mode 0600, and the vault open and unlocked in the session as the shown vault; or nothing at all (cancel, or a failure before the file was written).
- Possibly a new key file on disk, mode 0400.

### Steps

| Step | Title | Controls | Primary button |
|---|---|---|---|
| 1 | Name your vault | Name, Description | Continue |
| 2 | Encryption | Simple: Unlock time. Advanced: Cipher, Key derivation, Iterations or Rounds, Memory, Lanes | Continue |
| 3 | Password and keys | Password, Verify password, strength meter; behind "Add a Key File or Security Key": Key file, Hardware key | Create Vault |

### Texts

Our wording. Where design/mockup.html already has a text it is used (marked "mockup").

| ID | Where | Text (App) |
|---|---|---|
| M07-01 | Window title | New Vault |
| M07-02 | Step counter, top right | Step <n> of 3 |
| M07-03 | Step 1 line | The name shows in the vault list. Name and description stay editable in Vault Settings. |
| M07-04 | Step 1 labels | Name; Description, with the placeholder "Optional" |
| M07-05 | Step 2 line | Choose how long an unlock takes. A longer unlock makes your password harder to guess. Vault Settings › Security can change it at any time. |
| M07-06 | Step 2 simple mode | Label "Unlock time"; value such as "1.0 s"; ends "0.1 s" and "5 s"; button "Advanced Settings" |
| M07-07 | Step 2 advanced mode | Labels "Cipher" (items "AES-256", "Twofish-256", "ChaCha20"), "Key derivation" (items "Argon2id", "Argon2d", "AES-KDF"), "Iterations" (Argon2) or "Rounds" (AES-KDF) with the button "Tune for 1 Second", "Memory" with the unit "MiB", "Lanes"; button "Simple Settings". The items carry no "(default)" or "(recommended)": the default is the item chosen when the list first shows, and a closed list shows the chosen item's text, which Option A draws as "AES-256" and "Argon2id" here and on the vault settings' encryption page (Decided: spec/decisions.md LD-224) |
| M07-08 | Step 2 while measuring | Measuring this Mac… |
| M07-09 | Step 3 line | Choose what opens this vault. Only you should know it or have it. |
| M07-10 | Step 3 labels | "Password", "Verify password", the meter "Rated <level> · <bits> bits of strength" (mockup, editor), the eye button "Show password" / "Hide password" (mockup), the dice button "Generate password" (mockup) |
| M07-11 | Step 3 button that opens more parts | Add a Key File or Security Key |
| M07-12 | Key file part | Label "Key file"; note: Keep this file exactly as it is, and keep a copy somewhere safe: the vault opens only with this file, unchanged. Buttons "New Key File…", "Choose Key File…", "Remove" |
| M07-13 | Security key part | Label "Security key"; list "Choose a key and slot" and button "Look for keys again" (mockup); button "Remove" |
| M07-14 | Buttons | "Cancel", "Back", "Continue", "Create Vault" |
| M07-15 | While writing | Creating the vault… |
| M07-16 | Save panel title | Save the New Vault |

### Messages

| ID | When | Where | Text (App) |
|---|---|---|---|
| M07-20 | The two password fields differ | under the repeat field, red | The two passwords are different. |
| M07-21 | No password (also MOD-12.10 `vault.msg.no_password`) | alert: "Use No Password", "Cancel" (default) | Message: Use no password for this vault? Details: Then the key file or security key alone opens the vault, so anyone who gets hold of it can open it. Adding a password is safer. |
| M07-22 | Below the minimum quality | alert | FEA-05.20 `MSG-MK-TOO-WEAK` |
| M07-23 | Below Good | alert | FEA-05.20 `MSG-MK-WEAK`, buttons "Use this password" and "Cancel" (default) |
| M07-24 | No part at all (also `vault.msg.no_key_part`) | alert: "OK" | Add a password, a key file or a security key. A vault needs at least one. |
| M07-25 | A new key file could not be written | alert: "OK" | The new key file "<keyfile>" was not written: <reason>. |
| M07-26 | The chosen name for a new key file already exists (LD-99) | alert: "OK" | A file named "<keyfile>" already exists there. App never replaces a file with a new key file, because it may be another vault's key. Choose another name. |
| M07-27 | A chosen key file cannot be read | under the key file field | The APP-06 text for that `KeyFile` reason (M06-07 to M06-16) |
| M07-28 | A chosen key file is of an early kind | under the key file field, grey | "<keyfile>" is a key file of an early kind. It still works, but a future version of App may no longer read it; a new key file is safer. |
| M07-29 | The save panel's path is the chosen key file | alert: "OK" | The vault cannot be saved over its own key file. Choose another name or place. |
| M07-30 | The vault file cannot be written | alert: "OK"; the wizard stays on step 3 | The vault could not be created: <reason>. |
| M07-31 | Argon2 iterations above 10,000 | alert: "Use Anyway", "Cancel" (default) | <n> iterations make each unlock very slow on most Macs. Use them anyway? |
| M07-32 | AES-KDF rounds below 100,000 | alert: "Use Anyway", "Cancel" (default) | <n> rounds make the password much easier to find by trying many guesses. Use them anyway? |
| M07-33 | Below the safe minimum (memory under 19 MiB or fewer than 2 iterations) | alert: "Use Anyway", "Cancel" (default) | These settings are below App's safe minimum of 19 MiB and 2 iterations, so guessing the password gets faster. Each unlock would take about <time>. Use them anyway? |
| M07-34 | In the ask band of CRY-02.14 | alert: "Use Anyway", "Cancel" (default) | With these settings each unlock needs about <memory> of memory and about <time> on this Mac. Use them anyway? For AES-KDF the memory part is left out, as in M06-34. |
| M07-35 | Memory above the Mac's physical memory | under the Memory field, red | This Mac has <physical> of memory. Choose less. |

`<reason>` follows APP-06.30. `<time>` and `<memory>` are formatted as in APP-06.14. File names in messages follow APP-06.18.

## Rules

### The window

APP-07.1 **Starting it.** Each start in Inputs opens the wizard on step 1 with fresh values. Only one wizard at a time: a second start brings the open one to the front. The wizard does not need any vault to be open or unlocked.

APP-07.2 **Look and buttons.** The wizard is a sheet on the main window in the mockup's dialog style (raised background, 12-point corners, title at the top left, buttons at the bottom right), wider than the mockup's small dialogs so the form rows fit. M07-02 shows the step. Buttons: "Cancel" at the left; "Back" (hidden on step 1) and the primary button at the right. Return presses the primary button when it is enabled and the focus is not in the Description field's text; Escape is "Cancel". The reference uses the system's wizard window in its Mac style, with a background picture, and a title that names the product.

APP-07.3 **Cancel.** "Cancel" or Escape on any step closes the wizard. No vault is made and nothing is written, except a key file the user already created with "New Key File…" in step 3, which stays where the user saved it. Typed passwords are wiped (Rust) and the screen fields cleared. From the import assistant, a cancel drops the import result (FEA-08.5). Reference: the same.

APP-07.4 **Moving between steps.** "Continue" runs the step's checks (APP-07.9, APP-07.16) and moves on only when they pass. "Back" never checks and keeps every value, including typed passwords, until the wizard closes. Reference: its "back" keeps values too; each page's values are applied when the user moves forward.

### Step 1: name and description

APP-07.5 **Name and description.** Name is a one-line field, prefilled with "Passwords", all selected and focused, so typing replaces it. Description is a one-line field, empty. Both may be left empty; an empty name means the vault shows its file name where a name would show (APP-06.2 for locked vaults). Leading and trailing spaces are kept as typed. Length: up to the text limit (LD-22). They become `DatabaseName` and `DatabaseDescription` (MOD-12.3), with their "...Changed" times set to the creation time (MOD-12.22). Reference: the same two fields, prefilled "Passwords", focused and selected; no check.

### Step 2: encryption

APP-07.6 **Simple mode.** Step 2 opens in simple mode: a slider "Unlock time" from 0.1 to 5 seconds in steps of 0.1, at 1.0 s, with its value shown (M07-06). App keeps Argon2id, 64 MiB and lanes = min(4, logical processors) and sets the iterations so that one unlock takes about the chosen time (APP-07.8). The cipher is AES-256 (LD-20). Reference: the same slider (100 to 5,000 ms, default 1,000) and a format list; its KDF is Argon2d.

APP-07.7 **Advanced mode.** "Advanced Settings" swaps the slider for these controls; "Simple Settings" swaps back. Each mode keeps its own values while the wizard is open; the mode shown when the user presses "Continue" decides.

| Control | Choices or range | Default |
|---|---|---|
| Cipher | AES-256, Twofish-256, ChaCha20, in this order (CRY-01.19) | AES-256 |
| Key derivation | Argon2id, Argon2d, AES-KDF | Argon2id (LD-18) |
| Iterations (Argon2) or Rounds (AES-KDF) | 1 to 1,000,000,000 | Argon2id: tuned for 1 second (APP-07.8); AES-KDF: tuned for 1 second |
| Memory (Argon2 only) | 1 to 1,048,576 MiB | 64 MiB |
| Lanes (Argon2 only) | 1 to 128 | min(4, logical processors) |

"Tune for 1 Second" measures with the current kind, memory and lanes (APP-07.8) and fills the iterations or rounds for a 1,000 ms target. Changing the key derivation between the two families (Argon2 and AES-KDF) loads that family's defaults (Argon2: 64 MiB and min(4, logical processors) lanes) and measures again; changing between Argon2id and Argon2d keeps the fields. Memory and Lanes hide for AES-KDF. There is no file format choice (MOD-12.13) and no compression control (gzip, MOD-12.22). Reference: the same choices and ranges; when it switches from AES-KDF to Argon2 it resets the lanes to a fixed 4, not min(4, logical processors) (CRY-02.27).

APP-07.8 **Measuring this Mac.** App measures with CRY-02.28 (CPU time of the thread, LD-72) on a worker thread, never on the screen thread. It measures once when step 2 first appears (Argon2id, 64 MiB, the default lanes), again after "Tune for 1 Second", and again after a change of key derivation family, memory or lanes. While it measures, M07-08 and a spinner show and "Continue" is disabled; the rest of the step stays usable. One measured run gives the count for 1,000 ms, N = ceiling(count × 1.1 × 1,000 / time) (CRY-02.28), and from it the iterations (or rounds) for any target: ceiling(N × target / 1,000), so moving the slider needs no new measurement. That count is never below CRY-02.28's own result for the target and at most ceiling(target / 1,000) above it (LD-224). Argon2 iterations are capped at 1,000,000,000, the refuse ceiling (CRY-02.14). Each measurement is stored as the speed record (CRY-02.14). Reference: it measures on a worker thread while the window waits behind a busy cursor, once when the page opens and, in simple mode, again for the slider's time when the page is left; in advanced mode it measures again on its tune button and when the KDF family changes.

APP-07.9 **Checks when leaving step 2.** In simple mode none, since the values come from App's own measurement. In advanced mode, in this order:
1. Memory above the Mac's physical memory: M07-35; "Continue" stays disabled until the value is lowered. (CRY-02.28 refuses it.)
2. Memory under 19 MiB (19,456 KiB) or iterations under 2 (Argon2): M07-33 (MOD-12.12, D-12-6).
3. Argon2 iterations above 10,000: M07-31 (CRY-02.24).
4. AES-KDF rounds below 100,000: M07-32 (CRY-02.24).
5. The cost estimate of CRY-02.14 in its ask band (memory above 1 GiB, or more than 10,000 ms): M07-34.
Each alert's default is Cancel; Cancel stays on step 2 with the values as typed. "Use Anyway" goes on to the next check. Reference: checks 3 and 4 with their own texts; no checks 1, 2 and 5.

APP-07.10 **What step 2 decides.** The cipher, KDF and its settings are held in the new vault's encryption settings (LD-82) and used by the first save (APP-07.17); no KDF run happens in step 2 except the measurements. When App sets the iterations (or rounds) from a chosen unlock time by its own measurement (APP-07.8), the vault's custom data gets the unlock time item (CRY-02.25, MOD-12.11) with that time in milliseconds: simple mode, and both choices Option A draws for step 2, "Recommended" (`1000`) and "Custom" (its "Unlock time" slider; Custom also derives the count from the time, so the time is known). Only a count the user types (advanced mode's "Iterations" or "Rounds", which Option A does not draw) gives none, as in the reference, whose time is not known until the KDF runs (Decided: spec/decisions.md LD-224). The file version follows FMT-16 (4.0 for a new vault).

### Step 3: credentials

APP-07.11 **The password fields.** "Password" and "Verify password" (the repeat field) are both password-kind fields (APP-10.9): secure input, masked, no autofill. "Password" has the focus when step 3 first appears. The eye button and Control-H switch Show for both fields together. The dice button and Control-G open the generator popup (FEA-02); applying a generated password fills both fields. The meter under "Password" rates it as the editor's meter does (FEA-05.7, mockup), and shows nothing for an empty field. The Caps Lock note (APP-06.6) shows for "Password" only. While "Verify password" is not empty and differs from "Password", M07-20 shows under it and the field gets the error outline; when it matches, a check mark shows. Reference: the same pair, a strength bar, generator and show actions with Control on Mac; its repeat field turns red, or another colour while its text is still the start of the password.

APP-07.12 **More parts.** "Add a Key File or Security Key" opens the key file part and the hardware key part below the password, and hides itself. Both parts start empty. Reference: a toggle button reveals a key file part and a hardware key part.

APP-07.13 **New key file.** "New Key File…" opens the macOS save panel, named "<vault name>.appkey" (or "Passwords.appkey" when the name is empty), in the remembered key file folder (APP-01.15) or the Documents folder. When the user saves:
1. If a file already exists at the chosen path: M07-26, nothing is written, and the panel can be used again (Decided: spec/decisions.md LD-99; FMT-18.22).
2. App writes an XML 2.0 key file with 32 fresh random bytes from `app-crypto` (FMT-18.20, FMT-18.21; LD-31), in the exact layout of FMT-18.20 (278 bytes), then sets its mode to 0400 (FMT-18.22).
3. App reads the new file back with FMT-18 and uses the `F` it gets (FMT-18.23).
4. The key file field shows the path.
If writing fails, App removes any partial file and shows M07-25 with the reason. The key bytes live in a secret type and are wiped after the read back (FMT-18.26). Reference: a save panel with key file filters and no proposed name; it writes the XML form only when the chosen name ends with its own key file extension (case-sensitive), otherwise 128 raw random bytes (SF-10); it relies on the panel's replace question.

APP-07.14 **Existing key file.** "Choose Key File…" opens the open panel (all files allowed) in the remembered key file folder or the home folder. A file whose name ends in `.appvault` or the reference's vault extension asks M06-31 (FMT-18.24). The chosen file is read with FMT-18 at once: a key file error shows M07-27 and the field stays empty; a key file of an early kind (XML 1.0, Raw 32, Hex 64) shows M07-28 and keeps the file (FMT-18.18). There is no vault path yet, so the "vault itself" check of FMT-18.24 happens at the save panel instead (APP-07.17). "Remove" empties the part. Reference: it refuses the current vault file, warns on a vault-like name, and warns about an old format when the key is applied.

APP-07.15 **Hardware key.** The hardware key part lists keys and challenge-response slots as the unlock screen does (APP-06.8, INT-07), with "Look for keys again" and M06-36. Choosing a slot adds that key; no challenge happens before the save (APP-07.17), so the user touches the key once. "Remove" empties the part. Reference: when the credentials page is accepted it requires a found key and runs a test challenge on the chosen slot (a touch when the slot needs one), refusing a slot that does not answer; the real challenge follows at the first save.

APP-07.16 **Checks when pressing "Create Vault".** In this order:
1. The two password fields differ (also when only one is empty): M07-20 stays, the repeat field gets the focus, nothing else happens.
2. Password empty: M07-21. "Use No Password" means the vault has no password component (not the empty password, FMT-04.2).
3. Password quality below S-CFG-02: M07-22 (FEA-05.20).
4. Password quality below Good: M07-23 (FEA-05.20).
5. The key file part has a path: it must read without error now (FMT-18); else M07-27.
6. The hardware key part has a slot: that key must be present now (INT-07); else M06-17.
7. No part at all: M07-24.
8. The save panel (APP-07.17).
Cancel in any alert stays on step 3 with every value kept. MOD-12.10 lists the no-password warning before the match check; App checks the match first, so a text typed only into "Verify password" is not dropped silently. Reference: the no-password warning first, then the match, the minimum quality, the weak warning, the key file, the hardware key, and "no part".

### Saving and opening

APP-07.17 **The save panel and the write** (Decided: spec/decisions.md LD-98). After the checks pass, the save panel (M07-16) opens with the name of APP-01.34 (S-CFG-01, else "Passwords.appvault") in the last vault folder (S-STATE-06) or the Documents folder. The extension is always `.appvault`. Then:
1. If the chosen path is the key file of step 3 (same canonical path): M07-29, back to the panel.
2. If a file exists at the path, the panel's own replace question has been answered yes.
3. App builds the vault: the MOD-12.22 defaults, the name and description of step 1, the settings of step 2, the composite key of step 3 (FMT-04). With a hardware key, the challenge runs now with the new seed (FMT-04.17); M06-35 shows while it waits for a touch.
4. App writes the file with a fresh salt and seeds (CRY-03) through the safe save of APP-05.11, mode 0600 (SD-09), with M07-15 and a spinner; the KDF runs on a worker thread (CRY-02.15). The wizard's buttons are disabled meanwhile.
5. If any of this fails, nothing is left at the path (the safe save never leaves a partial file), M07-30 shows the reason (APP-06.30), and the wizard stays on step 3 with every value kept, so the user can pick another place.
Cancel in the save panel goes back to step 3 with every value kept. Reference: the wizard ends without asking for a place; the vault opens unsaved and marked changed; with its save-on-every-change setting on (the default; App's S-FILE-01) its first save asks for the place at once; if that is cancelled, the vault stays open with no file, and a lock closes it (APP-02.15 step 13).

APP-07.18 **After the write.** The new vault joins the session unlocked and becomes the shown vault, with the root group selected and no entry. App adds its path to the recent list (APP-01.14) and stores the folder (APP-01.15). It makes no quick unlock slot, so the first unlock after a lock asks for the new password, which also proves the user remembers it. Auto-open, the expiring entries search and the key change check do not run (the vault is empty and new). The typed passwords are wiped and the fields cleared. From the import assistant, FEA-08.5 then merges the import result into the new vault and marks it changed, and the normal saving of APP-05 writes it.

APP-07.19 **What the new vault holds.** MOD-12.22 lists every value. In short: an empty root group named `Root`, no other group, no entry; recycle bin on with no bin group until the first delete; history limits 10 items and 6 MiB; password field protection only, passwords always written protected (MOD-12.17); compression gzip; no public name, colour or icon; no unlock time item in advanced mode. The reference's wizard gives the same, with Argon2d.

### Shared parts

APP-07.20 **Shared with the vault settings.** The vault settings' encryption page (MOD-12.11 to MOD-12.14) and credentials page (MOD-12.10) use the controls, measurement and texts of steps 2 and 3: M07-06 to M07-08, M07-10 to M07-13, M07-20 to M07-35. There, "Continue" and "Create Vault" are the screen's Apply, and the vault itself is known, so FMT-18.24's "vault itself" check runs when a key file is chosen (M06-30).

APP-07.21 **Keyboard and VoiceOver.** Every control has the name of its label or button text; the step counter and the step line are read when a step appears; messages under fields are live regions. Tab moves through the step's controls in visual order, then the buttons. AT-K06 checks it.

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| Name left empty | Allowed; the vault list shows the file name. |
| Name of 10,000 characters | Allowed (under the text limit); the vault list cuts it with "…". |
| Slider at 0.1 s | Iterations for 100 ms; no warning, because simple mode is App's own measurement. The unlock time item is `100`. |
| Slider at 5 s, slow Mac | Iterations for 5,000 ms; no ask (under 10,000 ms). |
| Advanced: Argon2id, 2 GiB, on a 16 GiB Mac | M07-34 with "about 2.0 GiB". |
| Advanced: memory 32 GiB on a 16 GiB Mac | M07-35; "Continue" disabled. |
| Advanced: AES-KDF, 60,000 rounds | M07-32. |
| Advanced: Argon2d, 8 MiB, 1 iteration | M07-33, then M07-34 does not apply (fast). |
| Change key derivation to AES-KDF and back to Argon2id | Argon2 defaults loaded again and measured. |
| "Tune for 1 Second" pressed twice quickly | One measurement at a time; the second press waits or is ignored while one runs. |
| Password `password` with S-CFG-02 = 0 | M07-23; "Use this password" goes on. |
| Password typed only in "Verify password" | M07-20 on "Create Vault"; focus on the repeat field. |
| Both password fields empty, a key file chosen | M07-21; "Use No Password": vault with the key file only. |
| Both empty, nothing else | M07-21; "Use No Password"; then M07-24. |
| "New Key File…" at the path of an existing photo | M07-26; the photo is unchanged. |
| New key file on a read-only disk | M07-25 with "the disk cannot be written"; no partial file. |
| Choose `key-xml-v1.appkey` | M07-28; the key works. |
| Choose an empty file as key file | M07-27 with M06-07; the field stays empty. |
| Save panel path equals the new key file's path | M07-29. |
| Save into a folder that is not writable | M07-30 with "App is not allowed to write there"; still on step 3. |
| Hardware key chosen, unplugged before "Create Vault" | M06-17 at check 6. |
| Hardware key not touched in time during the write | M07-30 with "the security key was not touched in time"; nothing written. |
| Cancel in the save panel | Back to step 3, values kept. |
| Escape during the write | Ignored; the write finishes or fails first. |
| Wizard open, the Mac's screen locks | The wizard stays open (it holds no vault yet); typed fields are kept. The password fields are cleared after 30 seconds of the window being inactive, as APP-06.5 does for the unlock field. |
| Import assistant Finish, then Cancel in the wizard | No vault; the import result is wiped (FEA-08.5). |

## Lead decisions

| ID | Question | Options | Recommended |
|---|---|---|---|
| D-A07-1 | When the new vault is written (APP-07.17) | (a) At "Create Vault", through a save panel that is part of the wizard; a cancelled panel returns to step 3; a vault with no file never exists. (b) As the reference: open the vault unsaved and let the first save ask for the place. | Decided: spec/decisions.md LD-98, option (a). |
| D-A07-2 | "New Key File…" at the path of an existing file (APP-07.13) | (a) Refuse, M07-26: App never replaces a file with a new key file. (b) Let the save panel's replace question decide (FMT-18.22 then allowed it with confirmation). | Decided: spec/decisions.md LD-99, option (a); FMT-18.22 now says App never overwrites an existing file. |

## Security notes

- **Random key files only from `app-crypto`** (AT-B04, SF-10): 32 fresh bytes per file, XML 2.0 with a check value, mode 0400, read back before use. App never replaces an existing file with a key file (LD-99).
- **Strong defaults**: Argon2id with 64 MiB tuned to one second (LD-18), AES-256 (LD-20). The measurement uses the thread's CPU time, so a busy Mac cannot make the tuned KDF weaker (LD-72, AT-B06).
- **No weak settings by accident**: App's safe minimum, the iterations and rounds warnings and the cost question all default to Cancel (MOD-12.12, CRY-02.24, CRY-02.14).
- **Master key guards** (SF-16): no-password warning with Cancel as default; minimum quality and weak warning (FEA-05.20); "no part" refused; a vault-like key file warned; the vault never saved over its own key file (M07-29).
- **Secrets**: both password fields are secure input fields (APP-10.9, AT-D05); the typed passwords go to Rust only at "Create Vault" and are wiped when the wizard closes; no password is written anywhere but into the composite key.
- **Files**: the vault is written with the safe save at 0600 (SD-09, AT-I06); a failed write leaves no partial file.
- What must never happen: a key file with non-random content; a new key file overwriting another file; a vault written with no key part; a KDF weaker than the user chose; a typed password in a log or in the debug output.
- Parity rows: SF-01 (three ciphers), SF-02 (three KDFs), SF-03 (benchmark to a target unlock time, 0.1 to 5 s), SF-04 (any combination of parts), SF-10 (new key files random and owner read-only; App only the XML form), SF-16 (master key guards), SD-09 (new vault and key file permissions), SC-06 (strength while typing).

## Test cases

Tests drive the wizard against `app-core` with a fake clock for the measurement, a fake hardware key driver, hooks for physical memory and logical processors (16 GiB, 8 processors unless stated), and a temp folder `/tmp/spec-app07`. Demo passwords only.

| Case | Given | When | Then |
|---|---|---|---|
| T01 APP-07.1 | No vault open | File > New Vault… | Wizard on step 1; a second Shift-Cmd-N brings the same wizard forward |
| T02 APP-07.2 | Step 1 | Press Escape | Wizard closed; nothing written in `/tmp/spec-app07` |
| T03 APP-07.3 | Step 3 with a key file made by "New Key File…" | Cancel | No vault file; the key file still exists, mode 0400 |
| T04 APP-07.4 | Step 3 with `demo-new-1` typed twice | Back, Back, Continue, Continue | Step 3 shows both fields still filled; step 1 values kept |
| T05 APP-07.5 | Step 1 | Type `Demo vault` | Replaces "Passwords" (it was selected); the file's `DatabaseName` is `Demo vault` |
| T06 APP-07.5 empty | Name emptied | Finish the wizard | Allowed; the vault list shows the file name |
| T07 APP-07.6 | Step 2, fake measurement | Continue in simple mode at 1.0 s | Argon2id, m = 65,536 KiB, P = 4, iterations from CRY-02.28 for 1,000 ms; cipher AES-256; unlock time item `1000` |
| T08 APP-07.6 slider | Same | Slider to 2.5 s | No new measurement; iterations = ceiling(N × 2,500 / 1,000), N = ceiling(count × 1.1 × 1,000 / time) |
| T09 APP-07.7 | Advanced | Look at the lists | Cipher: AES-256, Twofish-256, ChaCha20, AES-256 chosen; Key derivation: Argon2id, Argon2d, AES-KDF, Argon2id chosen; memory 64; lanes 4 |
| T10 APP-07.7 family | Advanced, Argon2id with 128 MiB | Choose AES-KDF, then Argon2id | Memory and Lanes hidden, then shown with 64 MiB and 4; a measurement after each change |
| T11 APP-07.7 same family | Argon2id, 128 MiB, 3 lanes | Choose Argon2d | Fields unchanged; no measurement |
| T12 APP-07.8 thread | Fake measurement that takes 2 s | Open step 2 | M07-08 shown; Continue disabled; the screen thread answers clicks meanwhile |
| T13 APP-07.8 cap | Fake clock gives an absurd count | Continue | Iterations capped at 1,000,000,000 |
| T14 APP-07.8 record | Measurement done | Read App's settings | A speed record for Argon2 with the measured run |
| T15 APP-07.9 order | Advanced, Argon2d, 8 MiB, 20,000 iterations | Continue; Use Anyway; Use Anyway | M07-33, then M07-31, then M07-34 if the estimate passes 10 s; Cancel at any of them stays on step 2 |
| T16 APP-07.9 physical | Memory 32,768 MiB, hook 16 GiB | Type it | M07-35; Continue disabled |
| T17 APP-07.9 AES | AES-KDF, 60,000 rounds | Continue | M07-32, Cancel is the default |
| T18 APP-07.10 Custom | "Custom" chosen: Argon2d, 128 MiB, "Unlock time" at 0.3 s, fake measurement | Finish | The unlock time item (key of CRY-02.25) is `300`; iterations = ceiling(N × 300 / 1,000) for the measured 128 MiB run (a typed count, not drawn in Option A, would write no item) |
| T19 APP-07.11 match | "Password" `demo-new-1`, "Verify password" `demo-new` then `demo-new-x` | Type | Check mark absent; M07-20 shown for `demo-new-x`; with `demo-new-1` a check mark |
| T20 APP-07.11 generator | Dice button, Apply | Look | Both fields hold the generated password |
| T21 APP-07.11 secure input | Focus each password field | Event tap probe (AT-D05) | No keystrokes received |
| T22 APP-07.13 new key file | "New Key File…" to `/tmp/spec-app07/k.appkey` | Save | 278 bytes, XML 2.0 layout of FMT-18.20, mode 0400; the `F` used equals the decoded data |
| T23 APP-07.13 exists | A file `/tmp/spec-app07/photo.jpg` exists | "New Key File…" there | M07-26; the photo's bytes unchanged |
| T24 APP-07.13 fail | Folder read-only | "New Key File…" there | M07-25; no file left |
| T25 APP-07.14 old | Choose `testdata/key-xml-v1.appkey` | Look | M07-28; the path kept |
| T26 APP-07.14 bad | Choose an empty file | Look | M07-27 with the M06-07 text; field empty |
| T27 APP-07.14 vault-like | Choose `x.appvault` | "Cancel" in M06-31 | Field unchanged |
| T28 APP-07.16 order | "Verify password" `abc`, "Password" empty | Create Vault | M07-20; focus on the repeat field; no other alert |
| T29 APP-07.16 no password | Both empty, a key file chosen | Create Vault; "Use No Password" | The vault's composite key holds only `F` (no `P`) |
| T30 APP-07.16 weak | `password`, S-CFG-02 = 0 | Create Vault | M07-23, Cancel default |
| T31 APP-07.16 minimum | `password`, S-CFG-02 = 3 | Create Vault | M07-22; still on step 3 |
| T32 APP-07.16 no part | Both empty, nothing else | Create Vault; "Use No Password" | M07-24 |
| T33 APP-07.17 panel | Valid step 3 | Create Vault | Save panel "Save the New Vault" with `Passwords.appvault` in the last vault folder |
| T34 APP-07.17 own key file | New key file `/tmp/spec-app07/k.appkey` | Save the vault as that same path | M07-29; the key file unchanged |
| T35 APP-07.17 write | Password `demo-new-1`, save to `/tmp/spec-app07/new.appvault` | Create | File mode 0600; header: version 4.0, AES-256, Argon2id, gzip; opens with `demo-new-1` in App and in the reference command line tool (E5-S8 check) |
| T36 APP-07.17 key file vault | Password plus a new key file | Create; open in the reference command line tool with `-k` | Opens (E5-S8 check) |
| T37 APP-07.17 fail | Save into a read-only folder | Create | M07-30; no file; step 3 with values kept |
| T38 APP-07.17 cancel | Save panel shown | Cancel | Step 3, values kept, nothing written |
| T39 APP-07.18 | Vault created | Look; lock; look | Shown and unlocked, root selected; recent list top is the new path; after the lock the password form shows (no Touch ID slot) |
| T40 APP-07.18 import | FEA-08.5 import of a CSV, wizard finished | Look | The new vault holds the imported entries and is saved by APP-05 |
| T41 APP-07.19 | New vault | Read the file | Root group `Root`, no entries, recycle bin on and absent, history 10 and 6,291,456, protection flags password only |
| T42 APP-07.20 | Vault settings, credentials page | Choose the vault's own file as key file | M06-30 |
| T43 APP-07.21 | VoiceOver on | Walk each step | Every control named by its label; the step counter is read |
| T44 APP-07.12 | Step 3 | Press "Add a Key File or Security Key" | The key file part and the hardware key part show, both empty; the button is hidden |
| T45 APP-07.15 | Fake driver with one key and one challenge-response slot | Look for keys; choose the slot; Create Vault; save | The slot shows as in APP-06.8; no challenge before the save panel; exactly one challenge during the write |

## How this was learned

- Read the reference source: the new vault wizard (its three pages and their order, title and subtitle texts, the empty vault it starts from with its root group name, its validation per page), the page widgets it reuses from the vault settings: the name and description page (prefill, focus, selection), the encryption page (simple and advanced modes, slider range, measuring on page open and when leaving, the format list, the warnings for iterations and rounds, family switching), the credentials page (the hidden extra parts, the order of its checks and warnings), the password part (repeat matching and its colours, generator), the key file part (create and browse, the name-based key file kind, the checks), the hardware key part; the tab container's new-vault routine (it checks that a key and a KDF were set and marks the vault changed) and the vault view's save routine (a vault with no path asks for one, proposing a default name in the last folder; saving after every change triggers it at once).
- The reference window was not run (it may read its real settings folder on this Mac): page order, the save panel after the wizard and the measured iterations are from the source (Verified 2026-10-28 against the source, V-A07-1: three pages in the order name, encryption, credentials; the wizard ends with no save panel and the vault opens in a new tab marked changed; the encryption page measures on a worker thread when a new vault's page opens, again for the slider's time when the page is left in simple mode, and on the tune button and a change of KDF family in advanced mode).
- design/mockup.html: the vault switcher's "New vault…" item with Shift-Cmd-N, the dialog look, the editor's password field with its meter, eye and dice buttons.
- Second review (E1-S5): checked every rule again against the reference source (the wizard and its page order, the name page, the encryption page with its ranges, defaults, family switching and measuring, the credentials page and its check order, the password, key file and hardware key parts, the tab container's new-vault routine, the auto-save default). Fixed the reference notes on where measuring runs and on the hardware key test challenge. Compared every App text with the reference's English UI strings by word overlap and rewrote the near matches (M07-10's second label, M07-12, M07-21, M07-25, M07-28, M07-31, M07-32 and M07-34's buttons). Applied LD-98 and LD-99.
