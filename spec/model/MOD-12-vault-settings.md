# MOD-12 Vault settings and field protection flags

Status: reviewed
Epics: E4-S14 (the screen is built in E5; the credentials page also serves E3-S3 and E10)
Parity rows: SF-01, SF-02, SF-03, SF-04, SF-08, SF-09, SF-10, SF-11, SF-12, SF-14, SF-16, SD-04, SD-05, SI-01, SI-02, SR-04

## What it does

Each vault carries its own settings inside the file. The vault settings screen shows and changes them. This card owns:
- every page and control of that screen, with Larsal's stable id, storage place, range, default and what applying it does;
- the five field protection flags and what they change when the vault is saved (SF-09);
- the defaults of a new vault, in the reference and in Larsal;
- the maintenance and browser actions that act on the vault at once.

How values are encoded in the file belongs to the format cards: metadata FMT-10, public header data FMT-03, compression FMT-08, protected fields FMT-09 and FMT-11.20, custom data FMT-14. KDF and cipher facts belong to CRY-01 and CRY-02. Behavior of history limits is MOD-03, of the recycle bin MOD-04, of icons MOD-06, of key change reminders MOD-13, of autosave APP-05, of the new vault wizard APP-07.

## Inputs and outputs

- In: the open vault, the user's edits on the screen, confirmations.
- Out: changed vault values, marked changed so normal saving follows (APP-05). Some changes run work at once: history truncation (MOD-12.5), a key derivation (MOD-12.14), icon removal (MOD-12.19).
- Larsal ids: `vault.*` for settings, `vault.act.*` for actions, `vault.msg.*` for messages. The screen texts are Larsal's own words.

## Rules

### The screen

MOD-12.1 **Pages.**

| Page | Reference | Larsal | Changes take effect |
|---|---|---|---|
| General | yes | yes (MOD-12.3 to MOD-12.8) | on Apply |
| Security: credentials | yes | yes (MOD-12.10) | on Apply |
| Security: encryption | yes | yes (MOD-12.11 to MOD-12.14) | on Apply |
| Security: field protection | no screen (flags only stored) | yes (MOD-12.16) | on Apply |
| Security: key change reminders | no screen (values only stored) | yes (MOD-13.12) | on Apply |
| Remote sync | yes | INT-09 | on Apply |
| Browser integration | yes | yes (MOD-12.18) | at once, per action |
| Shared groups | yes | INT-08 | on Apply |
| Maintenance | yes | yes (MOD-12.19) | at once, per action |

Not on Mac: the reference's Linux secret service page (which group is shared with the Linux secret service; stored as `FDO_SECRETS_EXPOSED_GROUP`, FMT-14.20). Larsal keeps that item unchanged and shows no page for it.

MOD-12.2 **Apply and Cancel.**
- Reference (source): Apply saves the pages in the order general, credentials, encryption, remote sync, shared groups. The first page that refuses (a failed check or a cancelled confirmation) stops the apply and is shown; the pages before it stay applied. Cancel drops the unapplied edits of every page. Browser and maintenance actions already done are not undone.
- Larsal (lead decision D-12-1, recommended): Apply first runs every check and confirmation of every page. Only when all pass does it apply all changes together. A refusal applies nothing and shows the page that refused. Browser and maintenance actions act at once and are not undone by Cancel, as in the reference.

### General page

MOD-12.3 **Name, description, default user name.**

| Larsal id | Control | Stored | Default (new vault) |
|---|---|---|---|
| `vault.name` | one-line text | `DatabaseName` | MOD-12.22 |
| `vault.description` | one-line text | `DatabaseDescription` | empty |
| `vault.default_username` | one-line text | `DefaultUserName` | empty |

Applying sets each value; its "...Changed" time moves only when the value really changes (FMT-10.24). The default user name is filled into the user name of every new entry made in the window (not in the command line tool). Length is bounded only by the text limit of LD-22.

MOD-12.4 **Public display settings.** `vault.public_name` (text), `vault.public_color` (colour picker with a Clear button), `vault.public_icon` (picker over Larsal's built-in vault icons, with a Clear button). Stored in the outer header's public custom data; FMT-03.23 owns names, types, the lowercase colour rule, removal when cleared and how Larsal shows them before unlock. The group box says these values are not encrypted and anyone with the file can read them (SF-12). Reference: applying the page rewrites a stored colour in lowercase and removes a colour it cannot read (FMT-03).

MOD-12.5 **History limits.** Two check-box-and-number pairs. Behavior of the limits: MOD-03.

| Larsal id | On | Off | Reference range | Larsal range |
|---|---|---|---|---|
| `vault.history_items` | `HistoryMaxItems` = n | −1 | 0 to 2,000,000,000 | 0 to 100,000 (MOD-03.10) |
| `vault.history_size` | `HistoryMaxSize` = n × 1,048,576 | −1 | 1 to 2,000,000,000 MiB | 1 to 2,047 MiB |

- Showing, reference: items ≥ 0 shows on with that number; −1 shows off with 10. Size: n = stored bytes / 1,048,576 rounded half away from zero; n ≥ 1 shows on with n; otherwise off with 6.
- Applying, reference: writes what the controls show, even if untouched. So a stored size of 3,500,000 bytes becomes 3 MiB = 3,145,728; a stored size of 100 bytes or 0 becomes −1 (no limit). Sizes of 2,048 MiB or more overflow the signed 32-bit value (2,048 MiB gives −2,147,483,648), which the next read ignores as below −1 (FMT-10.15).
- When either stored limit changes, every live entry's history is cut to the new limits at once (MOD-03; history items have no history of their own).
- Larsal (lead decision D-12-2, recommended): a control the user did not touch keeps the stored value exactly; ranges as in the table, so no overflow. The item limit stops at 100,000 because the reader refuses an entry with more history items (MOD-03.10, FMT-08.12). A stored value above 100,000 read from a file shows as read and is kept while untouched; MOD-03.10 still prunes every entry to 100,000 items.

MOD-12.6 **Recycle bin** `vault.recycle_bin`: check box, stored as `RecycleBinEnabled`, default on. Turning it off and applying runs MOD-04.12: a non-empty bin is either deleted with its contents (confirm, default No; deleted objects per FMT-15.7) or kept as a normal group named with ` (old)` added and given icon 48; an empty bin stays as a normal group; the recycle bin reference is cleared. Turning it on changes only the setting; MOD-04 creates a bin at the next delete. File facts: FMT-10.18.

MOD-12.7 **Compression** `vault.compression`: check box, on = gzip, off = none (FMT-08), default on. Takes effect at the next save.

MOD-12.8 **Autosave delay** `vault.autosave_delay`: check box and minutes. Stored as vault custom data, key `4B 50 58 43 5F 61 75 74 6F 73 61 76 65 44 65 6C 61 79 4D 69 6E` (stored encoded, name rule), value the decimal minutes; a missing item means 0 = off. Range 0 to 420,000,000; the number shows 5 while off. Behavior: APP-05. Reference: every apply writes the item, `0` when off, so applying an untouched page adds the item to a vault that had none (and refreshes `_LAST_MODIFIED`, FMT-14.18). Larsal (lead decision D-12-3, recommended): writes the item only when the value changes; turning the delay off removes it.

MOD-12.9 **Settings time.** Reference: every apply of the general page sets `SettingsChanged` to now, even when nothing changed (FMT-10.24). Larsal (decided LD-33: this list is the one rule, and FMT-10.24 points to it): `SettingsChanged` moves on apply only when a value of the **settings group** changed. The settings group (also used by MOD-11.19): recycle bin on or off, both history limits, `MaintenanceHistoryDays`, `Color`, the five protection flags, `MasterKeyChangeRec` and `MasterKeyChangeForce`, compression, cipher, KDF and its settings, the three public display settings. Not in it: name, description and default user name (own times), the composite key and the force-once flag (`MasterKeyChanged`, MOD-13), custom data items (merged by MOD-11.18).

### Credentials page

MOD-12.10 **Changing the composite key** (`vault.credentials`). The page shows the key parts the vault has: password, key file (FMT-18), hardware key challenge-response (INT-07). Each part has Add, Change and Remove. Key file and hardware key sit behind a "more protection" toggle, open when the vault already uses one. Nothing opened for editing and nothing removed: the key stays as it is. Otherwise, in this order:
1. Password missing, or opened and left empty: warning `vault.msg.no_password` (Larsal advises against a vault with no password), buttons continue without password and Cancel, default Cancel.
2. Password typed twice; the two must match (`vault.msg.password_mismatch`).
3. Password quality (FEA-05 levels) below the app setting for the minimum vault password quality (APP-01; 0 to 4, default 0 = none): refused (`vault.msg.password_below_minimum`).
4. Quality below Good: warning `vault.msg.password_weak` with continue and Cancel, default Cancel.
5. Key file must load (FMT-18); an error names the file and the reason. A key file of any kind other than XML version 2.0 or the hashed kind gets a warning advising a new key file. Choosing a file follows FMT-18.24 (the vault itself refused, a file named like a vault file warned).
6. Hardware key: a key with a challenge-response slot must be present (INT-07); errors: no key found, slot without challenge-response.
7. No part left at all: refused (`vault.msg.no_key_part`).
8. Effect: the new composite key replaces the old one; `MasterKeyChanged` = now, even when the same password was typed again (FMT-10.24); the force-once flag is cleared (MOD-13.11); this vault's quick unlock data is removed (APP-04); the vault is marked changed. The key derivation with the new key runs at the next save (CRY-03).
9. After that save, Larsal tells the user that backups and recovery copies made before the change still open with the old credentials, and offers to delete the ones Larsal made of this vault (APP-05.33; Decided: spec/decisions.md LD-53).

### Encryption page

MOD-12.11 **Simple mode** (`vault.unlock_time`). A slider for the target unlock time, 100 to 5,000 ms in steps of 100, default 1,000 (CRY-02.25). The page opens in simple mode when the vault holds the unlock time item (key `4B 50 58 43 5F 44 45 43 52 59 50 54 49 4F 4E 5F 54 49 4D 45 5F 50 52 45 46 45 52 45 4E 43 45`, stored encoded, name rule; shown as max(100, value)) and for a new vault; otherwise it opens in advanced mode. Applying in simple mode keeps the KDF kind, memory and lanes, sets the iterations (or rounds) by the benchmark for the chosen time (CRY-02.27 reference, CRY-02.28 Larsal) and stores the chosen time in that item.

MOD-12.12 **Advanced mode.**

| Larsal id | Control | Reference choices and range | Larsal |
|---|---|---|---|
| `vault.cipher` | list | AES-256, Twofish-256, ChaCha20 (CRY-01) | same three, AES-256 default (LD-20) |
| `vault.kdf` | list | version 4: Argon2d, Argon2id, AES-KDF; version 3: AES-KDF only | Argon2id (default), Argon2d, AES-KDF |
| `vault.kdf_iterations` | number + benchmark button (1,000 ms) | 1 to 1,000,000,000 | same range |
| `vault.kdf_memory` | MiB, Argon2 only | 1 to 1,048,576 | same range |
| `vault.kdf_parallelism` | lanes, Argon2 only | 1 to 128 | same range |

Changing the KDF kind loads the vault's own values when the family matches, else the family defaults and a benchmark (CRY-02.27). Before applying:
- reference warnings, each with keep and Cancel (default Cancel): Argon2 iterations above 10,000 (opening may take very long); AES-KDF rounds below 100,000 (weak against guessing) (CRY-02.24). Larsal keeps both.
- Larsal, cost check: the ask thresholds of CRY-02.14, which owns the numbers (today: memory above 1 GiB, more than 128 lanes, or an estimated time above 10,000 ms), ask with the cost shown before anything runs. The screen's lane limit of 128 means the lanes trigger is only reached by a vault read from a file.
- Larsal, safe minimum (plan/security.md extra hardening; lead decision D-12-6, recommended values): Argon2 memory below 19 MiB (19,456 KiB) or iterations below 2 is refused unless the user confirms with the estimated unlock time shown. AES-KDF uses the 100,000 rounds warning above.
Applying advanced mode removes the unlock time item.

MOD-12.13 **File format choice.** Reference: a format list with version 4 (marked recommended) and version 3; version 3 offers only AES-KDF; the list is locked, with a note, when the vault uses version 4 features. Larsal shows no format choice: it always writes version 4.0 or 4.1 (FMT-16, decided LD-07).

MOD-12.14 **When encryption changes take effect.** Reference: on apply, if any encryption control was touched or the mode was switched, the key is derived at once with the new settings and a new salt, on the screen thread (busy cursor); a failure refuses the page, and in advanced mode also shows `vault.msg.kdf_unchanged` (simple mode refuses without a message). Larsal shows the message in both modes. If nothing was touched, nothing runs. Larsal: the same trigger; the derivation runs on a worker thread with progress (CRY-02.15). The new cipher, KDF settings and compression are written by the next save, which derives again with a fresh salt (SF-14, CRY-02.21, CRY-03). A save never lowers these settings unless the user chose it on this page (AT-A09).

### Field protection flags

MOD-12.15 **The flags.** Five vault-level booleans in `Meta/MemoryProtection` (FMT-10.17): Title (default off), user name (off), password (on), URL (off), notes (off). Effect, only when saving: a standard field is written protected (encrypted with the inner stream, `Protected="True"`) when its own protected flag is set or the matching vault flag is on (FMT-11.20). Reading sets a field's own flag from its attribute, so a field read as protected stays protected even when the vault flag is off (FMT-11.21). The flags never change how values are shown on screen (masking is APP-01, SC-04), and never touch custom fields, whose own flag is set per field in the entry editor (MOD-01). Plain XML exports mark these fields with `ProtectInMemory="True"` instead (FEA-09; observed: with Title and notes flags on and the password flag off, the export marked Title and notes only). The reference has no screen for the flags: they are read, kept and written only.

MOD-12.16 **Larsal's field protection page** (lead decision D-12-4, recommended).
- Five switches `vault.protect_title`, `vault.protect_username`, `vault.protect_password`, `vault.protect_url`, `vault.protect_notes`.
- The password switch is always on and cannot be turned off; applying the page writes `ProtectPassword` True.
- Turning a switch on: from the next save that field is written protected in every entry and history item.
- Turning a switch off: also clears the own protected flag of that standard field in every entry and history item, without changing any entry time, so the next save writes it unprotected. Without this, turning a flag off would change nothing for any vault an app saved with the flag on.

MOD-12.17 **Passwords always protected** (lead decision D-12-5, recommended). Larsal sets the own protected flag of every `Password` field: on read, on creation, on import and on merge. So by FMT-11.20 every `Password` field is written protected, whatever the vault flag says (FMT-11.21 lets MOD-12 change own flags). The reference writes a password unprotected when both are off (observed: a vault imported with the password flag off kept its passwords unprotected). Both apps read either form.

### Actions that act at once

MOD-12.18 **Browser integration page.** Enabled only while browser integration is on in the app settings (APP-01, INT-02); otherwise a notice says to turn it on. Meaning of the items: INT-02.
- Table of stored associations: name (the key without the browser prefix `4B 50 58 43 5F 42 52 4F 57 53 45 52 5F`, stored encoded, name rule), public key value, created time (from the `_CREATED_` item, read only). Editing a name renames both the key item and its `_CREATED_` item; editing a value: the reference replaces the value of the first association it finds holding the old value (search order unspecified, so with two associations of equal value it may change the wrong one); Larsal changes the value of the edited row's own association.
- `vault.act.remove_association`: confirm (default Cancel), then removes the selected associations' key items and `_CREATED_` items.
- `vault.act.disconnect_all`: confirm, then removes every key item with the browser prefix and reports how many (none found: a notice). Reference: the `_CREATED_` items stay behind. Larsal (lead decision D-12-7, recommended): removes them too.
- `vault.act.forget_site_access`: confirm, then for each live entry holding the site-access item (key `4B 65 65 50 61 73 73 58 43 2D 42 72 6F 77 73 65 72 20 53 65 74 74 69 6E 67 73`, stored encoded, name rule) removes it as a normal entry edit (a history item is made and Mod moves, MOD-03), with progress and Abort; reports the count. History items keep theirs.
- `vault.act.new_root_id`: confirm, then gives the root group a new random id (the browser extension tells vaults apart by it, INT-02). No deleted object is added. A merge never matches roots of different ids (MOD-11.4).
- **No screen yet** (INT-02 second review 2026-10-28, R02-3; LD-189). The locked frame `vault-vault-settings-browser-keys` shows each connected browser with a Disconnect button (INT-02.8: `vault.act.remove_association` for that row) and "Remove all…" for stored site permissions (`vault.act.forget_site_access`). It has no control to rename an association or edit its value, and none for `vault.act.disconnect_all` or `vault.act.new_root_id`. Those rules wait for a mockup addition approved by the owner (AT-K05); Larsal builds no screen for them until then.

MOD-12.19 **Maintenance page.** A grid of the vault's custom icons in stored order, with two actions that act at once: `vault.act.delete_icons` (enabled while icons are selected) runs MOD-06.14, and `vault.act.purge_icons` runs MOD-06.15. In short: icons in use are removed only after one confirmation for the whole selection (default Skip); live entries then get icon 0 and groups icon 48 (their modification time moves), history items get icon 0 with no time change, and each removed icon gets a deleted-object record (FMT-15.7). Purge removes every icon no live entry and no group uses, including icons used only by history items, and reports how many it removed.

### Other values and defaults

MOD-12.20 **Values with no control.** `Color`, `MaintenanceHistoryDays`, `EntryTemplatesGroup`, `LastSelectedGroup`, `LastTopVisibleGroup` and `Generator` have no control in the reference or in Larsal; they are kept and written back (FMT-10). Neither app acts on `MaintenanceHistoryDays` (FMT-10.19). Command line tool: the reference's vault edit command changes only the credentials (set or unset password and key file) and moves `MasterKeyChanged` (FMT-10.24); its info command shows, among other facts (id, location, times, counts and password statistics), the name, description, cipher, KDF and the recycle bin state (observed, 2.7.11). INT-10 owns the commands.

MOD-12.21 **Who may change what.** The screen opens only for an unlocked vault, in both apps; the reference has no read-only vault mode. Changes made here are saved by the normal save flow; if that save fails (for example the folder is not writable), APP-05's save error flow applies and the changes stay in memory, marked unsaved.

MOD-12.22 **New vault defaults.**

| Value | Reference, window wizard | Reference, command line create | Larsal |
|---|---|---|---|
| Vault name | `Passwords`, prefilled and editable | empty | prefilled `Passwords`, editable (APP-07) |
| Root group name | `Root` | `Passwords` | `Root` |
| Description, default user name | empty | empty | empty |
| Cipher | AES-256 | AES-256 | AES-256 (LD-20) |
| KDF | Argon2d, 64 MiB, lanes min(4, cores), iterations for 1,000 ms (CRY-02.22) | AES-KDF, 1,000,000 rounds, or benchmarked when a time is given | Argon2id, 64 MiB, lanes min(4, cores), tuned to 1 second (LD-18, CRY-02.23) |
| File version | 4.0 | 3.1 | 4.0, or 4.1 when needed (FMT-16) |
| Compression | gzip | gzip | gzip |
| Recycle bin | on, no bin group until the first delete | same | same |
| History limits | 10 items, 6 MiB (6,291,456 bytes) | same | same |
| Protection flags | password only | same | password only, password always written protected (MOD-12.17) |
| Key change days | −1 and −1 (off) | same | same (MOD-13) |
| Maintenance days | 365 | same | 365 |
| "...Changed" times, `MasterKeyChanged`, `SettingsChanged` | creation time | creation time | creation time |
| Unlock time item | written by the wizard's simple mode | absent | written when the user picks a time in simple mode |
| Autosave delay item | absent | absent | absent |

## Edge cases and errors

- Stored `HistoryMaxSize` of 0 (no history by size): the reference shows it off and an untouched apply writes −1 (no limit). Larsal keeps 0 unless the user edits the control.
- Stored `HistoryMaxItems` of −1: shown off with 10; turning it on without editing stores 10.
- Typing 2,048 MiB or more in the reference's size field: overflow (MOD-12.5). Larsal cannot enter it.
- Apply where the credentials page refuses (for example passwords do not match): reference keeps the general page's changes; Larsal applies nothing.
- The KDF fails during apply (out of memory): `vault.msg.kdf_unchanged`; the page refuses; the old settings stay.
- Turning the recycle bin off while the bin holds items and choosing No: the bin becomes a normal group named with ` (old)`; deleting later moves nothing to it (MOD-04).
- Delete icons when one selected icon is used and another is not, answering Skip: only the unused icon is removed.
- Purge when every icon is in use: notice, nothing removed, vault not marked changed.
- `forget_site_access` aborted half way: entries already handled stay changed.
- A vault from another app with `ProtectPassword` False and unprotected passwords: Larsal writes the passwords protected on its next save (MOD-12.17); the flag becomes True only when the field protection page is applied.
- Field protection flag turned off for notes while an entry's notes were read with `ProtectInMemory`: Larsal clears that entry's own notes flag (MOD-12.16); the next save writes the notes unprotected.

## Security notes

- **Downgrades need the user (AT-A09).** Nothing on this screen lowers the cipher, KDF cost or protection without the user's explicit choice and the warnings of MOD-12.12. Loading and saving a vault never lowers them on its own, and neither does a merge (MOD-11.19, LD-60). Larsal adds the safe-minimum confirm and never lets passwords be written unprotected (MOD-12.16, MOD-12.17).
- **KDF cost (AT-A05, AT-B06).** Values typed on the screen go through the same CRY-02.14 checks as values read from a file. The benchmark runs on a worker thread.
- **Weak and missing passwords.** The checks of MOD-12.10 (no password warning, minimum quality refusal, weak password warning, at least one key part) must stay. A key change removes quick unlock data for the vault (SR-04, APP-04), so an old Touch ID item cannot open the vault with a key it no longer has.
- **Public header values (SF-12).** The display name, colour and icon are readable without the key. The page says so. They are shown before unlock only under FMT-03.23's rules.
- **Field protection (SF-08, SF-09).** Protected fields are encrypted a second time in the file. Turning flags on or off changes only the next save. A secret must never be written unprotected by accident: the password field always is protected (MOD-12.17).
- **Browser associations (SI-01, SI-02).** Removing associations and site access is a security action the user asks for; each needs a confirmation. The public keys shown are not secrets, but the screen still sets them as text only (AT-E01).
- **Hostile vault values (AT-E01).** Names, descriptions, association names and values come from the file and are set as text, never as markup.
- **Logs (AT-C06).** No setting value that comes from the vault, and no password quality detail, goes to the log.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| T01 MOD-12.1 pages | Unlocked vault in Larsal on this Mac | Open vault settings | Pages: General; Security with credentials, encryption, field protection, key change reminders; Remote sync; Browser integration; Shared groups; Maintenance. No secret service page |
| T02 MOD-12.2 atomic apply | Name changed to `New`; credentials page: password `abc` and repeat `abd` | Apply | Larsal: refused with `vault.msg.password_mismatch`, credentials page shown, name still the old one. Reference (source): name `New` applied |
| T03 MOD-12.3 changed time | Name `Demo`, DatabaseNameChanged T0 | Apply with name `Demo` (unchanged), then with `Demo2` at time T5 | First apply: DatabaseNameChanged stays T0. Second: T5 |
| T04 MOD-12.3 default user name | Default user name `demo` | Create a new entry in the window | Its user name field is `demo`. `larsal add` on the command line leaves it empty |
| T05 MOD-12.4 public colour | Public colour cleared | Apply, save, read the outer header | No public colour item (FMT-03.23); the page shows the "not encrypted" notice |
| T06 MOD-12.5 reference rounding | Stored HistoryMaxSize 3,500,000 | Reference: open settings, Apply untouched | Stored 3,145,728; histories cut to it |
| T07 MOD-12.5 Larsal keeps value | Stored HistoryMaxSize 3,500,000; HistoryMaxSize 100 in a second vault | Larsal: open settings, Apply untouched | 3,500,000 and 100 stay; SettingsChanged unchanged |
| T08 MOD-12.5 overflow | Reference size field 2,048 MiB | Apply, save, reopen | Stored −2,147,483,648, read back as the earlier value (FMT-10.15). Larsal: field refuses values above 2,047 |
| T09 MOD-12.5 truncation | Entry with 12 history items; HistoryMaxItems 10 → 5 | Apply | The entry keeps its 5 newest history items at once |
| T09b MOD-12.5 Larsal item range | Settings page; separately a file with `HistoryMaxItems` 200,000 | Enter 100,000, then 100,001; open the second vault's settings and apply without touching the history fields | 100,000 accepted, 100,001 refused by the control; the second vault keeps 200,000 in `Meta` while every entry is still pruned to 100,000 items (MOD-03.10) |
| T10 MOD-12.5 off | HistoryMaxItems 10 | Turn the item limit off, Apply | HistoryMaxItems −1; no history removed |
| T11 MOD-12.6 bin off, keep | Bin holds 2 entries | Turn the recycle bin off, answer No | Bin group renamed `<name> (old)`, icon 48; RecycleBinUUID null; RecycleBinEnabled False; no deleted objects added |
| T12 MOD-12.6 bin off, delete | Bin holds entry E(0A) and group G(02) holding E2(0B) | Turn off, answer Delete | Bin and contents gone; deleted objects E(0A), E2(0B), G(02), bin id, in that order (FMT-15.7) |
| T13 MOD-12.7 compression | Compression on | Turn off, Apply, save | Outer header compression flag = none (FMT-08) |
| T14 MOD-12.8 autosave item | Vault without the autosave item | Larsal: Apply the general page untouched | No autosave item added. Reference: item with value `0` added |
| T15 MOD-12.8 autosave off | Autosave item `5` | Larsal: turn autosave off, Apply | Item removed |
| T16 MOD-12.9 settings time | SettingsChanged T0 | Larsal: Apply with only the name changed, at T5; then with history items changed at T6 | After the first apply SettingsChanged stays T0; after the second it is T6. Reference: T5 after the first |
| T17 MOD-12.10 no password | Credentials: remove the password, keep a key file | Apply | Warning `vault.msg.no_password`, default Cancel; Cancel refuses; continue applies a key-file-only key |
| T18 MOD-12.10 minimum quality | Larsal setting minimum quality 3 (Good) | New password `password1` (quality below Good) | Refused with `vault.msg.password_below_minimum` |
| T19 MOD-12.10 weak warning | Minimum quality 0 | New password `password1` | Warning `vault.msg.password_weak`, default Cancel |
| T20 MOD-12.10 no key part | Remove the password and the key file | Apply, continue without password | Refused with `vault.msg.no_key_part` |
| T21 MOD-12.10 effect | MasterKeyChanged T0; force-once set; quick unlock stored for this vault | Change the password to `demo2` at T5, Apply | MasterKeyChanged T5; force-once cleared; quick unlock item for the vault gone (APP-04); after save the vault opens with `demo2` only |
| T22 MOD-12.10 same password again | Password `demo` | Open the password for editing, type `demo` twice, Apply at T5 | MasterKeyChanged T5 |
| T23 MOD-12.10 old key file kind | Key file of the raw 32-byte kind | Add it as a key part | Warning advising a new key file; the key part is still added |
| T23b MOD-12.10 old copies | Backups on, one backup of the vault exists | Change the password, Apply, save | `MSG-KEY-OLD-COPIES` (APP-05.33) lists the backup; Keep is the default |
| T24 MOD-12.11 simple mode | Vault with unlock time item `2000` | Open the encryption page | Simple mode, slider at 2,000 ms. Apply at 1,000 ms: iterations re-benchmarked (CRY-02.28), item `1000` |
| T25 MOD-12.12 warnings | Advanced mode | Argon2id iterations 20,000; separately AES-KDF rounds 50,000 | Each shows its warning, default Cancel; Cancel refuses the page |
| T26 MOD-12.12 safe minimum | Advanced mode, Larsal | Argon2id memory 8 MiB, iterations 3 | Confirm with the estimated unlock time shown; Cancel refuses |
| T27 MOD-12.12 cost ask | Advanced mode, Larsal | Argon2id memory 2,048 MiB | Cost confirm (CRY-02.14) before any work runs |
| T28 MOD-12.12 time item removed | Vault with unlock time item | Apply in advanced mode | Item removed |
| T29 MOD-12.13 no format choice | Larsal, vault read from a version 3.1 file | Open the encryption page | No format list; saving writes version 4 (FMT-16, LD-07) |
| T30 MOD-12.14 when it takes effect | Cipher AES-256 | Choose ChaCha20, Apply, save, open with the reference command line tool | The tool opens it; its info command reports ChaCha20; the screen stayed responsive during the derivation |
| T31 MOD-12.14 untouched | Encryption page opened and closed with Apply, nothing touched | Apply | No key derivation runs; nothing marked changed by this page |
| T32 MOD-12.15 flags on save (observed in export) | Flags: Title on, notes on, password off; entry T `T`, user `U`, password `P`, URL `http://x`, notes `N`, no own flags | Save; read the decrypted document | `Title` and `Notes` values carry `Protected="True"` and decode to `T` and `N` (FMT-09); `UserName` and `URL` have no attribute. Reference export of the same vault: `ProtectInMemory="True"` on Title and notes only |
| T33 MOD-12.15 own flag wins | Flag notes off; entry notes read with `Protected="True"` | Save | Notes still written protected (FMT-11.21) |
| T34 MOD-12.16 Larsal switches | Field protection page | Try to turn the password switch off | Not possible. Turn URL on, Apply, save: every entry's and history item's `URL` is written protected |
| T35 MOD-12.16 turning off clears own flags | Notes flag on; entry notes and its history item notes read protected | Turn notes off, Apply, save | Both written unprotected; the entry's Mod unchanged |
| T36 MOD-12.17 password always protected | Vault with ProtectPassword False, passwords read unprotected | Larsal saves | Every `Password` value is written `Protected="True"`; ProtectPassword still False in the file |
| T37 MOD-12.18 remove association | Associations `demo` (with `_CREATED_demo`) and `work` | Select `demo`, remove, confirm | Key item for `demo` and `_CREATED_demo` gone; `work` stays |
| T38 MOD-12.18 disconnect all | Associations `demo`, `work` with `_CREATED_` items | Disconnect all, confirm | Both key items removed; report says 2. Larsal: `_CREATED_demo` and `_CREATED_work` also gone. Reference: they stay |
| T39 MOD-12.18 forget site access | Entries E1 with the site-access item, E2 without; E1 has 1 history item | Forget site access, confirm, at T5 | E1 loses the item, E1 Mod = T5, E1 has 2 history items (the newest holds the item); report says 1 |
| T40 MOD-12.18 new root id | Root group id(01) | New root id, confirm | Root id is a new random id; no deleted object added |
| T41 MOD-12.18 integration off | Browser integration off in app settings | Open the page | Buttons and table disabled; notice to turn integration on |
| T42 MOD-12.19 delete used icon | Icon id(32) used by entry E (Mod T0) and by E's history item; group G uses it | Delete icon, confirm, at T5 | E icon 0, Mod T5; history item icon 0, its times unchanged; G icon 48; icon gone; deleted object id(32) at T5 |
| T43 MOD-12.19 purge | Icons id(32) unused, id(33) used only by a history item, id(34) used by a group | Purge at T5 | id(32) and id(33) removed, the history item gets icon 0 with its times unchanged; deleted objects id(32) and id(33) at T5; report says 2; id(34) stays |
| T44 MOD-12.20 kept values | `Color` `#1a2b3c`, MaintenanceHistoryDays 30, EntryTemplatesGroup = group id(07) | Open and Apply settings, save | All three written back unchanged |
| T45 MOD-12.21 save fails | Vault file in a folder made read only after unlock | Change the name, Apply | Name changed in memory; the save fails with APP-05's error; the vault stays marked unsaved; the file on disk is unchanged |
| T46 MOD-12.22 new vault | Larsal creates a vault with defaults | Inspect | Name `Passwords` unless edited, root `Root`, AES-256, Argon2id 64 MiB, lanes min(4, cores), version 4.0, gzip, recycle bin on and no bin group, 10 items, 6,291,456 bytes, only ProtectPassword on, MasterKeyChangeRec and MasterKeyChangeForce −1, MaintenanceHistoryDays 365 |
| T47 MOD-12.22 reference command line (observed) | Reference `db-create` with a password and a 100 ms target time | Export the vault | Empty vault name, root group `Passwords`, AES-KDF, ProtectPassword only, history 10 and 6,291,456, recycle bin on |

## How this was learned

- Read in the reference source: the vault settings dialog and its pages (general, credentials, encryption, browser integration, maintenance) with their screen definitions, the remote sync and shared-group pages only to list them, the new vault wizard and its simple metadata page, the credential part widgets (password, key file, hardware key), the vault core's key set, KDF change, cipher and compression setters, the metadata defaults, the custom data keys for autosave and unlock time, the protection flag reader and writer, and the browser service routine that removes site access.
- Ran the installed command line tool 2.7.11 on demo vaults in `/tmp/spec-mod11-13/` (password `demo`): T32's export observation and T47 are observed; the CLI's commands list and the vault edit command's options were read from its help.
- Not run: the window screens (not launched, by rule). Every reference statement about the screen comes from the source. Verify re-read the source for the three riskiest ones (Sprint 2): MOD-12.2 (Apply runs the general, credentials, encryption and remote sync pages in that order, then the shared-group and secret service pages, and stops at the first that refuses, leaving the earlier pages applied), MOD-12.5 (the rounding and overflow of MOD-03's size limit row) and MOD-12.8 (every apply sets the autosave item to the minutes or `0`, which adds the item when it is missing and then refreshes `_LAST_MODIFIED`). The rest still needs a run of the window: check with Verify.
- Lead decisions in this card: D-12-1 atomic apply, D-12-2 history limit controls, D-12-3 autosave item, D-12-4 field protection page, D-12-5 passwords always protected, D-12-6 safe minimum values (Argon2 19 MiB and 2 iterations, from the public OWASP password storage guidance), D-12-7 disconnect all removes created items. Each rule states the recommended option. None is listed in spec/decisions.md, so each is decided by its default rule: the recommended option. Also applied: LD-33 (MOD-12.9's list is the settings-time rule, FMT-10.24 points to it) and the MOD-03.10 item ceiling in MOD-12.5 (review of 2026-10-25).
- Sprint 1 close-out: the Larsal cost-check line now names all three ask thresholds of CRY-02.14 (lanes above 128 was missing) and points to CRY-02.14 for the numbers.
